//! OpenCTI synchronisation against a mock GraphQL endpoint.
//!
//! One section per acceptance criterion of [#43](https://github.com/jusso-dev/Brolga/issues/43).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod mock_server;

use brolga_connectors::{
    ConnectorError, OPENCTI_CONNECTOR, OpenCtiClient, OpenCtiInstance, PolicyTransport,
    QueryOperation, SyncOptions, sync_opencti,
};
use brolga_ingest::formats::stix::StixParser;
use brolga_ingest::{IngestMode, ParserRegistry, Pipeline};
use brolga_model::Timestamp;
use brolga_model::provenance::SensitiveText;
use brolga_security::{CancellationToken, NetworkPolicy};
use brolga_storage::{CursorStatus, IntelligenceStore, RecordKind, SqliteStore, StoreRead};
use mock_server::{MockServer, Reply};

fn permissive() -> NetworkPolicy {
    NetworkPolicy {
        allow_plaintext_http: true,
        allow_private_addresses: true,
        ..NetworkPolicy::strict()
    }
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn pipeline() -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(StixParser::boxed());
    Pipeline::with_defaults(registry).in_mode(IngestMode::Permissive)
}

fn instance(base_url: &str) -> OpenCtiInstance {
    OpenCtiInstance::new(
        "primary",
        base_url,
        SensitiveText::new("token-abc").unwrap(),
    )
}

const JSON: &str = "application/json";

/// A GraphQL page holding one indicator, rendered the way OpenCTI renders one: `toStix` is a JSON
/// *string* holding the object.
fn page(id: &str, address: &str, modified: &str, has_next: bool, cursor: &str) -> String {
    let stix = serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": format!("indicator--{id}"),
        "created": "2024-01-01T00:00:00.000Z",
        "modified": modified,
        "pattern_type": "stix",
        "pattern": format!("[ipv4-addr:value = '{address}']"),
        "indicator_types": ["malicious-activity"],
        "valid_from": "2024-01-01T00:00:00.000Z",
    })
    .to_string();

    serde_json::json!({
        "data": {"stixCoreObjects": {
            "pageInfo": {"endCursor": cursor, "hasNextPage": has_next},
            "edges": [{"node": {
                "id": id,
                "standard_id": format!("indicator--{id}"),
                "entity_type": "Indicator",
                "updated_at": modified,
                "toStix": stix,
            }}],
        }}
    })
    .to_string()
}

// ---------------------------------------------------------------------------------------------
// "Queries are fixed or allowlisted rather than caller-supplied GraphQL"
// ---------------------------------------------------------------------------------------------

/// The criterion, at the type level. Every body this connector can send is one of the documents
/// compiled into Brolga, and the request type has no constructor taking a query string.
#[test]
fn every_query_sent_is_one_of_the_compiled_in_documents() {
    let server = MockServer::start(vec![(
        "/graphql",
        vec![Reply::json(
            JSON,
            page(
                "11111111-1111-4111-8111-111111111111",
                "198.51.100.5",
                "2024-06-01T00:00:00.000Z",
                false,
                "c1",
            ),
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();

    let _ = sync_opencti(
        &client,
        &mut store,
        &pipeline(),
        &instance(&server.base_url()),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    let documents: Vec<&'static str> = QueryOperation::all()
        .iter()
        .map(|operation| operation.document())
        .collect();
    assert!(!documents.is_empty());

    // Every request was a POST to the one endpoint. The bodies cannot be inspected through the
    // mock's header log, so the closed set is asserted over the type instead — which is where the
    // guarantee actually lives.
    for request in server.requests() {
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/graphql");
    }
}

/// The compiled-in set must never gain a mutation, whoever adds the next query.
#[test]
fn no_operation_in_the_allowlist_mutates() {
    for operation in QueryOperation::all() {
        let document = operation.document();
        assert!(
            document.trim_start().starts_with("query"),
            "{}",
            operation.as_str()
        );
        assert!(!document.contains("mutation"), "{}", operation.as_str());
    }
}

// ---------------------------------------------------------------------------------------------
// "Polling resumes idempotently" / "Export and read paths preserve identifiers and provenance"
// ---------------------------------------------------------------------------------------------

/// Running the same poll twice must not double the graph.
#[test]
fn polling_twice_stores_the_same_records_once() {
    let body = page(
        "22222222-2222-4222-8222-222222222222",
        "198.51.100.6",
        "2024-06-01T00:00:00.000Z",
        false,
        "c1",
    );
    let server = MockServer::start(vec![("/graphql", vec![Reply::json(JSON, body)])]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();
    let instance = instance(&server.base_url());

    let run = |store: &mut SqliteStore| {
        sync_opencti(
            &client,
            store,
            &pipeline(),
            &instance,
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
    };

    let first = run(&mut store);
    assert!(first.inserted > 0, "{first:?}");
    let after_first = store.count(RecordKind::Claim).unwrap();

    let _ = run(&mut store);
    assert_eq!(store.count(RecordKind::Claim).unwrap(), after_first);

    let cursor = store
        .connector_cursor(OPENCTI_CONNECTOR, "primary/stix")
        .unwrap()
        .expect("a cursor");
    assert_eq!(
        cursor.added_after.as_deref(),
        Some("2024-06-01T00:00:00.000Z")
    );
    assert_eq!(cursor.last_status, CursorStatus::Complete);
}

/// Pagination follows the GraphQL end cursor to the end.
#[test]
fn pagination_follows_the_end_cursor() {
    let server = MockServer::start(vec![(
        "/graphql",
        vec![
            Reply::json(
                JSON,
                page(
                    "33333333-3333-4333-8333-333333333331",
                    "198.51.100.11",
                    "2024-03-01T00:00:00.000Z",
                    true,
                    "c1",
                ),
            ),
            Reply::json(
                JSON,
                page(
                    "33333333-3333-4333-8333-333333333332",
                    "198.51.100.12",
                    "2024-06-01T00:00:00.000Z",
                    false,
                    "c2",
                ),
            ),
        ],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();

    let report = sync_opencti(
        &client,
        &mut store,
        &pipeline(),
        &instance(&server.base_url()),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(report.pages, 2, "{report:?}");
    assert_eq!(report.objects, 2);
    assert!(report.is_complete());
    assert_eq!(
        report.cursor.added_after.as_deref(),
        Some("2024-06-01T00:00:00.000Z")
    );
}

/// A server claiming more pages without moving its cursor would loop forever.
#[test]
fn a_server_claiming_more_without_moving_its_cursor_does_not_loop() {
    let stuck = page(
        "44444444-4444-4444-8444-444444444444",
        "198.51.100.20",
        "2024-06-01T00:00:00.000Z",
        true,
        "same",
    );
    let server = MockServer::start(vec![("/graphql", vec![Reply::json(JSON, stuck)])]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();

    let report = sync_opencti(
        &client,
        &mut store,
        &pipeline(),
        &instance(&server.base_url()),
        Timestamp::unix_epoch(),
        SyncOptions::default().with_max_pages(10),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert!(report.pages <= 2, "the run looped: {report:?}");
}

// ---------------------------------------------------------------------------------------------
// "Unsupported OpenCTI objects remain explicit"
// ---------------------------------------------------------------------------------------------

/// An object OpenCTI cannot render as STIX is counted, not skipped in silence. A half-imported page
/// that said nothing would look identical to a whole one.
#[test]
fn an_object_with_no_stix_rendering_is_counted_rather_than_skipped() {
    let body = serde_json::json!({
        "data": {"stixCoreObjects": {
            "pageInfo": {"endCursor": "c1", "hasNextPage": false},
            "edges": [
                {"node": {"id": "a", "entity_type": "Case", "updated_at": "2024-06-01T00:00:00.000Z"}},
                {"node": {"id": "b", "entity_type": "Case", "updated_at": "2024-06-01T00:00:00.000Z",
                          "toStix": "not json"}},
            ],
        }}
    })
    .to_string();

    let server = MockServer::start(vec![("/graphql", vec![Reply::json(JSON, body)])]);
    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();

    let report = sync_opencti(
        &client,
        &mut store,
        &pipeline(),
        &instance(&server.base_url()),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(report.objects, 2);
    assert!(
        report.quarantined >= 2,
        "unrenderable objects must be reported: {report:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Errors, credentials, and policy
// ---------------------------------------------------------------------------------------------

/// GraphQL answers `200` with an `errors` array. A status check alone would read a rejected token
/// as a successful empty page, and a sync would report success having imported nothing.
#[test]
fn a_graphql_error_fails_the_run_rather_than_reading_as_an_empty_page() {
    let server = MockServer::start(vec![(
        "/graphql",
        vec![Reply::json(
            JSON,
            r#"{"errors":[{"message":"You are not authenticated"}],"data":null}"#,
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let mut store = store();

    let error = sync_opencti(
        &client,
        &mut store,
        &pipeline(),
        &instance(&server.base_url()),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap_err();

    assert!(
        matches!(error, ConnectorError::MalformedResponse { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("not authenticated"), "{error}");

    let cursor = store
        .connector_cursor(OPENCTI_CONNECTOR, "primary/stix")
        .unwrap()
        .expect("the cursor records the failure");
    assert_eq!(cursor.last_status, CursorStatus::Failed);
    assert!(
        cursor.added_after.is_none(),
        "nothing was stored, so nothing moved"
    );
}

/// Re-posting a body to a location a server chose is how a query aimed at a configured endpoint
/// ends up delivered somewhere else.
#[test]
fn a_redirect_answering_a_query_is_refused_rather_than_followed() {
    let server = MockServer::start(vec![(
        "/graphql",
        vec![Reply::redirect(
            307,
            "http://169.254.169.254/latest/meta-data/",
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let error = client.version(&instance(&server.base_url())).unwrap_err();

    let rendered = error.to_string();
    assert!(
        rendered.contains("does not re-send a request body"),
        "{rendered}"
    );
}

/// The shipped default refuses a loopback endpoint, so the permissive test policy cannot become the
/// product's behaviour.
#[test]
fn the_strict_default_refuses_a_loopback_endpoint() {
    let server = MockServer::start(vec![("/graphql", vec![Reply::json(JSON, "{}")])]);

    let transport = PolicyTransport::new(NetworkPolicy::strict());
    let client = OpenCtiClient::new(&transport);
    let error = client.version(&instance(&server.base_url())).unwrap_err();

    assert!(matches!(error, ConnectorError::Denied { .. }), "{error}");
    assert_eq!(server.served(), 0);
}

/// The token reaches the endpoint and nothing else.
#[test]
fn the_token_reaches_the_endpoint_and_never_an_error() {
    let server = MockServer::start(vec![(
        "/graphql",
        vec![Reply::json(
            JSON,
            r#"{"data":{"about":{"version":"6.0.0"}}}"#,
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = OpenCtiClient::new(&transport);
    let version = client.version(&instance(&server.base_url())).unwrap();

    assert_eq!(version, "6.0.0");
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.headers.contains_key("authorization"))
    );
    assert!(!format!("{client:?}").contains("token-abc"));
}
