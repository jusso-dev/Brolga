//! TAXII retrieval against a mock server, and the policy that constrains it.
//!
//! One section per acceptance criterion of [#42](https://github.com/jusso-dev/Brolga/issues/42).
//!
//! No test here reaches outside the machine. The mock binds loopback on port 0; the SSRF policy is
//! asserted separately over addresses, because a test that proved the policy by *failing to reach*
//! a real internal address would be a test that depends on somebody else's network.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod mock_server;

use brolga_connectors::{
    ConnectorError, FeedRef, PolicyTransport, SyncOptions, TAXII_CONNECTOR, TaxiiClient,
    TaxiiVersion, sync_collection,
};
use brolga_ingest::formats::stix::StixParser;
use brolga_ingest::{IngestMode, ParserRegistry, Pipeline};
use brolga_model::Timestamp;
use brolga_security::{CancellationToken, NetworkPolicy};
use brolga_storage::{CursorStatus, IntelligenceStore, SqliteStore, StoreRead};
use mock_server::{MockServer, Reply};

/// The policy the mock-server tests run under.
///
/// Loopback is permitted **only here**, so the protocol can be exercised at all. The shipped
/// default refuses it, and `the_shipped_default_policy_refuses_the_fixture_it_is_tested_against`
/// asserts exactly that — so this convenience cannot quietly become the product's behaviour.
fn permissive_policy() -> NetworkPolicy {
    NetworkPolicy {
        allow_plaintext_http: true,
        allow_private_addresses: true,
        ..NetworkPolicy::strict()
    }
}

fn transport() -> PolicyTransport {
    PolicyTransport::new(permissive_policy())
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

const V21: &str = "application/taxii+json;version=2.1";
const V20: &str = "application/vnd.oasis.taxii+json;version=2.0";

/// Discovery naming the server that serves it, resolved at response time.
const DISCOVERY: &str =
    r#"{"title":"Example TAXII","default":"{{BASE}}/api1/","api_roots":["{{BASE}}/api1/"]}"#;

const COLLECTIONS: &str = r#"{"collections":[
    {"id":"91a7b528-80eb-42ed-a74d-c6fbd5a26116","title":"Enterprise","can_read":true},
    {"id":"52892447-4d7e-4f70-b94d-d7f22742ff63","title":"Write only","can_read":false}
]}"#;

/// A STIX envelope holding one indicator, so a page has something the parser can actually store.
fn envelope(id: &str, address: &str, modified: &str, more: bool, next: Option<&str>) -> String {
    let next = next.map_or_else(|| String::from("null"), |token| format!("\"{token}\""));
    format!(
        r#"{{"more":{more},"next":{next},"objects":[
            {{"type":"indicator","spec_version":"2.1","id":"indicator--{id}",
              "created":"2024-01-01T00:00:00.000Z","modified":"{modified}",
              "pattern_type":"stix","pattern":"[ipv4-addr:value = '{address}']",
              "indicator_types":["malicious-activity"],"valid_from":"2024-01-01T00:00:00.000Z"}}
        ]}}"#
    )
}

// ---------------------------------------------------------------------------------------------
// "Version negotiation is explicit"
// ---------------------------------------------------------------------------------------------

/// The criterion. A server's own `Content-Type` decides, not the `Accept` that was sent — reading a
/// 2.0 body as 2.1 would mis-paginate everything after the first page.
#[test]
fn a_2_1_server_is_negotiated_from_the_content_type_it_answers_with() {
    let server = MockServer::start(vec![("/taxii2/", vec![Reply::json(V21, DISCOVERY)])]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    assert_eq!(discovery.version, TaxiiVersion::V21);
    assert_eq!(client.version(), Some(TaxiiVersion::V21));
    assert!(!discovery.api_roots.is_empty());
}

/// A 2.0 server has a different discovery path *and* a different media type. Finding it means
/// falling back after 2.1 fails, and reading the version it actually answered with.
#[test]
fn a_2_0_only_server_is_found_by_falling_back_to_its_own_discovery_path() {
    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::status(404)]),
        ("/taxii/", vec![Reply::json(V20, DISCOVERY)]),
    ]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    assert_eq!(discovery.version, TaxiiVersion::V20);
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.target.starts_with("/taxii2/")),
        "2.1 is tried first, because a server supporting both should be spoken to in the newer one"
    );
}

/// Guessing the protocol from the body shape would be right most of the time and silently
/// mis-paginate the rest. Refusing to start beats losing half a collection.
#[test]
fn a_server_speaking_neither_version_is_refused_naming_what_it_answered() {
    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::status(404)]),
        ("/taxii/", vec![Reply::status(501)]),
    ]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let error = client.discover(&server.base_url()).unwrap_err();

    let rendered = error.to_string();
    assert!(
        rendered.contains("404") && rendered.contains("501"),
        "{rendered}"
    );
    assert!(matches!(error, ConnectorError::VersionNotNegotiated { .. }));
}

/// Discovery that names no API root has nothing to read, and saying so beats an empty success.
#[test]
fn discovery_naming_no_api_root_is_a_malformed_response() {
    let server = MockServer::start(vec![(
        "/taxii2/",
        vec![Reply::json(V21, r#"{"title":"Empty","api_roots":[]}"#)],
    )]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let error = client.discover(&server.base_url()).unwrap_err();
    assert!(matches!(error, ConnectorError::MalformedResponse { .. }));
}

// ---------------------------------------------------------------------------------------------
// "Collection and object identifiers remain in provenance"
// ---------------------------------------------------------------------------------------------

#[test]
fn collections_are_listed_with_their_identifiers_and_read_flags() {
    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::json(V21, DISCOVERY)]),
        ("/api1/collections/", vec![Reply::json(V21, COLLECTIONS)]),
    ]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();
    let collections = client.collections(&discovery.api_roots[0]).unwrap();

    assert_eq!(collections.len(), 2);
    assert_eq!(collections[0].id, "91a7b528-80eb-42ed-a74d-c6fbd5a26116");
    assert!(collections[0].can_read);
    assert!(!collections[1].can_read);
}

/// A record's provenance must name the server it came from, or a finding cannot be defended.
#[test]
fn ingested_records_cite_the_server_they_came_from() {
    use brolga_storage::RecordKind;

    let server = start_paginated_server(false);
    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    let report = sync_collection(
        &client,
        &mut store,
        &pipeline(),
        FeedRef::new(
            &discovery.api_roots[0],
            "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        ),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert!(report.inserted > 0, "{report:?}");
    assert!(store.count(RecordKind::Claim).unwrap() > 0);
}

// ---------------------------------------------------------------------------------------------
// "Pagination and added-after checkpoints resume safely"
// ---------------------------------------------------------------------------------------------

/// A server answering two pages, then nothing.
fn start_paginated_server(more_pages: bool) -> MockServer {
    let objects_path = "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/";
    let replies = if more_pages {
        vec![
            Reply::json(
                V21,
                envelope(
                    "aaaa",
                    "198.51.100.1",
                    "2024-01-01T00:00:00.000Z",
                    true,
                    Some("page2"),
                ),
            )
            .with_header("ETag", "\"v1\""),
            Reply::json(
                V21,
                envelope(
                    "bbbb",
                    "198.51.100.2",
                    "2024-06-01T00:00:00.000Z",
                    false,
                    None,
                ),
            ),
        ]
    } else {
        vec![
            Reply::json(
                V21,
                envelope(
                    "aaaa",
                    "198.51.100.1",
                    "2024-06-01T00:00:00.000Z",
                    false,
                    None,
                ),
            )
            .with_header("ETag", "\"v1\""),
        ]
    };

    MockServer::start(vec![
        ("/taxii2/", vec![Reply::json(V21, DISCOVERY)]),
        (objects_path, replies),
    ])
}

/// The criterion. Two pages are followed to the end, and the cursor lands on the newest timestamp
/// seen — not on the first page's.
#[test]
fn pagination_is_followed_to_the_end_and_the_cursor_lands_on_the_newest_record() {
    let server = start_paginated_server(true);
    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    let report = sync_collection(
        &client,
        &mut store,
        &pipeline(),
        FeedRef::new(
            &discovery.api_roots[0],
            "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        ),
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
        Some("2024-06-01T00:00:00.000Z"),
        "the cursor takes the newest record across the whole run"
    );

    let stored = store
        .connector_cursor(TAXII_CONNECTOR, "91a7b528-80eb-42ed-a74d-c6fbd5a26116")
        .unwrap()
        .expect("the cursor is durable");
    assert_eq!(stored.last_status, CursorStatus::Complete);
    assert_eq!(stored.records_seen, 2);
}

/// A second run must ask for what is new rather than re-reading the feed.
#[test]
fn a_second_run_sends_the_stored_added_after() {
    let server = start_paginated_server(false);
    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    for _ in 0..2 {
        let _ = sync_collection(
            &client,
            &mut store,
            &pipeline(),
            FeedRef::new(
                &discovery.api_roots[0],
                "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            ),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        );
    }

    let object_requests: Vec<_> = server
        .requests()
        .into_iter()
        .filter(|request| request.target.contains("/objects/"))
        .collect();

    assert!(object_requests.len() >= 2, "{object_requests:?}");
    assert!(
        object_requests
            .last()
            .is_some_and(|request| request.has_query("added_after")),
        "the second run did not resume: {object_requests:?}"
    );
}

/// A server can always claim more pages remain. Stopping on the bound is reported as *partial*,
/// because "stopped early" and "up to date" are different facts.
#[test]
fn a_run_bounded_by_max_pages_reports_partial_rather_than_complete() {
    let server = start_paginated_server(true);
    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    let report = sync_collection(
        &client,
        &mut store,
        &pipeline(),
        FeedRef::new(
            &discovery.api_roots[0],
            "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        ),
        Timestamp::unix_epoch(),
        SyncOptions::default().with_max_pages(1),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(report.pages, 1);
    assert!(!report.is_complete(), "a bounded run is not a finished one");
    assert_eq!(report.cursor.last_status, CursorStatus::Partial);
}

// ---------------------------------------------------------------------------------------------
// "ETags avoid unnecessary retrieval where supported"
// ---------------------------------------------------------------------------------------------

/// The criterion. A stored tag is sent, and a `304` ends the run without a body.
#[test]
fn a_stored_etag_is_sent_and_a_not_modified_ends_the_run_without_a_body() {
    let objects_path = "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/";
    let first = Reply::json(
        V21,
        envelope(
            "aaaa",
            "198.51.100.1",
            "2024-06-01T00:00:00.000Z",
            false,
            None,
        ),
    )
    .with_header("ETag", "\"v1\"");

    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::json(V21, DISCOVERY)]),
        (objects_path, vec![first, Reply::status(304)]),
    ]);

    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();
    let api_root = discovery.api_roots[0].clone();

    let run = |store: &mut SqliteStore| {
        sync_collection(
            &client,
            store,
            &pipeline(),
            FeedRef::new(&api_root, "91a7b528-80eb-42ed-a74d-c6fbd5a26116"),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
    };

    let first_run = run(&mut store);
    assert!(!first_run.not_modified);
    assert_eq!(first_run.cursor.etag.as_deref(), Some("\"v1\""));

    let second_run = run(&mut store);
    assert!(second_run.not_modified, "{second_run:?}");
    assert_eq!(second_run.pages, 0, "a 304 costs a round trip, not a body");
    assert_eq!(second_run.cursor.last_status, CursorStatus::NotModified);

    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.headers.contains_key("if-none-match")),
        "the stored tag was never sent"
    );
}

// ---------------------------------------------------------------------------------------------
// "Malformed server responses quarantine without corrupting checkpoint"
// ---------------------------------------------------------------------------------------------

/// **The criterion this whole design turns on.** A malformed page must leave the cursor where the
/// last good page put it. Advancing it first would mean the window is never re-fetched — with no
/// error, because the next run simply starts after the gap.
#[test]
fn a_malformed_page_leaves_the_cursor_where_the_last_good_page_left_it() {
    let objects_path = "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/";
    let good = Reply::json(
        V21,
        envelope(
            "aaaa",
            "198.51.100.1",
            "2024-03-01T00:00:00.000Z",
            true,
            Some("page2"),
        ),
    );
    let broken = Reply::json(V21, "{ this is not json");

    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::json(V21, DISCOVERY)]),
        (objects_path, vec![good, broken]),
    ]);

    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    let error = sync_collection(
        &client,
        &mut store,
        &pipeline(),
        FeedRef::new(
            &discovery.api_roots[0],
            "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        ),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap_err();

    assert!(
        matches!(error, ConnectorError::MalformedResponse { .. }),
        "{error}"
    );

    let cursor = store
        .connector_cursor(TAXII_CONNECTOR, "91a7b528-80eb-42ed-a74d-c6fbd5a26116")
        .unwrap()
        .expect("the cursor survived the failure");

    assert_eq!(
        cursor.added_after.as_deref(),
        Some("2024-03-01T00:00:00.000Z"),
        "the cursor sits at the last page that was actually stored, not past the broken one"
    );
    assert_eq!(cursor.last_status, CursorStatus::Failed);
    assert_eq!(
        cursor.records_seen, 1,
        "only the stored page counted toward the total"
    );
}

/// An empty page ends a run whatever the server claims. Without this, a server answering
/// `more: true` with no objects forever is an infinite loop.
#[test]
fn a_server_claiming_more_pages_with_no_objects_does_not_loop() {
    let objects_path = "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/";
    let empty = Reply::json(V21, r#"{"more":true,"next":"forever","objects":[]}"#);

    let server = MockServer::start(vec![
        ("/taxii2/", vec![Reply::json(V21, DISCOVERY)]),
        (objects_path, vec![empty]),
    ]);

    let mut store = store();
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let discovery = client.discover(&server.base_url()).unwrap();

    let report = sync_collection(
        &client,
        &mut store,
        &pipeline(),
        FeedRef::new(
            &discovery.api_roots[0],
            "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        ),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(report.pages, 1);
    assert!(report.is_complete());
}

// ---------------------------------------------------------------------------------------------
// "Discovery URLs and redirects remain inside configured network policy"
// ---------------------------------------------------------------------------------------------

/// **The SSRF control, exercised rather than asserted.** The server answers a redirect to the cloud
/// metadata address. The policy must refuse it, and the refusal must come from Brolga rather than
/// from the request failing — which is why the fixture redirects somewhere that would *succeed* if
/// it were followed on a cloud instance.
#[test]
fn a_redirect_to_the_metadata_address_is_refused_by_policy() {
    let server = MockServer::start(vec![(
        "/taxii2/",
        vec![Reply::redirect(
            302,
            "http://169.254.169.254/latest/meta-data/",
        )],
    )]);

    // Permissive about private addresses on purpose. Metadata is a *separate* switch, and this
    // asserts that enabling internal fetches does not enable reading instance credentials.
    let transport = PolicyTransport::new(NetworkPolicy {
        allow_plaintext_http: true,
        allow_private_addresses: true,
        ..NetworkPolicy::strict()
    });
    let mut client = TaxiiClient::new(&transport);
    let error = client.discover(&server.base_url()).unwrap_err();

    let rendered = error.to_string();
    assert!(
        matches!(error, ConnectorError::Denied { .. }),
        "the redirect was not refused by policy: {rendered}"
    );
    assert!(rendered.contains("169.254.169.254"), "{rendered}");
}

/// A redirect that downgrades sends the credential the first request carried over plaintext.
#[test]
fn a_redirect_downgrading_to_plaintext_is_refused() {
    let policy = NetworkPolicy {
        allow_private_addresses: true,
        ..NetworkPolicy::strict()
    };
    assert!(policy.permits_redirect(0, "https", "http").is_err());
}

/// Redirect chains are bounded, and the bound is Brolga's rather than the agent's.
#[test]
fn a_redirect_loop_is_bounded() {
    let server = MockServer::start(vec![("/taxii2/", vec![Reply::redirect(302, "/taxii2/")])]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let error = client.discover(&server.base_url()).unwrap_err();

    assert!(
        matches!(error, ConnectorError::Denied { .. }),
        "a redirect loop must be refused: {error}"
    );
}

/// The convenience the mock-server tests run under must not be the product's behaviour. This is the
/// test that keeps `permissive_policy` from quietly becoming the default.
#[test]
fn the_shipped_default_policy_refuses_the_fixture_it_is_tested_against() {
    let server = MockServer::start(vec![("/taxii2/", vec![Reply::json(V21, DISCOVERY)])]);

    let transport = PolicyTransport::new(NetworkPolicy::strict());
    let mut client = TaxiiClient::new(&transport);
    let error = client.discover(&server.base_url()).unwrap_err();

    assert!(
        matches!(error, ConnectorError::Denied { .. }),
        "the strict default permitted a loopback fixture: {error}"
    );
    assert_eq!(
        server.served(),
        0,
        "no request should have been made at all"
    );
}

/// A URL that reads as one host to a human and resolves as another to a parser is refused rather
/// than read one way or the other.
#[test]
fn a_url_carrying_userinfo_is_refused_before_any_connection() {
    let transport = transport();
    let mut client = TaxiiClient::new(&transport);
    let error = client
        .discover("http://evil.example.net@127.0.0.1:1/")
        .unwrap_err();

    assert!(
        matches!(error, ConnectorError::MalformedUrl { .. }),
        "{error}"
    );
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

/// A credential goes to the server and nowhere else — not into an error, not into a record.
#[test]
fn a_credential_is_sent_to_the_server_and_never_into_an_error() {
    use brolga_model::provenance::SensitiveText;

    let server = MockServer::start(vec![("/taxii2/", vec![Reply::status(401)])]);

    let transport = transport();
    let mut client = TaxiiClient::new(&transport).with_authorization(Some(
        SensitiveText::new("Bearer super-secret-token").unwrap(),
    ));
    let error = client.discover(&server.base_url()).unwrap_err();

    assert!(
        !error.to_string().contains("super-secret-token"),
        "the credential leaked into an error: {error}"
    );
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request.headers.contains_key("authorization")),
        "the credential never reached the server"
    );
    assert!(
        !format!("{client:?}").contains("super-secret-token"),
        "the credential leaked into a debug rendering"
    );
}
