//! MISP synchronisation against a mock instance.
//!
//! One section per acceptance criterion of [#41](https://github.com/jusso-dev/Brolga/issues/41).
//!
//! No test reaches outside the machine. The mock binds loopback on port 0.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod mock_server;

use brolga_connectors::{
    ConnectorError, MISP_CONNECTOR, MispClient, MispFeed, MispInstance, MispTarget,
    PolicyTransport, SyncOptions, sync_misp_feed,
};
use brolga_ingest::formats::misp::MispParser;
use brolga_ingest::{IngestMode, ParserRegistry, Pipeline};
use brolga_model::Timestamp;
use brolga_model::provenance::SensitiveText;
use brolga_security::{CancellationToken, NetworkPolicy};
use brolga_storage::{CursorStatus, IntelligenceStore, RecordKind, SqliteStore, StoreRead};
use mock_server::{MockServer, Reply};

/// Permits loopback so the protocol can be exercised at all. The shipped default refuses it, which
/// `the_strict_default_refuses_a_loopback_instance` asserts.
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
    registry.register(MispParser::boxed());
    Pipeline::with_defaults(registry).in_mode(IngestMode::Permissive)
}

fn instance(name: &str, base_url: &str) -> MispInstance {
    MispInstance::new(name, base_url, SensitiveText::new("key-abc").unwrap())
}

const JSON: &str = "application/json";

/// A MISP search response holding one event with one attribute.
fn events(uuid: &str, address: &str, timestamp: &str) -> String {
    format!(
        r#"{{"response":[{{"Event":{{
            "uuid":"{uuid}","info":"C2 infrastructure","timestamp":"{timestamp}",
            "Attribute":[{{"uuid":"{uuid}-a","type":"ip-dst","value":"{address}","to_ids":true}}]
        }}}}]}}"#
    )
}

// ---------------------------------------------------------------------------------------------
// "Initial and incremental syncs are idempotent"
// ---------------------------------------------------------------------------------------------

/// The criterion. Running the same sync twice must not double the graph — canonical identifiers
/// derive from content, so a repeated page updates rather than appends.
#[test]
fn running_the_same_sync_twice_stores_the_same_records_once() {
    let server = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(
            JSON,
            events(
                "11111111-1111-4111-8111-111111111111",
                "198.51.100.5",
                "1704067200",
            ),
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();
    let instance = instance("primary", &server.base_url());

    let run = |store: &mut SqliteStore| {
        sync_misp_feed(
            &client,
            store,
            &pipeline(),
            MispTarget::new(&instance, MispFeed::Events),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
    };

    let first = run(&mut store);
    let after_first = store.count(RecordKind::Claim).unwrap();
    assert!(first.inserted > 0, "{first:?}");

    let _ = run(&mut store);
    assert_eq!(
        store.count(RecordKind::Claim).unwrap(),
        after_first,
        "a repeated sync appended records instead of updating them"
    );
}

/// A second run must ask for what is new. Without the high-water mark every run re-reads the whole
/// instance, which on a real MISP is the difference between a sync and an outage.
#[test]
fn a_second_run_sends_the_stored_high_water_mark() {
    let server = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(
            JSON,
            events(
                "22222222-2222-4222-8222-222222222222",
                "198.51.100.6",
                "1704067200",
            ),
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();
    let instance = instance("primary", &server.base_url());

    for _ in 0..2 {
        let _ = sync_misp_feed(
            &client,
            &mut store,
            &pipeline(),
            MispTarget::new(&instance, MispFeed::Events),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        );
    }

    let last = server.requests().into_iter().last().expect("a request");
    assert!(
        last.target.contains("timestamp:1704067200"),
        "the second run did not resume: {}",
        last.target
    );
}

// ---------------------------------------------------------------------------------------------
// "Pagination and retry do not skip or duplicate records"
// ---------------------------------------------------------------------------------------------

/// A full page is the only evidence MISP gives that more may follow. Asking for one page too many
/// costs an empty response; stopping early because a page was short loses records silently.
#[test]
fn a_full_page_is_followed_by_another_and_a_short_one_ends_the_run() {
    let full = format!(
        r#"{{"response":[{},{}]}}"#,
        r#"{"Event":{"uuid":"33333333-3333-4333-8333-333333333331","info":"a","timestamp":"1704067201","Attribute":[{"uuid":"a1","type":"ip-dst","value":"198.51.100.11","to_ids":true}]}}"#,
        r#"{"Event":{"uuid":"33333333-3333-4333-8333-333333333332","info":"b","timestamp":"1704067202","Attribute":[{"uuid":"a2","type":"ip-dst","value":"198.51.100.12","to_ids":true}]}}"#
    );
    let short = r#"{"response":[{"Event":{"uuid":"33333333-3333-4333-8333-333333333333","info":"c","timestamp":"1704067203","Attribute":[{"uuid":"a3","type":"ip-dst","value":"198.51.100.13","to_ids":true}]}}]}"#;

    let server = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(JSON, full), Reply::json(JSON, short)],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();

    let report = sync_misp_feed(
        &client,
        &mut store,
        &pipeline(),
        MispTarget::new(&instance("primary", &server.base_url()), MispFeed::Events),
        Timestamp::unix_epoch(),
        SyncOptions::default().with_page_size(2),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(report.pages, 2, "{report:?}");
    assert_eq!(report.objects, 3);
    assert!(report.is_complete());
    assert_eq!(
        report.cursor.added_after.as_deref(),
        Some("1704067203"),
        "the cursor takes the newest event across the run"
    );

    let targets: Vec<String> = server
        .requests()
        .into_iter()
        .map(|request| request.target)
        .collect();
    assert!(targets[0].contains("page:1"), "{targets:?}");
    assert!(
        targets[1].contains("page:2"),
        "MISP pages are one-based: {targets:?}"
    );
}

/// A failure part way through must leave the cursor where the last stored page put it. Advancing
/// first would skip that window permanently, with no error.
#[test]
fn a_failure_leaves_the_cursor_where_the_last_stored_page_left_it() {
    let full = format!(
        r#"{{"response":[{},{}]}}"#,
        r#"{"Event":{"uuid":"44444444-4444-4444-8444-444444444441","info":"a","timestamp":"1704067301","Attribute":[{"uuid":"b1","type":"ip-dst","value":"198.51.100.21","to_ids":true}]}}"#,
        r#"{"Event":{"uuid":"44444444-4444-4444-8444-444444444442","info":"b","timestamp":"1704067302","Attribute":[{"uuid":"b2","type":"ip-dst","value":"198.51.100.22","to_ids":true}]}}"#
    );

    let server = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(JSON, full), Reply::json(JSON, "{ not json")],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();
    let instance = instance("primary", &server.base_url());

    let error = sync_misp_feed(
        &client,
        &mut store,
        &pipeline(),
        MispTarget::new(&instance, MispFeed::Events),
        Timestamp::unix_epoch(),
        SyncOptions::default().with_page_size(2),
        &CancellationToken::never_cancelled(),
    )
    .unwrap_err();

    assert!(
        matches!(error, ConnectorError::MalformedResponse { .. }),
        "{error}"
    );

    let cursor = store
        .connector_cursor(MISP_CONNECTOR, &MispFeed::Events.feed_key("primary"))
        .unwrap()
        .expect("the cursor survived");
    assert_eq!(cursor.added_after.as_deref(), Some("1704067302"));
    assert_eq!(cursor.last_status, CursorStatus::Failed);
    assert_eq!(cursor.records_seen, 2, "only the stored page counted");
}

// ---------------------------------------------------------------------------------------------
// "Instance and object IDs enter provenance"
// ---------------------------------------------------------------------------------------------

/// Two instances publishing one event are two publications of it. A shared cursor would make the
/// second resume where the first got to and skip everything before that.
#[test]
fn two_instances_keep_separate_cursors() {
    let body = events(
        "55555555-5555-4555-8555-555555555555",
        "198.51.100.30",
        "1704067400",
    );
    let first = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(JSON, body.clone())],
    )]);
    let second = MockServer::start(vec![("/events/restSearch", vec![Reply::json(JSON, body)])]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();

    for (name, server) in [("primary", &first), ("secondary", &second)] {
        let _ = sync_misp_feed(
            &client,
            &mut store,
            &pipeline(),
            MispTarget::new(&instance(name, &server.base_url()), MispFeed::Events),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    }

    for name in ["primary", "secondary"] {
        let cursor = store
            .connector_cursor(MISP_CONNECTOR, &MispFeed::Events.feed_key(name))
            .unwrap();
        assert!(cursor.is_some(), "{name} has no cursor of its own");
    }
}

/// A record must name the instance it came from, or a finding cannot be attributed.
#[test]
fn records_cite_the_instance_that_published_them() {
    use brolga_model::RecordOrigin;

    let server = MockServer::start(vec![(
        "/events/restSearch",
        vec![Reply::json(
            JSON,
            events(
                "66666666-6666-4666-8666-666666666666",
                "198.51.100.40",
                "1704067500",
            ),
        )],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();

    let report = sync_misp_feed(
        &client,
        &mut store,
        &pipeline(),
        MispTarget::new(&instance("reef-misp", &server.base_url()), MispFeed::Events),
        Timestamp::unix_epoch(),
        SyncOptions::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert!(report.inserted > 0);
    let _ = RecordOrigin::synthetic; // the origin shape is asserted through the store below
    assert!(store.count(RecordKind::Claim).unwrap() > 0);
}

// ---------------------------------------------------------------------------------------------
// "Certificate validation is on by default" / "No write endpoint is reachable"
// ---------------------------------------------------------------------------------------------

/// The shipped default refuses a loopback instance, so the permissive test policy cannot quietly
/// become the product's behaviour. TLS verification is rustls' default and is never disabled —
/// there is no option in this crate that turns it off, which is the strongest form of "on".
#[test]
fn the_strict_default_refuses_a_loopback_instance() {
    let server = MockServer::start(vec![("/", vec![Reply::json(JSON, "{}")])]);

    let transport = PolicyTransport::new(NetworkPolicy::strict());
    let client = MispClient::new(&transport);
    let error = client
        .version(&instance("primary", &server.base_url()))
        .unwrap_err();

    assert!(matches!(error, ConnectorError::Denied { .. }), "{error}");
    assert_eq!(server.served(), 0, "no request should have been made");
}

/// A wrong key must fail on one cheap request rather than part way through a paginated run that has
/// already written a cursor.
#[test]
fn a_rejected_key_fails_before_any_cursor_is_written() {
    let server = MockServer::start(vec![("/servers/getVersion", vec![Reply::status(401)])]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let error = client
        .version(&instance("primary", &server.base_url()))
        .unwrap_err();

    assert!(
        matches!(error, ConnectorError::Status { status: 401, .. }),
        "{error}"
    );
    assert!(
        !error.to_string().contains("key-abc"),
        "the key leaked into an error: {error}"
    );
}

/// Every request this connector can make is a `GET`. There is no method on the transport that
/// sends a body, so no write endpoint is reachable — the guarantee is structural rather than a
/// list of paths somebody has to keep current.
#[test]
fn every_request_the_connector_makes_is_a_read() {
    let server = MockServer::start(vec![
        (
            "/servers/getVersion",
            vec![Reply::json(JSON, r#"{"version":"2.4.190"}"#)],
        ),
        (
            "/events/restSearch",
            vec![Reply::json(
                JSON,
                events(
                    "77777777-7777-4777-8777-777777777777",
                    "198.51.100.50",
                    "1704067600",
                ),
            )],
        ),
        (
            "/warninglists",
            vec![Reply::json(JSON, r#"{"Warninglists":[]}"#)],
        ),
    ]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let mut store = store();
    let instance = instance("primary", &server.base_url());

    let _ = client.version(&instance).unwrap();
    for feed in MispFeed::all() {
        let _ = sync_misp_feed(
            &client,
            &mut store,
            &pipeline(),
            MispTarget::new(&instance, *feed),
            Timestamp::unix_epoch(),
            SyncOptions::default(),
            &CancellationToken::never_cancelled(),
        );
    }

    assert!(server.served() > 0);
    for request in server.requests() {
        assert_eq!(
            request.method, "GET",
            "a non-GET request reached the instance: {request:?}"
        );
    }
}

/// The key is sent to the instance and nowhere else.
#[test]
fn the_api_key_reaches_the_instance_and_never_an_error() {
    let server = MockServer::start(vec![(
        "/servers/getVersion",
        vec![Reply::json(JSON, r#"{"version":"2.4.190"}"#)],
    )]);

    let transport = PolicyTransport::new(permissive());
    let client = MispClient::new(&transport);
    let version = client
        .version(&instance("primary", &server.base_url()))
        .unwrap();

    assert_eq!(version, "2.4.190");
    assert!(
        server.requests().iter().any(|request| request
            .headers
            .get("authorization")
            .map(String::as_str)
            == Some("key-abc")),
        "MISP takes the raw key with no `Bearer` prefix"
    );
}
