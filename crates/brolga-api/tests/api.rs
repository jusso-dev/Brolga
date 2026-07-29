//! End-to-end tests against a bound server and a real store.
//!
//! The unit tests cover the pieces. These bind a socket and speak HTTP, because the properties
//! that matter here — that an unauthenticated request is refused *before* a handler runs, that a
//! request id reaches the client, that a limit is enforced by the server rather than by the
//! handler's good manners — are properties of the assembled stack and are not observable from
//! inside any one part of it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;

use brolga_api::{ApiConfig, ApiState, Credential, REQUEST_ID_HEADER, router};
use brolga_ingest::formats::misp;
use brolga_ingest::formats::stix as stix_format;
use brolga_ingest::{Document, IngestMode, ParserRegistry, Pipeline};
use brolga_model::provenance::{MediaType, SensitiveText, SourceOrigin};
use brolga_security::{CancellationToken, ResourceLimits};
use brolga_storage::sqlite::SqliteStore;
use brolga_storage::store::IntelligenceStore;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// A store with a couple of entities in it, and the temporary directory keeping it alive.
struct Fixture {
    _directory: tempfile::TempDir,
    store: SqliteStore,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("brolga.db");
    let mut store = SqliteStore::open(&path, 5_000).expect("the store must open");
    store.migrate().expect("migrations must apply");

    Fixture {
        _directory: directory,
        store,
    }
}

/// A MISP event carrying one attribute, so a lookup has something to find.
///
/// The address is written here in the spelling a feed publishes. The lookup asks for it in a
/// different one. That difference is the point.
const EVENT: &str = r#"{
  "Event": {
    "uuid": "33333333-3333-4333-8333-333333333333",
    "info": "C2 infrastructure",
    "date": "2024-01-01",
    "Attribute": [
      {
        "uuid": "44444444-4444-4444-8444-444444444444",
        "type": "ip-dst",
        "category": "Network activity",
        "value": "203.0.113.42",
        "to_ids": true,
        "timestamp": "1704067200"
      }
    ]
  }
}"#;

/// A STIX bundle publishing **the same address**, inside an `indicator` pattern rather than as an
/// attribute.
///
/// STIX carries observables in `indicator` objects, so a deployment fed by STIX answers every
/// context lookup from these or from nothing at all
/// ([#95](https://github.com/jusso-dev/Brolga/issues/95)).
const BUNDLE: &str = r#"{
  "type": "bundle",
  "id": "bundle--55555555-5555-4555-8555-555555555555",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--66666666-6666-4666-8666-666666666666",
      "created": "2024-01-01T00:00:00.000Z",
      "name": "C2 address",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '203.0.113.42']",
      "indicator_types": ["malicious-activity"],
      "valid_from": "2024-01-01T00:00:00.000Z"
    }
  ]
}"#;

/// Which feeds a served store has been fed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Feed {
    /// Nothing ingested.
    None,
    /// The MISP event.
    Misp,
    /// The STIX bundle.
    Stix,
    /// Both, publishing one address two ways.
    Both,
}

/// Ingest a document into a store the API will serve, through the parser named.
fn ingest_document(store: &mut SqliteStore, bytes: &[u8], file_name: &'static str, stix: bool) {
    let mut registry = ParserRegistry::new();
    if stix {
        registry.register(stix_format::StixParser::boxed());
    } else {
        registry.register(misp::MispParser::boxed());
    }
    let pipeline =
        Pipeline::new(registry, ResourceLimits::defaults()).in_mode(IngestMode::Permissive);

    let document = Document {
        bytes,
        // Deliberately vague: the bytes are the evidence and the file name is only a hint, so
        // detection decides the format rather than the label deciding it.
        media_type: MediaType::new("application/octet-stream").expect("a usable media type"),
        file_name: Some(file_name),
        origin: SourceOrigin::LocalFile {
            path: SensitiveText::new(file_name).expect("a usable path"),
        },
        // Fixed rather than `now`, so the ingest is byte-identical on every run.
        retrieved_at: brolga_model::Timestamp::parse_rfc3339("2024-01-01T00:00:00Z")
            .expect("a usable timestamp"),
    };

    let report = pipeline
        .ingest_batch(store, &[document], &CancellationToken::never_cancelled())
        .expect("the document must ingest");

    // A fixture that silently ingested nothing would make every test below pass by testing an
    // empty store — which is exactly how the STIX version of this fixture used to fail.
    assert!(
        report.accepted() > 0,
        "the fixture ingested nothing: {report:?}"
    );
}

/// Bind the router on an ephemeral port and return the address.
///
/// Port 0 rather than a fixed one: a test that fights another test for a port fails for a reason
/// that has nothing to do with what it is testing.
async fn serve(config: ApiConfig) -> SocketAddr {
    serve_store(config, Feed::None).await
}

/// The same, over a store the MISP event has been ingested into.
async fn serve_ingested(config: ApiConfig) -> SocketAddr {
    serve_store(config, Feed::Misp).await
}

async fn serve_store(config: ApiConfig, feed: Feed) -> SocketAddr {
    let Fixture {
        _directory,
        mut store,
    } = fixture();

    if matches!(feed, Feed::Misp | Feed::Both) {
        ingest_document(&mut store, EVENT.as_bytes(), "event.json", false);
    }
    if matches!(feed, Feed::Stix | Feed::Both) {
        ingest_document(&mut store, BUNDLE.as_bytes(), "bundle.json", true);
    }

    let state = Arc::new(ApiState::new(store, config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port");
    let address = listener.local_addr().expect("the bound address");

    tokio::spawn(async move {
        // The directory must outlive the server, or the database file is deleted underneath it.
        let _keep = _directory;
        let _ = axum::serve(listener, router(state)).await;
    });

    address
}

/// The smallest HTTP client that will do, so the tests do not add a dependency to state a fact
/// about headers.
async fn request(address: SocketAddr, path: &str, token: Option<&str>) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("the server must accept");

    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{authorization}\r\n"
    );

    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    (status, head.to_owned(), body.to_owned())
}

// -------------------------------------------------------------------------------------------------
// Binding
// -------------------------------------------------------------------------------------------------

/// The invariant the whole crate is arranged around, stated at the level someone deploying it
/// would hit it.
#[test]
fn a_reachable_address_cannot_be_served_without_a_token() {
    let address: SocketAddr = "0.0.0.0:8787".parse().unwrap();
    assert!(ApiConfig::bind(address, None).is_err());

    let credential = Credential::new(TOKEN).unwrap();
    assert!(ApiConfig::bind(address, Some(credential)).is_ok());
}

// -------------------------------------------------------------------------------------------------
// Authentication
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_authenticated_server_refuses_a_request_with_no_token() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    let (status, head, body) = request(address, "/api/v1/stats", None).await;
    assert_eq!(status, 401, "{head}");
    assert!(head.to_lowercase().contains("www-authenticate"), "{head}");
    assert!(body.contains("\"code\":\"unauthorized\""), "{body}");
}

#[tokio::test]
async fn an_authenticated_server_refuses_a_wrong_token() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    let (status, _, _) = request(
        address,
        "/api/v1/stats",
        Some("ffffffffffffffffffffffffffffffff"),
    )
    .await;
    assert_eq!(status, 401);
}

/// A prefix of the token must not authenticate. The comparison is constant time, but the length
/// check in front of it is what makes a prefix fail, and this is the test that would catch its
/// removal.
#[tokio::test]
async fn a_prefix_of_the_token_does_not_authenticate() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    let (status, _, _) = request(address, "/api/v1/stats", Some(&TOKEN[..16])).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn an_authenticated_server_serves_the_right_token() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    let (status, _, body) = request(address, "/api/v1/stats", Some(TOKEN)).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("brolga.api.v1/1.0"), "{body}");
}

/// Every route is behind the credential, not just the ones that existed when the middleware was
/// written. This is why authentication is layered outside the router rather than per-handler.
#[tokio::test]
async fn every_route_except_health_requires_the_token() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    for path in [
        "/api/v1/stats",
        "/api/v1/ready",
        "/api/v1/entities",
        "/api/v1/entities/entity:00000000-0000-0000-0000-000000000000",
        "/api/v1/entities/x/neighbours",
        "/nonsense",
    ] {
        let (status, _, _) = request(address, path, None).await;
        assert_eq!(status, 401, "{path} answered without a token");
    }

    // Liveness is exempt: a probe that fails when the token rotates reports a working process as
    // dead, and the response reveals nothing that having the port open does not.
    let (status, _, _) = request(address, "/api/v1/health", None).await;
    assert_eq!(status, 200);
}

/// A loopback server has no credential to check, so it does not check one.
#[tokio::test]
async fn a_loopback_server_serves_without_a_token() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/stats", None).await;
    assert_eq!(status, 200, "{body}");
}

// -------------------------------------------------------------------------------------------------
// Responses
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_a_request_id_header() {
    let address = serve(ApiConfig::loopback(0)).await;

    for path in ["/api/v1/health", "/api/v1/stats", "/nonsense"] {
        let (_, head, _) = request(address, path, None).await;
        assert!(
            head.to_lowercase().contains(REQUEST_ID_HEADER),
            "{path} returned no request id: {head}"
        );
    }
}

/// Two requests must not share an id, or the id correlates nothing.
#[tokio::test]
async fn request_ids_differ_between_requests() {
    let address = serve(ApiConfig::loopback(0)).await;

    let extract = |head: String| {
        head.lines()
            .find(|line| line.to_lowercase().starts_with(REQUEST_ID_HEADER))
            .map(|line| line.to_owned())
    };

    let (_, first, _) = request(address, "/api/v1/health", None).await;
    let (_, second, _) = request(address, "/api/v1/health", None).await;
    assert_ne!(extract(first), extract(second));
}

/// An unrouted path answers in the same envelope as everything else, so a client needs one parser.
#[tokio::test]
async fn an_unknown_route_answers_in_the_standard_error_envelope() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v2/entities", None).await;

    assert_eq!(status, 404);
    assert!(body.contains("\"code\":\"not_found\""), "{body}");
    assert!(body.contains("brolga.api.error/1.0"), "{body}");
    assert!(body.contains("request_id"), "{body}");
}

#[tokio::test]
async fn every_successful_body_carries_the_response_schema() {
    let address = serve(ApiConfig::loopback(0)).await;

    for path in ["/api/v1/stats", "/api/v1/entities"] {
        let (status, _, body) = request(address, path, None).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert!(
            body.contains("brolga.api.v1/1.0"),
            "{path} carried no schema: {body}"
        );
    }
}

/// Liveness must not touch the store. A probe that fails because a query is slow causes an
/// orchestrator to restart a process that was working.
#[tokio::test]
async fn health_answers_without_reading_the_store() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/health", None).await;

    assert_eq!(status, 200);
    assert!(body.contains("\"status\":\"ok\""), "{body}");
}

/// Readiness does touch it — that is the difference between the two probes.
#[tokio::test]
async fn ready_reports_the_schema_version() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/ready", None).await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("schema_version"), "{body}");
}

// -------------------------------------------------------------------------------------------------
// Input handling
// -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_filter_value_is_a_bad_request_that_lists_the_alternatives() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/entities?kind=wombat", None).await;

    assert_eq!(status, 400, "{body}");
    assert!(body.contains("\"code\":\"bad_request\""), "{body}");
    assert!(body.contains("intrusion_set"), "{body}");
}

#[tokio::test]
async fn a_malformed_id_is_a_bad_request_rather_than_a_not_found() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/entities/not-an-id", None).await;

    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn a_well_formed_but_absent_id_is_a_not_found() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(
        address,
        "/api/v1/entities/entity:00000000-0000-0000-0000-000000000000",
        None,
    )
    .await;

    assert_eq!(status, 404, "{body}");
}

/// An ordinary page size must work. This is the regression guard for `#[serde(flatten)]`, which
/// routes every query value through serde as a string and made `?limit=10` a 400 on every route
/// that used it — including the ones a consumer reaches for first.
#[tokio::test]
async fn an_ordinary_page_size_is_accepted() {
    let address = serve(ApiConfig::loopback(0)).await;

    for query in [
        "?limit=10",
        "?offset=5",
        "?limit=10&offset=5",
        "?kind=intrusion_set&limit=10",
        "?current=true&limit=10",
    ] {
        let (status, _, body) = request(address, &format!("/api/v1/entities{query}"), None).await;
        assert_eq!(status, 200, "{query} was refused: {body}");
    }
}

/// An enormous limit is clamped rather than refused, so "give me everything" pages instead of
/// failing.
#[tokio::test]
async fn an_oversized_page_is_clamped_rather_than_refused() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/entities?limit=999999999", None).await;

    assert_eq!(status, 200, "{body}");
}

/// An empty store answers with an empty list and no cursor, not an error. A consumer starting up
/// against a Brolga that has ingested nothing yet should see "nothing known", not a failure.
#[tokio::test]
async fn an_empty_store_answers_with_an_empty_collection() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, _, body) = request(address, "/api/v1/entities", None).await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"data\":[]"), "{body}");
    assert!(
        !body.contains("next_offset"),
        "no cursor past the end: {body}"
    );
}

// -------------------------------------------------------------------------------------------------
// Context packs
// -------------------------------------------------------------------------------------------------

/// POST with a JSON body, for the context route.
async fn post(address: SocketAddr, path: &str, body: &str) -> (u16, String) {
    post_with_token(address, path, body, None).await
}

/// The same, carrying a bearer token.
async fn post_with_token(
    address: SocketAddr,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("the server must accept");

    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{authorization}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );

    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    (status, body.to_owned())
}

/// An observable Brolga has never heard of is `unknown` — never `benign`.
///
/// The distinction a consumer acts on. Reading "Brolga has not heard of this" as "Brolga says this
/// is fine" is the expensive direction of the mistake, because it closes an alert that should have
/// been raised.
#[tokio::test]
async fn an_unknown_observable_is_unknown_rather_than_benign() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.99"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"disposition\":\"unknown\""), "{body}");
    assert!(!body.contains("benign"), "{body}");
}

/// The pack carries the schema id consumers were built against. Kelpie's client checks it.
#[tokio::test]
async fn the_pack_carries_the_agreed_schema_id() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"domain","value":"example.com"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("\"schema_version\":\"brolga.context_pack/1.1\""),
        "{body}"
    );
}

/// Absence is stated, not implied. A consumer should not have to infer "Brolga knows nothing" from
/// an empty array that might equally mean "the field was omitted".
#[tokio::test]
async fn a_pack_about_nothing_says_so_in_gaps() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"198.51.100.7"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("nothing is stored about this observable"),
        "{body}"
    );
}

/// The pack echoes the *canonical* subject, which may differ from what was sent. A consumer that
/// caches by the value it sent would otherwise keep two cache entries for one observable.
#[tokio::test]
async fn the_pack_reports_the_canonical_subject_not_the_one_sent() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"domain","value":"  EXAMPLE.COM  "}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"value\":\"example.com\""), "{body}");
}

/// Two spellings of one observable must produce the same `observable_id`, because that id is what
/// the stored edges point at. If this fails, lookups silently miss data Brolga holds.
#[tokio::test]
async fn equivalent_spellings_resolve_to_one_observable() {
    let address = serve(ApiConfig::loopback(0)).await;

    let extract_id = |body: &str| {
        body.split("\"observable_id\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .map(str::to_owned)
    };

    let (_, plain) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"1.1.1.1"}}"#,
    )
    .await;
    let (_, padded) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ipv4","value":"  1.1.1.1  "}}"#,
    )
    .await;

    assert_eq!(extract_id(&plain), extract_id(&padded));
    assert!(extract_id(&plain).is_some(), "{plain}");
}

#[tokio::test]
async fn a_malformed_subject_is_a_bad_request() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"not-an-address"}}"#,
    )
    .await;

    assert_eq!(status, 400, "{body}");
    assert!(body.contains("\"code\":\"bad_request\""), "{body}");
}

/// The value came from outside. It must not be reflected back through a diagnostic.
#[tokio::test]
async fn a_hostile_subject_value_is_not_echoed_in_the_error() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"<script>alert(1)</script>"}}"#,
    )
    .await;

    assert_eq!(status, 400, "{body}");
    assert!(
        !body.contains("script"),
        "the value was echoed back: {body}"
    );
}

/// A detail level Brolga cannot serve is acknowledged rather than silently downgraded. Telling a
/// consumer it received L5 when it received L1 makes it stop looking for depth it never got.
#[tokio::test]
async fn an_unsupported_detail_level_is_reported_rather_than_pretended() {
    let address = serve(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"1.1.1.1"},"detail_level":"L5"}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"detail_level\":\"L1\""), "{body}");
    assert!(
        body.contains("progressive disclosure is not implemented"),
        "{body}"
    );
}

/// The context route is behind the credential like every other route.
#[tokio::test]
async fn the_context_route_requires_the_token() {
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();
    let address = serve(config).await;

    let (status, _) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"1.1.1.1"}}"#,
    )
    .await;
    assert_eq!(status, 401);
}

/// **The test this whole endpoint turns on.**
///
/// The bundle publishes `203.0.113.42` inside a STIX pattern. The lookup asks about the same
/// address in a different spelling and with a different `kind`. If ingest and lookup disagree
/// about canonicalisation by even one character, the derived observable id differs, and Brolga
/// answers "unknown" about something it holds an indicator for.
///
/// That failure is invisible: an empty pack is exactly what a genuinely unknown address returns.
/// Nothing else in the suite would catch it.
#[tokio::test]
async fn a_lookup_finds_what_ingest_stored() {
    let address = serve_ingested(ApiConfig::loopback(0)).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"  203.0.113.42  "}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("nothing is stored about this observable"),
        "ingest and lookup disagree about canonicalisation: {body}"
    );
    assert!(
        body.contains("\"claims\":[{") || body.contains("\"relationships\":[{"),
        "the ingested indicator was not reachable from the lookup: {body}"
    );
}

/// Having found it, the pack must attribute it. A claim a case cannot trace back to a source is
/// one an analyst cannot defend, and enrichment that cannot be defended is worse than none.
#[tokio::test]
async fn a_found_observable_carries_the_evidence_it_came_from() {
    let address = serve_ingested(ApiConfig::loopback(0)).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.42"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("source_object_id"),
        "no evidence in the pack: {body}"
    );
}

/// An address the bundle does not mention stays unknown even when the store is populated. Without
/// this, a lookup that returned everything for every subject would pass the test above.
#[tokio::test]
async fn a_populated_store_still_reports_unknown_for_an_unrelated_address() {
    let address = serve_ingested(ApiConfig::loopback(0)).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"192.0.2.200"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"disposition\":\"unknown\""), "{body}");
    assert!(
        body.contains("nothing is stored about this observable"),
        "{body}"
    );
}

/// **The STIX half of the test above**, and the reason
/// [#95](https://github.com/jusso-dev/Brolga/issues/95) existed. `indicator` is where STIX carries
/// observables, so while it was quarantined a STIX-fed Brolga answered `unknown` for every context
/// lookup — and an empty pack is indistinguishable from a genuinely unknown address, so nobody
/// pointing Kelpie or Tawny at it would have seen the misses.
#[tokio::test]
async fn a_lookup_finds_what_a_stix_indicator_stored() {
    let address = serve_store(ApiConfig::loopback(0), Feed::Stix).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"  203.0.113.42  "}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("nothing is stored about this observable"),
        "the STIX indicator was not reachable from the lookup: {body}"
    );
    assert!(body.contains("\"claims\":[{"), "{body}");
}

/// `indicator_types` is the only field of an indicator that states an assessment, and it must reach
/// the disposition a consumer acts on. Recording the pattern without the assessment would answer
/// `unknown` about an address a publisher called malicious.
#[tokio::test]
async fn a_stix_indicators_type_reaches_the_packs_disposition() {
    let address = serve_store(ApiConfig::loopback(0), Feed::Stix).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.42"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"disposition\":\"malicious\""), "{body}");
}

/// **The criterion that keeps a mixed deployment from double-counting.** The MISP attribute and the
/// STIX pattern name one address. If the two paths canonicalised differently they would derive two
/// observable identifiers, the address would sit in the graph twice, and one lookup would find half
/// of what Brolga holds — while still looking like a successful answer.
#[tokio::test]
async fn the_misp_and_stix_paths_land_on_one_observable_for_one_address() {
    let address = serve_store(ApiConfig::loopback(0), Feed::Both).await;

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.42"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("misp.ip-dst"),
        "the MISP attribute is missing from the pack: {body}"
    );
    assert!(
        body.contains("stix.indicator.pattern"),
        "the STIX indicator is missing from the pack, so the two paths derived two \
         observables: {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// "Restricted material cannot enter unauthorised pack or expansion" — #37
// ---------------------------------------------------------------------------------------------

/// A MISP event whose attribute carries TLP:RED, so a pack has something it must withhold.
const RED_EVENT: &str = r#"{
  "Event": {
    "uuid": "77777777-7777-4777-8777-777777777777",
    "info": "Restricted C2 infrastructure",
    "Tag": [{"name": "tlp:red"}],
    "Attribute": [
      {
        "uuid": "88888888-8888-4888-8888-888888888888",
        "type": "ip-dst",
        "value": "203.0.113.99",
        "to_ids": true
      }
    ]
  }
}"#;

/// **The criterion.** A caller who has identified nothing must not receive TLP:RED material, and
/// must be told that something was withheld rather than served a pack that reads as complete.
#[tokio::test]
async fn restricted_material_does_not_reach_an_unauthorised_caller() {
    let Fixture {
        _directory,
        mut store,
    } = fixture();
    ingest_document(&mut store, RED_EVENT.as_bytes(), "red.json", false);

    // Bound off-host with a credential, so the identity is `anonymous` rather than a local
    // operator. That is the path a network consumer takes.
    let credential = Credential::new(TOKEN).unwrap();
    let config = ApiConfig::bind("0.0.0.0:0".parse().unwrap(), Some(credential)).unwrap();

    let state = Arc::new(ApiState::new(store, config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _keep = _directory;
        let _ = axum::serve(listener, router(state)).await;
    });

    let (status, body) = post_with_token(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.99"}}"#,
        Some(TOKEN),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("misp.ip-dst"),
        "TLP:RED material reached an unidentified caller: {body}"
    );
    assert!(
        body.contains("\"restricted\":true"),
        "the pack must say something was withheld: {body}"
    );
    assert!(
        body.contains("policy_restricted"),
        "and must say why, in a form a consumer can branch on: {body}"
    );
}

/// The same store, served to a local operator, does contain it. Without this the test above would
/// pass just as well if the pack were empty for an unrelated reason.
#[tokio::test]
async fn the_same_material_reaches_a_local_operator() {
    let Fixture {
        _directory,
        mut store,
    } = fixture();
    ingest_document(&mut store, RED_EVENT.as_bytes(), "red.json", false);

    let state = Arc::new(ApiState::new(store, ApiConfig::loopback(0)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _keep = _directory;
        let _ = axum::serve(listener, router(state)).await;
    });

    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.99"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("misp.ip-dst"),
        "a local operator must still see their own data: {body}"
    );
    assert!(body.contains("\"restricted\":false"), "{body}");
}

/// Every pack records the policy context it was produced under, whether or not anything was
/// withheld. A pack that only mentioned policy when it bit would leave a consumer unable to tell
/// "nothing was restricted" from "policy did not run".
#[tokio::test]
async fn every_pack_records_its_policy_context() {
    let address = serve_ingested(ApiConfig::loopback(0)).await;
    let (status, body) = post(
        address,
        "/api/v1/context",
        r#"{"subject":{"kind":"ip","value":"203.0.113.42"}}"#,
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"policy\":{"), "{body}");
    assert!(body.contains("\"recipient\":"), "{body}");
    assert!(body.contains("\"markings\":"), "{body}");
    assert!(body.contains("\"restricted\":"), "{body}");
}
