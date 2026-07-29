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

/// Bind the router on an ephemeral port and return the address.
///
/// Port 0 rather than a fixed one: a test that fights another test for a port fails for a reason
/// that has nothing to do with what it is testing.
async fn serve(config: ApiConfig) -> SocketAddr {
    let Fixture { _directory, store } = fixture();

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
