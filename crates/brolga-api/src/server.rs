//! Building the router and running the server.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;

use brolga_storage::store::StoreRead;

use crate::auth::bearer_token;
use crate::error::{ApiError, RequestId};
use crate::routes;
use crate::schema::API_PREFIX;
use crate::state::ApiState;

/// The header a request id is returned in.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Build the router.
///
/// Layer order matters and is the security-relevant part of this function. Reading outward from
/// the handler: the body limit and timeout apply first, then authentication, then the request id.
/// Authentication sits *outside* the routes so that an unauthenticated request is rejected before
/// any handler, including one added later by someone who did not read this comment.
pub fn router<S>(state: Arc<ApiState<S>>) -> Router
where
    S: StoreRead + Send + 'static,
{
    let config = state.config().clone();

    let api = Router::new()
        .route("/health", get(routes::health))
        .route("/openapi.json", get(routes::openapi))
        .route("/ready", get(routes::ready::<S>))
        .route("/stats", get(routes::stats::<S>))
        .route("/context", post(crate::context::context::<S>))
        .route("/entities", get(routes::search_entities::<S>))
        .route("/entities/{id}", get(routes::get_entity::<S>))
        .route(
            "/entities/{id}/neighbours",
            get(routes::entity_neighbours::<S>),
        )
        .with_state(Arc::clone(&state));

    Router::new()
        .nest(API_PREFIX, api)
        .fallback(routes::not_found)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authenticate::<S>,
        ))
        .layer(middleware::from_fn(attach_request_id))
        .layer(DefaultBodyLimit::max(config.max_body_bytes()))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            config.request_timeout(),
        ))
}

/// Reject a request that does not present the configured credential.
///
/// When no credential is configured the server is bound to loopback — [`ApiConfig::bind`] refuses
/// any other combination — so there is nothing to check.
///
/// `/health` is exempt. A liveness probe that needs a credential is one that reports the process
/// as dead whenever the token is rotated, and the response says nothing an unauthenticated caller
/// could not learn by observing that the port is open.
async fn authenticate<S>(
    axum::extract::State(state): axum::extract::State<Arc<ApiState<S>>>,
    request: axum::extract::Request,
    next: Next,
) -> Response
where
    S: Send + 'static,
{
    let Some(credential) = state.config().credential() else {
        return next.run(request).await;
    };

    if request.uri().path() == concat!("/api/v1", "/health") {
        return next.run(request).await;
    }

    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);

    let accepted = presented.is_some_and(|token| credential.matches(token));

    if accepted {
        return next.run(request).await;
    }

    // `WWW-Authenticate` is what makes a 401 a 401 rather than a 403 with the wrong number. It
    // carries no detail about why: a client learning "the token was the right length" is a client
    // learning something.
    let id = RequestId::generate();
    let body = ApiError::Unauthorized.with_request_id(&id);
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        Json(body),
    )
        .into_response()
}

/// Put a request id on every response, including ones produced by layers rather than handlers.
///
/// A timeout or a body-limit rejection is exactly when someone needs the id, and those never reach
/// a handler.
async fn attach_request_id(request: axum::extract::Request, next: Next) -> Response {
    let id = RequestId::generate();
    let mut response = next.run(request).await;

    if let Ok(value) = HeaderValue::from_str(id.as_str()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    response
}

/// Bind and serve until the process is asked to stop.
///
/// # Errors
///
/// Returns the underlying I/O error if the address cannot be bound or the server stops abnormally.
/// Binding is the common one, and it is usually either the port being taken or the address not
/// existing on this host.
pub async fn serve<S>(state: Arc<ApiState<S>>) -> std::io::Result<()>
where
    S: StoreRead + Send + 'static,
{
    let address = state.config().address();
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!(
        address = %address,
        authenticated = state.config().requires_authentication(),
        "brolga api listening"
    );

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

/// Resolve when the process is asked to stop.
///
/// Graceful rather than abrupt so an in-flight read finishes instead of the client seeing a reset
/// connection it will retry, which on a restart loop turns one restart into a thundering herd.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                // Losing SIGTERM handling means a slower shutdown, not a broken server.
                tracing::warn!(%error, "cannot listen for SIGTERM; ctrl-c still works");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }

    tracing::info!("shutting down");
}

/// How long a graceful shutdown is allowed to take before the process exits anyway.
///
/// Exported for callers that supervise the server; the server itself does not enforce it, because
/// deciding to abandon in-flight requests belongs to whoever owns the process.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);
