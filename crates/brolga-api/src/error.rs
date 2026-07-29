//! The one shape every failure takes.
//!
//! A client that has to distinguish "not found" from "you are not allowed to know" by reading
//! prose will get it wrong. Every failure here is a stable machine-readable code plus a request id
//! that appears in both the response and the server's logs.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::schema::ERROR_SCHEMA;

/// A request id, generated per request and echoed back.
///
/// The point is a support conversation that consists of one identifier rather than a description
/// of what someone was doing at the time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// Generate a fresh identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// The identifier as it appears in the response.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::generate()
    }
}

/// Everything that can go wrong answering a request.
///
/// The variants are the API's taxonomy, not the storage layer's. A storage error that would reveal
/// a filesystem path or a SQL fragment maps to [`ApiError::Internal`] and the detail stays in the
/// server log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// A parameter was missing, malformed, or out of range.
    #[error("{message}")]
    BadRequest {
        /// What was wrong, in terms of the request rather than the implementation.
        message: String,
    },

    /// No credential was presented, or the one presented did not match.
    #[error("authentication required")]
    Unauthorized,

    /// The thing asked for does not exist.
    #[error("{kind} {id} was not found")]
    NotFound {
        /// The kind of record.
        kind: &'static str,
        /// The identifier that was not found.
        id: String,
    },

    /// The request body exceeded the configured limit.
    #[error("request body exceeds the {limit} byte limit")]
    PayloadTooLarge {
        /// The configured limit.
        limit: usize,
    },

    /// The request ran past its deadline.
    #[error("request exceeded its deadline")]
    Timeout,

    /// Something failed that the client cannot act on.
    #[error("internal error")]
    Internal,
}

impl ApiError {
    /// The HTTP status this maps to.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The stable code a client should branch on.
    ///
    /// This is a compatibility surface under ADR 0001 §6. A code never changes meaning; a new
    /// condition gets a new code. Clients that match on the message instead have been warned.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { .. } => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::NotFound { .. } => "not_found",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
        }
    }

    /// Attach a request id, producing the response body.
    #[must_use]
    pub fn with_request_id(self, request_id: &RequestId) -> ErrorBody {
        ErrorBody {
            schema: ERROR_SCHEMA,
            error: ErrorDetail {
                code: self.code(),
                message: self.to_string(),
            },
            request_id: request_id.as_str().to_owned(),
        }
    }
}

/// The body of every failed response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// The version of this envelope.
    pub schema: &'static str,
    /// The failure.
    pub error: ErrorDetail,
    /// The id that correlates this response with the server's logs.
    pub request_id: String,
}

/// The failure itself.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    /// The stable code to branch on.
    pub code: &'static str,
    /// A human-readable description. Not stable; do not parse it.
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Reached only where a handler returned an error without the middleware's id in scope. The
        // id is still generated rather than omitted, so the field is never absent.
        let status = self.status();
        let body = self.with_request_id(&RequestId::generate());
        (status, Json(body)).into_response()
    }
}

/// Map a read failure onto the API's taxonomy.
///
/// Everything becomes [`ApiError::Internal`]. Storage errors name files, SQL fragments, and
/// migration state; a client that cannot act on any of it does not need to be told, and a error
/// message is a fine place to leak a path from. The detail is logged against the request id
/// instead, which is what the id is for.
#[must_use]
pub fn from_read_failure(error: &crate::state::ReadFailed, request_id: &RequestId) -> ApiError {
    tracing::error!(
        request_id = request_id.as_str(),
        error = %error,
        "read failed while serving a request"
    );
    ApiError::Internal
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn each_error_has_its_conventional_status() {
        assert_eq!(
            ApiError::BadRequest {
                message: "no".into()
            }
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ApiError::NotFound {
                kind: "entity",
                id: "x".into()
            }
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::PayloadTooLarge { limit: 1 }.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(ApiError::Timeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            ApiError::Internal.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// The codes are a compatibility surface. This test is the thing that has to be edited,
    /// deliberately, for one to change.
    #[test]
    fn the_codes_are_the_ones_clients_were_told_about() {
        assert_eq!(ApiError::Unauthorized.code(), "unauthorized");
        assert_eq!(ApiError::Timeout.code(), "timeout");
        assert_eq!(ApiError::Internal.code(), "internal");
        assert_eq!(
            ApiError::NotFound {
                kind: "entity",
                id: "x".into()
            }
            .code(),
            "not_found"
        );
    }

    #[test]
    fn every_error_body_carries_the_request_id_and_a_schema() {
        let id = RequestId::generate();
        let body = ApiError::Unauthorized.with_request_id(&id);
        assert_eq!(body.request_id, id.as_str());
        assert_eq!(body.schema, ERROR_SCHEMA);
    }

    /// An unauthenticated caller must not learn anything from the message beyond "authenticate".
    #[test]
    fn the_unauthorized_message_describes_nothing_but_itself() {
        let message = ApiError::Unauthorized.to_string();
        assert_eq!(message, "authentication required");
    }

    #[test]
    fn request_ids_differ() {
        assert_ne!(RequestId::generate(), RequestId::generate());
    }
}
