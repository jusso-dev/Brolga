//! What can go wrong retrieving intelligence from a remote server.
//!
//! # A refusal and a failure are different answers
//!
//! [`ConnectorError::Denied`] means Brolga's own policy stopped the request. [`Self::Transport`]
//! means the network or the server did. They are kept apart because the operator response is
//! different — the first is a configuration decision to revisit, the second is somebody else's
//! outage — and an error type that blurred them would send every diagnosis down the wrong path.
//!
//! # No error carries a credential
//!
//! Per [ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §6, a variant may name a URL and a status. None of them holds a header, a token, or a response
//! body. An error message is the thing most likely to reach a log file, a bug report, or a terminal
//! somebody screenshots.

use thiserror::Error;

/// A retrieval failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectorError {
    /// Brolga's own policy refused the request.
    #[error("refused to fetch `{url}`: {reason}")]
    Denied {
        /// The URL that was refused.
        url: String,
        /// Which rule refused it.
        reason: String,
    },

    /// The URL could not be read confidently enough to check it.
    #[error("`{url}` is not a URL Brolga can check: {reason}")]
    MalformedUrl {
        /// The URL.
        url: String,
        /// Why it could not be read.
        reason: String,
    },

    /// The network or the server failed.
    #[error("could not fetch `{url}`: {reason}")]
    Transport {
        /// The URL.
        url: String,
        /// What happened, as reported by the transport.
        reason: String,
    },

    /// The server answered, with a status that is not success.
    #[error("`{url}` answered {status}")]
    Status {
        /// The URL.
        url: String,
        /// The HTTP status.
        status: u16,
    },

    /// The body was over the limit.
    #[error("`{url}` answered with a body over the {limit}-byte limit")]
    ResponseTooLarge {
        /// The URL.
        url: String,
        /// The limit that was exceeded.
        limit: usize,
    },

    /// The server's answer was not the shape the protocol requires.
    ///
    /// Distinct from [`Self::Transport`]: the request succeeded and the server replied with
    /// something Brolga cannot act on, which is a fact about the server rather than the network.
    #[error("`{url}` answered with a body this protocol cannot read: {reason}")]
    MalformedResponse {
        /// The URL.
        url: String,
        /// What was wrong with it.
        reason: String,
    },

    /// The server would not agree a protocol version.
    #[error("`{url}` does not speak a TAXII version Brolga reads: {detail}")]
    VersionNotNegotiated {
        /// The URL.
        url: String,
        /// What the server offered, or what was missing.
        detail: String,
    },

    /// Storing what was fetched failed.
    ///
    /// Carried here rather than surfaced as a storage error, because the cursor and the records are
    /// written together and a caller has to know the fetch as a whole did not complete.
    #[error("could not store what `{url}` returned: {reason}")]
    Storage {
        /// The URL whose page was being stored.
        url: String,
        /// The storage failure.
        reason: String,
    },

    /// The operator cancelled the fetch.
    #[error("the fetch was cancelled")]
    Cancelled,
}

impl ConnectorError {
    /// Whether retrying could plausibly succeed.
    ///
    /// A policy refusal and a malformed response never become correct by being repeated, so
    /// retrying them turns an operator's mistake or a broken server into sustained traffic. A
    /// transport failure and a 5xx often do.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            Self::Status { status, .. } => *status >= 500 || *status == 429,
            Self::Denied { .. }
            | Self::MalformedUrl { .. }
            | Self::ResponseTooLarge { .. }
            | Self::MalformedResponse { .. }
            | Self::VersionNotNegotiated { .. }
            | Self::Storage { .. }
            | Self::Cancelled => false,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// Repeating a refusal never makes it correct, and doing so turns an operator's misconfigured
    /// URL into sustained traffic aimed at whatever it names.
    #[test]
    fn a_refusal_is_never_retried_and_an_outage_is() {
        let denied = ConnectorError::Denied {
            url: "https://x.example".to_owned(),
            reason: "loopback".to_owned(),
        };
        assert!(!denied.is_retryable());

        assert!(
            ConnectorError::Transport {
                url: "https://x.example".to_owned(),
                reason: "connection reset".to_owned(),
            }
            .is_retryable()
        );
        assert!(
            ConnectorError::Status {
                url: "https://x.example".to_owned(),
                status: 503,
            }
            .is_retryable()
        );
        assert!(
            ConnectorError::Status {
                url: "https://x.example".to_owned(),
                status: 429,
            }
            .is_retryable(),
            "rate limiting is the server asking for a later attempt, not a refusal"
        );
        assert!(
            !ConnectorError::Status {
                url: "https://x.example".to_owned(),
                status: 404,
            }
            .is_retryable()
        );
    }

    /// An error message is the thing most likely to reach a log file or a screenshot.
    #[test]
    fn no_error_rendering_can_carry_a_credential() {
        let errors = [
            ConnectorError::Denied {
                url: "https://x.example".to_owned(),
                reason: "loopback".to_owned(),
            },
            ConnectorError::Status {
                url: "https://x.example".to_owned(),
                status: 401,
            },
            ConnectorError::MalformedResponse {
                url: "https://x.example".to_owned(),
                reason: "no `collections` array".to_owned(),
            },
        ];

        for error in errors {
            let rendered = error.to_string();
            assert!(!rendered.to_lowercase().contains("bearer"), "{rendered}");
            assert!(
                !rendered.to_lowercase().contains("authorization"),
                "{rendered}"
            );
        }
    }
}
