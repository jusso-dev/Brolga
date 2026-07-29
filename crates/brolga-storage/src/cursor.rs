//! How far a connector got, kept beside the records it fetched.
//!
//! # Why this is storage's problem and not a connector's config file
//!
//! A cursor kept anywhere other than the database can disagree with the database. Advance it, fail
//! to store the page, and the records in that window are never fetched again — with **no error**,
//! because the next run simply starts after the gap. That failure is silent and permanent, and it
//! is the reason the cursor is written in the same transaction as the records
//! ([ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §4). A crash then costs a repeated page, which is idempotent.
//!
//! # Keyed on the feed, not the URL
//!
//! A server that moves to a new hostname is the same feed and must not restart from the beginning;
//! two collections on one server are different feeds and must not share a cursor. So the key is
//! `(connector, feed)` — the connector's name and its own identifier for the collection — and the
//! URL is not part of it.

use serde::{Deserialize, Serialize};

/// How a connector's last run ended.
///
/// Kept so an operator can tell "this feed has nothing new" from "this feed has been failing since
/// Tuesday" without reading a log. Those look identical from the cursor alone, and the second is
/// the one worth an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CursorStatus {
    /// The run completed and stored everything it fetched.
    Complete,
    /// The run stopped part way, and the cursor covers only what was stored.
    ///
    /// Not an error state: a budget or a cancellation produces this, and resuming from the cursor
    /// is correct. It is distinguished so that "partial" never silently reads as "up to date".
    Partial,
    /// The run failed. The cursor is where the last **successful** page left it.
    Failed,
    /// The server said nothing had changed.
    NotModified,
}

impl CursorStatus {
    /// The wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::NotModified => "not_modified",
        }
    }

    /// Read one back.
    ///
    /// Not `FromStr`: that trait's error type would have to be a public error for a value whose
    /// only failure mode is "not one of four words", and every caller here wants the `Option`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "complete" => Self::Complete,
            "partial" => Self::Partial,
            "failed" => Self::Failed,
            "not_modified" => Self::NotModified,
            _ => return None,
        })
    }
}

impl core::fmt::Display for CursorStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A connector's position in one feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConnectorCursor {
    /// Which connector, such as `taxii`.
    pub connector: String,
    /// That connector's own identifier for the feed, such as a TAXII collection id.
    pub feed: String,
    /// The high-water mark, as an RFC 3339 string.
    ///
    /// A string rather than a `Timestamp` because it is echoed back to the server verbatim in the
    /// next request. Re-rendering a parsed timestamp risks handing back a value that differs from
    /// what the server issued in precision or offset, and a server comparing them literally would
    /// then re-send or skip a boundary record.
    pub added_after: Option<String>,
    /// The entity tag of the last response, for a conditional next request.
    pub etag: Option<String>,
    /// A protocol-specific continuation token, where the protocol has one.
    pub next_token: Option<String>,
    /// When the last run happened, as an RFC 3339 string.
    pub last_run_at: String,
    /// How that run ended.
    pub last_status: CursorStatus,
    /// How many records the feed has produced in total.
    pub records_seen: u64,
}

impl ConnectorCursor {
    /// A cursor for a feed nothing has been fetched from yet.
    #[must_use]
    pub fn starting(connector: impl Into<String>, feed: impl Into<String>, now: &str) -> Self {
        Self {
            connector: connector.into(),
            feed: feed.into(),
            added_after: None,
            etag: None,
            next_token: None,
            last_run_at: now.to_owned(),
            last_status: CursorStatus::Complete,
            records_seen: 0,
        }
    }

    /// Whether a fetch from this cursor would start from the beginning of the feed.
    #[must_use]
    pub const fn is_initial(&self) -> bool {
        self.added_after.is_none() && self.next_token.is_none()
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

    #[test]
    fn a_fresh_cursor_starts_from_the_beginning() {
        let cursor = ConnectorCursor::starting("taxii", "collection-1", "2024-01-01T00:00:00Z");
        assert!(cursor.is_initial());
        assert_eq!(cursor.records_seen, 0);
    }

    /// "Nothing new" and "failing since Tuesday" look identical from the cursor alone, and the
    /// second is the one worth an alert.
    #[test]
    fn every_status_round_trips_through_its_wire_name() {
        for status in [
            CursorStatus::Complete,
            CursorStatus::Partial,
            CursorStatus::Failed,
            CursorStatus::NotModified,
        ] {
            assert_eq!(CursorStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(CursorStatus::parse("nonsense"), None);
    }

    /// Re-rendering a parsed timestamp risks handing the server back a value differing in precision
    /// or offset, and a server comparing literally would re-send or skip a boundary record.
    #[test]
    fn added_after_is_kept_as_the_server_wrote_it() {
        let mut cursor = ConnectorCursor::starting("taxii", "c", "2024-01-01T00:00:00Z");
        cursor.added_after = Some("2024-06-01T12:00:00.123456Z".to_owned());
        assert_eq!(
            cursor.added_after.as_deref(),
            Some("2024-06-01T12:00:00.123456Z"),
            "the subsecond precision the server issued survives"
        );
        assert!(!cursor.is_initial());
    }
}
