//! Read-only synchronisation from one or more MISP instances.
//!
//! # Why this uses `GET` when MISP's own documentation says `POST`
//!
//! MISP's `restSearch` is normally a `POST` carrying a JSON filter body. [`Transport`] has no
//! method that sends a body, and that is not an oversight —
//! [ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §5 makes read-only *structural* rather than a default somebody can flip.
//!
//! MISP has supported the same filters as URL path parameters for a long time —
//! `/events/restSearch/returnFormat:json/limit:100/page:1/timestamp:1704067200` — and that form
//! does everything this connector needs. So the constraint is kept and the connector is written
//! against the `GET` form.
//!
//! The cost is real and worth stating: a filter set large enough to overflow a practical URL cannot
//! be expressed this way. Brolga's filters are a page size, a page number, and a high-water mark, so
//! it does not come close — but a future filter that needs hundreds of values would have to either
//! page differently or reopen ADR 0005 §5, and reopening it should be a decision rather than a
//! method quietly appearing on the transport.
//!
//! # An instance is a source, and instances do not merge
//!
//! Two MISP instances publishing the same event are two publications of it. Each instance gets its
//! own cursor, its own provenance, and its own name in every record it produced — because "three
//! sources agree" and "one source polled three times" are different facts, and a connector that
//! blurred them would manufacture corroboration.
//!
//! # What is synchronised, and what is deliberately not
//!
//! **Events** — which carry their attributes, tags, and galaxy clusters inline — and **warning
//! lists**. Both are shapes [`brolga_ingest::formats::misp`] actually maps.
//!
//! Sightings, taxonomies, and object templates are **not** fetched. Not because they are
//! uninteresting, but because the parser has no mapping for them: fetching them would spend an
//! operator's rate limit to produce records that quarantine. The project's rule is not to claim
//! support for a format without fixtures and tests, and that applies to an endpoint as much as to a
//! file.

use brolga_model::provenance::SensitiveText;
use serde_json::Value;

use crate::error::ConnectorError;
use crate::transport::{Request, Response, Transport};

/// This connector's name, and the first half of every cursor key it writes.
pub const MISP_CONNECTOR: &str = "misp";

/// The media type MISP answers with.
pub const MISP_MEDIA_TYPE: &str = "application/json";

/// Which collection of a MISP instance is being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MispFeed {
    /// Events, with their attributes, tags, and galaxy clusters inline.
    Events,
    /// Warning lists, which say a value is *likely a false positive* rather than that it is benign.
    WarningLists,
}

impl MispFeed {
    /// Every feed this connector reads.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Events, Self::WarningLists]
    }

    /// The cursor's feed key, scoped to an instance.
    ///
    /// The instance name is part of it, so two instances never share a position. Without that, a
    /// second instance would resume from wherever the first got to and skip everything before it.
    #[must_use]
    pub fn feed_key(self, instance: &str) -> String {
        format!("{instance}/{}", self.as_str())
    }

    /// A label for a diagnostic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::WarningLists => "warninglists",
        }
    }
}

impl core::fmt::Display for MispFeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One configured MISP instance.
#[derive(Debug, Clone)]
pub struct MispInstance {
    /// The operator's name for it, which is also half of every cursor key it owns.
    ///
    /// A name rather than the URL: an instance that moves hostname is the same instance and should
    /// not resync from the beginning, and two instances behind one load balancer are still two.
    pub name: String,
    /// Its base URL.
    pub base_url: String,
    /// The API key.
    ///
    /// [`SensitiveText`] end to end. MISP sends it in an `Authorization` header, and it grants the
    /// key's full role — which on many instances includes write endpoints this connector never
    /// calls but the credential itself does not know that.
    pub api_key: SensitiveText,
}

impl MispInstance {
    /// Name an instance.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        base_url: impl Into<String>,
        api_key: SensitiveText,
    ) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            api_key,
        }
    }
}

/// One page of a MISP feed, as fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MispPage {
    /// The raw body, handed to the ingestion pipeline unmodified.
    pub body: Vec<u8>,
    /// The URL it came from, after any redirects.
    pub url: String,
    /// How many top-level records the page held.
    pub record_count: usize,
    /// The newest event `timestamp` seen, as a unix-seconds string, for the cursor.
    pub newest_timestamp: Option<String>,
    /// Whether a further page is worth asking for.
    pub more: bool,
    /// The entity tag, if the instance set one.
    pub etag: Option<String>,
}

/// A MISP client over some [`Transport`].
pub struct MispClient<'a> {
    transport: &'a dyn Transport,
}

impl core::fmt::Debug for MispClient<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MispClient").finish_non_exhaustive()
    }
}

impl<'a> MispClient<'a> {
    /// Build a client over a transport.
    #[must_use]
    pub const fn new(transport: &'a dyn Transport) -> Self {
        Self { transport }
    }

    /// Confirm an instance answers and the key authenticates, returning its version.
    ///
    /// Run before any sync, so a wrong key fails on one cheap request rather than part way through
    /// a paginated run that has already written a cursor.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Status`] for a rejected key, and the transport's own errors otherwise.
    pub fn version(&self, instance: &MispInstance) -> Result<String, ConnectorError> {
        let url = join(&instance.base_url, "servers/getVersion");
        let response = self.get(&url, instance, None)?;
        require_success(&response)?;

        let document: Value = serde_json::from_slice(&response.body).map_err(|error| {
            ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: format!("the version response is not JSON: {error}"),
            }
        })?;

        Ok(document
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned())
    }

    /// Fetch one page of a feed.
    ///
    /// `since` is a unix-seconds string from the stored cursor. The caller ingests the page and
    /// only then advances the cursor.
    ///
    /// # Errors
    ///
    /// The transport's errors, plus [`ConnectorError::MalformedResponse`] for a body that is not
    /// the shape the endpoint promises.
    pub fn page(
        &self,
        instance: &MispInstance,
        feed: MispFeed,
        since: Option<&str>,
        page: usize,
        page_size: usize,
        etag: Option<&str>,
    ) -> Result<Option<MispPage>, ConnectorError> {
        let url = self.url_for(instance, feed, since, page, page_size);

        let response = self.get(&url, instance, etag)?;
        if response.is_not_modified() {
            return Ok(None);
        }
        require_success(&response)?;

        let document: Value = serde_json::from_slice(&response.body).map_err(|error| {
            ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: format!("the page is not JSON: {error}"),
            }
        })?;

        let (record_count, newest) = match feed {
            MispFeed::Events => summarise_events(&document, &response.final_url)?,
            MispFeed::WarningLists => (count_warninglists(&document), None),
        };

        Ok(Some(MispPage {
            record_count,
            newest_timestamp: newest,
            // MISP does not say whether more pages follow. A full page is the only evidence
            // available, and asking for one more page than exists costs one empty response —
            // whereas stopping early because a page happened to be short loses records silently.
            more: record_count >= page_size && matches!(feed, MispFeed::Events),
            etag: response.etag,
            url: response.final_url,
            body: response.body,
        }))
    }

    /// The URL for one page of a feed.
    fn url_for(
        &self,
        instance: &MispInstance,
        feed: MispFeed,
        since: Option<&str>,
        page: usize,
        page_size: usize,
    ) -> String {
        match feed {
            MispFeed::Events => {
                // MISP's path-parameter form. See the module documentation for why this is a `GET`
                // when MISP's own examples use `POST`.
                let mut path =
                    format!("events/restSearch/returnFormat:json/limit:{page_size}/page:{page}");
                if let Some(since) = since {
                    // `timestamp` on an event search is "modified at or after", so a re-run
                    // re-fetches the boundary event rather than skipping past it. Overlapping by one
                    // record is idempotent; a gap is not recoverable.
                    path.push_str(&format!("/timestamp:{}", encode_path(since)));
                }
                join(&instance.base_url, &path)
            }
            // Warning lists are small, unpaginated, and change rarely. Fetching them whole is
            // cheaper than paginating them and is what the endpoint offers.
            MispFeed::WarningLists => join(&instance.base_url, "warninglists"),
        }
    }

    /// A GET carrying the instance's key.
    fn get(
        &self,
        url: &str,
        instance: &MispInstance,
        etag: Option<&str>,
    ) -> Result<Response, ConnectorError> {
        // MISP takes the raw key as the `Authorization` value, with no `Bearer` prefix.
        let request = Request::new(url, MISP_MEDIA_TYPE)
            .with_authorization(Some(instance.api_key.clone()))
            .with_etag(etag.map(ToOwned::to_owned));
        self.transport.fetch(&request)
    }
}

/// Turn a non-success status into an error naming it.
fn require_success(response: &Response) -> Result<(), ConnectorError> {
    if response.is_success() {
        return Ok(());
    }
    Err(ConnectorError::Status {
        url: response.final_url.clone(),
        status: response.status,
    })
}

/// Count an events page and find its newest timestamp.
fn summarise_events(
    document: &Value,
    url: &str,
) -> Result<(usize, Option<String>), ConnectorError> {
    // MISP answers `{"response": [{"Event": {...}}, ...]}`. An empty search still carries the
    // array, so its absence is a malformed answer rather than an empty page.
    let entries = document
        .get("response")
        .and_then(Value::as_array)
        .ok_or_else(|| ConnectorError::MalformedResponse {
            url: url.to_owned(),
            reason: "the events page has no `response` array".to_owned(),
        })?;

    let newest = entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("Event")
                .and_then(|event| event.get("timestamp"))
                .and_then(numeric_string)
        })
        // Compared as numbers, not as strings: `"9"` sorts after `"10"` lexicographically, and a
        // cursor that moved backwards would re-fetch forever or skip forward, depending on which
        // way the comparison happened to fall.
        .max_by_key(|value| value.parse::<u64>().unwrap_or(0))
        .map(|value| value.to_owned());

    Ok((entries.len(), newest))
}

/// Count a warning-list document.
fn count_warninglists(document: &Value) -> usize {
    document
        .get("Warninglists")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// A MISP timestamp, which may arrive as a JSON number or as a string.
fn numeric_string(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Join a base URL and a path.
fn join(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// Percent-encode a value going into a URL *path* segment.
///
/// A MISP path parameter is `name:value`, so a value containing `/` or `:` would change which
/// parameter it is — or add one. Encoding conservatively is the only reading that cannot be got
/// wrong by a value an operator pasted from somewhere.
fn encode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
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

    fn instance() -> MispInstance {
        MispInstance::new(
            "primary",
            "https://misp.example.org/",
            SensitiveText::new("key-abc").unwrap(),
        )
    }

    /// Two instances publishing one event are two publications of it. A shared cursor would make a
    /// second instance resume where the first got to and skip everything before it.
    #[test]
    fn each_instance_owns_its_own_cursor_key() {
        assert_eq!(MispFeed::Events.feed_key("primary"), "primary/events");
        assert_ne!(
            MispFeed::Events.feed_key("primary"),
            MispFeed::Events.feed_key("secondary")
        );
        assert_ne!(
            MispFeed::Events.feed_key("primary"),
            MispFeed::WarningLists.feed_key("primary")
        );
    }

    #[test]
    fn an_events_url_uses_the_path_parameter_form() {
        let transport =
            crate::transport::PolicyTransport::new(brolga_security::NetworkPolicy::strict());
        let client = MispClient::new(&transport);
        let url = client.url_for(&instance(), MispFeed::Events, Some("1704067200"), 2, 50);

        assert_eq!(
            url,
            "https://misp.example.org/events/restSearch/returnFormat:json/limit:50/page:2/timestamp:1704067200"
        );
    }

    /// A path parameter is `name:value`. A value carrying `/` or `:` would change which parameter
    /// it is, or add one.
    #[test]
    fn a_path_parameter_value_is_encoded_conservatively() {
        assert_eq!(encode_path("1704067200"), "1704067200");
        assert_eq!(encode_path("1/2:3"), "1%2F2%3A3");
    }

    #[test]
    fn a_warninglist_url_is_not_paginated() {
        let transport =
            crate::transport::PolicyTransport::new(brolga_security::NetworkPolicy::strict());
        let client = MispClient::new(&transport);
        let url = client.url_for(&instance(), MispFeed::WarningLists, Some("1"), 3, 50);
        assert_eq!(url, "https://misp.example.org/warninglists");
    }

    /// `"9"` sorts after `"10"` lexicographically. A cursor that moved backwards would re-fetch
    /// forever or skip forward, depending on which way the comparison fell.
    #[test]
    fn the_newest_event_timestamp_is_compared_as_a_number() {
        let document = serde_json::json!({"response": [
            {"Event": {"timestamp": "9"}},
            {"Event": {"timestamp": "10"}},
            {"Event": {"timestamp": "1704067200"}},
        ]});
        let (count, newest) = summarise_events(&document, "https://x.example").unwrap();
        assert_eq!(count, 3);
        assert_eq!(newest.as_deref(), Some("1704067200"));
    }

    /// An empty search still carries the array, so its absence is a malformed answer rather than an
    /// empty page — and treating it as empty would end a sync reporting success.
    #[test]
    fn an_events_page_with_no_response_array_is_malformed_rather_than_empty() {
        let document = serde_json::json!({"message": "Authentication failed"});
        assert!(summarise_events(&document, "https://x.example").is_err());

        let empty = serde_json::json!({"response": []});
        let (count, newest) = summarise_events(&empty, "https://x.example").unwrap();
        assert_eq!(count, 0);
        assert_eq!(newest, None);
    }

    /// A non-numeric timestamp is ignored rather than parsed to zero, which would drag the cursor
    /// back to the epoch and re-fetch the whole instance.
    #[test]
    fn a_junk_timestamp_does_not_move_the_cursor() {
        let document = serde_json::json!({"response": [
            {"Event": {"timestamp": "not-a-number"}},
            {"Event": {"timestamp": ""}},
            {"Event": {}},
        ]});
        let (_, newest) = summarise_events(&document, "https://x.example").unwrap();
        assert_eq!(newest, None);
    }

    /// The key grants a role that on many instances includes write endpoints this connector never
    /// calls. It must not reach a log through any rendering.
    #[test]
    fn an_api_key_never_appears_in_a_debug_rendering() {
        let rendered = format!("{:?}", instance());
        assert!(!rendered.contains("key-abc"), "{rendered}");

        let transport =
            crate::transport::PolicyTransport::new(brolga_security::NetworkPolicy::strict());
        let client = MispClient::new(&transport);
        assert!(!format!("{client:?}").contains("key-abc"));
    }
}
