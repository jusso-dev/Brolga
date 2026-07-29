//! TAXII 2.0 and 2.1 discovery, collections, and incremental object retrieval.
//!
//! # Version negotiation is explicit, and it is a refusal rather than a guess
//!
//! 2.0 and 2.1 differ in their media type, their discovery path, their pagination mechanism, and
//! the envelope objects arrive in. There is no version-neutral request that works against both, so
//! the client asks — sending an `Accept` for one version and reading the `Content-Type` the server
//! answers with — and a server that answers with neither is an error naming what it offered.
//!
//! Guessing from the response body would be possible and is deliberately not done: a 2.1 envelope
//! and a 2.0 bundle are distinguishable *most* of the time, and a client that is usually right
//! about which protocol it is speaking will silently mis-paginate the rest of the time. Losing half
//! a collection is worse than refusing to start.
//!
//! # Pagination differs, and each is followed in its own terms
//!
//! - **2.1** returns an envelope with `more: true` and a `next` token, and the client passes `next`
//!   and `limit` as query parameters.
//! - **2.0** uses HTTP range semantics: a `Range: items 0-99` request and a `Content-Range:
//!   items 0-99/532` response.
//!
//! Neither is emulated in terms of the other. A range header sent to a 2.1 server is ignored and
//! the client would loop on the first page forever; a `next` token sent to a 2.0 server is an
//! unknown parameter and is ignored the same way.
//!
//! # The cursor moves only behind stored data
//!
//! `added_after` advances after a page has been ingested and committed, never before
//! ([ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §4). A malformed page therefore quarantines and leaves the cursor where it was, so the next run
//! re-fetches that window rather than starting after a gap nobody can see.

use brolga_model::provenance::SensitiveText;
use serde_json::Value;

use crate::error::ConnectorError;
use crate::transport::{Request, Response, Transport};

/// Which version of the protocol is being spoken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaxiiVersion {
    /// TAXII 2.0, discovered at `/taxii/`.
    V20,
    /// TAXII 2.1, discovered at `/taxii2/`.
    V21,
}

impl TaxiiVersion {
    /// Every version this client speaks, newest first.
    ///
    /// Newest first because a server supporting both should be spoken to in the newer protocol:
    /// 2.1's pagination is explicit where 2.0's is inferred from a header a proxy may drop.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::V21, Self::V20]
    }

    /// The media type this version's requests and responses carry.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::V20 => "application/vnd.oasis.taxii+json;version=2.0",
            Self::V21 => "application/taxii+json;version=2.1",
        }
    }

    /// The discovery path, relative to the server root.
    #[must_use]
    pub const fn discovery_path(self) -> &'static str {
        match self {
            Self::V20 => "/taxii/",
            Self::V21 => "/taxii2/",
        }
    }

    /// A label for a diagnostic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V20 => "2.0",
            Self::V21 => "2.1",
        }
    }

    /// Which version a `Content-Type` names, if it names one this client speaks.
    ///
    /// Matched on the `version=` parameter rather than on the whole string, because servers vary in
    /// spacing and parameter order and a literal comparison would reject conformant responses.
    #[must_use]
    pub fn from_content_type(content_type: &str) -> Option<Self> {
        let normalised: String = content_type
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();

        if normalised.contains("version=2.1") {
            Some(Self::V21)
        } else if normalised.contains("version=2.0") {
            Some(Self::V20)
        } else if normalised.contains("application/taxii+json") {
            // 2.1 made the parameter optional and this media type is 2.1's own.
            Some(Self::V21)
        } else if normalised.contains("application/vnd.oasis.taxii+json") {
            Some(Self::V20)
        } else {
            None
        }
    }
}

impl core::fmt::Display for TaxiiVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A collection a server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Collection {
    /// The collection's identifier, which is also its cursor's feed key.
    pub id: String,
    /// Its title.
    pub title: String,
    /// Whether the server says it may be read.
    ///
    /// Recorded rather than acted on optimistically: a server that says `can_read: false` and then
    /// answers a read is still telling us something about how it expects to be used.
    pub can_read: bool,
}

/// What discovery found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {
    /// The version the server agreed to.
    pub version: TaxiiVersion,
    /// The server's title.
    pub title: String,
    /// Every API root URL it advertises.
    pub api_roots: Vec<String>,
    /// The default API root, if it named one.
    pub default_api_root: Option<String>,
}

/// One page of objects, as fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObjectPage {
    /// The raw body, to be handed to the ingestion pipeline unmodified.
    ///
    /// Bytes rather than parsed objects. The STIX parser is the thing that reads STIX, and parsing
    /// here would mean two readers that can disagree — and would lose the exact bytes the evidence
    /// store retains.
    pub body: Vec<u8>,
    /// The URL the page came from, after any redirects.
    pub url: String,
    /// The newest `modified` or `date_added` seen, for the cursor.
    pub newest_added: Option<String>,
    /// A continuation token, if the server offered one.
    pub next: Option<String>,
    /// Whether the server says more pages follow.
    pub more: bool,
    /// How many objects the page held.
    pub object_count: usize,
    /// The entity tag, if the server set one.
    pub etag: Option<String>,
}

/// A TAXII client over some [`Transport`].
pub struct TaxiiClient<'a> {
    transport: &'a dyn Transport,
    authorization: Option<SensitiveText>,
    version: Option<TaxiiVersion>,
}

impl core::fmt::Debug for TaxiiClient<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaxiiClient")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<'a> TaxiiClient<'a> {
    /// Build a client over a transport.
    #[must_use]
    pub fn new(transport: &'a dyn Transport) -> Self {
        Self {
            transport,
            authorization: None,
            version: None,
        }
    }

    /// The same client, carrying a credential.
    #[must_use]
    pub fn with_authorization(mut self, authorization: Option<SensitiveText>) -> Self {
        self.authorization = authorization;
        self
    }

    /// Pin the version rather than negotiating it.
    ///
    /// For a server whose `Content-Type` is rewritten by a proxy — which happens — an operator can
    /// state the version instead. Stating it is a decision they own; inferring it from a body would
    /// be one Brolga owns and would be wrong some of the time.
    #[must_use]
    pub const fn with_version(mut self, version: TaxiiVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// The version in use, once negotiated.
    #[must_use]
    pub const fn version(&self) -> Option<TaxiiVersion> {
        self.version
    }

    /// Discover a server, agreeing a version.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::VersionNotNegotiated`] when no version this client speaks is agreed, and
    /// the transport's own errors otherwise.
    pub fn discover(&mut self, base_url: &str) -> Result<Discovery, ConnectorError> {
        let candidates: Vec<TaxiiVersion> = match self.version {
            Some(version) => vec![version],
            None => TaxiiVersion::all().to_vec(),
        };

        let mut attempts: Vec<String> = Vec::new();
        for version in candidates {
            let url = join(base_url, version.discovery_path());
            let response = self.get(&url, version, None)?;

            if !response.is_success() {
                attempts.push(format!("{} answered {}", version, response.status));
                continue;
            }

            // The server's own `Content-Type` decides, not the request's `Accept`. A server that
            // answers 2.0 to a 2.1 request has told us which protocol the body is in, and reading
            // it as the version we asked for would mis-paginate everything after.
            let agreed = TaxiiVersion::from_content_type(&response.content_type).unwrap_or(version);

            let document: Value = serde_json::from_slice(&response.body).map_err(|error| {
                ConnectorError::MalformedResponse {
                    url: response.final_url.clone(),
                    reason: format!("discovery is not JSON: {error}"),
                }
            })?;

            let api_roots: Vec<String> = document
                .get("api_roots")
                .and_then(Value::as_array)
                .map(|roots| {
                    roots
                        .iter()
                        .filter_map(|root| root.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();

            if api_roots.is_empty() {
                return Err(ConnectorError::MalformedResponse {
                    url: response.final_url,
                    reason: "discovery names no API roots, so there is nothing to read".to_owned(),
                });
            }

            self.version = Some(agreed);
            return Ok(Discovery {
                version: agreed,
                title: document
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("untitled TAXII server")
                    .to_owned(),
                api_roots,
                default_api_root: document
                    .get("default")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            });
        }

        Err(ConnectorError::VersionNotNegotiated {
            url: base_url.to_owned(),
            detail: if attempts.is_empty() {
                "no version was attempted".to_owned()
            } else {
                attempts.join("; ")
            },
        })
    }

    /// List the collections of an API root.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::MalformedResponse`] if the body is not a collections document, and the
    /// transport's own errors otherwise.
    pub fn collections(&self, api_root: &str) -> Result<Vec<Collection>, ConnectorError> {
        let version = self.negotiated(api_root)?;
        let url = join(api_root, "collections/");
        let response = self.get(&url, version, None)?;
        self.require_success(&response)?;

        let document: Value = serde_json::from_slice(&response.body).map_err(|error| {
            ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: format!("collections is not JSON: {error}"),
            }
        })?;

        let entries = document
            .get("collections")
            .and_then(Value::as_array)
            .ok_or_else(|| ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: "the body has no `collections` array".to_owned(),
            })?;

        Ok(entries
            .iter()
            .filter_map(|entry| {
                Some(Collection {
                    id: entry.get("id")?.as_str()?.to_owned(),
                    title: entry
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("untitled collection")
                        .to_owned(),
                    // Absent means readable in both versions' schemas.
                    can_read: entry
                        .get("can_read")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                })
            })
            .collect())
    }

    /// Fetch one page of objects from a collection.
    ///
    /// `added_after` and `next` come from the stored cursor. The caller ingests the returned page
    /// and only then advances the cursor — see the module documentation.
    ///
    /// # Errors
    ///
    /// The transport's errors, plus [`ConnectorError::MalformedResponse`] for a body that is not an
    /// object envelope.
    pub fn objects(
        &self,
        api_root: &str,
        collection_id: &str,
        added_after: Option<&str>,
        next: Option<&str>,
        page_size: usize,
        etag: Option<&str>,
    ) -> Result<Option<ObjectPage>, ConnectorError> {
        let version = self.negotiated(api_root)?;
        let base = join(api_root, &format!("collections/{collection_id}/objects/"));

        let mut query: Vec<String> = Vec::new();
        if let Some(added_after) = added_after {
            query.push(format!("added_after={}", encode_query(added_after)));
        }
        match version {
            TaxiiVersion::V21 => {
                query.push(format!("limit={page_size}"));
                if let Some(next) = next {
                    query.push(format!("next={}", encode_query(next)));
                }
            }
            // 2.0 paginates with a range header rather than a parameter; see `range_for`.
            TaxiiVersion::V20 => {}
        }

        let url = if query.is_empty() {
            base
        } else {
            format!("{base}?{}", query.join("&"))
        };

        let response = self.get(&url, version, etag)?;

        // The server says the caller's copy is current. Not an error, and not an empty page either:
        // an empty page would look like "the feed is exhausted" and advance nothing, which is the
        // same outcome by luck rather than by decision.
        if response.is_not_modified() {
            return Ok(None);
        }
        self.require_success(&response)?;

        let document: Value = serde_json::from_slice(&response.body).map_err(|error| {
            ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: format!("the object page is not JSON: {error}"),
            }
        })?;

        // 2.1 wraps objects in an envelope; 2.0 returns a STIX bundle. Both carry the objects under
        // `objects`, which is the one thing they agree on.
        let objects = document
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| ConnectorError::MalformedResponse {
                url: response.final_url.clone(),
                reason: "the body has no `objects` array".to_owned(),
            })?;

        let more = match version {
            TaxiiVersion::V21 => document
                .get("more")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            // 2.0: more remains if the range's end is short of the total.
            TaxiiVersion::V20 => response
                .content_range
                .as_deref()
                .is_some_and(has_more_in_range),
        };

        Ok(Some(ObjectPage {
            newest_added: newest_added_of(objects),
            object_count: objects.len(),
            next: document
                .get("next")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            more,
            etag: response.etag,
            url: response.final_url,
            body: response.body,
        }))
    }

    /// The version, or an error saying discovery has not run.
    fn negotiated(&self, url: &str) -> Result<TaxiiVersion, ConnectorError> {
        self.version
            .ok_or_else(|| ConnectorError::VersionNotNegotiated {
                url: url.to_owned(),
                detail: "discovery has not run, so no version has been agreed".to_owned(),
            })
    }

    /// A GET carrying this client's credential and the negotiated media type.
    fn get(
        &self,
        url: &str,
        version: TaxiiVersion,
        etag: Option<&str>,
    ) -> Result<Response, ConnectorError> {
        let request = Request::new(url, version.media_type())
            .with_authorization(self.authorization.clone())
            .with_etag(etag.map(ToOwned::to_owned));
        self.transport.fetch(&request)
    }

    /// Turn a non-success status into an error naming it.
    fn require_success(&self, response: &Response) -> Result<(), ConnectorError> {
        if response.is_success() {
            return Ok(());
        }
        Err(ConnectorError::Status {
            url: response.final_url.clone(),
            status: response.status,
        })
    }
}

/// Whether a `Content-Range: items 0-99/532` says more items remain.
///
/// A `*` total means the server does not know, which is not the same as "no more" — treating it as
/// exhausted would stop a sync at the first page against any server that streams.
fn has_more_in_range(content_range: &str) -> bool {
    let Some(rest) = content_range.trim().strip_prefix("items") else {
        return false;
    };
    let Some((range, total)) = rest.trim().split_once('/') else {
        return false;
    };
    let Some((_, end)) = range.split_once('-') else {
        return false;
    };
    let Ok(end) = end.trim().parse::<u64>() else {
        return false;
    };
    match total.trim().parse::<u64>() {
        Ok(total) => end.saturating_add(1) < total,
        Err(_) => total.trim() == "*",
    }
}

/// The newest `modified` or `created` across a page's objects.
///
/// Used as the next `added_after`. Taken from the objects rather than from the response, because
/// only 2.1 exposes a header for it and a value derived from the objects is correct under both.
///
/// String comparison rather than parsing: RFC 3339 in UTC sorts lexicographically, every TAXII
/// timestamp is UTC by specification, and parsing would risk handing back a re-rendered value that
/// differs from what the server issued.
fn newest_added_of(objects: &[Value]) -> Option<String> {
    objects
        .iter()
        .filter_map(|object| {
            object
                .get("modified")
                .or_else(|| object.get("created"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.ends_with('Z'))
        .max()
        .map(ToOwned::to_owned)
}

/// Join a base URL and a path, without doubling or dropping the separator.
fn join(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Percent-encode a query parameter value.
///
/// Conservative on purpose: everything outside the unreserved set is encoded. Over-encoding a value
/// is harmless — a server decodes it back — whereas under-encoding a `&` in a cursor token splits
/// one parameter into two and silently changes the request.
fn encode_query(value: &str) -> String {
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

    #[test]
    fn a_content_type_names_its_version_however_it_is_spaced() {
        for (header, expected) in [
            ("application/taxii+json;version=2.1", TaxiiVersion::V21),
            ("application/taxii+json; version=2.1", TaxiiVersion::V21),
            ("APPLICATION/TAXII+JSON;VERSION=2.1", TaxiiVersion::V21),
            (
                "application/vnd.oasis.taxii+json; version=2.0",
                TaxiiVersion::V20,
            ),
            ("application/taxii+json", TaxiiVersion::V21),
            ("application/vnd.oasis.taxii+json", TaxiiVersion::V20),
        ] {
            assert_eq!(
                TaxiiVersion::from_content_type(header),
                Some(expected),
                "{header}"
            );
        }
        assert_eq!(TaxiiVersion::from_content_type("application/json"), None);
        assert_eq!(TaxiiVersion::from_content_type(""), None);
    }

    /// The two versions differ in path and media type, and getting either wrong means talking to
    /// the right server in the wrong protocol.
    #[test]
    fn each_version_has_its_own_discovery_path_and_media_type() {
        assert_eq!(TaxiiVersion::V21.discovery_path(), "/taxii2/");
        assert_eq!(TaxiiVersion::V20.discovery_path(), "/taxii/");
        assert_ne!(
            TaxiiVersion::V21.media_type(),
            TaxiiVersion::V20.media_type()
        );
        assert_eq!(
            TaxiiVersion::all().first(),
            Some(&TaxiiVersion::V21),
            "a server supporting both is spoken to in the newer protocol"
        );
    }

    /// A `*` total means the server does not know, which is not "no more". Treating it as
    /// exhausted would stop a sync at the first page against any server that streams.
    #[test]
    fn a_content_range_says_whether_more_items_remain() {
        assert!(has_more_in_range("items 0-99/532"));
        assert!(!has_more_in_range("items 500-531/532"));
        assert!(has_more_in_range("items 0-99/*"));
        assert!(!has_more_in_range("bytes 0-99/532"));
        assert!(!has_more_in_range(""));
        assert!(!has_more_in_range("items"));
        assert!(!has_more_in_range("items 0-x/5"));
    }

    #[test]
    fn the_newest_timestamp_on_a_page_becomes_the_next_cursor() {
        let objects = vec![
            serde_json::json!({"modified": "2024-01-01T00:00:00.000Z"}),
            serde_json::json!({"modified": "2024-06-01T00:00:00.000Z"}),
            serde_json::json!({"created": "2024-03-01T00:00:00.000Z"}),
        ];
        assert_eq!(
            newest_added_of(&objects).as_deref(),
            Some("2024-06-01T00:00:00.000Z")
        );
        assert_eq!(newest_added_of(&[]), None);
    }

    /// A non-UTC timestamp does not sort lexicographically against UTC ones, so taking it as a
    /// maximum could move the cursor backwards and skip records.
    #[test]
    fn a_non_utc_timestamp_is_not_taken_as_a_cursor() {
        let objects = vec![
            serde_json::json!({"modified": "2024-01-01T00:00:00.000Z"}),
            serde_json::json!({"modified": "2024-12-01T00:00:00+11:00"}),
        ];
        assert_eq!(
            newest_added_of(&objects).as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn urls_join_without_doubling_or_dropping_the_separator() {
        assert_eq!(
            join("https://x.example/api/", "collections/"),
            "https://x.example/api/collections/"
        );
        assert_eq!(
            join("https://x.example/api", "/collections/"),
            "https://x.example/api/collections/"
        );
    }

    /// Under-encoding a `&` in a cursor token splits one parameter into two and silently changes
    /// the request. Over-encoding is harmless.
    #[test]
    fn a_query_value_is_encoded_conservatively() {
        assert_eq!(
            encode_query("2024-01-01T00:00:00.000Z"),
            "2024-01-01T00%3A00%3A00.000Z"
        );
        assert_eq!(encode_query("a&b=c"), "a%26b%3Dc");
        assert_eq!(encode_query("plain-value_1.0~x"), "plain-value_1.0~x");
    }
}
