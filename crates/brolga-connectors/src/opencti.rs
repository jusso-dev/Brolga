//! Read-only synchronisation from OpenCTI, over exports and a bounded GraphQL read client.
//!
//! # Two paths, because they answer different questions
//!
//! **The export path** reads a STIX bundle OpenCTI produced — a file, or a bundle served over
//! HTTP — and hands it to the STIX parser. It needs no GraphQL at all, works against any OpenCTI
//! version, and is what an operator doing a one-off import wants.
//!
//! **The GraphQL path** polls `stixCoreObjects` incrementally. It is the difference between a
//! connector and a manual import, and it is the only one of the two that can resume.
//!
//! # The queries are closed, not merely fixed
//!
//! Every query this connector sends is a [`QueryOperation`] — an enum variant whose document is a
//! `&'static str` compiled into Brolga. There is no way to express a caller-supplied query, and no
//! variant is a mutation. [ADR 0006](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0006-a-closed-set-of-query-bodies.md)
//! records why that shape was chosen over a general `post`, and a test walks every variant to check
//! none of them mutates.
//!
//! # `toStix` is the point
//!
//! OpenCTI's own model is richer than Brolga's, and re-deriving Brolga's canonical records from
//! OpenCTI's GraphQL shape would be a second mapping that can disagree with the STIX one. So the
//! query asks for each object's `toStix` rendering and hands *that* to the STIX parser — the same
//! parser, over the same shape, as every other STIX source.
//!
//! What that costs: an object OpenCTI cannot render as STIX is not imported, and the connector says
//! so rather than reaching into the GraphQL fields to reconstruct something. An object Brolga's
//! STIX parser does not map is quarantined with a reason, exactly as it would be from a file.

use brolga_model::provenance::SensitiveText;
use serde_json::Value;

use crate::error::ConnectorError;
use crate::transport::{QueryOperation, QueryRequest, Transport};

/// This connector's name, and the first half of every cursor key it writes.
pub const OPENCTI_CONNECTOR: &str = "opencti";

/// The GraphQL path, relative to an OpenCTI base URL.
pub const GRAPHQL_PATH: &str = "graphql";

/// One configured OpenCTI instance.
#[derive(Debug, Clone)]
pub struct OpenCtiInstance {
    /// The operator's name for it, which is also half of every cursor key it owns.
    pub name: String,
    /// Its base URL.
    pub base_url: String,
    /// The API token.
    pub token: SensitiveText,
}

impl OpenCtiInstance {
    /// Name an instance.
    #[must_use]
    pub fn new(name: impl Into<String>, base_url: impl Into<String>, token: SensitiveText) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            token,
        }
    }

    /// The cursor's feed key.
    #[must_use]
    pub fn feed_key(&self) -> String {
        format!("{}/stix", self.name)
    }

    /// The GraphQL endpoint.
    #[must_use]
    pub fn graphql_url(&self) -> String {
        format!("{}/{GRAPHQL_PATH}", self.base_url.trim_end_matches('/'))
    }
}

/// One page of STIX objects, as fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenCtiPage {
    /// A STIX bundle assembled from the page's `toStix` renderings.
    pub body: Vec<u8>,
    /// The endpoint it came from.
    pub url: String,
    /// How many objects the page held.
    pub object_count: usize,
    /// How many of them OpenCTI could not render as STIX.
    ///
    /// Reported rather than silently skipped: a page that half-imported and said nothing is
    /// indistinguishable from one that imported wholly.
    pub unrenderable: usize,
    /// The newest `updated_at` seen, for the cursor.
    pub newest_modified: Option<String>,
    /// The GraphQL end cursor, for the next page.
    pub end_cursor: Option<String>,
    /// Whether the server says more pages follow.
    pub more: bool,
}

/// An OpenCTI client over some [`Transport`].
pub struct OpenCtiClient<'a> {
    transport: &'a dyn Transport,
}

impl core::fmt::Debug for OpenCtiClient<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenCtiClient").finish_non_exhaustive()
    }
}

impl<'a> OpenCtiClient<'a> {
    /// Build a client over a transport.
    #[must_use]
    pub const fn new(transport: &'a dyn Transport) -> Self {
        Self { transport }
    }

    /// Confirm an instance answers and the token authenticates, returning its version.
    ///
    /// # Errors
    ///
    /// [`ConnectorError::Status`] for a rejected token, and the transport's errors otherwise.
    pub fn version(&self, instance: &OpenCtiInstance) -> Result<String, ConnectorError> {
        let url = instance.graphql_url();
        let request = QueryRequest::new(&url, QueryOperation::OpenCtiAbout, serde_json::json!({}))
            .with_authorization(Some(instance.token.clone()));

        let response = self.transport.fetch_query(&request)?;
        if !response.is_success() {
            return Err(ConnectorError::Status {
                url,
                status: response.status,
            });
        }

        let document = read_graphql(&response.body, &url)?;
        Ok(document
            .get("about")
            .and_then(|about| about.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned())
    }

    /// Fetch one page of STIX objects.
    ///
    /// # Errors
    ///
    /// The transport's errors, plus [`ConnectorError::MalformedResponse`] for a body that is not a
    /// GraphQL result of the shape the compiled-in query asks for.
    pub fn page(
        &self,
        instance: &OpenCtiInstance,
        since: Option<&str>,
        after: Option<&str>,
        page_size: usize,
    ) -> Result<OpenCtiPage, ConnectorError> {
        let url = instance.graphql_url();
        let request = QueryRequest::new(
            &url,
            QueryOperation::OpenCtiStixObjects,
            serde_json::json!({
                "first": page_size,
                "after": after,
                // The epoch rather than null, because OpenCTI's `gt` on a null value matches
                // nothing on some versions — which would make a first run import zero objects and
                // report success.
                "since": since.unwrap_or("1970-01-01T00:00:00.000Z"),
            }),
        )
        .with_authorization(Some(instance.token.clone()));

        let response = self.transport.fetch_query(&request)?;
        if !response.is_success() {
            return Err(ConnectorError::Status {
                url,
                status: response.status,
            });
        }

        let document = read_graphql(&response.body, &url)?;
        let connection =
            document
                .get("stixCoreObjects")
                .ok_or_else(|| ConnectorError::MalformedResponse {
                    url: url.clone(),
                    reason: "the result has no `stixCoreObjects`".to_owned(),
                })?;

        let edges = connection
            .get("edges")
            .and_then(Value::as_array)
            .ok_or_else(|| ConnectorError::MalformedResponse {
                url: url.clone(),
                reason: "`stixCoreObjects` has no `edges` array".to_owned(),
            })?;

        let mut objects = Vec::with_capacity(edges.len());
        let mut unrenderable = 0_usize;
        let mut newest: Option<String> = None;

        for edge in edges {
            let Some(node) = edge.get("node") else {
                continue;
            };

            // OpenCTI's `toStix` is a JSON *string* holding the object. Parsing it here rather than
            // passing it through means a malformed rendering is one skipped object with a count,
            // instead of a bundle the STIX parser refuses whole.
            match node
                .get("toStix")
                .and_then(Value::as_str)
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
            {
                Some(object) => objects.push(object),
                None => unrenderable = unrenderable.saturating_add(1),
            }

            if let Some(modified) = node.get("updated_at").and_then(Value::as_str) {
                // String comparison: OpenCTI issues UTC ISO-8601, which sorts lexicographically.
                // A value that is not UTC is skipped rather than compared, because mixing offsets
                // could move the cursor backwards and re-import forever.
                if modified.ends_with('Z')
                    && newest.as_deref().is_none_or(|current| modified > current)
                {
                    newest = Some(modified.to_owned());
                }
            }
        }

        let page_info = connection.get("pageInfo");
        let more = page_info
            .and_then(|info| info.get("hasNextPage"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let end_cursor = page_info
            .and_then(|info| info.get("endCursor"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        // A bundle, so the STIX parser reads it exactly as it reads any other bundle.
        let bundle = serde_json::json!({
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000000",
            "objects": objects,
        });

        Ok(OpenCtiPage {
            object_count: edges.len(),
            unrenderable,
            newest_modified: newest,
            end_cursor,
            more,
            body: bundle.to_string().into_bytes(),
            url,
        })
    }
}

/// Read a GraphQL response, turning a declared error into a connector error.
///
/// GraphQL answers `200` with an `errors` array, so a status check alone would read a rejected
/// token or a rate limit as a successful empty page — and a sync would report success having
/// imported nothing.
fn read_graphql(body: &[u8], url: &str) -> Result<Value, ConnectorError> {
    let document: Value =
        serde_json::from_slice(body).map_err(|error| ConnectorError::MalformedResponse {
            url: url.to_owned(),
            reason: format!("the response is not JSON: {error}"),
        })?;

    if let Some(errors) = document.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        // The first message only, and nothing else from the array. A GraphQL error may carry the
        // query, the variables, and a stack trace, and an error string is the thing most likely to
        // reach a log file.
        let message = errors
            .first()
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("the server declined the query");
        return Err(ConnectorError::MalformedResponse {
            url: url.to_owned(),
            reason: format!("GraphQL error: {}", bounded(message, 200)),
        });
    }

    document
        .get("data")
        .cloned()
        .ok_or_else(|| ConnectorError::MalformedResponse {
            url: url.to_owned(),
            reason: "the response carries neither `data` nor `errors`".to_owned(),
        })
}

/// Truncate at a character boundary.
fn bounded(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
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

    fn instance() -> OpenCtiInstance {
        OpenCtiInstance::new(
            "primary",
            "https://opencti.example.org/",
            SensitiveText::new("token-abc").unwrap(),
        )
    }

    /// **The criterion this whole design turns on.** No compiled-in operation may mutate, and a
    /// contributor adding one fails here rather than shipping it.
    #[test]
    fn no_compiled_in_operation_is_a_mutation() {
        for operation in QueryOperation::all() {
            let document = operation.document();
            assert!(
                document.trim_start().starts_with("query"),
                "{} does not begin with `query`",
                operation.as_str()
            );
            assert!(
                !document.contains("mutation"),
                "{} contains a mutation",
                operation.as_str()
            );
            assert!(
                !document.contains("subscription"),
                "{} contains a subscription",
                operation.as_str()
            );
        }
    }

    /// A caller cannot supply GraphQL. The body is always one of the compiled-in documents, and
    /// variables travel as values the server treats as values.
    #[test]
    fn a_request_body_is_always_a_compiled_in_document() {
        let url = "https://opencti.example.org/graphql";
        let request = QueryRequest::new(
            url,
            QueryOperation::OpenCtiStixObjects,
            serde_json::json!({"first": 10}),
        );
        let body: Value = serde_json::from_slice(&request.body()).unwrap();

        assert_eq!(
            body.get("query").and_then(Value::as_str),
            Some(QueryOperation::OpenCtiStixObjects.document())
        );
        assert_eq!(
            body.get("variables").and_then(|v| v.get("first")),
            Some(&serde_json::json!(10))
        );
    }

    #[test]
    fn the_graphql_endpoint_is_derived_from_the_base_url() {
        assert_eq!(
            instance().graphql_url(),
            "https://opencti.example.org/graphql"
        );
        assert_eq!(instance().feed_key(), "primary/stix");
    }

    /// GraphQL answers `200` with an `errors` array. A status check alone would read a rejected
    /// token as a successful empty page, and a sync would report success having imported nothing.
    #[test]
    fn a_graphql_error_is_a_failure_even_though_the_status_was_success() {
        let body = br#"{"errors":[{"message":"You are not authenticated"}],"data":null}"#;
        let error = read_graphql(body, "https://x.example/graphql").unwrap_err();
        assert!(error.to_string().contains("not authenticated"), "{error}");
    }

    /// A GraphQL error may carry the query, the variables, and a stack trace. Only the message is
    /// kept, and it is bounded.
    #[test]
    fn only_the_error_message_survives_into_a_diagnostic() {
        let body = br#"{"errors":[{"message":"nope","extensions":{"token":"token-abc"},
                        "path":["stixCoreObjects"]}]}"#;
        let error = read_graphql(body, "https://x.example/graphql").unwrap_err();
        let rendered = error.to_string();

        assert!(!rendered.contains("token-abc"), "{rendered}");
        assert!(!rendered.contains("extensions"), "{rendered}");
    }

    #[test]
    fn a_response_carrying_neither_data_nor_errors_is_malformed() {
        assert!(read_graphql(b"{}", "https://x.example/graphql").is_err());
        assert!(read_graphql(b"not json", "https://x.example/graphql").is_err());
        assert!(read_graphql(br#"{"data":{}}"#, "https://x.example/graphql").is_ok());
    }

    /// An empty `errors` array is not an error. Some servers include one unconditionally.
    #[test]
    fn an_empty_errors_array_is_not_a_failure() {
        let body = br#"{"errors":[],"data":{"about":{"version":"6.0.0"}}}"#;
        assert!(read_graphql(body, "https://x.example/graphql").is_ok());
    }

    #[test]
    fn a_token_never_appears_in_a_debug_rendering() {
        assert!(!format!("{:?}", instance()).contains("token-abc"));

        let request = QueryRequest::new(
            "https://x.example/graphql",
            QueryOperation::OpenCtiAbout,
            serde_json::json!({}),
        )
        .with_authorization(Some(SensitiveText::new("token-abc").unwrap()));
        assert!(!format!("{request:?}").contains("token-abc"));
    }
}
