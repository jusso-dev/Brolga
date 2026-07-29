//! The one place in Brolga that opens an outbound connection.
//!
//! Per [ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §2, every protocol client is written against [`Transport`] and cannot reach the network another
//! way. Reviewing Brolga's outbound safety means reviewing this file.
//!
//! # Redirects are followed here, not by the agent
//!
//! The HTTP agent is built with redirect-following **disabled**, and each hop is taken manually
//! after the policy has been asked about it.
//!
//! An agent that follows redirects internally re-resolves the target and connects before any of
//! this code runs, which makes every SSRF control decorative: a server answers `302` to
//! `http://169.254.169.254/`, the agent fetches it, and the check that would have refused that
//! address never happened. Following hops ourselves costs a loop, and it is the whole difference
//! between a control and a comment.
//!
//! # Every address is checked, not the first one
//!
//! A host is resolved and **every** address it resolves to is checked before connecting. Checking
//! only the first would leave the classic DNS rebinding gap open in the ordinary case, where a
//! hostile name resolves to one public address and one loopback address and the resolver is free to
//! return them in any order.
//!
//! This does not close rebinding entirely — the resolution used for the check and the resolution
//! used for the connection are different lookups, and only a resolving connector can close that gap
//! completely. What it does close is the whole family of cases where a name simply *is* internal,
//! which is what a misconfigured feed URL and a redirect to metadata both look like.

use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use brolga_model::provenance::SensitiveText;
use brolga_security::{NetworkDenied, NetworkPolicy};

use crate::error::ConnectorError;

/// Largest response body read, before any parsing.
///
/// A connector fetches from a server an operator configured, which is not the same as trusting it:
/// a compromised or merely broken feed answering with an unbounded stream would otherwise be a
/// memory-exhaustion bug in a process holding an intelligence database.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// How long a single request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// A request a connector wants to make.
///
/// Retrieval only. There is no body field, because [ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
/// §5 makes read-only a shape rather than a default: a publishing connector is a new decision, not
/// a field added here.
#[derive(Debug, Clone)]
pub struct Request {
    /// The absolute URL to fetch.
    pub url: String,
    /// The `Accept` header, which is how TAXII negotiates its version.
    pub accept: String,
    /// An `Authorization` header value, if the server needs one.
    ///
    /// [`SensitiveText`] so that a debug print of a request cannot put a bearer token in a log.
    pub authorization: Option<SensitiveText>,
    /// An `If-None-Match` value, so an unchanged resource costs a round trip rather than a body.
    pub etag: Option<String>,
}

impl Request {
    /// A plain retrieval of `url`.
    #[must_use]
    pub fn new(url: impl Into<String>, accept: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            accept: accept.into(),
            authorization: None,
            etag: None,
        }
    }

    /// The same request, carrying a credential.
    #[must_use]
    pub fn with_authorization(mut self, authorization: Option<SensitiveText>) -> Self {
        self.authorization = authorization;
        self
    }

    /// The same request, conditional on an entity tag.
    #[must_use]
    pub fn with_etag(mut self, etag: Option<String>) -> Self {
        self.etag = etag;
        self
    }
}

/// What a server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The `Content-Type`, as sent.
    pub content_type: String,
    /// The `ETag`, if the server set one.
    pub etag: Option<String>,
    /// The `Content-Range`, which is how TAXII 2.0 paginates.
    pub content_range: Option<String>,
    /// The body. Empty for a `304`.
    pub body: Vec<u8>,
    /// The URL the body actually came from, after any redirects.
    ///
    /// Not the URL that was requested. A record's provenance should say where the bytes came from,
    /// and after a redirect those are different places.
    pub final_url: String,
}

impl Response {
    /// Whether the server said the caller's cached copy is still current.
    #[must_use]
    pub const fn is_not_modified(&self) -> bool {
        self.status == 304
    }

    /// Whether the status is a success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// How a connector retrieves bytes.
///
/// One method, and no way to send a body. A protocol client holds a `&dyn Transport` and therefore
/// cannot open a socket itself, which is what makes the policy in [`PolicyTransport`] the only
/// outbound path rather than the usual one.
pub trait Transport: Send + Sync {
    /// Fetch a URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError::Denied`] when the policy refuses the URL, an address it resolves
    /// to, or a redirect; [`ConnectorError::Transport`] for a network failure; and
    /// [`ConnectorError::ResponseTooLarge`] for a body over [`MAX_RESPONSE_BYTES`].
    fn fetch(&self, request: &Request) -> Result<Response, ConnectorError>;
}

/// The transport that actually connects, with [`NetworkPolicy`] applied per request and per hop.
pub struct PolicyTransport {
    agent: ureq::Agent,
    policy: NetworkPolicy,
}

impl core::fmt::Debug for PolicyTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The agent holds connection state and, potentially, credentials from a previous request.
        // Naming it without printing it keeps a `{:?}` in a diagnostic from becoming a disclosure.
        f.debug_struct("PolicyTransport")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl PolicyTransport {
    /// Build one under a policy.
    #[must_use]
    pub fn new(policy: NetworkPolicy) -> Self {
        let config = ureq::Agent::config_builder()
            // The decision this whole type exists for. See the module documentation and ADR 0005 §3.
            .max_redirects(0)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build();

        Self {
            agent: config.into(),
            policy,
        }
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Check a URL's scheme and every address its host resolves to.
    fn check_url(&self, url: &str) -> Result<(), ConnectorError> {
        let (scheme, host, port) = split_url(url)?;
        self.policy
            .permits_scheme(&scheme)
            .map_err(|denied| ConnectorError::denied(url, denied))?;

        for address in resolve(&host, port)? {
            self.policy
                .permits_address(address)
                .map_err(|denied| ConnectorError::denied(url, denied))?;
        }
        Ok(())
    }
}

impl Transport for PolicyTransport {
    fn fetch(&self, request: &Request) -> Result<Response, ConnectorError> {
        let mut url = request.url.clone();
        let mut redirects = 0_u64;

        loop {
            self.check_url(&url)?;

            let mut call = self
                .agent
                .get(&url)
                .header("Accept", &request.accept)
                .header("User-Agent", concat!("brolga/", env!("CARGO_PKG_VERSION")));

            if let Some(authorization) = &request.authorization {
                call = call.header("Authorization", authorization.expose());
            }
            if let Some(etag) = &request.etag {
                call = call.header("If-None-Match", etag);
            }

            let response = match call.call() {
                Ok(response) => response,
                // A status outside 2xx is an answer, not a transport failure — a `304` in
                // particular is the successful outcome of a conditional request.
                Err(ureq::Error::StatusCode(code)) => {
                    return Ok(Response {
                        status: code,
                        content_type: String::new(),
                        etag: None,
                        content_range: None,
                        body: Vec::new(),
                        final_url: url,
                    });
                }
                Err(error) => {
                    return Err(ConnectorError::Transport {
                        url: url.clone(),
                        reason: error.to_string(),
                    });
                }
            };

            let status = response.status().as_u16();
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned)
            };

            // Only the statuses that actually relocate. `304 Not Modified` is a 3xx and is *not* a
            // redirect — it is the successful answer to a conditional request, and treating it as
            // one turned a working ETag into "the server answered 304 with no `Location`".
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let Some(location) = header("location") else {
                    return Err(ConnectorError::Transport {
                        url,
                        reason: format!("the server answered {status} with no `Location`"),
                    });
                };
                let target = resolve_relative(&url, &location)?;
                let (from_scheme, _, _) = split_url(&url)?;
                let (to_scheme, _, _) = split_url(&target)?;

                self.policy
                    .permits_redirect(redirects, &from_scheme, &to_scheme)
                    .map_err(|denied| ConnectorError::denied(&target, denied))?;

                redirects = redirects.saturating_add(1);
                url = target;
                continue;
            }

            let content_type = header("content-type").unwrap_or_default();
            let etag = header("etag");
            let content_range = header("content-range");

            // Read through a limited reader rather than to end and then check. Checking afterwards
            // means the allocation the limit exists to prevent has already happened.
            let mut body = Vec::new();
            let mut reader = response.into_body().into_reader().take(
                u64::try_from(MAX_RESPONSE_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            reader
                .read_to_end(&mut body)
                .map_err(|error| ConnectorError::Transport {
                    url: url.clone(),
                    reason: error.to_string(),
                })?;

            if body.len() > MAX_RESPONSE_BYTES {
                return Err(ConnectorError::ResponseTooLarge {
                    url,
                    limit: MAX_RESPONSE_BYTES,
                });
            }

            return Ok(Response {
                status,
                content_type,
                etag,
                content_range,
                body,
                final_url: url,
            });
        }
    }
}

/// Split a URL into its scheme, host, and port, without a URL-parsing dependency.
///
/// Deliberately strict. Anything it cannot read confidently is an error rather than a best guess,
/// because the host it extracts is what the SSRF check is applied to — a parser that guessed would
/// be checking one host and connecting to another, which is worse than not checking at all.
fn split_url(url: &str) -> Result<(String, String, u16), ConnectorError> {
    let malformed = |reason: &str| ConnectorError::MalformedUrl {
        url: url.to_owned(),
        reason: reason.to_owned(),
    };

    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| malformed("has no scheme"))?;
    let scheme = scheme.to_ascii_lowercase();

    // Authority ends at the first `/`, `?`, or `#`.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| malformed("has no authority"))?;
    if authority.is_empty() {
        return Err(malformed("has an empty authority"));
    }

    // Credentials in a URL are refused rather than stripped. `https://evil@good.example.com/` reads
    // as `good.example.com` to a human and resolves to whatever follows the `@` in some parsers;
    // refusing the shape is the only reading that cannot be got wrong.
    if authority.contains('@') {
        return Err(malformed(
            "carries userinfo before the host, which is ambiguous enough that Brolga refuses it \
             rather than picking a reading",
        ));
    }

    let default_port = if scheme == "http" { 80 } else { 443 };

    // A bracketed IPv6 literal holds colons that are not the port separator.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| malformed("has an unterminated IPv6 literal"))?;
        let port = match after.strip_prefix(':') {
            Some(port) => port
                .parse()
                .map_err(|_| malformed("has a port that is not a number"))?,
            None => default_port,
        };
        (host.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_owned(),
                port.parse()
                    .map_err(|_| malformed("has a port that is not a number"))?,
            ),
            None => (authority.to_owned(), default_port),
        }
    };

    if host.is_empty() {
        return Err(malformed("has an empty host"));
    }
    Ok((scheme, host, port))
}

/// Resolve a host to every address it names.
fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, ConnectorError> {
    // A literal address needs no resolver, and going through one would let a resolver's search
    // domains turn a refusal into a lookup.
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }

    let addresses: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| ConnectorError::Transport {
            url: host.to_owned(),
            reason: format!("could not be resolved: {error}"),
        })?
        .map(|socket| socket.ip())
        .collect();

    if addresses.is_empty() {
        return Err(ConnectorError::Transport {
            url: host.to_owned(),
            reason: "resolved to no addresses".to_owned(),
        });
    }
    Ok(addresses)
}

/// Resolve a `Location` against the URL it was returned from.
///
/// Handles the three shapes a server actually sends: absolute, scheme-relative, and root-relative.
/// A path-relative `Location` is refused rather than joined, because joining it correctly requires
/// the whole RFC 3986 algorithm and a wrong join produces a URL pointing somewhere nobody named.
fn resolve_relative(base: &str, location: &str) -> Result<String, ConnectorError> {
    if location.contains("://") {
        return Ok(location.to_owned());
    }
    let (scheme, host, port) = split_url(base)?;
    let authority = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    };

    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{location}"));
    }
    Err(ConnectorError::MalformedUrl {
        url: location.to_owned(),
        reason: "is a path-relative redirect, which Brolga does not join".to_owned(),
    })
}

/// Turn a policy refusal into a connector error naming the URL it refused.
impl ConnectorError {
    fn denied(url: &str, denied: NetworkDenied) -> Self {
        Self::Denied {
            url: url.to_owned(),
            reason: denied.to_string(),
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

    #[test]
    fn a_url_splits_into_the_parts_the_policy_is_applied_to() {
        assert_eq!(
            split_url("https://taxii.example.org/taxii2/").unwrap(),
            ("https".to_owned(), "taxii.example.org".to_owned(), 443)
        );
        assert_eq!(
            split_url("http://127.0.0.1:8080/x?y#z").unwrap(),
            ("http".to_owned(), "127.0.0.1".to_owned(), 8080)
        );
        assert_eq!(
            split_url("https://[2001:db8::1]:8443/a").unwrap(),
            ("https".to_owned(), "2001:db8::1".to_owned(), 8443)
        );
        assert_eq!(
            split_url("https://[2001:db8::1]/a").unwrap().2,
            443,
            "an IPv6 literal without a port takes the scheme's default"
        );
    }

    /// `https://evil@good.example.com/` reads as `good.example.com` to a human. Refusing the shape
    /// is the only reading that cannot be got wrong.
    #[test]
    fn a_url_carrying_userinfo_is_refused_rather_than_read_one_way_or_the_other() {
        let error = split_url("https://evil.example.net@good.example.com/x").unwrap_err();
        assert!(error.to_string().contains("userinfo"), "{error}");
    }

    #[test]
    fn a_malformed_url_is_refused_rather_than_guessed_at() {
        for url in [
            "",
            "not-a-url",
            "https://",
            "https:///path",
            "https://host:notaport/",
            "https://[2001:db8::1/a",
        ] {
            assert!(split_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn a_redirect_location_resolves_against_the_url_it_came_from() {
        let base = "https://taxii.example.org/taxii2/";
        assert_eq!(
            resolve_relative(base, "https://other.example.org/x").unwrap(),
            "https://other.example.org/x"
        );
        assert_eq!(
            resolve_relative(base, "/roots/1/").unwrap(),
            "https://taxii.example.org/roots/1/"
        );
        assert_eq!(
            resolve_relative(base, "//elsewhere.example.org/x").unwrap(),
            "https://elsewhere.example.org/x"
        );
        assert_eq!(
            resolve_relative("https://taxii.example.org:8443/a", "/b").unwrap(),
            "https://taxii.example.org:8443/b",
            "a non-default port survives the join"
        );
    }

    /// Joining a path-relative redirect correctly needs the whole RFC 3986 algorithm, and a wrong
    /// join produces a URL pointing somewhere nobody named.
    #[test]
    fn a_path_relative_redirect_is_refused_rather_than_joined() {
        assert!(resolve_relative("https://a.example.org/b/c", "d").is_err());
    }

    /// The SSRF control, stated over the policy rather than over a socket. Every address a name
    /// resolves to is checked, so a name resolving to one public and one loopback address is
    /// refused whichever order the resolver returns them in.
    #[test]
    fn the_strict_policy_refuses_the_addresses_an_ssrf_attempt_needs() {
        let policy = NetworkPolicy::strict();

        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "::1",
        ] {
            let parsed: IpAddr = address.parse().unwrap();
            assert!(
                policy.permits_address(parsed).is_err(),
                "{address} was permitted under the strict policy"
            );
        }
        // A genuinely routable address, not a documentation range. `198.51.100.0/24` is TEST-NET-3
        // and the policy classifies it as reserved rather than public — correctly, since a feed
        // pointed at documentation space is misconfigured whatever else is true.
        assert!(policy.permits_address("1.1.1.1".parse().unwrap()).is_ok());
        assert!(
            policy
                .permits_address("198.51.100.1".parse().unwrap())
                .is_err(),
            "a documentation range is reserved, not public"
        );
    }

    /// Enabling internal fetches almost never means "and also let a feed read my instance
    /// credentials". The two are separate switches and this asserts they stay separate.
    #[test]
    fn allowing_internal_addresses_does_not_allow_cloud_metadata() {
        let policy = NetworkPolicy::internal_network();
        assert!(policy.permits_address("10.0.0.1".parse().unwrap()).is_ok());
        assert!(
            policy
                .permits_address("169.254.169.254".parse().unwrap())
                .is_err()
        );
    }

    /// A redirect that downgrades sends the credentials the first request carried over plaintext.
    #[test]
    fn a_redirect_may_not_downgrade_to_plaintext() {
        let policy = NetworkPolicy::strict();
        assert!(policy.permits_redirect(0, "https", "http").is_err());
        assert!(policy.permits_redirect(0, "https", "https").is_ok());
        assert!(
            policy
                .permits_redirect(policy.max_redirects, "https", "https")
                .is_err(),
            "the hop limit is enforced"
        );
    }

    #[test]
    fn a_literal_address_is_not_sent_through_the_resolver() {
        assert_eq!(
            resolve("198.51.100.1", 443).unwrap(),
            vec!["198.51.100.1".parse::<IpAddr>().unwrap()]
        );
    }

    /// A request must not print its credential, whatever a diagnostic does with it.
    #[test]
    fn a_credential_does_not_appear_in_a_debug_rendering() {
        let request = Request::new("https://taxii.example.org/", "application/taxii+json")
            .with_authorization(Some(
                SensitiveText::new("Bearer super-secret-token").unwrap(),
            ));

        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("super-secret-token"),
            "the token leaked into a debug rendering: {rendered}"
        );
    }
}
