//! Bearer-token authentication.
//!
//! One credential, compared in constant time, never logged. Deliberately not a user system:
//! Brolga's consumers are services on a homelab, and a token in a systemd unit is the honest
//! version of what a more elaborate scheme would reduce to anyway.

use std::fmt;

use subtle::ConstantTimeEq;

/// Why a token was not accepted as a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialRejected {
    /// The token is shorter than [`Credential::MIN_LENGTH`].
    #[error("a token must be at least {minimum} bytes; this one is {actual}")]
    TooShort {
        /// The required minimum.
        minimum: usize,
        /// What was supplied.
        actual: usize,
    },

    /// The token contains bytes that cannot survive an HTTP header.
    #[error("a token must be printable ASCII without spaces")]
    NotHeaderSafe,
}

/// A shared secret a client presents to reach the API.
///
/// Neither [`fmt::Debug`] nor [`fmt::Display`] reveal it. A credential that appears in a log line,
/// a panic message, or a traced request is a credential that has to be rotated, and the usual way
/// that happens is a derived `Debug` on a config struct that someone printed while debugging
/// something unrelated.
#[derive(Clone)]
pub struct Credential {
    secret: String,
}

impl Credential {
    /// The shortest token accepted.
    ///
    /// Not a cryptographic threshold — it is the length below which someone has clearly typed a
    /// placeholder rather than generated a secret.
    pub const MIN_LENGTH: usize = 16;

    /// Build a credential from a token.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRejected`] if the token is too short or cannot be sent in a header.
    pub fn new(token: impl Into<String>) -> Result<Self, CredentialRejected> {
        let secret = token.into();

        if secret.len() < Self::MIN_LENGTH {
            return Err(CredentialRejected::TooShort {
                minimum: Self::MIN_LENGTH,
                actual: secret.len(),
            });
        }

        // A token with a newline in it can inject a header; one with a space in it silently
        // truncates at the space and authenticates a prefix of itself.
        if !secret
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"')
        {
            return Err(CredentialRejected::NotHeaderSafe);
        }

        Ok(Self { secret })
    }

    /// Whether a presented token matches, compared in constant time.
    ///
    /// A byte-by-byte comparison that returns on the first difference leaks the length of the
    /// matching prefix through timing, which turns guessing a token from infeasible into linear in
    /// its length. The length check below is not a leak: a token's length is not the secret, and
    /// the comparison itself is constant time for equal lengths.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        if presented.len() != self.secret.len() {
            return false;
        }
        self.secret.as_bytes().ct_eq(presented.as_bytes()).into()
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

/// Pull the token out of an `Authorization: Bearer <token>` header value.
///
/// Returns `None` for any other scheme rather than trying to be helpful: accepting `Basic` here
/// because it also carries a secret is how a credential ends up base64-encoded in an access log.
#[must_use]
pub fn bearer_token(header: &str) -> Option<&str> {
    let rest = header.strip_prefix("Bearer ").or_else(|| {
        // Schemes are case-insensitive per RFC 7235; the token is not.
        let (scheme, rest) = header.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(rest)
    })?;

    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const GOOD: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_matching_token_is_accepted_and_a_different_one_is_not() {
        let credential = Credential::new(GOOD).unwrap();
        assert!(credential.matches(GOOD));
        assert!(!credential.matches("0123456789abcdef0123456789abcdee"));
        assert!(!credential.matches(""));
    }

    /// A prefix must not authenticate. This is what the length check is for.
    #[test]
    fn a_prefix_of_the_token_is_not_accepted() {
        let credential = Credential::new(GOOD).unwrap();
        for length in 1..GOOD.len() {
            let prefix = GOOD.get(..length).unwrap();
            assert!(!credential.matches(prefix), "{prefix} authenticated");
        }
    }

    #[test]
    fn a_short_token_is_refused() {
        assert!(matches!(
            Credential::new("hunter2"),
            Err(CredentialRejected::TooShort { .. })
        ));
    }

    /// A token containing a newline can terminate the header and inject another one. A token
    /// containing a space is worse in a quieter way: some clients send it unquoted, the server
    /// reads up to the space, and a prefix of the secret becomes the secret.
    #[test]
    fn a_token_that_cannot_survive_a_header_is_refused() {
        for hostile in [
            "0123456789abcdef\nX-Admin: true",
            "0123456789abcdef with a space",
            "0123456789abcdef\r\nSet-Cookie: a=b",
            "0123456789abcdef\"quoted",
            "0123456789abcdef\u{0}nul",
        ] {
            assert!(
                matches!(
                    Credential::new(hostile),
                    Err(CredentialRejected::NotHeaderSafe)
                ),
                "accepted {hostile:?}"
            );
        }
    }

    /// The secret must not be recoverable from a debug print. This is the test that stops a
    /// `#[derive(Debug)]` on a config struct from putting the token in someone's terminal.
    #[test]
    fn the_secret_never_appears_in_debug_output() {
        let credential = Credential::new(GOOD).unwrap();
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains(GOOD), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn a_bearer_header_yields_its_token() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER abc"), Some("abc"));
    }

    /// Another scheme is not a bearer token even when it also carries a secret.
    #[test]
    fn a_non_bearer_scheme_yields_nothing() {
        assert_eq!(bearer_token("Basic dXNlcjpwYXNz"), None);
        assert_eq!(bearer_token("abc"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token(""), None);
    }
}
