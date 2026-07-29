//! How the server is bound, authenticated, and limited.
//!
//! The type in this module exists to make one class of mistake unrepresentable: serving a
//! threat-intelligence store to a network without requiring a credential.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use brolga_security::network::AddressCategory;

use crate::auth::Credential;

/// Why a server refused to start.
///
/// A startup refusal, not a request-time error. Everything here is a deployment mistake that is
/// cheaper to hit on the first run than to discover from someone else's traffic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigRejected {
    /// The bind address is reachable from off-host and no credential was configured.
    #[error(
        "refusing to bind {address}: it is reachable from other hosts and no token is configured. \
         Set a token, or bind 127.0.0.1."
    )]
    UnauthenticatedNonLoopback {
        /// The address that was refused.
        address: SocketAddr,
    },

    /// A limit was set to zero, which would reject every request rather than relaxing the limit.
    #[error("{name} must be greater than zero")]
    ZeroLimit {
        /// Which limit.
        name: &'static str,
    },
}

/// Everything the server needs to bind.
///
/// Built through [`ApiConfig::loopback`] or [`ApiConfig::bind`] so the authentication invariant is
/// checked once, at construction, rather than at each use.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    address: SocketAddr,
    credential: Option<Credential>,
    max_body_bytes: usize,
    request_timeout: Duration,
}

impl ApiConfig {
    /// The default: loopback only, no credential required.
    ///
    /// Safe without a token because reaching it already requires code execution on the host, at
    /// which point the SQLite file is readable anyway. This is the mode `brolga serve` uses when
    /// nobody asks for anything else.
    #[must_use]
    pub fn loopback(port: u16) -> Self {
        Self {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            credential: None,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Bind an arbitrary address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigRejected::UnauthenticatedNonLoopback`] if the address is reachable from
    /// another host and `credential` is `None`.
    ///
    /// The check is on the *address*, not on anyone's belief about the network. "It is only on the
    /// LAN" and "there is a firewall in front of it" are claims this process cannot verify and
    /// which stop being true without anyone editing this config. That a store of who-attacked-whom
    /// should not be readable by an unauthenticated GET is a property worth enforcing where it can
    /// be enforced.
    pub fn bind(
        address: SocketAddr,
        credential: Option<Credential>,
    ) -> Result<Self, ConfigRejected> {
        if credential.is_none() && !reachable_only_from_this_host(address.ip()) {
            return Err(ConfigRejected::UnauthenticatedNonLoopback { address });
        }
        Ok(Self {
            address,
            credential,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Cap the request body.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigRejected::ZeroLimit`] if `bytes` is zero, which would reject every request
    /// carrying a body rather than lifting the cap.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Result<Self, ConfigRejected> {
        if bytes == 0 {
            return Err(ConfigRejected::ZeroLimit {
                name: "max_body_bytes",
            });
        }
        self.max_body_bytes = bytes;
        Ok(self)
    }

    /// Cap how long a request may run before the server gives up on it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigRejected::ZeroLimit`] if the timeout is zero, which would time out every
    /// request before it began.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, ConfigRejected> {
        if timeout.is_zero() {
            return Err(ConfigRejected::ZeroLimit {
                name: "request_timeout",
            });
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// The address the server will bind.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The credential a request must present, if any.
    #[must_use]
    pub const fn credential(&self) -> Option<&Credential> {
        self.credential.as_ref()
    }

    /// The largest request body accepted.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// How long a request may run.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Whether requests must present a credential.
    #[must_use]
    pub const fn requires_authentication(&self) -> bool {
        self.credential.is_some()
    }
}

/// Whether an address can only be reached by something already running on this host.
///
/// The unspecified address (`0.0.0.0`, `::`) is the trap: it looks like "no particular address"
/// and binds every interface the host has, including the one facing the internet.
fn reachable_only_from_this_host(address: IpAddr) -> bool {
    match AddressCategory::of(address) {
        AddressCategory::Loopback => true,
        AddressCategory::Unspecified
        | AddressCategory::Private
        | AddressCategory::LinkLocal
        | AddressCategory::Multicast
        | AddressCategory::Public
        | AddressCategory::Reserved => false,
        // `AddressCategory` is `#[non_exhaustive]`, so a category added upstream lands here. It
        // must default to "not loopback": a new category being served without a token, because
        // this match had not been updated, is the failure worth avoiding.
        _ => false,
    }
}

/// 1 MiB. Large enough for any query this API accepts, small enough that a body cannot be used to
/// exhaust memory before the handler sees it.
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Ten seconds. A read against a local SQLite file that has not answered in ten seconds is not
/// going to; holding the connection open past that only helps an attacker accumulate them.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn socket(text: &str) -> SocketAddr {
        text.parse().expect("test address must parse")
    }

    #[test]
    fn loopback_needs_no_credential() {
        let config = ApiConfig::loopback(8080);
        assert!(!config.requires_authentication());
        assert_eq!(config.address().port(), 8080);
        assert!(config.address().ip().is_loopback());
    }

    /// The whole point of the type. Each of these addresses is reachable from another machine.
    #[test]
    fn binding_off_host_without_a_credential_is_refused() {
        for address in [
            "0.0.0.0:8080",
            "192.168.1.10:8080",
            "10.0.0.5:8080",
            "100.89.92.86:8080",
            "203.0.113.9:8080",
            "[::]:8080",
        ] {
            let result = ApiConfig::bind(socket(address), None);
            assert!(
                matches!(
                    result,
                    Err(ConfigRejected::UnauthenticatedNonLoopback { .. })
                ),
                "{address} was accepted without a credential"
            );
        }
    }

    /// `0.0.0.0` reads as "unspecified" and behaves as "every interface". Anyone who types it means
    /// "I do not want to think about the address", which is exactly when the check has to hold.
    #[test]
    fn the_unspecified_address_is_treated_as_off_host() {
        assert!(!reachable_only_from_this_host("0.0.0.0".parse().unwrap()));
        assert!(!reachable_only_from_this_host("::".parse().unwrap()));
    }

    #[test]
    fn binding_off_host_with_a_credential_is_allowed() {
        let credential = Credential::new("a-token-long-enough-to-be-worth-something").unwrap();
        let config = ApiConfig::bind(socket("0.0.0.0:8080"), Some(credential)).unwrap();
        assert!(config.requires_authentication());
    }

    #[test]
    fn ipv6_loopback_needs_no_credential() {
        let config = ApiConfig::bind(socket("[::1]:8080"), None).unwrap();
        assert!(!config.requires_authentication());
    }

    /// A zero limit reads like "unlimited" and behaves like "reject everything".
    #[test]
    fn a_zero_limit_is_refused_rather_than_read_as_unlimited() {
        let config = ApiConfig::loopback(8080);
        assert!(matches!(
            config.clone().with_max_body_bytes(0),
            Err(ConfigRejected::ZeroLimit { .. })
        ));
        assert!(matches!(
            config.with_request_timeout(Duration::ZERO),
            Err(ConfigRejected::ZeroLimit { .. })
        ));
    }

    #[test]
    fn the_defaults_are_bounded() {
        let config = ApiConfig::loopback(8080);
        assert!(config.max_body_bytes() > 0);
        assert!(!config.request_timeout().is_zero());
    }
}
