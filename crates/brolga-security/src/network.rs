//! Outbound network policy: the design that stops server-side request forgery.
//!
//! # The problem
//!
//! Brolga's connectors fetch URLs. Some of those URLs come from configuration, and later ones will
//! come from intelligence data — a STIX object's `external_references`, a MISP attribute, a TAXII
//! discovery response naming its own collection endpoints. A request Brolga makes on behalf of that
//! data is a request made *from inside the operator's network*, which is exactly what a cloud
//! metadata endpoint or an unauthenticated internal service is not expecting.
//!
//! # Why checking the URL is not enough
//!
//! The naive control — reject a URL whose host looks internal — fails three ways, and all three are
//! routinely exploited:
//!
//! 1. **DNS.** `evil.example` resolves to `169.254.169.254`. The host name is unremarkable.
//! 2. **Redirects.** The first request goes somewhere public; the response redirects to
//!    `http://localhost:8080/admin`. The URL that was checked is not the URL that was fetched.
//! 3. **Rebinding.** The name resolves to a public address when checked and a private one when
//!    connected — the classic time-of-check-to-time-of-use gap.
//!
//! So the boundary is the **resolved address, checked immediately before connecting, on every
//! request including each redirect**. [`NetworkPolicy::permits_address`] is that check.
//! [`NetworkPolicy::permits_scheme`] and [`NetworkPolicy::permits_redirect`] reject cheaply and
//! early, but neither is a substitute for it: they see a URL, and a URL is not what gets connected
//! to.
//!
//! This module is the policy and the classification. The connector that enforces it arrives in
//! `v0.6.0`; defining the contract now means that connector implements a reviewed design rather
//! than inventing one under deadline.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// URL schemes Brolga will fetch.
pub const ALLOWED_SCHEMES: &[&str] = &["https", "http"];

/// Why an outbound request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NetworkDenied {
    /// The scheme is not one Brolga fetches.
    #[error("scheme {scheme:?} is not permitted; Brolga fetches only {ALLOWED_SCHEMES:?}")]
    Scheme {
        /// The rejected scheme.
        scheme: String,
    },

    /// The resolved address is in a range Brolga will not connect to.
    #[error("address {address} is {category}, which outbound policy does not permit")]
    Address {
        /// The resolved address.
        address: IpAddr,
        /// Why it is refused.
        category: AddressCategory,
    },

    /// Plain HTTP was used where the policy requires TLS.
    #[error("plaintext HTTP is not permitted by this policy; use https")]
    PlaintextForbidden,

    /// The chain of redirects was longer than the policy allows.
    #[error("redirect limit of {limit} exceeded")]
    TooManyRedirects {
        /// The configured limit.
        limit: u64,
    },

    /// A redirect tried to change scheme in a way the policy forbids.
    #[error("a redirect from {from} to {to} changes scheme in a way policy does not permit")]
    RedirectSchemeChange {
        /// The scheme before the redirect.
        from: String,
        /// The scheme after it.
        to: String,
    },
}

/// What kind of address something resolved to.
///
/// Named categories rather than a boolean, so a diagnostic can say *why* an address was refused —
/// "it is a cloud metadata endpoint" is actionable in a way "it is not permitted" is not.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AddressCategory {
    /// Routable on the public internet.
    Public,
    /// This machine.
    Loopback,
    /// RFC 1918 or the IPv6 unique-local range.
    Private,
    /// Link-local, including the cloud metadata range.
    LinkLocal,
    /// The address of a cloud instance metadata service.
    ///
    /// Separate from `LinkLocal` because it is the single highest-value SSRF target and a
    /// diagnostic naming it explicitly saves an operator a great deal of guessing.
    CloudMetadata,
    /// Multicast.
    Multicast,
    /// Unspecified: `0.0.0.0` or `::`.
    Unspecified,
    /// Documentation, benchmarking, or otherwise reserved.
    Reserved,
}

impl AddressCategory {
    /// Whether this category is routable on the public internet.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }

    /// Classify an address.
    #[must_use]
    pub fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(v4) => Self::of_v4(v4),
            IpAddr::V6(v6) => Self::of_v6(v6),
        }
    }

    fn of_v4(address: Ipv4Addr) -> Self {
        // Checked before the link-local range, which contains it.
        if address == Ipv4Addr::new(169, 254, 169, 254) {
            return Self::CloudMetadata;
        }
        if address.is_loopback() {
            return Self::Loopback;
        }
        if address.is_private() {
            return Self::Private;
        }
        if address.is_link_local() {
            return Self::LinkLocal;
        }
        if address.is_multicast() {
            return Self::Multicast;
        }
        if address.is_unspecified() {
            return Self::Unspecified;
        }
        if address.is_broadcast() || address.is_documentation() {
            return Self::Reserved;
        }

        let [first, second, ..] = address.octets();
        // 100.64.0.0/10, carrier-grade NAT: not public, and reachable inside many networks.
        if first == 100 && (64..128).contains(&second) {
            return Self::Private;
        }
        // 0.0.0.0/8 "this network", and 240.0.0.0/4 reserved for future use.
        if first == 0 || first >= 240 {
            return Self::Reserved;
        }

        Self::Public
    }

    fn of_v6(address: Ipv6Addr) -> Self {
        // An IPv4-mapped address is an IPv4 address wearing a disguise, and classifying it as an
        // opaque IPv6 address would let `::ffff:127.0.0.1` through.
        if let Some(v4) = address.to_ipv4_mapped() {
            return Self::of_v4(v4);
        }
        if address.is_loopback() {
            return Self::Loopback;
        }
        if address.is_unspecified() {
            return Self::Unspecified;
        }
        if address.is_multicast() {
            return Self::Multicast;
        }

        let segments = address.segments();
        let first = segments.first().copied().unwrap_or_default();

        // fe80::/10 link-local.
        if first & 0xffc0 == 0xfe80 {
            return Self::LinkLocal;
        }
        // fc00::/7 unique local.
        if first & 0xfe00 == 0xfc00 {
            return Self::Private;
        }
        // 2001:db8::/32 documentation.
        if first == 0x2001 && segments.get(1) == Some(&0x0db8) {
            return Self::Reserved;
        }

        Self::Public
    }
}

impl fmt::Display for AddressCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Public => "publicly routable",
            Self::Loopback => "a loopback address",
            Self::Private => "a private address",
            Self::LinkLocal => "a link-local address",
            Self::CloudMetadata => "a cloud instance metadata endpoint",
            Self::Multicast => "a multicast address",
            Self::Unspecified => "the unspecified address",
            Self::Reserved => "a reserved address",
        };
        f.write_str(text)
    }
}

/// Outbound network policy.
///
/// The defaults refuse everything that is not publicly routable and refuse plaintext HTTP. An
/// operator running an internal MISP has to say so, and saying so is a visible configuration change
/// rather than the state Brolga shipped in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Whether plaintext HTTP may be used.
    ///
    /// `false`. Threat-intelligence feeds carry authentication tokens and describe what an
    /// organisation is investigating; both are worth protecting in transit.
    pub allow_plaintext_http: bool,

    /// Whether non-public addresses may be connected to.
    ///
    /// `false`. This is the SSRF control. An operator with an internal MISP sets it deliberately
    /// and, ideally, alongside an allow-list.
    pub allow_private_addresses: bool,

    /// Whether the cloud metadata address may be connected to.
    ///
    /// Separate from [`Self::allow_private_addresses`], and `false` even when that is `true`. An
    /// operator enabling internal fetches almost never means "and also let a feed read my instance
    /// credentials", and collapsing the two would make that the default consequence.
    pub allow_cloud_metadata: bool,

    /// How many redirects may be followed.
    pub max_redirects: u64,

    /// Whether a redirect may downgrade from HTTPS to HTTP.
    ///
    /// `false`. A redirect that downgrades is either an attack or a misconfiguration, and following
    /// it sends the credentials the first request carried over plaintext.
    pub allow_redirect_downgrade: bool,
}

impl NetworkPolicy {
    /// The safe defaults.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_plaintext_http: false,
            allow_private_addresses: false,
            allow_cloud_metadata: false,
            max_redirects: 3,
            allow_redirect_downgrade: false,
        }
    }

    /// A policy for reaching internal systems, still refusing cloud metadata.
    ///
    /// The shape an operator with an internal MISP actually needs, provided as a named constructor
    /// so it is reached for as a whole rather than assembled field by field until it works.
    #[must_use]
    pub const fn internal_network() -> Self {
        Self {
            allow_plaintext_http: false,
            allow_private_addresses: true,
            allow_cloud_metadata: false,
            ..Self::strict()
        }
    }

    /// Check a scheme.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDenied::Scheme`] for a scheme Brolga does not fetch, and
    /// [`NetworkDenied::PlaintextForbidden`] for `http` when the policy requires TLS.
    pub fn permits_scheme(&self, scheme: &str) -> Result<(), NetworkDenied> {
        let scheme = scheme.to_ascii_lowercase();

        if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
            return Err(NetworkDenied::Scheme { scheme });
        }
        if scheme == "http" && !self.allow_plaintext_http {
            return Err(NetworkDenied::PlaintextForbidden);
        }
        Ok(())
    }

    /// Check a resolved address.
    ///
    /// **This is the check that matters.** It must run immediately before connecting, on every
    /// request including each redirect, against the address actually being connected to. Checking a
    /// host name instead leaves DNS resolution, redirects, and rebinding as open doors.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDenied::Address`] naming the category that caused the refusal.
    pub fn permits_address(&self, address: IpAddr) -> Result<(), NetworkDenied> {
        let category = AddressCategory::of(address);

        let permitted = match category {
            AddressCategory::Public => true,
            AddressCategory::CloudMetadata => self.allow_cloud_metadata,
            AddressCategory::Loopback | AddressCategory::Private | AddressCategory::LinkLocal => {
                self.allow_private_addresses
            }
            // Never permitted by configuration. None of them is a thing Brolga fetches from, and
            // offering a switch would imply otherwise.
            AddressCategory::Multicast
            | AddressCategory::Unspecified
            | AddressCategory::Reserved => false,
        };

        if permitted {
            Ok(())
        } else {
            Err(NetworkDenied::Address { address, category })
        }
    }

    /// Check a redirect.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkDenied::TooManyRedirects`] past the limit and
    /// [`NetworkDenied::RedirectSchemeChange`] for a downgrade the policy forbids.
    pub fn permits_redirect(
        &self,
        redirects_so_far: u64,
        from_scheme: &str,
        to_scheme: &str,
    ) -> Result<(), NetworkDenied> {
        if redirects_so_far >= self.max_redirects {
            return Err(NetworkDenied::TooManyRedirects {
                limit: self.max_redirects,
            });
        }

        let from = from_scheme.to_ascii_lowercase();
        let to = to_scheme.to_ascii_lowercase();

        if from == "https" && to == "http" && !self.allow_redirect_downgrade {
            return Err(NetworkDenied::RedirectSchemeChange { from, to });
        }

        self.permits_scheme(&to)
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::strict()
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

    fn address(text: &str) -> IpAddr {
        text.parse().expect("a valid address")
    }

    #[test]
    fn the_cloud_metadata_endpoint_is_classified_separately() {
        // The single highest-value SSRF target, and worth naming in a diagnostic.
        assert_eq!(
            AddressCategory::of(address("169.254.169.254")),
            AddressCategory::CloudMetadata,
        );
        // Its neighbours are ordinary link-local addresses.
        assert_eq!(
            AddressCategory::of(address("169.254.169.253")),
            AddressCategory::LinkLocal,
        );
    }

    #[test]
    fn non_public_ranges_are_classified() {
        for (text, expected) in [
            ("127.0.0.1", AddressCategory::Loopback),
            ("10.0.0.1", AddressCategory::Private),
            ("172.16.0.1", AddressCategory::Private),
            ("192.168.1.1", AddressCategory::Private),
            ("100.64.0.1", AddressCategory::Private),
            ("169.254.1.1", AddressCategory::LinkLocal),
            ("224.0.0.1", AddressCategory::Multicast),
            ("0.0.0.0", AddressCategory::Unspecified),
            ("255.255.255.255", AddressCategory::Reserved),
            ("192.0.2.1", AddressCategory::Reserved),
            ("240.0.0.1", AddressCategory::Reserved),
            ("::1", AddressCategory::Loopback),
            ("::", AddressCategory::Unspecified),
            ("fe80::1", AddressCategory::LinkLocal),
            ("fc00::1", AddressCategory::Private),
            ("fd00::1", AddressCategory::Private),
            ("ff02::1", AddressCategory::Multicast),
            ("2001:db8::1", AddressCategory::Reserved),
        ] {
            assert_eq!(
                AddressCategory::of(address(text)),
                expected,
                "{text} misclassified",
            );
        }
    }

    #[test]
    fn public_addresses_are_classified_as_public() {
        for text in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(
                AddressCategory::of(address(text)).is_public(),
                "{text} should be public",
            );
        }
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_cannot_smuggle_a_loopback_through() {
        // Classifying it as an opaque IPv6 address would let `::ffff:127.0.0.1` reach localhost.
        assert_eq!(
            AddressCategory::of(address("::ffff:127.0.0.1")),
            AddressCategory::Loopback,
        );
        assert_eq!(
            AddressCategory::of(address("::ffff:169.254.169.254")),
            AddressCategory::CloudMetadata,
        );
        assert_eq!(
            AddressCategory::of(address("::ffff:10.0.0.1")),
            AddressCategory::Private,
        );

        let policy = NetworkPolicy::strict();
        assert!(policy.permits_address(address("::ffff:127.0.0.1")).is_err());
    }

    #[test]
    fn the_default_policy_refuses_everything_that_is_not_public() {
        let policy = NetworkPolicy::strict();
        assert_eq!(policy, NetworkPolicy::default());

        assert!(policy.permits_address(address("1.1.1.1")).is_ok());
        for text in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fd00::1",
            "0.0.0.0",
        ] {
            assert!(
                policy.permits_address(address(text)).is_err(),
                "{text} must be refused by default",
            );
        }
    }

    #[test]
    fn enabling_internal_fetches_does_not_enable_metadata_access() {
        // An operator with an internal MISP almost never means "and also let a feed read my
        // instance credentials".
        let policy = NetworkPolicy::internal_network();

        assert!(policy.permits_address(address("10.0.0.1")).is_ok());
        assert!(policy.permits_address(address("127.0.0.1")).is_ok());

        let refused = policy
            .permits_address(address("169.254.169.254"))
            .unwrap_err();
        assert!(
            matches!(
                refused,
                NetworkDenied::Address {
                    category: AddressCategory::CloudMetadata,
                    ..
                }
            ),
            "{refused:?}",
        );
        assert!(refused.to_string().contains("metadata"), "{refused}");
    }

    #[test]
    fn some_categories_cannot_be_enabled_by_configuration_at_all() {
        // Offering a switch would imply Brolga has a reason to fetch from them.
        let permissive = NetworkPolicy {
            allow_private_addresses: true,
            allow_cloud_metadata: true,
            allow_plaintext_http: true,
            ..NetworkPolicy::strict()
        };

        for text in ["224.0.0.1", "0.0.0.0", "255.255.255.255", "240.0.0.1"] {
            assert!(
                permissive.permits_address(address(text)).is_err(),
                "{text} must not be reachable under any policy",
            );
        }
    }

    #[test]
    fn only_http_and_https_are_fetched() {
        let policy = NetworkPolicy::strict();
        assert!(policy.permits_scheme("https").is_ok());

        for scheme in ["file", "ftp", "gopher", "data", "javascript", "dict", "jar"] {
            assert!(
                matches!(
                    policy.permits_scheme(scheme),
                    Err(NetworkDenied::Scheme { .. })
                ),
                "{scheme} must be refused",
            );
        }
    }

    #[test]
    fn plaintext_http_is_refused_unless_enabled() {
        let strict = NetworkPolicy::strict();
        assert!(matches!(
            strict.permits_scheme("http"),
            Err(NetworkDenied::PlaintextForbidden)
        ));

        let permissive = NetworkPolicy {
            allow_plaintext_http: true,
            ..NetworkPolicy::strict()
        };
        assert!(permissive.permits_scheme("http").is_ok());
    }

    #[test]
    fn scheme_matching_is_case_insensitive() {
        // `HTTPS://` is the same scheme, and a case-sensitive check would be a trivial bypass.
        let policy = NetworkPolicy::strict();
        assert!(policy.permits_scheme("HTTPS").is_ok());
        assert!(matches!(
            policy.permits_scheme("HTTP"),
            Err(NetworkDenied::PlaintextForbidden)
        ));
        assert!(policy.permits_scheme("FILE").is_err());
    }

    #[test]
    fn redirects_are_bounded() {
        let policy = NetworkPolicy::strict();
        assert!(policy.permits_redirect(0, "https", "https").is_ok());
        assert!(policy.permits_redirect(2, "https", "https").is_ok());
        assert!(matches!(
            policy.permits_redirect(3, "https", "https"),
            Err(NetworkDenied::TooManyRedirects { limit: 3 })
        ));
    }

    #[test]
    fn a_redirect_may_not_downgrade_to_plaintext() {
        // Following one sends the credentials the first request carried over plaintext.
        let policy = NetworkPolicy::strict();
        assert!(matches!(
            policy.permits_redirect(0, "https", "http"),
            Err(NetworkDenied::RedirectSchemeChange { .. })
        ));

        // Upgrading is fine.
        let permissive = NetworkPolicy {
            allow_plaintext_http: true,
            ..NetworkPolicy::strict()
        };
        assert!(permissive.permits_redirect(0, "http", "https").is_ok());
    }

    #[test]
    fn a_redirect_to_a_forbidden_scheme_is_refused() {
        // The classic escape: a public HTTPS URL redirecting to `file:///etc/passwd`.
        let policy = NetworkPolicy::strict();
        assert!(matches!(
            policy.permits_redirect(0, "https", "file"),
            Err(NetworkDenied::Scheme { .. })
        ));
    }

    #[test]
    fn refusals_explain_themselves_in_terms_an_operator_can_act_on() {
        let refused = NetworkPolicy::strict()
            .permits_address(address("10.0.0.1"))
            .unwrap_err();
        let rendered = refused.to_string();
        assert!(rendered.contains("10.0.0.1"), "{rendered}");
        assert!(rendered.contains("private"), "{rendered}");
    }

    #[test]
    fn a_policy_round_trips_and_rejects_unknown_fields() {
        let policy = NetworkPolicy::internal_network();
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(
            serde_json::from_str::<NetworkPolicy>(&json).unwrap(),
            policy
        );

        let mut hostile = serde_json::to_value(&policy).unwrap();
        hostile["allow_everything"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NetworkPolicy>(hostile).is_err());
    }
}
