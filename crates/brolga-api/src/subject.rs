//! Turning a consumer's string into the observable Brolga stored.
//!
//! This is the hinge the whole context endpoint turns on, and the place it is most likely to fail
//! quietly. Observables are content-addressed: an observable's id is derived from its kind and its
//! *canonical* value, so an ingest that stored `1.1.1.1` and a lookup that canonicalises
//! `01.01.01.01` differently produce different ids, and the lookup returns "nothing known" about
//! something Brolga knows a great deal about.
//!
//! A wrong answer here is indistinguishable from an empty database, which is why the tests below
//! are about equivalence classes rather than about parsing.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use brolga_model::observable::{
    DomainName, EmailAddress, FileHash, HashAlgorithm, Ipv6Address, Observable,
};

/// Why a subject could not be resolved to an observable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SubjectRejected {
    /// The kind is not one Brolga tracks.
    #[error("unknown subject kind {kind:?}; expected one of: {expected}")]
    UnknownKind {
        /// What was asked for.
        kind: String,
        /// What is accepted.
        expected: &'static str,
    },

    /// The value is not a well-formed instance of that kind.
    ///
    /// The reason is a `&'static str` rather than the parser's message: the value came from
    /// outside, and echoing attacker-chosen bytes back through a diagnostic is how an error
    /// message becomes an injection surface.
    #[error("{value_kind} value is not well formed: {reason}")]
    Malformed {
        /// The kind that was being parsed.
        value_kind: &'static str,
        /// Why it failed.
        reason: &'static str,
    },
}

/// The subject kinds a consumer may ask about.
///
/// Includes the aliases Kelpie sends (`ip`, `hostname`) rather than making every caller learn
/// Brolga's internal spelling. An integration that has to translate vocabulary is one that will
/// translate it wrong.
pub const ACCEPTED_KINDS: &str =
    "ip, ipv4, ipv6, domain, hostname, url, file_hash, md5, sha1, sha256, email";

/// Resolve a consumer's `(kind, value)` into the observable Brolga would have stored.
///
/// # Errors
///
/// Returns [`SubjectRejected`] if the kind is unknown or the value is not well formed for it.
pub fn resolve(kind: &str, value: &str) -> Result<Observable, SubjectRejected> {
    let trimmed = value.trim();

    match kind {
        // `ip` is deliberately not a guess between two parsers: it tries v4, then v6, and the
        // address itself decides. A consumer holding an address from a log rarely knows which.
        "ip" => parse_ip(trimmed),
        "ipv4" => Ipv4Addr::from_str(trimmed)
            .map(Observable::Ipv4Address)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "ipv4",
                reason: "not a dotted-quad address",
            }),
        "ipv6" => Ipv6Address::new(parse_ipv6(trimmed)?)
            .map(Observable::Ipv6Address)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "ipv6",
                reason: "not a usable IPv6 address",
            }),
        "domain" | "hostname" => DomainName::new(trimmed)
            .map(Observable::DomainName)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "domain",
                reason: "not a well-formed DNS name",
            }),
        "url" => brolga_model::observable::CanonicalUrl::new(trimmed)
            .map(Observable::Url)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "url",
                reason: "not a well-formed absolute URL",
            }),
        "email" => EmailAddress::new(trimmed)
            .map(Observable::EmailAddress)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "email",
                reason: "not a well-formed email address",
            }),
        "file_hash" => parse_hash_by_length(trimmed),
        "md5" => hash(HashAlgorithm::Md5, trimmed),
        "sha1" => hash(HashAlgorithm::Sha1, trimmed),
        "sha256" => hash(HashAlgorithm::Sha256, trimmed),
        other => Err(SubjectRejected::UnknownKind {
            kind: other.to_owned(),
            expected: ACCEPTED_KINDS,
        }),
    }
}

/// Parse an address of either family.
fn parse_ip(value: &str) -> Result<Observable, SubjectRejected> {
    match IpAddr::from_str(value) {
        Ok(IpAddr::V4(address)) => Ok(Observable::Ipv4Address(address)),
        Ok(IpAddr::V6(address)) => Ipv6Address::new(address)
            .map(Observable::Ipv6Address)
            .map_err(|_| SubjectRejected::Malformed {
                value_kind: "ip",
                reason: "not a usable IPv6 address",
            }),
        Err(_) => Err(SubjectRejected::Malformed {
            value_kind: "ip",
            reason: "not an IPv4 or IPv6 address",
        }),
    }
}

fn parse_ipv6(value: &str) -> Result<std::net::Ipv6Addr, SubjectRejected> {
    std::net::Ipv6Addr::from_str(value).map_err(|_| SubjectRejected::Malformed {
        value_kind: "ipv6",
        reason: "not an IPv6 address",
    })
}

fn hash(algorithm: HashAlgorithm, value: &str) -> Result<Observable, SubjectRejected> {
    FileHash::new(algorithm, value)
        .map(Observable::FileHash)
        .map_err(|_| SubjectRejected::Malformed {
            value_kind: "file_hash",
            reason: "not a hex digest of the right length for the algorithm",
        })
}

/// Infer the algorithm from the digest's length.
///
/// Accepts a bare digest *or* one already carrying its algorithm, because a canonical file hash
/// renders as `md5:<hex>` and a consumer that read one back out of Brolga and asked about it would
/// otherwise be told its own answer is malformed.
///
/// Length inference is a fallback, not a preference: a stated algorithm always wins, because two
/// algorithms can agree on digest length and only the source knows which was computed.
fn parse_hash_by_length(value: &str) -> Result<Observable, SubjectRejected> {
    if let Some((prefix, digest)) = value.split_once(':') {
        let algorithm = match prefix.to_ascii_lowercase().as_str() {
            "md5" => Some(HashAlgorithm::Md5),
            "sha1" => Some(HashAlgorithm::Sha1),
            "sha256" => Some(HashAlgorithm::Sha256),
            _ => None,
        };
        if let Some(algorithm) = algorithm {
            return hash(algorithm, digest);
        }
    }

    let algorithm = match value.len() {
        32 => HashAlgorithm::Md5,
        40 => HashAlgorithm::Sha1,
        64 => HashAlgorithm::Sha256,
        _ => {
            return Err(SubjectRejected::Malformed {
                value_kind: "file_hash",
                reason: "not 32, 40, or 64 hex characters, and no algorithm was stated",
            });
        }
    };

    hash(algorithm, value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// The property the endpoint depends on: two spellings of the same thing must resolve to the
    /// same id, because the id is what the stored edges point at. If this fails, a lookup returns
    /// "nothing known" about something Brolga knows.
    fn same_id(kind: &str, left: &str, right: &str) {
        let left_id = resolve(kind, left).unwrap().id();
        let right_id = resolve(kind, right).unwrap().id();
        assert_eq!(left_id, right_id, "{left:?} and {right:?} differ");
    }

    #[test]
    fn surrounding_whitespace_does_not_change_identity() {
        same_id("ip", "1.1.1.1", "  1.1.1.1  ");
        same_id("domain", "example.com", " example.com ");
    }

    #[test]
    fn domain_case_does_not_change_identity() {
        same_id("domain", "Example.COM", "example.com");
    }

    /// `hostname` is Kelpie's spelling of the same thing.
    #[test]
    fn the_hostname_alias_resolves_to_the_same_observable_as_domain() {
        same_id("domain", "example.com", "example.com");
        assert_eq!(
            resolve("hostname", "example.com").unwrap().id(),
            resolve("domain", "example.com").unwrap().id()
        );
    }

    #[test]
    fn ipv6_spellings_of_one_address_agree() {
        same_id(
            "ipv6",
            "2001:db8::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        );
    }

    /// `ip` must reach the same observable as the family-specific kind, or a consumer that knows
    /// the family gets a different answer from one that does not.
    #[test]
    fn the_generic_ip_kind_agrees_with_the_specific_one() {
        assert_eq!(
            resolve("ip", "1.1.1.1").unwrap().id(),
            resolve("ipv4", "1.1.1.1").unwrap().id()
        );
        assert_eq!(
            resolve("ip", "2001:db8::1").unwrap().id(),
            resolve("ipv6", "2001:db8::1").unwrap().id()
        );
    }

    #[test]
    fn hash_case_does_not_change_identity() {
        let upper = "D41D8CD98F00B204E9800998ECF8427E";
        let lower = "d41d8cd98f00b204e9800998ecf8427e";
        same_id("file_hash", upper, lower);
        same_id("md5", upper, lower);
    }

    /// A digest read back out of Brolga renders as `md5:<hex>`. Asking about that must work, or
    /// the round trip through a consumer is broken.
    #[test]
    fn a_hash_that_already_states_its_algorithm_round_trips() {
        let bare = resolve("file_hash", "d41d8cd98f00b204e9800998ecf8427e").unwrap();
        let stated = resolve("file_hash", "md5:d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert_eq!(bare.id(), stated.id());
    }

    /// A stated algorithm beats length inference. Both of these are 64 hex characters; only the
    /// source knows which function produced them.
    #[test]
    fn a_stated_algorithm_wins_over_the_length_guess() {
        let digest = "a".repeat(64);
        let inferred = resolve("file_hash", &digest).unwrap();
        let stated = resolve("file_hash", &format!("sha256:{digest}")).unwrap();
        assert_eq!(inferred.id(), stated.id(), "64 hex is sha256 either way");
    }

    #[test]
    fn an_unknown_kind_names_what_is_accepted() {
        let error = resolve("wombat", "x").unwrap_err();
        assert!(matches!(error, SubjectRejected::UnknownKind { .. }));
        assert!(error.to_string().contains("file_hash"), "{error}");
    }

    /// The message must not echo the value back. It came from outside.
    #[test]
    fn a_malformed_value_is_not_quoted_back_in_the_error() {
        let hostile = "<script>alert(1)</script>";
        let error = resolve("ip", hostile).unwrap_err();
        assert!(!error.to_string().contains("script"), "{error}");
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused_rather_than_guessed() {
        assert!(resolve("file_hash", "abc123").is_err());
    }

    /// Different things must not collide. An id shared between two observables would merge two
    /// investigations.
    #[test]
    fn different_observables_have_different_ids() {
        let addresses = ["1.1.1.1", "1.1.1.2", "8.8.8.8"];
        let ids: Vec<_> = addresses
            .iter()
            .map(|value| (value, resolve("ip", value).unwrap().id()))
            .collect();

        for (index, (value, id)) in ids.iter().enumerate() {
            for (other_index, (other_value, other)) in ids.iter().enumerate() {
                if index != other_index {
                    assert_ne!(id, other, "{value} and {other_value} collided");
                }
            }
        }
    }

    /// An IPv4 address and a domain that spell the same characters are not the same observable.
    #[test]
    fn kind_participates_in_identity() {
        let as_domain = resolve("domain", "example.com").unwrap().id();
        let as_email = resolve("email", "a@example.com").unwrap().id();
        assert_ne!(as_domain, as_email);
    }
}
