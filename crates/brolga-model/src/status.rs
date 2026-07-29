//! Lifecycle status and disposition.
//!
//! These are two different questions that are often conflated. [`LifecycleStatus`] is about the
//! *record*: is this assertion still standing, or has it been withdrawn or replaced?
//! [`Disposition`] is about the *subject*: is this thing malicious?
//!
//! A revoked record asserting `Malicious` and an active record asserting `Benign` are not the same
//! statement, and collapsing them into one field is how "we no longer believe this" turns into
//! "this is safe".

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Whether a record's assertion still stands.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LifecycleStatus {
    /// The assertion stands.
    #[default]
    Active,
    /// The publisher withdrew the assertion. It was wrong, not merely old.
    Revoked,
    /// A later record replaced this one. The subject is still described, by something else.
    Superseded,
    /// The assertion's validity window has closed. It was right, and is no longer current.
    Expired,
    /// The publisher discourages new use but has not withdrawn the assertion.
    Deprecated,
}

impl LifecycleStatus {
    /// Every status.
    ///
    /// See [`crate::EntityKind::all`] for why this exists rather than being spelled out at each
    /// call site.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Active,
            Self::Revoked,
            Self::Superseded,
            Self::Expired,
            Self::Deprecated,
        ]
    }

    /// Whether the assertion currently stands.
    ///
    /// The three false cases are distinct and are kept distinct in the type. A caller that only
    /// needs "should I act on this" uses this method; a caller that needs to explain *why not*
    /// matches on the variant.
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::Active | Self::Deprecated)
    }

    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Deprecated => "deprecated",
        }
    }
}

impl fmt::Display for LifecycleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An assessment of whether a subject is malicious.
///
/// There is no default. A subject that has not been assessed is [`Disposition::Unknown`], and the
/// roadmap's design commitments are explicit that presence in a feed is not itself evidence of
/// maliciousness — so an unassessed indicator must never quietly become `Malicious` because it
/// appeared in an import.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Disposition {
    /// Assessed as malicious.
    Malicious,
    /// Assessed as warranting attention without a malicious finding.
    Suspicious,
    /// Assessed as not malicious.
    Benign,
    /// Explicitly excluded from detection, for example because it is known-good infrastructure.
    ///
    /// Distinct from `Benign`: benign is a finding about the subject, allow-listed is a decision
    /// about how Brolga treats it regardless of the finding.
    AllowListed,
    /// Not assessed.
    Unknown,
}

impl Disposition {
    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Benign => "benign",
            Self::AllowListed => "allow_listed",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    fn withdrawn_and_stale_records_are_not_current() {
        assert!(LifecycleStatus::Active.is_current());
        assert!(LifecycleStatus::Deprecated.is_current());
        assert!(!LifecycleStatus::Revoked.is_current());
        assert!(!LifecycleStatus::Superseded.is_current());
        assert!(!LifecycleStatus::Expired.is_current());
    }

    #[test]
    fn the_reasons_a_record_is_not_current_stay_distinguishable() {
        // Collapsing these to a boolean loses the difference between "was wrong" and "is old".
        assert_ne!(LifecycleStatus::Revoked, LifecycleStatus::Expired);
        assert_ne!(LifecycleStatus::Superseded, LifecycleStatus::Revoked);
    }

    #[test]
    fn status_defaults_to_active_and_disposition_has_no_default() {
        assert_eq!(LifecycleStatus::default(), LifecycleStatus::Active);
        // `Disposition` deliberately does not implement `Default`; an unassessed subject must be
        // written as `Unknown` at the call site, visibly.
        assert_eq!(Disposition::Unknown.as_str(), "unknown");
    }

    #[test]
    fn allow_listed_is_not_the_same_as_benign() {
        assert_ne!(Disposition::AllowListed, Disposition::Benign);
    }

    #[test]
    fn round_trip_and_wire_names_are_stable() {
        for (status, wire) in [
            (LifecycleStatus::Active, "active"),
            (LifecycleStatus::Revoked, "revoked"),
            (LifecycleStatus::Superseded, "superseded"),
            (LifecycleStatus::Expired, "expired"),
            (LifecycleStatus::Deprecated, "deprecated"),
        ] {
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{wire}\"")
            );
            assert_eq!(status.as_str(), wire);
            let back: LifecycleStatus = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, status);
        }

        for (disposition, wire) in [
            (Disposition::Malicious, "malicious"),
            (Disposition::Suspicious, "suspicious"),
            (Disposition::Benign, "benign"),
            (Disposition::AllowListed, "allow_listed"),
            (Disposition::Unknown, "unknown"),
        ] {
            assert_eq!(
                serde_json::to_string(&disposition).unwrap(),
                format!("\"{wire}\"")
            );
            assert_eq!(disposition.as_str(), wire);
        }
    }

    #[test]
    fn rejects_unknown_variants() {
        assert!(serde_json::from_str::<LifecycleStatus>("\"deleted\"").is_err());
        assert!(serde_json::from_str::<Disposition>("\"probably_bad\"").is_err());
        assert!(serde_json::from_str::<Disposition>("1").is_err());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod all_variants_tests {
    use super::LifecycleStatus;

    /// See the equivalent in `entity.rs`: the wildcard-free `match` is what makes a new variant a
    /// build failure rather than a silently unreachable filter value.
    #[test]
    fn every_lifecycle_status_appears_in_all() {
        for status in LifecycleStatus::all() {
            match status {
                LifecycleStatus::Active
                | LifecycleStatus::Revoked
                | LifecycleStatus::Superseded
                | LifecycleStatus::Expired
                | LifecycleStatus::Deprecated => {}
            }
        }
        assert_eq!(LifecycleStatus::all().len(), 5);
    }
}
