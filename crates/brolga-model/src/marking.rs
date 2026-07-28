//! Handling restrictions attached to canonical records.
//!
//! Markings decide what may leave Brolga and to whom, so they are policy-relevant metadata in the
//! sense ADR 0001 and the roadmap use the phrase. Two consequences follow, and both are enforced
//! here rather than left to callers:
//!
//! - **A marking set is always serialised.** No `skip_serializing_if`, no `Option`. An empty set is
//!   written as `[]`, so a consumer can tell "no restrictions were recorded" from "this build did
//!   not emit the field". A missing markings field must never be readable as "unrestricted".
//! - **Combining marked material takes the most restrictive marking, never the average.** See
//!   [`MarkingSet::most_restrictive_tlp`].

use core::fmt;
use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::text::ShortText;

/// Traffic Light Protocol 2.0 sharing level.
///
/// Ordered from least to most restrictive, so `Ord` is a restrictiveness comparison and
/// [`Iterator::max`] over a set of levels yields the one that governs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TlpLevel {
    /// Unlimited disclosure.
    Clear,
    /// Disclosure limited to the community.
    Green,
    /// Limited disclosure, restricted to participants' organisations.
    Amber,
    /// Limited disclosure, restricted to participants' organisation only.
    AmberStrict,
    /// Not for disclosure, restricted to participants only.
    Red,
}

impl TlpLevel {
    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::AmberStrict => "amber_strict",
            Self::Red => "red",
        }
    }
}

impl fmt::Display for TlpLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLP:{}", self.as_str().to_uppercase().replace('_', "+"))
    }
}

/// Permissible Actions Protocol level: what may be *done* with intelligence, as distinct from who
/// may see it.
///
/// Ordered from least to most restrictive, for the same reason as [`TlpLevel`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PapLevel {
    /// No restriction on action.
    Clear,
    /// Action permitted if it cannot be attributed to the source.
    Green,
    /// Passive action only; active action requires approval.
    Amber,
    /// No action that could be detected by the subject.
    Red,
}

/// A single handling restriction.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum Marking {
    /// A Traffic Light Protocol sharing level.
    Tlp(TlpLevel),
    /// A Permissible Actions Protocol level.
    Pap(PapLevel),
    /// A free-text handling instruction from the source, such as a licence or caveat.
    ///
    /// [`ShortText`], not narrative: a handling instruction that needs paragraphs is not
    /// machine-actionable, and storing it here would suggest Brolga enforces something it cannot.
    Handling(ShortText),
    /// An attribution statement that must accompany any redistribution.
    Attribution(ShortText),
}

/// The set of markings on a record.
///
/// A `BTreeSet`, so the serialised order is deterministic and a fingerprint taken over a record
/// does not change because markings were inserted in a different order.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct MarkingSet(BTreeSet<Marking>);

impl MarkingSet {
    /// An empty set.
    ///
    /// Empty means "no restriction was recorded", which is not the same as "the source said it is
    /// unrestricted". A source that explicitly published TLP:CLEAR should carry
    /// `Marking::Tlp(TlpLevel::Clear)`, and policy code can then tell the two apart.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Build a set from any iterator of markings.
    #[must_use]
    pub fn from_iter_of(markings: impl IntoIterator<Item = Marking>) -> Self {
        Self(markings.into_iter().collect())
    }

    /// Add a marking. Returns whether it was newly inserted.
    pub fn insert(&mut self, marking: Marking) -> bool {
        self.0.insert(marking)
    }

    /// Iterate the markings in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &Marking> {
        self.0.iter()
    }

    /// Number of markings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no marking is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The most restrictive TLP level present, or `None` if no TLP marking is recorded.
    ///
    /// `None` means "unmarked", and a caller must not read it as TLP:CLEAR. Deciding what an
    /// unmarked record may do is a policy decision, and policy is not this crate's job.
    #[must_use]
    pub fn most_restrictive_tlp(&self) -> Option<TlpLevel> {
        self.0
            .iter()
            .filter_map(|marking| match marking {
                Marking::Tlp(level) => Some(*level),
                _ => None,
            })
            .max()
    }

    /// The most restrictive PAP level present, or `None` if no PAP marking is recorded.
    #[must_use]
    pub fn most_restrictive_pap(&self) -> Option<PapLevel> {
        self.0
            .iter()
            .filter_map(|marking| match marking {
                Marking::Pap(level) => Some(*level),
                _ => None,
            })
            .max()
    }

    /// The union of two marking sets.
    ///
    /// Used when material from several sources is combined. Every restriction from every
    /// contributor is carried forward: a derived record is at least as restricted as the most
    /// restricted thing it was derived from. Nothing here can loosen a marking, by construction.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).cloned().collect())
    }
}

impl FromIterator<Marking> for MarkingSet {
    fn from_iter<I: IntoIterator<Item = Marking>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'de> Deserialize<'de> for MarkingSet {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        // A sequence, so duplicates in a hostile payload collapse rather than being rejected;
        // a repeated marking is redundant, not dangerous.
        let markings = Vec::<Marking>::deserialize(deserializer)?;
        Ok(Self(markings.into_iter().collect()))
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

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    #[test]
    fn tlp_ordering_is_by_restrictiveness() {
        assert!(TlpLevel::Clear < TlpLevel::Green);
        assert!(TlpLevel::Green < TlpLevel::Amber);
        assert!(TlpLevel::Amber < TlpLevel::AmberStrict);
        assert!(TlpLevel::AmberStrict < TlpLevel::Red);
    }

    #[test]
    fn combining_takes_the_most_restrictive_level_not_the_average() {
        let markings = MarkingSet::from_iter_of([
            Marking::Tlp(TlpLevel::Clear),
            Marking::Tlp(TlpLevel::Red),
            Marking::Tlp(TlpLevel::Green),
        ]);
        assert_eq!(markings.most_restrictive_tlp(), Some(TlpLevel::Red));
    }

    #[test]
    fn an_unmarked_set_reports_none_rather_than_clear() {
        // The distinction matters: "nobody said" is not "somebody said it is public".
        let markings = MarkingSet::empty();
        assert_eq!(markings.most_restrictive_tlp(), None);
        assert_eq!(markings.most_restrictive_pap(), None);

        let explicit = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Clear)]);
        assert_eq!(explicit.most_restrictive_tlp(), Some(TlpLevel::Clear));
    }

    #[test]
    fn union_never_loosens() {
        let public = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Clear)]);
        let restricted = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
        let combined = public.union(&restricted);
        assert_eq!(combined.most_restrictive_tlp(), Some(TlpLevel::Red));
        assert_eq!(combined.len(), 2, "both source markings are retained");
    }

    #[test]
    fn an_empty_set_serialises_as_an_empty_array_not_as_absent() {
        let json = serde_json::to_value(MarkingSet::empty()).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[test]
    fn serialised_order_is_deterministic_regardless_of_insertion_order() {
        let one = MarkingSet::from_iter_of([
            Marking::Tlp(TlpLevel::Red),
            Marking::Attribution(short("Example CERT")),
            Marking::Pap(PapLevel::Amber),
        ]);
        let two = MarkingSet::from_iter_of([
            Marking::Pap(PapLevel::Amber),
            Marking::Attribution(short("Example CERT")),
            Marking::Tlp(TlpLevel::Red),
        ]);
        assert_eq!(
            serde_json::to_string(&one).unwrap(),
            serde_json::to_string(&two).unwrap(),
        );
    }

    #[test]
    fn round_trips_through_json() {
        let markings = MarkingSet::from_iter_of([
            Marking::Tlp(TlpLevel::AmberStrict),
            Marking::Pap(PapLevel::Red),
            Marking::Handling(short("Do not share with vendors")),
            Marking::Attribution(short("Example CERT")),
        ]);
        let json = serde_json::to_string(&markings).unwrap();
        let back: MarkingSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, markings);
    }

    #[test]
    fn duplicates_in_a_payload_collapse() {
        let json = r#"[{"type":"tlp","value":"red"},{"type":"tlp","value":"red"}]"#;
        let markings: MarkingSet = serde_json::from_str(json).unwrap();
        assert_eq!(markings.len(), 1);
    }

    #[test]
    fn rejects_unknown_marking_types_and_levels() {
        for hostile in [
            r#"[{"type":"tlp","value":"purple"}]"#,
            r#"[{"type":"unknown","value":"x"}]"#,
            r#"[{"type":"tlp","value":"red","extra":1}]"#,
            r#"[{"type":"handling","value":"line\nbreak"}]"#,
            r#"{"tlp":"red"}"#,
        ] {
            assert!(
                serde_json::from_str::<MarkingSet>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn tlp_display_uses_the_conventional_rendering() {
        assert_eq!(TlpLevel::Clear.to_string(), "TLP:CLEAR");
        assert_eq!(TlpLevel::AmberStrict.to_string(), "TLP:AMBER+STRICT");
    }
}
