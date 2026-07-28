//! Sightings: records that something was actually observed.
//!
//! A sighting is evidence of a different kind from a claim. A claim says "this is malicious"; a
//! sighting says "this was seen here, then, this many times". Sightings are what make recency and
//! prevalence answerable, and they are what distinguish an indicator that is live from one that a
//! feed has been republishing for two years.
//!
//! # Why the observer matters
//!
//! `observer` records who saw it. Without that, a hundred sightings republished by a hundred
//! aggregators from one original source look like a hundred independent observations. The roadmap
//! forbids counting known syndicated copies as independent corroboration, and keeping the observer
//! on every sighting is what makes that check possible later.

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::confidence::ConfidenceBreakdown;
use crate::entity::Entity;
use crate::error::{ModelError, Result};
use crate::id::{Id, Identifiable};
use crate::marking::MarkingSet;
use crate::relationship::NodeRef;
use crate::status::LifecycleStatus;
use crate::temporal::{TemporalState, Timestamp};
use crate::version::{SchemaTag, VersionedSchema};

/// How many times something was observed, at least once.
///
/// Zero is not representable. A sighting is a record that something *was* seen, so "seen zero
/// times" is not a weak sighting, it is a malformed one — and permitting it would let a feed pad
/// its apparent prevalence with empty entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SightingCount(u64);

impl SightingCount {
    /// A single observation.
    pub const ONE: Self = Self(1);

    /// Build a count.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ZeroSightingCount`] if `value` is zero.
    pub const fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(ModelError::ZeroSightingCount);
        }
        Ok(Self(value))
    }

    /// The count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for SightingCount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for SightingCount {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SightingCount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = u64::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

impl JsonSchema for SightingCount {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SightingCount".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": 1,
            "description": "How many times the subject was observed. At least one; zero is not a sighting.",
        })
    }
}

/// A record that a subject was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sighting {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// Canonical identifier.
    pub id: Id<Self>,
    /// What was observed.
    pub subject: NodeRef,
    /// Who observed it, if the source said.
    ///
    /// `None` means the source did not identify an observer, which is common in aggregated feeds
    /// and is itself worth knowing: an unattributed sighting cannot contribute to independent
    /// corroboration.
    pub observer: Option<Id<Entity>>,
    /// How many times it was observed in this window.
    pub count: SightingCount,
    /// Start of the observation window.
    pub first_seen: Timestamp,
    /// End of the observation window. Equal to `first_seen` for a single instant.
    pub last_seen: Timestamp,
    /// Whether this record's assertion still stands.
    pub status: LifecycleStatus,
    /// Any further temporal context the source supplied.
    pub temporal: TemporalState,
    /// Confidence in this sighting, with its components.
    pub confidence: Option<ConfidenceBreakdown>,
    /// Handling restrictions. Always serialised, empty or not.
    pub markings: MarkingSet,
}

impl Identifiable for Sighting {
    const ID_KIND: &'static str = "sighting";
}

impl VersionedSchema for Sighting {
    const SCHEMA_NAME: &'static str = "brolga.sighting";
}

impl Sighting {
    /// Derive an identifier from the subject, the observer, and the observation window.
    ///
    /// The observer is part of the derivation, so two observers reporting the same window produce
    /// two sightings. Collapsing them would erase the corroboration signal the observer exists to
    /// carry. An unattributed sighting derives under an explicit `-` marker, which cannot collide
    /// with an entity identifier.
    #[must_use]
    pub fn derive_id(
        subject: &NodeRef,
        observer: Option<&Id<Entity>>,
        first_seen: Timestamp,
        last_seen: Timestamp,
    ) -> Id<Self> {
        let subject = subject.to_string();
        let observer = observer.map_or_else(|| String::from("-"), ToString::to_string);
        Id::derive(&[
            &subject,
            &observer,
            &first_seen.to_rfc3339(),
            &last_seen.to_rfc3339(),
        ])
    }

    /// Build a sighting, deriving its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TimeOrder`] if `first_seen` is later than `last_seen`.
    pub fn new(
        subject: NodeRef,
        observer: Option<Id<Entity>>,
        count: SightingCount,
        first_seen: Timestamp,
        last_seen: Timestamp,
    ) -> Result<Self> {
        Self {
            schema_version: SchemaTag::new(),
            id: Self::derive_id(&subject, observer.as_ref(), first_seen, last_seen),
            subject,
            observer,
            count,
            first_seen,
            last_seen,
            status: LifecycleStatus::Active,
            temporal: TemporalState::unknown(),
            confidence: None,
            markings: MarkingSet::empty(),
        }
        .validated()
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TimeOrder`] if `first_seen` is later than `last_seen`, or if the
    /// additional temporal state is impossible.
    pub fn validated(self) -> Result<Self> {
        if self.first_seen > self.last_seen {
            return Err(ModelError::TimeOrder {
                earlier: "first_seen",
                earlier_value: self.first_seen.to_rfc3339(),
                later: "last_seen",
                later_value: self.last_seen.to_rfc3339(),
            });
        }
        let temporal = self.temporal.validated()?;
        Ok(Self { temporal, ..self })
    }
}

impl<'de> Deserialize<'de> for Sighting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<Sighting>,
            id: Id<Sighting>,
            subject: NodeRef,
            observer: Option<Id<Entity>>,
            count: SightingCount,
            first_seen: Timestamp,
            last_seen: Timestamp,
            status: LifecycleStatus,
            temporal: TemporalState,
            confidence: Option<ConfidenceBreakdown>,
            markings: MarkingSet,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            schema_version: raw.schema_version,
            id: raw.id,
            subject: raw.subject,
            observer: raw.observer,
            count: raw.count,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            status: raw.status,
            temporal: raw.temporal,
            confidence: raw.confidence,
            markings: raw.markings,
        }
        .validated()
        .map_err(D::Error::custom)
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
    use crate::entity::EntityKind;
    use crate::observable::{DomainName, Observable};
    use crate::text::ShortText;

    fn subject() -> NodeRef {
        NodeRef::Observable(Observable::DomainName(DomainName::new("example.com").unwrap()).id())
    }

    fn observer(name: &str) -> Id<Entity> {
        Entity::derive_id(
            EntityKind::Identity,
            &ShortText::new("vendor").unwrap(),
            &ShortText::new(name).unwrap(),
        )
    }

    fn at(value: &str) -> Timestamp {
        Timestamp::parse_rfc3339(value).unwrap()
    }

    #[test]
    fn a_sighting_of_zero_is_not_a_sighting() {
        assert!(matches!(
            SightingCount::new(0),
            Err(ModelError::ZeroSightingCount)
        ));
        assert_eq!(SightingCount::new(1).unwrap(), SightingCount::ONE);
        assert!(serde_json::from_str::<SightingCount>("0").is_err());
        assert!(serde_json::from_str::<SightingCount>("-1").is_err());
    }

    #[test]
    fn two_observers_of_the_same_window_are_two_sightings() {
        // Collapsing them would erase exactly the signal that separates corroboration from copying.
        let window = (at("2024-01-01T00:00:00Z"), at("2024-01-02T00:00:00Z"));
        let first = Sighting::derive_id(&subject(), Some(&observer("a")), window.0, window.1);
        let second = Sighting::derive_id(&subject(), Some(&observer("b")), window.0, window.1);
        assert_ne!(first, second);
    }

    #[test]
    fn an_unattributed_sighting_does_not_collide_with_an_attributed_one() {
        let window = (at("2024-01-01T00:00:00Z"), at("2024-01-02T00:00:00Z"));
        let anonymous = Sighting::derive_id(&subject(), None, window.0, window.1);
        let attributed = Sighting::derive_id(&subject(), Some(&observer("a")), window.0, window.1);
        assert_ne!(anonymous, attributed);
    }

    #[test]
    fn the_same_observer_and_window_derive_one_identifier() {
        let window = (at("2024-01-01T00:00:00Z"), at("2024-01-02T00:00:00Z"));
        assert_eq!(
            Sighting::derive_id(&subject(), Some(&observer("a")), window.0, window.1),
            Sighting::derive_id(&subject(), Some(&observer("a")), window.0, window.1),
        );
    }

    #[test]
    fn different_windows_are_different_sightings() {
        let observer = observer("a");
        assert_ne!(
            Sighting::derive_id(
                &subject(),
                Some(&observer),
                at("2024-01-01T00:00:00Z"),
                at("2024-01-02T00:00:00Z"),
            ),
            Sighting::derive_id(
                &subject(),
                Some(&observer),
                at("2024-02-01T00:00:00Z"),
                at("2024-02-02T00:00:00Z"),
            ),
        );
    }

    #[test]
    fn an_observation_window_cannot_run_backwards() {
        let error = Sighting::new(
            subject(),
            None,
            SightingCount::ONE,
            at("2024-01-02T00:00:00Z"),
            at("2024-01-01T00:00:00Z"),
        )
        .unwrap_err();
        assert!(matches!(error, ModelError::TimeOrder { .. }), "{error:?}");
    }

    #[test]
    fn a_single_instant_is_a_valid_window() {
        let instant = at("2024-01-01T00:00:00Z");
        assert!(Sighting::new(subject(), None, SightingCount::ONE, instant, instant).is_ok());
    }

    #[test]
    fn round_trips_through_json() {
        let sighting = Sighting::new(
            subject(),
            Some(observer("a")),
            SightingCount::new(42).unwrap(),
            at("2024-01-01T00:00:00Z"),
            at("2024-01-02T00:00:00Z"),
        )
        .unwrap();
        let json = serde_json::to_string(&sighting).unwrap();
        let back: Sighting = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sighting);
    }

    #[test]
    fn serialised_form_carries_schema_version_and_markings() {
        let sighting = Sighting::new(
            subject(),
            None,
            SightingCount::ONE,
            at("2024-01-01T00:00:00Z"),
            at("2024-01-01T00:00:00Z"),
        )
        .unwrap();
        let json = serde_json::to_value(&sighting).unwrap();
        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.sighting/1.0"),
        );
        assert_eq!(json.get("markings"), Some(&serde_json::json!([])));
        assert_eq!(json.get("observer"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(
            Sighting::new(
                subject(),
                None,
                SightingCount::ONE,
                at("2024-01-01T00:00:00Z"),
                at("2024-01-02T00:00:00Z"),
            )
            .unwrap(),
        )
        .unwrap();

        let mut zero_count = base.clone();
        zero_count["count"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Sighting>(zero_count).is_err());

        let mut backwards = base.clone();
        backwards["first_seen"] = serde_json::json!("2025-01-01T00:00:00Z");
        assert!(serde_json::from_value::<Sighting>(backwards).is_err());

        let mut wrong_observer_kind = base.clone();
        wrong_observer_kind["observer"] =
            serde_json::json!("claim:00000000-0000-0000-0000-000000000000");
        assert!(serde_json::from_value::<Sighting>(wrong_observer_kind).is_err());

        let mut unknown_field = base;
        unknown_field["source_feed"] = serde_json::json!("x");
        assert!(serde_json::from_value::<Sighting>(unknown_field).is_err());
    }
}
