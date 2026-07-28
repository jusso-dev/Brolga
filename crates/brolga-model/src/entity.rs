//! Entities: the named things intelligence is about.
//!
//! An entity is a thing with an identity and a name — an actor, a malware family, a campaign, a
//! vulnerability. It is distinct from an [`Observable`](crate::observable::Observable), which is a
//! technical artefact with no identity beyond its own value.
//!
//! # Names are untrusted, and names do not establish identity
//!
//! Every name and alias here is [`UntrustedText`], because it arrives from a feed. Two entities
//! with similar names are not the same entity: the roadmap's design commitments forbid merging
//! actors, malware, campaigns, or organisations on name similarity alone. This module therefore
//! offers no name-based identity at all. [`Entity::derive_id`] requires a naming *authority* plus
//! that authority's identifier for the thing, so `MITRE ATT&CK G0016` and `Vendor X G0016` stay
//! separate records until something with evidence decides otherwise.

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::confidence::ConfidenceBreakdown;
use crate::error::Result;
use crate::id::{Id, Identifiable};
use crate::marking::MarkingSet;
use crate::status::LifecycleStatus;
use crate::temporal::TemporalState;
use crate::text::{ShortText, UntrustedText};
use crate::version::{SchemaTag, VersionedSchema};

/// The kind of thing an [`Entity`] names.
///
/// Deliberately vocabulary-neutral. These are the categories the roadmap names, chosen so that STIX
/// domain objects, MISP galaxies, and ATT&CK groups can each map *onto* them without any of those
/// vocabularies leaking *into* the canonical model.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntityKind {
    /// A person or group conducting activity.
    ThreatActor,
    /// A named family of malicious software.
    MalwareFamily,
    /// A named tool, malicious or dual-use.
    Tool,
    /// A set of activity with a common objective over a period.
    Campaign,
    /// A set of activity attributed to a common origin across campaigns.
    IntrusionSet,
    /// A catalogued weakness, such as a CVE.
    Vulnerability,
    /// A technique, tactic, or procedure.
    AttackTechnique,
    /// Systems used to conduct or support activity.
    Infrastructure,
    /// A person or organisation, whether a source, a target, or a victim.
    Identity,
    /// A discrete security event under investigation.
    Incident,
    /// A published piece of reporting.
    Report,
    /// Something belonging to the operator's own environment.
    Asset,
    /// A geographic place.
    Location,
    /// An industry sector.
    Sector,
}

impl EntityKind {
    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThreatActor => "threat_actor",
            Self::MalwareFamily => "malware_family",
            Self::Tool => "tool",
            Self::Campaign => "campaign",
            Self::IntrusionSet => "intrusion_set",
            Self::Vulnerability => "vulnerability",
            Self::AttackTechnique => "attack_technique",
            Self::Infrastructure => "infrastructure",
            Self::Identity => "identity",
            Self::Incident => "incident",
            Self::Report => "report",
            Self::Asset => "asset",
            Self::Location => "location",
            Self::Sector => "sector",
        }
    }
}

impl core::fmt::Display for EntityKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A named thing that intelligence is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// Canonical identifier.
    pub id: Id<Self>,
    /// What kind of thing this is.
    pub kind: EntityKind,
    /// The primary name, as published. Untrusted.
    pub name: UntrustedText,
    /// Other names this thing is published under. Untrusted, and never merged automatically.
    pub aliases: Vec<UntrustedText>,
    /// Narrative description, as published. Untrusted.
    pub description: Option<UntrustedText>,
    /// Whether this record's assertion still stands.
    pub status: LifecycleStatus,
    /// Observation and validity windows.
    pub temporal: TemporalState,
    /// Confidence in this record, with its components.
    pub confidence: Option<ConfidenceBreakdown>,
    /// Handling restrictions. Always serialised, empty or not.
    pub markings: MarkingSet,
}

impl Identifiable for Entity {
    const ID_KIND: &'static str = "entity";
}

impl VersionedSchema for Entity {
    const SCHEMA_NAME: &'static str = "brolga.entity";
}

impl Entity {
    /// Derive an identifier from a naming authority and that authority's identifier.
    ///
    /// Both parts are required, and neither is the entity's name. Deriving from a name would make
    /// `APT29` and `apt29` and `APT-29` three entities, or worse, make two different groups that a
    /// vendor happened to label identically into one.
    ///
    /// `authority` is the system that assigned the identifier — `mitre-attack`, `nvd`, an
    /// operator's own namespace. `external_id` is that system's identifier for the thing.
    #[must_use]
    pub fn derive_id(kind: EntityKind, authority: &ShortText, external_id: &ShortText) -> Id<Self> {
        Id::derive(&[kind.as_str(), authority.as_str(), external_id.as_str()])
    }

    /// Build an entity with no optional metadata.
    #[must_use]
    pub fn new(id: Id<Self>, kind: EntityKind, name: UntrustedText) -> Self {
        Self {
            schema_version: SchemaTag::new(),
            id,
            kind,
            name,
            aliases: Vec::new(),
            description: None,
            status: LifecycleStatus::Active,
            temporal: TemporalState::unknown(),
            confidence: None,
            markings: MarkingSet::empty(),
        }
    }
}

impl<'de> Deserialize<'de> for Entity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<Entity>,
            id: Id<Entity>,
            kind: EntityKind,
            name: UntrustedText,
            aliases: Vec<UntrustedText>,
            description: Option<UntrustedText>,
            status: LifecycleStatus,
            temporal: TemporalState,
            confidence: Option<ConfidenceBreakdown>,
            markings: MarkingSet,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            schema_version: raw.schema_version,
            id: raw.id,
            kind: raw.kind,
            name: raw.name,
            aliases: raw.aliases,
            description: raw.description,
            status: raw.status,
            temporal: raw.temporal,
            confidence: raw.confidence,
            markings: raw.markings,
        }
        .validated()
        .map_err(D::Error::custom)
    }
}

impl Entity {
    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TimeOrder`](crate::error::ModelError::TimeOrder) if the temporal state
    /// is impossible.
    pub fn validated(self) -> Result<Self> {
        let temporal = self.temporal.validated()?;
        Ok(Self { temporal, ..self })
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
    use crate::confidence::ConfidenceScore;
    use crate::marking::{Marking, TlpLevel};
    use crate::temporal::Timestamp;

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    fn untrusted(value: &str) -> UntrustedText {
        UntrustedText::new(value).unwrap()
    }

    fn sample() -> Entity {
        let id = Entity::derive_id(
            EntityKind::ThreatActor,
            &short("mitre-attack"),
            &short("G0016"),
        );
        Entity {
            aliases: vec![untrusted("Cozy Bear"), untrusted("Nobelium")],
            description: Some(untrusted("Example description.\nSecond line.")),
            temporal: TemporalState::observed(
                Timestamp::parse_rfc3339("2015-01-01T00:00:00Z").unwrap(),
                Timestamp::parse_rfc3339("2024-01-01T00:00:00Z").unwrap(),
            )
            .unwrap(),
            confidence: Some(ConfidenceBreakdown::source_asserted(
                ConfidenceScore::new(80).unwrap(),
            )),
            markings: MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Green)]),
            ..Entity::new(id, EntityKind::ThreatActor, untrusted("APT29"))
        }
    }

    #[test]
    fn identity_comes_from_an_authority_not_from_a_name() {
        let mitre = Entity::derive_id(
            EntityKind::ThreatActor,
            &short("mitre-attack"),
            &short("G0016"),
        );
        let vendor =
            Entity::derive_id(EntityKind::ThreatActor, &short("vendor-x"), &short("G0016"));
        assert_ne!(
            mitre, vendor,
            "the same external id from two authorities is two records until evidence says otherwise"
        );

        let same = Entity::derive_id(
            EntityKind::ThreatActor,
            &short("mitre-attack"),
            &short("G0016"),
        );
        assert_eq!(mitre, same, "derivation must be reproducible");
    }

    #[test]
    fn the_same_external_id_under_two_kinds_is_two_entities() {
        let actor = Entity::derive_id(EntityKind::ThreatActor, &short("vendor"), &short("1"));
        let malware = Entity::derive_id(EntityKind::MalwareFamily, &short("vendor"), &short("1"));
        assert_ne!(actor, malware);
    }

    #[test]
    fn round_trips_through_json() {
        let entity = sample();
        let json = serde_json::to_string(&entity).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entity);
    }

    #[test]
    fn serialised_form_always_carries_schema_version_and_markings() {
        let entity = Entity::new(
            Entity::derive_id(EntityKind::Tool, &short("vendor"), &short("t1")),
            EntityKind::Tool,
            untrusted("Example Tool"),
        );
        let json = serde_json::to_value(&entity).unwrap();

        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.entity/1.0"),
        );
        // Empty, but present: a reader must never be able to mistake absence for "unrestricted".
        assert_eq!(json.get("markings"), Some(&serde_json::json!([])));
        assert!(json.get("confidence").is_some());
        assert!(json.get("description").is_some());
    }

    #[test]
    fn a_payload_from_a_future_major_version_is_rejected() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["schema_version"] = serde_json::json!("brolga.entity/2.0");
        assert!(serde_json::from_value::<Entity>(json).is_err());
    }

    #[test]
    fn a_payload_from_a_newer_minor_version_is_accepted() {
        let mut json = serde_json::to_value(sample()).unwrap();
        json["schema_version"] = serde_json::json!("brolga.entity/1.9");
        assert!(serde_json::from_value::<Entity>(json).is_ok());
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(sample()).unwrap();

        let mut unknown_field = base.clone();
        unknown_field["injected"] = serde_json::json!("x");
        assert!(serde_json::from_value::<Entity>(unknown_field).is_err());

        let mut wrong_id_kind = base.clone();
        wrong_id_kind["id"] = serde_json::json!("claim:00000000-0000-0000-0000-000000000000");
        assert!(serde_json::from_value::<Entity>(wrong_id_kind).is_err());

        let mut missing_markings = base.clone();
        missing_markings.as_object_mut().unwrap().remove("markings");
        assert!(
            serde_json::from_value::<Entity>(missing_markings).is_err(),
            "markings must not be omissible"
        );

        let mut bad_kind = base.clone();
        bad_kind["kind"] = serde_json::json!("wizard");
        assert!(serde_json::from_value::<Entity>(bad_kind).is_err());

        let mut nul_in_name = base.clone();
        nul_in_name["name"] = serde_json::json!("APT\u{0}29");
        assert!(serde_json::from_value::<Entity>(nul_in_name).is_err());

        let mut backwards_time = base;
        backwards_time["temporal"] = serde_json::json!({
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2015-01-01T00:00:00Z",
            "valid_from": null,
            "valid_until": null,
        });
        assert!(serde_json::from_value::<Entity>(backwards_time).is_err());
    }

    #[test]
    fn aliases_are_stored_but_never_used_for_identity() {
        let entity = sample();
        assert_eq!(entity.aliases.len(), 2);
        // Two entities sharing an alias remain distinct records.
        let other = Entity::derive_id(EntityKind::ThreatActor, &short("vendor-y"), &short("Z1"));
        assert_ne!(entity.id, other);
    }
}
