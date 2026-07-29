//! Relationships between canonical nodes.
//!
//! A relationship is directed and typed: `A uses B` and `B uses A` are different statements, and
//! the type carries meaning that a generic edge would throw away.
//!
//! Relationships are first-class records with their own identity, status, confidence, and
//! markings, because a relationship can be revoked, contradicted, or restricted independently of
//! the things it connects. Modelling edges as fields on an entity would make "we no longer believe
//! this connection" impossible to express without rewriting the entity.

use core::fmt;

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::confidence::ConfidenceBreakdown;
use crate::entity::Entity;
use crate::error::Result;
use crate::id::{Id, Identifiable};
use crate::marking::MarkingSet;
use crate::observable::Observable;
use crate::provenance::RecordOrigin;
use crate::status::LifecycleStatus;
use crate::temporal::TemporalState;
use crate::text::UntrustedText;
use crate::version::{SchemaTag, VersionedSchema};

/// One end of a relationship, or the subject of a claim or sighting.
///
/// Adjacently tagged so the referenced kind is explicit on the wire, which means a reader does not
/// have to guess from the identifier prefix and a consumer cannot resolve an entity reference
/// against the observable table.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum NodeRef {
    /// A named thing.
    Entity(Id<Entity>),
    /// A technical artefact.
    Observable(Id<Observable>),
}

impl fmt::Display for NodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entity(id) => write!(f, "{id}"),
            Self::Observable(id) => write!(f, "{id}"),
        }
    }
}

/// The meaning of a relationship.
///
/// Chosen to be source-vocabulary-neutral: a STIX `relationship_type`, a MISP object reference, and
/// an ATT&CK mapping each translate onto these, and none of them appears in the canonical model.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelationshipKind {
    /// The source employs the target.
    Uses,
    /// The source is directed at the target.
    Targets,
    /// The source is attributed to the target.
    AttributedTo,
    /// The source is evidence of the target's presence.
    Indicates,
    /// The source exchanges network traffic with the target.
    CommunicatesWith,
    /// The source resolves to the target.
    ResolvesTo,
    /// The source was retrieved from the target.
    DownloadedFrom,
    /// The source provides the target.
    Hosts,
    /// The source reduces the effect of the target.
    Mitigates,
    /// The source takes advantage of the target.
    Exploits,
    /// The source is a variant of the target.
    VariantOf,
    /// The source impersonates the target.
    Impersonates,
    /// The source is situated at the target.
    LocatedAt,
    /// The source is a component of the target.
    PartOf,
    /// The source was produced from the target by a transformation.
    DerivedFrom,
    /// The source replaces the target.
    Supersedes,
    /// The source and target are believed to be the same thing.
    ///
    /// An assertion with its own confidence and provenance, never an automatic merge. The roadmap
    /// requires that every merge decision stay inspectable, which means recording the claim rather
    /// than silently collapsing two records into one.
    DuplicateOf,
    /// A vulnerability affects a software package, or a package is affected by one.
    ///
    /// Directional and typed rather than `RelatedTo`, because "affects" is the question every
    /// consumer of vulnerability data actually asks, and answering it by filtering a generic edge
    /// means every consumer reimplements the filter.
    Affects,
    /// The source is connected to the target in a way none of the above expresses.
    ///
    /// Not a fallback for a relationship that has a proper kind. It records that a source asserted
    /// a connection without specifying its nature, which is a real thing feeds do.
    RelatedTo,
}

impl RelationshipKind {
    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uses => "uses",
            Self::Targets => "targets",
            Self::AttributedTo => "attributed_to",
            Self::Indicates => "indicates",
            Self::CommunicatesWith => "communicates_with",
            Self::ResolvesTo => "resolves_to",
            Self::DownloadedFrom => "downloaded_from",
            Self::Hosts => "hosts",
            Self::Mitigates => "mitigates",
            Self::Exploits => "exploits",
            Self::VariantOf => "variant_of",
            Self::Impersonates => "impersonates",
            Self::LocatedAt => "located_at",
            Self::PartOf => "part_of",
            Self::DerivedFrom => "derived_from",
            Self::Supersedes => "supersedes",
            Self::DuplicateOf => "duplicate_of",
            Self::Affects => "affects",
            Self::RelatedTo => "related_to",
        }
    }

    /// Whether the relationship means the same thing with its ends exchanged.
    ///
    /// Only `duplicate_of` and `related_to` are symmetric. Everything else is directed, and
    /// treating a directed edge as symmetric would turn "this malware targets this sector" into
    /// "this sector targets this malware".
    #[must_use]
    pub const fn is_symmetric(self) -> bool {
        matches!(self, Self::DuplicateOf | Self::RelatedTo)
    }
}

impl fmt::Display for RelationshipKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directed, typed, independently governed connection between two nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// Canonical identifier.
    pub id: Id<Self>,
    /// What the connection means.
    pub kind: RelationshipKind,
    /// The node the relationship points from.
    pub source: NodeRef,
    /// The node the relationship points to.
    pub target: NodeRef,
    /// Narrative supplied by the publisher. Untrusted.
    pub description: Option<UntrustedText>,
    /// Whether this record's assertion still stands.
    pub status: LifecycleStatus,
    /// Observation and validity windows.
    pub temporal: TemporalState,
    /// Confidence in this record, with its components.
    pub confidence: Option<ConfidenceBreakdown>,
    /// Handling restrictions. Always serialised, empty or not.
    pub markings: MarkingSet,
    /// Where this record came from.
    ///
    /// Not an `Option`. A source-derived record carries mandatory provenance and a synthetic
    /// one says who created it, so a record with no traceable origin is unrepresentable.
    pub origin: RecordOrigin,
}

impl Identifiable for Relationship {
    const ID_KIND: &'static str = "relationship";
}

impl VersionedSchema for Relationship {
    const SCHEMA_NAME: &'static str = "brolga.relationship";
}

impl Relationship {
    /// Derive an identifier from the statement the relationship makes.
    ///
    /// Re-importing the same edge from the same feed produces the same identifier, so ingestion is
    /// idempotent. For a symmetric kind the two endpoints are sorted before derivation, so
    /// `A duplicate_of B` and `B duplicate_of A` are one record rather than two mutually
    /// referencing ones.
    #[must_use]
    pub fn derive_id(kind: RelationshipKind, source: &NodeRef, target: &NodeRef) -> Id<Self> {
        let (first, second) = if kind.is_symmetric() && target < source {
            (target, source)
        } else {
            (source, target)
        };
        Id::derive(&[kind.as_str(), &first.to_string(), &second.to_string()])
    }

    /// Build a relationship with no optional metadata, deriving its identifier.
    #[must_use]
    pub fn new(
        kind: RelationshipKind,
        source: NodeRef,
        target: NodeRef,
        origin: RecordOrigin,
    ) -> Self {
        Self {
            schema_version: SchemaTag::new(),
            id: Self::derive_id(kind, &source, &target),
            kind,
            source,
            target,
            description: None,
            status: LifecycleStatus::Active,
            temporal: TemporalState::unknown(),
            confidence: None,
            markings: MarkingSet::empty(),
            origin,
        }
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`](crate::error::ModelError::InvalidValue) if the
    /// relationship points at itself, and
    /// [`ModelError::TimeOrder`](crate::error::ModelError::TimeOrder) if the temporal state is
    /// impossible.
    pub fn validated(self) -> Result<Self> {
        if self.source == self.target {
            return Err(crate::error::ModelError::invalid(
                "Relationship",
                format_args!(
                    "source and target are both {}; a node cannot be {} itself",
                    self.source, self.kind,
                ),
            ));
        }
        let temporal = self.temporal.validated()?;
        Ok(Self { temporal, ..self })
    }
}

impl<'de> Deserialize<'de> for Relationship {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<Relationship>,
            id: Id<Relationship>,
            kind: RelationshipKind,
            source: NodeRef,
            target: NodeRef,
            description: Option<UntrustedText>,
            status: LifecycleStatus,
            temporal: TemporalState,
            confidence: Option<ConfidenceBreakdown>,
            markings: MarkingSet,
            origin: RecordOrigin,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            schema_version: raw.schema_version,
            id: raw.id,
            kind: raw.kind,
            source: raw.source,
            target: raw.target,
            description: raw.description,
            status: raw.status,
            temporal: raw.temporal,
            confidence: raw.confidence,
            markings: raw.markings,
            origin: raw.origin,
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
    use crate::provenance::{SyntheticOrigin, SyntheticReason};
    use crate::text::ShortText;

    /// A synthetic origin for tests, so records under test declare where they came from without
    /// dragging a whole provenance chain into every case that is about something else.
    fn test_origin() -> RecordOrigin {
        RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::Fixture,
            ShortText::new("brolga-model-tests").expect("valid creator"),
        ))
    }
    use crate::entity::EntityKind;
    use crate::observable::DomainName;

    fn entity_ref(external_id: &str) -> NodeRef {
        NodeRef::Entity(Entity::derive_id(
            EntityKind::ThreatActor,
            &ShortText::new("vendor").unwrap(),
            &ShortText::new(external_id).unwrap(),
        ))
    }

    fn observable_ref(domain: &str) -> NodeRef {
        NodeRef::Observable(Observable::DomainName(DomainName::new(domain).unwrap()).id())
    }

    #[test]
    fn direction_is_part_of_the_statement() {
        let actor = entity_ref("A");
        let domain = observable_ref("example.com");
        let forward = Relationship::derive_id(RelationshipKind::Uses, &actor, &domain);
        let backward = Relationship::derive_id(RelationshipKind::Uses, &domain, &actor);
        assert_ne!(forward, backward);
    }

    #[test]
    fn symmetric_kinds_derive_one_identifier_for_both_orders() {
        let left = entity_ref("A");
        let right = entity_ref("B");
        assert_eq!(
            Relationship::derive_id(RelationshipKind::DuplicateOf, &left, &right),
            Relationship::derive_id(RelationshipKind::DuplicateOf, &right, &left),
        );
        assert_eq!(
            Relationship::derive_id(RelationshipKind::RelatedTo, &left, &right),
            Relationship::derive_id(RelationshipKind::RelatedTo, &right, &left),
        );
    }

    #[test]
    fn only_duplicate_and_related_are_symmetric() {
        assert!(RelationshipKind::DuplicateOf.is_symmetric());
        assert!(RelationshipKind::RelatedTo.is_symmetric());
        for directed in [
            RelationshipKind::Uses,
            RelationshipKind::Targets,
            RelationshipKind::AttributedTo,
            RelationshipKind::Indicates,
            RelationshipKind::ResolvesTo,
            RelationshipKind::Supersedes,
            RelationshipKind::DerivedFrom,
        ] {
            assert!(!directed.is_symmetric(), "{directed} must stay directed");
        }
    }

    #[test]
    fn a_node_cannot_relate_to_itself() {
        let node = entity_ref("A");
        let self_edge = Relationship::new(RelationshipKind::Uses, node, node, test_origin());
        assert!(self_edge.validated().is_err());
    }

    #[test]
    fn an_entity_and_an_observable_reference_are_never_interchangeable() {
        let entity = entity_ref("A");
        let observable = observable_ref("example.com");
        assert_ne!(entity, observable);

        let entity_json = serde_json::to_value(entity).unwrap();
        assert_eq!(
            entity_json.get("type").and_then(serde_json::Value::as_str),
            Some("entity")
        );
    }

    #[test]
    fn round_trips_through_json() {
        let relationship = Relationship::new(
            RelationshipKind::Uses,
            entity_ref("A"),
            observable_ref("example.com"),
            test_origin(),
        );
        let json = serde_json::to_string(&relationship).unwrap();
        let back: Relationship = serde_json::from_str(&json).unwrap();
        assert_eq!(back, relationship);
    }

    #[test]
    fn serialised_form_carries_schema_version_and_markings() {
        let relationship = Relationship::new(
            RelationshipKind::Targets,
            entity_ref("A"),
            entity_ref("B"),
            test_origin(),
        );
        let json = serde_json::to_value(&relationship).unwrap();
        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.relationship/1.0"),
        );
        assert_eq!(json.get("markings"), Some(&serde_json::json!([])));
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(Relationship::new(
            RelationshipKind::Uses,
            entity_ref("A"),
            entity_ref("B"),
            test_origin(),
        ))
        .unwrap();

        let mut self_referential = base.clone();
        self_referential["target"] = base["source"].clone();
        assert!(serde_json::from_value::<Relationship>(self_referential).is_err());

        let mut bad_kind = base.clone();
        bad_kind["kind"] = serde_json::json!("vibes_with");
        assert!(serde_json::from_value::<Relationship>(bad_kind).is_err());

        let mut mismatched_ref = base.clone();
        mismatched_ref["source"] = serde_json::json!({"type": "entity", "id": "observable:00000000-0000-0000-0000-000000000000"});
        assert!(serde_json::from_value::<Relationship>(mismatched_ref).is_err());

        let mut unknown_field = base;
        unknown_field["weight"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Relationship>(unknown_field).is_err());
    }
}
