//! Provenance: how a canonical record connects back to the evidence it came from.
//!
//! # The promise this module implements
//!
//! Brolga's defining promise is that compression never breaks the chain back to original evidence.
//! A chain that a record is merely *allowed* to carry is not a chain; it is a convention, and
//! conventions are followed until the day they are not. So the connection is made structural:
//!
//! - [`RecordOrigin`] has exactly two cases. A record is either derived from evidence, in which
//!   case it carries a [`Provenance`], or it is [`SyntheticOrigin`], in which case it says who made
//!   it up and why. **There is no third case, and no `Option`.** A source-derived record without
//!   provenance is not a validation failure to be caught later — it is unrepresentable.
//! - Every [`EvidenceReference`] inside a `Provenance` must cite a source object that the same
//!   `Provenance` lists. A dangling citation is rejected, so "expand this back to its source" can
//!   never resolve to nothing.
//! - Generated narrative must cite evidence: [`GeneratedContent`] cannot be constructed with an
//!   empty evidence list.
//!
//! # What is deliberately not here
//!
//! Blob storage. A [`SourceObject`] addresses evidence by content hash and records what it was and
//! where it came from; retaining, compressing, and retrieving the bytes is `v0.2.0`'s work. The
//! split is what lets provenance be correct before there is anywhere to put the bytes.

pub mod evidence;
pub mod hash;
pub mod source;
pub mod transformation;

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

pub use evidence::{
    EvidenceLocator, EvidenceReference, GeneratedContent, GenerationMethod, OriginalRepresentation,
};
pub use hash::ContentHash;
pub use source::{MediaType, SensitiveText, SourceObject, SourceOrigin};
pub use transformation::{TransformationChain, TransformationStage, TransformationStep};

use crate::error::{ModelError, Result};
use crate::id::Id;
use crate::temporal::Timestamp;
use crate::text::ShortText;
use crate::version::{SchemaTag, VersionedSchema};

/// Maximum number of source objects one record may cite.
pub const MAX_SOURCE_OBJECTS: usize = 64;

/// The evidence and transformation history behind a source-derived record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// The evidence this record was built from. Never empty.
    ///
    /// More than one means the record was built from several pieces of evidence — not that several
    /// sources independently corroborated it. Corroboration is a question about how many
    /// *independent* publishers those objects came from, which the source objects' origins answer
    /// and this list does not.
    pub source_objects: Vec<Id<SourceObject>>,
    /// What was done to the evidence, in order.
    pub chain: TransformationChain,
    /// What the source wrote, for fields that canonicalisation changed.
    pub original: OriginalRepresentation,
    /// Precise citations into the evidence.
    pub evidence: Vec<EvidenceReference>,
    /// Set when the record's content was produced rather than copied.
    pub generated: Option<GeneratedContent>,
}

impl VersionedSchema for Provenance {
    const SCHEMA_NAME: &'static str = "brolga.provenance";
}

impl Provenance {
    /// Build provenance from one source object and a transformation chain.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] or [`ModelError::TooLong`] as [`Provenance::validated`]
    /// describes.
    pub fn from_source(
        source_object: Id<SourceObject>,
        chain: TransformationChain,
    ) -> Result<Self> {
        Self {
            schema_version: SchemaTag::new(),
            source_objects: vec![source_object],
            chain,
            original: OriginalRepresentation::empty(),
            evidence: vec![EvidenceReference::whole(source_object)],
            generated: None,
        }
        .validated()
    }

    /// Record what the source wrote for a canonical field that canonicalisation changed.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`] if too many originals are already recorded.
    pub fn record_original(
        &mut self,
        field: &ShortText,
        original: crate::text::UntrustedText,
    ) -> Result<()> {
        self.original.record(field, original)
    }

    /// Add a citation.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the reference cites a source object this provenance
    /// does not list, and [`ModelError::TooLong`] beyond
    /// [`MAX_EVIDENCE_REFERENCES`](evidence::MAX_EVIDENCE_REFERENCES).
    pub fn cite(&mut self, reference: EvidenceReference) -> Result<()> {
        if !self.source_objects.contains(&reference.source_object) {
            return Err(ModelError::invalid(
                "Provenance",
                format_args!(
                    "citation names source object {}, which this provenance does not list",
                    reference.source_object,
                ),
            ));
        }
        if self.evidence.len() >= evidence::MAX_EVIDENCE_REFERENCES {
            return Err(ModelError::TooLong {
                field: "Provenance evidence",
                max: evidence::MAX_EVIDENCE_REFERENCES,
                actual: self.evidence.len().saturating_add(1),
            });
        }
        self.evidence.push(reference);
        Ok(())
    }

    /// Whether any of this record's content was produced by a language model.
    ///
    /// Callers rendering to an analyst or an agent use this to label output. Model-generated and
    /// deterministic content must never be presented as the same kind of thing.
    #[must_use]
    pub fn is_model_generated(&self) -> bool {
        self.generated
            .as_ref()
            .is_some_and(GeneratedContent::is_model_generated)
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] if no source object is listed, [`ModelError::TooLong`] beyond
    /// [`MAX_SOURCE_OBJECTS`] or the evidence limit, and [`ModelError::InvalidValue`] if any
    /// citation — including one inside [`GeneratedContent`] — names a source object this provenance
    /// does not list.
    pub fn validated(self) -> Result<Self> {
        if self.source_objects.is_empty() {
            return Err(ModelError::Empty {
                field: "Provenance source_objects",
            });
        }
        if self.source_objects.len() > MAX_SOURCE_OBJECTS {
            return Err(ModelError::TooLong {
                field: "Provenance source_objects",
                max: MAX_SOURCE_OBJECTS,
                actual: self.source_objects.len(),
            });
        }
        if self.evidence.len() > evidence::MAX_EVIDENCE_REFERENCES {
            return Err(ModelError::TooLong {
                field: "Provenance evidence",
                max: evidence::MAX_EVIDENCE_REFERENCES,
                actual: self.evidence.len(),
            });
        }

        // Every citation must resolve. This is what makes "expand back to source" total rather
        // than best-effort: a reference that names an object the record does not carry would be a
        // dead link at exactly the moment an analyst needed to follow it.
        let cited = self
            .evidence
            .iter()
            .map(|reference| &reference.source_object)
            .chain(
                self.generated
                    .iter()
                    .flat_map(|generated| generated.evidence.iter())
                    .map(|reference| &reference.source_object),
            );

        for source_object in cited {
            if !self.source_objects.contains(source_object) {
                return Err(ModelError::invalid(
                    "Provenance",
                    format_args!(
                        "citation names source object {source_object}, which this provenance does not list"
                    ),
                ));
            }
        }

        Ok(Self {
            chain: self.chain.validated()?,
            original: self.original.validated()?,
            ..self
        })
    }
}

impl<'de> Deserialize<'de> for Provenance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<Provenance>,
            source_objects: Vec<Id<SourceObject>>,
            chain: TransformationChain,
            original: OriginalRepresentation,
            evidence: Vec<EvidenceReference>,
            generated: Option<GeneratedContent>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            schema_version: raw.schema_version,
            source_objects: raw.source_objects,
            chain: raw.chain,
            original: raw.original,
            evidence: raw.evidence,
            generated: raw.generated,
        }
        .validated()
        .map_err(D::Error::custom)
    }
}

/// Why a record exists when it did not come from imported evidence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SyntheticReason {
    /// An operator entered it directly.
    OperatorEntered,
    /// Brolga derived it from other canonical records rather than from evidence.
    ///
    /// The records it was derived from are reachable through the relationships that connect them;
    /// this variant records that no *external* evidence underlies it.
    DerivedFromCanonical,
    /// It exists to support a test or a demonstration.
    ///
    /// An explicit variant rather than a convention, so a fixture that escapes into a real database
    /// is identifiable rather than indistinguishable from operator input.
    Fixture,
}

/// A record Brolga or an operator created, with no upstream evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyntheticOrigin {
    /// Why the record exists.
    pub reason: SyntheticReason,
    /// What created it: an operator identifier, or a Brolga component.
    pub creator: ShortText,
    /// When it was created. Runtime metadata; excluded from deterministic fingerprints.
    pub created_at: Option<Timestamp>,
}

impl SyntheticOrigin {
    /// Build a synthetic origin.
    #[must_use]
    pub const fn new(reason: SyntheticReason, creator: ShortText) -> Self {
        Self {
            reason,
            creator,
            created_at: None,
        }
    }
}

/// Where a canonical record came from.
///
/// Two cases, no `Option`, no third. This is the type that makes "canonical items require
/// provenance references where source-derived" a property of the model rather than a rule somebody
/// has to remember: constructing a source-derived record without provenance does not compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum RecordOrigin {
    /// Derived from imported evidence. Carries mandatory provenance.
    ///
    /// Boxed because [`Provenance`] is much larger than [`SyntheticOrigin`], and an unboxed variant
    /// would make every record — synthetic ones included — pay for the larger case.
    SourceDerived {
        /// The evidence and transformation history.
        provenance: Box<Provenance>,
    },
    /// Created inside Brolga, with no upstream evidence.
    Synthetic {
        /// Who made it and why.
        origin: SyntheticOrigin,
    },
}

impl RecordOrigin {
    /// Wrap provenance as a source-derived origin.
    #[must_use]
    pub fn source_derived(provenance: Provenance) -> Self {
        Self::SourceDerived {
            provenance: Box::new(provenance),
        }
    }

    /// Build a synthetic origin.
    #[must_use]
    pub const fn synthetic(origin: SyntheticOrigin) -> Self {
        Self::Synthetic { origin }
    }

    /// The provenance, if this record came from evidence.
    #[must_use]
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            Self::SourceDerived { provenance } => Some(provenance),
            Self::Synthetic { .. } => None,
        }
    }

    /// Whether this record traces back to imported evidence.
    #[must_use]
    pub const fn is_source_derived(&self) -> bool {
        matches!(self, Self::SourceDerived { .. })
    }

    /// The source objects this record cites, or an empty slice for a synthetic record.
    #[must_use]
    pub fn source_objects(&self) -> &[Id<SourceObject>] {
        self.provenance()
            .map_or(&[], |provenance| &provenance.source_objects)
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
    use crate::text::UntrustedText;

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    fn source(bytes: &[u8]) -> Id<SourceObject> {
        SourceObject::derive_id(ContentHash::of(bytes))
    }

    fn chain() -> TransformationChain {
        TransformationChain::new(vec![
            TransformationStep::new(
                TransformationStage::Parsing,
                short("brolga.parse.stix21"),
                1,
            ),
            TransformationStep::new(
                TransformationStage::Canonicalisation,
                short("brolga.canonicalise.domain"),
                1,
            ),
        ])
        .unwrap()
    }

    fn sample() -> Provenance {
        Provenance::from_source(source(b"bundle"), chain()).unwrap()
    }

    #[test]
    fn a_source_derived_record_cannot_exist_without_provenance() {
        // Structural, not validated: `RecordOrigin::SourceDerived` has a non-optional `Provenance`
        // field, so there is no value of this type that is source-derived and has none.
        let origin = RecordOrigin::source_derived(sample());
        assert!(origin.is_source_derived());
        assert!(origin.provenance().is_some());
        assert_eq!(origin.source_objects().len(), 1);
    }

    #[test]
    fn a_synthetic_record_says_who_made_it_and_why() {
        let origin = RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::OperatorEntered,
            short("analyst@example"),
        ));
        assert!(!origin.is_source_derived());
        assert!(origin.provenance().is_none());
        assert!(origin.source_objects().is_empty());
    }

    #[test]
    fn provenance_needs_at_least_one_source_object() {
        let mut orphan = sample();
        orphan.source_objects.clear();
        orphan.evidence.clear();
        assert!(matches!(orphan.validated(), Err(ModelError::Empty { .. })));
    }

    #[test]
    fn a_citation_that_resolves_to_nothing_is_rejected() {
        // "Expand back to source" must be total. A dangling citation is a dead link at exactly the
        // moment an analyst needs to follow it.
        let mut provenance = sample();
        let error = provenance
            .cite(EvidenceReference::whole(source(b"never-listed")))
            .unwrap_err();
        assert!(error.to_string().contains("does not list"), "{error}");

        provenance
            .evidence
            .push(EvidenceReference::whole(source(b"never-listed")));
        assert!(provenance.validated().is_err());
    }

    #[test]
    fn generated_content_citations_must_resolve_too() {
        let mut provenance = sample();
        provenance.generated = Some(
            GeneratedContent::new(
                GenerationMethod::LanguageModel,
                short("example-model"),
                1,
                vec![EvidenceReference::whole(source(b"never-listed"))],
            )
            .unwrap(),
        );
        assert!(
            provenance.validated().is_err(),
            "a generated summary must not cite evidence the record does not carry"
        );
    }

    #[test]
    fn citations_to_listed_objects_are_accepted() {
        let mut provenance = sample();
        let listed = source(b"bundle");
        provenance
            .cite(EvidenceReference::at(listed, EvidenceLocator::line(3).unwrap()).unwrap())
            .unwrap();
        assert_eq!(provenance.evidence.len(), 2);
        assert!(provenance.validated().is_ok());
    }

    #[test]
    fn model_generated_content_is_visible_from_the_provenance() {
        let mut provenance = sample();
        assert!(!provenance.is_model_generated());

        provenance.generated = Some(
            GeneratedContent::new(
                GenerationMethod::LanguageModel,
                short("example-model"),
                1,
                vec![EvidenceReference::whole(source(b"bundle"))],
            )
            .unwrap(),
        );
        assert!(provenance.is_model_generated());
    }

    #[test]
    fn original_values_survive_canonicalisation() {
        // The #4 acceptance criterion, end to end through a real provenance record.
        let mut provenance = sample();
        provenance
            .record_original(
                &short("observable.value"),
                UntrustedText::new("EXAMPLE.COM.").unwrap(),
            )
            .unwrap();
        provenance
            .record_original(
                &short("temporal.first_seen"),
                UntrustedText::new("2024-03-01T09:00:00+11:00").unwrap(),
            )
            .unwrap();

        let json = serde_json::to_string(&provenance).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();

        assert_eq!(
            back.original
                .get("observable.value")
                .map(UntrustedText::as_str),
            Some("EXAMPLE.COM."),
        );
        assert_eq!(
            back.original
                .get("temporal.first_seen")
                .map(UntrustedText::as_str),
            Some("2024-03-01T09:00:00+11:00"),
        );
    }

    #[test]
    fn round_trips_through_json() {
        let origin = RecordOrigin::source_derived(sample());
        let json = serde_json::to_string(&origin).unwrap();
        let back: RecordOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(back, origin);

        let synthetic = RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::Fixture,
            short("test-support"),
        ));
        let json = serde_json::to_string(&synthetic).unwrap();
        let back: RecordOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(back, synthetic);
    }

    #[test]
    fn serialised_provenance_carries_its_schema_version() {
        let json = serde_json::to_value(sample()).unwrap();
        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.provenance/1.0"),
        );
    }

    #[test]
    fn source_objects_are_bounded() {
        let mut provenance = sample();
        provenance.source_objects = (0..=MAX_SOURCE_OBJECTS)
            .map(|index| source(index.to_string().as_bytes()))
            .collect();
        provenance.evidence.clear();
        assert!(matches!(
            provenance.validated(),
            Err(ModelError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(sample()).unwrap();

        let mut no_sources = base.clone();
        no_sources["source_objects"] = serde_json::json!([]);
        no_sources["evidence"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Provenance>(no_sources).is_err());

        let mut empty_chain = base.clone();
        empty_chain["chain"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Provenance>(empty_chain).is_err());

        let mut wrong_id_kind = base.clone();
        wrong_id_kind["source_objects"] =
            serde_json::json!(["entity:00000000-0000-0000-0000-000000000000"]);
        assert!(serde_json::from_value::<Provenance>(wrong_id_kind).is_err());

        let mut unknown_field = base;
        unknown_field["trust_me"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Provenance>(unknown_field).is_err());

        // A record origin with neither case, or with an invented one.
        assert!(serde_json::from_str::<RecordOrigin>(r#"{"type":"vibes"}"#).is_err());
        assert!(serde_json::from_str::<RecordOrigin>(r#"{}"#).is_err());
    }
}
