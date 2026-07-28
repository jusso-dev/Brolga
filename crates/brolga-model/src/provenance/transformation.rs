//! Transformation chains: what was done to the evidence, in what order, by which algorithm version.
//!
//! A canonical record is the end of a pipeline that ran from retrieval to export. Without a record
//! of that pipeline, "why does this record say `example.com` when the source said `EXAMPLE.COM.`"
//! is unanswerable, and a change to a normalisation rule is indistinguishable from a change to the
//! underlying intelligence.
//!
//! # Algorithm identity is a compatibility surface
//!
//! ADR 0001 §6 makes `(algorithm_id, algorithm_version)` a versioned public surface: changing what
//! an existing pair *produces* is a breaking change. That is what makes a chain useful years later
//! — `brolga.canonicalise.domain` version 1 means one specific set of rules, permanently, and a
//! record stamped with it can be reproduced.
//!
//! # Timestamps are excluded from the fingerprint
//!
//! `docs/ARCHITECTURE.md` requires that a fixed input produce a fixed fingerprint, and that runtime
//! metadata be isolated from deterministic content. [`TransformationChain::fingerprint`] therefore
//! hashes the stages, algorithms, and versions, and deliberately omits `performed_at`. Two runs of
//! the same pipeline over the same bytes fingerprint identically even though they ran on different
//! days.

use core::fmt;

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::provenance::hash::ContentHash;
use crate::temporal::Timestamp;
use crate::text::ShortText;

/// Maximum number of steps in one chain.
///
/// A bound, not a target. A chain arrives from storage or from an API caller, and an unbounded one
/// is an unbounded allocation on an untrusted path.
pub const MAX_TRANSFORMATION_STEPS: usize = 64;

/// The pipeline stage a transformation belongs to.
///
/// Ordered as the pipeline runs, so `Ord` is "happens no later than" and a chain can be checked for
/// impossible ordering. The stages match the flow in `docs/ARCHITECTURE.md`, which is what lets a
/// chain identify everything from parsing through to export.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransformationStage {
    /// Obtaining the bytes.
    Retrieval,
    /// Deciding what the bytes are.
    Detection,
    /// Turning bytes into structured records.
    Parsing,
    /// Checking records against a schema or rule set.
    Validation,
    /// Mapping source vocabulary onto canonical types.
    Normalisation,
    /// Deterministic reduction of a value to its canonical form.
    Canonicalisation,
    /// Deciding which records refer to the same thing.
    Resolution,
    /// Collapsing records found to be duplicates.
    Deduplication,
    /// Adding derived attributes.
    Enrichment,
    /// Selecting and condensing for a context pack.
    Compression,
    /// Producing an output representation.
    Export,
}

impl TransformationStage {
    /// The `snake_case` wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retrieval => "retrieval",
            Self::Detection => "detection",
            Self::Parsing => "parsing",
            Self::Validation => "validation",
            Self::Normalisation => "normalisation",
            Self::Canonicalisation => "canonicalisation",
            Self::Resolution => "resolution",
            Self::Deduplication => "deduplication",
            Self::Enrichment => "enrichment",
            Self::Compression => "compression",
            Self::Export => "export",
        }
    }
}

impl fmt::Display for TransformationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One transformation applied to the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformationStep {
    /// Which pipeline stage this belongs to.
    pub stage: TransformationStage,
    /// The algorithm, conventionally `brolga.<stage>.<thing>`.
    ///
    /// Part of a versioned compatibility surface: renaming it orphans every record stamped with the
    /// old name.
    pub algorithm: ShortText,
    /// The algorithm's version.
    ///
    /// Incremented whenever the algorithm's *output* changes for any input. A fix that changes no
    /// output does not need a bump; a fix that changes one output does.
    pub algorithm_version: u32,
    /// Digest of what this step produced, where the step produced addressable bytes.
    ///
    /// `None` for a step whose output is an in-memory structure rather than a byte stream.
    pub output_hash: Option<ContentHash>,
    /// When the step ran.
    ///
    /// Runtime metadata. Excluded from [`TransformationChain::fingerprint`] so that determinism is
    /// a property of the pipeline rather than of the clock.
    pub performed_at: Option<Timestamp>,
    /// A note about this step, for a case the structured fields cannot express.
    pub note: Option<ShortText>,
}

impl TransformationStep {
    /// Build a step with no optional metadata.
    #[must_use]
    pub fn new(stage: TransformationStage, algorithm: ShortText, algorithm_version: u32) -> Self {
        Self {
            stage,
            algorithm,
            algorithm_version,
            output_hash: None,
            performed_at: None,
            note: None,
        }
    }

    /// The parts that contribute to a deterministic fingerprint.
    ///
    /// Excludes `performed_at`. Includes `output_hash`, because a step that produced different
    /// bytes did different work even if it claims the same algorithm version — which is exactly the
    /// discrepancy worth catching.
    fn fingerprint_parts(&self) -> Vec<String> {
        vec![
            self.stage.as_str().to_owned(),
            self.algorithm.as_str().to_owned(),
            self.algorithm_version.to_string(),
            self.output_hash
                .map_or_else(|| String::from("-"), |hash| hash.to_string()),
        ]
    }
}

impl<'de> Deserialize<'de> for TransformationStep {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            stage: TransformationStage,
            algorithm: ShortText,
            algorithm_version: u32,
            output_hash: Option<ContentHash>,
            performed_at: Option<Timestamp>,
            note: Option<ShortText>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            stage: raw.stage,
            algorithm: raw.algorithm,
            algorithm_version: raw.algorithm_version,
            output_hash: raw.output_hash,
            performed_at: raw.performed_at,
            note: raw.note,
        })
    }
}

/// An ordered, non-empty sequence of transformations.
///
/// Invariants, checked on construction and on deserialisation:
///
/// - non-empty, because a canonical record that came from somewhere had *something* done to it;
/// - no more than [`MAX_TRANSFORMATION_STEPS`] steps;
/// - stages never move backwards, because a pipeline that normalises before it parses did not
///   happen and a chain claiming it is either corrupt or fabricated.
///
/// Repeated stages are allowed: several canonicalisation steps in a row is normal, and forbidding it
/// would force unrelated work to be merged into one opaque step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct TransformationChain(Vec<TransformationStep>);

impl TransformationChain {
    /// Build a chain from steps in pipeline order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] for no steps, [`ModelError::TooLong`] beyond
    /// [`MAX_TRANSFORMATION_STEPS`], and [`ModelError::InvalidValue`] if a stage precedes one
    /// already recorded.
    pub fn new(steps: Vec<TransformationStep>) -> Result<Self> {
        Self(steps).validated()
    }

    /// A chain with one step.
    ///
    /// # Errors
    ///
    /// Cannot fail today; returns [`Result`] so that adding an invariant later is not a breaking
    /// signature change.
    pub fn single(step: TransformationStep) -> Result<Self> {
        Self::new(vec![step])
    }

    /// Append a step.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`] if the chain is already at its limit, and
    /// [`ModelError::InvalidValue`] if the step's stage precedes the last recorded stage.
    pub fn push(&mut self, step: TransformationStep) -> Result<()> {
        if self.0.len() >= MAX_TRANSFORMATION_STEPS {
            return Err(ModelError::TooLong {
                field: "TransformationChain",
                max: MAX_TRANSFORMATION_STEPS,
                actual: self.0.len().saturating_add(1),
            });
        }
        if let Some(last) = self.0.last()
            && step.stage < last.stage
        {
            return Err(ModelError::invalid(
                "TransformationChain",
                format_args!(
                    "stage {} follows {}, but the pipeline does not run backwards",
                    step.stage, last.stage,
                ),
            ));
        }
        self.0.push(step);
        Ok(())
    }

    /// The steps, in pipeline order.
    #[must_use]
    pub fn steps(&self) -> &[TransformationStep] {
        &self.0
    }

    /// Number of steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a chain cannot be empty.
    ///
    /// Present because Clippy asks for it beside `len`, and because a caller reading `len` should
    /// not have to check the type's documentation to learn that zero is impossible.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Whether the chain includes a step at the given stage.
    #[must_use]
    pub fn includes(&self, stage: TransformationStage) -> bool {
        self.0.iter().any(|step| step.stage == stage)
    }

    /// The stage the chain has reached.
    ///
    /// # Panics
    ///
    /// Does not panic. The chain is non-empty by invariant; the fallback exists only because the
    /// workspace forbids `unwrap`, and it is unreachable.
    #[must_use]
    pub fn current_stage(&self) -> TransformationStage {
        self.0
            .last()
            .map_or(TransformationStage::Retrieval, |step| step.stage)
    }

    /// A deterministic fingerprint of the pipeline, excluding when it ran.
    ///
    /// Two runs of the same pipeline over the same bytes fingerprint identically. Parts are
    /// length-prefixed before hashing, so a chain of `["ab", "c"]` cannot collide with `["a", "bc"]`
    /// — the same encoding rule [`Id::derive`](crate::id::Id::derive) uses, for the same reason.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        let mut encoded = Vec::new();
        for step in &self.0 {
            for part in step.fingerprint_parts() {
                encoded.extend_from_slice(part.len().to_string().as_bytes());
                encoded.push(b':');
                encoded.extend_from_slice(part.as_bytes());
            }
        }
        ContentHash::of(&encoded)
    }

    /// Check the chain's invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`], [`ModelError::TooLong`], or [`ModelError::InvalidValue`] as
    /// described on [`TransformationChain`].
    pub fn validated(self) -> Result<Self> {
        if self.0.is_empty() {
            return Err(ModelError::Empty {
                field: "TransformationChain",
            });
        }
        if self.0.len() > MAX_TRANSFORMATION_STEPS {
            return Err(ModelError::TooLong {
                field: "TransformationChain",
                max: MAX_TRANSFORMATION_STEPS,
                actual: self.0.len(),
            });
        }
        for pair in self.0.windows(2) {
            let (Some(previous), Some(next)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            if next.stage < previous.stage {
                return Err(ModelError::invalid(
                    "TransformationChain",
                    format_args!(
                        "stage {} follows {}, but the pipeline does not run backwards",
                        next.stage, previous.stage,
                    ),
                ));
            }
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for TransformationChain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let steps = Vec::<TransformationStep>::deserialize(deserializer)?;
        Self(steps).validated().map_err(D::Error::custom)
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

    fn step(stage: TransformationStage, algorithm: &str, version: u32) -> TransformationStep {
        TransformationStep::new(stage, ShortText::new(algorithm).unwrap(), version)
    }

    fn parse_to_canonical() -> TransformationChain {
        TransformationChain::new(vec![
            step(TransformationStage::Parsing, "brolga.parse.stix21", 1),
            step(TransformationStage::Validation, "brolga.validate.schema", 1),
            step(
                TransformationStage::Canonicalisation,
                "brolga.canonicalise.domain",
                1,
            ),
        ])
        .unwrap()
    }

    #[test]
    fn a_chain_identifies_parsing_through_export() {
        let mut chain = parse_to_canonical();
        chain
            .push(step(
                TransformationStage::Compression,
                "brolga.compress.rank",
                1,
            ))
            .unwrap();
        chain
            .push(step(TransformationStage::Export, "brolga.export.pack", 1))
            .unwrap();

        assert!(chain.includes(TransformationStage::Parsing));
        assert!(chain.includes(TransformationStage::Canonicalisation));
        assert!(chain.includes(TransformationStage::Export));
        assert_eq!(chain.current_stage(), TransformationStage::Export);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn a_chain_cannot_be_empty() {
        assert!(matches!(
            TransformationChain::new(Vec::new()),
            Err(ModelError::Empty { .. })
        ));
        assert!(serde_json::from_str::<TransformationChain>("[]").is_err());
        assert!(!parse_to_canonical().is_empty());
    }

    #[test]
    fn stages_cannot_run_backwards() {
        // A record claiming it was normalised before it was parsed did not happen.
        let error = TransformationChain::new(vec![
            step(
                TransformationStage::Canonicalisation,
                "brolga.canonicalise.domain",
                1,
            ),
            step(TransformationStage::Parsing, "brolga.parse.stix21", 1),
        ])
        .unwrap_err();
        assert!(
            error.to_string().contains("does not run backwards"),
            "{error}"
        );

        let mut chain = parse_to_canonical();
        assert!(
            chain
                .push(step(TransformationStage::Parsing, "brolga.parse.again", 1))
                .is_err()
        );
    }

    #[test]
    fn repeated_stages_are_allowed() {
        // Several canonicalisation steps is normal; forbidding it would force unrelated work to be
        // merged into one opaque step.
        let chain = TransformationChain::new(vec![
            step(
                TransformationStage::Canonicalisation,
                "brolga.canonicalise.domain",
                1,
            ),
            step(
                TransformationStage::Canonicalisation,
                "brolga.canonicalise.timestamp",
                1,
            ),
        ]);
        assert!(chain.is_ok());
    }

    #[test]
    fn the_fingerprint_ignores_when_the_pipeline_ran() {
        // The determinism requirement in docs/ARCHITECTURE.md, made testable.
        let monday = parse_to_canonical();
        let mut tuesday = parse_to_canonical();
        for existing in &mut tuesday.0 {
            existing.performed_at = Some(Timestamp::parse_rfc3339("2030-12-25T03:14:15Z").unwrap());
        }
        assert_ne!(monday, tuesday, "the records genuinely differ");
        assert_eq!(
            monday.fingerprint(),
            tuesday.fingerprint(),
            "but the pipeline they describe is the same"
        );
    }

    #[test]
    fn the_fingerprint_notices_an_algorithm_version_change() {
        let version_one = parse_to_canonical();
        let version_two = TransformationChain::new(vec![
            step(TransformationStage::Parsing, "brolga.parse.stix21", 1),
            step(TransformationStage::Validation, "brolga.validate.schema", 1),
            step(
                TransformationStage::Canonicalisation,
                "brolga.canonicalise.domain",
                2,
            ),
        ])
        .unwrap();
        assert_ne!(version_one.fingerprint(), version_two.fingerprint());
    }

    #[test]
    fn the_fingerprint_notices_differing_output_bytes() {
        // Same declared algorithm version, different output: worth catching, because one of the two
        // claims is wrong.
        let mut claimed = parse_to_canonical();
        let baseline = claimed.fingerprint();
        if let Some(last) = claimed.0.last_mut() {
            last.output_hash = Some(ContentHash::of(b"result"));
        }
        assert_ne!(claimed.fingerprint(), baseline);
    }

    #[test]
    fn fingerprint_part_boundaries_cannot_be_confused() {
        let ab_c = TransformationChain::new(vec![step(TransformationStage::Parsing, "ab", 1)])
            .unwrap()
            .fingerprint();
        let a_bc = TransformationChain::new(vec![step(TransformationStage::Parsing, "a", 1)])
            .unwrap()
            .fingerprint();
        assert_ne!(ab_c, a_bc);
    }

    #[test]
    fn fingerprints_are_reproducible() {
        assert_eq!(
            parse_to_canonical().fingerprint(),
            parse_to_canonical().fingerprint()
        );
    }

    #[test]
    fn round_trips_through_json() {
        let mut chain = parse_to_canonical();
        if let Some(last) = chain.0.last_mut() {
            last.output_hash = Some(ContentHash::of(b"result"));
            last.performed_at = Some(Timestamp::parse_rfc3339("2024-01-01T00:00:00Z").unwrap());
            last.note = Some(ShortText::new("lower-cased and dot-stripped").unwrap());
        }
        let json = serde_json::to_string(&chain).unwrap();
        let back: TransformationChain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, chain);
    }

    #[test]
    fn a_chain_is_bounded_because_it_arrives_from_untrusted_storage() {
        let too_many: Vec<_> = (0..=MAX_TRANSFORMATION_STEPS)
            .map(|_| step(TransformationStage::Enrichment, "brolga.enrich.x", 1))
            .collect();
        assert!(matches!(
            TransformationChain::new(too_many),
            Err(ModelError::TooLong { .. })
        ));

        let at_limit: Vec<_> = (0..MAX_TRANSFORMATION_STEPS)
            .map(|_| step(TransformationStage::Enrichment, "brolga.enrich.x", 1))
            .collect();
        let mut chain = TransformationChain::new(at_limit).unwrap();
        assert!(
            chain
                .push(step(TransformationStage::Export, "brolga.export.pack", 1))
                .is_err()
        );
    }

    #[test]
    fn rejects_hostile_payloads() {
        for hostile in [
            r#"[]"#,
            r#"[{"stage":"telepathy","algorithm":"x","algorithm_version":1,"output_hash":null,"performed_at":null,"note":null}]"#,
            r#"[{"stage":"parsing","algorithm":"x","algorithm_version":-1,"output_hash":null,"performed_at":null,"note":null}]"#,
            r#"[{"stage":"parsing","algorithm":"","algorithm_version":1,"output_hash":null,"performed_at":null,"note":null}]"#,
            r#"[{"stage":"parsing","algorithm":"x","algorithm_version":1,"output_hash":"deadbeef","performed_at":null,"note":null}]"#,
            r#"[{"stage":"parsing","algorithm":"x","algorithm_version":1,"output_hash":null,"performed_at":null,"note":null,"extra":1}]"#,
            r#"[{"stage":"canonicalisation","algorithm":"x","algorithm_version":1,"output_hash":null,"performed_at":null,"note":null},{"stage":"parsing","algorithm":"y","algorithm_version":1,"output_hash":null,"performed_at":null,"note":null}]"#,
        ] {
            assert!(
                serde_json::from_str::<TransformationChain>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn stage_order_matches_the_documented_pipeline() {
        assert!(TransformationStage::Retrieval < TransformationStage::Parsing);
        assert!(TransformationStage::Parsing < TransformationStage::Normalisation);
        assert!(TransformationStage::Normalisation < TransformationStage::Canonicalisation);
        assert!(TransformationStage::Canonicalisation < TransformationStage::Resolution);
        assert!(TransformationStage::Resolution < TransformationStage::Compression);
        assert!(TransformationStage::Compression < TransformationStage::Export);
    }
}
