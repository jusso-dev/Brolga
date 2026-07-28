//! Evidence references, original representations, and generated-content metadata.
//!
//! These are the three things that make a canonical record answerable rather than merely asserted:
//! where in the evidence it came from, what the source actually wrote before Brolga touched it, and
//! — if a human or a model produced the text — how, and on the basis of what.

use core::fmt;
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::id::Id;
use crate::provenance::source::SourceObject;
use crate::temporal::Timestamp;
use crate::text::{ShortText, UntrustedText};

/// Maximum number of recorded original representations on one record.
pub const MAX_ORIGINAL_FIELDS: usize = 64;

/// Maximum number of evidence references attached to one thing.
pub const MAX_EVIDENCE_REFERENCES: usize = 128;

// -------------------------------------------------------------------------------------------------
// Evidence locators
// -------------------------------------------------------------------------------------------------

/// Where inside a source object a piece of evidence sits.
///
/// Several forms, because the useful locator depends on what the evidence is: a byte range for an
/// arbitrary blob, a JSON pointer for a structured document, a line for a text feed. Recording the
/// wrong one is worse than recording `Whole`, which is honest about pointing at the whole object.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EvidenceLocator {
    /// The entire source object.
    Whole,
    /// A half-open byte range, `start..end`.
    ByteRange {
        /// First byte, inclusive.
        start: u64,
        /// Last byte, exclusive.
        end: u64,
    },
    /// An RFC 6901 JSON pointer into a structured document.
    JsonPointer {
        /// The pointer, for example `/objects/3/pattern`.
        pointer: ShortText,
    },
    /// A one-based line number in a text document.
    Line {
        /// The line number, counting from one.
        number: u64,
    },
}

impl EvidenceLocator {
    /// Build a byte range.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if `end` is not greater than `start`. An empty or
    /// inverted range points at nothing, and storing one produces a citation that cannot be
    /// followed.
    pub fn byte_range(start: u64, end: u64) -> Result<Self> {
        if end <= start {
            return Err(ModelError::invalid(
                "EvidenceLocator",
                format_args!("byte range {start}..{end} is empty or inverted"),
            ));
        }
        Ok(Self::ByteRange { start, end })
    }

    /// Build a one-based line locator.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if `number` is zero. Line numbering starts at one, and
    /// a zero here is an off-by-one that would silently cite the wrong line.
    pub fn line(number: u64) -> Result<Self> {
        if number == 0 {
            return Err(ModelError::invalid(
                "EvidenceLocator",
                "line numbers start at 1",
            ));
        }
        Ok(Self::Line { number })
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] for an empty or inverted byte range, a zero line
    /// number, or a JSON pointer that does not begin with `/`.
    pub fn validated(self) -> Result<Self> {
        match &self {
            Self::ByteRange { start, end } if end <= start => Err(ModelError::invalid(
                "EvidenceLocator",
                format_args!("byte range {start}..{end} is empty or inverted"),
            )),
            Self::Line { number } if *number == 0 => Err(ModelError::invalid(
                "EvidenceLocator",
                "line numbers start at 1",
            )),
            // RFC 6901: a non-empty pointer starts with `/`. The empty string is the whole
            // document, which this model expresses as `Whole`, so it is rejected here rather than
            // silently meaning something a reader would not expect.
            Self::JsonPointer { pointer } if !pointer.as_str().starts_with('/') => {
                Err(ModelError::invalid(
                    "EvidenceLocator",
                    "a JSON pointer must begin with '/'; use Whole for the entire document",
                ))
            }
            _ => Ok(self),
        }
    }
}

impl fmt::Display for EvidenceLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Whole => f.write_str("whole"),
            Self::ByteRange { start, end } => write!(f, "bytes {start}..{end}"),
            Self::JsonPointer { pointer } => write!(f, "pointer {}", pointer.as_str()),
            Self::Line { number } => write!(f, "line {number}"),
        }
    }
}

/// A citation: which source object, and where inside it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    /// The source object being cited.
    pub source_object: Id<SourceObject>,
    /// Where inside it.
    pub locator: EvidenceLocator,
}

impl EvidenceReference {
    /// Cite a whole source object.
    #[must_use]
    pub const fn whole(source_object: Id<SourceObject>) -> Self {
        Self {
            source_object,
            locator: EvidenceLocator::Whole,
        }
    }

    /// Cite part of a source object.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the locator is invalid.
    pub fn at(source_object: Id<SourceObject>, locator: EvidenceLocator) -> Result<Self> {
        Ok(Self {
            source_object,
            locator: locator.validated()?,
        })
    }
}

impl<'de> Deserialize<'de> for EvidenceReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            source_object: Id<SourceObject>,
            locator: EvidenceLocator,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            source_object: raw.source_object,
            locator: raw.locator.validated().map_err(D::Error::custom)?,
        })
    }
}

impl fmt::Display for EvidenceReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.source_object, self.locator)
    }
}

// -------------------------------------------------------------------------------------------------
// Original representations
// -------------------------------------------------------------------------------------------------

/// What the source actually wrote, keyed by the canonical field it became.
///
/// Canonicalisation is lossy on purpose: `EXAMPLE.COM.` becomes `example.com`, and
/// `2024-03-01T09:00:00+11:00` becomes `2024-02-29T22:00:00Z`. Both discard information that is
/// sometimes evidence in its own right — the offset a source chose can indicate where a report was
/// written, and the case a feed used can distinguish two publishers copying from each other.
///
/// This map is the other half of that trade. Values are [`UntrustedText`], because they are exactly
/// the bytes a feed wrote and nothing about being stored here makes them trustworthy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct OriginalRepresentation(BTreeMap<String, UntrustedText>);

impl OriginalRepresentation {
    /// An empty map, for a record with no canonicalised fields.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Record what the source wrote for one canonical field.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`] beyond [`MAX_ORIGINAL_FIELDS`].
    pub fn record(&mut self, field: &ShortText, original: UntrustedText) -> Result<()> {
        if !self.0.contains_key(field.as_str()) && self.0.len() >= MAX_ORIGINAL_FIELDS {
            return Err(ModelError::TooLong {
                field: "OriginalRepresentation",
                max: MAX_ORIGINAL_FIELDS,
                actual: self.0.len().saturating_add(1),
            });
        }
        self.0.insert(field.as_str().to_owned(), original);
        Ok(())
    }

    /// What the source wrote for a canonical field, if it was recorded.
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&UntrustedText> {
        self.0.get(field)
    }

    /// Iterate the recorded fields in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &UntrustedText)> {
        self.0.iter()
    }

    /// Number of recorded fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`] beyond [`MAX_ORIGINAL_FIELDS`], and
    /// [`ModelError::InvalidValue`] if a key is not a valid [`ShortText`] — the keys are field
    /// names, and a key carrying newlines or arbitrary length is unusable as one.
    pub fn validated(self) -> Result<Self> {
        if self.0.len() > MAX_ORIGINAL_FIELDS {
            return Err(ModelError::TooLong {
                field: "OriginalRepresentation",
                max: MAX_ORIGINAL_FIELDS,
                actual: self.0.len(),
            });
        }
        for key in self.0.keys() {
            ShortText::new(key.clone()).map_err(|error| {
                ModelError::invalid(
                    "OriginalRepresentation",
                    format_args!("field name is not a valid ShortText ({error})"),
                )
            })?;
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for OriginalRepresentation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let map = BTreeMap::<String, UntrustedText>::deserialize(deserializer)?;
        Self(map).validated().map_err(D::Error::custom)
    }
}

// -------------------------------------------------------------------------------------------------
// Generated content
// -------------------------------------------------------------------------------------------------

/// How a piece of content was produced, when it was not simply copied from a source.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GenerationMethod {
    /// Produced by a deterministic Brolga algorithm.
    Deterministic,
    /// Produced by a template applied to canonical fields.
    Template,
    /// Produced by a language model.
    ///
    /// `docs/ARCHITECTURE.md` keeps model providers optional, disabled by default, and outside
    /// deterministic core behaviour. Content produced this way must be identifiable as such
    /// wherever it surfaces, which is what this variant is for.
    LanguageModel,
    /// Written by a person.
    Operator,
}

/// Metadata for content Brolga produced rather than copied.
///
/// The invariant enforced here is the roadmap's rule that generated narrative always references
/// evidence and records its generation method: [`GeneratedContent::new`] rejects an empty evidence
/// list, so a generated summary that cites nothing cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedContent {
    /// How it was produced.
    pub method: GenerationMethod,
    /// The algorithm, template, or model identifier.
    pub generator: ShortText,
    /// The generator's version.
    pub generator_version: u32,
    /// When it was produced. Runtime metadata; excluded from deterministic fingerprints.
    pub generated_at: Option<Timestamp>,
    /// What it was based on. Never empty.
    pub evidence: Vec<EvidenceReference>,
}

impl GeneratedContent {
    /// Build generated-content metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] if `evidence` is empty, and [`ModelError::TooLong`] beyond
    /// [`MAX_EVIDENCE_REFERENCES`].
    pub fn new(
        method: GenerationMethod,
        generator: ShortText,
        generator_version: u32,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self> {
        Self {
            method,
            generator,
            generator_version,
            generated_at: None,
            evidence,
        }
        .validated()
    }

    /// Whether this content came from a language model.
    ///
    /// Callers rendering content to an analyst or an agent use this to label it. Deterministic and
    /// model-generated text must never be presented as the same kind of thing.
    #[must_use]
    pub const fn is_model_generated(&self) -> bool {
        matches!(self.method, GenerationMethod::LanguageModel)
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] for no evidence, and [`ModelError::TooLong`] beyond
    /// [`MAX_EVIDENCE_REFERENCES`].
    pub fn validated(self) -> Result<Self> {
        if self.evidence.is_empty() {
            return Err(ModelError::Empty {
                field: "GeneratedContent evidence",
            });
        }
        if self.evidence.len() > MAX_EVIDENCE_REFERENCES {
            return Err(ModelError::TooLong {
                field: "GeneratedContent evidence",
                max: MAX_EVIDENCE_REFERENCES,
                actual: self.evidence.len(),
            });
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for GeneratedContent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            method: GenerationMethod,
            generator: ShortText,
            generator_version: u32,
            generated_at: Option<Timestamp>,
            evidence: Vec<EvidenceReference>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            method: raw.method,
            generator: raw.generator,
            generator_version: raw.generator_version,
            generated_at: raw.generated_at,
            evidence: raw.evidence,
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
    use crate::provenance::hash::ContentHash;
    use crate::provenance::source::SourceObject;

    fn source() -> Id<SourceObject> {
        SourceObject::derive_id(ContentHash::of(b"bundle"))
    }

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    fn untrusted(value: &str) -> UntrustedText {
        UntrustedText::new(value).unwrap()
    }

    #[test]
    fn byte_ranges_must_be_non_empty_and_forward() {
        assert!(EvidenceLocator::byte_range(0, 1).is_ok());
        assert!(EvidenceLocator::byte_range(10, 20).is_ok());
        // A citation that cannot be followed is worse than one that says "the whole object".
        assert!(EvidenceLocator::byte_range(5, 5).is_err());
        assert!(EvidenceLocator::byte_range(20, 10).is_err());
    }

    #[test]
    fn line_numbers_start_at_one() {
        assert!(EvidenceLocator::line(1).is_ok());
        assert!(EvidenceLocator::line(0).is_err());
    }

    #[test]
    fn a_json_pointer_must_be_a_pointer() {
        assert!(
            EvidenceLocator::JsonPointer {
                pointer: short("/objects/3/pattern"),
            }
            .validated()
            .is_ok()
        );
        // The empty pointer means "the whole document" in RFC 6901, which this model spells `Whole`.
        assert!(
            EvidenceLocator::JsonPointer {
                pointer: short("objects/3"),
            }
            .validated()
            .is_err()
        );
    }

    #[test]
    fn locator_rules_are_enforced_on_the_untrusted_path_too() {
        for hostile in [
            r#"{"source_object":"source:00000000-0000-0000-0000-000000000000","locator":{"type":"byte_range","start":9,"end":2}}"#,
            r#"{"source_object":"source:00000000-0000-0000-0000-000000000000","locator":{"type":"line","number":0}}"#,
            r#"{"source_object":"source:00000000-0000-0000-0000-000000000000","locator":{"type":"json_pointer","pointer":"no-slash"}}"#,
            r#"{"source_object":"entity:00000000-0000-0000-0000-000000000000","locator":{"type":"whole"}}"#,
            r#"{"source_object":"source:00000000-0000-0000-0000-000000000000","locator":{"type":"telepathy"}}"#,
        ] {
            assert!(
                serde_json::from_str::<EvidenceReference>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn evidence_references_round_trip() {
        for locator in [
            EvidenceLocator::Whole,
            EvidenceLocator::byte_range(10, 42).unwrap(),
            EvidenceLocator::JsonPointer {
                pointer: short("/objects/3/pattern"),
            },
            EvidenceLocator::line(7).unwrap(),
        ] {
            let reference = EvidenceReference::at(source(), locator).unwrap();
            let json = serde_json::to_string(&reference).unwrap();
            let back: EvidenceReference = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reference);
        }
    }

    #[test]
    fn original_representations_survive_canonicalisation() {
        // The acceptance criterion for #4, made concrete: after canonicalisation, both the original
        // timezone representation and the original case are still readable.
        let mut original = OriginalRepresentation::empty();
        original
            .record(&short("observable.value"), untrusted("EXAMPLE.COM."))
            .unwrap();
        original
            .record(
                &short("temporal.first_seen"),
                untrusted("2024-03-01T09:00:00+11:00"),
            )
            .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let back: OriginalRepresentation = serde_json::from_str(&json).unwrap();

        assert_eq!(
            back.get("observable.value").map(UntrustedText::as_str),
            Some("EXAMPLE.COM."),
        );
        assert_eq!(
            back.get("temporal.first_seen").map(UntrustedText::as_str),
            Some("2024-03-01T09:00:00+11:00"),
            "the source's offset is evidence and must not be lost to UTC normalisation",
        );
    }

    #[test]
    fn recording_the_same_field_twice_replaces_it_without_growing_the_map() {
        let mut original = OriginalRepresentation::empty();
        original.record(&short("name"), untrusted("first")).unwrap();
        original
            .record(&short("name"), untrusted("second"))
            .unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(
            original.get("name").map(UntrustedText::as_str),
            Some("second")
        );
    }

    #[test]
    fn original_representations_are_bounded() {
        let mut original = OriginalRepresentation::empty();
        for index in 0..MAX_ORIGINAL_FIELDS {
            original
                .record(&short(&format!("field{index}")), untrusted("x"))
                .unwrap();
        }
        assert_eq!(original.len(), MAX_ORIGINAL_FIELDS);
        assert!(matches!(
            original.record(&short("one-too-many"), untrusted("x")),
            Err(ModelError::TooLong { .. })
        ));
    }

    #[test]
    fn original_representation_keys_must_be_usable_as_field_names() {
        let hostile = r#"{"two\nlines":"value"}"#;
        assert!(serde_json::from_str::<OriginalRepresentation>(hostile).is_err());
    }

    #[test]
    fn serialised_order_is_deterministic() {
        let mut one = OriginalRepresentation::empty();
        one.record(&short("z"), untrusted("1")).unwrap();
        one.record(&short("a"), untrusted("2")).unwrap();

        let mut two = OriginalRepresentation::empty();
        two.record(&short("a"), untrusted("2")).unwrap();
        two.record(&short("z"), untrusted("1")).unwrap();

        assert_eq!(
            serde_json::to_string(&one).unwrap(),
            serde_json::to_string(&two).unwrap(),
        );
    }

    #[test]
    fn generated_content_must_cite_evidence() {
        // The roadmap's rule, made unconstructable to violate.
        assert!(matches!(
            GeneratedContent::new(
                GenerationMethod::LanguageModel,
                short("example-model"),
                1,
                Vec::new(),
            ),
            Err(ModelError::Empty { .. })
        ));

        assert!(
            GeneratedContent::new(
                GenerationMethod::LanguageModel,
                short("example-model"),
                1,
                vec![EvidenceReference::whole(source())],
            )
            .is_ok()
        );
    }

    #[test]
    fn a_payload_with_no_evidence_is_rejected_too() {
        let hostile = r#"{"method":"language_model","generator":"m","generator_version":1,"generated_at":null,"evidence":[]}"#;
        assert!(serde_json::from_str::<GeneratedContent>(hostile).is_err());
    }

    #[test]
    fn model_generated_content_is_identifiable_as_such() {
        let evidence = vec![EvidenceReference::whole(source())];

        let model = GeneratedContent::new(
            GenerationMethod::LanguageModel,
            short("m"),
            1,
            evidence.clone(),
        )
        .unwrap();
        let deterministic =
            GeneratedContent::new(GenerationMethod::Deterministic, short("d"), 1, evidence)
                .unwrap();

        assert!(model.is_model_generated());
        assert!(!deterministic.is_model_generated());
    }

    #[test]
    fn generated_content_round_trips_and_is_bounded() {
        let content = GeneratedContent::new(
            GenerationMethod::Template,
            short("brolga.render.summary"),
            2,
            vec![
                EvidenceReference::whole(source()),
                EvidenceReference::at(source(), EvidenceLocator::line(4).unwrap()).unwrap(),
            ],
        )
        .unwrap();

        let json = serde_json::to_string(&content).unwrap();
        let back: GeneratedContent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, content);

        let too_many = (0..=MAX_EVIDENCE_REFERENCES)
            .map(|_| EvidenceReference::whole(source()))
            .collect();
        assert!(matches!(
            GeneratedContent::new(GenerationMethod::Deterministic, short("d"), 1, too_many),
            Err(ModelError::TooLong { .. })
        ));
    }
}
