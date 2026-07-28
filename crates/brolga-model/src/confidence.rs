//! Confidence expressed as components, not as a single opaque number.
//!
//! A bare "confidence: 85" is unusable: it cannot be explained, cannot be recomputed when one input
//! changes, and cannot be argued with. [`ConfidenceBreakdown`] keeps the components separate and
//! records how the overall figure was arrived at, so a later pack can show *why* something scored
//! as it did rather than asserting that it did.
//!
//! # What this module deliberately does not do
//!
//! It does not aggregate. There is no function here that turns four components into an overall
//! score, because choosing those weights is a product decision with real consequences for what an
//! analyst sees, and it belongs to the scoring work in `v0.3.0` where it can be versioned as an
//! algorithm and tested against fixtures. Until then `overall` is supplied by whoever asserts it,
//! and [`ConfidenceMethod`] records whether that was a source's own figure or Brolga's.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// A confidence value in the closed range `0..=100`.
///
/// Zero is a meaningful value — "asserted, and believed false" — and is not the same as an absent
/// component, which is `None`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfidenceScore(u8);

impl ConfidenceScore {
    /// The lowest expressible confidence.
    pub const MIN: Self = Self(0);
    /// The highest expressible confidence.
    pub const MAX: Self = Self(100);

    /// Build a score.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::ConfidenceOutOfRange`] if `value` exceeds 100.
    pub fn new(value: u8) -> Result<Self> {
        if value > 100 {
            return Err(ModelError::ConfidenceOutOfRange {
                found: u32::from(value),
            });
        }
        Ok(Self(value))
    }

    /// The score as a number in `0..=100`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ConfidenceScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfidenceScore({})", self.0)
    }
}

impl fmt::Display for ConfidenceScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u8> for ConfidenceScore {
    type Error = ModelError;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl Serialize for ConfidenceScore {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for ConfidenceScore {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        // Deserialised as `u32` rather than `u8` so that 250 and 5000 both produce the documented
        // out-of-range error instead of serde's generic integer-overflow message.
        let raw = u32::deserialize(deserializer)?;
        let narrowed = u8::try_from(raw)
            .map_err(|_| ModelError::ConfidenceOutOfRange { found: raw })
            .map_err(D::Error::custom)?;
        Self::new(narrowed).map_err(D::Error::custom)
    }
}

impl JsonSchema for ConfidenceScore {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ConfidenceScore".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
            "description": "Confidence in the closed range 0..=100. Zero means asserted and disbelieved, not unknown.",
        })
    }
}

/// How an overall confidence figure was arrived at.
///
/// Recorded so that a source's own rating is never silently presented as Brolga's assessment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfidenceMethod {
    /// Taken verbatim from the source that published the record.
    SourceAsserted,
    /// Computed by Brolga from the components, by a named and versioned algorithm.
    Derived,
    /// Entered by an operator.
    OperatorAsserted,
    /// No method was recorded. Carries no weight and must not be treated as agreement.
    Unknown,
}

/// The components behind a confidence figure.
///
/// The components use the same vocabulary as the Admiralty scale that intelligence practice
/// already uses — how reliable is the source, how credible is this particular report, and is it
/// corroborated — plus recency, which matters more in threat intelligence than in most domains
/// because infrastructure turns over quickly.
///
/// Every component is optional and absent means unknown. Inventing a default would be inventing
/// intelligence, which the roadmap's cross-cutting rules forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceBreakdown {
    /// The figure that downstream consumers should use.
    pub overall: ConfidenceScore,
    /// How the overall figure was produced.
    pub method: ConfidenceMethod,
    /// Track record of the publishing source, independent of this particular report.
    pub source_reliability: Option<ConfidenceScore>,
    /// Credibility of this particular report, independent of its source's track record.
    pub information_credibility: Option<ConfidenceScore>,
    /// Support from sources known to be independent of this one.
    ///
    /// Known syndicated copies must not raise this: the roadmap's design commitments forbid
    /// counting a copy as independent corroboration.
    pub corroboration: Option<ConfidenceScore>,
    /// How current the underlying observation is.
    pub recency: Option<ConfidenceScore>,
}

impl ConfidenceBreakdown {
    /// An overall figure with no components and no stated method.
    ///
    /// Honest about knowing nothing beyond the number itself.
    #[must_use]
    pub const fn unexplained(overall: ConfidenceScore) -> Self {
        Self {
            overall,
            method: ConfidenceMethod::Unknown,
            source_reliability: None,
            information_credibility: None,
            corroboration: None,
            recency: None,
        }
    }

    /// A figure taken verbatim from the source that published it.
    #[must_use]
    pub const fn source_asserted(overall: ConfidenceScore) -> Self {
        Self {
            method: ConfidenceMethod::SourceAsserted,
            ..Self::unexplained(overall)
        }
    }

    /// Whether any component was recorded alongside the overall figure.
    ///
    /// A breakdown with no components cannot be explained to an analyst, only asserted at them.
    #[must_use]
    pub const fn is_explained(&self) -> bool {
        self.source_reliability.is_some()
            || self.information_credibility.is_some()
            || self.corroboration.is_some()
            || self.recency.is_some()
    }
}

impl<'de> Deserialize<'de> for ConfidenceBreakdown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            overall: ConfidenceScore,
            method: ConfidenceMethod,
            #[serde(default)]
            source_reliability: Option<ConfidenceScore>,
            #[serde(default)]
            information_credibility: Option<ConfidenceScore>,
            #[serde(default)]
            corroboration: Option<ConfidenceScore>,
            #[serde(default)]
            recency: Option<ConfidenceScore>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            overall: raw.overall,
            method: raw.method,
            source_reliability: raw.source_reliability,
            information_credibility: raw.information_credibility,
            corroboration: raw.corroboration,
            recency: raw.recency,
        })
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

    fn score(value: u8) -> ConfidenceScore {
        ConfidenceScore::new(value).unwrap()
    }

    #[test]
    fn scores_accept_the_whole_documented_range() {
        assert_eq!(score(0), ConfidenceScore::MIN);
        assert_eq!(score(100), ConfidenceScore::MAX);
        assert_eq!(score(50).get(), 50);
    }

    #[test]
    fn scores_above_one_hundred_are_rejected() {
        assert!(matches!(
            ConfidenceScore::new(101),
            Err(ModelError::ConfidenceOutOfRange { found: 101 })
        ));
        assert!(matches!(
            ConfidenceScore::new(255),
            Err(ModelError::ConfidenceOutOfRange { found: 255 })
        ));
    }

    #[test]
    fn deserialisation_rejects_out_of_range_and_non_integer_values() {
        for hostile in [
            "101", "255", "256", "100000", "-1", "\"90\"", "90.5", "null",
        ] {
            assert!(
                serde_json::from_str::<ConfidenceScore>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
        assert_eq!(
            serde_json::from_str::<ConfidenceScore>("0").unwrap(),
            score(0)
        );
        assert_eq!(
            serde_json::from_str::<ConfidenceScore>("100").unwrap(),
            score(100)
        );
    }

    #[test]
    fn zero_is_a_value_and_absent_is_not_zero() {
        let disbelieved = ConfidenceBreakdown {
            corroboration: Some(score(0)),
            ..ConfidenceBreakdown::unexplained(score(0))
        };
        let unknown = ConfidenceBreakdown::unexplained(score(0));

        assert!(disbelieved.is_explained());
        assert!(!unknown.is_explained());
        assert_ne!(disbelieved, unknown);
    }

    #[test]
    fn an_unexplained_figure_admits_it() {
        let breakdown = ConfidenceBreakdown::unexplained(score(85));
        assert_eq!(breakdown.method, ConfidenceMethod::Unknown);
        assert!(!breakdown.is_explained());
    }

    #[test]
    fn a_source_figure_is_labelled_as_the_sources_not_brolgas() {
        let breakdown = ConfidenceBreakdown::source_asserted(score(85));
        assert_eq!(breakdown.method, ConfidenceMethod::SourceAsserted);
        assert_ne!(breakdown.method, ConfidenceMethod::Derived);
    }

    #[test]
    fn round_trips_through_json_and_omits_no_component() {
        let breakdown = ConfidenceBreakdown {
            overall: score(72),
            method: ConfidenceMethod::Derived,
            source_reliability: Some(score(80)),
            information_credibility: Some(score(60)),
            corroboration: None,
            recency: Some(score(95)),
        };
        let json = serde_json::to_value(breakdown).unwrap();
        assert_eq!(json.get("corroboration"), Some(&serde_json::Value::Null));

        let back: ConfidenceBreakdown = serde_json::from_value(json).unwrap();
        assert_eq!(back, breakdown);
    }

    #[test]
    fn rejects_hostile_payloads() {
        for hostile in [
            r#"{"overall":101,"method":"derived"}"#,
            r#"{"overall":50,"method":"guessed"}"#,
            r#"{"overall":50}"#,
            r#"{"method":"derived"}"#,
            r#"{"overall":50,"method":"derived","weight":9}"#,
        ] {
            assert!(
                serde_json::from_str::<ConfidenceBreakdown>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }
}
