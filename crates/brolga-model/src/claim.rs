//! Claims: what somebody asserts about a subject.
//!
//! Brolga does not store facts, it stores claims. The difference matters when two sources
//! disagree: a fact model has to pick a winner at write time and lose the disagreement, whereas a
//! claim model keeps both, each with its own confidence, status, and markings, and lets the
//! contradiction be surfaced rather than resolved silently.
//!
//! This is what makes "never silently discard contradictory records" implementable rather than
//! aspirational.

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::confidence::ConfidenceBreakdown;
use crate::error::Result;
use crate::id::{Id, Identifiable};
use crate::marking::MarkingSet;
use crate::relationship::NodeRef;
use crate::status::{Disposition, LifecycleStatus};
use crate::temporal::TemporalState;
use crate::text::{ShortText, UntrustedText};
use crate::version::{SchemaTag, VersionedSchema};

/// What a claim actually asserts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum Assertion {
    /// An assessment of whether the subject is malicious.
    Disposition(Disposition),
    /// A named attribute of the subject.
    ///
    /// The name is a [`ShortText`] because it is a key that code and operators use; the value is
    /// [`UntrustedText`] because it came from a feed. That asymmetry is deliberate: a key that
    /// could carry newlines or arbitrary length would be unusable as an index and unsafe to render
    /// in a table.
    Attribute {
        /// The attribute's name.
        name: ShortText,
        /// The attribute's value, as published.
        value: UntrustedText,
    },
    /// A free-text assertion that does not fit a structured form.
    ///
    /// Preserved verbatim so it can be shown as evidence, and never parsed for meaning.
    Narrative(UntrustedText),
}

impl Assertion {
    /// A stable discriminator for this assertion's shape, used in identifier derivation.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Disposition(_) => "disposition",
            Self::Attribute { .. } => "attribute",
            Self::Narrative(_) => "narrative",
        }
    }

    /// A stable rendering of the assertion's content, used in identifier derivation.
    ///
    /// Returns the parts separately rather than pre-joined, so that
    /// [`Id::derive`](crate::id::Id::derive)'s length-prefixed encoding keeps the boundaries
    /// unambiguous.
    #[must_use]
    pub fn derivation_parts(&self) -> Vec<String> {
        match self {
            Self::Disposition(disposition) => vec![disposition.as_str().to_owned()],
            Self::Attribute { name, value } => {
                vec![name.as_str().to_owned(), value.as_str().to_owned()]
            }
            Self::Narrative(text) => vec![text.as_str().to_owned()],
        }
    }
}

/// An assertion about a subject, attributable and independently governed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// Canonical identifier.
    pub id: Id<Self>,
    /// What the claim is about.
    pub subject: NodeRef,
    /// What is asserted.
    pub assertion: Assertion,
    /// Whether this claim still stands.
    ///
    /// A revoked claim is retained, not deleted. Deleting it would destroy the record that the
    /// assertion was ever made, which is exactly the history an analyst needs when a source
    /// changes its mind.
    pub status: LifecycleStatus,
    /// Observation and validity windows.
    pub temporal: TemporalState,
    /// Confidence in this claim, with its components.
    pub confidence: Option<ConfidenceBreakdown>,
    /// Handling restrictions. Always serialised, empty or not.
    pub markings: MarkingSet,
}

impl Identifiable for Claim {
    const ID_KIND: &'static str = "claim";
}

impl VersionedSchema for Claim {
    const SCHEMA_NAME: &'static str = "brolga.claim";
}

impl Claim {
    /// Derive an identifier from the subject and the assertion.
    ///
    /// Two sources making the identical assertion about the identical subject derive the same
    /// identifier. That is intentional and is *not* a merge: it means the graph holds one claim
    /// node, and the provenance model records that several sources asserted it. Corroboration is
    /// then a question about provenance — how many *independent* sources — rather than a question
    /// about how many duplicate rows a feed happened to publish.
    #[must_use]
    pub fn derive_id(subject: &NodeRef, assertion: &Assertion) -> Id<Self> {
        let subject = subject.to_string();
        let content = assertion.derivation_parts();

        let mut parts: Vec<&str> = Vec::with_capacity(content.len() + 2);
        parts.push(&subject);
        parts.push(assertion.kind_str());
        parts.extend(content.iter().map(String::as_str));

        Id::derive(&parts)
    }

    /// Build a claim with no optional metadata, deriving its identifier.
    #[must_use]
    pub fn new(subject: NodeRef, assertion: Assertion) -> Self {
        Self {
            schema_version: SchemaTag::new(),
            id: Self::derive_id(&subject, &assertion),
            subject,
            assertion,
            status: LifecycleStatus::Active,
            temporal: TemporalState::unknown(),
            confidence: None,
            markings: MarkingSet::empty(),
        }
    }

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

impl<'de> Deserialize<'de> for Claim {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<Claim>,
            id: Id<Claim>,
            subject: NodeRef,
            assertion: Assertion,
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
            assertion: raw.assertion,
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
    use crate::observable::{DomainName, Observable};

    fn subject(domain: &str) -> NodeRef {
        NodeRef::Observable(Observable::DomainName(DomainName::new(domain).unwrap()).id())
    }

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    fn untrusted(value: &str) -> UntrustedText {
        UntrustedText::new(value).unwrap()
    }

    #[test]
    fn contradictory_claims_about_one_subject_are_two_records() {
        // The whole point: disagreement is preserved rather than resolved at write time.
        let malicious = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        let benign = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Benign),
        );
        assert_ne!(malicious.id, benign.id);
        assert_eq!(malicious.subject, benign.subject);
    }

    #[test]
    fn the_identical_assertion_derives_one_identifier() {
        let first = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        let second = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn attribute_name_and_value_boundaries_cannot_be_confused() {
        let ab_c = Claim::new(
            subject("example.com"),
            Assertion::Attribute {
                name: short("ab"),
                value: untrusted("c"),
            },
        );
        let a_bc = Claim::new(
            subject("example.com"),
            Assertion::Attribute {
                name: short("a"),
                value: untrusted("bc"),
            },
        );
        assert_ne!(ab_c.id, a_bc.id);
    }

    #[test]
    fn assertion_kinds_do_not_collide() {
        let narrative = Claim::new(
            subject("example.com"),
            Assertion::Narrative(untrusted("malicious")),
        );
        let disposition = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        assert_ne!(narrative.id, disposition.id);
    }

    #[test]
    fn subjects_do_not_collide() {
        let one = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        let two = Claim::new(
            subject("example.org"),
            Assertion::Disposition(Disposition::Malicious),
        );
        assert_ne!(one.id, two.id);
    }

    #[test]
    fn every_assertion_shape_round_trips_through_json() {
        for assertion in [
            Assertion::Disposition(Disposition::Suspicious),
            Assertion::Attribute {
                name: short("registrar"),
                value: untrusted("Example Registrar"),
            },
            Assertion::Narrative(untrusted("Observed in a phishing campaign.\nSee report.")),
        ] {
            let claim = Claim::new(subject("example.com"), assertion);
            let json = serde_json::to_string(&claim).unwrap();
            let back: Claim = serde_json::from_str(&json).unwrap();
            assert_eq!(back, claim);
        }
    }

    #[test]
    fn a_revoked_claim_is_retained_not_erased() {
        let mut claim = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        );
        claim.status = LifecycleStatus::Revoked;

        let json = serde_json::to_value(&claim).unwrap();
        let back: Claim = serde_json::from_value(json).unwrap();
        assert_eq!(back.status, LifecycleStatus::Revoked);
        assert_eq!(
            back.assertion,
            Assertion::Disposition(Disposition::Malicious),
            "the withdrawn assertion is still readable"
        );
    }

    #[test]
    fn serialised_form_carries_schema_version_and_markings() {
        let claim = Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Unknown),
        );
        let json = serde_json::to_value(&claim).unwrap();
        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.claim/1.0"),
        );
        assert_eq!(json.get("markings"), Some(&serde_json::json!([])));
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(Claim::new(
            subject("example.com"),
            Assertion::Disposition(Disposition::Malicious),
        ))
        .unwrap();

        let mut bad_assertion = base.clone();
        bad_assertion["assertion"] = serde_json::json!({"type": "prophecy", "value": "doom"});
        assert!(serde_json::from_value::<Claim>(bad_assertion).is_err());

        let mut bad_disposition = base.clone();
        bad_disposition["assertion"] =
            serde_json::json!({"type": "disposition", "value": "very_bad"});
        assert!(serde_json::from_value::<Claim>(bad_disposition).is_err());

        let mut multiline_attribute_name = base.clone();
        multiline_attribute_name["assertion"] = serde_json::json!({
            "type": "attribute",
            "value": {"name": "two\nlines", "value": "x"},
        });
        assert!(serde_json::from_value::<Claim>(multiline_attribute_name).is_err());

        let mut wrong_schema = base;
        wrong_schema["schema_version"] = serde_json::json!("brolga.entity/1.0");
        assert!(serde_json::from_value::<Claim>(wrong_schema).is_err());
    }
}
