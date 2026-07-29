//! Measuring what compression cost, not only what it saved.
//!
//! # A reduction ratio is not a score
//!
//! Deleting everything achieves a 100% reduction. That is the whole problem with reporting one
//! number: it is maximised by the worst possible behaviour, and any process optimised against it
//! drifts toward producing less rather than producing *better*.
//!
//! So [`QualityReport`] refuses to expose a single figure of merit.
//! [`QualityReport::reduction_percent`] exists because operators need it, and sits beside
//! [`QualityReport::evidence_retention_percent`] and [`QualityReport::contradiction_retention_percent`]
//! — which a lossy pass *lowers*. [`QualityReport::is_acceptable`] requires all three, so a pack
//! that compressed brilliantly by throwing away its evidence fails.
//!
//! # Counts must reconcile
//!
//! Every canonical record is included, clustered into a representative, or dropped —
//! [`QualityReport::reconciles`] checks the arithmetic. A report whose parts do not add up is
//! measuring something other than what happened, and would hide exactly the bug it exists to catch.
//!
//! # Golden packs
//!
//! A golden pack is a recorded output a test compares against. It is only useful if the same input
//! produces the same output, so [`GoldenPack`] compares by *fingerprint* — which excludes the
//! documented runtime metadata — rather than by bytes. Comparing bytes would fail on every run
//! because of a timestamp, and a test that always fails is a test that gets deleted.

use std::collections::BTreeSet;

/// What one compression pass did, in every dimension that matters.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct QualityReport {
    /// Source objects the records came from.
    pub source_objects: u64,
    /// Canonical records considered.
    pub canonical_records: u64,
    /// Records folded into a cluster representative.
    pub clustered: u64,
    /// Records that reached the pack in their own right.
    pub included: u64,
    /// Records dropped entirely.
    pub dropped: u64,
    /// Approximate bytes of the canonical records before compression.
    pub source_bytes: u64,
    /// Approximate bytes of the pack after it.
    pub output_bytes: u64,
    /// Estimated tokens before.
    pub source_tokens: u64,
    /// Estimated tokens after.
    pub output_tokens: u64,
    /// Distinct evidence references the canonical records cited.
    pub evidence_before: u64,
    /// Distinct evidence references the pack still cites.
    ///
    /// The number a reduction ratio hides. A pass that halved the pack by dropping every source
    /// reference reads as a success on size alone.
    pub evidence_after: u64,
    /// Contradictions present before.
    pub contradictions_before: u64,
    /// Contradictions surviving.
    ///
    /// Must not fall. Dropping one turns "two sources disagree" into "one source said this", which
    /// is a stronger claim than the evidence supports.
    pub contradictions_after: u64,
}

impl QualityReport {
    /// Whether the record counts add up.
    ///
    /// Every canonical record is included, clustered, or dropped. A report whose parts do not
    /// reconcile is measuring something other than what happened, and would hide exactly the bug it
    /// exists to catch.
    #[must_use]
    pub fn reconciles(&self) -> bool {
        self.included
            .saturating_add(self.clustered)
            .saturating_add(self.dropped)
            == self.canonical_records
    }

    /// How much smaller the output is, as a percentage.
    ///
    /// Deliberately not called a score. Deleting everything scores 100 here.
    #[must_use]
    pub fn reduction_percent(&self) -> u8 {
        percent_of(
            self.source_bytes.saturating_sub(self.output_bytes),
            self.source_bytes,
        )
    }

    /// The same, in tokens.
    #[must_use]
    pub fn token_reduction_percent(&self) -> u8 {
        percent_of(
            self.source_tokens.saturating_sub(self.output_tokens),
            self.source_tokens,
        )
    }

    /// What share of the evidence references survived.
    ///
    /// The counterweight. A pass that halved the pack by dropping every source reference reads as a
    /// success on size and fails here.
    #[must_use]
    pub fn evidence_retention_percent(&self) -> u8 {
        percent_of(self.evidence_after, self.evidence_before)
    }

    /// What share of the contradictions survived.
    #[must_use]
    pub fn contradiction_retention_percent(&self) -> u8 {
        percent_of(self.contradictions_after, self.contradictions_before)
    }

    /// Whether this pass is acceptable on every axis at once.
    ///
    /// Not a weighted score. Three separate gates, because a single number would let a brilliant
    /// reduction buy its way past a lost contradiction — which is precisely the trade nobody would
    /// approve if asked directly.
    #[must_use]
    pub fn is_acceptable(&self, minimum_evidence_retention: u8) -> bool {
        self.reconciles()
            && self.evidence_retention_percent() >= minimum_evidence_retention
            && self.contradiction_retention_percent() == 100
    }

    /// Every way this pass falls short, for a diagnostic.
    #[must_use]
    pub fn shortfalls(&self, minimum_evidence_retention: u8) -> Vec<String> {
        let mut problems = Vec::new();

        if !self.reconciles() {
            problems.push(format!(
                "counts do not reconcile: {} included + {} clustered + {} dropped != {} canonical",
                self.included, self.clustered, self.dropped, self.canonical_records
            ));
        }
        let retention = self.evidence_retention_percent();
        if retention < minimum_evidence_retention {
            problems.push(format!(
                "evidence retention {retention}% is below the {minimum_evidence_retention}% floor; \
                 a claim that cannot be traced to a source cannot be defended"
            ));
        }
        if self.contradiction_retention_percent() != 100 {
            problems.push(format!(
                "{} of {} contradictions were dropped; losing one turns `two sources disagree` \
                 into `one source said this`",
                self.contradictions_before
                    .saturating_sub(self.contradictions_after),
                self.contradictions_before
            ));
        }
        problems
    }
}

/// A percentage of a whole, with an empty whole reported as complete.
///
/// Zero out of zero is 100%, not 0%. A pack with no contradictions has not lost any, and reporting
/// it as a total loss would fail every empty case for no reason.
fn percent_of(part: u64, whole: u64) -> u8 {
    if whole == 0 {
        return 100;
    }
    #[allow(clippy::integer_division)]
    let percent = part.saturating_mul(100) / whole;
    u8::try_from(percent).unwrap_or(100)
}

/// A recorded pack output, for a test to compare against.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GoldenPack {
    /// What this golden pack is called.
    pub name: String,
    /// The fingerprint the pack must reproduce.
    ///
    /// A fingerprint rather than the bytes. Comparing bytes would fail on every run because of a
    /// timestamp, and a test that always fails is a test somebody deletes.
    pub fingerprint: String,
    /// Fields that must be present, whatever else changes.
    ///
    /// Named explicitly so their disappearance is a *test failure* rather than a smaller
    /// fingerprint nobody investigates. Evidence and policy fields going missing is the regression
    /// this whole file exists to catch.
    pub required_fields: BTreeSet<String>,
}

/// Why a pack did not match its golden record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GoldenMismatch {
    /// The fingerprint changed.
    #[error(
        "`{name}` produced fingerprint `{actual}`, expected `{expected}`. If this change is \
         intended, re-record the golden pack; if it is not, the compression behaviour has moved"
    )]
    Fingerprint {
        /// The golden pack's name.
        name: String,
        /// What was expected.
        expected: String,
        /// What was produced.
        actual: String,
    },

    /// A field that must always be present is gone.
    #[error(
        "`{name}` no longer contains `{field}`. A pack that lost an evidence or policy field is \
         not a smaller pack, it is a different and less defensible one"
    )]
    MissingField {
        /// The golden pack's name.
        name: String,
        /// The field.
        field: String,
    },
}

impl GoldenPack {
    /// Record a golden pack.
    #[must_use]
    pub fn new(name: impl Into<String>, fingerprint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fingerprint: fingerprint.into(),
            required_fields: BTreeSet::new(),
        }
    }

    /// Require a field to be present.
    #[must_use]
    pub fn requiring(mut self, field: impl Into<String>) -> Self {
        self.required_fields.insert(field.into());
        self
    }

    /// The fields every golden pack should require.
    ///
    /// Evidence, markings, and gaps — the same floor the profile engine refuses to let an operator
    /// cross, checked again here from the other direction. A rule enforced only where it is
    /// configured is a rule that a code path can route around.
    #[must_use]
    pub fn with_default_requirements(self) -> Self {
        self.requiring("evidence")
            .requiring("policy")
            .requiring("gaps")
            .requiring("exclusions")
    }

    /// Compare a produced pack against this record.
    ///
    /// # Errors
    ///
    /// [`GoldenMismatch::Fingerprint`] when the pack differs, and [`GoldenMismatch::MissingField`]
    /// for each required field that has disappeared.
    #[must_use]
    pub fn check(&self, fingerprint: &str, produced: &serde_json::Value) -> Vec<GoldenMismatch> {
        let mut problems = Vec::new();

        if fingerprint != self.fingerprint {
            problems.push(GoldenMismatch::Fingerprint {
                name: self.name.clone(),
                expected: self.fingerprint.clone(),
                actual: fingerprint.to_owned(),
            });
        }

        for field in &self.required_fields {
            if !contains_field(produced, field) {
                problems.push(GoldenMismatch::MissingField {
                    name: self.name.clone(),
                    field: field.clone(),
                });
            }
        }

        problems
    }
}

/// Whether a JSON document holds a key anywhere in it.
///
/// Searched at any depth rather than at the top level, because the fields that matter moved once
/// already — `evidence` sits inside findings, `markings` inside policy — and a check keyed on a
/// path would silently start passing the moment somebody restructured the pack.
fn contains_field(value: &serde_json::Value, field: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.contains_key(field) || map.values().any(|nested| contains_field(nested, field))
        }
        serde_json::Value::Array(items) => items.iter().any(|item| contains_field(item, field)),
        _ => false,
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

    fn report() -> QualityReport {
        QualityReport {
            source_objects: 3,
            canonical_records: 100,
            clustered: 30,
            included: 40,
            dropped: 30,
            source_bytes: 10_000,
            output_bytes: 2_000,
            source_tokens: 2_500,
            output_tokens: 500,
            evidence_before: 20,
            evidence_after: 20,
            contradictions_before: 2,
            contradictions_after: 2,
        }
    }

    /// **The criterion.** Every canonical record is included, clustered, or dropped. A report whose
    /// parts do not add up is measuring something other than what happened.
    #[test]
    fn the_counts_must_reconcile() {
        assert!(report().reconciles());

        let mut wrong = report();
        wrong.dropped = 29;
        assert!(!wrong.reconciles());
        assert!(wrong.shortfalls(90)[0].contains("do not reconcile"));
    }

    /// **The criterion.** Deleting everything achieves a 100% reduction, which is why one number
    /// cannot be the measure.
    #[test]
    fn a_reduction_ratio_is_not_treated_as_the_sole_measure() {
        let mut destroyed = report();
        destroyed.output_bytes = 0;
        destroyed.output_tokens = 0;
        destroyed.evidence_after = 0;
        destroyed.contradictions_after = 0;
        destroyed.included = 0;
        destroyed.dropped = 70;

        assert_eq!(
            destroyed.reduction_percent(),
            100,
            "on size alone this is a perfect result"
        );
        assert!(
            !destroyed.is_acceptable(90),
            "and it must not be acceptable"
        );

        let problems = destroyed.shortfalls(90);
        assert!(problems.iter().any(|p| p.contains("evidence retention")));
        assert!(problems.iter().any(|p| p.contains("contradictions")));
    }

    /// A pass that halved the pack by dropping every source reference reads as a success on size.
    #[test]
    fn losing_evidence_fails_however_good_the_reduction_is() {
        let mut lossy = report();
        lossy.evidence_after = 10;

        assert_eq!(lossy.reduction_percent(), 80);
        assert_eq!(lossy.evidence_retention_percent(), 50);
        assert!(!lossy.is_acceptable(90));
        assert!(lossy.is_acceptable(50), "the floor is the caller's to set");
    }

    /// Losing one turns "two sources disagree" into "one source said this".
    #[test]
    fn losing_a_contradiction_is_never_acceptable_at_any_floor() {
        let mut lossy = report();
        lossy.contradictions_after = 1;

        assert!(!lossy.is_acceptable(0), "not even with no evidence floor");
        assert_eq!(lossy.contradiction_retention_percent(), 50);
    }

    /// Zero out of zero is complete, not total loss. A pack with no contradictions has not lost
    /// any, and reporting it as a failure would fail every empty case for no reason.
    #[test]
    fn an_empty_whole_is_reported_as_complete_rather_than_as_a_total_loss() {
        let mut empty = report();
        empty.contradictions_before = 0;
        empty.contradictions_after = 0;
        empty.evidence_before = 0;
        empty.evidence_after = 0;

        assert_eq!(empty.contradiction_retention_percent(), 100);
        assert_eq!(empty.evidence_retention_percent(), 100);
        assert!(empty.is_acceptable(90));
    }

    /// **The criterion.** Byte and token estimates are both recorded, because a consumer sizing a
    /// prompt cares about tokens and an operator sizing a database cares about bytes.
    #[test]
    fn both_byte_and_token_estimates_are_recorded() {
        let report = report();
        assert_eq!(report.reduction_percent(), 80);
        assert_eq!(report.token_reduction_percent(), 80);
        assert_ne!(report.source_bytes, report.source_tokens);
    }

    /// **The criterion.** Comparing bytes would fail on every run because of a timestamp, and a
    /// test that always fails is a test somebody deletes.
    #[test]
    fn a_golden_pack_compares_by_fingerprint_rather_than_by_bytes() {
        let golden = GoldenPack::new("triage", "sha256:abc");
        let body = serde_json::json!({"anything": "at all"});

        assert!(golden.check("sha256:abc", &body).is_empty());

        let problems = golden.check("sha256:def", &body);
        assert!(matches!(problems[0], GoldenMismatch::Fingerprint { .. }));
        assert!(
            problems[0].to_string().contains("re-record"),
            "the message must say what to do about it: {}",
            problems[0]
        );
    }

    /// **The criterion.** A pack that lost an evidence or policy field is not a smaller pack, it is
    /// a different and less defensible one — and a fingerprint change alone would not say which.
    #[test]
    fn a_golden_pack_fails_when_a_mandatory_field_disappears() {
        let golden = GoldenPack::new("triage", "sha256:abc").with_default_requirements();

        let complete = serde_json::json!({
            "findings": [{"evidence": [{"source_object_id": "x"}]}],
            "policy": {"markings": []},
            "gaps": [],
            "exclusions": [],
        });
        assert!(golden.check("sha256:abc", &complete).is_empty());

        let stripped = serde_json::json!({
            "findings": [{}],
            "policy": {"markings": []},
            "gaps": [],
            "exclusions": [],
        });
        let problems = golden.check("sha256:abc", &stripped);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].to_string().contains("evidence"),
            "{}",
            problems[0]
        );
    }

    /// The fields that matter are nested, and they have moved before. A check keyed on a path would
    /// silently start passing the moment somebody restructured the pack.
    #[test]
    fn a_required_field_is_found_at_any_depth() {
        let golden = GoldenPack::new("t", "f").requiring("markings");

        let nested = serde_json::json!({"a": {"b": [{"policy": {"markings": []}}]}});
        assert!(golden.check("f", &nested).is_empty());

        let absent = serde_json::json!({"a": {"b": [{"policy": {}}]}});
        assert_eq!(golden.check("f", &absent).len(), 1);
    }

    /// The same floor the profile engine refuses to let an operator cross, checked from the other
    /// direction. A rule enforced only where it is configured is one a code path can route around.
    #[test]
    fn the_default_requirements_are_the_same_floor_profiles_enforce() {
        let golden = GoldenPack::new("t", "f").with_default_requirements();
        for field in ["evidence", "policy", "gaps", "exclusions"] {
            assert!(golden.required_fields.contains(field), "{field}");
        }
    }
}
