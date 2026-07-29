//! Composing a confidence figure out of components that can each be argued with.
//!
//! # Why this is a sibling of contradiction detection rather than part of it
//!
//! Contradiction detection answers "do these two claims disagree?". Confidence composition answers
//! "how much should anyone believe this one?", and takes the first as *one input among five*.
//! Keeping them apart is not tidiness: each carries its own `(algorithm, version)` pair, which
//! ADR 0001 §6 makes a compatibility surface. Fused into one module they would share a version, and
//! rewording a disposition rule would force every stored confidence figure to be treated as stale.
//!
//! # Where this picks up from `brolga-model`
//!
//! [`ConfidenceBreakdown`] deliberately does not aggregate — its module says so, and says the
//! aggregation belongs to `v0.3.0` "where it can be versioned as an algorithm and tested against
//! fixtures". This is that module. It builds on those types rather than replacing them: the figure
//! it produces *is* a [`ConfidenceBreakdown`], with [`ConfidenceMethod::Derived`] recording that
//! Brolga computed it rather than a source asserting it.
//!
//! The breakdown carries the four components the model defines. The assessment carries more —
//! weights, per-component reasons, penalties, and the contradictions — because a figure an analyst
//! cannot take apart is a figure they can only be told.
//!
//! # Corroboration is counted by the deduplicator, not here
//!
//! [`Corroboration::from_lineage`] reads a [`RecordLineage`] and counts only the observations that
//! [`DedupVerdict::increases_corroboration`] admits. A syndicated copy therefore cannot raise this
//! score, however many aggregators mirror it — and the count of what was discounted is kept, so
//! "five sources have this" and "one source has this and four mirrored it" are visibly different
//! rather than silently identical.
//!
//! # Unknown is not zero
//!
//! A component nobody supplied is omitted, not scored zero. It contributes neither value nor
//! weight, so an unknown source reliability leaves the other components' balance untouched instead
//! of quietly halving the result. When no component at all is known there is no derived figure —
//! the assessment says [`ConfidenceMethod::Unknown`] rather than asserting a number it cannot
//! defend.
//!
//! # Recency is not this module's opinion
//!
//! This module once carried its own banded step function over an observation's age, and its
//! documentation said [#23](https://github.com/jusso-dev/Brolga/issues/23) would take that over. It
//! has. The recency component is now the standing that [`crate::decay`] computes, under the
//! [`DecayPolicy`] carried in [`ConfidencePolicy::decay`], and
//! [`ConfidencePolicy::recency_score`] is a delegation rather than a second answer. Two notions of
//! freshness would drift the first time somebody tuned one of them, and an analyst comparing a
//! ranked list against a confidence figure would be comparing two different opinions about the same
//! day.
//!
//! What stays here is the *weight* recency carries against the other four components. How fast a
//! kind of artefact stops being the thing that was observed is a temporal question and lives there;
//! how much that costs a confidence figure is a composition question and lives here.
//!
//! # Configuration is versioned, because changing it changes the answer
//!
//! Every weight, curve, ladder rung, and penalty lives in [`ConfidencePolicy`], which produces a
//! [`ConfidencePolicy::digest`] — and that digest covers the decay policy's digest too, so a
//! half-life change makes stored figures stale exactly as a weight change does. Each assessment
//! records the digest that produced it, so [`ConfidenceAssessment::needs_recalculation`] can tell a
//! figure computed under today's configuration from one computed under last month's. Without that,
//! a weight change would leave two incomparable figures in the database with nothing to distinguish
//! them.

use std::collections::BTreeMap;

use brolga_model::{
    ConfidenceBreakdown, ConfidenceMethod, ConfidenceScore, ContentHash, LifecycleStatus, Timestamp,
};

use crate::contradiction::{ClaimStance, ContradictionDecision};
use crate::decay::{DecayPolicy, age_in_days};
use crate::dedup::{DedupVerdict, RecordLineage};

/// This algorithm's identifier, stamped into every assessment it produces.
///
/// A compatibility surface under ADR 0001 §6: changing what this `(id, version)` pair computes for
/// the same inputs *under the same policy* is a breaking change.
pub const CONFIDENCE_ALGORITHM: &str = "brolga.confidence.weighted-components";

/// This algorithm's version.
///
/// Bump when the *composition* changes — a new component, a different penalty order, a changed
/// treatment of unknowns. Changing a weight is a policy change, not an algorithm change, and is
/// carried by [`ConfidencePolicy::digest`] instead.
///
/// `2` because the recency component stopped being a band of this module's own and became the
/// standing [`crate::decay`] computes. Where a component's *value comes from* is composition, not
/// configuration: a figure computed under version 1 was scored against a different question, and
/// the digest alone would not have said so.
pub const CONFIDENCE_ALGORITHM_VERSION: u32 = 2;

/// The component name for a source's track record.
pub const COMPONENT_SOURCE_RELIABILITY: &str = "source_reliability";
/// The component name for this particular report's credibility.
pub const COMPONENT_INFORMATION_CREDIBILITY: &str = "information_credibility";
/// The component name for support from independent parties.
pub const COMPONENT_CORROBORATION: &str = "corroboration";
/// The component name for how current the underlying observation is.
pub const COMPONENT_RECENCY: &str = "recency";
/// The component name for how the claim came to be held.
pub const COMPONENT_STANCE: &str = "stance";

/// How much each component counts.
///
/// Integers, and combined by an integer weighted mean, so the same inputs give the same answer on
/// every machine. A weight of zero disables a component without removing it from the explanation,
/// which is the difference between "this did not count" and "this was never considered".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentWeights {
    /// Weight of the source's track record.
    pub source_reliability: u32,
    /// Weight of this report's credibility.
    pub information_credibility: u32,
    /// Weight of independent corroboration.
    pub corroboration: u32,
    /// Weight of how current the observation is.
    pub recency: u32,
    /// Weight of how the claim came to be held.
    pub stance: u32,
}

impl ComponentWeights {
    /// The starting balance.
    ///
    /// Reliability, credibility, and corroboration count equally because the Admiralty scale treats
    /// them as three separate questions and none of them subsumes another. Recency counts for less
    /// because an old observation of a still-live artefact is still evidence, and stance counts for
    /// least because it discriminates between four cases rather than a hundred.
    ///
    /// These are a starting policy for an operator to change, not a finding.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            source_reliability: 3,
            information_credibility: 3,
            corroboration: 3,
            recency: 2,
            stance: 1,
        }
    }
}

impl Default for ComponentWeights {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Everything an operator can change about how a figure is composed.
///
/// Every collection is ordered, so the [`Self::digest`] does not depend on insertion order or on
/// hash seeding: two deployments configured the same way produce the same digest and therefore the
/// same figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidencePolicy {
    /// An operator-set revision label.
    ///
    /// Part of the digest, so bumping it alone forces a recalculation. That is deliberate: an
    /// operator who wants everything recomputed should not have to perturb a weight to get it.
    pub revision: u32,
    /// How much each component counts.
    pub weights: ComponentWeights,
    /// The score for a given number of independent parties, indexed by that number.
    ///
    /// A ladder rather than a formula because each rung is a judgement somebody can disagree with
    /// in the open. Counts beyond the last rung take the last rung: corroboration saturates, so a
    /// widely mirrored indicator cannot climb past a genuinely well-attested one.
    pub corroboration_ladder: Vec<u8>,
    /// How a record's standing falls with age.
    ///
    /// The whole of the recency question, delegated. This module used to keep a band table of its
    /// own beside it; two notions of freshness in one crate is one too many, and the decay policy
    /// is the versioned, per-kind, floored one.
    pub decay: DecayPolicy,
    /// The score for each way a claim may have come to be held.
    pub stance_scores: BTreeMap<ClaimStance, u8>,
    /// Points deducted when an unresolved contradiction stands against the claim.
    ///
    /// A deduction rather than a veto. A contested claim is still evidence, and suppressing it
    /// would be the silent discard this project exists to avoid.
    pub contradiction_penalty: u8,
    /// Points deducted when the claim itself is no longer current.
    pub withdrawn_penalty: u8,
}

impl ConfidencePolicy {
    /// The starting policy.
    ///
    /// Every number here is a default for an operator to change, and every one of them is visible
    /// in the assessment it produces. None of it is a finding about any source.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            revision: 1,
            weights: ComponentWeights::defaults(),
            // Nought parties is not evidence; one is a single voice; the gain from the second is
            // the largest because it is the first that could have disagreed and did not.
            corroboration_ladder: vec![0, 25, 60, 80, 90, 100],
            decay: DecayPolicy::defaults(),
            stance_scores: BTreeMap::from([
                (ClaimStance::Observed, 100),
                // An analyst of this instance is trusted, but an operator's own note is not
                // stronger evidence than somebody who watched the thing happen.
                (ClaimStance::Analyst, 90),
                (ClaimStance::Reported, 70),
                // An inference is only ever as good as what it was drawn from, and what it was
                // drawn from is already counted elsewhere in this sum.
                (ClaimStance::Inferred, 55),
            ]),
            contradiction_penalty: 25,
            withdrawn_penalty: 40,
        }
    }

    /// The score for a given number of independent parties.
    ///
    /// Saturating: a count beyond the ladder takes its last rung rather than running off the end.
    #[must_use]
    pub fn corroboration_score(&self, independent_parties: usize) -> u8 {
        let last = self.corroboration_ladder.len().saturating_sub(1);
        self.corroboration_ladder
            .get(independent_parties.min(last))
            .copied()
            .unwrap_or(0)
    }

    /// The score for an observation of a given kind and age in whole days.
    ///
    /// A delegation, deliberately. The curve, the per-kind half-lives, the floors, and the
    /// exemptions all belong to [`crate::decay`], and a second implementation here — however
    /// small — would be a second answer to "how old is too old" that nothing would keep in step.
    #[must_use]
    pub fn recency_score(&self, kind: Option<&str>, age_in_days: u32) -> u8 {
        self.decay.standing_after(kind, age_in_days)
    }

    /// The score for a stance, where the policy gives one.
    #[must_use]
    pub fn stance_score(&self, stance: ClaimStance) -> Option<u8> {
        self.stance_scores.get(&stance).copied()
    }

    /// A digest of the whole configuration.
    ///
    /// Recorded on every assessment so that a figure can be told to have been computed under a
    /// configuration that no longer applies. Deterministic: fixed field order, and every collection
    /// iterated here is ordered.
    #[must_use]
    pub fn digest(&self) -> ContentHash {
        let mut material = format!(
            "brolga.confidence.policy/2\nrevision={}\nweights={},{},{},{},{}\ndecay={}\npenalties={},{}\nladder=",
            self.revision,
            self.weights.source_reliability,
            self.weights.information_credibility,
            self.weights.corroboration,
            self.weights.recency,
            self.weights.stance,
            // The decay policy's own digest rather than its fields, so a change there makes stored
            // confidence figures stale without this function having to know its shape.
            self.decay.digest(),
            self.contradiction_penalty,
            self.withdrawn_penalty,
        );
        for rung in &self.corroboration_ladder {
            material.push_str(&format!("{rung},"));
        }
        material.push_str("\nstances=");
        for (stance, score) in &self.stance_scores {
            material.push_str(&format!("{stance}:{score},"));
        }
        ContentHash::of(material.as_bytes())
    }
}

impl Default for ConfidencePolicy {
    fn default() -> Self {
        Self::defaults()
    }
}

/// How many independent parties assert a record, and how many observations were discounted.
///
/// Both halves are kept. "Five sources have this" and "one source has this and four mirrored it"
/// must not look the same, and the second number is the only thing that tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Corroboration {
    /// Distinct parties whose observation counted as independent.
    pub independent_parties: usize,
    /// Observations that did not count: exact duplicates, restatements, and syndicated copies.
    pub discounted_observations: usize,
}

impl Corroboration {
    /// Count a deduplicated record's lineage.
    ///
    /// The wiring that makes "a syndicated copy must not raise confidence" structural rather than
    /// remembered: an observation counts here only if [`DedupVerdict::increases_corroboration`]
    /// says it may, and that method has exactly one variant that returns `true`.
    #[must_use]
    pub fn from_lineage(lineage: &RecordLineage) -> Self {
        Self {
            independent_parties: lineage.corroboration(),
            discounted_observations: lineage
                .decisions
                .iter()
                .filter(|decision| !decision.verdict.increases_corroboration())
                .count(),
        }
    }

    /// Whether any observation was discounted.
    #[must_use]
    pub const fn discounted_anything(&self) -> bool {
        self.discounted_observations > 0
    }

    /// Whether a given verdict would count towards [`Self::independent_parties`].
    ///
    /// Exposed so a caller assembling corroboration by hand asks the deduplicator rather than
    /// re-deciding, which is how the two would drift apart.
    #[must_use]
    pub const fn counts(verdict: DedupVerdict) -> bool {
        verdict.increases_corroboration()
    }
}

/// One component's contribution, with the reason it contributed that much.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreComponent {
    /// Which component this is.
    pub component: &'static str,
    /// Its score, 0–100.
    pub score: ConfidenceScore,
    /// How much it counted. Zero means the policy switched it off.
    pub weight: u32,
    /// Why it scored what it did, in authored words.
    ///
    /// `&'static str`, never interpolated from feed content.
    pub reason: &'static str,
    /// The measurement behind the score — a count, an age, a label.
    ///
    /// Bounded and stripped of control characters, because it is rendered to operators.
    pub evidence: Option<String>,
}

/// A deduction from the composed figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Penalty {
    /// A stable label.
    pub name: &'static str,
    /// Points deducted.
    pub points: u8,
    /// Why, in authored words.
    pub reason: &'static str,
}

/// Why an analyst override was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OverrideRefused {
    /// The override named no decision-maker.
    #[error(
        "a confidence override must name the analyst making it; an unattributable override cannot be reviewed or appealed"
    )]
    NoActor,
    /// The override named no authority.
    #[error(
        "a confidence override must state its policy context; without it there is no record of under what authority the figure was changed"
    )]
    NoPolicyContext,
}

/// An operator's own figure, standing over what the sources support.
///
/// The actor and policy context are **required**, exactly as they are for a manual resolution
/// operation. A figure that overrides the evidence and names nobody is worse than no figure: it
/// cannot be reviewed, appealed, or learned from, and it is indistinguishable from a bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalystOverride {
    /// The figure the analyst asserts.
    pub score: ConfidenceScore,
    /// Who asserted it. Never empty.
    pub actor: String,
    /// Under what authority — a case reference, a policy name, a ticket. Never empty.
    pub policy_context: String,
    /// A bounded note.
    pub note: Option<String>,
}

impl AnalystOverride {
    /// Record an override.
    ///
    /// # Errors
    ///
    /// [`OverrideRefused`] if the override names no actor or no policy context.
    pub fn new(
        score: ConfidenceScore,
        actor: &str,
        policy_context: &str,
        note: Option<&str>,
    ) -> Result<Self, OverrideRefused> {
        if actor.trim().is_empty() {
            return Err(OverrideRefused::NoActor);
        }
        if policy_context.trim().is_empty() {
            return Err(OverrideRefused::NoPolicyContext);
        }
        Ok(Self {
            score,
            actor: bounded(actor),
            policy_context: bounded(policy_context),
            note: note.map(bounded),
        })
    }
}

/// Everything the scorer needs about one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoringInputs {
    /// What is being scored, as a stable rendering — normally a claim identifier.
    pub subject: String,
    /// The kind of subject, which selects the decay profile. `None` takes the default profile.
    ///
    /// An address and a file digest do not stop being what was observed at the same rate, and a
    /// single curve for both would be wrong for one of them.
    pub kind: Option<String>,
    /// The source's track record, where it is known. `None` means unknown, never zero.
    pub source_reliability: Option<ConfidenceScore>,
    /// This report's credibility, where it is known. `None` means unknown, never zero.
    pub information_credibility: Option<ConfidenceScore>,
    /// What the deduplicator counted, where deduplication has run.
    pub corroboration: Option<Corroboration>,
    /// When the subject was last observed, where that is known.
    pub observed_at: Option<Timestamp>,
    /// The instant the assessment is made against.
    pub now: Timestamp,
    /// How the claim came to be held.
    pub stance: ClaimStance,
    /// Whether the claim still stands.
    pub status: LifecycleStatus,
    /// Every contradiction decision touching this claim.
    ///
    /// Carried into the assessment whole rather than reduced to a count, because a penalty an
    /// analyst cannot expand into "which claim, from whom, saying what" is a number they can only
    /// be told.
    pub contradictions: Vec<ContradictionDecision>,
    /// An operator's figure, where one was entered.
    pub analyst_override: Option<AnalystOverride>,
}

impl ScoringInputs {
    /// Inputs that know nothing except what is being scored and when.
    ///
    /// Every component starts absent, so an assessment built from this admits it is unexplained
    /// rather than reporting a confident zero.
    #[must_use]
    pub fn unknown(subject: &str, now: Timestamp, stance: ClaimStance) -> Self {
        Self {
            subject: bounded(subject),
            kind: None,
            source_reliability: None,
            information_credibility: None,
            corroboration: None,
            observed_at: None,
            now,
            stance,
            status: LifecycleStatus::Active,
            contradictions: Vec::new(),
            analyst_override: None,
        }
    }
}

/// A composed confidence figure with everything behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidenceAssessment {
    /// What was scored.
    pub subject: String,
    /// Every component considered, in a fixed order.
    pub components: Vec<ScoreComponent>,
    /// Every deduction applied, in a fixed order.
    pub penalties: Vec<Penalty>,
    /// What the sources support, before any operator override.
    ///
    /// Kept even when an override is present. That is what "recorded separately from source claims"
    /// means: an operator can raise or lower the figure, and cannot make the evidence say something
    /// else.
    pub derived: ConfidenceBreakdown,
    /// The operator's figure, where one was entered.
    pub analyst_override: Option<AnalystOverride>,
    /// The figure downstream consumers should use.
    ///
    /// Equal to [`Self::derived`] unless an override stands, in which case the overall figure is the
    /// operator's and the method says so.
    pub breakdown: ConfidenceBreakdown,
    /// Every contradiction that bears on this claim, kept visible rather than folded into a number.
    pub contradictions: Vec<ContradictionDecision>,
    /// Which algorithm composed this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// The policy revision in force.
    pub policy_revision: u32,
    /// The digest of the policy in force.
    pub policy_digest: ContentHash,
}

impl ConfidenceAssessment {
    /// Whether any component was recorded.
    ///
    /// A figure with no components can only be asserted at an analyst, never explained to one.
    #[must_use]
    pub fn is_explained(&self) -> bool {
        !self.components.is_empty()
    }

    /// How many contradictions bear on this claim.
    #[must_use]
    pub fn contradiction_count(&self) -> usize {
        self.contradictions
            .iter()
            .filter(|decision| decision.is_contradiction())
            .count()
    }

    /// Whether an operator's figure stands over the evidence.
    #[must_use]
    pub const fn is_overridden(&self) -> bool {
        self.analyst_override.is_some()
    }

    /// Whether this figure was computed under the given policy and this build's algorithm.
    #[must_use]
    pub fn is_current_under(&self, policy: &ConfidencePolicy) -> bool {
        self.algorithm == CONFIDENCE_ALGORITHM
            && self.algorithm_version == CONFIDENCE_ALGORITHM_VERSION
            && self.policy_digest == policy.digest()
    }

    /// Whether this figure must be recomputed before it can be compared with a fresh one.
    ///
    /// The other half of "configuration changes produce versioned recalculation": a stored figure
    /// carries the digest that produced it, so a weight change makes every figure computed under
    /// the old weights visibly stale instead of silently incomparable.
    #[must_use]
    pub fn needs_recalculation(&self, policy: &ConfidencePolicy) -> bool {
        !self.is_current_under(policy)
    }

    /// A full explanation, for an operator.
    ///
    /// Every line is authored text or a bounded measurement. Contradiction evidence is rendered by
    /// [`ContradictionDecision::explain`], which withholds quotations that a handling restriction
    /// forbids repeating — so an explanation of a restricted decision can be shown without the
    /// restricted content travelling with it.
    #[must_use]
    pub fn explain(&self) -> String {
        let mut lines = vec![format!(
            "{} = {} ({}) by {} v{} under policy revision {}",
            self.subject,
            self.breakdown.overall,
            method_label(self.breakdown.method),
            self.algorithm,
            self.algorithm_version,
            self.policy_revision,
        )];

        for component in &self.components {
            let measurement = component
                .evidence
                .as_ref()
                .map_or_else(String::new, |evidence| format!(" [{evidence}]"));
            lines.push(format!(
                "  {} = {} (weight {}){measurement}: {}",
                component.component, component.score, component.weight, component.reason
            ));
        }

        for penalty in &self.penalties {
            lines.push(format!(
                "  -{} {}: {}",
                penalty.points, penalty.name, penalty.reason
            ));
        }

        for decision in &self.contradictions {
            lines.push(format!("  contradiction: {}", decision.explain()));
        }

        if let Some(override_figure) = &self.analyst_override {
            lines.push(format!(
                "  override = {} by {} under {}: sources support {}",
                override_figure.score,
                override_figure.actor,
                override_figure.policy_context,
                self.derived.overall,
            ));
        }

        lines.join("\n")
    }
}

/// Composes confidence figures under one policy.
#[derive(Debug, Clone, Default)]
pub struct ConfidenceScorer {
    policy: ConfidencePolicy,
}

impl ConfidenceScorer {
    /// A scorer under the starting policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A scorer under an operator's policy.
    #[must_use]
    pub const fn with_policy(policy: ConfidencePolicy) -> Self {
        Self { policy }
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &ConfidencePolicy {
        &self.policy
    }

    /// Compose a figure.
    ///
    /// Deterministic for fixed inputs: components are produced in a fixed order, contradictions are
    /// sorted before they are counted or carried, the arithmetic is integer throughout, and no
    /// collection iterated here is hash-ordered.
    #[must_use]
    pub fn assess(&self, inputs: &ScoringInputs) -> ConfidenceAssessment {
        let mut components = Vec::new();

        if let Some(reliability) = inputs.source_reliability {
            components.push(ScoreComponent {
                component: COMPONENT_SOURCE_RELIABILITY,
                score: reliability,
                weight: self.policy.weights.source_reliability,
                reason: "the publishing source's track record, which is a property of the source \
                         and not of this particular report",
                evidence: None,
            });
        }

        if let Some(credibility) = inputs.information_credibility {
            components.push(ScoreComponent {
                component: COMPONENT_INFORMATION_CREDIBILITY,
                score: credibility,
                weight: self.policy.weights.information_credibility,
                reason: "the credibility of this particular report, which a reliable source can \
                         get wrong and an unreliable one can get right",
                evidence: None,
            });
        }

        if let Some(corroboration) = inputs.corroboration {
            let score = self
                .policy
                .corroboration_score(corroboration.independent_parties);
            components.push(ScoreComponent {
                component: COMPONENT_CORROBORATION,
                score: score_of(score),
                weight: self.policy.weights.corroboration,
                reason: if corroboration.discounted_anything() {
                    "support from parties the deduplicator judged independent; copies and \
                     restatements were discounted and did not raise this"
                } else {
                    "support from parties the deduplicator judged independent"
                },
                evidence: Some(bounded(&format!(
                    "{} independent, {} discounted",
                    corroboration.independent_parties, corroboration.discounted_observations
                ))),
            });
        }

        if let Some(observed_at) = inputs.observed_at {
            let kind = inputs.kind.as_deref();
            let age = age_in_days(observed_at, inputs.now);
            let profile = self.policy.decay.profile_for(kind);
            components.push(ScoreComponent {
                component: COMPONENT_RECENCY,
                score: score_of(self.policy.recency_score(kind, age)),
                weight: self.policy.weights.recency,
                reason: if profile.never_decays() {
                    "how current the underlying observation is; policy exempts this kind from \
                     decay, because age is only evidence where the thing observed can stop being \
                     the thing observed"
                } else {
                    "how current the underlying observation is, taken from the decay curve for \
                     this kind of record: one half-life halves what remains, and it never falls \
                     below the policy's floor"
                },
                evidence: Some(bounded(&format!(
                    "{age} days old, half-life {} days, floor {}",
                    profile.half_life_days(),
                    profile.floor(),
                ))),
            });
        }

        if let Some(stance) = self.policy.stance_score(inputs.stance) {
            components.push(ScoreComponent {
                component: COMPONENT_STANCE,
                score: score_of(stance),
                weight: self.policy.weights.stance,
                reason: "how the claim came to be held: seeing a thing, relaying somebody who saw \
                         it, and working it out are different standings",
                evidence: Some(bounded(inputs.stance.as_str())),
            });
        }

        // Sorted before anything is counted, so the order contradictions were handed over in cannot
        // change the figure or the record of it.
        let mut contradictions = inputs.contradictions.clone();
        contradictions.sort_by(|a, b| {
            a.subject
                .cmp(&b.subject)
                .then_with(|| a.left.cmp(&b.left))
                .then_with(|| a.right.cmp(&b.right))
        });

        let base = weighted_mean(&components);

        let mut penalties = Vec::new();
        if contradictions
            .iter()
            .any(ContradictionDecision::is_contradiction)
        {
            penalties.push(Penalty {
                name: "contradicted",
                points: self.policy.contradiction_penalty,
                reason: "an unresolved contradiction stands against this claim; the claim is kept \
                         and shown rather than suppressed, and the disagreement costs it",
            });
        }
        if let Some(reason) = withdrawal_reason(inputs.status) {
            penalties.push(Penalty {
                name: "not_current",
                points: self.policy.withdrawn_penalty,
                reason,
            });
        }

        let deduction = penalties
            .iter()
            .fold(0_u8, |total, penalty| total.saturating_add(penalty.points));

        let derived = match base {
            Some(value) => ConfidenceBreakdown {
                overall: score_of(value.saturating_sub(deduction)),
                method: ConfidenceMethod::Derived,
                source_reliability: inputs.source_reliability,
                information_credibility: inputs.information_credibility,
                corroboration: component_score(&components, COMPONENT_CORROBORATION),
                recency: component_score(&components, COMPONENT_RECENCY),
            },
            // Nothing was known, so nothing is asserted. A zero here would read as "assessed and
            // disbelieved", which is a different statement from "not assessed".
            None => ConfidenceBreakdown::unexplained(ConfidenceScore::MIN),
        };

        let breakdown = match &inputs.analyst_override {
            Some(override_figure) => ConfidenceBreakdown {
                overall: override_figure.score,
                method: ConfidenceMethod::OperatorAsserted,
                ..derived
            },
            None => derived,
        };

        ConfidenceAssessment {
            subject: inputs.subject.clone(),
            components,
            penalties,
            derived,
            analyst_override: inputs.analyst_override.clone(),
            breakdown,
            contradictions,
            algorithm: CONFIDENCE_ALGORITHM,
            algorithm_version: CONFIDENCE_ALGORITHM_VERSION,
            policy_revision: self.policy.revision,
            policy_digest: self.policy.digest(),
        }
    }
}

/// The weighted mean of the components, or `None` when nothing carried any weight.
///
/// Integer throughout, and `checked_div` rather than `/` so a policy that zeroes every weight
/// produces "no figure" instead of a division by zero. Rounds down, which errs towards claiming
/// less.
fn weighted_mean(components: &[ScoreComponent]) -> Option<u8> {
    let mut weighted: u64 = 0;
    let mut total: u64 = 0;
    for component in components {
        weighted = weighted.saturating_add(
            u64::from(component.score.get()).saturating_mul(u64::from(component.weight)),
        );
        total = total.saturating_add(u64::from(component.weight));
    }
    let mean = weighted.checked_div(total)?;
    u8::try_from(mean.min(100)).ok()
}

/// One component's score, for the model's breakdown.
fn component_score(components: &[ScoreComponent], name: &str) -> Option<ConfidenceScore> {
    components
        .iter()
        .find(|component| component.component == name)
        .map(|component| component.score)
}

/// Why a claim is not current, where it is not.
///
/// A match rather than `is_current`, because the reasons stay distinguishable: "was wrong" and "is
/// old" are different statements and an analyst reading a penalty needs to know which applies.
const fn withdrawal_reason(status: LifecycleStatus) -> Option<&'static str> {
    match status {
        LifecycleStatus::Revoked => Some(
            "the publisher withdrew this assertion; it was wrong rather than merely old, and it is \
             retained as history",
        ),
        LifecycleStatus::Superseded => Some(
            "a later record replaced this one; the subject is still described, by something else",
        ),
        LifecycleStatus::Expired => Some(
            "the asserted validity window has closed; the claim was right and is no longer current",
        ),
        _ => None,
    }
}

/// Build a score from a value already bounded to `0..=100`.
///
/// Written as a clamp rather than an unwrap because this crate does not panic on arithmetic: every
/// caller here has already bounded the value, so the clamp never fires, and if a future one has not
/// then a wrong-but-explainable figure beats a crash on hostile input.
fn score_of(value: u8) -> ConfidenceScore {
    ConfidenceScore::new(value.min(100)).unwrap_or(ConfidenceScore::MAX)
}

/// A stable label for a method, for explanations.
const fn method_label(method: ConfidenceMethod) -> &'static str {
    match method {
        ConfidenceMethod::SourceAsserted => "source asserted",
        ConfidenceMethod::Derived => "derived",
        ConfidenceMethod::OperatorAsserted => "operator asserted",
        _ => "method unknown",
    }
}

/// Bound an excerpt and strip control characters.
///
/// Assessments are rendered to operators through terminals, and a measurement or a note carrying
/// escape sequences must not reach one intact.
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
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

    fn now() -> Timestamp {
        Timestamp::parse_rfc3339("2026-07-29T00:00:00Z").unwrap()
    }

    fn score(value: u8) -> ConfidenceScore {
        ConfidenceScore::new(value).unwrap()
    }

    /// A component nobody supplied must not be scored as a zero. That is how a source which simply
    /// never published a reliability rating gets treated as though it had been rated untrustworthy.
    #[test]
    fn an_absent_component_is_not_the_same_as_a_component_scored_zero() {
        let scorer = ConfidenceScorer::new();

        let mut absent = ScoringInputs::unknown("claim-1", now(), ClaimStance::Observed);
        absent.information_credibility = Some(score(80));

        let mut rated_zero = absent.clone();
        rated_zero.source_reliability = Some(score(0));

        let absent = scorer.assess(&absent);
        let rated_zero = scorer.assess(&rated_zero);

        assert!(
            absent.breakdown.overall > rated_zero.breakdown.overall,
            "unknown was treated as a zero: {} against {}",
            absent.breakdown.overall,
            rated_zero.breakdown.overall
        );
        assert_eq!(absent.components.len(), 2, "credibility and stance");
        assert_eq!(rated_zero.components.len(), 3);
    }

    /// Nothing known means nothing asserted. A confident zero is a different statement from "not
    /// assessed", and the model's own types keep them apart.
    #[test]
    fn an_assessment_with_no_components_admits_it_knows_nothing() {
        let policy = ConfidencePolicy {
            weights: ComponentWeights {
                source_reliability: 0,
                information_credibility: 0,
                corroboration: 0,
                recency: 0,
                stance: 0,
            },
            ..ConfidencePolicy::defaults()
        };
        let scorer = ConfidenceScorer::with_policy(policy);
        let assessment = scorer.assess(&ScoringInputs::unknown(
            "claim-1",
            now(),
            ClaimStance::Observed,
        ));

        assert_eq!(assessment.breakdown.method, ConfidenceMethod::Unknown);
        assert_eq!(assessment.breakdown.overall, ConfidenceScore::MIN);
    }

    /// The corroboration ladder must saturate, or a widely mirrored indicator could out-score a
    /// genuinely well-attested one simply by being mirrored more.
    #[test]
    fn the_corroboration_ladder_saturates_at_its_last_rung() {
        let policy = ConfidencePolicy::defaults();
        assert_eq!(
            policy.corroboration_score(5),
            policy.corroboration_score(50)
        );
        assert_eq!(policy.corroboration_score(0), 0);
    }

    /// Recency must be the decay module's answer, not a second one kept here. If this ever
    /// diverges, an analyst comparing a ranked list against a confidence figure is comparing two
    /// different opinions about the same day.
    #[test]
    fn the_recency_component_is_the_decay_policys_answer_and_not_a_second_one() {
        let policy = ConfidencePolicy::defaults();
        for (kind, age) in [
            (None, 0),
            (None, 45),
            (Some("domain_name"), 45),
            (Some("ipv4_address"), 200),
            (Some("file_hash"), 10_000),
        ] {
            assert_eq!(
                policy.recency_score(kind, age),
                policy.decay.standing_after(kind, age),
                "{kind:?} at {age} days"
            );
        }

        // A kind the operator exempted does not age, and one that decays never reaches nought.
        assert_eq!(policy.recency_score(Some("file_hash"), 10_000), 100);
        assert!(policy.recency_score(Some("ipv4_address"), 100_000) > 0);
    }

    /// A timestamp in the future is a data error, and must not make a claim fresher than one
    /// observed this morning. Whether such a timestamp is believed at all is
    /// [`crate::decay::FutureDating`]'s decision, not this module's.
    #[test]
    fn an_observation_dated_in_the_future_is_treated_as_no_age_at_all() {
        let future = Timestamp::parse_rfc3339("2030-01-01T00:00:00Z").unwrap();
        assert_eq!(age_in_days(future, now()), 0);
    }

    /// The policy is configuration, and configuration that cannot be identified cannot be shown to
    /// have changed.
    #[test]
    fn changing_any_part_of_the_policy_changes_its_digest() {
        let base = ConfidencePolicy::defaults();
        assert_eq!(base.digest(), ConfidencePolicy::defaults().digest());

        let mut reweighted = ConfidencePolicy::defaults();
        reweighted.weights.recency = 5;
        assert_ne!(base.digest(), reweighted.digest());

        let mut relabelled = ConfidencePolicy::defaults();
        relabelled.revision = 2;
        assert_ne!(base.digest(), relabelled.digest());

        let mut repenalised = ConfidencePolicy::defaults();
        repenalised.contradiction_penalty = 5;
        assert_ne!(base.digest(), repenalised.digest());

        // The decay policy is part of this configuration now, so retuning a half-life must make
        // stored confidence figures stale exactly as retuning a weight does.
        let mut re_decayed = ConfidencePolicy::defaults();
        re_decayed.decay = DecayPolicy::defaults().with_revision(2);
        assert_ne!(base.digest(), re_decayed.digest());
    }

    /// An override must name who made it and under what authority, or it is indistinguishable from
    /// a bug.
    #[test]
    fn an_override_without_an_actor_or_a_context_is_refused() {
        assert_eq!(
            AnalystOverride::new(score(20), "  ", "case-1", None),
            Err(OverrideRefused::NoActor)
        );
        assert_eq!(
            AnalystOverride::new(score(20), "analyst@example.org", "", None),
            Err(OverrideRefused::NoPolicyContext)
        );
        assert!(AnalystOverride::new(score(20), "analyst@example.org", "case-1", None).is_ok());
    }

    /// Every assessment carries the algorithm, version, and policy that produced it, so a stored
    /// figure can be attributed rather than assumed.
    #[test]
    fn every_assessment_carries_its_algorithm_version_and_policy() {
        let scorer = ConfidenceScorer::new();
        let assessment = scorer.assess(&ScoringInputs::unknown(
            "claim-1",
            now(),
            ClaimStance::Observed,
        ));

        assert_eq!(assessment.algorithm, CONFIDENCE_ALGORITHM);
        assert_eq!(assessment.algorithm_version, CONFIDENCE_ALGORITHM_VERSION);
        assert_eq!(
            assessment.policy_digest,
            ConfidencePolicy::defaults().digest()
        );
        assert!(!assessment.needs_recalculation(&ConfidencePolicy::defaults()));
    }
}
