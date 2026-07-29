//! Predicate-aware contradiction detection: telling disagreement from difference.
//!
//! # Why this cannot be "the values differ"
//!
//! Two claims about `evil.example` saying `malicious` and `benign` disagree. Two claims saying
//! `registrar = Example Registrar` and `country = AU` do not — they are not even about the same
//! question. Comparing values without first agreeing on *which question* they answer manufactures
//! contradictions out of ordinary difference, and an operator who is shown ten fabricated conflicts
//! stops reading the eleventh, which is real.
//!
//! So a comparison happens only inside one **predicate slot** — one named question about one
//! subject. Different slots are not compared at all, and a slot this build has no rule for is
//! reported as undecided rather than guessed at.
//!
//! # What is deliberately never compared
//!
//! Free-text narrative occupies no predicate slot. Deciding whether *"observed hosting a phishing
//! kit"* contradicts *"no malicious activity observed"* needs a similarity measure over prose, and
//! [#21](https://github.com/jusso-dev/Brolga/issues/21)'s non-goals rule out fuzzy matching,
//! embeddings, and any heuristic that cannot be explained to the analyst it affects. Declining is
//! the honest answer; a plausible guess is not.
//!
//! Attributes are compared only when an operator has declared the attribute single-valued. A domain
//! has one registrar and may have many tags, and Brolga does not know which is which until it is
//! told. Treating every differing attribute as a conflict would drown the real ones.
//!
//! # Withdrawal is not disagreement
//!
//! A publisher that revokes its own claim, or replaces it with a later one, has changed its mind —
//! it is not in a fight with itself. Checking status and supersession *before* the value table is
//! what stops a source correcting itself from being reported as a contradiction, which would
//! penalise exactly the publishers who behave well.
//!
//! # Every decision is a record
//!
//! ADR 0004 §2. Each decision carries what it compared, what it decided, which algorithm and
//! version decided it, and why. The reasons are authored `&'static str`, never interpolated from
//! feed content: a reason is read by an operator and may be branched on by a policy, and untrusted
//! bytes belong in neither. Where the decision has to quote what was compared, that goes in
//! [`ContradictionDecision::evidence`], bounded and stripped of control characters — and withheld
//! entirely when a contributing claim's handling restriction forbids repeating it, which is this
//! issue's security note: a restricted claim may still move an internal decision, provided the
//! output can explain the decision without leaking the content.

use std::collections::BTreeSet;

use brolga_model::{
    Assertion, Claim, ContentHash, Disposition, Id, LifecycleStatus, MarkingSet, NodeRef,
    Timestamp, TlpLevel,
};
use serde::{Deserialize, Serialize};

/// This detector's identifier, stamped into every decision it records.
///
/// A compatibility surface under ADR 0001 §6: changing what this `(id, version)` pair decides for
/// the same inputs is a breaking change, because stored decisions carry it and a consumer may have
/// relied on them.
pub const CONTRADICTION_ALGORITHM: &str = "brolga.contradiction.predicate-slots";

/// This detector's version.
///
/// Bump when the *decision* changes for some input, not when a message is reworded.
pub const CONTRADICTION_ALGORITHM_VERSION: u32 = 1;

/// How a claim came to be held.
///
/// The four cases [#22](https://github.com/jusso-dev/Brolga/issues/22) names. They are kept apart
/// because they are not interchangeable evidence: somebody who saw a thing, somebody relaying
/// somebody else who saw it, somebody who worked it out, and an operator of this instance are four
/// different standings, and collapsing them would make "who actually saw this?" unanswerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClaimStance {
    /// The publisher observed the subject itself.
    Observed,
    /// The publisher relays an observation somebody else made.
    Reported,
    /// Derived by analysis rather than observed. Only ever as good as what it was derived from.
    Inferred,
    /// Entered by an operator of this instance, not by a source.
    Analyst,
}

impl ClaimStance {
    /// Whether this claim came from an operator of this instance rather than from a source.
    ///
    /// The distinction an override rests on: an analyst disagreeing with a feed is a decision to be
    /// recorded, not a contradiction between two sources.
    #[must_use]
    pub const fn is_analyst(self) -> bool {
        matches!(self, Self::Analyst)
    }

    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Reported => "reported",
            Self::Inferred => "inferred",
            Self::Analyst => "analyst",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "observed" => Some(Self::Observed),
            "reported" => Some(Self::Reported),
            "inferred" => Some(Self::Inferred),
            "analyst" => Some(Self::Analyst),
            _ => None,
        }
    }
}

impl core::fmt::Display for ClaimStance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The named question a claim answers about its subject.
///
/// Two claims are comparable only when they answer the same question. There is no slot for
/// narrative, which is what keeps prose out of the comparison entirely.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Predicate {
    /// Whether the subject is malicious. Intrinsically single-valued, so its conflicts are built in.
    Disposition,
    /// A named attribute of the subject.
    ///
    /// Whether two values in this slot conflict depends on whether the attribute holds one value at
    /// a time, which only an operator can say — see [`ContradictionRules::single_valued`].
    Attribute(String),
}

impl Predicate {
    /// The slot an assertion occupies, if it occupies one.
    ///
    /// `None` for narrative, and for any assertion shape a later model version adds. Declining to
    /// place an assertion is safe; placing it in the wrong slot manufactures a contradiction.
    #[must_use]
    pub fn of(assertion: &Assertion) -> Option<Self> {
        match assertion {
            Assertion::Disposition(_) => Some(Self::Disposition),
            Assertion::Attribute { name, .. } => Some(Self::Attribute(name.as_str().to_owned())),
            _ => None,
        }
    }

    /// A stable label, used for ordering and written to the database.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Disposition => "disposition".to_owned(),
            Self::Attribute(name) => format!("attribute:{name}"),
        }
    }
}

impl core::fmt::Display for Predicate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.label())
    }
}

/// What the detector concluded about one pair of claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClaimRelation {
    /// One slot, one value: two voices saying the same thing.
    Agrees,
    /// One slot, different values that can both stand.
    ///
    /// `malicious` and `suspicious` differ in strength, not in direction. Recording this separately
    /// from [`Self::Agrees`] keeps "they said the same thing" honest.
    Compatible,
    /// One slot, values that cannot both be acted on. **Kept and surfaced, never resolved.**
    Conflicts,
    /// The same publisher replaced its earlier claim with a later one.
    ///
    /// A publisher changing its mind is not in a fight with itself, and reporting it as one would
    /// penalise the sources that correct themselves.
    Supersedes,
    /// One side was withdrawn by the publisher that made it.
    ///
    /// A withdrawn claim is retained — deleting it would destroy the record that the assertion was
    /// ever made — but it no longer disagrees with anything.
    Revoked,
    /// An analyst's claim standing over a source's.
    ///
    /// Recorded as its own relation so that an operator's judgement is never counted as a second
    /// source disagreeing with the first.
    AnalystOverride,
    /// Different subjects, different slots, or an assertion that occupies no slot.
    Unrelated,
    /// One slot, and this build has no rule for the pair of values in it.
    ///
    /// The honest answer when the model gains a value this version was not written against.
    /// Inventing agreement would hide a conflict; inventing a conflict would fabricate one.
    Undecided,
}

impl ClaimRelation {
    /// Whether this relation is a contradiction that an analyst must see.
    ///
    /// Exactly one variant returns `true`. An analyst override is a decision, not a disagreement,
    /// and a withdrawal is a correction.
    #[must_use]
    pub const fn is_contradiction(self) -> bool {
        matches!(self, Self::Conflicts)
    }

    /// Whether the two claims say the same thing.
    #[must_use]
    pub const fn is_agreement(self) -> bool {
        matches!(self, Self::Agrees)
    }

    /// Whether the pair was compared at all.
    ///
    /// `false` for pairs that share no slot and for pairs this build has no rule for, which are two
    /// different kinds of "no answer" and stay distinguishable in the variant.
    #[must_use]
    pub const fn was_compared(self) -> bool {
        !matches!(self, Self::Unrelated | Self::Undecided)
    }

    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agrees => "agrees",
            Self::Compatible => "compatible",
            Self::Conflicts => "conflicts",
            Self::Supersedes => "supersedes",
            Self::Revoked => "revoked",
            Self::AnalystOverride => "analyst_override",
            Self::Unrelated => "unrelated",
            Self::Undecided => "undecided",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "agrees" => Some(Self::Agrees),
            "compatible" => Some(Self::Compatible),
            "conflicts" => Some(Self::Conflicts),
            "supersedes" => Some(Self::Supersedes),
            "revoked" => Some(Self::Revoked),
            "analyst_override" => Some(Self::AnalystOverride),
            "unrelated" => Some(Self::Unrelated),
            "undecided" => Some(Self::Undecided),
            _ => None,
        }
    }
}

impl core::fmt::Display for ClaimRelation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A claim as the detector sees it.
///
/// The publisher and stance are caller-supplied rather than derived from the claim, for the same
/// reason [`Observation::publisher`](crate::dedup::Observation::publisher) is: "who published this"
/// and "did they see it themselves" are policy questions that the record itself cannot settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedClaim {
    /// The claim's canonical identifier.
    pub id: Id<Claim>,
    /// What the claim is about. Claims about different subjects are never compared.
    pub subject: NodeRef,
    /// What is asserted.
    pub assertion: Assertion,
    /// How the claim came to be held.
    pub stance: ClaimStance,
    /// Whether the assertion still stands.
    pub status: LifecycleStatus,
    /// Who published it.
    pub publisher: String,
    /// When the publisher last observed the subject, where that is known.
    ///
    /// Used only to order two claims from one publisher. Absent means the two cannot be ordered,
    /// and the pair falls through to the value comparison rather than guessing which came first.
    pub asserted_at: Option<Timestamp>,
    /// Handling restrictions, so evidence can be withheld without the decision being lost.
    pub markings: MarkingSet,
}

impl ReviewedClaim {
    /// Build from a canonical claim.
    ///
    /// The stance and publisher have to be supplied because a [`Claim`] does not carry either: the
    /// model records where a record came from, not whether the party that sent it saw the thing.
    #[must_use]
    pub fn from_claim(claim: &Claim, stance: ClaimStance, publisher: String) -> Self {
        Self {
            id: claim.id,
            subject: claim.subject,
            assertion: claim.assertion.clone(),
            stance,
            status: claim.status,
            publisher,
            asserted_at: claim.temporal.last_seen,
            markings: claim.markings.clone(),
        }
    }

    /// The slot this claim's assertion occupies, if any.
    #[must_use]
    pub fn predicate(&self) -> Option<Predicate> {
        Predicate::of(&self.assertion)
    }

    /// The most restrictive sharing level on this claim.
    fn sharing_level(&self) -> Option<TlpLevel> {
        self.markings.most_restrictive_tlp()
    }
}

/// A recorded contradiction decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionDecision {
    /// The subject both claims are about, as a stable rendering.
    ///
    /// The decision's subject rather than either claim's identifier, so every decision about one
    /// domain can be found together.
    pub subject: String,
    /// The slot compared, where the pair shared one.
    pub predicate: Option<Predicate>,
    /// The lower claim identifier of the pair.
    pub left: Id<Claim>,
    /// The higher claim identifier of the pair.
    pub right: Id<Claim>,
    /// What was decided.
    pub relation: ClaimRelation,
    /// Which algorithm decided it.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// Why, in authored words.
    ///
    /// `&'static str`, never interpolated from feed content: an operator reads this and a policy may
    /// branch on it, and untrusted bytes belong in neither.
    pub reason: &'static str,
    /// What was actually compared, quoted.
    ///
    /// Owned because it quotes record content, so it is bounded and stripped of control characters.
    /// `None` when there was nothing to quote, or when [`Self::evidence_withheld`] is set.
    pub evidence: Option<String>,
    /// Whether the quotation was suppressed by a handling restriction.
    ///
    /// The decision still stands and still counts. This issue's security note permits restricted
    /// material to move an internal decision precisely so long as the output can explain the
    /// decision without repeating the content, and the flag is how a reader tells "nothing to
    /// quote" from "not allowed to quote".
    pub evidence_withheld: bool,
}

impl ContradictionDecision {
    /// Whether this decision is a contradiction an analyst must see.
    #[must_use]
    pub const fn is_contradiction(&self) -> bool {
        self.relation.is_contradiction()
    }

    /// A one-line explanation, for a queue a person reads.
    #[must_use]
    pub fn explain(&self) -> String {
        let slot = self
            .predicate
            .as_ref()
            .map_or_else(|| "no shared predicate".to_owned(), Predicate::label);
        match (&self.evidence, self.evidence_withheld) {
            (Some(evidence), _) => {
                format!("{} [{slot}] — {}: {evidence}", self.relation, self.reason)
            }
            (None, true) => format!(
                "{} [{slot}] — {}: evidence withheld under a handling restriction",
                self.relation, self.reason
            ),
            (None, false) => format!("{} [{slot}] — {}", self.relation, self.reason),
        }
    }
}

/// Which attributes hold one value at a time, and how much may be quoted.
///
/// Empty by default, and deliberately so. Brolga does not know whether `tag` may repeat and
/// `registrar` may not, and guessing would either fabricate conflicts or hide them. An operator
/// declares it, the declaration is part of the configuration, and changing it changes what is
/// detected — which is why [`ContradictionRules::digest`] exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionRules {
    single_valued: BTreeSet<String>,
    evidence_ceiling: TlpLevel,
}

impl Default for ContradictionRules {
    fn default() -> Self {
        Self::new()
    }
}

impl ContradictionRules {
    /// Rules that declare no attribute single-valued and quote nothing above `TLP:AMBER`.
    ///
    /// The ceiling is a default an operator may raise or lower; it is not a claim about what any
    /// particular deployment is permitted to show.
    #[must_use]
    pub fn new() -> Self {
        Self {
            single_valued: BTreeSet::new(),
            evidence_ceiling: TlpLevel::Amber,
        }
    }

    /// Declare an attribute to hold one value at a time.
    #[must_use]
    pub fn with_single_valued(mut self, attribute: &str) -> Self {
        self.single_valued.insert(attribute.to_owned());
        self
    }

    /// Set the most restrictive sharing level whose content may be quoted in evidence.
    #[must_use]
    pub fn with_evidence_ceiling(mut self, ceiling: TlpLevel) -> Self {
        self.evidence_ceiling = ceiling;
        self
    }

    /// Whether an attribute has been declared to hold one value at a time.
    #[must_use]
    pub fn single_valued(&self, attribute: &str) -> bool {
        self.single_valued.contains(attribute)
    }

    /// The most restrictive sharing level whose content may be quoted.
    #[must_use]
    pub const fn evidence_ceiling(&self) -> TlpLevel {
        self.evidence_ceiling
    }

    /// A digest of the configuration these rules represent.
    ///
    /// Two deployments with the same digest detect the same contradictions from the same claims.
    /// Deterministic because the attribute set is a `BTreeSet`, so the rendering does not depend on
    /// insertion order or on hash seeding.
    #[must_use]
    pub fn digest(&self) -> ContentHash {
        let mut material = String::from("brolga.contradiction.rules/1\nceiling=");
        material.push_str(self.evidence_ceiling.as_str());
        material.push_str("\nsingle_valued=");
        for attribute in &self.single_valued {
            material.push_str(attribute);
            material.push('\u{1f}');
        }
        ContentHash::of(material.as_bytes())
    }
}

/// Judges claims about one subject against each other.
#[derive(Debug, Clone, Default)]
pub struct ContradictionDetector {
    rules: ContradictionRules,
}

impl ContradictionDetector {
    /// A detector with no attribute declared single-valued.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector over an operator's rules.
    #[must_use]
    pub const fn with_rules(rules: ContradictionRules) -> Self {
        Self { rules }
    }

    /// The rules in force.
    #[must_use]
    pub const fn rules(&self) -> &ContradictionRules {
        &self.rules
    }

    /// Judge one pair.
    ///
    /// Deterministic for fixed inputs: the pair is ordered by identifier before anything is
    /// compared, so `relate(a, b)` and `relate(b, a)` are the same decision rather than mirror
    /// images that a caller has to reconcile.
    #[must_use]
    pub fn relate(&self, left: &ReviewedClaim, right: &ReviewedClaim) -> ContradictionDecision {
        let (first, second) = if left.id <= right.id {
            (left, right)
        } else {
            (right, left)
        };

        let forbidden = self.quotation_forbidden(first, second);
        let decide = |predicate: Option<Predicate>,
                      relation,
                      reason,
                      evidence: Option<String>|
         -> ContradictionDecision {
            // Withheld only where there was something to withhold, so a reader can tell "nothing
            // to quote" from "not allowed to quote" and knows when to go and ask for it.
            let withheld = forbidden && evidence.is_some();
            ContradictionDecision {
                subject: first.subject.to_string(),
                predicate,
                left: first.id,
                right: second.id,
                relation,
                algorithm: CONTRADICTION_ALGORITHM,
                algorithm_version: CONTRADICTION_ALGORITHM_VERSION,
                reason,
                evidence: if withheld {
                    None
                } else {
                    evidence.map(|text| bounded(&text))
                },
                evidence_withheld: withheld,
            }
        };

        // Different subjects are not a disagreement about anything.
        if first.subject != second.subject {
            return decide(
                None,
                ClaimRelation::Unrelated,
                "the two claims are about different subjects, so neither can contradict the other",
                None,
            );
        }

        // Narrative occupies no slot, and neither does any assertion shape this build does not
        // know. Deciding whether two paragraphs disagree needs a similarity measure over prose,
        // which this crate does not have and will not acquire.
        let (Some(left_slot), Some(right_slot)) = (first.predicate(), second.predicate()) else {
            return decide(
                None,
                ClaimRelation::Unrelated,
                "at least one assertion occupies no comparable predicate slot; comparing free text \
                 would need a similarity measure this crate deliberately does not have",
                None,
            );
        };

        if left_slot != right_slot {
            return decide(
                None,
                ClaimRelation::Unrelated,
                "the two claims answer different questions about the subject, and different \
                 questions cannot disagree",
                None,
            );
        }

        let slot = Some(left_slot);

        // Withdrawal and supersession come before the value table. A publisher that corrected
        // itself is not in a fight with itself, and reporting it as one would penalise exactly the
        // sources that behave well.
        if first.status == LifecycleStatus::Revoked || second.status == LifecycleStatus::Revoked {
            return decide(
                slot,
                ClaimRelation::Revoked,
                "one of the two claims was withdrawn by the publisher that made it; it is retained \
                 as history and no longer disagrees with anything",
                None,
            );
        }

        if first.status == LifecycleStatus::Superseded
            || second.status == LifecycleStatus::Superseded
        {
            return decide(
                slot,
                ClaimRelation::Supersedes,
                "one of the two claims was marked as replaced by a later record, so the pair is a \
                 revision rather than a disagreement",
                None,
            );
        }

        let same_value = same_assertion(&first.assertion, &second.assertion);

        if !same_value && first.publisher == second.publisher && ordered_in_time(first, second) {
            return decide(
                slot,
                ClaimRelation::Supersedes,
                "the same publisher later asserted a different value in this slot; that is a \
                 publisher changing its mind, not two publishers disagreeing",
                Some(quoted_pair(&first.assertion, &second.assertion)),
            );
        }

        // An analyst disagreeing with a feed is a decision this instance made, and counting it as a
        // second source disagreeing with the first would let an operator manufacture consensus.
        if !same_value && first.stance.is_analyst() != second.stance.is_analyst() {
            return decide(
                slot,
                ClaimRelation::AnalystOverride,
                "an analyst of this instance asserts a different value from a source; that is a \
                 recorded decision, not a disagreement between two sources",
                Some(quoted_pair(&first.assertion, &second.assertion)),
            );
        }

        if same_value {
            return decide(
                slot,
                ClaimRelation::Agrees,
                "both claims assert the same value in the same slot about the same subject",
                Some(quoted_pair(&first.assertion, &second.assertion)),
            );
        }

        let (relation, reason) = self.compare_values(&first.assertion, &second.assertion);
        decide(
            slot,
            relation,
            reason,
            Some(quoted_pair(&first.assertion, &second.assertion)),
        )
    }

    /// Judge every pair in a set.
    ///
    /// Ordered by subject, then slot, then identifier, so two runs over the same claims in any
    /// arrival order produce byte-identical output. Nothing here iterates a hash-ordered collection.
    #[must_use]
    pub fn review(&self, claims: &[ReviewedClaim]) -> ContradictionReport {
        let mut decisions = Vec::new();
        for (index, left) in claims.iter().enumerate() {
            for right in claims.iter().skip(index.saturating_add(1)) {
                decisions.push(self.relate(left, right));
            }
        }
        decisions.sort_by(|a, b| {
            a.subject
                .cmp(&b.subject)
                .then_with(|| slot_label(a).cmp(&slot_label(b)))
                .then_with(|| a.left.cmp(&b.left))
                .then_with(|| a.right.cmp(&b.right))
        });
        ContradictionReport { decisions }
    }

    /// Whether a quotation of either claim's content is forbidden by its handling restrictions.
    fn quotation_forbidden(&self, left: &ReviewedClaim, right: &ReviewedClaim) -> bool {
        [left.sharing_level(), right.sharing_level()]
            .into_iter()
            .flatten()
            .any(|level| level > self.rules.evidence_ceiling)
    }

    /// Compare two differing values in one slot.
    fn compare_values(&self, left: &Assertion, right: &Assertion) -> (ClaimRelation, &'static str) {
        match (left, right) {
            (Assertion::Disposition(first), Assertion::Disposition(second)) => {
                disposition_rule(*first, *second)
            }
            (Assertion::Attribute { name, .. }, Assertion::Attribute { .. }) => {
                if self.rules.single_valued(name.as_str()) {
                    (
                        ClaimRelation::Conflicts,
                        "this attribute was declared to hold one value at a time, and the two \
                         claims give it different values",
                    )
                } else {
                    (
                        ClaimRelation::Compatible,
                        "this attribute was not declared to hold one value at a time, so two \
                         different values may both stand; declaring it is an operator decision",
                    )
                }
            }
            _ => (
                ClaimRelation::Undecided,
                "the two claims share a predicate slot that this build has no comparison rule for, \
                 so it declines to decide rather than inventing agreement or conflict",
            ),
        }
    }
}

/// Everything the detector concluded about a set of claims.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContradictionReport {
    /// Every decision, in a deterministic order.
    ///
    /// Every pair, not only the conflicting ones. "These two were compared and agreed" is as much a
    /// finding as a conflict, and dropping it would leave nobody able to tell a pair that was
    /// judged compatible from a pair that was never judged.
    pub decisions: Vec<ContradictionDecision>,
}

impl ContradictionReport {
    /// The decisions an analyst must see.
    #[must_use]
    pub fn contradictions(&self) -> Vec<&ContradictionDecision> {
        self.decisions
            .iter()
            .filter(|decision| decision.is_contradiction())
            .collect()
    }

    /// How many pairs conflict.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.is_contradiction())
            .count()
    }

    /// Whether anything conflicts.
    #[must_use]
    pub fn has_contradiction(&self) -> bool {
        self.decisions
            .iter()
            .any(ContradictionDecision::is_contradiction)
    }
}

/// The rule for two differing dispositions.
///
/// An exhaustive table rather than an ordering, because the five values are not on one axis:
/// `allow_listed` is a decision about how Brolga treats a subject, not a finding about it, so it
/// conflicts with a malicious finding while agreeing in effect with a benign one.
///
/// Normalised so each pair is written once. The wildcard is reachable only if
/// [`Disposition`] gains a value, and it answers [`ClaimRelation::Undecided`] rather than guessing.
fn disposition_rule(left: Disposition, right: Disposition) -> (ClaimRelation, &'static str) {
    let (lower, higher) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };

    match (lower, higher) {
        (Disposition::Malicious, Disposition::Suspicious) => (
            ClaimRelation::Compatible,
            "a malicious assessment and a suspicious one differ in strength, not in direction, and \
             acting on either does not deny the other",
        ),
        (Disposition::Malicious, Disposition::Benign) => (
            ClaimRelation::Conflicts,
            "one publisher assessed the subject as malicious and another as not malicious; both \
             cannot be acted on, and the disagreement is kept rather than resolved",
        ),
        (Disposition::Malicious, Disposition::AllowListed) => (
            ClaimRelation::Conflicts,
            "the subject is asserted malicious and is also excluded from detection; acting on \
             either denies the other, and an exclusion that hides a malicious finding is exactly \
             what an operator needs to be shown",
        ),
        (Disposition::Suspicious, Disposition::Benign) => (
            ClaimRelation::Conflicts,
            "one publisher assessed the subject as warranting attention and another as not \
             malicious; the disagreement is kept rather than averaged away",
        ),
        (Disposition::Suspicious, Disposition::AllowListed) => (
            ClaimRelation::Conflicts,
            "the subject warrants attention and is also excluded from detection; acting on either \
             denies the other",
        ),
        (Disposition::Benign, Disposition::AllowListed) => (
            ClaimRelation::Compatible,
            "a benign finding and an exclusion from detection point the same way, even though one \
             is a finding about the subject and the other a decision about how it is treated",
        ),
        (_, Disposition::Unknown) => (
            ClaimRelation::Compatible,
            "one side records that the subject has not been assessed, and an unassessed \
             disposition denies nothing",
        ),
        _ => (
            ClaimRelation::Undecided,
            "this build has no rule for the pair of dispositions in this slot, so it declines to \
             decide rather than inventing agreement or conflict",
        ),
    }
}

/// Whether two assertions state the same thing.
fn same_assertion(left: &Assertion, right: &Assertion) -> bool {
    left == right
}

/// Whether the two claims can be put in time order.
///
/// Both timestamps are required. One claim with a time and one without cannot be ordered, and
/// assuming the dated one is later would turn a missing field into a supersession.
fn ordered_in_time(left: &ReviewedClaim, right: &ReviewedClaim) -> bool {
    match (left.asserted_at, right.asserted_at) {
        (Some(first), Some(second)) => first != second,
        _ => false,
    }
}

/// Render the two values compared, for evidence.
///
/// Not a reason: this quotes record content, so it is bounded and stripped by [`bounded`] before it
/// reaches a decision.
fn quoted_pair(left: &Assertion, right: &Assertion) -> String {
    format!("{} vs {}", rendered(left), rendered(right))
}

/// Render one assertion's value.
fn rendered(assertion: &Assertion) -> String {
    match assertion {
        Assertion::Disposition(disposition) => disposition.as_str().to_owned(),
        Assertion::Attribute { name, value } => format!("{}={}", name.as_str(), value.as_str()),
        Assertion::Narrative(text) => text.as_str().to_owned(),
        // `Assertion` is `#[non_exhaustive]`. An unknown shape must still render to something a
        // reader can tell apart from a known one, rather than to an empty string.
        _ => "unrenderable assertion shape".to_owned(),
    }
}

/// The sort key for a decision's slot.
fn slot_label(decision: &ContradictionDecision) -> String {
    decision
        .predicate
        .as_ref()
        .map_or_else(String::new, Predicate::label)
}

/// Bound an excerpt and strip control characters.
///
/// Evidence quotes record content and is read through terminals, so a value carrying escape
/// sequences or a megabyte of text must not reach one intact.
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
    use brolga_model::observable::{DomainName, Observable};
    use brolga_model::{ShortText, UntrustedText};

    fn subject(domain: &str) -> NodeRef {
        NodeRef::Observable(Observable::DomainName(DomainName::new(domain).unwrap()).id())
    }

    fn claim(domain: &str, assertion: Assertion, publisher: &str) -> ReviewedClaim {
        let subject = subject(domain);
        ReviewedClaim {
            id: Claim::derive_id(&subject, &assertion),
            subject,
            assertion,
            stance: ClaimStance::Observed,
            status: LifecycleStatus::Active,
            publisher: publisher.to_owned(),
            asserted_at: None,
            markings: MarkingSet::empty(),
        }
    }

    fn disposition(domain: &str, value: Disposition, publisher: &str) -> ReviewedClaim {
        claim(domain, Assertion::Disposition(value), publisher)
    }

    /// Exactly one relation may be a contradiction. If a second ever is, an analyst override or a
    /// publisher's own correction starts being counted as a source disagreement.
    #[test]
    fn exactly_one_relation_is_a_contradiction() {
        let contradicting = [
            ClaimRelation::Agrees,
            ClaimRelation::Compatible,
            ClaimRelation::Conflicts,
            ClaimRelation::Supersedes,
            ClaimRelation::Revoked,
            ClaimRelation::AnalystOverride,
            ClaimRelation::Unrelated,
            ClaimRelation::Undecided,
        ]
        .into_iter()
        .filter(|relation| relation.is_contradiction())
        .count();
        assert_eq!(contradicting, 1);
    }

    /// Labels are written to the database, so they are a compatibility surface.
    #[test]
    fn every_relation_label_round_trips_and_an_unknown_one_is_refused() {
        for relation in [
            ClaimRelation::Agrees,
            ClaimRelation::Compatible,
            ClaimRelation::Conflicts,
            ClaimRelation::Supersedes,
            ClaimRelation::Revoked,
            ClaimRelation::AnalystOverride,
            ClaimRelation::Unrelated,
            ClaimRelation::Undecided,
        ] {
            assert_eq!(
                ClaimRelation::from_str_opt(relation.as_str()),
                Some(relation)
            );
        }
        assert_eq!(ClaimRelation::from_str_opt("probably_fine"), None);
    }

    /// Stance labels are written to the database too.
    #[test]
    fn every_stance_label_round_trips_and_an_unknown_one_is_refused() {
        for stance in [
            ClaimStance::Observed,
            ClaimStance::Reported,
            ClaimStance::Inferred,
            ClaimStance::Analyst,
        ] {
            assert_eq!(ClaimStance::from_str_opt(stance.as_str()), Some(stance));
        }
        assert_eq!(ClaimStance::from_str_opt("guessed"), None);
    }

    /// Every pair of dispositions this build knows must be decided. If the table loses an arm, a
    /// real conflict silently becomes "undecided" and nobody is shown it.
    #[test]
    fn every_known_pair_of_dispositions_has_a_rule() {
        let all = [
            Disposition::Malicious,
            Disposition::Suspicious,
            Disposition::Benign,
            Disposition::AllowListed,
            Disposition::Unknown,
        ];
        for left in all {
            for right in all {
                if left == right {
                    continue;
                }
                let (relation, reason) = disposition_rule(left, right);
                assert_ne!(
                    relation,
                    ClaimRelation::Undecided,
                    "no rule for {left} vs {right}"
                );
                assert!(!reason.is_empty());
            }
        }
    }

    /// The table must be symmetric, or which claim arrived first would change the verdict.
    #[test]
    fn the_disposition_table_is_symmetric() {
        let all = [
            Disposition::Malicious,
            Disposition::Suspicious,
            Disposition::Benign,
            Disposition::AllowListed,
            Disposition::Unknown,
        ];
        for left in all {
            for right in all {
                assert_eq!(
                    disposition_rule(left, right).0,
                    disposition_rule(right, left).0
                );
            }
        }
    }

    /// Every decision carries the algorithm and version that made it, so a stored decision can be
    /// attributed rather than assumed.
    #[test]
    fn every_decision_carries_its_algorithm_and_version() {
        let detector = ContradictionDetector::new();
        let decision = detector.relate(
            &disposition("example.com", Disposition::Malicious, "feed-a"),
            &disposition("example.com", Disposition::Benign, "feed-b"),
        );
        assert_eq!(decision.algorithm, CONTRADICTION_ALGORITHM);
        assert_eq!(decision.algorithm_version, CONTRADICTION_ALGORITHM_VERSION);
        assert!(!decision.reason.is_empty());
    }

    /// The pair order must not change the decision, or a caller would have to reconcile mirror
    /// images of one judgement.
    #[test]
    fn relating_a_pair_is_symmetric() {
        let detector = ContradictionDetector::new();
        let malicious = disposition("example.com", Disposition::Malicious, "feed-a");
        let benign = disposition("example.com", Disposition::Benign, "feed-b");

        assert_eq!(
            detector.relate(&malicious, &benign),
            detector.relate(&benign, &malicious)
        );
    }

    /// Evidence quotes record content, so a feed publishing a megabyte of it must not put a
    /// megabyte into a record an operator reads.
    #[test]
    fn evidence_is_bounded_however_long_the_quoted_value_is() {
        let rules = ContradictionRules::new().with_single_valued("registrar");
        let detector = ContradictionDetector::with_rules(rules);

        let left = claim(
            "example.com",
            Assertion::Attribute {
                name: ShortText::new("registrar").unwrap(),
                value: UntrustedText::new("a".repeat(5_000)).unwrap(),
            },
            "feed-a",
        );
        let right = claim(
            "example.com",
            Assertion::Attribute {
                name: ShortText::new("registrar").unwrap(),
                value: UntrustedText::new("Other Registrar").unwrap(),
            },
            "feed-b",
        );

        let decision = detector.relate(&left, &right);
        let evidence = decision.evidence.unwrap();
        assert_eq!(decision.relation, ClaimRelation::Conflicts);
        assert!(evidence.chars().count() <= 200);
    }

    /// The model refuses control characters at the boundary, so this is the second line of
    /// defence — and the one that still holds if evidence is ever assembled from somewhere the
    /// model did not vet.
    #[test]
    fn bounding_strips_control_characters_as_well_as_truncating() {
        let stripped = bounded(&format!("\u{1b}[2J{}", "a".repeat(500)));
        assert!(!stripped.chars().any(char::is_control));
        assert_eq!(stripped.chars().count(), 200);
    }

    /// The rules are configuration, and configuration that cannot be identified cannot be shown to
    /// have changed.
    #[test]
    fn changing_the_rules_changes_their_digest() {
        let base = ContradictionRules::new();
        assert_eq!(base.digest(), ContradictionRules::new().digest());
        assert_ne!(
            base.digest(),
            base.clone().with_single_valued("registrar").digest()
        );
        assert_ne!(
            base.digest(),
            base.clone().with_evidence_ceiling(TlpLevel::Red).digest()
        );
    }

    /// Declaration order must not change the digest, or two identically configured deployments
    /// would look different.
    #[test]
    fn the_rules_digest_does_not_depend_on_declaration_order() {
        let one = ContradictionRules::new()
            .with_single_valued("registrar")
            .with_single_valued("asn");
        let other = ContradictionRules::new()
            .with_single_valued("asn")
            .with_single_valued("registrar");
        assert_eq!(one.digest(), other.digest());
    }
}
