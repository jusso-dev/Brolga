//! Entity resolution: deciding when two records are the same thing.
//!
//! # Names are not identity
//!
//! The single most damaging thing an intelligence platform can do is merge two threat actors
//! because their names look alike. "APT28" and "APT-28" probably are the same group. "Lazarus" the
//! DPRK actor and "Lazarus" the ransomware family are not. "Sandworm" and "Sandworm Team" are;
//! "Turla" and "Turla Group" are; "Winnti" the group and "Winnti" the malware are famously not.
//!
//! A merge is also close to irreversible in practice: once two actors' claims, sightings, and
//! relationships are attributed to one identity, unpicking which evidence belonged to which is
//! work nobody has the information to do afterwards.
//!
//! So [#21](https://github.com/jusso-dev/Brolga/issues/21) requires that actors, malware,
//! campaigns, and organisations **never merge on name similarity alone**, and this module enforces
//! that structurally rather than by policy: a merge requires at least one
//! [`Strength::Decisive`] signal, and no name-based matcher can produce one. Name similarity is
//! evidence that a human should look, and nothing else.
//!
//! # What counts as decisive
//!
//! Only identity that an external authority assigned and both records carry:
//!
//! - The **same canonical identifier** — the records already resolve to one thing.
//! - The **same external identifier** in the same namespace — two records both carrying MITRE's
//!   `G0007`, or the same MISP UUID, or the same CVE. The authority did the identification; Brolga
//!   is reading it, not inferring it.
//! - A **declared alias** — somebody stated that these two names denote one thing, and that
//!   statement is recorded with who made it.
//!
//! Everything else is supporting evidence at best.
//!
//! # A rejection is a standing decision
//!
//! When an analyst says "these two are not the same", that has to survive the next import. Otherwise
//! every automatic pass re-proposes the same wrong merge and the analyst's judgement is worn down by
//! a machine that cannot remember. A rejection stands until it is explicitly withdrawn — which is
//! itself a recorded operation with an actor against it.

use std::collections::{BTreeMap, BTreeSet};

use brolga_model::{Entity, EntityKind, Id, Marking, MarkingSet};
use serde::{Deserialize, Serialize};

/// This resolver's identifier, stamped into every candidate and decision it produces.
pub const RESOLVE_ALGORITHM: &str = "brolga.resolve.exact-and-declared";

/// This resolver's version.
pub const RESOLVE_ALGORITHM_VERSION: u32 = 1;

/// How much weight a matcher's finding carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Strength {
    /// Suggestive, and never sufficient on its own.
    ///
    /// Every name-based signal is at most this. That is the structural half of "never merge on name
    /// similarity alone": a merge asks for a decisive signal, and no name matcher can produce one.
    Weak,
    /// Meaningful corroboration, still not sufficient alone.
    Supporting,
    /// An external authority already identified these as one thing.
    Decisive,
}

impl Strength {
    /// Whether a signal of this strength can, by itself, justify a merge.
    #[must_use]
    pub const fn can_merge_alone(self) -> bool {
        matches!(self, Self::Decisive)
    }

    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Supporting => "supporting",
            Self::Decisive => "decisive",
        }
    }
}

impl core::fmt::Display for Strength {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One matcher's finding about a pair of records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchSignal {
    /// Which matcher found it.
    pub matcher: &'static str,
    /// How much weight it carries.
    pub strength: Strength,
    /// A 0–100 contribution, for ordering candidates a human will review.
    pub score: u8,
    /// Why, in authored words.
    pub reason: &'static str,
    /// What was actually compared — the shared identifier, the alias, the names.
    ///
    /// Owned because it quotes record content. Bounded and stripped of control characters, because
    /// a candidate list is read by analysts through terminals.
    pub evidence: String,
}

/// What resolution concluded about a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResolutionOutcome {
    /// Two distinct things. Nothing suggested otherwise.
    Distinct,
    /// Something suggested they are the same, but nothing decisive. **A human decides.**
    Candidate,
    /// A decisive signal: automatically resolved to one identity.
    Merged,
    /// A human said these are not the same, and that stands until withdrawn.
    Rejected,
    /// A human pinned this identity: it may not be merged into anything by any automatic pass.
    Pinned,
}

impl ResolutionOutcome {
    /// Whether the two records end up as one identity.
    #[must_use]
    pub const fn unifies(self) -> bool {
        matches!(self, Self::Merged)
    }

    /// Whether this outcome is waiting on a person.
    #[must_use]
    pub const fn needs_review(self) -> bool {
        matches!(self, Self::Candidate)
    }

    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Distinct => "distinct",
            Self::Candidate => "candidate",
            Self::Merged => "merged",
            Self::Rejected => "rejected",
            Self::Pinned => "pinned",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "distinct" => Some(Self::Distinct),
            "candidate" => Some(Self::Candidate),
            "merged" => Some(Self::Merged),
            "rejected" => Some(Self::Rejected),
            "pinned" => Some(Self::Pinned),
            _ => None,
        }
    }
}

impl core::fmt::Display for ResolutionOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A resolution proposal about one pair, with everything needed to judge it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionCandidate {
    /// The lower identifier of the pair.
    pub left: Id<Entity>,
    /// The higher identifier of the pair.
    pub right: Id<Entity>,
    /// What was concluded.
    pub outcome: ResolutionOutcome,
    /// Every matcher's finding, strongest first.
    pub signals: Vec<MatchSignal>,
    /// The combined score, 0–100, for ordering a review queue.
    pub score: u8,
    /// Which resolver produced this.
    pub algorithm: &'static str,
    /// That resolver's version.
    pub algorithm_version: u32,
}

impl ResolutionCandidate {
    /// The strongest signal found.
    #[must_use]
    pub fn strongest(&self) -> Option<Strength> {
        self.signals.iter().map(|signal| signal.strength).max()
    }

    /// A one-line explanation, for a review queue.
    #[must_use]
    pub fn explain(&self) -> String {
        let reasons: Vec<String> = self
            .signals
            .iter()
            .map(|signal| {
                format!(
                    "{} ({}): {}",
                    signal.matcher, signal.strength, signal.reason
                )
            })
            .collect();
        if reasons.is_empty() {
            return format!("{} — nothing matched", self.outcome);
        }
        format!(
            "{} (score {}) — {}",
            self.outcome,
            self.score,
            reasons.join("; ")
        )
    }
}

/// Which manual operation an analyst performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationKind {
    /// Declare two identities to be one.
    Merge,
    /// Undo a merge, restoring two identities.
    Split,
    /// Declare two identities to be different, standing until withdrawn.
    Reject,
    /// Declare one name to denote the same thing as another.
    Alias,
    /// Protect an identity from any automatic merge.
    Pin,
}

impl OperationKind {
    /// The operation that reverses this one, where there is one.
    ///
    /// `Split` reverses `Merge`. Everything else reverses by being withdrawn, which is recorded as
    /// its own operation rather than by deleting the original — an audit trail that can be edited
    /// is not one.
    #[must_use]
    pub const fn inverse(self) -> Option<Self> {
        match self {
            Self::Merge => Some(Self::Split),
            Self::Split => Some(Self::Merge),
            _ => None,
        }
    }

    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Split => "split",
            Self::Reject => "reject",
            Self::Alias => "alias",
            Self::Pin => "pin",
        }
    }
}

impl core::fmt::Display for OperationKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A manual resolution decision, with who made it and under what authority.
///
/// The actor and policy context are **required**, not optional. A merge with no attributable
/// decision-maker cannot be reviewed, appealed, or learned from, and this issue's security note
/// makes them a precondition rather than metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualOperation {
    /// What was done.
    pub kind: OperationKind,
    /// The lower identifier.
    pub left: Id<Entity>,
    /// The higher identifier, where the operation concerns a pair.
    pub right: Option<Id<Entity>>,
    /// Who did it. Never empty.
    pub actor: String,
    /// Under what authority — a case reference, a policy name, a ticket.  Never empty.
    pub policy_context: String,
    /// A free-text note, bounded.
    pub note: Option<String>,
    /// Whether this operation withdraws an earlier one of the same kind.
    ///
    /// A withdrawal is recorded, never a deletion. An audit trail that can be edited is not one.
    pub withdraws: bool,
}

/// Why a manual operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OperationRefused {
    /// The operation named no decision-maker.
    #[error(
        "a {kind} operation must name the actor performing it; an unattributable decision cannot be reviewed or appealed"
    )]
    NoActor {
        /// The operation attempted.
        kind: OperationKind,
    },
    /// The operation named no authority.
    #[error(
        "a {kind} operation must state its policy context; without it there is no record of under what authority the decision was made"
    )]
    NoPolicyContext {
        /// The operation attempted.
        kind: OperationKind,
    },
    /// The operation concerns a pair but named only one identity.
    #[error("a {kind} operation concerns two identities and only one was given")]
    NeedsPair {
        /// The operation attempted.
        kind: OperationKind,
    },
    /// A merge was attempted against a pinned identity.
    #[error("{pinned} is pinned and cannot be merged; a pin exists precisely to stop this")]
    Pinned {
        /// The pinned identity.
        pinned: String,
    },
}

/// Declared aliases and standing analyst decisions.
///
/// Deterministic by construction: every collection here is ordered, so replaying the same
/// operations in the same order always yields the same state, and iterating never depends on hash
/// seeding.
#[derive(Debug, Default, Clone)]
pub struct ResolutionState {
    aliases: BTreeMap<String, String>,
    rejections: BTreeSet<(String, String)>,
    pins: BTreeSet<String>,
    merges: BTreeMap<String, String>,
    history: Vec<ManualOperation>,
}

impl ResolutionState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a manual operation, recording it.
    ///
    /// # Errors
    ///
    /// [`OperationRefused`] if the operation names no actor, no policy context, needs a pair it was
    /// not given, or targets a pinned identity.
    pub fn apply(&mut self, operation: ManualOperation) -> Result<(), OperationRefused> {
        if operation.actor.trim().is_empty() {
            return Err(OperationRefused::NoActor {
                kind: operation.kind,
            });
        }
        if operation.policy_context.trim().is_empty() {
            return Err(OperationRefused::NoPolicyContext {
                kind: operation.kind,
            });
        }

        let needs_pair = matches!(
            operation.kind,
            OperationKind::Merge
                | OperationKind::Split
                | OperationKind::Reject
                | OperationKind::Alias
        );
        if needs_pair && operation.right.is_none() {
            return Err(OperationRefused::NeedsPair {
                kind: operation.kind,
            });
        }

        let left = operation.left.to_string();
        let right = operation.right.map(|id| id.to_string());

        match operation.kind {
            OperationKind::Merge => {
                let right = right.clone().unwrap_or_default();
                // A pin exists precisely to stop this, and it stops a *manual* merge too — an
                // analyst who pinned an identity should not have it merged by a colleague who did
                // not see the pin.
                for candidate in [&left, &right] {
                    if self.pins.contains(candidate) {
                        return Err(OperationRefused::Pinned {
                            pinned: candidate.clone(),
                        });
                    }
                }
                let (survivor, absorbed) = ordered(&left, &right);
                self.merges.insert(absorbed, survivor);
            }
            OperationKind::Split => {
                let right = right.clone().unwrap_or_default();
                let (_, absorbed) = ordered(&left, &right);
                self.merges.remove(&absorbed);
            }
            OperationKind::Reject => {
                let right = right.clone().unwrap_or_default();
                let pair = ordered(&left, &right);
                if operation.withdraws {
                    self.rejections.remove(&pair);
                } else {
                    self.rejections.insert(pair);
                }
            }
            OperationKind::Alias => {
                let right = right.clone().unwrap_or_default();
                let (canonical, alias) = ordered(&left, &right);
                if operation.withdraws {
                    self.aliases.remove(&alias);
                } else {
                    self.aliases.insert(alias, canonical);
                }
            }
            OperationKind::Pin => {
                if operation.withdraws {
                    self.pins.remove(&left);
                } else {
                    self.pins.insert(left.clone());
                }
            }
        }

        self.history.push(operation);
        Ok(())
    }

    /// Replay a sequence of operations onto a fresh state.
    ///
    /// The audit trail *is* the state: the same operations in the same order always reconstruct the
    /// same result, so "how did we get here?" is answerable by replaying rather than by trusting a
    /// snapshot.
    ///
    /// # Errors
    ///
    /// The first [`OperationRefused`] encountered, with the state left as it was up to that point.
    pub fn replay(
        operations: impl IntoIterator<Item = ManualOperation>,
    ) -> Result<Self, OperationRefused> {
        let mut state = Self::new();
        for operation in operations {
            state.apply(operation)?;
        }
        Ok(state)
    }

    /// Every operation applied, in order.
    #[must_use]
    pub fn history(&self) -> &[ManualOperation] {
        &self.history
    }

    /// Whether a pair has been rejected and the rejection still stands.
    #[must_use]
    pub fn is_rejected(&self, left: Id<Entity>, right: Id<Entity>) -> bool {
        self.rejections
            .contains(&ordered(&left.to_string(), &right.to_string()))
    }

    /// Whether an identity is pinned.
    #[must_use]
    pub fn is_pinned(&self, id: Id<Entity>) -> bool {
        self.pins.contains(&id.to_string())
    }

    /// The identity a record has been merged into, following the chain to its end.
    ///
    /// Bounded: a merge chain cannot exceed the number of recorded merges, so a cycle introduced by
    /// a bad sequence terminates rather than looping.
    #[must_use]
    pub fn canonical_identity(&self, id: Id<Entity>) -> String {
        let mut current = id.to_string();
        for _ in 0..=self.merges.len() {
            match self.merges.get(&current) {
                Some(next) if *next != current => current = next.clone(),
                _ => break,
            }
        }
        current
    }

    /// Whether two identities are declared aliases of one another.
    #[must_use]
    pub fn is_alias(&self, left: Id<Entity>, right: Id<Entity>) -> bool {
        let (canonical, alias) = ordered(&left.to_string(), &right.to_string());
        self.aliases.get(&alias) == Some(&canonical)
    }
}

/// Order a pair so that a comparison is symmetric.
///
/// Without this, rejecting (A, B) would leave (B, A) un-rejected and the next automatic pass would
/// re-propose the merge an analyst just refused.
fn ordered(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_owned(), right.to_owned())
    } else {
        (right.to_owned(), left.to_owned())
    }
}

/// Which entity kinds this issue names as never mergeable on name similarity alone.
///
/// The list is the issue's, not an inference. Every other kind is held to the same rule anyway —
/// see [`Resolver::resolve`] — but these are the ones where getting it wrong is most damaging.
pub const NAME_SENSITIVE_KINDS: &[EntityKind] = &[
    EntityKind::ThreatActor,
    EntityKind::MalwareFamily,
    EntityKind::Campaign,
    EntityKind::Identity,
    EntityKind::IntrusionSet,
];

/// A record as the resolver sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvableRecord {
    /// The canonical identifier.
    pub id: Id<Entity>,
    /// What kind of thing it is.
    pub kind: EntityKind,
    /// Its primary name.
    pub name: String,
    /// External identifiers it carries, as `namespace` to `value`.
    ///
    /// The decisive signal. `mitre-attack` to `G0007`, `misp` to a UUID, `cve` to `CVE-2021-44228`.
    pub external_ids: BTreeMap<String, String>,
    /// Markings, so a merge can be checked for marking loss.
    pub markings: MarkingSet,
    /// The source objects this record's evidence came from.
    pub sources: Vec<String>,
}

impl ResolvableRecord {
    /// Build from a canonical entity.
    #[must_use]
    pub fn from_entity(entity: &Entity, external_ids: BTreeMap<String, String>) -> Self {
        Self {
            id: entity.id,
            kind: entity.kind,
            name: entity.name.as_str().to_owned(),
            external_ids,
            markings: entity.markings.clone(),
            sources: Vec::new(),
        }
    }
}

/// Resolves records against each other, honouring standing analyst decisions.
#[derive(Debug, Default)]
pub struct Resolver {
    state: ResolutionState,
}

impl Resolver {
    /// A resolver with no standing decisions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A resolver over an existing set of analyst decisions.
    #[must_use]
    pub const fn with_state(state: ResolutionState) -> Self {
        Self { state }
    }

    /// The standing decisions.
    #[must_use]
    pub const fn state(&self) -> &ResolutionState {
        &self.state
    }

    /// The standing decisions, mutably.
    pub const fn state_mut(&mut self) -> &mut ResolutionState {
        &mut self.state
    }

    /// Judge one pair.
    ///
    /// Deterministic for fixed inputs: the pair is ordered before anything is compared, signals are
    /// produced in a fixed matcher order and then sorted by strength then matcher name, and no
    /// collection iterated here is hash-ordered.
    #[must_use]
    pub fn resolve(
        &self,
        left: &ResolvableRecord,
        right: &ResolvableRecord,
    ) -> ResolutionCandidate {
        let (first, second) = if left.id.to_string() <= right.id.to_string() {
            (left, right)
        } else {
            (right, left)
        };

        // Standing analyst decisions come first. A rejection that could be overridden by the next
        // import is not a decision, it is a suggestion the machine is free to ignore.
        if self.state.is_rejected(first.id, second.id) {
            return candidate(first, second, ResolutionOutcome::Rejected, vec![], 0);
        }

        let mut signals = Vec::new();

        if first.id == second.id {
            signals.push(MatchSignal {
                matcher: "canonical-identifier",
                strength: Strength::Decisive,
                score: 100,
                reason: "both records already resolve to the same canonical identifier",
                evidence: bounded(&first.id.to_string()),
            });
        }

        // The authority did the identification; Brolga is reading it, not inferring it.
        for (namespace, value) in &first.external_ids {
            if second.external_ids.get(namespace) == Some(value) {
                signals.push(MatchSignal {
                    matcher: "external-identifier",
                    strength: Strength::Decisive,
                    score: 95,
                    reason: "both records carry the same identifier in the same external namespace, \
                             assigned by that authority rather than inferred here",
                    evidence: bounded(&format!("{namespace}={value}")),
                });
            }
        }

        if self.state.is_alias(first.id, second.id) {
            signals.push(MatchSignal {
                matcher: "declared-alias",
                strength: Strength::Decisive,
                score: 90,
                reason: "an analyst declared these two names to denote one thing, and the \
                         declaration is recorded with who made it",
                evidence: bounded(&format!("{} = {}", first.name, second.name)),
            });
        }

        if first.kind == second.kind && normalised(&first.name) == normalised(&second.name) {
            // Deliberately not decisive, even for an exact name match after normalisation. Two
            // things genuinely do share a name — "Lazarus" the actor and "Lazarus" the malware,
            // "Winnti" the group and "Winnti" the tool — and a merge is close to irreversible in
            // practice once claims and sightings are attributed to one identity.
            signals.push(MatchSignal {
                matcher: "normalised-name",
                strength: Strength::Supporting,
                score: 60,
                reason: "the names match after normalisation, which is evidence a human should \
                         look and is never sufficient on its own",
                evidence: bounded(&format!("{} ~ {}", first.name, second.name)),
            });
        } else if first.kind == second.kind && shares_a_token(&first.name, &second.name) {
            signals.push(MatchSignal {
                matcher: "shared-name-token",
                strength: Strength::Weak,
                score: 25,
                reason: "the names share a significant token, which is the weakest kind of hint \
                         and routinely wrong",
                evidence: bounded(&format!("{} ~ {}", first.name, second.name)),
            });
        }

        signals.sort_by(|a, b| {
            b.strength
                .cmp(&a.strength)
                .then_with(|| a.matcher.cmp(b.matcher))
                .then_with(|| a.evidence.cmp(&b.evidence))
        });

        let score = signals
            .iter()
            .map(|signal| u32::from(signal.score))
            .max()
            .unwrap_or(0);
        let score = u8::try_from(score.min(100)).unwrap_or(100);

        let decisive = signals
            .iter()
            .any(|signal| signal.strength.can_merge_alone());

        // A pin blocks the automatic merge, not the evidence. The signals still surface so an
        // analyst can see what would have happened.
        let pinned = self.state.is_pinned(first.id) || self.state.is_pinned(second.id);

        let outcome = if signals.is_empty() {
            ResolutionOutcome::Distinct
        } else if pinned {
            ResolutionOutcome::Pinned
        } else if decisive {
            ResolutionOutcome::Merged
        } else {
            ResolutionOutcome::Candidate
        };

        candidate(first, second, outcome, signals, score)
    }

    /// Judge every pair in a set, returning only the pairs that concluded something.
    ///
    /// Ordered by score descending then by identifier, so a review queue is stable across runs.
    #[must_use]
    pub fn resolve_all(&self, records: &[ResolvableRecord]) -> Vec<ResolutionCandidate> {
        let mut out = Vec::new();
        for (index, left) in records.iter().enumerate() {
            for right in records.iter().skip(index.saturating_add(1)) {
                let candidate = self.resolve(left, right);
                if candidate.outcome != ResolutionOutcome::Distinct {
                    out.push(candidate);
                }
            }
        }
        out.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.left.to_string().cmp(&b.left.to_string()))
                .then_with(|| a.right.to_string().cmp(&b.right.to_string()))
        });
        out
    }
}

/// The markings a merged identity must carry.
///
/// The **union**, never the intersection. Merging an AMBER record into a CLEAR one and keeping
/// CLEAR would silently declassify the AMBER evidence — this issue's security note calls that out,
/// and it is the kind of loss nobody notices until the data has already been shared.
#[must_use]
pub fn merged_markings(left: &MarkingSet, right: &MarkingSet) -> MarkingSet {
    let mut merged = left.union(right);
    // `union` is the operation; this loop is belt and braces against a future change to it.
    for marking in right.iter() {
        merged.insert(marking.clone());
    }
    merged
}

/// The source lineage a merged identity must carry.
///
/// Every source from both sides, de-duplicated and ordered. Dropping one would make a record cite
/// less evidence after a merge than before it, which is the wrong direction.
#[must_use]
pub fn merged_sources(left: &[String], right: &[String]) -> Vec<String> {
    let mut sources: BTreeSet<String> = left.iter().cloned().collect();
    sources.extend(right.iter().cloned());
    sources.into_iter().collect()
}

/// Whether a merge would lose a marking that one side carried.
///
/// Exists so a caller can assert the invariant rather than trust it.
#[must_use]
pub fn merge_loses_a_marking(left: &MarkingSet, right: &MarkingSet, merged: &MarkingSet) -> bool {
    let present: BTreeSet<String> = merged.iter().map(marking_key).collect();
    left.iter()
        .chain(right.iter())
        .any(|marking| !present.contains(&marking_key(marking)))
}

/// A comparable key for a marking.
fn marking_key(marking: &Marking) -> String {
    match marking {
        Marking::Tlp(level) => format!("tlp:{level:?}"),
        Marking::Pap(level) => format!("pap:{level:?}"),
        Marking::Handling(text) => format!("handling:{}", text.as_str()),
        Marking::Attribution(text) => format!("attribution:{}", text.as_str()),
        // `Marking` is `#[non_exhaustive]`. A variant this build does not know must still produce a
        // distinct key, or an unknown marking would compare equal to every other unknown one and
        // `merge_loses_a_marking` would report a loss that did not happen — or worse, miss one.
        other => format!("unknown:{other:?}"),
    }
}

/// Build a candidate.
fn candidate(
    left: &ResolvableRecord,
    right: &ResolvableRecord,
    outcome: ResolutionOutcome,
    signals: Vec<MatchSignal>,
    score: u8,
) -> ResolutionCandidate {
    ResolutionCandidate {
        left: left.id,
        right: right.id,
        outcome,
        signals,
        score,
        algorithm: RESOLVE_ALGORITHM,
        algorithm_version: RESOLVE_ALGORITHM_VERSION,
    }
}

/// Fold case and collapse the punctuation feeds vary on.
///
/// `APT28`, `APT-28`, and `apt 28` are one spelling. This is a *normalisation*, not a similarity
/// measure — it either matches or it does not, which is what keeps the result deterministic.
fn normalised(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether two names share a token long enough to be worth noting.
///
/// The weakest signal there is, and it exists only so a reviewer can see *why* a pair was surfaced.
fn shares_a_token(left: &str, right: &str) -> bool {
    let tokens = |value: &str| -> BTreeSet<String> {
        value
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| token.len() >= 4)
            .map(str::to_lowercase)
            .collect()
    };
    !tokens(left).is_disjoint(&tokens(right))
}

/// Bound an excerpt and strip control characters.
///
/// Candidate evidence quotes record content, and a review queue is read through terminals.
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}
