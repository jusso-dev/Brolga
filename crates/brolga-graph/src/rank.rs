//! Ranking and structural condensation, by explainable factors.
//!
//! # Structural, not textual
//!
//! Nothing here summarises prose. Compression happens by *dropping whole records* Brolga can
//! justify dropping, by *grouping* records that say the same thing, and by *choosing a
//! representative* for a group — never by rewriting what a source said into shorter words.
//!
//! That is the difference between compression an analyst can defend and compression that produces
//! a plausible sentence nobody wrote. [#29](https://github.com/jusso-dev/Brolga/issues/29) names
//! "no embedding or LLM requirement" as a non-goal; this module needs neither, and the reason is
//! not cost. A paraphrase cannot be traced to a source object, and a claim that cannot be traced
//! is one an analyst cannot use.
//!
//! # No formula is the only option
//!
//! [`FactorWeights`] is data. Every factor can be weighted to zero, and a caller supplying its own
//! weights gets its own ordering. The shipped [`FactorWeights::balanced`] is a *default*, not the
//! algorithm — the acceptance criterion is that no ranking formula is hard-coded as the only one,
//! and the way to satisfy that is to make the formula a parameter rather than to offer two
//! hard-coded ones.
//!
//! # Every decision explains itself, including the exclusions
//!
//! [`Ranked::factors`] carries each factor's value for every candidate, included or not, and
//! [`Ranked::verdict`] says what happened to it. A ranking that only explained its winners would
//! leave "why is this not in my pack?" unanswerable, which is the question operators actually ask.
//!
//! # Some things are never pruned
//!
//! A contradiction and an exactly-requested observable bypass scoring entirely
//! ([`Verdict::Protected`]). Dropping a contradiction turns "two sources disagree" into "one source
//! said this", which is a *stronger* claim than the evidence supports and is produced by an
//! optimisation nobody would have approved if asked. Dropping the observable the caller named
//! answers a different question from the one asked.

use std::collections::BTreeMap;

use brolga_model::{Claim, Id, NodeRef, Observable, Timestamp};

/// A ranking factor.
///
/// Closed, so a caller's weight map cannot silently name a factor that does not exist and quietly
/// weight nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Factor {
    /// How sure the source was.
    Confidence,
    /// How recently it was observed or asserted.
    Freshness,
    /// How many *independent* sources said it.
    Corroboration,
    /// Whether it says something the pack does not already say.
    Novelty,
    /// Whether the record is complete enough to act on.
    Quality,
    /// Whether a reader could do something with it.
    Actionability,
    /// How much room it takes. Subtracted rather than added — see [`Factor::is_cost`].
    Cost,
}

impl Factor {
    /// Every factor.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Confidence,
            Self::Freshness,
            Self::Corroboration,
            Self::Novelty,
            Self::Quality,
            Self::Actionability,
            Self::Cost,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confidence => "confidence",
            Self::Freshness => "freshness",
            Self::Corroboration => "corroboration",
            Self::Novelty => "novelty",
            Self::Quality => "quality",
            Self::Actionability => "actionability",
            Self::Cost => "cost",
        }
    }

    /// Whether a higher value should *lower* the score.
    ///
    /// Cost is the only one. Kept as a property of the factor rather than as a minus sign at the
    /// call site, so a caller writing its own weights cannot accidentally reward expense.
    #[must_use]
    pub const fn is_cost(self) -> bool {
        matches!(self, Self::Cost)
    }
}

impl core::fmt::Display for Factor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much each factor counts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FactorWeights {
    weights: BTreeMap<Factor, u8>,
}

impl FactorWeights {
    /// The shipped default.
    ///
    /// A default, not *the* algorithm. Confidence and corroboration lead because a pack exists to
    /// tell an analyst what is worth acting on, and something one uncertain source said is not.
    #[must_use]
    pub fn balanced() -> Self {
        Self {
            weights: BTreeMap::from([
                (Factor::Confidence, 90),
                (Factor::Corroboration, 80),
                (Factor::Freshness, 70),
                (Factor::Actionability, 60),
                (Factor::Quality, 50),
                (Factor::Novelty, 40),
                (Factor::Cost, 30),
            ]),
        }
    }

    /// Every factor at zero, for a caller building its own from scratch.
    #[must_use]
    pub fn none() -> Self {
        Self {
            weights: Factor::all().iter().map(|factor| (*factor, 0)).collect(),
        }
    }

    /// Set one factor's weight, clamped to 100.
    #[must_use]
    pub fn with(mut self, factor: Factor, weight: u8) -> Self {
        self.weights.insert(factor, weight.min(100));
        self
    }

    /// One factor's weight.
    #[must_use]
    pub fn weight(&self, factor: Factor) -> u8 {
        self.weights.get(&factor).copied().unwrap_or(0)
    }

    /// Whether every factor is zero, which makes ranking a no-op.
    ///
    /// Worth asking rather than discovering: a caller that zeroed everything gets insertion order,
    /// and should be told that rather than believing a ranking ran.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        Factor::all().iter().all(|factor| self.weight(*factor) == 0)
    }
}

impl Default for FactorWeights {
    fn default() -> Self {
        Self::balanced()
    }
}

/// What happened to a candidate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    /// Scored and kept.
    Included,
    /// Scored and dropped, with the reason.
    Excluded {
        /// Why.
        reason: String,
    },
    /// Never scored, because it must not be pruned.
    Protected {
        /// Why it is protected.
        reason: String,
    },
    /// Folded into a cluster, which is represented by another record.
    Clustered {
        /// The representative's identifier.
        representative: String,
    },
}

impl Verdict {
    /// Whether the candidate reaches the pack in its own right.
    #[must_use]
    pub const fn is_kept(&self) -> bool {
        matches!(self, Self::Included | Self::Protected { .. })
    }
}

/// One candidate, scored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ranked {
    /// The record's identifier.
    pub id: String,
    /// Its overall score, 0 to 100.
    pub score: u8,
    /// Every factor's value, whatever the verdict.
    ///
    /// Present for exclusions too. A ranking that only explained its winners leaves "why is this
    /// not in my pack?" unanswerable, which is the question operators actually ask.
    pub factors: BTreeMap<Factor, u8>,
    /// What happened to it.
    pub verdict: Verdict,
}

/// What a ranking pass is told about one record.
///
/// Deliberately pre-computed values rather than the record itself: the factors come from several
/// places — confidence from the model, corroboration from provenance, novelty from what the pack
/// already holds — and a ranker that reached for all of them would need to know about all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The record's identifier.
    pub id: String,
    /// Each factor's raw value, 0 to 100.
    pub factors: BTreeMap<Factor, u8>,
    /// Why this record may not be pruned, if it may not be.
    pub protected: Option<String>,
    /// A key records saying the same thing share, for clustering.
    pub cluster_key: Option<String>,
}

impl Candidate {
    /// A candidate with no factors set.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            factors: BTreeMap::new(),
            protected: None,
            cluster_key: None,
        }
    }

    /// Set a factor.
    #[must_use]
    pub fn with_factor(mut self, factor: Factor, value: u8) -> Self {
        self.factors.insert(factor, value.min(100));
        self
    }

    /// Mark this candidate as one no pruning may drop.
    #[must_use]
    pub fn protected(mut self, reason: impl Into<String>) -> Self {
        self.protected = Some(reason.into());
        self
    }

    /// Give this candidate a cluster key.
    #[must_use]
    pub fn in_cluster(mut self, key: impl Into<String>) -> Self {
        self.cluster_key = Some(key.into());
        self
    }
}

/// A group of records that say the same thing, with one standing for the rest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cluster {
    /// The key its members share.
    pub key: String,
    /// The member chosen to represent it.
    pub representative: String,
    /// Every member, including the representative.
    ///
    /// Retained rather than discarded. A cluster that kept only its representative would have
    /// thrown away the fact that six sources agreed, which is the *reason* the cluster is worth
    /// more than its representative alone.
    pub members: Vec<String>,
    /// Why the representative was chosen.
    pub selection: String,
}

/// What a ranking pass decided.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RankingPlan {
    /// Every candidate, in descending score order.
    pub ranked: Vec<Ranked>,
    /// The clusters formed.
    pub clusters: Vec<Cluster>,
    /// Whether the weights were inert, so the ordering is insertion order.
    pub inert: bool,
}

impl RankingPlan {
    /// The identifiers that reach the pack, in order.
    #[must_use]
    pub fn kept(&self) -> Vec<&str> {
        self.ranked
            .iter()
            .filter(|ranked| ranked.verdict.is_kept())
            .map(|ranked| ranked.id.as_str())
            .collect()
    }

    /// Why one candidate ended up as it did.
    #[must_use]
    pub fn explain(&self, id: &str) -> Option<&Ranked> {
        self.ranked.iter().find(|ranked| ranked.id == id)
    }
}

/// Rank candidates, cluster the ones that repeat, and say why for each.
///
/// `keep` bounds how many *scored* candidates survive. Protected candidates are outside it: a
/// budget is a reason to drop something ordinary, and never a reason to drop a contradiction.
///
/// Ordering is by descending score, then by identifier. The tie-break is what makes the result
/// stable — two candidates with the same score must not swap places between runs, or a pack
/// fingerprint changes for no reason anybody can point at.
#[must_use]
pub fn rank(candidates: &[Candidate], weights: &FactorWeights, keep: usize) -> RankingPlan {
    let inert = weights.is_inert();

    // Clusters first, so a representative is scored and its members are not competing with it for
    // the same slot.
    let (clusters, representatives) = cluster(candidates, weights);

    let mut scored: Vec<Ranked> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let score = score_of(candidate, weights);
        let factors = complete_factors(candidate);

        if let Some(reason) = &candidate.protected {
            scored.push(Ranked {
                id: candidate.id.clone(),
                score,
                factors,
                verdict: Verdict::Protected {
                    reason: reason.clone(),
                },
            });
            continue;
        }

        if let Some(key) = &candidate.cluster_key
            && let Some(representative) = representatives.get(key)
            && representative != &candidate.id
        {
            scored.push(Ranked {
                id: candidate.id.clone(),
                score,
                factors,
                verdict: Verdict::Clustered {
                    representative: representative.clone(),
                },
            });
            continue;
        }

        scored.push(Ranked {
            id: candidate.id.clone(),
            score,
            factors,
            verdict: Verdict::Included,
        });
    }

    // Descending score, then identifier. The second key is not cosmetic: without it two equally
    // scored candidates may swap between runs, and a pack fingerprint moves for no reason.
    scored.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });

    // Then apply the bound, counting only candidates that are actually competing.
    let mut kept = 0_usize;
    for ranked in &mut scored {
        if !matches!(ranked.verdict, Verdict::Included) {
            continue;
        }
        if kept < keep {
            kept = kept.saturating_add(1);
        } else {
            ranked.verdict = Verdict::Excluded {
                reason: format!("ranked below the {keep}-record limit for this section"),
            };
        }
    }

    RankingPlan {
        ranked: scored,
        clusters,
        inert,
    }
}

/// Group candidates by their cluster key and choose a representative for each.
fn cluster(
    candidates: &[Candidate],
    weights: &FactorWeights,
) -> (Vec<Cluster>, BTreeMap<String, String>) {
    let mut groups: BTreeMap<String, Vec<&Candidate>> = BTreeMap::new();
    for candidate in candidates {
        // A protected candidate is never folded into a cluster. Representing a contradiction by
        // another record is exactly the pruning it is protected from.
        if candidate.protected.is_some() {
            continue;
        }
        if let Some(key) = &candidate.cluster_key {
            groups.entry(key.clone()).or_default().push(candidate);
        }
    }

    let mut clusters = Vec::new();
    let mut representatives = BTreeMap::new();

    for (key, members) in groups {
        // A group of one is not a cluster. Recording it as one would put a "cluster" in the pack
        // that compresses nothing and reads as though several sources agreed.
        if members.len() < 2 {
            continue;
        }

        let best = members.iter().max_by(|left, right| {
            score_of(left, weights)
                .cmp(&score_of(right, weights))
                // Same tie-break as the ordering, so the representative of an all-equal cluster is
                // the same one on every run.
                .then_with(|| right.id.cmp(&left.id))
        });
        let Some(best) = best else { continue };

        let mut ids: Vec<String> = members.iter().map(|member| member.id.clone()).collect();
        ids.sort();

        representatives.insert(key.clone(), best.id.clone());
        clusters.push(Cluster {
            key,
            representative: best.id.clone(),
            selection: format!(
                "highest-scoring member at {} of 100 across {} members",
                score_of(best, weights),
                ids.len()
            ),
            members: ids,
        });
    }

    (clusters, representatives)
}

/// A candidate's overall score, 0 to 100.
///
/// A weighted mean rather than a sum, so a caller adding a factor does not change the meaning of
/// every existing score. Cost is subtracted from its own contribution rather than added.
fn score_of(candidate: &Candidate, weights: &FactorWeights) -> u8 {
    let mut total: u32 = 0;
    let mut divisor: u32 = 0;

    for factor in Factor::all() {
        let weight = u32::from(weights.weight(*factor));
        if weight == 0 {
            continue;
        }
        let raw = u32::from(candidate.factors.get(factor).copied().unwrap_or(0));
        // Cost inverts: a cheap record scores where an expensive one does not.
        let value = if factor.is_cost() {
            100_u32.saturating_sub(raw)
        } else {
            raw
        };

        total = total.saturating_add(value.saturating_mul(weight));
        divisor = divisor.saturating_add(weight);
    }

    if divisor == 0 {
        return 0;
    }
    // Integer division on purpose. A score is a coarse rank rather than a measurement, floats would
    // make two runs on different platforms able to disagree in the last bit, and a pack fingerprint
    // that moved because of a rounding difference would be worse than a score that truncates.
    #[allow(clippy::integer_division)]
    let mean = total / divisor;
    u8::try_from(mean).unwrap_or(100)
}

/// Every factor's value, with absent ones shown as zero.
///
/// Filled in rather than left sparse, because an explanation with a missing row reads as "this
/// factor did not apply" when it means "nothing supplied a value".
fn complete_factors(candidate: &Candidate) -> BTreeMap<Factor, u8> {
    Factor::all()
        .iter()
        .map(|factor| (*factor, candidate.factors.get(factor).copied().unwrap_or(0)))
        .collect()
}

/// Build a candidate from a claim, filling the factors this crate can compute.
///
/// Freshness is relative to `now` and to `horizon_days`: a claim at the horizon scores zero and one
/// asserted now scores 100. Corroboration counts *distinct source objects*, because two copies of
/// one feed are one source however many times they are imported — counting them separately is how a
/// syndicated report becomes fabricated agreement.
#[must_use]
pub fn candidate_from_claim(
    claim: &Claim,
    now: Timestamp,
    horizon_days: u32,
    exact_subjects: &[Id<Observable>],
) -> Candidate {
    let mut candidate = Candidate::new(claim.id.to_string());

    if let Some(breakdown) = &claim.confidence {
        candidate = candidate.with_factor(Factor::Confidence, breakdown.overall.get());
    }

    let sources = claim.origin.source_objects();
    let corroboration = u8::try_from(sources.len().saturating_mul(25)).unwrap_or(100);
    candidate = candidate.with_factor(Factor::Corroboration, corroboration.min(100));

    candidate = candidate.with_factor(Factor::Freshness, freshness(claim, now, horizon_days));

    // A withdrawn claim is still evidence of what somebody said, and is still worth showing when
    // there is room — but it should not outrank a standing one.
    candidate = candidate.with_factor(
        Factor::Quality,
        if claim.status.is_current() { 100 } else { 25 },
    );

    // The observable the caller named is never pruned. Answering about a different observable is
    // answering a different question.
    if let NodeRef::Observable(id) = claim.subject
        && exact_subjects.contains(&id)
    {
        candidate = candidate.protected("the caller asked about this observable by name");
    }

    candidate
}

/// How fresh a claim is, from 0 at the horizon to 100 now.
fn freshness(claim: &Claim, now: Timestamp, horizon_days: u32) -> u8 {
    let Some(seen) = claim
        .temporal
        .last_seen
        .or(claim.temporal.first_seen)
        .or(claim.temporal.valid_from)
    else {
        // No temporal information is not the same as old. Scoring it as stale would bury every
        // record from a source that publishes no timestamps, which is most of them.
        return 50;
    };

    let horizon_seconds = i64::from(horizon_days).saturating_mul(86_400);
    if horizon_seconds <= 0 {
        return 100;
    }

    let age = now.unix_timestamp().saturating_sub(seen.unix_timestamp());
    if age <= 0 {
        return 100;
    }
    if age >= horizon_seconds {
        return 0;
    }

    let remaining = horizon_seconds.saturating_sub(age).saturating_mul(100);
    #[allow(clippy::integer_division)]
    let scaled = remaining / horizon_seconds;
    u8::try_from(scaled).unwrap_or(100)
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

    fn candidate(id: &str, confidence: u8) -> Candidate {
        Candidate::new(id).with_factor(Factor::Confidence, confidence)
    }

    /// **The criterion.** The formula is a parameter, not the algorithm. A caller supplying its own
    /// weights gets its own ordering.
    #[test]
    fn no_ranking_formula_is_the_only_option() {
        let candidates = vec![
            Candidate::new("cheap-but-unsure")
                .with_factor(Factor::Confidence, 10)
                .with_factor(Factor::Cost, 0),
            Candidate::new("sure-but-costly")
                .with_factor(Factor::Confidence, 100)
                .with_factor(Factor::Cost, 100),
        ];

        let by_confidence = rank(
            &candidates,
            &FactorWeights::none().with(Factor::Confidence, 100),
            10,
        );
        assert_eq!(by_confidence.kept()[0], "sure-but-costly");

        let by_cost = rank(
            &candidates,
            &FactorWeights::none().with(Factor::Cost, 100),
            10,
        );
        assert_eq!(
            by_cost.kept()[0],
            "cheap-but-unsure",
            "a caller weighting only cost gets a different order"
        );
    }

    /// A caller that zeroed everything should be told rather than believing a ranking ran.
    #[test]
    fn inert_weights_are_reported_rather_than_silently_producing_insertion_order() {
        let plan = rank(&[candidate("a", 90)], &FactorWeights::none(), 10);
        assert!(plan.inert);
        assert!(!rank(&[candidate("a", 90)], &FactorWeights::balanced(), 10).inert);
    }

    /// **The criterion.** "Why is this not in my pack?" is the question operators actually ask, and
    /// a ranking that only explained its winners cannot answer it.
    #[test]
    fn every_candidate_exposes_its_factors_including_the_excluded_ones() {
        let candidates = vec![candidate("kept", 100), candidate("dropped", 1)];
        let plan = rank(&candidates, &FactorWeights::balanced(), 1);

        let dropped = plan.explain("dropped").expect("the excluded candidate");
        assert!(matches!(dropped.verdict, Verdict::Excluded { .. }));
        assert_eq!(
            dropped.factors.len(),
            Factor::all().len(),
            "every factor is shown, not only the ones that were set"
        );
        assert_eq!(dropped.factors.get(&Factor::Confidence), Some(&1));

        if let Verdict::Excluded { reason } = &dropped.verdict {
            assert!(reason.contains("limit"), "{reason}");
        }
    }

    /// **The criterion.** Dropping a contradiction turns "two sources disagree" into "one source
    /// said this" — a stronger claim than the evidence supports, produced by an optimisation nobody
    /// would have approved if asked.
    #[test]
    fn a_protected_candidate_survives_a_limit_that_excludes_everything_else() {
        let candidates = vec![
            candidate("ordinary-high", 100),
            Candidate::new("contradiction")
                .with_factor(Factor::Confidence, 0)
                .protected("two sources disagree about this"),
        ];

        // A limit of zero: nothing ordinary survives.
        let plan = rank(&candidates, &FactorWeights::balanced(), 0);
        let kept = plan.kept();

        assert_eq!(kept, vec!["contradiction"]);
        let protected = plan.explain("contradiction").unwrap();
        assert!(matches!(protected.verdict, Verdict::Protected { .. }));
    }

    /// Representing a contradiction by another record is exactly the pruning it is protected from.
    #[test]
    fn a_protected_candidate_is_never_folded_into_a_cluster() {
        let candidates = vec![
            Candidate::new("a")
                .with_factor(Factor::Confidence, 90)
                .in_cluster("k"),
            Candidate::new("b")
                .with_factor(Factor::Confidence, 10)
                .in_cluster("k"),
            Candidate::new("protected")
                .with_factor(Factor::Confidence, 5)
                .in_cluster("k")
                .protected("contradicted"),
        ];

        let plan = rank(&candidates, &FactorWeights::balanced(), 10);
        let protected = plan.explain("protected").unwrap();
        assert!(matches!(protected.verdict, Verdict::Protected { .. }));

        let cluster = &plan.clusters[0];
        assert!(
            !cluster.members.contains(&"protected".to_owned()),
            "{cluster:?}"
        );
    }

    /// **The criterion.** A cluster that kept only its representative would have thrown away the
    /// fact that several sources agreed — which is the reason the cluster is worth more than the
    /// representative alone.
    #[test]
    fn a_cluster_retains_its_membership_and_says_how_it_chose() {
        let candidates = vec![
            Candidate::new("weak")
                .with_factor(Factor::Confidence, 10)
                .in_cluster("same"),
            Candidate::new("strong")
                .with_factor(Factor::Confidence, 95)
                .in_cluster("same"),
            Candidate::new("middling")
                .with_factor(Factor::Confidence, 50)
                .in_cluster("same"),
        ];

        let plan = rank(&candidates, &FactorWeights::balanced(), 10);
        assert_eq!(plan.clusters.len(), 1);

        let cluster = &plan.clusters[0];
        assert_eq!(cluster.representative, "strong");
        assert_eq!(cluster.members.len(), 3, "every member is retained");
        assert!(
            cluster.selection.contains("highest-scoring"),
            "{}",
            cluster.selection
        );

        // And the folded members say which record stands for them.
        let weak = plan.explain("weak").unwrap();
        assert_eq!(
            weak.verdict,
            Verdict::Clustered {
                representative: "strong".to_owned()
            }
        );
    }

    /// A "cluster" of one compresses nothing and reads as though several sources agreed.
    #[test]
    fn a_group_of_one_is_not_a_cluster() {
        let candidates = vec![Candidate::new("alone").in_cluster("k")];
        let plan = rank(&candidates, &FactorWeights::balanced(), 10);

        assert!(plan.clusters.is_empty());
        assert_eq!(plan.kept(), vec!["alone"]);
    }

    /// **The criterion.** Two candidates with the same score must not swap between runs, or a pack
    /// fingerprint changes for no reason anybody can point at.
    #[test]
    fn stable_input_produces_stable_ordering() {
        let candidates = vec![
            candidate("zeta", 50),
            candidate("alpha", 50),
            candidate("mid", 50),
        ];

        let first = rank(&candidates, &FactorWeights::balanced(), 10);
        let second = rank(&candidates, &FactorWeights::balanced(), 10);
        assert_eq!(first, second);
        assert_eq!(first.kept(), vec!["alpha", "mid", "zeta"]);

        // And the input order does not decide it either.
        let reordered = vec![
            candidate("mid", 50),
            candidate("zeta", 50),
            candidate("alpha", 50),
        ];
        assert_eq!(
            rank(&reordered, &FactorWeights::balanced(), 10).kept(),
            first.kept()
        );
    }

    /// An all-equal cluster must pick the same representative on every run.
    #[test]
    fn a_representative_is_chosen_deterministically_when_members_tie() {
        let candidates = vec![
            Candidate::new("b")
                .with_factor(Factor::Confidence, 50)
                .in_cluster("k"),
            Candidate::new("a")
                .with_factor(Factor::Confidence, 50)
                .in_cluster("k"),
        ];
        let first = rank(&candidates, &FactorWeights::balanced(), 10);
        let second = rank(&candidates, &FactorWeights::balanced(), 10);
        assert_eq!(
            first.clusters[0].representative,
            second.clusters[0].representative
        );
    }

    /// Cost inverts. A caller writing its own weights must not be able to accidentally reward
    /// expense by treating cost like every other factor.
    #[test]
    fn cost_lowers_a_score_rather_than_raising_it() {
        let cheap = Candidate::new("cheap").with_factor(Factor::Cost, 0);
        let costly = Candidate::new("costly").with_factor(Factor::Cost, 100);
        let weights = FactorWeights::none().with(Factor::Cost, 100);

        assert!(score_of(&cheap, &weights) > score_of(&costly, &weights));
        assert!(Factor::Cost.is_cost());
        assert!(Factor::all().iter().filter(|f| f.is_cost()).count() == 1);
    }

    #[test]
    fn a_score_is_a_weighted_mean_so_adding_a_factor_does_not_rescale_everything() {
        let candidate = Candidate::new("x")
            .with_factor(Factor::Confidence, 100)
            .with_factor(Factor::Freshness, 100);

        let one = FactorWeights::none().with(Factor::Confidence, 100);
        let two = one.clone().with(Factor::Freshness, 100);

        assert_eq!(score_of(&candidate, &one), 100);
        assert_eq!(
            score_of(&candidate, &two),
            100,
            "two factors at full value still mean full score"
        );
    }

    /// No temporal information is not the same as old. Scoring it as stale would bury every record
    /// from a source that publishes no timestamps, which is most of them.
    #[test]
    fn a_claim_with_no_timestamp_is_neither_fresh_nor_stale() {
        use brolga_model::provenance::{RecordOrigin, SyntheticOrigin, SyntheticReason};
        use brolga_model::{Assertion, Disposition, NodeRef, Observable, ShortText};

        let origin = RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::Fixture,
            ShortText::new("rank-tests").unwrap(),
        ));
        let subject =
            NodeRef::Observable(Observable::Ipv4Address("198.51.100.1".parse().unwrap()).id());
        let claim = Claim::new(
            subject,
            Assertion::Disposition(Disposition::Malicious),
            origin,
        );

        assert_eq!(freshness(&claim, Timestamp::unix_epoch(), 30), 50);
    }

    #[test]
    fn every_factor_has_a_distinct_name_and_appears_in_all() {
        let mut names: Vec<&str> = Factor::all().iter().map(|f| f.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(count, 7);

        for factor in Factor::all() {
            match factor {
                Factor::Confidence
                | Factor::Freshness
                | Factor::Corroboration
                | Factor::Novelty
                | Factor::Quality
                | Factor::Actionability
                | Factor::Cost => {}
            }
        }
    }
}
