//! Fitting a pack into explicit limits, and reporting what it cost.
//!
//! # An estimate that says it is an estimate
//!
//! [`TokenEstimator`] is a trait, and [`HeuristicTokens`] is the shipped implementation: it needs
//! no network, no model, and no tokeniser file. It is *approximate*, and [`Fitted::variance`]
//! exists because it is — a caller with a real tokeniser can supply one and the same fitting
//! algorithm uses it.
//!
//! An estimator that pretended to be exact would be the worse failure. A consumer sizing a prompt
//! against a number it believes is exact has no reason to leave headroom, and discovers the error
//! when a model refuses the request.
//!
//! # Required survives, or the budget fails out loud
//!
//! A section a profile marked required is never dropped to make room. If it does not fit, fitting
//! **fails** with [`BudgetFailure::RequiredDoesNotFit`] rather than quietly producing a pack
//! missing the thing an operator said always to keep.
//!
//! That is the whole design decision. The tempting alternative — drop it and note it in an
//! exclusion — produces a pack that looks complete, satisfies the request, and silently violates a
//! rule somebody wrote down deliberately. A loud failure is recoverable; a quiet one is not.
//!
//! # Fitting is deterministic
//!
//! Sections are considered in a fixed order, items within a section arrive pre-ranked, and the
//! first item that does not fit stops that section rather than skipping ahead to a smaller one.
//! Skipping ahead would fit more in and make the output depend on item sizes in a way nobody could
//! predict from the ranking — and would put a low-ranked small item in a pack while leaving a
//! high-ranked large one out.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How many bytes the heuristic estimator treats as one token.
///
/// Four is the widely used rule of thumb for English text through byte-pair encoders. It is wrong
/// for every specific input and close enough across a pack, which is the honest description of
/// what this is.
pub const BYTES_PER_TOKEN: usize = 4;

/// Turns text into an approximate token count.
///
/// A trait so a deployment with a real tokeniser can supply one. The shipped implementation is
/// deliberately crude and says so, rather than embedding a vocabulary file and implying a precision
/// it does not have across the models a consumer might use.
pub trait TokenEstimator: Send + Sync {
    /// Approximately how many tokens this text costs.
    fn estimate(&self, text: &str) -> u64;

    /// A name for the estimate's provenance, so a report can say what produced its numbers.
    fn name(&self) -> &'static str;

    /// Whether this estimator is exact.
    ///
    /// Answered by the estimator rather than assumed by the caller. A pack that reported a variance
    /// of zero from a heuristic would be claiming a precision nobody has.
    fn is_exact(&self) -> bool {
        false
    }
}

/// The offline estimator: bytes divided by a constant, with no model and no network.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicTokens;

impl TokenEstimator for HeuristicTokens {
    fn estimate(&self, text: &str) -> u64 {
        // Over the byte length rather than the character count. A tokeniser works on bytes, and a
        // pack full of non-ASCII would otherwise be badly under-estimated — which is the direction
        // that hurts, because it produces a pack larger than the caller budgeted for.
        let bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
        let per = u64::try_from(BYTES_PER_TOKEN).unwrap_or(4);
        // Rounded up: a fragment of a token still costs one, and rounding down accumulates into an
        // under-estimate across a whole pack.
        bytes.div_ceil(per)
    }

    fn name(&self) -> &'static str {
        "heuristic.bytes_per_token"
    }
}

/// The limits a pack must fit inside.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Approximate tokens.
    pub tokens: Option<u64>,
    /// Serialised bytes.
    pub bytes: Option<u64>,
    /// Items of any kind.
    pub objects: Option<u64>,
    /// Relationships specifically.
    pub relationships: Option<u64>,
    /// Traversal depth.
    pub depth: Option<u32>,
    /// Wall-clock milliseconds.
    pub time_ms: Option<u64>,
}

impl Limits {
    /// No limits at all.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            tokens: None,
            bytes: None,
            objects: None,
            relationships: None,
            depth: None,
            time_ms: None,
        }
    }

    /// A token limit.
    #[must_use]
    pub const fn tokens(mut self, tokens: u64) -> Self {
        self.tokens = Some(tokens);
        self
    }

    /// A byte limit.
    #[must_use]
    pub const fn bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// An object-count limit.
    #[must_use]
    pub const fn objects(mut self, objects: u64) -> Self {
        self.objects = Some(objects);
        self
    }

    /// A relationship-count limit.
    #[must_use]
    pub const fn relationships(mut self, relationships: u64) -> Self {
        self.relationships = Some(relationships);
        self
    }

    /// A depth limit.
    #[must_use]
    pub const fn depth(mut self, depth: u32) -> Self {
        self.depth = Some(depth);
        self
    }

    /// A deadline.
    #[must_use]
    pub const fn time_ms(mut self, time_ms: u64) -> Self {
        self.time_ms = Some(time_ms);
        self
    }
}

/// Which budget stopped something.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Dimension {
    /// The token budget.
    Tokens,
    /// The byte budget.
    Bytes,
    /// The object count.
    Objects,
    /// The relationship count.
    Relationships,
    /// The traversal depth.
    Depth,
    /// The deadline.
    Time,
}

impl Dimension {
    /// Every dimension.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Tokens,
            Self::Bytes,
            Self::Objects,
            Self::Relationships,
            Self::Depth,
            Self::Time,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Bytes => "bytes",
            Self::Objects => "objects",
            Self::Relationships => "relationships",
            Self::Depth => "depth",
            Self::Time => "time",
        }
    }
}

impl core::fmt::Display for Dimension {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why fitting could not produce a pack at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BudgetFailure {
    /// A required item does not fit.
    ///
    /// A failure rather than a silent omission. Dropping it would produce a pack that looks
    /// complete, satisfies the request, and silently violates a rule somebody wrote down
    /// deliberately — and a quiet violation is not recoverable, because nobody sees it.
    #[error(
        "`{item}` is required and does not fit the {dimension} budget: it needs {needed} and \
         {available} remains. Raise the budget or change the profile; Brolga will not drop a \
         required section to make a pack fit"
    )]
    RequiredDoesNotFit {
        /// The item.
        item: String,
        /// Which budget it exceeded.
        dimension: Dimension,
        /// What it needs.
        needed: u64,
        /// What was left.
        available: u64,
    },

    /// The deadline passed before the required items were fitted.
    #[error("the {limit_ms}ms deadline passed before the required sections were assembled")]
    DeadlineBeforeRequired {
        /// The deadline.
        limit_ms: u64,
    },
}

/// One thing being fitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its identifier.
    pub id: String,
    /// Which section it belongs to.
    pub section: String,
    /// Its serialised size in bytes.
    pub bytes: u64,
    /// Its estimated token cost.
    pub tokens: u64,
    /// Whether it is a relationship, for the relationship budget.
    pub is_relationship: bool,
    /// Whether it must survive fitting.
    pub required: bool,
}

impl Item {
    /// Measure an item from its serialised text.
    #[must_use]
    pub fn measure(
        id: impl Into<String>,
        section: impl Into<String>,
        text: &str,
        estimator: &dyn TokenEstimator,
    ) -> Self {
        Self {
            id: id.into(),
            section: section.into(),
            bytes: u64::try_from(text.len()).unwrap_or(u64::MAX),
            tokens: estimator.estimate(text),
            is_relationship: false,
            required: false,
        }
    }

    /// Mark this item as a relationship.
    #[must_use]
    pub const fn as_relationship(mut self) -> Self {
        self.is_relationship = true;
        self
    }

    /// Mark this item as one fitting may not drop.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// What one budget dimension was asked for and what it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Spend {
    /// What the caller allowed, if it set a limit.
    pub requested: Option<u64>,
    /// What was estimated to be used.
    pub estimated: u64,
    /// Whether this dimension is what stopped the fitting.
    pub binding: bool,
}

/// What fitting produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fitted {
    /// The items that fit, in the order they were considered.
    pub kept: Vec<String>,
    /// The items that did not, with the dimension that stopped each.
    pub dropped: Vec<(String, Dimension)>,
    /// Per-dimension accounting.
    pub spend: BTreeMap<Dimension, Spend>,
    /// How the estimate was produced, so a consumer knows what its numbers mean.
    pub estimator: &'static str,
    /// Whether the estimate is exact.
    ///
    /// A consumer sizing a prompt against an approximate number should leave headroom, and can only
    /// know to if the pack says which it got.
    pub exact: bool,
}

impl Fitted {
    /// The dimensions that stopped something.
    #[must_use]
    pub fn binding(&self) -> Vec<Dimension> {
        self.spend
            .iter()
            .filter(|(_, spend)| spend.binding)
            .map(|(dimension, _)| *dimension)
            .collect()
    }

    /// How far over or under an estimate a real measurement turned out to be, as a percentage.
    ///
    /// Present because the shipped estimator is approximate. A caller that measures the finished
    /// pack can record the difference, and a deployment that sees a consistent bias can supply its
    /// own estimator rather than padding every request by guesswork.
    #[must_use]
    pub fn variance(&self, dimension: Dimension, actual: u64) -> i64 {
        let Some(spend) = self.spend.get(&dimension) else {
            return 0;
        };
        if spend.estimated == 0 {
            return 0;
        }
        let estimated = i64::try_from(spend.estimated).unwrap_or(i64::MAX);
        let actual = i64::try_from(actual).unwrap_or(i64::MAX);
        #[allow(clippy::integer_division)]
        let percent = actual.saturating_sub(estimated).saturating_mul(100) / estimated;
        percent
    }

    /// Whether anything was dropped.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        !self.dropped.is_empty()
    }
}

/// Fit items into limits, keeping every required item or failing.
///
/// Items arrive pre-ranked — [`crate::rank::rank`] decides the order and this decides what fits. The two
/// are separate because "which is most valuable" and "what will fit" are different questions, and a
/// function answering both would let a size accidentally outrank a score.
///
/// `started` is when the work began, for the deadline. A caller measuring from its own start rather
/// than from this call is what makes the deadline cover retrieval as well as fitting.
///
/// # Errors
///
/// [`BudgetFailure::RequiredDoesNotFit`] when a required item exceeds a budget, and
/// [`BudgetFailure::DeadlineBeforeRequired`] when the deadline passes first.
pub fn fit(
    items: &[Item],
    limits: &Limits,
    estimator: &dyn TokenEstimator,
    started: Instant,
) -> Result<Fitted, BudgetFailure> {
    let mut used_tokens = 0_u64;
    let mut used_bytes = 0_u64;
    let mut used_objects = 0_u64;
    let mut used_relationships = 0_u64;

    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    let mut binding: BTreeMap<Dimension, bool> = BTreeMap::new();

    // Required first, always, and regardless of the order they were ranked in. Fitting them after
    // optional items would let an optional item consume the room a required one needed, which is
    // the same failure as dropping the required one — arrived at by a different route.
    let ordered: Vec<&Item> = items
        .iter()
        .filter(|item| item.required)
        .chain(items.iter().filter(|item| !item.required))
        .collect();

    // Sections that have stopped, so a section does not skip past a large item to a small one.
    // Skipping would fit more in and make the result depend on item sizes in a way nobody could
    // predict from the ranking — and would put a low-ranked small item in the pack while leaving a
    // high-ranked large one out.
    let mut closed: BTreeMap<String, Dimension> = BTreeMap::new();

    for item in ordered {
        let elapsed = started.elapsed();
        if let Some(limit_ms) = limits.time_ms
            && elapsed >= Duration::from_millis(limit_ms)
        {
            if item.required {
                return Err(BudgetFailure::DeadlineBeforeRequired { limit_ms });
            }
            binding.insert(Dimension::Time, true);
            dropped.push((item.id.clone(), Dimension::Time));
            continue;
        }

        if let Some(dimension) = closed.get(&item.section).copied()
            && !item.required
        {
            dropped.push((item.id.clone(), dimension));
            continue;
        }

        let over = exceeds(
            item,
            limits,
            used_tokens,
            used_bytes,
            used_objects,
            used_relationships,
        );

        if let Some((dimension, needed, available)) = over {
            if item.required {
                return Err(BudgetFailure::RequiredDoesNotFit {
                    item: item.id.clone(),
                    dimension,
                    needed,
                    available,
                });
            }
            binding.insert(dimension, true);
            closed.insert(item.section.clone(), dimension);
            dropped.push((item.id.clone(), dimension));
            continue;
        }

        used_tokens = used_tokens.saturating_add(item.tokens);
        used_bytes = used_bytes.saturating_add(item.bytes);
        used_objects = used_objects.saturating_add(1);
        if item.is_relationship {
            used_relationships = used_relationships.saturating_add(1);
        }
        kept.push(item.id.clone());
    }

    let spend = BTreeMap::from([
        (
            Dimension::Tokens,
            Spend {
                requested: limits.tokens,
                estimated: used_tokens,
                binding: binding.contains_key(&Dimension::Tokens),
            },
        ),
        (
            Dimension::Bytes,
            Spend {
                requested: limits.bytes,
                estimated: used_bytes,
                binding: binding.contains_key(&Dimension::Bytes),
            },
        ),
        (
            Dimension::Objects,
            Spend {
                requested: limits.objects,
                estimated: used_objects,
                binding: binding.contains_key(&Dimension::Objects),
            },
        ),
        (
            Dimension::Relationships,
            Spend {
                requested: limits.relationships,
                estimated: used_relationships,
                binding: binding.contains_key(&Dimension::Relationships),
            },
        ),
        (
            Dimension::Time,
            Spend {
                requested: limits.time_ms,
                estimated: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                binding: binding.contains_key(&Dimension::Time),
            },
        ),
    ]);

    Ok(Fitted {
        kept,
        dropped,
        spend,
        estimator: estimator.name(),
        exact: estimator.is_exact(),
    })
}

/// Which budget an item would exceed, with what it needs and what remains.
fn exceeds(
    item: &Item,
    limits: &Limits,
    used_tokens: u64,
    used_bytes: u64,
    used_objects: u64,
    used_relationships: u64,
) -> Option<(Dimension, u64, u64)> {
    if let Some(limit) = limits.tokens
        && used_tokens.saturating_add(item.tokens) > limit
    {
        return Some((
            Dimension::Tokens,
            item.tokens,
            limit.saturating_sub(used_tokens),
        ));
    }
    if let Some(limit) = limits.bytes
        && used_bytes.saturating_add(item.bytes) > limit
    {
        return Some((
            Dimension::Bytes,
            item.bytes,
            limit.saturating_sub(used_bytes),
        ));
    }
    if let Some(limit) = limits.objects
        && used_objects.saturating_add(1) > limit
    {
        return Some((Dimension::Objects, 1, limit.saturating_sub(used_objects)));
    }
    if item.is_relationship
        && let Some(limit) = limits.relationships
        && used_relationships.saturating_add(1) > limit
    {
        return Some((
            Dimension::Relationships,
            1,
            limit.saturating_sub(used_relationships),
        ));
    }
    None
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

    fn item(id: &str, tokens: u64) -> Item {
        Item {
            id: id.to_owned(),
            section: "claims".to_owned(),
            bytes: tokens.saturating_mul(4),
            tokens,
            is_relationship: false,
            required: false,
        }
    }

    /// **The criterion.** No network, no model, no vocabulary file.
    #[test]
    fn the_default_estimator_needs_no_network_or_model() {
        let estimator = HeuristicTokens;
        assert_eq!(estimator.estimate(""), 0);
        assert_eq!(estimator.estimate("abcd"), 1);
        assert_eq!(
            estimator.estimate("abcde"),
            2,
            "a fragment still costs a token"
        );
        assert_eq!(estimator.name(), "heuristic.bytes_per_token");
        assert!(
            !estimator.is_exact(),
            "it must not claim a precision it lacks"
        );
    }

    /// Under-estimating is the direction that hurts: it produces a pack larger than the caller
    /// budgeted for. Non-ASCII must be measured in bytes, not characters.
    #[test]
    fn a_multibyte_string_is_not_under_estimated() {
        let estimator = HeuristicTokens;
        // Four characters, twelve bytes.
        let text = "日本語で";
        assert_eq!(text.chars().count(), 4);
        assert!(
            estimator.estimate(text) >= 3,
            "counting characters would have said 1"
        );
    }

    /// **The criterion.** A pack missing something an operator said always to keep must be a loud
    /// failure. The tempting alternative produces a pack that looks complete and silently violates
    /// a rule somebody wrote down.
    #[test]
    fn a_required_item_that_does_not_fit_fails_rather_than_being_dropped() {
        let items = vec![item("huge", 500).required()];
        let error = fit(
            &items,
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap_err();

        assert!(
            matches!(
                error,
                BudgetFailure::RequiredDoesNotFit {
                    dimension: Dimension::Tokens,
                    ..
                }
            ),
            "{error}"
        );
        // And the message tells the operator what to do about it.
        assert!(error.to_string().contains("Raise the budget"), "{error}");
    }

    /// Fitting required items after optional ones would let an optional item consume the room a
    /// required one needed — the same failure by a different route.
    #[test]
    fn required_items_are_fitted_before_optional_ones_whatever_their_rank() {
        let items = vec![item("optional", 8), item("required", 8).required()];
        let fitted = fit(
            &items,
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(fitted.kept, vec!["required"]);
        assert_eq!(
            fitted.dropped,
            vec![("optional".to_owned(), Dimension::Tokens)]
        );
    }

    /// **The criterion.** Every budget type, at the boundary.
    #[test]
    fn every_budget_holds_exactly_at_its_boundary() {
        let now = Instant::now();

        // Exactly at the limit fits; one more does not.
        let fitted = fit(
            &[item("a", 10)],
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            now,
        )
        .unwrap();
        assert_eq!(fitted.kept, vec!["a"]);

        let fitted = fit(
            &[item("a", 11)],
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            now,
        )
        .unwrap();
        assert!(fitted.kept.is_empty());
        assert_eq!(fitted.binding(), vec![Dimension::Tokens]);

        // Bytes.
        let mut big = item("a", 1);
        big.bytes = 100;
        let fitted = fit(
            &[big.clone()],
            &Limits::unlimited().bytes(100),
            &HeuristicTokens,
            now,
        )
        .unwrap();
        assert_eq!(fitted.kept, vec!["a"]);
        let fitted = fit(
            &[big],
            &Limits::unlimited().bytes(99),
            &HeuristicTokens,
            now,
        )
        .unwrap();
        assert_eq!(fitted.binding(), vec![Dimension::Bytes]);

        // Objects.
        let two = vec![item("a", 1), item("b", 1)];
        assert_eq!(
            fit(&two, &Limits::unlimited().objects(2), &HeuristicTokens, now)
                .unwrap()
                .kept
                .len(),
            2
        );
        let fitted = fit(&two, &Limits::unlimited().objects(1), &HeuristicTokens, now).unwrap();
        assert_eq!(fitted.kept.len(), 1);
        assert_eq!(fitted.binding(), vec![Dimension::Objects]);

        // Relationships, which bound only relationship items.
        let mixed = vec![
            item("claim", 1),
            item("edge-1", 1).as_relationship(),
            item("edge-2", 1).as_relationship(),
        ];
        let fitted = fit(
            &mixed,
            &Limits::unlimited().relationships(1),
            &HeuristicTokens,
            now,
        )
        .unwrap();
        assert!(fitted.kept.contains(&"claim".to_owned()), "{fitted:?}");
        assert_eq!(
            fitted
                .kept
                .iter()
                .filter(|id| id.starts_with("edge"))
                .count(),
            1
        );
    }

    /// A zero budget admits nothing, and must not admit one item by an off-by-one.
    #[test]
    fn a_zero_budget_admits_nothing() {
        let fitted = fit(
            &[item("a", 1)],
            &Limits::unlimited().objects(0),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();
        assert!(fitted.kept.is_empty());
    }

    /// **The criterion.** Requested, estimated, and which dimension bound it — plus what produced
    /// the numbers, so a consumer knows whether to leave headroom.
    #[test]
    fn the_report_states_requested_estimated_and_the_binding_dimension() {
        let fitted = fit(
            &[item("a", 5), item("b", 50)],
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();

        let tokens = fitted.spend.get(&Dimension::Tokens).unwrap();
        assert_eq!(tokens.requested, Some(10));
        assert_eq!(tokens.estimated, 5);
        assert!(tokens.binding);

        assert!(fitted.is_truncated());
        assert_eq!(fitted.estimator, "heuristic.bytes_per_token");
        assert!(!fitted.exact, "a consumer must know to leave headroom");

        // A dimension with no limit is reported too, so a consumer sees the whole cost.
        let bytes = fitted.spend.get(&Dimension::Bytes).unwrap();
        assert_eq!(bytes.requested, None);
        assert!(!bytes.binding);
    }

    /// Variance is why the estimator's approximation is honest rather than hidden.
    #[test]
    fn variance_reports_how_far_off_the_estimate_turned_out_to_be() {
        let fitted = fit(
            &[item("a", 100)],
            &Limits::unlimited(),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(fitted.variance(Dimension::Tokens, 100), 0);
        assert_eq!(fitted.variance(Dimension::Tokens, 120), 20);
        assert_eq!(fitted.variance(Dimension::Tokens, 80), -20);
    }

    /// **The criterion.** Generation stops cleanly at the deadline — and a deadline that passes
    /// before the required sections are assembled is a failure, not a truncated pack.
    #[test]
    fn a_deadline_stops_generation_cleanly() {
        let long_ago = Instant::now()
            .checked_sub(Duration::from_millis(500))
            .unwrap_or_else(Instant::now);

        let fitted = fit(
            &[item("a", 1)],
            &Limits::unlimited().time_ms(10),
            &HeuristicTokens,
            long_ago,
        )
        .unwrap();
        assert!(fitted.kept.is_empty());
        assert_eq!(fitted.binding(), vec![Dimension::Time]);

        let error = fit(
            &[item("a", 1).required()],
            &Limits::unlimited().time_ms(10),
            &HeuristicTokens,
            long_ago,
        )
        .unwrap_err();
        assert!(
            matches!(error, BudgetFailure::DeadlineBeforeRequired { .. }),
            "{error}"
        );
    }

    /// Skipping past a large item to a small one would fit more in and make the result depend on
    /// sizes in a way nobody could predict from the ranking — putting a low-ranked small item in
    /// the pack while leaving a high-ranked large one out.
    #[test]
    fn a_section_stops_at_its_first_overflow_rather_than_skipping_to_smaller_items() {
        let items = vec![item("big", 100), item("small", 1)];
        let fitted = fit(
            &items,
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();

        assert!(fitted.kept.is_empty(), "{fitted:?}");
        assert_eq!(fitted.dropped.len(), 2);
    }

    /// A closed section must not close the others. Two sections have separate budgets to spend.
    #[test]
    fn one_section_overflowing_does_not_close_another() {
        let mut edge = item("edge", 1);
        edge.section = "relationships".to_owned();

        let items = vec![item("big-claim", 100), edge];
        let fitted = fit(
            &items,
            &Limits::unlimited().tokens(10),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(fitted.kept, vec!["edge"]);
    }

    /// Unlimited means unlimited, and must not be mistaken for zero.
    #[test]
    fn no_limit_admits_everything() {
        let items = vec![item("a", 1_000_000), item("b", 1_000_000)];
        let fitted = fit(
            &items,
            &Limits::unlimited(),
            &HeuristicTokens,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(fitted.kept.len(), 2);
        assert!(!fitted.is_truncated());
        assert!(fitted.binding().is_empty());
    }

    /// A deployment with a real tokeniser supplies one, and says it is exact.
    #[test]
    fn a_caller_can_supply_its_own_estimator() {
        struct Exact;
        impl TokenEstimator for Exact {
            fn estimate(&self, text: &str) -> u64 {
                u64::try_from(text.split_whitespace().count()).unwrap_or(u64::MAX)
            }
            fn name(&self) -> &'static str {
                "test.words"
            }
            fn is_exact(&self) -> bool {
                true
            }
        }

        let measured = Item::measure("a", "claims", "one two three", &Exact);
        assert_eq!(measured.tokens, 3);

        let fitted = fit(&[measured], &Limits::unlimited(), &Exact, Instant::now()).unwrap();
        assert_eq!(fitted.estimator, "test.words");
        assert!(fitted.exact);
    }

    #[test]
    fn every_dimension_has_a_distinct_name_and_appears_in_all() {
        let mut names: Vec<&str> = Dimension::all().iter().map(|d| d.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);

        for dimension in Dimension::all() {
            match dimension {
                Dimension::Tokens
                | Dimension::Bytes
                | Dimension::Objects
                | Dimension::Relationships
                | Dimension::Depth
                | Dimension::Time => {}
            }
        }
    }
}
