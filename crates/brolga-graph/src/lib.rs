//! Brolga's graph layer: deciding what the accumulated records mean.
//!
//! Added by [ADR 0004](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0004-graph-crate-boundary.md),
//! which amends ADR 0001 §1 as ADR 0003 did. It sits above `brolga-storage` and beside
//! `brolga-ingest`, which it neither depends on nor is depended on by — a parser and a deduplicator
//! have no business knowing about each other. One turns bytes into records; the other decides what
//! a pile of records means.
//!
//! # Every decision here is a record, not a side effect
//!
//! ADR 0004 §2. A deduplication that silently collapses two records leaves nobody able to answer
//! "why is there one of these?", and the same is true of a resolution, a contradiction, or a decay
//! step. So each decision carries **what it compared, what it decided, which algorithm and version
//! decided it, and why** — and the reasons are authored strings rather than text interpolated from
//! feed content, which would put untrusted bytes into a record an operator reads and a policy may
//! branch on.
//!
//! # What is here
//!
//! - [`dedup`] — telling a duplicate from a corroboration, which is the difference between "two
//!   organisations observed this" and "one observed it and another copied it".
//! - [`resolve`] — deciding when two records are the same thing, and refusing to decide it on a
//!   name. A merge is close to irreversible in practice: once two actors' claims and sightings are
//!   attributed to one identity, unpicking which evidence belonged to which is work nobody has the
//!   information to do afterwards.
//! - [`contradiction`] — telling disagreement from difference, one predicate slot at a time.
//!   Comparing values without first agreeing which question they answer manufactures conflicts out
//!   of ordinary difference, and an operator shown ten fabricated conflicts stops reading the
//!   eleventh, which is real.
//! - [`confidence`] — composing a figure out of components that can each be argued with, and
//!   recording the configuration that produced it. A bare number cannot be explained, recomputed
//!   when one input changes, or disagreed with.
//! - [`mod@traverse`] — following relationships without following them forever. An unbounded
//!   traversal over a graph an attacker can publish into is a denial of service, so every walk is
//!   held to a depth, node, edge, and fan-out budget plus the request's cancellation token, and says
//!   which one stopped it.
//! - [`decay`] — how a record's standing falls with age, under a versioned policy, at an evaluation
//!   instant the caller names. It owns freshness outright: [`confidence`] delegates its recency
//!   component here rather than keeping a second opinion about what "old" means. Nothing decays to
//!   nought, because an indicator that has aged out was observed by somebody and one that was never
//!   asserted was not.
//! - [`checkpoint`] — telling a change from churn. A re-import that changed nothing, a
//!   re-serialisation, a connector cursor moving forward: a delta that reports those is a delta
//!   nobody reads, and an operator who has learned to skim the delta skims the line that says an
//!   attribution was revoked. So materiality is defined once, its exclusions are written down, and
//!   a no-op re-import produces nothing at all.

#![forbid(unsafe_code)]

pub mod budget;
pub mod checkpoint;
pub mod confidence;
pub mod contradiction;
pub mod decay;
pub mod dedup;
pub mod quality;
pub mod rank;
pub mod resolve;
pub mod traverse;

pub use budget::{
    BYTES_PER_TOKEN, BudgetFailure, Dimension, Fitted, HeuristicTokens, Item, Limits, Spend,
    TokenEstimator, fit,
};
pub use checkpoint::{
    CHECKPOINT_ALGORITHM, CHECKPOINT_ALGORITHM_VERSION, CaptureError, Change, ChangeCategory,
    Checkpoint, CheckpointRequest, ConfidenceBand, Delta, DeltaLimits, DeltaRefused,
    DeltaTruncation, EXCLUDED_FROM_MATERIALITY, FacetChange, FacetState, MaterialFacet,
    RecordClass, RecordFingerprint, RecordKey, SourceSyncState, Succession, SuccessionKind,
    VersionChange, capture, compare, fingerprint_entity, fingerprint_observable,
    fingerprint_relationship, shape_of,
};
pub use confidence::{
    AnalystOverride, COMPONENT_CORROBORATION, COMPONENT_INFORMATION_CREDIBILITY, COMPONENT_RECENCY,
    COMPONENT_SOURCE_RELIABILITY, COMPONENT_STANCE, CONFIDENCE_ALGORITHM,
    CONFIDENCE_ALGORITHM_VERSION, ComponentWeights, ConfidenceAssessment, ConfidencePolicy,
    ConfidenceScorer, Corroboration, OverrideRefused, Penalty, ScoreComponent, ScoringInputs,
};
pub use contradiction::{
    CONTRADICTION_ALGORITHM, CONTRADICTION_ALGORITHM_VERSION, ClaimRelation, ClaimStance,
    ContradictionDecision, ContradictionDetector, ContradictionReport, ContradictionRules,
    Predicate, ReviewedClaim,
};
pub use decay::{
    DECAY_ALGORITHM, DECAY_ALGORITHM_VERSION, DecayAnchor, DecayAssessment, DecayEvaluator,
    DecayInputs, DecayLedger, DecayPolicy, DecayProfile, DecayState, FutureDating, RecordTimeline,
    SourceInstant, StateTransition, age_in_days,
};
pub use dedup::{
    DEDUP_ALGORITHM, DEDUP_ALGORITHM_VERSION, DedupDecision, DedupVerdict, Deduplicator,
    Observation, RecordLineage,
};
pub use quality::{GoldenMismatch, GoldenPack, QualityReport};
pub use rank::{
    Candidate, Cluster, Factor, FactorWeights, Ranked, RankingPlan, Verdict, candidate_from_claim,
    rank,
};
pub use resolve::{
    ManualOperation, MatchSignal, NAME_SENSITIVE_KINDS, OperationKind, OperationRefused,
    RESOLVE_ALGORITHM, RESOLVE_ALGORITHM_VERSION, ResolutionCandidate, ResolutionOutcome,
    ResolutionState, ResolvableRecord, Resolver, Strength, merge_loses_a_marking, merged_markings,
    merged_sources,
};
pub use traverse::{
    PlanRefused, ReachedNode, TRAVERSE_ALGORITHM, TRAVERSE_ALGORITHM_VERSION, Traversal,
    TraversalError, TraversalLimits, TraversalPlan, TraversalPolicy, TraversalRequest, Truncation,
    traverse,
};
