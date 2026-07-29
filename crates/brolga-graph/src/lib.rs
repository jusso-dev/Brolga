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

#![forbid(unsafe_code)]

pub mod dedup;

pub use dedup::{
    DEDUP_ALGORITHM, DEDUP_ALGORITHM_VERSION, DedupDecision, DedupVerdict, Deduplicator,
    Observation, RecordLineage,
};
