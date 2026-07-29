//! Recorded decisions made by the graph layer.
//!
//! ADR 0004 §2: every graph decision is a record, not a side effect. A deduplication that silently
//! collapses two records leaves nobody able to answer "why is there one of these?", and the same is
//! true of a resolution, a contradiction, or a decay step.
//!
//! One row shape rather than one table per algorithm. Deduplication, resolution, contradiction, and
//! decay all owe the same four things — what was compared, what was decided, which algorithm and
//! version decided it, and why — and five near-identical tables would drift apart the first time
//! somebody added a column to one of them.

use brolga_model::provenance::ContentHash;

/// One decision, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphDecisionRow {
    /// Which family of decision this is, for example `dedup`.
    pub kind: String,
    /// What the decision is about — a canonical record identifier.
    pub subject: String,
    /// The observation being judged.
    pub observation: String,
    /// What it was compared against, where there was one.
    pub compared_with: Option<String>,
    /// The verdict's stable label.
    pub verdict: String,
    /// Which algorithm decided.
    pub algorithm: String,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// Why, in authored words.
    pub reason: String,
    /// When it was recorded, as an RFC 3339 string. Runtime metadata, never part of the identity.
    pub decided_at: String,
}

impl GraphDecisionRow {
    /// The deterministic identifier for this decision.
    ///
    /// Derived from what was decided about what — kind, subject, observation, and comparison — and
    /// deliberately **not** from the verdict, the reason, or the clock. Re-running an algorithm over
    /// the same inputs therefore updates one row, and a changed verdict overwrites the old one
    /// rather than sitting beside it claiming both are current.
    #[must_use]
    pub fn derive_id(&self) -> String {
        let material = format!(
            "{}|{}|{}|{}",
            self.kind,
            self.subject,
            self.observation,
            self.compared_with.as_deref().unwrap_or("-"),
        );
        ContentHash::of(material.as_bytes()).to_string()
    }
}
