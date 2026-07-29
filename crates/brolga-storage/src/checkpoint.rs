//! Named baselines, so "what changed since last week" has an answer.
//!
//! A checkpoint held only in memory answers "what changed since this process started", which is not
//! a question anybody asks. Storage keeps the baseline; it does not interpret it.
//!
//! The document travels as JSON rather than shredded into columns, for the same reason canonical
//! records do: it is read back whole, its shape is versioned by the algorithm that produced it, and
//! a column per facet would have to change every time a facet was added.

/// What is known about a stored checkpoint without decoding it.
///
/// `shape` and `algorithm_version` are here as well as inside the document because comparing two
/// checkpoints taken with different traversals, or by different algorithm versions, is a **refusal**
/// rather than a diff — and refusing has to be possible without decoding both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSummary {
    /// The name it is stored under, such as `nightly` or `before-the-migration`.
    pub name: String,
    /// A digest of the traversal it was taken with.
    pub shape: String,
    /// The graph's material-change counter when the capture ran.
    pub graph_version: u64,
    /// Which algorithm produced it.
    pub algorithm: String,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// When the capture was taken, as an RFC 3339 string.
    pub captured_at: String,
    /// Whether a budget stopped the capture short.
    ///
    /// Stored beside the document so a caller can refuse to use a truncated baseline without
    /// decoding it. A delta against a partial baseline reports records as added when the baseline
    /// merely did not reach them.
    pub truncated: bool,
}
