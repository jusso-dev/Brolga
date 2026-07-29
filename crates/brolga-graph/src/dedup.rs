//! Telling a duplicate from a corroboration.
//!
//! # The distinction that matters
//!
//! Two feeds both reporting `evil.example` looks like corroboration. Whether it *is* corroboration
//! depends entirely on where the second one got it. If feed B syndicates feed A, then "two sources
//! agree" is one source counted twice, and every confidence score built on it is inflated by a
//! number nobody can see.
//!
//! Getting this wrong is not a tidiness problem. It is the difference between "two independent
//! organisations observed this" and "one organisation observed this and another copied it", and an
//! analyst acting on the first when the second is true is acting on evidence that does not exist.
//!
//! # The signal that settles most of it
//!
//! **Byte-identical content from two publishers is a copy, not corroboration.** Two analysts writing
//! independently do not produce identical bytes — not the same whitespace, not the same field order,
//! not the same timestamps. Identical bytes mean one origin and one or more redistributors.
//!
//! That single rule resolves the common case without any configuration, any allow-list of known
//! syndication relationships, or any heuristic about publisher names. Where it does not apply —
//! different bytes producing the same canonical record — the records genuinely are independent
//! observations of the same artefact, which *is* corroboration.
//!
//! # Every decision is a record
//!
//! ADR 0004 §2: a deduplication that silently collapses two records leaves nobody able to answer
//! "why is there one of these?". So each decision persists what it compared, what it decided, which
//! algorithm and version decided it, and why — and the reasons are authored strings, not
//! interpolated from feed content.

use std::collections::BTreeMap;

use brolga_model::{ContentHash, Id, SourceObject};
use serde::{Deserialize, Serialize};

/// This algorithm's identifier, stamped into every decision it records.
///
/// A compatibility surface under ADR 0001 §6: changing what this `(id, version)` pair decides for
/// the same inputs is a breaking change, because stored decisions carry it and a consumer may have
/// relied on them.
pub const DEDUP_ALGORITHM: &str = "brolga.dedup.content-and-canonical";

/// This algorithm's version.
///
/// Bump when the *decision* changes for some input, not when a message is reworded.
pub const DEDUP_ALGORITHM_VERSION: u32 = 1;

/// What the deduplicator concluded about two observations of one canonical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DedupVerdict {
    /// The same bytes, seen again. One source object, one observation.
    ///
    /// A feed re-published, or the same file imported twice. Contributes nothing new at all.
    ExactDuplicate,

    /// Different bytes from the *same* publisher, producing the same canonical record.
    ///
    /// The publisher restated or re-exported something they already said. Still one voice.
    CanonicalDuplicate,

    /// Byte-identical content from a *different* publisher.
    ///
    /// A redistributed copy. This is the case that must not increase corroboration: two analysts
    /// writing independently do not produce identical bytes, so identical bytes mean one origin.
    SyndicatedCopy,

    /// Different bytes, different publisher, same canonical record.
    ///
    /// Genuine independent corroboration — two parties observed the same artefact and described it
    /// in their own words.
    IndependentCorroboration,

    /// The same canonical record, from the same publisher, with materially different content.
    ///
    /// An update. The earlier version stays traceable rather than being overwritten out of history.
    Update,
}

impl DedupVerdict {
    /// Whether this observation adds to how many independent parties assert the record.
    ///
    /// The whole point of the enum. Exactly one variant returns `true`.
    #[must_use]
    pub const fn increases_corroboration(self) -> bool {
        matches!(self, Self::IndependentCorroboration)
    }

    /// Whether this observation contributes any new evidence at all.
    #[must_use]
    pub const fn is_new_evidence(self) -> bool {
        !matches!(self, Self::ExactDuplicate)
    }

    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactDuplicate => "exact_duplicate",
            Self::CanonicalDuplicate => "canonical_duplicate",
            Self::SyndicatedCopy => "syndicated_copy",
            Self::IndependentCorroboration => "independent_corroboration",
            Self::Update => "update",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "exact_duplicate" => Some(Self::ExactDuplicate),
            "canonical_duplicate" => Some(Self::CanonicalDuplicate),
            "syndicated_copy" => Some(Self::SyndicatedCopy),
            "independent_corroboration" => Some(Self::IndependentCorroboration),
            "update" => Some(Self::Update),
            _ => None,
        }
    }
}

impl core::fmt::Display for DedupVerdict {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One observation of a canonical record: which record, from which evidence, published by whom.
///
/// The publisher is a caller-supplied identity rather than something derived from the source object,
/// because "who published this" is a policy question — two connector endpoints may be one
/// organisation, and one endpoint may relay several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The canonical record this observation is of.
    pub record_id: String,
    /// The evidence it came from.
    pub source_object: Id<SourceObject>,
    /// The digest of that evidence.
    pub content_hash: ContentHash,
    /// Who published it.
    pub publisher: String,
    /// A digest of the canonical record's own content, for detecting updates.
    ///
    /// Separate from [`Self::content_hash`], which digests the *evidence*. Two different bundles can
    /// produce byte-identical canonical records, and one bundle can be re-exported with a changed
    /// record inside it; only comparing both tells those apart.
    pub record_hash: ContentHash,
}

/// A recorded deduplication decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupDecision {
    /// The canonical record the decision is about.
    pub record_id: String,
    /// The observation being judged.
    pub observation: Id<SourceObject>,
    /// The observation it was compared against, where there was one.
    pub compared_with: Option<Id<SourceObject>>,
    /// What was decided.
    pub verdict: DedupVerdict,
    /// Which algorithm decided it.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// Why, in authored words.
    ///
    /// `&'static str` for the same reason detection reasons are: a reason interpolated from feed
    /// content would put untrusted bytes into a record an operator reads and a policy may branch on.
    pub reason: &'static str,
}

impl DedupDecision {
    /// Whether this decision counts towards corroboration.
    #[must_use]
    pub const fn increases_corroboration(&self) -> bool {
        self.verdict.increases_corroboration()
    }
}

/// What is known about a canonical record after every observation of it has been judged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordLineage {
    /// Every decision, in the order the observations were offered.
    pub decisions: Vec<DedupDecision>,
    /// The distinct publishers whose observations counted as independent.
    pub corroborating_publishers: Vec<String>,
    /// Every version of the record that was seen, oldest first.
    ///
    /// An update does not overwrite history; the earlier digest stays here so "what did they say
    /// before?" has an answer.
    pub versions: Vec<ContentHash>,
}

impl RecordLineage {
    /// How many independent parties assert this record.
    ///
    /// Counts distinct publishers whose observation was independent corroboration, plus the first
    /// observation itself. A syndicated copy does not increase it however many times it arrives.
    #[must_use]
    pub fn corroboration(&self) -> usize {
        self.corroborating_publishers.len()
    }

    /// How many times the record's content materially changed.
    #[must_use]
    pub fn revisions(&self) -> usize {
        self.versions.len().saturating_sub(1)
    }
}

/// Judges observations of canonical records against each other.
///
/// Stateful across a run: each observation is compared against what has already been seen for the
/// same record, which is what makes "the third copy of this" answerable.
#[derive(Debug, Default)]
pub struct Deduplicator {
    seen: BTreeMap<String, Vec<Observation>>,
    lineages: BTreeMap<String, RecordLineage>,
}

impl Deduplicator {
    /// A deduplicator that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
            lineages: BTreeMap::new(),
        }
    }

    /// Judge one observation, recording the decision.
    ///
    /// Deterministic: the same observations in the same order always produce the same decisions, and
    /// the comparison always runs against the earliest matching prior observation rather than
    /// whichever happened to be checked first.
    pub fn observe(&mut self, observation: Observation) -> DedupDecision {
        let prior = self.seen.entry(observation.record_id.clone()).or_default();

        let decision = judge(&observation, prior);

        let lineage = self
            .lineages
            .entry(observation.record_id.clone())
            .or_default();

        if lineage.versions.is_empty() {
            lineage.versions.push(observation.record_hash);
        } else if decision.verdict == DedupVerdict::Update {
            // A new version, appended rather than replacing. The earlier digest is what makes
            // "what did they say before?" answerable after the fact.
            lineage.versions.push(observation.record_hash);
        }

        if decision.verdict == DedupVerdict::IndependentCorroboration
            && !lineage
                .corroborating_publishers
                .contains(&observation.publisher)
        {
            lineage
                .corroborating_publishers
                .push(observation.publisher.clone());
        }

        lineage.decisions.push(decision.clone());
        prior.push(observation);
        decision
    }

    /// What is known about one record.
    #[must_use]
    pub fn lineage(&self, record_id: &str) -> Option<&RecordLineage> {
        self.lineages.get(record_id)
    }

    /// Every record judged, in identifier order.
    #[must_use]
    pub fn record_ids(&self) -> Vec<&str> {
        self.lineages.keys().map(String::as_str).collect()
    }

    /// Every decision made, in record then observation order.
    #[must_use]
    pub fn decisions(&self) -> Vec<&DedupDecision> {
        self.lineages
            .values()
            .flat_map(|lineage| lineage.decisions.iter())
            .collect()
    }
}

/// Decide what one observation is, given what has already been seen of the same record.
///
/// Ordered most specific first. Each branch names the comparison that settled it, so a stored
/// decision can be re-derived from its inputs rather than trusted.
fn judge(observation: &Observation, prior: &[Observation]) -> DedupDecision {
    let decide = |verdict, compared_with, reason| DedupDecision {
        record_id: observation.record_id.clone(),
        observation: observation.source_object,
        compared_with,
        verdict,
        algorithm: DEDUP_ALGORITHM,
        algorithm_version: DEDUP_ALGORITHM_VERSION,
        reason,
    };

    // Nothing to compare against: the first observation of a record is the record.
    let Some(first) = prior.first() else {
        return decide(
            DedupVerdict::IndependentCorroboration,
            None,
            "first observation of this record, so it is its own first independent assertion",
        );
    };

    // The same evidence, seen again. Checked before anything else because it is the only case that
    // contributes nothing at all, and because a re-import is the commonest thing that happens.
    if let Some(same_bytes) = prior
        .iter()
        .find(|seen| seen.content_hash == observation.content_hash)
    {
        return if same_bytes.publisher == observation.publisher {
            decide(
                DedupVerdict::ExactDuplicate,
                Some(same_bytes.source_object),
                "byte-identical evidence from the same publisher: the same document, seen again",
            )
        } else {
            // The rule that does most of the work. Two analysts writing independently do not
            // produce identical bytes — not the same whitespace, field order, or timestamps.
            decide(
                DedupVerdict::SyndicatedCopy,
                Some(same_bytes.source_object),
                "byte-identical evidence from a different publisher: a redistributed copy, not a \
                 second independent observation, because independent authors do not produce \
                 identical bytes",
            )
        };
    }

    let same_publisher = prior
        .iter()
        .find(|seen| seen.publisher == observation.publisher);

    if let Some(same_publisher) = same_publisher {
        return if same_publisher.record_hash == observation.record_hash {
            decide(
                DedupVerdict::CanonicalDuplicate,
                Some(same_publisher.source_object),
                "different evidence from the same publisher producing an identical canonical \
                 record: the same assertion restated",
            )
        } else {
            decide(
                DedupVerdict::Update,
                Some(same_publisher.source_object),
                "the same publisher now asserts materially different content for this record; the \
                 earlier version stays traceable rather than being overwritten",
            )
        };
    }

    decide(
        DedupVerdict::IndependentCorroboration,
        Some(first.source_object),
        "different evidence from a publisher not seen before for this record: an independent \
         observation of the same artefact",
    )
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

    fn observation(record: &str, bytes: &[u8], publisher: &str, content: &[u8]) -> Observation {
        let hash = ContentHash::of(bytes);
        Observation {
            record_id: record.to_owned(),
            source_object: SourceObject::derive_id(hash),
            content_hash: hash,
            publisher: publisher.to_owned(),
            record_hash: ContentHash::of(content),
        }
    }

    /// Exactly one verdict may increase corroboration. If a second ever does, every confidence
    /// score built on this is inflated by a number nobody can see.
    #[test]
    fn exactly_one_verdict_increases_corroboration() {
        let increasing = [
            DedupVerdict::ExactDuplicate,
            DedupVerdict::CanonicalDuplicate,
            DedupVerdict::SyndicatedCopy,
            DedupVerdict::IndependentCorroboration,
            DedupVerdict::Update,
        ]
        .into_iter()
        .filter(|verdict| verdict.increases_corroboration())
        .count();
        assert_eq!(increasing, 1);
    }

    /// Labels are written to the database, so they are a compatibility surface.
    #[test]
    fn every_verdict_label_round_trips_and_an_unknown_one_is_refused() {
        for verdict in [
            DedupVerdict::ExactDuplicate,
            DedupVerdict::CanonicalDuplicate,
            DedupVerdict::SyndicatedCopy,
            DedupVerdict::IndependentCorroboration,
            DedupVerdict::Update,
        ] {
            assert_eq!(DedupVerdict::from_str_opt(verdict.as_str()), Some(verdict));
        }
        assert_eq!(DedupVerdict::from_str_opt("probably_fine"), None);
    }

    /// Every decision carries the algorithm and version that made it, so a stored decision can be
    /// attributed rather than assumed.
    #[test]
    fn every_decision_carries_its_algorithm_and_version() {
        let mut dedup = Deduplicator::new();
        let decision = dedup.observe(observation("r", b"a", "feed-a", b"content"));
        assert_eq!(decision.algorithm, DEDUP_ALGORITHM);
        assert_eq!(decision.algorithm_version, DEDUP_ALGORITHM_VERSION);
        assert!(!decision.reason.is_empty());
    }

    /// The order observations arrive must not change what is decided about the set.
    #[test]
    fn judging_is_deterministic_regardless_of_which_copy_arrives_first() {
        let first_order = {
            let mut dedup = Deduplicator::new();
            dedup.observe(observation("r", b"bundle", "feed-a", b"content"));
            dedup.observe(observation("r", b"bundle", "feed-b", b"content"));
            dedup.lineage("r").unwrap().corroboration()
        };
        let second_order = {
            let mut dedup = Deduplicator::new();
            dedup.observe(observation("r", b"bundle", "feed-b", b"content"));
            dedup.observe(observation("r", b"bundle", "feed-a", b"content"));
            dedup.lineage("r").unwrap().corroboration()
        };
        assert_eq!(first_order, second_order);
    }
}
