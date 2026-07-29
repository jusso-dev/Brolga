//! Reproducible graph checkpoints, and the material difference between two of them.
//!
//! # A delta nobody reads is worse than no delta
//!
//! Re-import a feed that published nothing new and a naive comparison lights up: every record was
//! re-serialised, every `last_seen` moved forward, every connector cursor advanced, every source
//! object got a new retrieval timestamp. None of that is intelligence. An operator handed a
//! thousand-line report of it learns to close the report, and the one line in next week's report
//! that says an actor attribution was revoked goes with it.
//!
//! So this module does not diff records. It diffs **material state**, defined here and nowhere
//! else, and a re-import that changed nothing produces an empty delta.
//!
//! ## What counts as material
//!
//! A record's material state is the set of [`MaterialFacet`]s below. Each one is something an
//! analyst would act on differently if it changed:
//!
//! - [`MaterialFacet::Kind`] — what the record asserts it is.
//! - [`MaterialFacet::Endpoints`] — which two nodes a relationship connects. Re-pointing an edge is
//!   a different statement about the world, not an edit.
//! - [`MaterialFacet::Names`] — the name and aliases a thing is published under, which is how an
//!   analyst finds it and how a downstream tool matches it.
//! - [`MaterialFacet::Status`] — whether the assertion still stands.
//! - [`MaterialFacet::Validity`] — the window in which it is asserted to apply.
//! - [`MaterialFacet::Confidence`] — the confidence *band*, not the figure. See below.
//! - [`MaterialFacet::Markings`] — handling restrictions, which decide who may see it.
//! - [`MaterialFacet::Sources`] — which evidence asserts it, because a second independent source
//!   arriving is the change most worth reading.
//!
//! ## What is deliberately excluded, and why
//!
//! Named in [`EXCLUDED_FROM_MATERIALITY`] so the exclusions are a data structure a test can walk
//! rather than a paragraph a reader has to trust. The reasons, in short:
//!
//! - **Observation timestamps.** A feed republishing the same indicator every morning moves
//!   `first_seen`/`last_seen` every morning. That says "we saw it again", which is not the same
//!   statement as "something changed", and it is the single largest source of churn in a threat
//!   intelligence graph.
//! - **Retrieval metadata.** Re-fetching identical bytes mints a new retrieval time and may mint a
//!   new source object. Nothing the graph asserts moved.
//! - **Connector sync state.** A connector polling and receiving nothing new advances its cursor.
//!   Carried on the checkpoint as metadata — the issue asks for it — and excluded from both the
//!   fingerprint and the delta, because a cursor is a fact about Brolga, not about the world.
//! - **Schema version and serialisation.** A record re-encoded under a newer schema tag, or with a
//!   different field order, has different bytes and the same meaning.
//! - **Narrative description.** The commonest cosmetic edit a publisher makes. A delta full of
//!   "description reworded" trains an operator to skim.
//! - **Decision timestamps.** When a decision was recorded is runtime metadata, exactly as
//!   `brolga_storage::GraphDecisionRow::derive_id` already treats it.
//! - **Sub-band confidence drift.** A recency component recomputed daily moves a composed figure by
//!   a point or two every day, for ever. Banding is the honest trade: a fingerprint has to be a
//!   function of *one* record's state, so a pairwise "changed by more than five points" threshold is
//!   not expressible in one, and a band is. The cost is real and is stated rather than hidden — a
//!   drift from 41 to 59 is not reported, and one from 59 to 60 is.
//!
//! # Reproducible, and therefore comparable
//!
//! A checkpoint's [`Checkpoint::fingerprint`] is a function of the graph state it describes and of
//! nothing else. It excludes the capture time, the label, and the graph version, so two captures of
//! an unchanged graph are byte-identical — which is what makes "is this the same graph?" one
//! comparison rather than a diff. **Nothing in the comparison path reads a clock**: every timestamp
//! is supplied by the caller, so comparing the same two checkpoints twice gives the same delta.
//!
//! # A delta is two traversals of the same shape
//!
//! Captures read the graph through [`mod@crate::traverse`] rather than through a second, unbounded
//! way of walking it. The traversal's budgets, cancellation token, and handling policy therefore
//! apply to a capture unchanged, and a checkpoint records the [`Checkpoint::shape`] it was taken
//! with. [`compare`] refuses two checkpoints of different shapes, because "these fifty records
//! disappeared" is a lie when the second capture simply looked less far.
//!
//! # Bounded, and honest about it
//!
//! [`compare`] is held to [`DeltaLimits`] and a [`CancellationToken`], and reports which bound
//! stopped it in [`Delta::truncated`] — plus, in [`Delta::inherited`], any budget that stopped the
//! *captures*. A truncated answer that does not admit it is worse than no answer.
//!
//! # Every decision is a record
//!
//! ADR 0004 §2. Each [`Change`] carries what was compared, what was decided, which algorithm and
//! version decided it, and why — and the reasons are `&'static str`, never interpolated from feed
//! content. Record content appears only in [`Change::evidence`], bounded and stripped of control
//! characters, because a delta is read through a terminal.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use brolga_model::{
    ConfidenceBreakdown, ConfidenceScore, ContentHash, Entity, LifecycleStatus, MarkingSet,
    NodeRef, Relationship, TemporalState, Timestamp,
};
use brolga_security::{CancellationToken, Cancelled};
use brolga_storage::{StorageError, StoreRead};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::traverse::{TraversalError, TraversalLimits, TraversalRequest, Truncation, traverse};

/// This algorithm's identifier, stamped into every checkpoint and delta it produces.
///
/// A compatibility surface under ADR 0001 §6, for the same reason the deduplicator's is: a consumer
/// may have stored a fingerprint carrying this pair, and changing what the pair produces for the
/// same graph is a breaking change.
pub const CHECKPOINT_ALGORITHM: &str = "brolga.checkpoint.material-delta";

/// This algorithm's version.
///
/// Bump when the *materiality rules* change — a facet added, removed, or rendered differently — not
/// when a reason is reworded. Every stored fingerprint changes when this changes, which is the point:
/// checkpoints taken under different rules are not comparable and must not silently appear to be.
pub const CHECKPOINT_ALGORITHM_VERSION: u32 = 1;

/// The domain separator every digest in this module starts with.
///
/// Without it, a fingerprint over one kind of thing could collide with a fingerprint over another
/// that happened to render the same way.
const FINGERPRINT_DOMAIN: &str = "brolga.checkpoint.v1";

/// Field separator inside a canonical rendering.
///
/// A unit separator, which is a control character. Every value that reaches a rendering is either a
/// digest in hexadecimal or a label from a closed enum, so it cannot contain one — the encoding is
/// unambiguous by construction rather than by escaping.
const FIELD: char = '\u{1f}';

/// Record separator inside a canonical rendering.
const RECORD: char = '\u{1e}';

/// How much record content an evidence excerpt may quote.
///
/// The same bound the resolver and the contradiction detector use, for the same reason: a review
/// queue is read through a terminal.
const EVIDENCE_MAX_CHARS: usize = 200;

/// How many records are examined between cancellation checks.
///
/// Checked in batches rather than per record because the check is not free and a batch of this size
/// is well under any human-noticeable delay, while a per-record check would show up in a comparison
/// of two large checkpoints.
const CANCEL_CHECK_INTERVAL: usize = 256;

// -------------------------------------------------------------------------------------------------
// What a record is, and what part of it is material
// -------------------------------------------------------------------------------------------------

/// Which kind of thing a checkpointed record is.
///
/// Narrower than `brolga_storage::RecordKind` on purpose: a checkpoint is taken over a traversal,
/// and a traversal reaches nodes and edges. Claims and sightings hang off nodes and are reached
/// through them, so admitting them here would promise a completeness the capture does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecordClass {
    /// A named thing.
    Entity,
    /// A directed connection.
    Relationship,
    /// A content-addressed value.
    ///
    /// An observable's identifier *is* its value, so an observable cannot change — only appear or
    /// disappear. It carries no facets beyond its class for that reason, and that is a statement
    /// about the model rather than an omission.
    Observable,
}

impl RecordClass {
    /// A stable label, written into fingerprints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Relationship => "relationship",
            Self::Observable => "observable",
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which record a fingerprint or a change is about.
///
/// Ordered by class and then identifier, which is what gives a delta a stable order without any
/// sorting step that could be forgotten.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey {
    /// What kind of record.
    pub class: RecordClass,
    /// Its canonical identifier.
    pub id: String,
}

impl RecordKey {
    /// Name a record.
    #[must_use]
    pub fn new(class: RecordClass, id: impl Into<String>) -> Self {
        Self {
            class,
            id: id.into(),
        }
    }

    /// Name whichever record a traversal node refers to.
    ///
    /// `None` for a node kind this build does not understand. Guessing a class for it would put a
    /// record into the checkpoint under a name a build that *does* understand it would not use, and
    /// the two builds' checkpoints would then report the same record as removed and added.
    #[must_use]
    pub fn of_node(node: NodeRef) -> Option<Self> {
        match node {
            NodeRef::Entity(id) => Some(Self::new(RecordClass::Entity, id.to_string())),
            NodeRef::Observable(id) => Some(Self::new(RecordClass::Observable, id.to_string())),
            _ => None,
        }
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.class.as_str(), self.id)
    }
}

/// One part of a record's material state.
///
/// A closed set, because the fingerprint is a compatibility surface: adding a facet changes every
/// fingerprint and is therefore a [`CHECKPOINT_ALGORITHM_VERSION`] bump, not an incidental edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MaterialFacet {
    /// What the record asserts it is.
    Kind,
    /// Which two nodes a relationship connects.
    Endpoints,
    /// The name and aliases the thing is published under.
    Names,
    /// Whether the assertion still stands.
    Status,
    /// The window in which the record is asserted to apply.
    Validity,
    /// The confidence band. Not the figure — see the module documentation.
    Confidence,
    /// Handling restrictions.
    Markings,
    /// Which evidence asserts the record.
    Sources,
}

impl MaterialFacet {
    /// Every facet, in fingerprint order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Kind,
            Self::Endpoints,
            Self::Names,
            Self::Status,
            Self::Validity,
            Self::Confidence,
            Self::Markings,
            Self::Sources,
        ]
    }

    /// A stable label, written into fingerprints and rendered to operators.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Endpoints => "endpoints",
            Self::Names => "names",
            Self::Status => "status",
            Self::Validity => "validity",
            Self::Confidence => "confidence",
            Self::Markings => "markings",
            Self::Sources => "sources",
        }
    }

    /// Why this part of a record is treated as material.
    ///
    /// Authored words, and part of the public surface: an operator who disagrees with a delta needs
    /// to be able to read the rule rather than infer it from the output.
    #[must_use]
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::Kind => "what a record asserts it is changes what every consumer does with it",
            Self::Endpoints => {
                "re-pointing an edge is a different statement about the world, not an edit"
            }
            Self::Names => {
                "the names a thing is published under are how an analyst finds it and how a \
                 downstream tool matches it"
            }
            Self::Status => {
                "whether the assertion still stands is the question an analyst asks first"
            }
            Self::Validity => {
                "the window a record is asserted to apply to decides whether it is still current"
            }
            Self::Confidence => {
                "a confidence band crossing is the point at which an analyst treats a record \
                 differently"
            }
            Self::Markings => {
                "handling restrictions decide who may see the record and what may be done with it"
            }
            Self::Sources => {
                "a second independent source arriving is the change most worth reading, and one \
                 being withdrawn is the change most worth acting on"
            }
        }
    }
}

impl fmt::Display for MaterialFacet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything a record can carry that is deliberately **not** material, and why not.
///
/// A data structure rather than a paragraph, so a test can walk it and so the exclusions can be
/// rendered to an operator who asks "why did my re-import produce nothing?". Every entry is a change
/// that a byte comparison would report and that an analyst would not act on.
pub const EXCLUDED_FROM_MATERIALITY: &[(&str, &str)] = &[
    (
        "observation_window",
        "a feed republishing the same indicator every morning moves first_seen and last_seen every \
         morning; that says we saw it again, not that anything changed",
    ),
    (
        "retrieval_metadata",
        "re-fetching identical bytes mints a new retrieval time and may mint a new source object \
         row, while nothing the graph asserts has moved",
    ),
    (
        "connector_sync_state",
        "a connector polling and receiving nothing new advances its cursor; a cursor is a fact \
         about Brolga rather than about the world, so it is carried as checkpoint metadata and \
         excluded from both the fingerprint and the delta",
    ),
    (
        "schema_version",
        "a record re-encoded under a newer schema tag has different bytes and the same meaning",
    ),
    (
        "document_serialisation",
        "canonical JSON field order and whitespace are an encoding detail; a re-serialisation is \
         not an assertion",
    ),
    (
        "description",
        "narrative rewording is the commonest cosmetic edit a publisher makes, and a delta full of \
         it trains an operator to skim the deltas that matter",
    ),
    (
        "decision_timestamps",
        "when a decision was recorded is runtime metadata, exactly as the stored decision's own \
         identifier already treats it",
    ),
    (
        "sub_band_confidence_drift",
        "a recency component recomputed daily moves a composed figure by a point or two every day \
         for ever; a fingerprint must be a function of one record's state, so the band is what can \
         be expressed in one",
    ),
    (
        "graph_version",
        "the counter answers how many material changes have been applied, not what the graph says; \
         including it would make an undone change indistinguishable from a change",
    ),
    (
        "capture_time",
        "when a checkpoint was taken is metadata about the capture; including it would mean two \
         captures of an unchanged graph never matched",
    ),
];

/// A confidence band: the granularity at which a confidence change is material.
///
/// Coarse on purpose. See the module documentation for the trade this makes and what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfidenceBand {
    /// No confidence was recorded at all.
    ///
    /// Distinct from [`Self::VeryLow`]: "nobody assessed this" and "somebody assessed it as almost
    /// certainly wrong" are different statements, and collapsing them would invent an assessment.
    Unstated,
    /// 0–19.
    VeryLow,
    /// 20–39.
    Low,
    /// 40–59.
    Moderate,
    /// 60–79.
    High,
    /// 80–100.
    VeryHigh,
}

impl ConfidenceBand {
    /// The band a score falls in.
    #[must_use]
    pub const fn of_score(score: ConfidenceScore) -> Self {
        match score.get() {
            0..=19 => Self::VeryLow,
            20..=39 => Self::Low,
            40..=59 => Self::Moderate,
            60..=79 => Self::High,
            _ => Self::VeryHigh,
        }
    }

    /// The band a record's confidence falls in, or [`Self::Unstated`] when it has none.
    #[must_use]
    pub fn of(breakdown: Option<&ConfidenceBreakdown>) -> Self {
        breakdown.map_or(Self::Unstated, |breakdown| {
            Self::of_score(breakdown.overall)
        })
    }

    /// A stable label, written into fingerprints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unstated => "unstated",
            Self::VeryLow => "very_low",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::VeryHigh => "very_high",
        }
    }
}

impl fmt::Display for ConfidenceBand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One facet's state: a digest of the whole value, and a bounded excerpt of it.
///
/// Two fields rather than one, and the split is load-bearing. The **digest** is taken over the
/// complete value, so two names that differ only in their three-hundredth character are still two
/// different names. The **excerpt** is what a delta quotes, bounded and stripped of control
/// characters, so a hostile alias cannot carry an escape sequence into an operator's terminal and a
/// checkpoint over a large neighbourhood does not hold a copy of every narrative field in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetState {
    /// A digest of the complete value. What comparison uses.
    pub digest: ContentHash,
    /// A bounded, control-character-free excerpt. What evidence quotes.
    pub excerpt: String,
}

impl FacetState {
    /// Digest a value and take a safe excerpt of it.
    #[must_use]
    pub fn of(value: &str) -> Self {
        Self {
            digest: ContentHash::of(value.as_bytes()),
            excerpt: bounded(value),
        }
    }
}

/// A record's material state, as one digest and the facets it was composed from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordFingerprint {
    /// What kind of record this describes.
    pub class: RecordClass,
    /// Its lifecycle status, where it has one.
    ///
    /// Carried as a typed value beside the [`MaterialFacet::Status`] facet rather than parsed back
    /// out of it, because the delta's lifecycle categories branch on it and a category decided by
    /// re-reading a rendered string is a category one truncation away from being wrong.
    pub status: Option<LifecycleStatus>,
    /// Each material facet the record has, in facet order.
    pub facets: BTreeMap<MaterialFacet, FacetState>,
    /// A digest of every facet, which is what "has this record changed?" compares.
    pub digest: ContentHash,
}

impl RecordFingerprint {
    /// Compose a fingerprint from a record's facets.
    fn compose(
        class: RecordClass,
        status: Option<LifecycleStatus>,
        facets: BTreeMap<MaterialFacet, FacetState>,
    ) -> Self {
        let mut material = String::from(FINGERPRINT_DOMAIN);
        material.push(RECORD);
        material.push_str(class.as_str());
        for (facet, state) in &facets {
            material.push(RECORD);
            material.push_str(facet.as_str());
            material.push(FIELD);
            material.push_str(&state.digest.to_hex());
        }

        Self {
            class,
            status,
            digest: ContentHash::of(material.as_bytes()),
            facets,
        }
    }

    /// Which facets differ between this fingerprint and another.
    #[must_use]
    pub fn differing_facets(&self, other: &Self) -> BTreeSet<MaterialFacet> {
        MaterialFacet::all()
            .iter()
            .copied()
            .filter(|facet| {
                self.facets.get(facet).map(|state| state.digest)
                    != other.facets.get(facet).map(|state| state.digest)
            })
            .collect()
    }
}

/// The material state of one entity.
#[must_use]
pub fn fingerprint_entity(entity: &Entity) -> RecordFingerprint {
    let mut facets = BTreeMap::new();
    facets.insert(MaterialFacet::Kind, FacetState::of(entity.kind.as_str()));
    facets.insert(MaterialFacet::Names, FacetState::of(&render_names(entity)));
    facets.insert(
        MaterialFacet::Status,
        FacetState::of(entity.status.as_str()),
    );
    facets.insert(
        MaterialFacet::Validity,
        FacetState::of(&render_validity(&entity.temporal)),
    );
    facets.insert(
        MaterialFacet::Confidence,
        FacetState::of(ConfidenceBand::of(entity.confidence.as_ref()).as_str()),
    );
    facets.insert(
        MaterialFacet::Markings,
        FacetState::of(&render_markings(&entity.markings)),
    );
    facets.insert(
        MaterialFacet::Sources,
        FacetState::of(&render_sources(&entity.origin)),
    );

    RecordFingerprint::compose(RecordClass::Entity, Some(entity.status), facets)
}

/// The material state of one relationship.
#[must_use]
pub fn fingerprint_relationship(edge: &Relationship) -> RecordFingerprint {
    let mut facets = BTreeMap::new();
    facets.insert(MaterialFacet::Kind, FacetState::of(edge.kind.as_str()));
    facets.insert(
        MaterialFacet::Endpoints,
        FacetState::of(&format!("{} -> {}", edge.source, edge.target)),
    );
    facets.insert(MaterialFacet::Status, FacetState::of(edge.status.as_str()));
    facets.insert(
        MaterialFacet::Validity,
        FacetState::of(&render_validity(&edge.temporal)),
    );
    facets.insert(
        MaterialFacet::Confidence,
        FacetState::of(ConfidenceBand::of(edge.confidence.as_ref()).as_str()),
    );
    facets.insert(
        MaterialFacet::Markings,
        FacetState::of(&render_markings(&edge.markings)),
    );
    facets.insert(
        MaterialFacet::Sources,
        FacetState::of(&render_sources(&edge.origin)),
    );

    RecordFingerprint::compose(RecordClass::Relationship, Some(edge.status), facets)
}

/// The material state of one observable, which is only that it is present.
///
/// An observable is content-addressed: its identifier is a function of its value, so a changed
/// value is a different observable. There is nothing else about it that can move.
#[must_use]
pub fn fingerprint_observable() -> RecordFingerprint {
    let mut facets = BTreeMap::new();
    facets.insert(
        MaterialFacet::Kind,
        FacetState::of(RecordClass::Observable.as_str()),
    );
    RecordFingerprint::compose(RecordClass::Observable, None, facets)
}

// -------------------------------------------------------------------------------------------------
// Where a record went
// -------------------------------------------------------------------------------------------------

/// How a record left the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuccessionKind {
    /// It became part of exactly one other record.
    Merged,
    /// It became several other records.
    Split,
}

impl SuccessionKind {
    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Merged => "merged",
            Self::Split => "split",
        }
    }
}

impl fmt::Display for SuccessionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What a record became, recorded so that a record which left the graph stays traceable.
///
/// Supplied by the caller — typically from [`crate::resolve`]'s recorded operations — rather than
/// inferred. Inferring a merge from "one record vanished and another gained its aliases" would
/// invent a lineage nobody asserted, and a merge is close to irreversible in practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succession {
    /// Whether it merged into one record or split into several.
    pub kind: SuccessionKind,
    /// What it became, in identifier order.
    pub successors: BTreeSet<RecordKey>,
}

impl Succession {
    /// Record that a record became these successors.
    ///
    /// Returns `None` for an empty set: a succession with no successor traces nothing, and storing
    /// one would let a deletion masquerade as a merge. That case is a
    /// [`ChangeCategory::Removed`] and is reported as such.
    #[must_use]
    pub fn into_records(successors: BTreeSet<RecordKey>) -> Option<Self> {
        let kind = match successors.len() {
            0 => return None,
            1 => SuccessionKind::Merged,
            _ => SuccessionKind::Split,
        };
        Some(Self { kind, successors })
    }

    /// Record that a record merged into exactly one other.
    #[must_use]
    pub fn merged_into(successor: RecordKey) -> Self {
        Self {
            kind: SuccessionKind::Merged,
            successors: BTreeSet::from([successor]),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Checkpoint metadata
// -------------------------------------------------------------------------------------------------

/// Where a connector had got to when a checkpoint was taken.
///
/// Carried because the issue asks for source sync state, and excluded from the fingerprint because
/// a cursor advancing is the definition of a change nobody should be shown. See
/// [`EXCLUDED_FROM_MATERIALITY`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceSyncState {
    /// The connector's opaque position, where it has one.
    pub cursor: Option<String>,
    /// How many source objects had been ingested from this source.
    pub objects: u64,
}

/// What to capture, and the metadata to capture alongside it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckpointRequest {
    /// The traversal that defines what the checkpoint covers.
    ///
    /// Its budgets, cancellation behaviour, and handling policy are the capture's, unchanged. Two
    /// checkpoints are comparable only if this is the same, which [`Checkpoint::shape`] enforces.
    pub traversal: TraversalRequest,
    /// When the capture was taken, supplied rather than read.
    ///
    /// Metadata only. It is not fingerprinted and never reaches the comparison path, which is what
    /// makes a delta reproducible.
    pub captured_at: Timestamp,
    /// Configuration, plugin, and algorithm versions in force, by component name.
    ///
    /// Fingerprinted. A checkpoint taken under a different confidence algorithm version is not
    /// comparable to one taken before it, and a delta between them says so in
    /// [`Delta::version_changes`] so that a wave of confidence changes is attributable to the
    /// upgrade rather than mistaken for new intelligence.
    pub versions: BTreeMap<String, u32>,
    /// A digest of the configuration in force.
    pub configuration: ContentHash,
    /// Where each source had got to, by source name.
    pub sources: BTreeMap<String, SourceSyncState>,
    /// What records that left the graph became.
    pub successions: BTreeMap<RecordKey, Succession>,
}

impl CheckpointRequest {
    /// A capture over one traversal, with no configuration or lineage metadata.
    #[must_use]
    pub fn over(traversal: TraversalRequest, captured_at: Timestamp) -> Self {
        Self {
            traversal,
            captured_at,
            versions: BTreeMap::new(),
            configuration: ContentHash::of(b""),
            sources: BTreeMap::new(),
            successions: BTreeMap::new(),
        }
    }

    /// Record one component's version.
    #[must_use]
    pub fn with_version(mut self, component: impl Into<String>, version: u32) -> Self {
        self.versions.insert(component.into(), version);
        self
    }

    /// Replace the configuration digest.
    #[must_use]
    pub const fn with_configuration(mut self, configuration: ContentHash) -> Self {
        self.configuration = configuration;
        self
    }

    /// Record one source's sync state.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>, state: SourceSyncState) -> Self {
        self.sources.insert(source.into(), state);
        self
    }

    /// Record what a record that left the graph became.
    #[must_use]
    pub fn with_succession(mut self, key: RecordKey, succession: Succession) -> Self {
        self.successions.insert(key, succession);
        self
    }
}

/// A reproducible description of what the graph said, over one traversal's worth of it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Checkpoint {
    /// A digest of the traversal this was taken with.
    ///
    /// Two checkpoints are comparable only if these match. A comparison across shapes would report
    /// records as removed when the second capture merely looked less far.
    pub shape: ContentHash,
    /// The graph's material-change counter when the capture ran.
    ///
    /// Migration 0004's counter, which moves only on a material change and not on a no-op upsert, a
    /// rolled-back transaction, or a retention write. It is metadata, not part of the fingerprint —
    /// see [`Self::still_current`] for what it is for.
    pub graph_version: u64,
    /// When the capture was taken, as supplied by the caller.
    pub captured_at: Timestamp,
    /// Every record covered, in key order.
    pub records: BTreeMap<RecordKey, RecordFingerprint>,
    /// What records that left the graph became.
    pub successions: BTreeMap<RecordKey, Succession>,
    /// Configuration, plugin, and algorithm versions in force.
    pub versions: BTreeMap<String, u32>,
    /// A digest of the configuration in force.
    pub configuration: ContentHash,
    /// Where each source had got to.
    pub sources: BTreeMap<String, SourceSyncState>,
    /// Which traversal budgets stopped the capture. Empty means it covered its whole neighbourhood.
    pub truncated: BTreeSet<Truncation>,
    /// How many records the handling policy withheld.
    ///
    /// Reported rather than silently dropped, for the same reason a traversal reports it: "there is
    /// more here that you cannot see" is itself something an analyst needs to know, and a checkpoint
    /// that quietly omitted restricted records would show them as removed to a colleague who could.
    pub withheld_by_policy: usize,
    /// How many reached nodes were of a kind this build does not understand.
    ///
    /// Counted rather than dropped in silence, and fingerprinted, so a checkpoint taken by an older
    /// build cannot pass itself off as a complete one. Without it, comparing across builds would
    /// report a whole class of node as removed and then as added.
    pub unrecognised_nodes: usize,
    /// Which algorithm produced this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
}

impl Checkpoint {
    /// The digest that answers "is the graph in the same state?".
    ///
    /// A function of the material state and of nothing else. It deliberately excludes the capture
    /// time, the graph version, and every connector's sync cursor — see
    /// [`EXCLUDED_FROM_MATERIALITY`] — so two captures of an unchanged graph produce the same value.
    ///
    /// It deliberately *includes* the truncation set, because a partial checkpoint and a complete
    /// one covering the same records are not interchangeable, and a fingerprint that could not tell
    /// them apart would let a truncated capture be adopted as a baseline.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        let mut material = String::from(FINGERPRINT_DOMAIN);
        material.push(RECORD);
        material.push_str(CHECKPOINT_ALGORITHM);
        material.push(FIELD);
        material.push_str(&self.algorithm_version.to_string());
        material.push(RECORD);
        material.push_str(&self.shape.to_hex());
        material.push(RECORD);
        material.push_str(&self.configuration.to_hex());

        for (component, version) in &self.versions {
            material.push(RECORD);
            material.push_str(component);
            material.push(FIELD);
            material.push_str(&version.to_string());
        }

        for reason in &self.truncated {
            material.push(RECORD);
            material.push_str("truncated");
            material.push(FIELD);
            material.push_str(reason.as_str());
        }

        material.push(RECORD);
        material.push_str("unrecognised");
        material.push(FIELD);
        material.push_str(&self.unrecognised_nodes.to_string());

        for (key, fingerprint) in &self.records {
            material.push(RECORD);
            material.push_str(&key.to_string());
            material.push(FIELD);
            material.push_str(&fingerprint.digest.to_hex());
        }

        for (key, succession) in &self.successions {
            material.push(RECORD);
            material.push_str("succession");
            material.push(FIELD);
            material.push_str(&key.to_string());
            material.push(FIELD);
            material.push_str(succession.kind.as_str());
            for successor in &succession.successors {
                material.push(FIELD);
                material.push_str(&successor.to_string());
            }
        }

        ContentHash::of(material.as_bytes())
    }

    /// How many records the checkpoint covers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the checkpoint covers nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether the capture covered its whole neighbourhood rather than hitting a budget.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.truncated.is_empty()
    }

    /// Whether the graph has had no material change since this checkpoint was taken.
    ///
    /// One integer comparison against migration 0004's counter rather than a diff, which is the
    /// whole reason that counter increments only on material change. A `true` answer means a
    /// comparison would be empty and need not be run at all.
    ///
    /// # Errors
    ///
    /// [`StorageError`] if the counter could not be read.
    pub fn still_current(&self, store: &dyn StoreRead) -> Result<bool, StorageError> {
        Ok(store.graph_version()? == self.graph_version)
    }
}

/// Why a capture could not be completed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// The traversal the capture reads through was refused or failed.
    #[error("the capture's traversal failed: {0}")]
    Traversal(#[from] TraversalError),

    /// A record could not be read.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// The graph changed materially while the capture was running.
    ///
    /// Refused rather than returned, and this is what makes a checkpoint transactional with the
    /// graph version: a capture reads many rows over many statements, so without this fence a
    /// checkpoint could describe half of one version and half of the next while claiming to be one.
    /// A checkpoint that straddles two versions is worse than no checkpoint, because every later
    /// delta taken against it reports changes that never happened.
    #[error(
        "the graph changed from version {from} to {to} while the checkpoint was being captured; \
         nothing consistent could be recorded"
    )]
    ConcurrentChange {
        /// The version the capture started at.
        from: u64,
        /// The version it finished at.
        to: u64,
    },
}

/// Capture a checkpoint over one traversal of the graph.
///
/// The graph's material-change counter is read before and after, and a capture that straddles a
/// change is refused rather than returned — see [`CaptureError::ConcurrentChange`].
///
/// # Errors
///
/// [`CaptureError::Traversal`] if the traversal was refused or a hop could not be read,
/// [`CaptureError::Storage`] if a record could not be read, and
/// [`CaptureError::ConcurrentChange`] if the graph changed materially while the capture ran.
pub fn capture(
    store: &dyn StoreRead,
    request: CheckpointRequest,
    token: &CancellationToken,
) -> Result<Checkpoint, CaptureError> {
    let before = store.graph_version()?;

    let traversal = traverse(store, request.traversal.clone(), token)?;
    let policy = request.traversal.policy;

    let mut records: BTreeMap<RecordKey, RecordFingerprint> = BTreeMap::new();
    let mut truncated = traversal.truncated.clone();
    let mut withheld_by_policy = traversal.withheld_by_policy;
    let mut unrecognised_nodes = 0_usize;

    for (examined, reached) in traversal.nodes.iter().enumerate() {
        if examined.is_multiple_of(CANCEL_CHECK_INTERVAL) && token.is_cancelled() {
            truncated.insert(Truncation::Cancelled);
            break;
        }

        let Some(key) = RecordKey::of_node(reached.node) else {
            unrecognised_nodes = unrecognised_nodes.saturating_add(1);
            continue;
        };

        match reached.node {
            NodeRef::Entity(id) => {
                // A node the traversal reached but whose row is gone is skipped rather than
                // fingerprinted as an empty record: an empty fingerprint would compare as a
                // material change to every other capture of the same record.
                let Some(entity) = store.get_entity(id)? else {
                    continue;
                };
                if !policy.permits(&entity.markings) {
                    withheld_by_policy = withheld_by_policy.saturating_add(1);
                    continue;
                }
                records.insert(key, fingerprint_entity(&entity));
            }
            NodeRef::Observable(_) => {
                records.insert(key, fingerprint_observable());
            }
            _ => unrecognised_nodes = unrecognised_nodes.saturating_add(1),
        }
    }

    for edge in &traversal.edges {
        records.insert(
            RecordKey::new(RecordClass::Relationship, edge.id.to_string()),
            fingerprint_relationship(edge),
        );
    }

    let after = store.graph_version()?;
    if after != before {
        return Err(CaptureError::ConcurrentChange {
            from: before,
            to: after,
        });
    }

    Ok(Checkpoint {
        shape: shape_of(&request.traversal),
        graph_version: before,
        captured_at: request.captured_at,
        records,
        successions: request.successions,
        versions: request.versions,
        configuration: request.configuration,
        sources: request.sources,
        truncated,
        withheld_by_policy,
        unrecognised_nodes,
        algorithm: CHECKPOINT_ALGORITHM,
        algorithm_version: CHECKPOINT_ALGORITHM_VERSION,
    })
}

/// A digest of what a traversal covers.
///
/// Rendered explicitly from the request's fields rather than from its `Debug` output, because two
/// checkpoints' comparability turns on this and a derived formatting is not a compatibility surface.
#[must_use]
pub fn shape_of(request: &TraversalRequest) -> ContentHash {
    let limits: TraversalLimits = request.limits;
    let mut material = String::from(FINGERPRINT_DOMAIN);
    material.push(RECORD);
    material.push_str("shape");
    material.push(FIELD);
    material.push_str(&request.filter.node.to_string());
    material.push(FIELD);
    material.push_str(request.filter.direction.as_str());

    material.push(FIELD);
    for kind in &request.filter.kinds {
        material.push_str(kind.as_str());
        material.push(',');
    }
    material.push(FIELD);
    for status in &request.filter.statuses {
        material.push_str(status.as_str());
        material.push(',');
    }

    material.push(FIELD);
    material.push_str(&limits.max_depth.to_string());
    material.push(FIELD);
    material.push_str(&limits.max_nodes.to_string());
    material.push(FIELD);
    material.push_str(&limits.max_edges.to_string());
    material.push(FIELD);
    material.push_str(&limits.max_fan_out.to_string());

    material.push(FIELD);
    material.push_str(
        request
            .policy
            .permitted_tlp()
            .map_or("unrestricted", brolga_model::TlpLevel::as_str),
    );

    ContentHash::of(material.as_bytes())
}

// -------------------------------------------------------------------------------------------------
// Deltas
// -------------------------------------------------------------------------------------------------

/// What a record's material state did between two checkpoints.
///
/// Mutually exclusive by construction: [`compare`] assigns exactly one to each changed record, by
/// the precedence in [`ChangeCategory::precedence`]. Overlapping categories would mean the same
/// record counted twice in a summary, and a summary whose numbers do not add up is one nobody
/// trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChangeCategory {
    /// It was not in the earlier checkpoint.
    Added,
    /// It left the graph and became exactly one other record.
    Merged,
    /// It left the graph and became several.
    Split,
    /// It left the graph with no recorded successor.
    ///
    /// Distinct from [`Self::Merged`] on purpose. "It became that one over there" and "it is gone
    /// and nobody said where" are different findings, and the second is the one that needs
    /// investigating.
    Removed,
    /// Its publisher withdrew the assertion. It was wrong, not merely old.
    Revoked,
    /// Its validity window closed. It was right, and is no longer current.
    Expired,
    /// It was not current and now is.
    Reactivated,
    /// Some other material facet moved.
    ///
    /// Which ones is in [`Change::facets`] — confidence, relationships, sources, markings, names,
    /// and validity are all reported through here with the facet named, rather than as separate
    /// top-level categories, so that a record whose confidence *and* sources both moved is one
    /// change rather than two.
    Changed,
}

impl ChangeCategory {
    /// Every category, in precedence order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Added,
            Self::Merged,
            Self::Split,
            Self::Removed,
            Self::Revoked,
            Self::Expired,
            Self::Reactivated,
            Self::Changed,
        ]
    }

    /// How this category ranks when more than one could apply. Lower wins.
    ///
    /// Presence beats lifecycle beats attributes. A record that left the graph *and* was revoked on
    /// the way out is reported as having left: "it is gone" is the finding an analyst acts on, and
    /// "it was revoked" describes a record they can no longer look at.
    #[must_use]
    pub const fn precedence(self) -> u8 {
        match self {
            Self::Added | Self::Merged | Self::Split | Self::Removed => 0,
            Self::Revoked | Self::Expired | Self::Reactivated => 1,
            Self::Changed => 2,
        }
    }

    /// Whether the record is absent from the later checkpoint.
    #[must_use]
    pub const fn is_departure(self) -> bool {
        matches!(self, Self::Merged | Self::Split | Self::Removed)
    }

    /// A stable label, rendered to operators and written to records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Merged => "merged",
            Self::Split => "split",
            Self::Removed => "removed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Reactivated => "reactivated",
            Self::Changed => "changed",
        }
    }

    /// Parse a label read back from a stored delta.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "added" => Some(Self::Added),
            "merged" => Some(Self::Merged),
            "split" => Some(Self::Split),
            "removed" => Some(Self::Removed),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "reactivated" => Some(Self::Reactivated),
            "changed" => Some(Self::Changed),
            _ => None,
        }
    }
}

impl fmt::Display for ChangeCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One facet's before and after, quoted.
///
/// The excerpts are bounded and stripped of control characters at fingerprint time, so nothing here
/// can carry an escape sequence into the terminal a delta is read in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetChange {
    /// Which facet.
    pub facet: MaterialFacet,
    /// What it was, where the record existed before.
    pub before: Option<String>,
    /// What it became, where the record exists after.
    pub after: Option<String>,
}

/// One record's material change, with what it was compared against and why it was categorised so.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Change {
    /// Which record.
    pub key: RecordKey,
    /// What happened to it. Exactly one category per record.
    pub category: ChangeCategory,
    /// Which material facets differ. Empty for a departure, which has nothing to compare against.
    pub facets: BTreeSet<MaterialFacet>,
    /// What it became, for a merge or a split.
    pub successors: BTreeSet<RecordKey>,
    /// Why this category, in authored words.
    ///
    /// `&'static str` for the same reason every other reason in this crate is: a reason interpolated
    /// from feed content would put untrusted bytes into a record an operator reads and a policy may
    /// branch on.
    pub reason: &'static str,
    /// The record content behind the finding, bounded and control-character-free.
    pub evidence: Vec<FacetChange>,
    /// Which algorithm decided this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
}

/// One component's version moving between two checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionChange {
    /// Which configuration, plugin, or algorithm.
    pub component: String,
    /// Its version in the earlier checkpoint.
    pub before: Option<u32>,
    /// Its version in the later one.
    pub after: Option<u32>,
}

/// Every bound a comparison is held to.
///
/// There is no unlimited variant, for the same reason [`TraversalLimits`] has none: a comparison of
/// two checkpoints an attacker can grow is a denial of service, and one missing budget is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DeltaLimits {
    /// How many records may be examined.
    pub max_records: usize,
    /// How many changes may be reported.
    ///
    /// Separate from the record budget because the two failures are different: a graph with a
    /// million unchanged records needs the first, and a wholesale re-import that changed everything
    /// needs the second.
    pub max_changes: usize,
}

impl DeltaLimits {
    /// Records a default comparison examines.
    pub const DEFAULT_MAX_RECORDS: usize = 50_000;

    /// Changes a default comparison reports.
    ///
    /// Ten thousand, because a delta larger than that is not read line by line by anybody — it is
    /// read as "something enormous happened", which the truncation flag says more honestly and more
    /// cheaply.
    pub const DEFAULT_MAX_CHANGES: usize = 10_000;

    /// Build a set of budgets.
    #[must_use]
    pub const fn new(max_records: usize, max_changes: usize) -> Self {
        Self {
            max_records,
            max_changes,
        }
    }
}

impl Default for DeltaLimits {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_RECORDS, Self::DEFAULT_MAX_CHANGES)
    }
}

/// Which budget stopped a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeltaTruncation {
    /// The record budget was reached with records still uncompared.
    Records,
    /// The change budget was reached.
    Changes,
    /// The cancellation token fired: an operator interrupt, a dropped client, or the deadline.
    Cancelled,
}

impl DeltaTruncation {
    /// A stable label, for diagnostics and recorded results.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::Changes => "changes",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for DeltaTruncation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why two checkpoints could not be compared.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DeltaRefused {
    /// A budget was zero, so the comparison would have examined nothing.
    #[error("the {limit} budget is zero, so the comparison would examine nothing")]
    EmptyBudget {
        /// Which budget.
        limit: &'static str,
    },

    /// The two checkpoints cover different parts of the graph.
    ///
    /// Refused rather than answered, because a comparison across shapes reports every record the
    /// narrower capture did not reach as removed. An operator handed that would spend an afternoon
    /// investigating a change in the traversal budget.
    #[error(
        "the checkpoints were taken over different traversals ({before} and {after}), so records \
         the narrower one did not reach would be reported as removed"
    )]
    ShapeMismatch {
        /// The earlier checkpoint's shape.
        before: String,
        /// The later checkpoint's shape.
        after: String,
    },

    /// The two checkpoints were produced by different versions of this algorithm.
    ///
    /// Refused because a fingerprint is only meaningful under the materiality rules that produced
    /// it: comparing digests across a rules change would report every record as changed.
    #[error(
        "the checkpoints were produced by algorithm versions {before} and {after}, whose \
         materiality rules differ; recapture the baseline rather than comparing across them"
    )]
    AlgorithmMismatch {
        /// The earlier checkpoint's algorithm version.
        before: u32,
        /// The later checkpoint's algorithm version.
        after: u32,
    },
}

/// What changed materially between two checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Delta {
    /// The earlier checkpoint's fingerprint.
    pub before: ContentHash,
    /// The later checkpoint's fingerprint.
    pub after: ContentHash,
    /// The traversal shape both were taken over.
    pub shape: ContentHash,
    /// Every material change, in record key order.
    pub changes: Vec<Change>,
    /// How many records were examined.
    pub compared: usize,
    /// How many were examined and found unchanged.
    ///
    /// Counted rather than listed. Criterion: an unchanged record does not appear in
    /// [`Self::changes`], and a count is how "we did look at them" stays answerable without a
    /// report the length of the database.
    pub unchanged: usize,
    /// Which budgets stopped the comparison. Empty means it examined everything.
    pub truncated: BTreeSet<DeltaTruncation>,
    /// Which budgets stopped the *captures* this compared.
    ///
    /// Separate from [`Self::truncated`] because the remedies differ: a comparison that ran out of
    /// budget is re-run with a larger one, and a capture that did is re-taken.
    pub inherited: BTreeSet<Truncation>,
    /// Why cancellation stopped it, when it did.
    pub cancellation: Option<Cancelled>,
    /// Which configuration, plugin, or algorithm versions moved between the two captures.
    ///
    /// The honesty signal that stops a delta being misread. If the confidence algorithm was upgraded
    /// between captures, a hundred confidence changes are attributable to the upgrade rather than to
    /// new intelligence, and only this field can say so.
    pub version_changes: Vec<VersionChange>,
    /// Whether the configuration digest moved.
    pub configuration_changed: bool,
    /// Whether any source's sync state moved.
    ///
    /// Reported and never a change. A connector advancing its cursor without importing anything new
    /// is the archetypal non-material event — see [`EXCLUDED_FROM_MATERIALITY`].
    pub sync_advanced: bool,
    /// How many records each checkpoint withheld under the handling policy.
    ///
    /// A delta between two captures with different clearances would look like a mass deletion, so
    /// the counts travel with the answer.
    pub withheld_by_policy: (usize, usize),
    /// Which algorithm produced this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
}

impl Delta {
    /// Whether anything material changed.
    #[must_use]
    pub fn is_material(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Whether the comparison examined everything, and both captures were complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.truncated.is_empty() && self.inherited.is_empty()
    }

    /// Whether one particular budget stopped it.
    #[must_use]
    pub fn stopped_by(&self, reason: DeltaTruncation) -> bool {
        self.truncated.contains(&reason)
    }

    /// How many changes fell in each category, in category order.
    ///
    /// Sums to [`Self::changes`]'s length, which is only true because the categories are mutually
    /// exclusive.
    #[must_use]
    pub fn counts(&self) -> BTreeMap<ChangeCategory, usize> {
        let mut counts = BTreeMap::new();
        for change in &self.changes {
            let seen = counts.entry(change.category).or_insert(0_usize);
            *seen = seen.saturating_add(1);
        }
        counts
    }

    /// Every change in one category, in record key order.
    #[must_use]
    pub fn in_category(&self, category: ChangeCategory) -> Vec<&Change> {
        self.changes
            .iter()
            .filter(|change| change.category == category)
            .collect()
    }

    /// Whether some component's version moved between the two captures.
    ///
    /// A `true` answer means every change here needs reading with the upgrade in mind, because a
    /// scoring change and a world change look identical in a fingerprint.
    #[must_use]
    pub fn attributable_to_version_change(&self) -> bool {
        !self.version_changes.is_empty() || self.configuration_changed
    }
}

/// Compare two checkpoints and report what changed materially.
///
/// Reproducible: the same two checkpoints always produce the same delta, including the order of the
/// changes and which ones survive truncation, because every collection walked here is ordered and
/// nothing in this path reads a clock.
///
/// # Errors
///
/// [`DeltaRefused::EmptyBudget`] if a budget is zero, [`DeltaRefused::ShapeMismatch`] if the two
/// checkpoints cover different traversals, and [`DeltaRefused::AlgorithmMismatch`] if they were
/// produced under different materiality rules. A budget being *reached* is not an error: the partial
/// delta is returned with [`Delta::truncated`] saying which budget stopped it.
pub fn compare(
    before: &Checkpoint,
    after: &Checkpoint,
    limits: DeltaLimits,
    token: &CancellationToken,
) -> Result<Delta, DeltaRefused> {
    if limits.max_records == 0 {
        return Err(DeltaRefused::EmptyBudget { limit: "records" });
    }
    if limits.max_changes == 0 {
        return Err(DeltaRefused::EmptyBudget { limit: "changes" });
    }
    if before.shape != after.shape {
        return Err(DeltaRefused::ShapeMismatch {
            before: before.shape.to_string(),
            after: after.shape.to_string(),
        });
    }
    if before.algorithm_version != after.algorithm_version {
        return Err(DeltaRefused::AlgorithmMismatch {
            before: before.algorithm_version,
            after: after.algorithm_version,
        });
    }

    // A BTreeSet, so the walk is in key order and truncation therefore keeps the *same* prefix on
    // every run rather than an arbitrary subset that happened to be visited first.
    let keys: BTreeSet<&RecordKey> = before.records.keys().chain(after.records.keys()).collect();

    let mut changes: Vec<Change> = Vec::new();
    let mut truncated: BTreeSet<DeltaTruncation> = BTreeSet::new();
    let mut cancellation: Option<Cancelled> = None;
    let mut compared = 0_usize;
    let mut unchanged = 0_usize;

    for key in keys {
        if compared.is_multiple_of(CANCEL_CHECK_INTERVAL)
            && let Some(reason) = token.reason()
        {
            cancellation = Some(reason);
            truncated.insert(DeltaTruncation::Cancelled);
            break;
        }
        if compared >= limits.max_records {
            truncated.insert(DeltaTruncation::Records);
            break;
        }
        compared = compared.saturating_add(1);

        let Some(change) = categorise(
            key,
            before.records.get(key),
            after.records.get(key),
            after.successions.get(key),
        ) else {
            unchanged = unchanged.saturating_add(1);
            continue;
        };

        if changes.len() >= limits.max_changes {
            truncated.insert(DeltaTruncation::Changes);
            break;
        }
        changes.push(change);
    }

    let mut inherited = before.truncated.clone();
    inherited.extend(after.truncated.iter().copied());

    Ok(Delta {
        before: before.fingerprint(),
        after: after.fingerprint(),
        shape: before.shape,
        changes,
        compared,
        unchanged,
        truncated,
        inherited,
        cancellation,
        version_changes: version_changes(&before.versions, &after.versions),
        configuration_changed: before.configuration != after.configuration,
        sync_advanced: before.sources != after.sources,
        withheld_by_policy: (before.withheld_by_policy, after.withheld_by_policy),
        algorithm: CHECKPOINT_ALGORITHM,
        algorithm_version: CHECKPOINT_ALGORITHM_VERSION,
    })
}

/// Decide what happened to one record, or that nothing did.
///
/// Ordered by [`ChangeCategory::precedence`]: presence, then lifecycle, then attributes. Exactly one
/// category is returned, and `None` means the record's material state is identical — which is the
/// case that must produce nothing at all.
fn categorise(
    key: &RecordKey,
    before: Option<&RecordFingerprint>,
    after: Option<&RecordFingerprint>,
    succession: Option<&Succession>,
) -> Option<Change> {
    let build = |category: ChangeCategory,
                 facets: BTreeSet<MaterialFacet>,
                 successors: BTreeSet<RecordKey>,
                 reason: &'static str,
                 evidence: Vec<FacetChange>| {
        Some(Change {
            key: key.clone(),
            category,
            facets,
            successors,
            reason,
            evidence,
            algorithm: CHECKPOINT_ALGORITHM,
            algorithm_version: CHECKPOINT_ALGORITHM_VERSION,
        })
    };

    match (before, after) {
        (None, None) => None,

        (None, Some(current)) => build(
            ChangeCategory::Added,
            current.facets.keys().copied().collect(),
            BTreeSet::new(),
            "the record is in the later checkpoint and was not in the earlier one",
            quote(None, Some(current)),
        ),

        (Some(previous), None) => match succession {
            Some(succession) => {
                let (category, reason) = match succession.kind {
                    SuccessionKind::Merged => (
                        ChangeCategory::Merged,
                        "the record left the graph into a recorded successor, so its claims and \
                         sightings are attributed there and remain traceable",
                    ),
                    SuccessionKind::Split => (
                        ChangeCategory::Split,
                        "the record left the graph into several recorded successors, so what was \
                         one identity is now more than one and each stays traceable",
                    ),
                };
                build(
                    category,
                    BTreeSet::new(),
                    succession.successors.clone(),
                    reason,
                    quote(Some(previous), None),
                )
            }
            None => build(
                ChangeCategory::Removed,
                BTreeSet::new(),
                BTreeSet::new(),
                "the record is absent from the later checkpoint with no recorded successor, so \
                 where its evidence went cannot be answered from the checkpoints alone",
                quote(Some(previous), None),
            ),
        },

        (Some(previous), Some(current)) => {
            // The case the whole module exists for: identical material state produces nothing,
            // however much of the record's serialisation, timestamps, or sync state moved.
            if previous.digest == current.digest {
                return None;
            }

            let facets = previous.differing_facets(current);
            let evidence = quote_differences(previous, current, &facets);

            let (category, reason) = lifecycle_of(previous.status, current.status, &facets)
                .unwrap_or((
                    ChangeCategory::Changed,
                    "a material facet of the record differs between the two checkpoints",
                ));

            build(category, facets, BTreeSet::new(), reason, evidence)
        }
    }
}

/// Which lifecycle category a status move falls in, if it is one.
///
/// `None` means the status did not move in a way that has its own category, and the change is an
/// ordinary attribute change.
fn lifecycle_of(
    before: Option<LifecycleStatus>,
    after: Option<LifecycleStatus>,
    facets: &BTreeSet<MaterialFacet>,
) -> Option<(ChangeCategory, &'static str)> {
    if !facets.contains(&MaterialFacet::Status) {
        return None;
    }
    let (before, after) = (before?, after?);

    match after {
        LifecycleStatus::Revoked => Some((
            ChangeCategory::Revoked,
            "the publisher withdrew the assertion: it was wrong, not merely old, so anything \
             derived from it needs revisiting rather than ageing out",
        )),
        LifecycleStatus::Expired => Some((
            ChangeCategory::Expired,
            "the record's validity window closed: it was right and is no longer current, which is \
             a different finding from having been withdrawn",
        )),
        // Superseded is deliberately not a category of its own here. A superseded record is still
        // in the graph, so reporting it as a departure would be false; it surfaces as a status
        // change with the facet named.
        _ if after.is_current() && !before.is_current() => Some((
            ChangeCategory::Reactivated,
            "the record was not current in the earlier checkpoint and is current in the later one, \
             so something an analyst had discounted is being asserted again",
        )),
        _ => None,
    }
}

/// Quote every facet of a record that appeared or disappeared.
fn quote(
    before: Option<&RecordFingerprint>,
    after: Option<&RecordFingerprint>,
) -> Vec<FacetChange> {
    let source = before.or(after);
    source.map_or_else(Vec::new, |fingerprint| {
        fingerprint
            .facets
            .iter()
            .map(|(facet, state)| FacetChange {
                facet: *facet,
                before: before.map(|_| state.excerpt.clone()),
                after: after.map(|_| state.excerpt.clone()),
            })
            .collect()
    })
}

/// Quote only the facets that differ, which is what makes a change evidence-backed rather than
/// merely asserted.
fn quote_differences(
    before: &RecordFingerprint,
    after: &RecordFingerprint,
    facets: &BTreeSet<MaterialFacet>,
) -> Vec<FacetChange> {
    facets
        .iter()
        .map(|facet| FacetChange {
            facet: *facet,
            before: before.facets.get(facet).map(|state| state.excerpt.clone()),
            after: after.facets.get(facet).map(|state| state.excerpt.clone()),
        })
        .collect()
}

/// Which components' versions moved, in component order.
fn version_changes(
    before: &BTreeMap<String, u32>,
    after: &BTreeMap<String, u32>,
) -> Vec<VersionChange> {
    let components: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    components
        .into_iter()
        .filter_map(|component| {
            let (was, is) = (before.get(component), after.get(component));
            (was != is).then(|| VersionChange {
                component: component.clone(),
                before: was.copied(),
                after: is.copied(),
            })
        })
        .collect()
}

/// The names a thing is published under, canonically ordered.
///
/// Sorted, so that a feed listing the same aliases in a different order is not a change. Publishers
/// reorder lists constantly and mean nothing by it.
fn render_names(entity: &Entity) -> String {
    let mut aliases: Vec<&str> = entity
        .aliases
        .iter()
        .map(brolga_model::UntrustedText::as_str)
        .collect();
    aliases.sort_unstable();
    aliases.dedup();

    let mut rendered = String::from(entity.name.as_str());
    for alias in aliases {
        rendered.push('\u{1}');
        rendered.push_str(alias);
    }
    rendered
}

/// The window a record is asserted to apply to.
///
/// `valid_from` and `valid_until` only. `first_seen` and `last_seen` are excluded, and that single
/// omission is what stops a daily re-import producing a delta the length of the feed.
fn render_validity(temporal: &TemporalState) -> String {
    let render = |value: Option<Timestamp>| {
        value.map_or_else(|| String::from("-"), brolga_model::Timestamp::to_rfc3339)
    };
    format!(
        "from={}|until={}",
        render(temporal.valid_from),
        render(temporal.valid_until)
    )
}

/// The handling restrictions on a record, canonically ordered.
///
/// A `MarkingSet` is already a `BTreeSet`, so iteration order is stable and the rendering is a
/// function of the set rather than of the order somebody inserted into it.
fn render_markings(markings: &MarkingSet) -> String {
    let mut rendered = String::new();
    for marking in markings.iter() {
        rendered.push_str(&marking_label(marking));
        rendered.push('\u{1}');
    }
    rendered
}

/// A stable label for one marking.
fn marking_label(marking: &brolga_model::Marking) -> String {
    match marking {
        brolga_model::Marking::Tlp(level) => format!("tlp:{}", level.as_str()),
        brolga_model::Marking::Pap(level) => format!("pap:{level:?}"),
        brolga_model::Marking::Handling(text) => format!("handling:{}", text.as_str()),
        brolga_model::Marking::Attribution(text) => format!("attribution:{}", text.as_str()),
        // A marking kind this build does not know is still a restriction, and rendering it as
        // nothing would make adding one silently non-material.
        other => format!("unknown:{other:?}"),
    }
}

/// Which evidence asserts a record, canonically ordered.
///
/// The source object identifiers, sorted and de-duplicated. Their *count* and *retrieval times* are
/// not here: a re-fetch that produced identical bytes reuses the same content-addressed identifier,
/// so this changes exactly when the set of things asserting the record changes.
fn render_sources(origin: &brolga_model::RecordOrigin) -> String {
    let mut ids: Vec<String> = origin
        .source_objects()
        .iter()
        .map(ToString::to_string)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.join("\u{1}")
}

/// Bound an excerpt and strip control characters.
///
/// Deltas are rendered to operators through terminals, and a name or an alias carrying escape
/// sequences must not reach one intact. Applied to the *excerpt* only: the digest that decides
/// whether something changed is taken over the complete value, so a difference beyond this bound is
/// still a difference.
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(EVIDENCE_MAX_CHARS)
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
    use brolga_model::{
        EntityKind, Id, RecordOrigin, RelationshipKind, ShortText, SyntheticOrigin,
        SyntheticReason, UntrustedText,
    };

    fn origin() -> RecordOrigin {
        RecordOrigin::Synthetic {
            origin: SyntheticOrigin::new(
                SyntheticReason::Fixture,
                ShortText::new("checkpoint-unit").unwrap(),
            ),
        }
    }

    fn entity(name: &str) -> Entity {
        Entity::new(
            Id::derive(&["entity", name]),
            EntityKind::ThreatActor,
            UntrustedText::new(name).unwrap(),
            origin(),
        )
    }

    fn node(name: &str) -> NodeRef {
        NodeRef::Entity(Id::derive(&["entity", name]))
    }

    fn edge(from: &str, to: &str) -> Relationship {
        Relationship::new(RelationshipKind::Uses, node(from), node(to), origin())
    }

    /// Every facet label and every category label is written into stored deltas, so they are a
    /// compatibility surface and two of them sharing a label would make a delta ambiguous.
    #[test]
    fn every_facet_and_category_has_a_distinct_label() {
        let facets: BTreeSet<&str> = MaterialFacet::all()
            .iter()
            .copied()
            .map(MaterialFacet::as_str)
            .collect();
        assert_eq!(facets.len(), MaterialFacet::all().len());

        let categories: BTreeSet<&str> = ChangeCategory::all()
            .iter()
            .copied()
            .map(ChangeCategory::as_str)
            .collect();
        assert_eq!(categories.len(), ChangeCategory::all().len());

        for category in ChangeCategory::all() {
            assert_eq!(
                ChangeCategory::from_str_opt(category.as_str()),
                Some(*category)
            );
        }
        assert_eq!(ChangeCategory::from_str_opt("probably_fine"), None);
    }

    /// Every exclusion must name itself and explain itself. An undocumented exclusion is
    /// indistinguishable from a bug that drops a field.
    #[test]
    fn every_materiality_exclusion_is_named_and_justified() {
        let names: BTreeSet<&str> = EXCLUDED_FROM_MATERIALITY
            .iter()
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(names.len(), EXCLUDED_FROM_MATERIALITY.len());

        for (name, reason) in EXCLUDED_FROM_MATERIALITY {
            assert!(!name.is_empty());
            assert!(
                reason.len() > 40,
                "{name} is excluded without a reason worth reading",
            );
        }

        // An exclusion that names a facet the fingerprint actually covers would be a lie in the
        // documentation, which is worse than no documentation.
        let included: BTreeSet<&str> = MaterialFacet::all()
            .iter()
            .copied()
            .map(MaterialFacet::as_str)
            .collect();
        for (name, _) in EXCLUDED_FROM_MATERIALITY {
            assert!(!included.contains(name), "{name} is both material and not");
        }
    }

    /// A band boundary is where an analyst changes what they do. If the boundaries move, every
    /// stored fingerprint's meaning moves with them.
    #[test]
    fn confidence_bands_partition_the_whole_range_at_the_documented_boundaries() {
        assert_eq!(ConfidenceBand::of(None), ConfidenceBand::Unstated);
        for (value, expected) in [
            (0_u8, ConfidenceBand::VeryLow),
            (19, ConfidenceBand::VeryLow),
            (20, ConfidenceBand::Low),
            (39, ConfidenceBand::Low),
            (40, ConfidenceBand::Moderate),
            (59, ConfidenceBand::Moderate),
            (60, ConfidenceBand::High),
            (79, ConfidenceBand::High),
            (80, ConfidenceBand::VeryHigh),
            (100, ConfidenceBand::VeryHigh),
        ] {
            let score = ConfidenceScore::new(value).unwrap();
            assert_eq!(ConfidenceBand::of_score(score), expected, "score {value}");
        }
    }

    /// The reason an alias list is sorted before hashing. Publishers reorder lists constantly and
    /// mean nothing by it, and a delta that reported every reorder would be unreadable.
    #[test]
    fn reordering_aliases_is_not_a_material_change() {
        let mut first = entity("Bunyip Panda");
        first.aliases = vec![
            UntrustedText::new("BUNYIP").unwrap(),
            UntrustedText::new("Panda").unwrap(),
        ];
        let mut second = entity("Bunyip Panda");
        second.aliases = vec![
            UntrustedText::new("Panda").unwrap(),
            UntrustedText::new("BUNYIP").unwrap(),
        ];

        assert_eq!(
            fingerprint_entity(&first).digest,
            fingerprint_entity(&second).digest,
        );
    }

    /// Two facets rendering to the same bytes must not make two different records fingerprint the
    /// same, which is what the domain separator and the per-facet labels are for.
    #[test]
    fn an_entity_and_a_relationship_never_share_a_fingerprint() {
        let entity = fingerprint_entity(&entity("thing"));
        let relationship = fingerprint_relationship(&edge("a", "b"));
        assert_ne!(entity.digest, relationship.digest);
        assert_ne!(entity.class, relationship.class);
    }

    /// The split that makes evidence safe without making comparison lossy: the digest sees the
    /// whole value, the excerpt is bounded and control-character-free.
    #[test]
    fn a_long_value_is_digested_in_full_and_quoted_in_part() {
        let long = "a".repeat(EVIDENCE_MAX_CHARS + 50);
        let longer = format!("{long}b");

        let first = FacetState::of(&long);
        let second = FacetState::of(&longer);

        assert_ne!(
            first.digest, second.digest,
            "a difference past the excerpt bound is still a difference",
        );
        assert_eq!(first.excerpt.chars().count(), EVIDENCE_MAX_CHARS);

        let hostile = FacetState::of("APT\u{1b}[2Jnine");
        assert!(!hostile.excerpt.chars().any(char::is_control));
        assert_eq!(hostile.excerpt, "APT[2Jnine");
    }

    /// Presence beats lifecycle beats attributes, and every category has exactly one rank. If two
    /// categories at rank zero could both apply to one record it would be counted twice.
    #[test]
    fn category_precedence_is_total_and_departures_outrank_lifecycle() {
        for category in ChangeCategory::all() {
            assert!(category.precedence() <= 2);
            if category.is_departure() {
                assert_eq!(category.precedence(), 0);
            }
        }
        assert!(ChangeCategory::Removed.precedence() < ChangeCategory::Revoked.precedence());
        assert!(ChangeCategory::Revoked.precedence() < ChangeCategory::Changed.precedence());
        assert!(!ChangeCategory::Added.is_departure());
    }

    /// A succession with no successor traces nothing. Storing one would let a plain deletion
    /// present itself as a merge, which is the one thing the traceability criterion forbids.
    #[test]
    fn a_succession_with_no_successor_is_refused() {
        assert_eq!(Succession::into_records(BTreeSet::new()), None);

        let one =
            Succession::into_records(BTreeSet::from([RecordKey::new(RecordClass::Entity, "a")]))
                .unwrap();
        assert_eq!(one.kind, SuccessionKind::Merged);

        let many = Succession::into_records(BTreeSet::from([
            RecordKey::new(RecordClass::Entity, "a"),
            RecordKey::new(RecordClass::Entity, "b"),
        ]))
        .unwrap();
        assert_eq!(many.kind, SuccessionKind::Split);
    }

    /// A zero budget is a caller mistake with a very different meaning from "too small", and it is
    /// refused by name rather than silently returning an empty delta that looks like "no changes".
    #[test]
    fn a_zero_budget_is_refused_by_name() {
        let checkpoint = Checkpoint {
            shape: ContentHash::of(b"shape"),
            graph_version: 1,
            captured_at: Timestamp::parse_rfc3339("2026-07-29T00:00:00Z").unwrap(),
            records: BTreeMap::new(),
            successions: BTreeMap::new(),
            versions: BTreeMap::new(),
            configuration: ContentHash::of(b""),
            sources: BTreeMap::new(),
            truncated: BTreeSet::new(),
            withheld_by_policy: 0,
            unrecognised_nodes: 0,
            algorithm: CHECKPOINT_ALGORITHM,
            algorithm_version: CHECKPOINT_ALGORITHM_VERSION,
        };

        let refused = compare(
            &checkpoint,
            &checkpoint,
            DeltaLimits::new(0, 10),
            &CancellationToken::never_cancelled(),
        );
        assert!(matches!(
            refused,
            Err(DeltaRefused::EmptyBudget { limit: "records" })
        ));

        let refused = compare(
            &checkpoint,
            &checkpoint,
            DeltaLimits::new(10, 0),
            &CancellationToken::never_cancelled(),
        );
        assert!(matches!(
            refused,
            Err(DeltaRefused::EmptyBudget { limit: "changes" })
        ));
    }

    /// The defaults must be usable, or a caller taking them would be refused by the very check that
    /// exists to catch a mistake.
    #[test]
    fn the_default_budgets_are_all_usable() {
        let limits = DeltaLimits::default();
        assert!(limits.max_records > 0);
        assert!(limits.max_changes > 0);
    }

    /// Truncation labels travel in stored deltas, so they are a compatibility surface.
    #[test]
    fn every_delta_truncation_reason_has_a_distinct_label() {
        let labels: BTreeSet<&str> = [
            DeltaTruncation::Records,
            DeltaTruncation::Changes,
            DeltaTruncation::Cancelled,
        ]
        .into_iter()
        .map(DeltaTruncation::as_str)
        .collect();
        assert_eq!(labels.len(), 3);
    }
}
