//! Backend-neutral storage contracts.
//!
//! # No arbitrary SQL crosses this boundary
//!
//! Every method here takes typed canonical values and typed queries. There is no `execute(sql)`,
//! no `where_clause: String`, and no escape hatch — so a caller cannot inject SQL through the
//! storage layer, and a future PostgreSQL backend is a real alternative rather than a place where
//! SQLite-shaped strings happen to work.
//!
//! It also means the safe query language planned for `v1.0.0` has somewhere to compile *to*. If
//! callers could pass SQL, that language would be optional, and an optional safety boundary is not
//! one.
//!
//! # Reads and writes are separate traits
//!
//! [`StoreWrite`] is what a transaction hands to the closure that runs inside it. Keeping it apart
//! from [`StoreRead`] means a read-only caller cannot accidentally be given something that can
//! write, and it keeps [`StoreWrite`] object-safe so the transaction can pass `&mut dyn StoreWrite`
//! without the generic machinery a single combined trait would need.
//!
//! # Synchronous, deliberately
//!
//! SQLite is a blocking library. Wrapping it in `async` here would produce futures that block the
//! executor while pretending not to, which is worse than being honest. Application services run
//! storage work on a blocking pool; the cancellation model that surrounds that belongs to
//! `brolga-security`.

use std::collections::BTreeSet;

use brolga_model::claim::Claim;
use brolga_model::entity::{Entity, EntityKind};
use brolga_model::id::Id;
use brolga_model::provenance::{ContentHash, SourceObject};
use brolga_model::relationship::{NodeRef, Relationship, RelationshipKind};
use brolga_model::sighting::Sighting;
use brolga_model::status::LifecycleStatus;
use brolga_model::temporal::Timestamp;
use serde::{Deserialize, Serialize};

use crate::blob::{
    BlobMetadata, BlobOutcome, BlobRequest, RetentionClass, RetentionEvent, RetrievedBlob,
};
use crate::checkpoint::CheckpointSummary;
use crate::cursor::ConnectorCursor;
use crate::decision::GraphDecisionRow;
use crate::error::Result;
use crate::quarantine::{QuarantineEntry, QuarantineRecord};

/// What an upsert did.
///
/// `Unchanged` exists because re-importing a feed is expected to be common and cheap. A caller that
/// cannot tell "stored again, identically" from "changed" has to treat every re-import as a change,
/// which makes change detection useless exactly when a feed is republishing its whole catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum UpsertOutcome {
    /// The record did not exist and was written.
    Inserted,
    /// The record existed with a different document and was replaced.
    Updated,
    /// The record existed and the document was identical. Nothing was written.
    Unchanged,
}

impl UpsertOutcome {
    /// Whether the stored state changed.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Inserted | Self::Updated)
    }
}

/// Which kind of record a count or a listing is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    /// Original evidence metadata.
    SourceObject,
    /// A named thing.
    Entity,
    /// A directed connection.
    Relationship,
    /// An assertion.
    Claim,
    /// An observation.
    Sighting,
}

impl RecordKind {
    /// The table this kind lives in.
    ///
    /// Not a caller-supplied string: the value comes from this closed enum, so it can be
    /// interpolated into a statement where SQLite does not accept a bound parameter. That is the
    /// only interpolation anywhere in the backend, and it is why this method exists rather than a
    /// `table: &str` argument.
    #[must_use]
    pub const fn table(self) -> &'static str {
        match self {
            Self::SourceObject => "source_objects",
            Self::Entity => "entities",
            Self::Relationship => "relationships",
            Self::Claim => "claims",
            Self::Sighting => "sightings",
        }
    }

    /// Every kind, for callers that need to sweep them all.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SourceObject,
            Self::Entity,
            Self::Relationship,
            Self::Claim,
            Self::Sighting,
        ]
    }
}

/// A bounded slice of results.
///
/// There is no unbounded listing method. A query whose result set is proportional to the database
/// is a query that works in testing and exhausts memory in production, and adding pagination after
/// the fact means finding every caller that assumed otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Page {
    limit: u32,
    offset: u64,
}

impl Page {
    /// Largest page a caller may request.
    pub const MAX_LIMIT: u32 = 1000;

    /// Build a page, clamping the limit to [`Page::MAX_LIMIT`] and treating zero as one.
    ///
    /// Clamped rather than rejected: a caller asking for too much wants as much as it can have, and
    /// failing the query teaches it nothing it can act on.
    #[must_use]
    pub const fn new(limit: u32, offset: u64) -> Self {
        let limit = if limit == 0 {
            1
        } else if limit > Self::MAX_LIMIT {
            Self::MAX_LIMIT
        } else {
            limit
        };
        Self { limit, offset }
    }

    /// The first page of a given size.
    #[must_use]
    pub const fn first(limit: u32) -> Self {
        Self::new(limit, 0)
    }

    /// The clamped limit.
    #[must_use]
    pub const fn limit(self) -> u32 {
        self.limit
    }

    /// The offset.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// The page after this one.
    #[must_use]
    pub fn next(self) -> Self {
        Self {
            limit: self.limit,
            offset: self.offset.saturating_add(u64::from(self.limit)),
        }
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::first(100)
    }
}

/// Which way an edge points, relative to the node being asked about.
///
/// A closed enum rather than a `&str` or a boolean pair, for the reason the whole module exists: a
/// caller names a direction, never a column. A relationship is directed, and collapsing that into
/// "connected" would turn "this malware targets this sector" into "this sector targets this
/// malware".
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Direction {
    /// Edges that point away from the node.
    Outgoing,
    /// Edges that point at the node.
    Incoming,
    /// Edges at either end.
    ///
    /// The default, because a caller asking "what is connected to this" almost never means "only
    /// what points away from it".
    #[default]
    Either,
}

impl Direction {
    /// Whether an edge with this node as its source is in scope.
    #[must_use]
    pub const fn includes_source(self) -> bool {
        matches!(self, Self::Outgoing | Self::Either)
    }

    /// Whether an edge with this node as its target is in scope.
    #[must_use]
    pub const fn includes_target(self) -> bool {
        matches!(self, Self::Incoming | Self::Either)
    }

    /// A stable label, for diagnostics and recorded decisions.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
            Self::Either => "either",
        }
    }
}

/// A typed filter over stored entities.
///
/// Every field is a closed enum, a typed value, or a set of them. There is no free-text predicate
/// and no field name a caller can supply, so this is what the safe query language planned for
/// `v1.0.0` compiles *to* rather than a place where it could be bypassed.
///
/// An empty set means **unconstrained**, not "match nothing". A filter that silently matched
/// nothing when a caller forgot to populate it would report an empty graph as a confident answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct EntityQuery {
    /// Which kinds to admit. Empty admits every kind.
    pub kinds: BTreeSet<EntityKind>,
    /// Which lifecycle statuses to admit. Empty admits every status.
    ///
    /// Not defaulted to "current only". A caller investigating why something was withdrawn needs
    /// the revoked records, and a default that hid them would answer a different question from the
    /// one asked.
    pub statuses: BTreeSet<LifecycleStatus>,
    /// Admit only entities last seen on or after the start of this instant's UTC day.
    ///
    /// **UTC-day granularity, deliberately.** `last_seen` is stored as RFC 3339 text with variable
    /// subsecond precision, and lexicographic order is not chronological order *within* a second —
    /// `…:00Z` sorts after `…:00.5Z`. Comparing at second or finer granularity would therefore be
    /// quietly wrong for records near the bound, and a filter that is silently wrong is worse than
    /// one that states its granularity. A day boundary is exact because the date prefix is
    /// fixed-width.
    ///
    /// An entity with no recorded `last_seen` does not match a `last_seen` bound.
    pub last_seen_from: Option<Timestamp>,
    /// Admit only entities last seen before the start of this instant's UTC day.
    ///
    /// Same granularity, and the same reason, as [`Self::last_seen_from`].
    pub last_seen_before: Option<Timestamp>,
}

impl EntityQuery {
    /// A query that constrains nothing.
    #[must_use]
    pub fn unfiltered() -> Self {
        Self::default()
    }

    /// Admit one more kind.
    #[must_use]
    pub fn with_kind(mut self, kind: EntityKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Admit one more lifecycle status.
    #[must_use]
    pub fn with_status(mut self, status: LifecycleStatus) -> Self {
        self.statuses.insert(status);
        self
    }

    /// Admit only records whose assertion currently stands.
    ///
    /// Spelled out rather than left to each caller, because "current" is
    /// [`LifecycleStatus::is_current`]'s two variants and a caller that remembers only `Active`
    /// drops every deprecated-but-standing record without noticing.
    #[must_use]
    pub fn only_current(mut self) -> Self {
        for status in [LifecycleStatus::Active, LifecycleStatus::Deprecated] {
            self.statuses.insert(status);
        }
        self
    }

    /// Bound the earliest `last_seen` admitted, at UTC-day granularity.
    #[must_use]
    pub const fn last_seen_from(mut self, at: Timestamp) -> Self {
        self.last_seen_from = Some(at);
        self
    }

    /// Bound the latest `last_seen` admitted, at UTC-day granularity.
    #[must_use]
    pub const fn last_seen_before(mut self, at: Timestamp) -> Self {
        self.last_seen_before = Some(at);
        self
    }

    /// Whether this query constrains nothing at all.
    ///
    /// A cost signal: an unfiltered search is a scan, and a caller that can see that before running
    /// it can decide whether it meant to.
    #[must_use]
    pub fn is_unfiltered(&self) -> bool {
        self.kinds.is_empty()
            && self.statuses.is_empty()
            && self.last_seen_from.is_none()
            && self.last_seen_before.is_none()
    }
}

/// A typed filter over the edges at one node.
///
/// The adjacency query `docs/ARCHITECTURE.md` commits to: relational adjacency tables, read one hop
/// at a time, so a traversal's depth is the caller's decision rather than the database's. The
/// `relationships_source` and `relationships_target` indexes are `(ref, kind)`, which is why kind is
/// a filter here and not something applied after the rows come back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EdgeQuery {
    /// The node whose edges are wanted.
    pub node: NodeRef,
    /// Which way the edges point, relative to that node.
    pub direction: Direction,
    /// Which relationship kinds to admit. Empty admits every kind.
    pub kinds: BTreeSet<RelationshipKind>,
    /// Which lifecycle statuses to admit. Empty admits every status.
    pub statuses: BTreeSet<LifecycleStatus>,
}

impl EdgeQuery {
    /// Every edge at a node, in the given direction.
    #[must_use]
    pub fn at(node: NodeRef, direction: Direction) -> Self {
        Self {
            node,
            direction,
            kinds: BTreeSet::new(),
            statuses: BTreeSet::new(),
        }
    }

    /// Admit one more relationship kind.
    #[must_use]
    pub fn with_kind(mut self, kind: RelationshipKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Admit one more lifecycle status.
    #[must_use]
    pub fn with_status(mut self, status: LifecycleStatus) -> Self {
        self.statuses.insert(status);
        self
    }

    /// Admit only edges whose assertion currently stands.
    #[must_use]
    pub fn only_current(mut self) -> Self {
        for status in [LifecycleStatus::Active, LifecycleStatus::Deprecated] {
            self.statuses.insert(status);
        }
        self
    }

    /// The same filter asked about a different node.
    ///
    /// What a traversal does at every hop: the predicate is the caller's, and only the node moves.
    #[must_use]
    pub fn about(&self, node: NodeRef) -> Self {
        Self {
            node,
            direction: self.direction,
            kinds: self.kinds.clone(),
            statuses: self.statuses.clone(),
        }
    }
}

/// What migrating did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// The schema version before migrating. Zero for a fresh database.
    pub from_version: u32,
    /// The schema version after migrating.
    pub to_version: u32,
    /// Which migrations were applied, in order. Empty when the database was already current.
    pub applied: Vec<u32>,
}

impl MigrationReport {
    /// Whether anything was applied.
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.applied.is_empty()
    }
}

/// Reading canonical records.
pub trait StoreRead {
    /// The schema version the database is at.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the version cannot be read.
    fn schema_version(&self) -> Result<u32>;

    /// A connector's position in one feed, if it has ever run.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the cursor cannot be read.
    fn connector_cursor(&self, connector: &str, feed: &str) -> Result<Option<ConnectorCursor>>;

    /// Every connector cursor, for an operator asking which feeds are stale or failing.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the cursors cannot be read.
    fn connector_cursors(&self) -> Result<Vec<ConnectorCursor>>;

    /// How many records of a kind are stored.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the count fails.
    fn count(&self, kind: RecordKind) -> Result<u64>;

    /// Fetch a source object by identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn get_source_object(&self, id: Id<SourceObject>) -> Result<Option<SourceObject>>;

    /// Fetch a source object by the digest of its bytes.
    ///
    /// The lookup that makes re-import idempotent: evidence is addressed by content, so this
    /// answers "have I already stored these exact bytes" without needing to know the identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn find_source_object_by_hash(&self, hash: &ContentHash) -> Result<Option<SourceObject>>;

    /// Fetch an entity by identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn get_entity(&self, id: Id<Entity>) -> Result<Option<Entity>>;

    /// Fetch a relationship by identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn get_relationship(&self, id: Id<Relationship>) -> Result<Option<Relationship>>;

    /// Fetch a claim by identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn get_claim(&self, id: Id<Claim>) -> Result<Option<Claim>>;

    /// Fetch a sighting by identifier.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or the stored
    /// document cannot be decoded.
    fn get_sighting(&self, id: Id<Sighting>) -> Result<Option<Sighting>>;

    /// List entities, newest observation first, bounded by `page`.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn list_entities(&self, page: Page) -> Result<Vec<Entity>>;

    /// Relationships with the given node at either end, bounded by `page`.
    ///
    /// Both directions, because a relationship is directed but a caller asking "what is connected
    /// to this" almost never means "only what points away from it".
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn relationships_touching(&self, node: &NodeRef, page: Page) -> Result<Vec<Relationship>>;

    /// Entities matching a typed filter, in identifier order, bounded by `page`.
    ///
    /// Ordered by identifier rather than by recency, because identifier order is a *total* order
    /// over a unique column: two runs against unchanged data return the same records in the same
    /// order, and page two does not overlap page one because a record's `last_seen` moved between
    /// the two reads. Ordering by a mutable column is how offset paging silently skips and repeats
    /// rows.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn search_entities(&self, query: &EntityQuery, page: Page) -> Result<Vec<Entity>>;

    /// Edges at one node matching a typed filter, in identifier order, bounded by `page`.
    ///
    /// One hop. Recursion is the caller's, held to the caller's budget, because a recursive query
    /// that decides its own depth inside the database is a denial of service with an index on it.
    ///
    /// Identifier order for the same reason as [`Self::search_entities`]: a traversal that returned
    /// neighbours in a different order between runs would make every downstream comparison
    /// worthless.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn edges_at(&self, query: &EdgeQuery, page: Page) -> Result<Vec<Relationship>>;

    /// How many edges the same filter would match, without reading any of them.
    ///
    /// The cost estimate a caller checks *before* expanding a node. Reading a million edges to
    /// discover there were a million of them is the failure this exists to prevent.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn degree(&self, query: &EdgeQuery) -> Result<u64>;

    /// Claims about a subject, bounded by `page`.
    ///
    /// Every claim, including revoked and contradictory ones. Filtering them here would decide on
    /// the caller's behalf which disagreements are worth knowing about.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn claims_about(&self, subject: &NodeRef, page: Page) -> Result<Vec<Claim>>;

    /// Sightings of a subject, most recent last-seen first, bounded by `page`.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the query fails or a stored
    /// document cannot be decoded.
    fn sightings_of(&self, subject: &NodeRef, page: Page) -> Result<Vec<Sighting>>;

    /// Read a retained source object's original bytes back.
    ///
    /// The digest is recomputed and compared to the address before the bytes are returned, so a
    /// corrupted row surfaces as an error rather than as plausible bytes. That check is here, in
    /// the only path that hands bytes to a caller, rather than left to each caller to remember.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Corrupt`] if the stored bytes do not decode, or no longer hash to the
    /// address they were fetched from. [`crate::StorageError::Query`] for a backend failure.
    fn get_source_blob(&self, content_hash: &ContentHash) -> Result<Option<RetrievedBlob>>;

    /// What is known about a retained object without reading its bytes.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure, [`crate::StorageError::Corrupt`] for a row whose
    /// codec or retention class this build does not recognise.
    fn source_blob_metadata(&self, content_hash: &ContentHash) -> Result<Option<BlobMetadata>>;

    /// Every retention decision recorded for an address, oldest first.
    ///
    /// Returns events for an address whose blob has since been released, which is the case the
    /// audit log exists for.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn source_blob_audit(&self, content_hash: &ContentHash) -> Result<Vec<RetentionEvent>>;

    /// Every quarantined record for one source, most recent first.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure, [`crate::StorageError::Corrupt`] for a
    /// row whose stage this build does not recognise.
    fn quarantined_for_source(&self, source_hash: &ContentHash) -> Result<Vec<QuarantineRecord>>;

    /// How many distinct rejections are quarantined.
    ///
    /// Distinct, not total: a broken feed re-imported nightly is one problem, not thirty.
    /// [`Self::quarantine_occurrences`] is the other number.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn quarantine_count(&self) -> Result<u64>;

    /// How many rejection *events* are quarantined, counting repeats.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn quarantine_occurrences(&self) -> Result<u64>;

    /// Every retained source object, newest first.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn list_source_objects(&self, page: Page) -> Result<Vec<SourceObject>>;

    /// Fetch a stored entity as its serialised document.
    ///
    /// Returns the document as stored rather than a re-serialisation of a decoded value, so what an
    /// operator sees is what is on disk — a difference between the two is exactly the thing worth
    /// being able to notice.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure, [`crate::StorageError::Corrupt`] if
    /// the stored document is not valid JSON.
    fn get_entity_json(&self, id: &str) -> Result<Option<serde_json::Value>>;

    /// As [`Self::get_entity_json`], for a relationship.
    ///
    /// # Errors
    ///
    /// As [`Self::get_entity_json`].
    fn get_relationship_json(&self, id: &str) -> Result<Option<serde_json::Value>>;

    /// As [`Self::get_entity_json`], for a claim.
    ///
    /// # Errors
    ///
    /// As [`Self::get_entity_json`].
    fn get_claim_json(&self, id: &str) -> Result<Option<serde_json::Value>>;

    /// As [`Self::get_entity_json`], for a sighting.
    ///
    /// # Errors
    ///
    /// As [`Self::get_entity_json`].
    fn get_sighting_json(&self, id: &str) -> Result<Option<serde_json::Value>>;

    /// As [`Self::get_entity_json`], for a source object.
    ///
    /// # Errors
    ///
    /// As [`Self::get_entity_json`].
    fn get_source_object_json(&self, id: &str) -> Result<Option<serde_json::Value>>;

    /// Read a named checkpoint back.
    ///
    /// Returned as the stored document, for the caller to decode into whatever the producing
    /// algorithm's type is. Storage does not know what a checkpoint means and should not have to.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure, [`crate::StorageError::Corrupt`] if
    /// the stored document is not valid JSON.
    fn get_checkpoint(&self, name: &str) -> Result<Option<serde_json::Value>>;

    /// Every stored checkpoint's name and summary, most recent capture first.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn list_checkpoints(&self) -> Result<Vec<CheckpointSummary>>;

    /// The graph's material-change version.
    ///
    /// Increments when a graph record is inserted or changed, and not when an upsert is a no-op —
    /// so comparing it answers "has anything actually changed?" rather than "did somebody run an
    /// import?".
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn graph_version(&self) -> Result<u64>;

    /// Every recorded graph decision about one subject, oldest first.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn graph_decisions_for(&self, kind: &str, subject: &str) -> Result<Vec<GraphDecisionRow>>;

    /// How many graph decisions of one kind carry a given verdict.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn graph_decision_count(&self, kind: &str, verdict: &str) -> Result<u64>;

    /// Whether an entity exists, without decoding it.
    ///
    /// Exists so referential integrity can be checked cheaply on every edge write.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn entity_exists(&self, id: Id<Entity>) -> Result<bool>;

    /// How many objects are retained.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn source_blob_count(&self) -> Result<u64>;

    /// Total bytes occupied by retained objects, after encoding.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn source_blob_stored_bytes(&self) -> Result<u64>;
}

/// Writing canonical records, inside a transaction.
///
/// Object-safe on purpose: [`IntelligenceStore::transaction`] hands out `&mut dyn StoreWrite`, so
/// the closure that does the work cannot keep the handle beyond the transaction.
pub trait StoreWrite {
    /// Store a source object.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the write fails.
    fn upsert_source_object(&mut self, source: &SourceObject) -> Result<UpsertOutcome>;

    /// Store an entity.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the write fails.
    fn upsert_entity(&mut self, entity: &Entity) -> Result<UpsertOutcome>;

    /// Store a relationship.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the write fails.
    fn upsert_relationship(&mut self, relationship: &Relationship) -> Result<UpsertOutcome>;

    /// Store a claim.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the write fails.
    fn upsert_claim(&mut self, claim: &Claim) -> Result<UpsertOutcome>;

    /// Store a sighting.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the write fails.
    fn upsert_sighting(&mut self, sighting: &Sighting) -> Result<UpsertOutcome>;

    /// Retain an original source object, addressed by its own digest.
    ///
    /// Byte-identical objects store once: a second request for bytes already present returns
    /// [`BlobOutcome::Deduplicated`] and writes nothing. This is on [`StoreWrite`] rather than on a
    /// store of its own so that evidence and the canonical records derived from it commit in **one
    /// transaction** — a canonical record referencing a blob that was never written is a dangling
    /// reference nothing later can repair.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::BlobTooLarge`] if the object is over the configured ceiling, in which case
    /// nothing is written and no reference exists to dangle. [`crate::StorageError::Query`] for a backend
    /// failure.
    fn put_source_blob(&mut self, request: &BlobRequest<'_>) -> Result<BlobOutcome>;

    /// Write a connector's cursor.
    ///
    /// Called inside the same transaction as the records the page produced. A cursor advanced
    /// outside that transaction can disagree with the database, and the disagreement is invisible:
    /// the next run starts after a window whose records were never stored. See
    /// [`crate::cursor`].
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if the cursor cannot be written.
    fn put_connector_cursor(&mut self, cursor: &ConnectorCursor) -> Result<()>;

    /// Remove a retained object deliberately, recording why.
    ///
    /// Returns `false` if nothing was retained at that address. The audit entry is written either
    /// way: "somebody tried to release evidence that was not there" is worth being able to see.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::RetentionRefused`] if the blob's retention class forbids removal.
    /// [`crate::StorageError::Query`] for a backend failure.
    fn release_source_blob(&mut self, content_hash: &ContentHash, reason: &str) -> Result<bool>;

    /// Record a rejected record so it can be inspected rather than lost.
    ///
    /// Re-offering the same rejection updates the existing row and increments its occurrence count
    /// instead of appending, because a quarantine that grows on every retry of a broken feed is one
    /// nobody reads. Returns `true` when this rejection was seen for the first time.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn quarantine(&mut self, entry: &QuarantineEntry) -> Result<bool>;

    /// Store a checkpoint under a name, replacing any checkpoint already under it.
    ///
    /// Replacing rather than appending, because a checkpoint is a *named baseline* — "nightly",
    /// "before the migration" — and an operator who re-takes one means to move it. History of what
    /// changed lives in the deltas, not in a pile of superseded baselines.
    ///
    /// Returns `true` when the name was new.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn put_checkpoint(
        &mut self,
        summary: &CheckpointSummary,
        document: &serde_json::Value,
    ) -> Result<bool>;

    /// Remove a named checkpoint.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn delete_checkpoint(&mut self, name: &str) -> Result<bool>;

    /// Record a graph decision, replacing any earlier decision about the same inputs.
    ///
    /// Re-running an algorithm over the same inputs updates one row rather than appending, because
    /// re-running is what happens on every re-import and a log that grows each time is one nobody
    /// reads. Returns `true` when the decision was recorded for the first time.
    ///
    /// Deliberately **not** a graph mutation: recording why something was decided does not change
    /// what the graph says, so it does not move the graph version.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn record_graph_decision(&mut self, decision: &GraphDecisionRow) -> Result<bool>;

    /// Change a retained object's retention class, recording why.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Query`] for a backend failure.
    fn reclassify_source_blob(
        &mut self,
        content_hash: &ContentHash,
        retention: RetentionClass,
        reason: &str,
    ) -> Result<bool>;
}

/// A complete storage backend.
pub trait IntelligenceStore: StoreRead {
    /// Bring the database up to the schema this build implements.
    ///
    /// Idempotent: running it against a current database applies nothing and reports so.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`](crate::error::StorageError) if a migration fails, if an applied
    /// migration's checksum no longer matches this build, or if the database is newer than this
    /// build understands.
    fn migrate(&mut self) -> Result<MigrationReport>;

    /// Run `work` inside a transaction, committing on `Ok` and rolling back on `Err`.
    ///
    /// Rollback happens on the error path *and* on a panic, because a transaction handle that is
    /// dropped without committing rolls back. A partially applied import is worse than a failed
    /// one: the failure is visible, and the partial state is not.
    ///
    /// # Errors
    ///
    /// Returns the closure's error after rolling back, or a
    /// [`StorageError`](crate::error::StorageError) if the transaction could not be started or
    /// committed.
    fn transaction<R>(&mut self, work: impl FnOnce(&mut dyn StoreWrite) -> Result<R>) -> Result<R>;
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

    #[test]
    fn an_unchanged_upsert_is_distinguishable_from_a_change() {
        // Otherwise a feed republishing its catalogue looks like a catalogue of changes.
        assert!(UpsertOutcome::Inserted.changed());
        assert!(UpsertOutcome::Updated.changed());
        assert!(!UpsertOutcome::Unchanged.changed());
    }

    #[test]
    fn a_page_limit_is_clamped_rather_than_rejected() {
        // A caller asking for too much wants as much as it can have; failing teaches it nothing.
        assert_eq!(Page::new(u32::MAX, 0).limit(), Page::MAX_LIMIT);
        assert_eq!(
            Page::new(0, 0).limit(),
            1,
            "zero would return nothing forever"
        );
        assert_eq!(Page::new(50, 0).limit(), 50);
        assert_eq!(Page::default().limit(), 100);
    }

    #[test]
    fn paging_advances_by_the_page_size_and_cannot_overflow() {
        let page = Page::first(25);
        assert_eq!(page.offset(), 0);
        assert_eq!(page.next().offset(), 25);
        assert_eq!(page.next().next().offset(), 50);

        let last = Page::new(10, u64::MAX);
        assert_eq!(
            last.next().offset(),
            u64::MAX,
            "saturates rather than wrapping"
        );
    }

    #[test]
    fn every_record_kind_has_a_distinct_table() {
        let tables: std::collections::BTreeSet<&str> =
            RecordKind::all().iter().map(|kind| kind.table()).collect();
        assert_eq!(tables.len(), RecordKind::all().len());
        assert_eq!(RecordKind::all().len(), 5);
    }

    #[test]
    fn table_names_are_a_closed_set_not_caller_supplied() {
        // The only place a name is interpolated into a statement, and it can only come from here.
        for kind in RecordKind::all() {
            let table = kind.table();
            assert!(
                table.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{table} is not a plain identifier",
            );
        }
    }

    #[test]
    fn an_empty_query_constrains_nothing_and_says_so() {
        // The cost signal a caller checks before running a scan it did not mean to ask for.
        assert!(EntityQuery::unfiltered().is_unfiltered());
        assert!(
            !EntityQuery::unfiltered()
                .with_kind(EntityKind::ThreatActor)
                .is_unfiltered()
        );
        assert!(
            !EntityQuery::unfiltered()
                .last_seen_from(brolga_model::temporal::Timestamp::unix_epoch())
                .is_unfiltered()
        );
    }

    #[test]
    fn current_means_both_standing_statuses_not_just_active() {
        // A caller that remembers only `Active` drops every deprecated-but-standing record without
        // noticing, which is why this is spelled out once here rather than at each call site.
        let query = EntityQuery::unfiltered().only_current();
        assert!(query.statuses.contains(&LifecycleStatus::Active));
        assert!(query.statuses.contains(&LifecycleStatus::Deprecated));
        assert_eq!(query.statuses.len(), 2);

        for status in [
            LifecycleStatus::Revoked,
            LifecycleStatus::Superseded,
            LifecycleStatus::Expired,
        ] {
            assert!(!query.statuses.contains(&status));
            assert!(!status.is_current());
        }
    }

    #[test]
    fn a_direction_admits_exactly_the_ends_it_names() {
        // A relationship is directed. Treating one direction as both would turn "this malware
        // targets this sector" into "this sector targets this malware".
        assert!(Direction::Outgoing.includes_source());
        assert!(!Direction::Outgoing.includes_target());
        assert!(Direction::Incoming.includes_target());
        assert!(!Direction::Incoming.includes_source());
        assert!(Direction::Either.includes_source() && Direction::Either.includes_target());
        assert_eq!(Direction::default(), Direction::Either);
    }

    #[test]
    fn moving_a_filter_to_another_node_keeps_the_predicate() {
        // What a traversal does at every hop. If the predicate drifted, a walk would widen as it
        // went — which is exactly the failure the budgets exist to prevent.
        let first = NodeRef::Entity(Id::derive(&["entity", "a"]));
        let second = NodeRef::Entity(Id::derive(&["entity", "b"]));

        let query = EdgeQuery::at(first, Direction::Outgoing)
            .with_kind(RelationshipKind::Uses)
            .only_current();
        let moved = query.about(second);

        assert_eq!(moved.node, second);
        assert_eq!(moved.direction, query.direction);
        assert_eq!(moved.kinds, query.kinds);
        assert_eq!(moved.statuses, query.statuses);
    }

    #[test]
    fn a_migration_report_says_whether_anything_happened() {
        let nothing = MigrationReport {
            from_version: 1,
            to_version: 1,
            applied: Vec::new(),
        };
        assert!(!nothing.changed());

        let something = MigrationReport {
            from_version: 0,
            to_version: 1,
            applied: vec![1],
        };
        assert!(something.changed());
    }
}
