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

use brolga_model::claim::Claim;
use brolga_model::entity::Entity;
use brolga_model::id::Id;
use brolga_model::provenance::{ContentHash, SourceObject};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::sighting::Sighting;

use crate::blob::{
    BlobMetadata, BlobOutcome, BlobRequest, RetentionClass, RetentionEvent, RetrievedBlob,
};
use crate::error::Result;

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
