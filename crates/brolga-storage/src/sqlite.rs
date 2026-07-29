//! The SQLite backend.
//!
//! # Connection settings, and why each one is set
//!
//! - **`journal_mode = WAL`.** Readers do not block the writer and the writer does not block
//!   readers. Without it, every read during an import waits, which for a tool whose whole job is
//!   answering questions about imported intelligence is the wrong trade.
//! - **`busy_timeout`.** Bounded, from configuration. SQLite's default is to fail *immediately* on
//!   contention, which turns a momentary overlap into a spurious error; an unbounded wait would
//!   turn it into a hang. Both are worse than waiting a stated number of milliseconds.
//! - **`foreign_keys = ON`.** Off by default in SQLite, for backwards compatibility. Declared
//!   constraints that are not enforced are worse than no constraints, because they read as
//!   guarantees.
//! - **`synchronous = NORMAL`.** The documented pairing with WAL: durable across process crashes,
//!   and only at risk from an operating-system crash or power loss. Brolga's canonical records are
//!   derived from retained source objects, so the recovery path is re-derivation, not a restore.
//! - **`trusted_schema = OFF`** and **`defensive = ON`.** A database file is an input. If one is
//!   ever opened from somewhere unexpected, these stop schema-embedded constructs from running.
//!
//! # Every statement is a constant with bound parameters
//!
//! No caller-supplied string is ever concatenated into SQL. The single interpolation in this file
//! substitutes a table name from the closed [`RecordKind`] enum, in a position where SQLite does
//! not accept a bound parameter — it cannot carry a caller's value.

use std::path::{Path, PathBuf};

use brolga_model::claim::Claim;
use brolga_model::entity::Entity;
use brolga_model::id::{Id, Identifiable};
use brolga_model::provenance::{ContentHash, SourceObject};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::sighting::Sighting;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::blob::{
    BlobCodec, BlobMetadata, BlobOutcome, BlobRequest, RetentionAction, RetentionClass,
    RetentionEvent, RetrievedBlob, decode_bytes, encode_bytes,
};
use crate::decision::GraphDecisionRow;
use crate::error::{Result, StorageError};
use crate::migration::{MIGRATIONS, MIGRATIONS_TABLE, latest_version};
use crate::quarantine::{QuarantineEntry, QuarantineRecord, QuarantineStage};
use crate::store::{
    IntelligenceStore, MigrationReport, Page, RecordKind, StoreRead, StoreWrite, UpsertOutcome,
};

/// Default busy timeout, in milliseconds, matching `brolga-config`'s default.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5000;

/// A SQLite-backed intelligence store.
#[derive(Debug)]
pub struct SqliteStore {
    connection: Connection,
    path: StorePath,
    max_blob_bytes: u64,
}

/// Where a store lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorePath {
    /// A file on disk.
    File(PathBuf),
    /// A private in-memory database, for tests and for `--dry-run` work.
    Memory,
}

impl StorePath {
    fn describe(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Memory => ":memory:".to_owned(),
        }
    }
}

impl SqliteStore {
    /// Open a database file, creating it if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::UnusablePath`] if the path contains a `..` component or a NUL byte,
    /// and [`StorageError::Open`] if the file cannot be opened or the connection cannot be
    /// configured.
    pub fn open(path: impl AsRef<Path>, busy_timeout_ms: u64) -> Result<Self> {
        let path = path.as_ref();
        validate_path(path)?;

        let connection = Connection::open(path).map_err(|error| StorageError::Open {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;

        let store = Self {
            connection,
            path: StorePath::File(path.to_path_buf()),
            max_blob_bytes: crate::blob::DEFAULT_MAX_BLOB_BYTES,
        };
        store.configure(busy_timeout_ms)?;
        Ok(store)
    }

    /// Open a private in-memory database.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Open`] if the connection cannot be created or configured.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(|error| StorageError::Open {
            path: ":memory:".to_owned(),
            reason: error.to_string(),
        })?;

        let store = Self {
            connection,
            path: StorePath::Memory,
            max_blob_bytes: crate::blob::DEFAULT_MAX_BLOB_BYTES,
        };
        store.configure(DEFAULT_BUSY_TIMEOUT_MS)?;
        Ok(store)
    }

    /// Where this store lives.
    #[must_use]
    pub const fn path(&self) -> &StorePath {
        &self.path
    }

    /// Set the largest source object this store will retain.
    ///
    /// A ceiling, not a target. Beyond it [`put_source_blob`](StoreWrite::put_source_blob) fails
    /// and writes nothing, so a batch that would have exceeded it leaves no canonical record
    /// pointing at evidence that was never stored.
    #[must_use]
    pub const fn with_max_blob_bytes(mut self, max_blob_bytes: u64) -> Self {
        self.max_blob_bytes = max_blob_bytes;
        self
    }

    /// The largest source object this store will retain.
    #[must_use]
    pub const fn max_blob_bytes(&self) -> u64 {
        self.max_blob_bytes
    }

    /// Apply the connection settings documented at the top of this module.
    fn configure(&self, busy_timeout_ms: u64) -> Result<()> {
        let open = |reason: String| StorageError::Open {
            path: self.path.describe(),
            reason,
        };

        // WAL is persistent in the database file, so this is a no-op after the first open. An
        // in-memory database cannot use WAL at all and reports `memory`, which is expected.
        let journal_mode: String = self
            .connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|error| open(format!("could not enable WAL: {error}")))?;

        if !matches!(self.path, StorePath::Memory) && !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(open(format!(
                "journal mode is {journal_mode}, not WAL; the database may be on a filesystem that does not support it"
            )));
        }

        self.connection
            .busy_timeout(core::time::Duration::from_millis(busy_timeout_ms))
            .map_err(|error| open(format!("could not set the busy timeout: {error}")))?;

        for pragma in [
            "PRAGMA foreign_keys = ON",
            "PRAGMA synchronous = NORMAL",
            "PRAGMA trusted_schema = OFF",
        ] {
            self.connection
                .execute_batch(pragma)
                .map_err(|error| open(format!("{pragma} failed: {error}")))?;
        }

        // A database file is an input. `defensive` blocks writes to internal schema structures; it
        // is not available on every build of SQLite, so a failure here is not fatal.
        let _ = self
            .connection
            .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true);

        Ok(())
    }

    /// Whether write-ahead logging is active.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the pragma cannot be read.
    pub fn journal_mode(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|error| StorageError::query("reading the journal mode", error))
    }

    /// The configured busy timeout, in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the pragma cannot be read.
    pub fn busy_timeout_ms(&self) -> Result<i64> {
        self.connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .map_err(|error| StorageError::query("reading the busy timeout", error))
    }

    /// Read a stored document back as JSON, without decoding it into its typed form first.
    ///
    /// What is returned is what is on disk. Re-serialising a decoded value would hide a difference
    /// between the two, and that difference is exactly the thing worth being able to notice.
    fn document_json(
        &self,
        sql: &str,
        id: &str,
        kind: &'static str,
    ) -> Result<Option<serde_json::Value>> {
        let document: Option<String> = self
            .connection
            .query_row(sql, params![id], |row| row.get(0))
            .optional()
            .map_err(|error| StorageError::query("reading a record", error))?;

        document
            .map(|document| {
                serde_json::from_str(&document).map_err(|error| StorageError::Corrupt {
                    kind,
                    id: id.to_owned(),
                    reason: format!("stored document is not valid JSON: {error}"),
                })
            })
            .transpose()
    }

    /// Read a single non-negative count, for the aggregate queries that return one.
    fn scalar(&self, sql: &str) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(sql, [], |row| row.get(0))
            .map_err(|error| StorageError::query("counting retained source blobs", error))?;
        Ok(u64::try_from(value).unwrap_or(0))
    }

    fn fetch<T: DeserializeOwned>(
        &self,
        kind: &'static str,
        sql: &str,
        key: &str,
    ) -> Result<Option<T>> {
        let document: Option<String> = self
            .connection
            .query_row(sql, params![key], |row| row.get(0))
            .optional()
            .map_err(|error| StorageError::query("reading a record", error))?;

        document
            .map(|document| decode(kind, key, &document))
            .transpose()
    }

    fn fetch_many<T: DeserializeOwned>(
        &self,
        kind: &'static str,
        sql: &str,
        binds: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<T>> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(|error| StorageError::query("preparing a listing", error))?;

        let rows = statement
            .query_map(binds, |row| row.get::<_, String>(0))
            .map_err(|error| StorageError::query("running a listing", error))?;

        let mut out = Vec::new();
        for row in rows {
            let document =
                row.map_err(|error| StorageError::query("reading a listing row", error))?;
            out.push(decode(kind, "<listing>", &document)?);
        }
        Ok(out)
    }
}

fn decode<T: DeserializeOwned>(kind: &'static str, id: &str, document: &str) -> Result<T> {
    serde_json::from_str(document).map_err(|error| StorageError::Corrupt {
        kind,
        id: id.to_owned(),
        reason: error.to_string(),
    })
}

fn encode<T: Serialize>(kind: &'static str, id: &str, value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| StorageError::Corrupt {
        kind,
        id: id.to_owned(),
        reason: error.to_string(),
    })
}

/// Reject a database path that could escape where the operator meant it to be.
fn validate_path(path: &Path) -> Result<()> {
    let rendered = path.display().to_string();

    if rendered.is_empty() {
        return Err(StorageError::UnusablePath {
            path: rendered,
            reason: "path must not be empty".to_owned(),
        });
    }
    if rendered.contains('\0') {
        return Err(StorageError::UnusablePath {
            path: rendered.replace('\0', "\\0"),
            reason: "path must not contain a NUL byte".to_owned(),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(StorageError::UnusablePath {
            path: rendered,
            reason: "path must not contain a parent-directory component".to_owned(),
        });
    }

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Statements. Constants, every value bound.
// -------------------------------------------------------------------------------------------------

const GET_SOURCE_OBJECT: &str = "SELECT document FROM source_objects WHERE id = ?1";
const GET_SOURCE_OBJECT_BY_HASH: &str =
    "SELECT document FROM source_objects WHERE content_hash = ?1";
const GET_ENTITY: &str = "SELECT document FROM entities WHERE id = ?1";
const GET_RELATIONSHIP: &str = "SELECT document FROM relationships WHERE id = ?1";
const GET_CLAIM: &str = "SELECT document FROM claims WHERE id = ?1";
const GET_SIGHTING: &str = "SELECT document FROM sightings WHERE id = ?1";

const LIST_SOURCE_OBJECTS: &str = "\
SELECT document FROM source_objects ORDER BY retrieved_at DESC, id ASC LIMIT ?1 OFFSET ?2";

const LIST_ENTITIES: &str = "\
SELECT document FROM entities
ORDER BY last_seen DESC NULLS LAST, id ASC
LIMIT ?1 OFFSET ?2";

const RELATIONSHIPS_TOUCHING: &str = "\
SELECT document FROM relationships
WHERE source_ref = ?1 OR target_ref = ?1
ORDER BY id ASC
LIMIT ?2 OFFSET ?3";

const CLAIMS_ABOUT: &str = "\
SELECT document FROM claims
WHERE subject_ref = ?1
ORDER BY id ASC
LIMIT ?2 OFFSET ?3";

const SIGHTINGS_OF: &str = "\
SELECT document FROM sightings
WHERE subject_ref = ?1
ORDER BY last_seen DESC, id ASC
LIMIT ?2 OFFSET ?3";

impl StoreRead for SqliteStore {
    fn schema_version(&self) -> Result<u32> {
        let exists: bool = self
            .connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'brolga_schema_migrations'",
                [],
                |_| Ok(true),
            )
            .optional()
            .map_err(|error| StorageError::query("checking for the migrations table", error))?
            .unwrap_or(false);

        if !exists {
            return Ok(0);
        }

        let version: Option<u32> = self
            .connection
            .query_row("SELECT MAX(id) FROM brolga_schema_migrations", [], |row| {
                row.get(0)
            })
            .map_err(|error| StorageError::query("reading the schema version", error))?;

        Ok(version.unwrap_or(0))
    }

    fn count(&self, kind: RecordKind) -> Result<u64> {
        // The one interpolation in this file. The value comes from a closed enum, in a position
        // where SQLite does not accept a bound parameter, so it cannot carry a caller's input.
        let sql = format!("SELECT COUNT(*) FROM {}", kind.table());
        self.connection
            .query_row(&sql, [], |row| row.get::<_, i64>(0))
            .map(|count| u64::try_from(count).unwrap_or(0))
            .map_err(|error| StorageError::query("counting records", error))
    }

    fn get_source_object(&self, id: Id<SourceObject>) -> Result<Option<SourceObject>> {
        self.fetch("source_object", GET_SOURCE_OBJECT, &id.to_string())
    }

    fn find_source_object_by_hash(&self, hash: &ContentHash) -> Result<Option<SourceObject>> {
        self.fetch(
            "source_object",
            GET_SOURCE_OBJECT_BY_HASH,
            &hash.to_string(),
        )
    }

    fn get_entity(&self, id: Id<Entity>) -> Result<Option<Entity>> {
        self.fetch("entity", GET_ENTITY, &id.to_string())
    }

    fn get_relationship(&self, id: Id<Relationship>) -> Result<Option<Relationship>> {
        self.fetch("relationship", GET_RELATIONSHIP, &id.to_string())
    }

    fn get_claim(&self, id: Id<Claim>) -> Result<Option<Claim>> {
        self.fetch("claim", GET_CLAIM, &id.to_string())
    }

    fn get_sighting(&self, id: Id<Sighting>) -> Result<Option<Sighting>> {
        self.fetch("sighting", GET_SIGHTING, &id.to_string())
    }

    fn list_entities(&self, page: Page) -> Result<Vec<Entity>> {
        self.fetch_many(
            "entity",
            LIST_ENTITIES,
            &[
                &page.limit(),
                &i64::try_from(page.offset()).unwrap_or(i64::MAX),
            ],
        )
    }

    fn relationships_touching(&self, node: &NodeRef, page: Page) -> Result<Vec<Relationship>> {
        let node = node.to_string();
        self.fetch_many(
            "relationship",
            RELATIONSHIPS_TOUCHING,
            &[
                &node,
                &page.limit(),
                &i64::try_from(page.offset()).unwrap_or(i64::MAX),
            ],
        )
    }

    fn claims_about(&self, subject: &NodeRef, page: Page) -> Result<Vec<Claim>> {
        let subject = subject.to_string();
        self.fetch_many(
            "claim",
            CLAIMS_ABOUT,
            &[
                &subject,
                &page.limit(),
                &i64::try_from(page.offset()).unwrap_or(i64::MAX),
            ],
        )
    }

    fn sightings_of(&self, subject: &NodeRef, page: Page) -> Result<Vec<Sighting>> {
        let subject = subject.to_string();
        self.fetch_many(
            "sighting",
            SIGHTINGS_OF,
            &[
                &subject,
                &page.limit(),
                &i64::try_from(page.offset()).unwrap_or(i64::MAX),
            ],
        )
    }

    fn get_source_blob(&self, content_hash: &ContentHash) -> Result<Option<RetrievedBlob>> {
        let address = content_hash.to_string();
        let row = self
            .connection
            .query_row(
                "SELECT codec, original_length, stored_length, retention, stored_at, bytes
                 FROM source_blobs WHERE content_hash = ?1",
                params![address],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| StorageError::query("reading a source blob", error))?;

        let Some((codec, original_length, stored_length, retention, stored_at, stored)) = row
        else {
            return Ok(None);
        };
        let metadata = build_metadata(
            *content_hash,
            &codec,
            original_length,
            stored_length,
            &retention,
            stored_at,
        )?;

        let bytes = decode_bytes(metadata.codec, &stored).ok_or_else(|| StorageError::Corrupt {
            kind: "source_blob",
            id: address.clone(),
            reason: format!("stored bytes do not decode as {}", metadata.codec),
        })?;

        let retrieved = RetrievedBlob { metadata, bytes };

        // The check that makes content addressing mean something. A row whose bytes no longer hash
        // to the address they were fetched from is corrupt, and returning them would hand a caller
        // evidence that is not the evidence it asked for.
        if !retrieved.integrity_holds() {
            return Err(StorageError::Corrupt {
                kind: "source_blob",
                id: address,
                reason: "stored bytes no longer hash to the address they are filed under"
                    .to_owned(),
            });
        }

        Ok(Some(retrieved))
    }

    fn source_blob_metadata(&self, content_hash: &ContentHash) -> Result<Option<BlobMetadata>> {
        let address = content_hash.to_string();
        let row = self
            .connection
            .query_row(
                "SELECT codec, original_length, stored_length, retention, stored_at
                 FROM source_blobs WHERE content_hash = ?1",
                params![address],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| StorageError::query("reading source blob metadata", error))?;

        row.map(
            |(codec, original_length, stored_length, retention, stored_at)| {
                build_metadata(
                    *content_hash,
                    &codec,
                    original_length,
                    stored_length,
                    &retention,
                    stored_at,
                )
            },
        )
        .transpose()
    }

    fn source_blob_audit(&self, content_hash: &ContentHash) -> Result<Vec<RetentionEvent>> {
        let address = content_hash.to_string();
        let mut statement = self
            .connection
            .prepare(
                "SELECT action, reason, at FROM source_blob_audit
                 WHERE content_hash = ?1 ORDER BY id ASC",
            )
            .map_err(|error| StorageError::query("preparing a retention audit query", error))?;

        let rows = statement
            .query_map(params![address], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| StorageError::query("reading a retention audit", error))?;

        let mut events = Vec::new();
        for row in rows {
            let (action, reason, at) =
                row.map_err(|error| StorageError::query("reading a retention audit row", error))?;
            let action =
                RetentionAction::from_str_opt(&action).ok_or_else(|| StorageError::Corrupt {
                    kind: "source_blob_audit",
                    id: address.clone(),
                    reason: format!("unknown retention action {action:?}"),
                })?;
            events.push(RetentionEvent {
                content_hash: *content_hash,
                action,
                reason,
                at,
            });
        }
        Ok(events)
    }

    fn source_blob_count(&self) -> Result<u64> {
        self.scalar("SELECT COUNT(*) FROM source_blobs")
    }

    fn source_blob_stored_bytes(&self) -> Result<u64> {
        self.scalar("SELECT COALESCE(SUM(stored_length), 0) FROM source_blobs")
    }

    fn quarantined_for_source(&self, source_hash: &ContentHash) -> Result<Vec<QuarantineRecord>> {
        let address = source_hash.to_string();
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, parser, parser_version, stage, reason_kind, reason, record_index,
                        byte_offset, fragment, first_seen_at, last_seen_at, occurrences
                 FROM quarantine WHERE source_hash = ?1 ORDER BY last_seen_at DESC, id ASC",
            )
            .map_err(|error| StorageError::query("preparing a quarantine query", error))?;

        let rows = statement
            .query_map(params![address], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            })
            .map_err(|error| StorageError::query("reading quarantine", error))?;

        let mut records = Vec::new();
        for row in rows {
            let row =
                row.map_err(|error| StorageError::query("reading a quarantine row", error))?;
            let stage =
                QuarantineStage::from_str_opt(&row.3).ok_or_else(|| StorageError::Corrupt {
                    kind: "quarantine",
                    id: row.0.clone(),
                    reason: format!("unknown stage {:?}", row.3),
                })?;
            records.push(QuarantineRecord {
                id: row.0,
                source_hash: *source_hash,
                parser: row.1,
                parser_version: u32::try_from(row.2).unwrap_or(0),
                stage,
                reason_kind: row.4,
                reason: row.5,
                record_index: row.6.and_then(|value| u64::try_from(value).ok()),
                byte_offset: row.7.and_then(|value| u64::try_from(value).ok()),
                fragment: row.8,
                first_seen_at: row.9,
                last_seen_at: row.10,
                occurrences: u64::try_from(row.11).unwrap_or(0),
            });
        }
        Ok(records)
    }

    fn quarantine_count(&self) -> Result<u64> {
        self.scalar("SELECT COUNT(*) FROM quarantine")
    }

    fn quarantine_occurrences(&self) -> Result<u64> {
        self.scalar("SELECT COALESCE(SUM(occurrences), 0) FROM quarantine")
    }

    fn list_source_objects(&self, page: Page) -> Result<Vec<SourceObject>> {
        self.fetch_many(
            "source_object",
            LIST_SOURCE_OBJECTS,
            &[
                &page.limit(),
                &i64::try_from(page.offset()).unwrap_or(i64::MAX),
            ],
        )
    }

    fn get_entity_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(GET_ENTITY, id, "entity")
    }

    fn get_relationship_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(GET_RELATIONSHIP, id, "relationship")
    }

    fn get_claim_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(GET_CLAIM, id, "claim")
    }

    fn get_sighting_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(GET_SIGHTING, id, "sighting")
    }

    fn get_source_object_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(GET_SOURCE_OBJECT, id, "source_object")
    }

    fn graph_version(&self) -> Result<u64> {
        self.scalar("SELECT version FROM graph_meta WHERE id = 1")
    }

    fn entity_exists(&self, id: Id<Entity>) -> Result<bool> {
        let found: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM entities WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StorageError::query("checking whether an entity exists", error))?;
        Ok(found.is_some())
    }

    fn graph_decisions_for(&self, kind: &str, subject: &str) -> Result<Vec<GraphDecisionRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT observation, compared_with, verdict, algorithm, algorithm_version, reason,
                        decided_at
                 FROM graph_decisions WHERE decision_kind = ?1 AND subject = ?2
                 ORDER BY decided_at ASC, id ASC",
            )
            .map_err(|error| StorageError::query("preparing a graph decision query", error))?;

        let rows = statement
            .query_map(params![kind, subject], |row| {
                Ok(GraphDecisionRow {
                    kind: String::new(),
                    subject: String::new(),
                    observation: row.get(0)?,
                    compared_with: row.get(1)?,
                    verdict: row.get(2)?,
                    algorithm: row.get(3)?,
                    algorithm_version: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                    reason: row.get(5)?,
                    decided_at: row.get(6)?,
                })
            })
            .map_err(|error| StorageError::query("reading graph decisions", error))?;

        let mut decisions = Vec::new();
        for row in rows {
            let mut row =
                row.map_err(|error| StorageError::query("reading a graph decision row", error))?;
            row.kind = kind.to_owned();
            row.subject = subject.to_owned();
            decisions.push(row);
        }
        Ok(decisions)
    }

    fn graph_decision_count(&self, kind: &str, verdict: &str) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM graph_decisions WHERE decision_kind = ?1 AND verdict = ?2",
                params![kind, verdict],
                |row| row.get(0),
            )
            .map_err(|error| StorageError::query("counting graph decisions", error))?;
        Ok(u64::try_from(value).unwrap_or(0))
    }
}

impl IntelligenceStore for SqliteStore {
    fn migrate(&mut self) -> Result<MigrationReport> {
        self.connection
            .execute_batch(MIGRATIONS_TABLE)
            .map_err(|error| StorageError::Migration {
                id: 0,
                name: "migrations_table".to_owned(),
                reason: error.to_string(),
            })?;

        let from_version = self.schema_version()?;

        if from_version > latest_version() {
            return Err(StorageError::SchemaTooNew {
                expected: latest_version(),
                found: from_version,
            });
        }

        // Verify every already-applied migration before applying anything new. A build whose
        // migration 0001 differs from the one the database was created with must not go on to apply
        // 0002 against a schema it cannot reason about.
        for migration in MIGRATIONS {
            let recorded: Option<String> = self
                .connection
                .query_row(
                    "SELECT checksum FROM brolga_schema_migrations WHERE id = ?1",
                    params![migration.id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| StorageError::query("reading a migration checksum", error))?;

            let expected = migration.checksum().to_string();
            if let Some(recorded) = recorded
                && recorded != expected
            {
                return Err(StorageError::MigrationChanged {
                    id: migration.id,
                    name: migration.name.to_owned(),
                    recorded,
                    expected,
                });
            }
        }

        let mut applied = Vec::new();

        for migration in MIGRATIONS {
            if migration.id <= from_version {
                continue;
            }

            // Each migration in its own transaction: a failure leaves the database at the last
            // version that fully applied, rather than half-way through one.
            let transaction =
                self.connection
                    .transaction()
                    .map_err(|error| StorageError::Transaction {
                        action: "started",
                        reason: error.to_string(),
                    })?;

            transaction
                .execute_batch(migration.sql)
                .map_err(|error| StorageError::Migration {
                    id: migration.id,
                    name: migration.name.to_owned(),
                    reason: error.to_string(),
                })?;

            transaction
                .execute(
                    "INSERT INTO brolga_schema_migrations (id, name, checksum, applied_at)
                     VALUES (?1, ?2, ?3, datetime('now'))",
                    params![
                        migration.id,
                        migration.name,
                        migration.checksum().to_string()
                    ],
                )
                .map_err(|error| StorageError::Migration {
                    id: migration.id,
                    name: migration.name.to_owned(),
                    reason: error.to_string(),
                })?;

            transaction
                .commit()
                .map_err(|error| StorageError::Transaction {
                    action: "committed",
                    reason: error.to_string(),
                })?;

            applied.push(migration.id);
        }

        Ok(MigrationReport {
            from_version,
            to_version: self.schema_version()?,
            applied,
        })
    }

    fn transaction<R>(&mut self, work: impl FnOnce(&mut dyn StoreWrite) -> Result<R>) -> Result<R> {
        let max_blob_bytes = self.max_blob_bytes;
        let transaction =
            self.connection
                .transaction()
                .map_err(|error| StorageError::Transaction {
                    action: "started",
                    reason: error.to_string(),
                })?;

        let mut writer = SqliteWriter {
            transaction,
            max_blob_bytes,
        };
        match work(&mut writer) {
            Ok(value) => {
                writer
                    .transaction
                    .commit()
                    .map_err(|error| StorageError::Transaction {
                        action: "committed",
                        reason: error.to_string(),
                    })?;
                Ok(value)
            }
            // Dropping the transaction rolls it back. Explicit, so the intent is visible rather
            // than a consequence of a `Drop` impl a reader has to know about.
            Err(error) => {
                drop(writer.transaction);
                Err(error)
            }
        }
    }
}

/// The writer handed to a transaction's closure.
struct SqliteWriter<'connection> {
    transaction: Transaction<'connection>,
    max_blob_bytes: u64,
}

impl SqliteWriter<'_> {
    /// Append one retention decision.
    ///
    /// Every path that stores, refuses, releases, or reclassifies calls this. A retention decision
    /// that is not recorded is indistinguishable afterwards from one nobody made.
    fn audit(&self, address: &str, action: RetentionAction, reason: &str) -> Result<()> {
        self.transaction
            .execute(
                "INSERT INTO source_blob_audit (content_hash, action, reason, at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![address, action.as_str(), reason, now_rfc3339()],
            )
            .map_err(|error| StorageError::query("recording a retention decision", error))?;
        Ok(())
    }

    /// Bump the graph's material-change counter.
    ///
    /// Called only when an upsert actually changed something. A version that ticked on every write
    /// would answer "somebody ran an import" rather than "has anything changed".
    fn touch_graph(&self, outcome: UpsertOutcome) -> Result<UpsertOutcome> {
        if outcome.changed() {
            self.transaction
                .execute(
                    "UPDATE graph_meta SET version = version + 1, last_changed_at = ?1 WHERE id = 1",
                    params![now_rfc3339()],
                )
                .map_err(|error| StorageError::query("incrementing the graph version", error))?;
        }
        Ok(outcome)
    }

    /// Refuse an edge whose endpoint names an entity that does not exist.
    ///
    /// Observable endpoints are content-addressed — their identifier is a function of their value,
    /// so there is nothing to dangle from. Entity endpoints name a row, and a row that is not there
    /// makes traversal silently return nothing rather than fail.
    fn require_node(
        &self,
        kind: &'static str,
        id: &str,
        endpoint: &'static str,
        node: &NodeRef,
    ) -> Result<()> {
        let NodeRef::Entity(entity) = node else {
            return Ok(());
        };
        let found: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM entities WHERE id = ?1",
                params![entity.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StorageError::query("checking an edge endpoint", error))?;

        if found.is_none() {
            return Err(StorageError::DanglingEdge {
                kind,
                id: id.to_owned(),
                endpoint,
                missing: entity.to_string(),
            });
        }
        Ok(())
    }

    /// Read the stored document for `id`, so an identical write can be reported as `Unchanged`.
    fn existing(&self, table_sql: &str, id: &str) -> Result<Option<String>> {
        self.transaction
            .query_row(table_sql, params![id], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|error| StorageError::query("reading a record before writing", error))
    }
}

impl StoreWrite for SqliteWriter<'_> {
    fn upsert_source_object(&mut self, source: &SourceObject) -> Result<UpsertOutcome> {
        let id = source.id.to_string();
        let document = encode("source_object", &id, source)?;

        if let Some(existing) = self.existing(GET_SOURCE_OBJECT, &id)?
            && existing == document
        {
            return Ok(UpsertOutcome::Unchanged);
        }

        let changed = self
            .transaction
            .execute(
                "INSERT INTO source_objects
                    (id, content_hash, media_type, byte_length, retrieved_at, origin_kind, document)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                    content_hash = excluded.content_hash,
                    media_type   = excluded.media_type,
                    byte_length  = excluded.byte_length,
                    retrieved_at = excluded.retrieved_at,
                    origin_kind  = excluded.origin_kind,
                    document     = excluded.document",
                params![
                    id,
                    source.content_hash.to_string(),
                    source.media_type.as_str(),
                    i64::try_from(source.byte_length).unwrap_or(i64::MAX),
                    source.retrieved_at.to_rfc3339(),
                    source.origin.kind_str(),
                    document,
                ],
            )
            .map_err(|error| StorageError::query("writing a source object", error))?;

        Ok(outcome(
            changed,
            self.existing(GET_SOURCE_OBJECT, &id)?.is_some(),
        ))
    }

    fn upsert_entity(&mut self, entity: &Entity) -> Result<UpsertOutcome> {
        let id = entity.id.to_string();
        let document = encode("entity", &id, entity)?;
        let existed = self.existing(GET_ENTITY, &id)?;

        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }

        self.transaction
            .execute(
                "INSERT INTO entities (id, kind, status, first_seen, last_seen, document)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    kind       = excluded.kind,
                    status     = excluded.status,
                    first_seen = excluded.first_seen,
                    last_seen  = excluded.last_seen,
                    document   = excluded.document",
                params![
                    id,
                    entity.kind.as_str(),
                    entity.status.as_str(),
                    entity.temporal.first_seen.map(|at| at.to_rfc3339()),
                    entity.temporal.last_seen.map(|at| at.to_rfc3339()),
                    document,
                ],
            )
            .map_err(|error| StorageError::query("writing an entity", error))?;

        self.touch_graph(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_relationship(&mut self, relationship: &Relationship) -> Result<UpsertOutcome> {
        let id = relationship.id.to_string();
        self.require_node("relationship", &id, "source", &relationship.source)?;
        self.require_node("relationship", &id, "target", &relationship.target)?;
        let document = encode("relationship", &id, relationship)?;
        let existed = self.existing(GET_RELATIONSHIP, &id)?;

        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }

        self.transaction
            .execute(
                "INSERT INTO relationships (id, kind, source_ref, target_ref, status, document)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    kind       = excluded.kind,
                    source_ref = excluded.source_ref,
                    target_ref = excluded.target_ref,
                    status     = excluded.status,
                    document   = excluded.document",
                params![
                    id,
                    relationship.kind.as_str(),
                    relationship.source.to_string(),
                    relationship.target.to_string(),
                    relationship.status.as_str(),
                    document,
                ],
            )
            .map_err(|error| StorageError::query("writing a relationship", error))?;

        self.touch_graph(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_claim(&mut self, claim: &Claim) -> Result<UpsertOutcome> {
        let id = claim.id.to_string();
        self.require_node("claim", &id, "subject", &claim.subject)?;
        let document = encode("claim", &id, claim)?;
        let existed = self.existing(GET_CLAIM, &id)?;

        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }

        self.transaction
            .execute(
                "INSERT INTO claims (id, subject_ref, assertion_kind, status, document)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                    subject_ref    = excluded.subject_ref,
                    assertion_kind = excluded.assertion_kind,
                    status         = excluded.status,
                    document       = excluded.document",
                params![
                    id,
                    claim.subject.to_string(),
                    claim.assertion.kind_str(),
                    claim.status.as_str(),
                    document,
                ],
            )
            .map_err(|error| StorageError::query("writing a claim", error))?;

        self.touch_graph(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_sighting(&mut self, sighting: &Sighting) -> Result<UpsertOutcome> {
        let id = sighting.id.to_string();
        self.require_node("sighting", &id, "subject", &sighting.subject)?;
        let document = encode("sighting", &id, sighting)?;
        let existed = self.existing(GET_SIGHTING, &id)?;

        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }

        self.transaction
            .execute(
                "INSERT INTO sightings
                    (id, subject_ref, observer, first_seen, last_seen, observations, status, document)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                    subject_ref  = excluded.subject_ref,
                    observer     = excluded.observer,
                    first_seen   = excluded.first_seen,
                    last_seen    = excluded.last_seen,
                    observations = excluded.observations,
                    status       = excluded.status,
                    document     = excluded.document",
                params![
                    id,
                    sighting.subject.to_string(),
                    sighting.observer.map(|observer| observer.to_string()),
                    sighting.first_seen.to_rfc3339(),
                    sighting.last_seen.to_rfc3339(),
                    i64::try_from(sighting.count.get()).unwrap_or(i64::MAX),
                    sighting.status.as_str(),
                    document,
                ],
            )
            .map_err(|error| StorageError::query("writing a sighting", error))?;

        self.touch_graph(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn put_source_blob(&mut self, request: &BlobRequest<'_>) -> Result<BlobOutcome> {
        let address = request.content_hash().to_string();
        let length = request.length();

        // Checked before anything is encoded or written. Returning here leaves the transaction
        // untouched, so a canonical record written alongside it rolls back with this error rather
        // than committing a reference to evidence that was refused.
        if length > self.max_blob_bytes {
            self.audit(
                &address,
                RetentionAction::Refused,
                &format!("over the {}-byte retention limit", self.max_blob_bytes),
            )?;
            return Err(StorageError::BlobTooLarge {
                actual: length,
                limit: self.max_blob_bytes,
            });
        }

        let present: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM source_blobs WHERE content_hash = ?1",
                params![address],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StorageError::query("checking for a retained source blob", error))?;

        if present.is_some() {
            // Byte-identical objects store once. The audit entry still lands, because "this arrived
            // again" is a fact about the feed worth being able to see.
            self.audit(&address, RetentionAction::Deduplicated, request.reason())?;
            return Ok(BlobOutcome::Deduplicated);
        }

        let (codec, encoded) = encode_bytes(request.bytes());
        let stored_length = u64::try_from(encoded.len()).unwrap_or(u64::MAX);

        self.transaction
            .execute(
                "INSERT INTO source_blobs
                    (content_hash, codec, original_length, stored_length, bytes, retention, stored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    address,
                    codec.as_str(),
                    i64::try_from(length).unwrap_or(i64::MAX),
                    i64::try_from(stored_length).unwrap_or(i64::MAX),
                    encoded,
                    request.retention().as_str(),
                    now_rfc3339(),
                ],
            )
            .map_err(|error| StorageError::query("retaining a source blob", error))?;

        self.audit(&address, RetentionAction::Stored, request.reason())?;
        Ok(BlobOutcome::Stored {
            stored_length,
            codec,
        })
    }

    fn release_source_blob(&mut self, content_hash: &ContentHash, reason: &str) -> Result<bool> {
        let address = content_hash.to_string();

        let retention: Option<String> = self
            .transaction
            .query_row(
                "SELECT retention FROM source_blobs WHERE content_hash = ?1",
                params![address],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StorageError::query("reading a blob's retention class", error))?;

        let Some(retention) = retention else {
            // Nothing there. Still audited: an attempt to release evidence that was already gone is
            // exactly the thing somebody will want to see afterwards.
            self.audit(
                &address,
                RetentionAction::Released,
                &format!("{reason} (nothing was retained at this address)"),
            )?;
            return Ok(false);
        };

        let class =
            RetentionClass::from_str_opt(&retention).ok_or_else(|| StorageError::Corrupt {
                kind: "source_blob",
                id: address.clone(),
                reason: format!("unknown retention class {retention:?}"),
            })?;

        if !class.may_be_swept() {
            return Err(StorageError::RetentionRefused {
                content_hash: address,
                retention: class.as_str(),
                reason: "the class exists so an automated sweep cannot remove evidence somebody is relying on",
            });
        }

        self.transaction
            .execute(
                "DELETE FROM source_blobs WHERE content_hash = ?1",
                params![address],
            )
            .map_err(|error| StorageError::query("releasing a source blob", error))?;

        // Audited after the delete, and into a table with no foreign key to the blob, so the record
        // that it was released outlives the thing released.
        self.audit(&address, RetentionAction::Released, reason)?;
        Ok(true)
    }

    fn reclassify_source_blob(
        &mut self,
        content_hash: &ContentHash,
        retention: RetentionClass,
        reason: &str,
    ) -> Result<bool> {
        let address = content_hash.to_string();
        let changed = self
            .transaction
            .execute(
                "UPDATE source_blobs SET retention = ?2 WHERE content_hash = ?1",
                params![address, retention.as_str()],
            )
            .map_err(|error| StorageError::query("reclassifying a source blob", error))?;

        if changed == 0 {
            return Ok(false);
        }
        self.audit(
            &address,
            RetentionAction::Reclassified,
            &format!("{reason} (now {retention})"),
        )?;
        Ok(true)
    }

    fn quarantine(&mut self, entry: &QuarantineEntry) -> Result<bool> {
        let id = entry.derive_id();
        let now = now_rfc3339();

        // Upsert on the derived identity, incrementing rather than appending. `first_seen_at` is
        // left alone by the update, so the row keeps saying when this first went wrong.
        let changed = self
            .transaction
            .execute(
                "INSERT INTO quarantine
                    (id, source_hash, parser, parser_version, stage, reason_kind, reason,
                     record_index, byte_offset, fragment, first_seen_at, last_seen_at, occurrences)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, 1)
                 ON CONFLICT(id) DO UPDATE SET
                    reason       = excluded.reason,
                    fragment     = excluded.fragment,
                    last_seen_at = excluded.last_seen_at,
                    occurrences  = quarantine.occurrences + 1",
                params![
                    id,
                    entry.source_hash.to_string(),
                    entry.parser,
                    i64::from(entry.parser_version),
                    entry.stage.as_str(),
                    entry.reason_kind,
                    entry.reason,
                    entry.record_index.and_then(|v| i64::try_from(v).ok()),
                    entry.byte_offset.and_then(|v| i64::try_from(v).ok()),
                    entry.fragment,
                    now,
                ],
            )
            .map_err(|error| StorageError::query("quarantining a record", error))?;

        let occurrences: i64 = self
            .transaction
            .query_row(
                "SELECT occurrences FROM quarantine WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|error| StorageError::query("reading a quarantine occurrence count", error))?;

        let _ = changed;
        Ok(occurrences == 1)
    }

    fn record_graph_decision(&mut self, decision: &GraphDecisionRow) -> Result<bool> {
        let id = decision.derive_id();
        let existed: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM graph_decisions WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StorageError::query("checking for a graph decision", error))?;

        self.transaction
            .execute(
                "INSERT INTO graph_decisions
                    (id, decision_kind, subject, observation, compared_with, verdict, algorithm,
                     algorithm_version, reason, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                    verdict           = excluded.verdict,
                    algorithm         = excluded.algorithm,
                    algorithm_version = excluded.algorithm_version,
                    reason            = excluded.reason,
                    decided_at        = excluded.decided_at",
                params![
                    id,
                    decision.kind,
                    decision.subject,
                    decision.observation,
                    decision.compared_with,
                    decision.verdict,
                    decision.algorithm,
                    i64::from(decision.algorithm_version),
                    decision.reason,
                    now_rfc3339(),
                ],
            )
            .map_err(|error| StorageError::query("recording a graph decision", error))?;

        Ok(existed.is_none())
    }
}

fn outcome(_rows_changed: usize, existed_before: bool) -> UpsertOutcome {
    if existed_before {
        UpsertOutcome::Updated
    } else {
        UpsertOutcome::Inserted
    }
}

/// The identifier kind a [`NodeRef`] renders to, used when a caller needs to know what a stored
/// reference points at without decoding the document.
#[must_use]
pub fn node_ref_kind(node: &NodeRef) -> &'static str {
    match node {
        NodeRef::Entity(_) => Entity::ID_KIND,
        NodeRef::Observable(_) => <brolga_model::observable::Observable as Identifiable>::ID_KIND,
        _ => "unknown",
    }
}

/// Rebuild blob metadata from a row, refusing labels this build does not know.
///
/// A row written by a newer build and read as a default would be worse than an error: an unknown
/// codec silently treated as `identity` returns compressed bytes as though they were the original.
fn build_metadata(
    content_hash: ContentHash,
    codec: &str,
    original_length: i64,
    stored_length: i64,
    retention: &str,
    stored_at: String,
) -> Result<BlobMetadata> {
    let address = content_hash.to_string();
    Ok(BlobMetadata {
        content_hash,
        codec: BlobCodec::from_str_opt(codec).ok_or_else(|| StorageError::Corrupt {
            kind: "source_blob",
            id: address.clone(),
            reason: format!("unknown codec {codec:?}"),
        })?,
        original_length: u64::try_from(original_length).unwrap_or(0),
        stored_length: u64::try_from(stored_length).unwrap_or(0),
        retention: RetentionClass::from_str_opt(retention).ok_or_else(|| {
            StorageError::Corrupt {
                kind: "source_blob",
                id: address,
                reason: format!("unknown retention class {retention:?}"),
            }
        })?,
        stored_at,
    })
}

/// The current instant, as an RFC 3339 string.
///
/// Runtime metadata only. ADR 0001 §6 keeps clock values out of every fingerprint, so this reaches
/// audit rows and nothing that is compared for equality.
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
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
    fn a_database_path_cannot_escape_with_a_traversal() {
        for hostile in ["../brolga.sqlite", "data/../../brolga.sqlite", ".."] {
            let error = validate_path(Path::new(hostile)).unwrap_err();
            assert!(
                matches!(error, StorageError::UnusablePath { .. }),
                "expected {hostile:?} to be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn ordinary_paths_are_accepted() {
        for benign in [
            "brolga.sqlite",
            "data/brolga.sqlite",
            "/var/lib/brolga/b.sqlite",
        ] {
            assert!(
                validate_path(Path::new(benign)).is_ok(),
                "expected {benign:?} to be accepted"
            );
        }
    }

    #[test]
    fn a_path_with_a_nul_byte_is_rejected() {
        // The path Rust validates and the path the C library opens must be the same path.
        assert!(validate_path(Path::new("brolga\u{0}.sqlite")).is_err());
    }

    #[test]
    fn a_fresh_in_memory_store_reports_version_zero_before_migrating() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), 0);
    }

    #[test]
    fn the_busy_timeout_is_bounded_rather_than_immediate_or_infinite() {
        // SQLite's default is to fail immediately on contention, which turns a momentary overlap
        // into a spurious error.
        let store = SqliteStore::open_in_memory().unwrap();
        let timeout = store.busy_timeout_ms().unwrap();
        assert!(timeout > 0, "an immediate failure is not a timeout");
        assert_eq!(timeout, i64::try_from(DEFAULT_BUSY_TIMEOUT_MS).unwrap());
    }

    #[test]
    fn foreign_keys_are_enforced() {
        // Off by default in SQLite. Declared constraints that are not enforced read as guarantees.
        let store = SqliteStore::open_in_memory().unwrap();
        let enabled: i64 = store
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
    }
}
