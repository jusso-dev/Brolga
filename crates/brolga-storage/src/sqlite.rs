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

use crate::error::{Result, StorageError};
use crate::migration::{MIGRATIONS, MIGRATIONS_TABLE, latest_version};
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
        };
        store.configure(DEFAULT_BUSY_TIMEOUT_MS)?;
        Ok(store)
    }

    /// Where this store lives.
    #[must_use]
    pub const fn path(&self) -> &StorePath {
        &self.path
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
        let transaction =
            self.connection
                .transaction()
                .map_err(|error| StorageError::Transaction {
                    action: "started",
                    reason: error.to_string(),
                })?;

        let mut writer = SqliteWriter { transaction };
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
}

impl SqliteWriter<'_> {
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

        Ok(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_relationship(&mut self, relationship: &Relationship) -> Result<UpsertOutcome> {
        let id = relationship.id.to_string();
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

        Ok(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_claim(&mut self, claim: &Claim) -> Result<UpsertOutcome> {
        let id = claim.id.to_string();
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

        Ok(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_sighting(&mut self, sighting: &Sighting) -> Result<UpsertOutcome> {
        let id = sighting.id.to_string();
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

        Ok(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
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
