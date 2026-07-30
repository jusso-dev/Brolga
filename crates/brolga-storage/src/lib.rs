//! Transactional persistence for Brolga's canonical records.
//!
//! Backend-neutral traits in [`store`], schema migrations in [`migration`], a SQLite
//! implementation in [`sqlite`], and an optional PostgreSQL path behind feature `postgres`
//! ([ADR 0011](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0011-postgresql-backend-and-safe-query-language.md)).
//! Layer 1 under ADR 0001: it depends on `brolga-model` and nothing else first-party.
//!
//! # No arbitrary SQL crosses the trait boundary
//!
//! Every method takes typed canonical values and typed queries. There is no `execute(sql)` and no
//! escape hatch, so SQL cannot be injected through the storage layer and the safe query language
//! planned for a later milestone has somewhere real to compile *to*. If callers could pass SQL,
//! that language would be optional — and an optional safety boundary is not one.
//!
//! Inside the backend, every value is a bound parameter. The single interpolation substitutes a
//! table name drawn from the closed [`RecordKind`] enum, in a position where
//! SQLite does not accept a bound parameter, so it cannot carry a caller's input. An integration
//! test round-trips `'; DROP TABLE entities; --` and friends and asserts both that the payloads
//! come back byte-identical and that every table still exists.
//!
//! # Records are stored as a canonical document plus indexed columns
//!
//! Each table keeps the full canonical JSON in `document` and lifts out only what is needed to find
//! records. Shredding every field into columns would mean a migration for every model change and
//! would make the database the authority on the model's shape — which it is not. The Rust types
//! are, and each document carries the `schema_version` that says which version wrote it.
//!
//! The indexed columns are duplicated *from* the document, never authoritative over it.
//!
//! # A released migration is immutable
//!
//! ADR 0001 §6 makes migration identifiers a compatibility surface. Every applied migration's
//! checksum is recorded and re-checked on every start-up, so editing a released migration fails at
//! the next run instead of quietly producing two deployments that report the same schema version
//! and have different schemas.
//!
//! # Example
//!
//! ```
//! use brolga_model::entity::{Entity, EntityKind};
//! use brolga_model::provenance::{RecordOrigin, SyntheticOrigin, SyntheticReason};
//! use brolga_model::text::{ShortText, UntrustedText};
//! use brolga_storage::sqlite::SqliteStore;
//! use brolga_storage::store::{IntelligenceStore, RecordKind, StoreRead, UpsertOutcome};
//!
//! let mut store = SqliteStore::open_in_memory()?;
//! let report = store.migrate()?;
//! assert!(report.changed());
//!
//! let origin = RecordOrigin::synthetic(SyntheticOrigin::new(
//!     SyntheticReason::OperatorEntered,
//!     ShortText::new("analyst@example")?,
//! ));
//! let actor = Entity::new(
//!     Entity::derive_id(
//!         EntityKind::ThreatActor,
//!         &ShortText::new("mitre-attack")?,
//!         &ShortText::new("G0016")?,
//!     ),
//!     EntityKind::ThreatActor,
//!     UntrustedText::new("APT29")?,
//!     origin,
//! );
//!
//! // Writes happen inside a transaction, which rolls back on error.
//! let outcome = store.transaction(|write| write.upsert_entity(&actor))?;
//! assert_eq!(outcome, UpsertOutcome::Inserted);
//!
//! // Re-importing the same record is idempotent and says so.
//! let again = store.transaction(|write| write.upsert_entity(&actor))?;
//! assert_eq!(again, UpsertOutcome::Unchanged);
//! assert!(!again.changed());
//!
//! assert_eq!(store.count(RecordKind::Entity)?, 1);
//! assert_eq!(store.get_entity(actor.id)?, Some(actor));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Full-text search
//!
//! Not implemented in `v0.1.0`, and deliberately not half-implemented. The plan it is designed for:
//! narrative fields live in the canonical document, so an FTS5 external-content table over
//! `entities(document)` and `claims(document)` can be added as an appended migration without
//! touching the stored records or any existing index. Adding it now would mean choosing a tokeniser
//! and a ranking function with no ingestion to evaluate them against, and both are hard to change
//! once operators have indexes built on them.
//!
//! # What this crate deliberately leaves to others
//!
//! - **PostgreSQL.** Feature `postgres` (ADR 0011): full [`IntelligenceStore`] via
//!   [`PostgresStore`], shared migration checksums, dual-backend contract tests when
//!   `BROLGA_POSTGRES_URL` is set.
//! - **Graph traversal.** `docs/ARCHITECTURE.md` commits to relational adjacency with bounded
//!   recursive queries. This crate supplies the adjacency *primitives* —
//!   [`EdgeQuery`], [`StoreRead::edges_at`], and [`StoreRead::degree`] — which read exactly one hop
//!   and report what a hop would cost. Recursion, and the budget it is held to, belong to
//!   `brolga-graph`: a recursive query that decides its own depth inside the database is a denial
//!   of service with an index on it.
//! - **Content-addressed blob retention.** [`SourceObject`](brolga_model::provenance::SourceObject)
//!   metadata is stored; the bytes it addresses are a later milestone's problem.
//! - **A query language.** [`brolga-query`](https://github.com/jusso-dev/Brolga/tree/main/crates/brolga-query)
//!   compiles human syntax to these traits (never to raw SQL).

#![forbid(unsafe_code)]

pub mod audit;
pub mod blob;
pub mod checkpoint;
pub mod cursor;
pub mod decision;
pub mod error;
pub mod migration;
pub mod open;
pub mod postgres_sql;
pub mod quarantine;
pub mod sqlite;
pub mod store;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use audit::{
    AuditAction, AuditEvent, BoundedLabels, FailurePolicy, MAX_LABEL_CARDINALITY, Outcome,
};
pub use blob::{
    BlobCodec, BlobMetadata, BlobOutcome, BlobRequest, DEFAULT_MAX_BLOB_BYTES, RetentionAction,
    RetentionClass, RetentionEvent, RetrievedBlob,
};
pub use checkpoint::CheckpointSummary;
pub use cursor::{ConnectorCursor, CursorStatus};
pub use decision::GraphDecisionRow;
pub use error::StorageError;
pub use migration::{MIGRATIONS, Migration, latest_version};
pub use open::{OpenedStore, is_postgres_url};
pub use quarantine::{QuarantineEntry, QuarantineRecord, QuarantineStage};
pub use sqlite::{SqliteStore, StorePath};
pub use store::{
    Direction, EdgeQuery, EntityQuery, IntelligenceStore, MigrationReport, Page, RecordKind,
    StoreRead, StoreWrite, UpsertOutcome,
};

#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;
