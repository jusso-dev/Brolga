//! Schema migrations.
//!
//! # A released migration is immutable
//!
//! ADR 0001 §6 makes migration identifiers a compatibility surface: appending a migration is a
//! compatible change, and editing or reordering a released one is breaking. That is not a policy
//! this module states and hopes for — every applied migration's checksum is recorded, and a
//! mismatch on start-up is a hard error naming the migration.
//!
//! Without that check, editing a migration produces two databases with the same recorded version
//! and different schemas, and every later migration is written against a schema that only some
//! deployments have.
//!
//! # Deterministic on both paths
//!
//! A database created from empty and a database upgraded from an older version must end up
//! identical. Migrations are applied in identifier order, each inside its own transaction, and the
//! integration tests compare the resulting schema of a fresh database against an upgraded one
//! rather than assuming it.

use brolga_model::provenance::ContentHash;

/// One schema change, identified permanently by its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Migration {
    /// Monotonic identifier. Never reused, never reordered.
    pub id: u32,
    /// Snake-case name, for diagnostics.
    pub name: &'static str,
    /// The statements to apply.
    pub sql: &'static str,
}

impl Migration {
    /// A digest of the migration's SQL, recorded when it is applied.
    ///
    /// Compared on every subsequent start-up, so editing a released migration is caught at the next
    /// run rather than discovered later as an unexplainable schema difference.
    #[must_use]
    pub fn checksum(&self) -> ContentHash {
        ContentHash::of(self.sql.as_bytes())
    }

    /// The zero-padded identifier used in diagnostics and in the migrations table.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{:04}_{}", self.id, self.name)
    }
}

/// The bookkeeping table. Created outside the numbered migrations, because it is what records that
/// the numbered migrations ran.
pub const MIGRATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS brolga_schema_migrations (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
) STRICT;";

/// Every migration this build carries, in order.
///
/// Appending is a compatible change. Editing or reordering an entry is breaking, and the checksum
/// check turns that from a silent divergence into a failed start-up.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        id: 1,
        name: "initial_schema",
        sql: INITIAL_SCHEMA,
    },
    Migration {
        id: 2,
        name: "source_blobs",
        sql: SOURCE_BLOBS,
    },
];

/// The highest migration identifier this build carries.
#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS
        .iter()
        .map(|migration| migration.id)
        .max()
        .unwrap_or(0)
}

/// The initial schema.
///
/// # Why records are stored as a canonical document plus indexed columns
///
/// Each table keeps the full canonical JSON in `document` and lifts out only the columns needed to
/// find records. Shredding every field into columns would mean a migration for every model change
/// and would make the database the authority on the model's shape, which it is not — the Rust types
/// are, and they carry a `schema_version` that travels with each document.
///
/// The indexed columns are duplicated *from* the document, never authoritative over it. Reads
/// decode the document; the columns exist to narrow the set of documents to decode.
///
/// `STRICT` tables reject a value of the wrong storage class instead of coercing it, so a bug that
/// writes a number where text belongs fails at the write rather than surfacing as a mis-typed read
/// months later.
const INITIAL_SCHEMA: &str = "\
CREATE TABLE source_objects (
    id            TEXT    NOT NULL PRIMARY KEY,
    content_hash  TEXT    NOT NULL UNIQUE,
    media_type    TEXT    NOT NULL,
    byte_length   INTEGER NOT NULL,
    retrieved_at  TEXT    NOT NULL,
    origin_kind   TEXT    NOT NULL,
    document      TEXT    NOT NULL
) STRICT;

CREATE INDEX source_objects_retrieved_at ON source_objects (retrieved_at);
CREATE INDEX source_objects_origin_kind  ON source_objects (origin_kind);

CREATE TABLE entities (
    id          TEXT NOT NULL PRIMARY KEY,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL,
    first_seen  TEXT,
    last_seen   TEXT,
    document    TEXT NOT NULL
) STRICT;

CREATE INDEX entities_kind        ON entities (kind);
CREATE INDEX entities_status      ON entities (status);
CREATE INDEX entities_last_seen   ON entities (last_seen);
CREATE INDEX entities_kind_status ON entities (kind, status);

CREATE TABLE relationships (
    id          TEXT NOT NULL PRIMARY KEY,
    kind        TEXT NOT NULL,
    source_ref  TEXT NOT NULL,
    target_ref  TEXT NOT NULL,
    status      TEXT NOT NULL,
    document    TEXT NOT NULL
) STRICT;

-- Adjacency in both directions. docs/ARCHITECTURE.md commits to relational adjacency tables with
-- bounded recursive queries rather than a dedicated graph database, and traversal in either
-- direction has to be indexed for that to hold.
CREATE INDEX relationships_source ON relationships (source_ref, kind);
CREATE INDEX relationships_target ON relationships (target_ref, kind);
CREATE INDEX relationships_status ON relationships (status);

CREATE TABLE claims (
    id             TEXT NOT NULL PRIMARY KEY,
    subject_ref    TEXT NOT NULL,
    assertion_kind TEXT NOT NULL,
    status         TEXT NOT NULL,
    document       TEXT NOT NULL
) STRICT;

CREATE INDEX claims_subject   ON claims (subject_ref, assertion_kind);
CREATE INDEX claims_status    ON claims (status);

CREATE TABLE sightings (
    id           TEXT    NOT NULL PRIMARY KEY,
    subject_ref  TEXT    NOT NULL,
    observer     TEXT,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    observations INTEGER NOT NULL,
    status       TEXT    NOT NULL,
    document     TEXT    NOT NULL
) STRICT;

CREATE INDEX sightings_subject   ON sightings (subject_ref, last_seen);
CREATE INDEX sightings_observer  ON sightings (observer);
CREATE INDEX sightings_last_seen ON sightings (last_seen);
";

/// Content-addressed retention of original source bytes, and the audit log of retention decisions.
///
/// Two deliberate omissions, both load-bearing:
///
/// **No foreign key to `source_objects`.** Deleting a canonical record must not destroy the
/// evidence it was derived from; a cascade would make a routine cleanup silently remove the only
/// proof of what a source published. The link runs the other way, from a canonical record's
/// provenance to a content hash, and a blob outliving its records is a supported state.
///
/// **`source_blob_audit` has no foreign key either**, so that releasing a blob does not erase the
/// record that it was released. An audit log that disappears with the thing it audits answers no
/// question anybody asks afterwards.
const SOURCE_BLOBS: &str = "\
CREATE TABLE source_blobs (
    content_hash    TEXT    NOT NULL PRIMARY KEY,
    codec           TEXT    NOT NULL,
    original_length INTEGER NOT NULL,
    stored_length   INTEGER NOT NULL,
    bytes           BLOB    NOT NULL,
    retention       TEXT    NOT NULL,
    stored_at       TEXT    NOT NULL
) STRICT;

CREATE INDEX source_blobs_retention ON source_blobs (retention);
CREATE INDEX source_blobs_stored_at ON source_blobs (stored_at);

CREATE TABLE source_blob_audit (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    content_hash TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    at           TEXT    NOT NULL
) STRICT;

CREATE INDEX source_blob_audit_hash ON source_blob_audit (content_hash, id);
";

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn identifiers_are_unique_ordered_and_start_at_one() {
        let ids: Vec<u32> = MIGRATIONS.iter().map(|migration| migration.id).collect();
        let unique: BTreeSet<u32> = ids.iter().copied().collect();

        assert_eq!(ids.len(), unique.len(), "duplicate migration identifier");
        assert_eq!(ids.first(), Some(&1), "identifiers start at 1");

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "migrations must be listed in identifier order");
    }

    #[test]
    fn names_are_unique_and_snake_case() {
        let names: BTreeSet<&str> = MIGRATIONS.iter().map(|migration| migration.name).collect();
        assert_eq!(names.len(), MIGRATIONS.len(), "duplicate migration name");

        for migration in MIGRATIONS {
            assert!(
                migration
                    .name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{} is not snake_case",
                migration.name,
            );
        }
    }

    #[test]
    fn checksums_are_deterministic_and_distinguish_migrations() {
        for migration in MIGRATIONS {
            assert_eq!(migration.checksum(), migration.checksum());
        }

        let checksums: BTreeSet<String> = MIGRATIONS
            .iter()
            .map(|migration| migration.checksum().to_string())
            .collect();
        assert_eq!(
            checksums.len(),
            MIGRATIONS.len(),
            "two migrations share a checksum, so editing one would be undetectable",
        );
    }

    #[test]
    fn the_initial_migration_checksum_is_pinned() {
        // Pinned deliberately. If this fails, migration 0001 was edited — which is exactly the
        // change ADR 0001 §6 forbids, and the fix is a new migration, not a new expected value.
        let initial = MIGRATIONS.first().expect("at least one migration");
        assert_eq!(
            initial.checksum().to_string(),
            "sha256:9b1fb1f29ad848b8ad2e45ec56c424d62a0e2d0a312f90ea4e534ec3051eaafa",
            "migration 0001 changed; append a new migration instead of editing a released one",
        );
    }

    /// Pinned like migration 0001's. A released migration is immutable under ADR 0001 §6, and a
    /// checksum in a test is what turns that from a rule into a failing build.
    #[test]
    fn the_source_blobs_migration_checksum_is_pinned() {
        let migration = MIGRATIONS
            .iter()
            .find(|migration| migration.id == 2)
            .expect("migration 0002 exists");
        assert_eq!(migration.name, "source_blobs");
        assert_eq!(
            migration.checksum().to_string(),
            "sha256:53d26648abfed4aafbd89bcb81f7028d97d42944fb2ea13d15ea0103a0068f62",
            "migration 0002 changed; append a new migration instead of editing a released one",
        );
    }

    /// The two omitted foreign keys are the design. A cascade from `source_objects` would let a
    /// canonical cleanup destroy the evidence, and one from the audit table would erase the record
    /// that a blob was released at the moment it was released.
    #[test]
    fn retention_tables_carry_no_foreign_key_that_could_cascade() {
        assert!(
            !SOURCE_BLOBS.contains("REFERENCES"),
            "a foreign key here would let canonical deletion destroy retained evidence",
        );
        assert!(SOURCE_BLOBS.contains("CREATE TABLE source_blobs"));
        assert!(SOURCE_BLOBS.contains("CREATE TABLE source_blob_audit"));
        assert_eq!(
            SOURCE_BLOBS.matches("STRICT").count(),
            2,
            "both retention tables are STRICT, like every other table",
        );
    }

    #[test]
    fn latest_version_matches_the_highest_identifier() {
        // Derived from MIGRATIONS rather than hard-coded, so appending a migration does not
        // require editing this test — which would make it a formality rather than a check.
        assert_eq!(
            latest_version(),
            MIGRATIONS
                .iter()
                .map(|migration| migration.id)
                .max()
                .unwrap(),
        );
    }

    #[test]
    fn labels_are_zero_padded_so_they_sort_lexically() {
        let migration = Migration {
            id: 7,
            name: "add_index",
            sql: "",
        };
        assert_eq!(migration.label(), "0007_add_index");
    }

    #[test]
    fn the_schema_uses_strict_tables() {
        // Without STRICT, SQLite coerces rather than rejecting, so a bug that writes a number where
        // text belongs surfaces as a mis-typed read months later instead of as a failed write.
        let create_count = INITIAL_SCHEMA.matches("CREATE TABLE").count();
        let strict_count = INITIAL_SCHEMA.matches("STRICT").count();
        assert_eq!(create_count, strict_count, "every table must be STRICT");
        assert!(create_count >= 5);
    }

    #[test]
    fn adjacency_is_indexed_in_both_directions() {
        // docs/ARCHITECTURE.md commits to relational adjacency with bounded recursive queries, so
        // traversal in either direction has to be indexed for that commitment to hold.
        assert!(INITIAL_SCHEMA.contains("relationships_source"));
        assert!(INITIAL_SCHEMA.contains("relationships_target"));
    }

    #[test]
    fn the_migrations_table_is_created_idempotently() {
        // It is created outside the numbered migrations, because it is what records that they ran.
        assert!(MIGRATIONS_TABLE.contains("IF NOT EXISTS"));
        assert!(MIGRATIONS_TABLE.contains("checksum"));
    }
}
