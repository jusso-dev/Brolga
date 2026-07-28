//! Storage errors.
//!
//! Every variant is reachable from either operator configuration or stored data, so none of them
//! embeds an unbounded value and none quotes raw SQL back at a caller. A driver message can leak the
//! shape of a query and occasionally a parameter, so driver text is kept as a `reason` string on a
//! variant that names what Brolga was doing, rather than surfaced as the whole error.

use thiserror::Error;

/// Anything that can go wrong reading or writing canonical records.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The database file could not be opened.
    #[error("could not open the database at {path}: {reason}")]
    Open {
        /// The configured path.
        path: String,
        /// Why it failed.
        reason: String,
    },

    /// A configured path was rejected before it was opened.
    #[error("database path {path:?} is not usable: {reason}")]
    UnusablePath {
        /// A truncated preview of the configured path.
        path: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A migration failed to apply.
    #[error("migration {id:04} ({name}) failed: {reason}")]
    Migration {
        /// The migration's identifier.
        id: u32,
        /// The migration's name.
        name: String,
        /// Why it failed.
        reason: String,
    },

    /// A migration that was already applied no longer matches what this build carries.
    ///
    /// A released migration is immutable. If the recorded checksum and the built-in one disagree,
    /// either the migration was edited after release or the database came from a different build,
    /// and applying anything further would produce a schema nobody can reason about.
    #[error(
        "migration {id:04} ({name}) was applied with checksum {recorded}, but this build carries {expected}; a released migration must never be edited"
    )]
    MigrationChanged {
        /// The migration's identifier.
        id: u32,
        /// The migration's name.
        name: String,
        /// What the database recorded when it was applied.
        recorded: String,
        /// What this build carries.
        expected: String,
    },

    /// The database is newer than this build understands.
    #[error(
        "database is at schema version {found}, but this build implements {expected}; upgrade Brolga rather than downgrading the database"
    )]
    SchemaTooNew {
        /// The highest migration this build carries.
        expected: u32,
        /// The highest migration the database has applied.
        found: u32,
    },

    /// A query or statement failed.
    #[error("{operation} failed: {reason}")]
    Query {
        /// What Brolga was doing, in plain words.
        operation: &'static str,
        /// The driver's message.
        reason: String,
    },

    /// A stored record could not be decoded into its canonical type.
    ///
    /// Distinct from a query failure: the database worked, and what came back is not a record this
    /// build can interpret. Usually a schema-version mismatch that migrations did not catch.
    #[error("stored {kind} record {id} could not be decoded: {reason}")]
    Corrupt {
        /// Which kind of record.
        kind: &'static str,
        /// The record's identifier.
        id: String,
        /// Why decoding failed.
        reason: String,
    },

    /// A source object was larger than the retention ceiling.
    ///
    /// Nothing is written when this is returned — not the blob, and not any canonical record in the
    /// same transaction — so no reference to a missing blob can exist afterwards.
    #[error(
        "source object is {actual} bytes, over the {limit}-byte retention limit; \
         nothing was written, so no canonical record references it"
    )]
    BlobTooLarge {
        /// How large the object is.
        actual: u64,
        /// The configured ceiling.
        limit: u64,
    },

    /// A retention class forbids removing this object.
    #[error(
        "source object {content_hash} is held under retention class {retention} and was not released: {reason}"
    )]
    RetentionRefused {
        /// Which object.
        content_hash: String,
        /// The class that refused.
        retention: &'static str,
        /// Why the class forbids it.
        reason: &'static str,
    },

    /// A transaction could not be started, committed, or rolled back.
    #[error("transaction could not be {action}: {reason}")]
    Transaction {
        /// `started`, `committed`, or `rolled back`.
        action: &'static str,
        /// The driver's message.
        reason: String,
    },
}

impl StorageError {
    /// Build a [`StorageError::Query`] without repeating the field names.
    pub(crate) fn query(operation: &'static str, reason: impl core::fmt::Display) -> Self {
        Self::Query {
            operation,
            reason: reason.to_string(),
        }
    }
}

/// Convenience alias for fallible storage operations.
pub type Result<T> = core::result::Result<T, StorageError>;

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
    fn a_changed_migration_says_what_is_wrong_and_why_it_matters() {
        let error = StorageError::MigrationChanged {
            id: 1,
            name: "initial_schema".to_owned(),
            recorded: "sha256:aaa".to_owned(),
            expected: "sha256:bbb".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("0001"), "{rendered}");
        assert!(rendered.contains("never be edited"), "{rendered}");
    }

    #[test]
    fn a_newer_database_tells_the_operator_which_direction_to_move() {
        let rendered = StorageError::SchemaTooNew {
            expected: 1,
            found: 7,
        }
        .to_string();
        assert!(rendered.contains("upgrade Brolga"), "{rendered}");
        assert!(rendered.contains('7'), "{rendered}");
    }

    #[test]
    fn a_corrupt_record_is_distinguishable_from_a_failed_query() {
        // The database worked; what came back is not interpretable. Different problem, different
        // fix, so a caller must be able to tell them apart.
        let corrupt = StorageError::Corrupt {
            kind: "entity",
            id: "entity:1".to_owned(),
            reason: "unknown variant".to_owned(),
        };
        assert!(matches!(corrupt, StorageError::Corrupt { .. }));
        assert!(corrupt.to_string().contains("could not be decoded"));
    }

    #[test]
    fn migration_ids_are_zero_padded_so_they_sort_readably() {
        let rendered = StorageError::Migration {
            id: 7,
            name: "add_index".to_owned(),
            reason: "syntax error".to_owned(),
        }
        .to_string();
        assert!(rendered.contains("0007"), "{rendered}");
    }
}
