//! Translate canonical (SQLite) migration SQL into PostgreSQL dialect.
//!
//! Canonical migration text in [`crate::migration::MIGRATIONS`] is hashed for immutability.
//! PostgreSQL applies a deterministic dialect transform of that same text so checksums stay shared.

/// Convert SQLite migration SQL used by Brolga into PostgreSQL.
#[must_use]
pub fn sqlite_migration_to_postgres(sql: &str) -> String {
    let mut out = sql.to_owned();
    // STRICT is SQLite-only type enforcement.
    out = out.replace(") STRICT;", ");");
    out = out.replace(") STRICT\n", ");\n");
    // Blob type.
    out = out.replace("BLOB", "BYTEA");
    // Auto-increment primary keys (must run before the general INTEGER rewrite).
    out = out.replace(
        "INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT",
        "BIGSERIAL PRIMARY KEY",
    );
    // SQLite INTEGER is 64-bit; PostgreSQL INTEGER is 32-bit. Use BIGINT so
    // rust-postgres i64 binds/reads match (i64 only accepts/produces INT8).
    out = out.replace("INTEGER", "BIGINT");
    // SQLite datetime helper used when recording applied migrations.
    out = out.replace("datetime('now')", "(NOW() AT TIME ZONE 'UTC')");
    out
}

/// Migrations bookkeeping table for PostgreSQL.
pub const POSTGRES_MIGRATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS brolga_schema_migrations (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
);";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MIGRATIONS;

    #[test]
    fn every_migration_translates_without_strict() {
        for migration in MIGRATIONS {
            let pg = sqlite_migration_to_postgres(migration.sql);
            assert!(
                !pg.contains("STRICT"),
                "migration {} still has STRICT",
                migration.id
            );
            assert!(
                !pg.contains("AUTOINCREMENT"),
                "migration {} still has AUTOINCREMENT",
                migration.id
            );
            // Bare INTEGER must not remain (would be 32-bit and break i64 binds).
            assert!(
                !pg.split_whitespace().any(|t| t == "INTEGER"),
                "migration {} still has bare INTEGER",
                migration.id
            );
        }
    }

    #[test]
    fn sqlite_integer_becomes_bigint() {
        let pg = sqlite_migration_to_postgres(
            "CREATE TABLE t (n INTEGER NOT NULL, id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT) STRICT;",
        );
        assert!(pg.contains("BIGINT"));
        assert!(pg.contains("BIGSERIAL"));
        assert!(!pg.contains("STRICT"));
        assert!(!pg.contains("AUTOINCREMENT"));
    }
}
