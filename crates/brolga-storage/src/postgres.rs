//! PostgreSQL backend foundation (feature `postgres`, ADR 0011 / #55).
//!
//! This module opens a connection and applies the same migration identifiers as SQLite after a
//! deterministic dialect transform. Full [`IntelligenceStore`] parity and dual-backend contract
//! tests land as follow-up commits on this issue; the checksum immutability contract is enforced
//! here already.

use postgres::{Client, NoTls};

use crate::error::{Result, StorageError};
use crate::migration::{MIGRATIONS, latest_version};
use crate::postgres_sql::{POSTGRES_MIGRATIONS_TABLE, sqlite_migration_to_postgres};
use crate::store::MigrationReport;

/// A PostgreSQL connection that can migrate a Brolga schema.
pub struct PostgresStore {
    client: Client,
    endpoint: String,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    /// Connect with a libpq URL or keyword/value string.
    ///
    /// # Errors
    ///
    /// [`StorageError::Open`] if the server cannot be reached.
    pub fn connect(connection_string: &str) -> Result<Self> {
        let client =
            Client::connect(connection_string, NoTls).map_err(|error| StorageError::Open {
                path: redact_endpoint(connection_string),
                reason: error.to_string(),
            })?;
        Ok(Self {
            client,
            endpoint: redact_endpoint(connection_string),
        })
    }

    /// Redacted endpoint for diagnostics (credentials stripped).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Highest applied migration id, or 0 on an empty database.
    ///
    /// # Errors
    ///
    /// Query failures against the migrations table.
    pub fn schema_version(&mut self) -> Result<u32> {
        let exists = self
            .client
            .query_opt(
                "SELECT 1 FROM information_schema.tables
                 WHERE table_schema = 'public' AND table_name = 'brolga_schema_migrations'",
                &[],
            )
            .map_err(|error| StorageError::Query {
                operation: "checking for migrations table",
                reason: error.to_string(),
            })?
            .is_some();
        if !exists {
            return Ok(0);
        }
        let row = self
            .client
            .query_one(
                "SELECT COALESCE(MAX(id), 0)::int FROM brolga_schema_migrations",
                &[],
            )
            .map_err(|error| StorageError::Query {
                operation: "reading schema version",
                reason: error.to_string(),
            })?;
        let version: i32 = row.get(0);
        u32::try_from(version).map_err(|_| StorageError::Corrupt {
            kind: "schema",
            id: "version".to_owned(),
            reason: "negative schema version".to_owned(),
        })
    }

    /// Apply pending migrations (same ids/checksums as SQLite).
    ///
    /// # Errors
    ///
    /// Migration apply failures, checksum mismatches, or schema-too-new.
    pub fn migrate(&mut self) -> Result<MigrationReport> {
        self.client
            .batch_execute(POSTGRES_MIGRATIONS_TABLE)
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

        for migration in MIGRATIONS {
            let recorded: Option<String> = self
                .client
                .query_opt(
                    "SELECT checksum FROM brolga_schema_migrations WHERE id = $1",
                    &[&i32::try_from(migration.id).unwrap_or(i32::MAX)],
                )
                .map_err(|error| StorageError::Query {
                    operation: "reading a migration checksum",
                    reason: error.to_string(),
                })?
                .map(|row| row.get(0));

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
            let mut transaction =
                self.client
                    .transaction()
                    .map_err(|error| StorageError::Transaction {
                        action: "started",
                        reason: error.to_string(),
                    })?;

            let sql = sqlite_migration_to_postgres(migration.sql);
            transaction
                .batch_execute(&sql)
                .map_err(|error| StorageError::Migration {
                    id: migration.id,
                    name: migration.name.to_owned(),
                    reason: error.to_string(),
                })?;

            let applied_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());

            transaction
                .execute(
                    "INSERT INTO brolga_schema_migrations (id, name, checksum, applied_at)
                     VALUES ($1, $2, $3, $4)",
                    &[
                        &i32::try_from(migration.id).unwrap_or(i32::MAX),
                        &migration.name,
                        &migration.checksum().to_string(),
                        &applied_at,
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
            to_version: latest_version(),
            applied,
        })
    }
}

fn redact_endpoint(connection_string: &str) -> String {
    let mut s = connection_string.to_owned();
    if let Some(at) = s.find('@')
        && let Some(scheme) = s.find("://")
    {
        let head = s.get(..=scheme + 2).unwrap_or("postgres://");
        let tail = s.get(at..).unwrap_or("@");
        s = format!("{head}***{tail}");
    }
    if let Some(idx) = s.find("password=") {
        let end = s
            .get(idx..)
            .and_then(|rest| rest.find([' ', '&']).map(|i| idx + i))
            .unwrap_or(s.len());
        s = format!(
            "{}password=***{}",
            s.get(..idx).unwrap_or(""),
            s.get(end..).unwrap_or("")
        );
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn redact_hides_userinfo() {
        let redacted = redact_endpoint("postgres://alice:s3cret@db.example:5432/brolga");
        assert!(!redacted.contains("s3cret"));
        assert!(redacted.contains("db.example"));
    }

    #[test]
    fn migrate_against_live_server_when_url_set() {
        let Ok(url) = std::env::var("BROLGA_POSTGRES_URL") else {
            return;
        };
        if url.is_empty() {
            return;
        }
        let mut store = PostgresStore::connect(&url).expect("connect");
        let report = store.migrate().expect("migrate");
        assert_eq!(report.to_version, latest_version());
        let again = store.migrate().expect("idempotent migrate");
        assert!(!again.changed());
    }
}
