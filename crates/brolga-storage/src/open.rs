//! Open a store from a path or a PostgreSQL connection string.

use std::path::Path;

use crate::error::Result;
use crate::sqlite::{DEFAULT_BUSY_TIMEOUT_MS, SqliteStore};
use crate::store::{IntelligenceStore, StoreRead};

#[cfg(feature = "postgres")]
use crate::postgres::PostgresStore;

#[cfg(not(feature = "postgres"))]
use crate::error::StorageError;

/// A store opened from operator configuration — SQLite file path or PostgreSQL URL.
///
/// Implements [`StoreRead`] and [`IntelligenceStore`] by dispatching to the underlying backend.
#[derive(Debug)]
pub enum OpenedStore {
    /// Local SQLite database.
    Sqlite(SqliteStore),
    /// PostgreSQL server (feature `postgres`).
    #[cfg(feature = "postgres")]
    Postgres(Box<PostgresStore>),
}

impl OpenedStore {
    /// Open and migrate from a filesystem path (SQLite) or a `postgres://` / `postgresql://` URL.
    ///
    /// # Errors
    ///
    /// Open or migration failures. A postgres URL without the `postgres` feature is a configuration
    /// error naming the feature.
    pub fn open(spec: impl AsRef<str>) -> Result<Self> {
        Self::open_with_timeout(spec.as_ref(), DEFAULT_BUSY_TIMEOUT_MS)
    }

    /// Open with a SQLite busy timeout (ignored for PostgreSQL).
    ///
    /// # Errors
    ///
    /// See [`OpenedStore::open`].
    pub fn open_with_timeout(spec: &str, busy_timeout_ms: u64) -> Result<Self> {
        let trimmed = spec.trim();
        if is_postgres_url(trimmed) {
            #[cfg(feature = "postgres")]
            {
                let mut store = PostgresStore::connect(trimmed)?;
                store.migrate()?;
                return Ok(Self::Postgres(Box::new(store)));
            }
            #[cfg(not(feature = "postgres"))]
            {
                return Err(StorageError::Open {
                    path: redact_for_log(trimmed),
                    reason: "this build has no PostgreSQL support; rebuild with \
                             `--features postgres` (brolga-storage / brolga-cli)"
                        .to_owned(),
                });
            }
        }

        let path = Path::new(trimmed);
        let mut store = SqliteStore::open(path, busy_timeout_ms)?;
        store.migrate()?;
        Ok(Self::Sqlite(store))
    }

    /// Backend label for diagnostics.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => "postgres",
        }
    }
}

/// Whether `spec` is a libpq-style PostgreSQL URL.
#[must_use]
pub fn is_postgres_url(spec: &str) -> bool {
    let lower = spec.trim().to_ascii_lowercase();
    lower.starts_with("postgres://") || lower.starts_with("postgresql://")
}

#[cfg(not(feature = "postgres"))]
fn redact_for_log(spec: &str) -> String {
    // Never put passwords in error paths that may be logged.
    if let Some(at) = spec.find('@')
        && let Some(scheme) = spec.find("://")
    {
        let head = spec.get(..=scheme + 2).unwrap_or("postgres://");
        let tail = spec.get(at..).unwrap_or("@");
        return format!("{head}***{tail}");
    }
    spec.to_owned()
}

macro_rules! dispatch {
    ($self:expr, $method:ident ( $($arg:expr),* $(,)? )) => {
        match $self {
            Self::Sqlite(store) => store.$method($($arg),*),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.$method($($arg),*),
        }
    };
}

impl StoreRead for OpenedStore {
    fn schema_version(&self) -> Result<u32> {
        dispatch!(self, schema_version())
    }

    fn connector_cursor(
        &self,
        connector: &str,
        feed: &str,
    ) -> Result<Option<crate::cursor::ConnectorCursor>> {
        dispatch!(self, connector_cursor(connector, feed))
    }

    fn connector_cursors(&self) -> Result<Vec<crate::cursor::ConnectorCursor>> {
        dispatch!(self, connector_cursors())
    }

    fn count(&self, kind: crate::store::RecordKind) -> Result<u64> {
        dispatch!(self, count(kind))
    }

    fn get_source_object(
        &self,
        id: brolga_model::id::Id<brolga_model::provenance::SourceObject>,
    ) -> Result<Option<brolga_model::provenance::SourceObject>> {
        dispatch!(self, get_source_object(id))
    }

    fn find_source_object_by_hash(
        &self,
        hash: &brolga_model::provenance::ContentHash,
    ) -> Result<Option<brolga_model::provenance::SourceObject>> {
        dispatch!(self, find_source_object_by_hash(hash))
    }

    fn get_entity(
        &self,
        id: brolga_model::id::Id<brolga_model::entity::Entity>,
    ) -> Result<Option<brolga_model::entity::Entity>> {
        dispatch!(self, get_entity(id))
    }

    fn get_relationship(
        &self,
        id: brolga_model::id::Id<brolga_model::relationship::Relationship>,
    ) -> Result<Option<brolga_model::relationship::Relationship>> {
        dispatch!(self, get_relationship(id))
    }

    fn get_claim(
        &self,
        id: brolga_model::id::Id<brolga_model::claim::Claim>,
    ) -> Result<Option<brolga_model::claim::Claim>> {
        dispatch!(self, get_claim(id))
    }

    fn get_sighting(
        &self,
        id: brolga_model::id::Id<brolga_model::sighting::Sighting>,
    ) -> Result<Option<brolga_model::sighting::Sighting>> {
        dispatch!(self, get_sighting(id))
    }

    fn list_entities(&self, page: crate::store::Page) -> Result<Vec<brolga_model::entity::Entity>> {
        dispatch!(self, list_entities(page))
    }

    fn relationships_touching(
        &self,
        node: &brolga_model::relationship::NodeRef,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::relationship::Relationship>> {
        dispatch!(self, relationships_touching(node, page))
    }

    fn search_entities(
        &self,
        query: &crate::store::EntityQuery,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::entity::Entity>> {
        dispatch!(self, search_entities(query, page))
    }

    fn edges_at(
        &self,
        query: &crate::store::EdgeQuery,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::relationship::Relationship>> {
        dispatch!(self, edges_at(query, page))
    }

    fn degree(&self, query: &crate::store::EdgeQuery) -> Result<u64> {
        dispatch!(self, degree(query))
    }

    fn claims_about(
        &self,
        subject: &brolga_model::relationship::NodeRef,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::claim::Claim>> {
        dispatch!(self, claims_about(subject, page))
    }

    fn sightings_of(
        &self,
        subject: &brolga_model::relationship::NodeRef,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::sighting::Sighting>> {
        dispatch!(self, sightings_of(subject, page))
    }

    fn get_source_blob(
        &self,
        content_hash: &brolga_model::provenance::ContentHash,
    ) -> Result<Option<crate::blob::RetrievedBlob>> {
        dispatch!(self, get_source_blob(content_hash))
    }

    fn source_blob_metadata(
        &self,
        content_hash: &brolga_model::provenance::ContentHash,
    ) -> Result<Option<crate::blob::BlobMetadata>> {
        dispatch!(self, source_blob_metadata(content_hash))
    }

    fn source_blob_audit(
        &self,
        content_hash: &brolga_model::provenance::ContentHash,
    ) -> Result<Vec<crate::blob::RetentionEvent>> {
        dispatch!(self, source_blob_audit(content_hash))
    }

    fn quarantined_for_source(
        &self,
        source_hash: &brolga_model::provenance::ContentHash,
    ) -> Result<Vec<crate::quarantine::QuarantineRecord>> {
        dispatch!(self, quarantined_for_source(source_hash))
    }

    fn quarantine_count(&self) -> Result<u64> {
        dispatch!(self, quarantine_count())
    }

    fn quarantine_occurrences(&self) -> Result<u64> {
        dispatch!(self, quarantine_occurrences())
    }

    fn list_source_objects(
        &self,
        page: crate::store::Page,
    ) -> Result<Vec<brolga_model::provenance::SourceObject>> {
        dispatch!(self, list_source_objects(page))
    }

    fn get_entity_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_entity_json(id))
    }

    fn get_relationship_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_relationship_json(id))
    }

    fn get_claim_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_claim_json(id))
    }

    fn get_sighting_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_sighting_json(id))
    }

    fn get_source_object_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_source_object_json(id))
    }

    fn get_checkpoint(&self, name: &str) -> Result<Option<serde_json::Value>> {
        dispatch!(self, get_checkpoint(name))
    }

    fn list_checkpoints(&self) -> Result<Vec<crate::checkpoint::CheckpointSummary>> {
        dispatch!(self, list_checkpoints())
    }

    fn graph_version(&self) -> Result<u64> {
        dispatch!(self, graph_version())
    }

    fn graph_decisions_for(
        &self,
        kind: &str,
        subject: &str,
    ) -> Result<Vec<crate::decision::GraphDecisionRow>> {
        dispatch!(self, graph_decisions_for(kind, subject))
    }

    fn graph_decision_count(&self, kind: &str, verdict: &str) -> Result<u64> {
        dispatch!(self, graph_decision_count(kind, verdict))
    }

    fn entity_exists(
        &self,
        id: brolga_model::id::Id<brolga_model::entity::Entity>,
    ) -> Result<bool> {
        dispatch!(self, entity_exists(id))
    }

    fn source_blob_count(&self) -> Result<u64> {
        dispatch!(self, source_blob_count())
    }

    fn source_blob_stored_bytes(&self) -> Result<u64> {
        dispatch!(self, source_blob_stored_bytes())
    }
}

impl IntelligenceStore for OpenedStore {
    fn migrate(&mut self) -> Result<crate::store::MigrationReport> {
        dispatch!(self, migrate())
    }

    fn transaction<R>(
        &mut self,
        work: impl FnOnce(&mut dyn crate::store::StoreWrite) -> Result<R>,
    ) -> Result<R> {
        match self {
            Self::Sqlite(store) => store.transaction(work),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.transaction(work),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_postgres_urls() {
        assert!(is_postgres_url("postgres://localhost/brolga"));
        assert!(is_postgres_url("postgresql://u:p@h/db"));
        assert!(is_postgres_url("POSTGRES://LOCALHOST/x"));
        assert!(!is_postgres_url("brolga.sqlite"));
        assert!(!is_postgres_url("/data/brolga.sqlite"));
    }

    #[test]
    fn open_sqlite_in_memory_style_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.sqlite");
        let store = OpenedStore::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.backend_name(), "sqlite");
        assert!(store.schema_version().unwrap() > 0);
    }
}
