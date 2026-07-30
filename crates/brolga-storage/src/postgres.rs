//! PostgreSQL backend implementing [`crate::IntelligenceStore`] (ADR 0011 / #55).
//!
//! Same migration identifiers and checksums as SQLite; SQL is dialect-adapted at apply time.
//! Every caller value is a bound parameter. Table names come only from closed enums.

use std::sync::Mutex;

use brolga_model::claim::Claim;
use brolga_model::entity::Entity;
use brolga_model::id::Id;
use brolga_model::provenance::{ContentHash, SourceObject};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::sighting::Sighting;
use postgres::types::ToSql;
use postgres::{Client, NoTls, Transaction};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::blob::{
    BlobCodec, BlobMetadata, BlobOutcome, BlobRequest, RetentionAction, RetentionClass,
    RetentionEvent, RetrievedBlob, decode_bytes, encode_bytes,
};
use crate::checkpoint::CheckpointSummary;
use crate::cursor::{ConnectorCursor, CursorStatus};
use crate::decision::GraphDecisionRow;
use crate::error::{Result, StorageError};
use crate::migration::{MIGRATIONS, latest_version};
use crate::postgres_sql::{POSTGRES_MIGRATIONS_TABLE, sqlite_migration_to_postgres};
use crate::quarantine::{QuarantineEntry, QuarantineRecord, QuarantineStage};
use crate::store::{
    Direction, EdgeQuery, EntityQuery, IntelligenceStore, MigrationReport, Page, RecordKind,
    StoreRead, StoreWrite, UpsertOutcome,
};

/// A PostgreSQL-backed intelligence store.
pub struct PostgresStore {
    client: Mutex<Client>,
    endpoint: String,
    max_blob_bytes: u64,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore")
            .field("endpoint", &self.endpoint)
            .field("max_blob_bytes", &self.max_blob_bytes)
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
            client: Mutex::new(client),
            endpoint: redact_endpoint(connection_string),
            max_blob_bytes: crate::blob::DEFAULT_MAX_BLOB_BYTES,
        })
    }

    /// Redacted endpoint for diagnostics.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Cap retained source blob size.
    #[must_use]
    pub const fn with_max_blob_bytes(mut self, max_blob_bytes: u64) -> Self {
        self.max_blob_bytes = max_blob_bytes;
        self
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Client>> {
        self.client.lock().map_err(|_| StorageError::Query {
            operation: "locking the postgres client",
            reason: "mutex poisoned".to_owned(),
        })
    }

    fn qerr(operation: &'static str, error: postgres::Error) -> StorageError {
        StorageError::Query {
            operation,
            reason: error.to_string(),
        }
    }

    fn fetch<T: DeserializeOwned>(
        &self,
        kind: &'static str,
        sql: &str,
        key: &str,
    ) -> Result<Option<T>> {
        let mut client = self.lock()?;
        let row = client
            .query_opt(sql, &[&key])
            .map_err(|e| Self::qerr("reading a record", e))?;
        match row {
            None => Ok(None),
            Some(row) => {
                let document: String = row.get(0);
                decode(kind, key, &document)
            }
        }
    }

    fn fetch_many<T: DeserializeOwned>(
        &self,
        kind: &'static str,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<T>> {
        let mut client = self.lock()?;
        let rows = client
            .query(sql, params)
            .map_err(|e| Self::qerr("running a listing", e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let document: String = row.get(0);
            out.push(decode(kind, "<listing>", &document)?);
        }
        Ok(out)
    }

    fn document_json(
        &self,
        sql: &str,
        id: &str,
        kind: &'static str,
    ) -> Result<Option<serde_json::Value>> {
        let mut client = self.lock()?;
        let row = client
            .query_opt(sql, &[&id])
            .map_err(|e| Self::qerr("reading a record", e))?;
        match row {
            None => Ok(None),
            Some(row) => {
                let document: String = row.get(0);
                serde_json::from_str(&document).map_err(|error| StorageError::Corrupt {
                    kind,
                    id: id.to_owned(),
                    reason: format!("stored document is not valid JSON: {error}"),
                })
            }
        }
    }

    fn scalar(&self, sql: &str) -> Result<u64> {
        let mut client = self.lock()?;
        let row = client
            .query_one(sql, &[])
            .map_err(|e| Self::qerr("counting", e))?;
        let value: i64 = row.get(0);
        Ok(u64::try_from(value).unwrap_or(0))
    }

    fn scalar_params(
        &self,
        operation: &'static str,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64> {
        let mut client = self.lock()?;
        let row = client
            .query_one(sql, params)
            .map_err(|e| Self::qerr(operation, e))?;
        let value: i64 = row.get(0);
        Ok(u64::try_from(value).unwrap_or(0))
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

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
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

fn utc_day(at: brolga_model::temporal::Timestamp) -> String {
    let rendered = at.to_rfc3339();
    rendered.get(..10).unwrap_or(&rendered).to_owned()
}

fn i64_limit(page: Page) -> i64 {
    i64::from(page.limit())
}

fn i64_offset(page: Page) -> i64 {
    i64::try_from(page.offset()).unwrap_or(i64::MAX)
}

fn dollar_in(start: usize, count: usize) -> String {
    let mut out = String::new();
    for i in 0..count {
        if i > 0 {
            out.push(',');
        }
        out.push('$');
        out.push_str(&(start + i).to_string());
    }
    out
}

/// Compile entity filter → WHERE fragment + owned bind values (kinds/statuses/days as String).
fn entity_predicate(query: &EntityQuery) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !query.kinds.is_empty() {
        let start = values.len() + 1;
        clauses.push(format!("kind IN ({})", dollar_in(start, query.kinds.len())));
        values.extend(query.kinds.iter().map(|k| k.as_str().to_owned()));
    }
    if !query.statuses.is_empty() {
        let start = values.len() + 1;
        clauses.push(format!(
            "status IN ({})",
            dollar_in(start, query.statuses.len())
        ));
        values.extend(query.statuses.iter().map(|s| s.as_str().to_owned()));
    }
    if let Some(from) = query.last_seen_from {
        values.push(utc_day(from));
        clauses.push(format!("last_seen >= ${}", values.len()));
    }
    if let Some(before) = query.last_seen_before {
        values.push(utc_day(before));
        clauses.push(format!("last_seen < ${}", values.len()));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    (where_sql, values)
}

fn edge_predicate(query: &EdgeQuery) -> (String, Vec<String>) {
    let node = query.node.to_string();
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    match query.direction {
        Direction::Outgoing => {
            values.push(node);
            clauses.push(format!("source_ref = ${}", values.len()));
        }
        Direction::Incoming => {
            values.push(node);
            clauses.push(format!("target_ref = ${}", values.len()));
        }
        Direction::Either => {
            values.push(node.clone());
            values.push(node);
            let a = values.len() - 1;
            let b = values.len();
            clauses.push(format!("(source_ref = ${a} OR target_ref = ${b})"));
        }
    }
    if !query.kinds.is_empty() {
        let start = values.len() + 1;
        clauses.push(format!("kind IN ({})", dollar_in(start, query.kinds.len())));
        values.extend(query.kinds.iter().map(|k| k.as_str().to_owned()));
    }
    if !query.statuses.is_empty() {
        let start = values.len() + 1;
        clauses.push(format!(
            "status IN ({})",
            dollar_in(start, query.statuses.len())
        ));
        values.extend(query.statuses.iter().map(|s| s.as_str().to_owned()));
    }
    (format!("WHERE {}", clauses.join(" AND ")), values)
}

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

fn cursor_from_row(row: &postgres::Row) -> ConnectorCursor {
    let status: String = row.get(6);
    let records_seen: i64 = row.get(7);
    ConnectorCursor {
        connector: row.get(0),
        feed: row.get(1),
        added_after: row.get(2),
        etag: row.get(3),
        next_token: row.get(4),
        last_run_at: row.get(5),
        last_status: CursorStatus::parse(&status).unwrap_or(CursorStatus::Failed),
        records_seen: u64::try_from(records_seen).unwrap_or(0),
    }
}

impl StoreRead for PostgresStore {
    fn schema_version(&self) -> Result<u32> {
        // One lock for both queries — std::sync::Mutex is not reentrant.
        let mut client = self.lock()?;
        let exists = client
            .query_opt(
                "SELECT 1 FROM information_schema.tables
                 WHERE table_schema = 'public' AND table_name = 'brolga_schema_migrations'",
                &[],
            )
            .map_err(|e| Self::qerr("checking for migrations table", e))?
            .is_some();
        if !exists {
            return Ok(0);
        }
        let row = client
            .query_one(
                "SELECT COALESCE(MAX(id), 0)::int FROM brolga_schema_migrations",
                &[],
            )
            .map_err(|e| Self::qerr("reading schema version", e))?;
        let v: i32 = row.get(0);
        u32::try_from(v).map_err(|_| StorageError::Corrupt {
            kind: "schema",
            id: "version".to_owned(),
            reason: "negative schema version".to_owned(),
        })
    }

    fn connector_cursor(&self, connector: &str, feed: &str) -> Result<Option<ConnectorCursor>> {
        let mut client = self.lock()?;
        let row = client
            .query_opt(
                "SELECT connector, feed, added_after, etag, next_token, last_run_at, last_status,
                        records_seen
                 FROM connector_cursors WHERE connector = $1 AND feed = $2",
                &[&connector, &feed],
            )
            .map_err(|e| Self::qerr("reading a connector cursor", e))?;
        Ok(row.map(|row| cursor_from_row(&row)))
    }

    fn connector_cursors(&self) -> Result<Vec<ConnectorCursor>> {
        let mut client = self.lock()?;
        let rows = client
            .query(
                "SELECT connector, feed, added_after, etag, next_token, last_run_at, last_status,
                        records_seen
                 FROM connector_cursors ORDER BY connector ASC, feed ASC",
                &[],
            )
            .map_err(|e| Self::qerr("reading connector cursors", e))?;
        Ok(rows.into_iter().map(|row| cursor_from_row(&row)).collect())
    }

    fn count(&self, kind: RecordKind) -> Result<u64> {
        let sql = format!("SELECT COUNT(*)::bigint FROM {}", kind.table());
        self.scalar(&sql)
    }

    fn get_source_object(&self, id: Id<SourceObject>) -> Result<Option<SourceObject>> {
        self.fetch(
            "source_object",
            "SELECT document FROM source_objects WHERE id = $1",
            &id.to_string(),
        )
    }

    fn find_source_object_by_hash(&self, hash: &ContentHash) -> Result<Option<SourceObject>> {
        self.fetch(
            "source_object",
            "SELECT document FROM source_objects WHERE content_hash = $1",
            &hash.to_string(),
        )
    }

    fn get_entity(&self, id: Id<Entity>) -> Result<Option<Entity>> {
        self.fetch(
            "entity",
            "SELECT document FROM entities WHERE id = $1",
            &id.to_string(),
        )
    }

    fn get_relationship(&self, id: Id<Relationship>) -> Result<Option<Relationship>> {
        self.fetch(
            "relationship",
            "SELECT document FROM relationships WHERE id = $1",
            &id.to_string(),
        )
    }

    fn get_claim(&self, id: Id<Claim>) -> Result<Option<Claim>> {
        self.fetch(
            "claim",
            "SELECT document FROM claims WHERE id = $1",
            &id.to_string(),
        )
    }

    fn get_sighting(&self, id: Id<Sighting>) -> Result<Option<Sighting>> {
        self.fetch(
            "sighting",
            "SELECT document FROM sightings WHERE id = $1",
            &id.to_string(),
        )
    }

    fn list_entities(&self, page: Page) -> Result<Vec<Entity>> {
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        self.fetch_many(
            "entity",
            "SELECT document FROM entities
             ORDER BY last_seen DESC NULLS LAST, id ASC
             LIMIT $1 OFFSET $2",
            &[&limit, &offset],
        )
    }

    fn relationships_touching(&self, node: &NodeRef, page: Page) -> Result<Vec<Relationship>> {
        let node = node.to_string();
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        self.fetch_many(
            "relationship",
            "SELECT document FROM relationships
             WHERE source_ref = $1 OR target_ref = $1
             ORDER BY id ASC LIMIT $2 OFFSET $3",
            &[&node, &limit, &offset],
        )
    }

    fn search_entities(&self, query: &EntityQuery, page: Page) -> Result<Vec<Entity>> {
        let (predicate, values) = entity_predicate(query);
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        let base = values.len();
        let sql = format!(
            "SELECT document FROM entities {predicate} ORDER BY id ASC LIMIT ${} OFFSET ${}",
            base + 1,
            base + 2
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(values.len() + 2);
        for value in &values {
            params.push(value);
        }
        params.push(&limit);
        params.push(&offset);
        self.fetch_many("entity", &sql, &params)
    }

    fn edges_at(&self, query: &EdgeQuery, page: Page) -> Result<Vec<Relationship>> {
        let (predicate, values) = edge_predicate(query);
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        let base = values.len();
        let sql = format!(
            "SELECT document FROM relationships {predicate} ORDER BY id ASC LIMIT ${} OFFSET ${}",
            base + 1,
            base + 2
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(values.len() + 2);
        for value in &values {
            params.push(value);
        }
        params.push(&limit);
        params.push(&offset);
        self.fetch_many("relationship", &sql, &params)
    }

    fn degree(&self, query: &EdgeQuery) -> Result<u64> {
        let (predicate, values) = edge_predicate(query);
        let sql = format!("SELECT COUNT(*)::bigint FROM relationships {predicate}");
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(values.len());
        for value in &values {
            params.push(value);
        }
        self.scalar_params("counting the edges at a node", &sql, &params)
    }

    fn claims_about(&self, subject: &NodeRef, page: Page) -> Result<Vec<Claim>> {
        let subject = subject.to_string();
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        self.fetch_many(
            "claim",
            "SELECT document FROM claims WHERE subject_ref = $1
             ORDER BY id ASC LIMIT $2 OFFSET $3",
            &[&subject, &limit, &offset],
        )
    }

    fn sightings_of(&self, subject: &NodeRef, page: Page) -> Result<Vec<Sighting>> {
        let subject = subject.to_string();
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        self.fetch_many(
            "sighting",
            "SELECT document FROM sightings WHERE subject_ref = $1
             ORDER BY last_seen DESC, id ASC LIMIT $2 OFFSET $3",
            &[&subject, &limit, &offset],
        )
    }

    fn get_source_blob(&self, content_hash: &ContentHash) -> Result<Option<RetrievedBlob>> {
        let address = content_hash.to_string();
        let mut client = self.lock()?;
        let row = client
            .query_opt(
                "SELECT codec, original_length, stored_length, retention, stored_at, bytes
                 FROM source_blobs WHERE content_hash = $1",
                &[&address],
            )
            .map_err(|e| Self::qerr("reading a source blob", e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let codec: String = row.get(0);
        let original_length: i64 = row.get(1);
        let stored_length: i64 = row.get(2);
        let retention: String = row.get(3);
        let stored_at: String = row.get(4);
        let stored: Vec<u8> = row.get(5);
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
        let mut client = self.lock()?;
        let row = client
            .query_opt(
                "SELECT codec, original_length, stored_length, retention, stored_at
                 FROM source_blobs WHERE content_hash = $1",
                &[&address],
            )
            .map_err(|e| Self::qerr("reading source blob metadata", e))?;
        row.map(|row| {
            build_metadata(
                *content_hash,
                &row.get::<_, String>(0),
                row.get(1),
                row.get(2),
                &row.get::<_, String>(3),
                row.get(4),
            )
        })
        .transpose()
    }

    fn source_blob_audit(&self, content_hash: &ContentHash) -> Result<Vec<RetentionEvent>> {
        let address = content_hash.to_string();
        let mut client = self.lock()?;
        let rows = client
            .query(
                "SELECT action, reason, at FROM source_blob_audit
                 WHERE content_hash = $1 ORDER BY id ASC",
                &[&address],
            )
            .map_err(|e| Self::qerr("reading a retention audit", e))?;
        let mut events = Vec::new();
        for row in rows {
            let action: String = row.get(0);
            let reason: String = row.get(1);
            let at: String = row.get(2);
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

    fn quarantined_for_source(&self, source_hash: &ContentHash) -> Result<Vec<QuarantineRecord>> {
        let address = source_hash.to_string();
        let mut client = self.lock()?;
        let rows = client
            .query(
                "SELECT id, parser, parser_version, stage, reason_kind, reason, record_index,
                        byte_offset, fragment, first_seen_at, last_seen_at, occurrences
                 FROM quarantine WHERE source_hash = $1 ORDER BY last_seen_at DESC, id ASC",
                &[&address],
            )
            .map_err(|e| Self::qerr("reading quarantine", e))?;
        let mut records = Vec::new();
        for row in rows {
            let id: String = row.get(0);
            let parser: String = row.get(1);
            let parser_version: i64 = row.get(2);
            let stage_s: String = row.get(3);
            let reason_kind: String = row.get(4);
            let reason: String = row.get(5);
            let record_index: Option<i64> = row.get(6);
            let byte_offset: Option<i64> = row.get(7);
            let fragment: Option<String> = row.get(8);
            let first_seen_at: String = row.get(9);
            let last_seen_at: String = row.get(10);
            let occurrences: i64 = row.get(11);
            let stage =
                QuarantineStage::from_str_opt(&stage_s).ok_or_else(|| StorageError::Corrupt {
                    kind: "quarantine",
                    id: id.clone(),
                    reason: format!("unknown stage {stage_s:?}"),
                })?;
            records.push(QuarantineRecord {
                id,
                source_hash: *source_hash,
                parser,
                parser_version: u32::try_from(parser_version).unwrap_or(0),
                stage,
                reason_kind,
                reason,
                record_index: record_index.and_then(|v| u64::try_from(v).ok()),
                byte_offset: byte_offset.and_then(|v| u64::try_from(v).ok()),
                fragment,
                first_seen_at,
                last_seen_at,
                occurrences: u64::try_from(occurrences).unwrap_or(0),
            });
        }
        Ok(records)
    }

    fn quarantine_count(&self) -> Result<u64> {
        self.scalar("SELECT COUNT(*)::bigint FROM quarantine")
    }

    fn quarantine_occurrences(&self) -> Result<u64> {
        self.scalar("SELECT COALESCE(SUM(occurrences), 0)::bigint FROM quarantine")
    }

    fn list_source_objects(&self, page: Page) -> Result<Vec<SourceObject>> {
        let limit = i64_limit(page);
        let offset = i64_offset(page);
        self.fetch_many(
            "source_object",
            "SELECT document FROM source_objects ORDER BY retrieved_at DESC, id ASC
             LIMIT $1 OFFSET $2",
            &[&limit, &offset],
        )
    }

    fn get_entity_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json("SELECT document FROM entities WHERE id = $1", id, "entity")
    }

    fn get_relationship_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(
            "SELECT document FROM relationships WHERE id = $1",
            id,
            "relationship",
        )
    }

    fn get_claim_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json("SELECT document FROM claims WHERE id = $1", id, "claim")
    }

    fn get_sighting_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(
            "SELECT document FROM sightings WHERE id = $1",
            id,
            "sighting",
        )
    }

    fn get_source_object_json(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(
            "SELECT document FROM source_objects WHERE id = $1",
            id,
            "source_object",
        )
    }

    fn get_checkpoint(&self, name: &str) -> Result<Option<serde_json::Value>> {
        self.document_json(
            "SELECT document FROM graph_checkpoints WHERE name = $1",
            name,
            "graph_checkpoint",
        )
    }

    fn list_checkpoints(&self) -> Result<Vec<CheckpointSummary>> {
        let mut client = self.lock()?;
        let rows = client
            .query(
                "SELECT name, shape, graph_version, algorithm, algorithm_version, captured_at,
                        truncated
                 FROM graph_checkpoints ORDER BY captured_at DESC, name ASC",
                &[],
            )
            .map_err(|e| Self::qerr("listing checkpoints", e))?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let graph_version: i64 = row.get(2);
                let algorithm_version: i64 = row.get(4);
                let truncated: i64 = row.get(6);
                CheckpointSummary {
                    name: row.get(0),
                    shape: row.get(1),
                    graph_version: u64::try_from(graph_version).unwrap_or(0),
                    algorithm: row.get(3),
                    algorithm_version: u32::try_from(algorithm_version).unwrap_or(0),
                    captured_at: row.get(5),
                    truncated: truncated != 0,
                }
            })
            .collect())
    }

    fn graph_version(&self) -> Result<u64> {
        self.scalar("SELECT version::bigint FROM graph_meta WHERE id = 1")
    }

    fn graph_decisions_for(&self, kind: &str, subject: &str) -> Result<Vec<GraphDecisionRow>> {
        let mut client = self.lock()?;
        let rows = client
            .query(
                "SELECT observation, compared_with, verdict, algorithm, algorithm_version, reason,
                        decided_at, actor, policy_context
                 FROM graph_decisions WHERE decision_kind = $1 AND subject = $2
                 ORDER BY decided_at ASC, id ASC",
                &[&kind, &subject],
            )
            .map_err(|e| Self::qerr("reading graph decisions", e))?;
        let mut decisions = Vec::new();
        for row in rows {
            let algorithm_version: i64 = row.get(4);
            decisions.push(GraphDecisionRow {
                kind: kind.to_owned(),
                subject: subject.to_owned(),
                observation: row.get(0),
                compared_with: row.get(1),
                verdict: row.get(2),
                algorithm: row.get(3),
                algorithm_version: u32::try_from(algorithm_version).unwrap_or(0),
                reason: row.get(5),
                decided_at: row.get(6),
                actor: row.get(7),
                policy_context: row.get(8),
            });
        }
        Ok(decisions)
    }

    fn graph_decision_count(&self, kind: &str, verdict: &str) -> Result<u64> {
        self.scalar_params(
            "counting graph decisions",
            "SELECT COUNT(*)::bigint FROM graph_decisions
             WHERE decision_kind = $1 AND verdict = $2",
            &[&kind, &verdict],
        )
    }

    fn entity_exists(&self, id: Id<Entity>) -> Result<bool> {
        let id = id.to_string();
        let mut client = self.lock()?;
        let row = client
            .query_opt("SELECT 1 FROM entities WHERE id = $1", &[&id])
            .map_err(|e| Self::qerr("checking whether an entity exists", e))?;
        Ok(row.is_some())
    }

    fn source_blob_count(&self) -> Result<u64> {
        self.scalar("SELECT COUNT(*)::bigint FROM source_blobs")
    }

    fn source_blob_stored_bytes(&self) -> Result<u64> {
        self.scalar("SELECT COALESCE(SUM(stored_length), 0)::bigint FROM source_blobs")
    }
}

// -------------------------------------------------------------------------------------------------
// Writer (transaction scope)
// -------------------------------------------------------------------------------------------------

struct PostgresWriter<'a> {
    tx: Transaction<'a>,
    max_blob_bytes: u64,
}

impl PostgresWriter<'_> {
    fn qerr(operation: &'static str, error: postgres::Error) -> StorageError {
        StorageError::Query {
            operation,
            reason: error.to_string(),
        }
    }

    fn existing(&mut self, sql: &str, id: &str) -> Result<Option<String>> {
        let row = self
            .tx
            .query_opt(sql, &[&id])
            .map_err(|e| Self::qerr("reading a record before writing", e))?;
        Ok(row.map(|r| r.get(0)))
    }

    fn audit(&mut self, address: &str, action: RetentionAction, reason: &str) -> Result<()> {
        let at = now_rfc3339();
        self.tx
            .execute(
                "INSERT INTO source_blob_audit (content_hash, action, reason, at)
                 VALUES ($1, $2, $3, $4)",
                &[&address, &action.as_str(), &reason, &at],
            )
            .map_err(|e| Self::qerr("recording a retention decision", e))?;
        Ok(())
    }

    fn touch_graph(&mut self, outcome: UpsertOutcome) -> Result<UpsertOutcome> {
        if outcome.changed() {
            let at = now_rfc3339();
            self.tx
                .execute(
                    "UPDATE graph_meta SET version = version + 1, last_changed_at = $1 WHERE id = 1",
                    &[&at],
                )
                .map_err(|e| Self::qerr("incrementing the graph version", e))?;
        }
        Ok(outcome)
    }

    fn require_node(
        &mut self,
        kind: &'static str,
        id: &str,
        endpoint: &'static str,
        node: &NodeRef,
    ) -> Result<()> {
        let NodeRef::Entity(entity) = node else {
            return Ok(());
        };
        let key = entity.to_string();
        let found = self
            .tx
            .query_opt("SELECT 1 FROM entities WHERE id = $1", &[&key])
            .map_err(|e| Self::qerr("checking an edge endpoint", e))?;
        if found.is_none() {
            return Err(StorageError::DanglingEdge {
                kind,
                id: id.to_owned(),
                endpoint,
                missing: key,
            });
        }
        Ok(())
    }
}

impl StoreWrite for PostgresWriter<'_> {
    fn upsert_source_object(&mut self, source: &SourceObject) -> Result<UpsertOutcome> {
        let id = source.id.to_string();
        let document = encode("source_object", &id, source)?;
        if let Some(existing) =
            self.existing("SELECT document FROM source_objects WHERE id = $1", &id)?
            && existing == document
        {
            return Ok(UpsertOutcome::Unchanged);
        }
        let existed = self
            .existing("SELECT document FROM source_objects WHERE id = $1", &id)?
            .is_some();
        let content_hash = source.content_hash.to_string();
        let media_type = source.media_type.as_str();
        let byte_length = i64::try_from(source.byte_length).unwrap_or(i64::MAX);
        let retrieved_at = source.retrieved_at.to_rfc3339();
        let origin_kind = source.origin.kind_str();
        self.tx
            .execute(
                "INSERT INTO source_objects
                    (id, content_hash, media_type, byte_length, retrieved_at, origin_kind, document)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT(id) DO UPDATE SET
                    content_hash = EXCLUDED.content_hash,
                    media_type   = EXCLUDED.media_type,
                    byte_length  = EXCLUDED.byte_length,
                    retrieved_at = EXCLUDED.retrieved_at,
                    origin_kind  = EXCLUDED.origin_kind,
                    document     = EXCLUDED.document",
                &[
                    &id,
                    &content_hash,
                    &media_type,
                    &byte_length,
                    &retrieved_at,
                    &origin_kind,
                    &document,
                ],
            )
            .map_err(|e| Self::qerr("writing a source object", e))?;
        Ok(if existed {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn upsert_entity(&mut self, entity: &Entity) -> Result<UpsertOutcome> {
        let id = entity.id.to_string();
        let document = encode("entity", &id, entity)?;
        let existed = self.existing("SELECT document FROM entities WHERE id = $1", &id)?;
        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }
        let kind = entity.kind.as_str();
        let status = entity.status.as_str();
        let first_seen = entity.temporal.first_seen.map(|at| at.to_rfc3339());
        let last_seen = entity.temporal.last_seen.map(|at| at.to_rfc3339());
        self.tx
            .execute(
                "INSERT INTO entities (id, kind, status, first_seen, last_seen, document)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT(id) DO UPDATE SET
                    kind       = EXCLUDED.kind,
                    status     = EXCLUDED.status,
                    first_seen = EXCLUDED.first_seen,
                    last_seen  = EXCLUDED.last_seen,
                    document   = EXCLUDED.document",
                &[&id, &kind, &status, &first_seen, &last_seen, &document],
            )
            .map_err(|e| Self::qerr("writing an entity", e))?;
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
        let existed = self.existing("SELECT document FROM relationships WHERE id = $1", &id)?;
        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }
        let kind = relationship.kind.as_str();
        let source_ref = relationship.source.to_string();
        let target_ref = relationship.target.to_string();
        let status = relationship.status.as_str();
        self.tx
            .execute(
                "INSERT INTO relationships (id, kind, source_ref, target_ref, status, document)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT(id) DO UPDATE SET
                    kind       = EXCLUDED.kind,
                    source_ref = EXCLUDED.source_ref,
                    target_ref = EXCLUDED.target_ref,
                    status     = EXCLUDED.status,
                    document   = EXCLUDED.document",
                &[&id, &kind, &source_ref, &target_ref, &status, &document],
            )
            .map_err(|e| Self::qerr("writing a relationship", e))?;
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
        let existed = self.existing("SELECT document FROM claims WHERE id = $1", &id)?;
        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }
        let subject_ref = claim.subject.to_string();
        let assertion_kind = claim.assertion.kind_str();
        let status = claim.status.as_str();
        self.tx
            .execute(
                "INSERT INTO claims (id, subject_ref, assertion_kind, status, document)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(id) DO UPDATE SET
                    subject_ref    = EXCLUDED.subject_ref,
                    assertion_kind = EXCLUDED.assertion_kind,
                    status         = EXCLUDED.status,
                    document       = EXCLUDED.document",
                &[&id, &subject_ref, &assertion_kind, &status, &document],
            )
            .map_err(|e| Self::qerr("writing a claim", e))?;
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
        let existed = self.existing("SELECT document FROM sightings WHERE id = $1", &id)?;
        if existed.as_deref() == Some(document.as_str()) {
            return Ok(UpsertOutcome::Unchanged);
        }
        let subject_ref = sighting.subject.to_string();
        let observer = sighting.observer.map(|o| o.to_string());
        let first_seen = sighting.first_seen.to_rfc3339();
        let last_seen = sighting.last_seen.to_rfc3339();
        let observations = i64::try_from(sighting.count.get()).unwrap_or(i64::MAX);
        let status = sighting.status.as_str();
        self.tx
            .execute(
                "INSERT INTO sightings
                    (id, subject_ref, observer, first_seen, last_seen, observations, status, document)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT(id) DO UPDATE SET
                    subject_ref  = EXCLUDED.subject_ref,
                    observer     = EXCLUDED.observer,
                    first_seen   = EXCLUDED.first_seen,
                    last_seen    = EXCLUDED.last_seen,
                    observations = EXCLUDED.observations,
                    status       = EXCLUDED.status,
                    document     = EXCLUDED.document",
                &[
                    &id,
                    &subject_ref,
                    &observer,
                    &first_seen,
                    &last_seen,
                    &observations,
                    &status,
                    &document,
                ],
            )
            .map_err(|e| Self::qerr("writing a sighting", e))?;
        self.touch_graph(if existed.is_some() {
            UpsertOutcome::Updated
        } else {
            UpsertOutcome::Inserted
        })
    }

    fn put_connector_cursor(&mut self, cursor: &ConnectorCursor) -> Result<()> {
        let status = cursor.last_status.as_str();
        let records_seen = i64::try_from(cursor.records_seen).unwrap_or(i64::MAX);
        self.tx
            .execute(
                "INSERT INTO connector_cursors
                     (connector, feed, added_after, etag, next_token, last_run_at, last_status,
                      records_seen)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (connector, feed) DO UPDATE SET
                     added_after  = EXCLUDED.added_after,
                     etag         = EXCLUDED.etag,
                     next_token   = EXCLUDED.next_token,
                     last_run_at  = EXCLUDED.last_run_at,
                     last_status  = EXCLUDED.last_status,
                     records_seen = EXCLUDED.records_seen",
                &[
                    &cursor.connector,
                    &cursor.feed,
                    &cursor.added_after,
                    &cursor.etag,
                    &cursor.next_token,
                    &cursor.last_run_at,
                    &status,
                    &records_seen,
                ],
            )
            .map_err(|e| Self::qerr("writing a connector cursor", e))?;
        Ok(())
    }

    fn put_source_blob(&mut self, request: &BlobRequest<'_>) -> Result<BlobOutcome> {
        let address = request.content_hash().to_string();
        let length = request.length();
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
        let present = self
            .tx
            .query_opt(
                "SELECT 1 FROM source_blobs WHERE content_hash = $1",
                &[&address],
            )
            .map_err(|e| Self::qerr("checking for a retained source blob", e))?;
        if present.is_some() {
            self.audit(&address, RetentionAction::Deduplicated, request.reason())?;
            return Ok(BlobOutcome::Deduplicated);
        }
        let (codec, encoded) = encode_bytes(request.bytes());
        let stored_length = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        let original_length = i64::try_from(length).unwrap_or(i64::MAX);
        let stored_length_i = i64::try_from(stored_length).unwrap_or(i64::MAX);
        let retention = request.retention().as_str();
        let stored_at = now_rfc3339();
        let codec_s = codec.as_str();
        self.tx
            .execute(
                "INSERT INTO source_blobs
                    (content_hash, codec, original_length, stored_length, bytes, retention, stored_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &address,
                    &codec_s,
                    &original_length,
                    &stored_length_i,
                    &encoded,
                    &retention,
                    &stored_at,
                ],
            )
            .map_err(|e| Self::qerr("retaining a source blob", e))?;
        self.audit(&address, RetentionAction::Stored, request.reason())?;
        Ok(BlobOutcome::Stored {
            stored_length,
            codec,
        })
    }

    fn release_source_blob(&mut self, content_hash: &ContentHash, reason: &str) -> Result<bool> {
        let address = content_hash.to_string();
        let row = self
            .tx
            .query_opt(
                "SELECT retention FROM source_blobs WHERE content_hash = $1",
                &[&address],
            )
            .map_err(|e| Self::qerr("reading a blob's retention class", e))?;
        let Some(row) = row else {
            self.audit(
                &address,
                RetentionAction::Released,
                &format!("{reason} (nothing was retained at this address)"),
            )?;
            return Ok(false);
        };
        let retention: String = row.get(0);
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
        self.tx
            .execute(
                "DELETE FROM source_blobs WHERE content_hash = $1",
                &[&address],
            )
            .map_err(|e| Self::qerr("releasing a source blob", e))?;
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
        let retention_s = retention.as_str();
        let changed = self
            .tx
            .execute(
                "UPDATE source_blobs SET retention = $2 WHERE content_hash = $1",
                &[&address, &retention_s],
            )
            .map_err(|e| Self::qerr("reclassifying a source blob", e))?;
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
        let source_hash = entry.source_hash.to_string();
        let stage = entry.stage.as_str();
        let parser_version = i64::from(entry.parser_version);
        let record_index = entry.record_index.and_then(|v| i64::try_from(v).ok());
        let byte_offset = entry.byte_offset.and_then(|v| i64::try_from(v).ok());
        self.tx
            .execute(
                "INSERT INTO quarantine
                    (id, source_hash, parser, parser_version, stage, reason_kind, reason,
                     record_index, byte_offset, fragment, first_seen_at, last_seen_at, occurrences)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, 1)
                 ON CONFLICT(id) DO UPDATE SET
                    reason       = EXCLUDED.reason,
                    fragment     = EXCLUDED.fragment,
                    last_seen_at = EXCLUDED.last_seen_at,
                    occurrences  = quarantine.occurrences + 1",
                &[
                    &id,
                    &source_hash,
                    &entry.parser,
                    &parser_version,
                    &stage,
                    &entry.reason_kind,
                    &entry.reason,
                    &record_index,
                    &byte_offset,
                    &entry.fragment,
                    &now,
                ],
            )
            .map_err(|e| Self::qerr("quarantining a record", e))?;
        let row = self
            .tx
            .query_one("SELECT occurrences FROM quarantine WHERE id = $1", &[&id])
            .map_err(|e| Self::qerr("reading a quarantine occurrence count", e))?;
        let occurrences: i64 = row.get(0);
        Ok(occurrences == 1)
    }

    fn put_checkpoint(
        &mut self,
        summary: &CheckpointSummary,
        document: &serde_json::Value,
    ) -> Result<bool> {
        let encoded = serde_json::to_string(document).map_err(|error| StorageError::Corrupt {
            kind: "graph_checkpoint",
            id: summary.name.clone(),
            reason: format!("checkpoint could not be encoded: {error}"),
        })?;
        let existed = self
            .tx
            .query_opt(
                "SELECT 1 FROM graph_checkpoints WHERE name = $1",
                &[&summary.name],
            )
            .map_err(|e| Self::qerr("checking for a checkpoint", e))?
            .is_some();
        let graph_version = i64::try_from(summary.graph_version).unwrap_or(i64::MAX);
        let algorithm_version = i64::from(summary.algorithm_version);
        let truncated = i64::from(summary.truncated);
        self.tx
            .execute(
                "INSERT INTO graph_checkpoints
                    (name, shape, graph_version, algorithm, algorithm_version, captured_at,
                     truncated, document)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT(name) DO UPDATE SET
                    shape             = EXCLUDED.shape,
                    graph_version     = EXCLUDED.graph_version,
                    algorithm         = EXCLUDED.algorithm,
                    algorithm_version = EXCLUDED.algorithm_version,
                    captured_at       = EXCLUDED.captured_at,
                    truncated         = EXCLUDED.truncated,
                    document          = EXCLUDED.document",
                &[
                    &summary.name,
                    &summary.shape,
                    &graph_version,
                    &summary.algorithm,
                    &algorithm_version,
                    &summary.captured_at,
                    &truncated,
                    &encoded,
                ],
            )
            .map_err(|e| Self::qerr("storing a checkpoint", e))?;
        Ok(!existed)
    }

    fn delete_checkpoint(&mut self, name: &str) -> Result<bool> {
        let removed = self
            .tx
            .execute("DELETE FROM graph_checkpoints WHERE name = $1", &[&name])
            .map_err(|e| Self::qerr("deleting a checkpoint", e))?;
        Ok(removed > 0)
    }

    fn record_graph_decision(&mut self, decision: &GraphDecisionRow) -> Result<bool> {
        let id = decision.derive_id();
        let existed = self
            .tx
            .query_opt("SELECT 1 FROM graph_decisions WHERE id = $1", &[&id])
            .map_err(|e| Self::qerr("checking for a graph decision", e))?
            .is_some();
        let algorithm_version = i64::from(decision.algorithm_version);
        let decided_at = now_rfc3339();
        self.tx
            .execute(
                "INSERT INTO graph_decisions
                    (id, decision_kind, subject, observation, compared_with, verdict, algorithm,
                     algorithm_version, reason, decided_at, actor, policy_context)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 ON CONFLICT(id) DO UPDATE SET
                    verdict           = EXCLUDED.verdict,
                    algorithm         = EXCLUDED.algorithm,
                    algorithm_version = EXCLUDED.algorithm_version,
                    reason            = EXCLUDED.reason,
                    decided_at        = EXCLUDED.decided_at",
                &[
                    &id,
                    &decision.kind,
                    &decision.subject,
                    &decision.observation,
                    &decision.compared_with,
                    &decision.verdict,
                    &decision.algorithm,
                    &algorithm_version,
                    &decision.reason,
                    &decided_at,
                    &decision.actor,
                    &decision.policy_context,
                ],
            )
            .map_err(|e| Self::qerr("recording a graph decision", e))?;
        Ok(!existed)
    }
}

impl IntelligenceStore for PostgresStore {
    fn migrate(&mut self) -> Result<MigrationReport> {
        {
            let mut client = self.lock()?;
            client
                .batch_execute(POSTGRES_MIGRATIONS_TABLE)
                .map_err(|error| StorageError::Migration {
                    id: 0,
                    name: "migrations_table".to_owned(),
                    reason: error.to_string(),
                })?;
        }

        let from_version = self.schema_version()?;
        if from_version > latest_version() {
            return Err(StorageError::SchemaTooNew {
                expected: latest_version(),
                found: from_version,
            });
        }

        for migration in MIGRATIONS {
            let id = i32::try_from(migration.id).unwrap_or(i32::MAX);
            let recorded: Option<String> = {
                let mut client = self.lock()?;
                client
                    .query_opt(
                        "SELECT checksum FROM brolga_schema_migrations WHERE id = $1",
                        &[&id],
                    )
                    .map_err(|e| Self::qerr("reading a migration checksum", e))?
                    .map(|row| row.get(0))
            };
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
            let mut client = self.lock()?;
            let mut transaction =
                client
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
            let applied_at = now_rfc3339();
            let id = i32::try_from(migration.id).unwrap_or(i32::MAX);
            let checksum = migration.checksum().to_string();
            let name = migration.name;
            transaction
                .execute(
                    "INSERT INTO brolga_schema_migrations (id, name, checksum, applied_at)
                     VALUES ($1, $2, $3, $4)",
                    &[&id, &name, &checksum, &applied_at],
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
        let mut client = self.lock()?;
        let tx = client
            .transaction()
            .map_err(|error| StorageError::Transaction {
                action: "started",
                reason: error.to_string(),
            })?;
        let mut writer = PostgresWriter { tx, max_blob_bytes };
        match work(&mut writer) {
            Ok(value) => {
                writer
                    .tx
                    .commit()
                    .map_err(|error| StorageError::Transaction {
                        action: "committed",
                        reason: error.to_string(),
                    })?;
                Ok(value)
            }
            Err(error) => {
                // Drop rolls back.
                drop(writer.tx);
                Err(error)
            }
        }
    }
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
    fn entity_predicate_uses_dollar_placeholders() {
        let q = EntityQuery::unfiltered().with_kind(brolga_model::entity::EntityKind::ThreatActor);
        let (sql, values) = entity_predicate(&q);
        assert!(sql.contains("$1"));
        assert_eq!(values.len(), 1);
    }

    #[test]
    fn migrate_and_entity_round_trip_when_url_set() {
        let Ok(url) = std::env::var("BROLGA_POSTGRES_URL") else {
            return;
        };
        if url.is_empty() {
            return;
        }
        use brolga_model::entity::{Entity, EntityKind};
        use brolga_model::provenance::{RecordOrigin, SyntheticOrigin, SyntheticReason};
        use brolga_model::text::{ShortText, UntrustedText};

        // Unique database name via search_path / table wipe: drop public schema objects between runs
        // by migrating a fresh schema if possible. Operators should point URL at empty DB.
        let mut store = PostgresStore::connect(&url).expect("connect");
        let report = store.migrate().expect("migrate");
        assert_eq!(report.to_version, latest_version());
        let again = store.migrate().expect("idempotent");
        assert!(!again.changed());

        let origin = RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::OperatorEntered,
            ShortText::new("pg-test").unwrap(),
        ));
        let actor = Entity::new(
            Entity::derive_id(
                EntityKind::ThreatActor,
                &ShortText::new("pg-test").unwrap(),
                &ShortText::new("G-PG-1").unwrap(),
            ),
            EntityKind::ThreatActor,
            UntrustedText::new("Postgres Test Actor").unwrap(),
            origin,
        );
        let id = actor.id;
        let outcome = store
            .transaction(|w| w.upsert_entity(&actor))
            .expect("upsert");
        assert!(outcome.changed());
        let loaded = store.get_entity(id).expect("get").expect("present");
        assert_eq!(loaded.id, id);
        let again = store
            .transaction(|w| w.upsert_entity(&actor))
            .expect("upsert again");
        assert_eq!(again, UpsertOutcome::Unchanged);
    }
}
