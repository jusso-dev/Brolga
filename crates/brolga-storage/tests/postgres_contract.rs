//! Dual-backend contract: PostgreSQL implements the same IntelligenceStore semantics as SQLite.
//!
//! Runs only when `BROLGA_POSTGRES_URL` is set (lab compose or operator-provided empty database).

#![cfg(feature = "postgres")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_model::entity::{Entity, EntityKind};
use brolga_model::provenance::{
    ContentHash, MediaType, RecordOrigin, SourceObject, SourceOrigin, SyntheticOrigin,
    SyntheticReason,
};
use brolga_model::temporal::Timestamp;
use brolga_model::text::{ShortText, UntrustedText};
use brolga_storage::store::{IntelligenceStore, Page, RecordKind, StoreRead, UpsertOutcome};
use brolga_storage::{EntityQuery, PostgresStore, latest_version};

fn url() -> Option<String> {
    let url = std::env::var("BROLGA_POSTGRES_URL").ok()?;
    if url.is_empty() { None } else { Some(url) }
}

fn short(value: &str) -> ShortText {
    ShortText::new(value).unwrap()
}

fn synthetic() -> RecordOrigin {
    RecordOrigin::synthetic(SyntheticOrigin::new(
        SyntheticReason::OperatorEntered,
        short("pg-contract"),
    ))
}

fn entity(external: &str) -> Entity {
    Entity::new(
        Entity::derive_id(
            EntityKind::ThreatActor,
            &short("pg-contract"),
            &short(external),
        ),
        EntityKind::ThreatActor,
        UntrustedText::new(external).unwrap(),
        synthetic(),
    )
}

fn source_object(bytes: &[u8]) -> SourceObject {
    SourceObject::new(
        ContentHash::of(bytes),
        MediaType::new("application/json").unwrap(),
        u64::try_from(bytes.len()).unwrap(),
        Timestamp::parse_rfc3339("2024-01-01T00:00:00Z").unwrap(),
        SourceOrigin::NetworkFeed {
            publisher: short("Example CERT"),
            location: None,
        },
    )
}

#[test]
fn migrate_is_idempotent_and_reaches_latest() {
    let Some(url) = url() else {
        return;
    };
    let mut store = PostgresStore::connect(&url).unwrap();
    let first = store.migrate().unwrap();
    assert_eq!(first.to_version, latest_version());
    let second = store.migrate().unwrap();
    assert!(!second.changed());
    assert_eq!(store.schema_version().unwrap(), latest_version());
}

#[test]
fn entity_upsert_get_and_unchanged() {
    let Some(url) = url() else {
        return;
    };
    let mut store = PostgresStore::connect(&url).unwrap();
    store.migrate().unwrap();

    let actor = entity("G-CONTRACT-1");
    let id = actor.id;
    let inserted = store.transaction(|w| w.upsert_entity(&actor)).unwrap();
    assert_eq!(inserted, UpsertOutcome::Inserted);

    let loaded = store.get_entity(id).unwrap().expect("entity present");
    assert_eq!(loaded.id, id);
    assert_eq!(loaded.kind, EntityKind::ThreatActor);

    let again = store.transaction(|w| w.upsert_entity(&actor)).unwrap();
    assert_eq!(again, UpsertOutcome::Unchanged);
    assert!(store.entity_exists(id).unwrap());
    assert!(store.count(RecordKind::Entity).unwrap() >= 1);
}

#[test]
fn source_object_round_trip() {
    let Some(url) = url() else {
        return;
    };
    let mut store = PostgresStore::connect(&url).unwrap();
    store.migrate().unwrap();

    let source = source_object(b"pg-contract-feed-bytes");
    let id = source.id;
    let outcome = store
        .transaction(|w| w.upsert_source_object(&source))
        .unwrap();
    assert!(outcome.changed());
    let loaded = store
        .get_source_object(id)
        .unwrap()
        .expect("source present");
    assert_eq!(loaded.id, id);
    assert_eq!(loaded.content_hash, source.content_hash);
}

#[test]
fn search_entities_respects_kind_filter() {
    let Some(url) = url() else {
        return;
    };
    let mut store = PostgresStore::connect(&url).unwrap();
    store.migrate().unwrap();
    let actor = entity("G-SEARCH-1");
    store.transaction(|w| w.upsert_entity(&actor)).unwrap();

    let query = EntityQuery::unfiltered().with_kind(EntityKind::ThreatActor);
    let found = store.search_entities(&query, Page::first(50)).unwrap();
    assert!(found.iter().any(|e| e.id == actor.id));
}

#[test]
fn failed_transaction_rolls_back() {
    let Some(url) = url() else {
        return;
    };
    let mut store = PostgresStore::connect(&url).unwrap();
    store.migrate().unwrap();

    let actor = entity("G-ROLLBACK-1");
    let id = actor.id;
    let err: Result<(), brolga_storage::StorageError> = store.transaction(|w| {
        w.upsert_entity(&actor)?;
        Err(brolga_storage::StorageError::Query {
            operation: "forced",
            reason: "rollback".to_owned(),
        })
    });
    assert!(err.is_err());
    assert!(store.get_entity(id).unwrap().is_none());
}
