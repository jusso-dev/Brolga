//! Repository-level integration tests against a real SQLite database.
//!
//! These use actual files rather than only in-memory databases, because the properties #6 asks
//! about — WAL, concurrent reads, migration determinism across fresh and upgraded databases,
//! transactional consistency — are properties of a file-backed store and are invisible in memory.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_model::claim::{Assertion, Claim};
use brolga_model::entity::{Entity, EntityKind};
use brolga_model::marking::{Marking, MarkingSet, TlpLevel};
use brolga_model::observable::{DomainName, Observable};
use brolga_model::provenance::{
    ContentHash, MediaType, Provenance, RecordOrigin, SourceObject, SourceOrigin, SyntheticOrigin,
    SyntheticReason, TransformationChain, TransformationStage, TransformationStep,
};
use brolga_model::relationship::{NodeRef, Relationship, RelationshipKind};
use brolga_model::sighting::{Sighting, SightingCount};
use brolga_model::status::{Disposition, LifecycleStatus};
use brolga_model::temporal::{TemporalState, Timestamp};
use brolga_model::text::{ShortText, UntrustedText};
use brolga_storage::error::StorageError;
use brolga_storage::migration::latest_version;
use brolga_storage::sqlite::SqliteStore;
use brolga_storage::store::{IntelligenceStore, Page, RecordKind, StoreRead, UpsertOutcome};
use tempfile::TempDir;

// -------------------------------------------------------------------------------------------------
// Fixtures
// -------------------------------------------------------------------------------------------------

fn short(value: &str) -> ShortText {
    ShortText::new(value).unwrap()
}

fn untrusted(value: &str) -> UntrustedText {
    UntrustedText::new(value).unwrap()
}

fn at(value: &str) -> Timestamp {
    Timestamp::parse_rfc3339(value).unwrap()
}

fn synthetic() -> RecordOrigin {
    RecordOrigin::synthetic(SyntheticOrigin::new(
        SyntheticReason::Fixture,
        short("storage-tests"),
    ))
}

fn source_object(bytes: &[u8]) -> SourceObject {
    SourceObject::new(
        ContentHash::of(bytes),
        MediaType::new("application/json").unwrap(),
        u64::try_from(bytes.len()).unwrap(),
        at("2024-01-01T00:00:00Z"),
        SourceOrigin::NetworkFeed {
            publisher: short("Example CERT"),
            location: None,
        },
    )
}

fn source_derived(bytes: &[u8]) -> RecordOrigin {
    let chain = TransformationChain::new(vec![TransformationStep::new(
        TransformationStage::Parsing,
        short("brolga.parse.json"),
        1,
    )])
    .unwrap();
    RecordOrigin::source_derived(Provenance::from_source(source_object(bytes).id, chain).unwrap())
}

fn entity(external_id: &str) -> Entity {
    Entity::new(
        Entity::derive_id(
            EntityKind::ThreatActor,
            &short("vendor"),
            &short(external_id),
        ),
        EntityKind::ThreatActor,
        untrusted(external_id),
        synthetic(),
    )
}

fn observable_ref(domain: &str) -> NodeRef {
    NodeRef::Observable(Observable::DomainName(DomainName::new(domain).unwrap()).id())
}

fn open(directory: &TempDir) -> SqliteStore {
    let mut store = SqliteStore::open(directory.path().join("brolga.sqlite"), 5000).unwrap();
    store.migrate().unwrap();
    store
}

// -------------------------------------------------------------------------------------------------
// Migrations
// -------------------------------------------------------------------------------------------------

#[test]
fn a_fresh_database_migrates_to_the_current_version() {
    let directory = TempDir::new().unwrap();
    let mut store = SqliteStore::open(directory.path().join("brolga.sqlite"), 5000).unwrap();

    assert_eq!(store.schema_version().unwrap(), 0);

    let report = store.migrate().unwrap();
    assert_eq!(report.from_version, 0);
    assert_eq!(report.to_version, latest_version());
    assert_eq!(report.applied, vec![1]);
    assert!(report.changed());
}

#[test]
fn migrating_is_idempotent() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let second = store.migrate().unwrap();
    assert!(!second.changed(), "a current database must apply nothing");
    assert_eq!(second.from_version, latest_version());
    assert_eq!(second.to_version, latest_version());
}

#[test]
fn a_fresh_database_and_a_reopened_one_have_identical_schemas() {
    // Determinism across the two paths a database can arrive at the current version by. Asserted
    // rather than assumed, because a migration that behaves differently on the two paths produces
    // deployments that disagree about the schema while reporting the same version.
    let first_dir = TempDir::new().unwrap();
    let first = open(&first_dir);
    let fresh_schema = schema_of(&first);
    drop(first);

    let second_dir = TempDir::new().unwrap();
    {
        let _created = open(&second_dir);
    }
    let mut reopened = SqliteStore::open(second_dir.path().join("brolga.sqlite"), 5000).unwrap();
    reopened.migrate().unwrap();

    assert_eq!(fresh_schema, schema_of(&reopened));
    assert!(!fresh_schema.is_empty());
}

/// Read the schema as SQLite records it, so two databases can be compared exactly.
fn schema_of(store: &SqliteStore) -> Vec<String> {
    // Uses a second connection rather than reaching into the store's private one, which is also how
    // a real operator would inspect a database.
    let path = match store.path() {
        brolga_storage::sqlite::StorePath::File(path) => path.clone(),
        brolga_storage::sqlite::StorePath::Memory => panic!("needs a file-backed store"),
    };
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .unwrap();
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap();
    rows.map(|row| row.unwrap()).collect()
}

#[test]
fn a_database_newer_than_this_build_is_refused() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");
    {
        let _created = SqliteStore::open(&path, 5000).unwrap();
    }

    // Pretend a future build applied migration 9999.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS brolga_schema_migrations (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL
             ) STRICT;
             INSERT INTO brolga_schema_migrations (id, name, checksum, applied_at)
             VALUES (9999, 'from_the_future', 'sha256:x', '2030-01-01T00:00:00Z');",
        )
        .unwrap();
    drop(connection);

    let mut store = SqliteStore::open(&path, 5000).unwrap();
    let error = store.migrate().unwrap_err();
    assert!(
        matches!(error, StorageError::SchemaTooNew { found: 9999, .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("upgrade Brolga"));
}

#[test]
fn an_edited_released_migration_is_detected() {
    // The check that makes "a released migration is immutable" enforceable rather than aspirational.
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");
    {
        let _migrated = open(&directory);
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE brolga_schema_migrations SET checksum = ?1 WHERE id = 1",
            rusqlite::params![
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ],
        )
        .unwrap();
    drop(connection);

    let mut store = SqliteStore::open(&path, 5000).unwrap();
    let error = store.migrate().unwrap_err();
    assert!(
        matches!(error, StorageError::MigrationChanged { id: 1, .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("never be edited"));
}

// -------------------------------------------------------------------------------------------------
// Connection settings
// -------------------------------------------------------------------------------------------------

#[test]
fn a_file_backed_store_uses_write_ahead_logging() {
    let directory = TempDir::new().unwrap();
    let store = open(&directory);
    assert_eq!(store.journal_mode().unwrap().to_lowercase(), "wal");
}

#[test]
fn readers_are_not_blocked_by_an_open_write_transaction() {
    // The reason WAL is set. Without it, every read during an import waits, which for a tool whose
    // job is answering questions about imported intelligence is the wrong trade.
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let mut writer = SqliteStore::open(&path, 5000).unwrap();
    writer.migrate().unwrap();

    writer
        .transaction(|store| {
            store.upsert_entity(&entity("A"))?;
            Ok(())
        })
        .unwrap();

    let reader = SqliteStore::open(&path, 5000).unwrap();

    // Hold a write transaction open while the reader works.
    let result = writer.transaction(|store| {
        store.upsert_entity(&entity("B"))?;

        // The reader sees the committed state, immediately, without blocking.
        let visible = reader.count(RecordKind::Entity)?;
        assert_eq!(
            visible, 1,
            "reader must see committed data and not the open write"
        );

        Ok(())
    });
    assert!(result.is_ok());

    assert_eq!(reader.count(RecordKind::Entity).unwrap(), 2);
}

#[test]
fn the_busy_timeout_comes_from_configuration() {
    let directory = TempDir::new().unwrap();
    let store = SqliteStore::open(directory.path().join("brolga.sqlite"), 1234).unwrap();
    assert_eq!(store.busy_timeout_ms().unwrap(), 1234);
}

// -------------------------------------------------------------------------------------------------
// Upsert and lookup
// -------------------------------------------------------------------------------------------------

#[test]
fn every_record_kind_round_trips_through_storage() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let source = source_object(b"bundle");
    let actor = entity("A");
    let target = entity("B");
    let relationship = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(actor.id),
        NodeRef::Entity(target.id),
        synthetic(),
    );
    let claim = Claim::new(
        observable_ref("example.com"),
        Assertion::Disposition(Disposition::Malicious),
        source_derived(b"bundle"),
    );
    let sighting = Sighting::new(
        observable_ref("example.com"),
        Some(actor.id),
        SightingCount::new(42).unwrap(),
        at("2024-01-01T00:00:00Z"),
        at("2024-01-05T00:00:00Z"),
        synthetic(),
    )
    .unwrap();

    store
        .transaction(|write| {
            write.upsert_source_object(&source)?;
            write.upsert_entity(&actor)?;
            write.upsert_entity(&target)?;
            write.upsert_relationship(&relationship)?;
            write.upsert_claim(&claim)?;
            write.upsert_sighting(&sighting)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(store.get_source_object(source.id).unwrap(), Some(source));
    assert_eq!(store.get_entity(actor.id).unwrap(), Some(actor));
    assert_eq!(
        store.get_relationship(relationship.id).unwrap(),
        Some(relationship)
    );
    assert_eq!(store.get_claim(claim.id).unwrap(), Some(claim));
    assert_eq!(store.get_sighting(sighting.id).unwrap(), Some(sighting));
}

#[test]
fn provenance_survives_a_storage_round_trip() {
    // The whole promise: compression never breaks the chain back to evidence, and neither does
    // persistence.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let source = source_object(b"bundle");
    let claim = Claim::new(
        observable_ref("example.com"),
        Assertion::Disposition(Disposition::Malicious),
        source_derived(b"bundle"),
    );

    store
        .transaction(|write| {
            write.upsert_source_object(&source)?;
            write.upsert_claim(&claim)?;
            Ok(())
        })
        .unwrap();

    let stored = store.get_claim(claim.id).unwrap().unwrap();
    assert!(stored.origin.is_source_derived());
    assert_eq!(stored.origin.source_objects(), &[source.id]);

    // And the cited evidence is retrievable, so expansion back to source actually resolves.
    let cited = stored.origin.source_objects().first().copied().unwrap();
    assert_eq!(store.get_source_object(cited).unwrap(), Some(source));
}

#[test]
fn markings_survive_a_storage_round_trip() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let mut restricted = entity("A");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);

    store
        .transaction(|write| {
            write.upsert_entity(&restricted)?;
            Ok(())
        })
        .unwrap();

    let stored = store.get_entity(restricted.id).unwrap().unwrap();
    assert_eq!(stored.markings.most_restrictive_tlp(), Some(TlpLevel::Red));
}

#[test]
fn re_importing_identical_records_reports_unchanged() {
    // Re-importing a feed is expected and common. A caller that cannot tell "stored again,
    // identically" from "changed" has to treat a republished catalogue as a catalogue of changes.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);
    let actor = entity("A");

    let first = store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    assert_eq!(first, UpsertOutcome::Inserted);

    let second = store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    assert_eq!(second, UpsertOutcome::Unchanged);
    assert!(!second.changed());

    let mut edited = actor.clone();
    edited.status = LifecycleStatus::Revoked;
    let third = store
        .transaction(|write| write.upsert_entity(&edited))
        .unwrap();
    assert_eq!(third, UpsertOutcome::Updated);

    assert_eq!(store.count(RecordKind::Entity).unwrap(), 1);
}

#[test]
fn identical_evidence_from_two_routes_is_stored_once() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let from_feed = source_object(b"identical bytes");
    let mut from_file = source_object(b"identical bytes");
    from_file.origin = SourceOrigin::LocalFile {
        path: brolga_model::provenance::SensitiveText::new("/tmp/copy.json").unwrap(),
    };

    store
        .transaction(|write| {
            write.upsert_source_object(&from_feed)?;
            write.upsert_source_object(&from_file)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(store.count(RecordKind::SourceObject).unwrap(), 1);

    // And it is findable by content, which is what makes re-import idempotent without knowing an
    // identifier in advance.
    let found = store
        .find_source_object_by_hash(&ContentHash::of(b"identical bytes"))
        .unwrap();
    assert!(found.is_some());
}

#[test]
fn a_missing_record_is_none_rather_than_an_error() {
    let directory = TempDir::new().unwrap();
    let store = open(&directory);
    assert_eq!(store.get_entity(entity("nope").id).unwrap(), None);
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
}

// -------------------------------------------------------------------------------------------------
// Transactions
// -------------------------------------------------------------------------------------------------

#[test]
fn a_failed_transaction_leaves_no_partial_state() {
    // A partially applied import is worse than a failed one: the failure is visible, the partial
    // state is not.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let result: Result<(), StorageError> = store.transaction(|write| {
        write.upsert_entity(&entity("A"))?;
        write.upsert_entity(&entity("B"))?;
        Err(StorageError::Query {
            operation: "a deliberate failure",
            reason: "for the test".to_owned(),
        })
    });

    assert!(result.is_err());
    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        0,
        "both writes must have been rolled back",
    );

    // And the store is still usable afterwards.
    store
        .transaction(|write| write.upsert_entity(&entity("C")))
        .unwrap();
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 1);
}

#[test]
fn a_successful_transaction_commits_every_write_together() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    store
        .transaction(|write| {
            for index in 0..10 {
                write.upsert_entity(&entity(&format!("E{index}")))?;
            }
            Ok(())
        })
        .unwrap();

    assert_eq!(store.count(RecordKind::Entity).unwrap(), 10);
}

// -------------------------------------------------------------------------------------------------
// Queries
// -------------------------------------------------------------------------------------------------

#[test]
fn listings_are_bounded_and_pageable() {
    // There is no unbounded listing method: a query proportional to the database works in testing
    // and exhausts memory in production.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    store
        .transaction(|write| {
            for index in 0..25 {
                let mut record = entity(&format!("E{index:02}"));
                record.temporal = TemporalState {
                    last_seen: Some(at(&format!("2024-01-{:02}T00:00:00Z", index + 1))),
                    ..TemporalState::unknown()
                };
                write.upsert_entity(&record)?;
            }
            Ok(())
        })
        .unwrap();

    let first = store.list_entities(Page::first(10)).unwrap();
    assert_eq!(first.len(), 10);

    let second = store.list_entities(Page::first(10).next()).unwrap();
    assert_eq!(second.len(), 10);

    let third = store.list_entities(Page::first(10).next().next()).unwrap();
    assert_eq!(third.len(), 5);

    // Pages do not overlap.
    let ids: std::collections::BTreeSet<_> = first
        .iter()
        .chain(&second)
        .chain(&third)
        .map(|record| record.id)
        .collect();
    assert_eq!(ids.len(), 25);

    // A caller asking for more than the maximum gets the maximum, not an error.
    assert!(store.list_entities(Page::first(u32::MAX)).unwrap().len() <= 25);
}

#[test]
fn relationships_are_found_from_either_end() {
    // A relationship is directed, but a caller asking "what is connected to this" rarely means
    // "only what points away from it".
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let actor = entity("A");
    let victim = entity("B");
    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(actor.id),
        NodeRef::Entity(victim.id),
        synthetic(),
    );

    store
        .transaction(|write| {
            write.upsert_relationship(&edge)?;
            Ok(())
        })
        .unwrap();

    let from_source = store
        .relationships_touching(&NodeRef::Entity(actor.id), Page::default())
        .unwrap();
    let from_target = store
        .relationships_touching(&NodeRef::Entity(victim.id), Page::default())
        .unwrap();

    assert_eq!(from_source.len(), 1);
    assert_eq!(from_target.len(), 1);
    assert_eq!(from_source, from_target);
}

#[test]
fn contradictory_claims_about_one_subject_are_both_returned() {
    // Filtering here would decide on the caller's behalf which disagreements are worth knowing
    // about, which is exactly what the roadmap forbids.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let subject = observable_ref("example.com");
    let malicious = Claim::new(
        subject,
        Assertion::Disposition(Disposition::Malicious),
        synthetic(),
    );
    let mut benign = Claim::new(
        subject,
        Assertion::Disposition(Disposition::Benign),
        synthetic(),
    );
    benign.status = LifecycleStatus::Revoked;

    store
        .transaction(|write| {
            write.upsert_claim(&malicious)?;
            write.upsert_claim(&benign)?;
            Ok(())
        })
        .unwrap();

    let claims = store.claims_about(&subject, Page::default()).unwrap();
    assert_eq!(claims.len(), 2, "including the revoked one");
    assert!(
        claims
            .iter()
            .any(|claim| claim.status == LifecycleStatus::Revoked)
    );
}

#[test]
fn sightings_are_returned_most_recent_first() {
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);
    let subject = observable_ref("example.com");

    store
        .transaction(|write| {
            for day in 1..=5 {
                let sighting = Sighting::new(
                    subject,
                    None,
                    SightingCount::ONE,
                    at(&format!("2024-01-{day:02}T00:00:00Z")),
                    at(&format!("2024-01-{day:02}T12:00:00Z")),
                    synthetic(),
                )
                .unwrap();
                write.upsert_sighting(&sighting)?;
            }
            Ok(())
        })
        .unwrap();

    let sightings = store.sightings_of(&subject, Page::default()).unwrap();
    assert_eq!(sightings.len(), 5);

    let seen: Vec<_> = sightings
        .iter()
        .map(|sighting| sighting.last_seen)
        .collect();
    let mut expected = seen.clone();
    expected.sort_unstable_by(|left, right| right.cmp(left));
    assert_eq!(seen, expected, "most recent last_seen first");
}

// -------------------------------------------------------------------------------------------------
// Injection
// -------------------------------------------------------------------------------------------------

#[test]
fn hostile_values_are_stored_as_data_and_never_executed() {
    // Every value is bound, so a payload that looks like SQL is a string. Asserted end to end
    // rather than by reading the statements.
    let directory = TempDir::new().unwrap();
    let mut store = open(&directory);

    let payloads = [
        "'; DROP TABLE entities; --",
        "\" OR 1=1 --",
        "'); DELETE FROM claims; SELECT ('",
        "\u{2019}); DROP TABLE claims; --",
        "0x27 OR '1'='1",
    ];

    let mut stored = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let mut record = entity(&format!("H{index}"));
        record.aliases = vec![untrusted(payload)];
        stored.push(record);
    }

    store
        .transaction(|write| {
            for record in &stored {
                write.upsert_entity(record)?;
            }
            Ok(())
        })
        .unwrap();

    // Nothing was dropped or deleted, and every payload came back byte-identical.
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 5);
    for (record, payload) in stored.iter().zip(payloads) {
        let back = store.get_entity(record.id).unwrap().unwrap();
        assert_eq!(
            back.aliases.first().map(UntrustedText::as_str),
            Some(payload),
            "payload was altered in storage",
        );
    }

    // Every table still exists.
    for kind in RecordKind::all() {
        assert!(store.count(*kind).is_ok(), "{kind:?} table is gone");
    }
}

#[test]
fn a_store_cannot_be_opened_on_a_traversal_path() {
    let directory = TempDir::new().unwrap();
    let escaping = directory.path().join("..").join("escaped.sqlite");
    let error = SqliteStore::open(&escaping, 5000).unwrap_err();
    assert!(
        matches!(error, StorageError::UnusablePath { .. }),
        "{error:?}"
    );
}
