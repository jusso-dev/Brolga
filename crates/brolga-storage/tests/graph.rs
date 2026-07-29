//! Graph persistence: versions, referential integrity, and migration.
//!
//! One section per acceptance criterion of [#19](https://github.com/jusso-dev/Brolga/issues/19).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_model::{
    Assertion, Claim, Disposition, Entity, EntityKind, Id, NodeRef, Observable, RecordOrigin,
    Relationship, RelationshipKind, ShortText, Sighting, SightingCount, SyntheticOrigin,
    SyntheticReason, Timestamp, UntrustedText,
};
use brolga_storage::{
    IntelligenceStore, MIGRATIONS, RecordKind, SqliteStore, StorageError, StoreRead, latest_version,
};
use tempfile::TempDir;

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn synthetic() -> RecordOrigin {
    RecordOrigin::Synthetic {
        origin: SyntheticOrigin::new(
            SyntheticReason::Fixture,
            ShortText::new("graph-test").unwrap(),
        ),
    }
}

fn entity(name: &str) -> Entity {
    Entity::new(
        Id::derive(&["entity", name]),
        EntityKind::ThreatActor,
        UntrustedText::new(name).unwrap(),
        synthetic(),
    )
}

fn observable() -> Observable {
    Observable::DomainName(brolga_model::observable::DomainName::new("evil.example").unwrap())
}

// ---------------------------------------------------------------------------------------------
// "All canonical graph record types persist and retrieve"
// ---------------------------------------------------------------------------------------------

/// The criterion, over every record type rather than a sample. A type that persists but does not
/// retrieve is indistinguishable from one that was never written.
#[test]
fn every_graph_record_type_persists_and_retrieves_identically() {
    let mut store = store();
    let actor = entity("Bunyip Panda");
    let victim = entity("Example Corp");

    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(actor.id),
        NodeRef::Entity(victim.id),
        synthetic(),
    );
    let claim = Claim::new(
        NodeRef::Observable(observable().id()),
        Assertion::Disposition(Disposition::Malicious),
        synthetic(),
    );
    let sighting = Sighting::new(
        NodeRef::Observable(observable().id()),
        None,
        SightingCount::new(3).unwrap(),
        Timestamp::unix_epoch(),
        Timestamp::unix_epoch(),
        synthetic(),
    )
    .unwrap();

    store
        .transaction(|write| {
            write.upsert_entity(&actor)?;
            write.upsert_entity(&victim)?;
            write.upsert_relationship(&edge)?;
            write.upsert_claim(&claim)?;
            write.upsert_sighting(&sighting)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(store.get_entity(actor.id).unwrap().as_ref(), Some(&actor));
    assert_eq!(
        store.get_relationship(edge.id).unwrap().as_ref(),
        Some(&edge)
    );
    assert_eq!(store.get_claim(claim.id).unwrap().as_ref(), Some(&claim));
    assert_eq!(
        store.get_sighting(sighting.id).unwrap().as_ref(),
        Some(&sighting)
    );

    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 1);
    assert_eq!(store.count(RecordKind::Claim).unwrap(), 1);
    assert_eq!(store.count(RecordKind::Sighting).unwrap(), 1);
}

/// Provenance, markings, and temporal state must survive the round trip. A record that persists
/// with its policy metadata stripped is worse than one that failed to persist: it looks complete.
#[test]
fn provenance_markings_and_temporal_state_survive_persistence() {
    use brolga_model::{Marking, TlpLevel};

    let mut store = store();
    let mut actor = entity("Marked Actor");
    actor.markings.insert(Marking::Tlp(TlpLevel::Amber));
    actor.temporal =
        brolga_model::TemporalState::observed(Timestamp::unix_epoch(), Timestamp::unix_epoch())
            .unwrap();

    store
        .transaction(|write| {
            write.upsert_entity(&actor)?;
            Ok(())
        })
        .unwrap();

    let read = store.get_entity(actor.id).unwrap().unwrap();
    assert_eq!(read, actor, "nothing was dropped in the round trip");
    assert!(
        read.markings
            .iter()
            .any(|marking| *marking == Marking::Tlp(TlpLevel::Amber)),
        "the marking a future row filter would need is still there"
    );
}

// ---------------------------------------------------------------------------------------------
// "Referential integrity rejects dangling graph edges"
// ---------------------------------------------------------------------------------------------

/// The criterion. A dangling edge is invisible: traversal returns nothing at that endpoint, and
/// nothing distinguishes "no relationships" from "an edge pointing at a record never written".
#[test]
fn an_edge_to_an_entity_that_does_not_exist_is_refused() {
    let mut store = store();
    let present = entity("Present");
    let absent = entity("Absent");

    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(present.id),
        NodeRef::Entity(absent.id),
        synthetic(),
    );

    let error = store
        .transaction(|write| {
            write.upsert_entity(&present)?;
            write.upsert_relationship(&edge)
        })
        .unwrap_err();

    assert!(
        matches!(error, StorageError::DanglingEdge { .. }),
        "got {error}"
    );
    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        0,
        "the whole transaction rolled back"
    );
}

/// The diagnostic must name which endpoint and which identifier, or the operator has to guess which
/// half of the edge was wrong.
#[test]
fn the_dangling_edge_diagnostic_names_the_endpoint_and_the_missing_identifier() {
    let mut store = store();
    let absent = entity("Absent");
    let present = entity("Present");
    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(absent.id),
        NodeRef::Entity(present.id),
        synthetic(),
    );

    let error = store
        .transaction(|write| write.upsert_relationship(&edge))
        .unwrap_err();

    let rendered = error.to_string();
    assert!(rendered.contains("source"), "{rendered}");
    assert!(rendered.contains(&absent.id.to_string()), "{rendered}");
    assert!(
        rendered.contains("traversal"),
        "says why it matters: {rendered}"
    );
}

/// An observable endpoint is content-addressed: its identifier is a function of its value, so there
/// is nothing to dangle from. Requiring a row for one would make every claim about an observable
/// impossible.
#[test]
fn an_observable_endpoint_needs_no_row_because_its_identifier_is_its_value() {
    let mut store = store();
    let claim = Claim::new(
        NodeRef::Observable(observable().id()),
        Assertion::Disposition(Disposition::Malicious),
        synthetic(),
    );

    store
        .transaction(|write| write.upsert_claim(&claim))
        .unwrap();
    assert_eq!(store.count(RecordKind::Claim).unwrap(), 1);
}

/// Claims and sightings carry endpoints too, and an unchecked one dangles the same way.
#[test]
fn a_claim_or_sighting_about_a_missing_entity_is_refused() {
    let mut store = store();
    let absent = entity("Absent");

    let claim = Claim::new(
        NodeRef::Entity(absent.id),
        Assertion::Disposition(Disposition::Malicious),
        synthetic(),
    );
    assert!(
        store
            .transaction(|write| write.upsert_claim(&claim))
            .is_err()
    );

    let sighting = Sighting::new(
        NodeRef::Entity(absent.id),
        None,
        SightingCount::new(1).unwrap(),
        Timestamp::unix_epoch(),
        Timestamp::unix_epoch(),
        synthetic(),
    )
    .unwrap();
    assert!(
        store
            .transaction(|write| write.upsert_sighting(&sighting))
            .is_err()
    );
}

/// `entity_exists` is what the check is built on, and it must not need to decode the record.
#[test]
fn entity_existence_can_be_checked_without_decoding_the_record() {
    let mut store = store();
    let actor = entity("Present");
    assert!(!store.entity_exists(actor.id).unwrap());

    store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    assert!(store.entity_exists(actor.id).unwrap());
}

// ---------------------------------------------------------------------------------------------
// "Graph version changes only for material graph mutations"
// ---------------------------------------------------------------------------------------------

/// The criterion. A version that ticked on every write would answer "did somebody run an import?",
/// which is a different and much less useful question than "has anything changed?".
#[test]
fn the_graph_version_increments_on_a_material_change_and_not_on_a_no_op() {
    let mut store = store();
    let actor = entity("Bunyip Panda");

    assert_eq!(
        store.graph_version().unwrap(),
        0,
        "a fresh graph is at zero"
    );

    store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    let after_insert = store.graph_version().unwrap();
    assert_eq!(after_insert, 1);

    // The identical record again. Nothing about the graph changed, so the version must not move.
    store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    assert_eq!(
        store.graph_version().unwrap(),
        after_insert,
        "re-writing an identical record is not a material change"
    );

    let mut changed = actor.clone();
    changed.description = Some(UntrustedText::new("now with a description").unwrap());
    store
        .transaction(|write| write.upsert_entity(&changed))
        .unwrap();
    assert_eq!(store.graph_version().unwrap(), after_insert + 1);
}

/// Every record type must count, or "has anything changed" is only true for entities.
#[test]
fn every_graph_record_type_moves_the_version() {
    let mut store = store();
    let actor = entity("A");
    let victim = entity("B");

    store
        .transaction(|write| {
            write.upsert_entity(&actor)?;
            write.upsert_entity(&victim)
        })
        .unwrap();
    let after_entities = store.graph_version().unwrap();

    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(actor.id),
        NodeRef::Entity(victim.id),
        synthetic(),
    );
    store
        .transaction(|write| write.upsert_relationship(&edge))
        .unwrap();
    assert!(store.graph_version().unwrap() > after_entities);

    let after_edge = store.graph_version().unwrap();
    let claim = Claim::new(
        NodeRef::Observable(observable().id()),
        Assertion::Disposition(Disposition::Malicious),
        synthetic(),
    );
    store
        .transaction(|write| write.upsert_claim(&claim))
        .unwrap();
    assert!(store.graph_version().unwrap() > after_edge);
}

/// A rolled-back transaction must not leave the version moved. Otherwise a failed import looks
/// like a change and every incremental consumer re-reads for nothing.
#[test]
fn a_rolled_back_transaction_leaves_the_version_where_it_was() {
    let mut store = store();
    let actor = entity("A");
    store
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();
    let before = store.graph_version().unwrap();

    let absent = entity("Absent");
    let edge = Relationship::new(
        RelationshipKind::Targets,
        NodeRef::Entity(actor.id),
        NodeRef::Entity(absent.id),
        synthetic(),
    );
    let _ = store.transaction(|write| {
        write.upsert_entity(&entity("Also written but rolled back"))?;
        write.upsert_relationship(&edge)
    });

    assert_eq!(store.graph_version().unwrap(), before);
}

/// Retention operations are not graph mutations. Storing evidence changes what Brolga can prove,
/// not what the graph says.
#[test]
fn retaining_a_source_object_does_not_move_the_graph_version() {
    use brolga_storage::BlobRequest;

    let mut store = store();
    let before = store.graph_version().unwrap();
    store
        .transaction(|write| write.put_source_blob(&BlobRequest::standard(b"evidence", "test")))
        .unwrap();
    assert_eq!(store.graph_version().unwrap(), before);
}

// ---------------------------------------------------------------------------------------------
// "Concurrent reads observe consistent versions"
// ---------------------------------------------------------------------------------------------

/// The criterion. A reader that saw a bumped version before the records it describes would
/// conclude the graph changed and then fail to find the change.
#[test]
fn a_reader_never_sees_a_version_ahead_of_the_records_it_describes() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let mut writer = SqliteStore::open(&path, 5000).unwrap();
    writer.migrate().unwrap();

    let reader = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(reader.graph_version().unwrap(), 0);
    assert_eq!(reader.count(RecordKind::Entity).unwrap(), 0);

    let actor = entity("Written While Reading");
    writer
        .transaction(|write| write.upsert_entity(&actor))
        .unwrap();

    // After the commit, both move together — the version and the record become visible in the same
    // transaction, so there is no window where one is ahead of the other.
    let version = reader.graph_version().unwrap();
    let count = reader.count(RecordKind::Entity).unwrap();
    assert_eq!(version, 1);
    assert_eq!(count, 1);
    assert!(reader.entity_exists(actor.id).unwrap());
}

/// WAL is what makes a reader not block behind a writer. Asserted through the version so the test
/// is about observable behaviour rather than about a pragma.
#[test]
fn a_reader_is_not_blocked_by_an_open_write_transaction() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let mut writer = SqliteStore::open(&path, 5000).unwrap();
    writer.migrate().unwrap();
    let reader = SqliteStore::open(&path, 5000).unwrap();

    let actor = entity("Mid-Transaction");
    writer
        .transaction(|write| {
            write.upsert_entity(&actor)?;
            // Mid-transaction the reader still sees the committed state, not the pending one.
            assert_eq!(reader.graph_version().unwrap(), 0);
            assert_eq!(reader.count(RecordKind::Entity).unwrap(), 0);
            Ok(())
        })
        .unwrap();

    assert_eq!(reader.graph_version().unwrap(), 1);
}

// ---------------------------------------------------------------------------------------------
// "Migration and rollback tests pass"
// ---------------------------------------------------------------------------------------------

/// A fresh database and an upgraded one must end up identical. Until now there was only one
/// migration, so this could not be tested; there are four.
#[test]
fn a_database_upgraded_one_migration_at_a_time_matches_a_fresh_one() {
    let fresh_dir = TempDir::new().unwrap();
    let mut fresh = SqliteStore::open(fresh_dir.path().join("fresh.sqlite"), 5000).unwrap();
    fresh.migrate().unwrap();

    // Build a second database by applying the migrations by hand, in order, exactly as an older
    // deployment would have accumulated them.
    let upgraded_dir = TempDir::new().unwrap();
    let upgraded_path = upgraded_dir.path().join("upgraded.sqlite");
    {
        let connection = rusqlite::Connection::open(&upgraded_path).unwrap();
        connection
            .execute_batch(brolga_storage::migration::MIGRATIONS_TABLE)
            .unwrap();
        for migration in MIGRATIONS {
            connection.execute_batch(migration.sql).unwrap();
            connection
                .execute(
                    "INSERT INTO brolga_schema_migrations (id, name, checksum, applied_at)
                     VALUES (?1, ?2, ?3, '1970-01-01T00:00:00Z')",
                    rusqlite::params![
                        migration.id,
                        migration.name,
                        migration.checksum().to_string()
                    ],
                )
                .unwrap();
        }
    }
    let mut upgraded = SqliteStore::open(&upgraded_path, 5000).unwrap();
    // Re-running must be a no-op: every migration is already recorded.
    let report = upgraded.migrate().unwrap();
    assert!(!report.changed(), "an up-to-date database migrates nothing");

    assert_eq!(fresh.schema_version().unwrap(), latest_version());
    assert_eq!(upgraded.schema_version().unwrap(), latest_version());
    assert_eq!(schema_of(fresh.path()), schema_of(upgraded.path()));
}

/// Reading the schema back out, so the comparison is of what SQLite actually holds rather than of
/// what the migration list says it should.
fn schema_of(path: &brolga_storage::StorePath) -> Vec<String> {
    let brolga_storage::StorePath::File(path) = path else {
        panic!("expected a file-backed store");
    };
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok(format!(
                "{}|{}|{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?.unwrap_or_default()
            ))
        })
        .unwrap();
    rows.map(Result::unwrap).collect()
}

/// A migration is immutable once released. Editing one must fail at start-up rather than produce
/// two deployments reporting the same schema version with different schemas.
#[test]
fn an_edited_released_migration_is_refused_at_start_up() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    {
        let mut store = SqliteStore::open(&path, 5000).unwrap();
        store.migrate().unwrap();
    }
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE brolga_schema_migrations SET checksum = 'sha256:tampered' WHERE id = 4",
                [],
            )
            .unwrap();
    }

    let mut store = SqliteStore::open(&path, 5000).unwrap();
    let error = store.migrate().unwrap_err();
    assert!(
        matches!(error, StorageError::MigrationChanged { id: 4, .. }),
        "got {error}"
    );
}

/// The graph version must survive the round trip through a reopened database — it is durable state,
/// not a process counter.
#[test]
fn the_graph_version_survives_reopening_the_database() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    {
        let mut store = SqliteStore::open(&path, 5000).unwrap();
        store.migrate().unwrap();
        store
            .transaction(|write| write.upsert_entity(&entity("Durable")))
            .unwrap();
        assert_eq!(store.graph_version().unwrap(), 1);
    }

    let store = SqliteStore::open(&path, 5000).unwrap();
    assert_eq!(store.graph_version().unwrap(), 1);
}
