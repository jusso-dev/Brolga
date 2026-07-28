//! Content-addressed retention, against a real database.
//!
//! One section per acceptance criterion of [#16](https://github.com/jusso-dev/Brolga/issues/16).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_model::provenance::ContentHash;
use brolga_storage::{
    BlobCodec, BlobOutcome, BlobRequest, IntelligenceStore, RecordKind, RetentionAction,
    RetentionClass, SqliteStore, StorageError, StoreRead,
};

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn put(store: &mut SqliteStore, bytes: &[u8], reason: &str) -> BlobOutcome {
    store
        .transaction(|writer| writer.put_source_blob(&BlobRequest::standard(bytes, reason)))
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// "Byte-identical objects store once"
// ---------------------------------------------------------------------------------------------

/// The criterion. Two feeds publishing one bundle, or one feed publishing it daily, is the normal
/// case — storing it repeatedly would multiply the disk cost of a scheduled import by its frequency.
#[test]
fn byte_identical_objects_are_stored_once_however_many_times_they_arrive() {
    let mut store = store();
    let bytes = b"{\"type\":\"bundle\",\"objects\":[]}";

    let first = put(&mut store, bytes, "first import");
    let second = put(&mut store, bytes, "same bundle, next day");
    let third = put(&mut store, bytes, "same bundle, from a second feed");

    assert!(first.wrote_bytes());
    assert_eq!(second, BlobOutcome::Deduplicated);
    assert_eq!(third, BlobOutcome::Deduplicated);
    assert_eq!(store.source_blob_count().unwrap(), 1);
}

/// Deduplication must be reported rather than hidden, or a caller counting retained evidence
/// cannot tell a fresh import from a repeat.
#[test]
fn a_duplicate_is_reported_distinctly_from_a_fresh_write() {
    let mut store = store();
    assert!(put(&mut store, b"evidence", "first").wrote_bytes());
    assert!(!put(&mut store, b"evidence", "again").wrote_bytes());
}

/// Every arrival is audited even when nothing is written. "This bundle arrived four times" is a
/// fact about the feed that the row count alone cannot answer.
#[test]
fn a_deduplicated_arrival_is_still_audited() {
    let mut store = store();
    let bytes = b"evidence";
    put(&mut store, bytes, "first");
    put(&mut store, bytes, "second");

    let audit = store.source_blob_audit(&ContentHash::of(bytes)).unwrap();
    let actions: Vec<_> = audit.iter().map(|event| event.action).collect();
    assert_eq!(
        actions,
        vec![RetentionAction::Stored, RetentionAction::Deduplicated]
    );
}

// ---------------------------------------------------------------------------------------------
// "Original bytes retrieve exactly"
// ---------------------------------------------------------------------------------------------

/// The criterion, over inputs that exercise both codecs and the awkward edges: empty, binary,
/// every byte value, and something highly compressible.
#[test]
fn original_bytes_retrieve_exactly_whatever_they_contain() {
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"x".to_vec(),
        (0..=255_u8).collect(),
        b"the same sentence over and over. ".repeat(500),
        vec![0_u8; 1024],
        "unicode: \u{4f60}\u{597d} \u{1f600}".as_bytes().to_vec(),
    ];

    let mut store = store();
    for bytes in cases {
        put(&mut store, &bytes, "round trip");
        let retrieved = store
            .get_source_blob(&ContentHash::of(&bytes))
            .unwrap()
            .expect("retained");
        assert_eq!(
            retrieved.bytes, bytes,
            "bytes did not survive the round trip"
        );
        assert_eq!(
            retrieved.metadata.original_length,
            u64::try_from(bytes.len()).unwrap()
        );
    }
}

/// Compression must be a storage detail the caller never has to know about, and it must actually
/// happen where it pays.
#[test]
fn compression_is_transparent_and_only_applied_when_it_helps() {
    let mut store = store();

    let repetitive = b"the same sentence over and over. ".repeat(500);
    put(&mut store, &repetitive, "compressible");
    let compressed = store
        .source_blob_metadata(&ContentHash::of(&repetitive))
        .unwrap()
        .unwrap();
    assert_eq!(compressed.codec, BlobCodec::Deflate);
    assert!(compressed.stored_length < compressed.original_length);

    let tiny = b"no";
    put(&mut store, tiny, "incompressible");
    let stored = store
        .source_blob_metadata(&ContentHash::of(tiny))
        .unwrap()
        .unwrap();
    assert_eq!(stored.codec, BlobCodec::Identity);
    assert!(
        stored.stored_length <= stored.original_length,
        "compression must never make a blob larger"
    );
}

/// An address nothing was stored under is absence, not an error — a caller checking whether
/// evidence was retained should not have to distinguish "no" from "broken".
#[test]
fn an_unknown_address_reads_back_as_absent_rather_than_as_an_error() {
    let store = store();
    assert!(
        store
            .get_source_blob(&ContentHash::of(b"never stored"))
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------------------------
// "Corruption is detected"
// ---------------------------------------------------------------------------------------------

/// The criterion. Content addressing is only worth having if the address is *checked* — otherwise
/// it is a naming convention. Corrupting the stored bytes behind the store's back must surface as
/// an error rather than as plausible evidence.
#[test]
fn bytes_that_no_longer_hash_to_their_address_are_refused_rather_than_returned() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let bytes = b"authentic evidence that somebody will tamper with";
    let address = ContentHash::of(bytes);
    {
        let mut store = SqliteStore::open(&path, 5000).unwrap();
        store.migrate().unwrap();
        store
            .transaction(|writer| writer.put_source_blob(&BlobRequest::standard(bytes, "genuine")))
            .unwrap();
    }

    // Tamper underneath the store, as disk corruption or an attacker with database access would.
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE source_blobs SET bytes = ?1, codec = 'identity' WHERE content_hash = ?2",
                rusqlite::params![
                    b"forged evidence of the same length!!!!!!!!!!!!!!!!".to_vec(),
                    address.to_string()
                ],
            )
            .unwrap();
    }

    let store = SqliteStore::open(&path, 5000).unwrap();
    let error = store.get_source_blob(&address).unwrap_err();
    assert!(
        matches!(error, StorageError::Corrupt { .. }),
        "tampered bytes must not be returned as evidence: {error}"
    );
}

/// A row whose codec this build does not recognise must be an error, not a default. Treating an
/// unknown codec as `identity` would return compressed bytes as though they were the original.
#[test]
fn an_unrecognised_codec_is_an_error_rather_than_a_silent_default() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");
    let bytes = b"evidence";
    let address = ContentHash::of(bytes);
    {
        let mut store = SqliteStore::open(&path, 5000).unwrap();
        store.migrate().unwrap();
        store
            .transaction(|writer| writer.put_source_blob(&BlobRequest::standard(bytes, "genuine")))
            .unwrap();
    }
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE source_blobs SET codec = 'brotli' WHERE content_hash = ?1",
                rusqlite::params![address.to_string()],
            )
            .unwrap();
    }

    let store = SqliteStore::open(&path, 5000).unwrap();
    assert!(matches!(
        store.source_blob_metadata(&address).unwrap_err(),
        StorageError::Corrupt { .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// "Canonical deletion does not silently destroy retained evidence"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the reason there is no foreign key. A cleanup that removes canonical records
/// must leave the evidence they were derived from, or the routine maintenance job is also the
/// evidence-destruction job.
#[test]
fn removing_canonical_records_leaves_the_retained_evidence_untouched() {
    let directory = tempfile::TempDir::new().unwrap();
    let mut store = SqliteStore::open(directory.path().join("brolga.sqlite"), 5000).unwrap();
    store.migrate().unwrap();

    let bytes = b"the bundle everything was derived from";
    let address = ContentHash::of(bytes);
    store
        .transaction(|writer| writer.put_source_blob(&BlobRequest::standard(bytes, "import")))
        .unwrap();

    // Delete every canonical record, as a retention sweep over derived data would.
    {
        let connection =
            rusqlite::Connection::open(directory.path().join("brolga.sqlite")).unwrap();
        for table in [
            "entities",
            "relationships",
            "claims",
            "sightings",
            "source_objects",
        ] {
            connection
                .execute(&format!("DELETE FROM {table}"), [])
                .unwrap();
        }
    }

    let store = SqliteStore::open(directory.path().join("brolga.sqlite"), 5000).unwrap();
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
    let retrieved = store
        .get_source_blob(&address)
        .unwrap()
        .expect("evidence survives");
    assert_eq!(retrieved.bytes, bytes);
}

/// Releasing evidence has to be something somebody asked for, by address, with a reason.
#[test]
fn evidence_is_removed_only_by_an_explicit_release() {
    let mut store = store();
    let bytes = b"evidence";
    let address = ContentHash::of(bytes);
    put(&mut store, bytes, "import");

    let released = store
        .transaction(|writer| writer.release_source_blob(&address, "operator request, ticket 42"))
        .unwrap();

    assert!(released);
    assert!(store.get_source_blob(&address).unwrap().is_none());
}

/// A `Hold` is the one class an automated sweep must not be able to act on. Without it, the
/// evidence somebody is actively relying on is exactly what a retention job removes.
#[test]
fn a_held_blob_refuses_release_and_survives_the_attempt() {
    let mut store = store();
    let bytes = b"evidence under investigation";
    let address = ContentHash::of(bytes);

    store
        .transaction(|writer| {
            writer.put_source_blob(&BlobRequest::new(
                bytes,
                RetentionClass::Hold,
                "referenced by an open case",
            ))
        })
        .unwrap();

    let error = store
        .transaction(|writer| writer.release_source_blob(&address, "routine sweep"))
        .unwrap_err();

    assert!(
        matches!(error, StorageError::RetentionRefused { .. }),
        "got {error}"
    );
    assert!(
        store.get_source_blob(&address).unwrap().is_some(),
        "the blob must survive a refused release"
    );
}

// ---------------------------------------------------------------------------------------------
// "Retention decisions are auditable"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the harder half: the audit must survive the blob. An audit log that
/// disappears with the thing it audits answers no question anybody asks afterwards.
#[test]
fn the_audit_trail_outlives_the_blob_it_describes() {
    let mut store = store();
    let bytes = b"evidence";
    let address = ContentHash::of(bytes);

    put(&mut store, bytes, "imported from feed A");
    store
        .transaction(|writer| writer.release_source_blob(&address, "expired under policy P"))
        .unwrap();

    assert!(store.get_source_blob(&address).unwrap().is_none());

    let audit = store.source_blob_audit(&address).unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].action, RetentionAction::Stored);
    assert_eq!(audit[0].reason, "imported from feed A");
    assert_eq!(audit[1].action, RetentionAction::Released);
    assert_eq!(audit[1].reason, "expired under policy P");
}

/// Releasing something that was never there is worth being able to see — it usually means a
/// reference was wrong, or something else already removed it.
#[test]
fn releasing_an_absent_address_reports_false_and_is_still_audited() {
    let mut store = store();
    let address = ContentHash::of(b"never stored");

    let released = store
        .transaction(|writer| writer.release_source_blob(&address, "sweep"))
        .unwrap();

    assert!(!released);
    let audit = store.source_blob_audit(&address).unwrap();
    assert_eq!(audit.len(), 1);
    assert!(audit[0].reason.contains("nothing was retained"));
}

/// Reclassification changes what a sweep may do, so it is a retention decision like any other.
#[test]
fn reclassifying_is_recorded_and_changes_what_a_sweep_may_do() {
    let mut store = store();
    let bytes = b"evidence";
    let address = ContentHash::of(bytes);
    put(&mut store, bytes, "import");

    store
        .transaction(|writer| {
            writer.reclassify_source_blob(&address, RetentionClass::Hold, "case opened")
        })
        .unwrap();

    assert!(
        store
            .transaction(|writer| writer.release_source_blob(&address, "sweep"))
            .is_err(),
        "a reclassified blob must now refuse release"
    );

    let audit = store.source_blob_audit(&address).unwrap();
    assert_eq!(audit.last().unwrap().action, RetentionAction::Reclassified);
    assert!(audit.last().unwrap().reason.contains("hold"));
}

// ---------------------------------------------------------------------------------------------
// "Storage limits fail without partial references"
// ---------------------------------------------------------------------------------------------

/// The criterion. The dangerous failure is not the refusal — it is a canonical record committing
/// alongside a reference to evidence that was never written, which nothing later can repair.
#[test]
fn an_oversized_object_is_refused_and_nothing_in_its_transaction_commits() {
    let mut store = SqliteStore::open_in_memory()
        .unwrap()
        .with_max_blob_bytes(64);
    store.migrate().unwrap();

    let oversized = vec![b'x'; 1024];
    let address = ContentHash::of(&oversized);

    let error = store
        .transaction(|writer| {
            // A canonical write first, so the test proves the *transaction* rolls back rather than
            // that the blob write alone returned early.
            writer.put_source_blob(&BlobRequest::standard(b"small companion", "fine"))?;
            writer.put_source_blob(&BlobRequest::standard(&oversized, "too big"))
        })
        .unwrap_err();

    assert!(
        matches!(error, StorageError::BlobTooLarge { .. }),
        "got {error}"
    );
    assert!(store.get_source_blob(&address).unwrap().is_none());
    assert_eq!(
        store.source_blob_count().unwrap(),
        0,
        "the companion write in the same transaction must have rolled back too",
    );
}

/// The refusal message must name both numbers and say nothing was written, or an operator has to
/// go looking for which half of the batch landed.
#[test]
fn the_refusal_says_what_the_limit_was_and_that_nothing_was_written() {
    let mut store = SqliteStore::open_in_memory()
        .unwrap()
        .with_max_blob_bytes(64);
    store.migrate().unwrap();

    let error = store
        .transaction(|writer| writer.put_source_blob(&BlobRequest::standard(&[b'x'; 100], "big")))
        .unwrap_err();

    let rendered = error.to_string();
    assert!(rendered.contains("100"), "{rendered}");
    assert!(rendered.contains("64"), "{rendered}");
    assert!(rendered.contains("nothing was written"), "{rendered}");
}

/// Accounting has to be usable for a retention report, so the totals must reflect what is on disk
/// rather than what was offered.
#[test]
fn stored_byte_totals_count_what_was_kept_not_what_was_offered() {
    let mut store = store();
    let repetitive = b"the same sentence over and over. ".repeat(500);

    put(&mut store, &repetitive, "compressible");
    put(&mut store, &repetitive, "the same again");

    assert_eq!(store.source_blob_count().unwrap(), 1);
    let stored = store.source_blob_stored_bytes().unwrap();
    assert!(
        stored > 0 && stored < u64::try_from(repetitive.len()).unwrap(),
        "totals reflect compressed size, counted once: {stored} vs {}",
        repetitive.len()
    );
}
