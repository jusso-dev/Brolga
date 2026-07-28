//! Strict and permissive ingestion, quarantine, and metric reconciliation.
//!
//! One section per acceptance criterion of [#17](https://github.com/jusso-dev/Brolga/issues/17).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::testing::{TEST_MEDIA_TYPE, TestRecordsParser};
use brolga_ingest::{Document, IngestError, IngestMode, ParserRegistry, Pipeline};
use brolga_model::{
    ContentHash, ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, QuarantineStage, RecordKind, SqliteStore, StoreRead};

/// Two good records and two bad ones, so every count in a report has a distinct expected value.
const MIXED: &[u8] = b"entity:Alpha\nnot a record at all\nentity:Beta\nentity:\n";

fn pipeline(mode: IngestMode) -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    Pipeline::with_defaults(registry).in_mode(mode)
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn document(bytes: &[u8]) -> Document<'_> {
    Document {
        bytes,
        media_type: MediaType::new(TEST_MEDIA_TYPE).unwrap(),
        file_name: None,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("mode-test").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

fn ingest(store: &mut SqliteStore, mode: IngestMode, bytes: &[u8]) -> brolga_ingest::IngestReport {
    pipeline(mode)
        .ingest_batch(
            store,
            &[document(bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// "Strict mode rejects invalid input atomically as documented"
// ---------------------------------------------------------------------------------------------

/// The criterion. Importing the readable half of a feed that has started producing records Brolga
/// cannot read is how a partial dataset gets mistaken for a complete one.
#[test]
fn strict_mode_writes_nothing_at_all_when_any_record_is_rejected() {
    let mut store = store();
    let error = pipeline(IngestMode::Strict)
        .ingest_batch(
            &mut store,
            &[document(MIXED)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    assert!(
        matches!(error, IngestError::ParserFailed { .. }),
        "got {error:?}"
    );
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
    assert_eq!(store.count(RecordKind::SourceObject).unwrap(), 0);
    assert_eq!(
        store.source_blob_count().unwrap(),
        0,
        "not even the evidence is retained from a batch that did not land"
    );
    assert_eq!(
        store.quarantine_count().unwrap(),
        0,
        "strict mode refuses; it does not quarantine half a batch"
    );
}

/// Strict is the default, so a caller who never thinks about modes gets the safe one.
#[test]
fn strict_is_the_default_mode() {
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    assert_eq!(Pipeline::with_defaults(registry).mode(), IngestMode::Strict);
    assert!(!IngestMode::Strict.tolerates_rejections());
}

/// A rejection in one document must take the other documents in the batch with it, or "atomic"
/// means atomic per document, which is not what an operator reads it as.
#[test]
fn one_rejected_record_takes_the_whole_batch_including_other_documents() {
    let good = b"entity:Alpha\n".to_vec();
    let mut store = store();

    pipeline(IngestMode::Strict)
        .ingest_batch(
            &mut store,
            &[document(&good), document(MIXED)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
}

/// The diagnostic has to say how many were rejected and show one, or an operator cannot tell a
/// single typo from a feed that changed format.
#[test]
fn the_strict_refusal_says_how_many_were_rejected_and_shows_one() {
    let mut store = store();
    let error = pipeline(IngestMode::Strict)
        .ingest_batch(
            &mut store,
            &[document(MIXED)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    let rendered = error.to_string();
    assert!(rendered.contains("2 record(s) were rejected"), "{rendered}");
    assert!(rendered.contains("strict mode"), "{rendered}");
    assert!(rendered.contains("entity:"), "{rendered}");
}

// ---------------------------------------------------------------------------------------------
// "Permissive mode persists valid records and quarantines invalid ones"
// ---------------------------------------------------------------------------------------------

/// The criterion. Both halves matter: the good records land, *and* the bad ones are kept rather
/// than logged and dropped, so the loss is inspectable instead of a number in a summary.
#[test]
fn permissive_mode_keeps_the_good_records_and_quarantines_the_bad_ones() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, MIXED);

    assert_eq!(report.inserted, 2, "Alpha and Beta landed");
    assert_eq!(report.rejected, 2, "the malformed line and the empty name");
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    assert_eq!(store.quarantine_count().unwrap(), 2);
}

/// A quarantine that grows on every retry of a broken feed is one nobody reads.
#[test]
fn re_offering_the_same_bad_records_updates_one_row_rather_than_appending() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, MIXED);
    ingest(&mut store, IngestMode::Permissive, MIXED);
    ingest(&mut store, IngestMode::Permissive, MIXED);

    assert_eq!(
        store.quarantine_count().unwrap(),
        2,
        "still two distinct problems"
    );
    assert_eq!(
        store.quarantine_occurrences().unwrap(),
        6,
        "seen three times each"
    );
}

/// Permissive must still be all-or-nothing on genuine infrastructure failures — it tolerates bad
/// *records*, not a broken write.
#[test]
fn permissive_mode_still_rolls_back_when_storage_itself_refuses() {
    use brolga_storage::StorageError;

    let mut store = SqliteStore::open_in_memory()
        .unwrap()
        .with_max_blob_bytes(8);
    store.migrate().unwrap();

    let error = pipeline(IngestMode::Permissive)
        .ingest_batch(
            &mut store,
            &[document(MIXED)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    assert!(
        matches!(
            error,
            IngestError::Storage {
                source: StorageError::BlobTooLarge { .. }
            }
        ),
        "got {error:?}"
    );
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
    assert_eq!(store.quarantine_count().unwrap(), 0);
}

// ---------------------------------------------------------------------------------------------
// "Quarantine retains source and parser context"
// ---------------------------------------------------------------------------------------------

/// The criterion. A rejection without its source and parser can be counted but not diagnosed —
/// nobody can answer "what exactly did they send us?" from a tally.
#[test]
fn a_quarantined_record_names_its_source_parser_stage_and_position() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, MIXED);

    let address = ContentHash::of(MIXED);
    let quarantined = store.quarantined_for_source(&address).unwrap();
    assert_eq!(quarantined.len(), 2);

    let record = &quarantined[0];
    assert_eq!(record.source_hash, address);
    assert_eq!(record.parser, "brolga.test.records");
    assert_eq!(record.parser_version, 1);
    assert_eq!(record.stage, QuarantineStage::Parsing);
    assert!(record.byte_offset.is_some(), "the position in the document");
    assert!(
        !record.reason_kind.is_empty(),
        "a machine-readable category"
    );
    assert!(record.fragment.is_some(), "what was actually rejected");
}

/// The retained original is what makes a quarantined record diagnosable. Being able to fetch the
/// bytes back from the address the quarantine row names is the whole point of the link.
#[test]
fn the_source_a_quarantined_record_names_is_retrievable() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, MIXED);

    let quarantined = store
        .quarantined_for_source(&ContentHash::of(MIXED))
        .unwrap();
    let retrieved = store
        .get_source_blob(&quarantined[0].source_hash)
        .unwrap()
        .expect("the original is retained");
    assert_eq!(retrieved.bytes, MIXED);
}

/// Being rejected does not make a value safe. A quarantine table is read through terminals, and an
/// escape sequence in a rejected indicator would be rendered by whatever displays it.
#[test]
fn a_quarantined_fragment_carries_no_control_characters() {
    let hostile = b"entity:Alpha\nnot a record \x1b[31mred\x07 at all\n".to_vec();
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, &hostile);

    let quarantined = store
        .quarantined_for_source(&ContentHash::of(&hostile))
        .unwrap();
    let fragment = quarantined[0].fragment.as_deref().unwrap();
    assert!(
        !fragment.chars().any(char::is_control),
        "escape survived into quarantine: {fragment:?}"
    );
    assert!(fragment.contains("red"), "the readable content is kept");
}

/// A retry must be visible as a retry, not as a new problem, and the first sighting must not move.
#[test]
fn a_repeated_rejection_keeps_its_first_sighting_and_counts_up() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, MIXED);
    let first = store
        .quarantined_for_source(&ContentHash::of(MIXED))
        .unwrap();

    ingest(&mut store, IngestMode::Permissive, MIXED);
    let second = store
        .quarantined_for_source(&ContentHash::of(MIXED))
        .unwrap();

    assert_eq!(first[0].id, second[0].id, "same identity");
    assert_eq!(first[0].first_seen_at, second[0].first_seen_at);
    assert_eq!(first[0].occurrences, 1);
    assert_eq!(second[0].occurrences, 2);
}

// ---------------------------------------------------------------------------------------------
// "Metrics reconcile total, accepted, duplicate, and rejected counts"
// ---------------------------------------------------------------------------------------------

/// The criterion. A summary whose parts do not sum to its total is worse than no summary: it looks
/// authoritative while hiding whatever fell between the categories.
#[test]
fn accepted_and_rejected_account_for_every_record_offered() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, MIXED);

    assert!(report.reconciles(), "{report:?}");
    assert_eq!(report.total, 4);
    assert_eq!(report.accepted(), 2);
    assert_eq!(report.rejected, 2);
    assert_eq!(report.duplicates(), 0, "nothing was already present");
}

/// A record that was already present *was* accepted. Excluding it would make a re-import look like
/// it lost records.
#[test]
fn a_re_import_reconciles_with_everything_counted_as_a_duplicate() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, MIXED);
    let second = ingest(&mut store, IngestMode::Permissive, MIXED);

    assert!(second.reconciles(), "{second:?}");
    assert_eq!(second.total, 4);
    assert_eq!(second.accepted(), 2);
    assert_eq!(second.duplicates(), 2, "both records were already present");
    assert_eq!(second.inserted, 0);
    assert_eq!(second.rejected, 2);
}

/// A clean batch must reconcile too — the property is not only about the interesting case.
#[test]
fn a_batch_with_nothing_rejected_still_reconciles() {
    let mut store = store();
    let report = ingest(
        &mut store,
        IngestMode::Permissive,
        b"entity:Alpha\nentity:Beta\n",
    );

    assert!(report.reconciles(), "{report:?}");
    assert_eq!(report.rejected, 0);
    assert_eq!(report.total, report.accepted());
}

/// The report has to say which mode produced it, or two reports with different numbers are
/// indistinguishable from one pipeline behaving inconsistently.
#[test]
fn the_report_says_which_mode_produced_it() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, b"entity:Alpha\n");
    assert_eq!(report.mode, IngestMode::Permissive);
    assert_eq!(report.mode.to_string(), "permissive");
}

// ---------------------------------------------------------------------------------------------
// "Retries do not duplicate accepted records"
// ---------------------------------------------------------------------------------------------

/// The criterion. A retried import is the normal case — a network blip, a scheduled re-run, an
/// operator re-running a command — and each one must converge rather than accumulate.
#[test]
fn retrying_an_import_converges_rather_than_accumulating_records() {
    let mut store = store();
    for _ in 0..5 {
        ingest(&mut store, IngestMode::Permissive, MIXED);
    }

    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    assert_eq!(store.source_blob_count().unwrap(), 1);
    assert_eq!(store.quarantine_count().unwrap(), 2);
}

/// A retry after a strict failure must be able to succeed once the feed is fixed, and must not have
/// left anything behind from the failed attempt.
#[test]
fn a_strict_failure_leaves_nothing_that_would_taint_a_later_successful_retry() {
    let mut store = store();

    pipeline(IngestMode::Strict)
        .ingest_batch(
            &mut store,
            &[document(MIXED)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    let fixed = b"entity:Alpha\nentity:Beta\n".to_vec();
    let report = ingest(&mut store, IngestMode::Strict, &fixed);

    assert_eq!(report.inserted, 2);
    assert!(report.reconciles());
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    assert_eq!(
        store.source_blob_count().unwrap(),
        1,
        "only the successful batch's evidence is retained"
    );
}

/// The summary is what an operator reads. It must carry every number they act on, including the
/// zeroes — a summary that omits them makes "nothing was rejected" and "rejection was not measured"
/// look identical.
#[test]
fn the_summary_carries_every_number_including_the_zeroes() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, MIXED);
    let summary = report.summary();

    assert!(summary.starts_with("permissive ingest:"), "{summary}");
    for expected in [
        "4 offered",
        "2 accepted",
        "2 rejected",
        "0 updated",
        "0 unchanged",
    ] {
        assert!(
            summary.contains(expected),
            "missing {expected:?} in {summary}"
        );
    }
    assert!(
        !summary.contains("WARNING"),
        "a reconciling report must not warn: {summary}"
    );
}

/// If the numbers ever stop adding up, the summary has to say so rather than print them anyway.
#[test]
fn a_summary_that_does_not_reconcile_says_so() {
    let mut store = store();
    let mut report = ingest(&mut store, IngestMode::Permissive, MIXED);
    report.total = report.total.saturating_add(1);

    assert!(!report.reconciles());
    assert!(
        report.summary().contains("do not reconcile"),
        "{}",
        report.summary()
    );
}
