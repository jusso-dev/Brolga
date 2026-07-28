//! Integration tests for the pipeline against a real store.
//!
//! Each test names the acceptance criterion from
//! [#11](https://github.com/jusso-dev/Brolga/issues/11) it holds, because a test named after the
//! function it calls tells a later reader nothing about what breaks if it fails.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::testing::{CatchAllParser, TEST_MEDIA_TYPE, TestRecordsParser};
use brolga_ingest::{Document, IngestError, ParserRegistry, Pipeline};
use brolga_model::{
    ShortText, Timestamp, TransformationStage,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::{CancellationToken, InputLimits, ResourceLimits};
use brolga_storage::{IntelligenceStore, RecordKind, SqliteStore, StoreRead};

fn pipeline() -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    registry.register(CatchAllParser::boxed());
    Pipeline::with_defaults(registry)
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn origin() -> SourceOrigin {
    SourceOrigin::NetworkFeed {
        publisher: ShortText::new("integration-test").unwrap(),
        location: None,
    }
}

fn document(bytes: &[u8]) -> Document<'_> {
    Document {
        bytes,
        media_type: MediaType::new(TEST_MEDIA_TYPE).unwrap(),
        file_name: None,
        origin: origin(),
        retrieved_at: Timestamp::unix_epoch(),
    }
}

// ---------------------------------------------------------------------------------------------
// "Every stage records metrics and transformations"
// ---------------------------------------------------------------------------------------------

/// A stage missing from the report is indistinguishable from a stage that ran and did nothing, so
/// every stage must appear whether or not it changed anything.
#[test]
fn every_stage_appears_in_the_report_and_in_the_transformation_chain() {
    let report = pipeline()
        .prepare(
            &document(b"entity:Alpha\nentity:Beta\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let stages: Vec<_> = report.stages.iter().map(|metric| metric.stage).collect();
    assert_eq!(
        stages,
        vec![
            TransformationStage::Retrieval,
            TransformationStage::Detection,
            TransformationStage::Parsing,
            TransformationStage::Validation,
            TransformationStage::Canonicalisation,
        ],
        "every stage reports, in pipeline order"
    );

    for stage in &stages {
        assert!(
            report.chain.includes(*stage),
            "stage {stage} is in the metrics but missing from the chain"
        );
    }
}

/// Metrics have to be real counts, not placeholders. Records entering validation must equal the
/// records parsing produced, or the two numbers are not measuring the same thing.
#[test]
fn stage_metrics_carry_real_counts_that_join_up_between_stages() {
    let report = pipeline()
        .prepare(
            &document(b"entity:Alpha\nentity:Beta\nentity:Gamma\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let by_stage = |stage| {
        report
            .stages
            .iter()
            .find(|metric| metric.stage == stage)
            .unwrap()
            .clone()
    };

    let parsing = by_stage(TransformationStage::Parsing);
    let validation = by_stage(TransformationStage::Validation);
    let canonicalisation = by_stage(TransformationStage::Canonicalisation);

    assert_eq!(parsing.records_out, 3);
    assert_eq!(
        validation.records_in, parsing.records_out,
        "validation must receive exactly what parsing produced"
    );
    assert_eq!(validation.records_out, 3, "nothing was dropped");
    assert_eq!(canonicalisation.records_out, 3);
    assert_eq!(
        by_stage(TransformationStage::Retrieval).bytes_considered,
        38,
        "retrieval measures the document as retrieved"
    );
}

/// The chain fingerprint is what a caller compares to answer "did how we read this change?". It
/// must be a function of the pipeline and parser, not of when it ran.
#[test]
fn the_chain_fingerprint_is_stable_across_runs_of_the_same_bytes() {
    let bytes = b"entity:Alpha\n";
    let first = pipeline()
        .prepare(&document(bytes), &CancellationToken::never_cancelled())
        .unwrap();
    let second = pipeline()
        .prepare(&document(bytes), &CancellationToken::never_cancelled())
        .unwrap();

    assert_eq!(first.chain_fingerprint(), second.chain_fingerprint());
    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(first.source_object, second.source_object);
}

/// The parser is stamped into the chain by identifier and version, so provenance can distinguish
/// two results that came from different versions of nominally the same parser.
#[test]
fn the_chain_names_the_parser_that_actually_ran() {
    let report = pipeline()
        .prepare(
            &document(b"entity:Alpha\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let parsing = report
        .chain
        .steps()
        .iter()
        .find(|step| step.stage == TransformationStage::Parsing)
        .unwrap();

    assert_eq!(parsing.algorithm.as_str(), "brolga.test.records");
    assert_eq!(parsing.algorithm_version, report.parser_version);
}

// ---------------------------------------------------------------------------------------------
// "Batch ordering does not change canonical output"
// ---------------------------------------------------------------------------------------------

/// The acceptance criterion, against a real database. Two batches holding the same documents in
/// different orders must leave the store in the same state and issue the same writes.
#[test]
fn batch_order_changes_neither_the_writes_nor_the_stored_result() {
    let alpha = b"entity:Alpha\nentity:Beta\n".to_vec();
    let gamma = b"entity:Gamma\n".to_vec();

    let forwards = {
        let mut store = store();
        let report = pipeline()
            .ingest_batch(
                &mut store,
                &[document(&alpha), document(&gamma)],
                &CancellationToken::never_cancelled(),
            )
            .unwrap();
        (
            report.inserted,
            report.source_objects,
            store.count(RecordKind::Entity).unwrap(),
        )
    };

    let backwards = {
        let mut store = store();
        let report = pipeline()
            .ingest_batch(
                &mut store,
                &[document(&gamma), document(&alpha)],
                &CancellationToken::never_cancelled(),
            )
            .unwrap();
        (
            report.inserted,
            report.source_objects,
            store.count(RecordKind::Entity).unwrap(),
        )
    };

    assert_eq!(forwards, backwards);
    assert_eq!(forwards.0, 3, "three distinct entities either way");
}

/// Ordering *within* a document must not reach the result either, which is the half a
/// document-level test would miss.
#[test]
fn record_order_within_a_document_does_not_change_the_canonical_order() {
    let ascending = pipeline()
        .prepare(
            &document(b"entity:Alpha\nentity:Beta\nentity:Gamma\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    let descending = pipeline()
        .prepare(
            &document(b"entity:Gamma\nentity:Beta\nentity:Alpha\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let keys = |report: &brolga_ingest::DocumentReport| -> Vec<_> {
        report
            .records
            .iter()
            .map(brolga_ingest::ParsedRecord::sort_key)
            .collect()
    };

    assert_eq!(keys(&ascending), keys(&descending));
}

/// The same bytes offered twice address one source object, not two. A feed re-publishing a file is
/// normal, and counting it twice would inflate every "how many sources said this" answer.
#[test]
fn the_same_document_twice_in_one_batch_yields_one_source_object() {
    let bytes = b"entity:Alpha\n".to_vec();
    let mut store = store();
    let report = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes), document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(report.source_objects, 1);
    assert_eq!(store.count(RecordKind::SourceObject).unwrap(), 1);
}

/// Re-ingesting unchanged data must be reported as unchanged rather than as a write, or every
/// scheduled re-import would look like new intelligence.
#[test]
fn re_ingesting_the_same_batch_reports_unchanged_rather_than_inserted() {
    let bytes = b"entity:Alpha\nentity:Beta\n".to_vec();
    let mut store = store();

    let first = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    assert_eq!(first.inserted, 2);

    let second = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    assert_eq!(second.inserted, 0);
    assert_eq!(second.unchanged, 2);
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
}

// ---------------------------------------------------------------------------------------------
// Batch transaction semantics
// ---------------------------------------------------------------------------------------------

/// A half-written batch is worse than a rejected one: it looks like success to anything that only
/// counts rows. One bad document must leave the store exactly as it was.
#[test]
fn one_bad_document_rolls_the_whole_batch_back() {
    let good = b"entity:Alpha\n".to_vec();
    let bad = b"entity:Alpha\nnot a record at all\n".to_vec();

    let mut store = store();
    let error = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&good), document(&bad)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    assert!(
        matches!(error, IngestError::ParserFailed { .. }),
        "got {error:?}"
    );
    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        0,
        "the good document must not have landed"
    );
    assert_eq!(store.count(RecordKind::SourceObject).unwrap(), 0);
}

/// Cancellation must be observed before the transaction opens, not only inside it.
#[test]
fn a_cancelled_token_writes_nothing_and_says_it_was_cancelled() {
    let bytes = b"entity:Alpha\n".to_vec();
    let mut store = store();

    let error = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::already_cancelled(),
        )
        .unwrap_err();

    assert!(
        matches!(error, IngestError::Cancelled { .. }),
        "got {error:?}"
    );
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
}

// ---------------------------------------------------------------------------------------------
// "Unknown formats return actionable diagnostics" and limits
// ---------------------------------------------------------------------------------------------

/// The criterion. The message must carry what was tried, not only that nothing worked.
#[test]
fn an_unreadable_document_names_every_parser_that_declined() {
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    let pipeline = Pipeline::with_defaults(registry);

    let bytes = b"<stix:Bundle/>".to_vec();
    let error = pipeline
        .prepare(
            &Document {
                bytes: &bytes,
                media_type: MediaType::new("application/xml").unwrap(),
                file_name: None,
                origin: origin(),
                retrieved_at: Timestamp::unix_epoch(),
            },
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    let rendered = error.to_string();
    assert!(rendered.contains("brolga.test.records"), "{rendered}");
    assert!(rendered.contains("no `entity:` line"), "{rendered}");
}

/// The record limit is the pipeline's, applied to whatever the parser produced. A parser cannot
/// exceed it by not checking.
#[test]
fn a_parser_overrunning_the_record_limit_is_stopped_by_the_pipeline() {
    let mut limits = ResourceLimits::defaults();
    limits.input.max_records = InputLimits::MAX_RECORDS.min;

    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    let pipeline = Pipeline::new(registry, limits);

    let bytes = b"entity:Alpha\nentity:Beta\n".to_vec();
    let error = pipeline
        .prepare(&document(&bytes), &CancellationToken::never_cancelled())
        .unwrap_err();

    assert!(
        matches!(error, IngestError::TooManyRecords { .. }),
        "got {error:?}"
    );
}

/// A parser's note carries text from the document, so it must arrive stripped of control
/// characters — a terminal escape in a feed's comment would otherwise be rendered by whatever
/// reads the note.
#[test]
fn a_note_derived_from_the_document_carries_no_control_characters() {
    let bytes = b"# a \x1b[31mred\x1b[0m comment\nentity:Alpha\n".to_vec();
    let report = pipeline()
        .prepare(&document(&bytes), &CancellationToken::never_cancelled())
        .unwrap();

    assert_eq!(report.notes.len(), 1);
    let note = report.notes[0].as_str();
    assert!(
        !note.contains('\x1b'),
        "escape survived into a note: {note:?}"
    );
    assert!(note.contains("red"), "{note}");
}

/// Selection must be explainable after the fact, from the report alone.
#[test]
fn the_report_explains_which_parser_was_chosen_and_over_what() {
    let report = pipeline()
        .prepare(
            &document(b"entity:Alpha\n"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert!(
        report.selection.contains("selected brolga.test.records"),
        "{}",
        report.selection
    );
    assert!(
        report.selection.contains("brolga.test.catch-all"),
        "the explanation must name what it beat: {}",
        report.selection
    );
}

// ---------------------------------------------------------------------------------------------
// Source-object retention (#16), the contract #13-#15 depend on
// ---------------------------------------------------------------------------------------------

/// Ingestion retains the original bytes by default. A canonical record whose source was discarded
/// cannot be argued about later — a disagreement with an upstream platform becomes unresolvable.
#[test]
fn ingestion_retains_the_original_bytes_and_they_read_back_exactly() {
    use brolga_model::ContentHash;

    let bytes = b"entity:Alpha\nentity:Beta\n".to_vec();
    let mut store = store();
    let report = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(report.retained_sources, 1);
    let retrieved = store
        .get_source_blob(&ContentHash::of(&bytes))
        .unwrap()
        .expect("the source bytes are retained");
    assert_eq!(retrieved.bytes, bytes);
}

/// Re-importing the same file must not re-store it. A scheduled daily import would otherwise
/// multiply the disk cost of retention by its frequency.
#[test]
fn re_ingesting_the_same_document_deduplicates_the_retained_bytes() {
    let bytes = b"entity:Alpha\n".to_vec();
    let mut store = store();

    let first = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    let second = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(first.retained_sources, 1);
    assert_eq!(second.retained_sources, 0);
    assert_eq!(second.deduplicated_sources, 1);
    assert_eq!(store.source_blob_count().unwrap(), 1);
}

/// Discarding evidence has to be something the call site says out loud.
#[test]
fn a_pipeline_can_be_told_not_to_retain_and_then_retains_nothing() {
    use brolga_model::ContentHash;

    let bytes = b"entity:Alpha\n".to_vec();
    let mut store = store();
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());

    let report = Pipeline::with_defaults(registry)
        .without_retaining_sources()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(report.retained_sources, 0);
    assert!(
        store
            .get_source_blob(&ContentHash::of(&bytes))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        1,
        "records still landed"
    );
}

/// A refused blob must take the whole batch with it. The dangerous outcome is not the refusal —
/// it is a canonical record committing beside a reference to evidence that was never written.
#[test]
fn evidence_refused_for_size_rolls_back_the_canonical_records_too() {
    use brolga_storage::StorageError;

    let bytes = b"entity:Alpha\nentity:Beta\n".to_vec();
    let mut store = SqliteStore::open_in_memory()
        .unwrap()
        .with_max_blob_bytes(8);
    store.migrate().unwrap();

    let error = pipeline()
        .ingest_batch(
            &mut store,
            &[document(&bytes)],
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
    assert_eq!(store.count(RecordKind::SourceObject).unwrap(), 0);
    assert_eq!(store.source_blob_count().unwrap(), 0);
}
