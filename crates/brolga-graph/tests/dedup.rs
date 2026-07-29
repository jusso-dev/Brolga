//! Deduplication, and the decision records it leaves behind.
//!
//! One section per acceptance criterion of [#20](https://github.com/jusso-dev/Brolga/issues/20).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_graph::{
    DEDUP_ALGORITHM, DEDUP_ALGORITHM_VERSION, DedupVerdict, Deduplicator, Observation,
};
use brolga_model::{ContentHash, SourceObject};
use brolga_storage::{GraphDecisionRow, IntelligenceStore, SqliteStore, StoreRead};

/// One observation, built from the two things that actually distinguish observations: the evidence
/// bytes and who published them.
fn seen(record: &str, evidence: &[u8], publisher: &str, record_content: &[u8]) -> Observation {
    let hash = ContentHash::of(evidence);
    Observation {
        record_id: record.to_owned(),
        source_object: SourceObject::derive_id(hash),
        content_hash: hash,
        publisher: publisher.to_owned(),
        record_hash: ContentHash::of(record_content),
    }
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn row(decision: &brolga_graph::DedupDecision) -> GraphDecisionRow {
    GraphDecisionRow {
        kind: "dedup".to_owned(),
        subject: decision.record_id.clone(),
        observation: decision.observation.to_string(),
        compared_with: decision.compared_with.map(|id| id.to_string()),
        verdict: decision.verdict.as_str().to_owned(),
        algorithm: decision.algorithm.to_owned(),
        algorithm_version: decision.algorithm_version,
        reason: decision.reason.to_owned(),
        decided_at: String::new(),
    }
}

// ---------------------------------------------------------------------------------------------
// "Exact and canonical duplicates collapse deterministically"
// ---------------------------------------------------------------------------------------------

/// The same document imported twice contributes nothing. This is the commonest thing that happens
/// to a scheduled feed, and counting it would inflate every total by the import frequency.
#[test]
fn the_same_evidence_from_the_same_publisher_is_an_exact_duplicate() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle-v1", "feed-a", b"record"));
    let second = dedup.observe(seen("r1", b"bundle-v1", "feed-a", b"record"));

    assert_eq!(second.verdict, DedupVerdict::ExactDuplicate);
    assert!(!second.verdict.is_new_evidence());
    assert!(!second.increases_corroboration());
    assert_eq!(dedup.lineage("r1").unwrap().corroboration(), 1);
}

/// One publisher re-exporting the same assertion in a different wrapper is still one voice.
#[test]
fn different_evidence_from_one_publisher_for_the_same_record_is_a_canonical_duplicate() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle-v1", "feed-a", b"record"));
    let second = dedup.observe(seen("r1", b"bundle-reexported", "feed-a", b"record"));

    assert_eq!(second.verdict, DedupVerdict::CanonicalDuplicate);
    assert!(
        second.verdict.is_new_evidence(),
        "new bytes are new evidence"
    );
    assert!(
        !second.increases_corroboration(),
        "but the same publisher saying it twice is not two sources"
    );
    assert_eq!(dedup.lineage("r1").unwrap().corroboration(), 1);
}

/// The criterion's "deterministically". The order copies arrive in must not change the conclusion,
/// or a re-import in a different order would silently change a confidence score.
#[test]
fn the_order_observations_arrive_in_does_not_change_the_corroboration_count() {
    let orderings: [[(&str, &str); 3]; 3] = [
        [
            ("a-bytes", "feed-a"),
            ("b-bytes", "feed-b"),
            ("c-bytes", "feed-c"),
        ],
        [
            ("c-bytes", "feed-c"),
            ("a-bytes", "feed-a"),
            ("b-bytes", "feed-b"),
        ],
        [
            ("b-bytes", "feed-b"),
            ("c-bytes", "feed-c"),
            ("a-bytes", "feed-a"),
        ],
    ];

    let counts: Vec<usize> = orderings
        .iter()
        .map(|ordering| {
            let mut dedup = Deduplicator::new();
            for (evidence, publisher) in ordering {
                dedup.observe(seen("r1", evidence.as_bytes(), publisher, b"record"));
            }
            dedup.lineage("r1").unwrap().corroboration()
        })
        .collect();

    assert_eq!(
        counts,
        vec![3, 3, 3],
        "three independent publishers, always"
    );
}

// ---------------------------------------------------------------------------------------------
// "Updated versions remain historically traceable"
// ---------------------------------------------------------------------------------------------

/// The criterion. Overwriting a record loses what the publisher said before, which is exactly what
/// somebody asks about when the two disagree.
#[test]
fn an_update_keeps_the_earlier_version_rather_than_overwriting_it() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle-v1", "feed-a", b"record-v1"));
    let update = dedup.observe(seen("r1", b"bundle-v2", "feed-a", b"record-v2"));

    assert_eq!(update.verdict, DedupVerdict::Update);

    let lineage = dedup.lineage("r1").unwrap();
    assert_eq!(lineage.revisions(), 1);
    assert_eq!(lineage.versions.len(), 2);
    assert_eq!(lineage.versions[0], ContentHash::of(b"record-v1"));
    assert_eq!(lineage.versions[1], ContentHash::of(b"record-v2"));
}

/// An update is not corroboration. One publisher changing their mind twice is still one publisher.
#[test]
fn repeated_updates_from_one_publisher_do_not_increase_corroboration() {
    let mut dedup = Deduplicator::new();
    for version in 1..=4 {
        dedup.observe(seen(
            "r1",
            format!("bundle-v{version}").as_bytes(),
            "feed-a",
            format!("record-v{version}").as_bytes(),
        ));
    }

    let lineage = dedup.lineage("r1").unwrap();
    assert_eq!(lineage.corroboration(), 1);
    assert_eq!(lineage.revisions(), 3);
}

// ---------------------------------------------------------------------------------------------
// "Known syndicated copies do not increase corroboration"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the sharpest judgement in this module. Two analysts writing independently do
/// not produce identical bytes — not the same whitespace, field order, or timestamps. Identical
/// bytes mean one origin and one or more redistributors.
#[test]
fn byte_identical_evidence_from_a_different_publisher_is_a_copy_not_corroboration() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"the exact same bundle", "upstream", b"record"));
    let copy = dedup.observe(seen(
        "r1",
        b"the exact same bundle",
        "aggregator",
        b"record",
    ));

    assert_eq!(copy.verdict, DedupVerdict::SyndicatedCopy);
    assert!(!copy.increases_corroboration());
    assert_eq!(
        dedup.lineage("r1").unwrap().corroboration(),
        1,
        "one origin, however many redistributors"
    );
}

/// A feed syndicated to five aggregators is still one source. Without this, a widely-mirrored
/// indicator looks like overwhelming consensus.
#[test]
fn one_upstream_mirrored_by_many_aggregators_stays_a_single_source() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"one bundle", "upstream", b"record"));
    for aggregator in ["mirror-a", "mirror-b", "mirror-c", "mirror-d", "mirror-e"] {
        let decision = dedup.observe(seen("r1", b"one bundle", aggregator, b"record"));
        assert_eq!(decision.verdict, DedupVerdict::SyndicatedCopy);
    }

    assert_eq!(dedup.lineage("r1").unwrap().corroboration(), 1);
}

/// The reason must say why, because "syndicated copy" alone reads like a guess. It has to state the
/// inference the decision rests on.
#[test]
fn the_syndication_verdict_explains_the_inference_it_rests_on() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle", "upstream", b"record"));
    let copy = dedup.observe(seen("r1", b"bundle", "aggregator", b"record"));

    assert!(copy.reason.contains("identical bytes"), "{}", copy.reason);
    assert!(
        copy.reason.contains("independent authors"),
        "the inference is stated, not assumed: {}",
        copy.reason
    );
}

// ---------------------------------------------------------------------------------------------
// "Independent reports remain distinct evidence"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the converse of the one above. Collapsing genuine corroboration would be the
/// opposite failure: real agreement discarded as noise.
#[test]
fn different_evidence_from_different_publishers_is_independent_corroboration() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"report from A", "feed-a", b"record"));
    let second = dedup.observe(seen("r1", b"report from B", "feed-b", b"record"));

    assert_eq!(second.verdict, DedupVerdict::IndependentCorroboration);
    assert!(second.increases_corroboration());
    assert_eq!(dedup.lineage("r1").unwrap().corroboration(), 2);
}

/// One publisher must count once however many independent-looking reports they file.
#[test]
fn a_publisher_already_counted_is_not_counted_again() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"report 1", "feed-a", b"record"));
    dedup.observe(seen("r1", b"report 2", "feed-b", b"record"));
    dedup.observe(seen("r1", b"report 3", "feed-b", b"record-changed"));

    assert_eq!(
        dedup.lineage("r1").unwrap().corroboration(),
        2,
        "feed-b's second report is an update, not a third voice"
    );
}

/// The two halves must not interfere: a mirrored copy alongside genuine corroboration must count
/// the real one and not the copy.
#[test]
fn a_mirror_and_a_genuine_second_source_are_told_apart_in_one_run() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"upstream bundle", "upstream", b"record"));
    dedup.observe(seen("r1", b"upstream bundle", "mirror", b"record"));
    dedup.observe(seen("r1", b"independent analysis", "researcher", b"record"));

    let lineage = dedup.lineage("r1").unwrap();
    assert_eq!(
        lineage.corroboration(),
        2,
        "upstream and researcher, not the mirror"
    );

    let verdicts: Vec<_> = lineage
        .decisions
        .iter()
        .map(|decision| decision.verdict)
        .collect();
    assert_eq!(
        verdicts,
        vec![
            DedupVerdict::IndependentCorroboration,
            DedupVerdict::SyndicatedCopy,
            DedupVerdict::IndependentCorroboration,
        ]
    );
}

/// Records are judged independently of each other. A duplicate of one must not affect another.
#[test]
fn records_are_judged_independently_of_one_another() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle", "feed-a", b"record-1"));
    dedup.observe(seen("r2", b"bundle", "feed-a", b"record-2"));

    assert_eq!(dedup.record_ids(), vec!["r1", "r2"]);
    assert_eq!(dedup.lineage("r1").unwrap().corroboration(), 1);
    assert_eq!(dedup.lineage("r2").unwrap().corroboration(), 1);
}

// ---------------------------------------------------------------------------------------------
// "Every decision exposes inputs, algorithm version, and reasons"
// ---------------------------------------------------------------------------------------------

/// The criterion. A decision nobody can re-derive is a decision nobody can challenge.
#[test]
fn every_decision_names_what_it_compared_which_algorithm_decided_and_why() {
    let mut dedup = Deduplicator::new();
    let first = seen("r1", b"bundle-a", "feed-a", b"record");
    dedup.observe(first.clone());
    let second = dedup.observe(seen("r1", b"bundle-b", "feed-b", b"record"));

    assert_eq!(second.record_id, "r1");
    assert_eq!(second.compared_with, Some(first.source_object));
    assert_eq!(second.algorithm, DEDUP_ALGORITHM);
    assert_eq!(second.algorithm_version, DEDUP_ALGORITHM_VERSION);
    assert!(second.reason.len() > 20, "a reason, not a label");
}

/// The first observation has nothing to compare against, and must say so rather than inventing a
/// comparison.
#[test]
fn the_first_observation_records_that_it_had_nothing_to_compare_against() {
    let mut dedup = Deduplicator::new();
    let first = dedup.observe(seen("r1", b"bundle", "feed-a", b"record"));

    assert_eq!(first.compared_with, None);
    assert!(
        first.reason.contains("first observation"),
        "{}",
        first.reason
    );
}

/// Decisions persist, and read back with everything a caller needs to explain them.
#[test]
fn decisions_persist_and_read_back_with_their_algorithm_and_reason() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle", "upstream", b"record"));
    dedup.observe(seen("r1", b"bundle", "mirror", b"record"));

    let mut store = store();
    store
        .transaction(|write| {
            for decision in dedup.decisions() {
                write.record_graph_decision(&row(decision))?;
            }
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("dedup", "r1").unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[1].verdict, "syndicated_copy");
    assert_eq!(stored[1].algorithm, DEDUP_ALGORITHM);
    assert_eq!(stored[1].algorithm_version, DEDUP_ALGORITHM_VERSION);
    assert!(stored[1].reason.contains("identical bytes"));
    assert!(stored[1].compared_with.is_some());
}

/// Re-running over the same inputs must update one row, not append. Re-running is what happens on
/// every re-import, and a decision log that grows each time is one nobody reads.
#[test]
fn re_running_the_algorithm_updates_one_row_rather_than_appending() {
    let mut store = store();

    for _ in 0..3 {
        let mut dedup = Deduplicator::new();
        dedup.observe(seen("r1", b"bundle", "upstream", b"record"));
        dedup.observe(seen("r1", b"bundle", "mirror", b"record"));

        store
            .transaction(|write| {
                for decision in dedup.decisions() {
                    write.record_graph_decision(&row(decision))?;
                }
                Ok(())
            })
            .unwrap();
    }

    assert_eq!(
        store.graph_decisions_for("dedup", "r1").unwrap().len(),
        2,
        "three runs, still two decisions"
    );
    assert_eq!(
        store
            .graph_decision_count("dedup", "syndicated_copy")
            .unwrap(),
        1
    );
}

/// Recording *why* something was decided does not change what the graph says, so it must not move
/// the graph version — otherwise every re-run looks like a graph change to an incremental consumer.
#[test]
fn recording_a_decision_does_not_move_the_graph_version() {
    let mut dedup = Deduplicator::new();
    dedup.observe(seen("r1", b"bundle", "feed-a", b"record"));

    let mut store = store();
    let before = store.graph_version().unwrap();
    store
        .transaction(|write| {
            for decision in dedup.decisions() {
                write.record_graph_decision(&row(decision))?;
            }
            Ok(())
        })
        .unwrap();

    assert_eq!(store.graph_version().unwrap(), before);
}

/// A changed verdict for the same inputs must replace the old one rather than sit beside it, or two
/// contradictory decisions both claim to be current.
#[test]
fn a_changed_verdict_for_the_same_inputs_replaces_the_earlier_one() {
    let mut store = store();
    let observation = seen("r1", b"bundle", "feed-a", b"record");

    let mut original = row(&{
        let mut dedup = Deduplicator::new();
        dedup.observe(observation.clone())
    });
    original.verdict = "independent_corroboration".to_owned();

    let mut revised = original.clone();
    revised.verdict = "syndicated_copy".to_owned();
    revised.reason = "reclassified after a syndication relationship was declared".to_owned();

    store
        .transaction(|write| {
            assert!(write.record_graph_decision(&original)?, "first time");
            assert!(!write.record_graph_decision(&revised)?, "already seen");
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("dedup", "r1").unwrap();
    assert_eq!(stored.len(), 1, "one decision, not two contradictory ones");
    assert_eq!(stored[0].verdict, "syndicated_copy");
    assert!(stored[0].reason.contains("reclassified"));
}

/// Identity derives from what was decided *about*, never from the verdict or the clock — otherwise
/// a re-classification would orphan the row it was meant to replace.
#[test]
fn decision_identity_ignores_the_verdict_the_reason_and_the_clock() {
    let base = GraphDecisionRow {
        kind: "dedup".to_owned(),
        subject: "r1".to_owned(),
        observation: "obs-1".to_owned(),
        compared_with: Some("obs-0".to_owned()),
        verdict: "independent_corroboration".to_owned(),
        algorithm: DEDUP_ALGORITHM.to_owned(),
        algorithm_version: 1,
        reason: "first wording".to_owned(),
        decided_at: "2026-01-01T00:00:00Z".to_owned(),
    };

    let mut different = base.clone();
    different.verdict = "syndicated_copy".to_owned();
    different.reason = "a completely different explanation".to_owned();
    different.decided_at = "2026-07-29T00:00:00Z".to_owned();
    assert_eq!(base.derive_id(), different.derive_id());

    let mut other_subject = base.clone();
    other_subject.subject = "r2".to_owned();
    assert_ne!(base.derive_id(), other_subject.derive_id());
}
