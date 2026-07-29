//! Graph checkpoints and material delta comparison.
//!
//! One section per acceptance criterion of [#25](https://github.com/jusso-dev/Brolga/issues/25),
//! plus a section for the bounds every comparison is held to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use brolga_graph::{
    CHECKPOINT_ALGORITHM, CHECKPOINT_ALGORITHM_VERSION, CaptureError, Change, ChangeCategory,
    Checkpoint, CheckpointRequest, ConfidenceBand, Delta, DeltaLimits, DeltaRefused,
    DeltaTruncation, EXCLUDED_FROM_MATERIALITY, FacetState, MaterialFacet, RecordClass, RecordKey,
    SourceSyncState, Succession, SuccessionKind, TraversalLimits, TraversalPolicy,
    TraversalRequest, Truncation, capture, compare, fingerprint_entity, fingerprint_relationship,
    shape_of,
};
use brolga_model::{
    Claim, ConfidenceBreakdown, ConfidenceScore, ContentHash, Entity, EntityKind, Id,
    LifecycleStatus, Marking, MarkingSet, NodeRef, Provenance, RecordOrigin, Relationship,
    RelationshipKind, ShortText, Sighting, SourceObject, SyntheticOrigin, SyntheticReason,
    TemporalState, Timestamp, TlpLevel, TransformationChain, TransformationStage,
    TransformationStep, UntrustedText,
};
use brolga_security::{CancellationToken, Cancelled};
use brolga_storage::{
    BlobMetadata, CheckpointSummary, Direction, EdgeQuery, EntityQuery, GraphDecisionRow,
    IntelligenceStore, Page, QuarantineRecord, RecordKind, RetentionEvent, RetrievedBlob,
    SqliteStore, StorageError, StoreRead,
};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn synthetic() -> RecordOrigin {
    RecordOrigin::Synthetic {
        origin: SyntheticOrigin::new(
            SyntheticReason::Fixture,
            ShortText::new("checkpoint-test").unwrap(),
        ),
    }
}

/// A source-derived origin citing one piece of evidence, for the source facet.
fn from_evidence(bytes: &[u8]) -> RecordOrigin {
    let hash = ContentHash::of(bytes);
    let step = TransformationStep::new(
        TransformationStage::Parsing,
        ShortText::new("checkpoint-test").unwrap(),
        1,
    );
    let chain = TransformationChain::single(step).unwrap();
    RecordOrigin::source_derived(
        Provenance::from_source(SourceObject::derive_id(hash), chain).unwrap(),
    )
}

fn node(name: &str) -> NodeRef {
    NodeRef::Entity(Id::derive(&["entity", name]))
}

fn entity(name: &str) -> Entity {
    Entity::new(
        Id::derive(&["entity", name]),
        EntityKind::ThreatActor,
        UntrustedText::new(name).unwrap(),
        synthetic(),
    )
}

fn uses(from: &str, to: &str) -> Relationship {
    Relationship::new(RelationshipKind::Uses, node(from), node(to), synthetic())
}

fn at(when: &str) -> Timestamp {
    Timestamp::parse_rfc3339(when).unwrap()
}

fn now() -> Timestamp {
    at("2026-07-29T00:00:00Z")
}

fn write(store: &mut SqliteStore, entities: &[Entity], edges: &[Relationship]) {
    store
        .transaction(|writer| {
            for record in entities {
                writer.upsert_entity(record)?;
            }
            for edge in edges {
                writer.upsert_relationship(edge)?;
            }
            Ok(())
        })
        .unwrap();
}

/// Two actors, a tool, and the edges between them. Small enough to reason about, large enough that
/// a delta has somewhere to go wrong.
fn seed(store: &mut SqliteStore) {
    write(
        store,
        &[entity("hub"), entity("tool"), entity("other")],
        &[uses("hub", "tool"), uses("hub", "other")],
    );
}

fn request() -> TraversalRequest {
    TraversalRequest::starting_at(node("hub")).with_limits(TraversalLimits::new(5, 100, 500, 100))
}

fn checkpoint(store: &SqliteStore) -> Checkpoint {
    capture(
        store,
        CheckpointRequest::over(request(), now()),
        &CancellationToken::never_cancelled(),
    )
    .unwrap()
}

fn delta(before: &Checkpoint, after: &Checkpoint) -> Delta {
    compare(
        before,
        after,
        DeltaLimits::default(),
        &CancellationToken::never_cancelled(),
    )
    .unwrap()
}

fn key_of(name: &str) -> RecordKey {
    RecordKey::new(
        RecordClass::Entity,
        Id::<Entity>::derive(&["entity", name]).to_string(),
    )
}

fn change_for<'delta>(delta: &'delta Delta, key: &RecordKey) -> &'delta Change {
    delta
        .changes
        .iter()
        .find(|change| &change.key == key)
        .unwrap_or_else(|| panic!("no change reported for {key}"))
}

// ---------------------------------------------------------------------------------------------
// "Checkpoint fingerprints are deterministic"
// ---------------------------------------------------------------------------------------------

/// The property every other one rests on. If two captures of one unchanged graph disagreed, every
/// delta would be noise and "has anything changed?" would need a full diff to answer.
#[test]
fn capturing_an_unchanged_graph_twice_gives_the_same_fingerprint() {
    let mut store = store();
    seed(&mut store);

    let first = checkpoint(&store);
    let second = checkpoint(&store);

    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(first.records, second.records);
}

/// A fingerprint must be a function of the graph and nothing else. Capture time and the graph
/// version are metadata, and including either would mean two captures of an unchanged graph never
/// matched — which is precisely the failure that makes an operator stop reading deltas.
#[test]
fn a_fingerprint_ignores_the_capture_time_and_the_graph_version() {
    let mut store = store();
    seed(&mut store);

    let early = capture(
        &store,
        CheckpointRequest::over(request(), at("2020-01-01T00:00:00Z")),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();
    let late = capture(
        &store,
        CheckpointRequest::over(request(), at("2030-12-31T23:59:59Z")),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_ne!(early.captured_at, late.captured_at);
    assert_eq!(early.fingerprint(), late.fingerprint());

    // The same checkpoint with a different graph version stamped on it still fingerprints the same:
    // the counter says how many material changes have been applied, not what the graph says.
    let mut moved = early.clone();
    moved.graph_version = early.graph_version + 99;
    assert_eq!(moved.fingerprint(), early.fingerprint());
}

/// The other half of determinism: a fingerprint that never moved would be useless. A material
/// change must change it, and the exclusions must be visible rather than folklore.
#[test]
fn a_material_change_changes_the_fingerprint_and_the_exclusions_are_documented() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut revoked = entity("tool");
    revoked.status = LifecycleStatus::Revoked;
    write(&mut store, &[revoked], &[]);

    let after = checkpoint(&store);
    assert_ne!(before.fingerprint(), after.fingerprint());

    assert!(
        EXCLUDED_FROM_MATERIALITY.len() >= 8,
        "every non-material change must be written down, not merely handled",
    );
    let named: BTreeSet<&str> = EXCLUDED_FROM_MATERIALITY
        .iter()
        .map(|(name, _)| *name)
        .collect();
    for expected in [
        "observation_window",
        "connector_sync_state",
        "document_serialisation",
        "sub_band_confidence_drift",
    ] {
        assert!(named.contains(expected), "{expected} is not documented");
    }
}

/// Two checkpoints of different shapes are not comparable, and the shape digest is what makes that
/// detectable. Without it a narrower second capture would report everything it did not reach as
/// removed, and an operator would spend an afternoon investigating a budget change.
#[test]
fn a_narrower_traversal_is_a_different_shape_and_is_refused_rather_than_diffed() {
    let mut store = store();
    seed(&mut store);

    let wide = checkpoint(&store);
    let narrow = capture(
        &store,
        CheckpointRequest::over(
            request().with_limits(TraversalLimits::new(1, 100, 500, 100)),
            now(),
        ),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_ne!(wide.shape, narrow.shape);
    assert_ne!(shape_of(&request()), narrow.shape);

    let refused = compare(
        &wide,
        &narrow,
        DeltaLimits::default(),
        &CancellationToken::never_cancelled(),
    );
    assert!(matches!(refused, Err(DeltaRefused::ShapeMismatch { .. })));
}

/// Checkpoints taken under different materiality rules cannot be compared by digest: every record
/// would look changed. Refusing is the only honest answer, and it names the versions.
#[test]
fn checkpoints_from_different_algorithm_versions_are_refused() {
    let mut store = store();
    seed(&mut store);

    let before = checkpoint(&store);
    let mut after = before.clone();
    after.algorithm_version = CHECKPOINT_ALGORITHM_VERSION + 1;

    let refused = compare(
        &before,
        &after,
        DeltaLimits::default(),
        &CancellationToken::never_cancelled(),
    );
    assert!(matches!(
        refused,
        Err(DeltaRefused::AlgorithmMismatch { .. })
    ));
}

/// The same two checkpoints must produce the same delta every time, or a delta cannot be quoted in
/// a report, cached, or attached to a ticket. Nothing in the comparison path reads a clock, which
/// is what makes this hold.
#[test]
fn comparing_the_same_pair_twice_gives_an_identical_delta() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut changed = entity("tool");
    changed.status = LifecycleStatus::Revoked;
    write(&mut store, &[changed, entity("newcomer")], &[]);
    let after = checkpoint(&store);

    let first = delta(&before, &after);
    let second = delta(&before, &after);
    assert_eq!(first, second);
}

/// Ordering has to be a property of the data, not of whatever the iterator happened to do. Every
/// collection here is a `BTreeMap` or `BTreeSet` for exactly this: a delta whose lines moved
/// between runs could not be diffed against yesterday's.
#[test]
fn changes_come_back_in_a_stable_record_key_order() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    write(
        &mut store,
        &[entity("zebra"), entity("aardvark"), entity("marsupial")],
        &[
            uses("hub", "zebra"),
            uses("hub", "aardvark"),
            uses("hub", "marsupial"),
        ],
    );
    let after = checkpoint(&store);

    let keys: Vec<RecordKey> = delta(&before, &after)
        .changes
        .into_iter()
        .map(|change| change.key)
        .collect();

    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "changes must arrive in record key order");

    // And the same order on a second run, which is the claim that matters.
    let repeat: Vec<RecordKey> = delta(&before, &after)
        .changes
        .into_iter()
        .map(|change| change.key)
        .collect();
    assert_eq!(keys, repeat);
}

// ---------------------------------------------------------------------------------------------
// "Diff categories are mutually clear and evidence-backed"
// ---------------------------------------------------------------------------------------------

/// One record, one category. If two categories could describe the same record, every summary built
/// on the delta would double-count it, and a summary whose numbers do not add up is not read twice.
#[test]
fn every_changed_record_gets_exactly_one_category_and_the_counts_add_up() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut revoked = entity("tool");
    revoked.status = LifecycleStatus::Revoked;
    let mut renamed = entity("other");
    renamed.aliases = vec![UntrustedText::new("Second Name").unwrap()];
    write(&mut store, &[revoked, renamed, entity("newcomer")], &[]);
    let after = checkpoint(&store);

    let delta = delta(&before, &after);

    let mut seen: BTreeMap<RecordKey, usize> = BTreeMap::new();
    for change in &delta.changes {
        *seen.entry(change.key.clone()).or_insert(0) += 1;
    }
    assert!(
        seen.values().all(|count| *count == 1),
        "a record appeared under more than one category",
    );

    let total: usize = delta.counts().values().sum();
    assert_eq!(total, delta.changes.len());
    assert_eq!(delta.compared, delta.unchanged + delta.changes.len());
}

/// The three lifecycle findings mean different things and lead to different actions. A revocation
/// says the assertion was wrong and anything derived from it needs revisiting; an expiry says it
/// was right and has aged out; a reactivation says something discounted is being asserted again.
/// Collapsing them would destroy the only distinction an analyst uses here.
#[test]
fn revocation_expiry_and_reactivation_are_told_apart() {
    let mut store = store();
    write(
        &mut store,
        &[entity("hub"), entity("wrong"), entity("old"), {
            let mut dormant = entity("dormant");
            dormant.status = LifecycleStatus::Revoked;
            dormant
        }],
        &[
            uses("hub", "wrong"),
            uses("hub", "old"),
            uses("hub", "dormant"),
        ],
    );
    let before = checkpoint(&store);

    let mut wrong = entity("wrong");
    wrong.status = LifecycleStatus::Revoked;
    let mut old = entity("old");
    old.status = LifecycleStatus::Expired;
    let dormant = entity("dormant");
    write(&mut store, &[wrong, old, dormant], &[]);
    let after = checkpoint(&store);

    let delta = delta(&before, &after);
    assert_eq!(
        change_for(&delta, &key_of("wrong")).category,
        ChangeCategory::Revoked
    );
    assert_eq!(
        change_for(&delta, &key_of("old")).category,
        ChangeCategory::Expired
    );
    assert_eq!(
        change_for(&delta, &key_of("dormant")).category,
        ChangeCategory::Reactivated
    );
}

/// A category on its own is an assertion. An operator asked to act on "this changed" needs to see
/// what moved, which is what the facet set and the quoted before/after are for.
#[test]
fn every_change_names_the_facets_that_moved_and_quotes_them() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut renamed = entity("tool");
    renamed.aliases = vec![UntrustedText::new("Second Name").unwrap()];
    write(&mut store, &[renamed], &[]);
    let after = checkpoint(&store);

    let change = change_for(&delta(&before, &after), &key_of("tool")).clone();
    assert_eq!(change.category, ChangeCategory::Changed);
    assert_eq!(
        change.facets,
        BTreeSet::from([MaterialFacet::Names]),
        "only the names moved, so only the names may be reported",
    );
    assert!(!change.reason.is_empty());
    assert_eq!(change.algorithm, CHECKPOINT_ALGORITHM);
    assert_eq!(change.algorithm_version, CHECKPOINT_ALGORITHM_VERSION);

    let quoted = &change.evidence[0];
    assert_eq!(quoted.facet, MaterialFacet::Names);
    assert_ne!(quoted.before, quoted.after);
    assert!(quoted.after.as_deref().unwrap().contains("Second Name"));
}

/// Evidence quotes record content, and record content comes from feeds. A delta is read through a
/// terminal, so an alias carrying an escape sequence must not reach one intact and a narrative
/// field must not be quoted in full.
#[test]
fn evidence_is_bounded_and_stripped_of_control_characters() {
    let mut long = entity("subject");
    long.aliases = vec![UntrustedText::new("A".repeat(500)).unwrap()];
    let plain = entity("subject");

    let quoted = fingerprint_entity(&long);
    let excerpt = &quoted.facets[&MaterialFacet::Names].excerpt;
    assert!(excerpt.chars().count() <= 200, "an excerpt is bounded");
    assert_ne!(
        quoted.digest,
        fingerprint_entity(&plain).digest,
        "the digest still sees the whole value, so a long alias is not lost",
    );

    // The model refuses control characters at its own boundary, so this is the second line of
    // defence — for a value that reached a fingerprint by some other route.
    let hostile = FacetState::of("APT\u{1b}[2Jnine\u{7}");
    assert!(!hostile.excerpt.chars().any(char::is_control));
    assert_eq!(hostile.excerpt, "APT[2Jnine");
    assert_ne!(
        hostile.digest,
        FacetState::of("APT[2Jnine").digest,
        "stripping is for display only; the digest sees what was really there",
    );
}

/// The three change kinds the issue names beyond lifecycle. Each is reported through `Changed` with
/// its own facet, so a record whose confidence *and* sources both moved is one change with two
/// facets rather than two changes that double-count it.
#[test]
fn confidence_relationship_and_source_changes_are_each_named_by_facet() {
    let plain = entity("subject");

    let mut scored = entity("subject");
    scored.confidence = Some(ConfidenceBreakdown::unexplained(
        ConfidenceScore::new(90).unwrap(),
    ));
    assert_eq!(
        fingerprint_entity(&plain).differing_facets(&fingerprint_entity(&scored)),
        BTreeSet::from([MaterialFacet::Confidence]),
    );

    let mut sourced = entity("subject");
    sourced.origin = from_evidence(b"first bundle");
    let mut resourced = entity("subject");
    resourced.origin = from_evidence(b"second bundle");
    assert_eq!(
        fingerprint_entity(&sourced).differing_facets(&fingerprint_entity(&resourced)),
        BTreeSet::from([MaterialFacet::Sources]),
    );

    let edge = uses("hub", "tool");
    let mut repointed = edge.clone();
    repointed.target = node("elsewhere");
    assert_eq!(
        fingerprint_relationship(&edge).differing_facets(&fingerprint_relationship(&repointed)),
        BTreeSet::from([MaterialFacet::Endpoints]),
    );

    let mut restricted = entity("subject");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    assert_eq!(
        fingerprint_entity(&plain).differing_facets(&fingerprint_entity(&restricted)),
        BTreeSet::from([MaterialFacet::Markings]),
    );
}

/// Banding is the trade the module makes, and it must be the documented one rather than whatever
/// the arithmetic happened to do. A drift inside a band is not reported; crossing one is.
#[test]
fn confidence_is_material_at_band_boundaries_and_not_within_a_band() {
    let scored = |value: u8| {
        let mut record = entity("subject");
        record.confidence = Some(ConfidenceBreakdown::unexplained(
            ConfidenceScore::new(value).unwrap(),
        ));
        fingerprint_entity(&record)
    };

    assert_eq!(
        scored(41).digest,
        scored(59).digest,
        "an in-band drift is churn and must not reach a delta",
    );
    assert_ne!(
        scored(59).digest,
        scored(60).digest,
        "crossing a band is the point at which an analyst treats the record differently",
    );
    assert_eq!(ConfidenceBand::of(None), ConfidenceBand::Unstated);
}

/// A record appearing must be distinguishable from a record changing, and an addition carries every
/// facet as its evidence because there is no earlier state to contrast it with.
#[test]
fn an_added_record_is_categorised_as_added_and_quotes_its_whole_state() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    write(
        &mut store,
        &[entity("newcomer")],
        &[uses("hub", "newcomer")],
    );
    let after = checkpoint(&store);

    let change = change_for(&delta(&before, &after), &key_of("newcomer")).clone();
    assert_eq!(change.category, ChangeCategory::Added);
    assert!(change.successors.is_empty());
    assert!(!change.evidence.is_empty());
    for quoted in &change.evidence {
        assert!(quoted.before.is_none(), "an addition has no earlier state");
        assert!(quoted.after.is_some());
    }
}

// ---------------------------------------------------------------------------------------------
// "Unchanged records do not appear"
// ---------------------------------------------------------------------------------------------

/// The crux of the issue. Re-importing a feed that published nothing new must produce nothing at
/// all — not a short delta, not a delta of timestamps. An operator who is shown churn learns to
/// skim, and skims the line that matters next week.
#[test]
fn a_no_op_re_import_produces_an_empty_delta() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    // The same records, offered again. Exactly what a scheduled connector does every morning.
    seed(&mut store);
    let after = checkpoint(&store);

    let delta = delta(&before, &after);
    assert!(delta.changes.is_empty(), "a no-op re-import is not a delta");
    assert!(!delta.is_material());
    assert_eq!(delta.before, delta.after);
    assert_eq!(delta.unchanged, delta.compared);
    assert!(delta.is_complete());

    // And migration 0004's counter agrees, which is what makes the cheap check sound.
    assert!(before.still_current(&store).unwrap());
}

/// The single largest source of churn in a threat intelligence graph. A feed republishing the same
/// indicator moves `last_seen` every time it runs; that says "we saw it again", which is not a
/// change to what anybody asserts.
#[test]
fn a_last_seen_bump_is_not_a_material_change() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut bumped = entity("tool");
    bumped.temporal = TemporalState::observed(at("2020-01-01T00:00:00Z"), now()).unwrap();
    write(&mut store, &[bumped], &[]);

    // The stored document really did change — this is not a test of the storage layer's no-op path.
    assert!(
        !before.still_current(&store).unwrap(),
        "the graph version moved, so the delta is doing the work rather than the counter",
    );

    let after = checkpoint(&store);
    assert!(delta(&before, &after).changes.is_empty());
}

/// A connector polling and receiving nothing new advances its cursor. That is a fact about Brolga,
/// not about the world, so it is carried on the checkpoint, reported as context, and is never a
/// change.
#[test]
fn advancing_a_connector_cursor_is_reported_but_is_not_a_change() {
    let mut store = store();
    seed(&mut store);

    let early = capture(
        &store,
        CheckpointRequest::over(request(), now()).with_source(
            "example-feed",
            SourceSyncState {
                cursor: Some("page-1".to_owned()),
                objects: 12,
            },
        ),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();
    let later = capture(
        &store,
        CheckpointRequest::over(request(), now()).with_source(
            "example-feed",
            SourceSyncState {
                cursor: Some("page-2".to_owned()),
                objects: 12,
            },
        ),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(
        early.fingerprint(),
        later.fingerprint(),
        "sync state is metadata and must not reach the fingerprint",
    );

    let delta = delta(&early, &later);
    assert!(delta.changes.is_empty());
    assert!(delta.sync_advanced, "but it is still worth reporting");
}

/// Unchanged records are counted rather than listed. "We looked at four hundred thousand records
/// and three moved" is the useful shape; a report that lists the other 399,997 is not read at all.
#[test]
fn unchanged_records_are_counted_rather_than_listed() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);

    let mut revoked = entity("tool");
    revoked.status = LifecycleStatus::Revoked;
    write(&mut store, &[revoked], &[]);
    let after = checkpoint(&store);

    let delta = delta(&before, &after);
    assert_eq!(delta.changes.len(), 1);
    assert!(
        delta.unchanged >= 4,
        "the rest were looked at and were quiet"
    );
    assert_eq!(delta.compared, delta.unchanged + 1);
}

/// A checkpoint compared with itself is the degenerate case and must be empty rather than refused.
/// An operator re-checking a baseline should get "nothing changed", not an error.
#[test]
fn a_checkpoint_compared_with_itself_is_empty() {
    let mut store = store();
    seed(&mut store);
    let only = checkpoint(&store);

    let delta = delta(&only, &only);
    assert!(delta.changes.is_empty());
    assert!(!delta.attributable_to_version_change());
}

/// A version bump makes every confidence look like it moved. The delta cannot prevent that, so it
/// must say so — otherwise a scoring upgrade is read as a hundred pieces of new intelligence.
#[test]
fn a_configuration_or_algorithm_version_move_is_reported_as_such() {
    let mut store = store();
    seed(&mut store);

    let before = capture(
        &store,
        CheckpointRequest::over(request(), now()).with_version("brolga.confidence", 1),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();
    let after = capture(
        &store,
        CheckpointRequest::over(request(), now())
            .with_version("brolga.confidence", 2)
            .with_configuration(ContentHash::of(b"new policy")),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    let delta = delta(&before, &after);
    assert!(delta.changes.is_empty(), "no record moved");
    assert!(delta.attributable_to_version_change());
    assert!(delta.configuration_changed);
    assert_eq!(delta.version_changes.len(), 1);
    assert_eq!(delta.version_changes[0].component, "brolga.confidence");
    assert_eq!(delta.version_changes[0].before, Some(1));
    assert_eq!(delta.version_changes[0].after, Some(2));

    // The versions are fingerprinted, because two checkpoints scored by different algorithms do not
    // describe comparable states even when the records match.
    assert_ne!(before.fingerprint(), after.fingerprint());
}

// ---------------------------------------------------------------------------------------------
// "Deleted or merged records remain traceable"
// ---------------------------------------------------------------------------------------------

/// The traversal both traceability captures are taken over: current edges only, so withdrawing an
/// edge really does take the node it led to out of the checkpoint's reach.
fn current_only() -> TraversalRequest {
    request().with_filter(EdgeQuery::at(node("hub"), Direction::Either).only_current())
}

/// Seed the graph, capture a baseline over current edges, then withdraw the edge to `other` so it
/// genuinely leaves the checkpoint, and capture again with whatever lineage the caller recorded.
fn departure(successions: BTreeMap<RecordKey, Succession>) -> (Checkpoint, Checkpoint) {
    let mut store = store();
    seed(&mut store);

    let before = capture(
        &store,
        CheckpointRequest::over(current_only(), now()),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    let mut withdrawn = uses("hub", "other");
    withdrawn.status = LifecycleStatus::Revoked;
    write(&mut store, &[], &[withdrawn]);

    let mut request = CheckpointRequest::over(current_only(), now());
    for (key, succession) in successions {
        request = request.with_succession(key, succession);
    }
    let after = capture(&store, request, &CancellationToken::never_cancelled()).unwrap();

    assert!(before.records.contains_key(&key_of("other")));
    assert!(!after.records.contains_key(&key_of("other")));
    (before, after)
}

/// A merge is close to irreversible in practice: once two actors' claims and sightings are
/// attributed to one identity, unpicking which evidence belonged to which is work nobody has the
/// information to do afterwards. So the delta must name the successor.
#[test]
fn a_merged_record_names_where_it_went() {
    let gone = key_of("other");
    let survivor = key_of("tool");

    // The lineage is supplied rather than inferred. Guessing a merge from "one record vanished and
    // another gained its aliases" would invent a lineage nobody asserted.
    let (before, after) = departure(BTreeMap::from([(
        gone.clone(),
        Succession::merged_into(survivor.clone()),
    )]));

    let delta = delta(&before, &after);
    let change = change_for(&delta, &gone);
    assert_eq!(change.category, ChangeCategory::Merged);
    assert_eq!(change.successors, BTreeSet::from([survivor]));
    assert!(
        !change.evidence.is_empty(),
        "a departure still quotes what it was, or the trace leads nowhere",
    );
    for quoted in &change.evidence {
        assert!(quoted.before.is_some());
        assert!(quoted.after.is_none(), "there is no later state to quote");
    }
}

/// One identity becoming several is a different finding from one becoming another, and an analyst
/// tracking the old identifier needs every successor rather than the first.
#[test]
fn a_split_record_names_every_successor() {
    let successors = BTreeSet::from([key_of("left"), key_of("right")]);
    let succession = Succession::into_records(successors.clone()).unwrap();
    assert_eq!(succession.kind, SuccessionKind::Split);

    let gone = key_of("other");
    let (before, after) = departure(BTreeMap::from([(gone.clone(), succession)]));

    let change = change_for(&delta(&before, &after), &gone).clone();
    assert_eq!(change.category, ChangeCategory::Split);
    assert_eq!(change.successors, successors);
}

/// "It became that one over there" and "it is gone and nobody said where" are different findings,
/// and the second is the one that needs investigating. Reporting an untraceable deletion as a merge
/// would hide exactly the case the traceability criterion exists for.
#[test]
fn a_record_removed_with_no_recorded_successor_is_reported_as_untraceable() {
    let (before, after) = departure(BTreeMap::new());

    let change = change_for(&delta(&before, &after), &key_of("other")).clone();
    assert_eq!(change.category, ChangeCategory::Removed);
    assert!(change.successors.is_empty());
    assert!(change.reason.contains("no recorded successor"));
    assert!(change.category.is_departure());

    // A succession with no successor cannot be used to dress this up as a merge.
    assert_eq!(Succession::into_records(BTreeSet::new()), None);
}

// ---------------------------------------------------------------------------------------------
// "Checkpoint creation is transactional with graph version"
// ---------------------------------------------------------------------------------------------

/// A checkpoint records the version it describes, and migration 0004's counter moves only on a
/// material change. Together those make "has anything changed since this baseline?" one integer
/// comparison instead of a full capture and diff.
#[test]
fn a_checkpoint_records_its_graph_version_and_a_no_op_write_leaves_it_current() {
    let mut store = store();
    seed(&mut store);

    let baseline = checkpoint(&store);
    assert_eq!(baseline.graph_version, store.graph_version().unwrap());
    assert!(baseline.still_current(&store).unwrap());

    // A no-op upsert: the storage layer reports it unchanged and the counter does not move.
    seed(&mut store);
    assert!(baseline.still_current(&store).unwrap());

    // A material write does move it.
    write(&mut store, &[entity("newcomer")], &[]);
    assert!(!baseline.still_current(&store).unwrap());
}

/// A capture reads many rows over many statements. Without a fence it could describe half of one
/// version and half of the next while claiming to be one, and every later delta taken against it
/// would report changes that never happened. Refusing is the only safe answer.
#[test]
fn a_capture_that_straddles_a_material_change_is_refused_rather_than_returned() {
    let mut backing = store();
    seed(&mut backing);

    let shifting = ShiftingVersion::new(&backing);
    let refused = capture(
        &shifting,
        CheckpointRequest::over(request(), now()),
        &CancellationToken::never_cancelled(),
    );

    match refused {
        Err(CaptureError::ConcurrentChange { from, to }) => assert_ne!(from, to),
        other => panic!("a straddling capture must be refused, got {other:?}"),
    }
}

/// The handling policy applies to a capture exactly as it applies to a traversal. Two colleagues
/// with different clearances must not produce checkpoints that make the restricted records look
/// deleted, so the withheld counts travel with the delta.
#[test]
fn restricted_records_are_withheld_and_the_count_travels_with_the_delta() {
    let mut store = store();
    let mut secret = entity("secret");
    secret.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    write(
        &mut store,
        &[entity("hub"), secret],
        &[uses("hub", "secret")],
    );

    let cleared = checkpoint(&store);
    let restricted = capture(
        &store,
        CheckpointRequest::over(
            request().with_policy(TraversalPolicy::permitting(TlpLevel::Green)),
            now(),
        ),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(cleared.withheld_by_policy, 0);
    assert!(restricted.withheld_by_policy > 0);
    assert!(cleared.records.contains_key(&key_of("secret")));
    assert!(!restricted.records.contains_key(&key_of("secret")));

    // The policy is part of the shape, so the two are not comparable at all — which is stronger
    // than reporting the withheld count, and is why the shape carries the policy.
    assert_ne!(cleared.shape, restricted.shape);
    let refused = compare(
        &cleared,
        &restricted,
        DeltaLimits::default(),
        &CancellationToken::never_cancelled(),
    );
    assert!(matches!(refused, Err(DeltaRefused::ShapeMismatch { .. })));
}

// ---------------------------------------------------------------------------------------------
// Bounds: a comparison of two large graphs must stop, and must say that it stopped
// ---------------------------------------------------------------------------------------------

/// A partial answer that looks complete is worse than no answer. When the change budget stops the
/// comparison, the delta says so rather than reporting "three changes" for a graph where everything
/// moved.
#[test]
fn a_change_budget_stops_the_comparison_and_admits_it() {
    let mut store = store();
    write(&mut store, &[entity("hub")], &[]);
    let before = checkpoint(&store);

    let mut added: Vec<Entity> = Vec::new();
    let mut edges: Vec<Relationship> = Vec::new();
    for index in 0..20 {
        let name = format!("added-{index:02}");
        added.push(entity(&name));
        edges.push(uses("hub", &name));
    }
    write(&mut store, &added, &edges);
    let after = checkpoint(&store);

    let bounded = compare(
        &before,
        &after,
        DeltaLimits::new(1_000, 3),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(bounded.changes.len(), 3);
    assert!(bounded.stopped_by(DeltaTruncation::Changes));
    assert!(!bounded.is_complete());

    // Deterministic truncation: the same prefix every time, because the walk is in key order.
    let again = compare(
        &before,
        &after,
        DeltaLimits::new(1_000, 3),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();
    assert_eq!(bounded, again);
}

/// The other budget, for the other failure: a graph with a great many *unchanged* records still
/// costs something to walk, and a comparison that ran out of record budget must not present its
/// prefix as the whole answer.
#[test]
fn a_record_budget_stops_the_comparison_and_admits_it() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);
    let after = checkpoint(&store);

    let bounded = compare(
        &before,
        &after,
        DeltaLimits::new(2, 1_000),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert_eq!(bounded.compared, 2);
    assert!(bounded.stopped_by(DeltaTruncation::Records));
    assert!(bounded.changes.is_empty());
}

/// The request's deadline and an operator's interrupt are the same signal, and a comparison must
/// honour it. A cancelled comparison reports the cancellation rather than a short answer that reads
/// as "nothing else changed".
#[test]
fn a_cancelled_comparison_reports_the_cancellation() {
    let mut store = store();
    seed(&mut store);
    let before = checkpoint(&store);
    let after = checkpoint(&store);

    let token = CancellationToken::already_cancelled();
    let stopped = compare(&before, &after, DeltaLimits::default(), &token).unwrap();

    assert!(stopped.stopped_by(DeltaTruncation::Cancelled));
    assert_eq!(stopped.cancellation, Some(Cancelled::Requested));
    assert_eq!(stopped.compared, 0);
    assert!(!stopped.is_complete());

    // A deadline is the same stop condition arriving by a different route.
    let expired = CancellationToken::with_budget(Duration::ZERO);
    let timed = compare(&before, &after, DeltaLimits::default(), &expired).unwrap();
    assert!(timed.stopped_by(DeltaTruncation::Cancelled));
    assert_eq!(timed.cancellation, Some(Cancelled::DeadlineExceeded));
}

/// A capture that hit a traversal budget describes part of a neighbourhood. Any delta built from it
/// inherits that, and the two truncations stay separate because the remedies differ: a comparison
/// is re-run with a larger budget, a capture is re-taken.
#[test]
fn a_truncated_capture_is_inherited_by_every_delta_built_from_it() {
    let mut store = store();
    let mut names = vec![entity("hub")];
    let mut edges = Vec::new();
    for index in 0..10 {
        let name = format!("leaf-{index:02}");
        names.push(entity(&name));
        edges.push(uses("hub", &name));
    }
    write(&mut store, &names, &edges);

    let squeezed = TraversalRequest::starting_at(node("hub"))
        .with_limits(TraversalLimits::new(3, 4, 500, 100));
    let partial = capture(
        &store,
        CheckpointRequest::over(squeezed, now()),
        &CancellationToken::never_cancelled(),
    )
    .unwrap();

    assert!(!partial.is_complete());
    assert!(partial.truncated.contains(&Truncation::Nodes));

    let delta = delta(&partial, &partial);
    assert!(delta.changes.is_empty());
    assert!(
        delta.truncated.is_empty(),
        "the comparison itself completed"
    );
    assert!(
        delta.inherited.contains(&Truncation::Nodes),
        "but the inputs did not, and the delta must not pretend otherwise",
    );
    assert!(!delta.is_complete());
}

/// A truncated capture must not be adopted as a baseline by accident, so it must not fingerprint
/// the same as a complete capture that happens to cover the same records.
#[test]
fn a_truncated_checkpoint_never_fingerprints_as_a_complete_one() {
    let mut store = store();
    seed(&mut store);

    let complete = checkpoint(&store);
    let mut claimed_partial = complete.clone();
    claimed_partial.truncated = BTreeSet::from([Truncation::Nodes]);

    assert_eq!(complete.records, claimed_partial.records);
    assert_ne!(complete.fingerprint(), claimed_partial.fingerprint());
}

// ---------------------------------------------------------------------------------------------
// A store whose graph version moves under the capture, for the transactional-fence test
// ---------------------------------------------------------------------------------------------

/// A read-only view over a real store whose graph version advances on every read.
///
/// Stands in for a concurrent import committing while a capture is part-way through, which is not
/// otherwise reachable from a single-threaded test. Every other method delegates, so the capture
/// under test reads a genuine graph.
struct ShiftingVersion<'store> {
    inner: &'store SqliteStore,
    reads: std::cell::Cell<u64>,
}

impl<'store> ShiftingVersion<'store> {
    fn new(inner: &'store SqliteStore) -> Self {
        Self {
            inner,
            reads: std::cell::Cell::new(0),
        }
    }
}

impl StoreRead for ShiftingVersion<'_> {
    fn connector_cursor(
        &self,
        connector: &str,
        feed: &str,
    ) -> Result<Option<brolga_storage::ConnectorCursor>, StorageError> {
        self.inner.connector_cursor(connector, feed)
    }

    fn connector_cursors(&self) -> Result<Vec<brolga_storage::ConnectorCursor>, StorageError> {
        self.inner.connector_cursors()
    }

    fn get_checkpoint(&self, name: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_checkpoint(name)
    }

    fn list_checkpoints(&self) -> Result<Vec<CheckpointSummary>, StorageError> {
        self.inner.list_checkpoints()
    }

    fn graph_version(&self) -> Result<u64, StorageError> {
        let seen = self.reads.get();
        self.reads.set(seen + 1);
        Ok(self.inner.graph_version()? + seen)
    }

    fn schema_version(&self) -> Result<u32, StorageError> {
        self.inner.schema_version()
    }
    fn count(&self, kind: RecordKind) -> Result<u64, StorageError> {
        self.inner.count(kind)
    }
    fn get_source_object(
        &self,
        id: Id<SourceObject>,
    ) -> Result<Option<SourceObject>, StorageError> {
        self.inner.get_source_object(id)
    }
    fn find_source_object_by_hash(
        &self,
        hash: &ContentHash,
    ) -> Result<Option<SourceObject>, StorageError> {
        self.inner.find_source_object_by_hash(hash)
    }
    fn get_entity(&self, id: Id<Entity>) -> Result<Option<Entity>, StorageError> {
        self.inner.get_entity(id)
    }
    fn get_relationship(&self, id: Id<Relationship>) -> Result<Option<Relationship>, StorageError> {
        self.inner.get_relationship(id)
    }
    fn get_claim(&self, id: Id<Claim>) -> Result<Option<Claim>, StorageError> {
        self.inner.get_claim(id)
    }
    fn get_sighting(&self, id: Id<Sighting>) -> Result<Option<Sighting>, StorageError> {
        self.inner.get_sighting(id)
    }
    fn list_entities(&self, page: Page) -> Result<Vec<Entity>, StorageError> {
        self.inner.list_entities(page)
    }
    fn relationships_touching(
        &self,
        node: &NodeRef,
        page: Page,
    ) -> Result<Vec<Relationship>, StorageError> {
        self.inner.relationships_touching(node, page)
    }
    fn search_entities(
        &self,
        query: &EntityQuery,
        page: Page,
    ) -> Result<Vec<Entity>, StorageError> {
        self.inner.search_entities(query, page)
    }
    fn edges_at(&self, query: &EdgeQuery, page: Page) -> Result<Vec<Relationship>, StorageError> {
        self.inner.edges_at(query, page)
    }
    fn degree(&self, query: &EdgeQuery) -> Result<u64, StorageError> {
        self.inner.degree(query)
    }
    fn claims_about(&self, subject: &NodeRef, page: Page) -> Result<Vec<Claim>, StorageError> {
        self.inner.claims_about(subject, page)
    }
    fn sightings_of(&self, subject: &NodeRef, page: Page) -> Result<Vec<Sighting>, StorageError> {
        self.inner.sightings_of(subject, page)
    }
    fn get_source_blob(
        &self,
        content_hash: &ContentHash,
    ) -> Result<Option<RetrievedBlob>, StorageError> {
        self.inner.get_source_blob(content_hash)
    }
    fn source_blob_metadata(
        &self,
        content_hash: &ContentHash,
    ) -> Result<Option<BlobMetadata>, StorageError> {
        self.inner.source_blob_metadata(content_hash)
    }
    fn source_blob_audit(
        &self,
        content_hash: &ContentHash,
    ) -> Result<Vec<RetentionEvent>, StorageError> {
        self.inner.source_blob_audit(content_hash)
    }
    fn quarantined_for_source(
        &self,
        source_hash: &ContentHash,
    ) -> Result<Vec<QuarantineRecord>, StorageError> {
        self.inner.quarantined_for_source(source_hash)
    }
    fn quarantine_count(&self) -> Result<u64, StorageError> {
        self.inner.quarantine_count()
    }
    fn quarantine_occurrences(&self) -> Result<u64, StorageError> {
        self.inner.quarantine_occurrences()
    }
    fn list_source_objects(&self, page: Page) -> Result<Vec<SourceObject>, StorageError> {
        self.inner.list_source_objects(page)
    }
    fn get_entity_json(&self, id: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_entity_json(id)
    }
    fn get_relationship_json(&self, id: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_relationship_json(id)
    }
    fn get_claim_json(&self, id: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_claim_json(id)
    }
    fn get_sighting_json(&self, id: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_sighting_json(id)
    }
    fn get_source_object_json(&self, id: &str) -> Result<Option<serde_json::Value>, StorageError> {
        self.inner.get_source_object_json(id)
    }
    fn graph_decisions_for(
        &self,
        kind: &str,
        subject: &str,
    ) -> Result<Vec<GraphDecisionRow>, StorageError> {
        self.inner.graph_decisions_for(kind, subject)
    }
    fn graph_decision_count(&self, kind: &str, verdict: &str) -> Result<u64, StorageError> {
        self.inner.graph_decision_count(kind, verdict)
    }
    fn entity_exists(&self, id: Id<Entity>) -> Result<bool, StorageError> {
        self.inner.entity_exists(id)
    }
    fn source_blob_count(&self) -> Result<u64, StorageError> {
        self.inner.source_blob_count()
    }
    fn source_blob_stored_bytes(&self) -> Result<u64, StorageError> {
        self.inner.source_blob_stored_bytes()
    }
}

// ---------------------------------------------------------------------------------------------
// Persistence — a baseline that does not survive the run cannot answer the question anybody asks
// ---------------------------------------------------------------------------------------------

/// Everything storage needs to refuse an unusable baseline without decoding it.
fn summary_of(name: &str, taken: &Checkpoint) -> CheckpointSummary {
    CheckpointSummary {
        name: name.to_owned(),
        shape: taken.shape.to_string(),
        graph_version: taken.graph_version,
        algorithm: taken.algorithm.to_owned(),
        algorithm_version: taken.algorithm_version,
        captured_at: taken.captured_at.to_rfc3339(),
        truncated: !taken.is_complete(),
    }
}

/// The question is never "what changed since this process started". It is "what changed since last
/// week", and answering it means the baseline outlives the run that took it.
#[test]
fn a_checkpoint_survives_being_written_and_read_back_by_another_process() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let before = {
        let mut store = SqliteStore::open(&path, 5000).unwrap();
        store.migrate().unwrap();
        seed(&mut store);

        let before = checkpoint(&store);
        let summary = summary_of("nightly", &before);
        let document = serde_json::to_value(&before).unwrap();
        store
            .transaction(|write| write.put_checkpoint(&summary, &document))
            .unwrap();
        before
    };

    // A different `SqliteStore`, as a later run would have.
    let store = SqliteStore::open(&path, 5000).unwrap();
    let stored = store
        .get_checkpoint("nightly")
        .unwrap()
        .expect("the baseline outlived the process that took it");
    let restored: Checkpoint = serde_json::from_value(stored).unwrap();

    assert_eq!(restored.fingerprint(), before.fingerprint());
    assert_eq!(restored.shape, before.shape);
    assert_eq!(restored.records, before.records);
}

/// A delta against a reloaded baseline must equal one against the in-memory original. If
/// serialisation lost anything material, it shows up here as phantom change — which is the failure
/// a delta exists to avoid.
#[test]
fn a_delta_against_a_reloaded_baseline_matches_one_against_the_original() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("brolga.sqlite");

    let mut store = SqliteStore::open(&path, 5000).unwrap();
    store.migrate().unwrap();
    seed(&mut store);

    let baseline = checkpoint(&store);
    store
        .transaction(|write| {
            write.put_checkpoint(
                &summary_of("baseline", &baseline),
                &serde_json::to_value(&baseline).unwrap(),
            )
        })
        .unwrap();

    write(
        &mut store,
        &[entity("newcomer")],
        &[uses("hub", "newcomer")],
    );
    let now = checkpoint(&store);

    let restored: Checkpoint =
        serde_json::from_value(store.get_checkpoint("baseline").unwrap().unwrap()).unwrap();

    let from_memory = delta(&baseline, &now);
    let from_disk = delta(&restored, &now);

    assert_eq!(
        from_disk.changes.len(),
        from_memory.changes.len(),
        "a round trip through storage must not manufacture or lose a change"
    );
    assert_eq!(from_disk.unchanged, from_memory.unchanged);
    assert_eq!(from_disk.compared, from_memory.compared);
    assert_eq!(
        from_disk.counts(),
        from_memory.counts(),
        "every category must match, not merely the total"
    );
}

/// A named baseline is a name an operator reuses — "nightly" means the latest nightly. Re-taking it
/// moves it rather than accumulating superseded baselines nobody prunes.
#[test]
fn re_taking_a_named_checkpoint_moves_it_rather_than_appending() {
    let mut store = store();
    seed(&mut store);

    let first = checkpoint(&store);
    let created = store
        .transaction(|write| {
            write.put_checkpoint(
                &summary_of("nightly", &first),
                &serde_json::to_value(&first).unwrap(),
            )
        })
        .unwrap();
    assert!(created, "the name was new");

    write(
        &mut store,
        &[entity("newcomer")],
        &[uses("hub", "newcomer")],
    );
    let second = checkpoint(&store);
    let created_again = store
        .transaction(|write| {
            write.put_checkpoint(
                &summary_of("nightly", &second),
                &serde_json::to_value(&second).unwrap(),
            )
        })
        .unwrap();
    assert!(!created_again, "the name already existed");

    assert_eq!(
        store.list_checkpoints().unwrap().len(),
        1,
        "one baseline, moved"
    );
    let stored: Checkpoint =
        serde_json::from_value(store.get_checkpoint("nightly").unwrap().unwrap()).unwrap();
    assert_eq!(
        stored.fingerprint(),
        second.fingerprint(),
        "the stored baseline is the newer one"
    );
}

/// A truncated baseline must be refusable *without decoding it*. A delta against a partial baseline
/// reports records as added when the baseline merely did not reach them, which reads as a wave of
/// new intelligence.
#[test]
fn a_summary_says_whether_a_baseline_was_truncated_without_decoding_it() {
    let mut store = store();
    seed(&mut store);

    let complete = checkpoint(&store);
    let summary = summary_of("complete", &complete);
    assert!(!summary.truncated, "this capture reached everything");

    store
        .transaction(|write| {
            write.put_checkpoint(&summary, &serde_json::to_value(&complete).unwrap())
        })
        .unwrap();

    let listed = store.list_checkpoints().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].truncated);
    assert_eq!(listed[0].shape, complete.shape.to_string());
    assert_eq!(listed[0].algorithm_version, complete.algorithm_version);
}

/// Removing a baseline is explicit, and removing one that was never there is not a failure — an
/// operator cleaning up should not have to check first.
#[test]
fn deleting_a_checkpoint_is_explicit_and_absence_is_not_a_failure() {
    let mut store = store();
    seed(&mut store);

    let taken = checkpoint(&store);
    store
        .transaction(|write| {
            write.put_checkpoint(
                &summary_of("scratch", &taken),
                &serde_json::to_value(&taken).unwrap(),
            )
        })
        .unwrap();

    assert!(
        store
            .transaction(|write| write.delete_checkpoint("scratch"))
            .unwrap()
    );
    assert!(store.get_checkpoint("scratch").unwrap().is_none());
    assert!(
        !store
            .transaction(|write| write.delete_checkpoint("scratch"))
            .unwrap(),
        "deleting what is not there reports false rather than failing"
    );
}
