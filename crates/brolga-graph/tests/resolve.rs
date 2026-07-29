//! Entity resolution, manual operations, and replay.
//!
//! One section per acceptance criterion of [#21](https://github.com/jusso-dev/Brolga/issues/21).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;

use brolga_graph::{
    ManualOperation, NAME_SENSITIVE_KINDS, OperationKind, OperationRefused, RESOLVE_ALGORITHM,
    RESOLVE_ALGORITHM_VERSION, ResolutionOutcome, ResolutionState, ResolvableRecord, Resolver,
    Strength, merge_loses_a_marking, merged_markings, merged_sources,
};
use brolga_model::{Entity, EntityKind, Id, Marking, MarkingSet, PapLevel, TlpLevel};

fn record(name: &str, kind: EntityKind) -> ResolvableRecord {
    ResolvableRecord {
        id: Id::<Entity>::derive(&[kind.as_str(), name]),
        kind,
        name: name.to_owned(),
        external_ids: BTreeMap::new(),
        markings: MarkingSet::empty(),
        sources: Vec::new(),
    }
}

fn with_external(mut record: ResolvableRecord, namespace: &str, value: &str) -> ResolvableRecord {
    record
        .external_ids
        .insert(namespace.to_owned(), value.to_owned());
    record
}

fn operation(
    kind: OperationKind,
    left: &ResolvableRecord,
    right: Option<&ResolvableRecord>,
) -> ManualOperation {
    ManualOperation {
        kind,
        left: left.id,
        right: right.map(|record| record.id),
        actor: "analyst@example.org".to_owned(),
        policy_context: "case-4471".to_owned(),
        note: None,
        withdraws: false,
    }
}

// ---------------------------------------------------------------------------------------------
// "Actors, malware, campaigns, and organisations never merge on name similarity alone"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the most damaging thing this module could get wrong. A merge is close to
/// irreversible in practice: once two actors' claims and sightings are attributed to one identity,
/// unpicking which evidence belonged to which is work nobody can do afterwards.
#[test]
fn an_identical_name_never_merges_on_its_own_for_any_name_sensitive_kind() {
    let resolver = Resolver::new();

    for kind in NAME_SENSITIVE_KINDS {
        let left = record("Lazarus", *kind);
        // Same name, different derived identifier, no external identifier in common.
        let mut right = record("Lazarus", *kind);
        right.id = Id::<Entity>::derive(&["other-source", kind.as_str(), "Lazarus"]);

        let candidate = resolver.resolve(&left, &right);
        assert_eq!(
            candidate.outcome,
            ResolutionOutcome::Candidate,
            "{kind:?} merged on a name alone"
        );
        assert!(!candidate.outcome.unifies());
        assert!(candidate.outcome.needs_review());
    }
}

/// The structural half of the guarantee: no name-based matcher may produce a decisive signal, so
/// the rule holds by construction rather than by a policy check somebody could forget.
#[test]
fn no_name_based_signal_is_ever_decisive() {
    let resolver = Resolver::new();
    let left = record("Sandworm Team", EntityKind::ThreatActor);
    let mut right = record("Sandworm Team", EntityKind::ThreatActor);
    right.id = Id::<Entity>::derive(&["b", "Sandworm Team"]);

    let candidate = resolver.resolve(&left, &right);
    for signal in &candidate.signals {
        if signal.matcher.contains("name") {
            assert!(
                !signal.strength.can_merge_alone(),
                "{} produced a decisive signal from a name",
                signal.matcher
            );
        }
    }
    assert_eq!(candidate.strongest(), Some(Strength::Supporting));
}

/// The real-world case this rule exists for: one name, two different kinds of thing.
#[test]
fn two_different_kinds_sharing_a_name_are_not_even_candidates() {
    let resolver = Resolver::new();
    let actor = record("Winnti", EntityKind::ThreatActor);
    let malware = record("Winnti", EntityKind::MalwareFamily);

    let candidate = resolver.resolve(&actor, &malware);
    assert_eq!(candidate.outcome, ResolutionOutcome::Distinct);
    assert!(candidate.signals.is_empty());
}

/// A shared external identifier *is* decisive, because the authority did the identification and
/// Brolga is reading it rather than inferring it. Without this the resolver would never merge
/// anything and would be useless.
#[test]
fn a_shared_external_identifier_is_decisive_and_merges() {
    let resolver = Resolver::new();
    let left = with_external(
        record("APT28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("Fancy Bear", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    let candidate = resolver.resolve(&left, &right);
    assert_eq!(candidate.outcome, ResolutionOutcome::Merged);
    assert!(candidate.outcome.unifies());
    assert_eq!(candidate.strongest(), Some(Strength::Decisive));
}

/// The same identifier in *different* namespaces is not a match. `G0007` in MITRE and `G0007` in
/// somebody's internal numbering are unrelated strings.
#[test]
fn the_same_identifier_in_different_namespaces_does_not_match() {
    let resolver = Resolver::new();
    let left = with_external(
        record("A", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("B", EntityKind::ThreatActor),
        "internal-tracker",
        "G0007",
    );

    assert_eq!(
        resolver.resolve(&left, &right).outcome,
        ResolutionOutcome::Distinct
    );
}

// ---------------------------------------------------------------------------------------------
// "Every candidate includes evidence, score, reasons, and algorithm version"
// ---------------------------------------------------------------------------------------------

/// The criterion. A candidate a reviewer cannot evaluate is a candidate they will either rubber-
/// stamp or ignore, and both are worse than not surfacing it.
#[test]
fn every_signal_carries_evidence_a_score_a_reason_and_the_algorithm_that_found_it() {
    let resolver = Resolver::new();
    let left = with_external(
        record("APT28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("APT-28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    let candidate = resolver.resolve(&left, &right);
    assert_eq!(candidate.algorithm, RESOLVE_ALGORITHM);
    assert_eq!(candidate.algorithm_version, RESOLVE_ALGORITHM_VERSION);
    assert!(candidate.score > 0);

    assert!(!candidate.signals.is_empty());
    for signal in &candidate.signals {
        assert!(!signal.matcher.is_empty());
        assert!(signal.reason.len() > 20, "a reason, not a label");
        assert!(!signal.evidence.is_empty(), "what was actually compared");
        assert!(signal.score > 0);
    }
}

/// The explanation is what a reviewer reads. It must name the outcome and every signal.
#[test]
fn the_explanation_names_the_outcome_and_every_signal() {
    let resolver = Resolver::new();
    let left = with_external(
        record("APT28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("APT-28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    let explanation = resolver.resolve(&left, &right).explain();
    assert!(explanation.contains("merged"), "{explanation}");
    assert!(explanation.contains("external-identifier"), "{explanation}");
    assert!(explanation.contains("decisive"), "{explanation}");
}

/// Evidence quotes record content, and a review queue is read through terminals. An escape sequence
/// in an actor name must not survive into one.
#[test]
fn candidate_evidence_carries_no_control_characters() {
    let resolver = Resolver::new();
    let mut left = record("APT28", EntityKind::ThreatActor);
    left.name = "APT\u{1b}[31m28".to_owned();
    let mut right = record("APT28", EntityKind::ThreatActor);
    right.name = "APT\u{1b}[31m28".to_owned();
    right.id = Id::<Entity>::derive(&["b", "APT28"]);

    let candidate = resolver.resolve(&left, &right);
    for signal in &candidate.signals {
        assert!(
            !signal.evidence.chars().any(char::is_control),
            "escape survived into evidence: {:?}",
            signal.evidence
        );
    }
}

/// A review queue must be stable across runs, or a reviewer working through it loses their place
/// every time an import runs.
#[test]
fn the_review_queue_is_ordered_stably_across_runs() {
    let resolver = Resolver::new();
    let records = vec![
        with_external(
            record("A", EntityKind::ThreatActor),
            "mitre-attack",
            "G0001",
        ),
        with_external(
            record("B", EntityKind::ThreatActor),
            "mitre-attack",
            "G0001",
        ),
        record("Sandworm", EntityKind::ThreatActor),
        record("Sandworm Team", EntityKind::ThreatActor),
    ];

    let first: Vec<_> = resolver
        .resolve_all(&records)
        .into_iter()
        .map(|candidate| (candidate.left.to_string(), candidate.score))
        .collect();

    let mut shuffled = records.clone();
    shuffled.reverse();
    let second: Vec<_> = resolver
        .resolve_all(&shuffled)
        .into_iter()
        .map(|candidate| (candidate.left.to_string(), candidate.score))
        .collect();

    assert_eq!(first, second, "input order must not change the queue");
}

// ---------------------------------------------------------------------------------------------
// "Manual operations are reversible through recorded history"
// ---------------------------------------------------------------------------------------------

/// The criterion. A merge nobody can undo is a decision that outlives the evidence for it.
#[test]
fn a_merge_is_reversible_by_a_recorded_split() {
    let left = record("A", EntityKind::ThreatActor);
    let right = record("B", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();

    // Asserted as "both sides resolve to one identity", not as "the right-hand one was absorbed" —
    // which side survives is a deterministic detail of the ordering, and a test that depends on it
    // would be asserting the implementation rather than the property.
    state
        .apply(operation(OperationKind::Merge, &left, Some(&right)))
        .unwrap();
    assert_eq!(
        state.canonical_identity(left.id),
        state.canonical_identity(right.id),
        "after the merge both identifiers resolve to one identity"
    );

    state
        .apply(operation(OperationKind::Split, &left, Some(&right)))
        .unwrap();
    assert_ne!(
        state.canonical_identity(left.id),
        state.canonical_identity(right.id),
        "the split restored two separate identities"
    );
    assert_eq!(state.canonical_identity(left.id), left.id.to_string());
    assert_eq!(state.canonical_identity(right.id), right.id.to_string());

    assert_eq!(
        state.history().len(),
        2,
        "both operations are in the record"
    );
}

/// `Split` is `Merge`'s inverse, and the pairing is asserted rather than assumed.
#[test]
fn merge_and_split_are_declared_inverses_of_one_another() {
    assert_eq!(OperationKind::Merge.inverse(), Some(OperationKind::Split));
    assert_eq!(OperationKind::Split.inverse(), Some(OperationKind::Merge));
    // The rest reverse by withdrawal, which is recorded rather than deleted.
    assert_eq!(OperationKind::Reject.inverse(), None);
    assert_eq!(OperationKind::Alias.inverse(), None);
    assert_eq!(OperationKind::Pin.inverse(), None);
}

/// Withdrawing is a recorded operation, never a deletion. An audit trail that can be edited is not
/// one.
#[test]
fn withdrawing_a_decision_appends_to_history_rather_than_erasing_it() {
    let left = record("A", EntityKind::ThreatActor);
    let right = record("B", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();

    state
        .apply(operation(OperationKind::Reject, &left, Some(&right)))
        .unwrap();
    assert!(state.is_rejected(left.id, right.id));

    let mut withdrawal = operation(OperationKind::Reject, &left, Some(&right));
    withdrawal.withdraws = true;
    state.apply(withdrawal).unwrap();

    assert!(!state.is_rejected(left.id, right.id));
    assert_eq!(
        state.history().len(),
        2,
        "the original rejection is still in the record"
    );
    assert!(!state.history()[0].withdraws);
    assert!(state.history()[1].withdraws);
}

/// The audit trail *is* the state: replaying it must reconstruct the same result, so "how did we
/// get here?" is answerable rather than trusted.
#[test]
fn replaying_the_history_reconstructs_the_same_state() {
    let a = record("A", EntityKind::ThreatActor);
    let b = record("B", EntityKind::ThreatActor);
    let c = record("C", EntityKind::ThreatActor);

    let operations = vec![
        operation(OperationKind::Alias, &a, Some(&b)),
        operation(OperationKind::Reject, &a, Some(&c)),
        operation(OperationKind::Pin, &c, None),
    ];

    let direct = ResolutionState::replay(operations.clone()).unwrap();
    let replayed = ResolutionState::replay(direct.history().to_vec()).unwrap();

    assert_eq!(direct.is_alias(a.id, b.id), replayed.is_alias(a.id, b.id));
    assert_eq!(
        direct.is_rejected(a.id, c.id),
        replayed.is_rejected(a.id, c.id)
    );
    assert_eq!(direct.is_pinned(c.id), replayed.is_pinned(c.id));
    assert_eq!(direct.history().len(), replayed.history().len());
}

/// A decision with no attributable decision-maker cannot be reviewed, appealed, or learned from.
/// This issue's security note makes actor and policy context preconditions, not metadata.
#[test]
fn a_manual_operation_without_an_actor_or_a_policy_context_is_refused() {
    let left = record("A", EntityKind::ThreatActor);
    let right = record("B", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();

    let mut anonymous = operation(OperationKind::Merge, &left, Some(&right));
    anonymous.actor = "   ".to_owned();
    assert!(matches!(
        state.apply(anonymous).unwrap_err(),
        OperationRefused::NoActor { .. }
    ));

    let mut unauthorised = operation(OperationKind::Merge, &left, Some(&right));
    unauthorised.policy_context = String::new();
    assert!(matches!(
        state.apply(unauthorised).unwrap_err(),
        OperationRefused::NoPolicyContext { .. }
    ));

    assert!(
        state.history().is_empty(),
        "a refused operation is not recorded"
    );
}

/// An operation about a pair that names only one identity is a caller bug, not a half-operation.
#[test]
fn a_pair_operation_missing_its_second_identity_is_refused() {
    let left = record("A", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();

    for kind in [
        OperationKind::Merge,
        OperationKind::Split,
        OperationKind::Reject,
        OperationKind::Alias,
    ] {
        assert!(
            matches!(
                state.apply(operation(kind, &left, None)).unwrap_err(),
                OperationRefused::NeedsPair { .. }
            ),
            "{kind} should need a pair"
        );
    }

    // A pin concerns one identity, so it is fine without a second.
    assert!(
        state
            .apply(operation(OperationKind::Pin, &left, None))
            .is_ok()
    );
}

// ---------------------------------------------------------------------------------------------
// "Rejected matches stay rejected until explicit rule change"
// ---------------------------------------------------------------------------------------------

/// The criterion. Otherwise every automatic pass re-proposes the same wrong merge and the analyst's
/// judgement is worn down by a machine that cannot remember.
#[test]
fn a_rejected_pair_stays_rejected_even_when_a_decisive_signal_appears() {
    let left = with_external(
        record("A", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("B", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    // Without the rejection this pair merges automatically.
    assert_eq!(
        Resolver::new().resolve(&left, &right).outcome,
        ResolutionOutcome::Merged
    );

    let mut state = ResolutionState::new();
    state
        .apply(operation(OperationKind::Reject, &left, Some(&right)))
        .unwrap();
    let resolver = Resolver::with_state(state);

    assert_eq!(
        resolver.resolve(&left, &right).outcome,
        ResolutionOutcome::Rejected,
        "a decisive signal must not override a standing analyst decision"
    );
}

/// A rejection must hold in both directions, or the next pass re-proposes the same merge with the
/// arguments swapped.
#[test]
fn a_rejection_is_symmetric() {
    let left = record("A", EntityKind::ThreatActor);
    let right = record("B", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();
    state
        .apply(operation(OperationKind::Reject, &left, Some(&right)))
        .unwrap();

    assert!(state.is_rejected(left.id, right.id));
    assert!(state.is_rejected(right.id, left.id));

    let resolver = Resolver::with_state(state);
    assert_eq!(
        resolver.resolve(&right, &left).outcome,
        ResolutionOutcome::Rejected
    );
}

/// A pin blocks the merge but must not hide the evidence — a reviewer needs to see what *would*
/// have happened.
#[test]
fn a_pinned_identity_blocks_the_merge_while_still_surfacing_the_signals() {
    let left = with_external(
        record("A", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("B", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    let mut state = ResolutionState::new();
    state
        .apply(operation(OperationKind::Pin, &left, None))
        .unwrap();
    let resolver = Resolver::with_state(state);

    let candidate = resolver.resolve(&left, &right);
    assert_eq!(candidate.outcome, ResolutionOutcome::Pinned);
    assert!(
        !candidate.signals.is_empty(),
        "the evidence is still shown, so a reviewer can see what the pin prevented"
    );
}

/// A pin stops a *manual* merge too. An analyst who pinned an identity should not have it merged by
/// a colleague who did not see the pin.
#[test]
fn a_pin_refuses_a_manual_merge_as_well_as_an_automatic_one() {
    let left = record("A", EntityKind::ThreatActor);
    let right = record("B", EntityKind::ThreatActor);
    let mut state = ResolutionState::new();

    state
        .apply(operation(OperationKind::Pin, &left, None))
        .unwrap();
    let error = state
        .apply(operation(OperationKind::Merge, &left, Some(&right)))
        .unwrap_err();

    assert!(
        matches!(error, OperationRefused::Pinned { .. }),
        "got {error}"
    );
    assert!(
        error.to_string().contains("precisely to stop this"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------------------------
// "Resolution is deterministic for fixed inputs"
// ---------------------------------------------------------------------------------------------

/// The criterion. Two runs over the same records must agree, or a merge appearing and disappearing
/// between imports is indistinguishable from the data changing.
#[test]
fn resolving_the_same_pair_twice_gives_an_identical_candidate() {
    let resolver = Resolver::new();
    let left = with_external(
        record("APT28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("APT-28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    assert_eq!(
        resolver.resolve(&left, &right),
        resolver.resolve(&left, &right)
    );
}

/// The pair is ordered before anything is compared, so which argument is "left" cannot change the
/// result.
#[test]
fn argument_order_does_not_change_the_candidate() {
    let resolver = Resolver::new();
    let left = with_external(
        record("APT28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );
    let right = with_external(
        record("APT-28", EntityKind::ThreatActor),
        "mitre-attack",
        "G0007",
    );

    assert_eq!(
        resolver.resolve(&left, &right),
        resolver.resolve(&right, &left)
    );
}

/// A merge chain must terminate even if a bad sequence introduces a cycle, rather than looping.
#[test]
fn following_a_merge_chain_terminates_rather_than_looping() {
    let a = record("A", EntityKind::ThreatActor);
    let b = record("B", EntityKind::ThreatActor);
    let c = record("C", EntityKind::ThreatActor);

    let mut state = ResolutionState::new();
    state
        .apply(operation(OperationKind::Merge, &a, Some(&b)))
        .unwrap();
    state
        .apply(operation(OperationKind::Merge, &b, Some(&c)))
        .unwrap();

    // Terminates; the assertion is that this returns at all.
    let identity = state.canonical_identity(c.id);
    assert!(!identity.is_empty());
}

// ---------------------------------------------------------------------------------------------
// "Merges never erase restricted markings or source lineage"
// ---------------------------------------------------------------------------------------------

/// The security note. Merging an AMBER record into a CLEAR one and keeping CLEAR would silently
/// declassify the AMBER evidence, and nobody notices until it has been shared.
#[test]
fn a_merge_keeps_the_union_of_markings_never_the_intersection() {
    let mut restricted = MarkingSet::empty();
    restricted.insert(Marking::Tlp(TlpLevel::Amber));
    restricted.insert(Marking::Pap(PapLevel::Red));

    let mut open = MarkingSet::empty();
    open.insert(Marking::Tlp(TlpLevel::Clear));

    let merged = merged_markings(&restricted, &open);
    assert!(!merge_loses_a_marking(&restricted, &open, &merged));
    assert!(
        merged
            .iter()
            .any(|marking| *marking == Marking::Tlp(TlpLevel::Amber)),
        "the restrictive marking survived"
    );
    assert!(merged.len() >= 3);
}

/// The check itself must work, or the test above is asserting against a function that always says
/// "no loss".
#[test]
fn the_marking_loss_check_detects_an_actual_loss() {
    let mut restricted = MarkingSet::empty();
    restricted.insert(Marking::Tlp(TlpLevel::Red));
    let open = MarkingSet::empty();

    assert!(
        merge_loses_a_marking(&restricted, &open, &MarkingSet::empty()),
        "dropping the RED marking must be detected"
    );
}

/// A record must not cite less evidence after a merge than before it.
#[test]
fn a_merge_keeps_every_source_from_both_sides() {
    let left = vec!["source-a".to_owned(), "source-b".to_owned()];
    let right = vec!["source-b".to_owned(), "source-c".to_owned()];

    let merged = merged_sources(&left, &right);
    assert_eq!(
        merged,
        vec![
            "source-a".to_owned(),
            "source-b".to_owned(),
            "source-c".to_owned()
        ],
        "every source, de-duplicated and ordered"
    );
    for source in left.iter().chain(right.iter()) {
        assert!(merged.contains(source), "{source} was dropped");
    }
}
