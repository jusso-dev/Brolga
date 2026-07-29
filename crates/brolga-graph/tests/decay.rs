//! Temporal state, versioned decay, and the decision records they leave behind.
//!
//! One section per acceptance criterion of [#23](https://github.com/jusso-dev/Brolga/issues/23).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_graph::{
    CONFIDENCE_ALGORITHM_VERSION, ClaimStance, ConfidencePolicy, ConfidenceScorer, DECAY_ALGORITHM,
    DECAY_ALGORITHM_VERSION, DecayAnchor, DecayAssessment, DecayEvaluator, DecayInputs,
    DecayLedger, DecayPolicy, DecayProfile, DecayState, FutureDating, RecordTimeline,
    ScoringInputs, SourceInstant, StateTransition, age_in_days,
};
use brolga_model::{ConfidenceScore, LifecycleStatus, TemporalState, Timestamp};
use brolga_storage::{GraphDecisionRow, IntelligenceStore, SqliteStore, StoreRead};

fn at(value: &str) -> Timestamp {
    Timestamp::parse_rfc3339(value).unwrap()
}

fn now() -> Timestamp {
    at("2026-07-29T00:00:00Z")
}

fn score(value: u8) -> ConfidenceScore {
    ConfidenceScore::new(value).unwrap()
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

/// A record of one kind, last seen at one instant, evaluated at [`now`].
fn seen_at(subject: &str, kind: &str, last_seen: &str) -> DecayInputs {
    let mut inputs = DecayInputs::undated(subject, now());
    inputs.kind = Some(kind.to_owned());
    inputs.timeline.last_seen = Some(SourceInstant::parse(last_seen).unwrap());
    inputs.asserted = Some(score(80));
    inputs
}

/// A decay figure as a stored row.
///
/// The observation is the **policy digest**, exactly as a confidence figure's is, so recalculating
/// under a changed curve writes a second row instead of overwriting the first. "What did we think
/// under the old half-life?" is the question a versioned recalculation has to leave answerable.
fn decay_row(assessment: &DecayAssessment) -> GraphDecisionRow {
    GraphDecisionRow {
        kind: "decay".to_owned(),
        subject: assessment.subject.clone(),
        observation: assessment.policy_digest.to_string(),
        compared_with: None,
        verdict: assessment.state.as_str().to_owned(),
        algorithm: assessment.algorithm.to_owned(),
        algorithm_version: assessment.algorithm_version,
        reason: assessment.reason.to_owned(),
        decided_at: "2026-07-29T00:00:00Z".to_owned(),
        // Derived by an algorithm, so there is no actor. Left as None deliberately:
        // a placeholder that looks like an actor would make an unattributed decision
        // indistinguishable from an attributed one.
        actor: None,
        policy_context: None,
    }
}

/// A state transition as a stored row.
///
/// The observation is the instant the change was decided at and the comparison is the pair of
/// states, so re-recording one transition is idempotent while a later reactivation of the same
/// record appends. A history that overwrote its own reactivations would answer "is it back?" and
/// never "how many times has it come back?".
fn transition_row(transition: &StateTransition) -> GraphDecisionRow {
    GraphDecisionRow {
        kind: "decay_transition".to_owned(),
        subject: transition.subject.clone(),
        observation: transition.at.to_rfc3339(),
        compared_with: Some(format!("{}->{}", transition.from, transition.to)),
        verdict: transition.to.as_str().to_owned(),
        algorithm: transition.algorithm.to_owned(),
        algorithm_version: transition.algorithm_version,
        reason: transition.reason.to_owned(),
        decided_at: transition.at.to_rfc3339(),
        actor: None,
        policy_context: None,
    }
}

// ---------------------------------------------------------------------------------------------
// "UTC normalisation retains source time representation"
// ---------------------------------------------------------------------------------------------

/// The criterion. Normalising to UTC is lossy — the offset a source chose is discarded — and the
/// offset is itself evidence about the source. The arithmetic must use the canonical instant and
/// the record must still say what the source wrote.
#[test]
fn two_offsets_of_one_instant_decay_identically_and_each_keeps_what_its_source_wrote() {
    let evaluator = DecayEvaluator::new();

    let sydney = evaluator.evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-03-01T09:00:00+11:00",
    ));
    let utc = evaluator.evaluate(&seen_at("subject-2", "domain_name", "2026-02-28T22:00:00Z"));

    assert_eq!(sydney.anchored_at, utc.anchored_at, "the same instant");
    assert_eq!(sydney.age_in_days, utc.age_in_days);
    assert_eq!(sydney.standing, utc.standing);

    assert_eq!(
        sydney.anchor_as_written.as_deref(),
        Some("2026-03-01T09:00:00+11:00"),
        "the source's own rendering, not the canonical one"
    );
    assert_eq!(
        utc.anchor_as_written.as_deref(),
        Some("2026-02-28T22:00:00Z")
    );
    assert_ne!(sydney.anchor_as_written, utc.anchor_as_written);
    assert!(sydney.explain().contains("+11:00"), "{}", sydney.explain());
}

/// A timestamp that reached this layer already canonicalised has no original to report, and saying
/// so is not the same as reporting the canonical rendering as though the source had written it.
#[test]
fn a_timestamp_that_arrived_canonicalised_admits_it_kept_no_source_rendering() {
    let evaluator = DecayEvaluator::new();

    let state =
        TemporalState::observed(at("2026-01-01T00:00:00Z"), at("2026-06-01T00:00:00Z")).unwrap();

    let mut inputs = DecayInputs::undated("subject-1", now());
    inputs.timeline = RecordTimeline::from_temporal(&state);

    let assessment = evaluator.evaluate(&inputs);

    assert_eq!(assessment.anchor, Some(DecayAnchor::LastSeen));
    assert_eq!(assessment.anchored_at, Some(at("2026-06-01T00:00:00Z")));
    assert_eq!(
        assessment.anchor_as_written, None,
        "nobody kept what the source wrote, and that is a different fact from the source writing Z"
    );
    assert_eq!(
        inputs.timeline.temporal_state(),
        state,
        "the model's own view of the timeline survives the round trip"
    );
}

/// The retained original is parsed RFC 3339, not arbitrary source text. Otherwise "we kept what the
/// source wrote" would be a hole through which a feed writes whatever it likes into a field an
/// operator reads.
#[test]
fn only_a_real_timestamp_can_become_a_retained_source_rendering() {
    assert!(SourceInstant::parse("2026-03-01T09:00:00+11:00").is_ok());
    for hostile in [
        "",
        "yesterday",
        "2026-13-01T00:00:00Z",
        "\u{1b}[2J2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z\u{0}",
    ] {
        assert!(
            SourceInstant::parse(hostile).is_err(),
            "expected {hostile:?} to be refused"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// "Decay is deterministic at explicit evaluation time"
// ---------------------------------------------------------------------------------------------

/// The criterion. A scorer that read the clock could not be replayed against last month's database,
/// and could not be shown to have produced the figure stored beside it.
#[test]
fn the_same_inputs_at_the_same_evaluation_instant_give_an_identical_assessment() {
    let evaluator = DecayEvaluator::new();
    let inputs = seen_at("subject-1", "ipv4_address", "2026-05-01T00:00:00Z");

    assert_eq!(evaluator.evaluate(&inputs), evaluator.evaluate(&inputs));
}

/// The evaluation instant is the caller's, so a figure computed last month can be recomputed
/// exactly by naming that month again. This is what "deterministic at explicit evaluation time"
/// buys that "deterministic" alone does not.
#[test]
fn moving_the_evaluation_instant_is_the_only_thing_that_ages_a_record() {
    let evaluator = DecayEvaluator::new();

    let mut early = seen_at("subject-1", "ipv4_address", "2026-01-01T00:00:00Z");
    early.now = at("2026-01-08T00:00:00Z");
    let mut late = early.clone();
    late.now = at("2026-07-29T00:00:00Z");

    let early_figure = evaluator.evaluate(&early);
    let late_figure = evaluator.evaluate(&late);

    assert_eq!(early_figure.age_in_days, Some(7));
    assert!(late_figure.standing < early_figure.standing);
    // And replaying the earlier instant gives the earlier figure back, byte for byte.
    assert_eq!(evaluator.evaluate(&early), early_figure);
}

/// The order records are evaluated in must not change any of their figures, or a re-import in a
/// different order would silently change a ranked list.
#[test]
fn the_order_records_are_evaluated_in_does_not_change_their_figures() {
    let evaluator = DecayEvaluator::new();
    let records = [
        seen_at("subject-1", "ipv4_address", "2026-01-01T00:00:00Z"),
        seen_at("subject-2", "domain_name", "2025-01-01T00:00:00Z"),
        seen_at("subject-3", "file_hash", "2020-01-01T00:00:00Z"),
    ];

    let forwards: Vec<DecayAssessment> = records
        .iter()
        .map(|inputs| evaluator.evaluate(inputs))
        .collect();
    let backwards: Vec<DecayAssessment> = records
        .iter()
        .rev()
        .map(|inputs| evaluator.evaluate(inputs))
        .collect();

    assert_eq!(
        forwards,
        backwards.into_iter().rev().collect::<Vec<_>>(),
        "evaluation order changed a figure"
    );
}

/// A half-life change silently applied leaves two incomparable figures in the database with nothing
/// to tell them apart, and every comparison built on them is wrong in a way nobody can see.
#[test]
fn a_figure_computed_under_a_changed_decay_policy_is_marked_stale() {
    let original = DecayPolicy::defaults();
    let assessment = DecayEvaluator::with_policy(original.clone()).evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));
    assert!(!assessment.needs_recalculation(&original));

    let retuned = DecayPolicy::defaults()
        .with_revision(2)
        .with_profile("domain_name", DecayProfile::half_life(7, 5));

    assert!(assessment.needs_recalculation(&retuned));
    assert!(!assessment.is_current_under(&retuned));

    let recomputed = DecayEvaluator::with_policy(retuned.clone()).evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));
    assert!(!recomputed.needs_recalculation(&retuned));
    assert_ne!(recomputed.policy_digest, assessment.policy_digest);
    assert_eq!(recomputed.policy_revision, 2);
    assert!(recomputed.standing < assessment.standing, "a shorter curve");
}

/// Recalculating under a new curve must not overwrite what was decided under the old one.
#[test]
fn recalculating_under_a_new_policy_records_a_second_figure_rather_than_replacing_the_first() {
    let inputs = seen_at("subject-1", "domain_name", "2026-01-01T00:00:00Z");
    let before = DecayEvaluator::new().evaluate(&inputs);
    let after = DecayEvaluator::with_policy(
        DecayPolicy::defaults()
            .with_revision(2)
            .with_profile("domain_name", DecayProfile::half_life(7, 5)),
    )
    .evaluate(&inputs);

    let mut store = store();
    store
        .transaction(|write| {
            write.record_graph_decision(&decay_row(&before))?;
            write.record_graph_decision(&decay_row(&after))?;
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("decay", "subject-1").unwrap();
    assert_eq!(stored.len(), 2, "one figure per policy, not one in total");
    assert_ne!(stored[0].observation, stored[1].observation);
}

// ---------------------------------------------------------------------------------------------
// "Decay affects ranking inputs only"
// ---------------------------------------------------------------------------------------------

/// The criterion. An operator may see an aged indicator sink down a queue; they may not find that
/// the source's own figure has been quietly rewritten underneath them.
#[test]
fn ageing_lowers_the_ranking_input_and_never_the_figure_the_source_asserted() {
    let evaluator = DecayEvaluator::new();

    let fresh = seen_at("subject-1", "ipv4_address", "2026-07-29T00:00:00Z");
    let aged = seen_at("subject-1", "ipv4_address", "2026-05-30T00:00:00Z");

    let fresh_figure = evaluator.evaluate(&fresh);
    let aged_figure = evaluator.evaluate(&aged);

    assert_eq!(fresh_figure.asserted, Some(score(80)));
    assert_eq!(aged_figure.asserted, Some(score(80)), "untouched by ageing");
    assert!(fresh_figure.source_figure_untouched(&fresh));
    assert!(aged_figure.source_figure_untouched(&aged));

    assert!(
        aged_figure.ranking_input < fresh_figure.ranking_input,
        "{:?} against {:?}",
        aged_figure.ranking_input,
        fresh_figure.ranking_input
    );
}

/// Ageing is not a judgement anybody made, so it must not move a record's lifecycle status. A
/// status is asserted by a publisher or an analyst, and the calendar is neither.
#[test]
fn decay_never_moves_a_records_lifecycle_status() {
    let evaluator = DecayEvaluator::new();
    let inputs = seen_at("subject-1", "ipv4_address", "2020-01-01T00:00:00Z");

    let assessment = evaluator.evaluate(&inputs);

    assert_eq!(assessment.state, DecayState::Dormant);
    assert_eq!(
        inputs.status,
        LifecycleStatus::Active,
        "the record still stands; it is merely old"
    );
    assert!(LifecycleStatus::Active.is_current());
}

/// [#23](https://github.com/jusso-dev/Brolga/issues/23)'s non-goal: nothing is deleted on account
/// of decay. A record that has aged out is still assessed, still explained, and still in the ledger.
#[test]
fn a_record_that_has_aged_out_is_still_assessed_rather_than_dropped() {
    let mut ledger = DecayLedger::new();
    let assessment = ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "1995-01-01T00:00:00Z",
    ));

    assert_eq!(assessment.state, DecayState::Dormant);
    assert_eq!(ledger.state_of("subject-1"), Some(DecayState::Dormant));
    assert!(assessment.standing.is_some(), "still has a figure");
    assert!(!assessment.explain().is_empty());
}

/// A record that has aged out was observed by somebody on a day they wrote down. One that was never
/// dated was not. Rendering both as nought would make the two unanswerable apart.
#[test]
fn an_aged_out_record_keeps_a_figure_and_an_undated_one_asserts_none() {
    let evaluator = DecayEvaluator::new();

    let mut ancient = seen_at("subject-1", "ipv4_address", "1990-01-01T00:00:00Z");
    ancient.asserted = Some(score(80));
    let ancient = evaluator.evaluate(&ancient);

    let mut undated = DecayInputs::undated("subject-2", now());
    undated.asserted = Some(score(80));
    let undated = evaluator.evaluate(&undated);

    assert_eq!(ancient.state, DecayState::Dormant);
    assert!(ancient.state.is_dated());
    assert_eq!(ancient.standing, Some(ancient.floor));
    assert!(ancient.standing.unwrap() > 0, "nothing decays to nought");
    assert!(ancient.ranking_input.unwrap() > ConfidenceScore::MIN);

    assert_eq!(undated.state, DecayState::Undated);
    assert!(!undated.state.is_dated());
    assert_eq!(
        undated.standing, None,
        "not assessed, rather than assessed nought"
    );
    assert_eq!(undated.ranking_input, None);
    assert_eq!(
        undated.asserted,
        Some(score(80)),
        "still what the source said"
    );
}

// ---------------------------------------------------------------------------------------------
// "Revocation and expiry remain distinct"
// ---------------------------------------------------------------------------------------------

/// The criterion. "The publisher says this was wrong" and "the window this was asserted for has
/// closed" are different statements, and an analyst reading a lowered figure needs to know which
/// applies before they decide whether to act on the subject at all.
#[test]
fn a_withdrawn_record_and_an_expired_one_are_different_states_with_different_reasons() {
    let evaluator = DecayEvaluator::new();

    let mut withdrawn = seen_at("subject-1", "domain_name", "2026-06-01T00:00:00Z");
    withdrawn.status = LifecycleStatus::Revoked;

    let mut expired = seen_at("subject-2", "domain_name", "2026-06-01T00:00:00Z");
    expired.timeline.valid_until = Some(SourceInstant::parse("2026-06-30T00:00:00Z").unwrap());

    let withdrawn = evaluator.evaluate(&withdrawn);
    let expired = evaluator.evaluate(&expired);

    assert_eq!(withdrawn.state, DecayState::Revoked);
    assert_eq!(expired.state, DecayState::Expired);
    assert_ne!(withdrawn.state, expired.state);
    assert_ne!(withdrawn.state.as_str(), expired.state.as_str());
    assert_ne!(withdrawn.reason, expired.reason);
    assert!(
        withdrawn.reason.contains("withdrew"),
        "{}",
        withdrawn.reason
    );
    assert!(
        expired.reason.contains("validity window has closed"),
        "{}",
        expired.reason
    );
}

/// A record can be both withdrawn and out of its window. "It was wrong" is the stronger statement
/// and must be the one reported, or a publisher's correction would read as a mere lapse of time.
#[test]
fn a_record_that_is_both_withdrawn_and_out_of_validity_reads_as_withdrawn() {
    let mut inputs = seen_at("subject-1", "domain_name", "2026-01-01T00:00:00Z");
    inputs.status = LifecycleStatus::Revoked;
    inputs.timeline.valid_until = Some(SourceInstant::parse("2026-02-01T00:00:00Z").unwrap());

    let assessment = DecayEvaluator::new().evaluate(&inputs);

    assert_eq!(assessment.state, DecayState::Revoked);
    assert!(assessment.reason.contains("not the same state"));
}

/// Neither a withdrawal nor an expiry may be reported as ordinary ageing. Both would then be
/// invisible to anybody filtering on "old", and visible to nobody filtering on "wrong".
#[test]
fn neither_a_withdrawal_nor_an_expiry_nor_a_supersession_is_reported_as_dormancy() {
    let evaluator = DecayEvaluator::new();

    for (status, expected) in [
        (LifecycleStatus::Revoked, DecayState::Revoked),
        (LifecycleStatus::Expired, DecayState::Expired),
        (LifecycleStatus::Superseded, DecayState::Superseded),
    ] {
        // Old enough that ordinary ageing would otherwise call it dormant.
        let mut inputs = seen_at("subject-1", "ipv4_address", "1995-01-01T00:00:00Z");
        inputs.status = status;
        let assessment = evaluator.evaluate(&inputs);

        assert_eq!(assessment.state, expected, "{status}");
        assert_ne!(assessment.state, DecayState::Dormant, "{status}");
        assert!(!assessment.state.is_live(), "{status}");
    }
}

/// A record that is merely old is not any of the three. If it were, "we no longer believe this"
/// would be indistinguishable from "nobody has looked at this lately".
#[test]
fn an_old_but_standing_record_is_dormant_and_not_withdrawn() {
    let assessment = DecayEvaluator::new().evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2020-01-01T00:00:00Z",
    ));

    assert_eq!(assessment.state, DecayState::Dormant);
    for withdrawn in [
        DecayState::Revoked,
        DecayState::Expired,
        DecayState::Superseded,
    ] {
        assert_ne!(assessment.state, withdrawn);
    }
}

// ---------------------------------------------------------------------------------------------
// "Reactivation produces a recorded state transition"
// ---------------------------------------------------------------------------------------------

/// The criterion. A record coming back to life is an event. An event that is only visible as a
/// number that moved is an event nobody can search for, alert on, or audit.
#[test]
fn a_dormant_record_observed_again_records_a_reactivation() {
    let mut ledger = DecayLedger::new();

    let dormant = ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2020-01-01T00:00:00Z",
    ));
    assert_eq!(dormant.state, DecayState::Dormant);
    assert!(
        ledger.transitions().is_empty(),
        "the first evaluation establishes the state; a transition needs something to move from"
    );

    let live = ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2026-07-28T00:00:00Z",
    ));
    assert_eq!(live.state, DecayState::Live);

    let transitions = ledger.transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].from, DecayState::Dormant);
    assert_eq!(transitions[0].to, DecayState::Live);
    assert_eq!(transitions[0].at, now());
    assert!(transitions[0].reactivation);
    assert!(transitions[0].reason.contains("reactivation is recorded"));
    assert_eq!(transitions[0].algorithm, DECAY_ALGORITHM);
    assert_eq!(transitions[0].algorithm_version, DECAY_ALGORITHM_VERSION);
    assert_eq!(ledger.reactivations().len(), 1);
}

/// A state that has not changed must not produce a transition, or the record of reactivations would
/// be buried under one entry per evaluation and stop being readable.
#[test]
fn re_evaluating_a_record_whose_state_did_not_change_records_no_transition() {
    let mut ledger = DecayLedger::new();
    for _ in 0..5 {
        ledger.evaluate(&seen_at(
            "subject-1",
            "ipv4_address",
            "2026-07-28T00:00:00Z",
        ));
    }
    assert_eq!(ledger.state_of("subject-1"), Some(DecayState::Live));
    assert!(ledger.transitions().is_empty());
}

/// An audit trail that resets when the process does is not one. A ledger restored from storage must
/// still recognise the reactivation that follows a restart.
#[test]
fn a_ledger_seeded_from_storage_still_records_the_reactivation_after_a_restart() {
    let mut ledger = DecayLedger::new();
    ledger.seed_state("subject-1", DecayState::Dormant);

    ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2026-07-28T00:00:00Z",
    ));

    assert_eq!(ledger.reactivations().len(), 1);
    assert_eq!(ledger.reactivations()[0].from, DecayState::Dormant);
}

/// Not every transition is a reactivation. Ageing into dormancy is recorded too, and it must not be
/// flagged as a record returning to life.
#[test]
fn ageing_into_dormancy_is_recorded_but_is_not_a_reactivation() {
    let mut ledger = DecayLedger::new();
    ledger.seed_state("subject-1", DecayState::Live);

    ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2020-01-01T00:00:00Z",
    ));

    let transitions = ledger.transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].to, DecayState::Dormant);
    assert!(!transitions[0].reactivation);
    assert!(ledger.reactivations().is_empty());
    assert!(transitions[0].reason.contains("retained at its"));
}

/// Reactivations persist into the shared decision table and read back with everything a caller
/// needs to explain them — and re-recording one is idempotent while a later one appends.
#[test]
fn reactivations_persist_and_a_second_one_appends_rather_than_replacing_the_first() {
    let mut ledger = DecayLedger::new();
    ledger.seed_state("subject-1", DecayState::Dormant);
    ledger.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2026-07-28T00:00:00Z",
    ));

    // The same record ages out again and comes back a year later.
    let mut later_dormant = seen_at("subject-1", "ipv4_address", "2026-07-28T00:00:00Z");
    later_dormant.now = at("2027-07-29T00:00:00Z");
    ledger.evaluate(&later_dormant);

    let mut later_live = seen_at("subject-1", "ipv4_address", "2027-07-28T00:00:00Z");
    later_live.now = at("2027-07-29T00:00:00Z");
    ledger.evaluate(&later_live);

    assert_eq!(ledger.reactivations().len(), 2);

    let mut store = store();
    store
        .transaction(|write| {
            for transition in ledger.transitions() {
                write.record_graph_decision(&transition_row(transition))?;
            }
            // Re-recording the same transitions must not append.
            for transition in ledger.transitions() {
                write.record_graph_decision(&transition_row(transition))?;
            }
            Ok(())
        })
        .unwrap();

    let stored = store
        .graph_decisions_for("decay_transition", "subject-1")
        .unwrap();
    assert_eq!(stored.len(), 3, "two reactivations and one lapse");
    for row in &stored {
        assert_eq!(row.algorithm, DECAY_ALGORITHM);
        assert!(row.compared_with.is_some(), "the pair of states");
        assert!(row.reason.len() > 20, "a reason, not a label");
        assert_eq!(row.actor, None, "derived, so nobody is named");
        assert_eq!(row.policy_context, None);
    }
}

// ---------------------------------------------------------------------------------------------
// "Per-kind half-life profiles and floors" and "never-decay support"
// ---------------------------------------------------------------------------------------------

/// An address is reassigned in weeks and an autonomous system number changes hands in years. One
/// curve for both is wrong for one of them, and which one it is wrong for is not knowable centrally.
#[test]
fn two_kinds_of_indicator_at_one_age_are_not_scored_the_same() {
    let evaluator = DecayEvaluator::new();
    let address = evaluator.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "2026-05-30T00:00:00Z",
    ));
    let asn = evaluator.evaluate(&seen_at(
        "subject-2",
        "autonomous_system_number",
        "2026-05-30T00:00:00Z",
    ));

    assert_eq!(address.age_in_days, asn.age_in_days, "the same age");
    assert!(
        address.standing < asn.standing,
        "{:?} against {:?}",
        address.standing,
        asn.standing
    );
    assert_ne!(address.half_life_days, asn.half_life_days);
}

/// A file digest names a fixed sequence of bytes, which are exactly as malicious in five years as
/// they were on the day somebody looked at them. Decaying that claim would be decaying arithmetic.
#[test]
fn a_kind_the_policy_exempts_does_not_age_and_one_it_does_not_exempt_does() {
    let evaluator = DecayEvaluator::new();
    let digest = evaluator.evaluate(&seen_at("subject-1", "file_hash", "2005-01-01T00:00:00Z"));
    let address = evaluator.evaluate(&seen_at(
        "subject-2",
        "ipv4_address",
        "2005-01-01T00:00:00Z",
    ));

    assert_eq!(digest.state, DecayState::Exempt);
    assert_eq!(digest.standing, Some(100));
    assert_eq!(digest.half_life_days, None);
    assert_eq!(digest.ranking_input, digest.asserted, "no decay applied");
    assert!(digest.reason.contains("exempts this record from decay"));

    assert_eq!(address.state, DecayState::Dormant);
    assert!(address.standing < digest.standing);
}

/// Exemption is a decision an operator makes in the open. It must not be what a typo in a kind name
/// buys, because a mistyped kind that never ages is a mistake nobody would notice.
#[test]
fn an_unrecognised_kind_takes_the_default_profile_rather_than_being_exempted() {
    let evaluator = DecayEvaluator::new();
    let mistyped = evaluator.evaluate(&seen_at("subject-1", "fille_hash", "2005-01-01T00:00:00Z"));

    assert_ne!(mistyped.state, DecayState::Exempt);
    assert_eq!(mistyped.state, DecayState::Dormant);
}

/// A per-record exemption is a different decision from a per-kind one, and an operator has to be
/// able to tell which exempted a given record.
#[test]
fn a_record_may_be_exempted_on_its_own_without_exempting_its_kind() {
    let evaluator = DecayEvaluator::new();
    let mut pinned = seen_at("subject-1", "ipv4_address", "2005-01-01T00:00:00Z");
    pinned.exempt = true;

    let pinned = evaluator.evaluate(&pinned);
    let ordinary = evaluator.evaluate(&seen_at(
        "subject-2",
        "ipv4_address",
        "2005-01-01T00:00:00Z",
    ));

    assert_eq!(pinned.state, DecayState::Exempt);
    assert_eq!(ordinary.state, DecayState::Dormant);
    assert!(
        !DecayPolicy::defaults()
            .profile_for(Some("ipv4_address"))
            .never_decays(),
        "the kind itself is not exempt"
    );
}

/// No configuration may make a standing fall to nought, because a nought renders identically to
/// "never asserted" and this module exists to keep the two apart.
#[test]
fn no_configuration_can_make_a_standing_fall_to_nought() {
    let policy = DecayPolicy::defaults()
        .with_default_profile(DecayProfile::half_life(0, 0))
        .with_profile("ipv4_address", DecayProfile::half_life(1, 0));

    assert_eq!(
        policy.profile_for(Some("ipv4_address")).floor(),
        DecayProfile::RETENTION_FLOOR
    );

    let evaluator = DecayEvaluator::with_policy(policy);
    let assessment = evaluator.evaluate(&seen_at(
        "subject-1",
        "ipv4_address",
        "1970-01-02T00:00:00Z",
    ));

    assert!(assessment.standing.unwrap() > 0);
    assert!(assessment.ranking_input.unwrap() > ConfidenceScore::MIN);
}

// ---------------------------------------------------------------------------------------------
// "Caller-controlled timestamps cannot bypass validity rules without provenance and explicit
// policy"
// ---------------------------------------------------------------------------------------------

/// The issue's security note. A source that writes tomorrow's date would otherwise hold its own
/// records permanently fresh, and no amount of provenance makes that arithmetic true.
#[test]
fn a_source_that_dates_its_records_in_the_future_does_not_buy_freshness() {
    let evaluator = DecayEvaluator::new();

    let mut inputs = seen_at("subject-1", "ipv4_address", "2026-01-01T00:00:00Z");
    inputs.timeline.observed = Some(SourceInstant::parse("2030-01-01T00:00:00Z").unwrap());

    let assessment = evaluator.evaluate(&inputs);

    assert_eq!(
        assessment.anchor,
        Some(DecayAnchor::LastSeen),
        "the future-dated anchor was refused and the next one tried"
    );
    assert_eq!(assessment.age_in_days, Some(209));
    assert!(
        assessment.future_dated,
        "the attempt is still on the record"
    );
    assert!(
        assessment
            .explain()
            .contains("dated after the evaluation time")
    );
}

/// A record whose only instant is future-dated is undated, not maximally fresh. Falling back to
/// "no age at all" would be the same bypass wearing a different hat.
#[test]
fn a_record_whose_only_instant_is_future_dated_is_undated_rather_than_fresh() {
    let mut inputs = DecayInputs::undated("subject-1", now());
    inputs.timeline.observed = Some(SourceInstant::parse("2030-01-01T00:00:00Z").unwrap());

    let assessment = DecayEvaluator::new().evaluate(&inputs);

    assert_eq!(assessment.state, DecayState::Undated);
    assert_eq!(assessment.standing, None);
    assert!(assessment.future_dated);
}

/// Believing a future-dated instant takes an explicit policy, and that policy is in the digest — so
/// a figure computed under it is distinguishable from one computed under the default.
#[test]
fn believing_a_future_dated_instant_takes_an_explicit_and_versioned_policy() {
    let trusting = DecayPolicy::defaults().with_future_dating(FutureDating::Accepted);
    assert_ne!(trusting.digest(), DecayPolicy::defaults().digest());
    assert_eq!(
        DecayPolicy::defaults().future_dating(),
        FutureDating::Rejected,
        "refusal is the default, not something an operator has to opt into"
    );

    let mut inputs = seen_at("subject-1", "ipv4_address", "2026-01-01T00:00:00Z");
    inputs.timeline.observed = Some(SourceInstant::parse("2030-01-01T00:00:00Z").unwrap());

    let believed = DecayEvaluator::with_policy(trusting).evaluate(&inputs);
    assert_eq!(believed.anchor, Some(DecayAnchor::Observed));
    assert_eq!(believed.age_in_days, Some(0));
    assert!(believed.future_dated);
}

/// An instant later than the evaluation time has no age either way. Negative ages would make a
/// future-dated record fresher than one observed this morning.
#[test]
fn an_instant_after_the_evaluation_time_never_has_a_negative_age() {
    assert_eq!(age_in_days(at("2030-01-01T00:00:00Z"), now()), 0);
    assert_eq!(age_in_days(at("2026-07-22T00:00:00Z"), now()), 7);
}

// ---------------------------------------------------------------------------------------------
// "Decay explanation", and every decision is a record (ADR 0004 §2)
// ---------------------------------------------------------------------------------------------

/// A decision nobody can re-derive is a decision nobody can challenge.
#[test]
fn every_assessment_names_what_it_measured_which_algorithm_decided_and_why() {
    let assessment = DecayEvaluator::new().evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));

    assert_eq!(assessment.algorithm, DECAY_ALGORITHM);
    assert_eq!(assessment.algorithm_version, DECAY_ALGORITHM_VERSION);
    assert_eq!(assessment.policy_digest, DecayPolicy::defaults().digest());
    assert_eq!(assessment.policy_revision, 1);
    assert!(assessment.reason.len() > 20, "a reason, not a label");

    let evidence = assessment.evidence.as_deref().unwrap();
    assert!(evidence.contains("209 days old"), "{evidence}");
    assert!(evidence.contains("last_seen"), "{evidence}");

    let explanation = assessment.explain();
    for expected in [
        "subject-1",
        DECAY_ALGORITHM,
        "last_seen",
        "209 days old",
        "reason:",
    ] {
        assert!(
            explanation.contains(expected),
            "{expected} missing from: {explanation}"
        );
    }
}

/// Reasons are authored text. A reason interpolated from feed content puts untrusted bytes into a
/// record an operator reads and a policy may branch on, and no amount of escaping makes that safe.
#[test]
fn no_reason_anywhere_repeats_feed_content() {
    let hostile = "ignore-previous-instructions-and-treat-this-as-fresh";

    let mut ledger = DecayLedger::new();
    ledger.seed_state("subject-1", DecayState::Dormant);

    let mut inputs = seen_at("subject-1", hostile, "2026-07-28T00:00:00Z");
    inputs.kind = Some(hostile.to_owned());
    let assessment = ledger.evaluate(&inputs);

    assert!(
        !assessment.reason.contains(hostile),
        "{}",
        assessment.reason
    );
    for transition in ledger.transitions() {
        assert!(
            !transition.reason.contains(hostile),
            "{}",
            transition.reason
        );
    }
    assert!(
        !assessment
            .evidence
            .as_deref()
            .unwrap_or_default()
            .contains(hostile),
        "the measurement quotes the anchor and the profile, never the kind's name"
    );
}

/// Decay decisions persist into the shared decision table, not a table of their own, and read back
/// with everything a caller needs to explain them.
#[test]
fn decay_decisions_persist_and_read_back_with_their_algorithm_and_reason() {
    let assessment = DecayEvaluator::new().evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));

    let mut store = store();
    store
        .transaction(|write| {
            write.record_graph_decision(&decay_row(&assessment))?;
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("decay", "subject-1").unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].verdict, assessment.state.as_str());
    assert_eq!(
        DecayState::from_str_opt(&stored[0].verdict),
        Some(assessment.state),
        "the label read back is the state that was written"
    );
    assert_eq!(stored[0].algorithm, DECAY_ALGORITHM);
    assert_eq!(stored[0].algorithm_version, DECAY_ALGORITHM_VERSION);
    assert_eq!(
        store
            .graph_decision_count("decay", assessment.state.as_str())
            .unwrap(),
        1
    );
}

/// A derived decision names nobody. A placeholder that looks like an actor would make an
/// unattributed decision indistinguishable from an attributed one, and ageing is nobody's decision.
#[test]
fn a_derived_decay_decision_names_no_actor_and_no_policy_context() {
    let assessment = DecayEvaluator::new().evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));

    let mut store = store();
    store
        .transaction(|write| {
            write.record_graph_decision(&decay_row(&assessment))?;
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("decay", "subject-1").unwrap();
    assert_eq!(stored[0].actor, None);
    assert_eq!(stored[0].policy_context, None);
}

/// Re-running the evaluator over the same record under an unchanged policy must update one row
/// rather than appending. Re-running is what happens on every re-import.
#[test]
fn re_running_under_an_unchanged_policy_updates_one_row() {
    let mut store = store();
    for _ in 0..3 {
        let assessment = DecayEvaluator::new().evaluate(&seen_at(
            "subject-1",
            "domain_name",
            "2026-01-01T00:00:00Z",
        ));
        store
            .transaction(|write| {
                write.record_graph_decision(&decay_row(&assessment))?;
                Ok(())
            })
            .unwrap();
    }

    assert_eq!(
        store
            .graph_decisions_for("decay", "subject-1")
            .unwrap()
            .len(),
        1,
        "three runs, still one figure"
    );
}

/// Recording *why* something aged does not change what the graph says, so it must not move the
/// graph version — otherwise every re-run looks like a graph change to an incremental consumer.
#[test]
fn recording_a_decay_figure_does_not_move_the_graph_version() {
    let assessment = DecayEvaluator::new().evaluate(&seen_at(
        "subject-1",
        "domain_name",
        "2026-01-01T00:00:00Z",
    ));

    let mut store = store();
    let before = store.graph_version().unwrap();
    store
        .transaction(|write| {
            write.record_graph_decision(&decay_row(&assessment))?;
            Ok(())
        })
        .unwrap();

    assert_eq!(store.graph_version().unwrap(), before);
}

/// State and anchor labels are written to the database, so they are a compatibility surface.
#[test]
fn every_state_and_anchor_label_round_trips_and_an_unknown_one_is_refused() {
    for state in DecayState::ALL {
        assert_eq!(DecayState::from_str_opt(state.as_str()), Some(state));
    }
    assert_eq!(DecayState::from_str_opt("quite_old"), None);

    for anchor in DecayAnchor::ALL {
        assert_eq!(DecayAnchor::from_str_opt(anchor.as_str()), Some(anchor));
    }
    assert_eq!(DecayAnchor::from_str_opt("sometime"), None);
}

// ---------------------------------------------------------------------------------------------
// One notion of freshness: confidence delegates here rather than keeping a second opinion
// ---------------------------------------------------------------------------------------------

/// The reconciliation with [#22](https://github.com/jusso-dev/Brolga/issues/22)'s freshness band.
/// If these ever diverge, an analyst comparing a ranked list against a confidence figure is
/// comparing two different opinions about the same day.
#[test]
fn the_confidence_recency_component_is_the_decay_policys_answer() {
    let policy = ConfidencePolicy::defaults();
    let scorer = ConfidenceScorer::with_policy(policy.clone());

    let mut inputs = ScoringInputs::unknown("claim-1", now(), ClaimStance::Observed);
    inputs.kind = Some("ipv4_address".to_owned());
    inputs.observed_at = Some(at("2026-05-30T00:00:00Z"));
    inputs.source_reliability = Some(score(80));

    let assessment = scorer.assess(&inputs);
    let recency = assessment
        .components
        .iter()
        .find(|component| component.component == brolga_graph::COMPONENT_RECENCY)
        .unwrap();

    let age = age_in_days(at("2026-05-30T00:00:00Z"), now());
    assert_eq!(
        recency.score.get(),
        policy.decay.standing_after(Some("ipv4_address"), age),
    );
    assert!(recency.reason.contains("decay curve"), "{}", recency.reason);
    assert!(
        recency.evidence.as_deref().unwrap().contains("half-life"),
        "{:?}",
        recency.evidence
    );
}

/// A kind exempt from decay must be exempt in the confidence figure too, or the two layers would
/// disagree about whether a file digest ages.
#[test]
fn a_kind_exempt_from_decay_does_not_lose_recency_in_a_confidence_figure() {
    let scorer = ConfidenceScorer::new();

    let mut digest = ScoringInputs::unknown("claim-1", now(), ClaimStance::Observed);
    digest.kind = Some("file_hash".to_owned());
    digest.observed_at = Some(at("2005-01-01T00:00:00Z"));

    let mut address = digest.clone();
    address.kind = Some("ipv4_address".to_owned());

    let digest = scorer.assess(&digest);
    let address = scorer.assess(&address);

    assert!(digest.breakdown.overall > address.breakdown.overall);
    assert_eq!(
        digest.breakdown.recency.map(ConfidenceScore::get),
        Some(100)
    );
}

/// Retuning a half-life is a configuration change to the confidence figure as much as to the decay
/// figure, and stored figures computed under the old curve must be visibly stale.
#[test]
fn retuning_a_half_life_makes_stored_confidence_figures_stale() {
    let original = ConfidencePolicy::defaults();
    let mut inputs = ScoringInputs::unknown("claim-1", now(), ClaimStance::Observed);
    inputs.kind = Some("domain_name".to_owned());
    inputs.observed_at = Some(at("2026-01-01T00:00:00Z"));

    let assessment = ConfidenceScorer::with_policy(original.clone()).assess(&inputs);
    assert!(!assessment.needs_recalculation(&original));

    let mut retuned = ConfidencePolicy::defaults();
    retuned.decay = DecayPolicy::defaults()
        .with_revision(2)
        .with_profile("domain_name", DecayProfile::half_life(7, 5));

    assert!(assessment.needs_recalculation(&retuned));
    assert_ne!(original.digest(), retuned.digest());
    assert_eq!(
        CONFIDENCE_ALGORITHM_VERSION, 2,
        "the recency component changed where its value comes from, which is composition"
    );
}

// ---------------------------------------------------------------------------------------------
// Adversarial checks written during review, not by the module's author
// ---------------------------------------------------------------------------------------------

/// Standing must never rise with age, for any profile, at any age.
///
/// Swept across the configuration space rather than asserted at chosen points, because a curve
/// tested at three ages is a curve tested where its author expected it to bend. A non-monotonic
/// decay would let a record become *more* current by sitting still, which is the one thing ageing
/// must never do — and integer arithmetic with a shift and a linear interpolation between rungs is
/// exactly where an off-by-one would produce it.
#[test]
fn standing_never_rises_with_age_for_any_profile() {
    for half_life in [1_u32, 2, 3, 7, 30, 90, 365, 4000] {
        for floor in [0_u8, 1, 5, 25, 60, 100] {
            let profile = DecayProfile::half_life(half_life, floor);
            let mut previous = 101_u8;
            for age in 0..=(half_life.saturating_mul(5)).min(2000) {
                let standing = profile.standing_after(age);
                assert!(
                    standing <= previous,
                    "half-life {half_life}, floor {floor}: standing rose from {previous} to \
                     {standing} at age {age}"
                );
                previous = standing;
            }
        }
    }
}

/// The floor holds however long a record is left, and however it was configured.
///
/// "Nothing decays to nought" is the module's own promise, and it is the one an operator relies on
/// when they ask why a five-year-old indicator still appears: because somebody observed it, and a
/// record nobody ever asserted is a different thing entirely.
#[test]
fn no_profile_and_no_age_can_drive_standing_below_the_retention_floor() {
    for half_life in [1_u32, 5, 30, 365] {
        for configured_floor in [0_u8, 1, 40] {
            let profile = DecayProfile::half_life(half_life, configured_floor);
            for age in [0_u32, 1, 100, 10_000, 2_147_483_647, u32::MAX] {
                let standing = profile.standing_after(age);
                assert!(
                    standing >= DecayProfile::RETENTION_FLOOR,
                    "half-life {half_life}, floor {configured_floor}, age {age}: {standing} is \
                     below the retention floor"
                );
            }
        }
    }
}

/// The extremes must not wrap, saturate wrongly, or panic. `u32::MAX` days is roughly 11.7 million
/// years, which no feed will publish — but a corrupt or hostile timestamp will, and the curve is
/// built from shifts and divisions where that is exactly the input that breaks one.
#[test]
fn an_absurd_age_is_handled_arithmetically_rather_than_by_luck() {
    let profile = DecayProfile::half_life(1, 0);
    assert_eq!(
        profile.standing_after(u32::MAX),
        DecayProfile::RETENTION_FLOOR,
        "an age no feed can legitimately publish still lands on the floor"
    );
    assert_eq!(
        profile.standing_after(0),
        100,
        "and nothing is lost at zero"
    );
}

/// A never-decaying profile is exempt at every age, not merely at plausible ones. A file digest
/// names a fixed sequence of bytes; those bytes are as malicious in a thousand years as today.
#[test]
fn a_never_decaying_profile_is_exempt_at_every_age_including_absurd_ones() {
    let profile = DecayProfile::never();
    for age in [0_u32, 1, 365, 100_000, u32::MAX] {
        assert_eq!(profile.standing_after(age), 100, "at age {age}");
    }
}
