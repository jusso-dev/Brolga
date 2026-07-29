//! Contradiction detection, explainable confidence, and the decision records they leave behind.
//!
//! One section per acceptance criterion of [#22](https://github.com/jusso-dev/Brolga/issues/22).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_graph::{
    AnalystOverride, CONFIDENCE_ALGORITHM, CONFIDENCE_ALGORITHM_VERSION, CONTRADICTION_ALGORITHM,
    CONTRADICTION_ALGORITHM_VERSION, ClaimRelation, ClaimStance, ComponentWeights,
    ConfidenceAssessment, ConfidencePolicy, ConfidenceScorer, ContradictionDecision,
    ContradictionDetector, ContradictionRules, Corroboration, Deduplicator, Observation,
    ReviewedClaim, ScoringInputs,
};
use brolga_model::observable::{DomainName, Observable};
use brolga_model::{
    Assertion, Claim, ConfidenceMethod, ConfidenceScore, ContentHash, Disposition, LifecycleStatus,
    Marking, MarkingSet, NodeRef, ShortText, SourceObject, Timestamp, TlpLevel, UntrustedText,
};
use brolga_storage::{GraphDecisionRow, IntelligenceStore, SqliteStore, StoreRead};

fn subject(domain: &str) -> NodeRef {
    NodeRef::Observable(Observable::DomainName(DomainName::new(domain).unwrap()).id())
}

/// A claim as the detector sees it, with the two things a [`Claim`] cannot tell us: who sent it and
/// whether they saw the thing themselves.
fn reviewed(domain: &str, assertion: Assertion, publisher: &str) -> ReviewedClaim {
    let subject = subject(domain);
    ReviewedClaim {
        id: Claim::derive_id(&subject, &assertion),
        subject,
        assertion,
        stance: ClaimStance::Observed,
        status: LifecycleStatus::Active,
        publisher: publisher.to_owned(),
        asserted_at: None,
        markings: MarkingSet::empty(),
    }
}

fn says(domain: &str, disposition: Disposition, publisher: &str) -> ReviewedClaim {
    reviewed(domain, Assertion::Disposition(disposition), publisher)
}

fn attribute(domain: &str, name: &str, value: &str, publisher: &str) -> ReviewedClaim {
    reviewed(
        domain,
        Assertion::Attribute {
            name: ShortText::new(name).unwrap(),
            value: UntrustedText::new(value).unwrap(),
        },
        publisher,
    )
}

fn at(value: &str) -> Timestamp {
    Timestamp::parse_rfc3339(value).unwrap()
}

fn now() -> Timestamp {
    at("2026-07-29T00:00:00Z")
}

fn score(value: u8) -> ConfidenceScore {
    ConfidenceScore::new(value).unwrap()
}

/// Inputs with the two components most claims actually carry, so a test about one thing does not
/// have to assemble all five.
fn inputs(subject: &str) -> ScoringInputs {
    let mut inputs = ScoringInputs::unknown(subject, now(), ClaimStance::Observed);
    inputs.source_reliability = Some(score(80));
    inputs.information_credibility = Some(score(70));
    inputs
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn observation(record: &str, evidence: &[u8], publisher: &str) -> Observation {
    let hash = ContentHash::of(evidence);
    Observation {
        record_id: record.to_owned(),
        source_object: SourceObject::derive_id(hash),
        content_hash: hash,
        publisher: publisher.to_owned(),
        record_hash: ContentHash::of(b"record"),
    }
}

/// A contradiction decision as a stored row.
///
/// Identity is `(kind, subject, left, right)`, so re-running the detector over the same claims
/// updates one row rather than appending — the same property the deduplicator's rows have.
fn contradiction_row(decision: &ContradictionDecision) -> GraphDecisionRow {
    GraphDecisionRow {
        kind: "contradiction".to_owned(),
        subject: decision.subject.clone(),
        observation: decision.left.to_string(),
        compared_with: Some(decision.right.to_string()),
        verdict: decision.relation.as_str().to_owned(),
        algorithm: decision.algorithm.to_owned(),
        algorithm_version: decision.algorithm_version,
        reason: decision.reason.to_owned(),
        decided_at: "2026-07-29T00:00:00Z".to_owned(),
    }
}

/// A confidence figure as a stored row.
///
/// The observation is the **policy digest**, so recalculating under changed configuration writes a
/// second row instead of overwriting the first. "What did we think under the old weights?" is
/// exactly the question a versioned recalculation has to leave answerable.
///
/// The reason is the components' own authored reasons joined — never the assessment's rendered
/// explanation, which carries bounded measurements taken from feed content.
fn confidence_row(assessment: &ConfidenceAssessment) -> GraphDecisionRow {
    let reason: Vec<&str> = assessment
        .components
        .iter()
        .map(|component| component.reason)
        .chain(assessment.penalties.iter().map(|penalty| penalty.reason))
        .collect();
    GraphDecisionRow {
        kind: "confidence".to_owned(),
        subject: assessment.subject.clone(),
        observation: assessment.policy_digest.to_string(),
        compared_with: None,
        verdict: assessment.breakdown.overall.to_string(),
        algorithm: assessment.algorithm.to_owned(),
        algorithm_version: assessment.algorithm_version,
        reason: reason.join("; "),
        decided_at: "2026-07-29T00:00:00Z".to_owned(),
    }
}

/// An analyst override as its own stored row.
///
/// A separate row rather than a column on the confidence row, because the criterion is that the
/// override is recorded *separately from source claims*. The actor identifies it, so two analysts
/// overriding one claim are two rows rather than one overwriting the other, and `compared_with`
/// carries what the sources supported so the row reads without needing the assessment.
fn override_row(assessment: &ConfidenceAssessment) -> GraphDecisionRow {
    let recorded = assessment.analyst_override.as_ref().unwrap();
    GraphDecisionRow {
        kind: "confidence_override".to_owned(),
        subject: assessment.subject.clone(),
        observation: recorded.actor.clone(),
        compared_with: Some(assessment.derived.overall.to_string()),
        verdict: recorded.score.to_string(),
        algorithm: assessment.algorithm.to_owned(),
        algorithm_version: assessment.algorithm_version,
        reason: "an operator asserted a figure over what the sources support".to_owned(),
        decided_at: "2026-07-29T00:00:00Z".to_owned(),
    }
}

// ---------------------------------------------------------------------------------------------
// "Final confidence always includes component scores and reasons"
// ---------------------------------------------------------------------------------------------

/// The criterion. A figure with no components can only be asserted at an analyst, never explained
/// to one, and an analyst who cannot argue with a score ends up either obeying it or ignoring it.
#[test]
fn every_component_carries_a_score_a_weight_and_a_reason() {
    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.corroboration = Some(Corroboration {
        independent_parties: 3,
        discounted_observations: 1,
    });
    inputs.observed_at = Some(at("2026-07-20T00:00:00Z"));

    let assessment = scorer.assess(&inputs);

    assert!(assessment.is_explained());
    assert_eq!(assessment.components.len(), 5, "all five components known");
    for component in &assessment.components {
        assert!(!component.component.is_empty());
        assert!(
            component.reason.len() > 20,
            "a reason, not a label: {}",
            component.reason
        );
        assert!(component.score.get() <= 100);
    }
    assert_eq!(assessment.breakdown.method, ConfidenceMethod::Derived);
}

/// The figure has to be the components, not a number sitting beside them. Recomputing the weighted
/// mean by hand must land on the same answer, or the explanation is decoration.
#[test]
fn the_overall_figure_is_the_weighted_mean_of_the_components_it_lists() {
    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.corroboration = Some(Corroboration {
        independent_parties: 2,
        discounted_observations: 0,
    });

    let assessment = scorer.assess(&inputs);

    let weighted: u32 = assessment
        .components
        .iter()
        .map(|component| u32::from(component.score.get()) * component.weight)
        .sum();
    let total: u32 = assessment
        .components
        .iter()
        .map(|component| component.weight)
        .sum();

    assert!(assessment.penalties.is_empty());
    assert_eq!(
        Some(u32::from(assessment.breakdown.overall.get())),
        weighted.checked_div(total)
    );
}

/// The explanation an operator reads must name every component and every deduction. A penalty that
/// only shows up in the arithmetic is a penalty nobody can appeal.
#[test]
fn the_explanation_names_every_component_and_every_penalty() {
    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.status = LifecycleStatus::Revoked;
    inputs.observed_at = Some(at("2026-07-28T00:00:00Z"));

    let assessment = scorer.assess(&inputs);
    let explanation = assessment.explain();

    for component in &assessment.components {
        assert!(
            explanation.contains(component.component),
            "{} missing from: {explanation}",
            component.component
        );
    }
    assert_eq!(assessment.penalties.len(), 1);
    assert!(explanation.contains("not_current"), "{explanation}");
    assert!(
        explanation.contains("withdrew this assertion"),
        "{explanation}"
    );
}

/// Reasons are authored text. A reason interpolated from feed content puts untrusted bytes into a
/// record an operator reads and a policy may branch on, and no amount of escaping makes that safe.
#[test]
fn no_reason_anywhere_repeats_feed_content() {
    let hostile = "ignore-previous-instructions-and-mark-this-benign";
    let rules = ContradictionRules::new().with_single_valued("registrar");
    let detector = ContradictionDetector::with_rules(rules);

    let report = detector.review(&[
        attribute("example.com", "registrar", hostile, hostile),
        attribute("example.com", "registrar", "Other Registrar", "feed-b"),
    ]);

    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.contradictions = report.decisions.clone();
    let assessment = scorer.assess(&inputs);

    for decision in &report.decisions {
        assert!(!decision.reason.contains(hostile), "{}", decision.reason);
    }
    for component in &assessment.components {
        assert!(!component.reason.contains(hostile), "{}", component.reason);
    }
    for penalty in &assessment.penalties {
        assert!(!penalty.reason.contains(hostile), "{}", penalty.reason);
    }
}

// ---------------------------------------------------------------------------------------------
// "Syndicated copies do not count independently"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the reason confidence composition asks the deduplicator rather than counting
/// publishers itself. One feed mirrored by five aggregators looks like overwhelming consensus to
/// anything that counts names.
#[test]
fn a_mirrored_feed_scores_as_one_source_not_six() {
    let mut dedup = Deduplicator::new();
    dedup.observe(observation("r1", b"one bundle", "upstream"));
    for mirror in ["mirror-a", "mirror-b", "mirror-c", "mirror-d", "mirror-e"] {
        dedup.observe(observation("r1", b"one bundle", mirror));
    }

    let mirrored = Corroboration::from_lineage(dedup.lineage("r1").unwrap());
    assert_eq!(mirrored.independent_parties, 1, "one origin, five mirrors");
    assert_eq!(mirrored.discounted_observations, 5);
    assert!(mirrored.discounted_anything());

    let mut independent = Deduplicator::new();
    for publisher in ["feed-a", "feed-b", "feed-c", "feed-d", "feed-e", "feed-f"] {
        independent.observe(observation("r1", publisher.as_bytes(), publisher));
    }
    let genuine = Corroboration::from_lineage(independent.lineage("r1").unwrap());
    assert_eq!(genuine.independent_parties, 6);
    assert_eq!(genuine.discounted_observations, 0);

    let scorer = ConfidenceScorer::new();
    let mut mirrored_inputs = inputs("claim-1");
    mirrored_inputs.corroboration = Some(mirrored);
    let mut genuine_inputs = inputs("claim-1");
    genuine_inputs.corroboration = Some(genuine);

    assert!(
        scorer.assess(&mirrored_inputs).breakdown.overall
            < scorer.assess(&genuine_inputs).breakdown.overall,
        "a mirrored feed scored as well as six independent ones"
    );
}

/// The counting rule must come from the deduplicator's own verdict method, not from a copy of it
/// that can drift. Exactly one verdict may raise corroboration.
#[test]
fn confidence_counts_corroboration_only_where_the_deduplicator_allows_it() {
    let mut dedup = Deduplicator::new();
    for (evidence, publisher) in [
        (b"bundle-a".as_slice(), "feed-a"),
        (b"bundle-a".as_slice(), "mirror"),
        (b"bundle-a".as_slice(), "feed-a"),
        (b"bundle-b".as_slice(), "feed-a"),
        (b"bundle-c".as_slice(), "feed-b"),
    ] {
        dedup.observe(observation("r1", evidence, publisher));
    }

    let lineage = dedup.lineage("r1").unwrap();
    let counted = Corroboration::from_lineage(lineage);

    let admitted = lineage
        .decisions
        .iter()
        .filter(|decision| Corroboration::counts(decision.verdict))
        .count();
    assert_eq!(counted.independent_parties, admitted);
    assert_eq!(
        counted.discounted_observations,
        lineage.decisions.len() - admitted
    );
}

/// How many copies were discounted must stay visible. Without it, "five sources have this" and
/// "one source has this and four mirrored it" are the same record.
#[test]
fn the_number_of_discounted_copies_is_kept_in_the_component_evidence() {
    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.corroboration = Some(Corroboration {
        independent_parties: 1,
        discounted_observations: 4,
    });

    let assessment = scorer.assess(&inputs);
    let corroboration = assessment
        .components
        .iter()
        .find(|component| component.component == brolga_graph::COMPONENT_CORROBORATION)
        .unwrap();

    assert_eq!(
        corroboration.evidence.as_deref(),
        Some("1 independent, 4 discounted")
    );
    assert!(corroboration.reason.contains("discounted"));
}

// ---------------------------------------------------------------------------------------------
// "Contradictory evidence remains visible"
// ---------------------------------------------------------------------------------------------

/// The criterion. Brolga stores claims rather than facts precisely so a disagreement can be kept,
/// and a scoring layer that folded a conflict into a number would throw away what the model was
/// shaped to preserve.
#[test]
fn a_contradiction_lowers_the_figure_and_stays_readable_on_the_assessment() {
    let detector = ContradictionDetector::new();
    let malicious = says("example.com", Disposition::Malicious, "feed-a");
    let benign = says("example.com", Disposition::Benign, "feed-b");
    let report = detector.review(&[malicious.clone(), benign.clone()]);

    assert!(report.has_contradiction());
    assert_eq!(report.conflict_count(), 1);

    let scorer = ConfidenceScorer::new();
    let mut contested = inputs("claim-1");
    contested.contradictions = report.decisions.clone();
    let uncontested = inputs("claim-1");

    let contested = scorer.assess(&contested);
    let uncontested = scorer.assess(&uncontested);

    assert!(contested.breakdown.overall < uncontested.breakdown.overall);
    assert_eq!(contested.contradiction_count(), 1);
    assert_eq!(
        contested.contradictions[0].left,
        malicious.id.min(benign.id)
    );
    assert_eq!(
        contested.contradictions[0].right,
        malicious.id.max(benign.id)
    );
    assert!(
        contested.explain().contains("contradiction:"),
        "{}",
        contested.explain()
    );
}

/// A contested claim is still evidence. A penalty that zeroed it would be the silent discard this
/// project exists to avoid, dressed up as arithmetic.
#[test]
fn a_contested_claim_is_penalised_rather_than_suppressed() {
    let detector = ContradictionDetector::new();
    let report = detector.review(&[
        says("example.com", Disposition::Malicious, "feed-a"),
        says("example.com", Disposition::Benign, "feed-b"),
    ]);

    let scorer = ConfidenceScorer::new();
    let mut contested = inputs("claim-1");
    contested.contradictions = report.decisions;
    let assessment = scorer.assess(&contested);

    assert!(assessment.breakdown.overall > ConfidenceScore::MIN);
    assert_eq!(assessment.penalties.len(), 1);
    assert_eq!(assessment.penalties[0].name, "contradicted");
    assert!(
        assessment.penalties[0]
            .reason
            .contains("rather than suppressed")
    );
}

/// Agreement is a finding too. Dropping the pairs that agreed would leave nobody able to tell a
/// pair that was judged compatible from a pair that was never judged.
#[test]
fn the_report_keeps_the_pairs_that_agreed_as_well_as_the_pairs_that_conflicted() {
    let detector = ContradictionDetector::new();
    let report = detector.review(&[
        says("example.com", Disposition::Malicious, "feed-a"),
        says("example.com", Disposition::Malicious, "feed-b"),
        says("example.com", Disposition::Benign, "feed-c"),
    ]);

    let relations: Vec<ClaimRelation> = report
        .decisions
        .iter()
        .map(|decision| decision.relation)
        .collect();

    assert_eq!(report.decisions.len(), 3, "every pair judged");
    assert_eq!(
        relations
            .iter()
            .filter(|relation| relation.is_agreement())
            .count(),
        1
    );
    assert_eq!(report.conflict_count(), 2);
}

/// A publisher correcting itself is not a contradiction. Reporting it as one would penalise exactly
/// the sources that behave well, and bury the real conflicts under self-corrections.
#[test]
fn a_publisher_revising_or_withdrawing_its_own_claim_is_not_a_contradiction() {
    let detector = ContradictionDetector::new();

    let mut earlier = says("example.com", Disposition::Malicious, "feed-a");
    earlier.asserted_at = Some(at("2026-01-01T00:00:00Z"));
    let mut later = says("example.com", Disposition::Benign, "feed-a");
    later.asserted_at = Some(at("2026-06-01T00:00:00Z"));
    assert_eq!(
        detector.relate(&earlier, &later).relation,
        ClaimRelation::Supersedes
    );

    let mut withdrawn = says("example.com", Disposition::Malicious, "feed-a");
    withdrawn.status = LifecycleStatus::Revoked;
    let standing = says("example.com", Disposition::Benign, "feed-b");
    assert_eq!(
        detector.relate(&withdrawn, &standing).relation,
        ClaimRelation::Revoked
    );

    for relation in [ClaimRelation::Supersedes, ClaimRelation::Revoked] {
        assert!(!relation.is_contradiction());
    }
}

// ---------------------------------------------------------------------------------------------
// "Analyst override is recorded separately from source claims"
// ---------------------------------------------------------------------------------------------

/// The criterion. An operator may raise or lower the figure; they may not make the evidence say
/// something else, and the two must stay side by side or nobody can tell which is which.
#[test]
fn an_override_replaces_the_figure_and_leaves_what_the_sources_support_intact() {
    let scorer = ConfidenceScorer::new();
    let sources_only = scorer.assess(&inputs("claim-1"));

    let mut overridden = inputs("claim-1");
    overridden.analyst_override = Some(
        AnalystOverride::new(
            score(20),
            "analyst@example.org",
            "case-4471",
            Some("the registrar disputes this"),
        )
        .unwrap(),
    );
    let overridden = scorer.assess(&overridden);

    assert!(overridden.is_overridden());
    assert_eq!(overridden.breakdown.overall, score(20));
    assert_eq!(
        overridden.breakdown.method,
        ConfidenceMethod::OperatorAsserted
    );
    assert_eq!(overridden.derived.overall, sources_only.derived.overall);
    assert_eq!(overridden.derived.method, ConfidenceMethod::Derived);
    assert_ne!(overridden.derived, overridden.breakdown);
    assert_eq!(overridden.components, sources_only.components);
}

/// An override that names nobody is worse than no override: it cannot be reviewed, appealed, or
/// learned from, and it is indistinguishable from a bug.
#[test]
fn an_override_must_name_its_actor_and_its_authority() {
    assert!(AnalystOverride::new(score(20), "", "case-4471", None).is_err());
    assert!(AnalystOverride::new(score(20), "analyst@example.org", "   ", None).is_err());
    assert!(AnalystOverride::new(score(20), "analyst@example.org", "case-4471", None).is_ok());
}

/// An analyst disagreeing with a feed is a recorded decision, not a second source disagreeing with
/// the first. Counting it as one would let an operator manufacture consensus by writing it down.
#[test]
fn an_analyst_disagreeing_with_a_source_is_an_override_not_a_source_conflict() {
    let detector = ContradictionDetector::new();
    let source = says("example.com", Disposition::Malicious, "feed-a");
    let mut analyst = says("example.com", Disposition::Benign, "in-house");
    analyst.stance = ClaimStance::Analyst;

    let decision = detector.relate(&source, &analyst);

    assert_eq!(decision.relation, ClaimRelation::AnalystOverride);
    assert!(!decision.is_contradiction());
    assert!(decision.reason.contains("recorded decision"));
}

/// The override is stored as its own row, keyed on the analyst, so two analysts overriding one
/// claim are two records rather than one quietly replacing the other.
#[test]
fn overrides_persist_as_their_own_rows_beside_the_derived_figure() {
    let scorer = ConfidenceScorer::new();
    let mut overridden = inputs("claim-1");
    overridden.analyst_override =
        Some(AnalystOverride::new(score(20), "analyst@example.org", "case-4471", None).unwrap());
    let assessment = scorer.assess(&overridden);

    let mut second = overridden.clone();
    second.analyst_override =
        Some(AnalystOverride::new(score(95), "lead@example.org", "case-4471", None).unwrap());
    let second = scorer.assess(&second);

    let mut store = store();
    store
        .transaction(|write| {
            write.record_graph_decision(&confidence_row(&assessment))?;
            write.record_graph_decision(&override_row(&assessment))?;
            write.record_graph_decision(&override_row(&second))?;
            Ok(())
        })
        .unwrap();

    let figures = store.graph_decisions_for("confidence", "claim-1").unwrap();
    let overrides = store
        .graph_decisions_for("confidence_override", "claim-1")
        .unwrap();

    assert_eq!(figures.len(), 1, "one derived figure");
    assert_eq!(overrides.len(), 2, "two analysts, two records");
    assert_eq!(overrides[0].observation, "analyst@example.org");
    assert_eq!(overrides[1].observation, "lead@example.org");
    assert_eq!(
        overrides[0].compared_with.as_deref(),
        Some(assessment.derived.overall.to_string().as_str()),
        "the row says what the sources supported"
    );
}

// ---------------------------------------------------------------------------------------------
// "Configuration changes produce versioned recalculation"
// ---------------------------------------------------------------------------------------------

/// The criterion. A weight change silently applied leaves two incomparable figures in the database
/// with nothing to tell them apart, and every comparison built on them is wrong in a way nobody
/// can see.
#[test]
fn a_figure_computed_under_a_changed_policy_is_marked_stale() {
    let original = ConfidencePolicy::defaults();
    let assessment = ConfidenceScorer::with_policy(original.clone()).assess(&inputs("claim-1"));
    assert!(!assessment.needs_recalculation(&original));

    let mut reweighted = ConfidencePolicy::defaults();
    reweighted.weights = ComponentWeights {
        source_reliability: 1,
        ..ComponentWeights::defaults()
    };
    reweighted.revision = 2;

    assert!(assessment.needs_recalculation(&reweighted));
    assert!(!assessment.is_current_under(&reweighted));

    let recomputed = ConfidenceScorer::with_policy(reweighted.clone()).assess(&inputs("claim-1"));
    assert!(!recomputed.needs_recalculation(&reweighted));
    assert_ne!(recomputed.policy_digest, assessment.policy_digest);
    assert_eq!(recomputed.policy_revision, 2);
}

/// Recalculating under a new policy must not overwrite what was decided under the old one. "What
/// did we think under the old weights?" is exactly the question a versioned recalculation leaves
/// answerable, and it is unanswerable if the row is replaced.
#[test]
fn recalculating_under_a_new_policy_records_a_second_figure_rather_than_replacing_the_first() {
    let original = ConfidencePolicy::defaults();
    let mut stricter = ConfidencePolicy::defaults();
    stricter.revision = 2;
    stricter.corroboration_ladder = vec![0, 5, 10, 20, 30, 40];

    let mut with_corroboration = inputs("claim-1");
    with_corroboration.corroboration = Some(Corroboration {
        independent_parties: 5,
        discounted_observations: 0,
    });

    let before = ConfidenceScorer::with_policy(original).assess(&with_corroboration);
    let after = ConfidenceScorer::with_policy(stricter).assess(&with_corroboration);

    let mut store = store();
    store
        .transaction(|write| {
            write.record_graph_decision(&confidence_row(&before))?;
            write.record_graph_decision(&confidence_row(&after))?;
            Ok(())
        })
        .unwrap();

    let stored = store.graph_decisions_for("confidence", "claim-1").unwrap();
    assert_eq!(stored.len(), 2, "one figure per policy, not one in total");
    assert_ne!(stored[0].observation, stored[1].observation);
    assert!(after.breakdown.overall < before.breakdown.overall);
}

/// Re-running under an unchanged policy must update one row rather than appending. Re-running is
/// what happens on every re-import, and a decision log that grows each time is one nobody reads.
#[test]
fn re_running_under_an_unchanged_policy_updates_one_row() {
    let mut store = store();
    for _ in 0..3 {
        let assessment = ConfidenceScorer::new().assess(&inputs("claim-1"));
        store
            .transaction(|write| {
                write.record_graph_decision(&confidence_row(&assessment))?;
                Ok(())
            })
            .unwrap();
    }

    assert_eq!(
        store
            .graph_decisions_for("confidence", "claim-1")
            .unwrap()
            .len(),
        1,
        "three runs, still one figure"
    );
}

/// Detection rules are configuration too, and changing which attributes hold one value at a time
/// changes what is detected.
#[test]
fn declaring_an_attribute_single_valued_changes_what_is_detected_and_the_rules_digest() {
    let undeclared = ContradictionRules::new();
    let declared = ContradictionRules::new().with_single_valued("registrar");
    assert_ne!(undeclared.digest(), declared.digest());

    let pair = [
        attribute("example.com", "registrar", "Registrar A", "feed-a"),
        attribute("example.com", "registrar", "Registrar B", "feed-b"),
    ];

    assert!(
        !ContradictionDetector::with_rules(undeclared)
            .review(&pair)
            .has_contradiction(),
        "guessing that an attribute is single-valued fabricates conflicts"
    );
    assert!(
        ContradictionDetector::with_rules(declared)
            .review(&pair)
            .has_contradiction()
    );
}

// ---------------------------------------------------------------------------------------------
// "Predicate-aware rules" — and the fuzzy matching this must not smuggle in
// ---------------------------------------------------------------------------------------------

/// Claims that answer different questions cannot disagree. Comparing values without first agreeing
/// which question they answer manufactures conflicts out of ordinary difference.
#[test]
fn claims_in_different_predicate_slots_are_never_compared() {
    let detector = ContradictionDetector::with_rules(
        ContradictionRules::new().with_single_valued("registrar"),
    );

    let decision = detector.relate(
        &attribute("example.com", "registrar", "Registrar A", "feed-a"),
        &attribute("example.com", "country", "AU", "feed-b"),
    );

    assert_eq!(decision.relation, ClaimRelation::Unrelated);
    assert!(!decision.relation.was_compared());
    assert_eq!(decision.predicate, None);
}

/// Claims about different subjects are never compared, however alike they look.
#[test]
fn claims_about_different_subjects_are_never_compared() {
    let detector = ContradictionDetector::new();
    let decision = detector.relate(
        &says("example.com", Disposition::Malicious, "feed-a"),
        &says("example.org", Disposition::Benign, "feed-b"),
    );

    assert_eq!(decision.relation, ClaimRelation::Unrelated);
    assert!(decision.reason.contains("different subjects"));
}

/// [#21](https://github.com/jusso-dev/Brolga/issues/21)'s non-goals rule out fuzzy matching, and
/// #22 must not smuggle one in. Deciding whether two paragraphs disagree needs a similarity measure
/// over prose, and declining is the honest answer.
#[test]
fn narrative_claims_are_never_compared_for_contradiction() {
    let detector = ContradictionDetector::new();
    let decision = detector.relate(
        &reviewed(
            "example.com",
            Assertion::Narrative(UntrustedText::new("observed hosting a phishing kit").unwrap()),
            "feed-a",
        ),
        &reviewed(
            "example.com",
            Assertion::Narrative(UntrustedText::new("no malicious activity observed").unwrap()),
            "feed-b",
        ),
    );

    assert_eq!(decision.relation, ClaimRelation::Unrelated);
    assert!(decision.reason.contains("similarity measure"));
}

/// A stronger and a weaker assessment of the same subject point the same way. Calling that a
/// conflict would put a fabricated disagreement in front of an analyst on almost every indicator.
#[test]
fn a_stronger_and_a_weaker_assessment_of_one_subject_do_not_conflict() {
    let detector = ContradictionDetector::new();
    let decision = detector.relate(
        &says("example.com", Disposition::Malicious, "feed-a"),
        &says("example.com", Disposition::Suspicious, "feed-b"),
    );

    assert_eq!(decision.relation, ClaimRelation::Compatible);
    assert!(!decision.is_contradiction());
}

/// An exclusion from detection that hides a malicious finding is exactly the tension an operator
/// needs shown, even though an allow-list entry is a decision rather than a finding.
#[test]
fn an_allow_list_entry_conflicts_with_a_malicious_finding() {
    let detector = ContradictionDetector::new();
    let decision = detector.relate(
        &says("example.com", Disposition::Malicious, "feed-a"),
        &says("example.com", Disposition::AllowListed, "in-house"),
    );

    assert_eq!(decision.relation, ClaimRelation::Conflicts);
    assert!(decision.reason.contains("excluded from detection"));
}

/// An unassessed disposition denies nothing, so a feed that merely lists an indicator without
/// assessing it must not appear to disagree with one that did.
#[test]
fn an_unassessed_disposition_contradicts_nothing() {
    let detector = ContradictionDetector::new();
    for disposition in [
        Disposition::Malicious,
        Disposition::Suspicious,
        Disposition::Benign,
        Disposition::AllowListed,
    ] {
        let decision = detector.relate(
            &says("example.com", disposition, "feed-a"),
            &says("example.com", Disposition::Unknown, "feed-b"),
        );
        assert_eq!(
            decision.relation,
            ClaimRelation::Compatible,
            "{disposition} against unknown"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Deterministic for fixed inputs
// ---------------------------------------------------------------------------------------------

/// The order claims arrive in must not change what is decided about the set. A re-import in a
/// different order would otherwise silently change a confidence score.
#[test]
fn the_order_claims_arrive_in_does_not_change_the_report() {
    let detector = ContradictionDetector::new();
    let malicious = says("example.com", Disposition::Malicious, "feed-a");
    let benign = says("example.com", Disposition::Benign, "feed-b");
    let suspicious = says("example.com", Disposition::Suspicious, "feed-c");
    let elsewhere = says("example.org", Disposition::Benign, "feed-d");

    let orderings = [
        vec![
            malicious.clone(),
            benign.clone(),
            suspicious.clone(),
            elsewhere.clone(),
        ],
        vec![
            elsewhere.clone(),
            suspicious.clone(),
            benign.clone(),
            malicious.clone(),
        ],
        vec![
            benign.clone(),
            elsewhere.clone(),
            malicious.clone(),
            suspicious.clone(),
        ],
    ];

    let reports: Vec<_> = orderings
        .iter()
        .map(|claims| detector.review(claims))
        .collect();

    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
    assert_eq!(reports[0].conflict_count(), 2);
}

/// The order contradictions are handed to the scorer in must not change the figure or the record
/// of it, or two runs over one database would disagree about the same claim.
#[test]
fn the_order_contradictions_are_supplied_in_does_not_change_the_assessment() {
    let detector = ContradictionDetector::new();
    let report = detector.review(&[
        says("example.com", Disposition::Malicious, "feed-a"),
        says("example.com", Disposition::Benign, "feed-b"),
        says("example.com", Disposition::AllowListed, "in-house"),
    ]);

    let scorer = ConfidenceScorer::new();
    let mut forwards = inputs("claim-1");
    forwards.contradictions = report.decisions.clone();
    let mut backwards = inputs("claim-1");
    backwards.contradictions = report.decisions.iter().rev().cloned().collect();

    assert_eq!(scorer.assess(&forwards), scorer.assess(&backwards));
}

/// Assessing the same inputs twice must give the same answer down to the last field, or nothing
/// downstream can cache, compare, or diff a figure.
#[test]
fn assessing_the_same_inputs_twice_gives_an_identical_assessment() {
    let scorer = ConfidenceScorer::new();
    let mut inputs = inputs("claim-1");
    inputs.corroboration = Some(Corroboration {
        independent_parties: 2,
        discounted_observations: 3,
    });
    inputs.observed_at = Some(at("2026-05-01T00:00:00Z"));

    assert_eq!(scorer.assess(&inputs), scorer.assess(&inputs));
}

// ---------------------------------------------------------------------------------------------
// "Policy-restricted evidence may affect internal decisions only when output can explain the
// decision without leaking forbidden content"
// ---------------------------------------------------------------------------------------------

/// The issue's security note. A restricted claim must still be able to move the figure — hiding it
/// would make the score wrong — while nothing that quotes its content travels with the explanation.
#[test]
fn a_restricted_claim_still_moves_the_figure_and_its_content_is_not_quoted() {
    let detector = ContradictionDetector::with_rules(
        ContradictionRules::new()
            .with_single_valued("registrar")
            .with_evidence_ceiling(TlpLevel::Amber),
    );

    let secret_value = "Registrar Named In A Restricted Report";
    let mut restricted = attribute("example.com", "registrar", secret_value, "closed-source");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    let open = attribute("example.com", "registrar", "Registrar B", "feed-b");

    let decision = detector.relate(&restricted, &open);

    assert_eq!(decision.relation, ClaimRelation::Conflicts);
    assert!(
        decision.evidence_withheld,
        "the quotation must be suppressed"
    );
    assert_eq!(decision.evidence, None);
    assert!(!decision.reason.contains(secret_value));
    assert!(
        decision.explain().contains("withheld"),
        "the reader has to know there is something to ask for: {}",
        decision.explain()
    );

    let scorer = ConfidenceScorer::new();
    let mut contested = inputs("claim-1");
    contested.contradictions = vec![decision];
    let assessment = scorer.assess(&contested);

    assert_eq!(assessment.contradiction_count(), 1, "it still counts");
    assert_eq!(assessment.penalties.len(), 1);
    assert!(!assessment.explain().contains(secret_value));
}

/// A claim inside the ceiling is quoted normally, or the withholding above would be indistinguishable
/// from the detector simply never quoting anything.
#[test]
fn a_claim_within_the_disclosure_ceiling_is_quoted_normally() {
    let detector = ContradictionDetector::with_rules(
        ContradictionRules::new()
            .with_single_valued("registrar")
            .with_evidence_ceiling(TlpLevel::Amber),
    );

    let mut shareable = attribute("example.com", "registrar", "Registrar A", "feed-a");
    shareable.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Green)]);
    let open = attribute("example.com", "registrar", "Registrar B", "feed-b");

    let decision = detector.relate(&shareable, &open);

    assert!(!decision.evidence_withheld);
    assert!(decision.evidence.unwrap().contains("Registrar A"));
}

// ---------------------------------------------------------------------------------------------
// Every decision is a record, not a side effect (ADR 0004 §2)
// ---------------------------------------------------------------------------------------------

/// A decision nobody can re-derive is a decision nobody can challenge.
#[test]
fn every_contradiction_decision_names_what_it_compared_which_algorithm_decided_and_why() {
    let detector = ContradictionDetector::new();
    let malicious = says("example.com", Disposition::Malicious, "feed-a");
    let benign = says("example.com", Disposition::Benign, "feed-b");
    let decision = detector.relate(&malicious, &benign);

    assert_eq!(decision.subject, subject("example.com").to_string());
    assert_eq!(decision.algorithm, CONTRADICTION_ALGORITHM);
    assert_eq!(decision.algorithm_version, CONTRADICTION_ALGORITHM_VERSION);
    assert!(decision.reason.len() > 20, "a reason, not a label");
    assert_eq!(
        decision.evidence.as_deref(),
        Some("malicious vs benign"),
        "the values compared, quoted"
    );
}

/// Contradiction decisions persist into the shared decision table, not a table of their own, and
/// read back with everything a caller needs to explain them.
#[test]
fn contradiction_decisions_persist_and_read_back_with_their_algorithm_and_reason() {
    let detector = ContradictionDetector::new();
    let report = detector.review(&[
        says("example.com", Disposition::Malicious, "feed-a"),
        says("example.com", Disposition::Benign, "feed-b"),
    ]);

    let mut store = store();
    store
        .transaction(|write| {
            for decision in &report.decisions {
                write.record_graph_decision(&contradiction_row(decision))?;
            }
            Ok(())
        })
        .unwrap();

    let stored = store
        .graph_decisions_for("contradiction", &subject("example.com").to_string())
        .unwrap();

    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].verdict, "conflicts");
    assert_eq!(stored[0].algorithm, CONTRADICTION_ALGORITHM);
    assert_eq!(stored[0].algorithm_version, CONTRADICTION_ALGORITHM_VERSION);
    assert!(stored[0].compared_with.is_some());
    assert_eq!(
        store
            .graph_decision_count("contradiction", "conflicts")
            .unwrap(),
        1
    );
}

/// Re-running the detector over the same claims must update one row rather than appending.
#[test]
fn re_running_the_detector_updates_one_row_rather_than_appending() {
    let mut store = store();
    for _ in 0..3 {
        let report = ContradictionDetector::new().review(&[
            says("example.com", Disposition::Malicious, "feed-a"),
            says("example.com", Disposition::Benign, "feed-b"),
        ]);
        store
            .transaction(|write| {
                for decision in &report.decisions {
                    write.record_graph_decision(&contradiction_row(decision))?;
                }
                Ok(())
            })
            .unwrap();
    }

    assert_eq!(
        store
            .graph_decisions_for("contradiction", &subject("example.com").to_string())
            .unwrap()
            .len(),
        1,
        "three runs, still one decision"
    );
}

/// Recording *why* something was decided does not change what the graph says, so it must not move
/// the graph version — otherwise every re-run looks like a graph change to an incremental consumer.
#[test]
fn recording_a_contradiction_or_a_figure_does_not_move_the_graph_version() {
    let report = ContradictionDetector::new().review(&[
        says("example.com", Disposition::Malicious, "feed-a"),
        says("example.com", Disposition::Benign, "feed-b"),
    ]);
    let assessment = ConfidenceScorer::new().assess(&inputs("claim-1"));

    let mut store = store();
    let before = store.graph_version().unwrap();
    store
        .transaction(|write| {
            for decision in &report.decisions {
                write.record_graph_decision(&contradiction_row(decision))?;
            }
            write.record_graph_decision(&confidence_row(&assessment))?;
            Ok(())
        })
        .unwrap();

    assert_eq!(store.graph_version().unwrap(), before);
}

/// Every assessment carries the algorithm and version that composed it, so a stored figure can be
/// attributed rather than assumed.
#[test]
fn every_assessment_names_the_algorithm_and_version_that_composed_it() {
    let assessment = ConfidenceScorer::new().assess(&inputs("claim-1"));
    assert_eq!(assessment.algorithm, CONFIDENCE_ALGORITHM);
    assert_eq!(assessment.algorithm_version, CONFIDENCE_ALGORITHM_VERSION);
}
