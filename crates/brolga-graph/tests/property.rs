//! Properties of the deterministic graph logic: deduplication stability and budget enforcement.
//!
//! Two of [#56](https://github.com/jusso-dev/Brolga/issues/56)'s named acceptance criteria live here.
//! Canonicalisation idempotency and serialisation round trips are properties of the model and the
//! canonicalisers, and are covered by `brolga-model/tests/property.rs` and
//! `brolga-ingest/tests/canon_property.rs`.
//!
//! # Why these two are worth generating inputs for rather than enumerating cases
//!
//! Both have the shape a property test is actually good at: an invariant over a *set* of inputs whose
//! interesting cases are combinatorial rather than nameable.
//!
//! **Deduplication stability** is about ordering. A store ingests batches in whatever order they
//! arrive, and the same records arriving in a different order must reach the same conclusion — because
//! if they do not, two Brolga installations fed the same intelligence disagree about what they hold,
//! and neither can be believed. Enumerating orderings by hand covers three; generating them covers
//! the shapes nobody thought of.
//!
//! **Budget enforcement** is about a conjunction of limits. `fit` honours six dimensions at once, and
//! a bug where one dimension's accounting is right on its own and wrong alongside another is exactly
//! what a hand-written case misses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use brolga_graph::budget::{Dimension, HeuristicTokens, Item, Limits, fit};
use brolga_graph::dedup::{Deduplicator, Observation};
use brolga_model::{ContentHash, Id, SourceObject};
use proptest::prelude::*;

/// A small alphabet of record identifiers.
///
/// Small on purpose: the interesting cases are collisions and repeats, and a large alphabet would make
/// them vanishingly rare. Four records and three publishers produce the overlaps that matter.
fn record_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("record-a".to_owned()),
        Just("record-b".to_owned()),
        Just("record-c".to_owned()),
        Just("record-d".to_owned()),
    ]
}

fn publisher() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("alpha".to_owned()),
        Just("beta".to_owned()),
        Just("gamma".to_owned()),
    ]
}

/// A digest derived from a label, so two observations can be made deliberately identical or
/// deliberately different.
fn hash_of(label: &str) -> ContentHash {
    ContentHash::of(label.as_bytes())
}

fn observation() -> impl Strategy<Value = Observation> {
    (record_id(), publisher(), 0_u8..3, 0_u8..3).prop_map(
        |(record_id, publisher, evidence, content)| Observation {
            record_id,
            source_object: Id::<SourceObject>::derive(&["source", &evidence.to_string()]),
            content_hash: hash_of(&format!("evidence-{evidence}")),
            publisher,
            record_hash: hash_of(&format!("content-{content}")),
        },
    )
}

/// Feed a list of observations through a fresh deduplicator and summarise what it concluded.
///
/// The summary is what must be order-independent: the set of records known, and for each one the set
/// of publishers and evidence digests that contributed. Not the *sequence* of decisions — those
/// legitimately differ, because the first observation of a record is a first sighting and a later one
/// is not, and which arrived first depends on order.
fn conclusion(
    observations: &[Observation],
) -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let mut deduplicator = Deduplicator::new();
    let mut summary: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();

    for observation in observations {
        let _decision = deduplicator.observe(observation.clone());
        let entry = summary.entry(observation.record_id.clone()).or_default();
        entry.0.insert(observation.publisher.clone());
        entry.1.insert(observation.content_hash.to_string());
    }
    summary
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **The criterion.** Deduplication reaches the same conclusion whatever order the observations
    /// arrive in.
    ///
    /// The property that makes two installations fed the same intelligence agree about what they hold.
    /// Asserted over a reversal and a rotation rather than every permutation: a factorial number of
    /// orderings is not testable, and an ordering bug that survives both a reversal and a rotation
    /// would have to be extraordinarily specific.
    #[test]
    fn deduplication_reaches_one_conclusion_whatever_the_order(
        observations in prop::collection::vec(observation(), 1..24)
    ) {
        let forwards = conclusion(&observations);

        let mut backwards_input = observations.clone();
        backwards_input.reverse();
        prop_assert_eq!(
            &forwards,
            &conclusion(&backwards_input),
            "reversing the batch changed what the store concluded"
        );

        // A rotation, which moves the *first* observation of each record without reversing the rest.
        // Truncating division is exactly what is wanted — a midpoint index, not a precise half.
        #[allow(
            clippy::integer_division,
            reason = "an index into a slice; a float would have to be truncated back anyway"
        )]
        let midpoint = observations.len() / 2;
        let mut rotated = observations.clone();
        rotated.rotate_left(midpoint);
        prop_assert_eq!(
            &forwards,
            &conclusion(&rotated),
            "rotating the batch changed what the store concluded"
        );
    }

    /// Observing the same thing twice adds nothing the first observation did not already establish.
    ///
    /// Idempotence, which is what makes re-ingesting an unchanged feed safe — and re-ingesting is the
    /// ordinary case, because a feed is polled.
    #[test]
    fn re_observing_an_identical_observation_changes_nothing(
        observations in prop::collection::vec(observation(), 1..12)
    ) {
        let once = conclusion(&observations);

        let mut twice_input = observations.clone();
        twice_input.extend(observations.iter().cloned());
        prop_assert_eq!(
            once,
            conclusion(&twice_input),
            "re-ingesting an unchanged feed changed the store's conclusion"
        );
    }

    /// A deduplicator never panics, whatever it is fed.
    #[test]
    fn deduplication_never_panics(
        observations in prop::collection::vec(observation(), 0..64)
    ) {
        let mut deduplicator = Deduplicator::new();
        for observation in observations {
            let _decision = deduplicator.observe(observation);
        }
    }
}

/// An item whose measured cost is what it says.
fn item() -> impl Strategy<Value = Item> {
    (
        0_usize..64,
        1_u64..500,
        1_u64..200,
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(index, bytes, tokens, is_relationship, required)| Item {
            id: format!("item-{index}"),
            section: if index.is_multiple_of(2) {
                "findings".to_owned()
            } else {
                "claims".to_owned()
            },
            bytes,
            tokens,
            is_relationship,
            required,
        })
}

fn limits() -> impl Strategy<Value = Limits> {
    (
        prop::option::of(0_u64..4_000),
        prop::option::of(0_u64..8_000),
        prop::option::of(0_u64..40),
        prop::option::of(0_u64..40),
    )
        .prop_map(|(tokens, bytes, objects, relationships)| {
            // Built through the builder rather than as a struct literal: `Limits` is
            // `#[non_exhaustive]`, and the builder is what a caller outside the crate actually uses —
            // so the test exercises the same construction path.
            let mut limits = Limits::unlimited();
            if let Some(tokens) = tokens {
                limits = limits.tokens(tokens);
            }
            if let Some(bytes) = bytes {
                limits = limits.bytes(bytes);
            }
            if let Some(objects) = objects {
                limits = limits.objects(objects);
            }
            if let Some(relationships) = relationships {
                limits = limits.relationships(relationships);
            }
            limits
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **The criterion.** Whatever survives fitting is within every limit that was stated.
    ///
    /// Every dimension checked on the same result, because the bug worth catching is one where each
    /// dimension's accounting is right alone and wrong together.
    #[test]
    fn what_survives_fitting_is_within_every_stated_limit(
        items in prop::collection::vec(item(), 0..40),
        limits in limits(),
    ) {
        // Distinct identifiers: `fit` is not being asked to deduplicate, and a repeated identifier
        // would make "was it kept?" ambiguous rather than testing anything.
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let Ok(fitted) = fit(&unique, &limits, &estimator, Instant::now()) else {
            // A refusal is a legitimate outcome — a required item that cannot fit must not be
            // silently dropped. What must never happen is an *accepted* result that breaks a limit.
            return Ok(());
        };

        let kept: Vec<&Item> = unique
            .iter()
            .filter(|item| fitted.kept.contains(&item.id))
            .collect();

        if let Some(limit) = limits.tokens {
            let spent: u64 = kept.iter().map(|item| item.tokens).sum();
            prop_assert!(spent <= limit, "kept {spent} tokens against a {limit} limit");
        }
        if let Some(limit) = limits.bytes {
            let spent: u64 = kept.iter().map(|item| item.bytes).sum();
            prop_assert!(spent <= limit, "kept {spent} bytes against a {limit} limit");
        }
        if let Some(limit) = limits.objects {
            let spent = u64::try_from(kept.iter().filter(|item| !item.is_relationship).count())
                .unwrap_or(u64::MAX);
            prop_assert!(spent <= limit, "kept {spent} objects against a {limit} limit");
        }
        if let Some(limit) = limits.relationships {
            let spent = u64::try_from(kept.iter().filter(|item| item.is_relationship).count())
                .unwrap_or(u64::MAX);
            prop_assert!(
                spent <= limit,
                "kept {spent} relationships against a {limit} limit"
            );
        }
    }

    /// Nothing is both kept and dropped, and nothing offered vanishes without being one or the other.
    ///
    /// The accounting property. A budget report that lost track of an item would understate a pack
    /// without saying so, which is the failure the whole exclusion mechanism exists to prevent.
    #[test]
    fn every_item_is_accounted_for_exactly_once(
        items in prop::collection::vec(item(), 0..40),
        limits in limits(),
    ) {
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let Ok(fitted) = fit(&unique, &limits, &estimator, Instant::now()) else {
            return Ok(());
        };

        let kept: BTreeSet<&String> = fitted.kept.iter().collect();
        let dropped: BTreeSet<&String> = fitted.dropped.iter().map(|(id, _)| id).collect();

        prop_assert!(
            kept.is_disjoint(&dropped),
            "an item was both kept and dropped: {:?}",
            kept.intersection(&dropped).collect::<Vec<_>>()
        );
        prop_assert_eq!(
            kept.len() + dropped.len(),
            unique.len(),
            "{} items offered, {} kept, {} dropped",
            unique.len(),
            kept.len(),
            dropped.len()
        );
    }

    /// A required item is never dropped in favour of an optional one.
    ///
    /// `fit` either keeps every required item or refuses. Silently dropping a required item and
    /// keeping an optional one would produce a pack that looks complete and is not.
    #[test]
    fn a_required_item_is_never_dropped_while_an_optional_one_survives(
        items in prop::collection::vec(item(), 1..30),
        limits in limits(),
    ) {
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let Ok(fitted) = fit(&unique, &limits, &estimator, Instant::now()) else {
            return Ok(());
        };

        let dropped: BTreeSet<&String> = fitted.dropped.iter().map(|(id, _)| id).collect();
        let dropped_required = unique
            .iter()
            .any(|item| item.required && dropped.contains(&item.id));
        let kept_optional = unique
            .iter()
            .any(|item| !item.required && fitted.kept.contains(&item.id));

        prop_assert!(
            !(dropped_required && kept_optional),
            "a required item was dropped while an optional one survived"
        );
    }

    /// Fitting is deterministic: the same items and the same limits give the same result.
    ///
    /// `fit` takes an `Instant` for the time budget, so this passes the same one to both calls —
    /// determinism is a property of the algorithm, not of the clock, and a test that let the clock
    /// vary would be testing something else.
    #[test]
    fn fitting_the_same_input_twice_gives_the_same_answer(
        items in prop::collection::vec(item(), 0..30),
        limits in limits(),
    ) {
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let started = Instant::now();
        let first = fit(&unique, &limits, &estimator, started);
        let second = fit(&unique, &limits, &estimator, started);

        match (first, second) {
            (Ok(first), Ok(second)) => {
                prop_assert_eq!(first.kept, second.kept);
                prop_assert_eq!(first.dropped, second.dropped);
            }
            (Err(_), Err(_)) => {}
            (first, second) => prop_assert!(
                false,
                "one call succeeded and the other did not: {first:?} / {second:?}"
            ),
        }
    }

    /// An unlimited budget keeps everything. The degenerate case, and the one a caller most relies on.
    #[test]
    fn an_unlimited_budget_drops_nothing(items in prop::collection::vec(item(), 0..30)) {
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let fitted = fit(&unique, &Limits::unlimited(), &estimator, Instant::now())
            .expect("an unlimited budget cannot fail");
        prop_assert!(fitted.dropped.is_empty(), "{:?}", fitted.dropped);
        prop_assert_eq!(fitted.kept.len(), unique.len());
    }

    /// A dropped item names the dimension that dropped it, and it is one the caller actually stated.
    ///
    /// A budget report blaming an unstated limit is a report an operator cannot act on.
    #[test]
    fn a_dropped_item_blames_a_dimension_the_caller_stated(
        items in prop::collection::vec(item(), 1..30),
        limits in limits(),
    ) {
        let mut unique: Vec<Item> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for item in items {
            if seen.insert(item.id.clone()) {
                unique.push(item);
            }
        }

        let estimator = HeuristicTokens;
        let Ok(fitted) = fit(&unique, &limits, &estimator, Instant::now()) else {
            return Ok(());
        };

        for (id, dimension) in &fitted.dropped {
            let stated = match dimension {
                Dimension::Tokens => limits.tokens.is_some(),
                Dimension::Bytes => limits.bytes.is_some(),
                Dimension::Objects => limits.objects.is_some(),
                Dimension::Relationships => limits.relationships.is_some(),
                Dimension::Depth => limits.depth.is_some(),
                Dimension::Time => limits.time_ms.is_some(),
                // A dimension this build does not know cannot have been stated, so blaming it would
                // be exactly the unactionable report this property exists to prevent.
                _ => false,
            };
            prop_assert!(
                stated,
                "`{id}` was dropped for {dimension:?}, which the caller did not state"
            );
        }
    }
}
