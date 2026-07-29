//! Safe structured search and bounded graph traversal.
//!
//! One section per acceptance criterion of [#24](https://github.com/jusso-dev/Brolga/issues/24).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::Duration;

use brolga_graph::{
    PlanRefused, TRAVERSE_ALGORITHM, TRAVERSE_ALGORITHM_VERSION, Traversal, TraversalError,
    TraversalLimits, TraversalPlan, TraversalPolicy, TraversalRequest, Truncation, traverse,
};
use brolga_model::{
    Entity, EntityKind, Id, LifecycleStatus, Marking, MarkingSet, NodeRef, Observable,
    RecordOrigin, Relationship, RelationshipKind, ShortText, SyntheticOrigin, SyntheticReason,
    TemporalState, Timestamp, TlpLevel, UntrustedText,
};
use brolga_security::CancellationToken;
use brolga_storage::{
    Direction, EdgeQuery, EntityQuery, IntelligenceStore, Page, RecordKind, SqliteStore, StoreRead,
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
            ShortText::new("traverse-test").unwrap(),
        ),
    }
}

fn entity_of(kind: EntityKind, name: &str) -> Entity {
    Entity::new(
        Id::derive(&["entity", name]),
        kind,
        UntrustedText::new(name).unwrap(),
        synthetic(),
    )
}

fn entity(name: &str) -> Entity {
    entity_of(EntityKind::ThreatActor, name)
}

fn node(name: &str) -> NodeRef {
    NodeRef::Entity(Id::derive(&["entity", name]))
}

fn edge(kind: RelationshipKind, from: &str, to: &str) -> Relationship {
    Relationship::new(kind, node(from), node(to), synthetic())
}

fn uses(from: &str, to: &str) -> Relationship {
    edge(RelationshipKind::Uses, from, to)
}

/// Write a set of named entities and the edges between them, in the order given.
fn populate(store: &mut SqliteStore, names: &[&str], edges: &[Relationship]) {
    store
        .transaction(|write| {
            for name in names {
                write.upsert_entity(&entity(name))?;
            }
            for relationship in edges {
                write.upsert_relationship(relationship)?;
            }
            Ok(())
        })
        .unwrap();
}

/// A star: one hub with `leaves` outgoing edges.
fn star(leaves: usize) -> (Vec<String>, Vec<Relationship>) {
    let mut names = vec!["hub".to_owned()];
    let mut edges = Vec::new();
    for index in 0..leaves {
        let leaf = format!("leaf-{index}");
        edges.push(uses("hub", &leaf));
        names.push(leaf);
    }
    (names, edges)
}

fn borrowed(names: &[String]) -> Vec<&str> {
    names.iter().map(String::as_str).collect()
}

fn walk(store: &SqliteStore, request: TraversalRequest) -> Traversal {
    traverse(store, request, &CancellationToken::never_cancelled()).unwrap()
}

/// Generous budgets, for tests about something other than a budget.
fn roomy() -> TraversalLimits {
    TraversalLimits::new(10, 1_000, 10_000, 500)
}

// ---------------------------------------------------------------------------------------------
// "Example roadmap queries have structured equivalents"
// ---------------------------------------------------------------------------------------------

/// "Which threat actors and intrusion sets do we currently believe in?" — the commonest shape of
/// question, and it must be expressible without a single string a caller composed.
#[test]
fn which_actors_do_we_currently_believe_in_is_a_typed_filter() {
    let mut store = store();
    let mut believed = entity_of(EntityKind::ThreatActor, "Bunyip Panda");
    let mut withdrawn = entity_of(EntityKind::ThreatActor, "Retracted Actor");
    withdrawn.status = LifecycleStatus::Revoked;
    let other_kind = entity_of(EntityKind::MalwareFamily, "Drop Bear");
    believed.status = LifecycleStatus::Deprecated;

    store
        .transaction(|write| {
            write.upsert_entity(&believed)?;
            write.upsert_entity(&withdrawn)?;
            write.upsert_entity(&other_kind)?;
            Ok(())
        })
        .unwrap();

    let query = EntityQuery::unfiltered()
        .with_kind(EntityKind::ThreatActor)
        .with_kind(EntityKind::IntrusionSet)
        .only_current();

    let found = store.search_entities(&query, Page::first(50)).unwrap();
    assert_eq!(
        found,
        vec![believed],
        "deprecated still stands; revoked does not"
    );
}

/// "What has this actor been seen using since the start of March?" — a kind filter, a relationship
/// predicate, and a temporal comparison, all typed.
#[test]
fn what_an_actor_uses_and_when_it_was_last_seen_are_typed_filters() {
    let mut store = store();
    let march = Timestamp::parse_rfc3339("2026-03-01T00:00:00Z").unwrap();
    let february = Timestamp::parse_rfc3339("2026-02-10T09:30:00Z").unwrap();
    let april = Timestamp::parse_rfc3339("2026-04-02T18:45:12Z").unwrap();

    let mut stale = entity_of(EntityKind::Tool, "Old Loader");
    stale.temporal = TemporalState::observed(february, february).unwrap();
    let mut fresh = entity_of(EntityKind::Tool, "New Loader");
    fresh.temporal = TemporalState::observed(march, april).unwrap();

    store
        .transaction(|write| {
            write.upsert_entity(&entity("Bunyip Panda"))?;
            write.upsert_entity(&stale)?;
            write.upsert_entity(&fresh)?;
            write.upsert_relationship(&uses("Bunyip Panda", "Old Loader"))?;
            write.upsert_relationship(&uses("Bunyip Panda", "New Loader"))?;
            Ok(())
        })
        .unwrap();

    let recent = store
        .search_entities(
            &EntityQuery::unfiltered()
                .with_kind(EntityKind::Tool)
                .last_seen_from(march),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(recent, vec![fresh]);

    let outgoing = store
        .edges_at(
            &EdgeQuery::at(node("Bunyip Panda"), Direction::Outgoing)
                .with_kind(RelationshipKind::Uses),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(outgoing.len(), 2, "both tools, regardless of when seen");
}

/// "What points at this domain?" — direction is part of the query, not something applied
/// afterwards. A relationship is directed, and "connected to" would answer a different question.
#[test]
fn direction_is_part_of_the_query_rather_than_a_filter_applied_afterwards() {
    let mut store = store();
    populate(
        &mut store,
        &["actor", "infrastructure", "victim"],
        &[
            uses("actor", "infrastructure"),
            edge(RelationshipKind::Targets, "infrastructure", "victim"),
        ],
    );

    let inbound = store
        .edges_at(
            &EdgeQuery::at(node("infrastructure"), Direction::Incoming),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].source, node("actor"));

    let outbound = store
        .edges_at(
            &EdgeQuery::at(node("infrastructure"), Direction::Outgoing),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].target, node("victim"));

    let either = store
        .edges_at(
            &EdgeQuery::at(node("infrastructure"), Direction::Either),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(either.len(), 2);
}

/// "What is within two hops of this indicator?" — the traversal equivalent, with the hop count as a
/// budget rather than as a hand-written recursive query.
#[test]
fn a_two_hop_neighbourhood_is_a_traversal_request_with_a_depth_budget() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b", "c", "d"],
        &[uses("a", "b"), uses("b", "c"), uses("c", "d")],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_limits(TraversalLimits::new(2, 100, 100, 100)),
    );

    assert!(found.reached(node("b")));
    assert!(found.reached(node("c")));
    assert!(
        !found.reached(node("d")),
        "three hops away, so out of scope"
    );
    assert_eq!(found.depth_of(node("a")), Some(0));
    assert_eq!(found.depth_of(node("c")), Some(2));
}

/// An empty filter set must mean "unconstrained", never "match nothing". A query that silently
/// matched nothing when a caller populated none of it would report an empty graph as an answer.
#[test]
fn an_empty_filter_set_admits_everything_rather_than_nothing() {
    let mut store = store();
    populate(&mut store, &["a", "b"], &[uses("a", "b")]);

    let query = EntityQuery::unfiltered();
    assert!(query.is_unfiltered());
    assert_eq!(
        store
            .search_entities(&query, Page::first(50))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .edges_at(
                &EdgeQuery::at(node("a"), Direction::Either),
                Page::first(50)
            )
            .unwrap()
            .len(),
        1
    );
}

/// A lifecycle filter on edges, which is what "only relationships we still believe" needs.
#[test]
fn a_revoked_edge_is_excluded_by_a_current_only_predicate() {
    let mut store = store();
    let mut revoked = uses("a", "c");
    revoked.status = LifecycleStatus::Revoked;
    populate(&mut store, &["a", "b", "c"], &[uses("a", "b"), revoked]);

    let filter = EdgeQuery::at(node("a"), Direction::Either).only_current();
    assert_eq!(store.degree(&filter).unwrap(), 1);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_filter(filter)
            .with_limits(roomy()),
    );
    assert!(found.reached(node("b")));
    assert!(!found.reached(node("c")), "a withdrawn edge is not a path");
}

// ---------------------------------------------------------------------------------------------
// "No raw SQL input reaches backend"
// ---------------------------------------------------------------------------------------------

/// The criterion. Every filter is a closed enum or a typed value — there is no field name, no
/// operator, and no fragment a caller can supply — so a record whose *content* is a SQL payload is
/// just content. If any of it were interpolated, this test would drop a table.
#[test]
fn a_record_whose_content_is_a_sql_payload_is_stored_and_found_as_content() {
    let mut store = store();
    let hostile = "'; DROP TABLE entities; --";
    let victim = entity_of(EntityKind::Infrastructure, hostile);
    let neighbour = entity_of(EntityKind::Infrastructure, "\" OR 1=1 --");

    store
        .transaction(|write| {
            write.upsert_entity(&victim)?;
            write.upsert_entity(&neighbour)?;
            write.upsert_relationship(&Relationship::new(
                RelationshipKind::CommunicatesWith,
                NodeRef::Entity(victim.id),
                NodeRef::Entity(neighbour.id),
                synthetic(),
            ))?;
            Ok(())
        })
        .unwrap();

    let found = store
        .search_entities(
            &EntityQuery::unfiltered().with_kind(EntityKind::Infrastructure),
            Page::first(50),
        )
        .unwrap();
    assert_eq!(found.len(), 2, "both stored, byte-identical");
    assert!(found.contains(&victim));

    let reached = walk(
        &store,
        TraversalRequest::starting_at(NodeRef::Entity(victim.id)).with_limits(roomy()),
    );
    assert!(reached.reached(NodeRef::Entity(neighbour.id)));

    for kind in RecordKind::all() {
        store
            .count(*kind)
            .unwrap_or_else(|error| panic!("{} no longer exists: {error}", kind.table()));
    }
}

/// A traversal reads through the same typed surface, so its budgets cannot be sidestepped by a
/// caller who knows SQL: there is nothing to write SQL into. The plan is built from a filter that
/// only names enum members, and the walk reuses it at every hop.
#[test]
fn a_traversal_reuses_one_typed_predicate_at_every_hop() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b", "c"],
        &[
            uses("a", "b"),
            edge(RelationshipKind::Targets, "b", "c"),
            uses("b", "c"),
        ],
    );

    let filter = EdgeQuery::at(node("a"), Direction::Outgoing).with_kind(RelationshipKind::Uses);
    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_filter(filter.clone())
            .with_limits(roomy()),
    );

    assert!(found.reached(node("c")), "reached over a `uses` edge");
    assert!(
        found
            .edges
            .iter()
            .all(|relationship| relationship.kind == RelationshipKind::Uses),
        "the kind predicate held at the second hop, not just the first",
    );
    assert_eq!(filter.about(node("b")).node, node("b"));
}

// ---------------------------------------------------------------------------------------------
// "Traversal stops at every configured limit and reports truncation"
// ---------------------------------------------------------------------------------------------

/// The depth budget. Without it, one hop more is one hop more of an exponentially growing frontier.
#[test]
fn the_depth_budget_stops_the_walk_and_says_so() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b", "c", "d", "e"],
        &[
            uses("a", "b"),
            uses("b", "c"),
            uses("c", "d"),
            uses("d", "e"),
        ],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_limits(TraversalLimits::new(2, 100, 100, 100)),
    );

    assert_eq!(found.deepest(), 2);
    assert!(!found.reached(node("d")));
    assert!(found.stopped_by(Truncation::Depth));
    assert!(!found.is_complete(), "a truncated answer must admit it");
}

/// The node budget. A traversal that reaches every node in the database has not answered a
/// question, it has copied the database.
#[test]
fn the_node_budget_stops_the_walk_and_says_so() {
    let (names, edges) = star(5);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("hub"))
            .with_limits(TraversalLimits::new(5, 3, 1_000, 100)),
    );

    assert_eq!(found.nodes.len(), 3, "the hub and two leaves");
    assert!(found.stopped_by(Truncation::Nodes));
}

/// The edge budget, which binds separately from the node budget: a dense graph can exhaust it long
/// before the node count is interesting.
#[test]
fn the_edge_budget_stops_the_walk_and_says_so() {
    let mut store = store();
    let mut names = vec!["a".to_owned()];
    let mut edges = Vec::new();
    for branch in 0..2 {
        let hub = format!("b{branch}");
        edges.push(uses("a", &hub));
        for leaf in 0..3 {
            let child = format!("c{branch}-{leaf}");
            edges.push(uses(&hub, &child));
            names.push(child);
        }
        names.push(hub);
    }
    populate(&mut store, &borrowed(&names), &edges);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_limits(TraversalLimits::new(5, 1_000, 4, 100)),
    );

    assert_eq!(found.edges.len(), 4);
    assert!(found.stopped_by(Truncation::Edges));
}

/// The fan-out budget, which is the one a hub needs. Without it a single node with a hundred
/// thousand edges spends the whole edge budget in one hop and starves every other branch.
#[test]
fn the_fan_out_budget_caps_one_busy_node_and_says_so() {
    let (names, edges) = star(5);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("hub"))
            .with_limits(TraversalLimits::new(2, 1_000, 1_000, 2)),
    );

    assert_eq!(found.edges.len(), 2, "expanded two of the hub's five edges");
    assert!(found.stopped_by(Truncation::FanOut));
    assert!(
        !found.stopped_by(Truncation::Edges),
        "the fan-out cap is what bound it, and the report must not blame the wrong budget",
    );
}

/// A node with exactly as many edges as the fan-out budget is not truncated. Reporting truncation
/// that did not happen would make the flag useless, because a caller would learn to ignore it.
#[test]
fn a_node_that_exactly_fills_its_fan_out_budget_is_not_reported_as_truncated() {
    let (names, edges) = star(3);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("hub"))
            .with_limits(TraversalLimits::new(2, 1_000, 1_000, 3)),
    );

    assert_eq!(found.edges.len(), 3);
    assert!(!found.stopped_by(Truncation::FanOut));
    assert!(found.is_complete());
}

/// Cancellation. A traversal that ignored the token would keep reading after the client that asked
/// for it has gone, which is how one abandoned request becomes a permanent load.
#[test]
fn a_cancelled_token_stops_the_walk_and_says_why() {
    let (names, edges) = star(5);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let request = TraversalRequest::starting_at(node("hub")).with_limits(roomy());
    let plan = TraversalPlan::prepare(&store, request).unwrap();
    let found = plan
        .run(&store, &CancellationToken::already_cancelled())
        .unwrap();

    assert!(found.edges.is_empty(), "stopped before reading a hop");
    assert!(found.stopped_by(Truncation::Cancelled));
    assert_eq!(
        found.cancellation,
        Some(brolga_security::Cancelled::Requested)
    );
}

/// The deadline is the time budget, and it must be distinguishable from an operator interrupt: a
/// caller retries the two differently.
#[test]
fn an_expired_deadline_stops_the_walk_with_a_distinguishable_reason() {
    let (names, edges) = star(3);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let plan = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(node("hub")).with_limits(roomy()),
    )
    .unwrap();
    let found = plan
        .run(&store, &CancellationToken::with_budget(Duration::ZERO))
        .unwrap();

    assert!(found.stopped_by(Truncation::Cancelled));
    assert_eq!(
        found.cancellation,
        Some(brolga_security::Cancelled::DeadlineExceeded)
    );
}

/// A cycle must terminate, and must terminate *completely* rather than by running into a budget.
/// A feed can assert `A -> B -> C -> A`, and a walk that revisits nodes would never return.
#[test]
fn a_cycle_terminates_without_hitting_any_budget() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b", "c"],
        &[uses("a", "b"), uses("b", "c"), uses("c", "a")],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a")).with_limits(roomy()),
    );

    assert_eq!(found.nodes.len(), 3);
    assert_eq!(found.edges.len(), 3);
    assert!(
        found.is_complete(),
        "the cycle guard terminated it, not a budget: {:?}",
        found.truncated
    );
}

/// A self-referencing pair — `A duplicate_of B` asserted alongside `A uses B` — must not be walked
/// back and forth. Mutual edges are ordinary in intelligence data.
#[test]
fn mutual_edges_between_two_nodes_do_not_loop() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b"],
        &[
            uses("a", "b"),
            uses("b", "a"),
            edge(RelationshipKind::DuplicateOf, "a", "b"),
        ],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a")).with_limits(roomy()),
    );

    assert_eq!(found.nodes.len(), 2);
    assert_eq!(found.edges.len(), 3);
    assert!(found.is_complete());
}

/// Every result names the algorithm and version that produced it, for the same reason every
/// deduplication decision does: a result nobody can attribute is one nobody can challenge.
#[test]
fn every_traversal_names_the_algorithm_that_produced_it() {
    let mut store = store();
    populate(&mut store, &["a", "b"], &[uses("a", "b")]);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a")).with_limits(roomy()),
    );
    assert_eq!(found.algorithm, TRAVERSE_ALGORITHM);
    assert_eq!(found.algorithm_version, TRAVERSE_ALGORITHM_VERSION);
}

// ---------------------------------------------------------------------------------------------
// "Results are stably ordered"
// ---------------------------------------------------------------------------------------------

/// The criterion. Two runs over unchanged data must return the same sequence, not merely the same
/// set — otherwise every downstream diff, checkpoint, and cached context pack is worthless.
#[test]
fn two_runs_over_unchanged_data_return_an_identical_sequence() {
    let (names, edges) = star(8);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let request = || {
        TraversalRequest::starting_at(node("hub")).with_limits(TraversalLimits::new(3, 50, 50, 50))
    };

    assert_eq!(walk(&store, request()), walk(&store, request()));
}

/// The order records were *written* in must not change the order they come back in. Two operators
/// importing the same feeds in a different order must be able to compare their answers.
#[test]
fn the_order_records_were_written_in_does_not_change_the_result() {
    let (names, mut edges) = star(6);

    let mut forwards = store();
    populate(&mut forwards, &borrowed(&names), &edges);

    edges.reverse();
    let mut backwards = store();
    let mut reversed_names = names.clone();
    reversed_names.reverse();
    populate(&mut backwards, &borrowed(&reversed_names), &edges);

    let request = || {
        TraversalRequest::starting_at(node("hub")).with_limits(TraversalLimits::new(3, 50, 50, 50))
    };

    assert_eq!(walk(&forwards, request()), walk(&backwards, request()));
}

/// Nodes come back shallowest first, then in node order. Depth is the useful key, and the node
/// order breaks the ties so the sequence is total rather than merely grouped.
#[test]
fn nodes_are_ordered_by_depth_and_then_by_node() {
    let mut store = store();
    populate(
        &mut store,
        &["a", "b", "c", "d"],
        &[uses("a", "b"), uses("a", "c"), uses("b", "d")],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a")).with_limits(roomy()),
    );

    let depths: Vec<u32> = found.nodes.iter().map(|reached| reached.depth).collect();
    let mut sorted = depths.clone();
    sorted.sort_unstable();
    assert_eq!(depths, sorted, "shallowest first");

    let mut expected = found.nodes.clone();
    expected.sort_unstable();
    assert_eq!(found.nodes, expected, "a total order, so ties are broken");
}

/// Paging a search must not skip or repeat. Ordering by a mutable column — `last_seen`, say — is
/// how offset paging silently loses rows between page one and page two.
#[test]
fn paging_a_search_neither_skips_nor_repeats() {
    let mut store = store();
    let names: Vec<String> = (0..7).map(|index| format!("actor-{index}")).collect();
    populate(&mut store, &borrowed(&names), &[]);

    let query = EntityQuery::unfiltered().with_kind(EntityKind::ThreatActor);
    let mut page = Page::first(2);
    let mut collected: Vec<Id<Entity>> = Vec::new();
    loop {
        let batch = store.search_entities(&query, page).unwrap();
        if batch.is_empty() {
            break;
        }
        collected.extend(batch.iter().map(|found| found.id));
        page = page.next();
    }

    let mut sorted = collected.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(collected.len(), 7, "every record, once");
    assert_eq!(
        collected, sorted,
        "and in a stable total order across pages"
    );
}

/// Edges come back in identifier order, which is stable across runs because identifiers are derived
/// from the statement an edge makes rather than from when it was written.
#[test]
fn edges_are_returned_in_identifier_order() {
    let (names, edges) = star(6);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("hub")).with_limits(roomy()),
    );

    let ids: Vec<Id<Relationship>> = found.edges.iter().map(|found| found.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

// ---------------------------------------------------------------------------------------------
// "Query cost and policy checks occur before execution"
// ---------------------------------------------------------------------------------------------

/// A zero budget is a caller mistake, and it is refused by name rather than answered with an empty
/// result that looks like "nothing is connected to this".
#[test]
fn a_zero_budget_is_refused_by_name_before_anything_is_read() {
    let mut store = store();
    populate(&mut store, &["a", "b"], &[uses("a", "b")]);

    for (limits, expected) in [
        (TraversalLimits::new(0, 1, 1, 1), "depth"),
        (TraversalLimits::new(1, 0, 1, 1), "nodes"),
        (TraversalLimits::new(1, 1, 0, 1), "edges"),
        (TraversalLimits::new(1, 1, 1, 0), "fan-out"),
    ] {
        let refusal = TraversalPlan::prepare(
            &store,
            TraversalRequest::starting_at(node("a")).with_limits(limits),
        )
        .expect_err("a zero budget must be refused");

        match refusal {
            TraversalError::Refused(PlanRefused::EmptyBudget { limit }) => {
                assert_eq!(limit, expected);
            }
            other => panic!("expected an empty-budget refusal, got {other:?}"),
        }
    }
}

/// The cost check. The start node's own degree is read *before* any edge document is decoded, so a
/// request that could never fit its budget is refused having paid nothing.
#[test]
fn a_start_node_busier_than_the_edge_budget_is_refused_before_reading() {
    let (names, edges) = star(6);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let refusal = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(node("hub"))
            .with_limits(TraversalLimits::new(2, 100, 3, 100)),
    )
    .expect_err("six edges do not fit a three-edge budget");

    match refusal {
        TraversalError::Refused(PlanRefused::StartNodeTooBusy { degree, max_edges }) => {
            assert_eq!(degree, 6);
            assert_eq!(max_edges, 3);
        }
        other => panic!("expected a cost refusal, got {other:?}"),
    }
}

/// The same estimate is available to a caller that wants to decide for itself, which is the point
/// of planning being a separate step from running.
#[test]
fn a_plan_reports_what_the_first_hop_will_cost_before_it_runs() {
    let (names, edges) = star(4);
    let mut store = store();
    populate(&mut store, &borrowed(&names), &edges);

    let plan = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(node("hub")).with_limits(roomy()),
    )
    .unwrap();

    assert_eq!(plan.start_degree(), 4);
    assert_eq!(plan.request().start(), node("hub"));
}

/// "Nothing is connected to this" and "this is not in the database" are different answers, and an
/// analyst acts differently on each.
#[test]
fn a_start_entity_that_is_not_stored_is_refused_rather_than_answered_empty() {
    let store = store();

    let refusal = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(node("never-imported")).with_limits(roomy()),
    )
    .expect_err("an unknown start must be refused");

    assert!(matches!(
        refusal,
        TraversalError::Refused(PlanRefused::UnknownStart { .. })
    ));
}

/// Observables are content-addressed and have no row of their own — the same exemption referential
/// integrity makes on edge endpoints. Refusing them for "not being stored" would make half the
/// graph untraversable.
#[test]
fn an_observable_start_is_exempt_from_the_existence_check() {
    let mut store = store();
    let domain =
        Observable::DomainName(brolga_model::observable::DomainName::new("evil.example").unwrap());
    let actor = entity("Bunyip Panda");

    store
        .transaction(|write| {
            write.upsert_entity(&actor)?;
            write.upsert_relationship(&Relationship::new(
                RelationshipKind::Indicates,
                NodeRef::Observable(domain.id()),
                NodeRef::Entity(actor.id),
                synthetic(),
            ))?;
            Ok(())
        })
        .unwrap();

    let found = walk(
        &store,
        TraversalRequest::starting_at(NodeRef::Observable(domain.id())).with_limits(roomy()),
    );
    assert!(found.reached(NodeRef::Entity(actor.id)));
}

/// The policy check on the start node, before execution. Traversing from something the request may
/// not see and then filtering the output would already have leaked which node it was.
#[test]
fn a_start_node_the_request_may_not_see_is_refused_before_execution() {
    let mut store = store();
    let mut restricted = entity("Restricted Actor");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    store
        .transaction(|write| write.upsert_entity(&restricted))
        .unwrap();

    let refusal = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(NodeRef::Entity(restricted.id))
            .with_limits(roomy())
            .with_policy(TraversalPolicy::permitting(TlpLevel::Green)),
    )
    .expect_err("a start node above the policy must be refused");

    assert!(matches!(
        refusal,
        TraversalError::Refused(PlanRefused::PolicyRefused { .. })
    ));
}

/// A restricted edge is not merely omitted — it is not traversed *through*. An edge used as a
/// bridge leaks the connection even when the edge itself is withheld.
#[test]
fn a_restricted_edge_is_withheld_and_not_used_as_a_bridge() {
    let mut store = store();
    let mut restricted = uses("a", "secret");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    populate(
        &mut store,
        &["a", "b", "secret", "beyond"],
        &[uses("a", "b"), restricted, uses("secret", "beyond")],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a"))
            .with_limits(roomy())
            .with_policy(TraversalPolicy::permitting(TlpLevel::Amber)),
    );

    assert!(found.reached(node("b")));
    assert!(
        !found.reached(node("secret")),
        "withheld, not merely hidden"
    );
    assert!(
        !found.reached(node("beyond")),
        "and not reachable through the edge that was withheld",
    );
    assert_eq!(
        found.withheld_by_policy, 1,
        "and the caller is told there was more"
    );
}

/// An unrestricted policy withholds nothing, so the same graph traversed without a policy reaches
/// what the restricted one could not. Without this the previous test would pass on a bug that
/// dropped edges for an unrelated reason.
#[test]
fn the_same_graph_without_a_policy_reaches_what_the_policy_withheld() {
    let mut store = store();
    let mut restricted = uses("a", "secret");
    restricted.markings = MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)]);
    populate(
        &mut store,
        &["a", "b", "secret", "beyond"],
        &[uses("a", "b"), restricted, uses("secret", "beyond")],
    );

    let found = walk(
        &store,
        TraversalRequest::starting_at(node("a")).with_limits(roomy()),
    );

    assert!(found.reached(node("secret")));
    assert!(found.reached(node("beyond")));
    assert_eq!(found.withheld_by_policy, 0);
}

/// The degree estimate must respect the same predicate the walk will use, or the cost check would
/// be costing a different query from the one about to run.
#[test]
fn the_cost_estimate_uses_the_same_predicate_as_the_walk() {
    let mut store = store();
    populate(
        &mut store,
        &["hub", "x", "y"],
        &[
            uses("hub", "x"),
            edge(RelationshipKind::Targets, "hub", "y"),
        ],
    );

    let narrow = EdgeQuery::at(node("hub"), Direction::Outgoing).with_kind(RelationshipKind::Uses);
    assert_eq!(store.degree(&narrow).unwrap(), 1);
    assert_eq!(
        store
            .degree(&EdgeQuery::at(node("hub"), Direction::Either))
            .unwrap(),
        2
    );

    let plan = TraversalPlan::prepare(
        &store,
        TraversalRequest::starting_at(node("hub"))
            .with_filter(narrow)
            .with_limits(roomy()),
    )
    .unwrap();
    assert_eq!(plan.start_degree(), 1);
}

// ---------------------------------------------------------------------------------------------
// Adversarial checks written during review, not by the module's author
// ---------------------------------------------------------------------------------------------

/// A hostile graph shaped to defeat a naive visited-set: a ring, plus a chord from every node back
/// to the start, plus a chord to its predecessor. Every node is reachable from every other by
/// several routes, and every budget is generous — so the only thing that can stop it is the cycle
/// guard.
///
/// Written during review rather than alongside the module, because a bound tested only by the
/// person who wrote it tends to be tested on the shape they had in mind.
#[test]
fn a_graph_with_many_interlocking_cycles_still_terminates() {
    let mut store = store();
    let names: Vec<String> = (0..40).map(|index| format!("node-{index:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();

    // No self-edges: the model refuses a relationship whose ends are the same node, which is
    // itself worth knowing — a self-loop is the cheapest way to make a naive walk spin.
    let mut edges = Vec::new();
    for (index, name) in refs.iter().enumerate() {
        edges.push(uses(name, refs[(index + 1) % refs.len()]));
        if index > 0 {
            edges.push(uses(name, refs[0]));
            edges.push(uses(name, refs[index - 1]));
        }
    }
    populate(&mut store, &refs, &edges);

    let result = traverse(
        &store,
        TraversalRequest::starting_at(node("node-00"))
            .with_limits(TraversalLimits::new(100, 10_000, 10_000, 1_000)),
        &CancellationToken::never_cancelled(),
    )
    .expect("a cyclic graph must terminate, not loop");

    assert!(result.nodes.len() <= refs.len(), "no node visited twice");
    assert!(
        !result.truncated.contains(&Truncation::Nodes),
        "40 nodes is well inside a 10,000 budget; hitting it would mean revisiting"
    );
}

/// Every budget, driven to its limit on the same graph, must stop the walk *and say which one did*.
/// A budget that is checked but never reported leaves a caller unable to tell a complete answer
/// from a truncated one — and a truncated neighbourhood looks exactly like a small one.
#[test]
fn each_budget_in_turn_stops_the_walk_and_names_itself() {
    let mut store = store();
    let names: Vec<String> = (0..20).map(|index| format!("n-{index:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let edges: Vec<_> = refs.windows(2).map(|pair| uses(pair[0], pair[1])).collect();
    populate(&mut store, &refs, &edges);

    let cases = [
        (
            TraversalLimits::new(2, 1_000, 1_000, 1_000),
            Truncation::Depth,
        ),
        (
            TraversalLimits::new(100, 3, 1_000, 1_000),
            Truncation::Nodes,
        ),
        (
            TraversalLimits::new(100, 1_000, 2, 1_000),
            Truncation::Edges,
        ),
    ];

    for (limits, expected) in cases {
        let result = traverse(
            &store,
            TraversalRequest::starting_at(node("n-00")).with_limits(limits),
            &CancellationToken::never_cancelled(),
        )
        .expect("the walk runs");
        assert!(
            result.truncated.contains(&expected),
            "expected {expected:?}, got {:?}",
            result.truncated
        );
    }
}

/// The no-arbitrary-SQL claim, exercised through the whole stack rather than at the compiler.
///
/// A record whose *content* is a SQL payload must be stored and retrieved as content. If any layer
/// were interpolating values into statement text, this is where it would surface.
#[test]
fn a_sql_payload_in_a_record_name_is_stored_and_traversed_as_content() {
    let mut store = store();
    let hostile = "'; DROP TABLE entities; --";
    populate(
        &mut store,
        &[hostile, "ordinary"],
        &[uses(hostile, "ordinary")],
    );

    assert_eq!(
        store.count(brolga_storage::RecordKind::Entity).unwrap(),
        2,
        "the payload was data, not a statement"
    );

    let result = traverse(
        &store,
        TraversalRequest::starting_at(node(hostile))
            .with_limits(TraversalLimits::new(3, 100, 100, 100)),
        &CancellationToken::never_cancelled(),
    )
    .expect("a hostile name is just a name");
    assert!(result.nodes.len() >= 2);
}
