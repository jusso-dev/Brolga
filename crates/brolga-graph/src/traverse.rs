//! Bounded traversal of the relationship graph.
//!
//! # An unbounded traversal is a denial of service
//!
//! Threat intelligence graphs are hostile by construction. A single widely-mirrored indicator can
//! carry tens of thousands of edges, an aggregator can publish a hub that touches everything it has
//! ever seen, and a feed can assert a cycle. "Follow the relationships from here" over a graph like
//! that does not return late — it returns never, having read the whole database into memory first.
//!
//! So every traversal here is held to four budgets and a cancellation signal, and **each one is a
//! stop condition rather than a suggestion**:
//!
//! - [`TraversalLimits::max_depth`] — how many hops from the start.
//! - [`TraversalLimits::max_nodes`] — how many distinct nodes may be reached.
//! - [`TraversalLimits::max_edges`] — how many distinct edges may be collected.
//! - [`TraversalLimits::max_fan_out`] — how many edges may be expanded from any one node, which is
//!   what keeps a single hub from consuming the whole edge budget in one hop.
//! - A [`CancellationToken`], which carries the request's deadline. That is the time budget, and it
//!   is inherited rather than restarted per hop, because a per-hop timeout is how a request with a
//!   sixty-second budget runs for an hour.
//!
//! When a budget stops the walk, the result says which one, in [`Traversal::truncated`]. A
//! truncated answer that does not admit it is worse than no answer: an analyst reading "three
//! related indicators" has no way to tell it from "three related indicators, and we stopped
//! looking".
//!
//! # Cost and policy are decided before anything is read
//!
//! [`TraversalPlan::prepare`] runs first and can refuse. It checks that no budget is zero, that the
//! start node exists and is one this request may see, and that the start node's own degree does not
//! already exceed the entire edge budget. A traversal that would blow its budget on the first hop is
//! refused with nothing read, rather than discovered halfway through.
//!
//! Handling restrictions are enforced during the walk as well: an edge the request is not cleared
//! for is neither returned nor traversed *through*, so a restricted relationship cannot leak by
//! being used as a bridge to something unrestricted.
//!
//! # No SQL, and one hop at a time
//!
//! `docs/ARCHITECTURE.md` commits to relational adjacency tables with bounded recursive queries
//! rather than a graph database. The recursion lives here, not in the database: this module asks
//! `brolga-storage` for one hop at a time through [`EdgeQuery`], which is a typed filter over closed
//! enums. Nothing resembling a query string crosses the boundary, so the budgets above cannot be
//! bypassed by a caller who knows SQL.
//!
//! # Determinism
//!
//! The same graph and the same request produce the same result, in the same order, every time.
//! Frontiers are [`BTreeSet`]s, collected edges are a [`BTreeMap`] keyed by identifier, and storage
//! returns each hop in identifier order. A traversal that returned nodes in a different order
//! between runs would make every downstream comparison — a diff, a checkpoint, a cached context
//! pack — worthless.

use std::collections::{BTreeMap, BTreeSet};

use brolga_model::{Id, MarkingSet, NodeRef, Relationship, TlpLevel};
use brolga_security::{CancellationToken, Cancelled};
use brolga_storage::{Direction, EdgeQuery, Page, StorageError, StoreRead};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// This traversal's identifier, stamped into every result it produces.
///
/// A compatibility surface under ADR 0001 §6, for the same reason the deduplicator's is: a consumer
/// may have stored a result carrying this pair, and changing what the pair returns for the same
/// graph and the same request is a breaking change.
pub const TRAVERSE_ALGORITHM: &str = "brolga.traverse.bounded-breadth-first";

/// This traversal's version.
///
/// Bump when the *set of reachable nodes* or the order they are returned in changes for some input,
/// not when a message is reworded.
pub const TRAVERSE_ALGORITHM_VERSION: u32 = 1;

// -------------------------------------------------------------------------------------------------
// Budgets
// -------------------------------------------------------------------------------------------------

/// Every bound a traversal is held to.
///
/// There is no "unlimited" variant, and there is no constructor that leaves a budget unset. A
/// traversal with one budget missing is unbounded in that dimension, and an attacker only needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TraversalLimits {
    /// How many hops from the start node the walk may take.
    pub max_depth: u32,
    /// How many distinct nodes may be reached, including the start node.
    pub max_nodes: usize,
    /// How many distinct edges may be collected.
    pub max_edges: usize,
    /// How many edges may be expanded from any one node.
    ///
    /// The bound that hubs need. Without it a single node with a hundred thousand edges consumes
    /// the entire edge budget in one hop, and every other branch of the walk is starved by a node
    /// nobody asked about.
    pub max_fan_out: u32,
}

impl TraversalLimits {
    /// Hops a default traversal takes.
    ///
    /// Three, because two hops answers "what is this connected to, and what are *those* connected
    /// to", and the third is where an intelligence graph starts returning the whole corpus.
    pub const DEFAULT_MAX_DEPTH: u32 = 3;

    /// Nodes a default traversal may reach.
    pub const DEFAULT_MAX_NODES: usize = 500;

    /// Edges a default traversal may collect.
    pub const DEFAULT_MAX_EDGES: usize = 2_000;

    /// Edges a default traversal expands from any one node.
    pub const DEFAULT_MAX_FAN_OUT: u32 = 200;

    /// The largest fan-out any traversal may ask for.
    ///
    /// One below the storage layer's page ceiling, because a hop reads *one row more* than its
    /// fan-out budget in order to learn whether there were more without asking twice. Beyond this
    /// a "neighbourhood" is a table scan wearing a graph's clothes.
    pub const MAX_FAN_OUT: u32 = Page::MAX_LIMIT - 1;

    /// Build a set of budgets, clamping the fan-out to [`Self::MAX_FAN_OUT`].
    ///
    /// Clamped rather than rejected, matching [`Page::new`]: a caller asking for more than the
    /// backend can page wants as much as it can have, and failing teaches it nothing it can act on.
    /// A *zero* budget is not clamped, because zero is a caller mistake with a very different
    /// meaning from "too much", and [`TraversalPlan::prepare`] refuses it by name.
    #[must_use]
    pub const fn new(max_depth: u32, max_nodes: usize, max_edges: usize, max_fan_out: u32) -> Self {
        let max_fan_out = if max_fan_out > Self::MAX_FAN_OUT {
            Self::MAX_FAN_OUT
        } else {
            max_fan_out
        };
        Self {
            max_depth,
            max_nodes,
            max_edges,
            max_fan_out,
        }
    }

    /// The page a single hop reads.
    ///
    /// One row wider than the fan-out budget, so "there were more than you allowed" is known from
    /// the rows already in hand rather than from a second count query per node.
    #[must_use]
    pub const fn probe_page(self) -> Page {
        Page::first(self.max_fan_out.saturating_add(1))
    }

    /// The fan-out budget as a count of rows.
    ///
    /// Saturating rather than casting, because the workspace forbids `as` and a silently wrapped
    /// budget is exactly the class of bug that lint exists to prevent.
    #[must_use]
    pub fn fan_out(self) -> usize {
        usize::try_from(self.max_fan_out).unwrap_or(usize::MAX)
    }
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_DEPTH,
            Self::DEFAULT_MAX_NODES,
            Self::DEFAULT_MAX_EDGES,
            Self::DEFAULT_MAX_FAN_OUT,
        )
    }
}

/// Which budget stopped a traversal.
///
/// A set of these, not one: a walk can hit a node's fan-out cap on the way to exhausting its edge
/// budget, and collapsing that into a single reason would hide half of what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Truncation {
    /// The depth budget was reached with nodes still unexpanded.
    Depth,
    /// The node budget was reached.
    Nodes,
    /// The edge budget was reached.
    Edges,
    /// Some node had more edges than the fan-out budget allowed to be expanded.
    FanOut,
    /// The cancellation token fired: an operator interrupt, a dropped client, or the deadline.
    Cancelled,
}

impl Truncation {
    /// A stable label, for diagnostics and recorded results.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Nodes => "nodes",
            Self::Edges => "edges",
            Self::FanOut => "fan_out",
            Self::Cancelled => "cancelled",
        }
    }
}

impl core::fmt::Display for Truncation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// -------------------------------------------------------------------------------------------------
// Policy
// -------------------------------------------------------------------------------------------------

/// What handling restrictions a request is cleared to see.
///
/// Applied to the start node before the walk begins and to every edge as it is read. A restricted
/// edge is not merely omitted from the result — it is not traversed *through*, because an edge used
/// as a bridge leaks the fact of the connection even when the edge itself is withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalPolicy {
    permitted_tlp: Option<TlpLevel>,
}

impl TraversalPolicy {
    /// A policy that withholds nothing.
    ///
    /// For a local operator working with their own database, and for tests. Named to be conspicuous
    /// in review for the same reason [`CancellationToken::never_cancelled`] is: reaching for it
    /// inside a request that came from somewhere else is how a restriction gets lost.
    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            permitted_tlp: None,
        }
    }

    /// A policy admitting records at or below one Traffic Light Protocol level.
    #[must_use]
    pub const fn permitting(level: TlpLevel) -> Self {
        Self {
            permitted_tlp: Some(level),
        }
    }

    /// The level this policy admits, if it restricts anything.
    #[must_use]
    pub const fn permitted_tlp(self) -> Option<TlpLevel> {
        self.permitted_tlp
    }

    /// Whether a record carrying these markings may be seen.
    ///
    /// An **unmarked** record is admitted. Inventing a restriction the publisher did not state would
    /// be as wrong as ignoring one they did, and it would hide most of a graph assembled from feeds
    /// that mark nothing.
    #[must_use]
    pub fn permits(self, markings: &MarkingSet) -> bool {
        match (self.permitted_tlp, markings.most_restrictive_tlp()) {
            (None, _) | (Some(_), None) => true,
            (Some(permitted), Some(found)) => found <= permitted,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Request, plan, and result
// -------------------------------------------------------------------------------------------------

/// What to traverse, from where, and under what budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TraversalRequest {
    /// The edge predicate, whose node is where the walk starts.
    ///
    /// One filter rather than a start node plus a separate predicate, because every hop applies the
    /// *same* predicate at a different node — [`EdgeQuery::about`] is exactly that, and keeping them
    /// as one value makes it impossible for the two to drift apart.
    pub filter: EdgeQuery,
    /// The budgets the walk is held to.
    pub limits: TraversalLimits,
    /// What the request is cleared to see.
    pub policy: TraversalPolicy,
}

impl TraversalRequest {
    /// A default-budgeted, unrestricted walk in both directions from one node.
    #[must_use]
    pub fn starting_at(start: NodeRef) -> Self {
        Self {
            filter: EdgeQuery::at(start, Direction::Either),
            limits: TraversalLimits::default(),
            policy: TraversalPolicy::unrestricted(),
        }
    }

    /// Replace the edge predicate, keeping the start node it names.
    #[must_use]
    pub fn with_filter(mut self, filter: EdgeQuery) -> Self {
        self.filter = filter;
        self
    }

    /// Replace the budgets.
    #[must_use]
    pub const fn with_limits(mut self, limits: TraversalLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replace the policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: TraversalPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Where the walk starts.
    #[must_use]
    pub const fn start(&self) -> NodeRef {
        self.filter.node
    }
}

/// Why a traversal was refused before anything was read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PlanRefused {
    /// A budget was zero, so the walk could not have visited anything.
    #[error("the {limit} budget is zero, so the traversal would visit nothing")]
    EmptyBudget {
        /// Which budget.
        limit: &'static str,
    },

    /// The start entity is not stored.
    ///
    /// Refused rather than answered with an empty result, because "nothing is connected to this"
    /// and "this is not in the database" are different answers and an analyst acts differently on
    /// each. Observable start nodes are exempt: they are content-addressed and have no row of their
    /// own, which is the same exemption referential integrity makes on edge endpoints.
    #[error("the traversal starts at entity {id}, which is not stored")]
    UnknownStart {
        /// The identifier that was not found.
        id: String,
    },

    /// The start node's handling restrictions exceed what the request may see.
    #[error("the traversal starts at {id}, whose handling restrictions exceed this request's")]
    PolicyRefused {
        /// The identifier that was refused.
        id: String,
    },

    /// The start node alone has more edges than the whole edge budget.
    ///
    /// Refused before reading, which is the point: discovering this after collecting the edges
    /// would mean having already paid the cost the budget exists to prevent.
    #[error(
        "the start node has {degree} edges, over the {max_edges}-edge budget; nothing was read"
    )]
    StartNodeTooBusy {
        /// How many edges the start node has under this filter.
        degree: u64,
        /// The budget it exceeded.
        max_edges: usize,
    },
}

/// Why a traversal could not be completed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TraversalError {
    /// The cost or policy check refused it before execution.
    #[error("the traversal was refused before it ran: {0}")]
    Refused(#[from] PlanRefused),

    /// Reading a hop failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// One node the walk reached, and how far from the start it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReachedNode {
    /// How many hops from the start node. Zero for the start node itself.
    pub depth: u32,
    /// The node.
    pub node: NodeRef,
}

/// A checked, costed traversal that has not run yet.
///
/// Separate from running it so that "may this run, and what will it cost" is answerable without
/// reading the graph — which is what makes the cost check a *pre*-condition rather than a
/// post-mortem.
#[derive(Debug, Clone)]
pub struct TraversalPlan {
    request: TraversalRequest,
    start_degree: u64,
}

impl TraversalPlan {
    /// Check the budgets, the start node, and the policy, and cost the first hop.
    ///
    /// # Errors
    ///
    /// [`TraversalError::Refused`] if a budget is zero, the start entity is not stored, the policy
    /// withholds it, or its degree already exceeds the edge budget.
    /// [`TraversalError::Storage`] if the start node or its degree could not be read.
    pub fn prepare(
        store: &dyn StoreRead,
        request: TraversalRequest,
    ) -> Result<Self, TraversalError> {
        let limits = request.limits;
        if limits.max_depth == 0 {
            return Err(PlanRefused::EmptyBudget { limit: "depth" }.into());
        }
        if limits.max_nodes == 0 {
            return Err(PlanRefused::EmptyBudget { limit: "nodes" }.into());
        }
        if limits.max_edges == 0 {
            return Err(PlanRefused::EmptyBudget { limit: "edges" }.into());
        }
        if limits.max_fan_out == 0 {
            return Err(PlanRefused::EmptyBudget { limit: "fan-out" }.into());
        }

        // Entities have rows and so can be checked. Observables are content-addressed and have no
        // row of their own — the same reason referential integrity exempts them on edge endpoints.
        if let NodeRef::Entity(id) = request.start() {
            let Some(entity) = store.get_entity(id)? else {
                return Err(PlanRefused::UnknownStart { id: id.to_string() }.into());
            };
            if !request.policy.permits(&entity.markings) {
                return Err(PlanRefused::PolicyRefused { id: id.to_string() }.into());
            }
        }

        let start_degree = store.degree(&request.filter)?;
        if start_degree > u64::try_from(limits.max_edges).unwrap_or(u64::MAX) {
            return Err(PlanRefused::StartNodeTooBusy {
                degree: start_degree,
                max_edges: limits.max_edges,
            }
            .into());
        }

        Ok(Self {
            request,
            start_degree,
        })
    }

    /// How many edges the start node has under this request's filter.
    #[must_use]
    pub const fn start_degree(&self) -> u64 {
        self.start_degree
    }

    /// What was planned.
    #[must_use]
    pub const fn request(&self) -> &TraversalRequest {
        &self.request
    }

    /// Walk the graph, breadth first, stopping at the first budget that is reached.
    ///
    /// # Errors
    ///
    /// [`TraversalError::Storage`] if a hop could not be read. A budget being reached is **not** an
    /// error: the partial result is returned with [`Traversal::truncated`] saying which budget
    /// stopped it, because a caller that asked for a bounded answer got one.
    pub fn run(
        &self,
        store: &dyn StoreRead,
        token: &CancellationToken,
    ) -> Result<Traversal, TraversalError> {
        let limits = self.request.limits;
        let start = self.request.start();

        let mut visited: BTreeMap<NodeRef, u32> = BTreeMap::new();
        let mut collected: BTreeMap<Id<Relationship>, Relationship> = BTreeMap::new();
        let mut truncated: BTreeSet<Truncation> = BTreeSet::new();
        let mut cancellation: Option<Cancelled> = None;
        let mut withheld_by_policy = 0_usize;
        let mut edges_examined = 0_usize;
        let mut stopped_early = false;

        visited.insert(start, 0);
        let mut frontier: BTreeSet<NodeRef> = BTreeSet::from([start]);
        let mut depth = 0_u32;

        'walk: while depth < limits.max_depth && !frontier.is_empty() {
            let mut next: BTreeSet<NodeRef> = BTreeSet::new();

            for node in &frontier {
                // Checked once per node rather than once per edge: a node's edges are a single
                // bounded read, so checking inside the row loop would not stop it any sooner.
                if let Some(reason) = token.reason() {
                    cancellation = Some(reason);
                    truncated.insert(Truncation::Cancelled);
                    stopped_early = true;
                    break 'walk;
                }

                let mut rows =
                    store.edges_at(&self.request.filter.about(*node), limits.probe_page())?;
                if rows.len() > limits.fan_out() {
                    // The extra row the probe page asked for came back, so this node has more edges
                    // than the budget allows to be expanded. Say so, and expand only the budget.
                    truncated.insert(Truncation::FanOut);
                    rows.truncate(limits.fan_out());
                }

                for edge in rows {
                    edges_examined = edges_examined.saturating_add(1);

                    if !self.request.policy.permits(&edge.markings) {
                        // Not returned, and not traversed through: an edge used as a bridge leaks
                        // the connection even when the edge itself is withheld.
                        withheld_by_policy = withheld_by_policy.saturating_add(1);
                        continue;
                    }

                    let Some(other) = other_end(&edge, *node, self.request.filter.direction) else {
                        continue;
                    };

                    if !collected.contains_key(&edge.id) && collected.len() >= limits.max_edges {
                        truncated.insert(Truncation::Edges);
                        stopped_early = true;
                        break 'walk;
                    }

                    if !visited.contains_key(&other) {
                        if visited.len() >= limits.max_nodes {
                            truncated.insert(Truncation::Nodes);
                            stopped_early = true;
                            break 'walk;
                        }
                        // The guard that makes a cycle terminate: a node already reached is never
                        // queued again, so `A -> B -> C -> A` expands each node once and stops.
                        visited.insert(other, depth.saturating_add(1));
                        next.insert(other);
                    }

                    collected.insert(edge.id, edge);
                }
            }

            frontier = next;
            depth = depth.saturating_add(1);
        }

        // Nodes left unexpanded when the depth budget ran out. Reported as a depth truncation even
        // though those nodes might have had no further edges: "we stopped at the depth you set" is
        // the honest claim, and it is the one an analyst needs in order to ask for more.
        if !stopped_early && !frontier.is_empty() {
            truncated.insert(Truncation::Depth);
        }

        let mut nodes: Vec<ReachedNode> = visited
            .into_iter()
            .map(|(node, depth)| ReachedNode { depth, node })
            .collect();
        // Shallowest first, then by node. A total order over unique nodes, so two runs over the same
        // graph return the same sequence rather than merely the same set.
        nodes.sort_unstable();

        Ok(Traversal {
            start,
            nodes,
            edges: collected.into_values().collect(),
            truncated,
            cancellation,
            withheld_by_policy,
            edges_examined,
            algorithm: TRAVERSE_ALGORITHM,
            algorithm_version: TRAVERSE_ALGORITHM_VERSION,
        })
    }
}

/// What a traversal found, and what it did not look at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Traversal {
    /// Where the walk started.
    pub start: NodeRef,
    /// Every node reached, shallowest first and then in node order.
    ///
    /// Includes the start node, at depth zero, so [`Self::nodes`] is the neighbourhood rather than
    /// the neighbourhood minus its centre.
    pub nodes: Vec<ReachedNode>,
    /// Every edge collected, in identifier order.
    pub edges: Vec<Relationship>,
    /// Which budgets stopped the walk. Empty means the neighbourhood was exhausted.
    pub truncated: BTreeSet<Truncation>,
    /// Why cancellation stopped it, when it did.
    ///
    /// Separate from [`Truncation::Cancelled`] because a caller retries a deadline differently from
    /// an operator interrupt, and collapsing the two would lose that.
    pub cancellation: Option<Cancelled>,
    /// How many edges the policy withheld.
    ///
    /// Reported rather than silently dropped: "there is more here that you cannot see" is itself
    /// something an analyst needs to know.
    pub withheld_by_policy: usize,
    /// How many edge rows were read, including duplicates and withheld ones.
    pub edges_examined: usize,
    /// Which algorithm produced this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
}

impl Traversal {
    /// Whether the walk exhausted the neighbourhood rather than a budget.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.truncated.is_empty()
    }

    /// Whether one particular budget stopped it.
    #[must_use]
    pub fn stopped_by(&self, reason: Truncation) -> bool {
        self.truncated.contains(&reason)
    }

    /// How far from the start a node was reached, if it was.
    #[must_use]
    pub fn depth_of(&self, node: NodeRef) -> Option<u32> {
        self.nodes
            .iter()
            .find(|reached| reached.node == node)
            .map(|reached| reached.depth)
    }

    /// Whether a node was reached at all.
    #[must_use]
    pub fn reached(&self, node: NodeRef) -> bool {
        self.depth_of(node).is_some()
    }

    /// The deepest hop taken. Zero when only the start node was reached.
    #[must_use]
    pub fn deepest(&self) -> u32 {
        self.nodes
            .iter()
            .map(|reached| reached.depth)
            .max()
            .unwrap_or(0)
    }
}

/// Plan and run a traversal in one call.
///
/// The cost and policy checks still happen first — this only spares a caller that has no use for
/// the plan from naming it.
///
/// # Errors
///
/// [`TraversalError::Refused`] if the plan is refused, [`TraversalError::Storage`] if a hop could
/// not be read.
pub fn traverse(
    store: &dyn StoreRead,
    request: TraversalRequest,
    token: &CancellationToken,
) -> Result<Traversal, TraversalError> {
    TraversalPlan::prepare(store, request)?.run(store, token)
}

/// The end of an edge that is not the node it was expanded from.
///
/// Returns `None` for an edge that does not touch the node in a direction the request asked for,
/// which the storage filter should already have excluded — belt and braces, because silently
/// treating such a row as a neighbour would walk the graph in a direction the caller forbade.
fn other_end(edge: &Relationship, node: NodeRef, direction: Direction) -> Option<NodeRef> {
    if direction.includes_source() && edge.source == node {
        return Some(edge.target);
    }
    if direction.includes_target() && edge.target == node {
        return Some(edge.source);
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use brolga_model::{Marking, RecordOrigin, ShortText, SyntheticOrigin, SyntheticReason};

    fn origin() -> RecordOrigin {
        RecordOrigin::Synthetic {
            origin: SyntheticOrigin::new(
                SyntheticReason::Fixture,
                ShortText::new("traverse-unit").unwrap(),
            ),
        }
    }

    fn node(name: &str) -> NodeRef {
        NodeRef::Entity(Id::derive(&["entity", name]))
    }

    fn edge(from: &str, to: &str) -> Relationship {
        Relationship::new(
            brolga_model::RelationshipKind::Uses,
            node(from),
            node(to),
            origin(),
        )
    }

    /// The probe page must be exactly one row wider than the fan-out budget, and must stay inside
    /// the storage page ceiling. If it ever exceeded the ceiling the page would clamp, and a hub
    /// would silently look like it had exactly the ceiling's worth of edges.
    #[test]
    fn the_probe_page_is_one_wider_than_the_fan_out_and_still_pageable() {
        let limits = TraversalLimits::new(1, 1, 1, 10);
        assert_eq!(limits.probe_page().limit(), 11);

        let greedy = TraversalLimits::new(1, 1, 1, u32::MAX);
        assert_eq!(greedy.max_fan_out, TraversalLimits::MAX_FAN_OUT);
        assert_eq!(greedy.probe_page().limit(), Page::MAX_LIMIT);
    }

    /// An unmarked record must not be withheld. Most feeds mark nothing, and inventing a
    /// restriction the publisher never stated would hide most of a graph.
    #[test]
    fn an_unmarked_record_is_not_withheld_but_an_over_marked_one_is() {
        let policy = TraversalPolicy::permitting(TlpLevel::Green);
        assert!(policy.permits(&MarkingSet::empty()));
        assert!(policy.permits(&MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Clear)])));
        assert!(policy.permits(&MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Green)])));
        assert!(!policy.permits(&MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Amber)])));

        assert!(
            TraversalPolicy::unrestricted()
                .permits(&MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Red)])),
            "an unrestricted policy withholds nothing",
        );
    }

    /// Walking in one direction must not follow an edge backwards. Otherwise "what does this actor
    /// use" would also answer "what uses this actor", which is a different statement.
    #[test]
    fn the_far_end_is_only_taken_in_a_direction_the_request_asked_for() {
        let uses = edge("actor", "tool");

        assert_eq!(
            other_end(&uses, node("actor"), Direction::Outgoing),
            Some(node("tool"))
        );
        assert_eq!(
            other_end(&uses, node("tool"), Direction::Outgoing),
            None,
            "an incoming edge must not be followed by an outgoing-only walk",
        );
        assert_eq!(
            other_end(&uses, node("tool"), Direction::Incoming),
            Some(node("actor"))
        );
        assert_eq!(
            other_end(&uses, node("tool"), Direction::Either),
            Some(node("actor"))
        );
        assert_eq!(
            other_end(&uses, node("unrelated"), Direction::Either),
            None,
            "an edge that does not touch the node is not a neighbour",
        );
    }

    /// Truncation labels are written into results a consumer may store, so they are a compatibility
    /// surface and must be distinct.
    #[test]
    fn every_truncation_reason_has_a_distinct_label() {
        let labels: BTreeSet<&str> = [
            Truncation::Depth,
            Truncation::Nodes,
            Truncation::Edges,
            Truncation::FanOut,
            Truncation::Cancelled,
        ]
        .into_iter()
        .map(Truncation::as_str)
        .collect();
        assert_eq!(labels.len(), 5);
    }

    /// The defaults must all be non-zero, or a caller taking them would be refused by the very
    /// check that exists to catch a mistake.
    #[test]
    fn the_default_budgets_are_all_usable() {
        let limits = TraversalLimits::default();
        assert!(limits.max_depth > 0);
        assert!(limits.max_nodes > 0);
        assert!(limits.max_edges > 0);
        assert!(limits.max_fan_out > 0);
        assert!(limits.max_fan_out <= TraversalLimits::MAX_FAN_OUT);
    }
}
