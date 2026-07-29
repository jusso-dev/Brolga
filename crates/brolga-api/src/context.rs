//! `POST /api/v1/context` — the context pack.
//!
//! The route Brolga exists for. A consumer holds one observable — an address from a firewall log,
//! a hash from an endpoint detection — and asks what is known about it. The answer is a compact,
//! attributable summary rather than a dump of every record that touches it.
//!
//! # What is honest about this pack
//!
//! Every field is derived from stored records. Where Brolga does not know something it says so, in
//! `gaps`, rather than omitting the field and letting absence read as "no". A disposition of
//! `unknown` is a real answer and the most common correct one.
//!
//! Progressive disclosure (`detail_level` beyond `L1`) and `expansion_handles` are accepted and
//! acknowledged but not yet honoured; the pack reports the level it actually served so a consumer
//! is never told it received more depth than it did.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use brolga_model::claim::{Assertion, Claim};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::status::Disposition;
use brolga_storage::store::{Direction, EdgeQuery, Page, StoreRead};

use crate::error::{ApiError, RequestId, from_read_failure};
use crate::state::ApiState;
use crate::subject::{self, SubjectRejected};

/// The schema a consumer sees on the pack.
///
/// Matches the identifier Kelpie's consumer contract was written against.
pub const CONTEXT_PACK_SCHEMA: &str = "brolga.context_pack/1.0";

/// How many records of each kind are gathered before the pack stops growing.
///
/// A budget, not a page: an observable connected to ten thousand sightings produces a pack no
/// consumer can use and a response no case needs. What is dropped is reported in `exclusions`,
/// because a silently truncated pack is one a consumer will read as complete.
const DEFAULT_BUDGET: u32 = 50;

/// The largest budget a consumer may ask for.
const MAX_BUDGET: u32 = 500;

// -------------------------------------------------------------------------------------------------
// Request
// -------------------------------------------------------------------------------------------------

/// What a consumer POSTs.
#[derive(Debug, Clone, Deserialize)]
pub struct ContextRequest {
    /// The thing being asked about.
    pub subject: Subject,

    /// Why it is being asked. Recorded, not yet used to shape the pack.
    #[serde(default)]
    pub purpose: Option<String>,

    /// How much depth is wanted.
    #[serde(default)]
    pub detail_level: Option<String>,

    /// Soft caps.
    #[serde(default)]
    pub budgets: Option<Budgets>,

    /// The consumer's case, for correlation in Brolga's logs.
    #[serde(default)]
    pub case_id: Option<String>,
}

/// The observable being asked about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// `ip`, `domain`, `file_hash`, and the rest.
    pub kind: String,
    /// The value, in whatever spelling the consumer has.
    pub value: String,
}

/// Soft caps a consumer may request.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Budgets {
    /// Cap on records gathered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_objects: Option<u32>,
    /// Cap on relationship fan-out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_relationships: Option<u32>,
}

// -------------------------------------------------------------------------------------------------
// Response
// -------------------------------------------------------------------------------------------------

/// The pack.
#[derive(Debug, Clone, Serialize)]
pub struct ContextPack {
    /// The version of this body.
    pub schema_version: &'static str,
    /// What was asked about, canonicalised — which may differ from what was sent.
    pub subject: Subject,
    /// The canonical observable id the answer was assembled from.
    pub observable_id: String,
    /// The purpose the consumer declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The detail level actually served, which may be lower than the one requested.
    pub detail_level: &'static str,
    /// What Brolga makes of it.
    pub disposition: &'static str,
    /// Named entities connected to the subject.
    pub entities: Vec<EntitySummary>,
    /// Assertions about the subject.
    pub claims: Vec<ClaimSummary>,
    /// Edges at the subject.
    pub relationships: Vec<RelationshipSummary>,
    /// Where the answer came from.
    pub evidence: Vec<EvidenceRef>,
    /// What Brolga does not know. Stated rather than left to be inferred from absence.
    pub gaps: Vec<String>,
    /// What was deliberately left out, and why.
    pub exclusions: Vec<Exclusion>,
    /// What was asked for and what it cost.
    pub budget: BudgetReport,
}

/// A named thing connected to the subject.
#[derive(Debug, Clone, Serialize)]
pub struct EntitySummary {
    /// The entity id.
    pub id: String,
    /// Its kind.
    pub kind: String,
    /// Its name.
    pub name: String,
    /// Its lifecycle status — a revoked entity is still an answer, but a different one.
    pub status: String,
}

/// An assertion about the subject.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimSummary {
    /// What is asserted.
    pub predicate: String,
    /// What it is asserted about.
    pub object: String,
    /// The asserted status.
    pub status: String,
    /// Confidence, where the source expressed one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

/// An edge at the subject.
#[derive(Debug, Clone, Serialize)]
pub struct RelationshipSummary {
    /// The relationship kind.
    pub kind: String,
    /// The source node.
    pub source: String,
    /// The target node.
    pub target: String,
    /// Its lifecycle status.
    pub status: String,
}

/// Where a piece of the answer came from.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    /// The retained source object.
    pub source_object_id: String,
}

/// Something left out of the pack.
#[derive(Debug, Clone, Serialize)]
pub struct Exclusion {
    /// What was dropped.
    pub category: &'static str,
    /// Why.
    pub reason: String,
}

/// What the pack cost.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetReport {
    /// What the consumer asked for.
    pub requested: Budgets,
    /// What was actually gathered.
    pub consumed: Budgets,
}

// -------------------------------------------------------------------------------------------------
// Handler
// -------------------------------------------------------------------------------------------------

/// Build a context pack for one observable.
///
/// # Errors
///
/// Returns [`ApiError::BadRequest`] if the subject cannot be resolved to an observable, or
/// [`ApiError::Internal`] if the store cannot be read.
pub async fn context<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
    Json(request): Json<ContextRequest>,
) -> Result<Json<ContextPack>, ApiError> {
    let request_id = RequestId::generate();

    let observable = subject::resolve(&request.subject.kind, &request.subject.value).map_err(
        |error| match error {
            SubjectRejected::UnknownKind { .. } | SubjectRejected::Malformed { .. } => {
                ApiError::BadRequest {
                    message: error.to_string(),
                }
            }
        },
    )?;

    let observable_id = observable.id();
    let node = NodeRef::Observable(observable_id);

    // The consumer's case id goes in the log, not the pack. It correlates a Brolga query with the
    // case that prompted it without Brolga storing anything about the consumer's investigation.
    if let Some(case_id) = request.case_id.as_deref() {
        tracing::info!(
            request_id = request_id.as_str(),
            case_id,
            observable = %observable_id,
            "context requested"
        );
    }

    let requested = request.budgets.unwrap_or_default();
    let budget = requested
        .max_objects
        .unwrap_or(DEFAULT_BUDGET)
        .clamp(1, MAX_BUDGET);
    let edge_budget = requested
        .max_relationships
        .unwrap_or(DEFAULT_BUDGET)
        .clamp(1, MAX_BUDGET);

    // One lock acquisition for the whole pack. A pack assembled from several reads could describe
    // a graph that never existed at any instant, which is precisely the kind of answer a case
    // should not be enriched with.
    let gathered = state
        .read(|store| {
            let claims = store.claims_about(&node, Page::first(budget))?;
            let edges = store.edges_at(
                &EdgeQuery::at(node, Direction::Either),
                Page::first(edge_budget),
            )?;
            let sightings = store.sightings_of(&node, Page::first(budget))?;

            // Resolve the entity at the far end of each edge, so the pack names "Bunyip Panda"
            // rather than an opaque id the consumer would have to fetch separately.
            let mut entities = Vec::new();
            for edge in &edges {
                for end in [edge.source, edge.target] {
                    if let NodeRef::Entity(id) = end
                        && let Some(entity) = store.get_entity(id)?
                    {
                        entities.push(entity);
                    }
                }
            }

            Ok((claims, edges, sightings, entities))
        })
        .map_err(|error| from_read_failure(&error, &request_id))?;

    let (claims, edges, sightings, entities) = gathered;

    let mut evidence: BTreeSet<EvidenceRef> = BTreeSet::new();
    for claim in &claims {
        for source in claim.origin.source_objects() {
            evidence.insert(EvidenceRef {
                source_object_id: source.to_string(),
            });
        }
    }

    let disposition = disposition_of(&claims, &edges);

    let mut gaps = Vec::new();
    if claims.is_empty() && edges.is_empty() {
        gaps.push("nothing is stored about this observable".to_owned());
    }
    if sightings.is_empty() {
        gaps.push("no sightings recorded; Brolga cannot say when this was last seen".to_owned());
    }
    if evidence.is_empty() && !claims.is_empty() {
        gaps.push("claims are stored but no source object was retained for them".to_owned());
    }
    if !claims.is_empty() && claims.iter().all(|claim| !claim.status.is_current()) {
        // Not the same as never having heard of it. A consumer that treats them alike will
        // re-raise a finding someone deliberately retracted.
        gaps.push(
            "every stored claim about this observable has been withdrawn or superseded".to_owned(),
        );
    }

    let mut exclusions = Vec::new();
    if u32::try_from(claims.len()).unwrap_or(u32::MAX) >= budget {
        exclusions.push(Exclusion {
            category: "claims",
            reason: format!("stopped at the {budget}-record budget; there may be more"),
        });
    }
    if u32::try_from(edges.len()).unwrap_or(u32::MAX) >= edge_budget {
        exclusions.push(Exclusion {
            category: "relationships",
            reason: format!("stopped at the {edge_budget}-relationship budget; there may be more"),
        });
    }

    // Served, not requested. Telling a consumer it received L5 when it received L1 is worse than
    // telling it the truth, because it will stop looking for the depth it did not get.
    let served_level = "L1";
    if request
        .detail_level
        .as_deref()
        .is_some_and(|level| level != served_level)
    {
        exclusions.push(Exclusion {
            category: "detail_level",
            reason: format!("progressive disclosure is not implemented; served {served_level}"),
        });
    }

    let mut summaries: Vec<EntitySummary> = entities
        .iter()
        .map(|entity| EntitySummary {
            id: entity.id.to_string(),
            kind: entity.kind.as_str().to_owned(),
            name: entity.name.as_str().to_owned(),
            status: entity.status.as_str().to_owned(),
        })
        .collect();
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    summaries.dedup_by(|left, right| left.id == right.id);

    Ok(Json(ContextPack {
        schema_version: CONTEXT_PACK_SCHEMA,
        subject: Subject {
            kind: observable.kind().as_str().to_owned(),
            value: observable.canonical_value(),
        },
        observable_id: observable_id.to_string(),
        purpose: request.purpose,
        detail_level: served_level,
        disposition,
        claims: claims.iter().map(summarise_claim).collect(),
        relationships: edges.iter().map(summarise_relationship).collect(),
        evidence: evidence.into_iter().collect(),
        entities: summaries,
        gaps,
        exclusions,
        budget: BudgetReport {
            requested,
            consumed: Budgets {
                max_objects: Some(u32::try_from(claims.len()).unwrap_or(u32::MAX)),
                max_relationships: Some(u32::try_from(edges.len()).unwrap_or(u32::MAX)),
            },
        },
    }))
}

/// What Brolga makes of the subject overall.
///
/// The strongest *currently standing* disposition asserted about it. Deliberately biased towards
/// `unknown`: a consumer acting on this is deciding whether to raise a case, and inferring
/// `benign` from an absence of evidence would turn "Brolga has not heard of this" into "Brolga
/// says this is fine" — the more expensive of the two mistakes.
///
/// Withdrawn claims are ignored rather than counted, because a retracted finding that still drives
/// a disposition is a retraction that did not happen. An observable whose only claims are
/// withdrawn reports `unknown` and says so in `gaps`.
///
/// `allow_listed` outranks `benign` because it is a decision about how Brolga treats the subject
/// rather than a finding about it, and a decision should not be silently overridden by a feed.
fn disposition_of(claims: &[Claim], _edges: &[Relationship]) -> &'static str {
    let mut strongest = None;

    for claim in claims.iter().filter(|claim| claim.status.is_current()) {
        if let Assertion::Disposition(disposition) = &claim.assertion {
            let rank = severity(*disposition);
            if strongest.is_none_or(|(best, _)| rank > best) {
                strongest = Some((rank, disposition.as_str()));
            }
        }
    }

    strongest.map_or("unknown", |(_, name)| name)
}

/// How strongly a disposition should carry when several disagree.
const fn severity(disposition: Disposition) -> u8 {
    match disposition {
        Disposition::Unknown => 0,
        Disposition::Benign => 1,
        Disposition::AllowListed => 2,
        Disposition::Suspicious => 3,
        Disposition::Malicious => 4,
        // `Disposition` is `#[non_exhaustive]`. A variant added upstream ranks below anything
        // actionable rather than above it: over-reporting `malicious` because of an unrecognised
        // variant is how a consumer learns to ignore the field.
        _ => 0,
    }
}

fn summarise_claim(claim: &Claim) -> ClaimSummary {
    // The assertion's shape decides how it reads. A disposition is the answer a consumer acts on;
    // an attribute is a fact about the subject; a narrative is prose from a feed and is passed
    // through as evidence rather than interpreted.
    let (predicate, object) = match &claim.assertion {
        Assertion::Disposition(disposition) => {
            ("disposition".to_owned(), disposition.as_str().to_owned())
        }
        Assertion::Attribute { name, value } => {
            (name.as_str().to_owned(), value.as_str().to_owned())
        }
        Assertion::Narrative(text) => ("narrative".to_owned(), text.as_str().to_owned()),
        // `Assertion` is `#[non_exhaustive]`. An assertion shape added upstream is surfaced as
        // unrecognised rather than dropped: a consumer seeing "there is a claim here I cannot
        // read" can go and look, where a silently missing claim leaves no trace at all.
        _ => ("unrecognised".to_owned(), String::new()),
    };

    ClaimSummary {
        predicate,
        object,
        status: claim.status.as_str().to_owned(),
        confidence: claim
            .confidence
            .as_ref()
            .map(|breakdown| breakdown.overall.get()),
    }
}

fn summarise_relationship(edge: &Relationship) -> RelationshipSummary {
    RelationshipSummary {
        kind: edge.kind.as_str().to_owned(),
        source: edge.source.to_string(),
        target: edge.target.to_string(),
        status: edge.status.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn an_observable_with_nothing_stored_is_unknown_not_benign() {
        assert_eq!(disposition_of(&[], &[]), "unknown");
    }

    /// The pack's schema id is what Kelpie's consumer contract was written against. Changing it is
    /// a breaking change for an already-deployed integration.
    #[test]
    fn the_pack_schema_is_the_one_consumers_were_told_about() {
        assert_eq!(CONTEXT_PACK_SCHEMA, "brolga.context_pack/1.0");
    }

    /// Checked at compile time, because both are constants: a runtime assertion about them can
    /// only fail in a build that already shipped.
    const _: () = assert!(DEFAULT_BUDGET >= 1);
    const _: () = assert!(DEFAULT_BUDGET <= MAX_BUDGET);

    /// A budget the caller cannot exceed, so one consumer cannot ask for a pack that costs the
    /// server everything.
    #[test]
    fn the_requested_budget_is_clamped_to_the_ceiling() {
        assert_eq!(u32::MAX.clamp(1, MAX_BUDGET), MAX_BUDGET);
        assert_eq!(0_u32.clamp(1, MAX_BUDGET), 1);
    }
}
