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

use brolga_model::MarkingSet;
use brolga_model::claim::{Assertion, Claim};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::sighting::Sighting;
use brolga_model::status::Disposition;
use brolga_model::text::{ShortText, UntrustedText};
use brolga_model::version::SchemaTag;
use brolga_storage::store::{Direction, EdgeQuery, Page, StoreRead};

use crate::error::{ApiError, RequestId, from_read_failure};
use crate::state::ApiState;
use brolga_graph::subject;

/// The schema a consumer sees on the pack.
///
/// Matches the identifier Kelpie's consumer contract was written against.
pub const CONTEXT_PACK_SCHEMA: &str = "brolga.context_pack/1.1";

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

// The pack is a *model* type, not an API one. It is the thing a consumer stores, diffs, and acts
// on, and it must be identical whether it arrived over HTTP, over MCP, or out of the CLI — so it
// lives in `brolga-model` beside every other versioned schema, and this layer only builds one.
pub use brolga_model::pack::{
    Budget, BudgetReport, ClaimSummary, ContextPack, Contradiction, DetailLevel, EntitySummary,
    EvidenceRef, Exclusion, ExclusionReason, ExpansionHandle, Finding, Gap, PackGraph,
    PackMetadata, PackSubject, Pivot, PolicyContext, Recommendation, RelationshipSummary,
    SightingSummary,
};

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

    // Every rejection is the caller's to fix. `SubjectRejected` is `#[non_exhaustive]`, and a new
    // variant is still a bad request rather than an internal failure — mapping an unknown
    // rejection to a 500 would blame Brolga for a value the caller sent.
    let observable =
        subject::resolve(&request.subject.kind, &request.subject.value).map_err(|error| {
            ApiError::BadRequest {
                message: error.to_string(),
            }
        })?;

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

            // Read inside the same lock as everything else, so the version describes the graph the
            // pack was actually assembled from rather than one it may have moved to since.
            let graph_version = store.graph_version()?;

            Ok((claims, edges, sightings, entities, graph_version))
        })
        .map_err(|error| from_read_failure(&error, &request_id))?;

    let (claims, edges, sightings, entities, graph_version) = gathered;

    // The identity this request is served under. Loopback with no credential is a local operator;
    // anything else is anonymous until authentication says otherwise. Deriving it here rather than
    // defaulting to "everything" is the point — an unidentified caller must not out-rank an
    // authenticated one by saying less.
    let identity = state.policy_identity();

    // Withheld before anything is summarised, so restricted material never reaches a string that
    // later gets rendered. Filtering after formatting is how a redaction misses a copy.
    let (claims, claim_denials) = brolga_config::partition(
        &identity,
        &claims,
        brolga_config::Capability::Read,
        |claim| &claim.markings,
    );
    let (edges, edge_denials) =
        brolga_config::partition(&identity, &edges, brolga_config::Capability::Read, |edge| {
            &edge.markings
        });
    let claims: Vec<Claim> = claims.into_iter().cloned().collect();
    let edges: Vec<Relationship> = edges.into_iter().cloned().collect();
    let withheld = claim_denials.len().saturating_add(edge_denials.len());

    let mut evidence: BTreeSet<EvidenceRef> = BTreeSet::new();
    for claim in &claims {
        for source in claim.origin.source_objects() {
            evidence.insert(EvidenceRef::new(source.to_string()));
        }
    }

    let disposition = disposition_of(&claims, &edges);

    let mut gaps = Vec::new();
    if claims.is_empty() && edges.is_empty() {
        gaps.extend(gap("store", "nothing is stored about this observable"));
    }
    if sightings.is_empty() {
        gaps.extend(gap(
            "sightings",
            "no sightings recorded; Brolga cannot say when this was last seen",
        ));
    }
    if evidence.is_empty() && !claims.is_empty() {
        gaps.extend(gap(
            "evidence",
            "claims are stored but no source object was retained for them",
        ));
    }
    if !claims.is_empty() && claims.iter().all(|claim| !claim.status.is_current()) {
        // Not the same as never having heard of it. A consumer that treats them alike will
        // re-raise a finding someone deliberately retracted.
        gaps.extend(gap(
            "claims",
            "every stored claim about this observable has been withdrawn or superseded",
        ));
    }

    let mut exclusions = Vec::new();
    let mut exhausted = false;
    if withheld > 0 {
        exclusions.extend(exclusion("claims", ExclusionReason::PolicyRestricted));
        gaps.extend(gap(
            "policy",
            "some records were withheld because their handling markings exceed this caller's \
             clearance",
        ));
    }
    if u32::try_from(claims.len()).unwrap_or(u32::MAX) >= budget {
        exhausted = true;
        exclusions.extend(exclusion("claims", ExclusionReason::BudgetExhausted));
    }
    if u32::try_from(edges.len()).unwrap_or(u32::MAX) >= edge_budget {
        exhausted = true;
        exclusions.extend(exclusion("relationships", ExclusionReason::BudgetExhausted));
    }

    // Served, not requested. Telling a consumer it received L5 when it received L1 is worse than
    // telling it the truth, because it will stop looking for the depth it did not get.
    let served_level = DetailLevel::L1;
    if request
        .detail_level
        .as_deref()
        .is_some_and(|level| level != served_level.as_str())
    {
        exclusions.extend(exclusion("detail_level", ExclusionReason::NotImplemented));
        gaps.extend(gap(
            "detail_level",
            "progressive disclosure is not implemented; served L1",
        ));
    }

    let mut summaries: Vec<EntitySummary> = entities
        .iter()
        .filter_map(|entity| {
            Some(EntitySummary {
                id: entity.id.to_string(),
                kind: ShortText::new(entity.kind.as_str()).ok()?,
                name: entity.name.clone(),
                status: ShortText::new(entity.status.as_str()).ok()?,
            })
        })
        .collect();
    summaries.sort_by(|left, right| left.id.cmp(&right.id));
    summaries.dedup_by(|left, right| left.id == right.id);

    let evidence: Vec<EvidenceRef> = evidence.into_iter().collect();

    // The disposition is a *finding*, and a finding must cite its evidence — which is what makes
    // the pack's central assertion defensible rather than merely present. Where nothing was
    // retained, no finding is emitted and the gap above says why; a finding citing nothing would
    // fail validation, and rightly.
    let findings = disposition_finding(disposition, &evidence)
        .into_iter()
        .collect();

    let graph = PackGraph {
        entities: summaries,
        claims: claims
            .iter()
            .filter_map(|claim| summarise_claim(claim, &evidence))
            .collect(),
        relationships: edges.iter().filter_map(summarise_relationship).collect(),
        sightings: sightings.iter().filter_map(summarise_sighting).collect(),
        ..PackGraph::default()
    };

    // A handle per claim, so every compressed item is expandable back to its canonical record and
    // its original bytes. Issued at every level, including the summary ones — the point of a
    // summary is that it does not *carry* records, not that it hides where they are.
    let handles: Vec<ExpansionHandle> = claims
        .iter()
        .filter_map(|claim| {
            Some(ExpansionHandle::new(
                claim.id.to_string(),
                ShortText::new("claim").ok()?,
                DetailLevel::L5,
                graph_version,
                brolga_model::Timestamp::from_offset_date_time(::time::OffsetDateTime::now_utc())
                    .to_rfc3339(),
            ))
        })
        .collect();

    let pack = ContextPack {
        schema_version: SchemaTag::new(),
        fingerprint: String::new(),
        subject: PackSubject {
            kind: ShortText::new(observable.kind().as_str())
                .map_err(|error| unusable_pack(&error.to_string(), &request_id))?,
            value: ShortText::new(bounded_value(&observable.canonical_value()))
                .map_err(|error| unusable_pack(&error.to_string(), &request_id))?,
            observable_id: observable_id.to_string(),
        },
        purpose: request
            .purpose
            .as_deref()
            .and_then(|purpose| ShortText::new(purpose).ok()),
        detail_level: served_level,
        disposition,
        graph,
        handles,
        findings,
        recommendations: Vec::new(),
        gaps,
        exclusions,
        budget: BudgetReport {
            requested: Budget {
                objects: requested.max_objects.map(u64::from),
                relationships: requested.max_relationships.map(u64::from),
                ..Budget::default()
            },
            consumed: Budget {
                objects: Some(u64::try_from(claims.len()).unwrap_or(u64::MAX)),
                relationships: Some(u64::try_from(edges.len()).unwrap_or(u64::MAX)),
                ..Budget::default()
            },
            exhausted,
        },
        policy: PolicyContext {
            recipient: ShortText::new(&identity.name).ok(),
            // Gathered from the records that reached the pack, so a consumer can see what handling
            // applies without opening every claim. Nothing is withheld yet — that is #37 — and
            // `restricted` says so honestly rather than implying a filter that does not run.
            markings: pack_markings(&claims, &edges),
            restricted: withheld > 0,
        },
        metadata: PackMetadata {
            generated_at: brolga_model::Timestamp::from_offset_date_time(
                ::time::OffsetDateTime::now_utc(),
            )
            .to_rfc3339(),
            request_id: Some(request_id.as_str().to_owned()),
            build_duration_ms: None,
            brolga_version: env!("CARGO_PKG_VERSION").to_owned(),
            graph_version,
        },
    }
    .validated()
    .map_err(|error| unusable_pack(&error.to_string(), &request_id))?;

    Ok(Json(pack))
}

/// A pack that could not be built, logged and reported as an internal failure.
///
/// A validation failure here means Brolga assembled something that violates its own contract —
/// most likely a finding with no evidence. Returning the half-built pack would publish exactly the
/// thing validation exists to prevent, so it is refused and the reason goes to the log rather than
/// to the caller.
fn unusable_pack(reason: &str, request_id: &RequestId) -> ApiError {
    tracing::error!(
        request_id = request_id.as_str(),
        reason,
        "assembled a context pack that failed its own validation"
    );
    ApiError::Internal
}

/// The pack's central assertion, as a finding that cites its evidence.
fn disposition_finding(disposition: Disposition, evidence: &[EvidenceRef]) -> Option<Finding> {
    if evidence.is_empty() {
        return None;
    }
    Some(Finding {
        kind: ShortText::new("disposition").ok()?,
        statement: UntrustedText::new(format!("Brolga assesses this observable as {disposition}."))
            .ok()?,
        evidence: evidence.to_vec(),
    })
}

/// Every marking carried by the records that reached the pack.
fn pack_markings(claims: &[Claim], edges: &[Relationship]) -> MarkingSet {
    let mut set = MarkingSet::empty();
    for marking in claims
        .iter()
        .flat_map(|claim| claim.markings.iter())
        .chain(edges.iter().flat_map(|edge| edge.markings.iter()))
    {
        set.insert(marking.clone());
    }
    set
}

/// Truncate a canonical value to what `ShortText` accepts, at a character boundary.
fn bounded_value(value: &str) -> String {
    if value.len() <= ShortText::MAX_BYTES {
        return value.to_owned();
    }
    let mut end = ShortText::MAX_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// A gap, from compile-time literals.
///
/// `Option` rather than a fallback value. Every caller passes a literal that always constructs, so
/// the `None` arm is unreachable in practice — and a fabricated placeholder gap would be worse than
/// no gap, because a gap is a statement about what Brolga does not know and an invented one is a
/// false statement about that.
fn gap(subject: &'static str, detail: &'static str) -> Option<Gap> {
    Some(Gap {
        subject: ShortText::new(subject).ok()?,
        detail: UntrustedText::new(detail).ok()?,
    })
}

/// An exclusion naming a category and a machine-readable reason.
fn exclusion(category: &'static str, reason: ExclusionReason) -> Option<Exclusion> {
    Some(Exclusion {
        category: ShortText::new(category).ok()?,
        reason,
        dropped: None,
    })
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
fn disposition_of(claims: &[Claim], _edges: &[Relationship]) -> Disposition {
    let mut strongest: Option<(u8, Disposition)> = None;

    for claim in claims.iter().filter(|claim| claim.status.is_current()) {
        if let Assertion::Disposition(disposition) = &claim.assertion {
            let rank = severity(*disposition);
            if strongest.is_none_or(|(best, _)| rank > best) {
                strongest = Some((rank, *disposition));
            }
        }
    }

    strongest.map_or(Disposition::Unknown, |(_, disposition)| disposition)
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

fn summarise_claim(claim: &Claim, evidence: &[EvidenceRef]) -> Option<ClaimSummary> {
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

    let own: Vec<EvidenceRef> = claim
        .origin
        .source_objects()
        .iter()
        .map(|source| EvidenceRef::new(source.to_string()))
        .collect();

    Some(ClaimSummary {
        predicate: ShortText::new(predicate).ok()?,
        object: UntrustedText::new(object).ok()?,
        status: ShortText::new(claim.status.as_str()).ok()?,
        confidence: claim
            .confidence
            .as_ref()
            .map(|breakdown| breakdown.overall.get()),
        // Its own sources where it has them, falling back to the pack's so a claim is never
        // rendered as evidence-free when the pack as a whole is not.
        evidence: if own.is_empty() {
            evidence.to_vec()
        } else {
            own
        },
    })
}

fn summarise_relationship(edge: &Relationship) -> Option<RelationshipSummary> {
    Some(RelationshipSummary {
        kind: ShortText::new(edge.kind.as_str()).ok()?,
        source: edge.source.to_string(),
        target: edge.target.to_string(),
        status: ShortText::new(edge.status.as_str()).ok()?,
    })
}

/// An observation, as the pack renders one.
///
/// The window and the count, which is what corroboration is computed from. An unattributed sighting
/// keeps `observer` absent rather than naming a placeholder — an invented observer looks exactly
/// like corroboration, which is the one thing a sighting exists to measure.
fn summarise_sighting(sighting: &Sighting) -> Option<SightingSummary> {
    Some(SightingSummary {
        count: sighting.count.get(),
        first_seen: sighting.first_seen.to_rfc3339(),
        last_seen: sighting.last_seen.to_rfc3339(),
        observer: sighting.observer.map(|id| id.to_string()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn an_observable_with_nothing_stored_is_unknown_not_benign() {
        assert_eq!(disposition_of(&[], &[]), Disposition::Unknown);
    }

    /// The pack's schema id is what Kelpie's consumer contract was written against. Changing it is
    /// a breaking change for an already-deployed integration.
    #[test]
    fn the_pack_schema_is_the_one_consumers_were_told_about() {
        use brolga_model::version::VersionedSchema;

        assert_eq!(
            ContextPack::schema_identifier(),
            "brolga.context_pack/1.1",
            "the pack's schema id is what a deployed consumer contract was written against"
        );
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
