//! The `/api/v1` handlers.
//!
//! Read-only. Brolga's consumers pull context to enrich something they already have — a case, an
//! alert, an agent's question — and a read-only surface is one that cannot be talked into
//! rewriting the graph by a service that was only meant to look at it. Ingestion stays on the CLI,
//! where the operator running it is the one who chose the source.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use brolga_model::entity::{Entity, EntityKind};
use brolga_model::relationship::{NodeRef, Relationship};
use brolga_model::status::LifecycleStatus;
use brolga_storage::store::{Direction, EdgeQuery, EntityQuery, Page, RecordKind, StoreRead};

use crate::error::{ApiError, RequestId, from_read_failure};
use crate::schema::RESPONSE_SCHEMA;
use crate::state::ApiState;

/// The largest page a client may ask for.
///
/// A client that asks for everything gets the first thousand and a `next_offset`. Without this an
/// unauthenticated loopback request can ask the server to materialise the entire graph in memory.
const MAX_PAGE_SIZE: u32 = 1000;

/// The page size used when the client does not say.
const DEFAULT_PAGE_SIZE: u32 = 100;

// -------------------------------------------------------------------------------------------------
// Envelope
// -------------------------------------------------------------------------------------------------

/// The shape of every successful response.
///
/// Every payload is wrapped rather than returned bare, so that a response always has somewhere to
/// put the schema version and the paging cursor. A bare array has nowhere to grow.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope<T> {
    /// The version of this body.
    pub schema: &'static str,
    /// The payload.
    pub data: T,
    /// Where to continue from, absent when this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u64>,
}

impl<T> Envelope<T> {
    fn new(data: T) -> Self {
        Self {
            schema: RESPONSE_SCHEMA,
            data,
            next_offset: None,
        }
    }

    /// Attach a continuation cursor when a full page came back.
    ///
    /// A full page means "there may be more", not "there is more". Returning a cursor that yields
    /// an empty page is correct and cheap; omitting one when there is more silently truncates the
    /// answer, which is the failure that matters here.
    fn paged(data: T, returned: usize, page: Page) -> Self {
        let next_offset = (u64::try_from(returned).unwrap_or(u64::MAX) >= u64::from(page.limit()))
            .then(|| page.offset().saturating_add(u64::from(page.limit())));
        Self {
            schema: RESPONSE_SCHEMA,
            data,
            next_offset,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Paging
// -------------------------------------------------------------------------------------------------

/// `?limit=&offset=` on every collection route.
///
/// Deliberately *not* `#[serde(flatten)]`ed into the filter structs. Flattening routes the whole
/// query string through serde's internally-buffered map, where every value arrives as a string and
/// integer fields stop deserialising — which turns `?limit=100` into a 400 on every route that
/// uses it. The fields are declared on each filter instead and handed here to be resolved.
#[derive(Debug, Clone, Copy, Default)]
pub struct Paging {
    limit: Option<u32>,
    offset: Option<u64>,
}

impl Paging {
    /// Build from the raw query fields.
    const fn from_parts(limit: Option<u32>, offset: Option<u64>) -> Self {
        Self { limit, offset }
    }

    /// Resolve to a storage page, clamping rather than rejecting.
    ///
    /// A client asking for more than the cap gets the cap. Erroring would make the natural "give me
    /// everything" request fail rather than work in pages, and the cap is a server-side resource
    /// decision the client has no way to know.
    fn into_page(self) -> Page {
        let limit = self
            .limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        Page::new(limit, self.offset.unwrap_or(0))
    }
}

// -------------------------------------------------------------------------------------------------
// Health
// -------------------------------------------------------------------------------------------------

/// What `/health` returns.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Always `"ok"` — reaching the handler is the check.
    pub status: &'static str,
    /// The server's version.
    pub version: &'static str,
}

/// Liveness: is the process answering.
///
/// Deliberately does not touch the store. A liveness probe that fails when the database is busy
/// causes an orchestrator to restart a process that was working, which is how a slow query becomes
/// an outage.
pub async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// What `/ready` returns.
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// `"ready"` when the store answered.
    pub status: &'static str,
    /// The store's schema version.
    pub schema_version: u32,
    /// How many entities are stored.
    pub entities: u64,
}

/// Readiness: can the process actually serve a request.
///
/// This one does touch the store, because that is the difference between the two probes. A server
/// that is listening but whose store has not migrated should not receive traffic.
/// # Errors
///
/// Returns [`ApiError::Internal`] if the store cannot be read.
pub async fn ready<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
) -> Result<Json<Readiness>, ApiError> {
    let request_id = RequestId::generate();
    let schema_version = state
        .read(StoreRead::schema_version)
        .map_err(|error| from_read_failure(&error, &request_id))?;
    let entities = state
        .read(|store| store.count(RecordKind::Entity))
        .map_err(|error| from_read_failure(&error, &request_id))?;

    Ok(Json(Readiness {
        status: "ready",
        schema_version,
        entities,
    }))
}

// -------------------------------------------------------------------------------------------------
// Entities
// -------------------------------------------------------------------------------------------------

/// `?kind=&status=&current=` on the search route.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EntityFilter {
    kind: Option<String>,
    status: Option<String>,
    current: Option<bool>,
    limit: Option<u32>,
    offset: Option<u64>,
}

impl EntityFilter {
    fn paging(&self) -> Paging {
        Paging::from_parts(self.limit, self.offset)
    }
}

/// Search entities.
///
/// The route Kelpie and Tawny reach for: "what do you know that matches this".
/// # Errors
///
/// Returns [`ApiError::BadRequest`] for an unknown filter value, or
/// [`ApiError::Internal`] if the store cannot be read.
pub async fn search_entities<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
    Query(filter): Query<EntityFilter>,
) -> Result<Json<Envelope<Vec<Entity>>>, ApiError> {
    let request_id = RequestId::generate();
    let mut query = EntityQuery::unfiltered();

    if let Some(kind) = filter.kind.as_deref() {
        query = query.with_kind(parse_entity_kind(kind)?);
    }
    if let Some(status) = filter.status.as_deref() {
        query = query.with_status(parse_status(status)?);
    }
    if filter.current.unwrap_or(false) {
        query = query.only_current();
    }

    let page = filter.paging().into_page();
    let found = state
        .read(|store| store.search_entities(&query, page))
        .map_err(|error| from_read_failure(&error, &request_id))?;

    let returned = found.len();
    Ok(Json(Envelope::paged(found, returned, page)))
}

/// Fetch one entity by id.
/// # Errors
///
/// Returns [`ApiError::BadRequest`] for a malformed id, [`ApiError::NotFound`] if no such
/// entity is stored, or [`ApiError::Internal`] if the store cannot be read.
pub async fn get_entity<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
    Path(id): Path<String>,
) -> Result<Json<Envelope<Entity>>, ApiError> {
    let request_id = RequestId::generate();
    let parsed = brolga_model::id::Id::parse(&id).map_err(|_| ApiError::BadRequest {
        message: "not a well-formed entity id".to_owned(),
    })?;

    state
        .read(|store| store.get_entity(parsed))
        .map_err(|error| from_read_failure(&error, &request_id))?
        .map(|entity| Json(Envelope::new(entity)))
        .ok_or(ApiError::NotFound { kind: "entity", id })
}

/// `?direction=&kind=` on the neighbours route.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NeighbourFilter {
    direction: Option<String>,
    limit: Option<u32>,
    offset: Option<u64>,
}

impl NeighbourFilter {
    fn paging(&self) -> Paging {
        Paging::from_parts(self.limit, self.offset)
    }
}

/// The relationships at one entity.
///
/// The expansion step: a consumer that matched an indicator asks what it is connected to.
/// # Errors
///
/// Returns [`ApiError::BadRequest`] for a malformed id or unknown direction,
/// [`ApiError::NotFound`] if no such entity is stored — which is a different answer from an
/// entity with no edges — or [`ApiError::Internal`] if the store cannot be read.
pub async fn entity_neighbours<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
    Path(id): Path<String>,
    Query(filter): Query<NeighbourFilter>,
) -> Result<Json<Envelope<Vec<Relationship>>>, ApiError> {
    let request_id = RequestId::generate();
    let parsed = brolga_model::id::Id::parse(&id).map_err(|_| ApiError::BadRequest {
        message: "not a well-formed entity id".to_owned(),
    })?;

    // Asking about an entity that does not exist is a different answer from an entity with no
    // edges, and a consumer deciding whether to create a case needs to tell them apart.
    let exists = state
        .read(|store| store.get_entity(parsed))
        .map_err(|error| from_read_failure(&error, &request_id))?
        .is_some();
    if !exists {
        return Err(ApiError::NotFound { kind: "entity", id });
    }

    let direction = match filter.direction.as_deref() {
        None | Some("both") | Some("either") => Direction::Either,
        Some("outgoing") => Direction::Outgoing,
        Some("incoming") => Direction::Incoming,
        Some(other) => {
            return Err(ApiError::BadRequest {
                message: format!(
                    "unknown direction {other:?}; expected outgoing, incoming, or both"
                ),
            });
        }
    };

    let page = filter.paging().into_page();
    let query = EdgeQuery::at(NodeRef::Entity(parsed), direction);
    let edges = state
        .read(|store| store.edges_at(&query, page))
        .map_err(|error| from_read_failure(&error, &request_id))?;

    let returned = edges.len();
    Ok(Json(Envelope::paged(edges, returned, page)))
}

// -------------------------------------------------------------------------------------------------
// Stats
// -------------------------------------------------------------------------------------------------

/// What `/stats` returns.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    /// The store's schema version.
    pub schema_version: u32,
    /// Entities held.
    pub entities: u64,
    /// Relationships held.
    pub relationships: u64,
    /// Claims held.
    pub claims: u64,
    /// Sightings held.
    pub sightings: u64,
    /// Retained source objects.
    pub sources: u64,
    /// Records held back for review.
    pub quarantined: u64,
}

/// Counts, for a consumer deciding whether this Brolga is worth querying.
/// # Errors
///
/// Returns [`ApiError::Internal`] if the store cannot be read.
pub async fn stats<S: StoreRead>(
    State(state): State<Arc<ApiState<S>>>,
) -> Result<Json<Envelope<Stats>>, ApiError> {
    let request_id = RequestId::generate();

    // One lock acquisition for the whole set, so the counts describe a single moment rather than
    // six. A relationship count from after an ingest paired with an entity count from before it
    // would report a graph that never existed.
    let stats = state
        .read(|store| {
            Ok(Stats {
                schema_version: store.schema_version()?,
                entities: store.count(RecordKind::Entity)?,
                relationships: store.count(RecordKind::Relationship)?,
                claims: store.count(RecordKind::Claim)?,
                sightings: store.count(RecordKind::Sighting)?,
                sources: store.source_blob_count()?,
                quarantined: store.quarantine_count()?,
            })
        })
        .map_err(|error| from_read_failure(&error, &request_id))?;

    Ok(Json(Envelope::new(stats)))
}

// -------------------------------------------------------------------------------------------------
// Parsing
// -------------------------------------------------------------------------------------------------

/// Parse an entity kind, listing the alternatives when it does not match.
///
/// The list comes from [`EntityKind::all`], so a new variant appears in the message without anyone
/// remembering to add it.
fn parse_entity_kind(value: &str) -> Result<EntityKind, ApiError> {
    EntityKind::all()
        .iter()
        .find(|kind| kind.as_str() == value)
        .copied()
        .ok_or_else(|| ApiError::BadRequest {
            message: format!(
                "unknown kind {value:?}; expected one of: {}",
                EntityKind::all()
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
}

/// Parse a lifecycle status, listing the alternatives when it does not match.
fn parse_status(value: &str) -> Result<LifecycleStatus, ApiError> {
    LifecycleStatus::all()
        .iter()
        .find(|status| status.as_str() == value)
        .copied()
        .ok_or_else(|| ApiError::BadRequest {
            message: format!(
                "unknown status {value:?}; expected one of: {}",
                LifecycleStatus::all()
                    .iter()
                    .map(|status| status.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
}

/// Anything not routed.
///
/// Answers in the same envelope as every other failure. A bare 404 from the framework would be the
/// one response a client could not parse with the code it uses for everything else.
pub async fn not_found() -> Response {
    ApiError::NotFound {
        kind: "route",
        id: "unknown".to_owned(),
    }
    .into_response()
}

/// `GET /api/v1/openapi.json`.
///
/// Served rather than shipped as a file, so a consumer generating a client is generating against
/// the build it is actually talking to. A checked-in document is a document that can be stale, and
/// the failure mode is a client that compiles and then breaks on a field.
pub async fn openapi() -> Json<serde_json::Value> {
    Json(crate::openapi::document())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn paging_defaults_to_a_bounded_page() {
        let page = Paging::default().into_page();
        assert_eq!(page.limit(), DEFAULT_PAGE_SIZE);
        assert_eq!(page.offset(), 0);
    }

    /// An enormous limit is clamped, not refused. "Give me everything" should work in pages rather
    /// than fail, and the cap is a server-side decision the client cannot know.
    #[test]
    fn an_oversized_limit_is_clamped_to_the_cap() {
        let paging = Paging {
            limit: Some(u32::MAX),
            offset: None,
        };
        assert_eq!(paging.into_page().limit(), MAX_PAGE_SIZE);
    }

    /// Zero would be read by the store as "no rows", turning a paging mistake into an empty answer
    /// that looks like an empty database.
    #[test]
    fn a_zero_limit_becomes_one_rather_than_none() {
        let paging = Paging {
            limit: Some(0),
            offset: None,
        };
        assert_eq!(paging.into_page().limit(), 1);
    }

    /// A full page means "there may be more". A short page is the end.
    #[test]
    fn a_cursor_appears_only_when_the_page_was_full() {
        let page = Page::new(10, 0);

        let full = Envelope::paged(vec![0_u8; 10], 10, page);
        assert_eq!(full.next_offset, Some(10));

        let short = Envelope::paged(vec![0_u8; 3], 3, page);
        assert_eq!(short.next_offset, None);

        let empty = Envelope::paged(Vec::<u8>::new(), 0, page);
        assert_eq!(empty.next_offset, None);
    }

    #[test]
    fn the_cursor_continues_from_the_current_offset() {
        let page = Page::new(10, 40);
        assert_eq!(
            Envelope::paged(vec![0_u8; 10], 10, page).next_offset,
            Some(50)
        );
    }

    #[test]
    fn a_known_kind_parses_and_an_unknown_one_lists_the_alternatives() {
        assert_eq!(
            parse_entity_kind("intrusion_set").unwrap(),
            EntityKind::IntrusionSet
        );

        let error = parse_entity_kind("intrusion-set").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("intrusion_set"), "{message}");
    }

    #[test]
    fn a_known_status_parses_and_an_unknown_one_lists_the_alternatives() {
        assert_eq!(parse_status("active").unwrap(), LifecycleStatus::Active);
        let message = parse_status("alive").unwrap_err().to_string();
        assert!(message.contains("active"), "{message}");
    }

    /// The error message is built from the model's own list, so a new variant cannot be missing
    /// from it.
    #[test]
    fn the_alternatives_come_from_the_model_rather_than_a_copy() {
        let message = parse_entity_kind("nope").unwrap_err().to_string();
        for kind in EntityKind::all() {
            assert!(message.contains(kind.as_str()), "{} missing", kind.as_str());
        }
    }
}
