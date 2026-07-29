//! Building a context pack, once, for every interface.
//!
//! # Why this is not in the HTTP layer
//!
//! A pack served over HTTP, produced by the CLI, and returned over MCP must be the *same pack*. The
//! moment assembly lives inside one interface, the second interface either depends on that
//! interface — a CLI pulling in a web framework to produce a JSON document — or reimplements it,
//! and two implementations of "what does Brolga know about this?" will diverge in ways nobody
//! notices until they disagree in front of an analyst.
//!
//! So assembly lives here, above storage and beside ranking, and every interface calls it.
//!
//! # Policy is applied before anything is summarised
//!
//! Records are withheld before a single string is built. Filtering after formatting is how a
//! redaction misses a copy — a value that reached a summary, a log line, or a fingerprint is out,
//! whatever the final serialisation says.

use brolga_config::{Capability, PolicyIdentity, partition};
use brolga_model::pack::{
    Budget, BudgetReport, ClaimSummary, ContextPack, DetailLevel, EvidenceRef, Exclusion,
    ExclusionReason, ExpansionHandle, Finding, Gap, PackGraph, PackMetadata, PackSubject,
    PolicyContext, RelationshipSummary, SightingSummary,
};
use brolga_model::{
    Assertion, Claim, Disposition, MarkingSet, NodeRef, Observable, Relationship, SchemaTag,
    ShortText, Sighting, Timestamp, UntrustedText,
};

/// What the caller asked for.
#[derive(Debug, Clone)]
pub struct AssemblyRequest {
    /// The subject, already canonicalised.
    pub observable: Observable,
    /// The detail level to serve.
    pub detail_level: DetailLevel,
    /// The purpose the caller declared.
    pub purpose: Option<String>,
    /// Who is asking.
    pub identity: PolicyIdentity,
    /// How many records to gather.
    pub max_objects: u64,
    /// How many edges to gather.
    pub max_relationships: u64,
    /// When the pack is being built.
    pub now: Timestamp,
    /// The graph version it is built against.
    pub graph_version: u64,
    /// The request identifier, for correlating with a log.
    pub request_id: Option<String>,
}

/// Everything read from the store, before any policy or formatting is applied.
#[derive(Debug, Clone, Default)]
pub struct Gathered {
    /// Claims about the subject.
    pub claims: Vec<Claim>,
    /// Edges at it.
    pub edges: Vec<Relationship>,
    /// Observations of it.
    pub sightings: Vec<Sighting>,
    /// Entities at the far end of those edges.
    pub entities: Vec<brolga_model::Entity>,
}

/// Build a pack.
///
/// # Errors
///
/// Returns the reason a pack could not be assembled — which is always a violation of the pack's own
/// contract, since the inputs have already been read successfully. A half-built pack is not served.
pub fn build(request: &AssemblyRequest, gathered: &Gathered) -> Result<ContextPack, String> {
    // Withheld first. See the module documentation for why this cannot happen later.
    let (allowed_claims, claim_denials) = partition(
        &request.identity,
        &gathered.claims,
        Capability::Read,
        |claim| &claim.markings,
    );
    let (allowed_edges, edge_denials) = partition(
        &request.identity,
        &gathered.edges,
        Capability::Read,
        |edge| &edge.markings,
    );

    let claims: Vec<&Claim> = allowed_claims;
    let edges: Vec<&Relationship> = allowed_edges;
    let withheld = claim_denials.len().saturating_add(edge_denials.len());

    let mut evidence: Vec<EvidenceRef> = Vec::new();
    for claim in &claims {
        for source in claim.origin.source_objects() {
            let reference = EvidenceRef::new(source.to_string());
            if !evidence.contains(&reference) {
                evidence.push(reference);
            }
        }
    }
    evidence.sort_by(|left, right| left.source_object_id.cmp(&right.source_object_id));

    let disposition = disposition_of(&claims);

    let mut gaps = Vec::new();
    if claims.is_empty() && edges.is_empty() {
        gaps.extend(gap("store", "nothing is stored about this observable"));
    }
    if gathered.sightings.is_empty() {
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
    if u64::try_from(claims.len()).unwrap_or(u64::MAX) >= request.max_objects {
        exhausted = true;
        exclusions.extend(exclusion("claims", ExclusionReason::BudgetExhausted));
    }
    if u64::try_from(edges.len()).unwrap_or(u64::MAX) >= request.max_relationships {
        exhausted = true;
        exclusions.extend(exclusion("relationships", ExclusionReason::BudgetExhausted));
    }

    // A summary level carries no graph at all beyond its findings. Serving one that did would break
    // the contract `DetailLevel` makes, and the pack would refuse to validate — better to build the
    // right thing than to build the wrong one and be caught.
    let graph = if request.detail_level == DetailLevel::L0 {
        exclusions.extend(exclusion("graph", ExclusionReason::BelowDetailLevel));
        PackGraph::default()
    } else {
        PackGraph {
            entities: gathered
                .entities
                .iter()
                .filter_map(summarise_entity)
                .collect(),
            claims: claims
                .iter()
                .filter_map(|claim| summarise_claim(claim, &evidence))
                .collect(),
            relationships: edges
                .iter()
                .filter_map(|edge| summarise_edge(edge))
                .collect(),
            sightings: gathered
                .sightings
                .iter()
                .filter_map(summarise_sighting)
                .collect(),
            ..PackGraph::default()
        }
    };

    // A handle per claim, at every level. The point of a summary is that it does not *carry*
    // records, not that it hides where they are.
    let issued = request.now.to_rfc3339();
    let handles: Vec<ExpansionHandle> = claims
        .iter()
        .filter_map(|claim| {
            Some(ExpansionHandle::new(
                claim.id.to_string(),
                ShortText::new("claim").ok()?,
                DetailLevel::L5,
                request.graph_version,
                issued.clone(),
            ))
        })
        .collect();

    let findings = disposition_finding(disposition, &evidence)
        .into_iter()
        .collect();

    ContextPack {
        schema_version: SchemaTag::new(),
        fingerprint: String::new(),
        subject: PackSubject {
            kind: ShortText::new(request.observable.kind().as_str())
                .map_err(|error| error.to_string())?,
            value: ShortText::new(bounded(&request.observable.canonical_value()))
                .map_err(|error| error.to_string())?,
            observable_id: request.observable.id().to_string(),
        },
        purpose: request
            .purpose
            .as_deref()
            .and_then(|purpose| ShortText::new(purpose).ok()),
        detail_level: request.detail_level,
        disposition,
        graph,
        handles,
        findings,
        recommendations: Vec::new(),
        gaps,
        exclusions,
        budget: BudgetReport {
            requested: Budget {
                objects: Some(request.max_objects),
                relationships: Some(request.max_relationships),
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
            recipient: ShortText::new(&request.identity.name).ok(),
            markings: pack_markings(&claims, &edges),
            restricted: withheld > 0,
        },
        metadata: PackMetadata {
            generated_at: issued,
            request_id: request.request_id.clone(),
            build_duration_ms: None,
            brolga_version: env!("CARGO_PKG_VERSION").to_owned(),
            graph_version: request.graph_version,
        },
    }
    .validated()
    .map_err(|error| error.to_string())
}

/// The strongest currently standing disposition.
///
/// Biased toward `unknown`: a consumer acting on this is deciding whether to raise a case, and
/// inferring `benign` from an absence of evidence turns "Brolga has not heard of this" into "Brolga
/// says this is fine" — the more expensive of the two mistakes.
fn disposition_of(claims: &[&Claim]) -> Disposition {
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

/// How strongly a disposition carries when several disagree.
///
/// `allow_listed` outranks `benign` because it is a decision about how Brolga treats the subject
/// rather than a finding about it, and a decision should not be silently overridden by a feed.
const fn severity(disposition: Disposition) -> u8 {
    match disposition {
        Disposition::Malicious => 5,
        Disposition::Suspicious => 4,
        Disposition::AllowListed => 3,
        Disposition::Benign => 2,
        Disposition::Unknown => 1,
        _ => 0,
    }
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
fn pack_markings(claims: &[&Claim], edges: &[&Relationship]) -> MarkingSet {
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

fn summarise_entity(entity: &brolga_model::Entity) -> Option<brolga_model::pack::EntitySummary> {
    Some(brolga_model::pack::EntitySummary {
        id: entity.id.to_string(),
        kind: ShortText::new(entity.kind.as_str()).ok()?,
        name: entity.name.clone(),
        status: ShortText::new(entity.status.as_str()).ok()?,
    })
}

fn summarise_claim(claim: &Claim, evidence: &[EvidenceRef]) -> Option<ClaimSummary> {
    let (predicate, object) = match &claim.assertion {
        Assertion::Disposition(disposition) => {
            ("disposition".to_owned(), disposition.as_str().to_owned())
        }
        Assertion::Attribute { name, value } => {
            (name.as_str().to_owned(), value.as_str().to_owned())
        }
        Assertion::Narrative(text) => ("narrative".to_owned(), text.as_str().to_owned()),
        // `Assertion` is `#[non_exhaustive]`. A shape added upstream is surfaced as unrecognised
        // rather than dropped: a consumer seeing "there is a claim here I cannot read" can go and
        // look, where a silently missing claim leaves no trace.
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
        evidence: if own.is_empty() {
            evidence.to_vec()
        } else {
            own
        },
    })
}

fn summarise_edge(edge: &Relationship) -> Option<RelationshipSummary> {
    Some(RelationshipSummary {
        kind: ShortText::new(edge.kind.as_str()).ok()?,
        source: edge.source.to_string(),
        target: edge.target.to_string(),
        status: ShortText::new(edge.status.as_str()).ok()?,
    })
}

fn summarise_sighting(sighting: &Sighting) -> Option<SightingSummary> {
    Some(SightingSummary {
        count: sighting.count.get(),
        first_seen: sighting.first_seen.to_rfc3339(),
        last_seen: sighting.last_seen.to_rfc3339(),
        observer: sighting.observer.map(|id| id.to_string()),
    })
}

/// A gap from compile-time literals.
///
/// `Option` rather than a fallback. A fabricated placeholder gap is worse than no gap: a gap is a
/// statement about what Brolga does not know, and an invented one is a false statement about that.
fn gap(subject: &'static str, detail: &'static str) -> Option<Gap> {
    Some(Gap {
        subject: ShortText::new(subject).ok()?,
        detail: UntrustedText::new(detail).ok()?,
    })
}

fn exclusion(category: &'static str, reason: ExclusionReason) -> Option<Exclusion> {
    Some(Exclusion {
        category: ShortText::new(category).ok()?,
        reason,
        dropped: None,
    })
}

/// Truncate to what `ShortText` accepts, at a character boundary.
fn bounded(value: &str) -> String {
    if value.len() <= ShortText::MAX_BYTES {
        return value.to_owned();
    }
    let mut end = ShortText::MAX_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// The node a subject observable addresses.
#[must_use]
pub fn subject_node(observable: &Observable) -> NodeRef {
    NodeRef::Observable(observable.id())
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
    use brolga_model::provenance::{RecordOrigin, SyntheticOrigin, SyntheticReason};
    use brolga_model::{Marking, TlpLevel};

    fn origin() -> RecordOrigin {
        RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::Fixture,
            ShortText::new("assemble-tests").unwrap(),
        ))
    }

    fn observable() -> Observable {
        Observable::Ipv4Address("203.0.113.42".parse().unwrap())
    }

    fn claim(disposition: Disposition, markings: MarkingSet) -> Claim {
        let mut claim = Claim::new(
            subject_node(&observable()),
            Assertion::Disposition(disposition),
            origin(),
        );
        claim.markings = markings;
        claim
    }

    fn request(identity: PolicyIdentity) -> AssemblyRequest {
        AssemblyRequest {
            observable: observable(),
            detail_level: DetailLevel::L1,
            purpose: Some("triage".to_owned()),
            identity,
            max_objects: 100,
            max_relationships: 100,
            now: Timestamp::unix_epoch(),
            graph_version: 7,
            request_id: Some("req-1".to_owned()),
        }
    }

    fn red() -> MarkingSet {
        let mut set = MarkingSet::empty();
        set.insert(Marking::Tlp(TlpLevel::Red));
        set
    }

    /// One assembly for every interface. A CLI and an HTTP handler producing different packs from
    /// one store is the divergence this module exists to prevent.
    #[test]
    fn an_empty_store_produces_a_valid_pack_that_says_it_knows_nothing() {
        let pack = build(
            &request(PolicyIdentity::local_operator()),
            &Gathered::default(),
        )
        .unwrap();

        assert_eq!(pack.disposition, Disposition::Unknown);
        assert!(pack.findings.is_empty(), "no evidence, so no finding");
        assert!(
            pack.gaps
                .iter()
                .any(|gap| gap.detail.as_str().contains("nothing is stored")),
            "{:?}",
            pack.gaps
        );
        assert!(!pack.fingerprint.is_empty());
    }

    /// **The policy property, at the assembly layer.** A record withheld here never reaches a
    /// summary, a log line, or the fingerprint.
    #[test]
    fn restricted_records_never_reach_the_summary_or_the_fingerprint() {
        let gathered = Gathered {
            claims: vec![claim(Disposition::Malicious, red())],
            ..Gathered::default()
        };

        let withheld = build(&request(PolicyIdentity::anonymous()), &gathered).unwrap();

        assert!(
            withheld.graph.claims.is_empty(),
            "the claim reached a summary"
        );
        assert_eq!(withheld.disposition, Disposition::Unknown);
        assert!(withheld.policy.restricted);
        assert!(
            withheld
                .exclusions
                .iter()
                .any(|exclusion| exclusion.reason == ExclusionReason::PolicyRestricted)
        );

        // The same store, to somebody cleared for it.
        let served = build(&request(PolicyIdentity::local_operator()), &gathered).unwrap();
        assert_eq!(served.disposition, Disposition::Malicious);
        assert!(!served.policy.restricted);

        // And the two are genuinely different answers, which the fingerprint reflects.
        assert_ne!(withheld.fingerprint, served.fingerprint);
    }

    /// Inferring `benign` from an absence of evidence turns "Brolga has not heard of this" into
    /// "Brolga says this is fine" — the more expensive of the two mistakes.
    #[test]
    fn an_absence_of_evidence_is_unknown_rather_than_benign() {
        let pack = build(
            &request(PolicyIdentity::local_operator()),
            &Gathered::default(),
        )
        .unwrap();
        assert_eq!(pack.disposition, Disposition::Unknown);
        assert_ne!(pack.disposition, Disposition::Benign);
    }

    /// A withdrawn claim must not drive a disposition. A retracted finding that still does is a
    /// retraction that did not happen.
    #[test]
    fn a_withdrawn_claim_does_not_drive_the_disposition() {
        let mut withdrawn = claim(Disposition::Malicious, MarkingSet::empty());
        withdrawn.status = brolga_model::LifecycleStatus::Revoked;

        let pack = build(
            &request(PolicyIdentity::local_operator()),
            &Gathered {
                claims: vec![withdrawn],
                ..Gathered::default()
            },
        )
        .unwrap();

        assert_eq!(pack.disposition, Disposition::Unknown);
        assert!(
            pack.gaps
                .iter()
                .any(|gap| gap.detail.as_str().contains("withdrawn")),
            "{:?}",
            pack.gaps
        );
    }

    /// `L0` is the disposition and its evidence, and nothing else — the contract, honoured by
    /// building the right thing rather than by being caught in validation.
    #[test]
    fn l0_carries_no_graph_and_says_why() {
        let gathered = Gathered {
            claims: vec![claim(Disposition::Malicious, MarkingSet::empty())],
            ..Gathered::default()
        };

        let mut request = request(PolicyIdentity::local_operator());
        request.detail_level = DetailLevel::L0;
        let pack = build(&request, &gathered).unwrap();

        assert!(pack.graph.claims.is_empty());
        assert!(
            pack.exclusions
                .iter()
                .any(|exclusion| exclusion.reason == ExclusionReason::BelowDetailLevel)
        );
        // But the disposition and its handles survive: a summary hides records, not where they are.
        assert_eq!(pack.disposition, Disposition::Malicious);
        assert_eq!(pack.handles.len(), 1);
    }

    /// A decision about how Brolga treats a subject should not be silently overridden by a feed.
    #[test]
    fn an_allow_listing_outranks_a_benign_finding() {
        let gathered = Gathered {
            claims: vec![
                claim(Disposition::Benign, MarkingSet::empty()),
                claim(Disposition::AllowListed, MarkingSet::empty()),
            ],
            ..Gathered::default()
        };
        let pack = build(&request(PolicyIdentity::local_operator()), &gathered).unwrap();
        assert_eq!(pack.disposition, Disposition::AllowListed);
    }

    /// The same inputs must produce the same pack, or nothing downstream can cache or diff one.
    #[test]
    fn assembly_is_deterministic() {
        let gathered = Gathered {
            claims: vec![claim(Disposition::Malicious, MarkingSet::empty())],
            ..Gathered::default()
        };

        let first = build(&request(PolicyIdentity::local_operator()), &gathered).unwrap();
        let second = build(&request(PolicyIdentity::local_operator()), &gathered).unwrap();
        assert_eq!(first.fingerprint, second.fingerprint);
    }
}
