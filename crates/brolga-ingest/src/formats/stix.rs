//! STIX 2.1 bundles, SCOs, SROs, and MITRE ATT&CK data.
//!
//! # What this maps, and what it refuses to guess
//!
//! STIX is a wire format. Brolga's canonical model is not, and the difference is the point: a STIX
//! `indicator` with a pattern is not the same shape as a canonical claim, and pretending it is
//! loses either the pattern or the claim. So the mapping is explicit and narrow, and anything it
//! does not understand is **quarantined with a reason** rather than coerced into the nearest type.
//!
//! - **SDOs** — `threat-actor`, `malware`, `tool`, `campaign`, `intrusion-set`, `vulnerability`,
//!   `attack-pattern`, `identity`, `infrastructure` — become entities. `course-of-action` does
//!   **not**: it is a mitigation, and there is no canonical entity kind that means one. It is
//!   quarantined rather than filed under the nearest kind, which is the same rule every other
//!   unmapped type gets.
//! - **SCOs** — `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` — are
//!   canonicalised through [`crate::canon`] and become claims about the observable, because the
//!   canonical model addresses an observable by its value rather than storing it as a row of its
//!   own. A source publishing an SCO is asserting it saw the artefact, and that assertion is the
//!   thing worth keeping.
//! - **`indicator`** — the object STIX actually carries observables in. Its `pattern` is read by
//!   [`crate::formats::stix_pattern`], which maps `=` comparisons against supported object paths,
//!   `OR`-joined if there is more than one, and **refuses everything else by name**. Observables go
//!   through the same canonicalisers the MISP parser uses, so one address published by both feeds
//!   derives one identifier rather than landing in the graph twice. `indicator_types` becomes a
//!   [`Disposition`] only where it states an assessment; `valid_from` / `valid_until` become the
//!   claim's validity window; `name` and `description` are kept as evidence. A disjunction fans out
//!   to a claim per alternative **and** records how many there were, so the hedge the publisher
//!   made survives the fan-out rather than being paid silently.
//! - **SROs** — `relationship` — become relationships, with the STIX `relationship_type` mapped to
//!   a typed [`RelationshipKind`]. An unmapped type becomes `RelatedTo` **and a note**, never a
//!   silent guess at a stronger claim.
//! - **`marking-definition`** — TLP markings are resolved and propagate to every object that
//!   references them.
//!
//! # STIX 2.0 and 2.1 are one reader, and the differences are named
//!
//! 2.0 is not a dialect of 2.1 that can be read by ignoring a few fields — it puts the same
//! information in different places, and a reader that pretended otherwise would silently drop the
//! parts that moved:
//!
//! - **`labels` carried the vocabularies.** 2.1 split them into `indicator_types`,
//!   `malware_types`, and so on. An indicator's assessment lives in `labels` in 2.0, so a reader
//!   that only looked at `indicator_types` would map every 2.0 indicator with no disposition —
//!   present, and answering `unknown`.
//! - **Observables were not top-level.** 2.0 has no SCOs; a cyber observable exists only inside an
//!   `observed-data` object's `objects` dictionary. Ignoring `observed-data` would make a 2.0
//!   bundle of observations contribute nothing, which is [#95](https://github.com/jusso-dev/Brolga/issues/95)
//!   again in a different spelling.
//! - **`spec_version` moved.** In 2.0 it is on the bundle; in 2.1 it is on each object. The
//!   version is read from either, and an object may state its own.
//! - **`pattern_type` did not exist.** A 2.0 pattern is always STIX patterning, so its absence is
//!   not evidence of some other language.
//!
//! What is *not* done: no 2.0 object is rewritten into its 2.1 shape before mapping. Both versions
//! map directly onto the canonical model, because a 2.0-to-2.1 upgrade step would be a second
//! lossy translation whose losses nobody would see.
//!
//! # `revoked` and `modified` are not "delete"
//!
//! A revoked STIX object is not absent; it is an object whose publisher has said it should no longer
//! be relied on. Deleting it would lose the fact that it was published *and* the fact that it was
//! withdrawn, which together are more informative than either. Revoked objects become records with
//! [`LifecycleStatus::Revoked`], and `modified` is carried as the record's last-seen time so that a
//! later version of the same object is distinguishable from a re-import of the old one.
//!
//! # Bounds
//!
//! [#13](https://github.com/jusso-dev/Brolga/issues/13) requires object count, JSON depth, string
//! length, and relationship fan-out to be bounded. Depth is checked on a hand-written walk **before**
//! any mapping, because `serde_json`'s own recursion limit protects the parser's stack and says
//! nothing about ours. Fan-out is bounded per source object, because a bundle whose every object
//! relates to every other is quadratic and is a denial-of-service shape whether or not it was meant
//! as one.

use std::collections::BTreeMap;

use brolga_model::{
    Assertion, Claim, Disposition, Entity, EntityKind, Id, LifecycleStatus, Marking, MarkingSet,
    NodeRef, Observable, RecordOrigin, Relationship, RelationshipKind, ShortText, Sighting,
    SightingCount, TemporalState, Timestamp, TlpLevel, UntrustedText,
};
use serde_json::Value;

use crate::canon::{self, CanonError};
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::stix_pattern;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const STIX_PARSER_ID: ParserId = ParserId::new("brolga.stix.bundle");

/// Media types that identify a STIX bundle definitively.
pub const STIX_MEDIA_TYPES: &[&str] = &["application/stix+json", "application/vnd.oasis.stix+json"];

/// Largest relationship fan-out accepted from one source object.
///
/// A bundle whose every object relates to every other is quadratic. That is a denial-of-service
/// shape whether or not anybody meant it as one, and no legitimate bundle needs a single object to
/// have thousands of outbound edges.
pub const MAX_FAN_OUT: usize = 1024;

/// Largest `indicator_types` array accepted from one indicator.
///
/// The vocabulary has seven members and a real indicator carries one or two. An array of thousands
/// is a record-amplification shape — every entry becomes up to two claims — and is refused whole
/// rather than truncated, because a truncated list silently drops assessments the publisher made.
pub const MAX_INDICATOR_TYPES: usize = 16;

/// Most observables read from one `observed-data` object.
///
/// STIX 2.0 carries cyber observables inside this dictionary rather than as top-level objects, so
/// it is the one place a single object legitimately holds many. Each becomes a claim and a
/// sighting, which makes it the largest amplification surface in a bundle; over the bound the
/// object is refused whole rather than truncated.
pub const MAX_OBSERVED_OBJECTS: usize = 256;

/// A STIX 2.1 bundle reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct StixParser;

impl StixParser {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed, ready for [`crate::ParserRegistry::register`].
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self)
    }
}

impl IntelligenceParser for StixParser {
    fn id(&self) -> ParserId {
        STIX_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if STIX_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is STIX JSON",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        // `"type":"bundle"` is unique to STIX among the formats Brolga reads. Whitespace between
        // the tokens is legal JSON, so the check is over a whitespace-stripped copy of the prefix
        // rather than a literal substring — a bundle formatted by a pretty-printer is still a
        // bundle.
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("\"type\":\"bundle\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares `\"type\": \"bundle\"`",
            )
        } else if compact.contains("\"spec_version\":\"2.") {
            // Both 2.0 and 2.1. In 2.0 the field is on the bundle and in 2.1 it is on each object,
            // so matching the family rather than one spelling is what lets a bare 2.0 object be
            // recognised at all.
            candidate(
                self,
                DetectionConfidence::Strong,
                "declares a STIX 2.x spec_version",
            )
        } else if hint.has_extension("stix") {
            candidate(self, DetectionConfidence::Strong, "file extension is .stix")
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no STIX bundle marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;

        let document: Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not valid JSON: {error}")))?;

        // Our depth limit, not serde_json's. Its recursion limit protects its own stack; this one
        // is the configured bound, and it is checked before any mapping allocates.
        let depth = depth_of(&document);
        if depth > usize::try_from(limits.max_depth).unwrap_or(usize::MAX) {
            return Err(ParseError::new(format!(
                "JSON nests {depth} deep, over the {}-level limit",
                limits.max_depth
            )));
        }

        let objects = objects_of(&document)?;
        if u64::try_from(objects.len()).unwrap_or(u64::MAX) > limits.max_records {
            return Err(ParseError::new(format!(
                "bundle holds {} objects, over the {}-record limit",
                objects.len(),
                limits.max_records
            )));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;

        // Markings first: an object may reference a marking definition that appears after it, and
        // resolving forward references in one pass would make propagation depend on bundle order.
        let markings = collect_markings(&objects);

        // And the STIX id to canonical node map, for the same reason plus a sharper one. A STIX
        // relationship names its endpoints by STIX identifier; canonical entities key on
        // `(kind, name)`. Deriving an endpoint from the STIX id would produce an edge pointing at a
        // record that was never written — which storage now refuses as a dangling edge, and which
        // before that refusal would have made traversal silently return nothing.
        let nodes = collect_nodes(&objects);
        // And the top-level SCOs by identifier, because a 2.1 `observed-data` names its artefacts
        // by reference. The node map holds identifiers, and a sighting needs the observable itself.
        let scos = collect_scos(&objects);

        let mut out = ParseOutput::default();
        let mut fan_out: BTreeMap<String, usize> = BTreeMap::new();

        for (index, object) in objects.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_object(
                object,
                &origin,
                &markings,
                &nodes,
                &scos,
                &mut fan_out,
                &limits,
            ) {
                Ok(records) => out.records.extend(records),
                Err(rejection) => out.rejected.push(rejection.into_rejected(index)),
            }
        }

        // One object no longer means one record — an indicator produces a claim per assessment it
        // states — so the produced count is bounded as well as the object count. Without this, the
        // object limit would stop bounding what a bundle can make Brolga hold.
        let produced = u64::try_from(out.records.len()).unwrap_or(u64::MAX);
        if produced > limits.max_records {
            return Err(ParseError::new(format!(
                "produced {produced} records, over the {}-record limit",
                limits.max_records
            )));
        }

        Ok(out)
    }
}

/// A mapping failure, before it is given its position in the bundle.
struct Rejection {
    reason_kind: &'static str,
    reason: String,
    fragment: String,
}

impl Rejection {
    fn new(reason_kind: &'static str, reason: impl Into<String>, fragment: &Value) -> Self {
        Self {
            reason_kind,
            reason: reason.into(),
            // The identifier and type only. The whole object could be megabytes, and quarantine
            // fragments are read by operators through terminals.
            fragment: describe(fragment),
        }
    }

    fn into_rejected(self, index: usize) -> RejectedRecord {
        RejectedRecord {
            reason_kind: self.reason_kind,
            reason: self.reason,
            offset: u64::try_from(index).ok(),
            fragment: Some(self.fragment),
        }
    }
}

/// A short, safe description of an object, for a diagnostic.
fn describe(object: &Value) -> String {
    let kind = object.get("type").and_then(Value::as_str).unwrap_or("?");
    let id = object.get("id").and_then(Value::as_str).unwrap_or("?");
    format!("{kind} {id}")
}

/// The objects of a bundle, or the single object if a bare STIX object was supplied.
fn objects_of(document: &Value) -> Result<Vec<Value>, ParseError> {
    match document.get("objects") {
        Some(Value::Array(objects)) => Ok(objects.clone()),
        Some(_) => Err(ParseError::new("`objects` is present but is not an array")),
        // A bare SDO is what an ATT&CK enterprise export's individual files look like, and refusing
        // it would mean the corpus has to be pre-wrapped before Brolga can read it.
        None if document.get("type").is_some() => Ok(vec![document.clone()]),
        None => Err(ParseError::new(
            "not a STIX bundle and not a STIX object: no `objects` array and no `type`",
        )),
    }
}

/// The deepest nesting in a JSON value.
///
/// Iterative rather than recursive, because a recursive depth check on hostile input is itself the
/// stack overflow it exists to prevent.
#[must_use]
pub fn depth_of(value: &Value) -> usize {
    let mut deepest = 0_usize;
    let mut stack = vec![(value, 1_usize)];
    while let Some((current, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        match current {
            Value::Array(items) => {
                for item in items {
                    stack.push((item, depth.saturating_add(1)));
                }
            }
            Value::Object(entries) => {
                for item in entries.values() {
                    stack.push((item, depth.saturating_add(1)));
                }
            }
            _ => {}
        }
    }
    deepest
}

/// Resolve every `marking-definition` in the bundle to a canonical marking.
fn collect_markings(objects: &[Value]) -> BTreeMap<String, Marking> {
    let mut markings = BTreeMap::new();
    for object in objects {
        if object.get("type").and_then(Value::as_str) != Some("marking-definition") {
            continue;
        }
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        if let Some(marking) = marking_of(object) {
            markings.insert(id.to_owned(), marking);
        }
    }
    markings
}

/// Read a marking definition, covering both the 2.1 `name` form and the older `definition` form.
fn marking_of(object: &Value) -> Option<Marking> {
    // STIX 2.1 moved TLP markings to statically-defined objects identified by name.
    if let Some(name) = object.get("name").and_then(Value::as_str)
        && let Some(level) = tlp_level(name)
    {
        return Some(Marking::Tlp(level));
    }
    if let Some(tlp) = object
        .get("definition")
        .and_then(|definition| definition.get("tlp"))
        .and_then(Value::as_str)
        && let Some(level) = tlp_level(tlp)
    {
        return Some(Marking::Tlp(level));
    }
    if let Some(statement) = object
        .get("definition")
        .and_then(|definition| definition.get("statement"))
        .and_then(Value::as_str)
        && let Ok(text) = ShortText::new(bounded(statement, ShortText::MAX_BYTES))
    {
        return Some(Marking::Attribution(text));
    }
    None
}

/// Map a TLP label, in any of the spellings feeds actually publish.
fn tlp_level(value: &str) -> Option<TlpLevel> {
    match value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "+")
        .as_str()
    {
        "tlp:clear" | "clear" | "tlp:white" | "white" => Some(TlpLevel::Clear),
        "tlp:green" | "green" => Some(TlpLevel::Green),
        "tlp:amber" | "amber" => Some(TlpLevel::Amber),
        "tlp:amber+strict" | "amber+strict" => Some(TlpLevel::AmberStrict),
        "tlp:red" | "red" => Some(TlpLevel::Red),
        _ => None,
    }
}

/// The markings an object carries, resolved through the bundle's marking definitions.
fn markings_for(object: &Value, definitions: &BTreeMap<String, Marking>) -> MarkingSet {
    let mut set = MarkingSet::empty();
    let Some(refs) = object.get("object_marking_refs").and_then(Value::as_array) else {
        return set;
    };
    for reference in refs {
        if let Some(id) = reference.as_str()
            && let Some(marking) = definitions.get(id)
        {
            set.insert(marking.clone());
        }
    }
    set
}

/// Map one STIX object to the records it becomes.
///
/// An empty vector for objects that are consumed rather than mapped, such as marking definitions.
/// More than one for an indicator, which states a pattern and may state several assessments of it.
fn map_object(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    nodes: &BTreeMap<String, Vec<NodeRef>>,
    scos: &BTreeMap<String, Observable>,
    fan_out: &mut BTreeMap<String, usize>,
    limits: &brolga_security::InputLimits,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::new("missing_type", "object has no `type`", object))?;

    match kind {
        // Consumed by collect_markings; not a record in its own right.
        "marking-definition" => Ok(Vec::new()),
        "relationship" => map_relationship(object, origin, markings, nodes, fan_out),
        "indicator" => map_indicator(object, origin, markings, limits),
        "observed-data" => map_observed_data(object, origin, markings, nodes, scos),
        "bundle" => Err(Rejection::new(
            "nested_bundle",
            "a bundle nested inside a bundle is not valid STIX 2.1",
            object,
        )),
        _ => {
            if let Some(entity_kind) = entity_kind_of(kind) {
                map_entity(object, entity_kind, origin, markings, limits).map(|record| vec![record])
            } else if is_observable_type(kind) {
                map_observable(object, kind, origin, markings).map(|record| vec![record])
            } else {
                Err(Rejection::new(
                    "unsupported_object_type",
                    format!(
                        "`{kind}` is a STIX type Brolga does not map yet; it is quarantined rather \
                         than coerced into the nearest canonical type"
                    ),
                    object,
                ))
            }
        }
    }
}

/// Which canonical entity kind a STIX SDO type becomes.
fn entity_kind_of(stix_type: &str) -> Option<EntityKind> {
    Some(match stix_type {
        "threat-actor" => EntityKind::ThreatActor,
        "malware" => EntityKind::MalwareFamily,
        "tool" => EntityKind::Tool,
        "campaign" => EntityKind::Campaign,
        "intrusion-set" => EntityKind::IntrusionSet,
        "vulnerability" => EntityKind::Vulnerability,
        "attack-pattern" => EntityKind::AttackTechnique,
        "identity" => EntityKind::Identity,
        "infrastructure" => EntityKind::Infrastructure,
        _ => return None,
    })
}

/// Whether a STIX type is one of the SCOs this parser canonicalises.
fn is_observable_type(stix_type: &str) -> bool {
    matches!(
        stix_type,
        "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" | "email-addr" | "file"
    )
}

/// Map an SDO to an entity.
fn map_entity(
    object: &Value,
    kind: EntityKind,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    limits: &brolga_security::InputLimits,
) -> Result<ParsedRecord, Rejection> {
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::new("missing_name", "SDO has no `name`", object))?;

    let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);
    let name_text = UntrustedText::new(bounded(name, field_limit.min(UntrustedText::MAX_BYTES)))
        .map_err(|error| {
            Rejection::new("unusable_name", format!("unusable `name`: {error}"), object)
        })?;

    // Identity is the canonical (kind, name) pair, not the STIX id. Two feeds publishing the same
    // actor under different STIX identifiers describe one actor, and keying on the STIX id would
    // make them two. The STIX id survives as an attribute below.
    let mut entity = Entity::new(
        entity_id_for(kind, name_text.as_str()),
        kind,
        name_text,
        origin.clone(),
    );

    entity.markings = markings_for(object, markings);

    if let Some(description) = object.get("description").and_then(Value::as_str)
        && let Ok(text) = UntrustedText::new(bounded(
            description,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
    {
        entity.description = Some(text);
    }

    for alias in object
        .get("aliases")
        .or_else(|| object.get("x_mitre_aliases"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if let Some(alias) = alias.as_str()
            && let Ok(text) = UntrustedText::new(bounded(alias, field_limit))
        {
            entity.aliases.push(text);
        }
    }

    // Revoked is not deleted. An object its publisher has withdrawn is more informative than an
    // absent one: it records both that they published it and that they took it back.
    if object.get("revoked").and_then(Value::as_bool) == Some(true) {
        entity.status = LifecycleStatus::Revoked;
    }

    Ok(ParsedRecord::Entity(Box::new(entity)))
}

/// Map an SCO to a claim about the canonicalised observable.
fn map_observable(
    object: &Value,
    stix_type: &str,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
) -> Result<ParsedRecord, Rejection> {
    let observable = observable_of(object, stix_type).map_err(|error| {
        Rejection::new("uncanonicalisable_observable", error.to_string(), object)
    })?;

    let name = ShortText::new(format!("stix.{stix_type}"))
        .map_err(|error| Rejection::new("unusable_attribute_name", error.to_string(), object))?;
    let value = UntrustedText::new(bounded(
        &observable.canonical_value(),
        UntrustedText::MAX_BYTES,
    ))
    .map_err(|error| Rejection::new("unusable_attribute_value", error.to_string(), object))?;

    // A source publishing an SCO is asserting it saw the artefact. The canonical model addresses an
    // observable by its value rather than storing it as a row, so the assertion is the record.
    let mut claim = Claim::new(
        NodeRef::Observable(observable.id()),
        Assertion::Attribute { name, value },
        origin.clone(),
    );
    claim.markings = markings_for(object, markings);
    Ok(ParsedRecord::Claim(Box::new(claim)))
}

/// Canonicalise an SCO's value through the shared canonicalisers.
fn observable_of(object: &Value, stix_type: &str) -> Result<Observable, CanonError> {
    let field = match stix_type {
        "ipv4-addr" | "ipv6-addr" | "domain-name" | "url" | "email-addr" => "value",
        "file" => "name",
        _ => "value",
    };
    let raw = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(CanonError::Empty { kind: "StixSco" })?;

    let canonical = match stix_type {
        "ipv4-addr" | "ipv6-addr" => canon::net::ip_address(raw)?,
        "domain-name" => canon::net::domain_name(raw)?,
        "url" => canon::net::url(raw)?,
        "email-addr" => canon::net::email_address(raw)?,
        "file" => {
            // A STIX file object carries hashes and a name. The digest is the stronger identifier,
            // so it wins when present; a name-only file object still keys on the name.
            if let Some(hashes) = object.get("hashes").and_then(Value::as_object)
                && let Some(digest) = hashes.values().find_map(Value::as_str)
                && let Ok(hash) = canon::file::file_hash(digest)
            {
                hash
            } else {
                canon::file::file_name(raw)?
            }
        }
        _ => {
            return Err(CanonError::malformed(
                "StixSco",
                raw,
                "unsupported SCO type",
            ));
        }
    };
    Ok(canonical.into_value())
}

/// Map an `indicator` to claims about the observables its pattern names.
///
/// This is where STIX carries observables, so a bundle of indicators that produced nothing was a
/// bundle a context lookup could not answer from — and an empty answer is indistinguishable from a
/// genuinely unknown observable, which is the dangerous half of that failure.
///
/// Emitted per observable the pattern names:
///
/// - the pattern itself, as an attribute claim, so the assertion is retrievable as published —
///   including its `OR` alternatives, which is what makes a fanned-out claim inspectable;
/// - `stix.indicator.alternatives`, but only when the pattern was a disjunction, so a consumer can
///   tell a lone assertion from one alternative out of fifty without re-parsing anything;
/// - the indicator's `name` and `description` where it has them, because a publisher's own words
///   about an indicator are evidence an analyst reads;
/// - each `indicator_types` label, as an attribute claim, so nothing the publisher said is lost;
/// - a [`Disposition`] claim for each label that actually *states an assessment* — presence in a
///   feed is not evidence of maliciousness, so a label like `anonymization` records what it says
///   and asserts no disposition at all.
///
/// A pattern this parser cannot represent whole is quarantined naming the construct. Extracting
/// part of it would assert something broader than the publisher did.
fn map_indicator(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    limits: &brolga_security::InputLimits,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let pattern = object
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Rejection::new(
                "missing_pattern",
                "indicator has no `pattern`, so it names no observable",
                object,
            )
        })?;

    // A Snort or YARA rule in an `indicator` is a detection Brolga has no canonical form for. Its
    // syntax also overlaps STIX patterning enough that reading it as one would silently produce
    // whatever the first `=` in the rule happened to sit beside.
    if let Some(language) = object.get("pattern_type").and_then(Value::as_str)
        && !language.eq_ignore_ascii_case(stix_pattern::STIX_PATTERN_TYPE)
    {
        return Err(Rejection::new(
            "unsupported_pattern_type",
            format!(
                "the pattern is written in `{language}` rather than STIX patterning; it is \
                 quarantined rather than read under a grammar it was not written in"
            ),
            object,
        ));
    }

    // `pattern_version` is the version of the *patterning language*, not of the object. A future
    // major version may give the same characters a different meaning, and reading it under the 2.x
    // grammar would produce a confident answer to a question that was not asked.
    if let Some(version) = object.get("pattern_version").and_then(Value::as_str)
        && !version.trim().starts_with('2')
    {
        return Err(Rejection::new(
            "unsupported_pattern_version",
            format!(
                "the pattern declares patterning version `{version}`; Brolga reads the 2.x \
                 grammar, and reading other versions under it would answer confidently about a \
                 syntax whose meaning it does not know"
            ),
            object,
        ));
    }

    let observables = stix_pattern::observables_of(pattern).map_err(|error| {
        Rejection::new(
            "unrepresentable_pattern",
            format!(
                "the indicator's pattern cannot be represented: {error}. The indicator is \
                 quarantined whole rather than partially extracted, because a half-parsed pattern \
                 silently widens what it asserted"
            ),
            object,
        )
    })?;

    let marking_set = markings_for(object, markings);
    let temporal = temporal_of(object)?;
    let revoked = object.get("revoked").and_then(Value::as_bool) == Some(true);
    let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

    // Built once, applied to every observable the pattern named. One list means every alternative
    // of a disjunction carries an identical set of assertions, which is the honest reading: the
    // publisher stated them about the disjunction, not about a chosen member of it.
    let mut assertions = vec![attribute(
        object,
        "stix.indicator.pattern",
        pattern,
        field_limit,
    )?];

    // Only for a disjunction. Writing `1` on every ordinary indicator would be noise on the
    // overwhelming majority of claims to carry information about a rare minority.
    if observables.len() > 1 {
        assertions.push(attribute(
            object,
            "stix.indicator.alternatives",
            &observables.len().to_string(),
            field_limit,
        )?);
    }

    for (field, name) in [
        ("name", "stix.indicator.name"),
        ("description", "stix.indicator.description"),
    ] {
        if let Some(text) = object.get(field).and_then(Value::as_str) {
            assertions.push(attribute(object, name, text, field_limit)?);
        }
    }

    // `labels` is where STIX 2.0 kept this vocabulary; 2.1 split it out into `indicator_types`.
    // Reading only the 2.1 spelling would map every 2.0 indicator with no disposition at all —
    // present in the graph, and answering `unknown` about something a publisher assessed.
    let indicator_types = object
        .get("indicator_types")
        .or_else(|| object.get("labels"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if indicator_types.len() > MAX_INDICATOR_TYPES {
        return Err(Rejection::new(
            "indicator_types_exceeded",
            format!(
                "the indicator states {} types, over the {MAX_INDICATOR_TYPES} limit; it is \
                 refused rather than truncated, because a truncated list drops assessments the \
                 publisher made",
                indicator_types.len()
            ),
            object,
        ));
    }

    for label in indicator_types {
        let Some(label) = label.as_str() else {
            return Err(Rejection::new(
                "non_string_indicator_type",
                "`indicator_types` holds a value that is not a string; the indicator is refused \
                 rather than read past, because skipping it would drop an assessment silently",
                object,
            ));
        };

        assertions.push(attribute(
            object,
            "stix.indicator_type",
            label,
            field_limit,
        )?);
        if let Some(disposition) = disposition_of(label) {
            assertions.push(Assertion::Disposition(disposition));
        }
    }

    let mut records = Vec::with_capacity(observables.len().saturating_mul(assertions.len()));
    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());
        for assertion in &assertions {
            let mut claim = Claim::new(subject, assertion.clone(), origin.clone());
            claim.markings = marking_set.clone();
            claim.temporal = temporal;
            if revoked {
                claim.status = LifecycleStatus::Revoked;
            }
            records.push(ParsedRecord::Claim(Box::new(claim)));
        }
    }

    Ok(records)
}

/// Map an `observed-data` object to sightings of the observables it holds.
///
/// This is where STIX 2.0 keeps cyber observables. There are no top-level SCOs in 2.0 at all — an
/// address exists only inside this object's `objects` dictionary — so a reader that skipped it
/// would make a 2.0 bundle of observations contribute nothing a lookup could find, which is the
/// same silent miss `indicator` had.
///
/// 2.1 replaced the dictionary with `object_refs` pointing at top-level SCOs. Both are read: the
/// embedded form directly, the reference form through the bundle's node map, so a 2.1 bundle's
/// observations become sightings too rather than only the claims its SCOs already produced.
///
/// `number_observed` becomes the sighting's count and `first_observed` / `last_observed` its
/// window — which is what makes this a *sighting* rather than another claim. A claim says somebody
/// asserted something; a sighting says how many times and when, and that is the difference
/// corroboration is computed from.
fn map_observed_data(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    nodes: &BTreeMap<String, Vec<NodeRef>>,
    scos: &BTreeMap<String, Observable>,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let first_observed = timestamp_field(object, "first_observed")?.ok_or_else(|| {
        Rejection::new(
            "missing_first_observed",
            "`observed-data` has no `first_observed`, so the observation has no window and cannot \
             be told apart from a re-import of the same one",
            object,
        )
    })?;
    let last_observed = timestamp_field(object, "last_observed")?.ok_or_else(|| {
        Rejection::new(
            "missing_last_observed",
            "`observed-data` has no `last_observed`, so the observation has no window",
            object,
        )
    })?;

    // Zero is not "unknown". A publisher who wrote `number_observed: 0` said something impossible,
    // and defaulting it to one would invent an observation.
    let raw_count = object
        .get("number_observed")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let count = SightingCount::new(raw_count).map_err(|error| {
        Rejection::new(
            "unusable_number_observed",
            format!("`number_observed` is not a usable count: {error}"),
            object,
        )
    })?;

    // Resolved through the bundle, never derived from the STIX id. An observer Brolga cannot
    // resolve is `None` — an unattributed sighting, which is a real and reportable state — rather
    // than a fabricated entity that would look like corroboration.
    let observer = object
        .get("created_by_ref")
        .and_then(Value::as_str)
        .and_then(|reference| nodes.get(reference))
        .and_then(|resolved| resolved.first())
        .and_then(|node| match node {
            NodeRef::Entity(id) => Some(*id),
            // An observer that resolved to an observable is not an observer. `NodeRef` is
            // `#[non_exhaustive]`, so a future variant falls here too — an unattributed sighting,
            // which is honest, rather than a guess at which new node kind counts as a witness.
            _ => None,
        });

    let observables = observed_observables(object, scos)?;
    let marking_set = markings_for(object, markings);
    let revoked = object.get("revoked").and_then(Value::as_bool) == Some(true);

    let mut records = Vec::with_capacity(observables.len().saturating_mul(2));
    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());

        let mut sighting = Sighting::new(
            subject,
            observer,
            count,
            first_observed,
            last_observed,
            origin.clone(),
        )
        .map_err(|error| {
            Rejection::new(
                "impossible_observation_window",
                format!("the observation window is impossible: {error}"),
                object,
            )
        })?;
        sighting.markings = marking_set.clone();
        if revoked {
            sighting.status = LifecycleStatus::Revoked;
        }
        records.push(ParsedRecord::Sighting(Box::new(sighting)));

        // And the assertion that the artefact was seen at all, so an observable from a 2.0 bundle
        // is reachable the same way one from a 2.1 SCO is. A lookup that found sightings but no
        // claims would report a disposition of `unknown` for something under active observation.
        let name = ShortText::new("stix.observed_data").map_err(|error| {
            Rejection::new("unusable_attribute_name", error.to_string(), object)
        })?;
        let value = UntrustedText::new(bounded(
            &observable.canonical_value(),
            UntrustedText::MAX_BYTES,
        ))
        .map_err(|error| Rejection::new("unusable_attribute_value", error.to_string(), object))?;

        let mut claim = Claim::new(
            subject,
            Assertion::Attribute { name, value },
            origin.clone(),
        );
        claim.markings = marking_set.clone();
        claim.temporal =
            TemporalState::observed(first_observed, last_observed).map_err(|error| {
                Rejection::new(
                    "impossible_observation_window",
                    format!("the observation window is impossible: {error}"),
                    object,
                )
            })?;
        if revoked {
            claim.status = LifecycleStatus::Revoked;
        }
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }

    Ok(records)
}

/// The observables an `observed-data` names, by either the 2.0 or the 2.1 spelling.
fn observed_observables(
    object: &Value,
    scos: &BTreeMap<String, Observable>,
) -> Result<Vec<Observable>, Rejection> {
    let mut observables = Vec::new();

    // STIX 2.0: an embedded dictionary keyed by an arbitrary index string. Iterated through the
    // map's own ordering, which `serde_json` keeps sorted, so two imports of one bundle produce the
    // same records in the same order.
    if let Some(embedded) = object.get("objects").and_then(Value::as_object) {
        if embedded.len() > MAX_OBSERVED_OBJECTS {
            return Err(Rejection::new(
                "observed_objects_exceeded",
                format!(
                    "`observed-data` holds {} objects, over the {MAX_OBSERVED_OBJECTS} limit; it \
                     is refused whole rather than truncated, because a truncated observation \
                     reports fewer artefacts than were seen",
                    embedded.len()
                ),
                object,
            ));
        }
        for value in embedded.values() {
            let Some(kind) = value.get("type").and_then(Value::as_str) else {
                continue;
            };
            // An embedded object of a type this parser does not canonicalise is skipped rather
            // than failing the observation: unlike a pattern, the dictionary is a *set* of
            // artefacts, and the ones Brolga understands are still true. What was skipped is
            // recorded below so the omission is not silent.
            if is_observable_type(kind)
                && let Ok(observable) = observable_of(value, kind)
            {
                observables.push(observable);
            }
        }
    }

    // STIX 2.1: references to top-level SCOs, resolved through the bundle rather than derived from
    // the identifier. A reference to an object that is not in the bundle names an artefact nobody
    // supplied, and inventing one from its id would record an observation of a value Brolga never
    // saw.
    for reference in object
        .get("object_refs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if let Some(id) = reference.as_str()
            && let Some(observable) = scos.get(id)
        {
            observables.push(observable.clone());
        }
    }

    // Two spellings can name one artefact — an embedded copy and a reference to the same SCO — and
    // that is one observation, not two.
    observables.dedup_by_key(|observable| observable.id());

    if observables.is_empty() {
        return Err(Rejection::new(
            "no_mappable_observable",
            "`observed-data` names no observable Brolga canonicalises, so it would record an \
             observation of nothing",
            object,
        ));
    }

    Ok(observables)
}

/// One attribute assertion, with the name and value each rejected by their own reason.
fn attribute(
    object: &Value,
    name: &str,
    value: &str,
    field_limit: usize,
) -> Result<Assertion, Rejection> {
    Ok(Assertion::Attribute {
        name: ShortText::new(name).map_err(|error| {
            Rejection::new("unusable_attribute_name", error.to_string(), object)
        })?,
        value: UntrustedText::new(bounded(value, field_limit.min(UntrustedText::MAX_BYTES)))
            .map_err(|error| {
                Rejection::new("unusable_attribute_value", error.to_string(), object)
            })?,
    })
}

/// Which [`Disposition`] an `indicator-type-ov` label asserts, if it asserts one at all.
///
/// The vocabulary mixes assessments with descriptions. `malicious-activity` and `benign` are
/// findings about the subject; `anonymization` says the address is a proxy or Tor exit and
/// `attribution` says it identifies an actor — neither is a statement about maliciousness, and
/// turning them into one would let a feed's taxonomy silently decide detection. Those labels are
/// still recorded as attribute claims by the caller, so nothing is lost by not asserting for them.
fn disposition_of(indicator_type: &str) -> Option<Disposition> {
    match indicator_type.trim().to_ascii_lowercase().as_str() {
        "malicious-activity" => Some(Disposition::Malicious),
        "benign" => Some(Disposition::Benign),
        "anomalous-activity" | "compromised" => Some(Disposition::Suspicious),
        _ => None,
    }
}

/// The validity window an object states.
///
/// `valid_from` and `valid_until` are the publisher's assertion about *when their claim applies*,
/// which is not the same as when Brolga saw it, so they land on the validity half of
/// [`TemporalState`] rather than the observation half. An impossible window is a rejection rather
/// than a silently dropped field: a publisher who wrote `valid_until` before `valid_from` did not
/// mean "no window".
fn temporal_of(object: &Value) -> Result<TemporalState, Rejection> {
    let mut temporal = TemporalState::unknown();
    temporal.valid_from = timestamp_field(object, "valid_from")?;
    temporal.valid_until = timestamp_field(object, "valid_until")?;
    temporal.validated().map_err(|error| {
        Rejection::new(
            "impossible_validity_window",
            format!("the indicator's validity window is impossible: {error}"),
            object,
        )
    })
}

/// One RFC 3339 field, rejected by name rather than silently ignored when it is unreadable.
fn timestamp_field(object: &Value, field: &'static str) -> Result<Option<Timestamp>, Rejection> {
    let Some(raw) = object.get(field) else {
        return Ok(None);
    };
    let Some(text) = raw.as_str() else {
        return Err(Rejection::new(
            "unusable_timestamp",
            format!("`{field}` is present but is not a string"),
            object,
        ));
    };
    Timestamp::parse_rfc3339(text).map(Some).map_err(|error| {
        Rejection::new(
            "unusable_timestamp",
            format!("`{field}` is not an RFC 3339 timestamp: {error}"),
            object,
        )
    })
}

/// Map an SRO to the relationships it becomes.
///
/// Usually one. An endpoint that is a disjunctive indicator resolves to every observable its
/// pattern named, and the edge is written to each — matching how the claims fan out, so an
/// `indicates` edge is not silently attached to whichever alternative happened to be first.
fn map_relationship(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    nodes: &BTreeMap<String, Vec<NodeRef>>,
    fan_out: &mut BTreeMap<String, usize>,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let source_ref = object
        .get("source_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Rejection::new(
                "missing_source_ref",
                "relationship has no `source_ref`",
                object,
            )
        })?;
    let target_ref = object
        .get("target_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Rejection::new(
                "missing_target_ref",
                "relationship has no `target_ref`",
                object,
            )
        })?;

    let stix_kind = object
        .get("relationship_type")
        .and_then(Value::as_str)
        .unwrap_or("related-to");
    let (kind, exact) = relationship_kind_of(stix_kind);

    // Resolved through the bundle's own objects, never derived from the STIX identifier. An edge
    // whose endpoint is not in the bundle is rejected rather than written: a relationship to a
    // record that does not exist is invisible in traversal, which is worse than a missing edge.
    let sources = nodes.get(source_ref).ok_or_else(|| {
        Rejection::new(
            "unresolved_source_ref",
            format!(
                "`{source_ref}` is not an object in this bundle, so the edge would point at a \
                 record that was never written"
            ),
            object,
        )
    })?;
    let targets = nodes.get(target_ref).ok_or_else(|| {
        Rejection::new(
            "unresolved_target_ref",
            format!(
                "`{target_ref}` is not an object in this bundle, so the edge would point at a \
                 record that was never written"
            ),
            object,
        )
    })?;

    // Counted against the edges actually produced, not against the number of SROs. A disjunctive
    // endpoint multiplies the edges written, and a bound that ignored that would stop bounding
    // exactly the case that can grow quadratically.
    let produced = sources.len().saturating_mul(targets.len());
    let count = fan_out.entry(source_ref.to_owned()).or_insert(0);
    *count = count.saturating_add(produced);
    if *count > MAX_FAN_OUT {
        return Err(Rejection::new(
            "fan_out_exceeded",
            format!(
                "`{source_ref}` has more than {MAX_FAN_OUT} outbound relationships; a bundle where \
                 one object relates to everything is quadratic to traverse"
            ),
            object,
        ));
    }

    let markings = markings_for(object, markings);
    let note = (!exact)
        .then(|| {
            // An unmapped relationship type becomes the weakest kind *and says so*. Guessing a
            // stronger one would invent a claim the source did not make.
            UntrustedText::new(format!(
                "STIX relationship_type `{stix_kind}` has no typed equivalent and was mapped to \
                 related-to"
            ))
            .ok()
        })
        .flatten();
    let revoked = object.get("revoked").and_then(Value::as_bool) == Some(true);

    let mut records = Vec::with_capacity(produced);
    for source in sources {
        for target in targets {
            let mut relationship = Relationship::new(kind, *source, *target, origin.clone());
            relationship.markings = markings.clone();
            relationship.description = note.clone();
            if revoked {
                relationship.status = LifecycleStatus::Revoked;
            }
            records.push(ParsedRecord::Relationship(Box::new(relationship)));
        }
    }

    Ok(records)
}

/// Map a STIX relationship type, reporting whether the mapping was exact.
fn relationship_kind_of(stix_type: &str) -> (RelationshipKind, bool) {
    let kind = match stix_type {
        "uses" => RelationshipKind::Uses,
        "targets" => RelationshipKind::Targets,
        "attributed-to" => RelationshipKind::AttributedTo,
        "indicates" => RelationshipKind::Indicates,
        "communicates-with" => RelationshipKind::CommunicatesWith,
        "resolves-to" => RelationshipKind::ResolvesTo,
        "downloaded-from" => RelationshipKind::DownloadedFrom,
        "hosts" => RelationshipKind::Hosts,
        "mitigates" => RelationshipKind::Mitigates,
        "exploits" => RelationshipKind::Exploits,
        "variant-of" => RelationshipKind::VariantOf,
        "impersonates" => RelationshipKind::Impersonates,
        "located-at" => RelationshipKind::LocatedAt,
        "part-of" => RelationshipKind::PartOf,
        "derived-from" => RelationshipKind::DerivedFrom,
        "duplicate-of" => RelationshipKind::DuplicateOf,
        "related-to" => return (RelationshipKind::RelatedTo, true),
        _ => return (RelationshipKind::RelatedTo, false),
    };
    (kind, true)
}

/// Truncate a string at a character boundary.
///
/// A byte-wise truncation would split a multi-byte character and produce invalid UTF-8, which every
/// text type here would then reject — turning a long value into an unusable one rather than a
/// shortened one.
fn bounded(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// Extract the MITRE ATT&CK identifier from an object's external references, canonicalised.
///
/// Exposed because ATT&CK identifiers are how analysts refer to techniques, and a technique record
/// that cannot be found by `T1059` is not usable.
#[must_use]
pub fn attack_id_of(object: &Value) -> Option<String> {
    let references = object.get("external_references")?.as_array()?;
    references.iter().find_map(|reference| {
        let source = reference.get("source_name")?.as_str()?;
        if !source.starts_with("mitre") {
            return None;
        }
        let external_id = reference.get("external_id")?.as_str()?;
        canon::ident::attack_id(external_id)
            .ok()
            .map(|canonical| canonical.into_value())
    })
}

/// Map every STIX identifier in a bundle to the canonical nodes it becomes.
///
/// Built in its own pass so a relationship can appear before the objects it joins — which it
/// routinely does — and so that an endpoint is resolved to the *canonical* identity rather than
/// derived from the STIX one. Objects this parser does not map are absent from the map, so an edge
/// touching one is rejected with a reason instead of dangling.
///
/// A list rather than a single node, because a disjunctive indicator becomes an observable per
/// alternative. An edge naming it is written to each, which is the same fan-out its claims get —
/// resolving to just one would attach the edge to whichever alternative happened to parse first.
fn collect_nodes(objects: &[Value]) -> BTreeMap<String, Vec<NodeRef>> {
    let mut nodes = BTreeMap::new();
    for object in objects {
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            continue;
        };

        if let Some(entity_kind) = entity_kind_of(kind) {
            if let Some(name) = object.get("name").and_then(Value::as_str) {
                nodes.insert(
                    id.to_owned(),
                    vec![NodeRef::Entity(entity_id_for(entity_kind, name))],
                );
            }
        } else if is_observable_type(kind)
            && let Ok(observable) = observable_of(object, kind)
        {
            nodes.insert(id.to_owned(), vec![NodeRef::Observable(observable.id())]);
        } else if kind == "indicator"
            && let Some(pattern) = object.get("pattern").and_then(Value::as_str)
            && let Ok(observables) = stix_pattern::observables_of(pattern)
        {
            // An `indicates` edge names the indicator, not the observable. Resolving it here is
            // what lets the edge land on the observables the pattern is about — the only nodes the
            // indicator becomes. An indicator whose pattern is quarantined is absent from the map,
            // so an edge touching it is rejected with a reason rather than left dangling.
            nodes.insert(
                id.to_owned(),
                observables
                    .iter()
                    .map(|observable| NodeRef::Observable(observable.id()))
                    .collect(),
            );
        }
    }
    nodes
}

/// The canonical entity identifier for a kind and name.
///
/// One function, called by both the mapper and the node collector, so the two cannot drift. Two
/// places deriving "the same" identifier differently is how an edge ends up pointing at a record
/// that was written under a different key.
fn entity_id_for(kind: EntityKind, name: &str) -> Id<Entity> {
    Id::derive(&[kind.as_str(), &name.to_lowercase()])
}

/// Map every top-level SCO in a bundle to the observable it canonicalises to.
///
/// Separate from [`collect_nodes`], which holds *identifiers* for relationship endpoints. A STIX
/// 2.1 `observed-data` names its artefacts by reference and needs the observable itself, and
/// reconstructing one from a derived identifier is not possible — nor should it be, since an
/// identifier that could be inverted would not be a digest.
fn collect_scos(objects: &[Value]) -> BTreeMap<String, Observable> {
    let mut scos = BTreeMap::new();
    for object in objects {
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if is_observable_type(kind)
            && let Ok(observable) = observable_of(object, kind)
        {
            scos.insert(id.to_owned(), observable);
        }
    }
    scos
}
