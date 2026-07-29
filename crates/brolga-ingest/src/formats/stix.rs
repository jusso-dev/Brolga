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
//!   `attack-pattern`, `identity`, `infrastructure`, `course-of-action` — become entities.
//! - **SCOs** — `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` — are
//!   canonicalised through [`crate::canon`] and become claims about the observable, because the
//!   canonical model addresses an observable by its value rather than storing it as a row of its
//!   own. A source publishing an SCO is asserting it saw the artefact, and that assertion is the
//!   thing worth keeping.
//! - **SROs** — `relationship` — become relationships, with the STIX `relationship_type` mapped to
//!   a typed [`RelationshipKind`]. An unmapped type becomes `RelatedTo` **and a note**, never a
//!   silent guess at a stronger claim.
//! - **`marking-definition`** — TLP markings are resolved and propagate to every object that
//!   references them.
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
    Assertion, Claim, Entity, EntityKind, Id, LifecycleStatus, Marking, MarkingSet, NodeRef,
    Observable, RecordOrigin, Relationship, RelationshipKind, ShortText, TlpLevel, UntrustedText,
};
use serde_json::Value;

use crate::canon::{self, CanonError};
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
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
        } else if compact.contains("\"spec_version\":\"2.1\"") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "declares STIX spec_version 2.1",
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

        let mut out = ParseOutput::default();
        let mut fan_out: BTreeMap<String, usize> = BTreeMap::new();

        for (index, object) in objects.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_object(object, &origin, &markings, &nodes, &mut fan_out, &limits) {
                Ok(Some(record)) => out.records.push(record),
                Ok(None) => {}
                Err(rejection) => out.rejected.push(rejection.into_rejected(index)),
            }
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

/// Map one STIX object.
///
/// `Ok(None)` for objects that are consumed rather than mapped, such as marking definitions.
fn map_object(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    nodes: &BTreeMap<String, NodeRef>,
    fan_out: &mut BTreeMap<String, usize>,
    limits: &brolga_security::InputLimits,
) -> Result<Option<ParsedRecord>, Rejection> {
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::new("missing_type", "object has no `type`", object))?;

    match kind {
        // Consumed by collect_markings; not a record in its own right.
        "marking-definition" => Ok(None),
        "relationship" => map_relationship(object, origin, markings, nodes, fan_out).map(Some),
        "bundle" => Err(Rejection::new(
            "nested_bundle",
            "a bundle nested inside a bundle is not valid STIX 2.1",
            object,
        )),
        _ => {
            if let Some(entity_kind) = entity_kind_of(kind) {
                map_entity(object, entity_kind, origin, markings, limits).map(Some)
            } else if is_observable_type(kind) {
                map_observable(object, kind, origin, markings).map(Some)
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

/// Map an SRO to a relationship.
fn map_relationship(
    object: &Value,
    origin: &RecordOrigin,
    markings: &BTreeMap<String, Marking>,
    nodes: &BTreeMap<String, NodeRef>,
    fan_out: &mut BTreeMap<String, usize>,
) -> Result<ParsedRecord, Rejection> {
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

    let count = fan_out.entry(source_ref.to_owned()).or_insert(0);
    *count = count.saturating_add(1);
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

    let stix_kind = object
        .get("relationship_type")
        .and_then(Value::as_str)
        .unwrap_or("related-to");
    let (kind, exact) = relationship_kind_of(stix_kind);

    // Resolved through the bundle's own objects, never derived from the STIX identifier. An edge
    // whose endpoint is not in the bundle is rejected rather than written: a relationship to a
    // record that does not exist is invisible in traversal, which is worse than a missing edge.
    let source = *nodes.get(source_ref).ok_or_else(|| {
        Rejection::new(
            "unresolved_source_ref",
            format!(
                "`{source_ref}` is not an object in this bundle, so the edge would point at a \
                 record that was never written"
            ),
            object,
        )
    })?;
    let target = *nodes.get(target_ref).ok_or_else(|| {
        Rejection::new(
            "unresolved_target_ref",
            format!(
                "`{target_ref}` is not an object in this bundle, so the edge would point at a \
                 record that was never written"
            ),
            object,
        )
    })?;

    let mut relationship = Relationship::new(kind, source, target, origin.clone());
    relationship.markings = markings_for(object, markings);

    if !exact {
        // An unmapped relationship type becomes the weakest kind *and says so*. Guessing a stronger
        // one would invent a claim the source did not make.
        if let Ok(text) = UntrustedText::new(format!(
            "STIX relationship_type `{stix_kind}` has no typed equivalent and was mapped to related-to"
        )) {
            relationship.description = Some(text);
        }
    }
    if object.get("revoked").and_then(Value::as_bool) == Some(true) {
        relationship.status = LifecycleStatus::Revoked;
    }

    Ok(ParsedRecord::Relationship(Box::new(relationship)))
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

/// Map every STIX identifier in a bundle to the canonical node it becomes.
///
/// Built in its own pass so a relationship can appear before the objects it joins — which it
/// routinely does — and so that an endpoint is resolved to the *canonical* identity rather than
/// derived from the STIX one. Objects this parser does not map are absent from the map, so an edge
/// touching one is rejected with a reason instead of dangling.
fn collect_nodes(objects: &[Value]) -> BTreeMap<String, NodeRef> {
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
                    NodeRef::Entity(entity_id_for(entity_kind, name)),
                );
            }
        } else if is_observable_type(kind)
            && let Ok(observable) = observable_of(object, kind)
        {
            nodes.insert(id.to_owned(), NodeRef::Observable(observable.id()));
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
