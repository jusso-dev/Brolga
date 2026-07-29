//! MISP events, attributes, objects, tags, and warning lists.
//!
//! # Feed presence is not evidence of maliciousness
//!
//! This is the mapping decision that matters most, and it is the one a naive importer gets wrong.
//! A MISP attribute is a thing somebody wrote down. It may be an indicator of compromise, a piece of
//! infrastructure under investigation, a false positive somebody left in place, or an allow-listed
//! value. **Nothing about being present in an event makes it malicious.**
//!
//! So attributes become [`Assertion::Attribute`] claims recording what MISP said, and a
//! [`Disposition`] is only asserted where MISP actually expressed one — the `to_ids` flag, which is
//! an explicit "this is detectable badness" statement by the publisher. Everything else is recorded
//! and left for later scoring to weigh.
//!
//! Warning-list matches are handled the same way, and this is the sharper case: a value appearing on
//! a warning list means *somebody has flagged this as likely a false positive* — Google's DNS
//! servers, RFC 1918 space, Alexa top sites. A match is **evidence** attached as a claim, never an
//! automatic disposition, because "on a warning list" and "benign" are different statements and
//! collapsing them silently overrides an analyst's judgement.
//!
//! # Composite attributes keep their components
//!
//! MISP composites — `domain|ip`, `filename|md5`, `ip-src|port` — carry two facts in one string.
//! Splitting them into two unrelated records loses the association, and keeping them as one opaque
//! string loses both values as pivots. Both components are canonicalised **and** a relationship
//! between them is emitted, so the pairing survives as a fact rather than as punctuation.
//!
//! # Deleted, disabled, and decayed
//!
//! Each maps to something explicit, and none maps to "absent". A soft-deleted attribute is a record
//! its publisher withdrew; `disable_correlation` is an instruction about how to *use* a value, not a
//! statement about the value; decay scores are the publisher's confidence over time. Dropping any of
//! them would silently discard the publisher's own qualification of their data.

use std::collections::BTreeMap;

use brolga_model::{
    Assertion, Claim, Disposition, Entity, EntityKind, Id, LifecycleStatus, Marking, MarkingSet,
    NodeRef, Observable, PapLevel, RecordOrigin, Relationship, RelationshipKind, ShortText,
    TlpLevel, UntrustedText,
};
use serde_json::Value;

use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const MISP_PARSER_ID: ParserId = ParserId::new("brolga.misp.event");

/// A MISP JSON reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct MispParser;

impl MispParser {
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

impl IntelligenceParser for MispParser {
    fn id(&self) -> ParserId {
        MISP_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if hint.media_type() == "application/vnd.misp+json" {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is MISP JSON",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();

        if compact.contains("\"Event\":{") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares a MISP `Event` object",
            )
        } else if compact.contains("\"response\":[{\"Event\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "is a MISP search response",
            )
        } else if compact.contains("\"Attribute\":[") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "carries a MISP `Attribute` array",
            )
        } else if compact.contains("\"list\":[") && compact.contains("\"matching_attributes\"") {
            candidate(self, DetectionConfidence::Certain, "is a MISP warning list")
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no MISP Event, Attribute, or warning-list marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;

        let document: Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not valid JSON: {error}")))?;

        let depth = super::stix::depth_of(&document);
        if depth > usize::try_from(limits.max_depth).unwrap_or(usize::MAX) {
            return Err(ParseError::new(format!(
                "JSON nests {depth} deep, over the {}-level limit",
                limits.max_depth
            )));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;

        if let Some(list) = warning_list_of(&document) {
            return parse_warning_list(list, &origin, &limits);
        }

        let events = events_of(&document)?;
        let mut out = ParseOutput::default();
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        for event in &events {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;
            parse_event(event, &origin, field_limit, &limits, &mut out)?;
        }

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

/// The events in a document, covering the export, search-response, and bare-event shapes.
fn events_of(document: &Value) -> Result<Vec<Value>, ParseError> {
    if let Some(event) = document.get("Event") {
        return Ok(vec![event.clone()]);
    }
    if let Some(Value::Array(items)) = document.get("response") {
        return Ok(items
            .iter()
            .filter_map(|item| item.get("Event").cloned())
            .collect());
    }
    if document.get("Attribute").is_some() || document.get("uuid").is_some() {
        return Ok(vec![document.clone()]);
    }
    Err(ParseError::new(
        "not MISP JSON: no `Event`, no `response`, and no `Attribute` array",
    ))
}

/// A warning list document, if this is one.
fn warning_list_of(document: &Value) -> Option<&Value> {
    document
        .get("list")
        .is_some()
        .then_some(document)
        .filter(|value| value.get("matching_attributes").is_some() || value.get("name").is_some())
}

/// Map a warning list to claims that record membership, never a disposition.
///
/// A warning list says *somebody flagged this as likely a false positive* — Google's resolvers, RFC
/// 1918 space, Alexa top sites. That is evidence for later scoring to weigh, and it is not the same
/// statement as "benign". Collapsing the two would let a list author silently override an analyst.
fn parse_warning_list(
    document: &Value,
    origin: &RecordOrigin,
    limits: &brolga_security::InputLimits,
) -> Result<ParseOutput, ParseError> {
    let name = document
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed MISP warning list");
    let attribute_name =
        ShortText::new("misp.warninglist").map_err(|error| ParseError::new(error.to_string()))?;

    let entries = document
        .get("list")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    if u64::try_from(entries.len()).unwrap_or(u64::MAX) > limits.max_records {
        return Err(ParseError::new(format!(
            "warning list holds {} entries, over the {}-record limit",
            entries.len(),
            limits.max_records
        )));
    }

    let mut out = ParseOutput::default();
    for (index, entry) in entries.iter().enumerate() {
        let Some(raw) = entry.as_str() else {
            out.rejected.push(RejectedRecord {
                reason_kind: "non_string_warninglist_entry",
                reason: "warning-list entries must be strings".to_owned(),
                offset: u64::try_from(index).ok(),
                fragment: Some(entry.to_string()),
            });
            continue;
        };

        let Ok(observable) = canon::net::any_network(raw) else {
            out.rejected.push(RejectedRecord {
                reason_kind: "uncanonicalisable_warninglist_entry",
                reason: format!("`{raw}` is not a canonicalisable network observable"),
                offset: u64::try_from(index).ok(),
                fragment: Some(raw.to_owned()),
            });
            continue;
        };

        let Ok(value) = UntrustedText::new(name) else {
            continue;
        };
        out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
            NodeRef::Observable(observable.value().id()),
            Assertion::Attribute {
                name: attribute_name.clone(),
                value,
            },
            origin.clone(),
        ))));
    }
    Ok(out)
}

/// Map one MISP event and everything under it.
fn parse_event(
    event: &Value,
    origin: &RecordOrigin,
    field_limit: usize,
    limits: &brolga_security::InputLimits,
    out: &mut ParseOutput,
) -> Result<(), ParseError> {
    let info = event
        .get("info")
        .and_then(Value::as_str)
        .unwrap_or("untitled MISP event");
    let uuid = event
        .get("uuid")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let name = UntrustedText::new(bounded(info, field_limit.min(UntrustedText::MAX_BYTES)))
        .map_err(|error| ParseError::new(format!("unusable event `info`: {error}")))?;

    // Keyed on the MISP UUID where there is one. Unlike a STIX id, a MISP event UUID identifies the
    // *report*, and two reports with the same title are genuinely two reports.
    let event_id = Id::derive(&["misp.event", if uuid.is_empty() { info } else { uuid }]);
    let mut report = Entity::new(event_id, EntityKind::Report, name, origin.clone());

    let event_markings = markings_from_tags(event);
    report.markings = event_markings.clone();

    if event.get("deleted").and_then(Value::as_bool) == Some(true) {
        report.status = LifecycleStatus::Revoked;
    }
    out.records.push(ParsedRecord::Entity(Box::new(report)));

    let attributes = collect_attributes(event);
    if u64::try_from(attributes.len()).unwrap_or(u64::MAX) > limits.max_records {
        return Err(ParseError::new(format!(
            "event holds {} attributes, over the {}-record limit",
            attributes.len(),
            limits.max_records
        )));
    }

    for (index, attribute) in attributes.iter().enumerate() {
        match map_attribute(
            attribute,
            event_id,
            origin,
            &event_markings,
            field_limit,
            out,
        ) {
            Ok(()) => {}
            Err(rejection) => out.rejected.push(RejectedRecord {
                reason_kind: rejection.0,
                reason: rejection.1,
                offset: u64::try_from(index).ok(),
                fragment: Some(rejection.2),
            }),
        }
    }
    Ok(())
}

/// Every attribute in an event, including those nested inside MISP objects.
///
/// Attributes inside an object are attributes. Reading only the top-level array silently drops
/// everything a publisher structured, which is most of the useful content in a modern MISP event.
fn collect_attributes(event: &Value) -> Vec<Value> {
    let mut attributes: Vec<Value> = event
        .get("Attribute")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for object in event
        .get("Object")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if let Some(nested) = object.get("Attribute").and_then(Value::as_array) {
            attributes.extend(nested.iter().cloned());
        }
    }
    attributes
}

/// Map one attribute, appending claims and relationships.
fn map_attribute(
    attribute: &Value,
    event_id: Id<Entity>,
    origin: &RecordOrigin,
    event_markings: &MarkingSet,
    field_limit: usize,
    out: &mut ParseOutput,
) -> Result<(), (&'static str, String, String)> {
    let kind = attribute
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "missing_type",
                "attribute has no `type`".to_owned(),
                describe(attribute),
            )
        })?;
    let raw = attribute
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "missing_value",
                "attribute has no `value`".to_owned(),
                describe(attribute),
            )
        })?;

    let mut markings = event_markings.clone();
    for marking in markings_from_tags(attribute).iter() {
        markings.insert(marking.clone());
    }

    let components = canonicalise_attribute(kind, raw)
        .map_err(|reason| ("uncanonicalisable_value", reason, bounded(raw, 200)))?;

    let deleted = attribute.get("deleted").and_then(Value::as_bool) == Some(true);
    let correlation_disabled = attribute
        .get("disable_correlation")
        .and_then(Value::as_bool)
        == Some(true);
    // `to_ids` is MISP's own explicit "this is detectable badness" flag. It is the only field in a
    // MISP attribute that states maliciousness, so it is the only one that produces a disposition.
    let to_ids = attribute.get("to_ids").and_then(Value::as_bool) == Some(true);

    for observable in &components {
        let subject = NodeRef::Observable(observable.id());

        let mut attribute_claim = Claim::new(
            subject,
            Assertion::Attribute {
                name: ShortText::new(format!("misp.{kind}")).map_err(|error| {
                    (
                        "unusable_attribute_name",
                        error.to_string(),
                        kind.to_owned(),
                    )
                })?,
                value: UntrustedText::new(bounded(raw, field_limit.min(UntrustedText::MAX_BYTES)))
                    .map_err(|error| {
                        (
                            "unusable_attribute_value",
                            error.to_string(),
                            bounded(raw, 200),
                        )
                    })?,
            },
            origin.clone(),
        );
        attribute_claim.markings = markings.clone();
        if deleted {
            // Soft-deleted upstream. Not absent — a record its publisher withdrew, which says more
            // than silence.
            attribute_claim.status = LifecycleStatus::Revoked;
        }
        out.records
            .push(ParsedRecord::Claim(Box::new(attribute_claim)));

        if to_ids {
            let mut disposition = Claim::new(
                subject,
                Assertion::Disposition(Disposition::Malicious),
                origin.clone(),
            );
            disposition.markings = markings.clone();
            if deleted {
                disposition.status = LifecycleStatus::Revoked;
            }
            out.records.push(ParsedRecord::Claim(Box::new(disposition)));
        }

        if correlation_disabled {
            // An instruction about how to *use* the value, not a statement about the value. Kept
            // separate so a later correlation step can honour it without inferring anything about
            // whether the value is malicious.
            let mut note = Claim::new(
                subject,
                Assertion::Attribute {
                    name: ShortText::new("misp.disable_correlation").map_err(|error| {
                        ("unusable_attribute_name", error.to_string(), String::new())
                    })?,
                    value: UntrustedText::new("true").map_err(|error| {
                        ("unusable_attribute_value", error.to_string(), String::new())
                    })?,
                },
                origin.clone(),
            );
            note.markings = markings.clone();
            out.records.push(ParsedRecord::Claim(Box::new(note)));
        }

        if let Some(score) = decay_score(attribute) {
            let mut decayed = Claim::new(
                subject,
                Assertion::Attribute {
                    name: ShortText::new("misp.decay_score").map_err(|error| {
                        ("unusable_attribute_name", error.to_string(), String::new())
                    })?,
                    value: UntrustedText::new(score.clone())
                        .map_err(|error| ("unusable_attribute_value", error.to_string(), score))?,
                },
                origin.clone(),
            );
            decayed.markings = markings.clone();
            out.records.push(ParsedRecord::Claim(Box::new(decayed)));
        }

        // Every attribute links back to the event it was published in. That is this issue's "every
        // canonical result links to the MISP original" at the graph level, alongside the provenance
        // every record already carries.
        out.records
            .push(ParsedRecord::Relationship(Box::new(Relationship::new(
                RelationshipKind::PartOf,
                subject,
                NodeRef::Entity(event_id),
                origin.clone(),
            ))));
    }

    // A composite carried two facts in one string. Emitting the components without the pairing
    // would keep both values as pivots and lose the association that made them worth publishing
    // together.
    if let [first, second] = components.as_slice() {
        out.records
            .push(ParsedRecord::Relationship(Box::new(Relationship::new(
                composite_relationship(kind),
                NodeRef::Observable(first.id()),
                NodeRef::Observable(second.id()),
                origin.clone(),
            ))));
    }

    Ok(())
}

/// Which relationship a composite's two halves stand in.
fn composite_relationship(kind: &str) -> RelationshipKind {
    match kind {
        // `domain|ip` is a resolution at a point in time, which is a stronger and more useful
        // statement than "related to".
        "domain|ip" | "hostname|ip" => RelationshipKind::ResolvesTo,
        _ => RelationshipKind::RelatedTo,
    }
}

/// Canonicalise an attribute value, returning one observable or a composite's two.
fn canonicalise_attribute(kind: &str, raw: &str) -> Result<Vec<Observable>, String> {
    if let Some((left_kind, right_kind)) = kind.split_once('|') {
        let (left_raw, right_raw) = raw
            .split_once('|')
            .ok_or_else(|| format!("composite type `{kind}` but the value has no `|`"))?;
        let left = canonicalise_simple(left_kind, left_raw)?;
        let right = canonicalise_simple(right_kind, right_raw)?;
        return Ok(vec![left, right]);
    }
    Ok(vec![canonicalise_simple(kind, raw)?])
}

/// Canonicalise one non-composite MISP attribute type.
fn canonicalise_simple(kind: &str, raw: &str) -> Result<Observable, String> {
    let canonical = match kind {
        "ip-src" | "ip-dst" | "ip" => canon::net::ip_address(raw),
        "ip-src|port" | "ip-dst|port" => canon::net::ip_address(raw),
        "domain" | "hostname" => canon::net::domain_name(raw),
        "url" | "uri" | "link" => canon::net::url(raw),
        "email" | "email-src" | "email-dst" | "email-reply-to" => canon::net::email_address(raw),
        "md5" | "sha1" | "sha256" | "sha512" | "filename|md5" => canon::file::file_hash(raw),
        "filename" => canon::file::file_name(raw),
        "port" => return Err(format!("`{kind}` is not an observable on its own")),
        _ => canon::net::any_network(raw),
    }
    .map_err(|error| error.to_string())?;
    Ok(canonical.into_value())
}

/// The MISP decay score, where the instance publishes one.
fn decay_score(attribute: &Value) -> Option<String> {
    let decay = attribute.get("decay_score")?.as_array()?;
    let first = decay.first()?;
    let score = first.get("score")?;
    Some(score.to_string())
}

/// Markings from a MISP `Tag` array.
///
/// TLP and PAP tags become typed markings. Every other tag is kept as a handling instruction rather
/// than discarded — a galaxy or taxonomy tag is the publisher's classification and later policy may
/// need it, even though Brolga does not act on it today.
fn markings_from_tags(container: &Value) -> MarkingSet {
    let mut set = MarkingSet::empty();
    let Some(tags) = container.get("Tag").and_then(Value::as_array) else {
        return set;
    };
    for tag in tags {
        let Some(name) = tag.get("name").and_then(Value::as_str) else {
            continue;
        };
        let lowered = name.trim().to_ascii_lowercase();

        if let Some(level) = tlp_level(&lowered) {
            set.insert(Marking::Tlp(level));
        } else if let Some(level) = pap_level(&lowered) {
            set.insert(Marking::Pap(level));
        } else if let Ok(text) = ShortText::new(bounded(name, ShortText::MAX_BYTES)) {
            set.insert(Marking::Handling(text));
        }
    }
    set
}

/// Map a MISP TLP tag.
fn tlp_level(tag: &str) -> Option<TlpLevel> {
    match tag {
        "tlp:clear" | "tlp:white" => Some(TlpLevel::Clear),
        "tlp:green" => Some(TlpLevel::Green),
        "tlp:amber" => Some(TlpLevel::Amber),
        "tlp:amber+strict" => Some(TlpLevel::AmberStrict),
        "tlp:red" => Some(TlpLevel::Red),
        _ => None,
    }
}

/// Map a MISP PAP tag.
fn pap_level(tag: &str) -> Option<PapLevel> {
    match tag {
        "pap:clear" | "pap:white" => Some(PapLevel::Clear),
        "pap:green" => Some(PapLevel::Green),
        "pap:amber" => Some(PapLevel::Amber),
        "pap:red" => Some(PapLevel::Red),
        _ => None,
    }
}

/// A short, safe description of an attribute for a diagnostic.
fn describe(attribute: &Value) -> String {
    let kind = attribute.get("type").and_then(Value::as_str).unwrap_or("?");
    let uuid = attribute.get("uuid").and_then(Value::as_str).unwrap_or("?");
    format!("{kind} {uuid}")
}

/// Truncate at a character boundary.
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

/// Galaxy clusters attached to an event, as entity names.
///
/// Exposed so a caller can see what a publisher associated the event with. Not mapped to entities
/// automatically: a galaxy cluster is a *reference* to a known actor or malware family, and creating
/// an entity from it would assert the association is Brolga's finding rather than MISP's.
#[must_use]
pub fn galaxy_names(event: &Value) -> Vec<String> {
    let mut names = BTreeMap::new();
    for galaxy in event
        .get("Galaxy")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        for cluster in galaxy
            .get("GalaxyCluster")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            if let Some(value) = cluster.get("value").and_then(Value::as_str) {
                names.insert(value.to_owned(), ());
            }
        }
    }
    names.into_keys().collect()
}
