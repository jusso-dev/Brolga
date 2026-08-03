//! Sigma detection rules.
//!
//! # A rule is stored, never run
//!
//! Nothing here evaluates a condition, matches a field, or translates a rule into a query. A Sigma
//! rule is read as a *document about a detection* — its identity, its author, what it claims to
//! find, and which techniques it is tagged against. That is [#52](https://github.com/jusso-dev/Brolga/issues/52)'s
//! non-goal stated in code: no execution of Sigma, YARA, queries, or imported commands.
//!
//! # Detection logic is not a source of observables, except where it unambiguously is
//!
//! A Sigma `detection` block is a map of *log-source-specific field names* to values. `Image`,
//! `CommandLine`, `TargetObject`, and `User` are not observables, and a parser that canonicalised
//! whatever looked like one would invent file names out of command fragments and domains out of
//! registry paths.
//!
//! So values are read only from an allow-list of field names whose meaning does not depend on the
//! log source, and only under **plain equality**. A field carrying a modifier — `|contains`,
//! `|startswith`, `|re`, `|base64offset` — is a *predicate*, not a value: `DestinationHostname|contains: evil`
//! names an infinite set of hostnames, and recording `evil` as a domain observable would assert the
//! rule was about a domain nobody wrote down.
//!
//! Every field not read is named in a claim, so "why did my rule contribute no observables?" is
//! answerable from the data rather than from this documentation.
//!
//! # `tags` are the one place a rule says what it is about
//!
//! `attack.t1059.001` is a claim by the rule's author that it detects a technique. It becomes an
//! [`EntityKind::AttackTechnique`] entity and a typed edge. `attack.execution` — a tactic rather
//! than a technique — is recorded as a tag and produces no entity, because a tactic is a category
//! and minting an entity for one would put fourteen giant hubs in the middle of the graph.

use std::collections::BTreeMap;

use brolga_model::{
    Assertion, Claim, Entity, EntityKind, Id, LifecycleStatus, NodeRef, Observable, RecordOrigin,
    Relationship, RelationshipKind, ShortText, UntrustedText,
};

use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const SIGMA_PARSER_ID: ParserId = ParserId::new("brolga.detection.sigma");

/// Media types that identify a Sigma rule definitively.
pub const SIGMA_MEDIA_TYPES: &[&str] = &["application/x-sigma+yaml", "text/x-sigma"];

/// Most documents read from one file.
///
/// A Sigma file may hold several `---`-separated documents. A file of thousands is a
/// record-amplification shape rather than a rule collection, which is what a directory is for.
pub const MAX_DOCUMENTS: usize = 256;

/// Most `tags` read from one rule.
pub const MAX_TAGS: usize = 64;

/// A Sigma rule reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct SigmaParser;

impl SigmaParser {
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

impl IntelligenceParser for SigmaParser {
    fn id(&self) -> ParserId {
        SIGMA_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if SIGMA_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is a Sigma rule",
            );
        }

        // Sigma is YAML. Never compete on STIX/JSON media types: OpenCTI `toStix` pages arrive as
        // `application/stix+json`, and dual `Certain` with the STIX parser refuses the whole page.
        let media = hint.media_type();
        if media.contains("json") || media.contains("stix") || media.contains("xml") {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "media type is not a Sigma YAML type",
            );
        }

        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // JSON that happens to mention `logsource` / `detection` is still not a Sigma rule.
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "looks like JSON, not a Sigma YAML rule",
            );
        }

        // `logsource` and `detection` together are what make a YAML document a Sigma rule. Either
        // alone appears in unrelated configuration, and claiming every YAML file would take
        // documents this parser cannot read away from a parser that could.
        let has_logsource = text.contains("logsource:");
        let has_detection = text.contains("detection:");
        if has_logsource && has_detection {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares both `logsource:` and `detection:`",
            )
        } else if hint.has_extension("yml") || hint.has_extension("yaml") {
            candidate(
                self,
                DetectionConfidence::Declined,
                "is YAML but declares no Sigma `logsource:` and `detection:`",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no Sigma rule marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;

        let text = core::str::from_utf8(bytes)
            .map_err(|error| ParseError::new(format!("not valid UTF-8: {error}")))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_bytes {
            return Err(ParseError::new("input is over the byte limit"));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let mut out = ParseOutput::default();

        // Documents are deserialised one at a time rather than collected, so a file whose third
        // document is malformed still contributes its first two — and says which one failed.
        //
        // Multi-document streams are split on line-leading `---` markers and each slice is parsed
        // with `from_str`, which returns `Err` on hostile input. The multi-document
        // `Deserializer` iterator in `serde_norway` can *panic* on the same bytes (observed on a
        // fuzz finding: "unexpected end of mapping"), and release builds use `panic = "abort"`, so
        // catching is not available. Splitting is imperfect for markers inside quoted strings; a
        // false split becomes a rejected document rather than a process abort, which is the right
        // trade for untrusted rules.
        for (index, document) in yaml_document_slices(text).into_iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            if index >= MAX_DOCUMENTS {
                return Err(ParseError::new(format!(
                    "the file holds more than the {MAX_DOCUMENTS}-document limit"
                )));
            }

            let value: serde_norway::Value = match serde_norway::from_str(document) {
                Ok(value) => value,
                Err(error) => {
                    out.rejected.push(RejectedRecord {
                        reason_kind: "invalid_yaml",
                        reason: format!("the document is not readable YAML: {error}"),
                        offset: u64::try_from(index).ok(),
                        fragment: None,
                    });
                    continue;
                }
            };

            match map_rule(&value, &origin, field_limit) {
                Ok(records) => out.records.extend(records),
                Err(rejection) => out.rejected.push(RejectedRecord {
                    reason_kind: rejection.0,
                    reason: rejection.1,
                    offset: u64::try_from(index).ok(),
                    fragment: rejection.2,
                }),
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new(
                "the file holds no YAML document at all, so it is not a Sigma rule",
            ));
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

/// A mapping failure: reason kind, sentence, and a short fragment naming the rule.
type Rejection = (&'static str, String, Option<String>);

/// Split a YAML stream into document slices at line-leading `---` markers.
///
/// Empty slices (a bare `---` with nothing after it) are dropped. A stream with no markers yields
/// one slice — the whole input — so single-document rules keep one code path.
///
/// The marker line itself is not part of either adjacent document: a previous slice ends at the
/// marker, and the next starts after it. Including the marker in the previous slice leaves
/// `from_str` seeing a multi-document stream and refusing it.
fn yaml_document_slices(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut slices = Vec::new();
    let mut start = 0usize;
    let mut at_line_start = true;
    let mut index = 0usize;
    while index < bytes.len() {
        if at_line_start && is_document_marker(bytes, index) {
            if index > start {
                push_trimmed_slice(&mut slices, text, start, index);
            }
            start = skip_document_marker_line(bytes, index);
            index = start;
            at_line_start = true;
            continue;
        }
        at_line_start = bytes.get(index).copied() == Some(b'\n');
        index = index.saturating_add(1);
    }
    push_trimmed_slice(&mut slices, text, start, text.len());
    if slices.is_empty() {
        // Preserve the empty-input path: the caller reports "no YAML document".
        slices.push("");
    }
    slices
}

fn push_trimmed_slice<'a>(slices: &mut Vec<&'a str>, text: &'a str, start: usize, end: usize) {
    if start >= end {
        return;
    }
    let Some(slice) = text.get(start..end) else {
        return;
    };
    let trimmed = slice.trim();
    if !trimmed.is_empty() {
        slices.push(trimmed);
    }
}

/// Whether `bytes[index..]` begins a multi-document marker line (`---`, optional trailing space).
fn is_document_marker(bytes: &[u8], index: usize) -> bool {
    let Some(rest) = bytes.get(index..) else {
        return false;
    };
    if rest.get(..3) != Some(b"---") {
        return false;
    }
    match rest.get(3).copied() {
        None | Some(b'\n') | Some(b'\r') | Some(b' ') | Some(b'\t') => true,
        // `----` and `---foo` are not document markers.
        Some(_) => false,
    }
}

/// Byte index after the marker line that starts at `index`.
fn skip_document_marker_line(bytes: &[u8], index: usize) -> usize {
    let mut cursor = index.saturating_add(3);
    while let Some(&byte) = bytes.get(cursor) {
        cursor = cursor.saturating_add(1);
        if byte == b'\n' {
            break;
        }
    }
    cursor
}

/// Map one Sigma document to the rule entity and everything hanging off it.
fn map_rule(
    value: &serde_norway::Value,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let Some(mapping) = value.as_mapping() else {
        return Err((
            "not_a_rule",
            "the document is not a YAML mapping, so it is not a Sigma rule".to_owned(),
            None,
        ));
    };

    let title = string_at(mapping, "title");
    let rule_id = string_at(mapping, "id");
    let Some(title) = title.clone() else {
        return Err((
            "missing_title",
            "the rule has no `title`, which is the only field Sigma requires of every rule"
                .to_owned(),
            rule_id.clone(),
        ));
    };

    if mapping.get("detection").is_none() {
        return Err((
            "missing_detection",
            "the document has no `detection` block, so it describes no detection at all".to_owned(),
            Some(title),
        ));
    }

    let display = UntrustedText::new(bounded(&title, field_limit.min(UntrustedText::MAX_BYTES)))
        .map_err(|error| ("unusable_title", error.to_string(), Some(title.clone())))?;

    // Keyed on the rule's own UUID where it has one. Sigma requires `id` to be globally unique and
    // stable across edits, which is exactly the property an identifier needs; falling back to the
    // title would make two forks of one rule two rules, and a retitled rule a new one.
    let entity_id = Id::derive(&["sigma", rule_id.as_deref().unwrap_or(title.as_str())]);

    let mut rule = Entity::new(
        entity_id,
        EntityKind::DetectionRule,
        display,
        origin.clone(),
    );
    if let Some(description) = string_at(mapping, "description")
        && let Ok(text) = UntrustedText::new(bounded(
            &description,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
    {
        rule.description = Some(text);
    }
    // `deprecated` and `unsupported` are Sigma's own withdrawal states. A withdrawn rule is not an
    // absent one: it records both that somebody published it and that they took it back.
    match string_at(mapping, "status").as_deref() {
        Some("deprecated") => rule.status = LifecycleStatus::Deprecated,
        Some("unsupported") => rule.status = LifecycleStatus::Revoked,
        _ => {}
    }

    let rule_ref = NodeRef::Entity(rule.id);
    let mut records: Vec<ParsedRecord> = Vec::new();

    for (field, name) in [
        ("status", "sigma.status"),
        ("level", "sigma.level"),
        ("author", "sigma.author"),
        ("date", "sigma.date"),
        ("modified", "sigma.modified"),
        ("id", "sigma.id"),
    ] {
        if let Some(text) = string_at(mapping, field) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                rule_ref,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // The log source is what makes a rule runnable anywhere, and it is the first thing an operator
    // filters on when deciding whether a rule applies to their estate.
    if let Some(logsource) = mapping.get("logsource").and_then(|v| v.as_mapping()) {
        for field in ["category", "product", "service"] {
            if let Some(text) = string_at(logsource, field) {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    rule_ref,
                    attribute(&format!("sigma.logsource.{field}"), &text, field_limit)?,
                    origin.clone(),
                ))));
            }
        }
    }

    records.extend(map_tags(mapping, rule_ref, origin, field_limit)?);
    records.extend(map_detection(mapping, rule_ref, origin, field_limit)?);

    records.push(ParsedRecord::Entity(Box::new(rule)));
    Ok(records)
}

/// Map `tags`, minting technique entities for the ones that name a technique.
fn map_tags(
    mapping: &serde_norway::Mapping,
    rule_ref: NodeRef,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let tags = mapping
        .get("tags")
        .and_then(|value| value.as_sequence())
        .map(Vec::as_slice)
        .unwrap_or_default();

    if tags.len() > MAX_TAGS {
        return Err((
            "tags_exceeded",
            format!(
                "the rule states {} tags, over the {MAX_TAGS} limit; it is refused rather than \
                 truncated, because a truncated list drops attributions the author made",
                tags.len()
            ),
            None,
        ));
    }

    let mut records = Vec::new();
    for tag in tags {
        let Some(tag) = tag.as_str() else {
            continue;
        };
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            rule_ref,
            attribute("sigma.tag", tag, field_limit)?,
            origin.clone(),
        ))));

        // `attack.t1059.001` names a technique. `attack.execution` names a tactic, which is a
        // category rather than a thing — minting an entity for one would put a dozen giant hubs in
        // the middle of the graph that every rule connects to and nobody learns anything from.
        let Some(rest) = tag.strip_prefix("attack.") else {
            continue;
        };
        let Ok(technique) = canon::ident::attack_id(&rest.to_ascii_uppercase()) else {
            continue;
        };
        let technique = technique.into_value();

        let Ok(name) = UntrustedText::new(bounded(&technique, field_limit)) else {
            continue;
        };
        // Derived exactly as the STIX parser derives an ATT&CK entity, so a technique named by a
        // Sigma tag and the same technique imported from ATT&CK are one entity rather than two.
        let id = Id::derive(&["attack_technique", &technique.to_lowercase()]);
        let entity = Entity::new(id, EntityKind::AttackTechnique, name, origin.clone());

        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The rule's author asserts it finds this technique. `Indicates` is the edge for
            // "this thing is evidence of that thing", which is what a detection claims to be.
            RelationshipKind::Indicates,
            rule_ref,
            NodeRef::Entity(entity.id),
            origin.clone(),
        ))));
        records.push(ParsedRecord::Entity(Box::new(entity)));
    }
    Ok(records)
}

/// Read observables from the detection block, and name every field that was not read.
fn map_detection(
    mapping: &serde_norway::Mapping,
    rule_ref: NodeRef,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let Some(detection) = mapping
        .get("detection")
        .and_then(|value| value.as_mapping())
    else {
        return Ok(Vec::new());
    };

    let mut records = Vec::new();
    let mut observables: Vec<Observable> = Vec::new();
    let mut unread: Vec<String> = Vec::new();

    for (_, selection) in detection {
        let Some(selection) = selection.as_mapping() else {
            // `condition:` is a string and every other entry should be a mapping. A sequence of
            // mappings is legal Sigma too, and each of its entries is walked the same way.
            if let Some(entries) = selection.as_sequence() {
                for entry in entries {
                    if let Some(entry) = entry.as_mapping() {
                        collect_selection(entry, &mut observables, &mut unread);
                    }
                }
            }
            continue;
        };
        collect_selection(selection, &mut observables, &mut unread);
    }

    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());
        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The rule looks for this artefact. Not `PartOf`: the observable is not part of the
            // rule, it is a thing the rule's author expects to see.
            RelationshipKind::Indicates,
            rule_ref,
            subject,
            origin.clone(),
        ))));
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute(
                "sigma.detection",
                &observable.canonical_value(),
                field_limit,
            )?,
            origin.clone(),
        ))));
    }

    // Named rather than dropped. A rule whose every field carries a modifier contributes no
    // observables, and an operator asking why deserves an answer from the data.
    if !unread.is_empty() {
        unread.sort_unstable();
        unread.dedup();
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            rule_ref,
            attribute("sigma.detection.unread", &unread.join(", "), field_limit)?,
            origin.clone(),
        ))));
    }

    Ok(records)
}

/// Walk one selection mapping, sorting its fields into observables and unread names.
fn collect_selection(
    selection: &serde_norway::Mapping,
    observables: &mut Vec<Observable>,
    unread: &mut Vec<String>,
) {
    for (key, value) in selection {
        let Some(key) = key.as_str() else {
            continue;
        };

        // A modifier makes the field a predicate rather than a value. `DestinationHostname|contains: evil`
        // names an infinite set of hostnames, and recording `evil` as a domain would assert the rule
        // was about a domain nobody wrote down.
        if key.contains('|') {
            unread.push(format!("{key} (modifier)"));
            continue;
        }
        let Some(canonicaliser) = canonicaliser_for(key) else {
            unread.push(key.to_owned());
            continue;
        };

        let mut values: Vec<&serde_norway::Value> = Vec::new();
        match value.as_sequence() {
            Some(items) => values.extend(items),
            None => values.push(value),
        }

        for item in values {
            let Some(text) = item.as_str() else {
                unread.push(format!("{key} (not a string)"));
                continue;
            };
            match canonicaliser(text) {
                Ok(canonical) => {
                    let observable = canonical.into_value();
                    if !observables
                        .iter()
                        .any(|existing| existing.id() == observable.id())
                    {
                        observables.push(observable);
                    }
                }
                Err(error) => unread.push(format!("{key} ({error})")),
            }
        }
    }
}

/// Which canonicaliser a Sigma field name maps to, for the names whose meaning does not depend on
/// the log source.
///
/// Deliberately absent: `Image`, `CommandLine`, `TargetObject`, `ParentImage`, `User`, and every
/// other field whose content is a path, a command fragment, or an account. Canonicalising those
/// would invent file names out of command lines and domains out of registry paths.
fn canonicaliser_for(field: &str) -> Option<canon::Canonicaliser> {
    Some(match field.trim() {
        "DestinationIp" | "SourceIp" | "dst_ip" | "src_ip" | "DestinationAddress"
        | "SourceAddress" | "c-ip" | "cs-ip" => canon::net::ip_address,
        "DestinationHostname"
        | "SourceHostname"
        | "dns_query"
        | "QueryName"
        | "cs-host"
        | "DestinationDomain" => canon::net::domain_name,
        "c-uri" | "cs-uri" | "cs-uri-query" | "Url" | "uri" | "url" => canon::net::url,
        "md5" | "sha1" | "sha256" | "Hash" | "Hashes" | "FileHash" | "imphash" => {
            canon::file::file_hash
        }
        _ => return None,
    })
}

/// A string field of a mapping, if it is a string at all.
fn string_at(mapping: &serde_norway::Mapping, key: &str) -> Option<String> {
    mapping
        .get(key)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

/// One attribute assertion.
fn attribute(name: &str, value: &str, field_limit: usize) -> Result<Assertion, Rejection> {
    Ok(Assertion::Attribute {
        name: ShortText::new(name)
            .map_err(|error| ("unusable_attribute_name", error.to_string(), None))?,
        value: UntrustedText::new(bounded(value, field_limit.min(UntrustedText::MAX_BYTES)))
            .map_err(|error| ("unusable_attribute_value", error.to_string(), None))?,
    })
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

/// Which detection field names this parser reads, for a caller that wants to state the boundary.
///
/// Exposed because "Sigma support" means nothing without saying which parts are read, and a list
/// derived from the code cannot drift from it.
#[must_use]
pub fn readable_detection_fields() -> Vec<&'static str> {
    let mut fields: Vec<&'static str> = [
        "DestinationIp",
        "SourceIp",
        "dst_ip",
        "src_ip",
        "DestinationAddress",
        "SourceAddress",
        "c-ip",
        "cs-ip",
        "DestinationHostname",
        "SourceHostname",
        "dns_query",
        "QueryName",
        "cs-host",
        "DestinationDomain",
        "c-uri",
        "cs-uri",
        "cs-uri-query",
        "Url",
        "uri",
        "url",
        "md5",
        "sha1",
        "sha256",
        "Hash",
        "Hashes",
        "FileHash",
        "imphash",
    ]
    .into_iter()
    .filter(|field| canonicaliser_for(field).is_some())
    .collect();
    fields.sort_unstable();
    fields
}

/// A `BTreeMap` view of a rule's scalar fields, for a caller inspecting one without mapping it.
///
/// # Errors
///
/// Returns the reason the document could not be read as YAML.
pub fn rule_fields(text: &str) -> Result<BTreeMap<String, String>, String> {
    let value: serde_norway::Value =
        serde_norway::from_str(text).map_err(|error| error.to_string())?;
    let Some(mapping) = value.as_mapping() else {
        return Err("the document is not a YAML mapping".to_owned());
    };

    let mut fields = BTreeMap::new();
    for (key, value) in mapping {
        if let (Some(key), Some(value)) = (key.as_str(), value.as_str()) {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(fields)
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

    #[test]
    fn a_field_carrying_a_modifier_is_a_predicate_rather_than_a_value() {
        let selection: serde_norway::Mapping = serde_norway::from_str(
            "DestinationHostname|contains: evil\nDestinationHostname: real.example.com\n",
        )
        .unwrap();

        let mut observables = Vec::new();
        let mut unread = Vec::new();
        collect_selection(&selection, &mut observables, &mut unread);

        assert_eq!(observables.len(), 1, "only the plain equality is a value");
        assert_eq!(
            observables[0].canonical_value(),
            "real.example.com",
            "{observables:?}"
        );
        assert!(
            unread.iter().any(|entry| entry.contains("modifier")),
            "{unread:?}"
        );
    }

    /// Canonicalising these would invent file names out of command fragments and domains out of
    /// registry paths.
    #[test]
    fn log_source_specific_fields_are_never_canonicalised() {
        for field in [
            "Image",
            "CommandLine",
            "TargetObject",
            "ParentImage",
            "User",
            "EventID",
        ] {
            assert!(canonicaliser_for(field).is_none(), "{field}");
        }
    }

    #[test]
    fn the_readable_field_list_matches_what_the_code_reads() {
        for field in readable_detection_fields() {
            assert!(canonicaliser_for(field).is_some(), "{field}");
        }
        assert!(readable_detection_fields().contains(&"sha256"));
    }

    #[test]
    fn a_value_that_does_not_canonicalise_is_named_rather_than_dropped() {
        let selection: serde_norway::Mapping =
            serde_norway::from_str("DestinationIp: not-an-address\n").unwrap();

        let mut observables = Vec::new();
        let mut unread = Vec::new();
        collect_selection(&selection, &mut observables, &mut unread);

        assert!(observables.is_empty());
        assert!(
            unread
                .iter()
                .any(|entry| entry.starts_with("DestinationIp")),
            "{unread:?}"
        );
    }

    #[test]
    fn a_sequence_of_values_under_one_field_yields_each() {
        let selection: serde_norway::Mapping =
            serde_norway::from_str("DestinationIp:\n  - 198.51.100.1\n  - 198.51.100.2\n").unwrap();

        let mut observables = Vec::new();
        let mut unread = Vec::new();
        collect_selection(&selection, &mut observables, &mut unread);
        assert_eq!(observables.len(), 2);
    }
}
