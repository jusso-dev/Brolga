//! OSV — the Open Source Vulnerability schema.
//!
//! # Why OSV is the reference shape
//!
//! OSV is the format the rest of this milestone is measured against, because it is the one that
//! already says what the others only imply: which *package* is affected, in which *ecosystem*, over
//! which *version range*, and under which *other names* the flaw is known. GitHub, PyPI, RustSec,
//! Go, and OSS-Fuzz all publish it, and `osv.dev` aggregates them.
//!
//! # Aliases are the point
//!
//! An OSV record published by GitHub is identified `GHSA-…` and lists `CVE-…` in `aliases`. A record
//! from RustSec is `RUSTSEC-…` and does the same. [`crate::formats::vuln::vulnerability_id`] resolves
//! all of them onto the CVE, which is what makes three advisories about Log4Shell one entity here.
//!
//! # `affected` is read structurally; version ranges are not compared
//!
//! Each `affected` entry names a package and zero or more `ranges`. The range *events* — `introduced`,
//! `fixed`, `last_affected`, `limit` — are read and recorded as text against the package, keyed by
//! the vulnerability. Enumerated `versions` are recorded the same way, capped.
//!
//! What is deliberately not done: deciding whether an installed version falls inside a range. See
//! [`crate::formats::vuln`] for why — a wrong ecosystem comparator reports a vulnerable estate as
//! clean, and #53's non-goal is that Brolga is not a scanner.
//!
//! # What is read, and what is named as unread
//!
//! Read: `id`, `aliases`, `related`, `summary`, `details`, `published`, `modified`, `withdrawn`,
//! `severity`, `affected[].package`, `affected[].ranges`, `affected[].versions`,
//! `affected[].database_specific.cwe_ids`, and `references[].url`.
//!
//! Not read, and named in a claim so the boundary is visible in the data: `credits` (attribution of
//! the reporter, which is about people rather than the flaw) and `affected[].ecosystem_specific`
//! (free-form per-ecosystem payloads with no cross-ecosystem meaning).

use brolga_model::{Entity, LifecycleStatus, NodeRef, RecordOrigin, ShortText, UntrustedText};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{
    self, MAX_AFFECTED, attribute, bounded, strings_at, text_at, within_byte_limit,
    within_record_limit,
};
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const OSV_PARSER_ID: ParserId = ParserId::new("brolga.vulnerability.osv");

/// Media types that identify OSV definitively.
pub const OSV_MEDIA_TYPES: &[&str] = &["application/vnd.osv+json", "application/x-osv+json"];

/// Most enumerated versions read from one `affected` entry.
///
/// A record listing every affected version of a long-lived package runs to hundreds. Beyond this it
/// is a version list rather than intelligence, and the count is noted instead.
pub const MAX_VERSIONS: usize = 256;

/// Most records read from one OSV batch document.
pub const MAX_BATCH: usize = 10_000;

/// An OSV reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsvParser;

impl OsvParser {
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

impl IntelligenceParser for OsvParser {
    fn id(&self) -> ParserId {
        OSV_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if OSV_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is OSV");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // `schema_version` alongside an `affected` array is OSV's own marker and appears in nothing
        // else. `affected` alone is too generic to claim a document on.
        if text.contains("\"schema_version\"") && text.contains("\"affected\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares an OSV `schema_version` and an `affected` array",
            )
        } else if text.contains("\"affected\"")
            && (text.contains("\"GHSA-") || text.contains("\"RUSTSEC-") || text.contains("\"OSV-"))
        {
            candidate(
                self,
                DetectionConfidence::Strong,
                "has an `affected` array and an OSV-family identifier",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no OSV marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        within_byte_limit(bytes, limits.max_bytes)?;

        let document: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not readable JSON: {error}")))?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        // Three shapes in the wild, all of them OSV: a single record, a bare array of records, and
        // `osv.dev`'s query response `{"vulns": [...]}`. Accepting all three means an operator does
        // not have to reshape a file before ingesting it.
        let records: Vec<&serde_json::Value> = if let Some(array) = document.as_array() {
            array.iter().collect()
        } else if let Some(array) = document.get("vulns").and_then(serde_json::Value::as_array) {
            array.iter().collect()
        } else {
            vec![&document]
        };

        if records.len() > MAX_BATCH {
            return Err(ParseError::new(format!(
                "the document holds {} OSV records, over the {MAX_BATCH} limit",
                records.len()
            )));
        }

        let mut out = ParseOutput::default();
        for (index, record) in records.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_record(record, &origin, field_limit) {
                Ok(mut mapped) => {
                    out.records.append(&mut mapped.0);
                    out.notes.extend(mapped.1);
                }
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_osv_record",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: text_at(record, "id"),
                }),
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the document holds no OSV record at all"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Map one OSV record. Returns its records and any notes.
fn map_record(
    record: &serde_json::Value,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Vec<ParsedRecord>, Vec<ShortText>), ParseError> {
    let primary = text_at(record, "id").unwrap_or_default();
    // `related` names flaws that are *not* the same flaw, so it must never reach the alias list —
    // folding a related CVE into identity would merge two distinct vulnerabilities into one entity.
    let aliases = strings_at(record, "aliases");
    let identity = vuln::vulnerability_id(&primary, &aliases)
        .ok_or_else(|| ParseError::new("the record names no vulnerability identifier"))?;

    let summary = text_at(record, "summary");
    let (mut vulnerability, claims) =
        vuln::vulnerability_entity(&identity, summary.as_deref(), origin, field_limit)?;

    // `withdrawn` is OSV's retraction: the advisory was published and then taken back. That is not
    // the same as never having existed, and a store that dropped withdrawn records would leave an
    // operator unable to explain why last week's report named a flaw that is now absent.
    if record.get("withdrawn").is_some() {
        vulnerability.status = LifecycleStatus::Revoked;
    }
    if let Some(details) = text_at(record, "details")
        && vulnerability.description.is_none()
        && let Ok(text) = UntrustedText::new(bounded(&details, field_limit))
    {
        vulnerability.description = Some(text);
    }

    let vulnerability_id = vulnerability.id;
    let subject = NodeRef::Entity(vulnerability_id);
    let mut records: Vec<ParsedRecord> = Vec::new();
    let mut notes: Vec<ShortText> = Vec::new();

    for claim in claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }

    for (field, name) in [
        ("published", "vuln.published"),
        ("modified", "vuln.modified"),
        ("withdrawn", "vuln.withdrawn"),
        ("schema_version", "osv.schema_version"),
    ] {
        if let Some(text) = text_at(record, field) {
            records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // `related` is recorded, clearly labelled as *related* rather than *alias*, so the distinction
    // survives into the store.
    for related in strings_at(record, "related") {
        records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
            subject,
            attribute("vuln.related", &related, field_limit)?,
            origin.clone(),
        ))));
    }

    // Severity is a list of typed scores — `CVSS_V3`, `CVSS_V4`, `Ubuntu`. Each is recorded under its
    // own type, because a bare number with no vector is not comparable across scoring systems.
    for severity in vuln::array_at(record, "severity") {
        let Some(kind) = text_at(severity, "type") else {
            continue;
        };
        if let Some(score) = text_at(severity, "score") {
            records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
                subject,
                attribute(&format!("vuln.severity.{kind}"), &score, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    let references: Vec<String> = vuln::array_at(record, "references")
        .iter()
        .filter_map(|reference| text_at(reference, "url"))
        .collect();
    let (reference_claims, dropped) =
        vuln::reference_claims(vulnerability_id, &references, origin, field_limit)?;
    for claim in reference_claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }
    if let Some(dropped) = dropped
        && let Ok(note) = ShortText::new(bounded(&dropped, ShortText::MAX_BYTES))
    {
        notes.push(note);
    }

    // Fields this parser does not read, named in the data rather than only in documentation.
    for unread in ["credits"] {
        if record.get(unread).is_some() {
            records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
                subject,
                attribute("osv.unread_field", unread, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    let affected = vuln::array_at(record, "affected");
    if affected.len() > MAX_AFFECTED {
        return Err(ParseError::new(format!(
            "the record names {} affected packages, over the {MAX_AFFECTED} limit; it is refused \
             rather than truncated, because a truncated list understates what a flaw affects",
            affected.len()
        )));
    }

    for entry in affected {
        let (mut mapped, mut entry_notes) = map_affected(
            entry,
            vulnerability_id,
            &identity.canonical,
            origin,
            field_limit,
        )?;
        records.append(&mut mapped);
        notes.append(&mut entry_notes);
    }

    records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    Ok((records, notes))
}

/// Map one `affected` entry: the package, the edge, and the range text.
fn map_affected(
    entry: &serde_json::Value,
    vulnerability_id: brolga_model::Id<Entity>,
    vulnerability_name: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Vec<ParsedRecord>, Vec<ShortText>), ParseError> {
    let Some(package) = entry.get("package") else {
        // An `affected` entry with no package is legal OSV — it can carry only `ecosystem_specific`
        // data — and carries nothing this model can key on.
        return Ok((Vec::new(), Vec::new()));
    };

    let name = text_at(package, "name").unwrap_or_default();
    let ecosystem = text_at(package, "ecosystem").unwrap_or_default();
    let purl = text_at(package, "purl");

    // OSV names the package without a version: the version information lives in `ranges`. So the
    // package entity is the *unversioned* package, and the range is a claim on it. A purl carrying
    // no `@version` is exactly that same thing, which is why it can be used as the key unchanged.
    let (package_entity, package_claims) =
        vuln::package_entity(purl.as_deref(), &ecosystem, &name, "", origin, field_limit)?;
    let package_id = package_entity.id;

    let mut records: Vec<ParsedRecord> = Vec::new();
    let mut notes: Vec<ShortText> = Vec::new();
    for claim in package_claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }

    for range in vuln::array_at(entry, "ranges") {
        let kind = text_at(range, "type").unwrap_or_else(|| "UNKNOWN".to_owned());
        let mut events: Vec<String> = Vec::new();
        for event in vuln::array_at(range, "events") {
            let Some(object) = event.as_object() else {
                continue;
            };
            for (key, value) in object {
                if let Some(value) = value.as_str() {
                    events.push(format!("{key} {value}"));
                }
            }
        }
        if !events.is_empty() {
            records.push(ParsedRecord::Claim(Box::new(vuln::affected_range(
                package_id,
                vulnerability_name,
                &format!("{kind}: {}", events.join(", ")),
                origin,
                field_limit,
            )?)));
        }
    }

    let versions = strings_at(entry, "versions");
    let kept = versions.len().min(MAX_VERSIONS);
    if kept > 0 {
        records.push(ParsedRecord::Claim(Box::new(vuln::affected_range(
            package_id,
            vulnerability_name,
            &format!(
                "VERSIONS: {}",
                versions.get(..kept).unwrap_or_default().join(", ")
            ),
            origin,
            field_limit,
        )?)));
    }
    if versions.len() > kept
        && let Ok(note) = ShortText::new(bounded(
            &format!(
                "`{name}` enumerates {} affected versions; the first {kept} were kept",
                versions.len()
            ),
            ShortText::MAX_BYTES,
        ))
    {
        notes.push(note);
    }

    // CWE identifiers sit in `database_specific` in every publisher's OSV output. Canonicalised so
    // that `CWE-079` and `CWE-79` are one weakness.
    if let Some(specific) = entry.get("database_specific") {
        for raw in strings_at(specific, "cwe_ids") {
            if let Ok(cwe) = crate::canon::ident::cwe(&raw) {
                records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
                    NodeRef::Entity(vulnerability_id),
                    attribute("vuln.cwe", cwe.value(), field_limit)?,
                    origin.clone(),
                ))));
            }
        }
    }
    if entry.get("ecosystem_specific").is_some() {
        records.push(ParsedRecord::Claim(Box::new(brolga_model::Claim::new(
            NodeRef::Entity(package_id),
            attribute("osv.unread_field", "ecosystem_specific", field_limit)?,
            origin.clone(),
        ))));
    }

    records.push(ParsedRecord::Relationship(Box::new(vuln::affects(
        vulnerability_id,
        package_id,
        origin,
    ))));
    records.push(ParsedRecord::Entity(Box::new(package_entity)));
    Ok((records, notes))
}
