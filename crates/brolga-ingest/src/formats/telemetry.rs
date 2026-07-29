//! CEF, LEEF, and syslog records.
//!
//! # Telemetry is not intelligence, and the difference is kept
//!
//! A CEF line says a device fired a signature on some traffic. It does **not** say the addresses in
//! it are malicious — a signature fires on what it matches, including the benign, the allow-listed,
//! and the false positive, and an appliance's own management traffic appears in its logs constantly.
//! So nothing here asserts a [`Disposition`](brolga_model::Disposition). Observables are recorded as
//! having appeared in an event, the event's signature is recorded as the detection it is, and what
//! any of it *means* is left to something that can weigh it.
//!
//! This is the same rule the MISP parser applies to feed presence, for the same reason: the moment
//! "appeared in a log" becomes "malicious", every device on the network is malicious.
//!
//! # A signature is a detection, not a technique and not a tool
//!
//! `deviceVendor|deviceProduct|signatureId` names a rule somebody wrote. It becomes an
//! [`EntityKind::DetectionRule`], keyed on the vendor, product, and signature identifier together —
//! two vendors both numbering a signature `100` have written two different rules, and merging them
//! on the number alone would attribute one vendor's detections to another.
//!
//! # Raw records are preserved, and so are the ambiguities
//!
//! The whole line is retained as a claim, because a normalised field is a reading of a record and
//! the record is the evidence. Extension keys Brolga did not map, and values that did not
//! canonicalise, are named in a claim of their own rather than dropped — an operator asking "why
//! didn't my `dhost` become a domain?" gets an answer from the data instead of from the source.
//!
//! # What is not attempted
//!
//! - **Usernames are not email addresses.** `suser=jsmith` and `suser=j@example.com` are the same
//!   field, and a canonicaliser that took the second would create mailbox observables out of login
//!   names on any site that uses them.
//! - **Syslog priority is not severity.** The `<134>` facility-severity pair describes the *log*,
//!   not the finding, and mapping it onto confidence would let a chatty device outrank a quiet one.
//! - **No timestamp is invented.** RFC 3164 omits the year, so its timestamps are recorded as the
//!   text the device wrote rather than resolved against the clock Brolga happens to be running on.

use std::collections::BTreeMap;

use brolga_model::{
    Assertion, Claim, Entity, EntityKind, Id, NodeRef, Observable, RecordOrigin, Relationship,
    RelationshipKind, ShortText, UntrustedText,
};

use crate::canon::{self, CanonError, Canonical};
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const TELEMETRY_PARSER_ID: ParserId = ParserId::new("brolga.telemetry.event");

/// Media types that identify these records definitively.
pub const TELEMETRY_MEDIA_TYPES: &[&str] = &["text/x-cef", "text/x-leef", "application/x-syslog"];

/// Longest single record read.
///
/// A syslog line is bounded by the transport in practice; this bounds it here too, so a file with
/// no newline in it costs a buffer rather than the file.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Most extension key-value pairs read from one record.
pub const MAX_EXTENSION_PAIRS: usize = 256;

/// Which of the three shapes a record turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordShape {
    /// ArcSight Common Event Format.
    Cef,
    /// IBM QRadar Log Event Extended Format.
    Leef,
    /// A syslog line carrying neither.
    Syslog,
}

impl RecordShape {
    /// The prefix this shape's claims are named under.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Cef => "cef",
            Self::Leef => "leef",
            Self::Syslog => "syslog",
        }
    }
}

/// A CEF, LEEF, and syslog reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct TelemetryParser;

impl TelemetryParser {
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

impl IntelligenceParser for TelemetryParser {
    fn id(&self) -> ParserId {
        TELEMETRY_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if TELEMETRY_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is a telemetry record format",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // Judged on the first non-empty line, after any syslog frame. A file of CEF delivered over
        // syslog is a file of CEF, and deciding on the frame rather than the payload would file it
        // under the weaker shape.
        let Some(first) = text.lines().find(|line| !line.trim().is_empty()) else {
            return candidate(self, DetectionConfidence::Declined, "input is empty");
        };
        let (_, payload) = strip_syslog_frame(first.trim());

        if payload.starts_with("CEF:") {
            candidate(self, DetectionConfidence::Certain, "first record is CEF")
        } else if payload.starts_with("LEEF:") {
            candidate(self, DetectionConfidence::Certain, "first record is LEEF")
        } else if first.trim_start().starts_with('<') && payload != first.trim() {
            // A priority the frame reader actually consumed, rather than a line that merely begins
            // with a bracket — XML would otherwise claim to be syslog.
            candidate(
                self,
                DetectionConfidence::Strong,
                "first record carries a syslog priority",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no CEF, LEEF, or syslog marker in the first record",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;

        let text = core::str::from_utf8(bytes)
            .map_err(|error| ParseError::new(format!("not valid UTF-8: {error}")))?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let mut out = ParseOutput::default();
        let mut seen: u64 = 0;

        for (index, line) in text.lines().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            let line = line.trim_end_matches('\r').trim();
            if line.is_empty() {
                continue;
            }

            seen = seen.saturating_add(1);
            if seen > limits.max_records {
                return Err(ParseError::new(format!(
                    "input holds more than the {}-record limit",
                    limits.max_records
                )));
            }

            if line.len() > MAX_RECORD_BYTES {
                out.rejected.push(RejectedRecord {
                    reason_kind: "record_too_long",
                    reason: format!(
                        "the record is {} bytes, over the {MAX_RECORD_BYTES}-byte limit",
                        line.len()
                    ),
                    offset: u64::try_from(index).ok(),
                    fragment: Some(bounded(line, 200)),
                });
                continue;
            }

            match map_record(line, &origin, field_limit) {
                Ok(records) => out.records.extend(records),
                Err(rejection) => out.rejected.push(RejectedRecord {
                    reason_kind: rejection.0,
                    reason: rejection.1,
                    offset: u64::try_from(index).ok(),
                    // The whole record, bounded. A telemetry line an operator has to diagnose is
                    // useless summarised, and it is what the device actually wrote.
                    fragment: Some(bounded(line, 512)),
                }),
            }
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

/// Strip an RFC 3164 or RFC 5424 frame, returning the frame text and the payload.
///
/// The frame is returned rather than discarded: it names the host the record came from, which is
/// the one piece of a syslog envelope that says where evidence originated.
#[must_use]
pub fn strip_syslog_frame(line: &str) -> (Option<&str>, &str) {
    let Some(rest) = line.strip_prefix('<') else {
        return (None, line);
    };
    let Some((priority, rest)) = rest.split_once('>') else {
        return (None, line);
    };
    // A priority is one to three digits. Anything else is a line that merely started with `<`.
    if priority.is_empty() || priority.len() > 3 || !priority.bytes().all(|b| b.is_ascii_digit()) {
        return (None, line);
    }

    // RFC 5424 puts a version digit and a space next; RFC 3164 goes straight to the timestamp.
    // Either way the payload is what follows the header fields, and the header is bounded by the
    // point at which a known payload marker appears. Looking for the marker rather than parsing
    // the header is deliberate: syslog headers are widely malformed, and a strict header parser
    // would reject records whose *payload* is perfectly readable.
    for marker in ["CEF:", "LEEF:"] {
        if let Some(position) = rest.find(marker) {
            let (frame, payload) = rest.split_at(position);
            return (Some(frame.trim()), payload);
        }
    }
    (Some(""), rest)
}

/// Map one record to the entity, claims, and relationships it becomes.
fn map_record(
    line: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, (&'static str, String)> {
    let (frame, payload) = strip_syslog_frame(line);

    let (shape, header, extension) = if let Some(rest) = payload.strip_prefix("CEF:") {
        let (header, extension) = split_cef(rest)?;
        (RecordShape::Cef, header, extension)
    } else if let Some(rest) = payload.strip_prefix("LEEF:") {
        let (header, extension) = split_leef(rest)?;
        (RecordShape::Leef, header, extension)
    } else if frame.is_some() {
        (RecordShape::Syslog, Vec::new(), payload.to_owned())
    } else {
        return Err((
            "unrecognised_record",
            "the record is neither CEF, nor LEEF, nor a syslog line with a priority".to_owned(),
        ));
    };

    let pairs = parse_extension(shape, &extension)?;

    let mut records = Vec::new();
    let mut unmapped: Vec<String> = Vec::new();
    let mut observables: Vec<Observable> = Vec::new();

    for (key, value) in &pairs {
        match observable_for(shape, key, value) {
            Some(Ok(observable)) => {
                let observable = observable.into_value();
                if !observables
                    .iter()
                    .any(|existing| existing.id() == observable.id())
                {
                    observables.push(observable);
                }
            }
            // A key Brolga maps whose value did not canonicalise. Named, because "my `dst` is
            // missing" needs an answer from the data rather than from the source.
            Some(Err(error)) => unmapped.push(format!("{key} ({error})")),
            None => {}
        }
    }

    // The signature is the detection the device fired. Only CEF and LEEF name one; a bare syslog
    // line does not, and inventing a rule from the message text would fabricate a detection nobody
    // wrote.
    let rule = signature_entity(shape, &header, origin, field_limit)?;

    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());

        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute(
                &format!("{}.raw", shape.prefix()),
                line,
                field_limit.min(UntrustedText::MAX_BYTES),
            )?,
            origin.clone(),
        ))));

        if !unmapped.is_empty() {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(
                    &format!("{}.unmapped", shape.prefix()),
                    &unmapped.join(", "),
                    field_limit.min(UntrustedText::MAX_BYTES),
                )?,
                origin.clone(),
            ))));
        }

        if let Some(rule) = &rule {
            records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
                // The observable was part of the event the signature fired on. Not `Indicates`,
                // which would say the observable is evidence *of* the rule, and not `Uses`, which
                // would make a defender's detection an attacker's instrument.
                RelationshipKind::PartOf,
                subject,
                NodeRef::Entity(rule.id),
                origin.clone(),
            ))));
        }
    }

    // Ordered after the claims that reference it so a reader of this function sees the dependency,
    // though the pipeline sorts records by kind before writing either way.
    if let Some(rule) = rule {
        let rule_ref = NodeRef::Entity(rule.id);
        records.push(ParsedRecord::Entity(Box::new(rule)));

        // The raw record and the ambiguities hang off the signature too, so a record that named no
        // observable at all is still retrievable as evidence rather than only as a quarantine
        // fragment. This is the case that matters most: a record where *every* mapped key failed is
        // exactly the one an operator is trying to diagnose, and it is the one where attaching the
        // report to an observable is impossible because there is no observable.
        if observables.is_empty() {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                rule_ref,
                attribute(
                    &format!("{}.raw", shape.prefix()),
                    line,
                    field_limit.min(UntrustedText::MAX_BYTES),
                )?,
                origin.clone(),
            ))));

            if !unmapped.is_empty() {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    rule_ref,
                    attribute(
                        &format!("{}.unmapped", shape.prefix()),
                        &unmapped.join(", "),
                        field_limit.min(UntrustedText::MAX_BYTES),
                    )?,
                    origin.clone(),
                ))));
            }
        }
    } else if observables.is_empty() {
        return Err((
            "nothing_mappable",
            "the record names no signature and no observable Brolga canonicalises, so it would \
             store an event about nothing"
                .to_owned(),
        ));
    }

    Ok(records)
}

/// Build the detection-rule entity a CEF or LEEF header names.
fn signature_entity(
    shape: RecordShape,
    header: &[String],
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Option<Entity>, (&'static str, String)> {
    // CEF: version|vendor|product|version|signature id|name|severity
    // LEEF: version|vendor|product|version|event id
    let (vendor, product, signature, name) = match shape {
        RecordShape::Cef => (
            header.get(1),
            header.get(2),
            header.get(4),
            header.get(5).or_else(|| header.get(4)),
        ),
        RecordShape::Leef => (header.first(), header.get(1), header.get(3), header.get(3)),
        RecordShape::Syslog => return Ok(None),
    };

    let (Some(vendor), Some(product), Some(signature), Some(name)) =
        (vendor, product, signature, name)
    else {
        return Err((
            "incomplete_header",
            format!(
                "the {} header does not name a vendor, product, and signature",
                shape.prefix()
            ),
        ));
    };

    let display = UntrustedText::new(bounded(name, field_limit.min(UntrustedText::MAX_BYTES)))
        .map_err(|error| ("unusable_signature_name", error.to_string()))?;

    // Keyed on all three together. Two vendors both numbering a signature `100` wrote two rules,
    // and merging them on the number would attribute one vendor's detections to the other.
    let id = Id::derive(&[
        shape.prefix(),
        &vendor.to_lowercase(),
        &product.to_lowercase(),
        signature,
    ]);

    let mut entity = Entity::new(id, EntityKind::DetectionRule, display, origin.clone());
    if let Ok(text) = UntrustedText::new(format!("{vendor} {product} signature {signature}")) {
        entity.description = Some(text);
    }
    Ok(Some(entity))
}

/// Split a CEF payload into its seven header fields and its extension.
///
/// `\|` is a literal pipe and `\\` a literal backslash, so a signature name containing a pipe does
/// not silently become two fields — which would shift every field after it by one and file the
/// event under the wrong signature.
fn split_cef(rest: &str) -> Result<(Vec<String>, String), (&'static str, String)> {
    let fields = split_escaped(rest, '|');
    if fields.len() < 7 {
        return Err((
            "incomplete_header",
            format!(
                "a CEF record has seven header fields, found {}",
                fields.len()
            ),
        ));
    }
    let extension = fields
        .get(7..)
        .map(|rest| rest.join("|"))
        .unwrap_or_default();
    let header = fields.get(..7).map(<[String]>::to_vec).unwrap_or_default();
    Ok((header, extension))
}

/// Split a LEEF payload into its header fields and its extension.
///
/// LEEF 2.0 adds a delimiter field naming the character its extension uses. It is honoured rather
/// than assumed: a record that declared `^` and was read with tabs would parse as one enormous key.
fn split_leef(rest: &str) -> Result<(Vec<String>, String), (&'static str, String)> {
    let fields = split_escaped(rest, '|');
    // LEEF 1.0: version|vendor|product|version|eventid|extension  (5 header fields)
    // LEEF 2.0: version|vendor|product|version|eventid|delimiter|extension
    let version_is_2 = rest.starts_with("2.");
    let header_len = if version_is_2 { 6 } else { 5 };
    if fields.len() < header_len {
        return Err((
            "incomplete_header",
            format!(
                "a LEEF record has {header_len} header fields, found {}",
                fields.len()
            ),
        ));
    }

    let extension = fields
        .get(header_len..)
        .map(|rest| rest.join("|"))
        .unwrap_or_default();
    // The header the signature is built from starts after the LEEF version, so the indices match
    // CEF's vendor/product ordering minus its leading version.
    let header = fields
        .get(1..header_len)
        .map(<[String]>::to_vec)
        .unwrap_or_default();

    let delimiter = if version_is_2 {
        fields.get(5).and_then(|raw| leef_delimiter(raw))
    } else {
        None
    };
    let normalised = match delimiter {
        Some(character) => extension.replace(character, "\t"),
        None => extension,
    };
    Ok((header, normalised))
}

/// Read a LEEF 2.0 delimiter field, which may be a literal character or `x` followed by a hex code.
fn leef_delimiter(raw: &str) -> Option<char> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("x")
        .or_else(|| trimmed.strip_prefix("0x"))
        && let Ok(code) = u32::from_str_radix(hex, 16)
    {
        return char::from_u32(code);
    }
    let mut characters = trimmed.chars();
    match (characters.next(), characters.next()) {
        (Some(character), None) => Some(character),
        _ => None,
    }
}

/// Split on a delimiter, honouring backslash escapes.
fn split_escaped(value: &str, delimiter: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut characters = value.chars();

    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some(escaped) => current.push(escaped),
                None => current.push('\\'),
            },
            character if character == delimiter => {
                fields.push(core::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }
    fields.push(current);
    fields
}

/// Read the `key=value` pairs of an extension.
///
/// CEF separates pairs with spaces and permits unquoted spaces *inside* values, so a pair ends
/// where the next `key=` begins rather than at the next space. Splitting on whitespace would cut
/// every message field in half.
fn parse_extension(
    shape: RecordShape,
    extension: &str,
) -> Result<Vec<(String, String)>, (&'static str, String)> {
    let extension = extension.trim();
    if extension.is_empty() {
        return Ok(Vec::new());
    }

    let raw_pairs: Vec<&str> = match shape {
        // LEEF uses a hard delimiter, normalised to a tab by the header reader.
        RecordShape::Leef => extension.split('\t').collect(),
        RecordShape::Cef | RecordShape::Syslog => split_cef_extension(extension),
    };

    let mut pairs = Vec::new();
    for raw in raw_pairs {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((key, value)) = raw.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        if pairs.len() >= MAX_EXTENSION_PAIRS {
            return Err((
                "extension_pairs_exceeded",
                format!(
                    "the record holds more than {MAX_EXTENSION_PAIRS} extension pairs; it is \
                     refused whole rather than truncated, because a truncated event reports fewer \
                     fields than the device wrote"
                ),
            ));
        }
        pairs.push((key.to_owned(), unescape(value)));
    }
    Ok(pairs)
}

/// Split a CEF extension into pairs, cutting before each `key=` rather than at each space.
fn split_cef_extension(extension: &str) -> Vec<&str> {
    let bytes = extension.as_bytes();
    let mut cuts = vec![0_usize];

    // A cut point is a space that is followed by `<key>=`, where the key holds no space and no
    // equals. That is what distinguishes `msg=login failed src=…` from a value that merely
    // contains a space.
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b' ' {
            continue;
        }
        let after = index.saturating_add(1);
        let Some(rest) = extension.get(after..) else {
            continue;
        };
        let key: &str = match rest.split_once('=') {
            Some((key, _)) => key,
            None => continue,
        };
        if !key.is_empty() && !key.contains(' ') && !key.contains('\\') {
            cuts.push(after);
        }
    }

    let mut pairs = Vec::with_capacity(cuts.len());
    for (position, start) in cuts.iter().enumerate() {
        let end = cuts.get(position.saturating_add(1)).copied();
        let slice = match end {
            Some(end) => extension.get(*start..end.saturating_sub(1)),
            None => extension.get(*start..),
        };
        if let Some(slice) = slice {
            pairs.push(slice);
        }
    }
    pairs
}

/// Undo the escapes a value may carry.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// The observable an extension key names, if Brolga maps that key at all.
///
/// `None` means the key is not one this parser reads. `Some(Err(..))` means it is, and the value
/// did not canonicalise — a difference the caller reports rather than collapses, because "not a
/// field we read" and "a field we read that was unusable" send an operator to different places.
fn observable_for(
    shape: RecordShape,
    key: &str,
    value: &str,
) -> Option<Result<Canonical<Observable>, CanonError>> {
    let _ = shape;
    let canonicaliser: fn(&str) -> Result<Canonical<Observable>, CanonError> =
        match key.trim().to_ascii_lowercase().as_str() {
            // Addresses. `dvc`/`deviceAddress` is the reporting appliance itself, which is an
            // address worth holding — it says where evidence came from.
            "src" | "dst" | "sourceaddress" | "destinationaddress" | "dvc" | "deviceaddress"
            | "srcip" | "dstip" | "identsrc" | "identhostname" => canon::net::ip_address,
            // Host and domain fields. A single-label hostname is not a DNS name and will fail
            // canonicalisation, which is reported rather than coerced into one.
            "dhost"
            | "shost"
            | "destinationhostname"
            | "sourcehostname"
            | "dntdom"
            | "sntdom"
            | "destinationdnsdomain"
            | "sourcednsdomain"
            | "domain"
            | "srchost"
            | "dsthost" => canon::net::domain_name,
            "request" | "requesturl" | "url" | "uri" => canon::net::url,
            "filehash" | "oldfilehash" | "md5" | "sha1" | "sha256" | "hash" => {
                canon::file::file_hash
            }
            "fname" | "filename" | "oldfilename" => canon::file::file_name,
            // Deliberately absent: `suser`, `duser`, `sourceUserName`, `destinationUserName`. A
            // login name and an email address share these fields, and reading the second would mint
            // mailbox observables out of usernames on any site whose logins look like addresses.
            _ => return None,
        };
    Some(canonicaliser(value))
}

/// One attribute assertion.
fn attribute(name: &str, value: &str, limit: usize) -> Result<Assertion, (&'static str, String)> {
    Ok(Assertion::Attribute {
        name: ShortText::new(name)
            .map_err(|error| ("unusable_attribute_name", error.to_string()))?,
        value: UntrustedText::new(bounded(value, limit))
            .map_err(|error| ("unusable_attribute_value", error.to_string()))?,
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

/// The extension keys of a record, for a caller that wants to see what a device published.
///
/// Exposed because "which fields does my appliance actually send?" is the first question an
/// operator asks when a mapping produces less than they expected, and answering it from the data
/// beats answering it from a vendor's documentation.
///
/// # Errors
///
/// Returns the reason the record could not be split into pairs.
pub fn extension_keys(line: &str) -> Result<Vec<String>, String> {
    let (_, payload) = strip_syslog_frame(line.trim());
    let (shape, extension) = if let Some(rest) = payload.strip_prefix("CEF:") {
        let (_, extension) = split_cef(rest).map_err(|error| error.1)?;
        (RecordShape::Cef, extension)
    } else if let Some(rest) = payload.strip_prefix("LEEF:") {
        let (_, extension) = split_leef(rest).map_err(|error| error.1)?;
        (RecordShape::Leef, extension)
    } else {
        (RecordShape::Syslog, payload.to_owned())
    };

    let pairs = parse_extension(shape, &extension).map_err(|error| error.1)?;
    let mut keys: BTreeMap<String, ()> = BTreeMap::new();
    for (key, _) in pairs {
        keys.insert(key, ());
    }
    Ok(keys.into_keys().collect())
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
    fn a_cef_header_splits_into_its_seven_fields() {
        let (header, extension) =
            split_cef("0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1").unwrap();
        assert_eq!(header.len(), 7);
        assert_eq!(header[1], "Security");
        assert_eq!(header[5], "worm stopped");
        assert_eq!(extension, "src=10.0.0.1");
    }

    /// An escaped pipe inside a signature name must not become a field boundary. If it did, every
    /// field after it shifts by one and the event is filed under the wrong signature.
    #[test]
    fn an_escaped_pipe_in_a_header_field_is_not_a_boundary() {
        let (header, _) =
            split_cef("0|Security|threatmanager|1.0|100|detected a\\|b|10|src=10.0.0.1").unwrap();
        assert_eq!(header[5], "detected a|b");
        assert_eq!(header[6], "10");
    }

    /// CEF permits unquoted spaces inside values, so a pair ends where the next `key=` begins.
    /// Splitting on whitespace would cut every message field in half.
    #[test]
    fn a_cef_value_may_hold_spaces() {
        let pairs = parse_extension(
            RecordShape::Cef,
            "src=10.0.0.1 msg=login failed for user dst=10.0.0.2",
        )
        .unwrap();
        let map: BTreeMap<_, _> = pairs.into_iter().collect();
        assert_eq!(
            map.get("msg").map(String::as_str),
            Some("login failed for user")
        );
        assert_eq!(map.get("dst").map(String::as_str), Some("10.0.0.2"));
    }

    #[test]
    fn an_escaped_equals_stays_inside_a_value() {
        let pairs = parse_extension(RecordShape::Cef, "msg=a\\=b src=10.0.0.1").unwrap();
        let map: BTreeMap<_, _> = pairs.into_iter().collect();
        assert_eq!(map.get("msg").map(String::as_str), Some("a=b"));
    }

    #[test]
    fn a_syslog_frame_is_stripped_from_a_cef_payload() {
        let (frame, payload) = strip_syslog_frame(
            "<134>Jan  1 00:00:00 gateway CEF:0|Security|tm|1.0|100|worm|10|src=10.0.0.1",
        );
        assert!(frame.unwrap().contains("gateway"));
        assert!(payload.starts_with("CEF:0|"));
    }

    /// A line that merely begins with `<` is not syslog. XML would otherwise be claimed here.
    #[test]
    fn a_bracket_that_is_not_a_priority_is_not_a_frame() {
        let (frame, payload) = strip_syslog_frame("<IODEF-Document version=\"1.00\">");
        assert!(frame.is_none());
        assert_eq!(payload, "<IODEF-Document version=\"1.00\">");
    }

    #[test]
    fn leef_2_honours_the_delimiter_it_declares() {
        let (_, extension) = split_leef("2.0|Vendor|Product|1.0|E100|^|src=10.0.0.1^dst=10.0.0.2")
            .expect("a LEEF 2.0 record");
        let pairs = parse_extension(RecordShape::Leef, &extension).unwrap();
        assert_eq!(pairs.len(), 2, "{pairs:?}");
    }

    #[test]
    fn a_leef_delimiter_may_be_written_as_a_hex_code() {
        assert_eq!(leef_delimiter("x09"), Some('\t'));
        assert_eq!(leef_delimiter("^"), Some('^'));
    }

    /// A username is not an email address, and the fields that carry both are not read.
    #[test]
    fn user_fields_are_not_read_as_email_addresses() {
        assert!(observable_for(RecordShape::Cef, "suser", "j@example.com").is_none());
        assert!(observable_for(RecordShape::Cef, "duser", "jsmith").is_none());
    }

    /// A mapped key whose value is unusable is distinguishable from a key that is not mapped.
    #[test]
    fn an_unusable_value_is_reported_rather_than_treated_as_an_unread_key() {
        assert!(observable_for(RecordShape::Cef, "notakey", "10.0.0.1").is_none());
        assert!(
            observable_for(RecordShape::Cef, "src", "not an address").is_some_and(|r| r.is_err())
        );
    }
}
