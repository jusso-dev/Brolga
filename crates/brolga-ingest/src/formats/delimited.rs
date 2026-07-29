//! CSV, TSV, JSON arrays, NDJSON, and plain-text indicator lists.
//!
//! # Inference is a guess, and a guess that hides itself is the problem
//!
//! A flat feed publishes `192.0.2.1` with no schema. Brolga has to decide what that *is*, and it
//! will sometimes be wrong: `10.0.0.1` is an IP address and also a plausible version string,
//! `example.124` looks like a domain and is not one, a bare 32-hex string is an MD5 or a UUID or a
//! session token.
//!
//! The failure mode is not being wrong. It is being wrong **silently** — a value inferred as a
//! malicious IP when the column was "internal asset" is worse than a value nobody classified.
//!
//! So inference reports its own confidence, and anything below
//! [`InferenceConfidence::Confident`] is rejected into quarantine rather than guessed at. An
//! operator who wants those rows maps the columns explicitly with [`ColumnMapping`], which turns a
//! guess into a statement.
//!
//! # Spreadsheet formula prefixes are data
//!
//! A CSV field beginning `=`, `+`, `-`, or `@` is a formula injection payload aimed at whatever
//! opens the export in Excel. Brolga stores it **exactly as published** — it is what the source
//! said, and rewriting evidence to make it safe to open elsewhere is the wrong layer. Escaping
//! belongs to the exporter, and the value is flagged here so the exporter knows.
//!
//! # Bounds
//!
//! Line, field, and record counts are bounded, and the reader works line by line rather than
//! materialising a parsed representation of the whole file. A 2 GiB indicator list should cost a
//! line buffer, not 2 GiB of `Vec<Record>`.

use brolga_model::{Assertion, Claim, NodeRef, Observable, RecordOrigin, ShortText, UntrustedText};
use serde_json::Value;

use crate::canon::{self, CanonError, Canonical};
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// The delimited and line-oriented reader's identifier.
pub const DELIMITED_PARSER_ID: ParserId = ParserId::new("brolga.flat.delimited");

/// The JSON array and NDJSON reader's identifier.
pub const JSON_LINES_PARSER_ID: ParserId = ParserId::new("brolga.flat.json");

/// Longest single line accepted.
///
/// A flat feed line is a record. One without a terminator is not a very long record, it is a file
/// with no line breaks, and reading it into memory is the denial of service.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// How sure inference is about what a value represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum InferenceConfidence {
    /// Nothing recognised it.
    None,
    /// It could be several things, and picking one would be a guess.
    Ambiguous,
    /// One interpretation, and the syntax is decisive.
    Confident,
}

/// What inference decided about a value, and how sure it was.
#[derive(Debug, Clone)]
pub struct Inference {
    /// The canonicalised observable, when one was decided on.
    pub observable: Option<Canonical<Observable>>,
    /// How sure inference is.
    pub confidence: InferenceConfidence,
    /// Every interpretation that matched, for a diagnostic.
    pub candidates: Vec<&'static str>,
}

impl Inference {
    /// Nothing matched.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            observable: None,
            confidence: InferenceConfidence::None,
            candidates: Vec::new(),
        }
    }

    /// Whether this inference is usable without an explicit mapping.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self.confidence, InferenceConfidence::Confident)
    }
}

/// A canonicaliser reduced to one signature, so the inference table can hold them all.
type Canonicaliser = fn(&str) -> Result<Canonical<Observable>, CanonError>;

/// Infer what a bare value is.
///
/// Every canonicaliser that accepts the value is recorded. **One acceptance is confident; two or
/// more is ambiguous**, and ambiguous values are not guessed at — they are quarantined with the list
/// of what they could have been, so an operator can map the column and turn the guess into a
/// statement.
#[must_use]
pub fn infer(raw: &str) -> Inference {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Inference::none();
    }

    // Ordered most specific first, so the recorded candidate list reads sensibly. Every one is
    // tried regardless, because the count is what decides confidence.
    let attempts: [(&'static str, Canonicaliser); 6] = [
        ("url", canon::net::url),
        ("ip-range", canon::net::ip_range),
        ("ip-address", canon::net::ip_address),
        ("email-address", canon::net::email_address),
        ("file-hash", canon::file::file_hash),
        ("domain-name", canon::net::domain_name),
    ];

    let mut matched: Vec<(&'static str, Canonical<Observable>)> = Vec::new();
    for (label, canonicalise) in attempts {
        if let Ok(canonical) = canonicalise(trimmed) {
            matched.push((label, canonical));
        }
    }

    match matched.len() {
        0 => Inference::none(),
        1 => {
            let (label, canonical) = matched.remove(0);
            Inference {
                observable: Some(canonical),
                confidence: InferenceConfidence::Confident,
                candidates: vec![label],
            }
        }
        _ => Inference {
            observable: None,
            confidence: InferenceConfidence::Ambiguous,
            candidates: matched.into_iter().map(|(label, _)| label).collect(),
        },
    }
}

/// Which delimiter a file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delimiter {
    /// Comma-separated.
    Comma,
    /// Tab-separated.
    Tab,
    /// Semicolon-separated, as European locales export.
    Semicolon,
    /// One value per line, no delimiter.
    None,
}

impl Delimiter {
    /// The character, where there is one.
    #[must_use]
    pub const fn character(self) -> Option<char> {
        match self {
            Self::Comma => Some(','),
            Self::Tab => Some('\t'),
            Self::Semicolon => Some(';'),
            Self::None => None,
        }
    }

    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Comma => "comma",
            Self::Tab => "tab",
            Self::Semicolon => "semicolon",
            Self::None => "none",
        }
    }
}

/// Sniff the delimiter from the first non-comment lines.
///
/// The winner is the candidate whose field count is both greater than one and **consistent across
/// lines**. Counting occurrences alone picks whichever character happens to appear in the data —
/// a comma inside a description would beat a tab that actually separates the columns.
#[must_use]
pub fn sniff_delimiter(text: &str) -> Delimiter {
    let sample: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .take(10)
        .collect();
    if sample.is_empty() {
        return Delimiter::None;
    }

    let mut best = (Delimiter::None, 1_usize);
    for delimiter in [Delimiter::Tab, Delimiter::Semicolon, Delimiter::Comma] {
        let Some(character) = delimiter.character() else {
            continue;
        };
        let counts: Vec<usize> = sample
            .iter()
            .map(|line| line.matches(character).count())
            .collect();
        let first = counts.first().copied().unwrap_or(0);
        let consistent = first > 0 && counts.iter().all(|count| *count == first);
        if consistent && first.saturating_add(1) > best.1 {
            best = (delimiter, first.saturating_add(1));
        }
    }
    best.0
}

/// An explicit column-to-meaning mapping.
///
/// Turns an inference into a statement. A column mapped as `ip-address` is read as one even when the
/// value would have been ambiguous, because the operator has said what it is.
#[derive(Debug, Clone, Default)]
pub struct ColumnMapping {
    columns: Vec<Option<String>>,
}

impl ColumnMapping {
    /// Build from an ordered list of column kinds, `None` for columns to ignore.
    #[must_use]
    pub fn new(columns: Vec<Option<String>>) -> Self {
        Self { columns }
    }

    /// Infer a mapping from a header row.
    ///
    /// Recognises the header names flat feeds actually publish. An unrecognised header maps to
    /// `None`, so its column is recorded as an attribute rather than guessed at.
    #[must_use]
    pub fn from_header(header: &[&str]) -> Self {
        Self::new(
            header
                .iter()
                .map(|name| {
                    let lowered = name.trim().to_ascii_lowercase().replace([' ', '-'], "_");
                    match lowered.as_str() {
                        "ip" | "ip_address" | "ipv4" | "ipv6" | "address" | "src_ip" | "dst_ip" => {
                            Some("ip-address".to_owned())
                        }
                        "domain" | "hostname" | "host" | "fqdn" => Some("domain-name".to_owned()),
                        "url" | "uri" | "link" => Some("url".to_owned()),
                        "email" | "email_address" | "sender" => Some("email-address".to_owned()),
                        "hash" | "md5" | "sha1" | "sha256" | "sha512" | "file_hash" => {
                            Some("file-hash".to_owned())
                        }
                        "cidr" | "range" | "network" => Some("ip-range".to_owned()),
                        _ => None,
                    }
                })
                .collect(),
        )
    }

    /// The kind mapped to a column, if any.
    #[must_use]
    pub fn kind_at(&self, index: usize) -> Option<&str> {
        self.columns.get(index).and_then(Option::as_deref)
    }

    /// Whether any column was recognised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.columns.iter().all(Option::is_none)
    }
}

/// Whether a field begins with a spreadsheet formula prefix.
///
/// Not sanitised here. The value is what the source published, and rewriting evidence to make it
/// safe to open in Excel is the wrong layer — escaping belongs to the exporter. Flagged so the
/// exporter knows, and so an operator reading quarantine can see it.
#[must_use]
pub fn looks_like_a_formula(field: &str) -> bool {
    matches!(
        field.trim_start().chars().next(),
        Some('=' | '+' | '-' | '@')
    ) && field.trim().len() > 1
        && canon::net::ip_address(field.trim()).is_err()
}

/// Reads CSV, TSV, and plain-text indicator lists.
#[derive(Debug, Default, Clone)]
pub struct DelimitedParser {
    mapping: Option<ColumnMapping>,
}

impl DelimitedParser {
    /// Build one that infers everything.
    #[must_use]
    pub const fn new() -> Self {
        Self { mapping: None }
    }

    /// Build one with an explicit column mapping, which overrides inference.
    #[must_use]
    pub fn with_mapping(mapping: ColumnMapping) -> Self {
        Self {
            mapping: Some(mapping),
        }
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self::new())
    }
}

impl IntelligenceParser for DelimitedParser {
    fn id(&self) -> ParserId {
        DELIMITED_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        if text.trim_start().starts_with(['{', '[']) {
            return candidate(self, DetectionConfidence::Declined, "input looks like JSON");
        }
        match hint.media_type() {
            "text/csv" => {
                return candidate(self, DetectionConfidence::Certain, "media type is text/csv");
            }
            "text/tab-separated-values" => {
                return candidate(self, DetectionConfidence::Certain, "media type is TSV");
            }
            _ => {}
        }
        if hint.has_extension("csv") || hint.has_extension("tsv") {
            return candidate(
                self,
                DetectionConfidence::Strong,
                "file extension is .csv or .tsv",
            );
        }
        match sniff_delimiter(text) {
            Delimiter::None => {
                // A plain list of indicators is a legitimate and very common feed shape, but so is
                // any other line-oriented text. A weak claim lets a specific parser win.
                if text.lines().any(|line| infer(line).is_usable()) {
                    candidate(
                        self,
                        DetectionConfidence::Weak,
                        "lines look like bare indicators",
                    )
                } else {
                    candidate(
                        self,
                        DetectionConfidence::Declined,
                        "no delimiter and no recognisable indicator",
                    )
                }
            }
            _ => candidate(
                self,
                DetectionConfidence::Strong,
                "lines share a consistent delimiter",
            ),
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        let text = decode_utf8(bytes)?;
        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;

        let delimiter = sniff_delimiter(&text);
        let mut out = ParseOutput::default();
        let mut offset = 0_u64;
        let mut records = 0_u64;
        let mut mapping = self.mapping.clone();
        let mut header_consumed = false;

        for line in text.split_inclusive('\n') {
            context
                .check_cancelled()
                .map_err(|error| ParseError::at(offset, error.to_string()))?;

            let line_bytes = u64::try_from(line.len()).unwrap_or(0);
            let trimmed = line.trim_end_matches(['\n', '\r']).trim();

            if line.len() > MAX_LINE_BYTES {
                return Err(ParseError::at(
                    offset,
                    format!(
                        "a line is over the {MAX_LINE_BYTES}-byte limit; this is a file with no line breaks, not a long record"
                    ),
                ));
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                offset = offset.saturating_add(line_bytes);
                continue;
            }

            let fields: Vec<&str> = match delimiter.character() {
                Some(character) => trimmed.split(character).map(str::trim).collect(),
                None => vec![trimmed],
            };

            // A header is only a header if it is the first record *and* nothing on it looks like an
            // indicator. A feed whose first line is data would otherwise lose its first row.
            if !header_consumed {
                header_consumed = true;
                if delimiter != Delimiter::None
                    && fields.iter().all(|field| !infer(field).is_usable())
                {
                    let derived = ColumnMapping::from_header(&fields);
                    if mapping.is_none() && !derived.is_empty() {
                        mapping = Some(derived);
                    }
                    offset = offset.saturating_add(line_bytes);
                    continue;
                }
            }

            records = records.saturating_add(1);
            if records > limits.max_records {
                return Err(ParseError::at(
                    offset,
                    format!("over the {}-record limit", limits.max_records),
                ));
            }

            map_row(
                &fields,
                mapping.as_ref(),
                &origin,
                offset,
                &limits,
                &mut out,
            );
            offset = offset.saturating_add(line_bytes);
        }

        Ok(out)
    }
}

/// Map one row's fields.
fn map_row(
    fields: &[&str],
    mapping: Option<&ColumnMapping>,
    origin: &RecordOrigin,
    offset: u64,
    limits: &brolga_security::InputLimits,
    out: &mut ParseOutput,
) {
    let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

    for (index, field) in fields.iter().enumerate() {
        if field.is_empty() {
            continue;
        }
        if field.len() > field_limit {
            out.rejected.push(RejectedRecord::at(
                offset,
                "field_too_long",
                format!(
                    "a field is {} bytes, over the {field_limit}-byte limit",
                    field.len()
                ),
                bounded(field, 200),
            ));
            continue;
        }

        // An explicit mapping turns a guess into a statement, so it is tried before inference.
        let resolved = match mapping.and_then(|mapping| mapping.kind_at(index)) {
            Some(kind) => canonicalise_as(kind, field).map(|canonical| (canonical, kind)),
            None => {
                let inference = infer(field);
                if inference.is_usable() {
                    inference
                        .observable
                        .map(|canonical| {
                            (
                                canonical,
                                inference.candidates.first().copied().unwrap_or("inferred"),
                            )
                        })
                        .ok_or_else(|| "inference produced no value".to_owned())
                } else if inference.confidence == InferenceConfidence::Ambiguous {
                    out.rejected.push(RejectedRecord::at(
                        offset,
                        "ambiguous_inference",
                        format!(
                            "`{}` could be {} — map the column explicitly rather than letting Brolga guess",
                            bounded(field, 80),
                            inference.candidates.join(" or "),
                        ),
                        bounded(field, 200),
                    ));
                    continue;
                } else {
                    // Not an indicator and not ambiguous — ordinary column content. Not a rejection.
                    continue;
                }
            }
        };

        match resolved {
            Ok((canonical, kind)) => {
                let observable = canonical.value().clone();
                let Ok(name) = ShortText::new(format!("flat.{kind}")) else {
                    continue;
                };
                let Ok(value) = UntrustedText::new(bounded(field, field_limit)) else {
                    continue;
                };

                let mut claim = Claim::new(
                    NodeRef::Observable(observable.id()),
                    Assertion::Attribute { name, value },
                    origin.clone(),
                );

                // The formula prefix is preserved in the value and flagged here, so the exporter
                // knows to escape it and an operator can see why the value looks the way it does.
                if looks_like_a_formula(field)
                    && let Ok(flag) = ShortText::new("flat.spreadsheet_formula_prefix")
                    && let Ok(yes) = UntrustedText::new("true")
                {
                    claim.assertion = Assertion::Attribute {
                        name: flag,
                        value: yes,
                    };
                }
                out.records.push(ParsedRecord::Claim(Box::new(claim)));
            }
            Err(reason) => out.rejected.push(RejectedRecord::at(
                offset,
                "unmappable_field",
                reason,
                bounded(field, 200),
            )),
        }
    }
}

/// Canonicalise a field as an explicitly mapped kind.
fn canonicalise_as(kind: &str, field: &str) -> Result<Canonical<Observable>, String> {
    let result = match kind {
        "ip-address" => canon::net::ip_address(field),
        "ip-range" => canon::net::ip_range(field),
        "domain-name" => canon::net::domain_name(field),
        "url" => canon::net::url(field),
        "email-address" => canon::net::email_address(field),
        "file-hash" => canon::file::file_hash(field),
        other => return Err(format!("`{other}` is not a kind Brolga can canonicalise")),
    };
    result.map_err(|error| error.to_string())
}

/// Reads JSON arrays and NDJSON.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonLinesParser;

impl JsonLinesParser {
    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self)
    }
}

impl IntelligenceParser for JsonLinesParser {
    fn id(&self) -> ParserId {
        JSON_LINES_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        // Never claim STIX or MISP: they are JSON too, and a catch-all JSON reader that outbids a
        // specific parser would silently downgrade every bundle to untyped attributes.
        if compact.contains("\"type\":\"bundle\"") || compact.contains("\"Event\":{") {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "a more specific JSON format claims this",
            );
        }
        if hint.media_type() == "application/x-ndjson" || hint.has_extension("ndjson") {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type or extension is NDJSON",
            );
        }
        let trimmed = text.trim_start();
        if trimmed.starts_with('[') {
            candidate(self, DetectionConfidence::Strong, "input is a JSON array")
        } else if trimmed.starts_with('{')
            && text.lines().filter(|l| !l.trim().is_empty()).count() > 1
        {
            candidate(self, DetectionConfidence::Strong, "input looks like NDJSON")
        } else if trimmed.starts_with('{') {
            candidate(
                self,
                DetectionConfidence::Weak,
                "input is a single JSON object",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "input does not begin `[` or `{`",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        let text = decode_utf8(bytes)?;
        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;

        let mut out = ParseOutput::default();

        if text.trim_start().starts_with('[') {
            let array: Vec<Value> = serde_json::from_str(&text)
                .map_err(|error| ParseError::new(format!("not a JSON array: {error}")))?;
            if u64::try_from(array.len()).unwrap_or(u64::MAX) > limits.max_records {
                return Err(ParseError::new(format!(
                    "array holds {} records, over the {}-record limit",
                    array.len(),
                    limits.max_records
                )));
            }
            for (index, record) in array.iter().enumerate() {
                map_json_record(record, &origin, u64::try_from(index).unwrap_or(0), &mut out);
            }
            return Ok(out);
        }

        // NDJSON: one object per line, decoded one line at a time. A whole-file parse would
        // materialise every record before the first one is usable, which is the thing this format
        // exists to avoid.
        let mut offset = 0_u64;
        let mut records = 0_u64;
        for line in text.split_inclusive('\n') {
            context
                .check_cancelled()
                .map_err(|error| ParseError::at(offset, error.to_string()))?;

            let line_bytes = u64::try_from(line.len()).unwrap_or(0);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                offset = offset.saturating_add(line_bytes);
                continue;
            }
            if line.len() > MAX_LINE_BYTES {
                return Err(ParseError::at(
                    offset,
                    "a line is over the line-length limit",
                ));
            }

            records = records.saturating_add(1);
            if records > limits.max_records {
                return Err(ParseError::at(
                    offset,
                    format!("over the {}-record limit", limits.max_records),
                ));
            }

            match serde_json::from_str::<Value>(trimmed) {
                Ok(record) => map_json_record(&record, &origin, offset, &mut out),
                Err(error) => out.rejected.push(RejectedRecord::at(
                    offset,
                    "malformed_json_line",
                    format!("line is not valid JSON: {error}"),
                    bounded(trimmed, 200),
                )),
            }
            offset = offset.saturating_add(line_bytes);
        }
        Ok(out)
    }
}

/// Map one JSON record's string fields.
fn map_json_record(record: &Value, origin: &RecordOrigin, offset: u64, out: &mut ParseOutput) {
    let Some(fields) = record.as_object() else {
        out.rejected.push(RejectedRecord::at(
            offset,
            "not_an_object",
            "a record must be a JSON object".to_owned(),
            bounded(&record.to_string(), 200),
        ));
        return;
    };

    for (key, value) in fields {
        let Some(raw) = value.as_str() else {
            continue;
        };
        let inference = infer(raw);
        if inference.confidence == InferenceConfidence::Ambiguous {
            out.rejected.push(RejectedRecord::at(
                offset,
                "ambiguous_inference",
                format!(
                    "`{}` in field `{key}` could be {} — map the field explicitly",
                    bounded(raw, 80),
                    inference.candidates.join(" or "),
                ),
                bounded(raw, 200),
            ));
            continue;
        }
        let Some(canonical) = inference.observable else {
            continue;
        };
        let Ok(name) = ShortText::new(format!("flat.{}", bounded(key, 64))) else {
            continue;
        };
        let Ok(text) = UntrustedText::new(bounded(raw, UntrustedText::MAX_BYTES)) else {
            continue;
        };
        out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
            NodeRef::Observable(canonical.value().id()),
            Assertion::Attribute { name, value: text },
            origin.clone(),
        ))));
    }
}

/// Decode input as UTF-8, stripping a byte-order mark.
///
/// A BOM is what a Windows-exported CSV begins with, and leaving it in place makes the first header
/// cell unmatchable — a mapping failure that looks like a data problem.
fn decode_utf8(bytes: &[u8]) -> Result<String, ParseError> {
    let without_bom = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    core::str::from_utf8(without_bom)
        .map(str::to_owned)
        .map_err(|error| {
            ParseError::at(
                u64::try_from(error.valid_up_to()).unwrap_or(0),
                "input is not valid UTF-8; Brolga does not guess at legacy encodings",
            )
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
