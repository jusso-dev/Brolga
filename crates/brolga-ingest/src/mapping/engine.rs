//! Running a mapping, and explaining one without running it.
//!
//! # One parser identifier for every mapping
//!
//! [`MAPPING_PARSER_ID`] is fixed. Every mapping runs under it, and the mapping's own identifier and
//! version go into the record's transformation chain as a [`TransformationStage::Normalisation`] step
//! instead.
//!
//! That is not a compromise, it is the correct place for them. A [`ParserId`] is `&'static str`
//! because every parser at this milestone is compiled in (ADR 0003 §1), and a mapping is loaded at
//! runtime — so making the parser identifier carry the mapping name would mean leaking a string per
//! mapping, for a field that is not the one a reader wants anyway. What a reader wants is "which
//! mapping produced this record, at which version", and that is a provenance question. The chain
//! answers it, and it answers it *per record* rather than per registry entry.
//!
//! # Detection: a mapping is a fallback, never a competitor
//!
//! A mapped parser claims [`DetectionConfidence::Strong`] when the bytes are the shape the mapping
//! declares, and declines otherwise. Never `Certain`: a compiled parser that recognises a format
//! knows more about it than a mapping written against one feed, and a mapping should not take a STIX
//! bundle away from the STIX parser.
//!
//! Declining on a shape mismatch matters as much as claiming on a match. A mapping pointed at the
//! wrong file would otherwise run its paths against a document they cannot match and produce a
//! successful ingest of nothing, which is the failure an operator is least likely to notice.
//!
//! # Everything a record produces
//!
//! One observable — the subject — and claims about it. Nothing else, by design: see
//! [`super`] for why a mapping cannot mint entities or relationships.
//!
//! A record whose subject does not canonicalise is rejected with the value and the reason, so it
//! lands in quarantine rather than vanishing. A record whose *non-subject* field does not canonicalise
//! keeps the record and notes the field, because one bad optional column should not discard an
//! otherwise good indicator.

use brolga_model::{
    Assertion, Claim, Disposition, NodeRef, Observable, RecordOrigin, ShortText, UntrustedText,
    provenance::{TransformationStage, TransformationStep},
};

use super::{
    FieldMapping, Filter, FilterOp, Mapping, Path, PathLimits, SourceShape, Target, transform,
};
use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::delimited;
use crate::formats::xml;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// The identifier every declarative mapping runs under.
///
/// See the module documentation for why this is one identifier rather than one per mapping.
pub const MAPPING_PARSER_ID: ParserId = ParserId::new("brolga.mapping.declarative");

/// Media types that select a declarative mapping definitively.
pub const MAPPING_MEDIA_TYPES: &[&str] = &["application/vnd.brolga.mapped"];

/// Most rows read from a CSV source before the record limit is consulted.
///
/// A guard on the line scan itself, so a file of a hundred million lines is refused while reading
/// rather than after building a hundred million records.
pub const MAX_ROWS_SCANNED: usize = 10_000_000;

/// The truthy spellings a disposition target accepts.
///
/// A closed list. A disposition is the most consequential claim in the model, and an unrecognised
/// string is a rejection rather than a guess in either direction.
pub const TRUTHY: &[&str] = &["true", "yes", "y", "1", "malicious", "bad", "block", "deny"];

/// The falsy spellings a disposition target accepts.
pub const FALSY: &[&str] = &["false", "no", "n", "0", "benign", "good", "allow", "clean"];

/// A parser driven by a mapping document.
#[derive(Debug, Clone)]
pub struct MappedParser {
    mapping: Mapping,
}

impl MappedParser {
    /// Build a parser from a validated mapping.
    ///
    /// Takes a [`Mapping`] rather than bytes: `Mapping::load` validates, so a `MappedParser` can only
    /// be built from a mapping that passed validation.
    #[must_use]
    pub const fn new(mapping: Mapping) -> Self {
        Self { mapping }
    }

    /// Build one boxed, ready for [`crate::ParserRegistry::register`].
    #[must_use]
    pub fn boxed(mapping: Mapping) -> Box<dyn IntelligenceParser> {
        Box::new(Self::new(mapping))
    }

    /// The mapping this parser runs.
    #[must_use]
    pub const fn mapping(&self) -> &Mapping {
        &self.mapping
    }

    /// Describe what this mapping will do, without a document to do it to.
    ///
    /// What `brolga mapping explain` prints. Includes what the mapping *will not* do, because a
    /// description that lists only capabilities reads as a claim that everything else works too.
    #[must_use]
    pub fn explain(&self) -> Explanation {
        Explanation::of(&self.mapping)
    }
}

impl IntelligenceParser for MappedParser {
    fn id(&self) -> ParserId {
        MAPPING_PARSER_ID
    }

    fn version(&self) -> u32 {
        // The engine's version, not the mapping's. The mapping's version travels in the chain, where
        // it belongs — see the module documentation.
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if MAPPING_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type selects a declarative mapping",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        let leading = text.trim_start();

        // Shape agreement only. Never `Certain`: a compiled parser knows more about a format it
        // recognises than a mapping written against one feed.
        let agrees = match self.mapping.source {
            SourceShape::Json => leading.starts_with('{') || leading.starts_with('['),
            SourceShape::Xml => leading.starts_with('<'),
            // Anything that is not JSON or XML could be delimited text. A weaker claim than the other
            // two, and rightly so.
            SourceShape::Csv => {
                !leading.starts_with('{') && !leading.starts_with('[') && !leading.starts_with('<')
            }
        };

        if agrees {
            candidate(
                self,
                DetectionConfidence::Strong,
                "the bytes are the shape this mapping declares",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "the bytes are not the shape this mapping declares",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_bytes {
            return Err(ParseError::new("input is over the byte limit"));
        }
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        // Provenance carrying the mapping's identity, so a record can say which mapping produced it.
        let origin = self.mapped_origin(context)?;

        match self.mapping.source {
            SourceShape::Json => self.parse_json(context, bytes, &origin, field_limit),
            SourceShape::Csv => self.parse_csv(context, bytes, &origin, field_limit),
            SourceShape::Xml => self.parse_xml(context, bytes, &origin, field_limit),
        }
    }
}

impl MappedParser {
    /// A record origin whose chain names this mapping and its version.
    fn mapped_origin(&self, context: &ParseContext) -> Result<RecordOrigin, ParseError> {
        let mut chain = context.chain().clone();
        let algorithm =
            ShortText::new(bounded_name(&format!("brolga.mapping.{}", self.mapping.id))).map_err(
                |error| ParseError::new(format!("unusable mapping identifier: {error}")),
            )?;
        chain
            .push(TransformationStep::new(
                TransformationStage::Normalisation,
                algorithm,
                self.mapping.version,
            ))
            .map_err(|error| {
                ParseError::new(format!(
                    "could not record the mapping in provenance: {error}"
                ))
            })?;

        let provenance = brolga_model::Provenance::from_source(context.source_object(), chain)
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        Ok(RecordOrigin::source_derived(provenance))
    }

    /// Parse a JSON source.
    fn parse_json(
        &self,
        context: &ParseContext,
        bytes: &[u8],
        origin: &RecordOrigin,
        field_limit: usize,
    ) -> Result<ParseOutput, ParseError> {
        let document: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not readable JSON: {error}")))?;
        let path_limits = self.mapping.path_limits();

        // No `records` path means the document itself is one record, which is the shape a
        // single-object feed has.
        let records: Vec<&serde_json::Value> = match &self.mapping.records {
            Some(raw) => {
                let path = Path::parse(raw)
                    .map_err(|error| ParseError::new(format!("record path `{raw}`: {error}")))?;
                path.select_json(&document, path_limits)
                    .map_err(|visited| {
                        ParseError::new(format!(
                            "the record path visited {visited} nodes, over the mapping's \
                         {}-node limit",
                            path_limits.max_nodes
                        ))
                    })?
            }
            None => vec![&document],
        };

        self.check_record_count(records.len())?;

        let mut out = ParseOutput::default();
        for (index, record) in records.iter().enumerate() {
            if index.is_multiple_of(256) {
                context
                    .check_cancelled()
                    .map_err(|error| ParseError::new(error.to_string()))?;
            }
            let reader = Reader::Json(record);
            self.map_one(&reader, index, origin, field_limit, &mut out);
        }

        self.finish(out, limits_of(context))
    }

    /// Parse a delimited source. One row, one record.
    fn parse_csv(
        &self,
        context: &ParseContext,
        bytes: &[u8],
        origin: &RecordOrigin,
        field_limit: usize,
    ) -> Result<ParseOutput, ParseError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|error| ParseError::new(format!("not valid UTF-8: {error}")))?;
        let delimiter = self.mapping.delimiter.unwrap_or(',');

        let mut lines = text
            .lines()
            .map(str::trim_end_matches_carriage_return_shim)
            .filter(|line| !line.trim().is_empty());

        let header = lines
            .next()
            .ok_or_else(|| ParseError::new("the document has no header row"))?;
        let headers: Vec<String> = split_row(header, delimiter);

        let mut out = ParseOutput::default();
        let mut count = 0usize;
        for (index, line) in lines.enumerate() {
            if index >= MAX_ROWS_SCANNED {
                return Err(ParseError::new(format!(
                    "the document has more than the {MAX_ROWS_SCANNED}-row scan limit"
                )));
            }
            if index.is_multiple_of(256) {
                context
                    .check_cancelled()
                    .map_err(|error| ParseError::new(error.to_string()))?;
            }
            count = count.saturating_add(1);
            self.check_record_count(count)?;

            let row = split_row(line, delimiter);
            let reader = Reader::Row {
                headers: &headers,
                row: &row,
            };
            self.map_one(&reader, index, origin, field_limit, &mut out);
        }

        self.finish(out, limits_of(context))
    }

    /// Parse an XML source, through the reader that refuses a DTD.
    fn parse_xml(
        &self,
        context: &ParseContext,
        bytes: &[u8],
        origin: &RecordOrigin,
        field_limit: usize,
    ) -> Result<ParseOutput, ParseError> {
        // The same hostile reader every XML format in this crate uses: any `<!DOCTYPE>` is refused
        // before anything is parsed, which closes the entity-expansion family. A mapping cannot opt
        // out of that, which is the point of it living in the reader rather than in each parser.
        let root = xml::read_document(bytes)?;
        let path_limits = self.mapping.path_limits();

        let records: Vec<&xml::Element> = match &self.mapping.records {
            Some(raw) => {
                let path = Path::parse(raw)
                    .map_err(|error| ParseError::new(format!("record path `{raw}`: {error}")))?;
                path.select_elements(&root, path_limits)
                    .map_err(|visited| {
                        ParseError::new(format!(
                            "the record path visited {visited} nodes, over the mapping's \
                         {}-node limit",
                            path_limits.max_nodes
                        ))
                    })?
            }
            None => vec![&root],
        };

        self.check_record_count(records.len())?;

        let mut out = ParseOutput::default();
        for (index, record) in records.iter().enumerate() {
            if index.is_multiple_of(256) {
                context
                    .check_cancelled()
                    .map_err(|error| ParseError::new(error.to_string()))?;
            }
            let reader = Reader::Xml(record);
            self.map_one(&reader, index, origin, field_limit, &mut out);
        }

        self.finish(out, limits_of(context))
    }

    /// Refuse a document over the mapping's own record ceiling.
    fn check_record_count(&self, count: usize) -> Result<(), ParseError> {
        if u64::try_from(count).unwrap_or(u64::MAX) > self.mapping.limits.max_records {
            return Err(ParseError::new(format!(
                "the document holds {count} records, over the mapping's {}-record limit",
                self.mapping.limits.max_records
            )));
        }
        Ok(())
    }

    /// Final checks shared by all three sources.
    fn finish(
        &self,
        out: ParseOutput,
        limits: brolga_security::InputLimits,
    ) -> Result<ParseOutput, ParseError> {
        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new(format!(
                "the mapping `{}` matched nothing in this document — no record path result, or every \
                 record was filtered out",
                self.mapping.id
            )));
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

    /// Map one record, appending to the output.
    ///
    /// Takes `&mut ParseOutput` rather than returning a result, because a per-record failure is a
    /// rejection to accumulate rather than an error to propagate: one malformed row in a hundred
    /// thousand should not discard the other 99,999.
    fn map_one(
        &self,
        reader: &Reader<'_>,
        index: usize,
        origin: &RecordOrigin,
        field_limit: usize,
        out: &mut ParseOutput,
    ) {
        let path_limits = self.mapping.path_limits();

        // Filters first: a record that does not pass is not a rejection, it is a record this mapping
        // is not about. Recording it as a rejection would fill quarantine with the majority of a feed.
        for filter in &self.mapping.filters {
            match self.passes(filter, reader, path_limits) {
                Ok(true) => {}
                Ok(false) => return,
                Err(reason) => {
                    out.rejected.push(RejectedRecord {
                        reason_kind: "filter_evaluation_failed",
                        reason,
                        offset: u64::try_from(index).ok(),
                        fragment: None,
                    });
                    return;
                }
            }
        }

        let Some(subject_field) = self.mapping.subject_field() else {
            // Unreachable for a validated mapping; handled rather than asserted because a panic is
            // not a supported way to reject input (ADR 0003 §2).
            out.rejected.push(RejectedRecord {
                reason_kind: "mapping_has_no_subject",
                reason: "the mapping names no subject field".to_owned(),
                offset: u64::try_from(index).ok(),
                fragment: None,
            });
            return;
        };

        let raw_subject = match self.values_for(subject_field, reader, path_limits) {
            Ok(values) => values,
            Err(reason) => {
                out.rejected.push(RejectedRecord {
                    reason_kind: "path_limit_exceeded",
                    reason,
                    offset: u64::try_from(index).ok(),
                    fragment: None,
                });
                return;
            }
        };

        let subject_value = match raw_subject.as_slice() {
            [one] => one.clone(),
            [] => {
                out.rejected.push(RejectedRecord {
                    reason_kind: "no_subject_value",
                    reason: format!(
                        "the subject path `{}` selected nothing, so there is nothing for this \
                         record's claims to be about",
                        subject_field.path
                    ),
                    offset: u64::try_from(index).ok(),
                    fragment: None,
                });
                return;
            }
            many => {
                out.rejected.push(RejectedRecord {
                    reason_kind: "ambiguous_subject",
                    reason: format!(
                        "the subject path `{}` selected {} values; a record is about one thing, and \
                         picking the first would attach every other field to an arbitrary choice",
                        subject_field.path,
                        many.len()
                    ),
                    offset: u64::try_from(index).ok(),
                    fragment: many.first().map(|value| canon::preview(value)),
                });
                return;
            }
        };

        let subject = match self.canonicalise(&subject_field.target, &subject_value) {
            Ok(observable) => observable,
            Err(reason) => {
                out.rejected.push(RejectedRecord::at(
                    u64::try_from(index).unwrap_or(u64::MAX),
                    "subject_not_canonical",
                    reason,
                    canon::preview(&subject_value),
                ));
                return;
            }
        };
        let node = NodeRef::Observable(subject.id());

        let mut claims: Vec<Claim> = Vec::new();
        for field in &self.mapping.fields {
            if field.subject {
                continue;
            }
            let values = match self.values_for(field, reader, path_limits) {
                Ok(values) => values,
                Err(reason) => {
                    // A path-limit failure on an optional field keeps the record and says so.
                    if let Ok(note) = ShortText::new(bounded_name(&reason)) {
                        out.notes.push(note);
                    }
                    continue;
                }
            };
            if values.is_empty() && field.required {
                out.rejected.push(RejectedRecord {
                    reason_kind: "required_field_absent",
                    reason: format!(
                        "the required field `{}` selected nothing in this record",
                        field.path
                    ),
                    offset: u64::try_from(index).ok(),
                    fragment: Some(canon::preview(&subject_value)),
                });
                return;
            }

            for value in values {
                match self.claim_for(field, &value, node, origin, field_limit) {
                    Ok(Some(claim)) => claims.push(claim),
                    Ok(None) => {}
                    Err(reason) => {
                        // One unusable optional column does not discard an otherwise good indicator;
                        // it is named instead.
                        if let Ok(note) = ShortText::new(bounded_name(&format!(
                            "field `{}`: {reason}",
                            field.path
                        ))) {
                            out.notes.push(note);
                        }
                    }
                }
            }
        }

        // The subject's own value, claimed, so a record with no other field still says something and
        // the observable is reachable by a claim rather than existing only as a claim subject.
        if let Ok(assertion) = attribute("mapping.subject", &subject.to_string(), field_limit) {
            claims.push(Claim::new(node, assertion, origin.clone()));
        }

        out.records.extend(
            claims
                .into_iter()
                .map(|claim| ParsedRecord::Claim(Box::new(claim))),
        );
    }

    /// Whether a record satisfies one filter.
    fn passes(
        &self,
        filter: &Filter,
        reader: &Reader<'_>,
        limits: PathLimits,
    ) -> Result<bool, String> {
        let path = Path::parse(&filter.path).map_err(|error| error.to_string())?;
        let values = reader.select(&path, limits)?;
        let first = values.first().map(String::as_str).unwrap_or_default();
        let wanted = filter.value.as_deref().unwrap_or_default();

        Ok(match filter.op {
            FilterOp::Equals => values.iter().any(|value| value == wanted),
            FilterOp::NotEquals => !values.iter().any(|value| value == wanted),
            FilterOp::Present => !values.is_empty(),
            FilterOp::Absent => values.is_empty(),
            FilterOp::StartsWith => first.starts_with(wanted),
            FilterOp::Contains => first.contains(wanted),
        })
    }

    /// Every value a field selects, with its transforms applied and its default substituted.
    fn values_for(
        &self,
        field: &FieldMapping,
        reader: &Reader<'_>,
        limits: PathLimits,
    ) -> Result<Vec<String>, String> {
        let path = Path::parse(&field.path).map_err(|error| error.to_string())?;
        let raw = reader.select(&path, limits)?;

        let mut values: Vec<String> = raw
            .into_iter()
            .map(|value| transform::apply_chain(&field.transforms, &value))
            .filter(|value| !value.is_empty())
            .collect();

        // The default substitutes for an absence, not for every value: a field that selected three
        // values and a default is not four values.
        if values.is_empty()
            && let Some(default) = &field.default
            && !default.is_empty()
        {
            values.push(default.clone());
        }
        Ok(values)
    }

    /// Canonicalise a subject value under its target.
    fn canonicalise(&self, target: &Target, value: &str) -> Result<Observable, String> {
        match target {
            Target::Observable { kind } => {
                let canonicalise = canonicaliser_for(kind).ok_or_else(|| {
                    format!("`{kind}` is not an observable kind this build knows")
                })?;
                canonicalise(value)
                    .map(|canonical| canonical.into_value())
                    .map_err(|error| error.to_string())
            }
            Target::Infer => {
                let inference = delimited::infer(value);
                inference.observable.map(canon::Canonical::into_value).ok_or_else(|| {
                    if inference.candidates.len() > 1 {
                        format!(
                            "the value is ambiguous: it could be {}. An inferred subject is only \
                             accepted when exactly one canonicaliser takes it; name the kind in the \
                             mapping to turn the guess into a statement",
                            inference.candidates.join(" or ")
                        )
                    } else {
                        "no canonicaliser accepts the value".to_owned()
                    }
                })
            }
            other => Err(format!(
                "{} is not an observable target, so it cannot be a subject",
                other.as_str()
            )),
        }
    }

    /// The claim one field's value produces, if any.
    fn claim_for(
        &self,
        field: &FieldMapping,
        value: &str,
        subject: NodeRef,
        origin: &RecordOrigin,
        field_limit: usize,
    ) -> Result<Option<Claim>, String> {
        match &field.target {
            Target::Ignore => Ok(None),
            Target::Attribute { name } => Ok(Some(Claim::new(
                subject,
                attribute(name, value, field_limit)?,
                origin.clone(),
            ))),
            Target::Disposition => {
                let lowered = value.trim().to_ascii_lowercase();
                let disposition = if TRUTHY.contains(&lowered.as_str()) {
                    Disposition::Malicious
                } else if FALSY.contains(&lowered.as_str()) {
                    Disposition::Benign
                } else {
                    return Err(format!(
                        "`{}` is not a disposition this build recognises. Truthy: {}. Falsy: {}. An \
                         unrecognised value is refused rather than guessed, because a disposition is \
                         the most consequential claim in the model",
                        canon::preview(value),
                        TRUTHY.join(", "),
                        FALSY.join(", ")
                    ));
                };
                Ok(Some(Claim::new(
                    subject,
                    Assertion::Disposition(disposition),
                    origin.clone(),
                )))
            }
            // A non-subject observable target has nothing to be: a mapping cannot mint a second
            // observable per record, because there would be no stated relationship between them.
            // Recorded as an attribute carrying the canonical form, which keeps the value without
            // inventing an edge.
            Target::Observable { kind } => {
                let canonicalise = canonicaliser_for(kind).ok_or_else(|| {
                    format!("`{kind}` is not an observable kind this build knows")
                })?;
                let canonical = canonicalise(value).map_err(|error| error.to_string())?;
                Ok(Some(Claim::new(
                    subject,
                    attribute(
                        &format!("mapping.{kind}"),
                        &canonical.value().to_string(),
                        field_limit,
                    )?,
                    origin.clone(),
                )))
            }
            Target::Infer => {
                let inference = delimited::infer(value);
                let observable = inference
                    .observable
                    .ok_or_else(|| "no single canonicaliser accepts the value".to_owned())?;
                Ok(Some(Claim::new(
                    subject,
                    attribute(
                        "mapping.observable",
                        &observable.value().to_string(),
                        field_limit,
                    )?,
                    origin.clone(),
                )))
            }
        }
    }
}

/// One record, whichever shape it came in.
enum Reader<'a> {
    Json(&'a serde_json::Value),
    Row {
        headers: &'a [String],
        row: &'a [String],
    },
    Xml(&'a xml::Element),
}

impl Reader<'_> {
    /// Every value a path selects from this record.
    fn select(&self, path: &Path, limits: PathLimits) -> Result<Vec<String>, String> {
        let over = |visited: u64| {
            format!(
                "path `{}` visited {visited} nodes, over the mapping's {}-node limit; the result \
                 would be incomplete, so it is refused rather than truncated",
                path.as_str(),
                limits.max_nodes
            )
        };
        match self {
            Self::Json(value) => path.select_json_strings(value, limits).map_err(over),
            Self::Row { headers, row } => Ok(path.select_row(headers, row).into_iter().collect()),
            Self::Xml(element) => path.select_xml(element, limits).map_err(over),
        }
    }
}

/// Map an observable kind name to its canonicaliser.
///
/// The same names [`super::OBSERVABLE_KINDS`] lists, and validation rejects anything else — so this
/// returning `None` means the two lists have drifted, which
/// `every_documented_kind_has_a_canonicaliser` fails on.
#[must_use]
pub fn canonicaliser_for(kind: &str) -> Option<canon::Canonicaliser> {
    match kind {
        "ip-address" => Some(canon::net::ip_address),
        "ip-range" => Some(canon::net::ip_range),
        "domain-name" => Some(canon::net::domain_name),
        "url" => Some(canon::net::url),
        "email-address" => Some(canon::net::email_address),
        "file-hash" => Some(canon::file::file_hash),
        "file-name" => Some(canon::file::file_name),
        "file-path" => Some(canon::file::file_path),
        _ => None,
    }
}

/// One bounded attribute assertion.
fn attribute(name: &str, value: &str, field_limit: usize) -> Result<Assertion, String> {
    Ok(Assertion::Attribute {
        name: ShortText::new(bounded_name(name)).map_err(|error| error.to_string())?,
        value: UntrustedText::new(bounded_value(
            value,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
        .map_err(|error| error.to_string())?,
    })
}

/// Truncate to [`ShortText::MAX_BYTES`] at a character boundary.
fn bounded_name(value: &str) -> String {
    bounded_value(value, ShortText::MAX_BYTES)
}

/// Truncate at a character boundary.
fn bounded_value(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// The pipeline's input limits, for the shared final check.
fn limits_of(context: &ParseContext) -> brolga_security::InputLimits {
    context.limits().input
}

/// Split one delimited row, honouring double-quoted fields.
///
/// Deliberately minimal: this is not a CSV library, and the flat-format parser is the place for a
/// full one. What it must handle is a quoted field containing the delimiter, because that is the case
/// where a naive split silently shifts every subsequent column.
fn split_row(line: &str, delimiter: char) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();

    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                // A doubled quote inside a quoted field is one literal quote.
                current.push('"');
                let _ = characters.next();
            }
            '"' => quoted = !quoted,
            c if c == delimiter && !quoted => {
                fields.push(core::mem::take(&mut current));
            }
            c => current.push(c),
        }
    }
    fields.push(current);
    fields
        .into_iter()
        .map(|field| field.trim().to_owned())
        .collect()
}

/// A shim so the line iterator reads clearly. `str::lines` already strips `\n` but not `\r`.
trait CarriageReturnShim {
    fn trim_end_matches_carriage_return_shim(&self) -> &str;
}

impl CarriageReturnShim for str {
    fn trim_end_matches_carriage_return_shim(&self) -> &str {
        self.trim_end_matches('\r')
    }
}

/// What a mapping will do, and what it will not.
///
/// Produced by [`MappedParser::explain`] and printed by `brolga mapping explain`. The refusals are
/// part of the output rather than a footnote: a description listing only capabilities reads as a
/// claim that everything else works too.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Explanation {
    /// The mapping's identifier.
    pub id: String,
    /// Its version.
    pub version: u32,
    /// What it is for.
    pub description: Option<String>,
    /// The source shape.
    pub source: &'static str,
    /// The record selector, or a note that the document is one record.
    pub records: String,
    /// One line per filter.
    pub filters: Vec<String>,
    /// One line per field, in declaration order.
    pub fields: Vec<FieldExplanation>,
    /// The bounds it runs under.
    pub limits: LimitExplanation,
    /// What this engine will not do, whatever the mapping says.
    pub refusals: Vec<&'static str>,
}

/// One field, explained.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct FieldExplanation {
    /// The path as written.
    pub path: String,
    /// Where the value goes.
    pub target: String,
    /// The transform chain, in order.
    pub transforms: Vec<&'static str>,
    /// Whether this field is the record's subject.
    pub subject: bool,
    /// Whether a record missing it is rejected.
    pub required: bool,
    /// How many values the path may select.
    pub cardinality: &'static str,
}

/// The bounds, explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct LimitExplanation {
    /// Records per document.
    pub max_records: u64,
    /// Nodes per path evaluation.
    pub max_nodes: u64,
    /// Transforms per field.
    pub max_transforms: usize,
    /// Bytes per transform output.
    pub max_output_bytes: usize,
}

impl Explanation {
    /// Explain a mapping.
    #[must_use]
    pub fn of(mapping: &Mapping) -> Self {
        Self {
            id: mapping.id.clone(),
            version: mapping.version,
            description: mapping.description.clone(),
            source: mapping.source.as_str(),
            records: mapping
                .records
                .clone()
                .unwrap_or_else(|| match mapping.source {
                    SourceShape::Csv => "each row is one record".to_owned(),
                    _ => "the whole document is one record".to_owned(),
                }),
            filters: mapping
                .filters
                .iter()
                .map(|filter| match &filter.value {
                    Some(value) => {
                        format!("`{}` {} `{value}`", filter.path, filter.op.as_str())
                    }
                    None => format!("`{}` is {}", filter.path, filter.op.as_str()),
                })
                .collect(),
            fields: mapping
                .fields
                .iter()
                .map(|field| FieldExplanation {
                    path: field.path.clone(),
                    target: field.target.as_str(),
                    transforms: field
                        .transforms
                        .iter()
                        .map(transform::Transform::name)
                        .collect(),
                    subject: field.subject,
                    required: field.required,
                    cardinality: Path::parse(&field.path).map_or("unparsable", |path| {
                        if path.is_singular() {
                            "at most one value"
                        } else {
                            "many values"
                        }
                    }),
                })
                .collect(),
            limits: LimitExplanation {
                max_records: mapping.limits.max_records,
                max_nodes: mapping.limits.max_nodes,
                max_transforms: transform::MAX_CHAIN,
                max_output_bytes: transform::MAX_OUTPUT_BYTES,
            },
            refusals: REFUSALS.to_vec(),
        }
    }
}

/// What a mapping cannot do, whatever it says.
///
/// Printed with every explanation. These are properties of the engine, not of any one mapping, and a
/// reader deciding whether to trust a mapping from an untrusted source needs them more than they need
/// the field list.
pub const REFUSALS: &[&str] = &[
    "run a shell command, read a file, or open a network connection",
    "execute code: transforms are a closed enum, and an unknown name fails to load",
    "loop, branch, or evaluate an expression — the format has no mechanism for any of the three",
    "mint an entity or a relationship; a mapping produces one observable per record and claims about it",
    "raise its own limits above the ceilings this build enforces",
    "parse an XML document carrying a `<!DOCTYPE>`; a DTD is refused before parsing",
    "read a value the paths cannot reach: no recursive descent, no filter predicates, no slices",
];

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// **The criterion.** Every kind the mapping format documents has a canonicaliser, so validation
    /// accepting a kind and the engine handling it cannot drift.
    #[test]
    fn every_documented_kind_has_a_canonicaliser() {
        for kind in super::super::OBSERVABLE_KINDS {
            assert!(
                canonicaliser_for(kind).is_some(),
                "`{kind}` is documented but has no canonicaliser"
            );
        }
        assert!(canonicaliser_for("mood-ring").is_none());
    }

    #[test]
    fn a_quoted_field_containing_the_delimiter_does_not_shift_the_columns() {
        let row = split_row(r#"a,"b,c",d"#, ',');
        assert_eq!(row, vec!["a", "b,c", "d"]);
        let doubled = split_row(r#""say ""hi""",x"#, ',');
        assert_eq!(doubled, vec![r#"say "hi""#, "x"]);
    }

    #[test]
    fn the_truthy_and_falsy_lists_do_not_overlap() {
        for value in TRUTHY {
            assert!(
                !FALSY.contains(value),
                "`{value}` is both truthy and falsy, so a disposition would depend on check order"
            );
        }
    }
}
