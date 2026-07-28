//! A reference parser, for exercising the pipeline without a real format.
//!
//! ADR 0003 §1 permits a test parser and no other at this milestone. It exists so the pipeline's
//! own behaviour — selection, limits, stage metrics, batch ordering, transaction rollback — can be
//! tested against something whose output is obvious, rather than against a STIX bundle where a
//! failure could be the pipeline or could be the STIX reader.
//!
//! Behind the `testing` feature, off by default, so it cannot be registered in a shipped binary.
//!
//! # The format
//!
//! One record per line. Blank lines and lines beginning with `#` are skipped, with a note. Every
//! other line is `entity:<name>`. Anything else is an error carrying its byte offset.

use brolga_model::{Entity, EntityKind, Id, ShortText, UntrustedText};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, candidate,
};

/// The media type this parser is certain about.
pub const TEST_MEDIA_TYPE: &str = "application/vnd.brolga.test-records";

/// The reference parser's identifier.
pub const TEST_PARSER_ID: ParserId = ParserId::new("brolga.test.records");

/// A deliberately simple line-oriented parser.
#[derive(Debug, Default, Clone, Copy)]
pub struct TestRecordsParser;

impl TestRecordsParser {
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

impl IntelligenceParser for TestRecordsParser {
    fn id(&self) -> ParserId {
        TEST_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        // Certain on the media type it owns; strong on shape alone. The gap is what lets a
        // registry test tell a decisive claim from a probable one.
        let (confidence, reason) = if hint.media_type() == TEST_MEDIA_TYPE {
            (DetectionConfidence::Certain, "media type is exactly ours")
        } else if hint.has_extension("brolgatest") {
            (DetectionConfidence::Strong, "file extension is .brolgatest")
        } else if hint
            .first_line()
            .is_some_and(|line| line.starts_with("entity:"))
        {
            (DetectionConfidence::Strong, "first line begins `entity:`")
        } else if hint.prefix_str().is_none() {
            (DetectionConfidence::Declined, "input is not valid UTF-8")
        } else {
            (
                DetectionConfidence::Declined,
                "no `entity:` line and no recognised media type or extension",
            )
        };

        candidate(self, confidence, reason)
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let text = core::str::from_utf8(bytes).map_err(|error| {
            ParseError::at(offset_of(error.valid_up_to()), "input is not UTF-8")
        })?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;

        let mut records = Vec::new();
        let mut notes = Vec::new();
        let mut offset: u64 = 0;

        for line in text.split_inclusive('\n') {
            // Between records, not only between documents: a long file must remain interruptible.
            context
                .check_cancelled()
                .map_err(|error| ParseError::at(offset, error.to_string()))?;

            let trimmed = line.trim();
            let line_bytes = u64::try_from(line.len()).unwrap_or(0);

            if trimmed.is_empty() {
                offset = offset.saturating_add(line_bytes);
                continue;
            }
            if let Some(comment) = trimmed.strip_prefix('#') {
                notes.push(note(&format!("skipped comment at byte {offset}"), comment)?);
                offset = offset.saturating_add(line_bytes);
                continue;
            }

            let name = trimmed.strip_prefix("entity:").ok_or_else(|| {
                ParseError::at(
                    offset,
                    "expected a line beginning `entity:`, a blank line, or a `#` comment",
                )
            })?;
            let name = name.trim();
            if name.is_empty() {
                return Err(ParseError::at(offset, "`entity:` with no name"));
            }
            if u64::try_from(name.len()).unwrap_or(u64::MAX)
                > context.limits().input.max_field_bytes
            {
                return Err(ParseError::at(
                    offset,
                    format!(
                        "name is longer than the {}-byte field limit",
                        context.limits().input.max_field_bytes
                    ),
                ));
            }

            let name_text = UntrustedText::new(name)
                .map_err(|error| ParseError::at(offset, format!("unusable name: {error}")))?;

            records.push(ParsedRecord::Entity(Box::new(Entity::new(
                // Derived from the name alone, so the same name in two documents is one entity.
                // That is what makes the batch-ordering test meaningful rather than tautological.
                Id::derive(&[name]),
                EntityKind::ThreatActor,
                name_text,
                origin.clone(),
            ))));

            offset = offset.saturating_add(line_bytes);
        }

        Ok(ParseOutput { records, notes })
    }
}

/// A parser that claims everything weakly and produces nothing.
///
/// For testing that a weak claim loses to a strong one, and that a catch-all does not swallow
/// documents a specific parser would have read.
#[derive(Debug, Default, Clone, Copy)]
pub struct CatchAllParser;

impl CatchAllParser {
    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self)
    }
}

impl IntelligenceParser for CatchAllParser {
    fn id(&self) -> ParserId {
        ParserId::new("brolga.test.catch-all")
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, _hint: &FormatHint<'_>) -> Candidate {
        candidate(
            self,
            DetectionConfidence::Weak,
            "claims anything, as a last resort",
        )
    }

    fn parse(&self, _context: &ParseContext, _bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        Ok(ParseOutput::default())
    }
}

/// Convert a `usize` offset without an `as` cast, saturating rather than wrapping.
fn offset_of(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Build a note, keeping the untrusted half short and stripping control characters.
///
/// The comment body comes from the document, so it is exactly the kind of value that must not
/// reach a log line unfiltered — a terminal escape sequence in a feed's comment would otherwise be
/// rendered by whatever reads the note.
fn note(prefix: &str, untrusted: &str) -> Result<ShortText, ParseError> {
    let cleaned: String = untrusted
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect();
    ShortText::new(format!("{prefix}: {cleaned}"))
        .map_err(|error| ParseError::new(format!("could not record a note: {error}")))
}
