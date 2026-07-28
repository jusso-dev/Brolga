//! Ingestion diagnostics.
//!
//! Every variant here has to answer "what do I do now?" without the operator reading source. A
//! diagnostic that says only *unsupported format* leaves them guessing whether the file is wrong,
//! the media type is wrong, or Brolga simply cannot read it yet — three different actions.

use brolga_model::ModelError;
use brolga_security::Cancelled;
use brolga_storage::StorageError;
use thiserror::Error;

use crate::detect::Candidate;
use crate::parser::ParserId;

/// The result type used across ingestion.
pub type Result<T> = core::result::Result<T, IngestError>;

/// What went wrong while ingesting a document.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IngestError {
    /// No registered parser claimed the input.
    ///
    /// Carries every parser that was asked and the reason each declined, because "nothing matched"
    /// is only actionable alongside what was tried.
    #[error(
        "no registered parser accepted {media_type} ({byte_length} bytes); \
         {} parser(s) were asked and each declined: {}",
        considered.len(),
        Candidate::summarise(considered)
    )]
    UnknownFormat {
        /// The media type the document was offered under.
        media_type: String,
        /// How large the document was.
        byte_length: u64,
        /// Every parser asked, and why it declined. Ordered as the registry ordered them.
        considered: Vec<Candidate>,
    },

    /// Two parsers claimed the input with equal confidence.
    ///
    /// The registry breaks confidence ties by parser identifier so selection stays deterministic,
    /// but a tie at [`crate::detect::DetectionConfidence::Certain`] means two parsers each believe
    /// they are definitively correct, and at most one can be. Resolving it by alphabetical order
    /// would be deterministic and wrong, so it is refused instead.
    #[error(
        "parsers {first} and {second} both claimed {media_type} with certainty; \
         at most one can be correct, so the input is refused rather than resolved by name order"
    )]
    AmbiguousFormat {
        /// The lower identifier of the two.
        first: ParserId,
        /// The higher identifier of the two.
        second: ParserId,
        /// The media type both claimed.
        media_type: String,
    },

    /// The document is larger than [`brolga_security::InputLimits::max_bytes`].
    ///
    /// Checked before a parser is chosen, so an oversized document is rejected without any parser
    /// allocating against it.
    #[error(
        "document is {actual} bytes, over the {limit}-byte input limit; \
         raise `limits.input.max_bytes` or split the document"
    )]
    DocumentTooLarge {
        /// How large the document actually is.
        actual: u64,
        /// The configured ceiling.
        limit: u64,
    },

    /// A parser produced more records than [`brolga_security::InputLimits::max_records`].
    #[error(
        "parser {parser} produced {actual} records, over the {limit}-record limit; \
         raise `limits.input.max_records` or split the document"
    )]
    TooManyRecords {
        /// The parser that produced them.
        parser: ParserId,
        /// How many it produced.
        actual: u64,
        /// The configured ceiling.
        limit: u64,
    },

    /// A parser failed on the document.
    ///
    /// Names the parser and the byte offset where known, so the same document can be inspected at
    /// the point of failure rather than re-read from the start.
    #[error("parser {parser} failed{}: {detail}", Offset(*offset))]
    ParserFailed {
        /// The parser that failed.
        parser: ParserId,
        /// Byte offset into the document, where the parser could identify one.
        offset: Option<u64>,
        /// What went wrong, in the parser's words.
        detail: String,
    },

    /// A parser emitted a record that is not valid against the canonical model.
    ///
    /// A parser bug, not a bad document: the pipeline validates every record before it can reach
    /// storage, so an invalid record is caught here rather than persisted and found later.
    #[error("parser {parser} emitted an invalid record at index {index}: {source}")]
    InvalidRecord {
        /// The parser that emitted it.
        parser: ParserId,
        /// Position in the parser's own output.
        index: usize,
        /// The model's complaint.
        #[source]
        source: ModelError,
    },

    /// The request was cancelled or ran out of time.
    #[error("ingestion stopped: {source}")]
    Cancelled {
        /// Whether it was an explicit cancel or an expired deadline.
        #[source]
        source: Cancelled,
    },

    /// Persistence failed, so the batch was rolled back.
    #[error("ingestion could not be persisted, and the batch was rolled back: {source}")]
    Storage {
        /// The storage layer's complaint.
        #[source]
        source: StorageError,
    },

    /// Building canonical values failed inside the pipeline itself.
    #[error("ingestion could not build a canonical value: {source}")]
    Model {
        /// The model's complaint.
        #[source]
        source: ModelError,
    },
}

impl From<Cancelled> for IngestError {
    fn from(source: Cancelled) -> Self {
        Self::Cancelled { source }
    }
}

impl From<StorageError> for IngestError {
    fn from(source: StorageError) -> Self {
        Self::Storage { source }
    }
}

impl From<ModelError> for IngestError {
    fn from(source: ModelError) -> Self {
        Self::Model { source }
    }
}

/// Renders an optional byte offset into the sentence around it.
///
/// A separate type rather than a `format!` inside the attribute so the "no offset" case reads as a
/// complete sentence instead of trailing an empty parenthesis.
struct Offset(Option<u64>);

impl core::fmt::Display for Offset {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(offset) => write!(formatter, " at byte {offset}"),
            None => Ok(()),
        }
    }
}

/// What a parser reports when it cannot read a document.
///
/// Deliberately not [`IngestError`]: a parser does not know its own registered identifier, and
/// making it construct one would let two parsers disagree about who failed. The pipeline attaches
/// the identifier when it converts this into [`IngestError::ParserFailed`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{detail}")]
pub struct ParseError {
    /// What went wrong, in terms an operator can act on.
    pub detail: String,
    /// Byte offset into the document, where one can be identified.
    pub offset: Option<u64>,
}

impl ParseError {
    /// A failure with no known position.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            offset: None,
        }
    }

    /// A failure at a known byte offset.
    #[must_use]
    pub fn at(offset: u64, detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            offset: Some(offset),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests assert on known-good values; a wrong assumption should fail loudly here"
)]
mod tests {
    use super::*;
    use crate::detect::DetectionConfidence;
    fn candidate(id: &'static str, reason: &'static str) -> Candidate {
        Candidate {
            parser: ParserId::new(id),
            parser_version: 1,
            confidence: DetectionConfidence::Declined,
            reason,
        }
    }

    /// The point of the variant: an operator reading only the message can tell whether the file is
    /// wrong or Brolga simply has no parser for it.
    #[test]
    fn an_unknown_format_names_every_parser_that_was_asked_and_why_it_declined() {
        let error = IngestError::UnknownFormat {
            media_type: "application/xml".to_owned(),
            byte_length: 12,
            considered: vec![
                candidate("brolga.test.jsonl", "first byte is not `{`"),
                candidate("brolga.test.csv", "no delimiter in the first line"),
            ],
        };

        let rendered = error.to_string();
        assert!(rendered.contains("application/xml"), "{rendered}");
        assert!(rendered.contains("2 parser(s)"), "{rendered}");
        assert!(rendered.contains("brolga.test.jsonl"), "{rendered}");
        assert!(rendered.contains("first byte is not `{`"), "{rendered}");
        assert!(rendered.contains("brolga.test.csv"), "{rendered}");
    }

    /// A diagnostic that names no parser cannot be acted on when several are registered.
    #[test]
    fn a_parser_failure_names_the_parser_and_the_offset_when_there_is_one() {
        let with_offset = IngestError::ParserFailed {
            parser: ParserId::new("brolga.test.jsonl"),
            offset: Some(41),
            detail: "unterminated string".to_owned(),
        };
        assert!(with_offset.to_string().contains("at byte 41"));
        assert!(with_offset.to_string().contains("brolga.test.jsonl"));
    }

    /// Without an offset the sentence still has to read properly, rather than trailing an empty
    /// bracket that looks like a formatting bug.
    #[test]
    fn a_parser_failure_without_an_offset_reads_as_a_sentence() {
        let without_offset = IngestError::ParserFailed {
            parser: ParserId::new("brolga.test.jsonl"),
            offset: None,
            detail: "empty document".to_owned(),
        };
        let rendered = without_offset.to_string();
        assert_eq!(
            rendered, "parser brolga.test.jsonl failed: empty document",
            "no stray punctuation where the offset would have been"
        );
    }

    /// Every limit breach has to name the setting that raises it, or the operator has to search
    /// the documentation to act on a message that already knows the answer.
    #[test]
    fn every_limit_diagnostic_names_the_setting_that_raises_it() {
        let too_large = IngestError::DocumentTooLarge {
            actual: 100,
            limit: 10,
        };
        assert!(too_large.to_string().contains("limits.input.max_bytes"));

        let too_many = IngestError::TooManyRecords {
            parser: ParserId::new("brolga.test.jsonl"),
            actual: 100,
            limit: 10,
        };
        assert!(too_many.to_string().contains("limits.input.max_records"));
    }

    /// A certainty tie is a bug in one of the two parsers. Picking a winner alphabetically would
    /// hide it behind deterministic-looking behaviour.
    #[test]
    fn an_ambiguous_format_says_why_it_was_refused_rather_than_resolved() {
        let error = IngestError::AmbiguousFormat {
            first: ParserId::new("brolga.test.a"),
            second: ParserId::new("brolga.test.b"),
            media_type: "application/json".to_owned(),
        };
        let rendered = error.to_string();
        assert!(
            rendered.contains("at most one can be correct"),
            "{rendered}"
        );
        assert!(rendered.contains("brolga.test.a"), "{rendered}");
        assert!(rendered.contains("brolga.test.b"), "{rendered}");
    }

    /// The storage message must say the batch was rolled back. An operator who thinks a partial
    /// batch landed will go looking for which half.
    #[test]
    fn a_storage_failure_says_the_batch_was_rolled_back() {
        let error = IngestError::Storage {
            source: StorageError::Transaction {
                action: "commit",
                reason: "disk full".to_owned(),
            },
        };
        assert!(error.to_string().contains("rolled back"));
    }
}
