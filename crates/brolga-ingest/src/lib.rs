//! Brolga's ingestion layer: the parser contract, the registry that chooses between parsers, and
//! the pipeline that runs one.
//!
//! Added by [ADR 0003](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0003-ingestion-crate-boundary-and-parser-panic-policy.md),
//! which amends ADR 0001 §1. It sits above the `v0.1.0` leaf crates and below `brolga-cli`.
//!
//! # What is here, and why each exists
//!
//! - [`parser`] — the [`IntelligenceParser`] contract. A parser turns bytes into canonical records
//!   and does nothing else: it does not decide whether it should run, apply limits, build
//!   provenance, or touch storage. Every one of those is the pipeline's job, so a new parser gets
//!   them by construction and cannot weaken them by leaving something out.
//! - [`detect`] — what a parser is shown when asked "do you read this?", capped at
//!   [`detect::SNIFF_BYTES`] because detection runs for every parser on every document.
//! - [`registry`] — selection. Keyed and tie-broken by parser identifier, never by registration
//!   order, so reordering a dependency cannot change what Brolga ingests.
//! - [`pipeline`] — the stages, their metrics, the transformation chain, and one transaction per
//!   batch.
//!
//! # The three properties worth stating plainly
//!
//! **Selection is deterministic and explains itself.** Candidates sort by confidence, then by
//! identifier. A [`registry::Selection`] carries every parser that was asked and why each answered
//! as it did, so "why did *that* parser read my file?" has an answer that does not require reading
//! source. Two parsers both claiming [`detect::DetectionConfidence::Certain`] is refused rather
//! than resolved: certainty means no one else can be right, so two of them is a bug, and picking
//! alphabetically would hide it behind behaviour that merely looks deterministic.
//!
//! **Batch order does not reach the result.** Records are sorted by kind and identifier before
//! anything is written, so the same documents in a different order produce the same writes in the
//! same sequence.
//!
//! **A parser is stopped from panicking rather than caught panicking.** There is no
//! `catch_unwind` here. Release builds set `panic = "abort"`, which would make one dead code that
//! still looked like a guarantee. See ADR 0003 §2: the trait returns `Result`, the workspace lints
//! make `unwrap` a build failure, limits are applied before a parser is called, and a property test
//! drives arbitrary bytes through every registered parser. A *third-party* parser is not contained
//! by any of that, which is [#48](https://github.com/jusso-dev/Brolga/issues/48)'s problem and is
//! recorded as deferred rather than solved.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "testing")] {
//! use brolga_ingest::{ParserRegistry, Pipeline};
//! use brolga_ingest::testing::TestRecordsParser;
//! use brolga_ingest::detect::FormatHint;
//!
//! let mut registry = ParserRegistry::new();
//! registry.register(TestRecordsParser::boxed());
//! let pipeline = Pipeline::with_defaults(registry);
//!
//! // Selection explains itself.
//! let document = b"entity:APT-Example\n";
//! let hint = FormatHint::new("text/plain", None, document, 19);
//! let selection = pipeline.registry().select(&hint)?;
//! assert_eq!(selection.chosen().parser.as_str(), "brolga.test.records");
//! assert!(selection.explain().contains("first line begins"));
//!
//! // Nothing claims a format nobody reads, and the diagnostic says what was tried.
//! let unknown = FormatHint::new("application/xml", None, b"<stix/>", 7);
//! let error = pipeline.registry().select(&unknown).unwrap_err();
//! assert!(error.to_string().contains("no registered parser accepted"));
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

pub mod canon;
pub mod detect;
pub mod error;
pub mod parser;
pub mod pipeline;
pub mod registry;

#[cfg(feature = "testing")]
pub mod testing;

pub use canon::{CanonError, Canonical};
pub use detect::{Candidate, DetectionConfidence, FormatHint};
pub use error::{IngestError, ParseError, Result};
pub use parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
};
pub use pipeline::{
    Document, DocumentReport, IngestMode, IngestReport, PIPELINE_VERSION, Pipeline, StageMetrics,
};
pub use registry::{ParserRegistry, Selection};
