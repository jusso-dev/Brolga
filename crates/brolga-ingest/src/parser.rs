//! The parser contract.
//!
//! A parser turns bytes into canonical records. It does **not** decide whether it should run, apply
//! resource limits, touch storage, or build provenance — the pipeline does all four, so that every
//! parser gets the same treatment and a new parser cannot weaken it by omission.

use brolga_model::{
    Claim, Entity, Id, ModelError, Provenance, RecordOrigin, Relationship, ShortText, Sighting,
    SourceObject, Timestamp, TransformationChain,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::{CancellationToken, Cancelled, ResourceLimits};
use serde::Serialize;

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;

/// A parser's stable identifier.
///
/// Conventionally `brolga.<family>.<format>`. It is a compatibility surface: it appears in
/// transformation chains stamped onto stored records, so renaming one orphans the provenance of
/// everything that parser ever produced.
///
/// `&'static str` rather than an owned string because every parser at this milestone is compiled in
/// (ADR 0003 §1). Plugin-supplied identifiers are [#46](https://github.com/jusso-dev/Brolga/issues/46)'s
/// problem, and solving it here would mean designing an ABI for a case that does not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ParserId(&'static str);

impl ParserId {
    /// Wrap a static identifier.
    #[must_use]
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Borrow the identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for ParserId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// One canonical record produced by a parser.
///
/// Boxed variants: [`Entity`] and the rest differ enough in size that an unboxed enum would make
/// every record in a million-record batch pay for the largest one.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ParsedRecord {
    /// A thing.
    Entity(Box<Entity>),
    /// A link between two things.
    Relationship(Box<Relationship>),
    /// An assertion about a thing.
    Claim(Box<Claim>),
    /// An observation of a thing at a time and place.
    Sighting(Box<Sighting>),
}

impl ParsedRecord {
    /// A stable sort key for this record.
    ///
    /// Kind first, then identifier. This is what makes batch ordering irrelevant to the stored
    /// result: the pipeline sorts by this before writing, so two batches holding the same records
    /// in different orders issue the same writes in the same order.
    #[must_use]
    pub fn sort_key(&self) -> (u8, String) {
        match self {
            Self::Entity(record) => (0, record.id.to_string()),
            Self::Relationship(record) => (1, record.id.to_string()),
            Self::Claim(record) => (2, record.id.to_string()),
            Self::Sighting(record) => (3, record.id.to_string()),
        }
    }

    /// What kind of record this is, for metrics and diagnostics.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Entity(_) => "entity",
            Self::Relationship(_) => "relationship",
            Self::Claim(_) => "claim",
            Self::Sighting(_) => "sighting",
        }
    }
}

/// What a parser produced from one document.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct ParseOutput {
    /// The canonical records, in whatever order the parser produced them.
    ///
    /// The pipeline sorts them. A parser is not required to, and one that does gains nothing.
    pub records: Vec<ParsedRecord>,
    /// Anything the operator should know that is not a failure.
    ///
    /// A skipped record, an unrecognised optional field, a value that was truncated to fit a limit.
    /// Notes do not fail ingestion; they are why a successful ingest can still be worth reading.
    pub notes: Vec<ShortText>,
    /// Records this parser could read the shape of but could not accept.
    ///
    /// Returning these rather than failing the whole document is what makes permissive ingestion
    /// possible: one malformed row in a hundred thousand should not discard the other 99,999, and a
    /// parser that can only say "the document failed" forces exactly that. A parser that genuinely
    /// cannot read the document at all still returns [`ParseError`] instead.
    pub rejected: Vec<RejectedRecord>,
}

/// One record a parser read but could not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRecord {
    /// A stable machine-readable category, for grouping and for policy.
    ///
    /// `&'static str` for the same reason detection reasons are: a category interpolated from the
    /// document would put untrusted bytes somewhere a caller may branch on.
    pub reason_kind: &'static str,
    /// The full diagnostic, for a human.
    pub reason: String,
    /// Byte offset into the document, where the parser identified one.
    pub offset: Option<u64>,
    /// The offending text, as the parser saw it. Sanitised before it is stored.
    pub fragment: Option<String>,
}

impl RejectedRecord {
    /// A rejection at a known byte offset.
    #[must_use]
    pub fn at(
        offset: u64,
        reason_kind: &'static str,
        reason: impl Into<String>,
        fragment: impl Into<String>,
    ) -> Self {
        Self {
            reason_kind,
            reason: reason.into(),
            offset: Some(offset),
            fragment: Some(fragment.into()),
        }
    }
}

impl ParseOutput {
    /// An output holding exactly these records and no notes.
    #[must_use]
    pub fn from_records(records: Vec<ParsedRecord>) -> Self {
        Self {
            records,
            notes: Vec::new(),
            rejected: Vec::new(),
        }
    }
}

/// Everything a parser is given besides the bytes.
///
/// Holds the limits and the cancellation token rather than letting a parser source its own, so a
/// parser cannot opt out of either. It also holds the source object and the transformation chain
/// built so far, so that [`Self::record_origin`] hands back a correct source-derived origin and a
/// parser never has to assemble provenance itself — the commonest way a record would end up citing
/// the wrong evidence, or none.
#[derive(Debug, Clone)]
pub struct ParseContext {
    limits: ResourceLimits,
    cancel: CancellationToken,
    media_type: MediaType,
    retrieved_at: Timestamp,
    source_origin: SourceOrigin,
    source_object: Id<SourceObject>,
    chain: TransformationChain,
}

impl ParseContext {
    /// Build a context.
    ///
    /// Built by the pipeline, which is the only thing that knows the source object's identifier
    /// and the chain leading up to parsing.
    #[must_use]
    pub fn new(
        limits: ResourceLimits,
        cancel: CancellationToken,
        media_type: MediaType,
        retrieved_at: Timestamp,
        source_origin: SourceOrigin,
        source_object: Id<SourceObject>,
        chain: TransformationChain,
    ) -> Self {
        Self {
            limits,
            cancel,
            media_type,
            retrieved_at,
            source_origin,
            source_object,
            chain,
        }
    }

    /// The resource limits in force.
    #[must_use]
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// The media type the document was offered under.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// When the document was retrieved.
    #[must_use]
    pub const fn retrieved_at(&self) -> Timestamp {
        self.retrieved_at
    }

    /// Where the document came from.
    #[must_use]
    pub const fn source_origin(&self) -> &SourceOrigin {
        &self.source_origin
    }

    /// The content-addressed identifier of the document being parsed.
    #[must_use]
    pub const fn source_object(&self) -> Id<SourceObject> {
        self.source_object
    }

    /// The transformation chain up to and including parsing.
    #[must_use]
    pub const fn chain(&self) -> &TransformationChain {
        &self.chain
    }

    /// The cancellation token for this request.
    #[must_use]
    pub const fn cancel(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Stop early if the request has been cancelled or has run out of time.
    ///
    /// A parser working through a long document should call this between records. It is cheap.
    ///
    /// # Errors
    ///
    /// Returns [`Cancelled`] if the token has been cancelled or its deadline has passed.
    pub fn check_cancelled(&self) -> Result<(), Cancelled> {
        self.cancel.check()
    }

    /// Provenance citing this document and the chain that produced the record.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if the chain or evidence fails the model's own validation.
    pub fn provenance(&self) -> Result<Provenance, ModelError> {
        Provenance::from_source(self.source_object, self.chain.clone())
    }

    /// A source-derived record origin for this document.
    ///
    /// What a parser should give every record it builds. Using this rather than assembling a
    /// [`RecordOrigin`] by hand is what keeps "source-derived records cite their evidence" a
    /// property of the pipeline instead of a rule each parser has to remember.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if provenance cannot be built.
    pub fn record_origin(&self) -> Result<RecordOrigin, ModelError> {
        Ok(RecordOrigin::source_derived(self.provenance()?))
    }
}

/// A format Brolga can read.
///
/// # Contract
///
/// - [`Self::detect`] must be **pure and cheap**: same hint, same answer, no I/O, no allocation
///   proportional to the document. It is called for every registered parser on every document.
/// - [`Self::parse`] must not panic. Panicking is not a supported way to reject input; return
///   [`ParseError`] instead. See ADR 0003 §2 — `panic = "abort"` is set for release builds, so a
///   panic here terminates the process rather than being caught.
/// - Neither method may write to storage, open a network connection, or read the filesystem.
pub trait IntelligenceParser: Send + Sync {
    /// This parser's stable identifier.
    fn id(&self) -> ParserId;

    /// This parser's algorithm version.
    ///
    /// Incremented whenever the parser's *output* changes for any input, because it is stamped into
    /// the transformation chain of every record produced and is what makes two differing results
    /// from "the same parser" distinguishable after the fact.
    fn version(&self) -> u32;

    /// Whether this parser claims the document, and why.
    ///
    /// The reason is not decoration: it is what
    /// [`IngestError::UnknownFormat`](crate::IngestError::UnknownFormat) shows the operator when
    /// nothing matched, so it should say what was looked for and not found.
    fn detect(&self, hint: &FormatHint<'_>) -> Candidate;

    /// Turn the document into canonical records.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when the document cannot be read. Prefer
    /// [`ParseError::at`] so the operator can inspect the failing position.
    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError>;
}

/// Convenience for a parser building its own [`Candidate`].
///
/// Exists so the common case — "I looked for X and did/did not find it" — does not require each
/// parser to remember to copy its own identifier and version into the candidate, which is a thing
/// two parsers will eventually get wrong in different ways.
#[must_use]
pub fn candidate(
    parser: &dyn IntelligenceParser,
    confidence: DetectionConfidence,
    reason: &'static str,
) -> Candidate {
    Candidate {
        parser: parser.id(),
        parser_version: parser.version(),
        confidence,
        reason,
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
    use brolga_model::{
        EntityKind, Id, RecordOrigin, SyntheticOrigin, SyntheticReason, UntrustedText,
    };

    fn entity(name: &str) -> ParsedRecord {
        let origin = RecordOrigin::Synthetic {
            origin: SyntheticOrigin::new(
                SyntheticReason::Fixture,
                ShortText::new("brolga.test").unwrap(),
            ),
        };
        ParsedRecord::Entity(Box::new(Entity::new(
            Id::derive(&[name]),
            EntityKind::ThreatActor,
            UntrustedText::new(name).unwrap(),
            origin,
        )))
    }

    /// The sort key is what makes batch order irrelevant. If it were not total, two orderings could
    /// produce two different write sequences.
    #[test]
    fn sorting_by_the_sort_key_is_a_total_order_over_distinct_records() {
        let mut records = [entity("zeta"), entity("alpha"), entity("mu")];
        let mut keys: Vec<_> = records.iter().map(ParsedRecord::sort_key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 3, "distinct records must have distinct keys");

        records.sort_by_key(ParsedRecord::sort_key);
        let forwards: Vec<_> = records.iter().map(ParsedRecord::sort_key).collect();

        records.reverse();
        records.sort_by_key(ParsedRecord::sort_key);
        let backwards: Vec<_> = records.iter().map(ParsedRecord::sort_key).collect();

        assert_eq!(
            forwards, backwards,
            "sorting must not depend on input order"
        );
    }

    /// Kind participates in the key, so an entity and a claim that happen to derive the same
    /// identifier still order predictably rather than by whichever the sort saw first.
    #[test]
    fn the_sort_key_separates_kinds_before_identifiers() {
        assert!(
            entity("z").sort_key().0 < 1,
            "entities sort into the first group"
        );
    }

    /// The identifier is stamped into stored provenance, so it round-trips as a plain string
    /// rather than as a wrapper somebody has to unpick later.
    #[test]
    fn a_parser_id_serialises_as_a_bare_string() {
        let rendered = serde_json::to_string(&ParserId::new("brolga.test.jsonl")).unwrap();
        assert_eq!(rendered, "\"brolga.test.jsonl\"");
    }
}
