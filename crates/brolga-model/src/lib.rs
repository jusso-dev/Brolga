//! Brolga's canonical threat-intelligence model.
//!
//! This crate defines what Brolga believes an entity, an observable, a relationship, a claim, and a
//! sighting *are*, independently of any source format. It is the bottom of the dependency graph:
//! it has no first-party dependencies and every other Brolga crate may depend on it.
//!
//! # Source formats stop at the door
//!
//! There is no STIX field, no MISP field, and no ATT&CK field in this crate. Parsers translate
//! *onto* these types; none of their vocabulary translates *into* them. That boundary is what lets
//! a new source format be added later without renegotiating the meaning of an existing record, and
//! it is why the enums here are described in terms of what they mean rather than what any one
//! standard calls them.
//!
//! # The five commitments this crate enforces
//!
//! Each is enforced by types and tests rather than by convention, because a convention that only
//! holds when everyone remembers it is not a guarantee.
//!
//! 1. **Untrusted narrative is marked as such.** Text imported from a source has type
//!    [`UntrustedText`], and the classification is carried into the generated JSON Schema. It is
//!    stored and rendered, never interpreted.
//! 2. **Handling restrictions cannot be lost.** [`MarkingSet`] is always serialised, empty or not,
//!    so a missing field can never be read as "unrestricted". Combining marked material takes the
//!    most restrictive marking.
//! 3. **Every payload declares its own version.** Each top-level type carries a [`SchemaTag`] in
//!    the payload. A major-version mismatch is an error, not a best-effort parse.
//! 4. **Identifiers are derived, never generated.** There is no random or clock-based constructor
//!    in [`Id`], so re-importing a feed is idempotent and produces the same graph.
//! 5. **Hostile input is rejected at the boundary.** Validation lives in `Deserialize`, not only in
//!    constructors, so a payload cannot smuggle past the rules a caller would have to obey.
//! 6. **Nothing exists without a stated origin.** Every record carries a [`RecordOrigin`], which has
//!    exactly two cases and no `Option`: source-derived, carrying mandatory [`Provenance`], or
//!    synthetic, naming who created it and why. A source-derived record with no traceable evidence
//!    does not fail validation — it does not compile. Inside a `Provenance`, every citation must
//!    name a source object that the same record lists, so "expand this back to its source" can
//!    never resolve to nothing.
//!
//! # Canonicalisation is lossy, and the losses are kept
//!
//! `EXAMPLE.COM.` becomes `example.com`, and `2024-03-01T09:00:00+11:00` becomes
//! `2024-02-29T22:00:00Z`. Both discard information that is sometimes evidence in its own right:
//! the offset a source chose can indicate where a report was written, and the case a feed used can
//! distinguish two publishers copying from one another.
//!
//! [`OriginalRepresentation`] is the other half of that trade, and
//! [`Timestamp::parse_rfc3339_with_original`](temporal::Timestamp::parse_rfc3339_with_original) is
//! shaped so that a caller normalising to UTC is handed the original to keep, rather than having to
//! remember to ask for it.
//!
//! # What this crate deliberately leaves to others
//!
//! - **Blob storage.** A [`SourceObject`] addresses evidence by content hash and records what it
//!   was and where it came from. Retaining, compressing, and retrieving the bytes belongs to a
//!   later milestone; the split is what lets provenance be correct before there is anywhere to put
//!   the bytes.
//! - **Entity resolution.** Nothing here merges two records, and identifier derivation deliberately
//!   never uses a name.
//! - **Confidence aggregation.** [`ConfidenceBreakdown`] records components and how the overall
//!   figure was arrived at. It does not compute one.
//!
//! # Example
//!
//! ```
//! use brolga_model::claim::{Assertion, Claim};
//! use brolga_model::observable::{DomainName, Observable};
//! use brolga_model::provenance::{
//!     ContentHash, Provenance, RecordOrigin, SourceObject, TransformationChain,
//!     TransformationStage, TransformationStep,
//! };
//! use brolga_model::relationship::NodeRef;
//! use brolga_model::status::Disposition;
//! use brolga_model::text::{ShortText, UntrustedText};
//!
//! // Canonicalisation folds the representational differences that would otherwise split identity.
//! let domain = Observable::DomainName(DomainName::new("Example.COM.")?);
//! assert_eq!(domain.canonical_value(), "example.com");
//!
//! // Evidence is addressed by the digest of its exact bytes, so importing it twice yields one
//! // source object rather than two.
//! let bundle = br#"{"indicator":"EXAMPLE.COM."}"#;
//! let source = SourceObject::derive_id(ContentHash::of(bundle));
//!
//! // The chain records what was done, by which algorithm version, in pipeline order.
//! let chain = TransformationChain::new(vec![
//!     TransformationStep::new(
//!         TransformationStage::Parsing,
//!         ShortText::new("brolga.parse.json")?,
//!         1,
//!     ),
//!     TransformationStep::new(
//!         TransformationStage::Canonicalisation,
//!         ShortText::new("brolga.canonicalise.domain")?,
//!         1,
//!     ),
//! ])?;
//!
//! // Canonicalisation is lossy, so what the source actually wrote is kept alongside.
//! let mut provenance = Provenance::from_source(source, chain)?;
//! provenance.record_original(
//!     &ShortText::new("observable.value")?,
//!     UntrustedText::new("EXAMPLE.COM.")?,
//! )?;
//!
//! // A claim records who thinks what, so a later disagreement can be kept rather than resolved.
//! // Its origin is not optional: source-derived means provenance is present, by construction.
//! let claim = Claim::new(
//!     NodeRef::Observable(domain.id()),
//!     Assertion::Disposition(Disposition::Suspicious),
//!     RecordOrigin::source_derived(provenance),
//! );
//!
//! // The chain back to the original bytes is intact.
//! assert!(claim.origin.is_source_derived());
//! assert_eq!(claim.origin.source_objects(), &[source]);
//! assert_eq!(
//!     claim.origin.provenance().and_then(|p| p.original.get("observable.value")).map(|t| t.as_str()),
//!     Some("EXAMPLE.COM."),
//! );
//!
//! // Every payload declares its schema version, and markings are always present.
//! let json = serde_json::to_value(&claim)?;
//! assert_eq!(json["schema_version"], "brolga.claim/1.0");
//! assert_eq!(json["markings"], serde_json::json!([]));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

pub mod claim;
pub mod confidence;
pub mod entity;
pub mod error;
pub mod id;
pub mod marking;
pub mod observable;
pub mod provenance;
pub mod relationship;
pub mod schema;
pub mod sighting;
pub mod status;
pub mod temporal;
pub mod text;
pub mod version;

pub use claim::{Assertion, Claim};
pub use confidence::{ConfidenceBreakdown, ConfidenceMethod, ConfidenceScore};
pub use entity::{Entity, EntityKind};
pub use error::{ModelError, Result};
pub use id::{Id, Identifiable};
pub use marking::{Marking, MarkingSet, PapLevel, TlpLevel};
pub use observable::{Observable, ObservableKind};
pub use provenance::{
    ContentHash, EvidenceLocator, EvidenceReference, GeneratedContent, GenerationMethod,
    OriginalRepresentation, Provenance, RecordOrigin, SourceObject, SourceOrigin, SyntheticOrigin,
    SyntheticReason, TransformationChain, TransformationStage, TransformationStep,
};
pub use relationship::{NodeRef, Relationship, RelationshipKind};
pub use sighting::{Sighting, SightingCount};
pub use status::{Disposition, LifecycleStatus};
pub use temporal::{TemporalState, Timestamp};
pub use text::{ShortText, UntrustedText};
pub use version::{SchemaTag, VersionedSchema};
