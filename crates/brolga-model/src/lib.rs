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
//!
//! # What this crate deliberately leaves to others
//!
//! - **Provenance.** Content hashes, transformation chains, and evidence references are a separate
//!   concern with its own issue. This crate's canonicalisation is the lossy half of that pair, and
//!   [`Timestamp::parse_rfc3339_with_original`](temporal::Timestamp::parse_rfc3339_with_original)
//!   is shaped so a caller is handed the original representation to keep.
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
//! use brolga_model::relationship::NodeRef;
//! use brolga_model::status::Disposition;
//!
//! // Canonicalisation folds the representational differences that would otherwise split identity.
//! let domain = Observable::DomainName(DomainName::new("Example.COM.")?);
//! assert_eq!(domain.canonical_value(), "example.com");
//!
//! // A claim records who thinks what, so a later disagreement can be kept rather than resolved.
//! let claim = Claim::new(
//!     NodeRef::Observable(domain.id()),
//!     Assertion::Disposition(Disposition::Suspicious),
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
pub use relationship::{NodeRef, Relationship, RelationshipKind};
pub use sighting::{Sighting, SightingCount};
pub use status::{Disposition, LifecycleStatus};
pub use temporal::{TemporalState, Timestamp};
pub use text::{ShortText, UntrustedText};
pub use version::{SchemaTag, VersionedSchema};
