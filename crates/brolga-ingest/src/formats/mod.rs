//! Format parsers.
//!
//! Modules rather than crates, per ADR 0003 §1: a parser that cannot be selected by the registry is
//! not reachable, and a crate boundary between the registry and the things it registers costs
//! something now for a benefit that belongs to the plugin ABI ([#46](https://github.com/jusso-dev/Brolga/issues/46)).
//!
//! Every parser here implements [`crate::IntelligenceParser`] and nothing else. Limits, provenance,
//! cancellation, storage, and quarantine are the pipeline's, so a new format gets all five by
//! construction and cannot weaken any of them by leaving something out.

pub mod delimited;
pub mod misp;
pub mod stix;
pub mod stix_pattern;
