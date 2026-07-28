//! Shared resource limits for untrusted input.
//!
//! # Why the limits live here and not with each consumer
//!
//! Parsers, archive readers, XML readers, graph traversal, connectors, plugin hosts, and context
//! generation all need bounds on the same things: how much, how deep, how long. If each defined its
//! own, they would drift, and the weakest one would set the real limit while the documentation
//! described the strictest.
//!
//! This crate is layer 0 with no first-party dependencies precisely so every one of those can
//! depend on it.
//!
//! # Every limit is bounded on both sides
//!
//! A limit of zero disables a protection and a limit of `u64::MAX` is not a limit. Both are
//! rejected, and the permitted range is part of the error, so an operator who sets one wrongly is
//! told what would have been acceptable.
//!
//! # Two limits that are not obvious
//!
//! **Archive expansion ratio.** A 42-kilobyte zip file can expand to petabytes. A size limit on the
//! *archive* does nothing; the limit has to be on what comes out, expressed as a ratio to what went
//! in, and checked while decompressing rather than afterwards.
//!
//! **XML entity expansion.** The "billion laughs" attack is a small document whose entity
//! definitions expand exponentially. The only reliable control is refusing to process external and
//! recursive entity definitions at all, which is why [`XmlLimits::allow_external_entities`] exists
//! and defaults to `false` — it is a switch a future parser must go out of its way to flip.

use core::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A limit was outside its permitted range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{name} is {value}, which is outside the permitted range {min}..={max}")]
pub struct LimitOutOfRange {
    /// Which limit.
    pub name: &'static str,
    /// The value supplied.
    pub value: u64,
    /// Smallest permitted value.
    pub min: u64,
    /// Largest permitted value.
    pub max: u64,
}

/// A `u64` limit with a documented permitted range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Which limit this describes.
    pub name: &'static str,
    /// Smallest permitted value. Never zero: zero disables the protection.
    pub min: u64,
    /// Largest permitted value. Never `u64::MAX`: that is not a limit.
    pub max: u64,
    /// The value used when an operator sets nothing.
    pub default: u64,
}

impl Bounds {
    const fn new(name: &'static str, min: u64, max: u64, default: u64) -> Self {
        Self {
            name,
            min,
            max,
            default,
        }
    }

    /// Check a value against this range.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] naming the limit and its permitted range.
    pub const fn check(&self, value: u64) -> Result<u64, LimitOutOfRange> {
        if value < self.min || value > self.max {
            return Err(LimitOutOfRange {
                name: self.name,
                value,
                min: self.min,
                max: self.max,
            });
        }
        Ok(value)
    }
}

/// Limits on a single untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputLimits {
    /// Largest single document Brolga will read, in bytes.
    pub max_bytes: u64,
    /// Deepest structure Brolga will descend into.
    pub max_depth: u64,
    /// Most records accepted from one input.
    pub max_records: u64,
    /// Longest single field value, in bytes.
    pub max_field_bytes: u64,
}

impl InputLimits {
    /// Permitted range for [`Self::max_bytes`].
    pub const MAX_BYTES: Bounds =
        Bounds::new("max_bytes", 1024, 1024 * 1024 * 1024, 64 * 1024 * 1024);
    /// Permitted range for [`Self::max_depth`].
    pub const MAX_DEPTH: Bounds = Bounds::new("max_depth", 1, 1024, 64);
    /// Permitted range for [`Self::max_records`].
    pub const MAX_RECORDS: Bounds = Bounds::new("max_records", 1, 100_000_000, 1_000_000);
    /// Permitted range for [`Self::max_field_bytes`].
    pub const MAX_FIELD_BYTES: Bounds =
        Bounds::new("max_field_bytes", 64, 16 * 1024 * 1024, 65_536);

    /// The safe defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_bytes: Self::MAX_BYTES.default,
            max_depth: Self::MAX_DEPTH.default,
            max_records: Self::MAX_RECORDS.default,
            max_field_bytes: Self::MAX_FIELD_BYTES.default,
        }
    }

    /// Check every field.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] for the first field outside its range.
    pub const fn validated(self) -> Result<Self, LimitOutOfRange> {
        if let Err(error) = Self::MAX_BYTES.check(self.max_bytes) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_DEPTH.check(self.max_depth) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_RECORDS.check(self.max_records) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_FIELD_BYTES.check(self.max_field_bytes) {
            return Err(error);
        }
        Ok(self)
    }
}

impl Default for InputLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Limits on decompressing an archive.
///
/// A size limit on the archive itself is not a control: a 42-kilobyte zip can expand to petabytes.
/// The control is on the *output*, expressed as a ratio to the input, and it has to be enforced
/// while decompressing rather than after — checking afterwards means the damage already happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveLimits {
    /// Largest total size of everything extracted, in bytes.
    pub max_total_output_bytes: u64,
    /// Largest single extracted file, in bytes.
    pub max_entry_bytes: u64,
    /// Most entries in one archive.
    pub max_entries: u64,
    /// Largest permitted output-to-input ratio.
    ///
    /// Real data compresses well; a zip bomb compresses absurdly. A ratio catches the difference
    /// where an absolute size cannot.
    pub max_expansion_ratio: u64,
    /// Deepest nesting of archives inside archives.
    ///
    /// Zero forbids nested archives entirely, which is a legitimate and common choice.
    pub max_nesting: u64,
}

impl ArchiveLimits {
    /// Permitted range for [`Self::max_total_output_bytes`].
    pub const MAX_TOTAL_OUTPUT: Bounds = Bounds::new(
        "max_total_output_bytes",
        1024,
        64 * 1024 * 1024 * 1024,
        1024 * 1024 * 1024,
    );
    /// Permitted range for [`Self::max_entry_bytes`].
    pub const MAX_ENTRY: Bounds = Bounds::new(
        "max_entry_bytes",
        1024,
        8 * 1024 * 1024 * 1024,
        256 * 1024 * 1024,
    );
    /// Permitted range for [`Self::max_entries`].
    pub const MAX_ENTRIES: Bounds = Bounds::new("max_entries", 1, 1_000_000, 10_000);
    /// Permitted range for [`Self::max_expansion_ratio`].
    pub const MAX_RATIO: Bounds = Bounds::new("max_expansion_ratio", 2, 10_000, 100);
    /// Permitted range for [`Self::max_nesting`].
    pub const MAX_NESTING: Bounds = Bounds::new("max_nesting", 0, 8, 1);

    /// The safe defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_total_output_bytes: Self::MAX_TOTAL_OUTPUT.default,
            max_entry_bytes: Self::MAX_ENTRY.default,
            max_entries: Self::MAX_ENTRIES.default,
            max_expansion_ratio: Self::MAX_RATIO.default,
            max_nesting: Self::MAX_NESTING.default,
        }
    }

    /// Whether extracting `output_bytes` from `input_bytes` stays within the ratio.
    ///
    /// Call while decompressing, not afterwards. An empty input cannot produce output within any
    /// ratio, so it is refused rather than treated as unbounded.
    #[must_use]
    pub const fn ratio_permits(&self, input_bytes: u64, output_bytes: u64) -> bool {
        if input_bytes == 0 {
            return output_bytes == 0;
        }
        match input_bytes.checked_mul(self.max_expansion_ratio) {
            Some(allowed) => output_bytes <= allowed,
            // The permitted output overflowed `u64`, so any real output is within it.
            None => true,
        }
    }

    /// Check every field.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] for the first field outside its range.
    pub const fn validated(self) -> Result<Self, LimitOutOfRange> {
        if let Err(error) = Self::MAX_TOTAL_OUTPUT.check(self.max_total_output_bytes) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_ENTRY.check(self.max_entry_bytes) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_ENTRIES.check(self.max_entries) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_RATIO.check(self.max_expansion_ratio) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_NESTING.check(self.max_nesting) {
            return Err(error);
        }
        Ok(self)
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Limits and switches for reading XML.
///
/// STIX 1.x, TAXII 1.x, and several detection formats are XML, so Brolga will read it. XML brings
/// three attacks that have nothing to do with the data: entity expansion, external entity
/// resolution, and unbounded nesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XmlLimits {
    /// Whether external entity references may be resolved.
    ///
    /// **`false`, and there is no good reason to change it.** Resolving external entities lets a
    /// document read local files and make network requests as Brolga — the XXE vulnerability. It is
    /// a field rather than a hard-coded `false` so that a future parser must flip it visibly, in a
    /// diff someone reviews, rather than by passing a different reader configuration.
    pub allow_external_entities: bool,
    /// Whether internal entity definitions may be expanded at all.
    ///
    /// `false`. Entity expansion is the billion-laughs attack, and no threat-intelligence format
    /// needs it.
    pub allow_entity_expansion: bool,
    /// Deepest element nesting.
    pub max_depth: u64,
    /// Most elements in one document.
    pub max_elements: u64,
    /// Longest single attribute value, in bytes.
    pub max_attribute_bytes: u64,
}

impl XmlLimits {
    /// Permitted range for [`Self::max_depth`].
    pub const MAX_DEPTH: Bounds = Bounds::new("xml.max_depth", 1, 512, 64);
    /// Permitted range for [`Self::max_elements`].
    pub const MAX_ELEMENTS: Bounds = Bounds::new("xml.max_elements", 1, 10_000_000, 500_000);
    /// Permitted range for [`Self::max_attribute_bytes`].
    pub const MAX_ATTRIBUTE_BYTES: Bounds =
        Bounds::new("xml.max_attribute_bytes", 64, 1024 * 1024, 65_536);

    /// The safe defaults, with both entity switches off.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            allow_external_entities: false,
            allow_entity_expansion: false,
            max_depth: Self::MAX_DEPTH.default,
            max_elements: Self::MAX_ELEMENTS.default,
            max_attribute_bytes: Self::MAX_ATTRIBUTE_BYTES.default,
        }
    }

    /// Check every field.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] for the first field outside its range.
    pub const fn validated(self) -> Result<Self, LimitOutOfRange> {
        if let Err(error) = Self::MAX_DEPTH.check(self.max_depth) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_ELEMENTS.check(self.max_elements) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_ATTRIBUTE_BYTES.check(self.max_attribute_bytes) {
            return Err(error);
        }
        Ok(self)
    }
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Limits on a network response Brolga retrieves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseLimits {
    /// Largest response body Brolga will read, in bytes.
    ///
    /// Enforced while reading, not from a `Content-Length` header, which the server controls.
    pub max_body_bytes: u64,
    /// Most redirects followed before giving up.
    pub max_redirects: u64,
    /// Longest a single request may take, in seconds.
    pub timeout_seconds: u64,
}

impl ResponseLimits {
    /// Permitted range for [`Self::max_body_bytes`].
    pub const MAX_BODY: Bounds = Bounds::new(
        "max_body_bytes",
        1024,
        8 * 1024 * 1024 * 1024,
        256 * 1024 * 1024,
    );
    /// Permitted range for [`Self::max_redirects`].
    ///
    /// Zero is permitted and means "follow none", which is the right setting for a connector whose
    /// endpoint is fixed.
    pub const MAX_REDIRECTS: Bounds = Bounds::new("max_redirects", 0, 10, 3);
    /// Permitted range for [`Self::timeout_seconds`].
    pub const TIMEOUT_SECONDS: Bounds = Bounds::new("timeout_seconds", 1, 3600, 60);

    /// The safe defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_body_bytes: Self::MAX_BODY.default,
            max_redirects: Self::MAX_REDIRECTS.default,
            timeout_seconds: Self::TIMEOUT_SECONDS.default,
        }
    }

    /// The request timeout as a [`Duration`].
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    /// Check every field.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] for the first field outside its range.
    pub const fn validated(self) -> Result<Self, LimitOutOfRange> {
        if let Err(error) = Self::MAX_BODY.check(self.max_body_bytes) {
            return Err(error);
        }
        if let Err(error) = Self::MAX_REDIRECTS.check(self.max_redirects) {
            return Err(error);
        }
        if let Err(error) = Self::TIMEOUT_SECONDS.check(self.timeout_seconds) {
            return Err(error);
        }
        Ok(self)
    }
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Every shared limit, in one value.
///
/// Passed down rather than read from a global, so a caller can tighten limits for one operation —
/// an untrusted bulk import, say — without changing them for everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Limits on a single input document.
    pub input: InputLimits,
    /// Limits on archive extraction.
    pub archive: ArchiveLimits,
    /// Limits and switches for XML.
    pub xml: XmlLimits,
    /// Limits on network responses.
    pub response: ResponseLimits,
}

impl ResourceLimits {
    /// The safe defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            input: InputLimits::defaults(),
            archive: ArchiveLimits::defaults(),
            xml: XmlLimits::defaults(),
            response: ResponseLimits::defaults(),
        }
    }

    /// Check every limit.
    ///
    /// # Errors
    ///
    /// Returns [`LimitOutOfRange`] for the first limit outside its range.
    pub const fn validated(self) -> Result<Self, LimitOutOfRange> {
        if let Err(error) = self.input.validated() {
            return Err(error);
        }
        if let Err(error) = self.archive.validated() {
            return Err(error);
        }
        if let Err(error) = self.xml.validated() {
            return Err(error);
        }
        if let Err(error) = self.response.validated() {
            return Err(error);
        }
        Ok(self)
    }
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

    /// Every bound in the crate, so the invariants below are checked against all of them rather
    /// than against a sample somebody remembered to extend.
    fn every_bound() -> Vec<Bounds> {
        vec![
            InputLimits::MAX_BYTES,
            InputLimits::MAX_DEPTH,
            InputLimits::MAX_RECORDS,
            InputLimits::MAX_FIELD_BYTES,
            ArchiveLimits::MAX_TOTAL_OUTPUT,
            ArchiveLimits::MAX_ENTRY,
            ArchiveLimits::MAX_ENTRIES,
            ArchiveLimits::MAX_RATIO,
            ArchiveLimits::MAX_NESTING,
            XmlLimits::MAX_DEPTH,
            XmlLimits::MAX_ELEMENTS,
            XmlLimits::MAX_ATTRIBUTE_BYTES,
            ResponseLimits::MAX_BODY,
            ResponseLimits::MAX_REDIRECTS,
            ResponseLimits::TIMEOUT_SECONDS,
        ]
    }

    #[test]
    fn no_limit_can_be_set_to_something_that_is_not_a_limit() {
        for bounds in every_bound() {
            assert!(
                bounds.max < u64::MAX,
                "{} permits u64::MAX, which is not a limit",
                bounds.name,
            );
            assert!(
                bounds.min <= bounds.max,
                "{} has an empty range",
                bounds.name
            );
            assert!(
                bounds.default >= bounds.min && bounds.default <= bounds.max,
                "{}'s default is outside its own range",
                bounds.name,
            );
        }
    }

    #[test]
    fn only_the_limits_where_zero_is_meaningful_permit_zero() {
        // Zero disables a protection, so it is permitted only where "none" is a coherent setting:
        // no nested archives, and no redirects.
        for bounds in every_bound() {
            let zero_is_meaningful = bounds.name == "max_nesting" || bounds.name == "max_redirects";
            assert_eq!(
                bounds.min == 0,
                zero_is_meaningful,
                "{} permits zero but zero disables the protection",
                bounds.name,
            );
        }
    }

    #[test]
    fn the_defaults_validate() {
        assert!(ResourceLimits::defaults().validated().is_ok());
        assert_eq!(ResourceLimits::default(), ResourceLimits::defaults());
    }

    #[test]
    fn out_of_range_errors_name_the_limit_and_the_permitted_range() {
        // An operator who sets a limit wrongly should be told what would have been acceptable.
        let error = InputLimits {
            max_bytes: 0,
            ..InputLimits::defaults()
        }
        .validated()
        .unwrap_err();

        assert_eq!(error.name, "max_bytes");
        assert_eq!(error.value, 0);
        let rendered = error.to_string();
        assert!(rendered.contains("max_bytes"), "{rendered}");
        assert!(rendered.contains(&error.min.to_string()), "{rendered}");
        assert!(rendered.contains(&error.max.to_string()), "{rendered}");
    }

    #[test]
    fn every_limit_rejects_zero_and_the_maximum_where_those_are_invalid() {
        for build in [
            |value| ResourceLimits {
                input: InputLimits {
                    max_bytes: value,
                    ..InputLimits::defaults()
                },
                ..ResourceLimits::defaults()
            },
            |value| ResourceLimits {
                input: InputLimits {
                    max_depth: value,
                    ..InputLimits::defaults()
                },
                ..ResourceLimits::defaults()
            },
            |value| ResourceLimits {
                xml: XmlLimits {
                    max_depth: value,
                    ..XmlLimits::defaults()
                },
                ..ResourceLimits::defaults()
            },
            |value| ResourceLimits {
                response: ResponseLimits {
                    timeout_seconds: value,
                    ..ResponseLimits::defaults()
                },
                ..ResourceLimits::defaults()
            },
        ] {
            assert!(build(0).validated().is_err(), "zero must be rejected");
            assert!(
                build(u64::MAX).validated().is_err(),
                "u64::MAX must be rejected"
            );
        }
    }

    #[test]
    fn a_zip_bomb_is_caught_by_ratio_not_by_size() {
        // 42 kilobytes expanding to 4 gigabytes. Every absolute size involved is unremarkable.
        let limits = ArchiveLimits::defaults();
        assert!(!limits.ratio_permits(42 * 1024, 4 * 1024 * 1024 * 1024));

        // Real data compresses well, and must still be accepted. Ten to one is ordinary for JSON.
        assert!(limits.ratio_permits(1024 * 1024, 10 * 1024 * 1024));
        assert!(
            limits.ratio_permits(1024, 1024 * 100),
            "at the ratio exactly"
        );
        assert!(!limits.ratio_permits(1024, 1024 * 100 + 1), "one byte over");
    }

    #[test]
    fn an_empty_archive_cannot_produce_output() {
        // Treating zero input as unbounded would make the ratio trivially bypassable.
        let limits = ArchiveLimits::defaults();
        assert!(limits.ratio_permits(0, 0));
        assert!(!limits.ratio_permits(0, 1));
    }

    #[test]
    fn the_ratio_check_cannot_overflow() {
        let limits = ArchiveLimits {
            max_expansion_ratio: ArchiveLimits::MAX_RATIO.max,
            ..ArchiveLimits::defaults()
        };
        assert!(limits.ratio_permits(u64::MAX, u64::MAX));
    }

    #[test]
    fn xml_entity_processing_is_off_by_default() {
        // XXE and billion-laughs. Both switches are fields rather than hard-coded `false` so that a
        // future parser must flip one visibly, in a diff somebody reviews.
        let xml = XmlLimits::defaults();
        assert!(!xml.allow_external_entities);
        assert!(!xml.allow_entity_expansion);
        assert!(!ResourceLimits::defaults().xml.allow_external_entities);
    }

    #[test]
    fn no_redirects_is_a_legitimate_setting() {
        // The right choice for a connector whose endpoint is fixed.
        let limits = ResponseLimits {
            max_redirects: 0,
            ..ResponseLimits::defaults()
        };
        assert!(limits.validated().is_ok());
    }

    #[test]
    fn redirect_following_is_bounded_low() {
        // Each redirect is another chance to be sent somewhere internal, so the ceiling is small.
        const { assert!(ResponseLimits::MAX_REDIRECTS.max <= 10) };
        const { assert!(ResponseLimits::MAX_REDIRECTS.default <= 5) };
    }

    #[test]
    fn the_request_timeout_converts_to_a_duration() {
        assert_eq!(
            ResponseLimits::defaults().timeout(),
            Duration::from_secs(ResponseLimits::TIMEOUT_SECONDS.default),
        );
    }

    #[test]
    fn limits_round_trip_and_reject_unknown_fields() {
        let limits = ResourceLimits::defaults();
        let json = serde_json::to_string(&limits).unwrap();
        assert_eq!(
            serde_json::from_str::<ResourceLimits>(&json).unwrap(),
            limits
        );

        let mut hostile = serde_json::to_value(limits).unwrap();
        hostile["input"]["unbounded"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ResourceLimits>(hostile).is_err());
    }

    #[test]
    fn deserialisation_alone_does_not_validate_ranges() {
        // Deliberate: `validated` is a separate, explicit step so a caller cannot forget that a
        // deserialised value still has to be checked. This test records that expectation rather
        // than leaving it to be discovered.
        let mut value = serde_json::to_value(ResourceLimits::defaults()).unwrap();
        value["input"]["max_bytes"] = serde_json::json!(0);

        let parsed: ResourceLimits = serde_json::from_value(value).unwrap();
        assert!(parsed.validated().is_err());
    }
}
