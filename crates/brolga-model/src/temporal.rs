//! Canonical timestamps and the temporal state of a canonical record.
//!
//! # Why canonical time is always UTC
//!
//! Brolga merges records from sources that express time in different offsets. Comparing them
//! requires one representation, so [`Timestamp`] normalises to UTC on construction and serialises
//! as RFC 3339 with a `Z` suffix.
//!
//! That normalisation is lossy: `2024-03-01T09:00:00+11:00` and `2024-02-29T22:00:00Z` are the same
//! instant and become the same canonical value, but they are not the same *representation*, and the
//! offset a source chose can itself be evidence. Preserving the original representation is the job
//! of the provenance model, which records the source's exact bytes alongside the canonical value.
//! This module is deliberately the lossy half of that pair, and
//! [`Timestamp::parse_rfc3339_with_original`] exists so a caller cannot normalise without being
//! handed the original to keep.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{ModelError, Result, preview};

/// An instant on the UTC timeline.
///
/// Ordering is chronological, which makes it usable directly as a sort key and inside ordered
/// collections.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// The UNIX epoch, `1970-01-01T00:00:00Z`.
    #[must_use]
    pub const fn unix_epoch() -> Self {
        Self(OffsetDateTime::UNIX_EPOCH)
    }

    /// Wrap an [`OffsetDateTime`], converting it to UTC.
    #[must_use]
    pub const fn from_offset_date_time(value: OffsetDateTime) -> Self {
        Self(value.to_offset(time::UtcOffset::UTC))
    }

    /// Parse an RFC 3339 timestamp, converting it to UTC.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the input is not a valid RFC 3339 timestamp. The
    /// message quotes a truncated, escaped preview of the input rather than the raw bytes.
    pub fn parse_rfc3339(value: &str) -> Result<Self> {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(Self::from_offset_date_time)
            .map_err(|error| {
                ModelError::invalid(
                    "Timestamp",
                    format_args!("{:?} is not RFC 3339 ({error})", preview(value)),
                )
            })
    }

    /// Parse an RFC 3339 timestamp and return the original text alongside the canonical value.
    ///
    /// Normalising to UTC discards the source's offset and its choice of subsecond precision. This
    /// method hands both halves back together so that a caller storing a canonical timestamp always
    /// has the original representation available to record as provenance.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the input is not a valid RFC 3339 timestamp.
    pub fn parse_rfc3339_with_original(value: &str) -> Result<(Self, String)> {
        Ok((Self::parse_rfc3339(value)?, value.to_owned()))
    }

    /// Render as RFC 3339 in UTC.
    ///
    /// # Panics
    ///
    /// Does not panic. Formatting an [`OffsetDateTime`] as RFC 3339 can only fail for a year
    /// outside `0000..=9999`, and [`Timestamp`] rejects such values on construction and on
    /// deserialisation, so the fallible path is unreachable. It is handled rather than unwrapped
    /// anyway, because a lint that forbids `unwrap` is worth more than a shorter function.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        self.0
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("0000-01-01T00:00:00Z"))
    }

    /// The wrapped [`OffsetDateTime`], always at UTC offset.
    #[must_use]
    pub const fn as_offset_date_time(self) -> OffsetDateTime {
        self.0
    }

    /// Whole seconds since the UNIX epoch. Negative before 1970.
    #[must_use]
    pub const fn unix_timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Reject years RFC 3339 cannot represent in four digits.
    fn validate(self) -> Result<Self> {
        let year = self.0.year();
        if !(0..=9999).contains(&year) {
            return Err(ModelError::invalid(
                "Timestamp",
                format_args!("year {year} is outside the RFC 3339 range 0000..=9999"),
            ));
        }
        Ok(self)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.to_rfc3339())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self::from_offset_date_time(value)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse_rfc3339(&raw)
            .and_then(Self::validate)
            .map_err(D::Error::custom)
    }
}

impl JsonSchema for Timestamp {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Timestamp".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date-time",
            "description": "An RFC 3339 instant, always normalised to UTC and serialised with a `Z` suffix.",
        })
    }
}

/// When a record was observed, and when it is considered valid.
///
/// The two pairs answer different questions and are not interchangeable. `first_seen` and
/// `last_seen` are *observation* time: when a source encountered the thing. `valid_from` and
/// `valid_until` are *assertion* time: the window in which the claim is held to apply. An indicator
/// last seen a year ago may still be valid, and an indicator seen this morning may already have
/// expired.
///
/// Every field is optional, because a source may supply any subset and inventing the rest would be
/// fabricating intelligence. What is validated is that the values supplied are ordered possibly.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TemporalState {
    /// Earliest observation of the subject.
    pub first_seen: Option<Timestamp>,
    /// Most recent observation of the subject.
    pub last_seen: Option<Timestamp>,
    /// Start of the window in which the record is asserted to apply.
    pub valid_from: Option<Timestamp>,
    /// End of the window in which the record is asserted to apply.
    pub valid_until: Option<Timestamp>,
}

impl TemporalState {
    /// An empty temporal state: nothing observed, no validity asserted.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            first_seen: None,
            last_seen: None,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Build an observation window.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TimeOrder`] if `first_seen` is later than `last_seen`.
    pub fn observed(first_seen: Timestamp, last_seen: Timestamp) -> Result<Self> {
        Self {
            first_seen: Some(first_seen),
            last_seen: Some(last_seen),
            valid_from: None,
            valid_until: None,
        }
        .validated()
    }

    /// Check that the supplied timestamps are in a possible order.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TimeOrder`] if `first_seen` is later than `last_seen`, or if
    /// `valid_from` is later than `valid_until`.
    pub fn validated(self) -> Result<Self> {
        check_order("first_seen", self.first_seen, "last_seen", self.last_seen)?;
        check_order(
            "valid_from",
            self.valid_from,
            "valid_until",
            self.valid_until,
        )?;
        Ok(self)
    }

    /// Whether the record's asserted validity window has closed at `now`.
    ///
    /// A record with no `valid_until` never expires; absence of an end is not an end.
    #[must_use]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        self.valid_until.is_some_and(|until| until < now)
    }
}

impl<'de> Deserialize<'de> for TemporalState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        // A private mirror struct so the derived field parsing is reused, and the ordering check
        // runs on the untrusted path as well as on the constructor path.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            first_seen: Option<Timestamp>,
            #[serde(default)]
            last_seen: Option<Timestamp>,
            #[serde(default)]
            valid_from: Option<Timestamp>,
            #[serde(default)]
            valid_until: Option<Timestamp>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            valid_from: raw.valid_from,
            valid_until: raw.valid_until,
        }
        .validated()
        .map_err(D::Error::custom)
    }
}

fn check_order(
    earlier_name: &'static str,
    earlier: Option<Timestamp>,
    later_name: &'static str,
    later: Option<Timestamp>,
) -> Result<()> {
    if let (Some(earlier_value), Some(later_value)) = (earlier, later)
        && earlier_value > later_value
    {
        return Err(ModelError::TimeOrder {
            earlier: earlier_name,
            earlier_value: earlier_value.to_rfc3339(),
            later: later_name,
            later_value: later_value.to_rfc3339(),
        });
    }
    Ok(())
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

    fn at(value: &str) -> Timestamp {
        Timestamp::parse_rfc3339(value).unwrap()
    }

    #[test]
    fn offsets_normalise_to_the_same_utc_instant() {
        let sydney = at("2024-03-01T09:00:00+11:00");
        let utc = at("2024-02-29T22:00:00Z");
        assert_eq!(sydney, utc);
        assert_eq!(sydney.to_rfc3339(), "2024-02-29T22:00:00Z");
    }

    #[test]
    fn parsing_with_original_hands_back_the_source_representation() {
        // Normalisation is lossy, so the caller is handed the bytes provenance needs to keep.
        let source = "2024-03-01T09:00:00+11:00";
        let (canonical, original) = Timestamp::parse_rfc3339_with_original(source).unwrap();
        assert_eq!(original, source);
        assert_ne!(canonical.to_rfc3339(), original);
        assert_eq!(canonical, at("2024-02-29T22:00:00Z"));
    }

    #[test]
    fn subsecond_precision_is_preserved_and_trailing_zeroes_are_not_invented() {
        assert_eq!(
            at("2024-01-01T00:00:00.123456Z").to_rfc3339(),
            "2024-01-01T00:00:00.123456Z"
        );
        // A source that wrote `.000` and a source that wrote nothing mean the same instant, and
        // canonical output picks one rendering so a fingerprint over it is stable.
        assert_eq!(at("2024-01-01T00:00:00.000Z"), at("2024-01-01T00:00:00Z"),);
    }

    #[test]
    fn round_trips_through_json_by_value() {
        for source in [
            "1970-01-01T00:00:00Z",
            "2024-06-30T23:59:60Z",
            "2024-01-01T00:00:00.123456789Z",
            "1969-07-20T20:17:00Z",
        ] {
            let parsed = at(source);
            let json = serde_json::to_string(&parsed).unwrap();
            let back: Timestamp = serde_json::from_str(&json).unwrap();
            assert_eq!(back, parsed, "round trip failed for {source}");
        }
    }

    #[test]
    fn rejects_hostile_and_malformed_timestamps() {
        for hostile in [
            "",
            "not a time",
            "2024-13-01T00:00:00Z",
            "2024-02-30T00:00:00Z",
            "2024-01-01",
            "2024-01-01T00:00:00",
            "2024-01-01T00:00:00+99:00",
            "1e9",
            "2024-01-01T00:00:00Z\u{0}",
        ] {
            assert!(
                Timestamp::parse_rfc3339(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn deserialisation_rejects_a_number() {
        // A UNIX epoch integer is a common source representation, and accepting it here would make
        // the canonical format ambiguous about its units.
        assert!(serde_json::from_str::<Timestamp>("1704067200").is_err());
    }

    #[test]
    fn epoch_and_unix_timestamp_agree() {
        assert_eq!(Timestamp::unix_epoch().unix_timestamp(), 0);
        assert_eq!(Timestamp::unix_epoch().to_rfc3339(), "1970-01-01T00:00:00Z");
        assert_eq!(at("1969-12-31T23:59:59Z").unix_timestamp(), -1);
    }

    #[test]
    fn ordering_is_chronological() {
        assert!(at("2020-01-01T00:00:00Z") < at("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn temporal_state_rejects_impossible_observation_order() {
        let error = TemporalState::observed(at("2024-01-02T00:00:00Z"), at("2024-01-01T00:00:00Z"))
            .unwrap_err();
        assert!(
            matches!(
                error,
                ModelError::TimeOrder {
                    earlier: "first_seen",
                    later: "last_seen",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn temporal_state_rejects_impossible_validity_order() {
        let state = TemporalState {
            valid_from: Some(at("2025-01-01T00:00:00Z")),
            valid_until: Some(at("2024-01-01T00:00:00Z")),
            ..TemporalState::unknown()
        };
        assert!(matches!(
            state.validated(),
            Err(ModelError::TimeOrder {
                earlier: "valid_from",
                ..
            })
        ));
    }

    #[test]
    fn equal_timestamps_are_a_valid_instantaneous_window() {
        let instant = at("2024-01-01T00:00:00Z");
        assert!(TemporalState::observed(instant, instant).is_ok());
    }

    #[test]
    fn deserialisation_enforces_ordering_and_rejects_unknown_fields() {
        let backwards = r#"{"first_seen":"2024-01-02T00:00:00Z","last_seen":"2024-01-01T00:00:00Z","valid_from":null,"valid_until":null}"#;
        assert!(serde_json::from_str::<TemporalState>(backwards).is_err());

        let unknown = r#"{"first_seen":null,"last_seen":null,"valid_from":null,"valid_until":null,"injected":"x"}"#;
        assert!(serde_json::from_str::<TemporalState>(unknown).is_err());
    }

    #[test]
    fn temporal_state_round_trips_and_omits_nothing() {
        let state = TemporalState {
            first_seen: Some(at("2024-01-01T00:00:00Z")),
            last_seen: Some(at("2024-01-05T00:00:00Z")),
            valid_from: None,
            valid_until: None,
        };
        let json = serde_json::to_value(state).unwrap();
        // Absent values serialise as null rather than disappearing: a reader must be able to tell
        // "the source said nothing" from "this build did not emit the field".
        assert!(json.get("valid_from").is_some());
        assert_eq!(json.get("valid_from"), Some(&serde_json::Value::Null));

        let back: TemporalState = serde_json::from_value(json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn expiry_requires_an_explicit_end() {
        let now = at("2024-06-01T00:00:00Z");

        let never_expires = TemporalState {
            first_seen: Some(at("2000-01-01T00:00:00Z")),
            ..TemporalState::unknown()
        };
        assert!(!never_expires.is_expired_at(now));

        let expired = TemporalState {
            valid_until: Some(at("2024-05-31T23:59:59Z")),
            ..TemporalState::unknown()
        };
        assert!(expired.is_expired_at(now));

        let boundary = TemporalState {
            valid_until: Some(now),
            ..TemporalState::unknown()
        };
        assert!(
            !boundary.is_expired_at(now),
            "validity is inclusive of its end"
        );
    }
}
