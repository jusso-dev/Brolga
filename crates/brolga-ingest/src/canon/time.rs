//! Timestamp normalisation that keeps the offset the source wrote.
//!
//! Brolga stores instants in UTC, because comparing two timestamps that carry different offsets is
//! a bug waiting for a reader who forgets. But the offset is *evidence*: a report timestamped
//! `2026-03-01T09:00:00+10:00` tells you the publisher was on Australian eastern time, which is
//! part of attributing where an observation came from. Normalising to UTC and discarding the offset
//! throws that away silently, and no later step can recover it.
//!
//! So both are kept: [`Timestamp`] for comparison, and the source's exact string as the original.

use brolga_model::Timestamp;

use super::{CanonError, Canonical, no_control_characters, trimmed, within};

/// Longest timestamp accepted before any scan.
///
/// An RFC 3339 timestamp with maximal fractional seconds and an offset fits well inside this.
pub const TIMESTAMP_MAX_BYTES: usize = 64;

/// Canonicalise an RFC 3339 timestamp, retaining what the source wrote.
///
/// The canonical value is the instant in UTC. The original is retained whenever the source's
/// spelling differs from the canonical rendering — which is the case for any non-UTC offset, any
/// lowercase `t`/`z`, and any fractional-second precision the canonical form does not reproduce.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`] if the value is not RFC 3339.
pub fn rfc3339(raw: &str) -> Result<Canonical<Timestamp>, CanonError> {
    const KIND: &str = "Timestamp";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, TIMESTAMP_MAX_BYTES)?;

    let (timestamp, original) = Timestamp::parse_rfc3339_with_original(value).map_err(|_| {
        CanonError::malformed(
            KIND,
            value,
            "is not an RFC 3339 date-time with a date, a time, and an offset",
        )
    })?;

    // Compare against the canonical rendering rather than against the input, so that a value which
    // round-trips identically records no original and one that does not always records one.
    if timestamp.to_rfc3339() == original {
        Ok(Canonical::unchanged(timestamp))
    } else {
        Ok(Canonical::changed(timestamp, original))
    }
}

/// Whether a timestamp string carries an offset other than UTC.
///
/// Used to decide whether an offset is worth recording as a separate provenance note rather than
/// only as the original string.
#[must_use]
pub fn has_non_utc_offset(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.ends_with('Z') || trimmed.ends_with('z') {
        return false;
    }
    // The offset sign appears after the time, so only look past the date's own hyphens.
    let time_start = trimmed
        .find(['T', 't'])
        .map_or(0, |index| index.saturating_add(1));
    trimmed
        .get(time_start..)
        .is_some_and(|time| time.contains('+') || time.contains('-'))
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

    /// The criterion: an offset must survive canonicalisation as evidence, not be discarded.
    #[test]
    fn a_non_utc_offset_is_retained_as_the_original() {
        let canonical = rfc3339("2026-03-01T09:00:00+10:00").unwrap();
        assert_eq!(canonical.original(), Some("2026-03-01T09:00:00+10:00"));
        assert_eq!(
            canonical.value().to_rfc3339(),
            "2026-02-28T23:00:00Z",
            "the canonical value is the same instant in UTC"
        );
    }

    /// Two spellings of one instant must produce one canonical value, or every comparison between
    /// feeds on different offsets is wrong.
    #[test]
    fn two_offsets_naming_one_instant_canonicalise_to_the_same_value() {
        let sydney = rfc3339("2026-03-01T09:00:00+10:00").unwrap();
        let utc = rfc3339("2026-02-28T23:00:00Z").unwrap();
        assert_eq!(sydney.value(), utc.value());
        assert_ne!(
            sydney.original(),
            utc.original(),
            "but the two sources' spellings stay distinguishable"
        );
    }

    /// A value already in canonical form must not accumulate a redundant original.
    #[test]
    fn an_already_canonical_utc_timestamp_records_no_original() {
        let canonical = rfc3339("2026-02-28T23:00:00Z").unwrap();
        assert!(!canonical.was_changed());
    }

    /// Idempotence, stated directly for the type where it is easiest to get wrong.
    #[test]
    fn canonicalising_a_canonical_timestamp_changes_nothing() {
        let once = rfc3339("2026-03-01T09:00:00+10:00").unwrap();
        let twice = rfc3339(&once.value().to_rfc3339()).unwrap();
        assert_eq!(once.value(), twice.value());
        assert!(!twice.was_changed());
    }

    /// A date with no time is not an instant, and guessing midnight in some zone would invent data.
    #[test]
    fn a_bare_date_is_refused_rather_than_assumed_to_be_midnight() {
        assert!(matches!(
            rfc3339("2026-03-01").unwrap_err(),
            CanonError::Malformed { .. }
        ));
    }

    /// Offset detection must not mistake the date's hyphens for an offset sign.
    #[test]
    fn offset_detection_ignores_the_hyphens_in_the_date() {
        assert!(!has_non_utc_offset("2026-02-28T23:00:00Z"));
        assert!(has_non_utc_offset("2026-02-28T23:00:00-05:00"));
        assert!(has_non_utc_offset("2026-02-28T23:00:00+10:00"));
    }
}
