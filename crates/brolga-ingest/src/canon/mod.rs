//! Canonicalisation: turning what a source wrote into a stable key, without losing what it wrote.
//!
//! Two things have to be true at once, and they pull against each other.
//!
//! A canonical form has to be **stable**, or the same artefact imported from two feeds becomes two
//! records and every count is wrong. And the **source's exact bytes** have to survive, or a
//! disagreement between Brolga and an upstream platform becomes unarguable — nobody can tell
//! whether the feed said something different or Brolga mangled it.
//!
//! [`Canonical`] carries both. The original is retained **only when canonicalisation changed
//! something**, because storing an identical copy of every unchanged value is noise that makes the
//! cases that did change harder to find.
//!
//! # Idempotence is the property that matters
//!
//! `canonicalise(canonicalise(x)) == canonicalise(x)`, for every canonicaliser here, checked by
//! property test rather than by inspection. Without it, re-importing Brolga's own output drifts:
//! each pass produces a slightly different key, the same artefact accumulates identifiers, and
//! deduplication silently stops working. It is the one property whose failure is invisible until
//! the data is already wrong.
//!
//! # No regular expressions
//!
//! Every canonicaliser here is a hand-written linear scan. [#12](https://github.com/jusso-dev/Brolga/issues/12)
//! requires that regex use be reviewed for denial-of-service risk; not using one is the strongest
//! available answer, and these grammars are simple enough that a regex would be harder to read as
//! well as harder to bound. Where a length limit applies it is checked *before* the scan.

pub mod file;
pub mod ident;
pub mod net;
pub mod time;

use core::fmt;

/// A canonicalised value, together with what the source wrote if that differed.
///
/// `original` is `Some` only when canonicalisation changed the input. `None` means the source's
/// bytes and the canonical form are the same string, so there is nothing extra to retain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical<T> {
    value: T,
    original: Option<String>,
}

impl<T> Canonical<T> {
    /// A value that canonicalisation did not change.
    pub const fn unchanged(value: T) -> Self {
        Self {
            value,
            original: None,
        }
    }

    /// A value that canonicalisation changed, retaining what the source wrote.
    pub fn changed(value: T, original: impl Into<String>) -> Self {
        Self {
            value,
            original: Some(original.into()),
        }
    }

    /// Build from a canonical value and the raw input, deciding for itself whether they differ.
    ///
    /// The comparison is against `T`'s own `Display`, so this is only correct where that renders
    /// the canonical *value* alone. It does not for
    /// [`Observable`](brolga_model::Observable), whose `Display` is `kind:value` — use
    /// [`Self::from_parts`] there and pass `canonical_value()`. Getting this wrong marks every
    /// value as changed, which is silent: the data is still right, but every record grows a
    /// redundant original and the ones that genuinely changed stop standing out.
    pub fn from_raw(value: T, raw: &str) -> Self
    where
        T: fmt::Display,
    {
        Self::from_parts_inner(value, |value| value.to_string(), raw)
    }

    /// Build from a canonical value, an explicit rendering of it, and the raw input.
    ///
    /// For types whose `Display` is not the bare canonical form.
    pub fn from_parts(value: T, canonical_form: &str, raw: &str) -> Self {
        if canonical_form == raw {
            Self::unchanged(value)
        } else {
            Self::changed(value, raw)
        }
    }

    fn from_parts_inner(value: T, render: impl FnOnce(&T) -> String, raw: &str) -> Self {
        let rendered = render(&value);
        Self::from_parts(value, &rendered, raw)
    }

    /// The canonical value.
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// What the source wrote, when that differed from the canonical form.
    pub fn original(&self) -> Option<&str> {
        self.original.as_deref()
    }

    /// Whether canonicalisation changed anything.
    pub const fn was_changed(&self) -> bool {
        self.original.is_some()
    }

    /// Take the canonical value, discarding the original.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Apply a function to the canonical value, keeping the original.
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> Canonical<U> {
        Canonical {
            value: transform(self.value),
            original: self.original,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Canonical<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

/// Why a value could not be canonicalised.
///
/// Typed rather than a string, so a caller can decide what to do — quarantine, skip, or fail the
/// batch — without matching on prose that a later edit would silently change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CanonError {
    /// The value was empty or only whitespace.
    #[error("{kind} was empty")]
    Empty {
        /// What was being canonicalised.
        kind: &'static str,
    },

    /// The value exceeded the length this kind permits.
    ///
    /// Checked before any scan, so an oversized input costs a length comparison rather than a walk.
    #[error("{kind} is {actual} bytes, over the {max}-byte limit")]
    TooLong {
        /// What was being canonicalised.
        kind: &'static str,
        /// The permitted length.
        max: usize,
        /// The length supplied.
        actual: usize,
    },

    /// The value does not have the shape this kind requires.
    #[error("{kind} {preview:?} is not valid: {reason}")]
    Malformed {
        /// What was being canonicalised.
        kind: &'static str,
        /// A bounded, control-character-free excerpt of the input.
        preview: String,
        /// What specifically was wrong.
        reason: &'static str,
    },

    /// The value contained a character this kind does not permit.
    #[error("{kind} {preview:?} contains {character:?}, which is not permitted in {position}")]
    ForbiddenCharacter {
        /// What was being canonicalised.
        kind: &'static str,
        /// A bounded, control-character-free excerpt of the input.
        preview: String,
        /// The offending character.
        character: char,
        /// Where in the value it appeared.
        position: &'static str,
    },
}

impl CanonError {
    /// Which kind of value failed.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Empty { kind }
            | Self::TooLong { kind, .. }
            | Self::Malformed { kind, .. }
            | Self::ForbiddenCharacter { kind, .. } => kind,
        }
    }

    /// A malformed-value error carrying a safe excerpt.
    #[must_use]
    pub fn malformed(kind: &'static str, raw: &str, reason: &'static str) -> Self {
        Self::Malformed {
            kind,
            preview: preview(raw),
            reason,
        }
    }

    /// A forbidden-character error carrying a safe excerpt.
    #[must_use]
    pub fn forbidden(
        kind: &'static str,
        raw: &str,
        character: char,
        position: &'static str,
    ) -> Self {
        Self::ForbiddenCharacter {
            kind,
            preview: preview(raw),
            character,
            position,
        }
    }
}

/// How much of an offending value an error message may quote.
pub const PREVIEW_MAX_CHARS: usize = 64;

/// A bounded, control-character-free excerpt of untrusted input, for a diagnostic.
///
/// Diagnostics reach logs and terminals. An unfiltered excerpt of a hostile feed value is an
/// output-injection vector — an escape sequence in an indicator would be *rendered* by whatever
/// reads the log — so control characters are dropped rather than escaped, and the length is capped
/// so one bad record cannot fill a log file.
#[must_use]
pub fn preview(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|character| !character.is_control())
        .take(PREVIEW_MAX_CHARS)
        .collect();
    if raw.chars().filter(|c| !c.is_control()).count() > PREVIEW_MAX_CHARS {
        out.push('…');
    }
    out
}

/// Reject an empty or whitespace-only value, and trim surrounding whitespace.
///
/// Leading and trailing whitespace is a transport artefact of every line-oriented feed and carries
/// no meaning, so trimming it is safe. Interior whitespace is left alone, because in a file path or
/// a user agent it is content.
///
/// # Errors
///
/// Returns [`CanonError::Empty`] if nothing remains after trimming.
pub fn trimmed<'a>(kind: &'static str, raw: &'a str) -> Result<&'a str, CanonError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CanonError::Empty { kind });
    }
    Ok(trimmed)
}

/// Reject a value longer than a limit, before anything scans it.
///
/// # Errors
///
/// Returns [`CanonError::TooLong`] if the value is over the limit.
pub fn within(kind: &'static str, raw: &str, max: usize) -> Result<(), CanonError> {
    if raw.len() > max {
        return Err(CanonError::TooLong {
            kind,
            max,
            actual: raw.len(),
        });
    }
    Ok(())
}

/// Reject C0 and C1 control characters anywhere in a value.
///
/// Every canonicaliser here calls this. A NUL truncates a C string, and the remaining control codes
/// are terminal escapes that turn a stored indicator into an output-injection payload the moment
/// anything prints it.
///
/// # Errors
///
/// Returns [`CanonError::ForbiddenCharacter`] for the first control character found.
pub fn no_control_characters(kind: &'static str, raw: &str) -> Result<(), CanonError> {
    if let Some(character) = raw.chars().find(|character| character.is_control()) {
        return Err(CanonError::forbidden(kind, raw, character, "any position"));
    }
    Ok(())
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

    /// An unchanged value must not carry a redundant copy of itself.
    #[test]
    fn an_unchanged_value_retains_no_original() {
        let canonical = Canonical::from_raw("example.com".to_owned(), "example.com");
        assert!(!canonical.was_changed());
        assert_eq!(canonical.original(), None);
    }

    /// A changed value must retain exactly what the source wrote, not a tidied version of it.
    #[test]
    fn a_changed_value_retains_the_source_bytes_verbatim() {
        let canonical = Canonical::from_raw("example.com".to_owned(), "EXAMPLE.COM.");
        assert!(canonical.was_changed());
        assert_eq!(canonical.original(), Some("EXAMPLE.COM."));
        assert_eq!(canonical.value(), "example.com");
    }

    /// `from_raw` compares against the canonical form's own rendering, so a canonicaliser cannot
    /// change something and forget to record it.
    #[test]
    fn from_raw_detects_a_change_the_caller_did_not_declare() {
        let canonical = Canonical::from_raw(42_u32, "042");
        assert!(canonical.was_changed(), "042 and 42 are different strings");
    }

    /// Diagnostics reach logs and terminals. Dropping the ESC is what defuses the sequence — the
    /// `[31m` that follows is ordinary printable text and is harmless once nothing introduces it.
    #[test]
    fn a_preview_drops_control_characters_rather_than_escaping_them() {
        let rendered = preview("evil\u{1b}[31mred\u{0}");
        assert_eq!(rendered, "evil[31mred");
        assert!(!rendered.chars().any(char::is_control));
    }

    /// One hostile record must not be able to fill a log file.
    #[test]
    fn a_preview_is_capped_and_says_it_was_truncated() {
        let long = "a".repeat(PREVIEW_MAX_CHARS * 3);
        let rendered = preview(&long);
        assert_eq!(rendered.chars().count(), PREVIEW_MAX_CHARS + 1);
        assert!(rendered.ends_with('…'));
    }

    /// Surrounding whitespace is a transport artefact; interior whitespace is content.
    #[test]
    fn trimming_removes_surrounding_whitespace_and_keeps_interior_whitespace() {
        assert_eq!(trimmed("Test", "  a b  ").unwrap(), "a b");
        assert!(matches!(
            trimmed("Test", "   ").unwrap_err(),
            CanonError::Empty { .. }
        ));
    }

    /// The length check must happen before any scan, so an oversized input is cheap to reject.
    #[test]
    fn an_oversized_value_is_rejected_with_both_lengths() {
        let error = within("Test", "abcdef", 3).unwrap_err();
        assert!(matches!(
            error,
            CanonError::TooLong {
                max: 3,
                actual: 6,
                ..
            }
        ));
    }

    /// A NUL truncates a C string; the rest are terminal escapes.
    #[test]
    fn control_characters_are_refused_anywhere_in_a_value() {
        assert!(no_control_characters("Test", "clean").is_ok());
        let error = no_control_characters("Test", "bad\u{0}value").unwrap_err();
        assert!(matches!(
            error,
            CanonError::ForbiddenCharacter {
                character: '\u{0}',
                ..
            }
        ));
    }

    /// A caller routing a failure to quarantine needs the kind without parsing the message.
    #[test]
    fn every_error_reports_its_kind_without_the_caller_parsing_prose() {
        assert_eq!(CanonError::Empty { kind: "Cve" }.kind(), "Cve");
        assert_eq!(
            CanonError::malformed("Purl", "x", "no scheme").kind(),
            "Purl"
        );
    }
}
