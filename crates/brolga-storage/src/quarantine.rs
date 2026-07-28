//! Records that could not be accepted, kept where somebody can look at them.
//!
//! # Why quarantine rather than a log line
//!
//! A rejected record that only produced a log line is gone. Nobody can re-run it, diff it against
//! the feed, or answer "what exactly did they send us?" three weeks later when the vendor disagrees.
//! A count of failures tells you something is wrong and nothing about what.
//!
//! So a rejection is a **record**: what was rejected, which parser rejected it, at which stage, for
//! what typed reason, and the address of the retained original it came from. That last part is why
//! this arrived alongside [`crate::blob`] — a quarantined record whose source was not retained can
//! be counted but not diagnosed.
//!
//! # Identity is the rejection, not the attempt
//!
//! A quarantine row's identifier is derived from the source, parser, stage, reason, and position —
//! everything about *what went wrong* — and not from the time it happened. Re-importing a broken
//! feed therefore updates one row and increments its occurrence count, rather than appending a new
//! row per attempt. A quarantine that doubles in size on every retry is one nobody reads.
//!
//! # Quarantined content is still untrusted
//!
//! Being rejected does not make a value safe. The retained fragment is bounded and stripped of
//! control characters on the way in, because a quarantine table is read by operators and rendered
//! by whatever they read it with — which is exactly the output-injection path that a hostile feed
//! would aim at.

use core::fmt;

use brolga_model::provenance::ContentHash;
use serde::{Deserialize, Serialize};

/// Longest fragment of a rejected value retained, in characters.
///
/// Enough to recognise the record; far short of enough for one hostile row to fill the table.
pub const FRAGMENT_MAX_CHARS: usize = 512;

/// Which stage rejected a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QuarantineStage {
    /// No parser claimed the document.
    Detection,
    /// The parser could not read it.
    Parsing,
    /// The parser produced something the canonical model rejects.
    Validation,
    /// A limit was exceeded.
    Limits,
    /// Persistence refused it.
    Storage,
}

impl QuarantineStage {
    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Parsing => "parsing",
            Self::Validation => "validation",
            Self::Limits => "limits",
            Self::Storage => "storage",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "detection" => Some(Self::Detection),
            "parsing" => Some(Self::Parsing),
            "validation" => Some(Self::Validation),
            "limits" => Some(Self::Limits),
            "storage" => Some(Self::Storage),
            _ => None,
        }
    }
}

impl fmt::Display for QuarantineStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A rejected record, kept for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRecord {
    /// Deterministic identifier, derived from what went wrong rather than when.
    pub id: String,
    /// Address of the retained original this came from.
    pub source_hash: ContentHash,
    /// Which parser rejected it.
    pub parser: String,
    /// That parser's version at the time.
    pub parser_version: u32,
    /// Which stage rejected it.
    pub stage: QuarantineStage,
    /// A stable machine-readable reason category.
    pub reason_kind: String,
    /// The full diagnostic, for a human.
    pub reason: String,
    /// Position in the parser's own output, where there was one.
    pub record_index: Option<u64>,
    /// Byte offset into the document, where the parser identified one.
    pub byte_offset: Option<u64>,
    /// A bounded, control-character-free excerpt of what was rejected.
    pub fragment: Option<String>,
    /// When this rejection was first recorded.
    pub first_seen_at: String,
    /// When it was most recently recorded.
    pub last_seen_at: String,
    /// How many times this exact rejection has been seen.
    pub occurrences: u64,
}

/// A rejection being recorded, before the store fills in the timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// Address of the retained original this came from.
    pub source_hash: ContentHash,
    /// Which parser rejected it.
    pub parser: String,
    /// That parser's version.
    pub parser_version: u32,
    /// Which stage rejected it.
    pub stage: QuarantineStage,
    /// A stable machine-readable reason category.
    pub reason_kind: String,
    /// The full diagnostic.
    pub reason: String,
    /// Position in the parser's output, where there was one.
    pub record_index: Option<u64>,
    /// Byte offset into the document, where there was one.
    pub byte_offset: Option<u64>,
    /// A bounded, control-character-free excerpt of what was rejected.
    pub fragment: Option<String>,
}

impl QuarantineEntry {
    /// Build an entry, sanitising the fragment.
    #[must_use]
    pub fn new(
        source_hash: ContentHash,
        parser: impl Into<String>,
        parser_version: u32,
        stage: QuarantineStage,
        reason_kind: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            source_hash,
            parser: parser.into(),
            parser_version,
            stage,
            reason_kind: reason_kind.into(),
            reason: reason.into(),
            record_index: None,
            byte_offset: None,
            fragment: None,
        }
    }

    /// Attach the position in the parser's output.
    #[must_use]
    pub const fn at_index(mut self, index: u64) -> Self {
        self.record_index = Some(index);
        self
    }

    /// Attach a byte offset into the document.
    #[must_use]
    pub const fn at_offset(mut self, offset: u64) -> Self {
        self.byte_offset = Some(offset);
        self
    }

    /// Attach an excerpt of the rejected value.
    ///
    /// Sanitised here rather than by the caller: this is untrusted content on its way to a table an
    /// operator will read, and leaving the sanitising to each call site means one of them forgets.
    #[must_use]
    pub fn with_fragment(mut self, fragment: &str) -> Self {
        self.fragment = Some(sanitise_fragment(fragment));
        self
    }

    /// The deterministic identifier for this rejection.
    ///
    /// Derived from what went wrong — source, parser, stage, reason category, and position — and
    /// deliberately **not** from the clock or from the full diagnostic text. Two imports of the same
    /// broken feed produce one row with a higher occurrence count, and rewording a diagnostic does
    /// not orphan the row it used to identify.
    #[must_use]
    pub fn derive_id(&self) -> String {
        let position = match (self.record_index, self.byte_offset) {
            (Some(index), _) => format!("index:{index}"),
            (None, Some(offset)) => format!("offset:{offset}"),
            (None, None) => "whole-document".to_owned(),
        };
        let material = format!(
            "{}|{}|{}|{}|{}|{position}",
            self.source_hash, self.parser, self.parser_version, self.stage, self.reason_kind,
        );
        ContentHash::of(material.as_bytes()).to_string()
    }
}

/// Bound an excerpt and strip control characters.
///
/// Control characters are dropped rather than escaped, because a quarantine table is read by
/// operators through terminals and web views, and an escape sequence in a rejected indicator would
/// be *rendered* rather than displayed.
#[must_use]
pub fn sanitise_fragment(fragment: &str) -> String {
    let mut out: String = fragment
        .chars()
        .filter(|character| !character.is_control())
        .take(FRAGMENT_MAX_CHARS)
        .collect();
    if fragment.chars().filter(|c| !c.is_control()).count() > FRAGMENT_MAX_CHARS {
        out.push('…');
    }
    out
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

    fn entry() -> QuarantineEntry {
        QuarantineEntry::new(
            ContentHash::of(b"a feed"),
            "brolga.test.records",
            1,
            QuarantineStage::Parsing,
            "malformed_line",
            "expected a line beginning `entity:`",
        )
    }

    /// The point of deriving identity from the rejection rather than the attempt: a broken feed
    /// re-imported nightly must update one row, not append one per night.
    #[test]
    fn the_same_rejection_derives_the_same_identifier_however_often_it_happens() {
        assert_eq!(entry().derive_id(), entry().derive_id());
    }

    /// Rewording a diagnostic must not orphan the row it identified, or every message improvement
    /// silently resets the occurrence counts.
    #[test]
    fn rewording_the_diagnostic_does_not_change_the_identity() {
        let original = entry();
        let mut reworded = entry();
        reworded.reason = "expected a line starting with `entity:`".to_owned();
        assert_eq!(original.derive_id(), reworded.derive_id());
    }

    /// Two genuinely different rejections must not collapse into one row.
    #[test]
    fn different_rejections_derive_different_identifiers() {
        let base = entry();
        let mut other_stage = entry();
        other_stage.stage = QuarantineStage::Validation;
        let mut other_kind = entry();
        other_kind.reason_kind = "too_long".to_owned();

        let ids = [
            base.derive_id(),
            other_stage.derive_id(),
            other_kind.derive_id(),
            base.clone().at_index(3).derive_id(),
            base.clone().at_index(4).derive_id(),
        ];
        let mut unique = ids.clone().to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "identities collided");
    }

    /// A quarantine table is read through terminals. An escape sequence in a rejected indicator
    /// would be rendered by whatever displays it.
    #[test]
    fn a_fragment_is_stripped_of_control_characters_on_the_way_in() {
        let entry = entry().with_fragment("bad\u{1b}[31mvalue\u{0}");
        let fragment = entry.fragment.unwrap();
        assert!(!fragment.chars().any(char::is_control));
        assert!(fragment.contains("value"));
    }

    /// One hostile row must not be able to fill the table.
    #[test]
    fn a_fragment_is_bounded_and_says_it_was_truncated() {
        let entry = entry().with_fragment(&"x".repeat(FRAGMENT_MAX_CHARS * 4));
        let fragment = entry.fragment.unwrap();
        assert_eq!(fragment.chars().count(), FRAGMENT_MAX_CHARS + 1);
        assert!(fragment.ends_with('…'));
    }

    /// Stage labels are written to the database, so they are a compatibility surface.
    #[test]
    fn every_stage_label_round_trips_and_an_unknown_one_is_refused() {
        for stage in [
            QuarantineStage::Detection,
            QuarantineStage::Parsing,
            QuarantineStage::Validation,
            QuarantineStage::Limits,
            QuarantineStage::Storage,
        ] {
            assert_eq!(QuarantineStage::from_str_opt(stage.as_str()), Some(stage));
        }
        assert_eq!(QuarantineStage::from_str_opt("vibes"), None);
    }
}
