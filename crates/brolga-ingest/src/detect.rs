//! Format detection.
//!
//! Detection answers one question — *which parser reads this?* — and it has to answer it the same
//! way every time, and be able to say why. Both properties are load-bearing: a registry that picks
//! by whichever parser registered first turns a dependency reordering into a change in what Brolga
//! ingests, and a registry that cannot explain a miss leaves the operator with "unsupported" and no
//! next step.

use serde::Serialize;

use crate::parser::ParserId;

/// How many leading bytes a parser may look at when deciding.
///
/// Detection runs for every registered parser on every document, so it must not be proportional to
/// the document. A magic number, a root element, or a header line all live well inside this.
pub const SNIFF_BYTES: usize = 8192;

/// What a parser is shown when asked whether it claims a document.
///
/// Deliberately not the whole document: see [`SNIFF_BYTES`].
#[derive(Debug, Clone, Copy)]
pub struct FormatHint<'a> {
    media_type: &'a str,
    file_name: Option<&'a str>,
    prefix: &'a [u8],
    byte_length: u64,
}

impl<'a> FormatHint<'a> {
    /// Build a hint, truncating the sniffed prefix to [`SNIFF_BYTES`].
    #[must_use]
    pub fn new(
        media_type: &'a str,
        file_name: Option<&'a str>,
        bytes: &'a [u8],
        byte_length: u64,
    ) -> Self {
        let prefix = bytes.get(..SNIFF_BYTES).unwrap_or(bytes);
        Self {
            media_type,
            file_name,
            prefix,
            byte_length,
        }
    }

    /// The media type the document was offered under.
    ///
    /// Advisory. A feed that labels NDJSON as `application/octet-stream` is common enough that a
    /// parser refusing on media type alone would reject real data, so this is evidence rather than
    /// proof.
    #[must_use]
    pub const fn media_type(&self) -> &'a str {
        self.media_type
    }

    /// The file name, where the document came from somewhere that has one.
    #[must_use]
    pub const fn file_name(&self) -> Option<&'a str> {
        self.file_name
    }

    /// The leading bytes, capped at [`SNIFF_BYTES`].
    #[must_use]
    pub const fn prefix(&self) -> &'a [u8] {
        self.prefix
    }

    /// The full document length, which may exceed [`Self::prefix`].
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// The leading bytes as text, when they are valid UTF-8.
    ///
    /// `None` for binary formats, which is itself a useful signal for a text parser deciding to
    /// decline.
    #[must_use]
    pub fn prefix_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.prefix).ok()
    }

    /// The first non-empty line of the prefix, trimmed.
    ///
    /// The common shape of a text-format check, provided once so that ten parsers do not each write
    /// a slightly different version of it.
    #[must_use]
    pub fn first_line(&self) -> Option<&'a str> {
        self.prefix_str()?
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
    }

    /// Whether the file name ends with this extension, case-insensitively.
    ///
    /// Takes the extension without a dot, for example `"json"`.
    #[must_use]
    pub fn has_extension(&self, extension: &str) -> bool {
        self.file_name.is_some_and(|name| {
            name.rsplit_once('.')
                .is_some_and(|(_, found)| found.eq_ignore_ascii_case(extension))
        })
    }
}

/// How strongly a parser claims a document.
///
/// Ordered weakest to strongest so the registry can take the maximum. The gap between `Strong` and
/// `Certain` matters: `Certain` asserts that no other parser can be correct, and two parsers
/// claiming `Certain` on the same bytes is treated as a bug rather than resolved silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    /// This parser does not read this document.
    #[default]
    Declined,
    /// It might: the shape is plausible but nothing distinctive was found.
    ///
    /// A weak claim wins only if nothing claims more strongly, which is what makes a permissive
    /// catch-all parser usable without it swallowing documents a specific parser would have read
    /// properly.
    Weak,
    /// It very likely does: something distinctive to this format was found.
    Strong,
    /// It definitely does: a format marker was found that no other format carries.
    Certain,
}

impl DetectionConfidence {
    /// Whether this counts as a claim at all.
    #[must_use]
    pub const fn is_claim(self) -> bool {
        !matches!(self, Self::Declined)
    }

    /// A stable label for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declined => "declined",
            Self::Weak => "weak",
            Self::Strong => "strong",
            Self::Certain => "certain",
        }
    }
}

impl core::fmt::Display for DetectionConfidence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One parser's answer to "do you read this?".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// Which parser answered.
    pub parser: ParserId,
    /// Its algorithm version at the time it answered.
    pub parser_version: u32,
    /// How strongly it claims the document.
    pub confidence: DetectionConfidence,
    /// Why — what it looked for, and whether it found it.
    ///
    /// Shown to the operator when nothing matched, so "not JSON" is a worse reason than
    /// "first non-space byte is `<`, not `{`".
    ///
    /// `&'static str` on purpose. A reason interpolated from the document would put untrusted
    /// bytes into a diagnostic that is written to logs and shown to operators, which is the
    /// output-injection path the model's text types exist to close. Reasons are authored, not
    /// derived.
    pub reason: &'static str,
}

impl Candidate {
    /// The order the registry sorts candidates into: strongest claim first, then identifier.
    ///
    /// Identifier, not registration order, is the tie-break. Registration order is a property of
    /// how the binary was assembled; making it decide what gets parsed would mean a refactor could
    /// change ingestion results without changing a parser.
    #[must_use]
    pub fn selection_key(&self) -> (core::cmp::Reverse<DetectionConfidence>, &'static str) {
        (core::cmp::Reverse(self.confidence), self.parser.as_str())
    }

    /// Render a list of candidates for a diagnostic.
    #[must_use]
    pub fn summarise(candidates: &[Self]) -> String {
        candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{} ({}: {})",
                    candidate.parser, candidate.confidence, candidate.reason
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
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

    fn candidate(id: &'static str, confidence: DetectionConfidence) -> Candidate {
        Candidate {
            parser: ParserId::new(id),
            parser_version: 1,
            confidence,
            reason: "because",
        }
    }

    /// Detection must not read a gigabyte to decide. The cap is the mechanism.
    #[test]
    fn the_sniffed_prefix_is_capped_however_large_the_document_is() {
        let document = vec![b'x'; SNIFF_BYTES * 4];
        let length = u64::try_from(document.len()).unwrap();
        let hint = FormatHint::new("application/json", None, &document, length);

        assert_eq!(hint.prefix().len(), SNIFF_BYTES);
        assert_eq!(
            hint.byte_length(),
            length,
            "the full length is still reported, so a parser can decline on size"
        );
    }

    /// A document shorter than the cap must not be padded or truncated to it.
    #[test]
    fn a_short_document_is_sniffed_whole() {
        let hint = FormatHint::new("text/plain", None, b"hi", 2);
        assert_eq!(hint.prefix(), b"hi");
    }

    /// Binary input must not panic a text-oriented helper — this is the path hostile bytes take.
    #[test]
    fn invalid_utf8_yields_no_text_rather_than_a_panic() {
        let hint = FormatHint::new("application/octet-stream", None, &[0xff, 0xfe, 0x00], 3);
        assert_eq!(hint.prefix_str(), None);
        assert_eq!(hint.first_line(), None);
    }

    /// Leading blank lines are common in hand-edited feeds and must not defeat the check.
    #[test]
    fn the_first_line_skips_leading_blank_lines_and_trims() {
        let hint = FormatHint::new("text/csv", None, b"\n\n   name,value\nrow\n", 19);
        assert_eq!(hint.first_line(), Some("name,value"));
    }

    /// Extensions arrive in whatever case the filesystem had.
    #[test]
    fn extension_matching_ignores_case_and_needs_a_dot() {
        let hint = FormatHint::new("application/json", Some("Feed.JSON"), b"{}", 2);
        assert!(hint.has_extension("json"));
        assert!(!hint.has_extension("ndjson"));

        let no_dot = FormatHint::new("application/json", Some("jsonfile"), b"{}", 2);
        assert!(
            !no_dot.has_extension("json"),
            "a suffix is not an extension"
        );
    }

    /// The whole point of the ordering: registration order must not reach the outcome.
    #[test]
    fn candidates_sort_by_confidence_then_identifier_not_by_registration_order() {
        let mut forwards = vec![
            candidate("brolga.b", DetectionConfidence::Weak),
            candidate("brolga.a", DetectionConfidence::Strong),
            candidate("brolga.c", DetectionConfidence::Strong),
        ];
        let mut backwards = forwards.clone();
        backwards.reverse();

        forwards.sort_by_key(Candidate::selection_key);
        backwards.sort_by_key(Candidate::selection_key);

        let order: Vec<_> = forwards.iter().map(|c| c.parser.as_str()).collect();
        let other: Vec<_> = backwards.iter().map(|c| c.parser.as_str()).collect();

        assert_eq!(order, vec!["brolga.a", "brolga.c", "brolga.b"]);
        assert_eq!(order, other, "input order must not change the result");
    }

    /// `Declined` has to be the weakest so that taking the maximum never selects a refusal.
    #[test]
    fn declining_is_ordered_below_every_claim() {
        assert!(DetectionConfidence::Declined < DetectionConfidence::Weak);
        assert!(DetectionConfidence::Weak < DetectionConfidence::Strong);
        assert!(DetectionConfidence::Strong < DetectionConfidence::Certain);
        assert!(!DetectionConfidence::Declined.is_claim());
        assert!(DetectionConfidence::Weak.is_claim());
    }

    /// The summary is what the operator reads. It must carry the reason, not only the name.
    #[test]
    fn a_summary_carries_each_parser_its_confidence_and_its_reason() {
        let rendered =
            Candidate::summarise(&[candidate("brolga.a", DetectionConfidence::Declined)]);
        assert_eq!(rendered, "brolga.a (declined: because)");
    }
}
