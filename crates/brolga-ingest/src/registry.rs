//! The parser registry: which parser reads a document, and why that one.

use std::collections::BTreeMap;

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::{IngestError, Result};
use crate::parser::{IntelligenceParser, ParserId};

/// The outcome of asking every parser about a document.
///
/// Carries the losers as well as the winner. An operator asking "why did the CSV parser read my
/// STIX bundle?" needs to see that the STIX parser declined and what it was looking for; a
/// selection that returns only the winner cannot answer that.
#[derive(Debug, Clone)]
pub struct Selection {
    chosen: Candidate,
    considered: Vec<Candidate>,
}

impl Selection {
    /// The parser that will run.
    #[must_use]
    pub const fn chosen(&self) -> &Candidate {
        &self.chosen
    }

    /// Every parser that was asked, strongest claim first, then by identifier.
    #[must_use]
    pub fn considered(&self) -> &[Candidate] {
        &self.considered
    }

    /// A one-line explanation of the choice, for `--explain` output and logs.
    #[must_use]
    pub fn explain(&self) -> String {
        let others: Vec<String> = self
            .considered
            .iter()
            .filter(|candidate| candidate.parser != self.chosen.parser)
            .map(|candidate| {
                format!(
                    "{} ({}: {})",
                    candidate.parser, candidate.confidence, candidate.reason
                )
            })
            .collect();

        let tail = if others.is_empty() {
            "no other parser was registered".to_owned()
        } else {
            format!("over {}", others.join("; "))
        };

        format!(
            "selected {} v{} ({}: {}) {tail}",
            self.chosen.parser,
            self.chosen.parser_version,
            self.chosen.confidence,
            self.chosen.reason,
        )
    }
}

/// Every parser Brolga can select from.
///
/// Keyed by identifier in a [`BTreeMap`], so iteration order is the identifier order rather than
/// the insertion order. That is the difference between a registry whose behaviour is a property of
/// its contents and one whose behaviour is a property of the order somebody wrote the calls in.
#[derive(Default)]
pub struct ParserRegistry {
    parsers: BTreeMap<ParserId, Box<dyn IntelligenceParser>>,
}

impl core::fmt::Debug for ParserRegistry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ParserRegistry")
            .field("parsers", &self.ids())
            .finish()
    }
}

impl ParserRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parsers: BTreeMap::new(),
        }
    }

    /// Add a parser, replacing any parser already registered under the same identifier.
    ///
    /// Returns the displaced parser's identifier when one was replaced, so a caller that did not
    /// intend to shadow a parser can notice. Silent replacement is how two parsers end up sharing
    /// an identifier and only one of them ever runs.
    pub fn register(&mut self, parser: Box<dyn IntelligenceParser>) -> Option<ParserId> {
        let id = parser.id();
        self.parsers.insert(id, parser).map(|_| id)
    }

    /// Every registered identifier, in identifier order.
    #[must_use]
    pub fn ids(&self) -> Vec<ParserId> {
        self.parsers.keys().copied().collect()
    }

    /// How many parsers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Whether no parser is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Look a parser up by identifier.
    #[must_use]
    pub fn get(&self, id: ParserId) -> Option<&dyn IntelligenceParser> {
        self.parsers.get(&id).map(Box::as_ref)
    }

    /// Ask every parser about a document, without choosing one.
    ///
    /// Ordered strongest claim first, then by identifier.
    #[must_use]
    pub fn candidates(&self, hint: &FormatHint<'_>) -> Vec<Candidate> {
        let mut candidates: Vec<Candidate> = self
            .parsers
            .values()
            .map(|parser| parser.detect(hint))
            .collect();
        candidates.sort_by_key(Candidate::selection_key);
        candidates
    }

    /// Choose the parser for a document.
    ///
    /// # Errors
    ///
    /// - [`IngestError::UnknownFormat`] when every parser declined, carrying each one's reason.
    /// - [`IngestError::AmbiguousFormat`] when two parsers both claimed
    ///   [`DetectionConfidence::Certain`]. Certainty means "no other parser can be right", so two of
    ///   them is a contradiction, and picking the alphabetically first would bury a real bug under
    ///   behaviour that merely looks deterministic. Ties at every weaker level *are* resolved by
    ///   identifier, because "probably me" from two parsers is not a contradiction.
    pub fn select(&self, hint: &FormatHint<'_>) -> Result<Selection> {
        let considered = self.candidates(hint);

        let certain: Vec<&Candidate> = considered
            .iter()
            .filter(|candidate| candidate.confidence == DetectionConfidence::Certain)
            .collect();
        if let [first, second, ..] = certain.as_slice() {
            return Err(IngestError::AmbiguousFormat {
                first: first.parser,
                second: second.parser,
                media_type: hint.media_type().to_owned(),
            });
        }

        let chosen = considered
            .iter()
            .find(|candidate| candidate.confidence.is_claim())
            .cloned();

        match chosen {
            Some(chosen) => Ok(Selection { chosen, considered }),
            None => Err(IngestError::UnknownFormat {
                media_type: hint.media_type().to_owned(),
                byte_length: hint.byte_length(),
                considered,
            }),
        }
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
    use crate::error::ParseError;
    use crate::parser::{ParseContext, ParseOutput};

    /// A parser whose answer is fixed at construction, so a test can state the situation it wants
    /// rather than construct bytes that happen to produce it.
    struct Fixed {
        id: ParserId,
        confidence: DetectionConfidence,
    }

    impl Fixed {
        fn boxed(id: &'static str, confidence: DetectionConfidence) -> Box<dyn IntelligenceParser> {
            Box::new(Self {
                id: ParserId::new(id),
                confidence,
            })
        }
    }

    impl IntelligenceParser for Fixed {
        fn id(&self) -> ParserId {
            self.id
        }

        fn version(&self) -> u32 {
            1
        }

        fn detect(&self, _hint: &FormatHint<'_>) -> Candidate {
            Candidate {
                parser: self.id,
                parser_version: 1,
                confidence: self.confidence,
                reason: "fixed for the test",
            }
        }

        fn parse(
            &self,
            _context: &ParseContext,
            _bytes: &[u8],
        ) -> core::result::Result<ParseOutput, ParseError> {
            Ok(ParseOutput::default())
        }
    }

    fn hint<'a>(bytes: &'a [u8]) -> FormatHint<'a> {
        FormatHint::new("application/json", None, bytes, 2)
    }

    /// The acceptance criterion. Registration order is an accident of how the binary was
    /// assembled and must not decide what parses a document.
    #[test]
    fn selection_does_not_depend_on_registration_order() {
        let orderings = [
            ["brolga.a", "brolga.b", "brolga.c"],
            ["brolga.c", "brolga.b", "brolga.a"],
            ["brolga.b", "brolga.a", "brolga.c"],
        ];

        let mut chosen = Vec::new();
        for ordering in orderings {
            let mut registry = ParserRegistry::new();
            for id in ordering {
                registry.register(Fixed::boxed(id, DetectionConfidence::Strong));
            }
            chosen.push(
                registry
                    .select(&hint(b"{}"))
                    .unwrap()
                    .chosen()
                    .parser
                    .as_str(),
            );
        }

        assert_eq!(
            chosen,
            vec!["brolga.a", "brolga.a", "brolga.a"],
            "the same parser wins whatever order they were registered in"
        );
    }

    /// A stronger claim must beat an alphabetically earlier one, or the tie-break would quietly
    /// become the whole rule.
    #[test]
    fn a_stronger_claim_beats_an_earlier_identifier() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Weak));
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Strong));

        let selection = registry.select(&hint(b"{}")).unwrap();
        assert_eq!(selection.chosen().parser.as_str(), "brolga.zzz");
    }

    /// The registry must never select a parser that said no.
    #[test]
    fn a_declining_parser_is_never_selected() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Declined));
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Weak));

        let selection = registry.select(&hint(b"{}")).unwrap();
        assert_eq!(selection.chosen().parser.as_str(), "brolga.zzz");
    }

    /// Two parsers each asserting nobody else can be right is a contradiction. Resolving it by
    /// name order would be deterministic and would hide the bug.
    #[test]
    fn two_certain_parsers_are_refused_rather_than_resolved_by_name() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Certain));
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Certain));

        let error = registry.select(&hint(b"{}")).unwrap_err();
        assert!(
            matches!(error, IngestError::AmbiguousFormat { .. }),
            "got {error:?}"
        );
    }

    /// Two parsers saying "probably me" is not a contradiction, so it resolves rather than fails.
    #[test]
    fn a_tie_below_certainty_resolves_by_identifier_rather_than_failing() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Strong));
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Strong));

        let selection = registry.select(&hint(b"{}")).unwrap();
        assert_eq!(selection.chosen().parser.as_str(), "brolga.aaa");
    }

    /// The acceptance criterion for unknown formats: the diagnostic must carry every parser asked.
    #[test]
    fn an_unmatched_document_reports_every_parser_and_its_reason() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Declined));
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Declined));

        let error = registry.select(&hint(b"<xml/>")).unwrap_err();
        let IngestError::UnknownFormat { considered, .. } = &error else {
            panic!("got {error:?}");
        };
        assert_eq!(considered.len(), 2);
        assert!(error.to_string().contains("fixed for the test"));
    }

    /// An empty registry must say so as an unknown format rather than by some other route.
    #[test]
    fn an_empty_registry_reports_an_unknown_format_with_nothing_considered() {
        let registry = ParserRegistry::new();
        let error = registry.select(&hint(b"{}")).unwrap_err();
        let IngestError::UnknownFormat { considered, .. } = &error else {
            panic!("got {error:?}");
        };
        assert!(considered.is_empty());
    }

    /// Shadowing a registered parser silently is how two parsers share an identifier and only one
    /// ever runs.
    #[test]
    fn registering_over_an_identifier_reports_what_was_displaced() {
        let mut registry = ParserRegistry::new();
        assert_eq!(
            registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Weak)),
            None
        );
        assert_eq!(
            registry
                .register(Fixed::boxed("brolga.aaa", DetectionConfidence::Strong))
                .map(|id| id.as_str()),
            Some("brolga.aaa"),
        );
        assert_eq!(registry.len(), 1);
    }

    /// The explanation is the criterion's "explainable" half. It has to name the losers too.
    #[test]
    fn the_explanation_names_the_winner_and_what_it_beat() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Strong));
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Weak));

        let explanation = registry.select(&hint(b"{}")).unwrap().explain();
        assert!(
            explanation.contains("selected brolga.aaa v1"),
            "{explanation}"
        );
        assert!(explanation.contains("strong"), "{explanation}");
        assert!(explanation.contains("over brolga.zzz"), "{explanation}");
    }

    /// A lone parser must not produce a sentence trailing "over " with nothing after it.
    #[test]
    fn the_explanation_reads_properly_when_nothing_else_was_registered() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Strong));

        let explanation = registry.select(&hint(b"{}")).unwrap().explain();
        assert!(
            explanation.ends_with("no other parser was registered"),
            "{explanation}"
        );
    }

    /// Iteration order is the registry's determinism in its most direct form.
    #[test]
    fn identifiers_come_back_in_identifier_order_not_registration_order() {
        let mut registry = ParserRegistry::new();
        registry.register(Fixed::boxed("brolga.zzz", DetectionConfidence::Weak));
        registry.register(Fixed::boxed("brolga.aaa", DetectionConfidence::Weak));

        let ids: Vec<_> = registry.ids().iter().map(|id| id.as_str()).collect();
        assert_eq!(ids, vec!["brolga.aaa", "brolga.zzz"]);
    }
}
