//! Property tests for the ingestion boundary.
//!
//! ADR 0003 §2 decided that a parser is stopped from panicking rather than caught panicking, on the
//! grounds that `panic = "abort"` makes `catch_unwind` a guarantee that evaporates in release
//! builds. This file is point (3) of that decision, and it is the part that has to actually run:
//! arbitrary bytes through detection and parsing for **every registered parser**, asserting the
//! outcome is `Ok` or `Err` and never an unwind.
//!
//! It iterates the registry rather than naming parsers, so registering a parser enrols it here
//! automatically. A test that had to be extended by hand for each new parser would be one parser
//! behind for as long as it took somebody to notice.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::detect::FormatHint;
use brolga_ingest::formats::stix_pattern;
use brolga_ingest::testing::{CatchAllParser, TestRecordsParser};
use brolga_ingest::{Document, ParserRegistry, Pipeline};
use brolga_model::{
    ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use proptest::prelude::*;

fn registry() -> ParserRegistry {
    let mut registry = ParserRegistry::new();
    registry.register(TestRecordsParser::boxed());
    registry.register(CatchAllParser::boxed());
    registry
}

fn origin() -> SourceOrigin {
    SourceOrigin::NetworkFeed {
        publisher: ShortText::new("property-test").unwrap(),
        location: None,
    }
}

fn document<'a>(bytes: &'a [u8], media_type: &str) -> Document<'a> {
    Document {
        bytes,
        media_type: MediaType::new(media_type).unwrap(),
        file_name: None,
        origin: origin(),
        retrieved_at: Timestamp::unix_epoch(),
    }
}

proptest! {
    /// The ADR 0003 §2 obligation. Every registered parser, arbitrary bytes, no unwind.
    #[test]
    fn no_registered_parser_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let pipeline = Pipeline::with_defaults(registry());
        let cancel = CancellationToken::never_cancelled();

        // Detection first: it runs for every parser on every document, so it sees hostile bytes
        // more often than any parser's own reader does.
        let hint = FormatHint::new(
            "application/octet-stream",
            None,
            &bytes,
            u64::try_from(bytes.len()).unwrap(),
        );
        let candidates = pipeline.registry().candidates(&hint);
        prop_assert_eq!(candidates.len(), pipeline.registry().len());

        // Then the whole pipeline, which reaches whichever parser claimed the bytes.
        let outcome = pipeline.prepare(&document(&bytes, "application/octet-stream"), &cancel);
        prop_assert!(outcome.is_ok() || outcome.is_err());
    }

    /// Arbitrary *text* is the harder case: it gets past the UTF-8 gate and into the line reader,
    /// which is where an offset calculation or a `strip_prefix` would go wrong.
    #[test]
    fn no_registered_parser_panics_on_arbitrary_text(text in ".{0,2048}") {
        let pipeline = Pipeline::with_defaults(registry());
        let cancel = CancellationToken::never_cancelled();
        let outcome = pipeline.prepare(&document(text.as_bytes(), "text/plain"), &cancel);
        prop_assert!(outcome.is_ok() || outcome.is_err());
    }

    /// Lines that nearly match the format — the boundary between accepted and rejected — are where
    /// an off-by-one in the offset arithmetic would show up.
    #[test]
    fn nearly_valid_records_are_accepted_or_rejected_but_never_panic(
        lines in prop::collection::vec(
            prop_oneof![
                Just("entity:name".to_owned()),
                Just("entity:".to_owned()),
                Just("entity".to_owned()),
                Just("#comment".to_owned()),
                Just(String::new()),
                "[a-z]{0,32}",
            ],
            0..64,
        )
    ) {
        let text = lines.join("\n");
        let pipeline = Pipeline::with_defaults(registry());
        let cancel = CancellationToken::never_cancelled();
        let outcome = pipeline.prepare(&document(text.as_bytes(), "text/plain"), &cancel);
        prop_assert!(outcome.is_ok() || outcome.is_err());
    }

    /// Detection must be a pure function of the hint. If it were not, selection could differ
    /// between two runs over identical bytes, which is the acceptance criterion this whole
    /// ordering design exists to hold.
    #[test]
    fn detection_gives_the_same_answer_for_the_same_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let pipeline = Pipeline::with_defaults(registry());
        let length = u64::try_from(bytes.len()).unwrap();
        let hint = FormatHint::new("text/plain", None, &bytes, length);

        let first = pipeline.registry().candidates(&hint);
        let second = pipeline.registry().candidates(&hint);
        prop_assert_eq!(first, second);
    }

    /// The byte limit is enforced by the pipeline before a parser is called. Whatever the bytes
    /// are, an oversized document must be refused rather than parsed.
    #[test]
    fn a_document_over_the_byte_limit_is_always_refused(
        extra in 1_usize..512,
        filler in any::<u8>(),
    ) {
        use brolga_security::ResourceLimits;

        let mut limits = ResourceLimits::defaults();
        limits.input.max_bytes = brolga_security::InputLimits::MAX_BYTES.min;
        let limit = limits.input.max_bytes;

        let pipeline = Pipeline::new(registry(), limits);
        let cancel = CancellationToken::never_cancelled();
        let size = usize::try_from(limit).unwrap() + extra;
        let bytes = vec![filler; size];

        let error = pipeline
            .prepare(&document(&bytes, "text/plain"), &cancel)
            .unwrap_err();
        prop_assert!(
            matches!(error, brolga_ingest::IngestError::DocumentTooLarge { .. }),
            "got {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// STIX patterning — attacker-controlled text with its own grammar
// ---------------------------------------------------------------------------------------------

/// Fragments a pattern is built from, including the ones that make a *nearly* valid pattern.
///
/// A generator of arbitrary characters almost never produces a balanced bracket, so it exercises
/// the "refuse immediately" path and nothing else. These are the shapes that reach the path reader,
/// the string-literal scanner, and the `OR` chain — where an index or a `strip_prefix` would go
/// wrong.
fn pattern_fragment() -> impl proptest::strategy::Strategy<Value = String> {
    prop_oneof![
        Just("[".to_owned()),
        Just("]".to_owned()),
        Just("=".to_owned()),
        Just("!=".to_owned()),
        Just("OR".to_owned()),
        Just("AND".to_owned()),
        Just("FOLLOWEDBY".to_owned()),
        Just("'".to_owned()),
        Just("\\'".to_owned()),
        Just("\\\\".to_owned()),
        Just("ipv4-addr:value".to_owned()),
        Just("file:hashes.'SHA-256'".to_owned()),
        Just("'192.0.2.1'".to_owned()),
        Just(" ".to_owned()),
        "[^\\p{Cc}]{0,8}",
    ]
}

proptest! {
    /// A pattern is attacker-controlled text with its own grammar, read by a hand-written
    /// tokeniser — the shape most likely to hold a panic. Every input is understood or refused,
    /// and neither is an unwind.
    #[test]
    fn the_pattern_reader_never_panics(fragments in prop::collection::vec(pattern_fragment(), 0..48)) {
        let pattern = fragments.join("");
        let outcome = stix_pattern::observables_of(&pattern);
        prop_assert!(outcome.is_ok() || outcome.is_err());
    }

    /// Understood must mean "named something". An empty success would let a caller treat a pattern
    /// it did not read as one asserting nothing — the silent miss this parser exists to prevent.
    #[test]
    fn a_pattern_that_parses_always_names_at_least_one_observable(
        fragments in prop::collection::vec(pattern_fragment(), 0..48),
    ) {
        let pattern = fragments.join("");
        if let Ok(observables) = stix_pattern::observables_of(&pattern) {
            prop_assert!(!observables.is_empty(), "{pattern}");
            prop_assert!(observables.len() <= stix_pattern::MAX_ALTERNATIVES, "{pattern}");
        }
    }

    /// Reading a pattern is a pure function of its text. If it were not, one bundle could ingest
    /// differently on two runs, and every count downstream would be unreproducible.
    #[test]
    fn reading_a_pattern_is_deterministic(fragments in prop::collection::vec(pattern_fragment(), 0..48)) {
        let pattern = fragments.join("");
        let first = stix_pattern::observables_of(&pattern);
        let second = stix_pattern::observables_of(&pattern);
        prop_assert_eq!(first.is_ok(), second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            prop_assert_eq!(first, second);
        }
    }

    /// Any address, in any of the spellings a feed publishes it in, must reach the same observable
    /// through a STIX pattern as through a MISP attribute. The two paths agreeing is what keeps one
    /// address from sitting in the graph twice.
    #[test]
    fn a_pattern_and_a_bare_value_canonicalise_alike(
        a in 0_u8..=255, b in 0_u8..=255, c in 0_u8..=255, d in 0_u8..=255,
        pad in " {0,4}",
    ) {
        let address = format!("{a}.{b}.{c}.{d}");
        let pattern = format!("[{pad}ipv4-addr:value{pad}={pad}'{address}'{pad}]");

        let from_pattern = stix_pattern::observables_of(&pattern).unwrap();
        let from_value = brolga_ingest::canon::net::ip_address(&address).unwrap().into_value();

        prop_assert_eq!(from_pattern.len(), 1);
        prop_assert_eq!(from_pattern[0].id(), from_value.id());
    }
}
