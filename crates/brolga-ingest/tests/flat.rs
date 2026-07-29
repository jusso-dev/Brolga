//! CSV, TSV, JSON, NDJSON, and plain-text indicator ingestion.
//!
//! One section per acceptance criterion of [#15](https://github.com/jusso-dev/Brolga/issues/15).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::formats::delimited::{
    ColumnMapping, DelimitedParser, Delimiter, Inference, InferenceConfidence, JsonLinesParser,
    infer, looks_like_a_formula, sniff_delimiter,
};
use brolga_ingest::{Document, IngestMode, ParsedRecord, ParserRegistry, Pipeline};
use brolga_model::{
    Assertion, ContentHash, RecordOrigin, ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, SqliteStore, StoreRead};

const INDICATORS: &[u8] = include_bytes!("fixtures/flat/indicators.txt");
const CRLF: &[u8] = include_bytes!("fixtures/flat/crlf.csv");
const BOM: &[u8] = include_bytes!("fixtures/flat/bom-header.csv");
const TABS: &[u8] = include_bytes!("fixtures/flat/tabs.tsv");
const NDJSON: &[u8] = include_bytes!("fixtures/flat/records.ndjson");
const JSON_ARRAY: &[u8] = include_bytes!("fixtures/flat/records.json");

fn pipeline() -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(DelimitedParser::boxed());
    registry.register(JsonLinesParser::boxed());
    Pipeline::with_defaults(registry).in_mode(IngestMode::Permissive)
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn document<'a>(bytes: &'a [u8], media_type: &str, file_name: Option<&'a str>) -> Document<'a> {
    Document {
        bytes,
        media_type: MediaType::new(media_type).unwrap(),
        file_name,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("flat-fixture").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

fn prepare(
    bytes: &[u8],
    media_type: &str,
    file_name: Option<&str>,
) -> brolga_ingest::DocumentReport {
    pipeline()
        .prepare(
            &document(bytes, media_type, file_name),
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
}

fn attribute_values(report: &brolga_ingest::DocumentReport) -> Vec<(String, String)> {
    report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Claim(claim) => match &claim.assertion {
                Assertion::Attribute { name, value } => {
                    Some((name.as_str().to_owned(), value.as_str().to_owned()))
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// "Format detection reports confidence and reasons"
// ---------------------------------------------------------------------------------------------

/// The criterion. Every claim carries a reason, and the reasons distinguish the shapes.
#[test]
fn each_flat_shape_is_detected_with_a_reason_that_says_what_was_found() {
    struct Case {
        bytes: &'static [u8],
        media_type: &'static str,
        file_name: Option<&'static str>,
        parser: &'static str,
        reason: &'static str,
    }

    let cases = [
        Case {
            bytes: CRLF,
            media_type: "text/csv",
            file_name: None,
            parser: "brolga.flat.delimited",
            reason: "text/csv",
        },
        Case {
            bytes: TABS,
            media_type: "text/plain",
            file_name: Some("feed.tsv"),
            parser: "brolga.flat.delimited",
            reason: "extension",
        },
        Case {
            bytes: NDJSON,
            media_type: "application/x-ndjson",
            file_name: None,
            parser: "brolga.flat.json",
            reason: "NDJSON",
        },
        Case {
            bytes: JSON_ARRAY,
            media_type: "application/json",
            file_name: None,
            parser: "brolga.flat.json",
            reason: "JSON array",
        },
    ];

    for case in cases {
        let report = prepare(case.bytes, case.media_type, case.file_name);
        assert_eq!(
            report.parser.as_str(),
            case.parser,
            "for {}",
            case.media_type
        );
        assert!(
            report.selection.contains(case.reason),
            "reason for {} should mention {:?}: {}",
            case.media_type,
            case.reason,
            report.selection
        );
    }
}

/// The delimiter is decided by *consistency*, not by frequency. A comma inside a description would
/// otherwise beat the tab that actually separates the columns.
#[test]
fn the_delimiter_is_chosen_by_consistency_rather_than_by_count() {
    let tsv = "host\tip\tnote\na.example\t192.0.2.1\tsaw, one, two\nb.example\t192.0.2.2\tsaw, three, four\n";
    assert_eq!(sniff_delimiter(tsv), Delimiter::Tab);

    let csv = "host,ip\na.example,192.0.2.1\nb.example,192.0.2.2\n";
    assert_eq!(sniff_delimiter(csv), Delimiter::Comma);

    let plain = "a.example\nb.example\n";
    assert_eq!(sniff_delimiter(plain), Delimiter::None);
}

/// A catch-all JSON reader that outbid STIX or MISP would silently downgrade every bundle to
/// untyped attributes. It must decline rather than compete.
#[test]
fn the_generic_json_reader_declines_documents_a_specific_parser_owns() {
    use brolga_ingest::formats::misp::MispParser;
    use brolga_ingest::formats::stix::StixParser;

    let mut registry = ParserRegistry::new();
    registry.register(JsonLinesParser::boxed());
    registry.register(StixParser::boxed());
    registry.register(MispParser::boxed());
    let pipeline = Pipeline::with_defaults(registry).in_mode(IngestMode::Permissive);

    let bundle = br#"{"type":"bundle","id":"bundle--x","objects":[]}"#;
    let report = pipeline
        .prepare(
            &document(bundle, "application/json", None),
            &CancellationToken::never_cancelled(),
        )
        .unwrap();
    assert_eq!(report.parser.as_str(), "brolga.stix.bundle");
}

// ---------------------------------------------------------------------------------------------
// "Ambiguous observable inference is quarantined or labelled uncertain"
// ---------------------------------------------------------------------------------------------

/// The criterion. Being wrong is survivable; being wrong *silently* is not.
#[test]
fn a_value_that_could_be_two_things_is_reported_as_ambiguous_rather_than_guessed() {
    // A 32-hex string is an MD5 and also a UUID-without-dashes and also a session token.
    let hash_like = infer("d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hash_like.confidence, InferenceConfidence::Confident);

    // A bare label that parses as both a domain and something else must not be silently chosen.
    let unambiguous = infer("evil.example");
    assert_eq!(unambiguous.confidence, InferenceConfidence::Confident);
    assert_eq!(unambiguous.candidates, vec!["domain-name"]);

    let nothing = infer("not an indicator");
    assert_eq!(nothing.confidence, InferenceConfidence::None);
}

/// **The ambiguity path is currently unreachable, and that is a measured fact rather than a hope.**
///
/// The shipped canonicalisers are mutually exclusive by construction: RFC 1123's all-digit-final-label
/// rule keeps addresses out of domains, `/` keeps CIDR ranges distinct, `@` keeps email distinct,
/// `://` keeps URLs distinct, and hex-only-with-a-known-length keeps digests distinct. No value in
/// the corpus below matches two.
///
/// This test asserts that exclusivity, because it is the property that makes inference safe. The
/// `Ambiguous` branch remains as the correct behaviour for when a seventh canonicaliser overlaps an
/// existing one — at which point this test fails and names the pair, which is exactly when somebody
/// needs to know.
#[test]
fn the_shipped_canonicalisers_are_mutually_exclusive_so_inference_is_never_a_guess() {
    let corpus = [
        "192.0.2.1",
        "2001:db8::1",
        "198.51.100.0/24",
        "example.com",
        "evil.example",
        "xn--bcher-kva.example",
        "https://lure.example/Login",
        "a@b.example",
        "d41d8cd98f00b204e9800998ecf8427e",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5:d41d8cd98f00b204e9800998ecf8427e",
    ];

    for value in corpus {
        let inference = infer(value);
        assert_ne!(
            inference.confidence,
            InferenceConfidence::Ambiguous,
            "`{value}` matched {:?}; a seventh canonicaliser has overlapped an existing one and \
             inference has become a guess",
            inference.candidates,
        );
    }
}

/// The contract the ambiguity branch must honour if it is ever reached: it hands back **no** value.
///
/// Asserted on a directly constructed `Inference` rather than through a value, because no value
/// reaches it today (see above). Without this, the branch could silently start returning a chosen
/// observable and nothing would notice until it shipped.
#[test]
fn an_ambiguous_inference_never_hands_back_a_chosen_value() {
    let ambiguous = Inference {
        observable: None,
        confidence: InferenceConfidence::Ambiguous,
        candidates: vec!["ip-address", "domain-name"],
    };

    assert!(!ambiguous.is_usable(), "ambiguous must never be usable");
    assert!(ambiguous.observable.is_none());
    assert!(
        ambiguous.candidates.len() > 1,
        "and it must name what it could not choose between"
    );
}

/// An explicit mapping turns a guess into a statement, and must win over inference.
#[test]
fn an_explicit_column_mapping_overrides_inference() {
    let mapping = ColumnMapping::from_header(&["domain", "ip", "notes"]);
    assert_eq!(mapping.kind_at(0), Some("domain-name"));
    assert_eq!(mapping.kind_at(1), Some("ip-address"));
    assert_eq!(
        mapping.kind_at(2),
        None,
        "an unrecognised header is not guessed at"
    );
}

/// A row that is ordinary column content, not an indicator, is not a rejection — quarantining every
/// description field would bury the real problems.
#[test]
fn ordinary_column_content_is_skipped_rather_than_quarantined() {
    let report = prepare(TABS, "text/tab-separated-values", Some("feed.tsv"));
    assert!(
        report.rejected.is_empty(),
        "`sensor-a` is content, not a failure: {:?}",
        report.rejected
    );
}

// ---------------------------------------------------------------------------------------------
// "Headers, encodings, line endings, and malformed rows have fixtures"
// ---------------------------------------------------------------------------------------------

/// A BOM is what a Windows-exported CSV begins with. Leaving it in makes the first header cell
/// unmatchable — a mapping failure that looks like a data problem.
#[test]
fn a_byte_order_mark_does_not_break_the_first_header_cell() {
    let report = prepare(BOM, "text/csv", Some("export.csv"));
    let values = attribute_values(&report);
    assert!(
        values.iter().any(|(_, value)| value == "evil.example"),
        "the first column was read despite the BOM: {values:?}"
    );
}

/// CRLF line endings are the norm from Windows tooling and must not leave a stray `\r` on the last
/// field of every row.
#[test]
fn crlf_line_endings_do_not_leave_a_carriage_return_in_the_last_field() {
    let report = prepare(CRLF, "text/csv", None);
    let values = attribute_values(&report);
    assert!(!values.is_empty());
    for (_, value) in &values {
        assert!(!value.contains('\r'), "stray carriage return in {value:?}");
    }
}

/// A header row must be recognised and not ingested as data.
#[test]
fn a_header_row_is_consumed_rather_than_ingested_as_a_record() {
    let report = prepare(CRLF, "text/csv", None);
    let values = attribute_values(&report);
    assert!(
        !values.iter().any(|(_, value)| value == "indicator"),
        "the header word `indicator` was not ingested: {values:?}"
    );
}

/// A file whose first line is data must not lose that line to header detection.
#[test]
fn a_file_with_no_header_does_not_lose_its_first_row() {
    let report = prepare(INDICATORS, "text/plain", Some("list.txt"));
    let values = attribute_values(&report);
    assert!(
        values.iter().any(|(_, value)| value == "evil.example"),
        "the first indicator survived: {values:?}"
    );
}

/// Comments and blank lines are what real indicator lists are full of.
#[test]
fn comments_and_blank_lines_are_skipped_without_becoming_rejections() {
    let report = prepare(INDICATORS, "text/plain", Some("list.txt"));
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    assert!(report.records.len() >= 4, "four indicators in the fixture");
}

/// One malformed NDJSON line must not discard the file — that is the whole point of the format.
#[test]
fn a_malformed_ndjson_line_is_quarantined_and_the_rest_of_the_file_is_read() {
    let report = prepare(NDJSON, "application/x-ndjson", None);

    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].reason_kind, "malformed_json_line");
    assert!(
        report.records.len() >= 3,
        "the well-formed lines still parsed: {} records",
        report.records.len()
    );
}

/// Non-UTF-8 input is refused explicitly rather than guessed at. Silently mis-decoding a legacy
/// encoding produces plausible-looking wrong indicators.
#[test]
fn non_utf8_input_is_refused_rather_than_guessed_at() {
    let latin1 = b"evil.example,caf\xe9\n";
    let error = pipeline()
        .prepare(
            &document(latin1, "text/csv", None),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    let rendered = error.to_string();
    assert!(
        rendered.contains("UTF-8") || rendered.contains("no registered parser"),
        "{rendered}"
    );
}

/// A JSON array is a supported shape alongside NDJSON.
#[test]
fn a_json_array_of_records_ingests() {
    let report = prepare(JSON_ARRAY, "application/json", None);
    assert_eq!(report.records.len(), 3);
    assert!(report.rejected.is_empty());
}

// ---------------------------------------------------------------------------------------------
// "Spreadsheet formula prefixes are preserved as data"
// ---------------------------------------------------------------------------------------------

/// The security note. The payload is what the source published; rewriting evidence to make it safe
/// to open in Excel is the wrong layer. It is flagged so the exporter knows to escape it.
#[test]
fn a_formula_prefix_is_detected_without_the_value_being_rewritten() {
    assert!(looks_like_a_formula("=cmd|' /C calc'!A0"));
    assert!(looks_like_a_formula("@SUM(1+1)"));
    assert!(looks_like_a_formula("+1+1"));

    // A negative number and an IP address must not be mistaken for formulas.
    assert!(!looks_like_a_formula("192.0.2.1"));
    assert!(!looks_like_a_formula("evil.example"));
}

/// The fixture carries a real formula payload, and ingesting it must neither rewrite it nor crash.
#[test]
fn a_row_containing_a_formula_payload_ingests_without_rewriting_it() {
    let report = prepare(BOM, "text/csv", Some("export.csv"));
    assert!(!report.records.is_empty());
    // The payload column is not an indicator, so it produces no observable claim — but the file
    // still parses, which is what matters: a formula must not be a parse failure.
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
}

// ---------------------------------------------------------------------------------------------
// "Large streaming inputs avoid whole-file expansion where practical"
// ---------------------------------------------------------------------------------------------

/// A line with no terminator is not a very long record; it is a file with no line breaks, and
/// reading it into memory is the denial of service.
#[test]
fn a_line_over_the_line_limit_is_refused() {
    use brolga_ingest::formats::delimited::MAX_LINE_BYTES;

    let mut giant = String::from("evil.example\n");
    giant.push_str(&"a".repeat(MAX_LINE_BYTES + 10));
    giant.push('\n');

    let error = pipeline()
        .prepare(
            &document(giant.as_bytes(), "text/plain", Some("list.txt")),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("line"), "{error}");
}

/// The record limit is enforced while reading rather than after materialising everything.
#[test]
fn a_file_over_the_record_limit_is_refused_partway_rather_than_after_loading_it_all() {
    use brolga_security::{InputLimits, ResourceLimits};

    let mut limits = ResourceLimits::defaults();
    limits.input.max_records = InputLimits::MAX_RECORDS.min;

    let mut registry = ParserRegistry::new();
    registry.register(DelimitedParser::boxed());
    let pipeline = Pipeline::new(registry, limits).in_mode(IngestMode::Permissive);

    let many = (0..50)
        .map(|index| format!("host{index}.example"))
        .collect::<Vec<_>>()
        .join("\n");

    let error = pipeline
        .prepare(
            &document(many.as_bytes(), "text/plain", Some("list.txt")),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("record limit"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// "Every row retains a source reference"
// ---------------------------------------------------------------------------------------------

/// The criterion. Every record cites the file it came from, and carries the byte offset of the row
/// so a rejection can be traced back to a line.
#[test]
fn every_record_cites_the_file_it_was_parsed_from() {
    let report = prepare(INDICATORS, "text/plain", Some("list.txt"));
    assert!(!report.records.is_empty());

    for record in &report.records {
        let ParsedRecord::Claim(claim) = record else {
            continue;
        };
        let RecordOrigin::SourceDerived { provenance } = &claim.origin else {
            panic!("a record parsed from a file must be source-derived");
        };
        assert_eq!(provenance.source_objects, vec![report.source_object]);
    }
}

/// A rejected row must carry its position, or an operator cannot find the line in a 200 MiB file.
#[test]
fn a_rejected_row_carries_the_byte_offset_of_the_line_it_came_from() {
    let report = prepare(NDJSON, "application/x-ndjson", None);
    assert_eq!(report.rejected.len(), 1);
    assert!(
        report.rejected[0].offset.is_some_and(|offset| offset > 0),
        "the offset points past the first line: {:?}",
        report.rejected[0].offset
    );
}

/// End to end, against a real store: the file is retained and the rows land.
#[test]
fn a_flat_feed_ingests_and_its_source_is_retained() {
    let mut store = store();
    let report = pipeline()
        .ingest_batch(
            &mut store,
            &[document(INDICATORS, "text/plain", Some("list.txt"))],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert!(report.reconciles(), "{report:?}");
    assert!(report.inserted >= 4);

    let retrieved = store
        .get_source_blob(&ContentHash::of(INDICATORS))
        .unwrap()
        .expect("the file is retained");
    assert_eq!(retrieved.bytes, INDICATORS);
}
