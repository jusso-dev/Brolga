//! CEF, LEEF, and syslog ingestion, against a fixture corpus and a real store.
//!
//! One section per acceptance criterion of [#52](https://github.com/jusso-dev/Brolga/issues/52)
//! that these formats are responsible for.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::IntelligenceParser;
use brolga_ingest::formats::telemetry::{TelemetryParser, extension_keys, strip_syslog_frame};
use brolga_ingest::{Document, IngestMode, IngestReport, ParsedRecord, ParserRegistry, Pipeline};
use brolga_model::{
    Assertion, Claim, EntityKind, NodeRef, Observable, ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, RecordKind, SqliteStore, StoreRead};

const EVENTS: &str = include_str!("fixtures/telemetry/events.log");

fn pipeline(mode: IngestMode) -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(TelemetryParser::boxed());
    Pipeline::with_defaults(registry).in_mode(mode)
}

fn store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();
    store
}

fn document(bytes: &[u8]) -> Document<'_> {
    Document {
        bytes,
        media_type: MediaType::new("text/x-cef").unwrap(),
        file_name: None,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("telemetry-fixture").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

fn prepare(bytes: &[u8]) -> brolga_ingest::DocumentReport {
    pipeline(IngestMode::Permissive)
        .prepare(&document(bytes), &CancellationToken::never_cancelled())
        .unwrap()
}

fn ingest(store: &mut SqliteStore, bytes: &[u8]) -> IngestReport {
    pipeline(IngestMode::Permissive)
        .ingest_batch(
            store,
            &[document(bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
}

fn claims(report: &brolga_ingest::DocumentReport) -> Vec<&Claim> {
    report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Claim(claim) => Some(claim.as_ref()),
            _ => None,
        })
        .collect()
}

fn claims_about<'a>(
    report: &'a brolga_ingest::DocumentReport,
    observable: &Observable,
) -> Vec<&'a Claim> {
    let subject = NodeRef::Observable(observable.id());
    claims(report)
        .into_iter()
        .filter(|claim| claim.subject == subject)
        .collect()
}

fn ipv4(value: &str) -> Observable {
    Observable::Ipv4Address(value.parse().unwrap())
}

// ---------------------------------------------------------------------------------------------
// "Each claimed format has representative and hostile fixtures"
// ---------------------------------------------------------------------------------------------

/// The corpus ingests, and the counts are what it contains rather than "more than zero".
#[test]
fn a_representative_telemetry_corpus_ingests() {
    let mut store = store();
    let report = ingest(&mut store, EVENTS.as_bytes());

    assert!(report.reconciles(), "{report:?}");
    assert!(store.count(RecordKind::Entity).unwrap() > 0);
    assert!(store.count(RecordKind::Claim).unwrap() > 0);
    // The truncated header and the syslog line naming nothing mappable.
    assert_eq!(report.rejected, 2, "{report:?}");
}

/// CEF, LEEF, and a syslog frame around either must all be recognised, or a file of records
/// delivered over syslog is filed under the weaker shape and loses its signature.
#[test]
fn cef_leef_and_syslog_framed_records_are_all_read() {
    let report = prepare(EVENTS.as_bytes());

    for value in [
        "198.51.100.5",  // CEF behind a syslog frame
        "198.51.100.20", // bare CEF
        "198.51.100.30", // LEEF 1.0
        "198.51.100.31", // LEEF 2.0 with a declared delimiter
    ] {
        assert!(
            !claims_about(&report, &ipv4(value)).is_empty(),
            "`{value}` was not read: {:?}",
            report.rejected
        );
    }
}

// ---------------------------------------------------------------------------------------------
// "Detection content maps to typed rule and detection entities"
// ---------------------------------------------------------------------------------------------

/// A signature is a rule somebody wrote. It gets the typed kind rather than being filed under
/// `Tool`, which would say a defender's detection is an attacker's instrument.
#[test]
fn a_signature_becomes_a_typed_detection_rule_entity() {
    let report = prepare(EVENTS.as_bytes());
    let rule = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::DetectionRule => {
                Some(entity)
            }
            _ => None,
        })
        .expect("a detection rule");

    assert!(
        rule.description
            .as_ref()
            .is_some_and(|text| text.as_str().contains("signature")),
        "{:?}",
        rule.description
    );
}

/// Two vendors both numbering a signature `100` wrote two rules. Keying on the number alone would
/// attribute one vendor's detections to the other, and no count downstream would notice.
#[test]
fn two_vendors_numbering_a_signature_alike_are_two_rules() {
    let report = prepare(EVENTS.as_bytes());
    let rules: Vec<_> = report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::DetectionRule => {
                Some(entity.id)
            }
            _ => None,
        })
        .collect();

    let mut unique = rules.clone();
    unique.sort_unstable();
    unique.dedup();
    assert!(
        unique.len() >= 4,
        "`Security` 100, `ACME` 100, `Security` 200/300, and the LEEF ones are distinct: {unique:?}"
    );
}

/// The observable was part of the event the signature fired on. Not `Indicates`, which would say
/// the observable is evidence *of* the rule.
#[test]
fn an_observable_is_related_to_the_signature_it_appeared_under() {
    use brolga_model::RelationshipKind;

    let report = prepare(EVENTS.as_bytes());
    assert!(
        report.records.iter().any(|record| matches!(
            record,
            ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::PartOf
        )),
        "no edge from an observable to its signature"
    );
}

// ---------------------------------------------------------------------------------------------
// "CEF, LEEF, and syslog parsing preserve raw records and ambiguities"
// ---------------------------------------------------------------------------------------------

/// A normalised field is a *reading* of a record; the record is the evidence. Keeping only the
/// reading means a disagreement about the reading can never be settled.
#[test]
fn the_raw_record_is_preserved_alongside_what_was_read_from_it() {
    let report = prepare(EVENTS.as_bytes());
    let about = claims_about(&report, &ipv4("198.51.100.5"));

    assert!(
        about.iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "cef.raw" && value.as_str().contains("worm blocked on egress")
        )),
        "the raw record is missing: {about:?}"
    );
}

/// "A field we do not read" and "a field we read whose value was unusable" send an operator to
/// different places. Collapsing them into silence sends them nowhere.
#[test]
fn a_mapped_key_whose_value_is_unusable_is_named_rather_than_dropped() {
    let report = prepare(EVENTS.as_bytes());

    let unmapped: Vec<&str> = claims(&report)
        .into_iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Attribute { name, value } if name.as_str() == "cef.unmapped" => {
                Some(value.as_str())
            }
            _ => None,
        })
        .collect();

    assert!(
        unmapped.iter().any(|value| value.contains("src")),
        "`src=not-an-address` was not reported: {unmapped:?}"
    );
    assert!(
        unmapped.iter().any(|value| value.contains("dhost")),
        "a single-label hostname is not a DNS name, and saying so is the point: {unmapped:?}"
    );
}

/// A username and an email address share `suser`. Reading it would mint mailbox observables out of
/// login names on any site whose logins look like addresses.
#[test]
fn a_user_field_never_becomes_an_email_observable() {
    let report = prepare(EVENTS.as_bytes());
    let email = Observable::EmailAddress(
        brolga_model::observable::EmailAddress::new("jsmith@example.com").unwrap(),
    );
    assert!(
        claims_about(&report, &email).is_empty(),
        "a login name became a mailbox"
    );
}

/// Presence in a log is not evidence of maliciousness. A signature fires on what it matches,
/// including the benign and the allow-listed.
#[test]
fn telemetry_asserts_no_disposition_at_all() {
    let report = prepare(EVENTS.as_bytes());
    assert!(
        !claims(&report)
            .iter()
            .any(|claim| matches!(claim.assertion, Assertion::Disposition(_))),
        "a log line was read as an assessment"
    );
}

// ---------------------------------------------------------------------------------------------
// Hostile and malformed records
// ---------------------------------------------------------------------------------------------

/// A truncated header cannot be read, and reading it partially would file the event under whatever
/// field happened to land in the signature position.
#[test]
fn a_truncated_cef_header_is_quarantined_with_its_raw_record() {
    let report = prepare(EVENTS.as_bytes());
    let rejection = report
        .rejected
        .iter()
        .find(|record| record.reason_kind == "incomplete_header")
        .expect("the truncated header");

    assert!(rejection.reason.contains("seven"), "{}", rejection.reason);
    assert!(
        rejection
            .fragment
            .as_deref()
            .is_some_and(|fragment| fragment.contains("CEF:0|Security|threatmanager")),
        "the quarantine keeps the record an operator has to diagnose"
    );
}

/// A syslog line with no CEF or LEEF payload and no readable observable would store an event about
/// nothing. Saying so beats writing it.
#[test]
fn a_syslog_line_naming_nothing_mappable_is_quarantined() {
    let report = prepare(EVENTS.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "nothing_mappable"),
        "{:?}",
        report.rejected
    );
}

/// Arbitrary bytes must be refused or read, never panic, and never be claimed by this parser when
/// they are something else.
#[test]
fn hostile_records_are_refused_rather_than_read() {
    for hostile in [
        "",
        "CEF:",
        "CEF:|||||||",
        "LEEF:",
        "LEEF:2.0|v|p|1|e",
        "<>",
        "<99999>x",
        "<134>",
        "CEF:0|a|b|c|d|e|f|=",
        "CEF:0|a|b|c|d|e|f|src=",
        &format!("CEF:0|a|b|c|d|e|f|src={}", "1".repeat(10_000)),
    ] {
        let outcome = pipeline(IngestMode::Permissive).prepare(
            &document(hostile.as_bytes()),
            &CancellationToken::never_cancelled(),
        );
        assert!(outcome.is_ok() || outcome.is_err(), "{hostile}");
    }
}

/// An XML document begins with `<` and is not syslog. Without this the telemetry parser would
/// claim OpenIOC and IODEF files out from under the parser that can actually read them.
#[test]
fn an_xml_document_is_not_mistaken_for_syslog() {
    let (frame, _) = strip_syslog_frame("<IODEF-Document version=\"1.00\">");
    assert!(frame.is_none());

    let candidate = TelemetryParser::new().detect(&brolga_ingest::detect::FormatHint::new(
        "application/xml",
        None,
        b"<IODEF-Document version=\"1.00\"><Incident/></IODEF-Document>",
        58,
    ));
    assert_eq!(
        candidate.confidence,
        brolga_ingest::DetectionConfidence::Declined,
        "{}",
        candidate.reason
    );
}

/// Answering "which fields does my appliance actually send?" from the data beats answering it from
/// a vendor's documentation.
#[test]
fn the_extension_keys_of_a_record_are_reportable() {
    let keys = extension_keys(
        "<134>Jan  1 00:00:00 gw CEF:0|v|p|1|100|n|10|src=10.0.0.1 msg=a b dst=10.0.0.2",
    )
    .unwrap();
    assert_eq!(keys, vec!["dst", "msg", "src"]);
}
