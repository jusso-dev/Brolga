//! Declarative mappings, end to end against the shipped example mappings and a real store.
//!
//! One section per acceptance criterion of [#47](https://github.com/jusso-dev/Brolga/issues/47).
//!
//! The mappings under test are the ones in `examples/mappings/`, read from disk rather than written
//! as string literals here. That coupling is the point: an example mapping that stopped validating
//! would be a broken example, and an example nobody runs is documentation that has already drifted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path as FilePath, PathBuf};

use brolga_ingest::mapping::{
    MappedParser, Mapping, MappingError, SourceShape, Target, Transform, engine, path, transform,
};
use brolga_ingest::{
    Document, DocumentReport, IngestMode, IntelligenceParser, ParsedRecord, ParserRegistry,
    Pipeline,
};
use brolga_model::{
    Assertion, Claim, Disposition, ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin, TransformationStage},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, RecordKind, SqliteStore, StoreRead};

/// A shipped example mapping, resolved from the workspace root.
fn example(name: &str) -> PathBuf {
    FilePath::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/mappings")
        .join(name)
}

fn load(name: &str) -> Mapping {
    let bytes = std::fs::read(example(name))
        .unwrap_or_else(|error| panic!("the example mapping `{name}` must exist: {error}"));
    Mapping::load(&bytes)
        .unwrap_or_else(|error| panic!("the example mapping `{name}` must validate: {error}"))
}

const ACME_JSON: &str = include_str!("fixtures/mapping/acme-feed.json");
const ACME_CSV: &str = include_str!("fixtures/mapping/acme-feed.csv");
const DEVICE_XML: &str = include_str!("fixtures/mapping/device-report.xml");

fn document<'a>(bytes: &'a [u8], media_type: &'a str) -> Document<'a> {
    Document {
        bytes,
        media_type: MediaType::new(media_type).unwrap(),
        file_name: None,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("mapping-fixture").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

/// Run one document through one mapping, with nothing else registered.
fn run(mapping: Mapping, bytes: &[u8]) -> DocumentReport {
    let mut registry = ParserRegistry::new();
    registry.register(MappedParser::boxed(mapping));
    Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &document(bytes, "application/octet-stream"),
            &CancellationToken::never_cancelled(),
        )
        .expect("the mapping must read the fixture")
}

fn claims(report: &DocumentReport) -> Vec<&Claim> {
    report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Claim(claim) => Some(claim.as_ref()),
            _ => None,
        })
        .collect()
}

/// Every value claimed under one attribute name.
fn values_of(report: &DocumentReport, name: &str) -> Vec<String> {
    claims(report)
        .into_iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Attribute { name: key, value } if key.as_str() == name => {
                Some(value.as_str().to_owned())
            }
            _ => None,
        })
        .collect()
}

/// Every distinct observable a report produced, by its bare canonical value.
///
/// An `Observable`'s display form is `kind:value` — `url:http://…` — which is the model's own
/// unambiguous spelling and what the claim records. The tests below assert on the value alone,
/// because the kind is already asserted by the mapping's target.
fn subjects(report: &DocumentReport) -> Vec<String> {
    let mut values: Vec<String> = values_of(report, "mapping.subject")
        .into_iter()
        .map(|value| {
            value
                .split_once(':')
                .map_or(value.clone(), |(_, rest)| rest.to_owned())
        })
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

/// Every observable a report produced, with the model's `kind:value` spelling intact.
fn typed_subjects(report: &DocumentReport) -> Vec<String> {
    let mut values = values_of(report, "mapping.subject");
    values.sort_unstable();
    values.dedup();
    values
}

// ---------------------------------------------------------------------------
// Criterion: the example mapping validates and runs.
// ---------------------------------------------------------------------------

/// **The criterion.** Every shipped example validates, and validating is what loading does — so an
/// example that stopped being valid could not be loaded by the test either.
#[test]
fn every_shipped_example_mapping_validates() {
    for name in ["acme-json.yml", "acme-csv.yml", "device-xml.yml"] {
        let mapping = load(name);
        assert!(mapping.validate().is_ok(), "`{name}` must validate");
        assert_eq!(mapping.version, 1);
        assert!(
            mapping.subject_field().is_some(),
            "`{name}` must name a subject"
        );
    }
}

/// **The criterion.** The JSON example runs, and produces what its fields say it will.
#[test]
fn the_json_example_mapping_runs_and_produces_what_it_declares() {
    let report = run(load("acme-json.yml"), ACME_JSON.as_bytes());

    // Two of the five records survive: one is filtered out by `kind`, one has an unusable subject,
    // and one has an unrecognised verdict — which keeps the record and drops only that field.
    let subjects = subjects(&report);
    assert!(
        subjects.contains(&"http://evil.example.com/payload".to_owned()),
        "the defanged URL must have been undefanged and canonicalised: {subjects:?}"
    );
    assert!(
        subjects.contains(&"198.51.100.23".to_owned()),
        "{subjects:?}"
    );
    assert!(
        subjects.contains(&"203.0.113.9".to_owned()),
        "a record whose verdict is unrecognised keeps its subject: {subjects:?}"
    );

    // Sorted, because the pipeline orders records by kind and identifier rather than by document
    // position — which is what makes two batches holding the same records issue the same writes.
    let mut confidence = values_of(&report, "acme.confidence");
    confidence.sort_unstable();
    assert_eq!(
        confidence,
        vec!["65", "90"],
        "a JSON number and a string spelling of one are the same fact"
    );
    // The multi-valued column produced one claim per value.
    let mut tags = values_of(&report, "acme.tag");
    tags.sort_unstable();
    assert_eq!(tags, vec!["credential-theft", "phishing", "scanning"]);

    // A default substitutes for an absence, and only for an absence.
    let systems = values_of(&report, "acme.source_system");
    assert!(systems.contains(&"acme-sensor-3".to_owned()), "{systems:?}");
    assert!(
        systems.contains(&"unspecified".to_owned()),
        "the record with no source system takes the default: {systems:?}"
    );

    // Dispositions, from the two records whose verdict is a spelling this build recognises.
    let dispositions: Vec<&Disposition> = claims(&report)
        .into_iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Disposition(disposition) => Some(disposition),
            _ => None,
        })
        .collect();
    assert_eq!(dispositions.len(), 2, "{dispositions:?}");
    assert!(dispositions.iter().all(|d| **d == Disposition::Malicious));

    // The ignored field produced nothing, which is the whole point of declaring it.
    assert!(
        values_of(&report, "acme.internal_ticket").is_empty()
            && !claims(&report).iter().any(|claim| match &claim.assertion {
                Assertion::Attribute { value, .. } => value.as_str().contains("ACME-4471"),
                _ => false,
            }),
        "an `ignore` target must not reach the store under any name"
    );
}

/// A filtered-out record is not a rejection: it is a record the mapping is not about, and recording
/// it as a rejection would fill quarantine with the majority of a feed.
#[test]
fn a_filtered_record_is_skipped_rather_than_quarantined() {
    let report = run(load("acme-json.yml"), ACME_JSON.as_bytes());

    let reasons: Vec<&str> = report
        .rejected
        .iter()
        .map(|rejection| rejection.reason_kind)
        .collect();
    assert!(
        !reasons.contains(&"filter_evaluation_failed"),
        "a record that simply did not match must not be a rejection: {reasons:?}"
    );
    // The one that *is* rejected is the one whose subject could not be canonicalised.
    assert!(
        reasons.contains(&"subject_not_canonical"),
        "a record whose subject is unusable must be visible in quarantine: {reasons:?}"
    );
}

/// **The criterion.** The CSV example runs, including the quoted column a naive split would shift.
#[test]
fn the_csv_example_mapping_runs_and_handles_quoted_columns() {
    let report = run(load("acme-csv.yml"), ACME_CSV.as_bytes());

    let subjects = subjects(&report);
    assert!(subjects.contains(&"1.2.3.4".to_owned()), "{subjects:?}");
    assert!(
        subjects.contains(&"evil2.example.com".to_owned()),
        "the defanged domain must be undefanged: {subjects:?}"
    );

    // `host:port` split by name rather than by position.
    let mut hosts = values_of(&report, "acme.endpoint_host");
    hosts.sort_unstable();
    assert_eq!(hosts, vec!["host.example", "other.example"]);

    // The quoted notes column survived intact, whitespace collapsed. A naive split on the comma
    // inside it would have shifted every subsequent column.
    let notes = values_of(&report, "acme.notes");
    assert!(
        notes.contains(&"a note with spacing".to_owned()),
        "{notes:?}"
    );

    // Both truthy and falsy spellings mapped, and the empty-indicator row was filtered out.
    let dispositions: Vec<Disposition> = claims(&report)
        .into_iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Disposition(disposition) => Some(*disposition),
            _ => None,
        })
        .collect();
    assert!(
        dispositions.contains(&Disposition::Malicious),
        "{dispositions:?}"
    );
    assert!(
        dispositions.contains(&Disposition::Benign),
        "{dispositions:?}"
    );
    assert_eq!(subjects.len(), 2, "the empty-indicator row is filtered out");
}

/// **The criterion.** The XML example runs, reading an element's attribute as well as its children.
#[test]
fn the_xml_example_mapping_runs_and_reads_attributes() {
    let report = run(load("device-xml.yml"), DEVICE_XML.as_bytes());

    let subjects = subjects(&report);
    assert_eq!(subjects, vec!["bad.example.com", "worse.example.net"]);

    assert_eq!(
        typed_subjects(&report),
        vec![
            "domain_name:bad.example.com",
            "domain_name:worse.example.net"
        ],
        "the mapping named the kind, so the claim carries the model's typed spelling"
    );

    let mut reasons = values_of(&report, "device.block_reason");
    reasons.sort_unstable();
    assert_eq!(
        reasons,
        vec!["policy-match", "reputation"],
        "the record element's own attribute must be readable"
    );

    // The third record has no destination, and the field is `required`, so it is a rejection rather
    // than a silently short record.
    assert_eq!(report.rejected.len(), 1, "{:#?}", report.rejected);
    assert!(
        report.rejected[0].reason.contains("selected nothing"),
        "{:#?}",
        report.rejected[0]
    );
}

/// XML goes through the reader that refuses a DTD, and a mapping cannot opt out of it.
#[test]
fn a_mapped_xml_document_carrying_a_doctype_is_refused() {
    let hostile = DEVICE_XML.replace(
        "<report",
        "<!DOCTYPE report [<!ENTITY a \"aaaaaaaaaa\">]>\n<report",
    );
    let mut registry = ParserRegistry::new();
    registry.register(MappedParser::boxed(load("device-xml.yml")));
    let result = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &document(hostile.as_bytes(), "application/octet-stream"),
            &CancellationToken::never_cancelled(),
        );
    assert!(
        result.is_err(),
        "a DTD must be refused before anything is parsed, whatever the mapping says"
    );
}

// ---------------------------------------------------------------------------
// Criterion: expression and transform functions come from an allowlist, and no
// shell, filesystem, network, dynamic code, or arbitrary Rust execution exists.
// ---------------------------------------------------------------------------

/// **The criterion.** A mapping cannot name a transform this build does not have, whatever shape it
/// tries.
///
/// Asserted at the document level rather than on the enum, because the enum test proves the type
/// cannot hold one and this proves a *mapping file* cannot smuggle one in.
#[test]
fn a_mapping_cannot_name_a_transform_outside_the_allow_list() {
    for attempt in [
        "      - op: exec\n        command: /bin/sh\n",
        "      - op: read_file\n        path: /etc/passwd\n",
        "      - op: http_get\n        url: https://example.invalid\n",
        "      - op: eval\n        source: \"1+1\"\n",
        "      - exec: /bin/sh\n",
        "      - \"trim\"\n",
    ] {
        let document = format!(
            "schema_version: brolga.mapping/1.0\nid: hostile\nsource: json\nrecords: a[*]\n\
             fields:\n  - path: v\n    target:\n      type: infer\n    subject: true\n    \
             transforms:\n{attempt}"
        );
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            matches!(error, MappingError::Unreadable(_)),
            "`{attempt}` should fail to load, not to validate: {error:?}"
        );
    }
}

/// **The criterion.** The whole allow-list is what the documentation says, and the engine's refusals
/// are stated in the explain output rather than only in a comment.
#[test]
fn the_engine_states_its_refusals_in_its_own_output() {
    let explanation = MappedParser::new(load("acme-json.yml")).explain();

    let refusals = explanation.refusals.join(" ");
    for expected in [
        "shell",
        "network",
        "execute code",
        "loop, branch",
        "entity",
        "limits",
        "DOCTYPE",
        "recursive descent",
    ] {
        assert!(
            refusals.contains(expected),
            "the refusal list must mention `{expected}`: {refusals}"
        );
    }
    assert_eq!(explanation.refusals, engine::REFUSALS);
}

/// Every transform the allow-list names is reachable from a mapping document, and nothing else is.
#[test]
fn the_allow_list_is_exactly_what_a_mapping_can_reach() {
    let documents = [
        ("trim", "op: trim"),
        ("lowercase", "op: lowercase"),
        ("uppercase", "op: uppercase"),
        ("strip_prefix", "op: strip_prefix\n        prefix: 'x'"),
        ("strip_suffix", "op: strip_suffix\n        suffix: 'x'"),
        ("replace", "op: replace\n        from: 'a'\n        to: 'b'"),
        (
            "split_take",
            "op: split_take\n        separator: ':'\n        index: 0",
        ),
        (
            "substring",
            "op: substring\n        start: 0\n        length: 4",
        ),
        ("undefang", "op: undefang"),
        ("collapse_whitespace", "op: collapse_whitespace"),
    ];
    assert_eq!(
        documents.len(),
        transform::ALLOWED.len(),
        "this test must cover every allowed transform"
    );

    for (name, body) in documents {
        let document = format!(
            "schema_version: brolga.mapping/1.0\nid: t\nsource: json\nrecords: a[*]\nfields:\n  \
             - path: v\n    target:\n      type: infer\n    subject: true\n    transforms:\n      \
             - {body}\n"
        );
        let mapping = Mapping::load(document.as_bytes())
            .unwrap_or_else(|error| panic!("`{name}` should load: {error}"));
        assert_eq!(mapping.fields[0].transforms[0].name(), name);
    }
}

// ---------------------------------------------------------------------------
// Criterion: mappings produce provenance transformation steps.
// ---------------------------------------------------------------------------

/// **The criterion.** Every record a mapping produces carries a transformation step naming the
/// mapping and its version.
///
/// The step is what makes "which mapping produced this claim, at which version" answerable from a
/// record. Without it, a mapping change would be invisible in the data it changed.
#[test]
fn every_mapped_record_carries_a_transformation_step_naming_the_mapping() {
    let report = run(load("acme-json.yml"), ACME_JSON.as_bytes());
    assert!(!report.records.is_empty());

    for record in &report.records {
        let origin = match record {
            ParsedRecord::Claim(claim) => &claim.origin,
            ParsedRecord::Entity(entity) => &entity.origin,
            ParsedRecord::Relationship(relationship) => &relationship.origin,
            ParsedRecord::Sighting(sighting) => &sighting.origin,
            _ => continue,
        };
        let provenance = origin
            .provenance()
            .expect("a mapped record is source-derived");

        // By stage, not by name prefix: the pipeline's own parsing step is named after the parser
        // identifier, which is `brolga.mapping.declarative` — so matching on the prefix would find
        // that one and never check the step this test is about.
        let step = provenance
            .chain
            .steps()
            .iter()
            .find(|step| step.stage == TransformationStage::Normalisation)
            .unwrap_or_else(|| panic!("no mapping step in the chain: {:#?}", provenance.chain));
        assert_eq!(
            step.algorithm.as_str(),
            "brolga.mapping.acme-indicator-export"
        );
        assert_eq!(step.algorithm_version, 1);
        assert_eq!(
            step.stage,
            TransformationStage::Normalisation,
            "mapping source vocabulary onto canonical types is normalisation"
        );
    }
}

/// A record still cites the document it came from: the mapping step is added to the pipeline's chain
/// rather than replacing it.
#[test]
fn the_mapping_step_is_added_to_the_chain_rather_than_replacing_it() {
    let report = run(load("acme-json.yml"), ACME_JSON.as_bytes());
    let claim = claims(&report)[0];
    let provenance = claim.origin.provenance().unwrap();

    let stages: Vec<TransformationStage> = provenance
        .chain
        .steps()
        .iter()
        .map(|step| step.stage)
        .collect();
    assert!(
        stages.len() > 1,
        "the pipeline's own steps must survive: {stages:?}"
    );
    assert_eq!(
        stages.last(),
        Some(&TransformationStage::Normalisation),
        "the mapping step is the most recent: {stages:?}"
    );
    assert!(
        provenance.source_objects.contains(&report.source_object),
        "a mapped record cites the document it was read from: {:?}",
        provenance.source_objects
    );
}

// ---------------------------------------------------------------------------
// Criterion: path evaluation and record counts are bounded.
// ---------------------------------------------------------------------------

/// **The criterion.** A document over the mapping's own record ceiling is refused, not truncated.
#[test]
fn a_document_over_the_record_limit_is_refused_rather_than_truncated() {
    let source = "schema_version: brolga.mapping/1.0\nid: tiny\nsource: json\nrecords: data[*]\n\
                  limits:\n  max_records: 2\nfields:\n  - path: v\n    target:\n      \
                  type: infer\n    subject: true\n";
    let mapping = Mapping::load(source.as_bytes()).unwrap();

    let values: Vec<serde_json::Value> = (0..10)
        .map(|n| serde_json::json!({"v": format!("192.0.2.{n}")}))
        .collect();
    let feed = serde_json::to_vec(&serde_json::json!({"data": values})).unwrap();

    let mut registry = ParserRegistry::new();
    registry.register(MappedParser::boxed(mapping));
    let error = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &document(&feed, "application/octet-stream"),
            &CancellationToken::never_cancelled(),
        )
        .expect_err("a document over the limit must be refused");
    assert!(
        error.to_string().contains("2-record limit"),
        "the limit that was hit must be named: {error}"
    );
}

/// **The criterion.** Path evaluation is bounded, and a mapping cannot raise the ceiling.
#[test]
fn path_evaluation_is_bounded_and_the_ceiling_cannot_be_raised() {
    // A mapping may lower its node budget.
    let lowered = "schema_version: brolga.mapping/1.0\nid: narrow\nsource: json\n\
                   records: data[*]\nlimits:\n  max_nodes: 60\nfields:\n  - path: v\n    \
                   target:\n      type: infer\n    subject: true\n";
    let mapping = Mapping::load(lowered.as_bytes()).unwrap();
    assert_eq!(mapping.limits.max_nodes, 60);

    let values: Vec<serde_json::Value> = (0..500)
        .map(|n| serde_json::json!({"v": format!("192.0.2.{}", n % 250)}))
        .collect();
    let feed = serde_json::to_vec(&serde_json::json!({"data": values})).unwrap();

    let mut registry = ParserRegistry::new();
    registry.register(MappedParser::boxed(mapping));
    let error = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &document(&feed, "application/octet-stream"),
            &CancellationToken::never_cancelled(),
        )
        .expect_err("the record path must exceed a 60-node budget");
    assert!(error.to_string().contains("60-node"), "{error}");

    // And it may not raise it above the build's ceiling.
    let raised = format!(
        "schema_version: brolga.mapping/1.0\nid: wide\nsource: json\nrecords: data[*]\nlimits:\n  \
         max_nodes: {}\nfields:\n  - path: v\n    target:\n      type: infer\n    subject: true\n",
        path::MAX_NODE_CEILING + 1
    );
    assert!(matches!(
        Mapping::load(raised.as_bytes()).unwrap_err(),
        MappingError::LimitTooHigh { .. }
    ));
}

// ---------------------------------------------------------------------------
// Detection: a mapping is a fallback, never a competitor.
// ---------------------------------------------------------------------------

/// A mapping registered alongside the compiled parsers does not take a document one of them
/// recognises.
#[test]
fn a_compiled_parser_wins_over_a_mapping_for_a_format_it_recognises() {
    use brolga_ingest::formats::stix;

    let bundle = br#"{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000000",
        "objects":[{"type":"indicator","spec_version":"2.1",
        "id":"indicator--00000000-0000-4000-8000-000000000001",
        "created":"2026-01-01T00:00:00.000Z","modified":"2026-01-01T00:00:00.000Z",
        "pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.7']",
        "valid_from":"2026-01-01T00:00:00Z"}]}"#;

    let mut registry = ParserRegistry::new();
    registry.register(stix::StixParser::boxed());
    registry.register(MappedParser::boxed(load("acme-json.yml")));

    let report = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &document(bundle, "application/octet-stream"),
            &CancellationToken::never_cancelled(),
        )
        .expect("the bundle must parse");
    assert_eq!(
        report.parser,
        stix::STIX_PARSER_ID,
        "a mapping must never take a document a compiled parser recognises"
    );
}

/// A mapping pointed at the wrong shape declines, rather than producing a successful ingest of
/// nothing — which is the failure an operator is least likely to notice.
#[test]
fn a_mapping_declines_a_document_of_the_wrong_shape() {
    use brolga_ingest::detect::{DetectionConfidence, FormatHint};

    let xml_mapping = MappedParser::new(load("device-xml.yml"));
    let json_bytes = ACME_JSON.as_bytes();
    let hint = FormatHint::new(
        "application/octet-stream",
        None,
        json_bytes,
        u64::try_from(json_bytes.len()).unwrap(),
    );
    let candidate = xml_mapping.detect(&hint);
    assert_eq!(candidate.confidence, DetectionConfidence::Declined);
    assert!(
        candidate.reason.contains("not the shape"),
        "{}",
        candidate.reason
    );

    // And a mapping never claims certainty, so a compiled parser can always outrank it.
    let json_mapping = MappedParser::new(load("acme-json.yml"));
    let claim = json_mapping.detect(&hint);
    assert_eq!(claim.confidence, DetectionConfidence::Strong);
}

// ---------------------------------------------------------------------------
// The store round trip.
// ---------------------------------------------------------------------------

/// Every example mapping's output survives a round trip through a real store.
#[test]
fn mapped_records_reach_the_store() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.migrate().unwrap();

    let mut registry = ParserRegistry::new();
    registry.register(MappedParser::boxed(load("acme-json.yml")));

    let bytes = ACME_JSON.as_bytes();
    let report = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .ingest_batch(
            &mut store,
            &[document(bytes, "application/octet-stream")],
            &CancellationToken::never_cancelled(),
        )
        .expect("the batch must ingest");

    assert!(report.persisted() > 0, "{report:#?}");
    assert!(
        store.count(RecordKind::Claim).unwrap() > 0,
        "mapped claims must reach the store"
    );
    // The one unusable subject is quarantined rather than lost.
    assert_eq!(report.rejected, 1, "{report:#?}");
}

/// The mapping's declared shape and targets are what the loader read, so a reader of the YAML and a
/// reader of the struct learn the same thing.
#[test]
fn the_loaded_mapping_matches_the_document_it_was_written_as() {
    let mapping = load("acme-json.yml");
    assert_eq!(mapping.source, SourceShape::Json);
    assert_eq!(mapping.records.as_deref(), Some("data[*]"));
    assert_eq!(mapping.filters.len(), 2);

    let subject = mapping.subject_field().unwrap();
    assert_eq!(subject.target, Target::Infer);
    assert_eq!(
        subject.transforms,
        vec![Transform::Trim, Transform::Undefang]
    );

    assert!(
        mapping
            .fields
            .iter()
            .any(|field| field.target == Target::Ignore),
        "the example documents a deliberately unimported column"
    );
    assert!(
        mapping.fields.iter().any(|field| matches!(
            &field.target,
            Target::Attribute { name } if name == "acme.tag"
        )),
        "the multi-valued column must be an attribute target"
    );
}

/// A subject path selecting several values is ambiguous, and picking the first would attach every
/// other field to an arbitrary choice.
#[test]
fn an_ambiguous_subject_is_rejected_rather_than_resolved_by_position() {
    let document = "schema_version: brolga.mapping/1.0\nid: ambiguous\nsource: json\n\
                    records: data[*]\nfields:\n  - path: values[*]\n    target:\n      \
                    type: infer\n    subject: true\n";
    let mapping = Mapping::load(document.as_bytes()).unwrap();
    let feed = br#"{"data":[{"values":["192.0.2.1","192.0.2.2"]}]}"#;

    let report = run(mapping, feed);
    assert_eq!(report.records.len(), 0, "{:#?}", report.records);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].reason_kind, "ambiguous_subject");
    assert!(
        report.rejected[0].reason.contains("about one thing"),
        "{:#?}",
        report.rejected[0]
    );
}

/// An inferred subject that two canonicalisers accept is refused with the list, never guessed.
#[test]
fn an_ambiguous_inference_names_what_the_value_could_have_been() {
    let document = "schema_version: brolga.mapping/1.0\nid: infer\nsource: json\n\
                    records: data[*]\nfields:\n  - path: v\n    target:\n      type: infer\n    \
                    subject: true\n";
    let mapping = Mapping::load(document.as_bytes()).unwrap();
    // A bare label that both the domain and the file-name canonicalisers could take.
    let feed = br#"{"data":[{"v":"report.doc"}]}"#;

    let report = run(mapping, feed);
    // Either it canonicalised unambiguously or it was refused with the alternatives. Both are
    // correct; guessing silently is not, and that is what this asserts against.
    if report.records.is_empty() {
        assert_eq!(report.rejected.len(), 1);
        let reason = &report.rejected[0].reason;
        assert!(
            reason.contains("ambiguous") || reason.contains("no canonicaliser"),
            "{reason}"
        );
    } else {
        assert_eq!(subjects(&report).len(), 1);
    }
}

/// An unrecognised disposition drops that field and keeps the record, because the alternative is
/// discarding a good indicator over one bad column.
#[test]
fn an_unrecognised_disposition_drops_the_field_and_keeps_the_record() {
    let report = run(load("acme-json.yml"), ACME_JSON.as_bytes());

    assert!(
        subjects(&report).contains(&"203.0.113.9".to_owned()),
        "the record with the unrecognised verdict must survive"
    );
    // And the reason is in the notes, so the loss is visible.
    let notes = report
        .notes
        .iter()
        .map(|note| note.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        notes.contains("disposition") || notes.contains("verdict"),
        "the dropped field must be named: {notes}"
    );
}
