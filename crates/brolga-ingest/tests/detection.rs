//! Sigma, YARA, OpenIOC, and IODEF ingestion, against fixture corpora and a real store.
//!
//! One section per acceptance criterion of [#52](https://github.com/jusso-dev/Brolga/issues/52)
//! that these formats are responsible for.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::formats::{sigma, xml, yara};
use brolga_ingest::{
    Document, IngestMode, IntelligenceParser, ParsedRecord, ParserRegistry, Pipeline,
};
use brolga_model::{
    Assertion, Claim, Entity, EntityKind, NodeRef, Observable, RelationshipKind, ShortText,
    Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;

const SIGMA_RULES: &str = include_str!("fixtures/detection/rules.yml");
const YARA_RULES: &str = include_str!("fixtures/detection/rules.yar");
const OPENIOC: &str = include_str!("fixtures/xml/definition.ioc");
const IODEF: &str = include_str!("fixtures/xml/incident.iodef");

/// Every parser these fixtures need, registered together, so a fixture claimed by the wrong parser
/// fails here rather than in production.
fn pipeline() -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(sigma::SigmaParser::boxed());
    registry.register(yara::YaraParser::boxed());
    registry.register(xml::OpenIocParser::boxed());
    registry.register(xml::IodefParser::boxed());
    Pipeline::with_defaults(registry).in_mode(IngestMode::Permissive)
}

fn document<'a>(bytes: &'a [u8], media_type: &str) -> Document<'a> {
    Document {
        bytes,
        media_type: MediaType::new(media_type).unwrap(),
        file_name: None,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("detection-fixture").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

fn prepare(bytes: &[u8], media_type: &str) -> brolga_ingest::DocumentReport {
    pipeline()
        .prepare(
            &document(bytes, media_type),
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

fn entities(report: &brolga_ingest::DocumentReport) -> Vec<&Entity> {
    report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Entity(entity) => Some(entity.as_ref()),
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

fn attribute_values<'a>(report: &'a brolga_ingest::DocumentReport, key: &str) -> Vec<&'a str> {
    claims(report)
        .into_iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Attribute { name, value } if name.as_str() == key => Some(value.as_str()),
            _ => None,
        })
        .collect()
}

fn ipv4(value: &str) -> Observable {
    Observable::Ipv4Address(value.parse().unwrap())
}

fn domain(value: &str) -> Observable {
    Observable::DomainName(brolga_model::observable::DomainName::new(value).unwrap())
}

// ---------------------------------------------------------------------------------------------
// "Detection content maps to typed rule and detection entities"
// ---------------------------------------------------------------------------------------------

/// The criterion. A rule is a detection, not a tool and not a technique — filing it under either
/// only surfaces once somebody counts techniques and finds the detections mixed in.
#[test]
fn sigma_and_yara_rules_become_typed_detection_rule_entities() {
    for (bytes, media_type) in [
        (SIGMA_RULES.as_bytes(), "text/x-sigma"),
        (YARA_RULES.as_bytes(), "text/x-yara"),
    ] {
        let report = prepare(bytes, media_type);
        assert!(
            entities(&report)
                .iter()
                .any(|entity| entity.kind == EntityKind::DetectionRule),
            "{media_type} produced no detection rule: {:?}",
            report.rejected
        );
    }
}

/// A Sigma `id` is required to be globally unique and stable across edits — exactly the property an
/// identifier needs. Keying on the title would make a retitled rule a new rule and two forks of one
/// rule two rules.
#[test]
fn a_sigma_rule_is_keyed_on_its_own_uuid_rather_than_its_title() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");
    let retitled = SIGMA_RULES.replace(
        "title: Suspicious outbound to known C2",
        "title: Renamed but the same rule",
    );
    let after = prepare(retitled.as_bytes(), "text/x-sigma");

    let first = entities(&report)
        .into_iter()
        .find(|entity| entity.kind == EntityKind::DetectionRule)
        .unwrap()
        .id;
    let second = entities(&after)
        .into_iter()
        .find(|entity| entity.kind == EntityKind::DetectionRule)
        .unwrap()
        .id;

    assert_eq!(first, second, "a retitled rule is the same rule");
}

/// `attack.t1071.001` names a technique the author says the rule finds. It must derive the same
/// entity ATT&CK ingestion produces, or the technique sits in the graph twice.
#[test]
fn an_attack_tag_becomes_a_technique_entity_and_a_typed_edge() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");

    let technique = entities(&report)
        .into_iter()
        .find(|entity| entity.kind == EntityKind::AttackTechnique)
        .expect("a technique entity");
    assert_eq!(technique.name.as_str(), "T1071.001");

    assert!(
        report.records.iter().any(|record| matches!(
            record,
            ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::Indicates
        )),
        "no edge from the rule to the technique"
    );
}

/// A tactic is a category. Minting an entity for one would put a dozen giant hubs in the middle of
/// the graph that every rule connects to and nobody learns anything from.
#[test]
fn a_tactic_tag_is_recorded_without_becoming_an_entity() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");

    assert!(
        attribute_values(&report, "sigma.tag").contains(&"attack.command_and_control"),
        "the tactic tag is kept as evidence"
    );
    assert_eq!(
        entities(&report)
            .iter()
            .filter(|entity| entity.kind == EntityKind::AttackTechnique)
            .count(),
        1,
        "only the technique tag mints an entity"
    );
}

/// Sigma's own withdrawal states. A deprecated rule is not an absent one — it records both that
/// somebody published it and that they stepped back from it.
#[test]
fn a_deprecated_sigma_rule_is_kept_and_marked_rather_than_dropped() {
    use brolga_model::LifecycleStatus;

    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");
    let deprecated = entities(&report)
        .into_iter()
        .find(|entity| entity.name.as_str() == "Deprecated rule")
        .expect("the deprecated rule");
    assert_eq!(deprecated.status, LifecycleStatus::Deprecated);
}

/// A document with no `detection` block describes no detection. Storing it would put a rule in the
/// graph that finds nothing.
#[test]
fn a_sigma_document_with_no_detection_block_is_quarantined() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "missing_detection"),
        "{:?}",
        report.rejected
    );
}

// ---------------------------------------------------------------------------------------------
// "No execution of YARA, Sigma, queries, or imported commands"
// ---------------------------------------------------------------------------------------------

/// A field carrying a modifier is a predicate over a set. `DestinationHostname|contains: internal`
/// names an infinite set of hostnames, and recording `internal` as a domain would assert the rule
/// was about a domain nobody wrote down.
#[test]
fn a_sigma_field_with_a_modifier_yields_no_observable_and_is_named() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");

    // The operand must not appear as any observable's value. Asserting against a constructed
    // `DomainName` would be vacuous — `internal` is a single label and is not a valid domain at
    // all, so the check has to be over what was actually produced.
    let subjects: Vec<String> = claims(&report)
        .iter()
        .filter_map(|claim| match claim.subject {
            NodeRef::Observable(_) => match &claim.assertion {
                Assertion::Attribute { value, .. } => Some(value.as_str().to_owned()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert!(
        !subjects.iter().any(|value| value.contains("internal")),
        "a `contains` operand became an observable: {subjects:?}"
    );

    let unread = attribute_values(&report, "sigma.detection.unread").join(" ");
    assert!(unread.contains("modifier"), "{unread}");
}

/// `Image` and `CommandLine` are paths and command fragments. Canonicalising them would invent file
/// names out of arguments.
#[test]
fn log_source_specific_sigma_fields_are_named_rather_than_canonicalised() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");
    let unread = attribute_values(&report, "sigma.detection.unread").join(" ");

    assert!(unread.contains("Image"), "{unread}");
    assert!(unread.contains("CommandLine"), "{unread}");
}

/// Plain equality on an unambiguous field is the one case that states a value.
#[test]
fn a_plain_equality_on_an_unambiguous_sigma_field_yields_its_observable() {
    let report = prepare(SIGMA_RULES.as_bytes(), "text/x-sigma");

    for value in ["198.51.100.50", "198.51.100.51"] {
        assert!(
            !claims_about(&report, &ipv4(value)).is_empty(),
            "`{value}` was not read"
        );
    }
    assert!(!claims_about(&report, &domain("c2.example.net")).is_empty());
}

/// A YARA string is a pattern, usually a fragment, sometimes a regular expression. Canonicalising
/// them would mint observables out of pattern pieces — but the count still distinguishes a rule
/// with four patterns from one with none.
#[test]
fn yara_strings_are_counted_and_never_read_as_values() {
    let report = prepare(YARA_RULES.as_bytes(), "text/x-yara");

    assert!(
        claims_about(&report, &domain("evil.example.com")).is_empty(),
        "a YARA pattern became a domain observable"
    );
    assert!(
        attribute_values(&report, "yara.strings.count").contains(&"4"),
        "{:?}",
        attribute_values(&report, "yara.strings.count")
    );
}

/// A `hash` in `meta` is a stated fact about a sample the author tested against, written as a whole
/// value. That is the one place a YARA rule names an observable.
#[test]
fn a_yara_meta_hash_is_the_one_observable_a_rule_names() {
    let report = prepare(YARA_RULES.as_bytes(), "text/x-yara");

    let sha256 = Observable::FileHash(
        brolga_model::observable::FileHash::new(
            brolga_model::observable::HashAlgorithm::Sha256,
            "a".repeat(64),
        )
        .unwrap(),
    );
    assert!(
        !claims_about(&report, &sha256).is_empty(),
        "the `hash` meta value was not read"
    );
}

/// The word appears in comments and in prose. Treating every occurrence as a declaration would mint
/// entities out of documentation.
#[test]
fn the_word_rule_in_a_comment_does_not_mint_an_entity() {
    let report = prepare(YARA_RULES.as_bytes(), "text/x-yara");
    assert_eq!(
        entities(&report)
            .iter()
            .filter(|entity| entity.kind == EntityKind::DetectionRule)
            .count(),
        2,
        "the comment mentioning `rule` is not a rule"
    );
}

// ---------------------------------------------------------------------------------------------
// "XML entity expansion is disabled"
// ---------------------------------------------------------------------------------------------

/// The criterion, through the whole pipeline rather than only the reader. A document with a DTD is
/// refused before anything is expanded, which closes billion laughs and XXE together.
#[test]
fn an_xml_bomb_is_refused_by_the_pipeline() {
    let bomb = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="x">
  <short_description>&lol2;</short_description>
  <definition><Indicator><IndicatorItem condition="is">
    <Context search="Network/DNS"/><Content>&lol2;</Content>
  </IndicatorItem></Indicator></definition>
</ioc>"#;

    let error = pipeline()
        .prepare(
            &document(bomb.as_bytes(), "application/x-openioc+xml"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("DOCTYPE"), "{error}");
}

/// The external-entity shape. The same refusal is what stops a parse from reading a local file or
/// making a network request on the parser's behalf.
#[test]
fn an_external_entity_is_refused_by_the_pipeline() {
    let xxe = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<IODEF-Document version="1.00" xmlns="urn:ietf:params:xml:ns:iodef-1.0">
  <Incident><IncidentID name="x">&xxe;</IncidentID></Incident>
</IODEF-Document>"#;

    let error = pipeline()
        .prepare(
            &document(xxe.as_bytes(), "application/iodef+xml"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("DOCTYPE"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// OpenIOC and IODEF mapping
// ---------------------------------------------------------------------------------------------

/// An `<ioc>` defines how to find something, so it is a detection rule, and its `is` items name
/// whole values.
#[test]
fn an_openioc_definition_becomes_a_rule_and_its_is_items_become_observables() {
    let report = prepare(OPENIOC.as_bytes(), "application/x-openioc+xml");

    assert!(
        entities(&report)
            .iter()
            .any(|entity| entity.kind == EntityKind::DetectionRule),
        "{:?}",
        report.rejected
    );
    assert!(
        !claims_about(&report, &domain("c2.example.net")).is_empty(),
        "`C2.EXAMPLE.NET.` canonicalises like any other domain"
    );

    let md5 = Observable::FileHash(
        brolga_model::observable::FileHash::new(
            brolga_model::observable::HashAlgorithm::Md5,
            "b".repeat(32),
        )
        .unwrap(),
    );
    assert!(!claims_about(&report, &md5).is_empty());
}

/// `contains` describes a set of values. Taking `-enc` as an observable would record a value the
/// author never said was the artefact.
#[test]
fn an_openioc_condition_other_than_is_is_named_rather_than_mined() {
    let report = prepare(OPENIOC.as_bytes(), "application/x-openioc+xml");
    let unread = attribute_values(&report, "openioc.unread").join(" ");

    assert!(unread.contains("condition `contains`"), "{unread}");
    assert!(
        unread.contains("PortItem/remoteIP"),
        "a mapped path whose value was unusable is named too: {unread}"
    );
}

/// An `<Incident>` is a discrete event under investigation, which is exactly what the canonical
/// kind means.
#[test]
fn an_iodef_incident_becomes_an_incident_entity_with_its_addresses() {
    let report = prepare(IODEF.as_bytes(), "application/iodef+xml");

    let incidents: Vec<_> = entities(&report)
        .into_iter()
        .filter(|entity| entity.kind == EntityKind::Incident)
        .collect();
    assert_eq!(incidents.len(), 2, "{:?}", report.rejected);
    assert!(
        incidents[0].name.as_str().contains("csirt.example.com"),
        "the issuing team is part of the name, because an incident number is unique only to it"
    );

    assert!(!claims_about(&report, &ipv4("198.51.100.60")).is_empty());
}

/// A CIDR in an `ipv4-net` address is a range, and the range canonicaliser masks host bits — so the
/// `/24` a reporter wrote around `.5` is the network it names.
#[test]
fn an_iodef_network_address_becomes_a_masked_range() {
    let report = prepare(IODEF.as_bytes(), "application/iodef+xml");
    let range = Observable::IpRange(
        brolga_model::observable::IpRange::new("198.51.100.0".parse().unwrap(), 24).unwrap(),
    );
    assert!(!claims_about(&report, &range).is_empty());
}

/// "High impact" describes the effect on the reporting party, not whether an address is malicious.
/// Mapping it to a disposition would let a reporter's severity scale decide detection.
#[test]
fn an_iodef_impact_severity_is_recorded_and_never_becomes_a_disposition() {
    let report = prepare(IODEF.as_bytes(), "application/iodef+xml");

    assert!(attribute_values(&report, "iodef.impact.severity").contains(&"high"));
    assert!(
        !claims(&report)
            .iter()
            .any(|claim| matches!(claim.assertion, Assertion::Disposition(_))),
        "a reporter's severity became an assessment"
    );
}

/// An address category Brolga does not read is named, not guessed at. An ASN is not an address and
/// coercing one would produce an observable of the wrong kind.
#[test]
fn an_unread_iodef_address_category_is_named() {
    let report = prepare(IODEF.as_bytes(), "application/iodef+xml");
    let unread = attribute_values(&report, "iodef.unread").join(" ");
    assert!(unread.contains("asn"), "{unread}");
}

// ---------------------------------------------------------------------------------------------
// Detection must be decisive, and hostile input must never panic
// ---------------------------------------------------------------------------------------------

/// Each fixture must be claimed by the parser that can read it. A YAML file claimed by the XML
/// parser fails as "malformed XML", which sends an operator looking at the wrong thing.
#[test]
fn every_fixture_is_claimed_by_the_parser_that_can_read_it() {
    for (bytes, expected) in [
        (SIGMA_RULES.as_bytes(), "brolga.detection.sigma"),
        (YARA_RULES.as_bytes(), "brolga.detection.yara"),
        (OPENIOC.as_bytes(), "brolga.xml.openioc"),
        (IODEF.as_bytes(), "brolga.xml.iodef"),
    ] {
        let report = pipeline()
            .prepare(
                // Deliberately vague, so detection decides rather than the label.
                &document(bytes, "application/octet-stream"),
                &CancellationToken::never_cancelled(),
            )
            .unwrap();
        assert_eq!(report.parser.as_str(), expected, "{}", report.selection);
    }
}

/// Arbitrary and near-miss input through every one of these parsers. `Ok` or `Err`, never an
/// unwind — these are hand-written readers over attacker-supplied text.
#[test]
fn hostile_input_never_panics_in_any_detection_parser() {
    let parsers: Vec<Box<dyn IntelligenceParser>> = vec![
        sigma::SigmaParser::boxed(),
        yara::YaraParser::boxed(),
        xml::OpenIocParser::boxed(),
        xml::IodefParser::boxed(),
    ];

    let hostile: Vec<&[u8]> = vec![
        b"",
        b"\x00\x01\x02",
        b"title:",
        b"detection:\n  condition:",
        b"rule",
        b"rule R {",
        b"<ioc",
        b"<ioc></ioc>",
        b"<IODEF-Document></IODEF-Document>",
        b"---\n---\n---\n",
        b"{{{{{{{{",
        b"<a><a><a><a>",
    ];

    for parser in &parsers {
        for bytes in &hostile {
            let mut registry = ParserRegistry::new();
            registry.register(match parser.id().as_str() {
                "brolga.detection.sigma" => sigma::SigmaParser::boxed(),
                "brolga.detection.yara" => yara::YaraParser::boxed(),
                "brolga.xml.openioc" => xml::OpenIocParser::boxed(),
                _ => xml::IodefParser::boxed(),
            });
            let outcome = Pipeline::with_defaults(registry).prepare(
                &document(bytes, "application/octet-stream"),
                &CancellationToken::never_cancelled(),
            );
            assert!(
                outcome.is_ok() || outcome.is_err(),
                "{} on {bytes:?}",
                parser.id().as_str()
            );
        }
    }
}
