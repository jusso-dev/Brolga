//! STIX 2.1 and MITRE ATT&CK ingestion, against the fixture corpus and a real store.
//!
//! One section per acceptance criterion of [#13](https://github.com/jusso-dev/Brolga/issues/13).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::formats::stix::{MAX_FAN_OUT, StixParser, attack_id_of, depth_of};
use brolga_ingest::{Document, IngestMode, IngestReport, ParsedRecord, ParserRegistry, Pipeline};
use brolga_model::{
    ContentHash, EntityKind, LifecycleStatus, Marking, ShortText, Timestamp, TlpLevel,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, RecordKind, SqliteStore, StoreRead};

const BUNDLE: &str = include_str!("fixtures/stix/bundle.json");
const ATTACK: &str = include_str!("fixtures/stix/attack.json");
const BARE: &str = include_str!("fixtures/stix/bare-object.json");
const INDICATORS: &str = include_str!("fixtures/stix/indicators.json");
const BUNDLE_20: &str = include_str!("fixtures/stix/bundle-2.0.json");

fn pipeline(mode: IngestMode) -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(StixParser::boxed());
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
        media_type: MediaType::new("application/stix+json").unwrap(),
        file_name: None,
        origin: SourceOrigin::NetworkFeed {
            publisher: ShortText::new("stix-fixture").unwrap(),
            location: None,
        },
        retrieved_at: Timestamp::unix_epoch(),
    }
}

fn ingest(store: &mut SqliteStore, mode: IngestMode, bytes: &[u8]) -> IngestReport {
    pipeline(mode)
        .ingest_batch(
            store,
            &[document(bytes)],
            &CancellationToken::never_cancelled(),
        )
        .unwrap()
}

/// How many records carry the AMBER marking.
fn count_amber(report: &brolga_ingest::DocumentReport) -> usize {
    let amber = Marking::Tlp(TlpLevel::Amber);
    report
        .records
        .iter()
        .filter(|record| {
            let markings = match record {
                ParsedRecord::Entity(entity) => &entity.markings,
                ParsedRecord::Relationship(rel) => &rel.markings,
                ParsedRecord::Claim(claim) => &claim.markings,
                ParsedRecord::Sighting(sighting) => &sighting.markings,
                _ => return false,
            };
            markings.iter().any(|marking| *marking == amber)
        })
        .count()
}

fn prepare(bytes: &[u8]) -> brolga_ingest::DocumentReport {
    pipeline(IngestMode::Permissive)
        .prepare(&document(bytes), &CancellationToken::never_cancelled())
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// "Representative STIX 2.1 and enterprise ATT&CK fixtures ingest"
// ---------------------------------------------------------------------------------------------

/// The criterion. A bundle carrying SDOs, SCOs, SROs, and a marking definition ingests, and the
/// counts are what the fixture actually contains rather than "more than zero".
#[test]
fn a_representative_stix_bundle_ingests_into_typed_records() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, BUNDLE.as_bytes());

    assert!(report.reconciles(), "{report:?}");
    // 6 entities (intrusion-set, malware, attack-pattern, revoked campaign, identity,
    // infrastructure), 2 claims from SCOs, 2 relationships. `grouping` and `course-of-action` are
    // quarantined.
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 6);
    assert_eq!(store.count(RecordKind::Claim).unwrap(), 2);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 2);
    assert_eq!(report.rejected, 2, "`grouping` and `course-of-action`");
}

/// `course-of-action` is a mitigation, and no canonical entity kind means one. Filing it under the
/// nearest kind would assert it is a technique or a tool, which it is not — so it takes the same
/// quarantine every other unmapped type takes, and the module documentation says so.
#[test]
fn a_course_of_action_is_quarantined_rather_than_filed_under_the_nearest_kind() {
    let report = prepare(BUNDLE.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason.contains("course-of-action")),
        "{:?}",
        report.rejected
    );
}

/// The SDO types the module documentation lists must actually map. A doc that named a type the
/// code quarantined is how an operator concludes their feed is broken.
#[test]
fn identity_and_infrastructure_sdos_become_entities() {
    let report = prepare(BUNDLE.as_bytes());
    let kinds: Vec<EntityKind> = report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Entity(entity) => Some(entity.kind),
            _ => None,
        })
        .collect();

    assert!(kinds.contains(&EntityKind::Identity), "{kinds:?}");
    assert!(kinds.contains(&EntityKind::Infrastructure), "{kinds:?}");
}

/// The ATT&CK enterprise shape — techniques with external references, groups, and `uses` edges.
#[test]
fn an_enterprise_attack_bundle_ingests() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, ATTACK.as_bytes());

    assert!(report.reconciles(), "{report:?}");
    assert_eq!(report.rejected, 0, "every ATT&CK object maps");
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 1);
}

/// ATT&CK exports individual objects unwrapped. Refusing them would mean the corpus has to be
/// pre-wrapped before Brolga can read it.
#[test]
fn a_bare_stix_object_outside_a_bundle_ingests() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, BARE.as_bytes());
    assert_eq!(report.inserted, 1);
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 1);
}

/// Two feeds publishing one actor under different STIX identifiers describe one actor. Keying on
/// the STIX id would make them two, and every count downstream would be wrong.
#[test]
fn the_same_actor_from_two_bundles_with_different_stix_ids_is_one_entity() {
    let first = BUNDLE.replace("000000000001", "aaaaaaaaaaaa");
    let mut store = store();

    ingest(&mut store, IngestMode::Permissive, BUNDLE.as_bytes());
    ingest(&mut store, IngestMode::Permissive, first.as_bytes());

    let entities = store.count(RecordKind::Entity).unwrap();
    assert_eq!(entities, 6, "the second bundle described the same things");
}

/// Detection must be decisive on STIX and must say why.
#[test]
fn a_stix_bundle_is_detected_by_shape_as_well_as_by_media_type() {
    let by_content = pipeline(IngestMode::Permissive)
        .prepare(
            &Document {
                bytes: BUNDLE.as_bytes(),
                media_type: MediaType::new("application/json").unwrap(),
                file_name: None,
                origin: SourceOrigin::NetworkFeed {
                    publisher: ShortText::new("stix-fixture").unwrap(),
                    location: None,
                },
                retrieved_at: Timestamp::unix_epoch(),
            },
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(by_content.parser.as_str(), "brolga.stix.bundle");
    assert!(
        by_content.selection.contains("bundle"),
        "{}",
        by_content.selection
    );
}

// ---------------------------------------------------------------------------------------------
// "Unsupported objects are quarantined or retained with explicit diagnostics"
// ---------------------------------------------------------------------------------------------

/// The criterion. An unmapped STIX type must be *kept with a reason*, not dropped and not coerced
/// into the nearest canonical type — coercion invents a claim the source never made.
#[test]
fn an_unsupported_object_type_is_quarantined_with_an_explicit_reason() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, BUNDLE.as_bytes());

    let quarantined = store
        .quarantined_for_source(&ContentHash::of(BUNDLE.as_bytes()))
        .unwrap();
    assert_eq!(quarantined.len(), 2, "`grouping` and `course-of-action`");

    let record = quarantined
        .iter()
        .find(|record| record.reason.contains("grouping"))
        .expect("the `grouping` quarantine");
    assert_eq!(record.reason_kind, "unsupported_object_type");
    assert!(
        record.reason.contains("quarantined rather than coerced"),
        "the diagnostic says why it was not mapped: {}",
        record.reason
    );
    assert!(
        record.fragment.as_deref().unwrap().contains("grouping--"),
        "the fragment identifies which object"
    );
}

/// Strict mode must refuse a bundle containing anything it cannot map, rather than importing the
/// mappable part of a feed that has started publishing types Brolga does not understand.
#[test]
fn strict_mode_refuses_a_bundle_containing_an_unsupported_object() {
    let mut store = store();
    let error = pipeline(IngestMode::Strict)
        .ingest_batch(
            &mut store,
            &[document(BUNDLE.as_bytes())],
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    assert!(error.to_string().contains("strict mode"), "{error}");
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 0);
}

/// The quarantined object must be diagnosable, which means fetching the bundle it came from.
#[test]
fn the_bundle_a_quarantined_object_came_from_is_retrievable() {
    let mut store = store();
    ingest(&mut store, IngestMode::Permissive, BUNDLE.as_bytes());

    let retrieved = store
        .get_source_blob(&ContentHash::of(BUNDLE.as_bytes()))
        .unwrap()
        .expect("the bundle is retained");
    assert_eq!(retrieved.bytes, BUNDLE.as_bytes());
}

// ---------------------------------------------------------------------------------------------
// "Marking definitions propagate"
// ---------------------------------------------------------------------------------------------

/// The criterion. A marking that does not reach the records it governs is a marking that does not
/// exist as far as any later policy check is concerned.
#[test]
fn a_tlp_marking_propagates_to_every_object_that_references_it() {
    let report = prepare(BUNDLE.as_bytes());

    let marked = count_amber(&report);

    assert_eq!(
        marked, 2,
        "the intrusion set and the relationship both reference the AMBER marking"
    );
}

/// An object with no marking reference must not inherit one. Over-marking is as wrong as
/// under-marking — it makes shareable intelligence look restricted.
#[test]
fn an_object_referencing_no_marking_carries_none() {
    let report = prepare(BUNDLE.as_bytes());
    let malware = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::MalwareFamily => {
                Some(entity)
            }
            _ => None,
        })
        .expect("the malware entity");

    assert!(malware.markings.is_empty(), "no marking was referenced");
}

/// A marking definition appearing *after* the objects that reference it must still propagate, or
/// propagation depends on bundle order.
#[test]
fn a_marking_defined_after_the_objects_that_use_it_still_propagates() {
    let value: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
    let mut objects = value["objects"].as_array().unwrap().clone();
    let marking = objects.remove(0);
    objects.push(marking);
    let reordered =
        serde_json::json!({ "type": "bundle", "id": "bundle--reordered", "objects": objects });
    let bytes = serde_json::to_vec(&reordered).unwrap();

    let report = prepare(&bytes);
    let marked = count_amber(&report);

    assert_eq!(marked, 2, "order must not change what is marked");
}

// ---------------------------------------------------------------------------------------------
// "Relationships and external IDs remain typed"
// ---------------------------------------------------------------------------------------------

/// The criterion. `uses` must arrive as a typed kind, not as a string somebody parses later.
#[test]
fn a_known_relationship_type_maps_to_a_typed_kind() {
    use brolga_model::RelationshipKind;

    let report = prepare(BUNDLE.as_bytes());
    let uses = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::Uses => Some(rel),
            _ => None,
        })
        .expect("the `uses` relationship");
    assert!(
        uses.description.is_none(),
        "an exact mapping needs no caveat"
    );
}

/// An unmapped relationship type must become the *weakest* kind and say so. Guessing a stronger one
/// invents a claim the source did not make.
#[test]
fn an_unmapped_relationship_type_becomes_related_to_and_records_that_it_was_not_exact() {
    use brolga_model::RelationshipKind;

    let report = prepare(BUNDLE.as_bytes());
    let vague = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::RelatedTo => Some(rel),
            _ => None,
        })
        .expect("the `beguiles` relationship");

    let note = vague.description.as_ref().expect("a caveat is recorded");
    assert!(note.as_str().contains("beguiles"), "{}", note.as_str());
    assert!(
        note.as_str().contains("no typed equivalent"),
        "{}",
        note.as_str()
    );
}

/// ATT&CK identifiers are how analysts refer to techniques. A technique that cannot be found by
/// `T1059.001` is not usable, and the sub-technique suffix must survive.
#[test]
fn attack_external_ids_are_extracted_and_canonicalised() {
    let value: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
    let technique = value["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["type"] == "attack-pattern")
        .unwrap();

    assert_eq!(attack_id_of(technique).as_deref(), Some("T1059.001"));
}

/// A non-MITRE external reference must not be mistaken for an ATT&CK identifier.
#[test]
fn a_capec_reference_is_not_read_as_an_attack_id() {
    let value: serde_json::Value = serde_json::from_str(ATTACK).unwrap();
    let technique = &value["objects"][0];
    assert_eq!(
        attack_id_of(technique).as_deref(),
        Some("T1053.005"),
        "the mitre-attack reference wins over the capec one"
    );
}

/// SCO values go through the shared canonicalisers, so a trailing dot and shouted case do not
/// produce a second domain.
#[test]
fn sco_values_are_canonicalised_through_the_shared_canonicalisers() {
    let report = prepare(BUNDLE.as_bytes());
    let claims: Vec<_> = report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Claim(claim) => Some(claim),
            _ => None,
        })
        .collect();

    let rendered = format!("{claims:?}");
    assert!(
        rendered.contains("example.com"),
        "canonicalised: {rendered}"
    );
    assert!(!rendered.contains("EXAMPLE.COM."), "not the raw spelling");
}

// ---------------------------------------------------------------------------------------------
// "Revoked and modified objects"
// ---------------------------------------------------------------------------------------------

/// A revoked object is not an absent one. Deleting it would lose both that it was published and
/// that it was withdrawn, which together say more than either.
#[test]
fn a_revoked_object_is_kept_and_marked_revoked_rather_than_dropped() {
    let report = prepare(BUNDLE.as_bytes());
    let campaign = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::Campaign => Some(entity),
            _ => None,
        })
        .expect("the revoked campaign");

    assert_eq!(campaign.status, LifecycleStatus::Revoked);
    assert_eq!(campaign.name.as_str(), "Operation Withdrawn");
}

/// Objects that are not revoked must not be marked as such.
#[test]
fn an_unrevoked_object_stays_active() {
    let report = prepare(BUNDLE.as_bytes());
    let malware = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::MalwareFamily => {
                Some(entity)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(malware.status, LifecycleStatus::Active);
}

// ---------------------------------------------------------------------------------------------
// "Malformed and deeply nested fixture tests pass"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the bound this issue's security note requires. Depth is checked before any
/// mapping allocates.
#[test]
fn a_deeply_nested_document_is_refused_rather_than_walked() {
    let mut nested = String::from("{\"type\":\"bundle\",\"objects\":[");
    let depth = 400;
    for _ in 0..depth {
        nested.push_str("{\"a\":");
    }
    nested.push('1');
    for _ in 0..depth {
        nested.push('}');
    }
    nested.push_str("]}");

    let error = pipeline(IngestMode::Permissive)
        .prepare(
            &document(nested.as_bytes()),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();

    let rendered = error.to_string();
    assert!(
        rendered.contains("nests") || rendered.contains("recursion"),
        "a deeply nested bundle must be refused: {rendered}"
    );
}

/// Two independent limits, and it matters which one fires.
///
/// `serde_json`'s parser has its own recursion limit and refuses pathological input before a
/// `Value` exists at all — that protects *its* stack. `depth_of` then enforces Brolga's configured
/// limit, which is lower and is the one an operator can change. This asserts the second exists and
/// is not merely inherited from the first.
///
/// The depth here is deliberately modest: `serde_json::Value` has a **recursive `Drop`**, so
/// building a 20,000-deep value in a test overflows the stack on teardown rather than in anything
/// under test. That is a fact about the test harness, not about `depth_of`, and writing the test
/// that way would have been asserting the wrong thing.
#[test]
fn brolgas_depth_limit_is_its_own_rather_than_inherited_from_serde_json() {
    let mut value = serde_json::Value::Null;
    for _ in 0..300 {
        value = serde_json::Value::Array(vec![value]);
    }
    assert_eq!(depth_of(&value), 301);

    // Above serde_json's own default recursion limit, so its parser refuses first — proving the
    // two limits are layered rather than one standing in for the other.
    let deep = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
    assert!(
        serde_json::from_str::<serde_json::Value>(&deep).is_err(),
        "serde_json refuses input deeper than its own recursion limit"
    );
}

/// Truncated JSON is a real thing feeds serve. It must fail as a parse error, not a panic.
#[test]
fn truncated_json_fails_with_a_diagnostic() {
    let truncated = &BUNDLE.as_bytes()[..BUNDLE.len().div_euclid(2)];
    let error = pipeline(IngestMode::Permissive)
        .prepare(&document(truncated), &CancellationToken::never_cancelled())
        .unwrap_err();
    assert!(error.to_string().contains("not valid JSON"), "{error}");
}

/// A document that is valid JSON but not STIX must say so specifically, rather than failing with a
/// JSON error that sends the operator looking for a syntax problem.
#[test]
fn valid_json_that_is_not_stix_says_so_specifically() {
    let error = pipeline(IngestMode::Permissive)
        .prepare(
            &document(b"{\"hello\":\"world\"}"),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    let rendered = error.to_string();
    assert!(
        rendered.contains("not a STIX bundle") || rendered.contains("no registered parser"),
        "{rendered}"
    );
}

/// The security note requires relationship fan-out to be bounded. A bundle where one object relates
/// to everything is quadratic to traverse, whether or not it was meant as an attack.
#[test]
fn relationship_fan_out_from_one_object_is_bounded() {
    let mut objects = vec![serde_json::json!({
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": "intrusion-set--hub",
        "name": "Hub"
    })];
    // Every target exists, so this test isolates fan-out rather than also tripping the
    // unresolved-endpoint check.
    for index in 0..(MAX_FAN_OUT + 10) {
        objects.push(serde_json::json!({
            "type": "malware",
            "spec_version": "2.1",
            "id": format!("malware--{index}"),
            "name": format!("Spoke {index}"),
            "is_family": true
        }));
        objects.push(serde_json::json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": format!("relationship--{index}"),
            "relationship_type": "uses",
            "source_ref": "intrusion-set--hub",
            "target_ref": format!("malware--{index}")
        }));
    }
    let bundle =
        serde_json::json!({ "type": "bundle", "id": "bundle--fanout", "objects": objects });
    let bytes = serde_json::to_vec(&bundle).unwrap();

    let report = prepare(&bytes);
    assert_eq!(
        report.rejected.len(),
        10,
        "the excess is rejected, not the lot"
    );
    assert!(
        report.rejected[0].reason.contains("quadratic"),
        "{}",
        report.rejected[0].reason
    );
}

/// An object count over the record limit is refused before mapping.
#[test]
fn a_bundle_over_the_record_limit_is_refused() {
    use brolga_security::{InputLimits, ResourceLimits};

    let mut limits = ResourceLimits::defaults();
    limits.input.max_records = InputLimits::MAX_RECORDS.min;

    let mut registry = ParserRegistry::new();
    registry.register(StixParser::boxed());
    let pipeline = Pipeline::new(registry, limits).in_mode(IngestMode::Permissive);

    let error = pipeline
        .prepare(
            &document(BUNDLE.as_bytes()),
            &CancellationToken::never_cancelled(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("over the"), "{error}");
}

/// An object with no `type` cannot be mapped and must be quarantined rather than skipped.
#[test]
fn an_object_without_a_type_is_quarantined_rather_than_skipped() {
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--typeless",
        "objects": [{ "id": "something--0001", "name": "no type here" }]
    });
    let bytes = serde_json::to_vec(&bundle).unwrap();

    let report = prepare(&bytes);
    assert_eq!(report.records.len(), 0);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].reason_kind, "missing_type");
}

/// Every canonical record from a bundle must cite the bundle it came from — the round-trip evidence
/// reference this issue's scope requires.
#[test]
fn every_record_cites_the_bundle_it_came_from() {
    use brolga_model::RecordOrigin;

    let report = prepare(BUNDLE.as_bytes());
    assert!(!report.records.is_empty());

    for record in &report.records {
        let origin = match record {
            ParsedRecord::Entity(entity) => &entity.origin,
            ParsedRecord::Relationship(rel) => &rel.origin,
            ParsedRecord::Claim(claim) => &claim.origin,
            ParsedRecord::Sighting(sighting) => &sighting.origin,
            _ => panic!("unhandled record kind"),
        };
        let RecordOrigin::SourceDerived { provenance } = origin else {
            panic!("a record parsed from a bundle must be source-derived");
        };
        assert_eq!(
            provenance.source_objects,
            vec![report.source_object],
            "every record cites the bundle it was parsed from"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// "STIX indicators contribute observables" — https://github.com/jusso-dev/Brolga/issues/95
// ---------------------------------------------------------------------------------------------

/// Every claim in a report, for the assertions below.
fn claims(report: &brolga_ingest::DocumentReport) -> Vec<&brolga_model::Claim> {
    report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Claim(claim) => Some(claim.as_ref()),
            _ => None,
        })
        .collect()
}

/// Every claim whose subject is a given observable.
fn claims_about<'a>(
    report: &'a brolga_ingest::DocumentReport,
    observable: &brolga_model::Observable,
) -> Vec<&'a brolga_model::Claim> {
    let subject = brolga_model::NodeRef::Observable(observable.id());
    claims(report)
        .into_iter()
        .filter(|claim| claim.subject == subject)
        .collect()
}

fn ipv4(value: &str) -> brolga_model::Observable {
    brolga_model::Observable::Ipv4Address(value.parse().unwrap())
}

/// **The criterion this issue turns on.** An `indicator` is where STIX carries observables, so a
/// bundle of them that produced nothing left every context lookup answering "unknown" about
/// addresses Brolga held an indicator for — a miss indistinguishable from a genuine one.
#[test]
fn an_ipv4_indicator_produces_a_claim_about_the_address_its_pattern_names() {
    let report = prepare(INDICATORS.as_bytes());
    let about = claims_about(&report, &ipv4("203.0.113.42"));

    assert!(
        !about.is_empty(),
        "the indicator contributed no observable: {:?}",
        report.rejected
    );
    assert!(
        about.iter().any(|claim| matches!(
            &claim.assertion,
            brolga_model::Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator.pattern"
                    && value.as_str().contains("203.0.113.42")
        )),
        "the pattern is retained as published"
    );
}

/// The second criterion, and the one that decides whether a mixed deployment double-counts. The
/// MISP and STIX paths must derive **one** identifier for one address, or the same address sits in
/// the graph twice and a lookup finds half of what is held.
#[test]
fn a_stix_indicator_and_a_misp_attribute_for_one_address_derive_one_observable() {
    use brolga_ingest::formats::misp::MispParser;

    const EVENT: &str = r#"{"Event":{"uuid":"33333333-3333-4333-8333-333333333333",
        "info":"C2 infrastructure","Attribute":[
        {"uuid":"44444444-4444-4444-8444-444444444444","type":"ip-dst",
         "value":"203.0.113.42","to_ids":true}]}}"#;

    let stix = prepare(INDICATORS.as_bytes());

    let mut registry = ParserRegistry::new();
    registry.register(MispParser::boxed());
    let misp = Pipeline::with_defaults(registry)
        .in_mode(IngestMode::Permissive)
        .prepare(
            &Document {
                bytes: EVENT.as_bytes(),
                media_type: MediaType::new("application/vnd.misp+json").unwrap(),
                file_name: None,
                origin: SourceOrigin::NetworkFeed {
                    publisher: ShortText::new("misp-fixture").unwrap(),
                    location: None,
                },
                retrieved_at: Timestamp::unix_epoch(),
            },
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let address = ipv4("203.0.113.42");
    let from_stix = claims_about(&stix, &address);
    let from_misp = claims_about(&misp, &address);

    assert!(!from_stix.is_empty(), "the STIX indicator mapped nothing");
    assert!(!from_misp.is_empty(), "the MISP attribute mapped nothing");
    assert_eq!(
        from_stix[0].subject, from_misp[0].subject,
        "the two ingestion paths must address one observable"
    );
}

/// `indicator_types` is the only field of an indicator that states an assessment, so it is the only
/// one that may produce a disposition. Presence in a feed is not evidence of maliciousness.
#[test]
fn indicator_types_are_reflected_in_the_claims_disposition() {
    use brolga_model::{Assertion, Disposition};

    let report = prepare(INDICATORS.as_bytes());
    let dispositions: Vec<Disposition> = claims(&report)
        .into_iter()
        .filter_map(|claim| match claim.assertion {
            Assertion::Disposition(disposition) => Some(disposition),
            _ => None,
        })
        .collect();

    assert!(
        dispositions.contains(&Disposition::Malicious),
        "malicious-activity"
    );
    assert!(dispositions.contains(&Disposition::Benign), "benign");
    assert!(
        dispositions.contains(&Disposition::Suspicious),
        "compromised"
    );
    // Three from single-observable indicators, and one per alternative of the disjunction.
    assert_eq!(
        dispositions.len(),
        5,
        "`anonymization` and `attribution` describe a subject without assessing it, so neither \
         asserts a disposition: {dispositions:?}"
    );
}

/// A label that describes rather than assesses is still *recorded*. Not asserting a disposition
/// for it must not mean discarding what the publisher said.
#[test]
fn a_descriptive_indicator_type_is_recorded_even_though_it_asserts_no_disposition() {
    use brolga_model::Assertion;

    let report = prepare(INDICATORS.as_bytes());
    assert!(
        claims(&report).into_iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator_type" && value.as_str() == "anonymization"
        )),
        "the label is kept as evidence"
    );
}

/// `valid_from` and `valid_until` are the publisher's statement about when their claim applies, so
/// they land on the validity window rather than the observation window.
#[test]
fn valid_from_and_valid_until_become_the_claims_validity_window() {
    let report = prepare(INDICATORS.as_bytes());
    let claim = claims_about(&report, &ipv4("203.0.113.42"))[0];

    assert_eq!(
        claim
            .temporal
            .valid_from
            .map(Timestamp::to_rfc3339)
            .as_deref(),
        Some("2024-01-01T00:00:00Z")
    );
    assert_eq!(
        claim
            .temporal
            .valid_until
            .map(Timestamp::to_rfc3339)
            .as_deref(),
        Some("2024-12-31T23:59:59Z")
    );
    assert!(
        claim.temporal.first_seen.is_none(),
        "a validity window is not an observation"
    );
}

/// The criterion that keeps the fix honest. A pattern outside the representable subset must be
/// quarantined **naming the construct** — a half-parsed pattern asserts something broader than the
/// publisher did, which is worse than an unparsed one.
#[test]
fn an_unrepresentable_pattern_is_quarantined_naming_what_was_not_understood() {
    let report = prepare(INDICATORS.as_bytes());

    let reasons: Vec<&str> = report
        .rejected
        .iter()
        .map(|record| record.reason.as_str())
        .collect();

    for named in ["AND", "FOLLOWEDBY", "windows-registry-key", "snort"] {
        assert!(
            reasons.iter().any(|reason| reason.contains(named)),
            "no quarantine reason named `{named}`: {reasons:?}"
        );
    }
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "unrepresentable_pattern"),
        "{reasons:?}"
    );
}

/// The conjunction case, stated as a fact about the store rather than about a reason string: the
/// address inside a pattern Brolga refused must not appear as a claim, because the publisher
/// asserted the address *together with* a port and the address alone is a wider claim.
#[test]
fn a_multi_comparison_pattern_contributes_nothing_rather_than_its_first_half() {
    let report = prepare(INDICATORS.as_bytes());
    assert!(
        claims_about(&report, &ipv4("198.51.100.7")).is_empty(),
        "the conjunction was partially extracted"
    );
    assert!(
        claims_about(&report, &ipv4("198.51.100.8")).is_empty(),
        "the first of two observation expressions was extracted alone"
    );
}

/// An `indicates` edge names the indicator, not the observable. It must land on the observable the
/// pattern is about, or the edge points at a record that was never written.
#[test]
fn an_indicates_edge_from_an_indicator_resolves_to_the_observable_its_pattern_names() {
    use brolga_model::{NodeRef, RelationshipKind};

    let report = prepare(INDICATORS.as_bytes());
    let edge = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::Indicates => Some(rel),
            _ => None,
        })
        .expect("the `indicates` relationship");

    assert_eq!(
        edge.source,
        NodeRef::Observable(ipv4("203.0.113.42").id()),
        "the edge starts at the observable, not at a node the indicator invented"
    );
}

/// An edge whose indicator was quarantined must be rejected rather than dangling. A relationship to
/// a record that does not exist is invisible in traversal, which is worse than a missing edge.
#[test]
fn an_edge_from_a_quarantined_indicator_is_rejected_rather_than_left_dangling() {
    let report = prepare(INDICATORS.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "unresolved_source_ref"),
        "{:?}",
        report.rejected
    );
}

/// Markings, revocation, and canonicalisation reach indicator claims the same way they reach every
/// other record — the mapping is new, the guarantees around it are not.
#[test]
fn indicator_claims_carry_markings_revocation_and_canonical_values() {
    use brolga_model::Observable;

    let report = prepare(INDICATORS.as_bytes());

    assert_eq!(
        count_amber(&report),
        4,
        "the AMBER-marked indicator's four claims"
    );

    let url = Observable::Url(
        brolga_model::observable::CanonicalUrl::new("https://example.com/payload").unwrap(),
    );
    let revoked = claims_about(&report, &url);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].status, LifecycleStatus::Revoked);

    let domain =
        Observable::DomainName(brolga_model::observable::DomainName::new("example.com").unwrap());
    assert!(
        !claims_about(&report, &domain).is_empty(),
        "`EXAMPLE.COM.` canonicalises the same way an SCO's value does"
    );
}

/// The whole fixture, ingested. Counts rather than "more than zero", so a mapping that quietly
/// stopped producing something would fail here.
#[test]
fn an_indicator_bundle_ingests_into_claims_a_lookup_can_reach() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, INDICATORS.as_bytes());

    assert!(report.reconciles(), "{report:?}");
    // 25 claims. Six single-observable indicators contribute 15 between them — a pattern claim
    // each, one `name`, four `indicator_types` labels, three dispositions — and the disjunction
    // contributes 5 per alternative across its two: pattern, alternative count, description, type,
    // disposition.
    assert_eq!(store.count(RecordKind::Claim).unwrap(), 25);
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 1);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 1);
    // Five unrepresentable indicators, plus the edge that pointed at one of them.
    assert_eq!(report.rejected, 6, "{report:?}");
}

/// A disjunctive indicator is how feeds spell a published address list. Every alternative becomes
/// its own observable, or most of a STIX feed goes unread.
#[test]
fn a_disjunctive_indicator_contributes_every_alternative() {
    let report = prepare(INDICATORS.as_bytes());

    for value in ["198.51.100.20", "198.51.100.21"] {
        assert!(
            !claims_about(&report, &ipv4(value)).is_empty(),
            "`{value}` was not represented"
        );
    }
}

/// The trade the fan-out makes, kept visible rather than paid silently. The publisher said one of
/// these matched; Brolga records a claim about each. Both the whole pattern and the alternative
/// count ride on every claim, so a consumer can tell a lone assertion from one of fifty without
/// re-parsing anything.
#[test]
fn a_fanned_out_claim_carries_the_hedge_it_came_from() {
    use brolga_model::Assertion;

    let report = prepare(INDICATORS.as_bytes());
    let about = claims_about(&report, &ipv4("198.51.100.20"));

    assert!(
        about.iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator.alternatives" && value.as_str() == "2"
        )),
        "the alternative count is missing: {about:?}"
    );
    assert!(
        about.iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator.pattern" && value.as_str().contains(" OR ")
        )),
        "the disjunction is not readable from the claim"
    );
}

/// An ordinary indicator must not carry the count. Writing `1` on the overwhelming majority of
/// claims would make the field noise instead of a signal about the rare case.
#[test]
fn a_single_observable_indicator_carries_no_alternative_count() {
    use brolga_model::Assertion;

    let report = prepare(INDICATORS.as_bytes());
    assert!(
        !claims_about(&report, &ipv4("203.0.113.42"))
            .iter()
            .any(|claim| matches!(
                &claim.assertion,
                Assertion::Attribute { name, .. } if name.as_str() == "stix.indicator.alternatives"
            )),
    );
}

/// A publisher's own words about an indicator are evidence an analyst reads. Dropping them keeps
/// the observable and loses the reason it was published.
#[test]
fn an_indicators_name_and_description_are_kept_as_evidence() {
    use brolga_model::Assertion;

    let report = prepare(INDICATORS.as_bytes());

    let named = claims_about(&report, &ipv4("203.0.113.42"));
    assert!(
        named.iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator.name" && value.as_str() == "C2 address"
        )),
        "{named:?}"
    );

    let described = claims_about(&report, &ipv4("198.51.100.20"));
    assert!(
        described.iter().any(|claim| matches!(
            &claim.assertion,
            Assertion::Attribute { name, value }
                if name.as_str() == "stix.indicator.description"
                    && value.as_str().contains("one loader")
        )),
        "{described:?}"
    );
}

/// `pattern_version` is the version of the *patterning language*. A future major version may give
/// the same characters a different meaning, so reading it under the 2.x grammar would answer
/// confidently about a syntax Brolga does not know.
#[test]
fn a_pattern_declaring_a_future_language_version_is_quarantined() {
    let report = prepare(INDICATORS.as_bytes());
    let rejection = report
        .rejected
        .iter()
        .find(|record| record.reason_kind == "unsupported_pattern_version")
        .expect("the 3.0 pattern is quarantined");

    assert!(rejection.reason.contains("3.0"), "{}", rejection.reason);
    assert!(
        claims_about(&report, &ipv4("198.51.100.30")).is_empty(),
        "it was read under the 2.x grammar anyway"
    );
}

/// A publisher who wrote `valid_until` before `valid_from` did not mean "no window". Dropping the
/// pair silently would store the indicator as though it applied forever.
#[test]
fn an_impossible_validity_window_quarantines_the_indicator_rather_than_dropping_the_field() {
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--backwards",
        "objects": [{
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--backwards",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '203.0.113.42']",
            "valid_from": "2024-12-31T00:00:00Z",
            "valid_until": "2024-01-01T00:00:00Z"
        }]
    });
    let report = prepare(&serde_json::to_vec(&bundle).unwrap());

    assert_eq!(report.records.len(), 0);
    assert_eq!(report.rejected[0].reason_kind, "impossible_validity_window");
}

/// One object no longer means one record, so the amplification an indicator can cause is bounded.
/// Truncating the list instead would drop assessments the publisher made, without saying so.
#[test]
fn an_indicator_stating_more_types_than_the_limit_is_refused_rather_than_truncated() {
    use brolga_ingest::formats::stix::MAX_INDICATOR_TYPES;

    let types: Vec<String> = (0..=MAX_INDICATOR_TYPES)
        .map(|index| format!("malicious-activity-{index}"))
        .collect();
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--verbose",
        "objects": [{
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--verbose",
            "pattern_type": "stix",
            "pattern": "[ipv4-addr:value = '203.0.113.42']",
            "indicator_types": types
        }]
    });
    let report = prepare(&serde_json::to_vec(&bundle).unwrap());

    assert_eq!(report.records.len(), 0);
    assert_eq!(report.rejected[0].reason_kind, "indicator_types_exceeded");
    assert!(
        report.rejected[0].reason.contains("rather than truncated"),
        "{}",
        report.rejected[0].reason
    );
}

// ---------------------------------------------------------------------------------------------
// "STIX 2.0 differences" — https://github.com/jusso-dev/Brolga/issues/52
// ---------------------------------------------------------------------------------------------

/// 2.0 kept the indicator vocabulary in `labels`; 2.1 split it into `indicator_types`. A reader
/// that only knew the 2.1 spelling would map every 2.0 indicator present *and* undispositioned —
/// which reads to a consumer exactly like a publisher who declined to assess it.
#[test]
fn a_stix_2_0_indicator_takes_its_disposition_from_labels() {
    use brolga_model::{Assertion, Disposition};

    let report = prepare(BUNDLE_20.as_bytes());
    let about = claims_about(&report, &ipv4("203.0.113.42"));

    assert!(
        about
            .iter()
            .any(|claim| claim.assertion == Assertion::Disposition(Disposition::Malicious)),
        "`labels` did not reach the disposition: {about:?}"
    );
}

/// 2.0 has no top-level SCOs at all — an observable exists only inside `observed-data`. Skipping
/// that object would make a 2.0 bundle of observations contribute nothing a lookup could find,
/// which is #95 in a different spelling.
#[test]
fn stix_2_0_observed_data_contributes_the_observables_it_embeds() {
    let report = prepare(BUNDLE_20.as_bytes());

    assert!(
        !claims_about(&report, &ipv4("198.51.100.5")).is_empty(),
        "the embedded address was not represented: {:?}",
        report.rejected
    );

    let domain = brolga_model::Observable::DomainName(
        brolga_model::observable::DomainName::new("staging.example.net").unwrap(),
    );
    assert!(
        !claims_about(&report, &domain).is_empty(),
        "`STAGING.EXAMPLE.NET.` canonicalises the same way any other domain does"
    );
}

/// An observation is not a claim. `number_observed` and the window are what corroboration is
/// computed from, and a parser that recorded only claims would throw them away.
#[test]
fn observed_data_becomes_a_sighting_with_its_count_and_window() {
    let report = prepare(BUNDLE_20.as_bytes());
    let sighting = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Sighting(sighting)
                if sighting.subject
                    == brolga_model::NodeRef::Observable(ipv4("198.51.100.5").id()) =>
            {
                Some(sighting)
            }
            _ => None,
        })
        .expect("a sighting of the embedded address");

    assert_eq!(sighting.count.get(), 12);
    assert_eq!(sighting.first_seen.to_rfc3339(), "2024-01-01T00:00:00Z");
    assert_eq!(sighting.last_seen.to_rfc3339(), "2024-01-01T06:00:00Z");
    assert!(
        sighting.observer.is_some(),
        "`created_by_ref` names an identity in this bundle, so the sighting is attributed"
    );
}

/// An observer Brolga cannot resolve is `None`, not a fabricated entity. An invented observer
/// would look like corroboration, which is the one thing a sighting exists to measure.
#[test]
fn an_observation_with_no_resolvable_observer_is_unattributed_rather_than_invented() {
    let report = prepare(BUNDLE_20.as_bytes());
    let subject = brolga_model::NodeRef::Observable(ipv4("198.51.100.77").id());

    let sighting = report
        .records
        .iter()
        .find_map(|record| match record {
            ParsedRecord::Sighting(sighting) if sighting.subject == subject => Some(sighting),
            _ => None,
        })
        .expect("a sighting of the unattributed observation");

    assert!(
        sighting.observer.is_none(),
        "no `created_by_ref`, so nothing may stand in for one"
    );
    assert_eq!(sighting.count.get(), 3);
}

/// Zero is not "unknown". A publisher who wrote `number_observed: 0` said something impossible,
/// and defaulting it to one would invent an observation that nobody reported.
#[test]
fn an_observation_counted_zero_times_is_quarantined_rather_than_defaulted() {
    let report = prepare(BUNDLE_20.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "unusable_number_observed"),
        "{:?}",
        report.rejected
    );
    assert!(
        claims_about(&report, &ipv4("198.51.100.9")).is_empty(),
        "the impossible count was mapped anyway"
    );
}

/// An `observed-data` holding only artefacts Brolga has no canonicaliser for would record an
/// observation of nothing. Saying so is more useful than writing an empty observation.
#[test]
fn an_observation_of_nothing_mappable_is_quarantined_with_a_reason() {
    let report = prepare(BUNDLE_20.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|record| record.reason_kind == "no_mappable_observable"),
        "{:?}",
        report.rejected
    );
}

/// The whole 2.0 fixture. Counts, not "more than zero".
#[test]
fn a_stix_2_0_bundle_ingests() {
    let mut store = store();
    let report = ingest(&mut store, IngestMode::Permissive, BUNDLE_20.as_bytes());

    assert!(report.reconciles(), "{report:?}");
    // identity and malware.
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 2);
    // Three mapped observables across the accepted `observed-data`, one sighting each.
    assert_eq!(store.count(RecordKind::Sighting).unwrap(), 3);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 1);
    // Two observations refused: the zero count and the one holding nothing mappable.
    assert_eq!(report.rejected, 2, "{report:?}");
}

/// A 2.0 bundle must be recognised without its objects carrying `spec_version`, which in 2.0 sits
/// on the bundle rather than on each object.
#[test]
fn a_stix_2_0_bundle_is_detected() {
    let report = prepare(BUNDLE_20.as_bytes());
    assert_eq!(report.parser.as_str(), "brolga.stix.bundle");
}
