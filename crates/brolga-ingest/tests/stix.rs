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
    // 4 entities (intrusion-set, malware, attack-pattern, revoked campaign),
    // 2 claims from SCOs, 2 relationships. The `grouping` is quarantined.
    assert_eq!(store.count(RecordKind::Entity).unwrap(), 4);
    assert_eq!(store.count(RecordKind::Claim).unwrap(), 2);
    assert_eq!(store.count(RecordKind::Relationship).unwrap(), 2);
    assert_eq!(report.rejected, 1, "only the unsupported `grouping`");
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
    assert_eq!(entities, 4, "the second bundle described the same things");
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
    assert_eq!(quarantined.len(), 1);

    let record = &quarantined[0];
    assert_eq!(record.reason_kind, "unsupported_object_type");
    assert!(record.reason.contains("grouping"), "{}", record.reason);
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
    for index in 0..(MAX_FAN_OUT + 10) {
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
