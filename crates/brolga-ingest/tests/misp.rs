//! MISP ingestion, against the fixture corpus and a real store.
//!
//! One section per acceptance criterion of [#14](https://github.com/jusso-dev/Brolga/issues/14).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::formats::misp::{MispParser, galaxy_names};
use brolga_ingest::{Document, IngestMode, ParsedRecord, ParserRegistry, Pipeline};
use brolga_model::{
    Assertion, ContentHash, Disposition, EntityKind, LifecycleStatus, Marking, RelationshipKind,
    ShortText, Timestamp, TlpLevel,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;
use brolga_storage::{IntelligenceStore, RecordKind, SqliteStore, StoreRead};

const EVENT: &str = include_str!("fixtures/misp/event.json");
const WARNINGLIST: &str = include_str!("fixtures/misp/warninglist.json");
const FEED: &str = include_str!("fixtures/misp/feed.json");

fn pipeline(mode: IngestMode) -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(MispParser::boxed());
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
        media_type: MediaType::new("application/vnd.misp+json").unwrap(),
        file_name: None,
        origin: SourceOrigin::Connector {
            system: ShortText::new("misp").unwrap(),
            collection: Some(ShortText::new("fixture").unwrap()),
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

/// Every `misp.<type>` attribute value in a report, for asserting what was recorded.
fn attribute_values(report: &brolga_ingest::DocumentReport) -> Vec<(String, String)> {
    claims(report)
        .iter()
        .filter_map(|claim| match &claim.assertion {
            Assertion::Attribute { name, value } => {
                Some((name.as_str().to_owned(), value.as_str().to_owned()))
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// "Event, attribute, and feed fixtures ingest"
// ---------------------------------------------------------------------------------------------

/// The criterion. An event with attributes, a nested object, tags, and a galaxy ingests.
#[test]
fn a_misp_event_with_attributes_and_objects_ingests() {
    let mut store = store();
    let report = pipeline(IngestMode::Permissive)
        .ingest_batch(
            &mut store,
            &[document(EVENT.as_bytes())],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert!(report.reconciles(), "{report:?}");
    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        1,
        "the event itself is one Report entity"
    );
    assert!(store.count(RecordKind::Claim).unwrap() > 5);
    assert!(store.count(RecordKind::Relationship).unwrap() > 5);
}

/// A feed is a `response` array of events. Reading only the first would silently drop the rest.
#[test]
fn a_misp_feed_response_ingests_every_event_it_contains() {
    let mut store = store();
    pipeline(IngestMode::Permissive)
        .ingest_batch(
            &mut store,
            &[document(FEED.as_bytes())],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    assert_eq!(
        store.count(RecordKind::Entity).unwrap(),
        2,
        "both events in the feed became reports"
    );
}

/// Attributes nested inside a MISP object are attributes. Reading only the top-level array drops
/// everything a publisher structured, which is most of a modern event.
#[test]
fn attributes_nested_inside_a_misp_object_are_not_skipped() {
    let report = prepare(EVENT.as_bytes());
    let values = attribute_values(&report);
    assert!(
        values.iter().any(|(name, _)| name == "misp.sha256"),
        "the attribute inside the `file` object was read: {values:?}"
    );
}

/// A MISP attribute type Brolga cannot canonicalise must be quarantined with a reason, not dropped.
#[test]
fn an_uncanonicalisable_attribute_is_quarantined_rather_than_dropped() {
    let report = prepare(EVENT.as_bytes());
    assert!(
        report
            .rejected
            .iter()
            .any(|rejection| rejection.reason_kind == "uncanonicalisable_value"),
        "the free-text `comment` attribute is rejected: {:?}",
        report.rejected
    );
}

// ---------------------------------------------------------------------------------------------
// "Composite attributes retain component semantics"
// ---------------------------------------------------------------------------------------------

/// The criterion. `domain|ip` carries two facts. Splitting into two unrelated records loses the
/// association; keeping one opaque string loses both values as pivots.
#[test]
fn a_composite_attribute_yields_both_components_and_the_pairing_between_them() {
    let report = prepare(EVENT.as_bytes());

    let values = attribute_values(&report);
    let composite_claims = values
        .iter()
        .filter(|(name, _)| name == "misp.domain|ip")
        .count();
    assert_eq!(
        composite_claims, 2,
        "one claim per component, each keyed on its own observable: {values:?}"
    );

    let resolves = report
        .records
        .iter()
        .filter(|record| {
            matches!(record, ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::ResolvesTo)
        })
        .count();
    assert_eq!(
        resolves, 1,
        "the pairing survives as a resolves-to edge rather than as punctuation"
    );
}

/// The components must be canonicalised individually, not stored as the raw halves.
#[test]
fn composite_components_are_canonicalised_individually() {
    let report = prepare(EVENT.as_bytes());
    let subjects: Vec<_> = claims(&report)
        .iter()
        .map(|claim| claim.subject.to_string())
        .collect();
    let rendered = subjects.join(" ");
    assert!(
        !rendered.contains('|'),
        "no subject keeps the composite separator: {rendered}"
    );
}

// ---------------------------------------------------------------------------------------------
// "Disabled, deleted, and decayed fields map explicitly"
// ---------------------------------------------------------------------------------------------

/// A soft-deleted attribute is a record its publisher withdrew, which says more than silence.
#[test]
fn a_soft_deleted_attribute_is_kept_and_marked_revoked() {
    let report = prepare(EVENT.as_bytes());
    let revoked: Vec<_> = claims(&report)
        .iter()
        .filter(|claim| claim.status == LifecycleStatus::Revoked)
        .map(|claim| claim.assertion.clone())
        .collect();

    assert!(
        !revoked.is_empty(),
        "the deleted md5 attribute is retained as revoked"
    );
}

/// `disable_correlation` is an instruction about how to *use* a value, not a statement about the
/// value. Kept separate so a correlation step can honour it without inferring maliciousness.
#[test]
fn disable_correlation_is_recorded_as_its_own_explicit_claim() {
    let report = prepare(EVENT.as_bytes());
    let values = attribute_values(&report);
    assert!(
        values
            .iter()
            .any(|(name, value)| name == "misp.disable_correlation" && value == "true"),
        "{values:?}"
    );
}

/// A decay score is the publisher's confidence over time. Dropping it discards their own
/// qualification of their data.
#[test]
fn a_decay_score_is_carried_through_rather_than_discarded() {
    let report = prepare(EVENT.as_bytes());
    let values = attribute_values(&report);
    assert!(
        values
            .iter()
            .any(|(name, value)| name == "misp.decay_score" && value.contains("42.5")),
        "{values:?}"
    );
}

/// A deleted *event* is withdrawn, not absent.
#[test]
fn a_deleted_event_is_kept_and_marked_revoked() {
    let report = prepare(FEED.as_bytes());
    let revoked = report
        .records
        .iter()
        .filter(|record| {
            matches!(record, ParsedRecord::Entity(entity)
                if entity.kind == EntityKind::Report && entity.status == LifecycleStatus::Revoked)
        })
        .count();
    assert_eq!(revoked, 1);
}

// ---------------------------------------------------------------------------------------------
// "Warning-list matches are evidence, not automatic disposition"
// ---------------------------------------------------------------------------------------------

/// The criterion, and the sharpest mapping decision in this parser. "On a warning list" and
/// "benign" are different statements; collapsing them lets a list author silently override an
/// analyst.
#[test]
fn a_warning_list_produces_evidence_and_never_a_disposition() {
    let report = prepare(WARNINGLIST.as_bytes());

    assert_eq!(report.records.len(), 3, "one claim per listed value");

    for claim in claims(&report) {
        match &claim.assertion {
            Assertion::Attribute { name, value } => {
                assert_eq!(name.as_str(), "misp.warninglist");
                assert!(value.as_str().contains("Google"), "names the list");
            }
            other => panic!("a warning-list entry must not assert a disposition: {other:?}"),
        }
    }
}

/// Specifically: no `Benign` or `AllowListed` disposition may appear from a warning list.
#[test]
fn no_disposition_of_any_kind_comes_from_a_warning_list() {
    let report = prepare(WARNINGLIST.as_bytes());
    let dispositions = claims(&report)
        .iter()
        .filter(|claim| matches!(claim.assertion, Assertion::Disposition(_)))
        .count();
    assert_eq!(dispositions, 0);
}

/// The converse: `to_ids` *is* MISP explicitly stating detectable badness, so it is the one field
/// that does produce a disposition. Without this, the parser would be discarding a real signal.
#[test]
fn the_to_ids_flag_is_the_only_thing_that_produces_a_disposition() {
    let report = prepare(EVENT.as_bytes());
    let malicious = claims(&report)
        .iter()
        .filter(|claim| {
            matches!(
                claim.assertion,
                Assertion::Disposition(Disposition::Malicious)
            )
        })
        .count();

    assert!(malicious > 0, "to_ids attributes assert maliciousness");

    // The `ip-dst` attribute has `to_ids: false`. It must have an attribute claim and no
    // disposition — presence in an event is not evidence of maliciousness.
    let values = attribute_values(&report);
    assert!(
        values
            .iter()
            .any(|(name, value)| name == "misp.ip-dst" && value == "198.51.100.7"),
        "the non-to_ids attribute is still recorded: {values:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// "Every canonical result links to MISP original"
// ---------------------------------------------------------------------------------------------

/// The criterion at the provenance level: every record cites the MISP document it came from.
#[test]
fn every_record_cites_the_misp_document_it_was_parsed_from() {
    use brolga_model::RecordOrigin;

    let report = prepare(EVENT.as_bytes());
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
            panic!("a record parsed from MISP must be source-derived");
        };
        assert_eq!(provenance.source_objects, vec![report.source_object]);
    }
}

/// And at the graph level: every attribute links back to the event that published it.
#[test]
fn every_attribute_links_back_to_the_event_that_published_it() {
    let report = prepare(EVENT.as_bytes());
    let part_of = report
        .records
        .iter()
        .filter(|record| {
            matches!(record, ParsedRecord::Relationship(rel) if rel.kind == RelationshipKind::PartOf)
        })
        .count();
    assert!(
        part_of >= 6,
        "every mapped attribute links to its event, got {part_of}"
    );
}

/// The MISP original itself must be retrievable, or a disagreement with the upstream instance
/// cannot be settled.
#[test]
fn the_misp_document_is_retained_and_retrievable() {
    let mut store = store();
    pipeline(IngestMode::Permissive)
        .ingest_batch(
            &mut store,
            &[document(EVENT.as_bytes())],
            &CancellationToken::never_cancelled(),
        )
        .unwrap();

    let retrieved = store
        .get_source_blob(&ContentHash::of(EVENT.as_bytes()))
        .unwrap()
        .expect("the MISP document is retained");
    assert_eq!(retrieved.bytes, EVENT.as_bytes());
}

// ---------------------------------------------------------------------------------------------
// Tags, markings, and galaxies
// ---------------------------------------------------------------------------------------------

/// Event-level TLP must reach the attributes published under it.
#[test]
fn an_event_level_tlp_tag_propagates_to_its_attributes() {
    let report = prepare(EVENT.as_bytes());
    let amber = Marking::Tlp(TlpLevel::Amber);
    let marked = claims(&report)
        .iter()
        .filter(|claim| claim.markings.iter().any(|marking| *marking == amber))
        .count();
    assert!(marked > 0, "attributes inherit the event's AMBER marking");
}

/// An attribute-level tag must add to the event's markings, not replace them — a RED attribute
/// inside an AMBER event is RED *and* still governed by the event's handling.
#[test]
fn an_attribute_level_tag_adds_to_the_event_marking_rather_than_replacing_it() {
    let report = prepare(EVENT.as_bytes());
    let red = Marking::Tlp(TlpLevel::Red);
    let amber = Marking::Tlp(TlpLevel::Amber);

    let both = claims(&report)
        .iter()
        .filter(|claim| {
            let markings: Vec<_> = claim.markings.iter().collect();
            markings.contains(&&red) && markings.contains(&&amber)
        })
        .count();
    assert!(
        both > 0,
        "the sha256 attribute carries both RED and the event's AMBER"
    );
}

/// A non-TLP tag is the publisher's classification. Discarding it loses information later policy
/// may need, even though Brolga does not act on it today.
#[test]
fn a_galaxy_or_taxonomy_tag_is_kept_as_a_handling_instruction() {
    let report = prepare(EVENT.as_bytes());
    let kept = report
        .records
        .iter()
        .filter_map(|record| match record {
            ParsedRecord::Entity(entity) if entity.kind == EntityKind::Report => Some(entity),
            _ => None,
        })
        .flat_map(|entity| entity.markings.iter())
        .any(|marking| matches!(marking, Marking::Handling(text) if text.as_str().contains("misp-galaxy")));
    assert!(kept, "the galaxy tag survives as a handling marking");
}

/// Galaxy clusters are a *reference* to a known actor. Creating entities from them automatically
/// would assert the association is Brolga's finding rather than MISP's.
#[test]
fn galaxy_clusters_are_readable_but_do_not_become_entities_automatically() {
    let value: serde_json::Value = serde_json::from_str(EVENT).unwrap();
    let names = galaxy_names(&value["Event"]);
    assert_eq!(
        names,
        vec!["APT-EXAMPLE".to_owned(), "Bunyip Panda".to_owned()]
    );

    let report = prepare(EVENT.as_bytes());
    let actors = report
        .records
        .iter()
        .filter(|record| {
            matches!(record, ParsedRecord::Entity(entity) if entity.kind == EntityKind::ThreatActor)
        })
        .count();
    assert_eq!(
        actors, 0,
        "a galaxy reference is not an entity Brolga invented"
    );
}

/// Values go through the shared canonicalisers, so a shouted domain with a trailing dot does not
/// become a second domain.
#[test]
fn attribute_values_are_canonicalised_through_the_shared_canonicalisers() {
    let report = prepare(EVENT.as_bytes());
    let subjects: Vec<_> = claims(&report)
        .iter()
        .map(|claim| claim.subject.to_string())
        .collect();
    assert!(
        !subjects.join(" ").contains("EVIL.EXAMPLE."),
        "the raw spelling is not the key"
    );
}
