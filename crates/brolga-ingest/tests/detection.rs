//! Sigma detection-rule ingestion (the only rule format kept in the slim product).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::detect::{DetectionConfidence, FormatHint};
use brolga_ingest::formats::sigma;
use brolga_ingest::{Document, IngestMode, IntelligenceParser, ParserRegistry, Pipeline};
use brolga_model::{
    EntityKind, ShortText, Timestamp,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::CancellationToken;

const SIGMA_RULES: &str = include_str!("fixtures/detection/rules.yml");

fn pipeline() -> Pipeline {
    let mut registry = ParserRegistry::new();
    registry.register(sigma::SigmaParser::boxed());
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

#[test]
fn sigma_rules_become_detection_rule_entities() {
    let report = pipeline()
        .prepare(
            &document(SIGMA_RULES.as_bytes(), "application/x-yaml"),
            &CancellationToken::never_cancelled(),
        )
        .expect("sigma fixture should prepare");
    let has_rule = report.records.iter().any(|r| {
        matches!(
            r,
            brolga_ingest::ParsedRecord::Entity(e) if e.kind == EntityKind::DetectionRule
        )
    });
    assert!(has_rule, "expected at least one detection_rule entity");
}

#[test]
fn sigma_parser_claims_its_fixture() {
    let parser = sigma::SigmaParser::new();
    let hint = FormatHint::new(
        "application/x-yaml",
        Some("rules.yml"),
        SIGMA_RULES.as_bytes(),
        SIGMA_RULES.len() as u64,
    );
    let candidate = parser.detect(&hint);
    assert!(
        candidate.confidence >= DetectionConfidence::Weak,
        "sigma should claim its own fixture: {candidate:?}"
    );
}
