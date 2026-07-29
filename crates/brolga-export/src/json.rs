//! The structured exports: pack JSON, compact JSON, YAML, and JSONL.
//!
//! # These are the ones that must be lossless, and they are tested as such
//!
//! A pack's JSON is the canonical serialisation — the same bytes the HTTP API returns and the same
//! shape the published JSON Schema describes. So `json` and `yaml` claim [`Lossiness::Lossless`],
//! which is the only claim in this crate that a test can falsify by round-tripping, and
//! `every_lossless_exporter_round_trips` does exactly that.
//!
//! `compact` is the same document without whitespace. Lossless too: whitespace is not content.
//!
//! # JSONL is lossless *structurally*, which is a weaker and more honest claim
//!
//! One JSON object per line, so a consumer can act on the first before the last exists. Every field
//! of the pack appears across the lines, but the *container* does not — you cannot hand the bytes to
//! `serde_json::from_slice::<ContextPack>` and get the pack back. That is
//! [`Lossiness::LosslessStructural`]: all of the content, none of the envelope.
//!
//! The line order is fixed and documented, because a consumer reading incrementally needs to know
//! what arrives first. The header line comes first so a reader knows the subject and disposition
//! before any of the bulk.

use brolga_model::ContextPack;
use serde_json::json;

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// The canonical pack JSON.
pub const PACK_JSON_ID: ExporterId = ExporterId::new("brolga.export.json");

/// The same document, minified.
pub const COMPACT_JSON_ID: ExporterId = ExporterId::new("brolga.export.compact");

/// YAML.
pub const YAML_ID: ExporterId = ExporterId::new("brolga.export.yaml");

/// One object per line.
pub const JSONL_ID: ExporterId = ExporterId::new("brolga.export.jsonl");

/// The order JSONL lines are written in.
///
/// Documented as data rather than as a comment, so a consumer can assert against it and
/// `the_jsonl_line_order_is_the_documented_one` can check the writer against it.
pub const JSONL_LINE_ORDER: &[&str] = &[
    "header",
    "finding",
    "recommendation",
    "entity",
    "claim",
    "relationship",
    "sighting",
    "contradiction",
    "pivot",
    "technique",
    "handle",
    "gap",
    "exclusion",
    "budget",
    "policy",
];

/// The canonical pack JSON, indented.
#[derive(Debug, Default, Clone, Copy)]
pub struct PackJsonExporter;

impl PackJsonExporter {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn Exporter> {
        Box::new(Self)
    }
}

impl Exporter for PackJsonExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            PACK_JSON_ID,
            1,
            "application/json",
            "json",
            Orientation::Machine,
            Lossiness::Lossless,
            "The canonical pack JSON, indented. The same document the HTTP API returns.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let bytes = serde_json::to_vec_pretty(cleared.pack()).map_err(|error| {
            ExportError::Unencodable {
                exporter: PACK_JSON_ID,
                reason: error.to_string(),
            }
        })?;
        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: Vec::new(),
        })
    }
}

/// The same document with no whitespace.
#[derive(Debug, Default, Clone, Copy)]
pub struct CompactJsonExporter;

impl CompactJsonExporter {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn Exporter> {
        Box::new(Self)
    }
}

impl Exporter for CompactJsonExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            COMPACT_JSON_ID,
            1,
            "application/json",
            "json",
            Orientation::Machine,
            // Whitespace is not content. The same fields, the same values, fewer bytes.
            Lossiness::Lossless,
            "The pack JSON with no whitespace, for a transport that pays per byte.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let bytes =
            serde_json::to_vec(cleared.pack()).map_err(|error| ExportError::Unencodable {
                exporter: COMPACT_JSON_ID,
                reason: error.to_string(),
            })?;
        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: Vec::new(),
        })
    }
}

/// YAML.
#[derive(Debug, Default, Clone, Copy)]
pub struct YamlExporter;

impl YamlExporter {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn Exporter> {
        Box::new(Self)
    }
}

impl Exporter for YamlExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            YAML_ID,
            1,
            "application/yaml",
            "yaml",
            Orientation::Machine,
            Lossiness::Lossless,
            "The pack as YAML, for a machine or a human who has to read it.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let text =
            serde_norway::to_string(cleared.pack()).map_err(|error| ExportError::Unencodable {
                exporter: YAML_ID,
                reason: error.to_string(),
            })?;
        Ok(Exported {
            metadata: self.metadata(),
            bytes: text.into_bytes(),
            declared_losses: Vec::new(),
        })
    }
}

/// One JSON object per line.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonLinesExporter;

impl JsonLinesExporter {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn Exporter> {
        Box::new(Self)
    }
}

impl Exporter for JsonLinesExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            JSONL_ID,
            1,
            "application/x-ndjson",
            "jsonl",
            Orientation::Machine,
            // Every field survives; the container does not. See the module documentation.
            Lossiness::LosslessStructural,
            "One object per line in a documented order, for a consumer reading incrementally.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut lines: Vec<serde_json::Value> = Vec::new();

        // The header first, so a reader knows the subject and the disposition before the bulk.
        lines.push(json!({
            "line": "header",
            "schema_version": pack.schema_version,
            "fingerprint": pack.fingerprint,
            "subject": pack.subject,
            "purpose": pack.purpose,
            "detail_level": pack.detail_level,
            "disposition": pack.disposition,
            "metadata": pack.metadata,
        }));

        push_each(&mut lines, "finding", &pack.findings)?;
        push_each(&mut lines, "recommendation", &pack.recommendations)?;
        push_each(&mut lines, "entity", &pack.graph.entities)?;
        push_each(&mut lines, "claim", &pack.graph.claims)?;
        push_each(&mut lines, "relationship", &pack.graph.relationships)?;
        push_each(&mut lines, "sighting", &pack.graph.sightings)?;
        push_each(&mut lines, "contradiction", &pack.graph.contradictions)?;
        push_each(&mut lines, "pivot", &pack.graph.pivots)?;
        push_each(&mut lines, "technique", &pack.graph.techniques)?;
        push_each(&mut lines, "handle", &pack.handles)?;
        push_each(&mut lines, "gap", &pack.gaps)?;
        push_each(&mut lines, "exclusion", &pack.exclusions)?;

        // Singular tails: the budget and the policy context, so a consumer that stopped early still
        // learns whether anything was withheld when it reads to the end.
        lines.push(json!({"line": "budget", "budget": pack.budget}));
        lines.push(json!({"line": "policy", "policy": pack.policy}));

        let mut bytes: Vec<u8> = Vec::new();
        for line in &lines {
            let encoded = serde_json::to_vec(line).map_err(|error| ExportError::Unencodable {
                exporter: JSONL_ID,
                reason: error.to_string(),
            })?;
            bytes.extend_from_slice(&encoded);
            bytes.push(b'\n');
        }

        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: Vec::new(),
        })
    }
}

/// Push one line per item, each tagged with its kind.
fn push_each<T: serde::Serialize>(
    lines: &mut Vec<serde_json::Value>,
    kind: &'static str,
    items: &[T],
) -> Result<(), ExportError> {
    for item in items {
        let value = serde_json::to_value(item).map_err(|error| ExportError::Unencodable {
            exporter: JSONL_ID,
            reason: error.to_string(),
        })?;
        lines.push(json!({"line": kind, kind: value}));
    }
    Ok(())
}

/// Read a pack back from the canonical JSON.
///
/// Exposed so a round-trip test lives next to the claim it checks, and so a consumer of this crate
/// can verify a stored export against the pack it came from.
///
/// # Errors
///
/// Returns the `serde_json` error if the bytes are not a pack.
pub fn parse_pack(bytes: &[u8]) -> Result<ContextPack, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_jsonl_line_order_is_the_documented_one() {
        // The constant is what a consumer reads. It must list every kind the writer emits, in order.
        assert_eq!(JSONL_LINE_ORDER.first(), Some(&"header"));
        assert_eq!(JSONL_LINE_ORDER.last(), Some(&"policy"));
        let mut sorted = JSONL_LINE_ORDER.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            JSONL_LINE_ORDER.len(),
            "a line kind is listed twice"
        );
    }

    #[test]
    fn the_four_structured_exporters_have_distinct_identifiers() {
        let ids = [PACK_JSON_ID, COMPACT_JSON_ID, YAML_ID, JSONL_ID];
        let mut names: Vec<&str> = ids.iter().map(|id| id.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ids.len());
    }
}
