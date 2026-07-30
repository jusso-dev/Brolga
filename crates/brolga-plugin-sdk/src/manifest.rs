//! Plugin manifest: who the plugin is, what it speaks, what it wants.
//!
//! # Loaded before any code runs
//!
//! A manifest is data. The host (and `brolga plugin validate`) refuse a document that cannot
//! execute safely — unknown schema, incompatible API, unknown extension, wildcard capability —
//! rather than discovering it mid-call.
//!
//! # Required fields
//!
//! name, version, api range, at least one extension point, and a schema tag. Capabilities default
//! to the empty list. Configuration schema, formats, and outputs are declared per extension point
//! where they apply.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::abi::{PLUGIN_ABI_VERSION, abi_version};
use crate::capability::{self, Capability};
use crate::error::PluginError;
use crate::extension::{self, ExtensionPoint};
use crate::version::{ApiVersion, VersionRange};

/// Manifest schema tag.
pub const MANIFEST_SCHEMA: &str = "brolga.plugin.manifest/1.0";

/// Schema tags this build accepts.
pub const ACCEPTED_SCHEMAS: &[&str] = &[MANIFEST_SCHEMA];

/// Most extension points one manifest may declare.
pub const MAX_EXTENSION_POINTS: usize = 32;

/// Most capabilities one manifest may declare.
pub const MAX_CAPABILITIES: usize = 64;

/// Most formats or outputs listed on one extension point.
pub const MAX_FORMAT_LIST: usize = 128;

/// A versioned plugin manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Must be [`MANIFEST_SCHEMA`] (or a later accepted tag).
    pub schema_version: String,
    /// Stable plugin identifier. Conventionally reverse-DNS or `org.name.role`.
    pub name: String,
    /// Plugin release version (not the ABI version).
    pub version: String,
    /// ABI versions this plugin is willing to speak.
    pub api: VersionRange,
    /// Extension points this plugin implements.
    pub extension_points: Vec<ExtensionPointDecl>,
    /// Host capabilities requested. Empty means pure compute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Optional JSON Schema describing operator configuration for this plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_schema: Option<serde_json::Value>,
    /// Optional path or digest metadata for the component artefact (host uses this; SDK only stores it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<ComponentRef>,
}

/// One extension point declaration inside a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPointDecl {
    /// Which point.
    pub kind: ExtensionPoint,
    /// Contract major.minor this implementation speaks.
    pub contract_version: ApiVersion,
    /// Media types, file extensions, or format ids this point handles (parsers, exporters, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<String>,
    /// Output kinds produced (for example `claim`, `entity`, `stix-bundle`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<String>,
}

/// Reference to a WebAssembly component or other artefact. Opaque to the SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentRef {
    /// Path or URI relative to the operator's plugin root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Content digest algorithm, for example `sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    /// Hex digest of the artefact bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Human-readable explanation of a validated manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestExplanation {
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// API range as text.
    pub api_range: String,
    /// Whether this build's ABI is included.
    pub abi_compatible: bool,
    /// Lines describing each extension point.
    pub extension_lines: Vec<String>,
    /// Capability kind names (empty means pure compute).
    pub capabilities: Vec<String>,
    /// Fixed refusals that apply whatever the manifest says.
    pub refusals: Vec<&'static str>,
}

impl PluginManifest {
    /// Parse YAML or JSON bytes and validate.
    ///
    /// # Errors
    ///
    /// Every problem that would make running the plugin unsafe or undefined.
    pub fn load(bytes: &[u8]) -> Result<Self, PluginError> {
        let raw: PluginManifest = parse_document(bytes)?;
        raw.validate()?;
        Ok(raw)
    }

    /// Validate an already-deserialised manifest.
    ///
    /// # Errors
    ///
    /// See [`PluginError`].
    pub fn validate(&self) -> Result<(), PluginError> {
        if !ACCEPTED_SCHEMAS.contains(&self.schema_version.as_str()) {
            return Err(PluginError::UnknownSchema {
                found: self.schema_version.clone(),
                accepted: ACCEPTED_SCHEMAS.join(", "),
            });
        }

        if self.name.trim().is_empty() {
            return Err(PluginError::Missing { field: "name" });
        }
        if self.name.chars().any(|c| c.is_control()) {
            return Err(PluginError::Field {
                field: "name",
                reason: "must not contain control characters".to_owned(),
            });
        }
        if self.version.trim().is_empty() {
            return Err(PluginError::Missing { field: "version" });
        }

        let abi = abi_version();
        if !self.api.includes(abi) {
            return Err(PluginError::IncompatibleApi {
                range: self.api.to_string(),
                abi: PLUGIN_ABI_VERSION.to_owned(),
            });
        }

        if self.extension_points.is_empty() {
            return Err(PluginError::Missing {
                field: "extension_points",
            });
        }
        if self.extension_points.len() > MAX_EXTENSION_POINTS {
            return Err(PluginError::Field {
                field: "extension_points",
                reason: format!(
                    "lists {} points; at most {MAX_EXTENSION_POINTS} are permitted",
                    self.extension_points.len()
                ),
            });
        }

        let mut seen = BTreeSet::new();
        for decl in &self.extension_points {
            if !seen.insert(decl.kind) {
                return Err(PluginError::Field {
                    field: "extension_points",
                    reason: format!(
                        "extension `{}` is declared more than once; each point at most once",
                        decl.kind
                    ),
                });
            }
            extension::check_contract(decl.kind, decl.contract_version)?;
            if decl.formats.len() > MAX_FORMAT_LIST {
                return Err(PluginError::Field {
                    field: "extension_points",
                    reason: format!(
                        "`{}` lists too many formats (max {MAX_FORMAT_LIST})",
                        decl.kind
                    ),
                });
            }
            if decl.outputs.len() > MAX_FORMAT_LIST {
                return Err(PluginError::Field {
                    field: "extension_points",
                    reason: format!(
                        "`{}` lists too many outputs (max {MAX_FORMAT_LIST})",
                        decl.kind
                    ),
                });
            }
            for format in &decl.formats {
                if format.trim().is_empty() {
                    return Err(PluginError::Field {
                        field: "extension_points",
                        reason: format!("`{}` has an empty format entry", decl.kind),
                    });
                }
            }
        }

        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(PluginError::Field {
                field: "capabilities",
                reason: format!(
                    "lists {} capabilities; at most {MAX_CAPABILITIES} are permitted",
                    self.capabilities.len()
                ),
            });
        }
        capability::validate_all(&self.capabilities)?;

        if let Some(schema) = &self.configuration_schema
            && !schema.is_object()
        {
            return Err(PluginError::Field {
                field: "configuration_schema",
                reason: "must be a JSON object (a JSON Schema document)".to_owned(),
            });
        }

        Ok(())
    }

    /// Explain what a valid manifest declares, including fixed refusals.
    #[must_use]
    pub fn explain(&self) -> ManifestExplanation {
        let abi = abi_version();
        let extension_lines = self
            .extension_points
            .iter()
            .map(|decl| {
                let mut line = format!(
                    "{} contract {} — {}",
                    decl.kind,
                    decl.contract_version.to_string_compact(),
                    decl.kind.description()
                );
                if !decl.formats.is_empty() {
                    line.push_str(&format!("; formats: {}", decl.formats.join(", ")));
                }
                if !decl.outputs.is_empty() {
                    line.push_str(&format!("; outputs: {}", decl.outputs.join(", ")));
                }
                if decl.kind.is_advisory_only() {
                    line.push_str(" [advisory only]");
                }
                line
            })
            .collect();

        ManifestExplanation {
            name: self.name.clone(),
            version: self.version.clone(),
            api_range: self.api.to_string(),
            abi_compatible: self.api.includes(abi),
            extension_lines,
            capabilities: self
                .capabilities
                .iter()
                .map(Capability::kind_str)
                .map(str::to_owned)
                .collect(),
            refusals: REFUSALS.to_vec(),
        }
    }
}

/// Fixed refusals printed by `plugin explain`, whatever the manifest asks for.
pub const REFUSALS: &[&str] = &[
    "no native shared-library loading",
    "no filesystem or network access unless an explicit, scoped capability is granted by the host",
    "no policy decisions — policy extensions are advisory only",
    "no live database handle for storage extensions by default",
    "no host internals (store, transport, CLI streams) exposed through the SDK",
    "plugin output is TrustLevel::Untrusted",
    "unknown ABI majors and unknown extension points fail clearly",
];

fn parse_document(bytes: &[u8]) -> Result<PluginManifest, PluginError> {
    // YAML is a superset for our purposes; JSON documents parse as YAML via serde_norway.
    serde_norway::from_slice(bytes).map_err(|error| PluginError::Unreadable(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version: brolga.plugin.manifest/1.0
name: example.parser
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
    formats: ["application/x-example"]
    outputs: ["claim"]
capabilities: []
"#;

    #[test]
    fn minimal_manifest_loads() {
        let manifest = PluginManifest::load(MINIMAL.as_bytes()).unwrap();
        assert_eq!(manifest.name, "example.parser");
        assert!(manifest.capabilities.is_empty());
    }

    #[test]
    fn unknown_schema_fails() {
        let doc = MINIMAL.replace(MANIFEST_SCHEMA, "brolga.plugin.manifest/9.0");
        let error = PluginManifest::load(doc.as_bytes()).unwrap_err();
        assert!(matches!(error, PluginError::UnknownSchema { .. }));
    }

    #[test]
    fn incompatible_api_fails() {
        let doc = MINIMAL.replace("0.1.0", "9.0.0");
        let error = PluginManifest::load(doc.as_bytes()).unwrap_err();
        assert!(matches!(error, PluginError::IncompatibleApi { .. }));
    }

    #[test]
    fn unknown_extension_fails() {
        // Only the kind field — a blanket replace would also rewrite `example.parser`.
        let doc = r#"
schema_version: brolga.plugin.manifest/1.0
name: example.other
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: time_travel
    contract_version: "1.0"
"#;
        let error = PluginManifest::load(doc.as_bytes()).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unknown extension point") || message.contains("time_travel"),
            "unknown extension must fail clearly: {message}"
        );
    }

    #[test]
    fn wildcard_capability_fails() {
        let doc = r#"
schema_version: brolga.plugin.manifest/1.0
name: evil
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
capabilities:
  - kind: network_egress
    host: "*"
"#;
        let error = PluginManifest::load(doc.as_bytes()).unwrap_err();
        assert!(matches!(error, PluginError::WildcardCapability { .. }));
    }

    #[test]
    fn explain_lists_refusals() {
        let manifest = PluginManifest::load(MINIMAL.as_bytes()).unwrap();
        let explanation = manifest.explain();
        assert!(explanation.abi_compatible);
        assert!(!explanation.refusals.is_empty());
    }
}
