//! Acceptance criteria for #46 — plugin SDK, manifests, and WIT ABI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use brolga_plugin_sdk::abi::{self, PLUGIN_ABI_VERSION, verify_wit_package};
use brolga_plugin_sdk::extension::ExtensionPoint;
use brolga_plugin_sdk::manifest::PluginManifest;
use brolga_plugin_sdk::version::ApiVersion;
use brolga_plugin_sdk::{PluginError, contract_version};

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins")
}

#[test]
fn every_extension_point_has_a_version_and_compatibility_policy() {
    for point in ExtensionPoint::ALL {
        let version = contract_version(*point);
        assert_eq!(version.major, 1, "{point} must declare a contract major");
        // Compatibility: same major, plugin minor must not exceed implemented minor.
        brolga_plugin_sdk::extension::check_contract(*point, version).unwrap();
        let too_new = ApiVersion::new(version.major, version.minor.saturating_add(1), 0);
        assert!(
            brolga_plugin_sdk::extension::check_contract(*point, too_new).is_err(),
            "{point} must refuse a newer contract minor"
        );
        let wrong_major = ApiVersion::new(version.major.saturating_add(1), 0, 0);
        assert!(
            brolga_plugin_sdk::extension::check_contract(*point, wrong_major).is_err(),
            "{point} must refuse a different contract major"
        );
    }
}

#[test]
fn shipped_example_manifests_declare_required_fields_and_validate() {
    for name in ["parser-manifest.yml", "exporter-manifest.yml"] {
        let path = examples_dir().join(name);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let manifest =
            PluginManifest::load(&bytes).unwrap_or_else(|e| panic!("{name} must validate: {e}"));
        assert!(!manifest.name.is_empty());
        assert!(!manifest.version.is_empty());
        assert!(!manifest.extension_points.is_empty());
        // Capabilities, formats, outputs are present as fields (formats may be non-empty on examples).
        let explanation = manifest.explain();
        assert!(
            explanation.abi_compatible,
            "{name} must match ABI {PLUGIN_ABI_VERSION}"
        );
        assert!(
            !explanation.refusals.is_empty(),
            "explain must list security refusals"
        );
    }
}

#[test]
fn abi_uses_deterministic_serialisable_invoke_types() {
    let request = abi::InvokeRequest {
        extension: ExtensionPoint::Parser,
        contract_version: ApiVersion::new(1, 0, 0),
        body: serde_json::json!({
            "document": [123],
            "media_type": "application/x-acme-feed"
        }),
    };
    let bytes = abi::encode_invoke_request(&request).unwrap();
    // Stable key order is not required of serde_json maps, but the round trip must be equal.
    let decoded = abi::decode_invoke_request(&bytes).unwrap();
    assert_eq!(decoded.extension, ExtensionPoint::Parser);
    assert_eq!(decoded.contract_version, ApiVersion::new(1, 0, 0));
    assert_eq!(decoded.body["media_type"], "application/x-acme-feed");
}

#[test]
fn unknown_versions_fail_clearly() {
    let bad_schema = r#"
schema_version: brolga.plugin.manifest/99.0
name: x
version: 1
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
"#;
    match PluginManifest::load(bad_schema.as_bytes()) {
        Err(PluginError::UnknownSchema { found, .. }) => {
            assert!(found.contains("99.0"));
        }
        other => panic!("expected UnknownSchema, got {other:?}"),
    }

    let bad_api = r#"
schema_version: brolga.plugin.manifest/1.0
name: x
version: 1
api: "3.0.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
"#;
    match PluginManifest::load(bad_api.as_bytes()) {
        Err(PluginError::IncompatibleApi { abi, .. }) => {
            assert_eq!(abi, PLUGIN_ABI_VERSION);
        }
        other => panic!("expected IncompatibleApi, got {other:?}"),
    }
}

#[test]
fn sdk_does_not_depend_on_host_internals() {
    // Structural: Cargo.toml first-party deps are only model + security (layer 0).
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    for forbidden in [
        "brolga-storage",
        "brolga-connectors",
        "brolga-cli",
        "brolga-api",
        "brolga-ingest",
        "brolga-export",
        "brolga-graph",
        "brolga-config",
        "libloading",
        "wasmtime",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "plugin SDK Cargo.toml must not depend on host internal `{forbidden}`"
        );
    }
    assert!(manifest.contains("brolga-model"));
    assert!(manifest.contains("brolga-security"));
}

#[test]
fn wit_world_is_present_versioned_and_import_free() {
    verify_wit_package().unwrap();
    assert!(abi::WIT_WORLD.contains("world plugin"));
    assert!(abi::WIT_WORLD.contains("export manifest"));
    assert!(abi::WIT_WORLD.contains("export invoke"));
}

#[test]
fn capability_vocabulary_rejects_wildcards() {
    let doc = r#"
schema_version: brolga.plugin.manifest/1.0
name: x
version: 1
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
capabilities:
  - kind: read_filesystem
    path_prefix: "*"
"#;
    assert!(matches!(
        PluginManifest::load(doc.as_bytes()),
        Err(PluginError::WildcardCapability { .. })
    ));
}
