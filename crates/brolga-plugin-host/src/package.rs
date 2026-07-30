//! Load and authorise a plugin package without executing guest code.

use std::path::Path;

use brolga_plugin_sdk::abi::PLUGIN_ABI_VERSION;
use brolga_plugin_sdk::manifest::PluginManifest;

use crate::digest::{DigestAlgorithm, PluginDigest, digest_bytes};
use crate::error::HostError;
use crate::grant::GrantSet;
use crate::limits::PluginLimits;

/// Identity recorded for reproducibility after a successful load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentity {
    /// Manifest name.
    pub name: String,
    /// Manifest version.
    pub version: String,
    /// ABI this build speaks.
    pub abi: String,
    /// Component digest, if component bytes were present.
    pub digest: Option<PluginDigest>,
    /// Capabilities that were both requested and granted.
    pub granted: Vec<String>,
    /// Limit snapshot.
    pub limits: PluginLimits,
}

/// A package that passed validation and authorisation.
#[derive(Debug, Clone)]
pub struct LoadedPackage {
    /// Validated manifest.
    pub manifest: PluginManifest,
    /// Component bytes, if the package included them.
    pub component: Option<Vec<u8>>,
    /// Identity for audit / fingerprints.
    pub identity: PackageIdentity,
    /// Effective limits.
    pub limits: PluginLimits,
}

/// Load a package from a directory containing `manifest.yml` / `manifest.yaml` / `manifest.json`
/// and optional `component.wasm`.
///
/// # Errors
///
/// Missing files, invalid manifest, digest mismatch, capability denial, bad limits.
pub fn load_package_dir(
    dir: &Path,
    grants: &GrantSet,
    limits: PluginLimits,
) -> Result<LoadedPackage, HostError> {
    let limits = limits.validated()?;
    let manifest_path = find_manifest(dir)?;
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|error| HostError::Io(format!("read {}: {error}", manifest_path.display())))?;
    let component_path = dir.join("component.wasm");
    let component = if component_path.is_file() {
        Some(std::fs::read(&component_path).map_err(|error| {
            HostError::Io(format!("read {}: {error}", component_path.display()))
        })?)
    } else {
        None
    };
    load_package_files(&manifest_bytes, component.as_deref(), grants, limits)
}

/// Load from already-read bytes (tests and non-filesystem sources).
///
/// # Errors
///
/// Same as [`load_package_dir`].
pub fn load_package_files(
    manifest_bytes: &[u8],
    component: Option<&[u8]>,
    grants: &GrantSet,
    limits: PluginLimits,
) -> Result<LoadedPackage, HostError> {
    let limits = limits.validated()?;
    let manifest = PluginManifest::load(manifest_bytes)
        .map_err(|error| HostError::Manifest(error.to_string()))?;

    grants.authorise(&manifest.capabilities)?;

    let digest = match component {
        Some(bytes) => {
            let computed = digest_bytes(bytes);
            if let Some(declared) = manifest.component.as_ref()
                && let (Some(algo), Some(expected)) = (
                    declared.digest_algorithm.as_deref(),
                    declared.digest.as_deref(),
                )
            {
                let algorithm = DigestAlgorithm::parse(algo)?;
                let found = PluginDigest::of(algorithm, bytes);
                if !found.matches_hex(expected) {
                    return Err(HostError::DigestMismatch {
                        algorithm: algorithm.as_str().to_owned(),
                        expected: expected.to_owned(),
                        found: found.hex,
                    });
                }
            }
            Some(computed)
        }
        None => None,
    };

    // FS/network capabilities are not yet mapped to WIT imports (ADR 0009 §3 residual).
    // Refuse packages that request them so operators cannot believe a grant opened a hole it did not.
    for capability in &manifest.capabilities {
        if matches!(
            capability,
            brolga_plugin_sdk::Capability::ReadFilesystem { .. }
                | brolga_plugin_sdk::Capability::WriteFilesystem { .. }
                | brolga_plugin_sdk::Capability::NetworkEgress { .. }
        ) {
            return Err(HostError::CapabilityDenied {
                reason: format!(
                    "`{}` is recorded as a grant but this host build does not map it to a WIT import yet; refuse rather than claim access",
                    capability.kind_str()
                ),
            });
        }
    }

    let granted: Vec<String> = manifest
        .capabilities
        .iter()
        .map(brolga_plugin_sdk::Capability::kind_str)
        .map(str::to_owned)
        .collect();

    let identity = PackageIdentity {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        abi: PLUGIN_ABI_VERSION.to_owned(),
        digest,
        granted,
        limits,
    };

    Ok(LoadedPackage {
        manifest,
        component: component.map(Vec::from),
        identity,
        limits,
    })
}

fn find_manifest(dir: &Path) -> Result<std::path::PathBuf, HostError> {
    for name in ["manifest.yml", "manifest.yaml", "manifest.json"] {
        let path = dir.join(name);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(HostError::Io(format!(
        "{} has no manifest.yml/yaml/json",
        dir.display()
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use brolga_plugin_sdk::Capability;

    const MANIFEST: &str = r#"
schema_version: brolga.plugin.manifest/1.0
name: test.parser
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
    formats: ["application/x-test"]
    outputs: ["claim"]
capabilities: []
"#;

    #[test]
    fn pure_compute_package_loads() {
        let package = load_package_files(
            MANIFEST.as_bytes(),
            Some(b"\0asm not-real"),
            &GrantSet::empty(),
            PluginLimits::defaults(),
        )
        .unwrap();
        assert_eq!(package.identity.name, "test.parser");
        assert!(package.identity.digest.is_some());
        assert!(package.identity.granted.is_empty());
    }

    #[test]
    fn wall_clock_without_grant_is_denied() {
        let manifest = r#"
schema_version: brolga.plugin.manifest/1.0
name: test.clock
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
capabilities:
  - kind: wall_clock
"#;
        let error = load_package_files(
            manifest.as_bytes(),
            None,
            &GrantSet::empty(),
            PluginLimits::defaults(),
        )
        .unwrap_err();
        assert!(matches!(error, HostError::CapabilityDenied { .. }));
    }

    #[test]
    fn wall_clock_with_grant_is_allowed() {
        let manifest = r#"
schema_version: brolga.plugin.manifest/1.0
name: test.clock
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
capabilities:
  - kind: wall_clock
"#;
        let grants = GrantSet::try_from_grants(vec![Capability::WallClock]).unwrap();
        let package =
            load_package_files(manifest.as_bytes(), None, &grants, PluginLimits::defaults())
                .unwrap();
        assert_eq!(package.identity.granted, vec!["wall_clock".to_owned()]);
    }
}
