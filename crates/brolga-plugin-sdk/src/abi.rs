//! WIT world identity and the portable invoke envelope.
//!
//! # The world is the compatibility surface
//!
//! ADR 0001 §6: `brolga:plugin@<major>.<minor>.<patch>`. The file at `wit/world.wit` is the
//! source of truth; [`PLUGIN_ABI_VERSION`] and [`WIT_WORLD`] must match it (enforced by test).
//!
//! # Empty imports are the security property
//!
//! The `plugin` world exports `manifest` and `invoke` and imports nothing. Filesystem and network
//! appear only when a future host maps declared capabilities to imports under operator policy.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;
use crate::extension::ExtensionPoint;
use crate::version::ApiVersion;

/// Package name as it appears in the WIT file.
pub const PLUGIN_WIT_PACKAGE: &str = "brolga:plugin";

/// ABI version this build implements. Must match `package brolga:plugin@…` in `wit/world.wit`.
pub const PLUGIN_ABI_VERSION: &str = "0.1.0";

/// The embedded WIT world source.
pub const WIT_WORLD: &str = include_str!("../wit/world.wit");

/// Parse [`PLUGIN_ABI_VERSION`] as an [`ApiVersion`].
///
/// # Errors
///
/// Only if the constant is malformed — a build bug.
#[must_use]
pub fn abi_version() -> ApiVersion {
    PLUGIN_ABI_VERSION
        .parse()
        .unwrap_or_else(|_| ApiVersion::new(0, 0, 0))
}

/// Check that the embedded WIT file declares this build's package version.
///
/// # Errors
///
/// [`PluginError::Abi`] when the file is missing the package line or disagrees.
pub fn verify_wit_package() -> Result<(), PluginError> {
    let expected = format!("package {PLUGIN_WIT_PACKAGE}@{PLUGIN_ABI_VERSION}");
    if !WIT_WORLD.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == expected || trimmed == format!("{expected};")
    }) {
        return Err(PluginError::Abi {
            reason: format!(
                "wit/world.wit must declare `{expected}`; update the file and PLUGIN_ABI_VERSION together"
            ),
        });
    }
    // Default security property: the world must not import wasi or host capability interfaces.
    let forbidden = ["import wasi:", "import brolga:host", "import filesystem", "import network"];
    for needle in forbidden {
        if WIT_WORLD.contains(needle) {
            return Err(PluginError::Abi {
                reason: format!(
                    "wit/world.wit must not contain `{needle}` in the default world; capabilities map to imports only in the host"
                ),
            });
        }
    }
    Ok(())
}

/// Portable invoke request — mirrors the WIT `invoke.call` parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvokeRequest {
    /// Extension point name (snake_case).
    pub extension: ExtensionPoint,
    /// Contract major.minor the caller intends.
    pub contract_version: ApiVersion,
    /// UTF-8 JSON body for that contract.
    pub body: serde_json::Value,
}

/// Portable invoke success body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvokeResponse {
    /// UTF-8 JSON body for that contract.
    pub body: serde_json::Value,
}

/// Portable error body — mirrors the WIT `plugin-error` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvokeErrorBody {
    /// Stable machine code.
    pub code: String,
    /// Human-readable detail.
    pub message: String,
}

impl InvokeErrorBody {
    /// Build from a code and message.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Encode an [`InvokeRequest`] as JSON bytes for the WIT `list<u8>` request parameter.
///
/// # Errors
///
/// Only if JSON serialisation fails, which should not happen for these types.
pub fn encode_invoke_request(request: &InvokeRequest) -> Result<Vec<u8>, PluginError> {
    serde_json::to_vec(request).map_err(|error| PluginError::Abi {
        reason: format!("cannot encode invoke request: {error}"),
    })
}

/// Decode JSON bytes into an [`InvokeRequest`].
///
/// # Errors
///
/// Malformed JSON or an unknown extension point.
pub fn decode_invoke_request(bytes: &[u8]) -> Result<InvokeRequest, PluginError> {
    serde_json::from_slice(bytes).map_err(|error| PluginError::Abi {
        reason: format!("cannot decode invoke request: {error}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn wit_package_matches_constant() {
        assert!(
            verify_wit_package().is_ok(),
            "WIT and constant must agree: {:?}",
            verify_wit_package()
        );
    }

    #[test]
    fn abi_version_parses() {
        let version = abi_version();
        assert_eq!(version.major, 0);
        assert_eq!(version.minor, 1);
        assert_eq!(version.patch, 0);
    }
}
