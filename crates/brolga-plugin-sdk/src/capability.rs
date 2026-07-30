//! Plugin capability vocabulary.
//!
//! # Why a closed enum rather than free strings
//!
//! Free strings grow wildcards. The first operator who writes `capabilities: ["*"]` or
//! `network-egress: any` gets host-wide access if the host is polite enough to honour it. A closed
//! enum makes that unrepresentable: unknown names fail at load, and every known name is scoped.
//!
//! # Empty means pure compute
//!
//! The default and the only safe default. No filesystem, no network, no wall clock, no entropy
//! from the host. The WebAssembly world ships with empty imports for the same reason (ADR 0008 §2).
//!
//! # This crate declares; the host enforces
//!
//! Validating a capability list means the names and scopes are well-formed. It does not mean the
//! process has granted them. Grant checks are [#48](https://github.com/jusso-dev/Brolga/issues/48).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;

/// A single host capability a plugin may request.
///
/// Serialised as a tagged object so scopes travel with the name and a bare string cannot imply
/// host-wide access.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Capability {
    /// Read files under a path prefix. The host maps this to a pre-opened directory or refuses it.
    ReadFilesystem {
        /// Absolute or operator-configured prefix. Must not be empty, `/`, or contain `..`.
        path_prefix: String,
    },
    /// Write files under a path prefix. Same scope rules as read.
    WriteFilesystem {
        /// Absolute or operator-configured prefix.
        path_prefix: String,
    },
    /// Outbound network to one host, optionally one port.
    NetworkEgress {
        /// Hostname or literal address. Not a pattern; not `*`.
        host: String,
        /// When set, only this port. When absent, the host applies its own default allowlist policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    /// Non-deterministic wall clock. Default plugins see a frozen or host-injected clock instead.
    WallClock,
    /// Host entropy / random. Default plugins get deterministic synthetic randomness or nothing.
    Entropy,
}

impl Capability {
    /// Snake_case kind name for diagnostics and reproducibility metadata.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::ReadFilesystem { .. } => "read_filesystem",
            Self::WriteFilesystem { .. } => "write_filesystem",
            Self::NetworkEgress { .. } => "network_egress",
            Self::WallClock => "wall_clock",
            Self::Entropy => "entropy",
        }
    }

    /// Validate scopes. Refuses empty hosts, empty prefixes, path traversal, and wildcard hosts.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Capability`] or [`PluginError::WildcardCapability`].
    pub fn validate(&self) -> Result<(), PluginError> {
        match self {
            Self::ReadFilesystem { path_prefix } | Self::WriteFilesystem { path_prefix } => {
                validate_path_prefix(path_prefix)
            }
            Self::NetworkEgress { host, port } => validate_host(host, *port),
            Self::WallClock | Self::Entropy => Ok(()),
        }
    }

    /// Whether this capability implies non-determinism in plugin output.
    #[must_use]
    pub const fn is_nondeterministic(&self) -> bool {
        matches!(self, Self::WallClock | Self::Entropy)
    }
}

fn validate_path_prefix(path_prefix: &str) -> Result<(), PluginError> {
    let trimmed = path_prefix.trim();
    if trimmed.is_empty() {
        return Err(PluginError::Capability {
            reason: "filesystem capability has an empty path_prefix".to_owned(),
        });
    }
    if trimmed == "/" || trimmed == "\\" {
        return Err(PluginError::WildcardCapability {
            reason: "filesystem path_prefix `/` is host-wide; scope to a concrete prefix"
                .to_owned(),
        });
    }
    if trimmed == "*" || trimmed == "**" {
        return Err(PluginError::WildcardCapability {
            reason: "filesystem path_prefix may not be a wildcard".to_owned(),
        });
    }
    if trimmed.split(['/', '\\']).any(|part| part == "..") {
        return Err(PluginError::Capability {
            reason: format!("filesystem path_prefix `{trimmed}` must not contain `..`"),
        });
    }
    Ok(())
}

fn validate_host(host: &str, port: Option<u16>) -> Result<(), PluginError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(PluginError::Capability {
            reason: "network_egress capability has an empty host".to_owned(),
        });
    }
    if trimmed == "*" || trimmed == "0.0.0.0" || trimmed == "::" || trimmed == "any" {
        return Err(PluginError::WildcardCapability {
            reason: format!(
                "network_egress host `{trimmed}` is a wildcard or unspecified address; name one host"
            ),
        });
    }
    if trimmed.contains('*') || trimmed.contains('?') {
        return Err(PluginError::WildcardCapability {
            reason: format!("network_egress host `{trimmed}` must not contain wildcards"),
        });
    }
    if let Some(0) = port {
        return Err(PluginError::Capability {
            reason: "network_egress port 0 is not a real port".to_owned(),
        });
    }
    Ok(())
}

/// Validate a whole capability list.
///
/// # Errors
///
/// Returns the first capability error found.
pub fn validate_all(capabilities: &[Capability]) -> Result<(), PluginError> {
    for capability in capabilities {
        capability.validate()?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn root_filesystem_is_wildcard() {
        let cap = Capability::ReadFilesystem {
            path_prefix: "/".to_owned(),
        };
        assert!(matches!(
            cap.validate(),
            Err(PluginError::WildcardCapability { .. })
        ));
    }

    #[test]
    fn star_host_is_wildcard() {
        let cap = Capability::NetworkEgress {
            host: "*".to_owned(),
            port: None,
        };
        assert!(matches!(
            cap.validate(),
            Err(PluginError::WildcardCapability { .. })
        ));
    }

    #[test]
    fn scoped_read_is_ok() {
        let cap = Capability::ReadFilesystem {
            path_prefix: "/var/brolga/feeds".to_owned(),
        };
        assert!(cap.validate().is_ok());
    }
}
