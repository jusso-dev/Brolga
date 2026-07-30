//! Extension points a plugin may implement.
//!
//! Closed set. An unknown name in a manifest is a load error, not a skipped entry — a typo must
//! not silently disable half a plugin.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;
use crate::version::ApiVersion;

/// Where a plugin plugs in.
///
/// Every member has a contract version (see [`crate::contract::contract_version`]) and a
/// serialisable request/response body. The portable ABI calls them all through one
/// `invoke.call` (ADR 0008 §3).
///
/// Deserialises through [`FromStr`] so an unknown name becomes [`PluginError::UnknownExtension`]
/// (with the known list) rather than a generic serde failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionPoint {
    /// Bytes in, canonical records out.
    Parser,
    /// Deterministic field and observable normalisation.
    Normaliser,
    /// Add derived claims from already-canonical input (still untrusted output).
    Enricher,
    /// Propose entity-resolution candidates; host applies merge policy.
    Resolver,
    /// Rank or score candidates for compression and display.
    Scorer,
    /// Confidence component proposals; host aggregates.
    Confidence,
    /// Temporal decay parameterisation proposals; host owns floors and half-lives.
    Decay,
    /// Context-pack condensation helpers under host budgets.
    Compression,
    /// Token estimation for a declared model family.
    Token,
    /// Advisory policy annotations only — never a binding authorisation decision.
    Policy,
    /// Serialised-record transform/validate — never a live database handle by default.
    Storage,
    /// Context pack to bytes, after the host policy gate.
    Exporter,
    /// Context profile contribution (selection hints), not host config mutation.
    Profile,
    /// Outbound retrieval proposal; host still owns transport and SSRF policy.
    Connector,
}

impl ExtensionPoint {
    /// All known points, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Parser,
        Self::Normaliser,
        Self::Enricher,
        Self::Resolver,
        Self::Scorer,
        Self::Confidence,
        Self::Decay,
        Self::Compression,
        Self::Token,
        Self::Policy,
        Self::Storage,
        Self::Exporter,
        Self::Profile,
        Self::Connector,
    ];

    /// Snake_case wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Normaliser => "normaliser",
            Self::Enricher => "enricher",
            Self::Resolver => "resolver",
            Self::Scorer => "scorer",
            Self::Confidence => "confidence",
            Self::Decay => "decay",
            Self::Compression => "compression",
            Self::Token => "token",
            Self::Policy => "policy",
            Self::Storage => "storage",
            Self::Exporter => "exporter",
            Self::Profile => "profile",
            Self::Connector => "connector",
        }
    }

    /// One-line description for `plugin explain` and docs.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Parser => "parse untrusted bytes into canonical records",
            Self::Normaliser => "deterministically normalise fields and observables",
            Self::Enricher => "propose derived claims from canonical input",
            Self::Resolver => "propose entity-resolution candidates",
            Self::Scorer => "score candidates for ranking and display",
            Self::Confidence => "propose confidence components",
            Self::Decay => "propose temporal decay parameters",
            Self::Compression => "assist context-pack condensation under host budgets",
            Self::Token => "estimate tokens for a declared model family",
            Self::Policy => "advisory policy annotations only — never binding authorisation",
            Self::Storage => "transform or validate serialised records — no live DB handle",
            Self::Exporter => "render a cleared pack to bytes",
            Self::Profile => "contribute context profile selection hints",
            Self::Connector => "propose outbound retrieval; host owns transport and SSRF",
        }
    }

    /// Whether this point's output is always treated as untrusted proposals.
    ///
    /// Everything a plugin produces is untrusted in the threat model. This flag marks points where
    /// a naive reader might think the plugin *decides* — policy, storage, connector, resolver —
    /// so explain output can stress the refusal.
    #[must_use]
    pub const fn is_advisory_only(self) -> bool {
        matches!(
            self,
            Self::Policy | Self::Storage | Self::Connector | Self::Resolver | Self::Enricher
        )
    }

    /// Contract version this build implements for the point.
    #[must_use]
    pub const fn implemented_contract(self) -> ApiVersion {
        // All start at 1.0 for the first ABI. Independent majors can diverge later.
        ApiVersion::new(1, 0, 0)
    }
}

impl fmt::Display for ExtensionPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExtensionPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for ExtensionPoint {
    type Err = PluginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalised = value.trim().to_ascii_lowercase().replace('-', "_");
        for point in Self::ALL {
            if point.as_str() == normalised {
                return Ok(*point);
            }
        }
        // Accept British/American spelling for normaliser.
        if normalised == "normalizer" {
            return Ok(Self::Normaliser);
        }
        Err(PluginError::UnknownExtension {
            found: value.to_owned(),
            known: Self::ALL
                .iter()
                .map(|point| point.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })
    }
}

/// Check that a declared contract version is acceptable for this point.
///
/// Major must match the implemented major. A newer minor on the plugin side is refused if we do
/// not implement it yet (we are not a superset). A newer minor on *our* side is fine: the plugin
/// asked for an older minor we still speak.
///
/// # Errors
///
/// [`PluginError::UnsupportedContract`] when majors differ or the plugin requires a newer minor.
pub fn check_contract(point: ExtensionPoint, declared: ApiVersion) -> Result<(), PluginError> {
    let implemented = point.implemented_contract();
    if declared.major != implemented.major {
        return Err(PluginError::UnsupportedContract {
            extension: point.to_string(),
            found: declared.to_string_compact(),
            supported: implemented.to_string_compact(),
        });
    }
    if declared.minor > implemented.minor {
        return Err(PluginError::UnsupportedContract {
            extension: point.to_string(),
            found: declared.to_string_compact(),
            supported: implemented.to_string_compact(),
        });
    }
    Ok(())
}
