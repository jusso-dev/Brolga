//! Extension-point contracts: versioned, serialisable request and response types.
//!
//! # Deterministic serialisable types only
//!
//! The portable ABI carries JSON bytes. Rust traits here are ergonomic wrappers over the same
//! shapes. Nothing in a request or response is a host handle — no `Store`, no `Transport`, no
//! `PolicyIdentity`, no open file. That is how "SDK does not expose host internals by default"
//! stays true when someone adds a method later: there is no type to reach for.
//!
//! # Output trust
//!
//! Every response body is treated by the host as `TrustLevel::Untrusted` material derived from
//! untrusted input (threat model B8). This module does not re-tag values; classification is the
//! host's job when it rehydrates records.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::extension::ExtensionPoint;
use crate::version::ApiVersion;

/// Contract version this build implements for `point`.
#[must_use]
pub const fn contract_version(point: ExtensionPoint) -> ApiVersion {
    point.implemented_contract()
}

/// Byte buffer serialised as a JSON array of numbers 0–255.
///
/// Deterministic and unambiguous (no base64 alphabet choices). The host bounds length before the
/// plugin sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ByteBuf(pub Vec<u8>);

impl ByteBuf {
    /// Borrow the bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ByteBuf {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Serialize for ByteBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.iter().map(|b| u64::from(*b)))
    }
}

impl<'de> Deserialize<'de> for ByteBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<u64>::deserialize(deserializer)?;
        let mut out = Vec::with_capacity(values.len());
        for value in values {
            let byte = u8::try_from(value).map_err(|_| {
                serde::de::Error::custom(format!("byte value {value} is outside 0..=255"))
            })?;
            out.push(byte);
        }
        Ok(Self(out))
    }
}

impl JsonSchema for ByteBuf {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ByteBuf")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "array",
            "items": { "type": "integer", "minimum": 0, "maximum": 255 },
            "description": "Raw bytes as an array of integers 0–255",
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Parser
// -------------------------------------------------------------------------------------------------

/// Detection input: cheap prefix and hints, not the whole document unless it is small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectRequest {
    /// Declared media type, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// File extension without a leading dot, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Leading bytes of the document (host-bounded).
    pub prefix: ByteBuf,
}

/// Detection result. Higher confidence wins when the host ranks candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectResponse {
    /// 0–100. Host maps this onto its own confidence ladder.
    pub confidence: u8,
    /// Short reason for diagnostics and provenance.
    pub reason: String,
}

/// Parse input: the full document bytes, already size-bounded by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseRequest {
    /// Document bytes.
    pub document: ByteBuf,
    /// Optional media type the host already believes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// Parse output: canonical records as JSON values, each carrying its own `schema_version`.
///
/// The host re-validates every record against `brolga-model` schemas. A plugin cannot smuggle a
/// host type through; it can only emit JSON the host is willing to accept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseResponse {
    /// Records in any order; the host sorts before write.
    pub records: Vec<serde_json::Value>,
}

// -------------------------------------------------------------------------------------------------
// Exporter
// -------------------------------------------------------------------------------------------------

/// Export input: a **already policy-cleared** pack serialised as JSON.
///
/// The host runs the policy gate (ADR 0007) before this request is built. A plugin exporter never
/// sees a pack that was not cleared, and cannot call `clear` itself — that type is not in this crate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExporterPluginRequest {
    /// Serialised cleared context pack.
    pub pack: serde_json::Value,
}

/// Export output: bytes plus declared lossiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExporterPluginResponse {
    /// Rendered artefact.
    pub body: ByteBuf,
    /// Media type of `body`.
    pub media_type: String,
    /// Lossiness label: `lossless`, `partially_lossless`, `compressed`, or `derived`.
    pub lossiness: String,
    /// Human-readable loss notes when not lossless.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_losses: Vec<String>,
}

// -------------------------------------------------------------------------------------------------
// Generic envelope (all other points, and a fallback for invoke)
// -------------------------------------------------------------------------------------------------

/// Generic JSON body for extension points that do not yet have a dedicated Rust struct.
///
/// Dedicated structs above are preferred for parser and exporter because they are the first
/// examples (#50). Other points use this envelope until their shapes freeze; the contract version
/// still applies and unknown majors still fail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenericRequest {
    /// Extension-specific JSON object.
    pub body: serde_json::Value,
}

/// Generic JSON response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenericResponse {
    /// Extension-specific JSON object.
    pub body: serde_json::Value,
}

/// Advisory policy annotation — never a binding decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposal {
    /// What the plugin suggests, for operator review.
    pub summary: String,
    /// Evidence identifiers the host already knows (content addresses or record ids as strings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cites: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_round_trips_bytes_as_json_array() {
        let request = ParseRequest {
            document: ByteBuf(b"hello".to_vec()),
            media_type: Some("text/plain".to_owned()),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("[104,101,108,108,111]"));
        let back: ParseRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn every_extension_has_a_contract_version() {
        for point in ExtensionPoint::ALL {
            let version = contract_version(*point);
            assert_eq!(version.major, 1);
            assert_eq!(version.minor, 0);
        }
    }
}
