//! API and contract version identifiers.
//!
//! ADR 0001 §6 versions the Plugin ABI as `brolga:plugin@<major>.<minor>.<patch>`. Extension-point
//! contracts use `major.minor` (patch is reserved for the world, not each point). Both are data in
//! the manifest, not comments in a README.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;

/// A semantic version with major, minor, and optional patch.
///
/// `1.2` and `1.2.0` are equal. Patch defaults to zero when omitted so contract tags (`1.0`) and
/// ABI tags (`0.1.0`) share one type.
///
/// Serialises as a string. JSON Schema is a string, not an object of components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApiVersion {
    /// Incompatible when this changes.
    pub major: u16,
    /// Compatible additive growth within a major.
    pub minor: u16,
    /// Patch level. Zero when the source wrote only `major.minor`.
    pub patch: u16,
}

impl JsonSchema for ApiVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ApiVersion")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^[0-9]+\.[0-9]+(\.[0-9]+)?$",
            "description": "Semantic version major.minor or major.minor.patch",
        })
    }
}

impl ApiVersion {
    /// Construct a version.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Whether `other` is compatible with this version under ADR 0001 §6.
    ///
    /// Same major, and `other`'s minor is greater than or equal to this one (a newer minor is a
    /// superset). Patch is ignored for compatibility — it does not change the interface.
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && other.minor >= self.minor
    }

    /// Render as `major.minor.patch`.
    #[must_use]
    pub fn to_string_full(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Render as `major.minor` when patch is zero, otherwise full.
    #[must_use]
    pub fn to_string_compact(self) -> String {
        if self.patch == 0 {
            format!("{}.{}", self.major, self.minor)
        } else {
            self.to_string_full()
        }
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.patch == 0 {
            write!(formatter, "{}.{}", self.major, self.minor)
        } else {
            write!(
                formatter,
                "{}.{}.{}",
                self.major, self.minor, self.patch
            )
        }
    }
}

impl FromStr for ApiVersion {
    type Err = PluginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_version(value)
    }
}

impl TryFrom<String> for ApiVersion {
    type Error = PluginError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ApiVersion> for String {
    fn from(value: ApiVersion) -> Self {
        value.to_string_full()
    }
}

fn parse_version(value: &str) -> Result<ApiVersion, PluginError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PluginError::MalformedVersion {
            found: value.to_owned(),
            reason: "empty string".to_owned(),
        });
    }

    let mut parts = trimmed.split('.');
    let major = parse_component(parts.next(), value, "major")?;
    let minor = parse_component(parts.next(), value, "minor")?;
    let patch = match parts.next() {
        Some(part) => parse_component(Some(part), value, "patch")?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(PluginError::MalformedVersion {
            found: value.to_owned(),
            reason: "too many components; expected major.minor or major.minor.patch".to_owned(),
        });
    }

    Ok(ApiVersion {
        major,
        minor,
        patch,
    })
}

fn parse_component(part: Option<&str>, whole: &str, name: &str) -> Result<u16, PluginError> {
    let part = part.ok_or_else(|| PluginError::MalformedVersion {
        found: whole.to_owned(),
        reason: format!("missing {name} component"),
    })?;
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PluginError::MalformedVersion {
            found: whole.to_owned(),
            reason: format!("{name} must be a non-negative integer"),
        });
    }
    part.parse().map_err(|_| PluginError::MalformedVersion {
        found: whole.to_owned(),
        reason: format!("{name} is out of range for u16"),
    })
}

/// A range of API versions a plugin is willing to speak.
///
/// Supported forms:
/// - bare / caret: `0.1.0` or `^0.1.0` — same major, minor ≥ declared (0.x freezes the minor)
/// - bounded: `>=0.1.0,<0.2.0` — inclusive lower, exclusive upper
///
/// Wildcards (`*`, `x`) are refused. A range that cannot be parsed fails the manifest load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VersionRange {
    /// Inclusive lower bound.
    pub min: ApiVersion,
    /// Exclusive upper bound, if any.
    pub max_exclusive: Option<ApiVersion>,
}

impl JsonSchema for VersionRange {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("VersionRange")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "API version range: `0.1.0`, `^0.1.0`, or `>=0.1.0,<0.2.0`",
        })
    }
}

impl VersionRange {
    /// Caret range: `>=version` and `<next major` (for major ≥ 1), or `<0, next minor>` when
    /// major is 0 (0.x is unstable; minor bumps may break).
    #[must_use]
    pub const fn caret(version: ApiVersion) -> Self {
        let max_exclusive = if version.major == 0 {
            ApiVersion::new(0, version.minor.saturating_add(1), 0)
        } else {
            ApiVersion::new(version.major.saturating_add(1), 0, 0)
        };
        Self {
            min: version,
            max_exclusive: Some(max_exclusive),
        }
    }

    /// Whether `version` falls inside this range.
    #[must_use]
    pub fn includes(&self, version: ApiVersion) -> bool {
        if version < self.min {
            return false;
        }
        match self.max_exclusive {
            Some(max) => version < max,
            None => true,
        }
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.max_exclusive {
            Some(max) => write!(formatter, ">={},<{}", self.min.to_string_full(), max.to_string_full()),
            None => write!(formatter, ">={}", self.min.to_string_full()),
        }
    }
}

impl FromStr for VersionRange {
    type Err = PluginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_range(value)
    }
}

impl TryFrom<String> for VersionRange {
    type Error = PluginError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<VersionRange> for String {
    fn from(value: VersionRange) -> Self {
        value.to_string()
    }
}

fn parse_range(value: &str) -> Result<VersionRange, PluginError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PluginError::MalformedVersion {
            found: value.to_owned(),
            reason: "empty range".to_owned(),
        });
    }
    if trimmed.contains('*') || trimmed.contains('x') || trimmed.contains('X') {
        return Err(PluginError::WildcardCapability {
            reason: format!(
                "version range `{trimmed}` uses a wildcard; declare an explicit major.minor range"
            ),
        });
    }

    if let Some(rest) = trimmed.strip_prefix('^') {
        let version = parse_version(rest.trim())?;
        return Ok(VersionRange::caret(version));
    }

    if trimmed.contains(',') || trimmed.starts_with('>') || trimmed.starts_with('<') {
        return parse_bounded(trimmed);
    }

    // Bare version: treat as caret so `api: "0.1.0"` means "this ABI line".
    let version = parse_version(trimmed)?;
    Ok(VersionRange::caret(version))
}

fn parse_bounded(value: &str) -> Result<VersionRange, PluginError> {
    let mut min: Option<ApiVersion> = None;
    let mut max_exclusive: Option<ApiVersion> = None;

    for part in value.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(">=") {
            min = Some(parse_version(rest.trim())?);
        } else if let Some(rest) = part.strip_prefix('>') {
            // Exclusive lower: next patch step is awkward; refuse and ask for >=.
            let _ = rest;
            return Err(PluginError::MalformedVersion {
                found: value.to_owned(),
                reason: "use `>=` for the lower bound; bare `>` is not accepted".to_owned(),
            });
        } else if let Some(rest) = part.strip_prefix('<') {
            if rest.starts_with('=') {
                return Err(PluginError::MalformedVersion {
                    found: value.to_owned(),
                    reason: "use `<` for an exclusive upper bound; `<=` is not accepted".to_owned(),
                });
            }
            max_exclusive = Some(parse_version(rest.trim())?);
        } else {
            return Err(PluginError::MalformedVersion {
                found: value.to_owned(),
                reason: format!("unrecognised range clause `{part}`"),
            });
        }
    }

    let min = min.ok_or_else(|| PluginError::MalformedVersion {
        found: value.to_owned(),
        reason: "bounded range needs a `>=` lower bound".to_owned(),
    })?;

    Ok(VersionRange {
        min,
        max_exclusive,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn caret_on_zero_minor_does_not_cross_minor() {
        let range = VersionRange::caret(ApiVersion::new(0, 1, 0));
        assert!(range.includes(ApiVersion::new(0, 1, 0)));
        assert!(range.includes(ApiVersion::new(0, 1, 9)));
        assert!(!range.includes(ApiVersion::new(0, 2, 0)));
        assert!(!range.includes(ApiVersion::new(1, 0, 0)));
    }

    #[test]
    fn caret_on_one_allows_minor_growth() {
        let range = VersionRange::caret(ApiVersion::new(1, 2, 0));
        assert!(range.includes(ApiVersion::new(1, 2, 0)));
        assert!(range.includes(ApiVersion::new(1, 9, 0)));
        assert!(!range.includes(ApiVersion::new(2, 0, 0)));
        assert!(!range.includes(ApiVersion::new(1, 1, 0)));
    }

    #[test]
    fn wildcard_range_is_refused() {
        let error = VersionRange::from_str("0.*").unwrap_err();
        assert!(matches!(error, PluginError::WildcardCapability { .. }));
    }

    #[test]
    fn bounded_range_parses() {
        let range = VersionRange::from_str(">=0.1.0,<0.2.0").unwrap();
        assert!(range.includes(ApiVersion::new(0, 1, 5)));
        assert!(!range.includes(ApiVersion::new(0, 2, 0)));
    }

    #[test]
    fn contract_compatibility_requires_same_major() {
        let implemented = ApiVersion::new(1, 0, 0);
        assert!(implemented.is_compatible_with(ApiVersion::new(1, 2, 0)));
        assert!(!implemented.is_compatible_with(ApiVersion::new(2, 0, 0)));
        // Caller asks for 1.2 but we only implement 1.0: not a superset from our side.
        // is_compatible_with(self, other) means "other is compatible with self as the baseline".
        assert!(!ApiVersion::new(1, 2, 0).is_compatible_with(ApiVersion::new(1, 0, 0)));
    }
}
