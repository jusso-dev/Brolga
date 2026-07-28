//! Secret references.
//!
//! # Configuration never contains a secret
//!
//! It contains a *reference* to one. That is not a style preference — a configuration file is
//! copied into version control, attached to support tickets, printed by `config explain`, and
//! rendered into diagnostics, and every one of those is a path by which an inline value escapes.
//!
//! The rule is enforced by the type rather than by review: [`SecretRef`] deserialises only from a
//! tagged map, so a bare string is a *parse* failure with a message telling the operator what to
//! write instead. There is no `SecretRef::Inline` variant to reach for.
//!
//! # Resolution is not this crate's job
//!
//! Nothing here reads an environment variable or opens a file. A `SecretRef` is a description of
//! where a value lives; turning it into a value happens in the component that needs it, at the
//! moment it needs it, and the resolved value never travels back into a config structure. That
//! keeps resolution isolated from serialisation, from `Debug`, and from logging by construction
//! rather than by discipline.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigPath, Result, preview};

/// Maximum length of an environment variable name.
pub const MAX_ENV_NAME_BYTES: usize = 256;

/// Maximum length of a secret file path.
pub const MAX_SECRET_PATH_BYTES: usize = 4096;

/// Where a secret's value can be found.
///
/// Serialised as exactly one of `{ from_env = "NAME" }` or `{ from_file = "/path" }`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SecretRef {
    /// Read from an environment variable.
    FromEnv(EnvVarName),
    /// Read from a file, typically a mounted secret.
    FromFile(SecretPath),
}

impl SecretRef {
    /// Build a reference to an environment variable.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the name is empty, too long, or not a valid POSIX
    /// environment variable name.
    pub fn from_env(name: impl AsRef<str>, path: &ConfigPath) -> Result<Self> {
        Ok(Self::FromEnv(EnvVarName::new(name, path)?))
    }

    /// Build a reference to a file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the path is empty or too long, and
    /// [`ConfigError::PathTraversal`] if it contains a `..` component.
    pub fn from_file(file: impl AsRef<str>, path: &ConfigPath) -> Result<Self> {
        Ok(Self::FromFile(SecretPath::new(file, path)?))
    }

    /// A short description of where the value lives, safe to print.
    ///
    /// Names the *location*, never the value, because nothing in this crate has ever read the
    /// value to begin with.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::FromEnv(name) => format!("environment variable {}", name.as_str()),
            Self::FromFile(file) => format!("file {}", file.as_str()),
        }
    }
}

/// Renders the location, never a value.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Renders the location, never a value.
///
/// A hand-written `Debug` rather than a derived one, so that adding a variant that *did* hold a
/// value would not silently start printing it.
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromEnv(name) => write!(f, "SecretRef::FromEnv({:?})", name.as_str()),
            Self::FromFile(file) => write!(f, "SecretRef::FromFile({:?})", file.as_str()),
        }
    }
}

impl JsonSchema for SecretRef {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretRef".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["from_env"],
                    "properties": {
                        "from_env": {
                            "type": "string",
                            "maxLength": MAX_ENV_NAME_BYTES,
                            "pattern": "^[A-Za-z_][A-Za-z0-9_]*$",
                        },
                    },
                },
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["from_file"],
                    "properties": {
                        "from_file": {
                            "type": "string",
                            "maxLength": MAX_SECRET_PATH_BYTES,
                        },
                    },
                },
            ],
            "description": "Where a secret's value lives. Never the value itself.",
            "x-brolga-secret": "reference-only",
        })
    }
}

/// A POSIX environment variable name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EnvVarName(String);

impl EnvVarName {
    /// Validate an environment variable name.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the name is empty, longer than
    /// [`MAX_ENV_NAME_BYTES`], starts with a digit, or contains a character outside
    /// `[A-Za-z0-9_]`.
    pub fn new(name: impl AsRef<str>, path: &ConfigPath) -> Result<Self> {
        let name = name.as_ref();

        if name.is_empty() {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: "environment variable name must not be empty".to_owned(),
            });
        }
        if name.len() > MAX_ENV_NAME_BYTES {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: format!(
                    "environment variable name is {} bytes, exceeding the limit of {MAX_ENV_NAME_BYTES}",
                    name.len(),
                ),
            });
        }
        // A name that is not a valid POSIX identifier can never be set by a shell, so accepting it
        // would produce a reference that silently resolves to nothing at run time.
        let valid = name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');

        if !valid {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: format!(
                    "{:?} is not a valid environment variable name; expected [A-Za-z_][A-Za-z0-9_]*",
                    preview(name),
                ),
            });
        }

        Ok(Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvVarName({:?})", self.0)
    }
}

impl<'de> Deserialize<'de> for EnvVarName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw, &ConfigPath::root()).map_err(D::Error::custom)
    }
}

/// A filesystem path to a secret.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SecretPath(String);

impl SecretPath {
    /// Validate a secret file path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the path is empty, longer than
    /// [`MAX_SECRET_PATH_BYTES`], or contains a NUL byte, and [`ConfigError::PathTraversal`] if it
    /// contains a `..` component.
    pub fn new(file: impl AsRef<str>, path: &ConfigPath) -> Result<Self> {
        let file = file.as_ref();

        if file.is_empty() {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: "secret file path must not be empty".to_owned(),
            });
        }
        if file.len() > MAX_SECRET_PATH_BYTES {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: format!(
                    "secret file path is {} bytes, exceeding the limit of {MAX_SECRET_PATH_BYTES}",
                    file.len(),
                ),
            });
        }
        // A NUL truncates the path at the C boundary, so the path Rust validated and the path the
        // kernel opens would not be the same path.
        if file.contains('\0') {
            return Err(ConfigError::Invalid {
                path: path.clone(),
                reason: "secret file path must not contain a NUL byte".to_owned(),
            });
        }
        if has_parent_component(file) {
            return Err(ConfigError::PathTraversal {
                path: path.clone(),
                value: preview(file),
            });
        }

        Ok(Self(file.to_owned()))
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretPath({:?})", self.0)
    }
}

impl<'de> Deserialize<'de> for SecretPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw, &ConfigPath::root()).map_err(D::Error::custom)
    }
}

/// Whether a path contains a `..` component.
///
/// Splits on both separators regardless of platform. A configuration file written on one operating
/// system is read on another often enough that checking only the native separator would leave a
/// gap: `..\\secrets` is a traversal on Windows and would be one long filename on Linux, and the
/// value that matters is the one the *target* system will interpret.
fn has_parent_component(value: &str) -> bool {
    value.split(['/', '\\']).any(|component| component == "..")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn path() -> ConfigPath {
        ConfigPath::new("secrets.token")
    }

    #[test]
    fn a_bare_string_is_not_a_secret_reference() {
        // The rule that matters: an operator cannot paste a value into the config file and have it
        // work. The failure is at parse time, not at use time.
        assert!(serde_json::from_str::<SecretRef>("\"hunter2\"").is_err());
        assert!(serde_yaml_ng::from_str::<SecretRef>("hunter2").is_err());
    }

    #[test]
    fn references_round_trip_in_both_formats() {
        let env = SecretRef::from_env("BROLGA_FEED_TOKEN", &path()).unwrap();
        let file = SecretRef::from_file("/run/secrets/feed-token", &path()).unwrap();

        for reference in [env, file] {
            let json = serde_json::to_string(&reference).unwrap();
            assert_eq!(serde_json::from_str::<SecretRef>(&json).unwrap(), reference);

            let yaml = serde_yaml_ng::to_string(&reference).unwrap();
            assert_eq!(
                serde_yaml_ng::from_str::<SecretRef>(&yaml).unwrap(),
                reference
            );
        }
    }

    #[test]
    fn the_serialised_shape_is_the_documented_one() {
        let reference = SecretRef::from_env("BROLGA_TOKEN", &path()).unwrap();
        assert_eq!(
            serde_json::to_value(&reference).unwrap(),
            serde_json::json!({"from_env": "BROLGA_TOKEN"}),
        );
    }

    #[test]
    fn debug_and_display_name_the_location_and_never_a_value() {
        // These are the paths by which a value reaches a log line, a panic, or a pasted issue.
        for reference in [
            SecretRef::from_env("BROLGA_TOKEN", &path()).unwrap(),
            SecretRef::from_file("/run/secrets/token", &path()).unwrap(),
        ] {
            let debug = format!("{reference:?}");
            let display = format!("{reference}");
            assert!(debug.contains("BROLGA_TOKEN") || debug.contains("/run/secrets/token"));
            assert!(display.contains("environment variable") || display.contains("file"));
        }
    }

    #[test]
    fn environment_variable_names_must_be_usable_by_a_shell() {
        assert!(EnvVarName::new("BROLGA_TOKEN", &path()).is_ok());
        assert!(EnvVarName::new("_private", &path()).is_ok());
        assert!(EnvVarName::new("a1", &path()).is_ok());

        // A name a shell cannot set produces a reference that silently resolves to nothing.
        for hostile in [
            "",
            "1LEADING_DIGIT",
            "has-hyphen",
            "has space",
            "has=equals",
            "PATH;rm -rf /",
            "ÜNICODE",
        ] {
            assert!(
                EnvVarName::new(hostile, &path()).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }

        assert!(EnvVarName::new("A".repeat(MAX_ENV_NAME_BYTES + 1), &path()).is_err());
    }

    #[test]
    fn secret_paths_reject_traversal_on_either_separator() {
        assert!(SecretPath::new("/run/secrets/token", &path()).is_ok());
        assert!(SecretPath::new("secrets/token", &path()).is_ok());
        // A file legitimately named with dots is not a traversal.
        assert!(SecretPath::new("/run/secrets/..token", &path()).is_ok());
        assert!(SecretPath::new("/run/secrets/token..", &path()).is_ok());

        for hostile in [
            "../secrets",
            "/run/../etc/shadow",
            "..\\secrets",
            "C:\\run\\..\\Windows\\System32",
            "a/b/../../../../etc/passwd",
            "..",
        ] {
            assert!(
                matches!(
                    SecretPath::new(hostile, &path()),
                    Err(ConfigError::PathTraversal { .. })
                ),
                "expected {hostile:?} to be rejected as traversal"
            );
        }
    }

    #[test]
    fn secret_paths_reject_a_nul_byte() {
        // The path Rust validates and the path the kernel opens must be the same path.
        assert!(SecretPath::new("/run/secrets/token\u{0}/../../etc/shadow", &path()).is_err());
    }

    #[test]
    fn secret_paths_reject_empty_and_oversized_values() {
        assert!(SecretPath::new("", &path()).is_err());
        assert!(SecretPath::new("a".repeat(MAX_SECRET_PATH_BYTES + 1), &path()).is_err());
    }

    #[test]
    fn deserialisation_enforces_the_same_rules_as_construction() {
        for hostile in [
            r#"{"from_env": "1BAD"}"#,
            r#"{"from_env": ""}"#,
            r#"{"from_env": "has space"}"#,
            r#"{"from_file": "../escape"}"#,
            r#"{"from_file": ""}"#,
            r#"{"from_env": "A", "from_file": "/b"}"#,
            r#"{"inline": "hunter2"}"#,
            r#"{"from_env": "A", "extra": 1}"#,
        ] {
            assert!(
                serde_json::from_str::<SecretRef>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn the_schema_records_that_this_is_a_reference_only() {
        let schema = serde_json::to_value(schemars::schema_for!(SecretRef)).unwrap();
        assert_eq!(
            schema
                .get("x-brolga-secret")
                .and_then(serde_json::Value::as_str),
            Some("reference-only"),
        );
    }

    #[test]
    fn parent_component_detection_is_about_components_not_substrings() {
        assert!(has_parent_component("a/../b"));
        assert!(has_parent_component(".."));
        assert!(has_parent_component("a\\..\\b"));
        assert!(!has_parent_component("a/..b"));
        assert!(!has_parent_component("a/b../c"));
        assert!(!has_parent_component("...."));
    }
}
