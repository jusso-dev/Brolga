//! The configuration document itself.
//!
//! # Declarative, and only declarative
//!
//! Every value here is data: an enum variant, a bounded number, a path, or a secret *reference*.
//! There is no expression, no template, no interpolation, no include, and no command. That is a
//! deliberate limit rather than an unfinished feature — the moment configuration can compute, a
//! configuration file becomes a program, and a program supplied by whoever can write to that file
//! runs with Brolga's privileges.
//!
//! The shape enforces it. Every struct is `deny_unknown_fields`, so a `command:` or `exec:` key is
//! a parse error naming the offending path rather than a silently ignored line that an operator
//! believes is doing something.
//!
//! # Every numeric setting is bounded on both sides
//!
//! A limit of zero disables a protection; a limit of `u64::MAX` is not a limit. Both are rejected,
//! with the permitted range in the message.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigPath, Diagnostics, preview};
use crate::secret::SecretRef;

/// The configuration format version this build implements.
///
/// A compatibility surface under ADR 0001 §6. A document declaring a different version is rejected
/// rather than interpreted, because a version change means a key was removed, renamed, or retyped.
pub const CONFIG_VERSION: u16 = 1;

/// Maximum number of entries in the secret registry.
pub const MAX_SECRETS: usize = 128;

/// Bounds for a `u64` setting, used to keep the check and the diagnostic in one place.
struct Bounds {
    min: u64,
    max: u64,
}

impl Bounds {
    const fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    fn check(&self, path: &ConfigPath, value: u64, diagnostics: &mut Diagnostics) {
        if value < self.min || value > self.max {
            diagnostics.push(ConfigError::OutOfRange {
                path: path.clone(),
                value,
                min: self.min,
                max: self.max,
            });
        }
    }
}

/// A resolved Brolga configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrolgaConfig {
    /// Format version. Must equal [`CONFIG_VERSION`].
    pub version: u16,
    /// Where canonical records are persisted.
    pub storage: StorageConfig,
    /// Bounds applied to untrusted input.
    pub limits: LimitsConfig,
    /// Diagnostic output.
    pub logging: LoggingConfig,
    /// Named secret *references*, resolved by whichever component needs them.
    ///
    /// A registry rather than secrets attached to the things that use them, because the things that
    /// use them — connectors, model providers — do not exist yet. Naming them here lets an operator
    /// declare a reference now and lets a later milestone point at it by name without moving it.
    pub secrets: BTreeMap<String, SecretRef>,
}

/// Where canonical records are persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Which backend to use.
    pub backend: StorageBackend,
    /// Settings for the SQLite backend.
    pub sqlite: SqliteConfig,
}

/// The persistence backend.
///
/// One variant today. It is an enum rather than an implied default so that adding PostgreSQL is an
/// additive change to a surface that already exists, rather than the introduction of a choice where
/// operators had learned there was none.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StorageBackend {
    /// Local SQLite database.
    Sqlite,
}

/// SQLite backend settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    /// Database file path.
    pub path: String,
    /// How long to wait for a competing writer before giving up, in milliseconds.
    pub busy_timeout_ms: u64,
}

impl SqliteConfig {
    const BUSY_TIMEOUT: Bounds = Bounds::new(100, 300_000);
}

/// Bounds applied to untrusted input.
///
/// Shared limits for parsers, archives, and connectors are `brolga-security`'s job in
/// [#8](https://github.com/jusso-dev/Brolga/issues/8). What lives here is the operator-facing
/// *configuration* of those bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest single input document Brolga will read, in bytes.
    pub max_input_bytes: u64,
    /// Deepest structure Brolga will descend into.
    pub max_nesting_depth: u64,
    /// Most records accepted from one import.
    pub max_records_per_import: u64,
    /// Wall-clock limit for one operation, in seconds.
    pub operation_timeout_seconds: u64,
}

impl LimitsConfig {
    const MAX_INPUT_BYTES: Bounds = Bounds::new(1024, 1024 * 1024 * 1024);
    const MAX_NESTING_DEPTH: Bounds = Bounds::new(1, 1024);
    const MAX_RECORDS_PER_IMPORT: Bounds = Bounds::new(1, 100_000_000);
    const OPERATION_TIMEOUT_SECONDS: Bounds = Bounds::new(1, 86_400);
}

/// Diagnostic output settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum severity to emit.
    pub level: LogLevel,
    /// How log lines are rendered.
    pub format: LogFormat,
}

/// Minimum severity to emit.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Normal operational messages.
    Info,
    /// Detailed messages for diagnosing a problem.
    Debug,
    /// Everything, including per-record detail.
    ///
    /// Verbose enough that operators should assume the output is sensitive. It still never contains
    /// a secret value or a source body — those are prohibited everywhere, not merely at lower
    /// levels — but it does reveal which records were processed and in what order.
    Trace,
}

/// How log lines are rendered.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LogFormat {
    /// Human-readable single lines.
    Text,
    /// One JSON object per line.
    Json,
}

impl BrolgaConfig {
    /// The default configuration, as a JSON value.
    ///
    /// Returned as a value rather than a struct because defaults are applied as the *lowest layer*
    /// of the merge, which is what lets `config explain` say "this came from the defaults" without
    /// a second mechanism for tracking it.
    #[must_use]
    pub fn defaults_value() -> serde_json::Value {
        serde_json::json!({
            "version": CONFIG_VERSION,
            "storage": {
                "backend": "sqlite",
                "sqlite": {
                    "path": "brolga.sqlite",
                    "busy_timeout_ms": 5000,
                },
            },
            "limits": {
                // 64 MiB: comfortably larger than a real STIX bundle, far smaller than a machine.
                "max_input_bytes": 67_108_864,
                "max_nesting_depth": 64,
                "max_records_per_import": 1_000_000,
                "operation_timeout_seconds": 300,
            },
            "logging": {
                "level": "info",
                "format": "text",
            },
            "secrets": {},
        })
    }

    /// The default configuration.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: [`Self::defaults_value`] is a literal that this crate's
    /// `defaults_are_valid` test deserialises and validates on every run, so a malformed default is
    /// a failing test rather than a run-time surprise. The fallible path is still handled rather
    /// than unwrapped.
    ///
    /// # Errors
    ///
    /// Returns diagnostics if the built-in defaults do not satisfy their own validation, which
    /// would be a bug in this crate rather than in an operator's file.
    pub fn defaults() -> core::result::Result<Self, Diagnostics> {
        let value = Self::defaults_value();
        let config: Self = serde_json::from_value(value).map_err(|error| {
            let mut diagnostics = Diagnostics::new();
            diagnostics.push(ConfigError::Invalid {
                path: ConfigPath::root(),
                reason: format!("built-in defaults are malformed: {error}"),
            });
            diagnostics
        })?;
        config.validated()
    }

    /// Check every semantic rule, collecting *all* problems rather than stopping at the first.
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostics`] listing every rule the configuration breaks, each naming its path.
    pub fn validated(self) -> core::result::Result<Self, Diagnostics> {
        let mut diagnostics = Diagnostics::new();
        self.validate_into(&mut diagnostics);
        if diagnostics.is_empty() {
            Ok(self)
        } else {
            Err(diagnostics)
        }
    }

    /// Record every semantic problem into `diagnostics`.
    pub fn validate_into(&self, diagnostics: &mut Diagnostics) {
        if self.version != CONFIG_VERSION {
            diagnostics.push(ConfigError::UnsupportedVersion {
                expected: CONFIG_VERSION,
                found: self.version,
            });
        }

        let storage = ConfigPath::new("storage");
        let sqlite = storage.child("sqlite");

        validate_path_setting(
            &sqlite.child("path"),
            &self.storage.sqlite.path,
            diagnostics,
        );
        SqliteConfig::BUSY_TIMEOUT.check(
            &sqlite.child("busy_timeout_ms"),
            self.storage.sqlite.busy_timeout_ms,
            diagnostics,
        );

        let limits = ConfigPath::new("limits");
        LimitsConfig::MAX_INPUT_BYTES.check(
            &limits.child("max_input_bytes"),
            self.limits.max_input_bytes,
            diagnostics,
        );
        LimitsConfig::MAX_NESTING_DEPTH.check(
            &limits.child("max_nesting_depth"),
            self.limits.max_nesting_depth,
            diagnostics,
        );
        LimitsConfig::MAX_RECORDS_PER_IMPORT.check(
            &limits.child("max_records_per_import"),
            self.limits.max_records_per_import,
            diagnostics,
        );
        LimitsConfig::OPERATION_TIMEOUT_SECONDS.check(
            &limits.child("operation_timeout_seconds"),
            self.limits.operation_timeout_seconds,
            diagnostics,
        );

        let secrets = ConfigPath::new("secrets");
        if self.secrets.len() > MAX_SECRETS {
            diagnostics.push(ConfigError::Invalid {
                path: secrets.clone(),
                reason: format!(
                    "{} secret references exceed the limit of {MAX_SECRETS}",
                    self.secrets.len(),
                ),
            });
        }
        for name in self.secrets.keys() {
            if name.is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                diagnostics.push(ConfigError::Invalid {
                    path: secrets.child(name),
                    reason: format!(
                        "{:?} is not a usable secret name; expected letters, digits, hyphen, and underscore",
                        preview(name),
                    ),
                });
            }
        }
    }
}

/// Reject a configured filesystem path that could escape where the operator meant it to be.
fn validate_path_setting(path: &ConfigPath, value: &str, diagnostics: &mut Diagnostics) {
    if value.is_empty() {
        diagnostics.push(ConfigError::Invalid {
            path: path.clone(),
            reason: "path must not be empty".to_owned(),
        });
        return;
    }
    if value.contains('\0') {
        diagnostics.push(ConfigError::Invalid {
            path: path.clone(),
            reason: "path must not contain a NUL byte".to_owned(),
        });
        return;
    }
    // Both separators, whatever the host: a configuration file written on one platform is read on
    // another often enough that the value that matters is the one the target will interpret.
    if value.split(['/', '\\']).any(|component| component == "..") {
        diagnostics.push(ConfigError::PathTraversal {
            path: path.clone(),
            value: preview(value),
        });
    }
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

    fn defaults() -> BrolgaConfig {
        BrolgaConfig::defaults().expect("built-in defaults must be valid")
    }

    #[test]
    fn defaults_are_valid() {
        // If this fails, the shipped defaults break their own rules — a bug here, not in a file an
        // operator wrote.
        let config = defaults();
        assert_eq!(config.version, CONFIG_VERSION);
        assert_eq!(config.storage.backend, StorageBackend::Sqlite);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert!(config.secrets.is_empty());
    }

    #[test]
    fn defaults_are_lean_and_offline() {
        // ADR 0001 §3: a default build is offline and deterministic. Nothing in the default
        // configuration reaches a network or enables an optional subsystem.
        let value = BrolgaConfig::defaults_value().to_string();
        for forbidden in [
            "http", "https", "://", "postgres", "mcp", "plugin", "llm", "model",
        ] {
            assert!(
                !value.contains(forbidden),
                "default configuration mentions {forbidden:?}: {value}"
            );
        }
    }

    #[test]
    fn every_semantic_problem_is_reported_not_just_the_first() {
        // An operator fixing one error per run is an operator running the tool six times to learn
        // six things it knew on the first.
        let mut config = defaults();
        config.limits.max_input_bytes = 0;
        config.limits.max_nesting_depth = 0;
        config.limits.operation_timeout_seconds = 0;
        config.storage.sqlite.busy_timeout_ms = 1;

        let diagnostics = config.validated().unwrap_err();
        assert_eq!(diagnostics.len(), 4, "{diagnostics}");
        for error in diagnostics.as_slice() {
            assert!(matches!(error, ConfigError::OutOfRange { .. }), "{error:?}");
            assert!(error.path().is_some());
        }
    }

    #[test]
    fn a_limit_of_zero_is_rejected_because_it_disables_a_protection() {
        let mut config = defaults();
        config.limits.max_input_bytes = 0;
        let diagnostics = config.validated().unwrap_err();
        assert!(
            diagnostics.as_slice().iter().any(|error| error
                .path()
                .is_some_and(|path| path.as_str() == "limits.max_input_bytes")),
            "{diagnostics}"
        );
    }

    #[test]
    fn an_unbounded_limit_is_rejected_because_it_is_not_a_limit() {
        let mut config = defaults();
        config.limits.max_input_bytes = u64::MAX;
        assert!(config.validated().is_err());
    }

    #[test]
    fn limits_accept_their_documented_boundaries() {
        let mut config = defaults();
        config.limits.max_input_bytes = LimitsConfig::MAX_INPUT_BYTES.min;
        config.limits.max_nesting_depth = LimitsConfig::MAX_NESTING_DEPTH.max;
        config.limits.operation_timeout_seconds = LimitsConfig::OPERATION_TIMEOUT_SECONDS.max;
        config.storage.sqlite.busy_timeout_ms = SqliteConfig::BUSY_TIMEOUT.min;
        assert!(config.validated().is_ok());
    }

    #[test]
    fn a_database_path_cannot_escape_with_a_traversal() {
        for hostile in ["../../etc/brolga.sqlite", "..\\..\\brolga.sqlite", ".."] {
            let mut config = defaults();
            config.storage.sqlite.path = hostile.to_owned();
            let diagnostics = config.validated().unwrap_err();
            assert!(
                diagnostics
                    .as_slice()
                    .iter()
                    .any(|error| matches!(error, ConfigError::PathTraversal { .. })),
                "expected {hostile:?} to be rejected: {diagnostics}"
            );
        }
    }

    #[test]
    fn a_database_path_may_contain_dots_that_are_not_a_traversal() {
        let mut config = defaults();
        config.storage.sqlite.path = "data/..hidden/brolga..sqlite".to_owned();
        assert!(config.validated().is_ok());
    }

    #[test]
    fn a_version_this_build_cannot_interpret_is_rejected() {
        let mut config = defaults();
        config.version = CONFIG_VERSION + 1;
        let diagnostics = config.validated().unwrap_err();
        assert!(
            matches!(
                diagnostics.first(),
                Some(ConfigError::UnsupportedVersion { .. })
            ),
            "{diagnostics}"
        );
    }

    #[test]
    fn configuration_cannot_express_a_command() {
        // The declarative guarantee, tested rather than asserted: there is no key that runs
        // anything, and an attempt to add one is a parse error naming the path.
        for hostile in [
            r#"{"version":1,"command":"rm -rf /","storage":{},"limits":{},"logging":{},"secrets":{}}"#,
            r#"{"version":1,"storage":{"exec":"sh -c evil","backend":"sqlite","sqlite":{"path":"a","busy_timeout_ms":1000}},"limits":{"max_input_bytes":1024,"max_nesting_depth":1,"max_records_per_import":1,"operation_timeout_seconds":1},"logging":{"level":"info","format":"text"},"secrets":{}}"#,
        ] {
            let error = serde_json::from_str::<BrolgaConfig>(hostile).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "expected an unknown-field error, got: {error}"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected_rather_than_ignored() {
        // A silently ignored key is a setting the operator believes is in force and is not.
        let json = serde_json::to_value(defaults()).unwrap();
        let mut with_typo = json.clone();
        with_typo["storage"]["backedn"] = serde_json::json!("sqlite");
        assert!(serde_json::from_value::<BrolgaConfig>(with_typo).is_err());

        let mut top_level = json;
        top_level["loging"] = serde_json::json!({});
        assert!(serde_json::from_value::<BrolgaConfig>(top_level).is_err());
    }

    #[test]
    fn secret_names_must_be_usable_as_identifiers() {
        let mut config = defaults();
        config.secrets.insert(
            "feed token".to_owned(),
            SecretRef::from_env("A", &ConfigPath::root()).unwrap(),
        );
        let diagnostics = config.validated().unwrap_err();
        assert!(
            diagnostics.as_slice().iter().any(|error| error
                .path()
                .is_some_and(|path| path.as_str().starts_with("secrets."))),
            "{diagnostics}"
        );
    }

    #[test]
    fn the_secret_registry_is_bounded() {
        let mut config = defaults();
        for index in 0..=MAX_SECRETS {
            config.secrets.insert(
                format!("s{index}"),
                SecretRef::from_env("A", &ConfigPath::root()).unwrap(),
            );
        }
        assert!(config.validated().is_err());
    }

    #[test]
    fn round_trips_through_json_and_yaml() {
        let config = defaults();

        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(serde_json::from_str::<BrolgaConfig>(&json).unwrap(), config);

        let yaml = serde_yaml_ng::to_string(&config).unwrap();
        assert_eq!(
            serde_yaml_ng::from_str::<BrolgaConfig>(&yaml).unwrap(),
            config
        );
    }

    #[test]
    fn a_configuration_holding_a_secret_reference_round_trips_without_a_value() {
        let mut config = defaults();
        config.secrets.insert(
            "feed_token".to_owned(),
            SecretRef::from_env("BROLGA_FEED_TOKEN", &ConfigPath::root()).unwrap(),
        );

        let serialised = serde_json::to_string(&config).unwrap();
        assert!(serialised.contains("BROLGA_FEED_TOKEN"));
        assert!(!serialised.contains("hunter2"));
        assert_eq!(
            serde_json::from_str::<BrolgaConfig>(&serialised).unwrap(),
            config
        );
    }
}
