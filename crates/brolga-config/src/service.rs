//! The `config validate` and `config explain` application services, and the configuration
//! fingerprint.
//!
//! These are the operations the CLI will call. They live here rather than in the CLI so that the
//! HTTP API and the MCP server get the same answers later, and so that the behaviour is testable
//! without a process.
//!
//! # The fingerprint identifies the configuration, not the run
//!
//! [`ConfigFingerprint`] is a digest of the *resolved* configuration. It does not include which
//! layer supplied a value, the file paths involved, or when it was loaded — two deployments that
//! reach the same settings by different routes fingerprint identically, which is what makes it
//! usable for "was this pack produced under the same configuration".
//!
//! It contains no secret value, because no secret value ever enters a configuration structure. It
//! does cover secret *references*, since changing which environment variable a token is read from
//! is a change to the configuration.

use brolga_model::provenance::ContentHash;
use serde::Serialize;

use crate::error::{ConfigError, ConfigPath, Diagnostics, Result};
use crate::layer::{Attribution, Layer, LayerId, merge_layers};
use crate::load::deserialize_typed;
use crate::model::BrolgaConfig;

/// A deterministic identifier for a resolved configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConfigFingerprint(ContentHash);

impl ConfigFingerprint {
    /// Compute the fingerprint of a resolved configuration.
    ///
    /// Hashes the canonical JSON encoding. `serde_json` orders object keys, so the encoding depends
    /// on the configuration's *content* and not on the order an operator happened to write it, the
    /// format the file used, or which layer each value came from.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if the configuration cannot be encoded, which would be a
    /// bug in this crate rather than in an operator's file.
    pub fn of(config: &BrolgaConfig) -> Result<Self> {
        let canonical = serde_json::to_vec(config).map_err(|error| ConfigError::Invalid {
            path: ConfigPath::root(),
            reason: format!("configuration could not be encoded for fingerprinting: {error}"),
        })?;
        Ok(Self(ContentHash::of(&canonical)))
    }

    /// The underlying digest.
    #[must_use]
    pub const fn as_content_hash(&self) -> &ContentHash {
        &self.0
    }

    /// A short prefix, for a log line or a table where the full digest would not fit.
    ///
    /// Use the full digest for any comparison. This is for a human's eyes, and a truncated digest
    /// is not a digest.
    #[must_use]
    pub fn short(&self) -> String {
        self.0.to_hex().chars().take(12).collect()
    }
}

impl core::fmt::Display for ConfigFingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

/// A configuration that loaded, validated, and knows where each of its settings came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// The validated settings.
    pub config: BrolgaConfig,
    /// Which layer supplied each setting.
    pub attribution: Attribution,
    /// A deterministic identifier for the settings.
    pub fingerprint: ConfigFingerprint,
}

/// Load, merge, and validate a stack of layers.
///
/// Brolga's built-in defaults are inserted beneath everything the caller supplies, so a partial
/// file is enough and every unmentioned setting is attributed to `defaults` rather than appearing
/// out of nowhere.
///
/// # Errors
///
/// Returns [`Diagnostics`] listing every problem found. Shape errors are reported per layer, so a
/// typo is attributed to the file it came from rather than to the merged result.
pub fn resolve(layers: &[Layer]) -> core::result::Result<ResolvedConfig, Diagnostics> {
    let mut diagnostics = Diagnostics::new();

    // Check each layer's shape on its own first. Merging first would report a typo against the
    // merged document, which is not a file anybody can open.
    for layer in layers {
        if let Err(error) = deserialize_typed::<PartialCheck>(&layer.values) {
            diagnostics.push(attribute(error, &layer.id));
        }
    }

    let mut all_layers = Vec::with_capacity(layers.len().saturating_add(1));
    all_layers.push(Layer::new(
        LayerId::Defaults,
        BrolgaConfig::defaults_value(),
    ));
    all_layers.extend_from_slice(layers);

    let (merged, attribution) = merge_layers(&all_layers);

    let config = match deserialize_typed::<BrolgaConfig>(&merged) {
        Ok(config) => config,
        Err(error) => {
            diagnostics.push(error);
            return Err(diagnostics);
        }
    };

    config.validate_into(&mut diagnostics);

    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    let fingerprint = ConfigFingerprint::of(&config).map_err(|error| {
        let mut diagnostics = Diagnostics::new();
        diagnostics.push(error);
        diagnostics
    })?;

    Ok(ResolvedConfig {
        config,
        attribution,
        fingerprint,
    })
}

/// The `config validate` service.
///
/// Returns every problem rather than the first, so one run tells an operator everything that is
/// wrong with their file.
///
/// # Errors
///
/// Returns [`Diagnostics`] if the configuration does not load or does not validate.
pub fn validate(layers: &[Layer]) -> core::result::Result<ValidationReport, Diagnostics> {
    let resolved = resolve(layers)?;
    Ok(ValidationReport {
        fingerprint: resolved.fingerprint,
        settings: resolved.attribution.len(),
        layers: layers.iter().map(|layer| layer.id.clone()).collect(),
    })
}

/// What `config validate` reports on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Identifier for the resolved settings.
    pub fingerprint: ConfigFingerprint,
    /// How many settings were resolved.
    pub settings: usize,
    /// Which layers were considered, excluding the built-in defaults.
    pub layers: Vec<LayerId>,
}

/// One line of `config explain` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainedSetting {
    /// Dotted path to the setting.
    pub path: String,
    /// The resolved value, rendered as JSON.
    ///
    /// For a secret this is the *reference* — the environment variable name or file path — because
    /// that is all the configuration has ever held.
    pub value: String,
    /// Which layer supplied it.
    pub source: LayerId,
    /// Whether the value came from Brolga's built-in defaults.
    pub is_default: bool,
}

/// The `config explain` service.
///
/// Answers "why is this setting what it is" for every setting, which is the question an operator
/// actually has when a layered configuration surprises them.
///
/// # Errors
///
/// Returns [`Diagnostics`] if the configuration does not load or does not validate. There is
/// nothing useful to explain about a configuration that is not valid, and explaining it anyway
/// would describe a state Brolga would never run in.
pub fn explain(layers: &[Layer]) -> core::result::Result<ConfigExplanation, Diagnostics> {
    let resolved = resolve(layers)?;

    let encoded = serde_json::to_value(&resolved.config).map_err(|error| {
        let mut diagnostics = Diagnostics::new();
        diagnostics.push(ConfigError::Invalid {
            path: ConfigPath::root(),
            reason: format!("configuration could not be encoded for explanation: {error}"),
        });
        diagnostics
    })?;

    let mut settings = Vec::new();
    collect_leaves(&encoded, &ConfigPath::root(), &mut settings);

    let explained = settings
        .into_iter()
        .map(|(path, value)| {
            let source = resolved
                .attribution
                .source_of(&path)
                .cloned()
                .unwrap_or(LayerId::Defaults);
            ExplainedSetting {
                is_default: source == LayerId::Defaults,
                path,
                value,
                source,
            }
        })
        .collect();

    Ok(ConfigExplanation {
        settings: explained,
        fingerprint: resolved.fingerprint,
    })
}

/// What `config explain` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigExplanation {
    /// Every resolved setting, in deterministic path order.
    pub settings: Vec<ExplainedSetting>,
    /// Identifier for the resolved settings.
    pub fingerprint: ConfigFingerprint,
}

impl ConfigExplanation {
    /// The settings an operator changed from the defaults.
    ///
    /// Usually the interesting half: it is a short list, and it is where a surprising behaviour
    /// almost always comes from.
    pub fn overridden(&self) -> impl Iterator<Item = &ExplainedSetting> {
        self.settings.iter().filter(|setting| !setting.is_default)
    }

    /// Look up one setting.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&ExplainedSetting> {
        self.settings.iter().find(|setting| setting.path == path)
    }
}

/// Walk a JSON value, collecting `(dotted path, rendered value)` for every leaf.
fn collect_leaves(value: &serde_json::Value, path: &ConfigPath, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                collect_leaves(child, &path.child(key), out);
            }
        }
        other => out.push((path.as_str().to_owned(), other.to_string())),
    }
}

/// Note which layer a shape error came from, so the operator knows which file to open.
fn attribute(error: ConfigError, layer: &LayerId) -> ConfigError {
    match error {
        ConfigError::UnknownField {
            path,
            field,
            suggestion,
        } => ConfigError::UnknownField {
            path: ConfigPath::new(format!("{} [{}]", path.as_str(), layer.label())),
            field,
            suggestion,
        },
        ConfigError::Invalid { path, reason } => ConfigError::Invalid {
            path: ConfigPath::new(format!("{} [{}]", path.as_str(), layer.label())),
            reason,
        },
        // A layer is a *partial* document, so a missing field is expected and is not an error at
        // this stage. It is caught after merging, against the complete document.
        other => other,
    }
}

/// A permissive mirror of [`BrolgaConfig`] used to check one layer's shape.
///
/// Every field is optional, because a layer is a partial document, but `deny_unknown_fields` still
/// applies at every level — which is the whole point: a typo is caught in the file that contains
/// it, not in a merged document that exists only in memory.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialCheck {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u16>,
    #[serde(default)]
    #[allow(dead_code)]
    storage: Option<PartialStorage>,
    #[serde(default)]
    #[allow(dead_code)]
    limits: Option<PartialLimits>,
    #[serde(default)]
    #[allow(dead_code)]
    logging: Option<PartialLogging>,
    #[serde(default)]
    #[allow(dead_code)]
    secrets: Option<std::collections::BTreeMap<String, crate::secret::SecretRef>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialStorage {
    #[serde(default)]
    #[allow(dead_code)]
    backend: Option<crate::model::StorageBackend>,
    #[serde(default)]
    #[allow(dead_code)]
    sqlite: Option<PartialSqlite>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialSqlite {
    #[serde(default)]
    #[allow(dead_code)]
    path: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    busy_timeout_ms: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialLimits {
    #[serde(default)]
    #[allow(dead_code)]
    max_input_bytes: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    max_nesting_depth: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    max_records_per_import: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    operation_timeout_seconds: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialLogging {
    #[serde(default)]
    #[allow(dead_code)]
    level: Option<crate::model::LogLevel>,
    #[serde(default)]
    #[allow(dead_code)]
    format: Option<crate::model::LogFormat>,
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
    use crate::load::{Format, parse_layer};

    fn layer(name: &str, yaml: &str) -> Layer {
        parse_layer(name, yaml, Format::Yaml).expect("test fixture must parse")
    }

    #[test]
    fn an_empty_layer_stack_resolves_to_the_defaults() {
        let resolved = resolve(&[]).unwrap();
        assert_eq!(resolved.config, BrolgaConfig::defaults().unwrap());
        assert!(
            resolved
                .attribution
                .iter()
                .all(|(_, source)| *source == LayerId::Defaults)
        );
    }

    #[test]
    fn a_partial_file_only_has_to_mention_what_it_changes() {
        let resolved = resolve(&[layer("brolga.yaml", "logging:\n  level: debug\n")]).unwrap();
        assert_eq!(resolved.config.logging.level, crate::model::LogLevel::Debug);
        // Everything it did not mention is still there.
        assert_eq!(
            resolved.config.logging.format,
            crate::model::LogFormat::Text
        );
        assert_eq!(resolved.config.storage.sqlite.busy_timeout_ms, 5000);
    }

    #[test]
    fn the_fingerprint_depends_on_content_and_not_on_route() {
        // Two deployments reaching the same settings by different routes must fingerprint the same,
        // or the fingerprint answers a question nobody asked.
        let one = resolve(&[layer("a.yaml", "logging:\n  level: debug\n")]).unwrap();
        let two = resolve(&[
            layer("b.yaml", "logging:\n  level: trace\n"),
            layer("c.yaml", "logging:\n  level: debug\n"),
        ])
        .unwrap();

        assert_eq!(one.fingerprint, two.fingerprint);
        assert_ne!(one.attribution, two.attribution, "the routes did differ");
    }

    #[test]
    fn the_fingerprint_is_stable_across_runs_and_formats() {
        let yaml = resolve(&[layer("a.yaml", "logging:\n  level: debug\n")]).unwrap();
        let json = resolve(&[crate::load::parse_layer(
            "a.json",
            r#"{"logging": {"level": "debug"}}"#,
            Format::Json,
        )
        .unwrap()])
        .unwrap();

        assert_eq!(yaml.fingerprint, json.fingerprint);
        assert_eq!(
            yaml.fingerprint,
            resolve(&[layer("a.yaml", "logging:\n  level: debug\n")])
                .unwrap()
                .fingerprint,
        );
    }

    #[test]
    fn the_fingerprint_does_not_depend_on_key_order_in_the_file() {
        let one = resolve(&[layer(
            "a.yaml",
            "logging:\n  level: debug\n  format: json\n",
        )])
        .unwrap();
        let two = resolve(&[layer(
            "a.yaml",
            "logging:\n  format: json\n  level: debug\n",
        )])
        .unwrap();
        assert_eq!(one.fingerprint, two.fingerprint);
    }

    #[test]
    fn changing_any_setting_changes_the_fingerprint() {
        let base = resolve(&[]).unwrap().fingerprint;
        for change in [
            "logging:\n  level: debug\n",
            "storage:\n  sqlite:\n    path: other.sqlite\n",
            "limits:\n  max_input_bytes: 2048\n",
            "secrets:\n  token:\n    from_env: BROLGA_TOKEN\n",
        ] {
            assert_ne!(
                base,
                resolve(&[layer("a.yaml", change)]).unwrap().fingerprint,
                "changing {change:?} did not move the fingerprint"
            );
        }
    }

    #[test]
    fn changing_which_variable_a_secret_reads_changes_the_fingerprint() {
        // The value is not in the configuration, but which variable it comes from is a setting.
        let one = resolve(&[layer(
            "a.yaml",
            "secrets:\n  token:\n    from_env: TOKEN_A\n",
        )])
        .unwrap();
        let two = resolve(&[layer(
            "a.yaml",
            "secrets:\n  token:\n    from_env: TOKEN_B\n",
        )])
        .unwrap();
        assert_ne!(one.fingerprint, two.fingerprint);
    }

    #[test]
    fn a_short_fingerprint_is_for_humans_only() {
        let fingerprint = resolve(&[]).unwrap().fingerprint;
        assert_eq!(fingerprint.short().len(), 12);
        assert!(fingerprint.to_string().starts_with("sha256:"));
        assert!(fingerprint.to_string().contains(&fingerprint.short()));
    }

    #[test]
    fn explain_says_which_layer_supplied_each_setting() {
        // The question an operator actually has when a layered configuration surprises them.
        let explanation = explain(&[
            layer("site.yaml", "logging:\n  level: debug\n"),
            layer("host.yaml", "logging:\n  format: json\n"),
        ])
        .unwrap();

        let level = explanation.get("logging.level").unwrap();
        assert_eq!(level.value, "\"debug\"");
        assert_eq!(level.source, LayerId::File("site.yaml".to_owned()));
        assert!(!level.is_default);

        let format = explanation.get("logging.format").unwrap();
        assert_eq!(format.source, LayerId::File("host.yaml".to_owned()));

        let untouched = explanation.get("storage.sqlite.busy_timeout_ms").unwrap();
        assert_eq!(untouched.source, LayerId::Defaults);
        assert!(untouched.is_default);
    }

    #[test]
    fn explain_can_list_only_what_the_operator_changed() {
        let explanation = explain(&[layer("a.yaml", "logging:\n  level: debug\n")]).unwrap();
        let overridden: Vec<_> = explanation.overridden().collect();
        assert_eq!(overridden.len(), 1);
        assert_eq!(
            overridden.first().map(|setting| setting.path.as_str()),
            Some("logging.level")
        );
    }

    #[test]
    fn explain_shows_a_secret_reference_and_never_a_value() {
        let explanation = explain(&[layer(
            "a.yaml",
            "secrets:\n  feed_token:\n    from_env: BROLGA_FEED_TOKEN\n",
        )])
        .unwrap();

        let setting = explanation.get("secrets.feed_token.from_env").unwrap();
        assert_eq!(setting.value, "\"BROLGA_FEED_TOKEN\"");

        // Whatever the variable holds, the explanation only ever names where to look.
        let rendered = format!("{:?}", explanation.settings);
        assert!(rendered.contains("BROLGA_FEED_TOKEN"));
        assert!(!rendered.to_lowercase().contains("hunter2"));
    }

    #[test]
    fn explain_output_is_in_deterministic_path_order() {
        let build = || {
            explain(&[layer("a.yaml", "logging:\n  level: debug\n")])
                .unwrap()
                .settings
                .into_iter()
                .map(|setting| setting.path)
                .collect::<Vec<_>>()
        };
        let paths = build();
        assert_eq!(paths, build());

        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn a_typo_is_attributed_to_the_file_that_contains_it() {
        // Reporting it against the merged document would name something nobody can open.
        let diagnostics = resolve(&[
            layer("good.yaml", "logging:\n  level: debug\n"),
            layer("bad.yaml", "logging:\n  levle: debug\n"),
        ])
        .unwrap_err();

        let rendered = diagnostics.to_string();
        assert!(rendered.contains("bad.yaml"), "{rendered}");
        assert!(!rendered.contains("good.yaml"), "{rendered}");
        assert!(rendered.contains("levle"), "{rendered}");
        assert!(rendered.contains("did you mean \"level\""), "{rendered}");
    }

    #[test]
    fn validation_reports_every_problem_in_one_run() {
        let diagnostics = resolve(&[layer(
            "a.yaml",
            "limits:\n  max_input_bytes: 0\n  max_nesting_depth: 0\n  operation_timeout_seconds: 0\n",
        )])
        .unwrap_err();
        assert_eq!(diagnostics.len(), 3, "{diagnostics}");
    }

    #[test]
    fn a_valid_configuration_reports_its_fingerprint_and_layers() {
        let layers = vec![layer("a.yaml", "logging:\n  level: debug\n")];
        let report = validate(&layers).unwrap();
        assert_eq!(report.layers, vec![LayerId::File("a.yaml".to_owned())]);
        assert!(report.settings > 0);
        assert_eq!(report.fingerprint, resolve(&layers).unwrap().fingerprint);
    }

    #[test]
    fn explain_refuses_to_describe_an_invalid_configuration() {
        // Describing it would document a state Brolga would never run in.
        assert!(explain(&[layer("a.yaml", "limits:\n  max_input_bytes: 0\n")]).is_err());
    }

    #[test]
    fn a_later_layer_can_override_an_earlier_one_at_any_depth() {
        let resolved = resolve(&[
            layer("a.yaml", "storage:\n  sqlite:\n    path: a.sqlite\n"),
            layer("b.yaml", "storage:\n  sqlite:\n    busy_timeout_ms: 1000\n"),
        ])
        .unwrap();

        assert_eq!(resolved.config.storage.sqlite.path, "a.sqlite");
        assert_eq!(resolved.config.storage.sqlite.busy_timeout_ms, 1000);
        assert_eq!(
            resolved.attribution.source_of("storage.sqlite.path"),
            Some(&LayerId::File("a.yaml".to_owned())),
        );
        assert_eq!(
            resolved
                .attribution
                .source_of("storage.sqlite.busy_timeout_ms"),
            Some(&LayerId::File("b.yaml".to_owned())),
        );
    }
}
