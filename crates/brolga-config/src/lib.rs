//! Brolga's layered, declarative configuration.
//!
//! Loads YAML and JSON, merges layers lowest-to-highest, validates every rule, and can explain
//! where each resolved setting came from. It depends on `brolga-model` and nothing else
//! first-party, so the CLI can validate a configuration file without pulling in storage.
//!
//! # Declarative, and only declarative
//!
//! There is no expression, no template, no interpolation, no include, and no command anywhere in
//! the format. That is a deliberate limit, not an unfinished feature: the moment configuration can
//! compute, a configuration file becomes a program, and it runs with Brolga's privileges on behalf
//! of whoever can write to that file.
//!
//! Every struct is `deny_unknown_fields`, so an `exec:` or `command:` key is a parse error naming
//! the path — not a silently ignored line that an operator believes is doing something.
//!
//! # Configuration never contains a secret
//!
//! It contains a *reference* to one. [`SecretRef`] deserialises only from
//! `{ from_env = "NAME" }` or `{ from_file = "/path" }`; a bare string is a parse failure whose
//! message says what to write instead. There is no inline variant to reach for.
//!
//! Nothing in this crate reads an environment variable or opens a secret file. Resolution happens
//! in the component that needs the value, at the moment it needs it, and the value never travels
//! back into a configuration structure — which keeps it out of serialisation, out of `Debug`, and
//! out of logs by construction rather than by discipline.
//!
//! # Hostile input is bounded before it is parsed
//!
//! A configuration file is operator-supplied, which is not the same as trusted: it arrives from a
//! mounted volume, a deployment pipeline, or a repository more people can write to than anyone
//! remembers. Checks run cheapest-first, each *before* the step it protects — size, then YAML
//! anchors, then depth, then shape. See [`load`] for why anchors are rejected outright.
//!
//! # Layers, and why merging happens on values
//!
//! Merging typed structs would mean a field-by-field merge *and* a field-by-field provenance
//! record, and forgetting one is invisible until an operator asks why a setting is what it is.
//! Merging [`serde_json::Value`] means the merge is written once and provenance falls out of it, so
//! adding a setting gets both behaviours for free.
//!
//! # Example
//!
//! ```
//! use brolga_config::layer::LayerId;
//! use brolga_config::load::{parse_layer, Format};
//! use brolga_config::service::explain;
//!
//! // A layer states only what it changes; everything else keeps the value beneath it.
//! let site = parse_layer("site.yaml", "logging:\n  level: debug\n", Format::Yaml)?;
//! let host = parse_layer("host.yaml", "logging:\n  format: json\n", Format::Yaml)?;
//!
//! let explanation = explain(&[site, host])?;
//!
//! // `config explain` answers the question an operator actually has.
//! let level = explanation.get("logging.level").expect("resolved");
//! assert_eq!(level.value, "\"debug\"");
//! assert_eq!(level.source, LayerId::File("site.yaml".to_owned()));
//!
//! // A setting nobody overrode is attributed to the built-in defaults.
//! let timeout = explanation
//!     .get("storage.sqlite.busy_timeout_ms")
//!     .expect("resolved");
//! assert!(timeout.is_default);
//!
//! // The fingerprint identifies the settings, not the route taken to them.
//! assert!(explanation.fingerprint.to_string().starts_with("sha256:"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # What this crate deliberately leaves to others
//!
//! - **A mapping language.** Declarative source-to-canonical mappings arrive in a later milestone.
//!   Nothing here interprets a mapping, and nothing here evaluates anything.
//! - **Compression profiles and ranking.**
//! - **Connector credentials.** The secret *registry* exists so a later milestone can point at a
//!   reference by name; no connector reads one yet.
//! - **Shared resource-limit types.** [`LimitsConfig`] is the operator-facing
//!   configuration of bounds. The types parsers, archives, and connectors share belong to
//!   `brolga-security`.
//! - **Reading files.** This crate parses text and merges values. Deciding *which* files to read,
//!   in what order, is the CLI's job, because that decision is where the operator's intent lives.

#![forbid(unsafe_code)]

pub mod error;
pub mod layer;
pub mod load;
pub mod model;
pub mod schema;
pub mod secret;
pub mod service;

pub use error::{ConfigError, ConfigPath, Diagnostics};
pub use layer::{Attribution, Layer, LayerId};
pub use load::{Format, parse_document, parse_layer};
pub use model::{
    BrolgaConfig, CONFIG_VERSION, LimitsConfig, LogFormat, LogLevel, LoggingConfig, SqliteConfig,
    StorageBackend, StorageConfig,
};
pub use schema::{config_schema, schema_id};
pub use secret::SecretRef;
pub use service::{
    ConfigExplanation, ConfigFingerprint, ExplainedSetting, ResolvedConfig, ValidationReport,
    explain, resolve, validate,
};
