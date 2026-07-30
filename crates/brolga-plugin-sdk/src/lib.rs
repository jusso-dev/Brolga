//! Plugin SDK: manifests, capabilities, extension contracts, and the WIT ABI.
//!
//! Added by [ADR 0008](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0008-plugin-sdk-and-wit-abi.md)
//! for [#46](https://github.com/jusso-dev/Brolga/issues/46). This crate is the **types and ABI**,
//! not a runtime. The WebAssembly host is
//! [#48](https://github.com/jusso-dev/Brolga/issues/48).
//!
//! # What this crate is for
//!
//! Portable third-party extension without arbitrary native code or unrestricted host access.
//! Declarative mappings ([#47](https://github.com/jusso-dev/Brolga/issues/47)) already cover the
//! "data not code" path. Plugins cover the path that needs real code — and that code must declare
//! who it is, which ABI it speaks, what it can touch, and how it fails.
//!
//! # The four surfaces
//!
//! - [`manifest`] — versioned document an operator installs and `brolga plugin validate` checks
//! - [`capability`] — closed, scoped vocabulary; empty list means pure compute
//! - [`extension`] / [`contract`] — every extension point has a contract version and serialisable I/O
//! - [`abi`] — the WIT world `brolga:plugin@…` and the invoke envelope
//!
//! # What is deliberately absent
//!
//! - **No WebAssembly runtime.** Loading a component would pull a heavyweight dependency into every
//!   default build, which ADR 0001 §3 forbids until the `plugins` feature lands with the host.
//! - **No native `dlopen`.** The epic's non-goal, and nothing here provides a path.
//! - **No host handles.** No store, transport, policy decision, or filesystem type is reachable
//!   through this crate's public API. That is the acceptance criterion made structural (ADR 0008 §1).
//! - **No policy authority.** A `policy` extension may propose; it cannot clear output (ADR 0007).
//!
//! # Example
//!
//! ```
//! use brolga_plugin_sdk::manifest::PluginManifest;
//!
//! let yaml = r#"
//! schema_version: brolga.plugin.manifest/1.0
//! name: acme.parser.feed
//! version: 1.0.0
//! api: "0.1.0"
//! extension_points:
//!   - kind: parser
//!     contract_version: "1.0"
//!     formats: ["application/x-acme-feed"]
//!     outputs: ["claim"]
//! capabilities: []
//! "#;
//!
//! let manifest = PluginManifest::load(yaml.as_bytes())?;
//! assert!(manifest.capabilities.is_empty());
//! assert_eq!(manifest.name, "acme.parser.feed");
//! # Ok::<(), brolga_plugin_sdk::PluginError>(())
//! ```

#![forbid(unsafe_code)]

pub mod abi;
pub mod capability;
pub mod contract;
pub mod error;
pub mod extension;
pub mod manifest;
pub mod version;

/// Trust level the host must assign to every plugin output (threat model B8).
///
/// Re-exported so plugin authors and host code share one name without inventing a second enum.
pub const PLUGIN_OUTPUT_TRUST: brolga_security::TrustLevel = brolga_security::TrustLevel::Untrusted;

/// Schema-tag helper: records a plugin emits must still carry model `schema_version` values the
/// host re-validates. This constant is the documentation anchor that the SDK does not invent a
/// parallel record schema.
pub const CANONICAL_RECORDS_USE_MODEL_SCHEMAS: &str =
    "plugin parse/export bodies carry brolga-model schema_version tags; the host re-validates";

pub use abi::{
    PLUGIN_ABI_VERSION, PLUGIN_WIT_PACKAGE, WIT_WORLD, InvokeErrorBody, InvokeRequest,
    InvokeResponse,
};
pub use capability::Capability;
pub use contract::{
    ByteBuf, DetectRequest, DetectResponse, ExporterPluginRequest, ExporterPluginResponse,
    ParseRequest, ParseResponse, contract_version,
};
pub use error::PluginError;
pub use extension::ExtensionPoint;
pub use manifest::{ExtensionPointDecl, PluginManifest, MANIFEST_SCHEMA};
pub use version::{ApiVersion, VersionRange};
