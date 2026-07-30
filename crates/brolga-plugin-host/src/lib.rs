//! Capability-limited WebAssembly plugin host.
//!
//! [ADR 0009](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0009-capability-limited-wasm-plugin-host.md)
//! implements [#48](https://github.com/jusso-dev/Brolga/issues/48). The WIT contract and capability
//! vocabulary come from `brolga-plugin-sdk` (ADR 0008).
//!
//! # Default build: no runtime
//!
//! Package validation (manifest, digest, grant intersection, limits) is always available. Instantiating
//! a component requires the `runtime` feature, which pulls in Wasmtime. That is ADR 0001 §3: a
//! default `cargo build` must not compile a WebAssembly engine.
//!
//! # Default sandbox
//!
//! Empty host imports, no WASI, fuel + memory + wall-time caps. Plugin-declared capabilities are a
//! **request**; operator grants are required. Output is always untrusted
//! ([`brolga_plugin_sdk::PLUGIN_OUTPUT_TRUST`]).

#![forbid(unsafe_code)]

pub mod digest;
pub mod error;
pub mod grant;
pub mod limits;
pub mod package;

#[cfg(feature = "runtime")]
pub mod runtime;

pub use digest::{DigestAlgorithm, PluginDigest, digest_bytes};
pub use error::HostError;
pub use grant::{CapabilityGrant, GrantSet};
pub use limits::PluginLimits;
pub use package::{LoadedPackage, PackageIdentity, load_package_dir, load_package_files};

/// Trust level every host result carries for the rest of the pipeline.
pub use brolga_plugin_sdk::PLUGIN_OUTPUT_TRUST;
