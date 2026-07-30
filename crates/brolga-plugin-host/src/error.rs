//! Host errors: load-time and call-time failures that never unwind past the host API.

use thiserror::Error;

/// What went wrong loading or calling a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum HostError {
    /// I/O on the package path.
    #[error("plugin package I/O: {0}")]
    Io(String),

    /// Manifest failed SDK validation.
    #[error("plugin manifest: {0}")]
    Manifest(String),

    /// Declared content digest does not match the component bytes.
    #[error(
        "plugin component digest mismatch: expected {algorithm}:{expected}, got {algorithm}:{found}"
    )]
    DigestMismatch {
        /// Algorithm name.
        algorithm: String,
        /// Expected hex digest.
        expected: String,
        /// Computed hex digest.
        found: String,
    },

    /// Plugin requested a capability the operator did not grant.
    #[error("plugin capability not granted: {reason}")]
    CapabilityDenied {
        /// Why.
        reason: String,
    },

    /// Package is fine to inspect, but this build has no Wasmtime (`runtime` feature off).
    #[error(
        "plugin execution requires the `plugins`/`runtime` feature; this build can only validate packages"
    )]
    RuntimeDisabled,

    /// Component bytes are not a loadable Wasm component.
    #[error("plugin component refused: {reason}")]
    Component {
        /// Why.
        reason: String,
    },

    /// Guest trap, fuel exhaustion, epoch interrupt, or similar.
    #[error("plugin call terminated: {reason}")]
    CallTerminated {
        /// Why.
        reason: String,
    },

    /// Guest returned a structured `plugin-error`.
    #[error("plugin error `{code}`: {message}")]
    Guest {
        /// Stable code.
        code: String,
        /// Detail.
        message: String,
    },

    /// Limits configuration was out of range.
    #[error("plugin limits: {0}")]
    Limits(String),
}
