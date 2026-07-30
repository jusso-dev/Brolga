//! Structured LLM errors.

use thiserror::Error;

/// What went wrong proposing or approving model output.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LlmError {
    /// LLM subsystem is not enabled or not configured.
    #[error(
        "language-model providers are disabled: {reason}. Build with `--features llm` and configure \
         an explicit provider before any model call"
    )]
    Disabled {
        /// Why.
        reason: String,
    },

    /// Policy refused the transfer.
    #[error("policy refused model transfer: {reason}")]
    Policy {
        /// Why.
        reason: String,
    },

    /// Network policy refused the destination (SSRF baseline).
    #[error("network policy refused model endpoint: {reason}")]
    Network {
        /// Why.
        reason: String,
    },

    /// Provider configuration invalid.
    #[error("provider configuration: {reason}")]
    Config {
        /// Why.
        reason: String,
    },

    /// HTTP or protocol failure.
    #[error("model HTTP: {reason}")]
    Http {
        /// Why.
        reason: String,
    },

    /// Response could not be turned into a proposal (missing evidence, empty body, …).
    #[error("model response unusable: {reason}")]
    Response {
        /// Why.
        reason: String,
    },

    /// Prompt template failed validation.
    #[error("prompt template: {reason}")]
    Template {
        /// Why.
        reason: String,
    },
}
