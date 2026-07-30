//! Optional language-model **proposals** — never authoritative intelligence.
//!
//! [ADR 0010](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0010-optional-llm-proposal-providers.md)
//! implements [#49](https://github.com/jusso-dev/Brolga/issues/49).
//!
//! # Default build makes no model call
//!
//! Without the `http` feature there is no HTTP client. [`DisabledProvider`] is always available and
//! refuses every request with a clear error. That is how "disabled by default" stays true under
//! ADR 0001 §3 rather than as a runtime flag somebody can forget.
//!
//! # Output trust
//!
//! Every proposal is [`TrustLevel::Untrusted`](brolga_security::TrustLevel::Untrusted) and starts
//! in [`ApprovalState::Unverified`]. Deterministic validation or operator approval must upgrade it
//! before any consumer treats it as checked.

#![forbid(unsafe_code)]

pub mod error;
pub mod policy;
pub mod prompt;
pub mod proposal;
pub mod provider;

#[cfg(feature = "http")]
pub mod openai_compat;

pub use error::LlmError;
pub use policy::{TransferClass, TransferRequest, check_transfer};
pub use prompt::{PromptMessage, PromptRole, PromptTemplate};
pub use proposal::{ApprovalState, Proposal, ProposalMetadata, ProposalRequest};
pub use provider::{DisabledProvider, LanguageModelProvider, NullHttpProbe};

/// Trust level stamped on every model proposal (threat model B10).
pub const PROPOSAL_TRUST: brolga_security::TrustLevel = brolga_security::TrustLevel::Untrusted;
