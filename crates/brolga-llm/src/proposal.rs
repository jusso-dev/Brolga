//! Proposals: model output that is not yet intelligence.

use brolga_model::provenance::GeneratedContent;
use brolga_model::{ShortText, Timestamp};
use brolga_security::TrustLevel;
use serde::{Deserialize, Serialize};

use crate::PROPOSAL_TRUST;
use crate::error::LlmError;
use crate::prompt::PromptTemplate;

/// How far a proposal has been checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApprovalState {
    /// Fresh from a model. Default. Not for automated decisions.
    Unverified,
    /// A deterministic checker accepted the text against evidence.
    DeterministicallyValidated {
        /// Checker id.
        checker: String,
    },
    /// An operator accepted it.
    OperatorApproved {
        /// Actor name.
        actor: String,
    },
    /// Explicitly rejected.
    Rejected {
        /// Actor or checker.
        actor: String,
        /// Reason.
        reason: String,
    },
}

impl ApprovalState {
    /// Whether consumers may treat the text as reviewed.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(
            self,
            Self::DeterministicallyValidated { .. } | Self::OperatorApproved { .. }
        )
    }
}

/// Provenance fields persisted with a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalMetadata {
    /// Provider id (`openai-compat`, `ollama`, …).
    pub provider: String,
    /// Model name as configured.
    pub model: String,
    /// Prompt template id.
    pub template_id: String,
    /// Prompt template version.
    pub template_version: u32,
    /// When the call was made (runtime metadata).
    pub requested_at: Option<Timestamp>,
    /// Endpoint class for audit: `local` or `remote`.
    pub endpoint_class: String,
}

/// A language-model proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Stable id for this proposal instance.
    pub id: String,
    /// Model text. Always untrusted.
    pub text: String,
    /// Trust stamp — always [`PROPOSAL_TRUST`] for model output.
    pub trust: TrustLevel,
    /// Approval / verification state.
    pub state: ApprovalState,
    /// Generator metadata (must cite evidence).
    pub generated: GeneratedContent,
    /// Call metadata.
    pub metadata: ProposalMetadata,
}

impl Proposal {
    /// Build an unverified proposal from a model reply.
    ///
    /// # Errors
    ///
    /// Empty text or `GeneratedContent` that fails validation.
    pub fn unverified(
        id: impl Into<String>,
        text: impl Into<String>,
        generated: GeneratedContent,
        metadata: ProposalMetadata,
    ) -> Result<Self, LlmError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(LlmError::Response {
                reason: "model returned empty text".to_owned(),
            });
        }
        if !generated.is_model_generated() {
            return Err(LlmError::Response {
                reason: "proposal GeneratedContent must use GenerationMethod::LanguageModel"
                    .to_owned(),
            });
        }
        Ok(Self {
            id: id.into(),
            text,
            trust: PROPOSAL_TRUST,
            state: ApprovalState::Unverified,
            generated,
            metadata,
        })
    }

    /// Mark operator approval.
    #[must_use]
    pub fn approve(mut self, actor: impl Into<String>) -> Self {
        self.state = ApprovalState::OperatorApproved {
            actor: actor.into(),
        };
        self
    }

    /// Mark deterministic validation.
    #[must_use]
    pub fn validate_deterministically(mut self, checker: impl Into<String>) -> Self {
        self.state = ApprovalState::DeterministicallyValidated {
            checker: checker.into(),
        };
        self
    }

    /// Reject.
    #[must_use]
    pub fn reject(mut self, actor: impl Into<String>, reason: impl Into<String>) -> Self {
        self.state = ApprovalState::Rejected {
            actor: actor.into(),
            reason: reason.into(),
        };
        self
    }
}

/// Input to a provider call.
#[derive(Debug, Clone)]
pub struct ProposalRequest {
    /// Subject string (observable spelling or free text).
    pub subject: String,
    /// Evidence block already delimited by the caller.
    pub evidence: String,
    /// Template to render.
    pub template: PromptTemplate,
    /// Model name override; provider default when `None`.
    pub model: Option<String>,
}

impl ProposalRequest {
    /// Build a request with the default template.
    #[must_use]
    pub fn new(subject: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            evidence: evidence.into(),
            template: PromptTemplate::default_proposal(),
            model: None,
        }
    }

    /// Generator short-name for `GeneratedContent`.
    ///
    /// # Errors
    ///
    /// Invalid short text.
    pub fn generator_label(&self, provider: &str, model: &str) -> Result<ShortText, LlmError> {
        let raw = format!("{provider}/{model}");
        ShortText::new(&raw).map_err(|error| LlmError::Config {
            reason: error.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use brolga_model::provenance::{
        ContentHash, EvidenceReference, GenerationMethod, SourceObject,
    };

    fn evidence() -> Vec<EvidenceReference> {
        vec![EvidenceReference::whole(SourceObject::derive_id(
            ContentHash::of(b"feed"),
        ))]
    }

    #[test]
    fn new_proposal_is_unverified_and_untrusted() {
        let generated = GeneratedContent::new(
            GenerationMethod::LanguageModel,
            ShortText::new("mock/m").unwrap(),
            1,
            evidence(),
        )
        .unwrap();
        let proposal = Proposal::unverified(
            "p1",
            "maybe related",
            generated,
            ProposalMetadata {
                provider: "mock".to_owned(),
                model: "m".to_owned(),
                template_id: "t".to_owned(),
                template_version: 1,
                requested_at: None,
                endpoint_class: "local".to_owned(),
            },
        )
        .unwrap();
        assert!(!proposal.state.is_verified());
        assert_eq!(proposal.trust, TrustLevel::Untrusted);
        assert!(proposal.approve("alice").state.is_verified());
    }
}
