//! OpenAI-compatible chat completions client (feature `http`).
//!
//! One adapter covers OpenAI-compatible remote APIs, Ollama's `/v1` surface, and llama.cpp
//! server's OpenAI-compatible mode. Endpoint + model name differ; the wire format does not.

use std::time::Duration;

use brolga_config::policy::PolicyIdentity;
use brolga_model::MarkingSet;
use brolga_model::provenance::{
    ContentHash, EvidenceReference, GeneratedContent, GenerationMethod, SourceObject,
};
use brolga_security::NetworkPolicy;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::LlmError;
use crate::policy::{TransferClass, TransferRequest, check_transfer, classify_endpoint};
use crate::proposal::{Proposal, ProposalMetadata, ProposalRequest};
use crate::provider::LanguageModelProvider;

/// Configuration for an OpenAI-compatible endpoint.
#[derive(Debug, Clone)]
pub struct OpenAiCompatConfig {
    /// Base URL without trailing slash, e.g. `http://127.0.0.1:11434/v1` or `https://api.openai.com/v1`.
    pub base_url: String,
    /// Default model.
    pub model: String,
    /// Bearer token; never logged.
    pub api_key: Option<String>,
    /// Provider id for metadata (`ollama`, `llamacpp`, `openai-compat`).
    pub provider_id: String,
    /// Network policy for non-loopback endpoints.
    pub network: NetworkPolicy,
    /// Caller identity for transfer checks.
    pub identity: PolicyIdentity,
    /// Markings on evidence that would be sent.
    pub markings: MarkingSet,
    /// Request timeout.
    pub timeout: Duration,
}

impl OpenAiCompatConfig {
    /// Local Ollama defaults.
    #[must_use]
    pub fn ollama(model: impl Into<String>) -> Self {
        Self {
            base_url: "http://127.0.0.1:11434/v1".to_owned(),
            model: model.into(),
            api_key: None,
            provider_id: "ollama".to_owned(),
            network: NetworkPolicy::strict(),
            identity: PolicyIdentity::anonymous(),
            markings: MarkingSet::empty(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Local llama.cpp server defaults.
    #[must_use]
    pub fn llamacpp(model: impl Into<String>) -> Self {
        Self {
            base_url: "http://127.0.0.1:8080/v1".to_owned(),
            model: model.into(),
            api_key: None,
            provider_id: "llamacpp".to_owned(),
            network: NetworkPolicy::strict(),
            identity: PolicyIdentity::anonymous(),
            markings: MarkingSet::empty(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Remote OpenAI-compatible API.
    #[must_use]
    pub fn remote(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        identity: PolicyIdentity,
        markings: MarkingSet,
        network: NetworkPolicy,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            api_key: Some(api_key.into()),
            provider_id: "openai-compat".to_owned(),
            network,
            identity,
            markings,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Provider that posts to `/chat/completions`.
#[derive(Debug, Clone)]
pub struct OpenAiCompatProvider {
    config: OpenAiCompatConfig,
}

impl OpenAiCompatProvider {
    /// Build from config.
    #[must_use]
    pub fn new(config: OpenAiCompatConfig) -> Self {
        Self { config }
    }

    fn endpoint_url(&self) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        format!("{base}/chat/completions")
    }

    fn transfer_class(&self) -> Result<TransferClass, LlmError> {
        classify_endpoint(&self.config.base_url)
    }
}

impl LanguageModelProvider for OpenAiCompatProvider {
    fn id(&self) -> &str {
        &self.config.provider_id
    }

    fn is_remote(&self) -> bool {
        matches!(
            classify_endpoint(&self.config.base_url),
            Ok(TransferClass::Remote)
        )
    }

    fn default_model(&self) -> &str {
        &self.config.model
    }

    fn propose(&self, request: &ProposalRequest) -> Result<Proposal, LlmError> {
        let class = self.transfer_class()?;
        check_transfer(
            &TransferRequest {
                identity: self.config.identity.clone(),
                markings: self.config.markings.clone(),
                endpoint: self.config.base_url.clone(),
                class,
            },
            &self.config.network,
        )?;

        let messages = request
            .template
            .render(&request.subject, &request.evidence)?;
        let model = request
            .model
            .clone()
            .unwrap_or_else(|| self.config.model.clone());

        let wire_messages: Vec<WireMessage> = messages
            .iter()
            .map(|m| WireMessage {
                role: match m.role {
                    crate::prompt::PromptRole::System => "system",
                    crate::prompt::PromptRole::User => "user",
                    crate::prompt::PromptRole::Assistant => "assistant",
                }
                .to_owned(),
                content: m.content.clone(),
            })
            .collect();

        // No tools / functions field — injection cannot invoke tools that do not exist.
        let body = json!({
            "model": model,
            "messages": wire_messages,
            "temperature": 0.0,
        });

        let text = post_chat_completions(
            &self.endpoint_url(),
            self.config.api_key.as_deref(),
            &body,
            self.config.timeout,
        )?;

        let generator = request.generator_label(self.id(), &model)?;
        let evidence = vec![EvidenceReference::whole(SourceObject::derive_id(
            ContentHash::of(request.evidence.as_bytes()),
        ))];
        let generated =
            GeneratedContent::new(GenerationMethod::LanguageModel, generator, 1, evidence)
                .map_err(|error| LlmError::Response {
                    reason: error.to_string(),
                })?;

        let endpoint_class = match class {
            TransferClass::Local => "local",
            TransferClass::Remote => "remote",
        };

        Proposal::unverified(
            format!("{}-{}", self.id(), request.subject),
            text,
            generated,
            ProposalMetadata {
                provider: self.id().to_owned(),
                model,
                template_id: request.template.id.clone(),
                template_version: request.template.version,
                requested_at: None,
                endpoint_class: endpoint_class.to_owned(),
            },
        )
    }
}

#[derive(Debug, Serialize)]
struct WireMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

fn post_chat_completions(
    url: &str,
    api_key: Option<&str>,
    body: &serde_json::Value,
    timeout: Duration,
) -> Result<String, LlmError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build();
    let agent: ureq::Agent = config.into();

    let mut request = agent.post(url).header("content-type", "application/json");
    if let Some(key) = api_key {
        request = request.header("authorization", &format!("Bearer {key}"));
    }

    let response = request.send_json(body).map_err(|error| LlmError::Http {
        reason: error.to_string(),
    })?;

    let parsed: ChatResponse =
        response
            .into_body()
            .read_json()
            .map_err(|error| LlmError::Http {
                reason: error.to_string(),
            })?;

    let text = parsed
        .choices
        .into_iter()
        .next()
        .and_then(|c| c.message.content)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(LlmError::Response {
            reason: "chat completion had no content".to_owned(),
        });
    }
    Ok(text)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use brolga_config::policy::Capability;

    #[test]
    fn remote_config_without_redistribute_fails_before_http() {
        let config = OpenAiCompatConfig::remote(
            "https://api.openai.com/v1",
            "gpt-test",
            "sk-test",
            PolicyIdentity::anonymous(),
            MarkingSet::empty(),
            NetworkPolicy::strict(),
        );
        let provider = OpenAiCompatProvider::new(config);
        let err = provider
            .propose(&ProposalRequest::new("1.2.3.4", "evidence block"))
            .unwrap_err();
        assert!(
            matches!(err, LlmError::Policy { .. }),
            "must fail policy before HTTP: {err}"
        );
    }

    #[test]
    fn ollama_local_is_not_remote() {
        let provider = OpenAiCompatProvider::new(OpenAiCompatConfig::ollama("llama3"));
        assert!(!provider.is_remote());
    }

    #[test]
    fn remote_with_redistribute_still_hits_network_policy_or_http() {
        // We do not open a real socket in unit tests: strict policy + public DNS may still
        // refuse, or HTTP fails. Either is fine; what must not happen is success without a server.
        let mut identity = PolicyIdentity::anonymous();
        identity = identity.with_capability(Capability::Redistribute);
        // Raise TLP so clear material can redistribute if policy allows.
        identity.max_tlp = brolga_model::TlpLevel::Red;
        let config = OpenAiCompatConfig::remote(
            "https://198.51.100.1/v1", // TEST-NET, should fail connect or policy
            "gpt-test",
            "sk-test",
            identity,
            MarkingSet::empty(),
            NetworkPolicy::strict(),
        );
        let provider = OpenAiCompatProvider::new(config);
        let err = provider
            .propose(&ProposalRequest::new("1.2.3.4", "evidence"))
            .unwrap_err();
        assert!(
            matches!(
                err,
                LlmError::Network { .. } | LlmError::Http { .. } | LlmError::Policy { .. }
            ),
            "unexpected: {err}"
        );
    }
}
