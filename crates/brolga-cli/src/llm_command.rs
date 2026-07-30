//! `brolga llm status` and `brolga llm propose`.
//!
//! Default builds never call a model. Execution requires `--features llm` (ADR 0010).

use std::io::Write;

use crate::cli::{LlmCommand, LlmProposeArgs};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga llm`.
pub(crate) fn llm<Out: Write, Err: Write>(
    command: &LlmCommand,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match command {
        LlmCommand::Status => status(streams),
        LlmCommand::Propose(args) => propose(args, streams),
    }
}

fn status<Out: Write, Err: Write>(streams: &mut Streams<Out, Err>) -> ExitCode {
    #[cfg(feature = "llm")]
    let enabled = true;
    #[cfg(not(feature = "llm"))]
    let enabled = false;

    if streams.mode() == OutputMode::Human {
        if enabled {
            let _ = streams.result_line(
                "llm feature: enabled (HTTP adapters present; still requires explicit provider config)",
            );
        } else {
            let _ = streams.result_line(
                "llm feature: disabled (default). Build with `--features llm` to enable adapters. \
                 No model call is possible from this binary.",
            );
        }
    } else {
        let _ = streams.result_json(&serde_json::json!({
            "llm_feature": enabled,
            "default_provider": "disabled",
            "proposal_trust": "untrusted",
        }));
    }
    ExitCode::Success
}

fn propose<Out: Write, Err: Write>(
    args: &LlmProposeArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    #[cfg(not(feature = "llm"))]
    {
        // Even without the feature, `mock` is available via a thin path that only uses
        // brolga-llm's default (no-http) surface if we always depend on brolga-llm.
        // Default: refuse so default binary cannot produce model-shaped output.
        let _ = args;
        let _ = streams.problem(
            "`brolga llm propose` requires `--features llm` (ADR 0010). \
             `brolga llm status` works without it.",
        );
        ExitCode::NotImplemented
    }

    #[cfg(feature = "llm")]
    {
        propose_enabled(args, streams)
    }
}

#[cfg(feature = "llm")]
fn propose_enabled<Out: Write, Err: Write>(
    args: &LlmProposeArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    use brolga_llm::openai_compat::{OpenAiCompatConfig, OpenAiCompatProvider};
    use brolga_llm::provider::{DisabledProvider, LanguageModelProvider, MockProvider};
    use brolga_llm::{PROPOSAL_TRUST, ProposalRequest};

    let evidence = match std::fs::read_to_string(&args.evidence) {
        Ok(text) => text,
        Err(error) => {
            let _ = streams.problem(&format!(
                "cannot read evidence {}: {error}",
                args.evidence.display()
            ));
            return ExitCode::Io;
        }
    };

    // Delimit evidence so it cannot be mistaken for system instructions.
    let delimited = format!("-----BEGIN EVIDENCE-----\n{evidence}\n-----END EVIDENCE-----");
    let request = ProposalRequest::new(&args.subject, delimited);

    let result = match args.provider.as_str() {
        "disabled" => DisabledProvider.propose(&request),
        "mock" => MockProvider::new("unverified mock proposal").propose(&request),
        "ollama" => {
            let model = args.model.clone().unwrap_or_else(|| "llama3".to_owned());
            OpenAiCompatProvider::new(OpenAiCompatConfig::ollama(model)).propose(&request)
        }
        "llamacpp" => {
            let model = args.model.clone().unwrap_or_else(|| "local".to_owned());
            OpenAiCompatProvider::new(OpenAiCompatConfig::llamacpp(model)).propose(&request)
        }
        "openai" => {
            let _ = streams.problem(
                "provider `openai` requires base_url, API key env, and redistribute capability; \
                 use the library API for remote providers in this milestone",
            );
            return ExitCode::ConfigInvalid;
        }
        other => {
            let _ = streams.problem(&format!("unknown provider `{other}`"));
            return ExitCode::ConfigInvalid;
        }
    };

    match result {
        Ok(proposal) => {
            if streams.mode() == OutputMode::Human {
                let _ = streams.result_line(&format!(
                    "proposal (trust={}, state=unverified, provider={}):",
                    PROPOSAL_TRUST.as_str(),
                    proposal.metadata.provider
                ));
                let _ = streams.result_line(&proposal.text);
            } else {
                let _ = streams.result_json(&serde_json::json!({
                    "id": proposal.id,
                    "text": proposal.text,
                    "trust": "untrusted",
                    "state": "unverified",
                    "metadata": {
                        "provider": proposal.metadata.provider,
                        "model": proposal.metadata.model,
                        "template_id": proposal.metadata.template_id,
                        "template_version": proposal.metadata.template_version,
                        "endpoint_class": proposal.metadata.endpoint_class,
                    },
                }));
            }
            ExitCode::Success
        }
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            ExitCode::Failure
        }
    }
}
