//! `brolga plugin validate` and `brolga plugin explain`.
//!
//! # Manifests only — no host
//!
//! [#46](https://github.com/jusso-dev/Brolga/issues/46) ships the SDK and ABI. The WebAssembly host
//! is [#48](https://github.com/jusso-dev/Brolga/issues/48). These commands answer "would this
//! manifest load?" and "what does it claim?", without executing a component.

use std::io::Write;

use brolga_plugin_sdk::abi::PLUGIN_ABI_VERSION;
use brolga_plugin_sdk::manifest::PluginManifest;

use crate::cli::{PluginCommand, PluginFileArgs};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga plugin`.
pub(crate) fn plugin<Out: Write, Err: Write>(
    command: &PluginCommand,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match command {
        PluginCommand::Validate(args) => validate(args, streams),
        PluginCommand::Explain(args) => explain(args, streams),
    }
}

fn load<Out: Write, Err: Write>(
    args: &PluginFileArgs,
    streams: &mut Streams<Out, Err>,
) -> Result<PluginManifest, ExitCode> {
    let bytes = match std::fs::read(&args.path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = streams.problem(&format!("cannot read {}: {error}", args.path.display()));
            return Err(ExitCode::Io);
        }
    };

    PluginManifest::load(&bytes).map_err(|error| {
        let _ = streams.problem(&error.to_string());
        // ConfigInvalid: the command line was fine; the operator's file was not.
        ExitCode::ConfigInvalid
    })
}

fn validate<Out: Write, Err: Write>(
    args: &PluginFileArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let manifest = match load(args, streams) {
        Ok(manifest) => manifest,
        Err(code) => return code,
    };

    if streams.mode() == OutputMode::Human {
        let _ = streams.result_line(&format!(
            "`{}` v{} is valid for ABI {PLUGIN_ABI_VERSION}: {} extension point(s), {} capability grant(s)",
            manifest.name,
            manifest.version,
            manifest.extension_points.len(),
            manifest.capabilities.len(),
        ));
    } else {
        let _ = streams.result_json(&serde_json::json!({
            "name": manifest.name,
            "version": manifest.version,
            "valid": true,
            "abi": PLUGIN_ABI_VERSION,
            "extension_points": manifest.extension_points.len(),
            "capabilities": manifest.capabilities.len(),
        }));
    }
    ExitCode::Success
}

fn explain<Out: Write, Err: Write>(
    args: &PluginFileArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let manifest = match load(args, streams) {
        Ok(manifest) => manifest,
        Err(code) => return code,
    };
    let explanation = manifest.explain();

    if streams.mode() == OutputMode::Human {
        let _ = streams.result_line(&format!(
            "plugin `{}` v{} — api {} (this build ABI {PLUGIN_ABI_VERSION}, compatible: {})",
            explanation.name,
            explanation.version,
            explanation.api_range,
            explanation.abi_compatible,
        ));
        let _ = streams.result_line("extension points:");
        for line in &explanation.extension_lines {
            let _ = streams.result_line(&format!("  - {line}"));
        }
        if explanation.capabilities.is_empty() {
            let _ = streams.result_line("capabilities: (none — pure compute)");
        } else {
            let _ = streams.result_line(&format!(
                "capabilities: {}",
                explanation.capabilities.join(", ")
            ));
        }
        let _ = streams.result_line("refusals (apply whatever the manifest says):");
        for refusal in &explanation.refusals {
            let _ = streams.result_line(&format!("  - {refusal}"));
        }
    } else {
        let _ = streams.result_json(&serde_json::json!({
            "name": explanation.name,
            "version": explanation.version,
            "api_range": explanation.api_range,
            "abi": PLUGIN_ABI_VERSION,
            "abi_compatible": explanation.abi_compatible,
            "extension_points": explanation.extension_lines,
            "capabilities": explanation.capabilities,
            "refusals": explanation.refusals,
        }));
    }
    ExitCode::Success
}
