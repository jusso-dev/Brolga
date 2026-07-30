//! `brolga plugin validate`, `explain`, and (with `--features plugins`) `run`.
//!
//! Manifest commands always use the SDK. Execution requires the off-by-default host feature
//! (ADR 0001 §3, ADR 0009).

use std::io::Write;

use brolga_plugin_sdk::abi::PLUGIN_ABI_VERSION;
use brolga_plugin_sdk::manifest::PluginManifest;

use crate::cli::{PluginCommand, PluginFileArgs, PluginRunArgs};
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
        PluginCommand::Run(args) => run(args, streams),
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

fn run<Out: Write, Err: Write>(args: &PluginRunArgs, streams: &mut Streams<Out, Err>) -> ExitCode {
    #[cfg(not(feature = "plugins"))]
    {
        let _ = args;
        let _ = streams.problem(
            "`brolga plugin run` requires a binary built with `--features plugins` (ADR 0009). \
             Manifest validate/explain work without it.",
        );
        ExitCode::NotImplemented
    }

    #[cfg(feature = "plugins")]
    {
        run_with_host(args, streams)
    }
}

#[cfg(feature = "plugins")]
fn run_with_host<Out: Write, Err: Write>(
    args: &PluginRunArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    use brolga_plugin_host::grant::GrantSet;
    use brolga_plugin_host::limits::PluginLimits;
    use brolga_plugin_host::package::load_package_dir;
    use brolga_plugin_host::runtime::PluginEngine;

    let request = match &args.request {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = streams.problem(&format!("cannot read {}: {error}", path.display()));
                return ExitCode::Io;
            }
        },
        None => b"{}".to_vec(),
    };

    let package =
        match load_package_dir(&args.package, &GrantSet::empty(), PluginLimits::defaults()) {
            Ok(package) => package,
            Err(error) => {
                let _ = streams.problem(&error.to_string());
                return ExitCode::ConfigInvalid;
            }
        };

    let engine = match PluginEngine::new(PluginLimits::defaults()) {
        Ok(engine) => engine,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return ExitCode::Failure;
        }
    };

    match engine.invoke(&package, &args.extension, &args.contract, &request) {
        Ok(result) => {
            if streams.mode() == OutputMode::Human {
                match std::str::from_utf8(&result.body) {
                    Ok(text) => {
                        let _ = streams.result_line(text);
                    }
                    Err(_) => {
                        let _ = streams.result_line(&format!(
                            "binary response: {} bytes (fuel remaining: {:?})",
                            result.body.len(),
                            result.fuel_remaining
                        ));
                    }
                }
            } else {
                let body_json: serde_json::Value = serde_json::from_slice(&result.body)
                    .unwrap_or_else(|_| serde_json::json!({ "raw_len": result.body.len() }));
                let _ = streams.result_json(&serde_json::json!({
                    "plugin": package.identity.name,
                    "version": package.identity.version,
                    "extension": args.extension,
                    "contract": args.contract,
                    "fuel_remaining": result.fuel_remaining,
                    "body": body_json,
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
