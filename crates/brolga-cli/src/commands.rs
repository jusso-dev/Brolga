//! What each command actually does.
//!
//! Every command returns an [`ExitCode`] rather than calling `std::process::exit`, so the whole
//! tree is testable without spawning a process and so cleanup always runs.

use std::io::Write;
use std::path::Path;

use brolga_config::layer::Layer;
use brolga_config::load::{Format, parse_layer};
use brolga_config::service::{explain, resolve};
use brolga_config::{Diagnostics, config_schema};
use brolga_storage::sqlite::SqliteStore;
use brolga_storage::store::{IntelligenceStore, RecordKind, StoreRead};

use crate::cli::{
    CheckpointCommand, Cli, Command, CompletionArgs, ConfigCommand, GlobalOptions, InitArgs,
};
use crate::exit::ExitCode;
use crate::output::{CorrelationId, OutputMode, Streams};

/// The starter configuration `brolga init` writes.
///
/// Deliberately minimal and heavily commented. A generated file that dumps every setting is a file
/// operators stop reading, and it goes stale the moment a default changes.
const STARTER_CONFIG: &str = "\
# Brolga configuration.
#
# Every setting not mentioned here uses Brolga's built-in default. Run
# `brolga config explain` to see the resolved value of every setting and
# which layer supplied it, and `brolga config schema` for the full schema.
#
# Configuration is data only: there are no expressions, templates, includes,
# or commands, and an unrecognised key is an error rather than being ignored.
version: 1

# storage:
#   sqlite:
#     path: brolga.sqlite

# logging:
#   level: info      # error | warn | info | debug | trace
#   format: text     # text | json

# Secrets are referenced, never written here. A bare string is rejected.
# secrets:
#   feed_token:
#     from_env: BROLGA_FEED_TOKEN
";

/// Run a command.
pub(crate) fn run<Out: Write, Err: Write>(
    command: &Command,
    global: &GlobalOptions,
    correlation: &CorrelationId,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match command {
        Command::Init(args) => init(args, streams),
        Command::Ingest(args) => crate::store_commands::ingest(args, streams),
        Command::Stats(args) => crate::store_commands::stats(&args.database, streams),
        Command::Show(args) => crate::store_commands::show(args, streams),
        Command::Quarantine(args) => crate::store_commands::quarantine(args, streams),
        Command::Sources(args) => crate::store_commands::sources(&args.database, streams),
        Command::Search(args) => crate::graph_commands::search(args, streams),
        Command::Neighbours(args) => crate::graph_commands::neighbours(args, streams),
        Command::Checkpoint(sub) => match sub {
            CheckpointCommand::Take(args) => crate::graph_commands::checkpoint_take(args, streams),
            CheckpointCommand::List(args) => {
                crate::graph_commands::checkpoint_list(&args.database, streams)
            }
            CheckpointCommand::Diff(args) => crate::graph_commands::checkpoint_diff(args, streams),
            CheckpointCommand::Remove(args) => {
                crate::graph_commands::checkpoint_remove(args, streams)
            }
        },
        Command::Completion(args) => completion(args, streams),
        Command::Doctor => doctor(global, correlation, streams),
        Command::Config(sub) => config(sub, global, streams),
        Command::ExitCodes => exit_codes(streams),
        Command::Context(_) => not_implemented(command, streams),
    }
}

/// `brolga init`.
fn init<Out: Write, Err: Write>(args: &InitArgs, streams: &mut Streams<Out, Err>) -> ExitCode {
    if args.path.exists() && !args.force {
        let _ = streams.problem(&format!(
            "{} already exists. Pass --force to overwrite it.",
            args.path.display(),
        ));
        return ExitCode::Io;
    }

    if let Err(error) = std::fs::write(&args.path, STARTER_CONFIG) {
        let _ = streams.problem(&format!("could not write {}: {error}", args.path.display(),));
        return ExitCode::Io;
    }

    let _ = streams.note(&format!(
        "Wrote {}. Edit it, then run `brolga config validate`.",
        args.path.display(),
    ));

    match streams.mode() {
        OutputMode::Human | OutputMode::Table => {
            let _ = streams.result_line(&args.path.display().to_string());
        }
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "status": "ok",
                "wrote": args.path.display().to_string(),
            }));
        }
    }

    ExitCode::Success
}

/// `brolga doctor`.
///
/// Checks what an operator would otherwise discover one failure at a time: configuration loads,
/// storage opens, migrations are current. Every check runs even when an earlier one fails, because
/// the point is to produce a complete picture in one run.
fn doctor<Out: Write, Err: Write>(
    global: &GlobalOptions,
    correlation: &CorrelationId,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mut checks: Vec<Check> = Vec::new();

    let layers = match load_layers(&global.config) {
        Ok(layers) => {
            checks.push(Check::ok(
                "configuration files",
                &format!("{} file(s) parsed", layers.len()),
            ));
            Some(layers)
        }
        Err(problem) => {
            checks.push(Check::failed("configuration files", &problem));
            None
        }
    };

    let resolved = layers.as_ref().and_then(|layers| match resolve(layers) {
        Ok(resolved) => {
            checks.push(Check::ok(
                "configuration",
                &format!("valid, fingerprint {}", resolved.fingerprint.short()),
            ));
            Some(resolved)
        }
        Err(diagnostics) => {
            checks.push(Check::failed(
                "configuration",
                &format!("{} problem(s): {diagnostics}", diagnostics.len()),
            ));
            None
        }
    });

    if let Some(resolved) = &resolved {
        match SqliteStore::open(
            &resolved.config.storage.sqlite.path,
            resolved.config.storage.sqlite.busy_timeout_ms,
        ) {
            Ok(mut store) => {
                match store.migrate() {
                    Ok(report) => checks.push(Check::ok(
                        "storage",
                        &format!(
                            "schema version {}{}",
                            report.to_version,
                            if report.changed() { ", migrated" } else { "" },
                        ),
                    )),
                    Err(error) => {
                        checks.push(Check::failed("storage migrations", &error.to_string()))
                    }
                }

                match store.count(RecordKind::Entity) {
                    Ok(count) => checks.push(Check::ok("stored entities", &count.to_string())),
                    Err(error) => checks.push(Check::failed("stored entities", &error.to_string())),
                }
            }
            Err(error) => checks.push(Check::failed("storage", &error.to_string())),
        }
    }

    let failed = checks.iter().filter(|check| !check.passed).count();

    match streams.mode() {
        OutputMode::Human | OutputMode::Table => {
            for check in &checks {
                let mark = if check.passed { "ok" } else { "FAILED" };
                let _ =
                    streams.result_line(&format!("{mark:>6}  {}: {}", check.name, check.detail));
            }
            let _ = streams.result_line(&format!(
                "\n{} check(s), {failed} failed. Correlation id {correlation}.",
                checks.len(),
            ));
        }
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "status": if failed == 0 { "ok" } else { "failed" },
                "correlation_id": correlation.as_str(),
                "checks": checks
                    .iter()
                    .map(|check| serde_json::json!({
                        "name": check.name,
                        "passed": check.passed,
                        "detail": check.detail,
                    }))
                    .collect::<Vec<_>>(),
            }));
        }
    }

    if failed == 0 {
        ExitCode::Success
    } else {
        ExitCode::ConfigInvalid
    }
}

struct Check {
    name: String,
    passed: bool,
    detail: String,
}

impl Check {
    fn ok(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            passed: true,
            detail: detail.to_owned(),
        }
    }

    fn failed(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            passed: false,
            detail: detail.to_owned(),
        }
    }
}

/// `brolga config ...`.
fn config<Out: Write, Err: Write>(
    command: &ConfigCommand,
    global: &GlobalOptions,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    if matches!(command, ConfigCommand::Schema) {
        let schema = config_schema();
        // The schema is one document in every mode. There is nothing to tabulate and nothing to
        // stream, and rendering it as prose would make it unusable for the thing it is for.
        let _ = streams.result_json(&schema);
        return ExitCode::Success;
    }

    let layers = match load_layers(&global.config) {
        Ok(layers) => layers,
        Err(problem) => {
            let _ = streams.problem(&problem);
            return ExitCode::ConfigInvalid;
        }
    };

    match command {
        ConfigCommand::Validate => match resolve(&layers) {
            Ok(resolved) => {
                match streams.mode() {
                    OutputMode::Human | OutputMode::Table => {
                        let _ = streams.result_line(&format!(
                            "configuration is valid ({} settings, fingerprint {})",
                            resolved.attribution.len(),
                            resolved.fingerprint.short(),
                        ));
                    }
                    OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
                        let _ = streams.result_json(&serde_json::json!({
                            "status": "valid",
                            "settings": resolved.attribution.len(),
                            "fingerprint": resolved.fingerprint.to_string(),
                        }));
                    }
                }
                ExitCode::Success
            }
            Err(diagnostics) => {
                report_diagnostics(&diagnostics, streams);
                ExitCode::ConfigInvalid
            }
        },

        ConfigCommand::Explain { changed_only } => match explain(&layers) {
            Ok(explanation) => {
                let settings: Vec<_> = if *changed_only {
                    explanation.overridden().collect()
                } else {
                    explanation.settings.iter().collect()
                };

                match streams.mode() {
                    OutputMode::Human | OutputMode::Table => {
                        for setting in &settings {
                            let _ = streams.result_line(&format!(
                                "{} = {}  [{}]",
                                setting.path, setting.value, setting.source,
                            ));
                        }
                    }
                    OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
                        let _ = streams.result_json(&serde_json::json!({
                            "fingerprint": explanation.fingerprint.to_string(),
                            "settings": settings
                                .iter()
                                .map(|setting| serde_json::json!({
                                    "path": setting.path,
                                    "value": setting.value,
                                    "source": setting.source.label(),
                                    "is_default": setting.is_default,
                                }))
                                .collect::<Vec<_>>(),
                        }));
                    }
                }
                ExitCode::Success
            }
            Err(diagnostics) => {
                report_diagnostics(&diagnostics, streams);
                ExitCode::ConfigInvalid
            }
        },

        // Handled above, before any configuration is loaded, because printing the schema must work
        // even when the operator's configuration is what they are trying to fix.
        ConfigCommand::Schema => ExitCode::Success,
    }
}

/// `brolga exit-codes`.
fn exit_codes<Out: Write, Err: Write>(streams: &mut Streams<Out, Err>) -> ExitCode {
    match streams.mode() {
        OutputMode::Human | OutputMode::Table => {
            for code in ExitCode::all() {
                let _ = streams.result_line(&format!(
                    "{:>3}  {:<16} {}",
                    code.code(),
                    code.name(),
                    code.description(),
                ));
            }
        }
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(
                &ExitCode::all()
                    .iter()
                    .map(|code| {
                        serde_json::json!({
                            "code": code.code(),
                            "name": code.name(),
                            "description": code.description(),
                        })
                    })
                    .collect::<Vec<_>>(),
            );
        }
    }
    ExitCode::Success
}

/// A command that is declared but not implemented.
///
/// Fails loudly and names the milestone. `CONTRIBUTING.md` prohibits placeholders in production
/// paths, and a command that prints "done" and does nothing is the worst kind of placeholder.
fn not_implemented<Out: Write, Err: Write>(
    command: &Command,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let milestone = command.planned_milestone().unwrap_or("a later milestone");
    let message = format!(
        "`brolga {}` is not implemented in this build. It arrives in {milestone}.",
        command.name(),
    );

    let _ = streams.problem(&message);

    if streams.mode() == OutputMode::Json {
        let _ = streams.result_json(&serde_json::json!({
            "status": "not_implemented",
            "command": command.name(),
            "planned_milestone": milestone,
        }));
    }

    ExitCode::NotImplemented
}

/// Read and parse every configuration file named on the command line.
fn load_layers(paths: &[std::path::PathBuf]) -> core::result::Result<Vec<Layer>, String> {
    let mut layers = Vec::with_capacity(paths.len());

    for path in paths {
        let text = read_config(path)?;
        let name = path.display().to_string();
        let layer = parse_layer(&name, &text, Format::from_path(&name))
            .map_err(|error| format!("{name}: {error}"))?;
        layers.push(layer);
    }

    Ok(layers)
}

fn read_config(path: &Path) -> core::result::Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))
}

/// Write every diagnostic to stderr, one per line.
///
/// All of them, not the first. An operator fixing one problem per run is an operator running the
/// tool repeatedly to learn things it already knew.
fn report_diagnostics<Out: Write, Err: Write>(
    diagnostics: &Diagnostics,
    streams: &mut Streams<Out, Err>,
) {
    for error in diagnostics.as_slice() {
        let _ = streams.problem(&format!("error: {error}"));
    }
    let _ = streams.problem(&format!(
        "configuration has {} problem(s)",
        diagnostics.len()
    ));
}

/// `brolga completion`.
///
/// Generated from this build's command tree rather than shipped as a static file, so completion
/// can never advertise a command or flag the binary does not have — which is worse than no
/// completion, because it reads as documentation.
fn completion<Out: Write, Err: Write>(
    args: &CompletionArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mut command = <Cli as clap::CommandFactory>::command();
    let mut rendered: Vec<u8> = Vec::new();
    clap_complete::generate(args.shell, &mut command, "brolga", &mut rendered);

    match String::from_utf8(rendered) {
        Ok(script) => {
            // A result, so it redirects into a file without commentary mixed in.
            let _ = streams.result_line(script.trim_end());
            ExitCode::Success
        }
        Err(_) => {
            let _ = streams.problem("the completion script was not valid UTF-8");
            ExitCode::Failure
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::cli::{LogFormatArg, LogLevelArg, OutputModeArg};
    use clap::Parser;

    fn global() -> GlobalOptions {
        GlobalOptions {
            config: Vec::new(),
            output: OutputModeArg::Human,
            log_level: LogLevelArg::Info,
            log_format: LogFormatArg::Text,
            quiet: false,
            no_color: false,
        }
    }

    fn streams(mode: OutputMode) -> Streams<Vec<u8>, Vec<u8>> {
        Streams::new(Vec::new(), Vec::new(), mode, false)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("valid UTF-8")
    }

    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("valid command line")
    }

    /// The failure mode CONTRIBUTING.md prohibits: printing "done" and doing nothing.
    ///
    /// `ingest` was in this list and no longer is, because it is implemented. That is the whole
    /// point of the list shrinking rather than the test being deleted — it is the record of which
    /// promises are still outstanding.
    #[test]
    fn an_unimplemented_command_fails_rather_than_pretending_to_work() {
        {
            let argv = vec!["brolga", "context", "example.com"];
            let parsed = parse(&argv);
            let mut streams = streams(OutputMode::Human);
            let code = run(
                &parsed.command,
                &global(),
                &CorrelationId::generate(),
                &mut streams,
            );

            assert_eq!(code, ExitCode::NotImplemented);
            let (out, err) = streams.into_parts();
            assert!(out.is_empty(), "nothing may be reported as a result");
            let rendered = text(&err);
            assert!(rendered.contains("not implemented"), "{rendered}");
            assert!(
                rendered.contains("v0."),
                "the message names the milestone: {rendered}"
            );
        }
    }

    #[test]
    fn an_unimplemented_command_says_so_in_structured_output_too() {
        let parsed = parse(&["brolga", "--output", "json", "context"]);
        let mut streams = streams(OutputMode::Json);
        let code = run(
            &parsed.command,
            &global(),
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::NotImplemented);
        let (out, _) = streams.into_parts();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["status"], "not_implemented");
        assert!(parsed["planned_milestone"].is_string());
    }

    #[test]
    fn the_exit_code_registry_is_queryable_from_the_binary() {
        // Exit codes are a compatibility surface; a pipeline author should be able to read them
        // from the build they are running rather than from documentation that may not match.
        let mut streams = streams(OutputMode::Json);
        let code = run(
            &Command::ExitCodes,
            &global(),
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::Success);
        let (out, err) = streams.into_parts();
        assert!(err.is_empty());

        let listed: Vec<serde_json::Value> = serde_json::from_slice(&out).unwrap();
        assert_eq!(listed.len(), ExitCode::all().len());
        assert!(listed.iter().any(|entry| entry["code"] == 5));
    }

    #[test]
    fn the_configuration_schema_prints_without_loading_configuration() {
        // Printing the schema must work when the operator's configuration is what they are fixing.
        let mut options = global();
        options.config = vec![std::path::PathBuf::from("/does/not/exist.yaml")];

        let mut streams = streams(OutputMode::Human);
        let code = run(
            &Command::Config(ConfigCommand::Schema),
            &options,
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::Success);
        let (out, _) = streams.into_parts();
        let schema: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            schema["$id"]
                .as_str()
                .is_some_and(|id| id.contains("brolga.config"))
        );
    }

    #[test]
    fn validating_with_no_files_uses_the_defaults_and_succeeds() {
        let mut streams = streams(OutputMode::Json);
        let code = run(
            &Command::Config(ConfigCommand::Validate),
            &global(),
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::Success);
        let (out, _) = streams.into_parts();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["status"], "valid");
        assert!(
            parsed["fingerprint"]
                .as_str()
                .is_some_and(|f| f.starts_with("sha256:"))
        );
    }

    #[test]
    fn a_missing_configuration_file_is_a_configuration_error_not_a_usage_error() {
        // The command line was fine. The fix is in the environment, not in how it was called.
        let mut options = global();
        options.config = vec![std::path::PathBuf::from("/does/not/exist.yaml")];

        let mut streams = streams(OutputMode::Human);
        let code = run(
            &Command::Config(ConfigCommand::Validate),
            &options,
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::ConfigInvalid);
        let (out, err) = streams.into_parts();
        assert!(out.is_empty(), "a failure must not print a result");
        assert!(text(&err).contains("could not read"));
    }

    #[test]
    fn explain_reports_every_setting_with_its_source() {
        let mut streams = streams(OutputMode::Json);
        let code = run(
            &Command::Config(ConfigCommand::Explain {
                changed_only: false,
            }),
            &global(),
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::Success);
        let (out, _) = streams.into_parts();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let settings = parsed["settings"].as_array().unwrap();
        assert!(!settings.is_empty());
        assert!(settings.iter().all(|setting| setting["source"].is_string()));
        assert!(settings.iter().all(|setting| setting["is_default"] == true));
    }

    #[test]
    fn doctor_reports_every_check_even_when_one_fails() {
        // One failure per run is how an operator ends up running a diagnostic six times.
        let mut options = global();
        options.config = vec![std::path::PathBuf::from("/does/not/exist.yaml")];

        let mut streams = streams(OutputMode::Json);
        let code = run(
            &Command::Doctor,
            &options,
            &CorrelationId::generate(),
            &mut streams,
        );

        assert_eq!(code, ExitCode::ConfigInvalid);
        let (out, _) = streams.into_parts();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["status"], "failed");
        assert!(parsed["correlation_id"].as_str().is_some());
        assert!(!parsed["checks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn init_refuses_to_overwrite_without_force() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("brolga.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();

        let args = InitArgs {
            path: path.clone(),
            force: false,
        };
        let mut streams = streams(OutputMode::Human);
        let code = init(&args, &mut streams);

        assert_eq!(code, ExitCode::Io);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "version: 1\n",
            "the operator's file must be untouched",
        );

        let (_, err) = streams.into_parts();
        assert!(
            text(&err).contains("--force"),
            "the message says how to proceed"
        );
    }

    #[test]
    fn init_writes_a_configuration_that_actually_validates() {
        // A starter file that does not load is worse than none: the failure looks like the
        // operator's mistake.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("brolga.yaml");

        let mut streams = streams(OutputMode::Human);
        let code = init(
            &InitArgs {
                path: path.clone(),
                force: false,
            },
            &mut streams,
        );
        assert_eq!(code, ExitCode::Success);

        let layers = load_layers(&[path]).expect("the generated file must parse");
        assert!(resolve(&layers).is_ok(), "the generated file must validate");
    }

    #[test]
    fn init_overwrites_when_asked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("brolga.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();

        let mut streams = streams(OutputMode::Human);
        let code = init(
            &InitArgs {
                path: path.clone(),
                force: true,
            },
            &mut streams,
        );

        assert_eq!(code, ExitCode::Success);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("Brolga configuration")
        );
    }

    #[test]
    fn the_starter_configuration_never_shows_an_inline_secret() {
        // The file is copied and edited, so its examples teach a habit. Every secret it mentions
        // must be shown as a reference, including in the commented-out lines — an operator
        // uncommenting a bad example would produce a file that leaks.
        assert!(
            STARTER_CONFIG.contains("from_env"),
            "the starter file should demonstrate the reference form",
        );

        for line in STARTER_CONFIG.lines() {
            // Strip comment markers: a commented example is still an example.
            let content = line.trim_start().trim_start_matches('#').trim();
            let Some((key, value)) = content.split_once(':') else {
                continue;
            };

            let key = key.trim().to_lowercase();
            let looks_secret = ["token", "password", "secret", "api_key", "credential"]
                .iter()
                .any(|needle| key.contains(needle));

            if looks_secret && !value.trim().is_empty() {
                assert!(
                    key.starts_with("from_"),
                    "line {content:?} assigns a value to a secret-looking key inline",
                );
            }
        }
    }
}
