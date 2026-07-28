//! The command tree.
//!
//! # Commands that do not exist yet still appear here
//!
//! `ingest` and `context` are declared and exit with
//! [`ExitCode::NotImplemented`](crate::exit::ExitCode::NotImplemented). Hiding them until they work
//! would mean a script written against a later Brolga fails with an unhelpful "unrecognised
//! subcommand"; declaring them means it fails with a message naming the milestone that adds the
//! capability.
//!
//! What they must never do is *appear* to work. `CONTRIBUTING.md` prohibits placeholders in
//! production paths, and a command that prints "done" and does nothing is the worst kind.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::output::OutputMode;

/// Brolga — make sense of the signal.
#[derive(Debug, Parser)]
#[command(
    name = "brolga",
    version,
    about = "Compile threat intelligence into compact, evidence-backed context",
    long_about = None,
    propagate_version = true,
    disable_help_subcommand = false,
)]
pub(crate) struct Cli {
    /// Global options that apply to every command.
    #[command(flatten)]
    pub(crate) global: GlobalOptions,

    /// The command to run.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Options that apply to every command.
#[derive(Debug, Args, Clone)]
pub(crate) struct GlobalOptions {
    /// Configuration file, repeatable. Later files override earlier ones.
    ///
    /// Layering is the point: a site-wide file plus a host overlay is the common deployment, and
    /// `config explain` reports which one supplied each setting.
    #[arg(long = "config", short = 'c', value_name = "PATH", global = true)]
    pub(crate) config: Vec<PathBuf>,

    /// How results are rendered on stdout.
    #[arg(long, short = 'o', value_enum, default_value_t = OutputModeArg::Human, global = true)]
    pub(crate) output: OutputModeArg,

    /// Minimum severity of diagnostics written to stderr.
    #[arg(long, value_enum, default_value_t = LogLevelArg::Info, global = true)]
    pub(crate) log_level: LogLevelArg,

    /// How diagnostics are rendered on stderr.
    #[arg(long, value_enum, default_value_t = LogFormatArg::Text, global = true)]
    pub(crate) log_format: LogFormatArg,

    /// Suppress commentary on stderr. Never suppresses results or errors.
    #[arg(long, short = 'q', global = true)]
    pub(crate) quiet: bool,

    /// Do not colourise output. `NO_COLOR` and a non-terminal stdout do the same.
    #[arg(long, global = true)]
    pub(crate) no_color: bool,
}

/// How results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputModeArg {
    /// Readable text.
    Human,
    /// One JSON document.
    Json,
}

impl From<OutputModeArg> for OutputMode {
    fn from(value: OutputModeArg) -> Self {
        match value {
            OutputModeArg::Human => Self::Human,
            OutputModeArg::Json => Self::Json,
        }
    }
}

/// Minimum severity of diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum LogLevelArg {
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Normal operational messages.
    Info,
    /// Detail for diagnosing a problem.
    Debug,
    /// Everything.
    Trace,
}

impl LogLevelArg {
    /// The `tracing` filter directive for this level.
    #[must_use]
    pub(crate) const fn directive(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// How diagnostics are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum LogFormatArg {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// A Brolga command.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Write a starter configuration file.
    Init(InitArgs),

    /// Check that this installation can do its job.
    Doctor,

    /// Inspect configuration.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// List the exit codes this build can return.
    ///
    /// Exit codes are a compatibility surface, so they are queryable rather than only documented.
    /// A pipeline author can read them from the binary they are actually running.
    ExitCodes,

    /// Import intelligence from a file or feed.
    ///
    /// Declared but not implemented in this build. Exits `5`.
    Ingest(NotImplementedArgs),

    /// Produce a context pack for a subject.
    ///
    /// Declared but not implemented in this build. Exits `5`.
    Context(NotImplementedArgs),
}

/// `brolga init`.
#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// Where to write the configuration file.
    #[arg(default_value = "brolga.yaml")]
    pub(crate) path: PathBuf,

    /// Overwrite an existing file.
    ///
    /// Off by default. Silently replacing an operator's configuration is not something a tool
    /// should do because a flag was forgotten.
    #[arg(long)]
    pub(crate) force: bool,
}

/// Inspecting configuration.
#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Load and validate configuration, reporting every problem found.
    Validate,

    /// Show every resolved setting and which layer supplied it.
    Explain {
        /// Show only settings that differ from the built-in defaults.
        #[arg(long)]
        changed_only: bool,
    },

    /// Print the configuration JSON Schema.
    ///
    /// Point an editor at it and a typo is caught before anything runs.
    Schema,
}

/// Arguments accepted by a command that is declared but not implemented.
///
/// Everything is accepted and nothing is acted on, so a script written for a later Brolga fails
/// with a message about the version rather than about its arguments.
#[derive(Debug, Args)]
pub(crate) struct NotImplementedArgs {
    /// Any arguments. Accepted, ignored, and reported as unimplemented.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) arguments: Vec<String>,
}

impl Command {
    /// The milestone that implements this command, for commands that are not implemented yet.
    #[must_use]
    pub(crate) const fn planned_milestone(&self) -> Option<&'static str> {
        match self {
            Self::Ingest(_) => Some("v0.2.0 — Core ingestion"),
            Self::Context(_) => Some("v0.4.0 — Compression engine"),
            _ => None,
        }
    }

    /// The command's name, as typed.
    #[must_use]
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::Doctor => "doctor",
            Self::Config(_) => "config",
            Self::ExitCodes => "exit-codes",
            Self::Ingest(_) => "ingest",
            Self::Context(_) => "context",
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
    use clap::CommandFactory;

    #[test]
    fn the_binary_is_named_brolga() {
        assert_eq!(Cli::command().get_name(), "brolga");
    }

    #[test]
    fn the_command_tree_is_internally_consistent() {
        // clap's own audit: duplicate flags, conflicting shorts, malformed help.
        Cli::command().debug_assert();
    }

    #[test]
    fn global_options_apply_to_every_subcommand() {
        // `--config` after the subcommand must work, because that is where people type it.
        let parsed = Cli::try_parse_from([
            "brolga", "config", "validate", "--config", "a.yaml", "--output", "json",
        ])
        .unwrap();
        assert_eq!(parsed.global.config, vec![PathBuf::from("a.yaml")]);
        assert_eq!(parsed.global.output, OutputModeArg::Json);
    }

    #[test]
    fn configuration_files_are_repeatable_and_keep_their_order() {
        // Layering depends on order, so it must survive parsing.
        let parsed =
            Cli::try_parse_from(["brolga", "-c", "site.yaml", "-c", "host.yaml", "doctor"])
                .unwrap();
        assert_eq!(
            parsed.global.config,
            vec![PathBuf::from("site.yaml"), PathBuf::from("host.yaml")],
        );
    }

    #[test]
    fn defaults_are_the_conservative_ones() {
        let parsed = Cli::try_parse_from(["brolga", "doctor"]).unwrap();
        assert_eq!(parsed.global.output, OutputModeArg::Human);
        assert_eq!(parsed.global.log_level, LogLevelArg::Info);
        assert_eq!(parsed.global.log_format, LogFormatArg::Text);
        assert!(!parsed.global.quiet);
    }

    #[test]
    fn init_does_not_overwrite_unless_asked() {
        let parsed = Cli::try_parse_from(["brolga", "init"]).unwrap();
        match parsed.command {
            Command::Init(args) => {
                assert!(!args.force, "overwriting must be opt-in");
                assert_eq!(args.path, PathBuf::from("brolga.yaml"));
            }
            other => panic!("expected init, got {other:?}"),
        }
    }

    #[test]
    fn unimplemented_commands_are_declared_rather_than_hidden() {
        // A script written for a later Brolga should fail with a message about the version, not
        // with "unrecognised subcommand".
        for (argv, expected) in [
            (
                vec!["brolga", "ingest", "file.json"],
                "v0.2.0 — Core ingestion",
            ),
            (
                vec!["brolga", "context", "example.com"],
                "v0.4.0 — Compression engine",
            ),
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            assert_eq!(parsed.command.planned_milestone(), Some(expected));
        }
    }

    #[test]
    fn implemented_commands_claim_no_milestone() {
        for argv in [
            vec!["brolga", "doctor"],
            vec!["brolga", "init"],
            vec!["brolga", "config", "validate"],
            vec!["brolga", "exit-codes"],
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            assert_eq!(parsed.command.planned_milestone(), None);
        }
    }

    #[test]
    fn an_unimplemented_command_accepts_arguments_it_will_not_act_on() {
        // So the failure is about the version rather than about the arguments.
        let parsed =
            Cli::try_parse_from(["brolga", "ingest", "--format", "stix", "bundle.json"]).unwrap();
        match parsed.command {
            Command::Ingest(args) => assert!(!args.arguments.is_empty()),
            other => panic!("expected ingest, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_command_is_still_a_usage_error() {
        let error = Cli::try_parse_from(["brolga", "teleport"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{error}"
        );
    }

    #[test]
    fn an_invalid_option_value_is_rejected() {
        assert!(Cli::try_parse_from(["brolga", "--output", "yaml", "doctor"]).is_err());
        assert!(Cli::try_parse_from(["brolga", "--log-level", "shouty", "doctor"]).is_err());
    }

    #[test]
    fn every_command_has_a_stable_name() {
        use std::collections::BTreeSet;
        let names: BTreeSet<&str> = [
            vec!["brolga", "init"],
            vec!["brolga", "doctor"],
            vec!["brolga", "config", "validate"],
            vec!["brolga", "exit-codes"],
            vec!["brolga", "ingest"],
            vec!["brolga", "context"],
        ]
        .into_iter()
        .map(|argv| Cli::try_parse_from(argv).unwrap().command.name())
        .collect();
        assert_eq!(names.len(), 6);
    }

    #[test]
    fn log_directives_match_the_level_names() {
        assert_eq!(LogLevelArg::Error.directive(), "error");
        assert_eq!(LogLevelArg::Trace.directive(), "trace");
    }
}
