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
    /// One YAML document.
    Yaml,
    /// One JSON object per line.
    Jsonl,
    /// Aligned columns.
    Table,
    /// One JSON document.
    Json,
}

impl From<OutputModeArg> for OutputMode {
    fn from(value: OutputModeArg) -> Self {
        match value {
            OutputModeArg::Human => Self::Human,
            OutputModeArg::Json => Self::Json,
            OutputModeArg::Yaml => Self::Yaml,
            OutputModeArg::Jsonl => Self::Jsonl,
            OutputModeArg::Table => Self::Table,
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

    /// Import intelligence from one or more files.
    Ingest(IngestArgs),

    /// Pull intelligence from OpenCTI (primary) or TAXII.
    ///
    /// Read-only. Brolga never publishes back to the platform.
    Fetch(FetchArgs),

    /// Show what is in the store.
    Stats(DatabaseArgs),

    /// Show one record by identifier.
    Show(ShowArgs),

    /// List records that could not be accepted, and why.
    Quarantine(QuarantineArgs),

    /// List retained original source objects.
    Sources(DatabaseArgs),

    /// Find entities by typed filters.
    Search(SearchArgs),

    /// Show what one record is connected to, within a budget.
    Neighbours(NeighboursArgs),

    /// Take, list, and compare named graph baselines.
    #[command(subcommand)]
    Checkpoint(CheckpointCommand),

    /// Print shell completion for this build's command tree.
    /// Serve the read-only HTTP API.
    Serve(ServeArgs),

    Completion(CompletionArgs),

    /// Produce a context pack for a subject.
    Context(ContextArgs),

    /// Show what a context profile will do, without retrieving anything.
    ///
    /// The answer to "why did my pack not contain X?", available before the pack exists rather
    /// than by reading one and inferring backwards.
    ExplainPlan(ExplainPlanArgs),

    /// Validate and explain a declarative mapping for custom feed shapes.
    #[command(subcommand)]
    Mapping(MappingCommand),

    /// List the export formats this build ships.
    #[command(subcommand)]
    Export(ExportCommand),
}

/// What to ask about exporting.
#[derive(Debug, Subcommand)]
pub(crate) enum ExportCommand {
    /// List every format, with its orientation, its lossiness, and what it needs.
    ///
    /// Reading this before choosing a format is the point: "export to STIX" sounds like a change of
    /// encoding and is a change of model, and the table says which fields have nowhere to go.
    Formats,
}

/// What to do with a mapping document.
#[derive(Debug, Subcommand)]
pub(crate) enum MappingCommand {
    /// Load a mapping and report every problem found.
    ///
    /// Exits zero only if the mapping would run. A mapping that fails here would otherwise fail
    /// partway through a document, which is a worse place to learn about a typo.
    Validate(MappingFileArgs),

    /// Show what a mapping will do, without a document to do it to.
    ///
    /// Includes what the engine will refuse, whatever the mapping says — which is the half a reader
    /// evaluating a mapping from an untrusted source needs most.
    Explain(MappingFileArgs),
}

/// A mapping document to read.
#[derive(Debug, Args)]
pub(crate) struct MappingFileArgs {
    /// The mapping file. YAML or JSON.
    pub(crate) path: PathBuf,
}

/// `brolga context`.
#[derive(Debug, Args)]
pub(crate) struct ContextArgs {
    /// The observable kind: `ip`, `domain`, `url`, `email`, or `hash`.
    pub(crate) kind: String,

    /// The value, in whatever spelling you have. It is canonicalised before lookup.
    pub(crate) value: String,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,

    /// How much to return: `L0` through `L3`.
    ///
    /// `L4` and `L5` are reached by expanding a handle rather than by asking for a pack, because
    /// serving them would make one decision cover an unbounded amount of source material.
    #[arg(long, default_value = "L1")]
    pub(crate) detail_level: String,

    /// The purpose this is for, which names a profile.
    #[arg(long)]
    pub(crate) purpose: Option<String>,

    /// How many records to gather.
    #[arg(long, default_value_t = 100)]
    pub(crate) max_objects: u64,

    /// How many relationships to gather.
    #[arg(long, default_value_t = 100)]
    pub(crate) max_relationships: u64,

    /// Write the pack in an export format instead of printing it.
    ///
    /// `brolga export formats` lists them with what each one costs you. The policy decision is made
    /// **after** the format is chosen, because which capability an export needs depends on it: reading
    /// your own pack as Markdown is a read, and producing a STIX bundle is redistribution.
    #[arg(long, value_name = "NAME")]
    pub(crate) format: Option<String>,
}

/// `brolga explain-plan`.
#[derive(Debug, Args)]
pub(crate) struct ExplainPlanArgs {
    /// Which profile to explain. Omitted lists every profile instead.
    pub(crate) profile: Option<String>,

    /// The environment to evaluate relevance against.
    #[arg(long)]
    pub(crate) environment: Option<String>,
}

/// `brolga ingest`.
#[derive(Debug, Args)]
pub(crate) struct IngestArgs {
    /// Files to read. Format is detected per file.
    #[arg(required = true)]
    pub(crate) paths: Vec<PathBuf>,

    /// How to treat records that cannot be accepted.
    ///
    /// Strict by default: a feed that has started producing records Brolga cannot read should not
    /// be half-imported, because a partial dataset is easily mistaken for a complete one.
    #[arg(long, value_enum, default_value_t = Mode::Strict)]
    pub(crate) mode: Mode,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,

    /// Parse and report without writing anything.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Do not retain the original source bytes.
    ///
    /// Named so the loss is obvious at the call site. Retained evidence is what makes a
    /// disagreement with an upstream platform settleable.
    #[arg(long)]
    pub(crate) no_retain: bool,

    /// Stop after this many seconds.
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,

    /// Read the files through this declarative mapping, and through nothing else.
    ///
    /// The mapping is validated before a byte of feed data is read, and it becomes the only parser
    /// for this batch — the compiled parsers are not consulted. A mixed batch of a STIX bundle and an
    /// in-house CSV is therefore two invocations, which is clearer than a precedence rule.
    ///
    /// A mapping pointed at the wrong kind of file fails loudly: the mapping declares its source
    /// shape, and bytes of another shape are declined rather than run against paths that cannot
    /// match.
    #[arg(long, value_name = "FILE")]
    pub(crate) mapping: Option<PathBuf>,
}

/// How ingestion treats a record it cannot accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Mode {
    /// Any rejection fails the whole batch and nothing is written.
    Strict,
    /// Acceptable records are written; the rest are quarantined.
    Permissive,
}

/// Commands that only need to know which database to read.
///
/// A separate struct so every command names the database the same way. Two commands spelling it
/// differently is how `stats` ends up reporting zero for a store `ingest` had just filled.
#[derive(Debug, Args)]
pub(crate) struct DatabaseArgs {
    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga fetch`.
#[derive(Debug, Args)]
pub(crate) struct FetchArgs {
    /// Which protocol to speak.
    #[command(subcommand)]
    pub(crate) source: FetchSource,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite", global = true)]
    pub(crate) database: PathBuf,

    /// Permit connections to private and loopback addresses.
    ///
    /// Off by default. This is the SSRF control: an operator with an internal server sets it
    /// deliberately. It does **not** permit the cloud metadata address, which stays refused
    /// regardless — enabling internal fetches almost never means "and also let a feed read my
    /// instance credentials".
    #[arg(long, global = true)]
    pub(crate) allow_private: bool,

    /// Permit plaintext HTTP.
    ///
    /// Off by default. A request to an intelligence platform carries a credential and describes
    /// what an organisation is investigating; both are worth protecting in transit.
    #[arg(long, global = true)]
    pub(crate) allow_http: bool,

    /// Ignore the stored entity tag and re-fetch regardless.
    #[arg(long, global = true)]
    pub(crate) no_etag: bool,

    /// Objects to request per page.
    #[arg(long, default_value_t = 100, global = true)]
    pub(crate) page_size: usize,

    /// Stop after this many pages per feed.
    ///
    /// A server can always claim more pages remain. A run stopped by this bound reports `partial`
    /// rather than `complete`, so "stopped early" never reads as "up to date".
    #[arg(long, default_value_t = 1000, global = true)]
    pub(crate) max_pages: usize,

    /// Stop after this many seconds.
    #[arg(long, global = true)]
    pub(crate) timeout_seconds: Option<u64>,
}

/// Which upstream a fetch reads.
///
/// OpenCTI is the primary product integration. TAXII is for STIX collections outside OpenCTI.
/// Subcommands rather than a `--type` flag: the two protocols do not take the same arguments.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum FetchSource {
    /// Poll an OpenCTI instance (GraphQL → `toStix` → STIX parser). **Primary TI source.**
    Opencti(OpenCtiArgs),
    /// Read a TAXII 2.0 or 2.1 server (secondary STIX collections).
    Taxii(TaxiiArgs),
}

impl FetchSource {
    /// The connector's name, for a diagnostic.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Opencti(_) => "opencti",
            Self::Taxii(_) => "taxii",
        }
    }
}

/// `brolga fetch taxii`.
#[derive(Debug, Args)]
pub(crate) struct TaxiiArgs {
    /// The TAXII server's base URL.
    ///
    /// Discovery is attempted at `/taxii2/` and then `/taxii/`, so the base is what to give here
    /// rather than either path.
    pub(crate) url: String,

    /// Which collection to read. Repeatable.
    ///
    /// Omitted means every readable collection the server offers, which is what an operator
    /// syncing a whole server wants and is a large enough action to be worth spelling out rather
    /// than reaching by default from a bare command.
    #[arg(long = "collection")]
    pub(crate) collections: Vec<String>,

    /// List what the server offers and stop, without fetching or storing anything.
    #[arg(long)]
    pub(crate) discover_only: bool,
}

/// `brolga fetch opencti` — primary remote TI source.
#[derive(Debug, Args)]
pub(crate) struct OpenCtiArgs {
    /// The OpenCTI instance's base URL. The GraphQL endpoint is `<url>/graphql`.
    pub(crate) url: String,

    /// A name for this instance, defaulting to the URL's host.
    ///
    /// Half of the cursor key it owns, so an instance that moves hostname does not resync.
    #[arg(long)]
    pub(crate) name: Option<String>,
}

/// `brolga serve`.
#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    /// The address to bind.
    ///
    /// Loopback by default. Binding anything reachable from another host requires a token in
    /// `BROLGA_API_TOKEN`, and the server refuses to start without one.
    #[arg(long, default_value = "127.0.0.1:8787")]
    pub(crate) bind: String,

    /// How long a single request may run.
    #[arg(long, default_value_t = 10)]
    pub(crate) timeout_seconds: u64,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga show`.
#[derive(Debug, Args)]
pub(crate) struct ShowArgs {
    /// The record identifier, as printed by `brolga stats` or `brolga quarantine`.
    pub(crate) id: String,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga quarantine`.
#[derive(Debug, Args)]
pub(crate) struct QuarantineArgs {
    /// Show only rejections from this source object digest.
    #[arg(long)]
    pub(crate) source: Option<String>,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga search`.
#[derive(Debug, Args)]
pub(crate) struct SearchArgs {
    /// Safe query language expression (ADR 0011). Example: `kind = threat_actor and status = active`.
    ///
    /// Compiles to the same typed filter as `--kind` / `--status`. Cannot inject SQL.
    #[arg(long = "query", value_name = "EXPR")]
    pub(crate) query: Option<String>,

    /// Only entities of these kinds. Repeatable. Omitted admits every kind.
    #[arg(long = "kind", value_name = "KIND")]
    pub(crate) kinds: Vec<String>,

    /// Only entities with these lifecycle statuses. Repeatable.
    ///
    /// Not defaulted to `active`. Somebody investigating why a record was withdrawn needs the
    /// revoked ones, and a hidden default would answer a different question from the one asked.
    #[arg(long = "status", value_name = "STATUS")]
    pub(crate) statuses: Vec<String>,

    /// How many to return.
    #[arg(long, default_value_t = 50)]
    pub(crate) limit: u32,

    /// How many to skip.
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: u64,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga neighbours`.
#[derive(Debug, Args)]
pub(crate) struct NeighboursArgs {
    /// The record to walk out from, as printed by `brolga search`.
    pub(crate) id: String,

    /// How many hops.
    #[arg(long, default_value_t = 2)]
    pub(crate) depth: u32,

    /// Most records to visit.
    #[arg(long, default_value_t = 200)]
    pub(crate) max_nodes: usize,

    /// Most edges to expand.
    #[arg(long, default_value_t = 1000)]
    pub(crate) max_edges: usize,

    /// Most edges to follow out of any one record.
    #[arg(long, default_value_t = 100)]
    pub(crate) max_fan_out: u32,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// Named graph baselines.
#[derive(Debug, Subcommand)]
pub(crate) enum CheckpointCommand {
    /// Capture a baseline and store it under a name.
    Take(CheckpointTakeArgs),

    /// List stored baselines.
    List(DatabaseArgs),

    /// Report what changed between two baselines.
    Diff(CheckpointDiffArgs),

    /// Remove a stored baseline.
    Remove(CheckpointRemoveArgs),
}

/// `brolga checkpoint take`.
#[derive(Debug, Args)]
pub(crate) struct CheckpointTakeArgs {
    /// The name to store it under. Re-taking a name moves that baseline.
    pub(crate) name: String,

    /// The record to capture around.
    #[arg(long)]
    pub(crate) from: String,

    /// How many hops the capture covers.
    #[arg(long, default_value_t = 3)]
    pub(crate) depth: u32,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga checkpoint diff`.
#[derive(Debug, Args)]
pub(crate) struct CheckpointDiffArgs {
    /// The earlier baseline.
    pub(crate) before: String,

    /// The later baseline.
    pub(crate) after: String,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga checkpoint remove`.
#[derive(Debug, Args)]
pub(crate) struct CheckpointRemoveArgs {
    /// The baseline to remove.
    pub(crate) name: String,

    /// Where the database lives.
    #[arg(long, default_value = "brolga.sqlite")]
    pub(crate) database: PathBuf,
}

/// `brolga completion`.
#[derive(Debug, Args)]
pub(crate) struct CompletionArgs {
    /// Which shell.
    #[arg(value_enum)]
    pub(crate) shell: clap_complete::Shell,
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
    /// The command's name, as typed.
    #[must_use]
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::Doctor => "doctor",
            Self::Config(_) => "config",
            Self::ExitCodes => "exit-codes",
            Self::Ingest(_) => "ingest",
            Self::Fetch(_) => "fetch",
            Self::ExplainPlan(_) => "explain-plan",
            Self::Stats(_) => "stats",
            Self::Show(_) => "show",
            Self::Quarantine(_) => "quarantine",
            Self::Sources(_) => "sources",
            Self::Search(_) => "search",
            Self::Neighbours(_) => "neighbours",
            Self::Checkpoint(_) => "checkpoint",
            Self::Serve(_) => "serve",
            Self::Completion(_) => "completion",
            Self::Context(_) => "context",
            Self::Mapping(_) => "mapping",
            Self::Export(_) => "export",
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

    /// So the failure is about the version rather than about the arguments. `ingest` used to be
    /// the example here and is now implemented, which is the point of the test moving rather than
    /// `context` now takes real arguments, so a subject parses as a kind and a value rather than
    /// as an opaque pass-through.
    ///
    /// This test asserted the opposite until `context` was implemented: it was the last command
    /// accepting arguments it would not act on.
    #[test]
    fn context_parses_real_arguments() {
        let parsed = Cli::try_parse_from([
            "brolga",
            "context",
            "ip",
            "203.0.113.42",
            "--detail-level",
            "L2",
        ])
        .unwrap();
        match parsed.command {
            Command::Context(args) => {
                assert_eq!(args.kind, "ip");
                assert_eq!(args.value, "203.0.113.42");
                assert_eq!(args.detail_level, "L2");
            }
            other => panic!("expected context, got {other:?}"),
        }
    }

    /// `ingest` now takes real arguments, so a file path parses as a path rather than as an opaque
    /// pass-through.
    #[test]
    fn ingest_parses_real_arguments() {
        let parsed = Cli::try_parse_from([
            "brolga",
            "ingest",
            "bundle.json",
            "--mode",
            "permissive",
            "--dry-run",
        ])
        .unwrap();
        match parsed.command {
            Command::Ingest(args) => {
                assert_eq!(args.paths.len(), 1);
                assert!(args.dry_run);
                assert_eq!(args.mode, Mode::Permissive);
            }
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
        assert!(Cli::try_parse_from(["brolga", "--output", "hieroglyphs", "doctor"]).is_err());
        assert!(Cli::try_parse_from(["brolga", "--log-level", "shouty", "doctor"]).is_err());
    }

    /// Every output mode the enum defines is accepted on the command line. A mode that exists in
    /// code but is rejected by the parser is worse than one that does not exist: `--help` lists it.
    #[test]
    fn every_declared_output_mode_parses() {
        for mode in ["human", "json", "yaml", "jsonl", "table"] {
            let parsed = Cli::try_parse_from(["brolga", "--output", mode, "doctor"]);
            assert!(parsed.is_ok(), "--output {mode} was rejected");
        }
    }

    #[test]
    fn every_command_has_a_stable_name() {
        use std::collections::BTreeSet;
        let names: BTreeSet<&str> = [
            vec!["brolga", "init"],
            vec!["brolga", "doctor"],
            vec!["brolga", "config", "validate"],
            vec!["brolga", "exit-codes"],
            vec!["brolga", "ingest", "bundle.json"],
            vec!["brolga", "stats"],
            vec!["brolga", "show", "entity:x"],
            vec!["brolga", "sources"],
            vec!["brolga", "quarantine"],
            vec!["brolga", "context", "ip", "203.0.113.1"],
        ]
        .into_iter()
        .map(|argv| Cli::try_parse_from(argv).unwrap().command.name())
        .collect();
        assert_eq!(names.len(), 10, "every command has a distinct stable name");
    }

    #[test]
    fn log_directives_match_the_level_names() {
        assert_eq!(LogLevelArg::Error.directive(), "error");
        assert_eq!(LogLevelArg::Trace.directive(), "trace");
    }
}
