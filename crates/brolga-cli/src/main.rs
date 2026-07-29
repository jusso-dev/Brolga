//! The `brolga` binary.
//!
//! Parses the command line, installs diagnostics, runs one command, and returns its exit code.
//! Nothing here calls `std::process::exit`, so destructors run and every command stays testable
//! without spawning a process.
//!
//! # Two rules this file exists to enforce
//!
//! **stdout is the answer; stderr is everything else.** Commands are handed a
//! `Streams` rather than reaching for `println!`, and the workspace lints deny
//! `print_stdout` and `print_stderr` so the rule cannot be broken accidentally.
//!
//! **A command that cannot do the job fails.** `ingest` and `context` are declared, and they exit
//! `5` with a message naming the milestone that implements them. `CONTRIBUTING.md` prohibits
//! placeholders in production paths, and a command that prints "done" and does nothing is the worst
//! kind.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod context_command;
mod exit;
mod fetch_command;
mod graph_commands;
mod output;
mod plan_command;
mod serve_command;
mod store_commands;
mod telemetry;

use clap::Parser;
use tracing::info_span;

use cli::Cli;
use exit::ExitCode;
use output::{CorrelationId, Streams};

fn main() -> std::process::ExitCode {
    // `parse` exits 2 on a usage error, which is the conventional code and the one this registry
    // documents, so there is nothing to translate.
    let arguments = Cli::parse();

    telemetry::install(
        arguments.global.log_level,
        arguments.global.log_format,
        arguments.global.quiet,
        arguments.global.no_color,
    );

    let correlation = CorrelationId::generate();
    let span =
        info_span!("brolga", correlation_id = %correlation, command = arguments.command.name());
    let _entered = span.enter();

    let mut streams = Streams::process(arguments.global.output.into(), arguments.global.quiet);

    let code = commands::run(
        &arguments.command,
        &arguments.global,
        &correlation,
        &mut streams,
    );

    // A result that was buffered and never written is a result that was not produced.
    if streams.flush().is_err() && code.is_success() {
        return ExitCode::Io.into();
    }

    code.into()
}
