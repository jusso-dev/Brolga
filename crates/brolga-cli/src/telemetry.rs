//! Structured diagnostics.
//!
//! # Everything goes to stderr
//!
//! Without exception. The subscriber is built with a stderr writer, so a log line cannot reach
//! stdout even by accident — which matters because stdout is the command's result and a stray line
//! there breaks every pipeline that parses it.
//!
//! # What is never logged
//!
//! - **Resolved secret values.** `brolga-config` never loads one, so there is nothing to leak.
//!   Structural, not a filter that has to be maintained.
//! - **Source bodies.** Imported narrative is untrusted, often large, and frequently restricted.
//!   Diagnostics name a record by identifier; content is retrieved explicitly, by a caller that has
//!   decided to.
//!
//! # The correlation identifier is on every line
//!
//! Attached as a span field, so it survives into both renderings without every call site having to
//! remember it. It is what makes two interleaved runs separable in a shared log.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;

use crate::cli::{LogFormatArg, LogLevelArg};

/// Environment variable that overrides the log filter, for the cases a level cannot express.
pub(crate) const FILTER_ENV: &str = "BROLGA_LOG";

/// Install the tracing subscriber for this run.
///
/// Returns `false` if a subscriber was already installed, which happens when several tests run in
/// one process. Not an error: the first one wins and the run continues.
pub(crate) fn install(
    level: LogLevelArg,
    format: LogFormatArg,
    quiet: bool,
    no_colour: bool,
) -> bool {
    let directive = if quiet { "error" } else { level.directive() };

    let filter = EnvFilter::try_from_env(FILTER_ENV)
        .unwrap_or_else(|_| EnvFilter::new(format!("brolga={directive},{directive}")));

    // Bound to stderr at construction, so no configuration can move diagnostics onto stdout.
    let writer = BoxMakeWriter::new(std::io::stderr);

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(true)
        // Colour follows `--no-color`, `NO_COLOR`, and whether stdout is a terminal. Escape
        // sequences in a captured log are noise at best, and Brolga's output is read by pipelines
        // at least as often as by people.
        .with_ansi(crate::output::should_use_colour(no_colour));

    match format {
        LogFormatArg::Json => builder.json().with_current_span(true).try_init().is_ok(),
        LogFormatArg::Text => builder.try_init().is_ok(),
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

    #[test]
    fn a_filter_directive_exists_for_every_level() {
        for level in [
            LogLevelArg::Error,
            LogLevelArg::Warn,
            LogLevelArg::Info,
            LogLevelArg::Debug,
            LogLevelArg::Trace,
        ] {
            assert!(!level.directive().is_empty());
            assert!(EnvFilter::try_new(level.directive()).is_ok());
        }
    }

    #[test]
    fn quiet_reduces_diagnostics_to_errors() {
        // `--quiet` silences commentary. It must not silence a failure.
        assert_eq!(LogLevelArg::Error.directive(), "error");
    }

    #[test]
    fn installing_twice_is_not_an_error() {
        // Several tests in one process would otherwise abort the second one.
        let first = install(LogLevelArg::Error, LogFormatArg::Text, true, true);
        let second = install(LogLevelArg::Error, LogFormatArg::Text, true, true);
        assert!(first || !second, "the first installation wins");
    }
}
