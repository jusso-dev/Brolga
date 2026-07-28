//! Output streams, output modes, and the run's correlation identifier.
//!
//! # stdout is the answer, stderr is everything else
//!
//! The rule is absolute and it exists so that `brolga ... | jq` works. Anything on stdout is the
//! command's result; progress, warnings, and diagnostics go to stderr. A single stray `println!` of
//! a log line breaks every pipeline that parses stdout, and it breaks it *intermittently* —
//! whenever the condition that produces the message happens to occur.
//!
//! That is why callers here are handed a [`Streams`] rather than reaching for `println!`, and why
//! the workspace lints deny `print_stdout` and `print_stderr` outright.
//!
//! # What is never written anywhere
//!
//! Two categories, on any stream, at any log level:
//!
//! - **Resolved secret values.** `brolga-config` never loads one, so there is nothing here to
//!   leak — the guarantee is structural rather than a filter.
//! - **Source bodies.** Imported narrative is untrusted, potentially large, and frequently
//!   restricted. Diagnostics name a record by identifier and let a caller ask for the content
//!   explicitly.
//!
//! # The correlation identifier
//!
//! One per run, on every log line, and in structured output. It is random, and that is deliberate:
//! `brolga-model` has no random identifier constructor because canonical identity must be
//! reproducible, but a correlation identifier is not intelligence. It answers "which invocation
//! produced these lines", and reproducibility would defeat that.

use core::fmt;
use std::io::{self, IsTerminal, Write};

use serde::Serialize;

/// How a command's result is rendered on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub(crate) enum OutputMode {
    /// Readable text for a person.
    #[default]
    Human,
    /// One JSON document, for a machine.
    Json,
}

impl OutputMode {
    /// The value accepted on the command line.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for OutputMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A correlation identifier for one invocation.
///
/// Rendered as a plain lower-case hexadecimal string rather than a canonical Brolga identifier,
/// because it identifies a *run* and not a record, and blurring the two in a log would invite
/// someone to look it up in the graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CorrelationId(String);

impl CorrelationId {
    /// Generate a new identifier for this run.
    #[must_use]
    pub(crate) fn generate() -> Self {
        Self(uuid::Uuid::new_v4().as_simple().to_string())
    }

    /// The identifier.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The two output streams, and the mode results are rendered in.
///
/// Held by value so tests can substitute buffers and assert what landed where — a rule that is only
/// checked by reading the code is a rule that drifts.
pub(crate) struct Streams<Out: Write, Err: Write> {
    out: Out,
    err: Err,
    mode: OutputMode,
    quiet: bool,
}

impl Streams<io::Stdout, io::Stderr> {
    /// The real process streams.
    #[must_use]
    pub(crate) fn process(mode: OutputMode, quiet: bool) -> Self {
        Self {
            out: io::stdout(),
            err: io::stderr(),
            mode,
            quiet,
        }
    }
}

impl<Out: Write, Err: Write> Streams<Out, Err> {
    /// Build over arbitrary writers.
    ///
    /// Used only by tests today, which is the point: the stdout/stderr split is a rule, and a rule
    /// checked only by reading the code is a rule that drifts. Substituting buffers is what lets a
    /// test assert what actually landed where.
    #[cfg_attr(not(test), expect(dead_code, reason = "constructed by tests"))]
    pub(crate) const fn new(out: Out, err: Err, mode: OutputMode, quiet: bool) -> Self {
        Self {
            out,
            err,
            mode,
            quiet,
        }
    }

    /// The output mode.
    pub(crate) const fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Write a line of result to stdout.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the stream cannot be written.
    pub(crate) fn result_line(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.out, "{line}")
    }

    /// Write a structured result to stdout as one JSON document.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the value cannot be encoded or the stream cannot be written.
    pub(crate) fn result_json<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        let encoded = serde_json::to_string_pretty(value)
            .map_err(|error| io::Error::other(error.to_string()))?;
        writeln!(self.out, "{encoded}")
    }

    /// Write a diagnostic to stderr.
    ///
    /// Suppressed by `--quiet`, which is what `--quiet` is *for*: it silences commentary, and it
    /// must never silence the result, or a script would read an empty answer as an empty result.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the stream cannot be written.
    pub(crate) fn note(&mut self, line: &str) -> io::Result<()> {
        if self.quiet {
            return Ok(());
        }
        writeln!(self.err, "{line}")
    }

    /// Write an error to stderr.
    ///
    /// Never suppressed by `--quiet`. A silent failure is the one thing worse than a noisy one.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the stream cannot be written.
    pub(crate) fn problem(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.err, "{line}")
    }

    /// Flush both streams.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if either stream cannot be flushed.
    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.out.flush()?;
        self.err.flush()
    }

    /// The captured writers, for tests.
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by tests"))]
    pub(crate) fn into_parts(self) -> (Out, Err) {
        (self.out, self.err)
    }
}

/// Whether colour should be used.
///
/// Respects `NO_COLOR` and the absence of a terminal. Brolga's output is read by pipelines at least
/// as often as by people, and escape sequences in a captured log are noise at best.
#[must_use]
pub(crate) fn should_use_colour(explicit_no_colour: bool) -> bool {
    if explicit_no_colour || std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    io::stdout().is_terminal()
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

    fn streams(quiet: bool) -> Streams<Vec<u8>, Vec<u8>> {
        Streams::new(Vec::new(), Vec::new(), OutputMode::Human, quiet)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("valid UTF-8")
    }

    #[test]
    fn results_go_to_stdout_and_diagnostics_go_to_stderr() {
        // The rule that makes `brolga ... | jq` work. Checked rather than assumed.
        let mut streams = streams(false);
        streams.result_line("the answer").unwrap();
        streams.note("working on it").unwrap();
        streams.problem("something failed").unwrap();

        let (out, err) = streams.into_parts();
        assert_eq!(text(&out), "the answer\n");
        assert!(text(&err).contains("working on it"));
        assert!(text(&err).contains("something failed"));
        assert!(!text(&out).contains("working on it"));
        assert!(!text(&out).contains("something failed"));
    }

    #[test]
    fn structured_output_is_one_document_on_stdout() {
        let mut streams = Streams::new(Vec::new(), Vec::new(), OutputMode::Json, false);
        streams
            .result_json(&serde_json::json!({"status": "ok", "count": 2}))
            .unwrap();

        let (out, err) = streams.into_parts();
        let parsed: serde_json::Value = serde_json::from_slice(&out).expect("stdout must be JSON");
        assert_eq!(parsed["status"], "ok");
        assert!(err.is_empty(), "structured output must not touch stderr");
    }

    #[test]
    fn quiet_silences_commentary_but_never_the_result_or_an_error() {
        // Silencing the result would make a script read an empty answer as an empty result.
        let mut streams = streams(true);
        streams.result_line("the answer").unwrap();
        streams.note("working on it").unwrap();
        streams.problem("something failed").unwrap();

        let (out, err) = streams.into_parts();
        assert_eq!(text(&out), "the answer\n");
        assert!(!text(&err).contains("working on it"));
        assert!(
            text(&err).contains("something failed"),
            "a silent failure is worse than a noisy one",
        );
    }

    #[test]
    fn correlation_identifiers_are_unique_per_run() {
        let first = CorrelationId::generate();
        let second = CorrelationId::generate();
        assert_ne!(first, second);
    }

    #[test]
    fn a_correlation_identifier_is_not_shaped_like_a_canonical_identifier() {
        // Blurring the two in a log invites somebody to look a run up in the graph.
        let id = CorrelationId::generate();
        assert!(!id.as_str().contains(':'), "{id}");
        assert!(!id.as_str().contains('-'), "{id}");
        assert_eq!(id.as_str().len(), 32);
        assert!(id.as_str().chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn output_modes_render_as_the_values_accepted_on_the_command_line() {
        assert_eq!(OutputMode::Human.as_str(), "human");
        assert_eq!(OutputMode::Json.as_str(), "json");
        assert_eq!(OutputMode::default(), OutputMode::Human);
    }

    #[test]
    fn no_colour_is_respected_when_explicitly_requested() {
        assert!(!should_use_colour(true));
    }
}
