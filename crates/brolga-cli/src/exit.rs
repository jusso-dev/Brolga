//! The stable exit-code registry.
//!
//! # Why this is a compatibility surface
//!
//! Exit codes are the only thing a shell script, a cron job, or a CI pipeline can reliably branch
//! on. ADR 0001 §6 therefore treats them as a versioned public surface: adding a code is a
//! compatible change, and changing what an existing code *means* is breaking, because it silently
//! changes the behaviour of automation nobody will re-test.
//!
//! The numbers are pinned by a test. Reordering the enum must not move them.
//!
//! # Why the distinctions exist
//!
//! A single non-zero exit tells automation only that something went wrong. These codes let a
//! pipeline decide: retry a `Storage` failure, alert on `ConfigInvalid`, and treat `NotImplemented`
//! as a version mismatch rather than an outage. Collapsing them into `1` would push that decision
//! into log-scraping, which breaks the first time a message is reworded.

use core::fmt;

/// A stable exit code.
///
/// The numeric values are permanent. `2` follows the long-standing Unix convention for a usage
/// error, which is also what `clap` emits, and the rest are grouped so a caller can tell "the
/// operator's input was wrong" from "the environment was wrong" from "this build cannot do it".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub(crate) enum ExitCode {
    /// The command did what was asked.
    Success,

    /// Something failed that no more specific code covers.
    ///
    /// A last resort. Reaching for this where a specific code exists pushes the decision back into
    /// log-scraping.
    Failure,

    /// The command line was not understood.
    ///
    /// `2` by convention, and what `clap` already emits, so scripts that special-case it keep
    /// working.
    Usage,

    /// Configuration could not be loaded or did not validate.
    ///
    /// Distinct from `Usage`: the command was well-formed, the configuration was not, and the fix
    /// is in a file rather than on the command line.
    ConfigInvalid,

    /// Storage could not be opened, migrated, read, or written.
    ///
    /// The code a pipeline may reasonably retry: a locked database or a busy filesystem is usually
    /// transient, where a bad configuration is not.
    Storage,

    /// The command exists but this build does not implement it.
    ///
    /// A version mismatch, not an outage. A command reserved for a later milestone exits here
    /// rather than pretending to succeed.
    NotImplemented,

    /// A file or stream could not be read or written.
    Io,

    /// Policy refused the operation.
    ///
    /// Reserved. Nothing emits it yet, and it is declared now so the number is fixed before the
    /// milestone that needs it rather than chosen under pressure alongside the feature.
    PolicyDenied,

    /// The operation was cancelled or timed out.
    ///
    /// Reserved, for the same reason as `PolicyDenied`.
    Cancelled,
}

impl ExitCode {
    /// The numeric code.
    ///
    /// Written as an explicit match rather than an `as` cast of the discriminant, so the number a
    /// caller sees comes from this table and not from where a variant happens to sit in the enum.
    /// Reordering the enum cannot move a code.
    #[must_use]
    pub(crate) const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::ConfigInvalid => 3,
            Self::Storage => 4,
            Self::NotImplemented => 5,
            Self::Io => 6,
            Self::PolicyDenied => 7,
            Self::Cancelled => 8,
        }
    }

    /// A short machine-readable name, used in structured output.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Usage => "usage",
            Self::ConfigInvalid => "config_invalid",
            Self::Storage => "storage",
            Self::NotImplemented => "not_implemented",
            Self::Io => "io",
            Self::PolicyDenied => "policy_denied",
            Self::Cancelled => "cancelled",
        }
    }

    /// A one-line description, used by `brolga doctor` and the documentation.
    #[must_use]
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Success => "the command did what was asked",
            Self::Failure => "an error with no more specific code",
            Self::Usage => "the command line was not understood",
            Self::ConfigInvalid => "configuration could not be loaded or did not validate",
            Self::Storage => "storage could not be opened, migrated, read, or written",
            Self::NotImplemented => "the command exists but this build does not implement it",
            Self::Io => "a file or stream could not be read or written",
            Self::PolicyDenied => "policy refused the operation",
            Self::Cancelled => "the operation was cancelled or timed out",
        }
    }

    /// Whether this code means the command succeeded.
    #[must_use]
    pub(crate) const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Every code, for documentation and for the registry test.
    #[must_use]
    pub(crate) const fn all() -> &'static [Self] {
        &[
            Self::Success,
            Self::Failure,
            Self::Usage,
            Self::ConfigInvalid,
            Self::Storage,
            Self::NotImplemented,
            Self::Io,
            Self::PolicyDenied,
            Self::Cancelled,
        ]
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code(), self.name())
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(value: ExitCode) -> Self {
        // `u8` is what a process can actually return; every code here is far below 256, and the
        // registry test asserts that so a future addition cannot silently wrap.
        Self::from(u8::try_from(value.code()).unwrap_or(1))
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
    use std::collections::BTreeSet;

    #[test]
    fn the_numeric_values_are_pinned() {
        // These are a public compatibility surface under ADR 0001 §6. Changing one silently changes
        // the behaviour of automation nobody will re-test, so a change must fail here first.
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Failure.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::ConfigInvalid.code(), 3);
        assert_eq!(ExitCode::Storage.code(), 4);
        assert_eq!(ExitCode::NotImplemented.code(), 5);
        assert_eq!(ExitCode::Io.code(), 6);
        assert_eq!(ExitCode::PolicyDenied.code(), 7);
        assert_eq!(ExitCode::Cancelled.code(), 8);
    }

    #[test]
    fn usage_is_two_because_that_is_what_clap_and_convention_use() {
        // Scripts special-case 2 for "you called it wrong". Diverging would break them silently.
        assert_eq!(ExitCode::Usage.code(), 2);
    }

    #[test]
    fn codes_and_names_are_unique() {
        let codes: BTreeSet<i32> = ExitCode::all().iter().map(|code| code.code()).collect();
        let names: BTreeSet<&str> = ExitCode::all().iter().map(|code| code.name()).collect();

        assert_eq!(codes.len(), ExitCode::all().len(), "duplicate exit code");
        assert_eq!(
            names.len(),
            ExitCode::all().len(),
            "duplicate exit code name"
        );
    }

    #[test]
    fn every_code_fits_in_what_a_process_can_return() {
        // A code above 255 wraps, so 256 would become 0 and report success.
        for code in ExitCode::all() {
            assert!(
                u8::try_from(code.code()).is_ok(),
                "{code} does not fit in a process exit status",
            );
        }
    }

    #[test]
    fn only_zero_means_success() {
        assert!(ExitCode::Success.is_success());
        for code in ExitCode::all().iter().filter(|code| code.code() != 0) {
            assert!(!code.is_success(), "{code} must not be treated as success");
        }
    }

    #[test]
    fn every_code_is_documented() {
        // The registry is the documentation. An undocumented code is a code nobody can act on.
        for code in ExitCode::all() {
            assert!(!code.description().is_empty(), "{code} has no description");
            assert!(
                code.name()
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{code} has a name that is awkward to match on",
            );
        }
    }

    #[test]
    fn reserved_codes_are_declared_before_they_are_needed() {
        // Fixing the number now means the milestone that needs it is not choosing it under
        // pressure alongside the feature.
        assert_eq!(ExitCode::PolicyDenied.code(), 7);
        assert_eq!(ExitCode::Cancelled.code(), 8);
    }

    #[test]
    fn display_shows_both_the_number_and_the_name() {
        assert_eq!(ExitCode::ConfigInvalid.to_string(), "3 (config_invalid)");
    }
}
