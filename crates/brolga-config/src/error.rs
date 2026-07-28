//! Configuration errors that name the field they are about.
//!
//! An operator reading "invalid value" against a two-hundred-line file learns nothing. Every error
//! here carries the dotted path of the setting that caused it, so the message points at a line
//! rather than at a document.
//!
//! Errors are also an output path. A diagnostic that quoted a resolved secret would leak it into a
//! log, a terminal, and probably a pasted issue report — so nothing in this module ever holds a
//! secret's *value*. [`SecretRef`](crate::secret::SecretRef) is a reference, resolution happens
//! elsewhere, and the redaction is structural rather than a filter someone has to remember to
//! apply.

use core::fmt;

use thiserror::Error;

/// Maximum number of characters of an offending value that a diagnostic may quote.
const PREVIEW_CHARS: usize = 80;

/// A dotted path to a configuration setting, such as `storage.sqlite.path`.
///
/// Built during traversal, so a diagnostic can name the setting rather than the document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConfigPath(String);

impl ConfigPath {
    /// The document root.
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// A path from a dotted string.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Extend with a child segment.
    #[must_use]
    pub fn child(&self, segment: &str) -> Self {
        if self.0.is_empty() {
            Self(segment.to_owned())
        } else {
            Self(format!("{}.{segment}", self.0))
        }
    }

    /// The dotted path, or `<root>` for the document root.
    #[must_use]
    pub fn as_str(&self) -> &str {
        if self.0.is_empty() { "<root>" } else { &self.0 }
    }

    /// Whether this is the document root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ConfigPath {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Truncate and escape a value so it is safe to quote in a diagnostic.
#[must_use]
pub fn preview(value: &str) -> String {
    let mut out = String::new();
    for (count, ch) in value.chars().enumerate() {
        if count >= PREVIEW_CHARS {
            out.push('…');
            break;
        }
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// Everything that can go wrong loading, merging, or validating configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The document was larger than the limit.
    #[error("configuration is {actual} bytes, which exceeds the limit of {max} bytes")]
    TooLarge {
        /// The limit, in bytes.
        max: usize,
        /// The observed size, in bytes.
        actual: usize,
    },

    /// The document nested deeper than the limit.
    ///
    /// A depth bound is cheap and stops a pathological document from exhausting the stack during
    /// typed deserialisation.
    #[error("configuration nests {actual} levels deep at {path}, which exceeds the limit of {max}")]
    TooDeep {
        /// Where the limit was exceeded.
        path: ConfigPath,
        /// The limit.
        max: usize,
        /// The observed depth.
        actual: usize,
    },

    /// The document was not valid YAML or JSON.
    #[error("{format} at {path} could not be parsed: {reason}")]
    Syntax {
        /// Which parser was used.
        format: &'static str,
        /// Where the parser stopped, as far as it could tell.
        path: ConfigPath,
        /// The parser's message.
        reason: String,
    },

    /// A field was not recognised.
    ///
    /// Rejected rather than ignored. A silently ignored key is a setting the operator believes is
    /// in force and is not, which is worse than a failed start-up: it fails later, quietly, in
    /// whatever the setting was supposed to control.
    #[error("unknown field {field:?} at {path}{}", suggestion_suffix(.suggestion.as_deref()))]
    UnknownField {
        /// Where it appeared.
        path: ConfigPath,
        /// The unrecognised key.
        field: String,
        /// The closest known key, if one is close enough to be worth suggesting.
        suggestion: Option<String>,
    },

    /// A required field was absent and has no safe default.
    #[error("missing required field at {path}")]
    Missing {
        /// Where it should have been.
        path: ConfigPath,
    },

    /// A field had the wrong type or an unusable value.
    #[error("invalid value at {path}: {reason}")]
    Invalid {
        /// Which setting.
        path: ConfigPath,
        /// Why it was rejected.
        reason: String,
    },

    /// A numeric setting was outside its permitted range.
    #[error("{path} is {value}, which is outside the permitted range {min}..={max}")]
    OutOfRange {
        /// Which setting.
        path: ConfigPath,
        /// The supplied value.
        value: u64,
        /// Smallest permitted value.
        min: u64,
        /// Largest permitted value.
        max: u64,
    },

    /// A path contained a `..` component.
    ///
    /// Rejected wherever configuration names a file, because a relative traversal in a
    /// configuration file is how a database or a secret ends up somewhere the operator did not
    /// intend.
    #[error("{path} contains a parent-directory component, which is not permitted: {value:?}")]
    PathTraversal {
        /// Which setting.
        path: ConfigPath,
        /// A truncated, escaped preview of the offending value.
        value: String,
    },

    /// A secret was written inline instead of as a reference.
    #[error(
        "{path} contains an inline secret value; use a reference such as `{{ from_env = \"NAME\" }}` or `{{ from_file = \"/path\" }}` so the value never enters the configuration file"
    )]
    InlineSecret {
        /// Which setting.
        path: ConfigPath,
    },

    /// The configuration declared a version this build cannot interpret.
    #[error(
        "configuration version {found} is not supported by this build, which implements version {expected}"
    )]
    UnsupportedVersion {
        /// The version this build implements.
        expected: u16,
        /// The version the document declared.
        found: u16,
    },

    /// Two settings were individually valid but cannot both hold.
    #[error("{path} conflicts with {conflicts_with}: {reason}")]
    Conflict {
        /// One setting.
        path: ConfigPath,
        /// The other.
        conflicts_with: ConfigPath,
        /// Why they cannot both hold.
        reason: String,
    },
}

impl ConfigError {
    /// The setting this error is about, where it is about one.
    #[must_use]
    pub const fn path(&self) -> Option<&ConfigPath> {
        match self {
            Self::TooDeep { path, .. }
            | Self::Syntax { path, .. }
            | Self::UnknownField { path, .. }
            | Self::Missing { path }
            | Self::Invalid { path, .. }
            | Self::OutOfRange { path, .. }
            | Self::PathTraversal { path, .. }
            | Self::InlineSecret { path }
            | Self::Conflict { path, .. } => Some(path),
            Self::TooLarge { .. } | Self::UnsupportedVersion { .. } => None,
        }
    }
}

fn suggestion_suffix(suggestion: Option<&str>) -> String {
    suggestion.map_or_else(String::new, |candidate| {
        format!("; did you mean {candidate:?}?")
    })
}

/// Convenience alias for fallible configuration operations.
pub type Result<T> = core::result::Result<T, ConfigError>;

/// A collection of diagnostics.
///
/// Loading reports every problem it can find rather than stopping at the first. An operator fixing
/// a configuration file one error per run is an operator running the tool six times to learn six
/// things it already knew on the first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics(Vec<ConfigError>);

impl Diagnostics {
    /// An empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Record a problem.
    pub fn push(&mut self, error: ConfigError) {
        self.0.push(error);
    }

    /// Whether anything was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many problems were recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The recorded problems, in the order they were found.
    #[must_use]
    pub fn as_slice(&self) -> &[ConfigError] {
        &self.0
    }

    /// Consume and return the recorded problems.
    #[must_use]
    pub fn into_vec(self) -> Vec<ConfigError> {
        self.0
    }

    /// The first problem, for a caller that only needs one.
    #[must_use]
    pub fn first(&self) -> Option<&ConfigError> {
        self.0.first()
    }
}

impl FromIterator<ConfigError> for Diagnostics {
    fn from_iter<I: IntoIterator<Item = ConfigError>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

/// A collection of problems is itself an error, so a caller can use `?` on it and so it composes
/// with `Box<dyn Error>`.
///
/// `source` returns the first problem. A chain cannot represent several siblings, and picking the
/// first is more useful than picking none — the full set is still available through
/// [`Diagnostics::as_slice`] and through `Display`, which renders one per line.
impl std::error::Error for Diagnostics {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .first()
            .map(|error| -> &(dyn std::error::Error + 'static) { error })
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
    fn paths_build_dotted_and_name_the_root_readably() {
        let root = ConfigPath::root();
        assert!(root.is_root());
        assert_eq!(root.as_str(), "<root>");

        let nested = root.child("storage").child("sqlite").child("path");
        assert_eq!(nested.as_str(), "storage.sqlite.path");
        assert!(!nested.is_root());
    }

    #[test]
    fn every_field_error_names_its_setting() {
        // The point of the whole module: an operator must be told which line to look at.
        let errors = [
            ConfigError::Missing {
                path: ConfigPath::new("storage.backend"),
            },
            ConfigError::Invalid {
                path: ConfigPath::new("logging.level"),
                reason: "unknown level".to_owned(),
            },
            ConfigError::OutOfRange {
                path: ConfigPath::new("limits.max_input_bytes"),
                value: 0,
                min: 1,
                max: 100,
            },
            ConfigError::InlineSecret {
                path: ConfigPath::new("secrets.feed_token"),
            },
        ];

        for error in errors {
            let path = error.path().expect("field errors carry a path");
            assert!(
                error.to_string().contains(path.as_str()),
                "rendered error omits its path: {error}"
            );
        }
    }

    #[test]
    fn document_level_errors_have_no_path_and_say_so() {
        assert!(
            ConfigError::TooLarge {
                max: 10,
                actual: 11
            }
            .path()
            .is_none()
        );
        assert!(
            ConfigError::UnsupportedVersion {
                expected: 1,
                found: 2
            }
            .path()
            .is_none()
        );
    }

    #[test]
    fn an_unknown_field_can_suggest_the_intended_one() {
        let with = ConfigError::UnknownField {
            path: ConfigPath::new("storage"),
            field: "backedn".to_owned(),
            suggestion: Some("backend".to_owned()),
        };
        assert!(
            with.to_string().contains("did you mean \"backend\""),
            "{with}"
        );

        let without = ConfigError::UnknownField {
            path: ConfigPath::new("storage"),
            field: "wholly-unrelated".to_owned(),
            suggestion: None,
        };
        assert!(!without.to_string().contains("did you mean"), "{without}");
    }

    #[test]
    fn the_inline_secret_message_tells_the_operator_what_to_write_instead() {
        let error = ConfigError::InlineSecret {
            path: ConfigPath::new("secrets.token"),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("from_env"), "{rendered}");
        assert!(rendered.contains("from_file"), "{rendered}");
    }

    #[test]
    fn previews_are_truncated_and_stripped_of_control_characters() {
        assert_eq!(preview("a\nb"), "a\\nb");
        assert_eq!(preview("a\u{0}b"), "a\u{fffd}b");

        let long = "x".repeat(500);
        let previewed = preview(&long);
        assert_eq!(previewed.chars().count(), PREVIEW_CHARS + 1);
        assert!(previewed.ends_with('…'));
    }

    #[test]
    fn diagnostics_collect_every_problem_rather_than_only_the_first() {
        let mut diagnostics = Diagnostics::new();
        assert!(diagnostics.is_empty());

        diagnostics.push(ConfigError::Missing {
            path: ConfigPath::new("a"),
        });
        diagnostics.push(ConfigError::Missing {
            path: ConfigPath::new("b"),
        });

        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.first().is_some());

        let rendered = diagnostics.to_string();
        assert!(
            rendered.contains('a') && rendered.contains('b'),
            "{rendered}"
        );
        assert_eq!(rendered.lines().count(), 2);
    }
}
