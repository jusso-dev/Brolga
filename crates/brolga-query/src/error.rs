//! Query parse and compile errors with spans.

use thiserror::Error;

/// Byte range in the original query string (UTF-8 byte offsets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start.
    pub start: usize,
    /// Exclusive end.
    pub end: usize,
}

impl Span {
    /// Build a span.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Anything that can go wrong parsing or compiling a query.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryError {
    /// Lexer refused input.
    #[error("query syntax error at {start}..{end}: {reason}")]
    Lex {
        /// Why.
        reason: String,
        /// Start offset.
        start: usize,
        /// End offset.
        end: usize,
    },

    /// Parser refused a construct.
    #[error("query parse error at {start}..{end}: {reason}")]
    Parse {
        /// Why.
        reason: String,
        /// Start offset.
        start: usize,
        /// End offset.
        end: usize,
    },

    /// A hard limit was exceeded.
    #[error("query exceeds limit: {reason}")]
    Limit {
        /// Which limit.
        reason: String,
    },

    /// Compile refused a construct that parsed but cannot map to typed filters.
    #[error("query compile error: {reason}")]
    Compile {
        /// Why.
        reason: String,
    },
}

impl QueryError {
    /// Span when present.
    #[must_use]
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::Lex { start, end, .. } | Self::Parse { start, end, .. } => {
                Some(Span::new(*start, *end))
            }
            Self::Limit { .. } | Self::Compile { .. } => None,
        }
    }
}
