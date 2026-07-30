//! Closed AST for entity search expressions.

use crate::error::Span;

/// Fields the language understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// Entity kind (`threat_actor`, …).
    Kind,
    /// Lifecycle status (`active`, …).
    Status,
}

impl Field {
    /// Parse a field name, or `None` if unknown (caller maps to error).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "kind" => Some(Self::Kind),
            "status" => Some(Self::Status),
            _ => None,
        }
    }

    /// Canonical spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Status => "status",
        }
    }
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BinaryOp {
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
}

/// Literal values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Literal {
    /// Identifier or unquoted token (`threat_actor`, `active`).
    Ident(String),
    /// Double-quoted string.
    String(String),
}

/// Expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expr {
    /// `field = value` or `field != value`.
    Compare {
        /// Field.
        field: Field,
        /// Operator.
        op: BinaryOp,
        /// Right-hand side.
        value: Literal,
        /// Source span of the comparison.
        span: Span,
    },
    /// `left and right`.
    And {
        /// Left.
        left: Box<Expr>,
        /// Right.
        right: Box<Expr>,
        /// Span covering both.
        span: Span,
    },
    /// `left or right`.
    Or {
        /// Left.
        left: Box<Expr>,
        /// Right.
        right: Box<Expr>,
        /// Span covering both.
        span: Span,
    },
    /// Parenthesised group (preserved for span/depth only after parse).
    Group {
        /// Inner.
        inner: Box<Expr>,
        /// Span of the parentheses.
        span: Span,
    },
}

impl Expr {
    /// Maximum nesting depth of this tree.
    #[must_use]
    pub fn depth(&self) -> u32 {
        match self {
            Self::Compare { .. } => 1,
            Self::And { left, right, .. } | Self::Or { left, right, .. } => {
                1 + left.depth().max(right.depth())
            }
            Self::Group { inner, .. } => 1 + inner.depth(),
        }
    }
}
