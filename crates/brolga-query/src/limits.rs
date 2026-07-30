//! Hard caps on query size and cost.

/// Limits applied at parse and compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum lexer tokens (including EOF).
    pub max_tokens: usize,
    /// Maximum AST nesting depth.
    pub max_depth: u32,
    /// Maximum `limit` clause value (result rows).
    pub max_result_limit: u32,
    /// Maximum query string length in bytes.
    pub max_input_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tokens: 256,
            max_depth: 8,
            max_result_limit: 1_000,
            max_input_bytes: 4_096,
        }
    }
}

impl Limits {
    /// Strict limits for tests / hostile input.
    #[must_use]
    pub const fn tight() -> Self {
        Self {
            max_tokens: 32,
            max_depth: 3,
            max_result_limit: 50,
            max_input_bytes: 256,
        }
    }
}
