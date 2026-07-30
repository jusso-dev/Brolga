//! Safe structured query language for Brolga ([#55](https://github.com/jusso-dev/Brolga/issues/55),
//! [ADR 0011](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0011-postgresql-backend-and-safe-query-language.md)).
//!
//! # What this crate does
//!
//! Parse a **closed** human syntax into an AST, enforce limits, and compile to
//! [`EntityQuery`](brolga_storage::EntityQuery) (and later other typed filters). It never builds SQL.
//!
//! # Example
//!
//! ```
//! use brolga_query::{Limits, compile_entity_query};
//!
//! let query = compile_entity_query("kind = threat_actor and status = active", &Limits::default())?;
//! assert!(!query.is_unfiltered());
//! # Ok::<(), brolga_query::QueryError>(())
//! ```

#![forbid(unsafe_code)]

pub mod compile;
pub mod error;
pub mod limits;
pub mod parse;
pub mod syntax;

pub use compile::compile_entity_query;
pub use error::{QueryError, Span};
pub use limits::Limits;
pub use parse::parse;
pub use syntax::{BinaryOp, Expr, Field, Literal};
