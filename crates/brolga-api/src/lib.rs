//! A versioned, read-only HTTP API over a Brolga store.
//!
//! # Why this exists
//!
//! Brolga's consumers pull context to enrich something they already have: an incident-response
//! case, an endpoint alert, an agent's question. Three separate services doing that cannot each
//! shell out to the CLI over a shared SQLite file — SQLite has one writer, the binary would have
//! to be installed everywhere, and every consumer would need filesystem access to the database.
//! One process owns the file and answers questions about it.
//!
//! # What it does not do
//!
//! Writes. Ingestion stays on the CLI, where the operator running it chose the source. A read-only
//! surface is one that cannot be talked into rewriting the graph by a service that was only meant
//! to look at it — and "which of my three integrations corrupted the graph" is not a question
//! worth having to answer.
//!
//! # Binding
//!
//! The default is loopback. [`ApiConfig::bind`] refuses to serve an address reachable from another
//! host unless a credential is configured, because a store of who-attacked-whom should not be
//! readable by an unauthenticated `GET`.
//!
//! ```
//! use brolga_api::{ApiConfig, Credential};
//!
//! // Loopback needs no token.
//! let local = ApiConfig::loopback(8787);
//! assert!(!local.requires_authentication());
//!
//! // Anything else does.
//! let address = "0.0.0.0:8787".parse().unwrap();
//! assert!(ApiConfig::bind(address, None).is_err());
//!
//! let token = Credential::new("0123456789abcdef0123456789abcdef").unwrap();
//! assert!(ApiConfig::bind(address, Some(token)).is_ok());
//! ```
//!
//! # Compatibility
//!
//! Routes are versioned in the path (`/api/v1`) and bodies carry a schema version. Both are
//! compatibility surfaces under ADR 0001 §6.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod context;
pub mod error;
pub mod routes;
pub mod schema;
pub mod server;
pub mod state;
pub mod subject;

pub use auth::{Credential, CredentialRejected};
pub use config::{ApiConfig, ConfigRejected};
pub use context::{CONTEXT_PACK_SCHEMA, ContextPack, ContextRequest};
pub use error::{ApiError, ErrorBody, RequestId};
pub use schema::{API_PREFIX, ERROR_SCHEMA, RESPONSE_SCHEMA};
pub use server::{REQUEST_ID_HEADER, router, serve};
pub use state::{ApiState, ReadFailed};
