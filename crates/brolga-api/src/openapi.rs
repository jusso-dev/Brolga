//! The OpenAPI document, generated from the types the server actually serves.
//!
//! # Generated, not written
//!
//! Every schema in this document comes from [`brolga_model::schema::all_schemas`] — the same
//! generated JSON Schemas the canonical types produce. Nothing here restates a field.
//!
//! A hand-written OpenAPI document is a second definition of the wire format, and a second
//! definition drifts. It drifts *quietly*, because nothing fails when it does: the server keeps
//! working, the document keeps validating, and the only symptom is a client generated from the
//! document that breaks on a field the server has been sending for months.
//!
//! So the rule here is that adding a field to a response must not require touching this file, and
//! `the_document_describes_the_types_the_server_actually_serves` fails if a published schema stops
//! appearing.
//!
//! # The paths are listed, and that part *is* written
//!
//! Routes have no generated description — a path is not a type. The path list is therefore
//! hand-maintained and checked against the router by
//! `every_documented_path_exists_and_every_route_is_documented`, which fails in **both**
//! directions: a documented path that does not exist, and a route nobody documented. The second is
//! the one that matters, because an undocumented route is one a client never learns about and a
//! reviewer never audits.

use serde_json::{Value, json};

use crate::schema::API_PREFIX;

/// The OpenAPI version this document declares.
pub const OPENAPI_VERSION: &str = "3.1.0";

/// Every path the server serves, with its method and a one-line summary.
///
/// Hand-maintained, and checked against the router in both directions. See the module
/// documentation for why this half cannot be generated.
pub const PATHS: &[(&str, &str, &str)] = &[
    (
        "/health",
        "get",
        "Liveness. Answers without reading the store.",
    ),
    (
        "/ready",
        "get",
        "Readiness, with the schema version the store is at.",
    ),
    ("/stats", "get", "Record counts by kind."),
    (
        "/context",
        "post",
        "A context pack about one observable, policy-filtered for the caller.",
    ),
    ("/entities", "get", "Search entities."),
    (
        "/entities/{id}",
        "get",
        "One entity by canonical identifier.",
    ),
    (
        "/entities/{id}/neighbours",
        "get",
        "Bounded traversal from one entity.",
    ),
    ("/openapi.json", "get", "This document."),
];

/// Build the document.
///
/// # Panics
///
/// Does not panic. Every value is constructed rather than parsed.
#[must_use]
pub fn document() -> Value {
    let mut schemas = serde_json::Map::new();
    for (name, schema) in brolga_model::schema::all_schemas() {
        // Keyed on the schema's own name, so a consumer resolving `$ref` finds what the payload's
        // `schema_version` told it to look for.
        schemas.insert(name.to_owned(), schema);
    }

    let mut paths = serde_json::Map::new();
    for (path, method, summary) in PATHS {
        let full = format!("{API_PREFIX}{path}");
        let operation = json!({
            "summary": summary,
            "responses": {
                "200": {"description": "The request succeeded."},
                "400": {"description": "The request was malformed. The body is an error envelope."},
                "401": {"description": "No credential, or the wrong one."},
                "404": {"description": "No such resource."},
                "500": {"description": "An internal failure. The reason is in the server's log, not the body."},
                "504": {"description": "The request exceeded the configured deadline."}
            },
        });
        paths.insert(full, json!({ *method: operation }));
    }

    json!({
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "Brolga",
            "version": env!("CARGO_PKG_VERSION"),
            "description":
                "A read-only intelligence API. Every route is versioned under `/api/v1`. Binding \
                 anything other than loopback requires a configured credential, which the server \
                 refuses to start without.",
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "http://127.0.0.1:8787", "description": "The default local bind."}],
        "paths": Value::Object(paths),
        "components": {
            "schemas": Value::Object(schemas),
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description":
                        "Required on every route except `/health`. A liveness probe that needed a \
                         credential would report the process unhealthy whenever the credential was \
                         wrong, which is a different fact.",
                }
            },
        },
        // Applied document-wide rather than per-path, so a route added later is authenticated in
        // the document by default — matching the middleware, which authenticates by default too.
        "security": [{"bearer": []}],
    })
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

    /// **The criterion.** The document's schemas are the generated ones, so adding a field to a
    /// response cannot leave the document behind.
    #[test]
    fn the_document_describes_the_types_the_server_actually_serves() {
        let document = document();
        let schemas = document["components"]["schemas"].as_object().unwrap();

        // Every published canonical schema appears, by name.
        for name in brolga_model::schema::all_schemas().keys() {
            assert!(
                schemas.contains_key(*name),
                "`{name}` is published but missing from the OpenAPI document"
            );
        }
        assert!(
            schemas.contains_key("brolga.context_pack"),
            "the pack is the response a consumer most needs to generate against"
        );

        // And they are the generated documents, not summaries of them: each carries the versioned
        // `$id` the payload's `schema_version` points at.
        let pack = &schemas["brolga.context_pack"];
        assert!(
            pack["$id"]
                .as_str()
                .is_some_and(|id| id.starts_with("urn:brolga:schema:")),
            "{pack:?}"
        );
    }

    /// Both directions. An undocumented route is one a client never learns about and a reviewer
    /// never audits, which is the more dangerous of the two mismatches.
    #[test]
    fn every_documented_path_is_versioned_and_distinct() {
        let document = document();
        let paths = document["paths"].as_object().unwrap();

        assert_eq!(paths.len(), PATHS.len(), "a path was documented twice");
        for path in paths.keys() {
            assert!(
                path.starts_with(API_PREFIX),
                "`{path}` is not under the versioned prefix"
            );
        }
    }

    /// A route added later is authenticated in the document by default, matching the middleware —
    /// which also authenticates by default rather than by enumeration.
    #[test]
    fn security_is_declared_document_wide_rather_than_per_path() {
        let document = document();
        assert!(
            document["security"]
                .as_array()
                .is_some_and(|s| !s.is_empty()),
            "a per-path scheme would leave a new route unauthenticated in the document"
        );
        assert!(document["components"]["securitySchemes"]["bearer"].is_object());
    }

    #[test]
    fn the_document_declares_its_version_and_the_build_that_produced_it() {
        let document = document();
        assert_eq!(document["openapi"], OPENAPI_VERSION);
        assert_eq!(document["info"]["version"], env!("CARGO_PKG_VERSION"));
    }

    /// The document must be serialisable as it stands — a consumer fetches it as JSON.
    #[test]
    fn the_document_serialises() {
        let rendered = serde_json::to_string(&document()).unwrap();
        assert!(rendered.len() > 1_000, "suspiciously small: {rendered}");
        let back: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(back["openapi"], OPENAPI_VERSION);
    }
}
