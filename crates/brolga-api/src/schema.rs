//! The versions this API's payloads carry.
//!
//! Compatibility surfaces under ADR 0001 §6. Adding a field does not move a version; removing a
//! field, renaming one, or changing a type does. A consumer that has to guess whether a field
//! moved has no way to fail safely, so it is told.

/// The version stamped on every successful response body.
pub const RESPONSE_SCHEMA: &str = "brolga.api.v1/1.0";

/// The version stamped on every error body.
///
/// Versioned separately from [`RESPONSE_SCHEMA`] because it changes for different reasons and on a
/// different schedule. A client's error handling should not need revisiting because a search
/// result grew a field.
pub const ERROR_SCHEMA: &str = "brolga.api.error/1.0";

/// The path prefix every route lives under.
pub const API_PREFIX: &str = "/api/v1";

#[cfg(test)]
mod tests {
    /// A version that does not say what it versions is not much of a version.
    #[test]
    fn the_schemas_are_distinct_and_namespaced() {
        assert_ne!(super::RESPONSE_SCHEMA, super::ERROR_SCHEMA);
        assert!(super::RESPONSE_SCHEMA.starts_with("brolga.api."));
        assert!(super::ERROR_SCHEMA.starts_with("brolga.api."));
    }

    /// Routes are versioned in the path, so a breaking change can be served alongside the old one
    /// rather than replacing it under clients that have not been updated.
    #[test]
    fn the_prefix_carries_a_version() {
        assert_eq!(super::API_PREFIX, "/api/v1");
    }
}
