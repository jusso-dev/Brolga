//! The JSON Schema for a Brolga configuration document.
//!
//! Generated from the Rust types, so it cannot drift from what the loader actually accepts. An
//! editor pointed at this schema gives an operator completion and validation before they run
//! anything, which is the cheapest possible moment to catch a typo.
//!
//! The `$id` is a URN rather than an HTTPS URL, for the same reason as the canonical schemas: an
//! HTTPS identifier would imply Brolga operates a schema registry that it does not.

use schemars::SchemaGenerator;
use serde_json::Value;

use crate::model::{BrolgaConfig, CONFIG_VERSION};

/// The JSON Schema `$id` for the configuration format.
#[must_use]
pub fn schema_id() -> String {
    format!("urn:brolga:schema:brolga.config/{CONFIG_VERSION}.0")
}

/// Generate the configuration JSON Schema.
#[must_use]
pub fn config_schema() -> Value {
    let schema = SchemaGenerator::default().into_root_schema_for::<BrolgaConfig>();
    let mut value = schema.to_value();

    if let Value::Object(object) = &mut value {
        object.insert("$id".to_owned(), Value::String(schema_id()));
        object.insert(
            "x-brolga-config-version".to_owned(),
            Value::Number(CONFIG_VERSION.into()),
        );
    }

    value
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
    fn the_schema_is_versioned_and_identified() {
        let schema = config_schema();
        assert_eq!(
            schema.get("$id").and_then(Value::as_str),
            Some("urn:brolga:schema:brolga.config/1.0"),
        );
        assert_eq!(
            schema
                .get("x-brolga-config-version")
                .and_then(Value::as_u64),
            Some(1),
        );
    }

    #[test]
    fn the_schema_describes_every_top_level_section() {
        let schema = config_schema();
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("object schema");

        for section in ["version", "storage", "limits", "logging", "secrets"] {
            assert!(properties.contains_key(section), "schema omits {section}");
        }
    }

    #[test]
    fn the_schema_forbids_unknown_fields_so_an_editor_catches_a_typo() {
        let schema = config_schema();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "the loader rejects unknown fields, so the schema must too",
        );
    }

    #[test]
    fn the_schema_marks_secret_references_as_reference_only() {
        // An operator's editor should be able to tell them a bare string is wrong before they run
        // anything.
        let schema = config_schema().to_string();
        assert!(schema.contains("reference-only"), "{schema}");
        assert!(schema.contains("from_env"), "{schema}");
        assert!(schema.contains("from_file"), "{schema}");
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(config_schema().to_string(), config_schema().to_string());
    }
}
