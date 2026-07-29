//! JSON Schema documents for every top-level canonical type.
//!
//! ADR 0001 §6 makes JSON Schema documents a compatibility surface in their own right, carrying a
//! `$id` that ends in the same `brolga.<name>/<major>.<minor>` as the payload's `schema_version`.
//! The `$id` is a URN rather than an HTTPS URL: an HTTPS `$id` would imply Brolga operates a schema
//! registry that it does not operate, and a consumer that tried to dereference it would get a
//! 404 rather than a schema.
//!
//! These documents are generated from the Rust types, not maintained beside them, so they cannot
//! drift. [`all_schemas`] is the whole set, which is what a consumer needs to validate a payload
//! whose type it does not know in advance.

use std::collections::BTreeMap;

use schemars::{JsonSchema, SchemaGenerator};
use serde_json::Value;

use crate::claim::Claim;
use crate::entity::Entity;
use crate::observable::Observable;
use crate::pack::ContextPack;
use crate::provenance::{Provenance, SourceObject};
use crate::relationship::Relationship;
use crate::sighting::Sighting;
use crate::version::VersionedSchema;

/// Generate the JSON Schema document for one versioned type, with its `$id` set.
#[must_use]
pub fn schema_for<T: VersionedSchema + JsonSchema>() -> Value {
    let schema = SchemaGenerator::default().into_root_schema_for::<T>();
    let mut value = schema.to_value();

    if let Value::Object(object) = &mut value {
        // Inserted rather than derived, because `$id` identifies the *document*, and schemars has
        // no way to know the versioned URN this project assigns it.
        object.insert("$id".to_owned(), Value::String(T::schema_document_id()));
        object.insert(
            "x-brolga-schema-version".to_owned(),
            Value::String(T::schema_identifier()),
        );
    }

    value
}

/// Every top-level canonical schema, keyed by schema name.
///
/// Adding a type here is part of adding a top-level canonical type; the
/// `every_versioned_type_is_published` test fails if the two drift apart.
#[must_use]
pub fn all_schemas() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (Entity::SCHEMA_NAME, schema_for::<Entity>()),
        (Relationship::SCHEMA_NAME, schema_for::<Relationship>()),
        (Claim::SCHEMA_NAME, schema_for::<Claim>()),
        (Sighting::SCHEMA_NAME, schema_for::<Sighting>()),
        (Observable::SCHEMA_NAME, schema_for::<Observable>()),
        (SourceObject::SCHEMA_NAME, schema_for::<SourceObject>()),
        (Provenance::SCHEMA_NAME, schema_for::<Provenance>()),
        (ContextPack::SCHEMA_NAME, schema_for::<ContextPack>()),
    ])
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
    fn every_schema_carries_a_versioned_urn_id() {
        for (name, schema) in all_schemas() {
            let id = schema
                .get("$id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{name} has no $id"));

            assert!(id.starts_with("urn:brolga:schema:"), "{name}: {id}");

            // The *shape*, not a literal `1.0`. Pinning the version here made the test fail the
            // first time a type took a legitimate minor bump — which is the case the versioning
            // rule exists to allow, so a test that forbade it was asserting the wrong thing.
            let version = id
                .strip_prefix(&format!("urn:brolga:schema:{name}/"))
                .unwrap_or_else(|| {
                    panic!("{name}: $id must end in <name>/<major>.<minor>, found {id}")
                });
            let (major, minor) = version.split_once('.').unwrap_or_else(|| {
                panic!("{name}: version must be <major>.<minor>, found {version}")
            });
            assert!(
                major.parse::<u16>().is_ok() && minor.parse::<u16>().is_ok(),
                "{name}: version must be numeric, found {version}"
            );
        }
    }

    #[test]
    fn schema_ids_are_unique() {
        let schemas = all_schemas();
        let ids: std::collections::BTreeSet<_> = schemas
            .values()
            .filter_map(|schema| schema.get("$id").and_then(Value::as_str))
            .collect();
        assert_eq!(
            ids.len(),
            schemas.len(),
            "two schemas share an $id, so a consumer cannot tell them apart"
        );
    }

    #[test]
    fn schema_id_matches_the_payload_schema_version() {
        // The document's identity and the payload's declared version must agree, or a consumer
        // that selects a schema by the payload's `schema_version` picks the wrong document.
        let entity = schema_for::<Entity>();
        assert_eq!(
            entity.get("$id").and_then(Value::as_str),
            Some("urn:brolga:schema:brolga.entity/1.1"),
        );
        assert_eq!(
            entity
                .get("x-brolga-schema-version")
                .and_then(Value::as_str),
            Some("brolga.entity/1.1"),
        );
    }

    #[test]
    fn every_versioned_type_is_published() {
        // A top-level type whose schema is not published cannot be validated by a consumer.
        let published: std::collections::BTreeSet<_> = all_schemas().keys().copied().collect();
        for expected in [
            Entity::SCHEMA_NAME,
            Relationship::SCHEMA_NAME,
            Claim::SCHEMA_NAME,
            Sighting::SCHEMA_NAME,
            Observable::SCHEMA_NAME,
            SourceObject::SCHEMA_NAME,
            Provenance::SCHEMA_NAME,
            ContextPack::SCHEMA_NAME,
        ] {
            assert!(published.contains(expected), "{expected} is not published");
        }
        assert_eq!(
            published.len(),
            8,
            "a new top-level type needs a schema here"
        );
    }

    #[test]
    fn generated_schemas_are_deterministic() {
        // A schema that changed between two generations in one process could not be used as a
        // fingerprint input or committed as a golden file.
        assert_eq!(
            serde_json::to_string(&all_schemas()).unwrap(),
            serde_json::to_string(&all_schemas()).unwrap(),
        );
    }

    #[test]
    fn schemas_describe_the_fields_that_must_never_be_omitted() {
        let entity = schema_for::<Entity>();
        let properties = entity
            .get("properties")
            .and_then(Value::as_object)
            .expect("object schema");

        for required in ["schema_version", "markings", "status", "temporal"] {
            assert!(
                properties.contains_key(required),
                "entity schema omits {required}"
            );
        }
    }
}
