//! Schema version identifiers that travel inside the payload.
//!
//! ADR 0001 §6 requires that a version identifier be *data*, not documentation: a consumer must be
//! able to branch on it without out-of-band knowledge. [`SchemaTag`] implements that rule. Every
//! top-level canonical type carries one, it is always serialised, and deserialising a payload whose
//! major version differs from this build's is an error rather than a best-effort parse.
//!
//! The tag is a zero-sized type. It costs nothing in memory and cannot be constructed holding the
//! wrong schema name, because the name comes from the type parameter rather than from a field.

use core::fmt;
use core::marker::PhantomData;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserialize, Deserializer, Error as DeError};
use serde::ser::{Serialize, Serializer};

use crate::error::{ModelError, Result, preview};

/// A type that is serialised as a self-describing, independently versioned document.
///
/// Implementors get a [`SchemaTag`] field whose value is `brolga.<name>/<major>.<minor>`.
pub trait VersionedSchema {
    /// Dotted schema name, conventionally `brolga.<thing>`.
    ///
    /// This is a compatibility surface. Renaming it is a breaking change.
    const SCHEMA_NAME: &'static str;

    /// Major version. Incremented when a field is removed, renamed, retyped, or made required.
    const SCHEMA_MAJOR: u16 = 1;

    /// Minor version. Incremented when an optional field or a non-exhaustive variant is added.
    const SCHEMA_MINOR: u16 = 0;

    /// The full identifier this build emits, for example `brolga.entity/1.0`.
    #[must_use]
    fn schema_identifier() -> String {
        format!(
            "{}/{}.{}",
            Self::SCHEMA_NAME,
            Self::SCHEMA_MAJOR,
            Self::SCHEMA_MINOR
        )
    }

    /// The JSON Schema `$id` for this type.
    ///
    /// A URN rather than an HTTPS URL, so the identifier does not imply that Brolga operates a
    /// schema-hosting service it does not operate.
    #[must_use]
    fn schema_document_id() -> String {
        format!("urn:brolga:schema:{}", Self::schema_identifier())
    }
}

/// The in-payload version identifier for `T`.
///
/// Serialises as the string `brolga.<name>/<major>.<minor>`. Deserialising checks the name and the
/// major version; a newer minor version is accepted, because minor changes are additive by
/// definition, and the unknown fields such a payload might carry are rejected separately by
/// `deny_unknown_fields` on the containing struct.
pub struct SchemaTag<T: VersionedSchema> {
    /// `fn() -> T` rather than `T` so the tag is covariant and stays `Send`, `Sync`, and `Unpin`
    /// no matter what `T` is.
    marker: PhantomData<fn() -> T>,
}

impl<T: VersionedSchema> SchemaTag<T> {
    /// The tag for this build.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }

    /// The identifier this tag serialises to.
    #[must_use]
    pub fn identifier() -> String {
        T::schema_identifier()
    }

    /// Check a received identifier against this build without needing a value.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::MalformedSchemaTag`] if the string is not `name/major.minor`,
    /// [`ModelError::SchemaNameMismatch`] if it names a different schema, and
    /// [`ModelError::UnsupportedSchemaMajor`] if the major version is not this build's.
    pub fn validate(found: &str) -> Result<()> {
        let (name, version) =
            found
                .split_once('/')
                .ok_or_else(|| ModelError::MalformedSchemaTag {
                    found: preview(found),
                    reason: "expected the form <name>/<major>.<minor>".to_owned(),
                })?;

        if name != T::SCHEMA_NAME {
            return Err(ModelError::SchemaNameMismatch {
                expected: T::SCHEMA_NAME,
                found: preview(name),
            });
        }

        let (major, minor) =
            version
                .split_once('.')
                .ok_or_else(|| ModelError::MalformedSchemaTag {
                    found: preview(found),
                    reason: "version must be <major>.<minor>".to_owned(),
                })?;

        let major: u16 = major.parse().map_err(|_| ModelError::MalformedSchemaTag {
            found: preview(found),
            reason: "major version must be a non-negative integer".to_owned(),
        })?;

        // The minor version is parsed but not compared. Parsing it rejects `1.x`; comparing it
        // would reject a forward-compatible payload that this build can read correctly.
        minor
            .parse::<u16>()
            .map_err(|_| ModelError::MalformedSchemaTag {
                found: preview(found),
                reason: "minor version must be a non-negative integer".to_owned(),
            })?;

        if major != T::SCHEMA_MAJOR {
            return Err(ModelError::UnsupportedSchemaMajor {
                name: T::SCHEMA_NAME,
                expected: T::SCHEMA_MAJOR,
                found: major,
            });
        }

        Ok(())
    }
}

impl<T: VersionedSchema> Default for SchemaTag<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: VersionedSchema> Clone for SchemaTag<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: VersionedSchema> Copy for SchemaTag<T> {}

impl<T: VersionedSchema> PartialEq for SchemaTag<T> {
    fn eq(&self, _other: &Self) -> bool {
        // Two tags of the same type are the same version by construction.
        true
    }
}

impl<T: VersionedSchema> Eq for SchemaTag<T> {}

impl<T: VersionedSchema> PartialOrd for SchemaTag<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: VersionedSchema> Ord for SchemaTag<T> {
    fn cmp(&self, _other: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}

impl<T: VersionedSchema> core::hash::Hash for SchemaTag<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        T::SCHEMA_NAME.hash(state);
        T::SCHEMA_MAJOR.hash(state);
    }
}

impl<T: VersionedSchema> fmt::Debug for SchemaTag<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&T::schema_identifier())
    }
}

impl<T: VersionedSchema> fmt::Display for SchemaTag<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&T::schema_identifier())
    }
}

impl<T: VersionedSchema> Serialize for SchemaTag<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&T::schema_identifier())
    }
}

impl<'de, T: VersionedSchema> Deserialize<'de> for SchemaTag<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let found = String::deserialize(deserializer)?;
        Self::validate(&found).map_err(D::Error::custom)?;
        Ok(Self::new())
    }
}

impl<T: VersionedSchema> JsonSchema for SchemaTag<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("SchemaTag_{}", T::SCHEMA_NAME.replace('.', "_")).into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // A pattern rather than a `const`, so a forward-compatible minor version still validates
        // against a schema generated by an older build.
        let pattern = format!(
            "^{}/{}\\.[0-9]+$",
            regex_escape(T::SCHEMA_NAME),
            T::SCHEMA_MAJOR
        );
        json_schema!({
            "type": "string",
            "pattern": pattern,
            "description": format!(
                "Schema identifier. This build emits `{}` and accepts any minor version of major {}.",
                T::schema_identifier(),
                T::SCHEMA_MAJOR,
            ),
        })
    }
}

/// Escape the regular-expression metacharacters that can appear in a schema name.
///
/// Schema names are compile-time constants under our control, so this only has to handle the
/// characters our naming convention actually uses. It escapes the wider ASCII punctuation set
/// anyway, because a future name is easier to add than this bug is to find.
fn regex_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if r".^$*+?()[]{}|\/-".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
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

    struct Example;

    impl VersionedSchema for Example {
        const SCHEMA_NAME: &'static str = "brolga.example";
    }

    struct FutureMajor;

    impl VersionedSchema for FutureMajor {
        const SCHEMA_NAME: &'static str = "brolga.example";
        const SCHEMA_MAJOR: u16 = 2;
    }

    #[test]
    fn identifier_and_id_use_the_documented_forms() {
        assert_eq!(Example::schema_identifier(), "brolga.example/1.0");
        assert_eq!(
            Example::schema_document_id(),
            "urn:brolga:schema:brolga.example/1.0"
        );
    }

    #[test]
    fn tag_serialises_as_its_identifier() {
        let tag = SchemaTag::<Example>::new();
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, "\"brolga.example/1.0\"");
    }

    #[test]
    fn accepts_a_newer_minor_version() {
        // Minor changes are additive by definition, so an older build can still read them.
        assert!(SchemaTag::<Example>::validate("brolga.example/1.7").is_ok());
        let tag: SchemaTag<Example> = serde_json::from_str("\"brolga.example/1.7\"").unwrap();
        assert_eq!(tag, SchemaTag::<Example>::new());
    }

    #[test]
    fn rejects_a_different_major_version() {
        let error = SchemaTag::<Example>::validate("brolga.example/2.0").unwrap_err();
        assert!(
            matches!(
                error,
                ModelError::UnsupportedSchemaMajor {
                    expected: 1,
                    found: 2,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(serde_json::from_str::<SchemaTag<Example>>("\"brolga.example/2.0\"").is_err());
    }

    #[test]
    fn rejects_a_different_schema_name() {
        let error = SchemaTag::<Example>::validate("brolga.entity/1.0").unwrap_err();
        assert!(
            matches!(error, ModelError::SchemaNameMismatch { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_malformed_identifiers() {
        for malformed in [
            "",
            "brolga.example",
            "brolga.example/",
            "brolga.example/1",
            "brolga.example/x.0",
            "brolga.example/1.x",
            "brolga.example/-1.0",
            "brolga.example/999999.0",
            "/1.0",
        ] {
            let result = SchemaTag::<Example>::validate(malformed);
            assert!(result.is_err(), "expected {malformed:?} to be rejected");
        }
    }

    #[test]
    fn a_second_major_version_of_the_same_name_is_a_distinct_tag() {
        assert!(SchemaTag::<FutureMajor>::validate("brolga.example/2.3").is_ok());
        assert!(SchemaTag::<FutureMajor>::validate("brolga.example/1.0").is_err());
    }

    #[test]
    fn tag_is_zero_sized() {
        assert_eq!(core::mem::size_of::<SchemaTag<Example>>(), 0);
    }

    #[test]
    fn generated_schema_matches_this_build_and_a_newer_minor() {
        let schema = schemars::schema_for!(SchemaTag<Example>);
        let value = serde_json::to_value(&schema).unwrap();
        let pattern = value
            .get("pattern")
            .and_then(serde_json::Value::as_str)
            .expect("pattern present");
        assert_eq!(pattern, r"^brolga\.example/1\.[0-9]+$");
    }

    #[test]
    fn regex_escape_escapes_dots() {
        assert_eq!(regex_escape("brolga.entity"), r"brolga\.entity");
    }
}
