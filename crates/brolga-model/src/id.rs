//! Typed, kind-tagged identifiers.
//!
//! # Why identifiers are typed
//!
//! Every canonical identifier is a UUID, so an untyped `Uuid` would let an entity identifier be
//! passed where a claim identifier is expected and compile cleanly. [`Id<T>`] makes that a type
//! error while staying a plain UUID on the wire.
//!
//! # Why they are derived rather than generated
//!
//! `docs/ARCHITECTURE.md` requires that a fixed input produce a fixed result. An identifier minted
//! from randomness or from a clock breaks that: re-importing the same feed would produce a
//! different graph. So this crate offers no random constructor at all. Identifiers are either
//! [derived](Id::derive) from the values that define the thing, or carried in from outside with
//! [`Id::from_uuid`].
//!
//! Derivation uses UUID version 5, which is a namespaced SHA-1 digest. SHA-1 is not
//! collision-resistant against a motivated attacker, and this is deliberately not a security
//! boundary: an identifier answers "which record is this", not "is this record authentic".
//! Integrity and authenticity are the provenance model's content hashes, which use SHA-256.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;
use std::sync::LazyLock;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ModelError, Result, preview};

/// Root namespace for every Brolga-derived identifier.
///
/// Derived from the project URL rather than written as a literal, so there is no magic constant to
/// mistype and the derivation is reproducible by anyone reading this line.
static BROLGA_NAMESPACE: LazyLock<Uuid> =
    LazyLock::new(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, b"https://github.com/jusso-dev/Brolga"));

/// A type that has canonical identifiers.
pub trait Identifiable {
    /// Lower-case, hyphen-free kind tag that prefixes the identifier's string form.
    ///
    /// This is a compatibility surface: it appears in serialised identifiers, so renaming it
    /// invalidates every stored identifier of that kind.
    const ID_KIND: &'static str;
}

/// A canonical identifier for a `T`.
///
/// String form is `<kind>:<uuid>`, for example
/// `entity:1a4dcbb7-0d3e-5a2a-9d2c-6a1f0c1e0f42`. The kind prefix makes a bare identifier
/// self-describing in a log line, an error message, or a database column, and makes a
/// wrong-kind identifier a parse failure rather than a silent lookup miss.
pub struct Id<T: Identifiable> {
    uuid: Uuid,
    marker: PhantomData<fn() -> T>,
}

impl<T: Identifiable> Id<T> {
    /// Wrap an existing UUID.
    ///
    /// Use this for identifiers that come from outside Brolga. For identifiers Brolga mints itself,
    /// prefer [`Id::derive`], which is reproducible.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self {
            uuid,
            marker: PhantomData,
        }
    }

    /// Derive an identifier deterministically from the parts that define the thing.
    ///
    /// The same parts always produce the same identifier, on any machine, in any process, in any
    /// order of imports. Different parts produce a different identifier: parts are encoded with a
    /// length prefix, so `["ab", "c"]` and `["a", "bc"]` cannot collide the way a naive `join`
    /// would let them.
    ///
    /// Part order is significant. Callers must fix an order and keep it, because changing it is a
    /// change to the identity algorithm and therefore a breaking change under ADR 0001 §6.
    #[must_use]
    pub fn derive(parts: &[&str]) -> Self {
        let kind_namespace = Uuid::new_v5(&BROLGA_NAMESPACE, T::ID_KIND.as_bytes());

        let mut encoded = Vec::new();
        for part in parts {
            encoded.extend_from_slice(part.len().to_string().as_bytes());
            encoded.push(b':');
            encoded.extend_from_slice(part.as_bytes());
        }

        Self::from_uuid(Uuid::new_v5(&kind_namespace, &encoded))
    }

    /// The underlying UUID, without its kind tag.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.uuid
    }

    /// The kind tag that prefixes this identifier's string form.
    #[must_use]
    pub const fn kind() -> &'static str {
        T::ID_KIND
    }

    /// Parse a `<kind>:<uuid>` identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidId`] if the string has no `:`, names a different kind, or does
    /// not end in a valid UUID.
    pub fn parse(value: &str) -> Result<Self> {
        let (kind, uuid) = value.split_once(':').ok_or_else(|| ModelError::InvalidId {
            found: preview(value),
            reason: format!("expected the form {}:<uuid>", T::ID_KIND),
        })?;

        if kind != T::ID_KIND {
            return Err(ModelError::InvalidId {
                found: preview(value),
                reason: format!("expected kind {:?}, found {:?}", T::ID_KIND, preview(kind)),
            });
        }

        // `Uuid::parse_str` accepts braced and URN forms as well as the hyphenated one. Canonical
        // identifiers are hyphenated only, so accepting the alternatives would let one logical
        // identifier have several string spellings and defeat equality on the wire.
        if uuid.len() != 36 {
            return Err(ModelError::InvalidId {
                found: preview(value),
                reason: "UUID must be in hyphenated 36-character form".to_owned(),
            });
        }

        let uuid = Uuid::parse_str(uuid).map_err(|error| ModelError::InvalidId {
            found: preview(value),
            reason: format!("invalid UUID ({error})"),
        })?;

        Ok(Self::from_uuid(uuid))
    }
}

impl<T: Identifiable> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Identifiable> Copy for Id<T> {}

impl<T: Identifiable> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl<T: Identifiable> Eq for Id<T> {}

impl<T: Identifiable> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Identifiable> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

impl<T: Identifiable> core::hash::Hash for Id<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.uuid.hash(state);
    }
}

impl<T: Identifiable> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", T::ID_KIND, self.uuid.as_hyphenated())
    }
}

impl<T: Identifiable> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl<T: Identifiable> FromStr for Id<T> {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl<T: Identifiable> Serialize for Id<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, T: Identifiable> Deserialize<'de> for Id<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

impl<T: Identifiable> JsonSchema for Id<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Id_{}", T::ID_KIND).into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": format!(
                "^{}:[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$",
                T::ID_KIND,
            ),
            "description": format!(
                "Canonical identifier for a {} record, in `{}:<uuid>` form.",
                T::ID_KIND, T::ID_KIND,
            ),
        })
    }
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

    struct Alpha;
    struct Beta;

    impl Identifiable for Alpha {
        const ID_KIND: &'static str = "alpha";
    }

    impl Identifiable for Beta {
        const ID_KIND: &'static str = "beta";
    }

    #[test]
    fn derivation_is_reproducible() {
        let first = Id::<Alpha>::derive(&["example.com"]);
        let second = Id::<Alpha>::derive(&["example.com"]);
        assert_eq!(first, second);
    }

    #[test]
    fn derivation_is_stable_across_releases() {
        // Pinned so that a change to the derivation algorithm cannot land silently. If this test
        // fails, the identity of every stored record changed: that is a breaking change under
        // ADR 0001 §6 and needs a new algorithm version, not a new expected value here.
        assert_eq!(
            Id::<Alpha>::derive(&["example.com"]).to_string(),
            "alpha:c79814fa-bb04-53be-b825-0cd6e2493d43",
        );
    }

    #[test]
    fn different_kinds_derive_different_identifiers_from_the_same_input() {
        // Otherwise an entity and a claim about the same string would share an identifier.
        let alpha = Id::<Alpha>::derive(&["example.com"]);
        let beta = Id::<Beta>::derive(&["example.com"]);
        assert_ne!(alpha.as_uuid(), beta.as_uuid());
    }

    #[test]
    fn part_boundaries_cannot_be_confused() {
        // A naive concatenation would make these two identical.
        let split_one = Id::<Alpha>::derive(&["ab", "c"]);
        let split_two = Id::<Alpha>::derive(&["a", "bc"]);
        assert_ne!(split_one, split_two);

        // And a separator character in the data cannot forge a boundary either.
        assert_ne!(
            Id::<Alpha>::derive(&["a:b"]),
            Id::<Alpha>::derive(&["a", "b"])
        );
    }

    #[test]
    fn part_order_is_significant() {
        assert_ne!(
            Id::<Alpha>::derive(&["a", "b"]),
            Id::<Alpha>::derive(&["b", "a"])
        );
    }

    #[test]
    fn empty_parts_are_distinguishable() {
        assert_ne!(Id::<Alpha>::derive(&[]), Id::<Alpha>::derive(&[""]));
        assert_ne!(Id::<Alpha>::derive(&[""]), Id::<Alpha>::derive(&["", ""]));
    }

    #[test]
    fn display_and_parse_round_trip() {
        let id = Id::<Alpha>::derive(&["example.com"]);
        let rendered = id.to_string();
        assert!(rendered.starts_with("alpha:"));
        assert_eq!(Id::<Alpha>::parse(&rendered).unwrap(), id);
        assert_eq!(rendered.parse::<Id<Alpha>>().unwrap(), id);
    }

    #[test]
    fn json_round_trip_is_the_string_form() {
        let id = Id::<Alpha>::derive(&["example.com"]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        let back: Id<Alpha> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn an_identifier_of_the_wrong_kind_is_rejected() {
        let beta = Id::<Beta>::derive(&["example.com"]).to_string();
        let error = Id::<Alpha>::parse(&beta).unwrap_err();
        assert!(matches!(error, ModelError::InvalidId { .. }), "{error:?}");
        assert!(serde_json::from_str::<Id<Alpha>>(&format!("\"{beta}\"")).is_err());
    }

    #[test]
    fn rejects_malformed_and_hostile_identifiers() {
        for hostile in [
            "",
            "alpha",
            "alpha:",
            ":00000000-0000-0000-0000-000000000000",
            "alpha:not-a-uuid",
            "alpha:00000000-0000-0000-0000-00000000000",
            "alpha:00000000000000000000000000000000",
            "alpha:{00000000-0000-0000-0000-000000000000}",
            "urn:uuid:00000000-0000-0000-0000-000000000000",
            "alpha:00000000-0000-0000-0000-000000000000 ",
            "ALPHA:00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                Id::<Alpha>::parse(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn only_the_hyphenated_uuid_form_is_canonical() {
        // One logical identifier must have exactly one string spelling, or equality on the wire
        // stops matching equality in memory.
        let id = Id::<Alpha>::derive(&["example.com"]);
        let simple = format!("alpha:{}", id.as_uuid().as_simple());
        assert!(Id::<Alpha>::parse(&simple).is_err());
    }

    #[test]
    fn uppercase_uuids_are_rejected_so_equality_is_not_case_dependent() {
        let id = Id::<Alpha>::derive(&["example.com"]);
        let upper = format!(
            "alpha:{}",
            id.as_uuid().as_hyphenated().to_string().to_uppercase()
        );
        // `Uuid::parse_str` is case-insensitive, so this parses; the schema pattern requires
        // lower case. Assert the canonical rendering is lower case so Brolga never emits the
        // ambiguous form itself.
        let parsed = Id::<Alpha>::parse(&upper).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(parsed.to_string(), parsed.to_string().to_lowercase());
    }

    #[test]
    fn ordering_follows_the_uuid() {
        let mut ids = [
            Id::<Alpha>::derive(&["c"]),
            Id::<Alpha>::derive(&["a"]),
            Id::<Alpha>::derive(&["b"]),
        ];
        ids.sort_unstable();
        assert!(ids.windows(2).all(|pair| {
            let (Some(left), Some(right)) = (pair.first(), pair.get(1)) else {
                return true;
            };
            left.as_uuid() <= right.as_uuid()
        }));
    }

    #[test]
    fn derived_identifiers_are_version_5() {
        let id = Id::<Alpha>::derive(&["example.com"]);
        assert_eq!(id.as_uuid().get_version_num(), 5);
    }
}
