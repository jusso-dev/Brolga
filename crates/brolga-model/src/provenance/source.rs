//! Source objects: the original evidence a canonical record was derived from.
//!
//! A source object is *metadata about* and *an address for* original evidence. It is not the bytes.
//! Retention, compression, and blob storage are `v0.2.0`'s problem; what this module guarantees is
//! that a canonical record can always name the exact thing it came from, by content, so that a
//! stored blob can later be confirmed to be the same bytes the record was built from.
//!
//! # Sensitive locations
//!
//! Where evidence came from is often more sensitive than the evidence. A file path can name an
//! internal share, a URL can embed a subscription token, and a connector endpoint can identify an
//! organisation's supplier relationships. [`SensitiveText`] exists so that policy has something to
//! address: it is a distinct type, it is annotated in the generated JSON Schema, and its `Debug` and
//! `Display` implementations redact, so it cannot reach a log line by accident.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::id::{Id, Identifiable};
use crate::marking::MarkingSet;
use crate::provenance::hash::ContentHash;
use crate::temporal::Timestamp;
use crate::text::ShortText;
use crate::version::{SchemaTag, VersionedSchema};

/// Maximum length of a [`SensitiveText`], in bytes.
pub const SENSITIVE_TEXT_MAX_BYTES: usize = 2048;

/// Maximum length of a media type, in bytes.
pub const MEDIA_TYPE_MAX_BYTES: usize = 128;

// -------------------------------------------------------------------------------------------------
// Sensitive text
// -------------------------------------------------------------------------------------------------

/// A string whose *content* is restricted even when the record containing it is not.
///
/// Serialised verbatim, because the value has to survive to be usable. Redacted in `Debug` and
/// `Display`, because those are the paths by which a value reaches a log, a panic message, or an
/// error a user pastes into an issue. The type is the thing policy filters on; the redaction is a
/// safety net for the paths policy does not run on.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SensitiveText(String);

impl SensitiveText {
    /// Maximum length, in bytes.
    pub const MAX_BYTES: usize = SENSITIVE_TEXT_MAX_BYTES;

    /// Validate and wrap a sensitive string.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] if empty, [`ModelError::TooLong`] beyond [`Self::MAX_BYTES`],
    /// and [`ModelError::ForbiddenControlCharacter`] for any control character.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(ModelError::Empty {
                field: "SensitiveText",
            });
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "SensitiveText",
                max: Self::MAX_BYTES,
                actual: value.len(),
            });
        }
        if let Some((index, _)) = value.chars().enumerate().find(|(_, ch)| ch.is_control()) {
            return Err(ModelError::ForbiddenControlCharacter {
                field: "SensitiveText",
                index,
            });
        }
        Ok(Self(value))
    }

    /// The value.
    ///
    /// Named `expose` rather than `as_str` so that reading it is a visible decision at the call
    /// site and greppable in review, instead of looking like every other accessor.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A stable, non-reversible handle for this value.
    ///
    /// Lets two records be compared for "same location" in a log or a diagnostic without the
    /// location itself appearing anywhere.
    #[must_use]
    pub fn redacted_digest(&self) -> ContentHash {
        ContentHash::of_str(&self.0)
    }
}

impl fmt::Debug for SensitiveText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveText(<redacted {} bytes>)", self.0.len())
    }
}

impl fmt::Display for SensitiveText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SensitiveText {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SensitiveText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

impl JsonSchema for SensitiveText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SensitiveText".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "maxLength": SENSITIVE_TEXT_MAX_BYTES,
            "description": "A restricted value such as a source location. Policy must decide whether it may leave Brolga.",
            "x-brolga-sensitivity": "source-location",
            "x-brolga-handling": "Redact by default. Release only where policy explicitly permits it.",
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Media type
// -------------------------------------------------------------------------------------------------

/// An IANA media type such as `application/json`, recorded as the source declared it.
///
/// Validated for shape only. Brolga records what the source *said* the bytes were; it never trusts
/// that claim to decide how to parse them, because a declared media type is attacker-controlled
/// whenever the source is. Content detection is `v0.2.0`'s job and is deliberately separate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaType(String);

impl MediaType {
    /// Validate and canonicalise a media type.
    ///
    /// Lower-cased: RFC 9110 §8.3.1 makes the type and subtype case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] unless the value is `type/subtype` with both parts
    /// non-empty and drawn from the restricted token character set.
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref();
        if raw.len() > MEDIA_TYPE_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "MediaType",
                max: MEDIA_TYPE_MAX_BYTES,
                actual: raw.len(),
            });
        }

        let lowered = raw.to_ascii_lowercase();
        // Parameters such as `; charset=utf-8` are dropped: they describe an encoding, and the
        // canonical record already stores the bytes' digest. Keeping them would make two records
        // of identical content differ because one source was more verbose.
        let essence = lowered.split(';').next().unwrap_or_default().trim();

        let (kind, subtype) = essence
            .split_once('/')
            .ok_or_else(|| ModelError::invalid("MediaType", "expected the form type/subtype"))?;

        let is_token = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "!#$&^_-.+".contains(ch))
        };

        if !is_token(kind) || !is_token(subtype) {
            return Err(ModelError::invalid(
                "MediaType",
                "type and subtype must be non-empty RFC 9110 tokens",
            ));
        }

        Ok(Self(format!("{kind}/{subtype}")))
    }

    /// The canonical `type/subtype`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MediaType({:?})", self.0)
    }
}

impl Serialize for MediaType {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MediaType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(D::Error::custom)
    }
}

impl JsonSchema for MediaType {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "MediaType".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "maxLength": MEDIA_TYPE_MAX_BYTES,
            "pattern": "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$",
            "description": "The media type the source declared. Recorded, never trusted to decide how bytes are parsed.",
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Source origin
// -------------------------------------------------------------------------------------------------

/// Where a source object came from.
///
/// The publisher is a [`ShortText`] and the location is a [`SensitiveText`], because the two have
/// different sensitivities: "this came from the ACME feed" is usually shareable, while the URL that
/// reached it may carry a subscription token.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SourceOrigin {
    /// Read from the local filesystem.
    LocalFile {
        /// The path it was read from.
        path: SensitiveText,
    },
    /// Retrieved from a published feed.
    NetworkFeed {
        /// Who publishes the feed.
        publisher: ShortText,
        /// The retrieval location, if it may be recorded.
        location: Option<SensitiveText>,
    },
    /// Retrieved through a connector to an upstream platform.
    Connector {
        /// The upstream system, for example `opencti` or `taxii`.
        system: ShortText,
        /// The collection, feed, or endpoint within that system.
        collection: Option<ShortText>,
        /// The endpoint it was retrieved from, if it may be recorded.
        location: Option<SensitiveText>,
    },
    /// Entered by an operator rather than imported.
    ManualEntry {
        /// Who entered it, if recorded.
        operator: Option<ShortText>,
    },
}

impl SourceOrigin {
    /// A stable discriminator, used in identifier derivation and for indexing.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::LocalFile { .. } => "local_file",
            Self::NetworkFeed { .. } => "network_feed",
            Self::Connector { .. } => "connector",
            Self::ManualEntry { .. } => "manual_entry",
        }
    }

    /// Whether this origin carries a location that policy must decide about before release.
    #[must_use]
    pub const fn has_sensitive_location(&self) -> bool {
        match self {
            Self::LocalFile { .. } => true,
            Self::NetworkFeed { location, .. } | Self::Connector { location, .. } => {
                location.is_some()
            }
            Self::ManualEntry { .. } => false,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Source object
// -------------------------------------------------------------------------------------------------

/// Metadata addressing one piece of original evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceObject {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// Canonical identifier, derived from the content hash.
    pub id: Id<Self>,
    /// Digest of the exact bytes.
    pub content_hash: ContentHash,
    /// The media type the source declared.
    pub media_type: MediaType,
    /// Length of the original bytes.
    pub byte_length: u64,
    /// When Brolga obtained it.
    ///
    /// Retrieval time, not publication time. A source's own timestamps are claims about the world
    /// and belong on the records derived from it; this is a fact about Brolga's own behaviour.
    pub retrieved_at: Timestamp,
    /// Where it came from.
    pub origin: SourceOrigin,
    /// Handling restrictions on the evidence itself. Always serialised, empty or not.
    pub markings: MarkingSet,
}

impl Identifiable for SourceObject {
    const ID_KIND: &'static str = "source";
}

impl VersionedSchema for SourceObject {
    const SCHEMA_NAME: &'static str = "brolga.source_object";
}

impl SourceObject {
    /// Derive the identifier from the content hash alone.
    ///
    /// Content-addressed on purpose. Importing the same bytes twice, from two feeds, on two days,
    /// yields one source object, so evidence is stored once and every record that cites it cites
    /// the same identifier. Including the origin would produce two objects for identical evidence
    /// and quietly double any count of how many sources published it.
    #[must_use]
    pub fn derive_id(content_hash: ContentHash) -> Id<Self> {
        Id::derive(&[&content_hash.to_string()])
    }

    /// Build a source object, deriving its identifier from the content hash.
    #[must_use]
    pub fn new(
        content_hash: ContentHash,
        media_type: MediaType,
        byte_length: u64,
        retrieved_at: Timestamp,
        origin: SourceOrigin,
    ) -> Self {
        Self {
            schema_version: SchemaTag::new(),
            id: Self::derive_id(content_hash),
            content_hash,
            media_type,
            byte_length,
            retrieved_at,
            origin,
            markings: MarkingSet::empty(),
        }
    }

    /// Confirm that some bytes are the ones this object addresses.
    ///
    /// Integrity only. A `true` result means the bytes are unmodified since they were recorded; it
    /// says nothing about whether the publisher is genuine or the content is true.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        ContentHash::of(bytes) == self.content_hash
            && u64::try_from(bytes.len()).is_ok_and(|length| length == self.byte_length)
    }

    /// Check the invariants that are not expressible in the field types.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the identifier does not match the content hash it
    /// must be derived from. A payload whose identifier and digest disagree is either corrupt or
    /// an attempt to make one blob answer to another blob's address.
    pub fn validated(self) -> Result<Self> {
        let expected = Self::derive_id(self.content_hash);
        if self.id != expected {
            return Err(ModelError::invalid(
                "SourceObject",
                format_args!(
                    "identifier {} does not match the content hash, which derives {expected}",
                    self.id,
                ),
            ));
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for SourceObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<SourceObject>,
            id: Id<SourceObject>,
            content_hash: ContentHash,
            media_type: MediaType,
            byte_length: u64,
            retrieved_at: Timestamp,
            origin: SourceOrigin,
            markings: MarkingSet,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self {
            schema_version: raw.schema_version,
            id: raw.id,
            content_hash: raw.content_hash,
            media_type: raw.media_type,
            byte_length: raw.byte_length,
            retrieved_at: raw.retrieved_at,
            origin: raw.origin,
            markings: raw.markings,
        }
        .validated()
        .map_err(D::Error::custom)
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

    fn at(value: &str) -> Timestamp {
        Timestamp::parse_rfc3339(value).unwrap()
    }

    fn sample(bytes: &[u8]) -> SourceObject {
        SourceObject::new(
            ContentHash::of(bytes),
            MediaType::new("application/json").unwrap(),
            u64::try_from(bytes.len()).unwrap(),
            at("2024-01-01T00:00:00Z"),
            SourceOrigin::NetworkFeed {
                publisher: ShortText::new("Example CERT").unwrap(),
                location: Some(
                    SensitiveText::new("https://feed.example/private?token=s3cret").unwrap(),
                ),
            },
        )
    }

    #[test]
    fn sensitive_text_redacts_in_debug_and_display() {
        let secret = SensitiveText::new("https://feed.example/x?token=s3cret").unwrap();

        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(!display.contains("s3cret"), "{display}");
        assert_eq!(display, "<redacted>");

        // But the value is still reachable when a caller explicitly asks for it.
        assert!(secret.expose().contains("s3cret"));
    }

    #[test]
    fn sensitive_text_serialises_verbatim_because_it_must_survive_storage() {
        // Redaction is an output-path decision made by policy, not a storage decision made here.
        // Dropping the value at serialisation time would make it unrecoverable.
        let secret = SensitiveText::new("/mnt/internal/share/feed.json").unwrap();
        let json = serde_json::to_string(&secret).unwrap();
        assert_eq!(json, "\"/mnt/internal/share/feed.json\"");
        assert_eq!(
            serde_json::from_str::<SensitiveText>(&json).unwrap(),
            secret
        );
    }

    #[test]
    fn sensitive_text_offers_a_comparable_handle_that_leaks_nothing() {
        let one = SensitiveText::new("/mnt/a").unwrap();
        let same = SensitiveText::new("/mnt/a").unwrap();
        let other = SensitiveText::new("/mnt/b").unwrap();

        assert_eq!(one.redacted_digest(), same.redacted_digest());
        assert_ne!(one.redacted_digest(), other.redacted_digest());
        assert!(!one.redacted_digest().to_string().contains("mnt"));
    }

    #[test]
    fn sensitive_text_rejects_hostile_input() {
        assert!(SensitiveText::new("").is_err());
        assert!(SensitiveText::new("line\nbreak").is_err());
        assert!(SensitiveText::new("nul\u{0}").is_err());
        assert!(SensitiveText::new("a".repeat(SENSITIVE_TEXT_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn media_type_lowercases_and_drops_parameters() {
        assert_eq!(
            MediaType::new("Application/JSON").unwrap().as_str(),
            "application/json"
        );
        // Two records of identical bytes must not differ because one source was more verbose.
        assert_eq!(
            MediaType::new("text/csv; charset=UTF-8").unwrap(),
            MediaType::new("text/csv").unwrap(),
        );
    }

    #[test]
    fn media_type_rejects_malformed_input() {
        for hostile in [
            "",
            "json",
            "/json",
            "application/",
            "app lication/json",
            "a/b/c",
        ] {
            assert!(
                MediaType::new(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn identical_bytes_from_two_feeds_are_one_source_object() {
        // Otherwise identical evidence stored twice would double any count of how many sources
        // published it, which is precisely the syndication error the roadmap forbids.
        let bytes = b"{\"indicator\":\"example.com\"}";
        let from_feed = SourceObject::new(
            ContentHash::of(bytes),
            MediaType::new("application/json").unwrap(),
            u64::try_from(bytes.len()).unwrap(),
            at("2024-01-01T00:00:00Z"),
            SourceOrigin::NetworkFeed {
                publisher: ShortText::new("Feed A").unwrap(),
                location: None,
            },
        );
        let from_file = SourceObject::new(
            ContentHash::of(bytes),
            MediaType::new("application/json").unwrap(),
            u64::try_from(bytes.len()).unwrap(),
            at("2025-06-01T00:00:00Z"),
            SourceOrigin::LocalFile {
                path: SensitiveText::new("/tmp/copy.json").unwrap(),
            },
        );
        assert_eq!(from_feed.id, from_file.id);
    }

    #[test]
    fn different_bytes_are_different_source_objects() {
        assert_ne!(sample(b"one").id, sample(b"two").id);
    }

    #[test]
    fn integrity_check_confirms_bytes_not_authenticity() {
        let object = sample(b"payload");
        assert!(object.matches(b"payload"));
        assert!(!object.matches(b"payloax"));
        assert!(!object.matches(b""));
    }

    #[test]
    fn a_payload_whose_identifier_disagrees_with_its_digest_is_rejected() {
        let mut json = serde_json::to_value(sample(b"payload")).unwrap();
        json["content_hash"] = serde_json::json!(ContentHash::of(b"different").to_string());
        let error = serde_json::from_value::<SourceObject>(json).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the content hash"),
            "{error}"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let object = sample(b"payload");
        let json = serde_json::to_string(&object).unwrap();
        let back: SourceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back, object);
    }

    #[test]
    fn serialised_form_carries_schema_version_and_markings() {
        let json = serde_json::to_value(sample(b"payload")).unwrap();
        assert_eq!(
            json.get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some("brolga.source_object/1.0"),
        );
        assert_eq!(json.get("markings"), Some(&serde_json::json!([])));
    }

    #[test]
    fn origins_declare_whether_policy_must_decide_about_a_location() {
        assert!(
            SourceOrigin::LocalFile {
                path: SensitiveText::new("/mnt/x").unwrap()
            }
            .has_sensitive_location()
        );
        assert!(
            !SourceOrigin::NetworkFeed {
                publisher: ShortText::new("Feed").unwrap(),
                location: None,
            }
            .has_sensitive_location()
        );
        assert!(!SourceOrigin::ManualEntry { operator: None }.has_sensitive_location());
    }

    #[test]
    fn rejects_hostile_payloads() {
        let base = serde_json::to_value(sample(b"payload")).unwrap();

        let mut unknown_origin = base.clone();
        unknown_origin["origin"] = serde_json::json!({"type": "telepathy"});
        assert!(serde_json::from_value::<SourceObject>(unknown_origin).is_err());

        let mut bad_media = base.clone();
        bad_media["media_type"] = serde_json::json!("not a media type");
        assert!(serde_json::from_value::<SourceObject>(bad_media).is_err());

        let mut negative_length = base.clone();
        negative_length["byte_length"] = serde_json::json!(-1);
        assert!(serde_json::from_value::<SourceObject>(negative_length).is_err());

        let mut unknown_field = base;
        unknown_field["blob"] = serde_json::json!("...");
        assert!(serde_json::from_value::<SourceObject>(unknown_field).is_err());
    }
}
