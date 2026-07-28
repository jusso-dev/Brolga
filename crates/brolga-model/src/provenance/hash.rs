//! Content hashes used for integrity and addressing.
//!
//! # A hash is not a trust signal
//!
//! [`ContentHash`] answers "is this the same bytes as before" and "which stored object is this".
//! It does not answer "is this true", "did this come from who it says", or "is this safe to
//! process". Two things follow, and both are enforced rather than merely stated:
//!
//! - A matching hash on imported content means the bytes are unchanged, not that the publisher is
//!   who they claim. Authenticity requires a signature, which is a separate concern with a separate
//!   key-management problem, and pretending a digest provides it is worse than not having it.
//! - The digest algorithm is fixed at SHA-256, with no enum and no way to select a weaker one.
//!   [`HashAlgorithm`](crate::observable::HashAlgorithm) offers MD5 and SHA-1 because feeds publish
//!   them and Brolga must be able to *record* what a feed said; content addressing is Brolga's own
//!   decision, and a construction where an attacker chooses the algorithm is a construction where
//!   the attacker chooses MD5.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ModelError, Result, preview};

/// Length of a SHA-256 digest in hexadecimal characters.
pub const CONTENT_HASH_HEX_LENGTH: usize = 64;

/// The prefix that content hashes are rendered with, so a bare digest is never ambiguous about
/// which algorithm produced it.
pub const CONTENT_HASH_PREFIX: &str = "sha256:";

/// A SHA-256 digest of some bytes, rendered as `sha256:<64 lower-case hex characters>`.
///
/// The algorithm is part of the serialised form even though only one is supported, so that adding
/// a second one later is an additive change a consumer can branch on, rather than a silent
/// reinterpretation of every stored digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Hash a byte slice.
    ///
    /// Deterministic by construction: the same bytes give the same digest on any machine, in any
    /// process, forever. This is what makes a content-addressed source object retrievable and a
    /// re-import idempotent.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Hash a string's UTF-8 bytes.
    ///
    /// Note that this hashes the *encoded* bytes. Two strings that are canonically equivalent under
    /// Unicode normalisation but encoded differently hash differently, which is correct here:
    /// content addressing is about bytes, and normalising before hashing would make the digest
    /// disagree with the stored source object.
    #[must_use]
    pub fn of_str(value: &str) -> Self {
        Self::of(value.as_bytes())
    }

    /// The raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The lower-case hexadecimal digest, without the `sha256:` prefix.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(CONTENT_HASH_HEX_LENGTH);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Parse `sha256:<hex>`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the prefix is missing, the digest is not exactly
    /// [`CONTENT_HASH_HEX_LENGTH`] characters, or it contains a non-hexadecimal character.
    pub fn parse(value: &str) -> Result<Self> {
        let hex = value.strip_prefix(CONTENT_HASH_PREFIX).ok_or_else(|| {
            ModelError::invalid(
                "ContentHash",
                format_args!(
                    "{:?} is missing the {CONTENT_HASH_PREFIX} prefix; a bare digest is ambiguous about its algorithm",
                    preview(value),
                ),
            )
        })?;

        if hex.len() != CONTENT_HASH_HEX_LENGTH {
            return Err(ModelError::invalid(
                "ContentHash",
                format_args!(
                    "expected {CONTENT_HASH_HEX_LENGTH} hexadecimal characters, found {}",
                    hex.len(),
                ),
            ));
        }

        // Lower case only. `Uuid`-style case tolerance would give one digest two spellings, and
        // equality on the wire would stop matching equality in memory.
        if !hex
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        {
            return Err(ModelError::invalid(
                "ContentHash",
                "digest must be lower-case hexadecimal",
            ));
        }

        let mut bytes = [0_u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let start = index
                .checked_mul(2)
                .ok_or_else(|| ModelError::invalid("ContentHash", "digest index overflowed"))?;
            let pair = hex.get(start..start.saturating_add(2)).ok_or_else(|| {
                ModelError::invalid("ContentHash", "digest ended before 32 bytes were read")
            })?;
            *slot = u8::from_str_radix(pair, 16).map_err(|error| {
                ModelError::invalid("ContentHash", format_args!("invalid hex pair ({error})"))
            })?;
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(CONTENT_HASH_PREFIX)?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({self})")
    }
}

impl core::str::FromStr for ContentHash {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

impl JsonSchema for ContentHash {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ContentHash".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
            "description": "A SHA-256 digest. Supports integrity and addressing, not authenticity: a matching digest means the bytes are unchanged, not that the publisher is who they claim.",
            "x-brolga-integrity": "not-authentication",
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

    #[test]
    fn hashing_is_deterministic() {
        // The property everything else depends on: same bytes, same digest, always.
        assert_eq!(ContentHash::of(b"brolga"), ContentHash::of(b"brolga"));
        assert_ne!(ContentHash::of(b"brolga"), ContentHash::of(b"brolgb"));
        assert_ne!(ContentHash::of(b""), ContentHash::of(b"\0"));
    }

    #[test]
    fn digest_matches_the_published_sha256_vectors() {
        // Pinned against the values every SHA-256 implementation agrees on, so a dependency swap
        // that silently changed the algorithm would fail here rather than in production.
        assert_eq!(
            ContentHash::of(b"").to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            ContentHash::of(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn rendering_is_prefixed_lower_case_hex() {
        let hash = ContentHash::of(b"abc");
        assert!(hash.to_string().starts_with(CONTENT_HASH_PREFIX));
        assert_eq!(hash.to_hex().len(), CONTENT_HASH_HEX_LENGTH);
        assert_eq!(hash.to_hex(), hash.to_hex().to_lowercase());
        assert_eq!(
            hash.to_string(),
            format!("{CONTENT_HASH_PREFIX}{}", hash.to_hex())
        );
    }

    #[test]
    fn round_trips_through_its_string_form_and_json() {
        let hash = ContentHash::of(b"brolga");
        assert_eq!(ContentHash::parse(&hash.to_string()).unwrap(), hash);

        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{hash}\""));
        assert_eq!(serde_json::from_str::<ContentHash>(&json).unwrap(), hash);
    }

    #[test]
    fn rejects_a_bare_digest_and_a_foreign_algorithm() {
        let bare = ContentHash::of(b"abc").to_hex();
        assert!(
            ContentHash::parse(&bare).is_err(),
            "a digest without its algorithm is ambiguous"
        );
        assert!(ContentHash::parse(&format!("md5:{bare}")).is_err());
        assert!(ContentHash::parse(&format!("sha1:{bare}")).is_err());
        assert!(ContentHash::parse(&format!("SHA256:{bare}")).is_err());
    }

    #[test]
    fn rejects_malformed_and_hostile_digests() {
        for hostile in [
            "",
            "sha256:",
            "sha256:z",
            "sha256:abc",
            "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\u{0}",
        ] {
            assert!(
                ContentHash::parse(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }

        // 63 and 65 characters, either side of the correct length.
        let short = "a".repeat(CONTENT_HASH_HEX_LENGTH - 1);
        let long = "a".repeat(CONTENT_HASH_HEX_LENGTH + 1);
        assert!(ContentHash::parse(&format!("sha256:{short}")).is_err());
        assert!(ContentHash::parse(&format!("sha256:{long}")).is_err());
    }

    #[test]
    fn uppercase_is_rejected_so_one_digest_has_one_spelling() {
        let hash = ContentHash::of(b"abc");
        let upper = format!("{CONTENT_HASH_PREFIX}{}", hash.to_hex().to_uppercase());
        assert!(ContentHash::parse(&upper).is_err());
    }

    #[test]
    fn string_and_byte_hashing_agree() {
        assert_eq!(ContentHash::of_str("brolga"), ContentHash::of(b"brolga"));
    }

    #[test]
    fn hashing_is_over_encoded_bytes_not_normalised_text() {
        // Precomposed é versus e + combining acute. Canonically equivalent under Unicode, different
        // bytes, and therefore different content. Normalising here would make the digest disagree
        // with the source object it addresses.
        assert_ne!(ContentHash::of_str("é"), ContentHash::of_str("e\u{0301}"));
    }

    #[test]
    fn parsed_and_computed_digests_of_the_same_bytes_are_equal() {
        let computed = ContentHash::of(b"brolga");
        let parsed = ContentHash::parse(&computed.to_string()).unwrap();
        assert_eq!(computed, parsed);
        assert_eq!(computed.as_bytes(), parsed.as_bytes());
    }
}
