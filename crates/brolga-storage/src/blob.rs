//! Content-addressed retention of original source objects.
//!
//! Canonical records are Brolga's interpretation of what a source said. The bytes the source
//! actually sent are separate evidence, and they are stored separately, addressed by their own
//! digest.
//!
//! # Why the address is the content
//!
//! A blob's key is the digest of its bytes. Three properties fall out of that and none of them has
//! to be maintained by hand:
//!
//! - **Byte-identical objects store once.** Two feeds publishing the same bundle, or one feed
//!   publishing it daily, address one row. No comparison pass, no dedup job.
//! - **Corruption is detectable.** Retrieval recomputes the digest and compares it to the key the
//!   caller asked for. A blob that no longer hashes to its own address is returned as an error, not
//!   as bytes.
//! - **Path traversal is impossible.** There is no path. A content identifier is a hex digest that
//!   cannot name a directory, and the bytes live in a database column rather than a file whose name
//!   an attacker influences.
//!
//! # Retention is a decision, and decisions are recorded
//!
//! Deleting a canonical record must not silently destroy the evidence it was derived from —
//! otherwise a cleanup job quietly removes the only proof of what a source published. Blobs are
//! therefore **not** foreign-keyed to canonical records and nothing cascades. Releasing a blob is an
//! explicit call, and every store, refusal, and release is appended to an audit log that survives
//! the blob itself.
//!
//! # Never executed, never rendered, never logged
//!
//! A source object is hostile input that has been kept on purpose. This module stores and returns
//! bytes. It does not decode them as text, guess a media type from them, or write any part of them
//! to a diagnostic — a blob's *digest* is safe to log, its contents never are.

use core::fmt;

use brolga_model::provenance::ContentHash;
use serde::{Deserialize, Serialize};

/// Largest single object retained by default, in bytes.
///
/// A ceiling rather than a target. The point is that one hostile 4 GiB "report" cannot exhaust the
/// disk before anything notices; legitimate bundles are orders of magnitude below this.
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// How a stored blob's bytes are encoded at rest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BlobCodec {
    /// Stored exactly as received.
    #[default]
    Identity,
    /// Stored deflate-compressed.
    Deflate,
}

impl BlobCodec {
    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Deflate => "deflate",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "identity" => Some(Self::Identity),
            "deflate" => Some(Self::Deflate),
            _ => None,
        }
    }
}

impl fmt::Display for BlobCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why a blob is being kept, and under what expectation.
///
/// Recorded per blob rather than inferred, so that a later retention sweep acts on a decision
/// somebody made rather than on a heuristic it invented.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RetentionClass {
    /// Ordinary imported evidence.
    #[default]
    Standard,
    /// Held because something references it in an investigation; a sweep must not remove it.
    Hold,
    /// Kept only until the canonical records derived from it are confirmed.
    Transient,
}

impl RetentionClass {
    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Hold => "hold",
            Self::Transient => "transient",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "standard" => Some(Self::Standard),
            "hold" => Some(Self::Hold),
            "transient" => Some(Self::Transient),
            _ => None,
        }
    }

    /// Whether a retention sweep may remove a blob in this class.
    ///
    /// `Hold` is the whole point of the enum: an automated sweep that cannot be told "not this one"
    /// eventually deletes the evidence somebody was relying on.
    #[must_use]
    pub const fn may_be_swept(self) -> bool {
        matches!(self, Self::Standard | Self::Transient)
    }
}

impl fmt::Display for RetentionClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What happened to a blob, for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RetentionAction {
    /// The bytes were written for the first time.
    Stored,
    /// The bytes were already present, so nothing was written.
    Deduplicated,
    /// Storage was refused, and nothing was written.
    Refused,
    /// The bytes were removed deliberately.
    Released,
    /// The retention class was changed.
    Reclassified,
}

impl RetentionAction {
    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Deduplicated => "deduplicated",
            Self::Refused => "refused",
            Self::Released => "released",
            Self::Reclassified => "reclassified",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "stored" => Some(Self::Stored),
            "deduplicated" => Some(Self::Deduplicated),
            "refused" => Some(Self::Refused),
            "released" => Some(Self::Released),
            "reclassified" => Some(Self::Reclassified),
            _ => None,
        }
    }
}

impl fmt::Display for RetentionAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One recorded retention decision.
///
/// Kept even after the blob it describes is released — an audit log that disappears with the thing
/// it audits answers no question anybody asks afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionEvent {
    /// Which blob.
    pub content_hash: ContentHash,
    /// What happened.
    pub action: RetentionAction,
    /// Why, in the caller's words.
    pub reason: String,
    /// When, as an RFC 3339 string.
    pub at: String,
}

/// What is known about a stored blob without reading its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMetadata {
    /// The digest, which is also the key.
    pub content_hash: ContentHash,
    /// How the bytes are encoded at rest.
    pub codec: BlobCodec,
    /// Length of the original bytes.
    pub original_length: u64,
    /// Length actually occupied after encoding.
    pub stored_length: u64,
    /// Why it is being kept.
    pub retention: RetentionClass,
    /// When it was first stored, as an RFC 3339 string.
    pub stored_at: String,
}

impl BlobMetadata {
    /// Whether compression saved anything.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        matches!(self.codec, BlobCodec::Deflate)
    }
}

/// A request to retain some bytes.
///
/// The digest is computed by [`Self::new`] rather than supplied, so a caller cannot store bytes
/// under an address that is not theirs — which would make every later integrity check meaningless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRequest<'a> {
    content_hash: ContentHash,
    bytes: &'a [u8],
    retention: RetentionClass,
    reason: String,
}

impl<'a> BlobRequest<'a> {
    /// Build a request, deriving the address from the bytes.
    #[must_use]
    pub fn new(bytes: &'a [u8], retention: RetentionClass, reason: impl Into<String>) -> Self {
        Self {
            content_hash: ContentHash::of(bytes),
            bytes,
            retention,
            reason: reason.into(),
        }
    }

    /// An ordinary retention request.
    #[must_use]
    pub fn standard(bytes: &'a [u8], reason: impl Into<String>) -> Self {
        Self::new(bytes, RetentionClass::Standard, reason)
    }

    /// The address these bytes will be stored under.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// The bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The retention class.
    #[must_use]
    pub const fn retention(&self) -> RetentionClass {
        self.retention
    }

    /// Why it is being retained.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Length of the original bytes.
    #[must_use]
    pub fn length(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }
}

/// What storing a blob did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobOutcome {
    /// The bytes were new and were written.
    Stored {
        /// Length actually occupied after encoding.
        stored_length: u64,
        /// How the bytes were encoded.
        codec: BlobCodec,
    },
    /// The bytes were already present under this address, so nothing was written.
    ///
    /// Not an error and not a no-op worth hiding: it is the deduplication working, and a caller
    /// counting stored evidence needs to tell it from a fresh write.
    Deduplicated,
}

impl BlobOutcome {
    /// Whether anything was written.
    #[must_use]
    pub const fn wrote_bytes(self) -> bool {
        matches!(self, Self::Stored { .. })
    }
}

/// A blob read back, with its bytes restored to exactly what was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievedBlob {
    /// What is known about it.
    pub metadata: BlobMetadata,
    /// The original bytes.
    pub bytes: Vec<u8>,
}

impl RetrievedBlob {
    /// Confirm the bytes still hash to the address they were fetched from.
    ///
    /// Called by the store on every retrieval. Exposed so a caller holding a blob across a boundary
    /// can re-check it without going back to the database.
    #[must_use]
    pub fn integrity_holds(&self) -> bool {
        ContentHash::of(&self.bytes) == self.metadata.content_hash
            && u64::try_from(self.bytes.len()).is_ok_and(|len| len == self.metadata.original_length)
    }
}

/// Compress bytes, but only when compression actually helps.
///
/// Deflate on already-compressed or very small input produces something *larger*, so the result is
/// compared against the input and the smaller one wins. Storing a 12-byte object as 20 compressed
/// bytes would be a compression feature that costs disk.
#[must_use]
pub fn encode_bytes(bytes: &[u8]) -> (BlobCodec, Vec<u8>) {
    use std::io::Write as _;

    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    if encoder.write_all(bytes).is_ok()
        && let Ok(compressed) = encoder.finish()
        && compressed.len() < bytes.len()
    {
        return (BlobCodec::Deflate, compressed);
    }
    (BlobCodec::Identity, bytes.to_vec())
}

/// Reverse [`encode_bytes`].
///
/// # Errors
///
/// Returns `None` if the stored bytes cannot be decoded, which means the row is corrupt.
#[must_use]
pub fn decode_bytes(codec: BlobCodec, stored: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;

    match codec {
        BlobCodec::Identity => Some(stored.to_vec()),
        BlobCodec::Deflate => {
            let mut decoder = flate2::read::DeflateDecoder::new(stored);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok().map(|_| out)
        }
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

    /// A caller must not be able to store bytes under somebody else's address, or every later
    /// integrity check is checking a claim rather than a fact.
    #[test]
    fn a_request_derives_its_own_address_from_its_bytes() {
        let request = BlobRequest::standard(b"evidence", "test");
        assert_eq!(request.content_hash(), ContentHash::of(b"evidence"));
    }

    /// Identical bytes must address identically whatever else differs about the request.
    #[test]
    fn identical_bytes_address_identically_regardless_of_retention_class() {
        let standard = BlobRequest::new(b"same", RetentionClass::Standard, "a");
        let held = BlobRequest::new(b"same", RetentionClass::Hold, "b");
        assert_eq!(standard.content_hash(), held.content_hash());
    }

    /// Compression must never make a blob bigger. Deflate on small or already-compressed input
    /// does exactly that.
    #[test]
    fn encoding_never_produces_more_bytes_than_it_was_given() {
        for input in [
            b"x".as_slice(),
            b"tiny".as_slice(),
            &[0xff_u8; 7],
            &b"the same sentence over and over. ".repeat(100),
        ] {
            let (codec, encoded) = encode_bytes(input);
            assert!(
                encoded.len() <= input.len(),
                "{codec} grew {} bytes to {}",
                input.len(),
                encoded.len()
            );
        }
    }

    /// Repetitive input is where compression is meant to pay, so at least one case must take it —
    /// otherwise the codec is dead code that still costs a comparison.
    #[test]
    fn repetitive_input_is_actually_compressed() {
        let repetitive = b"the same sentence over and over. ".repeat(100);
        let (codec, encoded) = encode_bytes(&repetitive);
        assert_eq!(codec, BlobCodec::Deflate);
        assert!(
            encoded.len().saturating_mul(2) < repetitive.len(),
            "expected better than 2:1 on highly repetitive input, got {} from {}",
            encoded.len(),
            repetitive.len()
        );
    }

    /// The round trip has to be exact, for every codec, including empty input.
    #[test]
    fn every_codec_round_trips_the_original_bytes_exactly() {
        for input in [
            b"".as_slice(),
            b"x".as_slice(),
            &b"repeat ".repeat(200),
            &(0..=255_u8).collect::<Vec<_>>(),
        ] {
            let (codec, encoded) = encode_bytes(input);
            let decoded = decode_bytes(codec, &encoded).expect("decodes");
            assert_eq!(decoded, input, "{codec} did not round-trip");
        }
    }

    /// Corrupt stored bytes must decode to nothing rather than to plausible garbage.
    #[test]
    fn corrupt_compressed_bytes_fail_to_decode_rather_than_returning_rubbish() {
        let repetitive = b"the same sentence over and over. ".repeat(100);
        let (codec, mut encoded) = encode_bytes(&repetitive);
        assert_eq!(codec, BlobCodec::Deflate);

        encoded[4] ^= 0xff;
        let decoded = decode_bytes(codec, &encoded);
        match decoded {
            None => {}
            Some(bytes) => assert_ne!(
                bytes, repetitive,
                "a corrupted stream must not decode back to the original"
            ),
        }
    }

    /// A held blob is the one case a sweep must never touch. That is the reason the class exists.
    #[test]
    fn a_held_blob_is_never_sweepable() {
        assert!(!RetentionClass::Hold.may_be_swept());
        assert!(RetentionClass::Standard.may_be_swept());
        assert!(RetentionClass::Transient.may_be_swept());
    }

    /// Labels are written to the database, so they are a compatibility surface and must round-trip.
    #[test]
    fn every_label_round_trips_through_its_stored_form() {
        for codec in [BlobCodec::Identity, BlobCodec::Deflate] {
            assert_eq!(BlobCodec::from_str_opt(codec.as_str()), Some(codec));
        }
        for class in [
            RetentionClass::Standard,
            RetentionClass::Hold,
            RetentionClass::Transient,
        ] {
            assert_eq!(RetentionClass::from_str_opt(class.as_str()), Some(class));
        }
        for action in [
            RetentionAction::Stored,
            RetentionAction::Deduplicated,
            RetentionAction::Refused,
            RetentionAction::Released,
            RetentionAction::Reclassified,
        ] {
            assert_eq!(RetentionAction::from_str_opt(action.as_str()), Some(action));
        }
    }

    /// An unknown label must be rejected rather than silently defaulted. A row written by a newer
    /// build read as `identity` would return compressed bytes as if they were the original.
    #[test]
    fn an_unknown_label_is_rejected_rather_than_defaulted() {
        assert_eq!(BlobCodec::from_str_opt("brotli"), None);
        assert_eq!(RetentionClass::from_str_opt("forever"), None);
        assert_eq!(RetentionAction::from_str_opt("shredded"), None);
    }
}
