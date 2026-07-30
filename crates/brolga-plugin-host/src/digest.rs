//! Content digests for plugin components (reproducibility metadata).

use sha2::{Digest, Sha256};

use crate::error::HostError;

/// Supported digest algorithms for component bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
}

impl DigestAlgorithm {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }

    /// Parse a wire name.
    ///
    /// # Errors
    ///
    /// Unknown algorithm.
    pub fn parse(name: &str) -> Result<Self, HostError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(Self::Sha256),
            other => Err(HostError::Component {
                reason: format!("unsupported digest algorithm `{other}`"),
            }),
        }
    }
}

/// A digest of component bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginDigest {
    /// Algorithm.
    pub algorithm: DigestAlgorithm,
    /// Lowercase hex.
    pub hex: String,
}

impl PluginDigest {
    /// Compute a digest of `bytes`.
    #[must_use]
    pub fn of(algorithm: DigestAlgorithm, bytes: &[u8]) -> Self {
        let hex = match algorithm {
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                hex_encode(&hasher.finalize())
            }
        };
        Self { algorithm, hex }
    }

    /// Compare to an expected hex string (case-insensitive).
    #[must_use]
    pub fn matches_hex(&self, expected: &str) -> bool {
        self.hex.eq_ignore_ascii_case(expected.trim())
    }
}

/// Digest `bytes` with SHA-256.
#[must_use]
pub fn digest_bytes(bytes: &[u8]) -> PluginDigest {
    PluginDigest::of(DigestAlgorithm::Sha256, bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        if let (Some(&h), Some(&l)) = (HEX.get(high), HEX.get(low)) {
            out.push(char::from(h));
            out.push(char::from(l));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_sha256_is_well_known() {
        let digest = digest_bytes(b"");
        assert_eq!(
            digest.hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
