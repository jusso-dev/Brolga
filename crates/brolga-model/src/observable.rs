//! Strongly typed observables.
//!
//! # No arbitrary-string fallback
//!
//! There is no `Other(String)` variant. A catch-all would make the enum trivially extensible and
//! trivially useless: every source that Brolga could not model properly would land in it, nothing
//! downstream could reason about the contents, and the type would offer no more guarantee than a
//! `HashMap<String, String>`. Adding a genuinely new observable kind is a schema minor version
//! change, which is cheap and visible. Silently accepting anything is neither.
//!
//! # Canonicalisation performed here
//!
//! A canonical record holds canonical values, so the constructors normalise the small,
//! uncontroversial set of representational differences that would otherwise make one thing look
//! like several:
//!
//! - ASCII case is folded in DNS names, in an email address's domain part, and in hexadecimal
//!   digests. These are case-insensitive by specification.
//! - A single trailing dot is removed from a fully qualified DNS name.
//! - IP addresses, MAC addresses, and CIDR ranges are re-rendered from their parsed form.
//!
//! Everything else is preserved exactly. In particular an email address's local part keeps its
//! case, because RFC 5321 makes it case-*sensitive*, and folding it would merge two mailboxes that
//! a mail server treats as distinct.
//!
//! Normalisation here is idempotent and is tested to be. The source's exact original bytes are not
//! this type's responsibility; they belong to the provenance model, which stores them alongside.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{ModelError, Result, preview};
use crate::id::{Id, Identifiable};
use crate::text::ShortText;
use crate::version::VersionedSchema;

/// Maximum length of a DNS name, in bytes, as a presentation-format string.
pub const DOMAIN_NAME_MAX_BYTES: usize = 253;

/// Maximum length of a DNS label, in bytes.
pub const DOMAIN_LABEL_MAX_BYTES: usize = 63;

/// Maximum length of an email address, in bytes.
pub const EMAIL_ADDRESS_MAX_BYTES: usize = 254;

/// Maximum length of an email address's local part, in bytes.
pub const EMAIL_LOCAL_PART_MAX_BYTES: usize = 64;

/// Maximum length of a URL, in bytes.
pub const URL_MAX_BYTES: usize = 4096;

/// URL schemes that Brolga stores as URL observables.
///
/// An allow-list rather than a deny-list. A `javascript:` or `data:` payload is a script or a blob,
/// not a network location, and modelling it as a URL observable would let it flow into code paths
/// that reasonably assume a URL identifies somewhere to retrieve. Adding a scheme here is an
/// additive schema change.
pub const ALLOWED_URL_SCHEMES: &[&str] = &["http", "https", "ftp", "ftps"];

// ---------------------------------------------------------------------------------------------
// Domain names
// ---------------------------------------------------------------------------------------------

/// A syntactically valid DNS name, ASCII-lowercased, without a trailing dot.
///
/// Internationalised names must be supplied in A-label (`xn--`) form. This type validates
/// presentation syntax; it does not perform IDNA conversion, because a Unicode-to-ASCII mapping is
/// a transformation that has to be recorded in a provenance chain rather than applied invisibly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Validate and canonicalise a DNS name.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Empty`] for an empty name, [`ModelError::TooLong`] if the name exceeds
    /// [`DOMAIN_NAME_MAX_BYTES`], and [`ModelError::InvalidValue`] if any label is empty, too long,
    /// contains a character outside letters, digits, and hyphen, or begins or ends with a hyphen.
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref();
        if raw.is_empty() {
            return Err(ModelError::Empty {
                field: "DomainName",
            });
        }

        // One trailing dot marks an explicitly fully qualified name and carries no extra meaning
        // once the name is stored, so it is dropped. Two would mean an empty final label.
        let trimmed = raw.strip_suffix('.').unwrap_or(raw);
        if trimmed.len() > DOMAIN_NAME_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "DomainName",
                max: DOMAIN_NAME_MAX_BYTES,
                actual: trimmed.len(),
            });
        }

        let lowered = trimmed.to_ascii_lowercase();
        let labels: Vec<&str> = lowered.split('.').collect();

        if labels.len() < 2 {
            return Err(ModelError::invalid(
                "DomainName",
                format_args!(
                    "{:?} has no dot, so it names no zone; a single label is a host name, not a domain",
                    preview(&lowered),
                ),
            ));
        }

        for label in &labels {
            if label.is_empty() {
                return Err(ModelError::invalid(
                    "DomainName",
                    format_args!("{:?} contains an empty label", preview(&lowered)),
                ));
            }
            if label.len() > DOMAIN_LABEL_MAX_BYTES {
                return Err(ModelError::invalid(
                    "DomainName",
                    format_args!(
                        "label {:?} is {} bytes, exceeding the limit of {DOMAIN_LABEL_MAX_BYTES}",
                        preview(label),
                        label.len(),
                    ),
                ));
            }
            if !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            {
                return Err(ModelError::invalid(
                    "DomainName",
                    format_args!(
                        "label {:?} contains a character outside letters, digits, and hyphen; supply internationalised names in xn-- form",
                        preview(label),
                    ),
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ModelError::invalid(
                    "DomainName",
                    format_args!("label {:?} begins or ends with a hyphen", preview(label)),
                ));
            }
        }

        // RFC 1123 §2.1 forbids an all-numeric top-level label precisely so that a name cannot be
        // confused with an IPv4 address. Without this, `10.0.0.1` parses as a four-label domain and
        // the same string becomes two different observables depending on which parser reads it.
        if labels
            .last()
            .is_some_and(|tld| tld.chars().all(|ch| ch.is_ascii_digit()))
        {
            return Err(ModelError::invalid(
                "DomainName",
                format_args!(
                    "{:?} has an all-numeric top-level label, which is ambiguous with an IP address",
                    preview(&lowered),
                ),
            ));
        }

        Ok(Self(lowered))
    }

    /// The canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------------------------
// Email addresses
// ---------------------------------------------------------------------------------------------

/// An email address whose domain part is a valid [`DomainName`].
///
/// The local part keeps its case. RFC 5321 §2.4 leaves local-part interpretation to the receiving
/// host and requires that it be treated as case-sensitive, so folding it would merge mailboxes a
/// mail server considers distinct.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailAddress {
    local_part: String,
    domain: DomainName,
}

impl EmailAddress {
    /// Validate and canonicalise an email address.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`], [`ModelError::Empty`], or [`ModelError::InvalidValue`] if
    /// the address has no `@`, has an empty or oversized local part, contains whitespace or a
    /// control character, or has a domain part that is not a valid [`DomainName`].
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref();
        if raw.len() > EMAIL_ADDRESS_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "EmailAddress",
                max: EMAIL_ADDRESS_MAX_BYTES,
                actual: raw.len(),
            });
        }

        // Split from the right: a quoted local part may legally contain `@`, and splitting from the
        // left would silently truncate it into a different address.
        let (local_part, domain) = raw.rsplit_once('@').ok_or_else(|| {
            ModelError::invalid(
                "EmailAddress",
                format_args!("{:?} has no @ separator", preview(raw)),
            )
        })?;

        if local_part.is_empty() {
            return Err(ModelError::Empty {
                field: "EmailAddress local part",
            });
        }
        if local_part.len() > EMAIL_LOCAL_PART_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "EmailAddress local part",
                max: EMAIL_LOCAL_PART_MAX_BYTES,
                actual: local_part.len(),
            });
        }
        if local_part
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(ModelError::invalid(
                "EmailAddress",
                "local part contains whitespace or a control character",
            ));
        }
        // A second `@` means the address was already ambiguous; storing it would let one string
        // resolve to two different mailboxes depending on which parser reads it.
        if local_part.contains('@') {
            return Err(ModelError::invalid(
                "EmailAddress",
                "local part contains a second @",
            ));
        }

        Ok(Self {
            local_part: local_part.to_owned(),
            domain: DomainName::new(domain)?,
        })
    }

    /// The case-preserved local part.
    #[must_use]
    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    /// The canonicalised domain part.
    #[must_use]
    pub const fn domain(&self) -> &DomainName {
        &self.domain
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain.as_str())
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmailAddress({:?})", self.to_string())
    }
}

// ---------------------------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------------------------

/// A URL with a network-retrievable scheme.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalUrl(Url);

impl CanonicalUrl {
    /// Parse and validate a URL.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::TooLong`] beyond [`URL_MAX_BYTES`], and [`ModelError::InvalidValue`]
    /// if the URL does not parse or its scheme is not in [`ALLOWED_URL_SCHEMES`].
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref();
        if raw.len() > URL_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "Url",
                max: URL_MAX_BYTES,
                actual: raw.len(),
            });
        }

        let parsed = Url::parse(raw).map_err(|error| {
            ModelError::invalid("Url", format_args!("{:?} ({error})", preview(raw)))
        })?;

        if !ALLOWED_URL_SCHEMES.contains(&parsed.scheme()) {
            return Err(ModelError::invalid(
                "Url",
                format_args!(
                    "scheme {:?} is not one of {ALLOWED_URL_SCHEMES:?}",
                    preview(parsed.scheme()),
                ),
            ));
        }

        // Re-check after parsing: percent-encoding can lengthen the serialised form.
        if parsed.as_str().len() > URL_MAX_BYTES {
            return Err(ModelError::TooLong {
                field: "Url",
                max: URL_MAX_BYTES,
                actual: parsed.as_str().len(),
            });
        }

        Ok(Self(parsed))
    }

    /// The parsed URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    /// The canonical serialised form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

// ---------------------------------------------------------------------------------------------
// File hashes
// ---------------------------------------------------------------------------------------------

/// A cryptographic digest algorithm Brolga records for file observables.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// MD5. Retained because feeds still publish it; collision-vulnerable and never a trust signal.
    Md5,
    /// SHA-1. Retained for the same reason, with the same caveat.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Length of this algorithm's digest, in hexadecimal characters.
    #[must_use]
    pub const fn hex_length(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// Lower-case name used in canonical string renderings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A digest of a file, with the algorithm that produced it.
///
/// The digest length is checked against the algorithm, so a SHA-256 value cannot be stored under a
/// `Md5` label. That mislabelling is a real failure mode in aggregated feeds and it silently
/// destroys correlation, because the same file then appears under two unrelated observables.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileHash {
    /// The algorithm that produced the digest.
    pub algorithm: HashAlgorithm,
    /// Lower-case hexadecimal digest.
    value: String,
}

impl FileHash {
    /// Validate a digest against its algorithm and canonicalise its case.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the digest is not hexadecimal or is not exactly the
    /// length [`HashAlgorithm::hex_length`] requires.
    pub fn new(algorithm: HashAlgorithm, value: impl AsRef<str>) -> Result<Self> {
        let lowered = value.as_ref().to_ascii_lowercase();

        if lowered.len() != algorithm.hex_length() {
            return Err(ModelError::invalid(
                "FileHash",
                format_args!(
                    "{algorithm} requires {} hexadecimal characters, found {}",
                    algorithm.hex_length(),
                    lowered.len(),
                ),
            ));
        }
        if !lowered.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(ModelError::invalid(
                "FileHash",
                "digest contains a non-hexadecimal character",
            ));
        }

        Ok(Self {
            algorithm,
            value: lowered,
        })
    }

    /// The lower-case hexadecimal digest.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.value)
    }
}

impl<'de> Deserialize<'de> for FileHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            algorithm: HashAlgorithm,
            value: String,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.algorithm, raw.value).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------------
// MAC addresses
// ---------------------------------------------------------------------------------------------

/// A 48-bit MAC address.
///
/// Accepts colon- and hyphen-separated input and always renders lower-case colon-separated, so one
/// hardware address has one canonical spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Parse a MAC address.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] unless the input is six two-digit hexadecimal octets
    /// separated consistently by `:` or `-`.
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let raw = value.as_ref();
        let separator = if raw.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = raw.split(separator).collect();

        if parts.len() != 6 {
            return Err(ModelError::invalid(
                "MacAddress",
                format_args!(
                    "{:?} does not have six {separator}-separated octets",
                    preview(raw),
                ),
            ));
        }

        let mut octets = [0_u8; 6];
        for (slot, part) in octets.iter_mut().zip(parts) {
            if part.len() != 2 || !part.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(ModelError::invalid(
                    "MacAddress",
                    format_args!("octet {:?} is not two hexadecimal digits", preview(part)),
                ));
            }
            *slot = u8::from_str_radix(part, 16).map_err(|error| {
                ModelError::invalid(
                    "MacAddress",
                    format_args!("octet is not hexadecimal ({error})"),
                )
            })?;
        }

        Ok(Self(octets))
    }

    /// The six octets, most significant first.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

// ---------------------------------------------------------------------------------------------
// IP ranges
// ---------------------------------------------------------------------------------------------

/// A CIDR range whose host bits are zero.
///
/// `10.0.0.1/8` is rejected in favour of `10.0.0.0/8`. Both describe the same range, and accepting
/// either would let one range have many spellings, so equality and deduplication would depend on
/// which spelling a feed happened to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpRange {
    address: IpAddr,
    prefix_length: u8,
}

impl IpRange {
    /// Build a range from a network address and a prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the prefix length exceeds the address family's
    /// width, or if any host bit is set.
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self> {
        let width: u8 = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_length > width {
            return Err(ModelError::invalid(
                "IpRange",
                format_args!("prefix length {prefix_length} exceeds {width} bits"),
            ));
        }

        let host_bits_set = match address {
            IpAddr::V4(v4) => {
                let bits = u32::from_be_bytes(v4.octets());
                let mask = if prefix_length == 0 {
                    0
                } else {
                    u32::MAX
                        .checked_shl(u32::from(width - prefix_length))
                        .unwrap_or(0)
                };
                bits & !mask != 0
            }
            IpAddr::V6(v6) => {
                let bits = u128::from_be_bytes(v6.octets());
                let mask = if prefix_length == 0 {
                    0
                } else {
                    u128::MAX
                        .checked_shl(u32::from(width - prefix_length))
                        .unwrap_or(0)
                };
                bits & !mask != 0
            }
        };

        if host_bits_set {
            return Err(ModelError::invalid(
                "IpRange",
                format_args!(
                    "{address}/{prefix_length} sets host bits; use the network address of the range"
                ),
            ));
        }

        Ok(Self {
            address,
            prefix_length,
        })
    }

    /// Parse `<address>/<prefix>`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the input has no `/`, the address does not parse,
    /// the prefix is not an integer, or [`IpRange::new`] rejects the pair.
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            ModelError::invalid(
                "IpRange",
                format_args!("{:?} is not <address>/<prefix>", preview(value)),
            )
        })?;

        let address = IpAddr::from_str(address).map_err(|error| {
            ModelError::invalid("IpRange", format_args!("invalid address ({error})"))
        })?;
        let prefix_length: u8 = prefix.parse().map_err(|_| {
            ModelError::invalid(
                "IpRange",
                format_args!("prefix {:?} is not an integer in 0..=128", preview(prefix)),
            )
        })?;

        Self::new(address, prefix_length)
    }

    /// The network address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_length)
    }
}

// ---------------------------------------------------------------------------------------------
// String-backed serde and schema plumbing
// ---------------------------------------------------------------------------------------------

/// Give a validated string-backed type the serde and schema impls that route through its
/// constructor, so the untrusted deserialisation path enforces exactly the same rules as the
/// constructor path.
macro_rules! string_backed {
    ($name:ident, $ctor:expr, $render:expr, $description:literal $(, $extra_key:literal : $extra_value:expr)* $(,)?) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&$render(self))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                #[allow(clippy::redundant_closure_call)]
                ($ctor)(raw).map_err(D::Error::custom)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self> {
                #[allow(clippy::redundant_closure_call)]
                ($ctor)(value.to_owned())
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                #[allow(unused_mut)]
                let mut schema = json_schema!({
                    "type": "string",
                    "description": $description,
                });
                $(schema.insert($extra_key.to_owned(), serde_json::json!($extra_value));)*
                schema
            }
        }
    };
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl fmt::Debug for CanonicalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalUrl({:?})", self.0.as_str())
    }
}

string_backed!(
    DomainName,
    DomainName::new,
    DomainName::to_string,
    "A DNS name, ASCII-lowercased, without a trailing dot. Internationalised names in xn-- form.",
    "maxLength": DOMAIN_NAME_MAX_BYTES,
);

string_backed!(
    EmailAddress,
    EmailAddress::new,
    EmailAddress::to_string,
    "An email address. The domain part is lowercased; the local part is case-sensitive and preserved.",
    "maxLength": EMAIL_ADDRESS_MAX_BYTES,
);

string_backed!(
    CanonicalUrl,
    CanonicalUrl::new,
    CanonicalUrl::to_string,
    "A URL with an http, https, ftp, or ftps scheme.",
    "maxLength": URL_MAX_BYTES,
);

string_backed!(
    MacAddress,
    MacAddress::new,
    MacAddress::to_string,
    "A 48-bit MAC address, rendered lower-case and colon-separated.",
    "pattern": "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$",
);

string_backed!(
    IpRange,
    |value: String| IpRange::parse(&value),
    IpRange::to_string,
    "A CIDR range whose host bits are zero, for example 10.0.0.0/8.",
);

// ---------------------------------------------------------------------------------------------
// The observable enum
// ---------------------------------------------------------------------------------------------

/// The kind of an [`Observable`], without its value.
///
/// Useful as an index key and as a filter, and stable as a string: the `snake_case` renderings are
/// the `type` discriminator in the serialised form, so renaming one is a breaking schema change.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ObservableKind {
    /// An IPv4 address.
    Ipv4Address,
    /// An IPv6 address.
    Ipv6Address,
    /// A CIDR range.
    IpRange,
    /// A DNS name.
    DomainName,
    /// A URL.
    Url,
    /// An email address.
    EmailAddress,
    /// A file digest.
    FileHash,
    /// A MAC address.
    MacAddress,
    /// An autonomous system number.
    AutonomousSystemNumber,
    /// A file name without a path.
    FileName,
    /// A file system path.
    FilePath,
    /// A named mutex.
    MutexName,
    /// A registry key path.
    RegistryKey,
    /// An HTTP user-agent string.
    UserAgent,
}

impl ObservableKind {
    /// The stable `snake_case` discriminator for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4Address => "ipv4_address",
            Self::Ipv6Address => "ipv6_address",
            Self::IpRange => "ip_range",
            Self::DomainName => "domain_name",
            Self::Url => "url",
            Self::EmailAddress => "email_address",
            Self::FileHash => "file_hash",
            Self::MacAddress => "mac_address",
            Self::AutonomousSystemNumber => "autonomous_system_number",
            Self::FileName => "file_name",
            Self::FilePath => "file_path",
            Self::MutexName => "mutex_name",
            Self::RegistryKey => "registry_key",
            Self::UserAgent => "user_agent",
        }
    }
}

impl fmt::Display for ObservableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single observed technical artefact.
///
/// Serialised adjacently tagged, as `{"type": "domain_name", "value": "example.com"}`, so the kind
/// is readable without a schema and a value can never be interpreted under the wrong kind.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum Observable {
    /// An IPv4 address.
    Ipv4Address(Ipv4Addr),
    /// An IPv6 address, never an IPv4-mapped one.
    Ipv6Address(Ipv6Address),
    /// A CIDR range.
    IpRange(IpRange),
    /// A DNS name.
    DomainName(DomainName),
    /// A URL.
    Url(CanonicalUrl),
    /// An email address.
    EmailAddress(EmailAddress),
    /// A file digest.
    FileHash(FileHash),
    /// A MAC address.
    MacAddress(MacAddress),
    /// An autonomous system number.
    AutonomousSystemNumber(u32),
    /// A file name without a path.
    FileName(ShortText),
    /// A file system path.
    FilePath(ShortText),
    /// A named mutex.
    MutexName(ShortText),
    /// A registry key path.
    RegistryKey(ShortText),
    /// An HTTP user-agent string.
    UserAgent(ShortText),
}

/// An IPv6 address that is not an IPv4-mapped or IPv4-compatible form.
///
/// `::ffff:192.0.2.1` and `192.0.2.1` are the same host. Allowing both to be stored, one as an
/// IPv6 observable and one as an IPv4 observable, would split a host's intelligence in two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Address(Ipv6Addr);

impl Ipv6Address {
    /// Validate an IPv6 address.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the address is an IPv4-mapped or IPv4-compatible
    /// form, which must be stored as [`Observable::Ipv4Address`] instead.
    pub fn new(address: Ipv6Addr) -> Result<Self> {
        if let Some(v4) = address.to_ipv4_mapped() {
            return Err(ModelError::invalid(
                "Ipv6Address",
                format_args!("{address} is IPv4-mapped; store {v4} as an ipv4_address observable"),
            ));
        }
        // `to_ipv4` also matches the deprecated IPv4-compatible `::a.b.c.d` form, excluding the
        // unspecified address and loopback, which are genuine IPv6 addresses.
        if address.to_ipv4().is_some() && !address.is_unspecified() && !address.is_loopback() {
            return Err(ModelError::invalid(
                "Ipv6Address",
                format_args!(
                    "{address} is an IPv4-compatible address; store it as an ipv4_address observable"
                ),
            ));
        }
        Ok(Self(address))
    }

    /// The wrapped address.
    #[must_use]
    pub const fn as_ipv6_addr(self) -> Ipv6Addr {
        self.0
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

string_backed!(
    Ipv6Address,
    |value: String| Ipv6Addr::from_str(&value)
        .map_err(|error| ModelError::invalid(
            "Ipv6Address",
            format_args!("{:?} is not an IPv6 address ({error})", preview(&value))
        ))
        .and_then(Ipv6Address::new),
    Ipv6Address::to_string,
    "An IPv6 address. IPv4-mapped and IPv4-compatible forms are rejected; store those as ipv4_address.",
    "format": "ipv6",
);

impl Identifiable for Observable {
    const ID_KIND: &'static str = "observable";
}

impl VersionedSchema for Observable {
    const SCHEMA_NAME: &'static str = "brolga.observable";
}

impl Observable {
    /// This observable's kind, without its value.
    #[must_use]
    pub const fn kind(&self) -> ObservableKind {
        match self {
            Self::Ipv4Address(_) => ObservableKind::Ipv4Address,
            Self::Ipv6Address(_) => ObservableKind::Ipv6Address,
            Self::IpRange(_) => ObservableKind::IpRange,
            Self::DomainName(_) => ObservableKind::DomainName,
            Self::Url(_) => ObservableKind::Url,
            Self::EmailAddress(_) => ObservableKind::EmailAddress,
            Self::FileHash(_) => ObservableKind::FileHash,
            Self::MacAddress(_) => ObservableKind::MacAddress,
            Self::AutonomousSystemNumber(_) => ObservableKind::AutonomousSystemNumber,
            Self::FileName(_) => ObservableKind::FileName,
            Self::FilePath(_) => ObservableKind::FilePath,
            Self::MutexName(_) => ObservableKind::MutexName,
            Self::RegistryKey(_) => ObservableKind::RegistryKey,
            Self::UserAgent(_) => ObservableKind::UserAgent,
        }
    }

    /// The canonical string rendering of this observable's value, without its kind.
    #[must_use]
    pub fn canonical_value(&self) -> String {
        match self {
            Self::Ipv4Address(value) => value.to_string(),
            Self::Ipv6Address(value) => value.to_string(),
            Self::IpRange(value) => value.to_string(),
            Self::DomainName(value) => value.to_string(),
            Self::Url(value) => value.to_string(),
            Self::EmailAddress(value) => value.to_string(),
            Self::FileHash(value) => value.to_string(),
            Self::MacAddress(value) => value.to_string(),
            Self::AutonomousSystemNumber(value) => value.to_string(),
            Self::FileName(value)
            | Self::FilePath(value)
            | Self::MutexName(value)
            | Self::RegistryKey(value)
            | Self::UserAgent(value) => value.as_str().to_owned(),
        }
    }

    /// The identifier this observable derives from its own value.
    ///
    /// Two imports of the same artefact produce the same identifier without any lookup, which is
    /// what makes re-importing a feed idempotent. The kind is part of the derivation, so a file
    /// named `example.com` and the DNS name `example.com` stay distinct.
    #[must_use]
    pub fn id(&self) -> Id<Self> {
        Id::derive(&[self.kind().as_str(), &self.canonical_value()])
    }
}

impl fmt::Display for Observable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind(), self.canonical_value())
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
    fn domain_names_are_lowercased_and_lose_a_trailing_dot() {
        assert_eq!(
            DomainName::new("Example.COM.").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            DomainName::new("sub.Example.com").unwrap().as_str(),
            "sub.example.com"
        );
    }

    #[test]
    fn domain_normalisation_is_idempotent() {
        let once = DomainName::new("Example.COM.").unwrap();
        let twice = DomainName::new(once.as_str()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn domain_names_reject_hostile_and_malformed_input() {
        for hostile in [
            "",
            ".",
            "..",
            "example..com",
            "localhost",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "example.com\u{0}",
            "exämple.com",
            "example.com..",
            // All-numeric top-level labels are ambiguous with IPv4 addresses.
            "10.0.0.1",
            "example.124",
            "http://example.com",
            "example.com/path",
        ] {
            assert!(
                DomainName::new(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }

        let long_label = format!("{}.com", "a".repeat(DOMAIN_LABEL_MAX_BYTES + 1));
        assert!(DomainName::new(long_label).is_err());

        let long_name = format!("{}.com", "a.".repeat(DOMAIN_NAME_MAX_BYTES));
        assert!(DomainName::new(long_name).is_err());
    }

    #[test]
    fn punycode_labels_are_accepted() {
        assert_eq!(
            DomainName::new("xn--bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn email_lowercases_the_domain_but_preserves_the_local_part() {
        let address = EmailAddress::new("Alice.Smith@Example.COM").unwrap();
        assert_eq!(address.local_part(), "Alice.Smith");
        assert_eq!(address.domain().as_str(), "example.com");
        assert_eq!(address.to_string(), "Alice.Smith@example.com");
    }

    #[test]
    fn email_rejects_hostile_input() {
        for hostile in [
            "",
            "no-at-sign",
            "@example.com",
            "user@",
            "user@localhost",
            "user name@example.com",
            "user\u{0}@example.com",
            "us@er@example.com",
        ] {
            assert!(
                EmailAddress::new(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }

        let long_local = format!("{}@example.com", "a".repeat(EMAIL_LOCAL_PART_MAX_BYTES + 1));
        assert!(EmailAddress::new(long_local).is_err());
    }

    #[test]
    fn urls_accept_retrievable_schemes_and_reject_the_rest() {
        assert!(CanonicalUrl::new("https://example.com/a?b=c#d").is_ok());
        assert!(CanonicalUrl::new("ftp://example.com/file").is_ok());

        for hostile in [
            "",
            "not a url",
            "javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=",
            "file:///etc/passwd",
            "//example.com/protocol-relative",
        ] {
            assert!(
                CanonicalUrl::new(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }

        let long = format!("https://example.com/{}", "a".repeat(URL_MAX_BYTES));
        assert!(CanonicalUrl::new(long).is_err());
    }

    #[test]
    fn file_hash_length_must_match_the_algorithm() {
        let sha256 = "e".repeat(64);
        assert!(FileHash::new(HashAlgorithm::Sha256, &sha256).is_ok());
        // The classic aggregation bug: a SHA-256 digest labelled MD5.
        assert!(FileHash::new(HashAlgorithm::Md5, &sha256).is_err());
        assert!(FileHash::new(HashAlgorithm::Sha256, "e".repeat(63)).is_err());
        assert!(FileHash::new(HashAlgorithm::Sha256, "z".repeat(64)).is_err());
    }

    #[test]
    fn file_hash_case_is_folded_and_idempotent() {
        let upper = "ABCDEF0123456789".repeat(4);
        let hash = FileHash::new(HashAlgorithm::Sha256, &upper).unwrap();
        assert_eq!(hash.value(), upper.to_ascii_lowercase());
        let again = FileHash::new(HashAlgorithm::Sha256, hash.value()).unwrap();
        assert_eq!(hash, again);
    }

    #[test]
    fn mac_addresses_canonicalise_to_lower_case_colons() {
        assert_eq!(
            MacAddress::new("AA-BB-CC-DD-EE-FF").unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            MacAddress::new("aa:bb:cc:dd:ee:ff").unwrap().octets(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );

        for hostile in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aabbccddeeff",
            "gg:bb:cc:dd:ee:ff",
            "a:b:c:d:e:f",
        ] {
            assert!(
                MacAddress::new(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn ip_ranges_require_the_network_address() {
        assert_eq!(
            IpRange::parse("10.0.0.0/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            IpRange::parse("2001:db8::/32").unwrap().to_string(),
            "2001:db8::/32"
        );
        assert!(IpRange::parse("0.0.0.0/0").is_ok());
        assert!(IpRange::parse("::/0").is_ok());
        assert!(IpRange::parse("192.0.2.1/32").is_ok());

        // Host bits set: the same range with three different spellings would otherwise be three
        // different observables.
        assert!(IpRange::parse("10.0.0.1/8").is_err());
        assert!(IpRange::parse("2001:db8::1/32").is_err());
    }

    #[test]
    fn ip_ranges_reject_malformed_input() {
        for hostile in [
            "",
            "10.0.0.0",
            "10.0.0.0/",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/-1",
            "10.0.0.0/8/8",
            "not-an-address/8",
        ] {
            assert!(
                IpRange::parse(hostile).is_err(),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_is_rejected_so_a_host_is_not_split_in_two() {
        let mapped: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(Ipv6Address::new(mapped).is_err());

        let compatible: Ipv6Addr = "::192.0.2.1".parse().unwrap();
        assert!(Ipv6Address::new(compatible).is_err());

        // Genuine IPv6 addresses that happen to look convertible are still valid.
        assert!(Ipv6Address::new(Ipv6Addr::LOCALHOST).is_ok());
        assert!(Ipv6Address::new(Ipv6Addr::UNSPECIFIED).is_ok());
        assert!(Ipv6Address::new("2001:db8::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn observable_serialises_adjacently_tagged() {
        let observable = Observable::DomainName(DomainName::new("example.com").unwrap());
        let json = serde_json::to_value(&observable).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "domain_name", "value": "example.com"})
        );
    }

    #[test]
    fn every_observable_variant_round_trips_through_json() {
        for observable in sample_observables() {
            let json = serde_json::to_string(&observable).unwrap();
            let back: Observable = serde_json::from_str(&json).unwrap();
            assert_eq!(back, observable, "round trip failed for {observable}");
        }
    }

    #[test]
    fn deserialisation_validates_as_strictly_as_construction() {
        // A hostile payload cannot smuggle an invalid value in through serde.
        for hostile in [
            r#"{"type":"domain_name","value":"-bad-.com"}"#,
            r#"{"type":"domain_name","value":"localhost"}"#,
            r#"{"type":"url","value":"javascript:alert(1)"}"#,
            r#"{"type":"ipv6_address","value":"::ffff:192.0.2.1"}"#,
            r#"{"type":"ip_range","value":"10.0.0.1/8"}"#,
            r#"{"type":"file_hash","value":{"algorithm":"md5","value":"aa"}}"#,
            r#"{"type":"mac_address","value":"zz:bb:cc:dd:ee:ff"}"#,
            r#"{"type":"email_address","value":"user@localhost"}"#,
            r#"{"type":"unknown_kind","value":"x"}"#,
            r#"{"type":"domain_name","value":"example.com","extra":1}"#,
            r#"{"type":"autonomous_system_number","value":-1}"#,
            r#"{"type":"autonomous_system_number","value":"64500"}"#,
        ] {
            assert!(
                serde_json::from_str::<Observable>(hostile).is_err(),
                "expected {hostile} to be rejected"
            );
        }
    }

    #[test]
    fn identifiers_are_derived_from_kind_and_value() {
        let domain = Observable::DomainName(DomainName::new("example.com").unwrap());
        let same = Observable::DomainName(DomainName::new("EXAMPLE.com.").unwrap());
        assert_eq!(
            domain.id(),
            same.id(),
            "case and trailing dot must not split identity"
        );

        let file_name = Observable::FileName(ShortText::new("example.com").unwrap());
        assert_ne!(
            domain.id(),
            file_name.id(),
            "a file named example.com is not the DNS name example.com"
        );
    }

    #[test]
    fn identifiers_are_stable_across_releases() {
        // Pinned. A change here re-identifies every stored observable, which ADR 0001 §6 classes as
        // a breaking algorithm change requiring a new algorithm version.
        let domain = Observable::DomainName(DomainName::new("example.com").unwrap());
        assert_eq!(
            domain.id().to_string(),
            "observable:b3d22c64-06a4-590e-8486-b3499862768f"
        );
    }

    #[test]
    fn kind_strings_match_the_serde_discriminator() {
        for observable in sample_observables() {
            let json = serde_json::to_value(&observable).unwrap();
            let tag = json
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap();
            assert_eq!(
                tag,
                observable.kind().as_str(),
                "ObservableKind::as_str must match the wire discriminator"
            );
        }
    }

    #[test]
    fn display_is_kind_prefixed() {
        let observable = Observable::AutonomousSystemNumber(64_500);
        assert_eq!(observable.to_string(), "autonomous_system_number:64500");
    }

    fn sample_observables() -> Vec<Observable> {
        vec![
            Observable::Ipv4Address("192.0.2.1".parse().unwrap()),
            Observable::Ipv6Address(Ipv6Address::new("2001:db8::1".parse().unwrap()).unwrap()),
            Observable::IpRange(IpRange::parse("10.0.0.0/8").unwrap()),
            Observable::DomainName(DomainName::new("example.com").unwrap()),
            Observable::Url(CanonicalUrl::new("https://example.com/a").unwrap()),
            Observable::EmailAddress(EmailAddress::new("user@example.com").unwrap()),
            Observable::FileHash(FileHash::new(HashAlgorithm::Sha256, "a".repeat(64)).unwrap()),
            Observable::MacAddress(MacAddress::new("aa:bb:cc:dd:ee:ff").unwrap()),
            Observable::AutonomousSystemNumber(64_500),
            Observable::FileName(ShortText::new("payload.exe").unwrap()),
            Observable::FilePath(ShortText::new("C:\\Windows\\Temp\\payload.exe").unwrap()),
            Observable::MutexName(ShortText::new("Global\\ExampleMutex").unwrap()),
            Observable::RegistryKey(
                ShortText::new("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run").unwrap(),
            ),
            Observable::UserAgent(ShortText::new("Mozilla/5.0 (compatible)").unwrap()),
        ]
    }

    #[test]
    fn sample_covers_every_observable_kind() {
        // Guards against a new variant being added without a round-trip test covering it.
        let covered: std::collections::BTreeSet<_> = sample_observables()
            .iter()
            .map(|observable| observable.kind().as_str())
            .collect();
        assert_eq!(
            covered.len(),
            14,
            "add the new variant to sample_observables"
        );
    }
}
