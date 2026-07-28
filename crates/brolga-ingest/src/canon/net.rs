//! Network observables: addresses, ranges, domains, URLs, and email.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use brolga_model::observable::{DomainName, EmailAddress, IpRange, Observable};

use super::{CanonError, Canonical, no_control_characters, trimmed, within};

/// Longest domain name accepted before any scan.
pub const DOMAIN_MAX_BYTES: usize = 253;
/// Longest URL accepted before any scan.
pub const URL_MAX_BYTES: usize = 8192;
/// Longest email address accepted before any scan.
pub const EMAIL_MAX_BYTES: usize = 320;

/// Canonicalise an IP address, v4 or v6.
///
/// `::ffff:192.0.2.1` stays an IPv6 address. Folding it to its embedded IPv4 form would merge two
/// values that firewalls, allow-lists, and routing treat as different things, and the whole point
/// of the SSRF checks in `brolga-security` is that the *form* of an address matters.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::ForbiddenCharacter`], or [`CanonError::Malformed`].
pub fn ip_address(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "IpAddress";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;

    let address: IpAddr = value.parse().map_err(|_| {
        CanonError::malformed(KIND, value, "not a dotted-quad or colon-hex address")
    })?;

    // `IpAddr`'s own Display is the canonical form: v4 without leading zeros, v6 lowercased and
    // shortened by the RFC 5952 rules. Re-rendering rather than trusting the input is what makes
    // this idempotent — `2001:0DB8::0001` and `2001:db8::1` reduce to one key.
    let observable = match address {
        IpAddr::V4(value) => ipv4(value),
        IpAddr::V6(value) => ipv6(value)?,
    };
    Ok(from_observable(observable, raw))
}

/// Canonicalise a CIDR range.
///
/// The address is masked to the prefix length, so `192.0.2.5/24` and `192.0.2.0/24` become one
/// key. A range whose host bits are set is describing the network it is in, not a different network.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::ForbiddenCharacter`], or [`CanonError::Malformed`].
pub fn ip_range(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "IpRange";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;

    // The model refuses a range whose host bits are set, on the grounds that `192.0.2.5/24` is not
    // a network address. That refusal is right for the model and wrong for ingestion: feeds publish
    // that spelling constantly, and it unambiguously means the /24 the address sits in. Masking it
    // here, and recording what the source wrote, is exactly the transformation this layer exists to
    // perform — the model stays strict and the feed still parses.
    let (address, prefix) = split_cidr(KIND, value)?;
    let masked = mask_host_bits(address, prefix);
    let range = IpRange::new(masked, prefix).map_err(|_| {
        CanonError::malformed(
            KIND,
            value,
            "has a prefix length wider than its address family",
        )
    })?;
    Ok(from_observable(Observable::IpRange(range), raw))
}

/// Canonicalise a domain name, converting a Unicode name to its A-label form.
///
/// **Both forms are retained.** The canonical key is the ASCII A-label, because that is what
/// resolves and what every other system will key on; the Unicode form the source wrote is kept as
/// the original. Keeping only the Unicode form would make the key depend on our normalisation
/// choices, and keeping only the ASCII form would lose the fact that a homograph attack was
/// spelled the way it was spelled — which is the whole content of that finding.
///
/// The model's [`DomainName`] deliberately refuses to do this conversion itself, precisely so it
/// happens here where the original can be recorded in a provenance chain.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`] when IDNA conversion or DNS syntax validation fails.
pub fn domain_name(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "DomainName";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, DOMAIN_MAX_BYTES)?;

    // Only convert when there is something to convert. Running IDNA over an already-ASCII name is
    // wasted work and gives a second place for the two paths to disagree.
    let ascii = if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(value).map_err(|_| {
            CanonError::malformed(KIND, value, "cannot be converted to an ASCII A-label form")
        })?
    };

    let domain = DomainName::new(&ascii)
        .map_err(|_| CanonError::malformed(KIND, value, "is not a syntactically valid DNS name"))?;

    Ok(from_observable(Observable::DomainName(domain), raw))
}

/// Canonicalise a URL without erasing distinctions that mean something.
///
/// What is normalised: the scheme and host are lowercased, an IDN host becomes its A-label form,
/// and a port that is the scheme's default is dropped. Those genuinely cannot distinguish two
/// resources.
///
/// What is **left alone**, deliberately:
///
/// - **The path's case.** `/Admin` and `/admin` are different resources on any case-sensitive
///   server, which is most of them.
/// - **A trailing slash.** `/a` and `/a/` are routinely different, and merging them would collapse
///   a directory listing into a file.
/// - **Query parameter order.** Reordering assumes parameters are a set. They are a sequence, and
///   repeated keys are meaningful in several frameworks.
/// - **Percent-encoding.** Decoding `%2F` inside a path segment turns one segment into two and
///   changes what the URL addresses. This is the classic path-traversal normalisation bug, and the
///   safe direction is to not normalise.
/// - **The fragment.** It is not sent to the server, but it is what a report was pointing at.
///
/// A canonicaliser that erases any of these makes two different indicators look like one, which is
/// worse than leaving two spellings of the same one.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`] when the URL cannot be parsed or its scheme is not permitted.
pub fn url(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "Url";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, URL_MAX_BYTES)?;

    let canonical = brolga_model::observable::CanonicalUrl::new(value).map_err(|_| {
        CanonError::malformed(
            KIND,
            value,
            "is not an absolute URL with a permitted scheme and a host",
        )
    })?;

    Ok(from_observable(Observable::Url(canonical), raw))
}

/// Canonicalise an email address.
///
/// The domain is lowercased and IDNA-converted. **The local part is not touched.** Case sensitivity
/// in the local part is the receiving server's business — RFC 5321 §2.4 reserves it to them — and
/// lowercasing `Bob@example.com` asserts a policy Brolga has no way to know. Two spellings of one
/// mailbox is a smaller error than merging two mailboxes.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`].
pub fn email_address(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "EmailAddress";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, EMAIL_MAX_BYTES)?;

    // Split on the last `@`: a quoted local part may legally contain one, the domain may not.
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or_else(|| CanonError::malformed(KIND, value, "has no `@`"))?;
    if local.is_empty() {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has an empty local part",
        ));
    }

    let domain_ascii = if domain.is_ascii() {
        domain.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(domain).map_err(|_| {
            CanonError::malformed(KIND, value, "has a domain that cannot become an A-label")
        })?
    };

    let address = EmailAddress::new(format!("{local}@{domain_ascii}")).map_err(|_| {
        CanonError::malformed(KIND, value, "is not a syntactically valid email address")
    })?;

    Ok(from_observable(Observable::EmailAddress(address), raw))
}

/// Canonicalise whichever of the network kinds a value turns out to be.
///
/// Ordered most specific first. A CIDR range is tried before a bare address because `1.2.3.4/32`
/// parses as neither on the other path; a URL before a domain because `http://example.com` contains
/// a domain but is not one.
///
/// # Errors
///
/// [`CanonError::Malformed`] naming `NetworkObservable` when nothing matched. The individual
/// canonicalisers' reasons are not merged into it, because a value that is not any of five things
/// has five reasons and none of them is the useful one.
pub fn any_network(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    if raw.contains('/')
        && !raw.contains("://")
        && let Ok(range) = ip_range(raw)
    {
        return Ok(range);
    }
    if let Ok(address) = ip_address(raw) {
        return Ok(address);
    }
    if raw.contains("://") {
        return url(raw);
    }
    if raw.contains('@') {
        return email_address(raw);
    }
    domain_name(raw)
}

/// Wrap an IPv4 address as an observable.
fn ipv4(value: Ipv4Addr) -> Observable {
    Observable::Ipv4Address(value)
}

/// Wrap an IPv6 address as an observable, through the model's own validation.
fn ipv6(value: Ipv6Addr) -> Result<Observable, CanonError> {
    brolga_model::observable::Ipv6Address::new(value)
        .map(Observable::Ipv6Address)
        .map_err(|_| {
            CanonError::malformed(
                "IpAddress",
                &value.to_string(),
                "is not a usable IPv6 address",
            )
        })
}

/// Wrap an observable, comparing the raw input against its canonical *value* rather than against
/// its `Display`, which is `kind:value`.
fn from_observable(observable: Observable, raw: &str) -> Canonical<Observable> {
    let rendered = observable.canonical_value();
    Canonical::from_parts(observable, &rendered, raw)
}

/// Split `address/prefix`, rejecting anything else.
fn split_cidr(kind: &'static str, value: &str) -> Result<(IpAddr, u8), CanonError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| CanonError::malformed(kind, value, "has no `/` and a prefix length"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| CanonError::malformed(kind, value, "does not begin with an IP address"))?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        CanonError::malformed(kind, value, "has a prefix length that is not a number")
    })?;
    Ok((address, prefix))
}

/// Clear the host bits below a prefix length.
fn mask_host_bits(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(value) => {
            let bits = u32::from_be_bytes(value.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX
                    .checked_shl(u32::from(32_u8.saturating_sub(prefix)))
                    .unwrap_or(u32::MAX)
            };
            IpAddr::V4(Ipv4Addr::from((bits & mask).to_be_bytes()))
        }
        IpAddr::V6(value) => {
            let bits = u128::from_be_bytes(value.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX
                    .checked_shl(u32::from(128_u8.saturating_sub(prefix)))
                    .unwrap_or(u128::MAX)
            };
            IpAddr::V6(Ipv6Addr::from((bits & mask).to_be_bytes()))
        }
    }
}
