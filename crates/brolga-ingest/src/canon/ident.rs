//! Catalogue and platform identifiers.
//!
//! These canonicalise to **strings**, not to [`Observable`](brolga_model::Observable) variants.
//!
//! A CVE, a CWE, and an ATT&CK technique already have homes in the canonical model as
//! [`EntityKind::Vulnerability`](brolga_model::EntityKind) and
//! [`EntityKind::AttackTechnique`](brolga_model::EntityKind); adding observable variants for them
//! would give one real-world thing two canonical representations, which is how a graph ends up with
//! a vulnerability that is not connected to itself.
//!
//! The platform identifiers — CPE, package URL, container image, cloud resource, Kubernetes
//! resource — have no model variant *yet*, and deliberately do not get one here. Nothing produces
//! them until a format parser does ([#13](https://github.com/jusso-dev/Brolga/issues/13)–[#15](https://github.com/jusso-dev/Brolga/issues/15)),
//! and adding five canonical variants that nothing emits is the speculative compatibility surface
//! ADR 0001 §1 was written to avoid. The canonicalisation — which is the hard, testable part, and
//! what this issue's acceptance criteria are about — exists now and is reusable when a parser needs
//! it.
//!
//! Every function here is a linear scan with a length check first. No regular expressions.

use super::{CanonError, Canonical, no_control_characters, trimmed, within};

/// Longest identifier accepted before any scan.
pub const IDENTIFIER_MAX_BYTES: usize = 2048;

/// Canonicalise a CVE identifier to `CVE-YYYY-NNNN...`.
///
/// Uppercased; the numeric part is left exactly as written. Stripping leading zeros would be wrong:
/// `CVE-2014-0160` is the identifier, and `CVE-2014-160` is not a shorter spelling of it, it is
/// nothing at all.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn cve(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "Cve";
    let value = prepared(KIND, raw)?;
    let upper = value.to_ascii_uppercase();

    let rest = upper
        .strip_prefix("CVE-")
        .ok_or_else(|| CanonError::malformed(KIND, value, "does not begin `CVE-`"))?;
    let (year, sequence) = rest.split_once('-').ok_or_else(|| {
        CanonError::malformed(KIND, value, "has no sequence number after the year")
    })?;

    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CanonError::malformed(KIND, value, "has no four-digit year"));
    }
    // Four is the CVE minimum; there is no maximum, and assuming one has broken tooling before.
    if sequence.len() < 4 || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has a sequence number that is not at least four digits",
        ));
    }

    Ok(Canonical::from_raw(upper, raw))
}

/// Canonicalise a CWE identifier to `CWE-NNN`.
///
/// Leading zeros *are* stripped here, unlike CVE: CWE numbers are written unpadded by MITRE, and
/// `CWE-079` and `CWE-79` are the same weakness written two ways.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn cwe(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "Cwe";
    let value = prepared(KIND, raw)?;
    let upper = value.to_ascii_uppercase();

    let digits = upper
        .strip_prefix("CWE-")
        .ok_or_else(|| CanonError::malformed(KIND, value, "does not begin `CWE-`"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has a non-numeric identifier",
        ));
    }

    let trimmed_digits = digits.trim_start_matches('0');
    let number = if trimmed_digits.is_empty() {
        "0"
    } else {
        trimmed_digits
    };

    Ok(Canonical::from_raw(format!("CWE-{number}"), raw))
}

/// Canonicalise a MITRE ATT&CK identifier: `T1059`, `T1059.001`, `TA0002`, `S0154`, `G0016`.
///
/// A sub-technique keeps its parent and its three-digit suffix. Collapsing `T1059.001` to `T1059`
/// would merge PowerShell into "Command and Scripting Interpreter" generally, which is the
/// difference between a detection and a category.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn attack_id(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "AttackId";
    let value = prepared(KIND, raw)?;
    let upper = value.to_ascii_uppercase();

    let (prefix, rest) = if let Some(rest) = upper.strip_prefix("TA") {
        ("TA", rest)
    } else {
        let mut characters = upper.chars();
        let first = characters.next().ok_or(CanonError::Empty { kind: KIND })?;
        match first {
            'T' => ("T", upper.get(1..).unwrap_or_default()),
            'S' => ("S", upper.get(1..).unwrap_or_default()),
            'G' => ("G", upper.get(1..).unwrap_or_default()),
            'M' => ("M", upper.get(1..).unwrap_or_default()),
            _ => {
                return Err(CanonError::malformed(
                    KIND,
                    value,
                    "does not begin T, TA, S, G, or M",
                ));
            }
        }
    };

    let (base, sub) = match rest.split_once('.') {
        Some((base, sub)) => (base, Some(sub)),
        None => (rest, None),
    };

    if base.len() < 4 || !base.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has fewer than four digits after its prefix",
        ));
    }
    if let Some(sub) = sub {
        if sub.len() != 3 || !sub.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CanonError::malformed(
                KIND,
                value,
                "has a sub-technique suffix that is not three digits",
            ));
        }
        // Only techniques have sub-techniques.
        if prefix != "T" {
            return Err(CanonError::malformed(
                KIND,
                value,
                "has a sub-technique suffix on something that is not a technique",
            ));
        }
    }

    Ok(Canonical::from_raw(upper, raw))
}

/// Canonicalise a CPE 2.3 formatted-string name.
///
/// Lowercases the scheme, version, and part fields — which are a closed vocabulary — and leaves
/// every remaining component exactly as written. Vendor and product components are case-sensitive
/// in the CPE specification's matching rules, and lowercasing them would merge two entries the
/// dictionary treats as distinct.
///
/// Only 2.3 formatted strings (`cpe:2.3:...`) are accepted. The 2.2 URI binding (`cpe:/a:...`) is a
/// different grammar with different escaping, and silently converting between them loses
/// information in both directions.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn cpe(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "Cpe";
    const COMPONENT_COUNT: usize = 13;
    let value = prepared(KIND, raw)?;

    let components: Vec<&str> = value.split(':').collect();
    if components.len() != COMPONENT_COUNT {
        return Err(CanonError::malformed(
            KIND,
            value,
            "is not a 13-component CPE 2.3 formatted string",
        ));
    }
    let scheme = components.first().copied().unwrap_or_default();
    let version = components.get(1).copied().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("cpe") || version != "2.3" {
        return Err(CanonError::malformed(
            KIND,
            value,
            "is not `cpe:2.3:`; the 2.2 URI binding is a different grammar",
        ));
    }

    let part = components.get(2).copied().unwrap_or_default();
    if !matches!(
        part.to_ascii_lowercase().as_str(),
        "a" | "o" | "h" | "*" | "-"
    ) {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has a part that is not a, o, h, *, or -",
        ));
    }

    let mut canonical = String::with_capacity(value.len());
    canonical.push_str("cpe:2.3:");
    canonical.push_str(&part.to_ascii_lowercase());
    for component in components.iter().skip(3) {
        canonical.push(':');
        canonical.push_str(component);
    }

    Ok(Canonical::from_raw(canonical, raw))
}

/// Canonicalise a package URL (`pkg:type/namespace/name@version?qualifiers#subpath`).
///
/// The scheme and type are lowercased, per the purl specification, which states both are
/// case-insensitive. **The name and version are not**, because for most ecosystems they are not:
/// a Maven artefact and a Go module both distinguish case, and lowercasing would merge distinct
/// packages. The specification names a few types where the name *is* case-insensitive; applying
/// that per-type rule needs the type registry, and guessing is worse than not normalising.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn package_url(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "PackageUrl";
    let value = prepared(KIND, raw)?;

    let rest = strip_prefix_ignore_case(value, "pkg:")
        .ok_or_else(|| CanonError::malformed(KIND, value, "does not begin `pkg:`"))?;
    // The spec permits `pkg://type/...`; the slashes carry no meaning.
    let rest = rest.trim_start_matches('/');

    let (kind, remainder) = rest
        .split_once('/')
        .ok_or_else(|| CanonError::malformed(KIND, value, "has no type followed by a name"))?;
    if kind.is_empty() {
        return Err(CanonError::malformed(KIND, value, "has an empty type"));
    }
    if !kind
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+')
    {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has a type outside the permitted alphanumeric set",
        ));
    }
    if remainder.is_empty() {
        return Err(CanonError::malformed(KIND, value, "has an empty name"));
    }

    let canonical = format!("pkg:{}/{remainder}", kind.to_ascii_lowercase());
    Ok(Canonical::from_raw(canonical, raw))
}

/// Canonicalise an OCI container image reference.
///
/// The registry host is lowercased — it is a DNS name — and so is the repository path, which the
/// distribution specification requires to be lowercase. A tag or digest is left exactly as written:
/// tags are case-sensitive, and a digest is a digest.
///
/// The default registry and the `latest` tag are **not** filled in. `alpine` and
/// `docker.io/library/alpine:latest` resolve to the same thing under Docker's defaults and to
/// different things under another registry's, so expanding them would bake one client's
/// configuration into stored intelligence.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn container_image(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "ContainerImage";
    let value = prepared(KIND, raw)?;

    // Split the digest first: it may contain `:` and must not be confused with a tag separator.
    let (before_digest, digest) = match value.split_once('@') {
        Some((before, digest)) => {
            if digest.is_empty() {
                return Err(CanonError::malformed(KIND, value, "has an empty digest"));
            }
            (before, Some(digest))
        }
        None => (value, None),
    };

    // A `:` after the last `/` is a tag. A `:` before it is a registry port.
    let last_slash = before_digest.rfind('/');
    let tag_separator = before_digest
        .rfind(':')
        .filter(|colon| last_slash.is_none_or(|slash| *colon > slash));

    let (name, tag) = match tag_separator {
        Some(index) => {
            let name = before_digest.get(..index).unwrap_or_default();
            let tag = before_digest
                .get(index.saturating_add(1)..)
                .unwrap_or_default();
            if tag.is_empty() {
                return Err(CanonError::malformed(KIND, value, "has an empty tag"));
            }
            (name, Some(tag))
        }
        None => (before_digest, None),
    };

    if name.is_empty() {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has an empty repository",
        ));
    }

    let mut canonical = name.to_ascii_lowercase();
    if let Some(tag) = tag {
        canonical.push(':');
        canonical.push_str(tag);
    }
    if let Some(digest) = digest {
        canonical.push('@');
        canonical.push_str(digest);
    }

    Ok(Canonical::from_raw(canonical, raw))
}

/// Canonicalise a cloud resource identifier: an AWS ARN, an Azure resource id, or a GCP resource
/// name.
///
/// Each provider's own case rules are applied, and nothing else:
///
/// - **AWS ARN** — the first five colon-separated fields (`arn`, partition, service, region,
///   account) are lowercased. The resource part is left alone: S3 object keys are case-sensitive,
///   and lowercasing one changes which object is named.
/// - **Azure** — the `/subscriptions/...` key segments are lowercased, since Azure's resource
///   identifiers are case-insensitive, but resource *names* are preserved.
/// - **GCP** — left as written. GCP resource names are case-sensitive throughout.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn cloud_resource(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "CloudResource";
    let value = prepared(KIND, raw)?;

    if let Some(rest) = strip_prefix_ignore_case(value, "arn:") {
        let fields: Vec<&str> = rest.splitn(5, ':').collect();
        if fields.len() < 5 {
            return Err(CanonError::malformed(
                KIND,
                value,
                "is an ARN with fewer than six colon-separated fields",
            ));
        }
        let mut canonical = String::from("arn:");
        for field in fields.iter().take(4) {
            canonical.push_str(&field.to_ascii_lowercase());
            canonical.push(':');
        }
        // The resource field keeps its case; S3 keys and IAM paths are case-sensitive.
        canonical.push_str(fields.get(4).copied().unwrap_or_default());
        return Ok(Canonical::from_raw(canonical, raw));
    }

    if value.starts_with('/') {
        // Azure: lowercase the well-known key segments, keep the values that follow them.
        let canonical: Vec<String> = value
            .split('/')
            .enumerate()
            .map(|(index, segment)| {
                // Segments alternate key/value after the leading empty one.
                if index % 2 == 1 {
                    segment.to_ascii_lowercase()
                } else {
                    segment.to_owned()
                }
            })
            .collect();
        return Ok(Canonical::from_raw(canonical.join("/"), raw));
    }

    if value.contains('/') {
        // GCP resource name: case-sensitive throughout, so nothing is rewritten.
        return Ok(Canonical::from_raw(value.to_owned(), raw));
    }

    Err(CanonError::malformed(
        KIND,
        value,
        "is not an ARN, an Azure resource id, or a GCP resource name",
    ))
}

/// Canonicalise a Kubernetes resource reference as `kind/namespace/name` or `kind/name`.
///
/// The kind is lowercased and singularised to its API form; the namespace and name are left alone,
/// because Kubernetes object names are case-sensitive (and in practice already lowercase, which is
/// a validation rule rather than something to enforce here).
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], or [`CanonError::Malformed`].
pub fn kubernetes_resource(raw: &str) -> Result<Canonical<String>, CanonError> {
    const KIND: &str = "KubernetesResource";
    let value = prepared(KIND, raw)?;

    let parts: Vec<&str> = value.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(CanonError::malformed(
            KIND,
            value,
            "has an empty path segment",
        ));
    }

    let canonical = match parts.as_slice() {
        [kind, name] => format!("{}/{name}", kind.to_ascii_lowercase()),
        [kind, namespace, name] => {
            format!("{}/{namespace}/{name}", kind.to_ascii_lowercase())
        }
        _ => {
            return Err(CanonError::malformed(
                KIND,
                value,
                "is not `kind/name` or `kind/namespace/name`",
            ));
        }
    };

    Ok(Canonical::from_raw(canonical, raw))
}

/// Shared preparation: trim, refuse control characters, and bound the length before scanning.
fn prepared<'a>(kind: &'static str, raw: &'a str) -> Result<&'a str, CanonError> {
    let value = trimmed(kind, raw)?;
    no_control_characters(kind, value)?;
    within(kind, value, IDENTIFIER_MAX_BYTES)?;
    Ok(value)
}

/// `strip_prefix`, ignoring ASCII case, without allocating the whole lowercased string first.
fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| value.get(prefix.len()..))
        .flatten()
}
