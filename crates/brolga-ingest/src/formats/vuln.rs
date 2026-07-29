//! What every vulnerability and software-inventory format shares.
//!
//! Seven parsers land in [#53](https://github.com/jusso-dev/Brolga/issues/53) — OSV, NVD, CSAF,
//! CVRF, CycloneDX, SPDX, CISA KEV, and SARIF. They disagree about almost everything at the wire
//! level and agree about three things underneath: a vulnerability has an identity, a package has an
//! identity, and one affects the other over a range of versions. Those three live here, so that a
//! CVE read from NVD and the same CVE read from an OSV record are **one entity**, not two.
//!
//! # Identity is the whole game
//!
//! The reason this module exists rather than each parser deriving its own identifiers: a
//! vulnerability arrives under several names. `GHSA-jfh8-c2jp-5v3q`, `CVE-2021-44228`, and
//! `SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720` are one flaw, and every advisory that mentions it
//! lists the others as aliases. So [`vulnerability_id`] prefers a canonical CVE drawn from the
//! document's own identifier *or* its alias list, and falls back to the upstream identifier only
//! when no CVE is named. Every name that was not chosen is recorded as a `vuln.alias` attribute, so
//! a lookup by the discarded name still finds the entity through its claims.
//!
//! That rule has a consequence worth stating: an advisory published under a GHSA identifier
//! *before* a CVE was assigned produces one entity, and the same advisory re-ingested after the CVE
//! is assigned produces a **different** entity, because its identity now resolves to the CVE. The
//! two are linked by the alias claims rather than merged. Merging them would need identity to be
//! mutable, and a stored identifier that can change is not an identifier. Deduplication across a
//! late CVE assignment is [#55](https://github.com/jusso-dev/Brolga/issues/55)'s problem, where a
//! query language makes alias-following expressible.
//!
//! # Affected ranges hang off the package, keyed by the vulnerability
//!
//! A range is a property of the *pair* — `log4j-core` is affected between 2.0-beta9 and 2.15.0,
//! which is neither a fact about the package alone nor about the flaw alone. The canonical model
//! has no claims about relationships ([`NodeRef`] is an entity or an observable, deliberately), so
//! the range is recorded as an attribute on the package entity whose name carries the vulnerability
//! identifier: `vuln.affected_range.CVE-2021-44228`. That keeps it unambiguous and queryable
//! without inventing an edge-property mechanism for one case.
//!
//! # What is lost, stated plainly
//!
//! - **Version-range semantics are text, not comparisons.** `introduced 2.0.0, fixed 2.15.0` is
//!   stored as written. Brolga does not know that `2.14.1` falls inside it, because deciding that
//!   needs an ecosystem-specific comparator per purl type — semver, PEP 440, Maven, Debian's
//!   `dpkg --compare-versions`, RPM's `rpmvercmp` — and a wrong comparator silently reports a
//!   vulnerable estate as clean. That is a scanner's job, and #53's non-goal says Brolga is not one.
//! - **CVSS vectors are recorded as their vector string and base score, not decomposed.**
//! - **CPE match rules** (`vulnerable: true` with `versionEndExcluding`, running-on-conditions,
//!   node-level `AND`/`OR`) are recorded as the CPE plus the range text. The boolean tree that
//!   NVD's configurations express is not reconstructed, and a parser that flattened it would turn
//!   "vulnerable only when running on this platform" into "vulnerable".

use brolga_model::{
    Assertion, Claim, Entity, EntityKind, Id, NodeRef, RecordOrigin, Relationship,
    RelationshipKind, ShortText, UntrustedText,
};

use crate::canon;
use crate::error::ParseError;

/// Most identifiers read from one document's alias list.
pub const MAX_ALIASES: usize = 64;

/// Most references read from one advisory.
///
/// References are evidence a human follows. A document naming thousands is a link dump rather than
/// an advisory, and the excess is noted rather than stored.
pub const MAX_REFERENCES: usize = 64;

/// Most affected packages read from one advisory.
pub const MAX_AFFECTED: usize = 1_024;

/// Most components read from one SBOM.
///
/// An SBOM for a large container image runs to several thousand components, so this is set well
/// above the ordinary case and below the point where one document dominates a store.
pub const MAX_COMPONENTS: usize = 20_000;

/// Most results read from one static-analysis run.
pub const MAX_RESULTS: usize = 20_000;

/// The canonical identity chosen for a vulnerability, and the names that were not chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityIdentity {
    /// The identifier the entity is keyed on. A canonical CVE where one was available.
    pub canonical: String,
    /// Every other name the document gave, in the order it gave them.
    pub aliases: Vec<String>,
}

/// Choose an identity from a primary identifier and an alias list.
///
/// A canonical CVE wins, wherever it appears. Otherwise the primary identifier is used as written
/// but uppercased, because advisory identifiers are conventionally uppercase and `ghsa-...` and
/// `GHSA-...` are the same advisory.
///
/// Returns `None` when the primary identifier is empty and no alias is usable — a document that
/// names no vulnerability at all.
#[must_use]
pub fn vulnerability_id(primary: &str, aliases: &[String]) -> Option<VulnerabilityIdentity> {
    let mut names: Vec<String> = Vec::with_capacity(aliases.len() + 1);
    for candidate in core::iter::once(primary).chain(aliases.iter().map(String::as_str)) {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalised = canon::ident::cve(trimmed)
            .map(canon::Canonical::into_value)
            .unwrap_or_else(|_| trimmed.to_ascii_uppercase());
        if !names.contains(&normalised) {
            names.push(normalised);
        }
        if names.len() > MAX_ALIASES {
            break;
        }
    }

    // A CVE anywhere in the list wins, in the order the document listed them. Position matters only
    // for the pathological document naming two different CVEs, where "the first one written" is at
    // least a rule somebody can read off the source.
    let chosen = names
        .iter()
        .position(|name| canon::ident::cve(name).is_ok())
        .unwrap_or(0);
    if names.is_empty() {
        return None;
    }
    let canonical = names.remove(chosen);
    Some(VulnerabilityIdentity {
        canonical,
        aliases: names,
    })
}

/// The stable entity identifier for a vulnerability.
///
/// Lowercased in the derivation so that a source shouting `cve-2021-44228` and one whispering it
/// land on the same entity. The canonical form retained on the entity is the uppercase one.
#[must_use]
pub fn vulnerability_entity_id(canonical: &str) -> Id<Entity> {
    Id::derive(&["vulnerability", &canonical.to_lowercase()])
}

/// The stable entity identifier for a software package.
///
/// Keyed on a canonical purl where the document supplied one, because a purl already encodes
/// ecosystem, name, and version in a form every SBOM tool emits. Without one, the parts are used
/// directly — an ecosystem-qualified name and version is the best available substitute, and it is
/// the shape OSV's `package` object has when it omits the purl.
#[must_use]
pub fn package_entity_id(
    purl: Option<&str>,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Id<Entity> {
    if let Some(purl) = purl
        && let Ok(canonical) = canon::ident::package_url(purl)
    {
        return Id::derive(&["software_package", canonical.value()]);
    }
    Id::derive(&["software_package", &ecosystem.to_lowercase(), name, version])
}

/// Build a vulnerability entity with a display name and its aliases as claims.
///
/// # Errors
///
/// Returns [`ParseError`] if the identifier or summary cannot be held by the model's bounded text
/// types, which for a vulnerability identifier means the document was not describing one.
pub fn vulnerability_entity(
    identity: &VulnerabilityIdentity,
    summary: Option<&str>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Entity, Vec<Claim>), ParseError> {
    let display = UntrustedText::new(bounded(&identity.canonical, field_limit))
        .map_err(|error| ParseError::new(format!("unusable vulnerability identifier: {error}")))?;

    let id = vulnerability_entity_id(&identity.canonical);
    let mut entity = Entity::new(id, EntityKind::Vulnerability, display, origin.clone());
    if let Some(summary) = summary
        && let Ok(text) = UntrustedText::new(bounded(summary, field_limit))
    {
        entity.description = Some(text);
    }

    let subject = NodeRef::Entity(id);
    let mut claims = Vec::with_capacity(identity.aliases.len() + 1);
    // The chosen identifier is claimed too, not only carried in the display name: a consumer
    // filtering claims for `vuln.id` should find it without having to know that the display name
    // happens to hold it.
    claims.push(Claim::new(
        subject,
        attribute("vuln.id", &identity.canonical, field_limit)?,
        origin.clone(),
    ));
    for alias in &identity.aliases {
        claims.push(Claim::new(
            subject,
            attribute("vuln.alias", alias, field_limit)?,
            origin.clone(),
        ));
    }
    Ok((entity, claims))
}

/// Build a software-package entity.
///
/// The display name is the purl where there is one, because a purl is what an operator pastes into
/// a search. Without one it is `name@version`, which is what the tooling of every ecosystem prints.
///
/// # Errors
///
/// Returns [`ParseError`] if the name cannot be held as bounded text.
pub fn package_entity(
    purl: Option<&str>,
    ecosystem: &str,
    name: &str,
    version: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Entity, Vec<Claim>), ParseError> {
    if name.trim().is_empty() {
        return Err(ParseError::new("a package with no name is not a package"));
    }

    let canonical_purl = purl
        .and_then(|raw| canon::ident::package_url(raw).ok())
        .map(canon::Canonical::into_value);
    let label = canonical_purl.clone().unwrap_or_else(|| {
        if version.is_empty() {
            name.to_owned()
        } else {
            format!("{name}@{version}")
        }
    });

    let display = UntrustedText::new(bounded(&label, field_limit))
        .map_err(|error| ParseError::new(format!("unusable package name: {error}")))?;
    let id = package_entity_id(purl, ecosystem, name, version);
    let entity = Entity::new(id, EntityKind::SoftwarePackage, display, origin.clone());

    let subject = NodeRef::Entity(id);
    let mut claims = Vec::new();
    for (field, value) in [
        ("package.name", name),
        ("package.version", version),
        ("package.ecosystem", ecosystem),
    ] {
        if !value.trim().is_empty() {
            claims.push(Claim::new(
                subject,
                attribute(field, value, field_limit)?,
                origin.clone(),
            ));
        }
    }
    if let Some(purl) = canonical_purl {
        claims.push(Claim::new(
            subject,
            attribute("package.purl", &purl, field_limit)?,
            origin.clone(),
        ));
    }
    Ok((entity, claims))
}

/// The typed edge from a vulnerability to a package it affects.
#[must_use]
pub fn affects(
    vulnerability: Id<Entity>,
    package: Id<Entity>,
    origin: &RecordOrigin,
) -> Relationship {
    Relationship::new(
        RelationshipKind::Affects,
        NodeRef::Entity(vulnerability),
        NodeRef::Entity(package),
        origin.clone(),
    )
}

/// An affected-version-range claim on a package, keyed by the vulnerability it belongs to.
///
/// See the module documentation for why the range lives here rather than on the edge, and why the
/// value is text rather than a comparable structure.
///
/// # Errors
///
/// Returns [`ParseError`] if the composed attribute name exceeds [`ShortText`]'s bound, which
/// happens only for an absurdly long vulnerability identifier.
pub fn affected_range(
    package: Id<Entity>,
    vulnerability: &str,
    range: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Claim, ParseError> {
    Ok(Claim::new(
        NodeRef::Entity(package),
        attribute(
            &format!("vuln.affected_range.{vulnerability}"),
            range,
            field_limit,
        )?,
        origin.clone(),
    ))
}

/// One attribute assertion, bounded on both sides.
///
/// # Errors
///
/// Returns [`ParseError`] if the name is not usable as a [`ShortText`] key or the value is not
/// usable as [`UntrustedText`] even after truncation.
pub fn attribute(name: &str, value: &str, field_limit: usize) -> Result<Assertion, ParseError> {
    Ok(Assertion::Attribute {
        name: ShortText::new(bounded(name, ShortText::MAX_BYTES))
            .map_err(|error| ParseError::new(format!("unusable attribute name: {error}")))?,
        value: UntrustedText::new(bounded(value, field_limit.min(UntrustedText::MAX_BYTES)))
            .map_err(|error| ParseError::new(format!("unusable attribute value: {error}")))?,
    })
}

/// Truncate at a character boundary.
#[must_use]
pub fn bounded(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

/// A string field from a JSON object, trimmed, absent when empty.
#[must_use]
pub fn text_at(value: &serde_json::Value, key: &str) -> Option<String> {
    let text = value.get(key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// A JSON array field, or an empty slice.
#[must_use]
pub fn array_at<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Every string in a JSON array field.
#[must_use]
pub fn strings_at(value: &serde_json::Value, key: &str) -> Vec<String> {
    array_at(value, key)
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .collect()
}

/// Reference claims on a vulnerability, capped, with the overflow reported.
///
/// Returns the claims and a note when references were dropped, because "this advisory had more
/// links than we kept" is exactly the kind of silent loss that makes a store untrustworthy.
///
/// # Errors
///
/// Returns [`ParseError`] if a reference cannot be held as bounded text.
pub fn reference_claims(
    subject: Id<Entity>,
    references: &[String],
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Vec<Claim>, Option<String>), ParseError> {
    let kept = references.len().min(MAX_REFERENCES);
    let mut claims = Vec::with_capacity(kept);
    for reference in references.iter().take(kept) {
        claims.push(Claim::new(
            NodeRef::Entity(subject),
            attribute("vuln.reference", reference, field_limit)?,
            origin.clone(),
        ));
    }
    let note = (references.len() > kept).then(|| {
        format!(
            "the advisory lists {} references; the first {kept} were kept",
            references.len()
        )
    });
    Ok((claims, note))
}

/// Check a document's byte length against the configured input limit.
///
/// # Errors
///
/// Returns [`ParseError`] when the document is over the limit.
pub fn within_byte_limit(bytes: &[u8], max_bytes: u64) -> Result<(), ParseError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(ParseError::new("input is over the byte limit"));
    }
    Ok(())
}

/// Check a produced record count against the configured record limit.
///
/// # Errors
///
/// Returns [`ParseError`] when the parser produced more records than the limit allows.
pub fn within_record_limit(produced: usize, max_records: u64) -> Result<(), ParseError> {
    let produced = u64::try_from(produced).unwrap_or(u64::MAX);
    if produced > max_records {
        return Err(ParseError::new(format!(
            "produced {produced} records, over the {max_records}-record limit"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_cve_anywhere_in_the_alias_list_becomes_the_identity() {
        let identity = vulnerability_id(
            "GHSA-jfh8-c2jp-5v3q",
            &["CVE-2021-44228".to_owned(), "SNYK-JAVA-1234".to_owned()],
        )
        .unwrap();
        assert_eq!(identity.canonical, "CVE-2021-44228");
        assert!(identity.aliases.contains(&"GHSA-JFH8-C2JP-5V3Q".to_owned()));
        assert!(identity.aliases.contains(&"SNYK-JAVA-1234".to_owned()));
    }

    /// **The criterion.** One flaw read from two advisories is one entity.
    #[test]
    fn two_sources_naming_one_flaw_derive_one_identifier() {
        let from_nvd = vulnerability_id("CVE-2021-44228", &[]).unwrap();
        let from_ghsa =
            vulnerability_id("GHSA-jfh8-c2jp-5v3q", &["CVE-2021-44228".to_owned()]).unwrap();
        assert_eq!(
            vulnerability_entity_id(&from_nvd.canonical),
            vulnerability_entity_id(&from_ghsa.canonical),
        );
    }

    #[test]
    fn case_does_not_split_an_identity() {
        assert_eq!(
            vulnerability_entity_id("CVE-2021-44228"),
            vulnerability_entity_id(&vulnerability_id("cve-2021-44228", &[]).unwrap().canonical),
        );
    }

    #[test]
    fn an_advisory_with_no_cve_keeps_its_own_identifier() {
        let identity = vulnerability_id("GHSA-aaaa-bbbb-cccc", &[]).unwrap();
        assert_eq!(identity.canonical, "GHSA-AAAA-BBBB-CCCC");
        assert!(identity.aliases.is_empty());
    }

    #[test]
    fn a_document_naming_nothing_yields_no_identity() {
        assert!(vulnerability_id("   ", &[]).is_none());
        assert!(vulnerability_id("", &[String::new()]).is_none());
    }

    /// A purl and the loose parts must not describe two packages when the purl is present in one
    /// document and absent in another — but they legitimately do, and the test states that so the
    /// behaviour is a decision rather than a surprise.
    #[test]
    fn a_purl_keys_a_package_and_its_absence_falls_back_to_the_parts() {
        let with = package_entity_id(
            Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
        );
        let same = package_entity_id(
            Some("PKG:MAVEN/org.apache.logging.log4j/log4j-core@2.14.1"),
            "",
            "",
            "",
        );
        assert_eq!(with, same, "the purl scheme and type are case-insensitive");

        let without = package_entity_id(
            None,
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
        );
        assert_ne!(
            with, without,
            "a purl and an ecosystem-qualified name are different keys; a source that omits the \
             purl produces a distinct entity, which is why parsers emit the purl wherever the \
             document carries one"
        );
    }

    #[test]
    fn an_alias_list_is_capped() {
        let aliases: Vec<String> = (0..500).map(|n| format!("GHSA-{n:04}")).collect();
        let identity = vulnerability_id("GHSA-primary", &aliases).unwrap();
        assert!(identity.aliases.len() <= MAX_ALIASES);
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // Three bytes each. Cutting at 4 must not split the second one.
        let text = "日本語";
        let cut = bounded(text, 4);
        assert_eq!(cut, "日");
    }

    /// A synthetic origin, sufficient here: these tests exercise mapping, and the pipeline is what
    /// supplies a source-derived one in the ingest path.
    fn origin() -> RecordOrigin {
        use brolga_model::provenance::{SyntheticOrigin, SyntheticReason};
        RecordOrigin::synthetic(SyntheticOrigin::new(
            SyntheticReason::OperatorEntered,
            ShortText::new("vuln-unit-test").expect("a usable creator"),
        ))
    }

    #[test]
    fn dropped_references_are_reported_rather_than_silently_lost() {
        let origin = origin();
        let references: Vec<String> = (0..MAX_REFERENCES + 5)
            .map(|n| format!("https://example.invalid/{n}"))
            .collect();
        let (claims, note) = reference_claims(
            vulnerability_entity_id("CVE-2021-44228"),
            &references,
            &origin,
            512,
        )
        .unwrap();
        assert_eq!(claims.len(), MAX_REFERENCES);
        assert!(note.is_some_and(|note| note.contains("were kept")));
    }
}
