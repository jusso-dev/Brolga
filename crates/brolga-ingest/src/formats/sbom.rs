//! CycloneDX and SPDX — software bills of materials.
//!
//! # An SBOM is an inventory, and that changes what it is for
//!
//! Every other format in this milestone describes a *flaw*. An SBOM describes *what you have*. It is
//! the other half of the join: an advisory says `log4j-core` before 2.15.0 is vulnerable, an SBOM says
//! this image contains `log4j-core 2.14.1`, and the two meet on the package identifier.
//!
//! Which is why identity discipline matters more here than anywhere else in the milestone. If an SBOM
//! keys a package differently from the way an advisory does, the join silently produces nothing — and
//! "no results" reads identically to "nothing affected". So both parsers emit the purl wherever the
//! document carries one, and [`crate::formats::vuln::package_entity_id`] keys on the canonicalised
//! purl. CycloneDX populates `purl` almost universally; SPDX carries it in
//! `externalRefs[].referenceLocator` with `referenceType: purl`, which is read.
//!
//! # Brolga does not compute the join
//!
//! Storing both halves is not the same as answering "which of my packages are vulnerable". Answering
//! that needs a version comparator per ecosystem, which [`crate::formats::vuln`] explains is
//! deliberately absent. What an SBOM buys today: a package named by an advisory and the same package
//! named by an inventory are **one entity**, so a context lookup on either reaches both, and the
//! affected-range text is right there next to the installed version for a human to read.
//!
//! # CycloneDX
//!
//! Read: `metadata.component` as the subject of the SBOM, `components[]` with `name`, `version`,
//! `purl`, `type`, `group`, `publisher`, `licenses`, and `hashes`; `components[].components[]` nesting;
//! and `vulnerabilities[]` where a CycloneDX VEX section is embedded.
//!
//! `dependencies[]` — the actual dependency graph — is read as `PartOf` edges only from a component to
//! the SBOM's own subject component, not between components. A full transitive dependency graph from a
//! large image is tens of thousands of edges whose value is in graph queries Brolga cannot yet express
//! ([#55](https://github.com/jusso-dev/Brolga/issues/55)), and importing it now would multiply store
//! size for a capability that does not exist. The `dependsOn` lists are recorded as a count claim so
//! the omission is visible.
//!
//! # SPDX
//!
//! Read: `name` and `documentNamespace` as the document's identity, `packages[]` with `name`,
//! `versionInfo`, `licenseConcluded`, `licenseDeclared`, `supplier`, `checksums`, and purl external
//! references. `relationships[]` is read only for `CONTAINS` and `DEPENDS_ON` edges to the document's
//! describes-target, for the same reason as CycloneDX.
//!
//! SPDX tag-value files (`.spdx`) are **not** read — only the JSON serialisation. The tag-value grammar
//! is a distinct format with its own line-continuation and multi-line-text rules, and a half-correct
//! reader of it would produce packages with truncated names. That is a documented gap rather than a
//! silent one: detection declines tag-value input by name.

use brolga_model::{Claim, Entity, Id, NodeRef, RecordOrigin, RelationshipKind, ShortText};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{
    self, MAX_COMPONENTS, attribute, text_at, within_byte_limit, within_record_limit,
};
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// The CycloneDX parser's identifier.
pub const CYCLONEDX_PARSER_ID: ParserId = ParserId::new("brolga.sbom.cyclonedx");

/// The SPDX parser's identifier.
pub const SPDX_PARSER_ID: ParserId = ParserId::new("brolga.sbom.spdx");

/// Media types that identify CycloneDX definitively.
pub const CYCLONEDX_MEDIA_TYPES: &[&str] = &["application/vnd.cyclonedx+json"];

/// Media types that identify SPDX definitively.
pub const SPDX_MEDIA_TYPES: &[&str] = &["application/spdx+json"];

/// Deepest component nesting walked in a CycloneDX document.
pub const MAX_COMPONENT_DEPTH: usize = 32;

/// A CycloneDX reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct CycloneDxParser;

impl CycloneDxParser {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed, ready for [`crate::ParserRegistry::register`].
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self)
    }
}

impl IntelligenceParser for CycloneDxParser {
    fn id(&self) -> ParserId {
        CYCLONEDX_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if CYCLONEDX_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is CycloneDX",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        // `bomFormat: "CycloneDX"` is required by the specification and appears in nothing else.
        if text.contains("\"bomFormat\"") && text.contains("CycloneDX") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares `bomFormat: CycloneDX`",
            )
        } else if text.contains("\"specVersion\"") && text.contains("\"components\"") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "has a CycloneDX `specVersion` alongside a component list",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no CycloneDX marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        within_byte_limit(bytes, limits.max_bytes)?;

        let document: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not readable JSON: {error}")))?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let mut out = ParseOutput::default();

        // The SBOM's subject: what this inventory is *of*. Everything else is `PartOf` it, which is
        // what makes "show me what is in this image" a single-hop traversal.
        let subject = document
            .get("metadata")
            .and_then(|metadata| metadata.get("component"));
        let subject_id = match subject {
            Some(component) => {
                let (entity, claims) = component_entity(component, &origin, field_limit)?;
                let id = entity.id;
                for claim in claims {
                    out.records.push(ParsedRecord::Claim(Box::new(claim)));
                }
                out.records.push(ParsedRecord::Entity(Box::new(entity)));
                Some(id)
            }
            None => None,
        };

        let mut flattened: Vec<serde_json::Value> = Vec::new();
        collect_components(&document, 0, &mut flattened);
        if flattened.len() > MAX_COMPONENTS {
            return Err(ParseError::new(format!(
                "the SBOM holds {} components, over the {MAX_COMPONENTS} limit",
                flattened.len()
            )));
        }

        for (index, component) in flattened.iter().enumerate() {
            if index.is_multiple_of(256) {
                context
                    .check_cancelled()
                    .map_err(|error| ParseError::new(error.to_string()))?;
            }

            match component_entity(component, &origin, field_limit) {
                Ok((entity, claims)) => {
                    let id = entity.id;
                    for claim in claims {
                        out.records.push(ParsedRecord::Claim(Box::new(claim)));
                    }
                    out.records
                        .extend(component_detail(component, id, &origin, field_limit)?);
                    if let Some(subject_id) = subject_id
                        && subject_id != id
                    {
                        out.records
                            .push(ParsedRecord::Relationship(Box::new(part_of(
                                id, subject_id, &origin,
                            ))));
                    }
                    out.records.push(ParsedRecord::Entity(Box::new(entity)));
                }
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_component",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: text_at(component, "name"),
                }),
            }
        }

        // The dependency graph is not imported. Its size is recorded so the omission is a stated fact
        // rather than an absence somebody has to notice.
        let dependencies = vuln::array_at(&document, "dependencies");
        if !dependencies.is_empty()
            && let Ok(note) = ShortText::new(format!(
                "{} dependency entries were not imported as edges",
                dependencies.len()
            ))
        {
            out.notes.push(note);
        }

        if let Some(version) = text_at(&document, "specVersion")
            && let Some(subject_id) = subject_id
        {
            out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
                NodeRef::Entity(subject_id),
                attribute("sbom.spec_version", &version, field_limit)?,
                origin.clone(),
            ))));
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the SBOM names no components at all"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Flatten `components[]`, including nested `components[].components[]`.
fn collect_components(node: &serde_json::Value, depth: usize, out: &mut Vec<serde_json::Value>) {
    if depth > MAX_COMPONENT_DEPTH || out.len() > MAX_COMPONENTS {
        return;
    }
    for component in vuln::array_at(node, "components") {
        out.push(component.clone());
        collect_components(component, depth.saturating_add(1), out);
    }
}

/// Build a package entity from a CycloneDX component.
fn component_entity(
    component: &serde_json::Value,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Entity, Vec<Claim>), ParseError> {
    let name =
        text_at(component, "name").ok_or_else(|| ParseError::new("the component has no `name`"))?;
    // `group` is CycloneDX's namespace — the Maven group, the npm scope. Two components named `core`
    // in different groups are different packages, so the group must be part of the fallback key.
    let qualified = match text_at(component, "group") {
        Some(group) => format!("{group}:{name}"),
        None => name,
    };
    let version = text_at(component, "version").unwrap_or_default();
    let purl = text_at(component, "purl");
    let ecosystem = text_at(component, "type").unwrap_or_else(|| "cyclonedx".to_owned());

    vuln::package_entity(
        purl.as_deref(),
        &ecosystem,
        &qualified,
        &version,
        origin,
        field_limit,
    )
}

/// Licences, hashes, and publisher, as claims on a component.
fn component_detail(
    component: &serde_json::Value,
    package_id: Id<Entity>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let subject = NodeRef::Entity(package_id);
    let mut records = Vec::new();

    for (field, name) in [
        ("publisher", "package.publisher"),
        ("type", "package.type"),
        ("description", "package.description"),
        ("cpe", "package.cpe"),
    ] {
        if let Some(text) = text_at(component, field) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // A licence is stated either as an SPDX identifier or as free-text; both shapes occur in the same
    // document. Recorded under distinct names so a consumer filtering for identifiers does not have to
    // guess whether a value is one.
    for licence in vuln::array_at(component, "licenses") {
        if let Some(entry) = licence.get("license") {
            if let Some(id) = text_at(entry, "id") {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute("package.license_id", &id, field_limit)?,
                    origin.clone(),
                ))));
            } else if let Some(name) = text_at(entry, "name") {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute("package.license_name", &name, field_limit)?,
                    origin.clone(),
                ))));
            }
        }
        if let Some(expression) = text_at(licence, "expression") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("package.license_expression", &expression, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // Hashes identify the artefact, which is what makes an SBOM entry verifiable rather than merely
    // asserted. Recorded under the algorithm's own name.
    for hash in vuln::array_at(component, "hashes") {
        if let (Some(algorithm), Some(value)) = (text_at(hash, "alg"), text_at(hash, "content")) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(
                    &format!("package.hash.{}", algorithm.to_lowercase()),
                    &value,
                    field_limit,
                )?,
                origin.clone(),
            ))));
        }
    }

    Ok(records)
}

/// A component is part of the thing the SBOM describes.
fn part_of(
    component: Id<Entity>,
    subject: Id<Entity>,
    origin: &RecordOrigin,
) -> brolga_model::Relationship {
    brolga_model::Relationship::new(
        RelationshipKind::PartOf,
        NodeRef::Entity(component),
        NodeRef::Entity(subject),
        origin.clone(),
    )
}

/// An SPDX 2.x JSON reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpdxParser;

impl SpdxParser {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed, ready for [`crate::ParserRegistry::register`].
    #[must_use]
    pub fn boxed() -> Box<dyn IntelligenceParser> {
        Box::new(Self)
    }
}

impl IntelligenceParser for SpdxParser {
    fn id(&self) -> ParserId {
        SPDX_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if SPDX_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is SPDX JSON",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        // The tag-value serialisation is a different format and is declined by name rather than
        // half-read. See the module documentation.
        if text.starts_with("SPDXVersion:") || text.contains("\nSPDXVersion:") {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "is SPDX tag-value, which this parser does not read; only the JSON serialisation",
            );
        }
        if text.contains("\"spdxVersion\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares an `spdxVersion`",
            )
        } else if text.contains("\"SPDXID\"") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "carries SPDX element identifiers",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no SPDX marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        within_byte_limit(bytes, limits.max_bytes)?;

        let document: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| ParseError::new(format!("not readable JSON: {error}")))?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let packages = vuln::array_at(&document, "packages");
        if packages.is_empty() {
            return Err(ParseError::new("the document holds no `packages` array"));
        }
        if packages.len() > MAX_COMPONENTS {
            return Err(ParseError::new(format!(
                "the document holds {} packages, over the {MAX_COMPONENTS} limit",
                packages.len()
            )));
        }

        // SPDX's `describes` target: the package the document is about. `documentDescribes` in 2.2,
        // a `DESCRIBES` relationship in 2.3. Both are checked, because both are in circulation.
        let described: Vec<String> = {
            let mut described = vuln::strings_at(&document, "documentDescribes");
            for relationship in vuln::array_at(&document, "relationships") {
                if text_at(relationship, "relationshipType").as_deref() == Some("DESCRIBES")
                    && let Some(target) = text_at(relationship, "relatedSpdxElement")
                {
                    described.push(target);
                }
            }
            described
        };

        let mut out = ParseOutput::default();
        let mut by_spdx_id: std::collections::BTreeMap<String, Id<Entity>> =
            std::collections::BTreeMap::new();

        for (index, package) in packages.iter().enumerate() {
            if index.is_multiple_of(256) {
                context
                    .check_cancelled()
                    .map_err(|error| ParseError::new(error.to_string()))?;
            }

            match spdx_package(package, &origin, field_limit) {
                Ok((entity, claims)) => {
                    let id = entity.id;
                    if let Some(spdx_id) = text_at(package, "SPDXID") {
                        by_spdx_id.insert(spdx_id, id);
                    }
                    for claim in claims {
                        out.records.push(ParsedRecord::Claim(Box::new(claim)));
                    }
                    out.records
                        .extend(spdx_detail(package, id, &origin, field_limit)?);
                    out.records.push(ParsedRecord::Entity(Box::new(entity)));
                }
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_spdx_package",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: text_at(package, "name"),
                }),
            }
        }

        // `PartOf` edges to the described package only, for the reason the module documentation gives.
        for target in &described {
            let Some(subject_id) = by_spdx_id.get(target).copied() else {
                continue;
            };
            for package_id in by_spdx_id.values().copied() {
                if package_id == subject_id {
                    continue;
                }
                out.records
                    .push(ParsedRecord::Relationship(Box::new(part_of(
                        package_id, subject_id, &origin,
                    ))));
            }
        }

        let relationships = vuln::array_at(&document, "relationships");
        if !relationships.is_empty()
            && let Ok(note) = ShortText::new(format!(
                "{} SPDX relationships were read only for DESCRIBES",
                relationships.len()
            ))
        {
            out.notes.push(note);
        }

        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Build a package entity from an SPDX package, reading its purl external reference.
fn spdx_package(
    package: &serde_json::Value,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Entity, Vec<Claim>), ParseError> {
    let name =
        text_at(package, "name").ok_or_else(|| ParseError::new("the package has no `name`"))?;
    let version = text_at(package, "versionInfo").unwrap_or_default();

    // The purl lives in `externalRefs`, and finding it is what makes an SPDX package join with an
    // advisory's package rather than sitting beside it.
    let purl = vuln::array_at(package, "externalRefs")
        .iter()
        .find(|reference| text_at(reference, "referenceType").as_deref() == Some("purl"))
        .and_then(|reference| text_at(reference, "referenceLocator"));

    vuln::package_entity(
        purl.as_deref(),
        "spdx",
        &name,
        &version,
        origin,
        field_limit,
    )
}

/// Licences, checksums, and supplier, as claims on an SPDX package.
fn spdx_detail(
    package: &serde_json::Value,
    package_id: Id<Entity>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let subject = NodeRef::Entity(package_id);
    let mut records = Vec::new();

    for (field, name) in [
        ("licenseConcluded", "package.license_concluded"),
        ("licenseDeclared", "package.license_declared"),
        ("supplier", "package.supplier"),
        ("originator", "package.originator"),
        ("downloadLocation", "package.download_location"),
        ("SPDXID", "package.spdx_id"),
    ] {
        if let Some(text) = text_at(package, field) {
            // `NOASSERTION` is SPDX's explicit "we are not saying". Recording it as a licence would
            // turn a refusal to answer into an answer.
            if text == "NOASSERTION" || text == "NONE" {
                continue;
            }
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    for checksum in vuln::array_at(package, "checksums") {
        if let (Some(algorithm), Some(value)) = (
            text_at(checksum, "algorithm"),
            text_at(checksum, "checksumValue"),
        ) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(
                    &format!("package.hash.{}", algorithm.to_lowercase()),
                    &value,
                    field_limit,
                )?,
                origin.clone(),
            ))));
        }
    }

    // Every external reference other than the purl, which was used as the key.
    for reference in vuln::array_at(package, "externalRefs") {
        let kind = text_at(reference, "referenceType").unwrap_or_default();
        if kind == "purl" {
            continue;
        }
        if let Some(locator) = text_at(reference, "referenceLocator") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(&format!("package.ref.{kind}"), &locator, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    Ok(records)
}
