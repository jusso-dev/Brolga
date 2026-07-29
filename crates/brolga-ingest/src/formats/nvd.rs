//! NVD JSON — the CVE feed, in both the 2.0 API shape and the retired 1.1 feed shape.
//!
//! # Two shapes, one parser
//!
//! NVD's 1.1 data feeds were retired in 2023 and the 2.0 API replaced them, but 1.1 files are still
//! in circulation: mirrors carry them, air-gapped installations were seeded from them, and tooling
//! that predates the cutover still writes them. One parser reads both, because from an operator's
//! side they are the same intelligence and having to know which vintage a file is would be a
//! Brolga-shaped problem rather than a real one.
//!
//! The shapes are distinguished by their container: `{"vulnerabilities": [{"cve": …}]}` is 2.0,
//! `{"CVE_Items": [{"cve": {"CVE_data_meta": …}}]}` is 1.1. The version read is recorded as a claim,
//! so a record's vintage is answerable from the store.
//!
//! # CPE configurations become the CPE and the range, not a boolean tree
//!
//! NVD expresses applicability as nested `nodes` combining `cpeMatch` entries under `AND`/`OR`, with
//! `vulnerable: true|false` per match and optional `versionStartIncluding`-style bounds. A
//! `vulnerable: false` match is a *running-on* condition — "vulnerable only when installed on this
//! platform" — and it is recorded as such rather than as an affected package, because flattening it
//! would turn a conditional into an unconditional claim.
//!
//! The tree structure itself is not reconstructed. What survives is: each `vulnerable: true` CPE as a
//! package entity with an `Affects` edge, its version bounds as range text, and each
//! `vulnerable: false` CPE as a `vuln.runs_on` attribute on the vulnerability. That is enough to
//! answer "does this flaw concern this product" and deliberately not enough to answer "is this
//! specific install exploitable", which needs the tree and a version comparator.
//!
//! # CVSS
//!
//! Recorded as the vector string and the base score, per metric version, under the scoring system's
//! own name (`cvssMetricV31`, `cvssMetricV2`, …). A bare score with no vector and no version is not
//! comparable to anything, so the version is never dropped.
//!
//! # Not read
//!
//! `vendorComments`, `cveTags`, and `evaluatorSolution` are named as unread rather than mined.
//! `configurations` beyond the first-level nodes are summarised as above.

use brolga_model::{Claim, LifecycleStatus, NodeRef, RecordOrigin, ShortText, UntrustedText};

use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{
    self, MAX_AFFECTED, attribute, bounded, text_at, within_byte_limit, within_record_limit,
};
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const NVD_PARSER_ID: ParserId = ParserId::new("brolga.vulnerability.nvd");

/// Media types that identify an NVD feed definitively.
pub const NVD_MEDIA_TYPES: &[&str] = &["application/vnd.nvd+json"];

/// Most CVE items read from one feed file.
///
/// A full NVD year file holds roughly twenty thousand CVEs, so this is set above a realistic year
/// and below the point at which one document would dominate a store.
pub const MAX_ITEMS: usize = 50_000;

/// Deepest `configurations` node nesting walked.
pub const MAX_NODE_DEPTH: usize = 8;

/// Which NVD shape a document is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedShape {
    /// The 2.0 API response: `{"vulnerabilities": [{"cve": …}]}`.
    Api20,
    /// The retired 1.1 data feed: `{"CVE_Items": [...]}`.
    Feed11,
}

impl FeedShape {
    /// A stable label, recorded on every record so a vintage is answerable from the store.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api20 => "2.0",
            Self::Feed11 => "1.1",
        }
    }
}

/// An NVD JSON reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct NvdParser;

impl NvdParser {
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

impl IntelligenceParser for NvdParser {
    fn id(&self) -> ParserId {
        NVD_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if NVD_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is NVD JSON");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // Both container keys are NVD's own and appear in no other format.
        if text.contains("\"CVE_data_meta\"") || text.contains("\"CVE_Items\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the NVD 1.1 feed container",
            )
        } else if text.contains("\"vulnerabilities\"")
            && (text.contains("\"cisaExploitAdd\"")
                || text.contains("\"vulnStatus\"")
                || text.contains("\"sourceIdentifier\""))
        {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the NVD 2.0 API container",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no NVD container in the first bytes",
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

        let (shape, items) = if document.get("CVE_Items").is_some() {
            (FeedShape::Feed11, vuln::array_at(&document, "CVE_Items"))
        } else if document.get("vulnerabilities").is_some() {
            (
                FeedShape::Api20,
                vuln::array_at(&document, "vulnerabilities"),
            )
        } else {
            return Err(ParseError::new(
                "the document declares neither `vulnerabilities` (NVD 2.0) nor `CVE_Items` (1.1)",
            ));
        };

        if items.len() > MAX_ITEMS {
            return Err(ParseError::new(format!(
                "the feed holds {} CVE items, over the {MAX_ITEMS} limit",
                items.len()
            )));
        }

        let mut out = ParseOutput::default();
        for (index, item) in items.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            // Both shapes wrap the CVE in a `cve` object; 2.0 puts the identifier at `cve.id`, 1.1
            // at `cve.CVE_data_meta.ID`.
            let Some(cve) = item.get("cve") else {
                out.rejected.push(RejectedRecord {
                    reason_kind: "missing_cve_object",
                    reason: "the item carries no `cve` object, so it describes no vulnerability"
                        .to_owned(),
                    offset: u64::try_from(index).ok(),
                    fragment: None,
                });
                continue;
            };

            match map_cve(cve, shape, &origin, field_limit) {
                Ok((mut records, notes)) => {
                    out.records.append(&mut records);
                    out.notes.extend(notes);
                }
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_cve_item",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: identifier_of(cve, shape),
                }),
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the feed holds no CVE item at all"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// The CVE identifier, from whichever place this shape keeps it.
fn identifier_of(cve: &serde_json::Value, shape: FeedShape) -> Option<String> {
    match shape {
        FeedShape::Api20 => text_at(cve, "id"),
        FeedShape::Feed11 => cve
            .get("CVE_data_meta")
            .and_then(|meta| text_at(meta, "ID")),
    }
}

/// The English description, from whichever place this shape keeps it.
fn description_of(cve: &serde_json::Value, shape: FeedShape) -> Option<String> {
    let list = match shape {
        FeedShape::Api20 => vuln::array_at(cve, "descriptions"),
        FeedShape::Feed11 => cve
            .get("description")
            .map(|d| vuln::array_at(d, "description_data"))
            .unwrap_or_default(),
    };
    // English first, then whatever is there: a Japanese-only description is better than none, and
    // the language is not asserted to be English by recording it.
    list.iter()
        .find(|entry| text_at(entry, "lang").as_deref() == Some("en"))
        .or_else(|| list.first())
        .and_then(|entry| text_at(entry, "value"))
}

/// Map one CVE item.
fn map_cve(
    cve: &serde_json::Value,
    shape: FeedShape,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Vec<ParsedRecord>, Vec<ShortText>), ParseError> {
    let identifier = identifier_of(cve, shape)
        .ok_or_else(|| ParseError::new("the item names no CVE identifier"))?;
    let identity = vuln::vulnerability_id(&identifier, &[])
        .ok_or_else(|| ParseError::new("the item's CVE identifier is empty"))?;

    let description = description_of(cve, shape);
    let (mut vulnerability, claims) =
        vuln::vulnerability_entity(&identity, description.as_deref(), origin, field_limit)?;

    // `Rejected` is NVD's own withdrawal state: the identifier was assigned and then found not to
    // be a vulnerability. Recording it as revoked keeps the fact that it was once published.
    let status = text_at(cve, "vulnStatus");
    if status.as_deref() == Some("Rejected")
        || description
            .as_deref()
            .is_some_and(|text| text.starts_with("** REJECT **"))
    {
        vulnerability.status = LifecycleStatus::Revoked;
    }
    if let Some(details) = description.as_deref()
        && vulnerability.description.is_none()
        && let Ok(text) = UntrustedText::new(bounded(details, field_limit))
    {
        vulnerability.description = Some(text);
    }

    let vulnerability_id = vulnerability.id;
    let subject = NodeRef::Entity(vulnerability_id);
    let mut records: Vec<ParsedRecord> = Vec::new();
    let notes: Vec<ShortText> = Vec::new();

    for claim in claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }
    records.push(ParsedRecord::Claim(Box::new(Claim::new(
        subject,
        attribute("nvd.shape", shape.as_str(), field_limit)?,
        origin.clone(),
    ))));

    for (field, name) in [
        ("published", "vuln.published"),
        ("lastModified", "vuln.modified"),
        ("vulnStatus", "nvd.status"),
        ("sourceIdentifier", "nvd.source"),
        // 1.1 spelling.
        ("publishedDate", "vuln.published"),
        ("lastModifiedDate", "vuln.modified"),
    ] {
        if let Some(text) = text_at(cve, field) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // CISA's KEV flag appears inside NVD 2.0 records as well as in the standalone catalogue. It is
    // recorded with the date CISA added it, never as a disposition — see `kev.rs` for why.
    if let Some(added) = text_at(cve, "cisaExploitAdd") {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("kev.date_added", &added, field_limit)?,
            origin.clone(),
        ))));
    }

    records.extend(weaknesses(cve, shape, subject, origin, field_limit)?);
    records.extend(metrics(cve, subject, origin, field_limit)?);
    records.extend(references(
        cve,
        shape,
        vulnerability_id,
        origin,
        field_limit,
    )?);

    for unread in ["vendorComments", "cveTags", "evaluatorSolution"] {
        if cve.get(unread).is_some() {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("nvd.unread_field", unread, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    records.extend(configurations(
        cve,
        shape,
        vulnerability_id,
        &identity.canonical,
        origin,
        field_limit,
    )?);

    records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    Ok((records, notes))
}

/// CWE identifiers, canonicalised.
fn weaknesses(
    cve: &serde_json::Value,
    shape: FeedShape,
    subject: NodeRef,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let list = match shape {
        FeedShape::Api20 => vuln::array_at(cve, "weaknesses").to_vec(),
        FeedShape::Feed11 => cve
            .get("problemtype")
            .map(|p| vuln::array_at(p, "problemtype_data").to_vec())
            .unwrap_or_default(),
    };

    let mut records = Vec::new();
    for entry in &list {
        for description in vuln::array_at(entry, "description") {
            let Some(value) = text_at(description, "value") else {
                continue;
            };
            // `NVD-CWE-noinfo` and `NVD-CWE-Other` are NVD's placeholders for "we did not classify
            // this". They are not weaknesses, and recording them as `vuln.cwe` would put two
            // enormous non-weaknesses at the top of any weakness histogram.
            if let Ok(cwe) = canon::ident::cwe(&value) {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute("vuln.cwe", cwe.value(), field_limit)?,
                    origin.clone(),
                ))));
            } else {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute("nvd.unclassified_weakness", &value, field_limit)?,
                    origin.clone(),
                ))));
            }
        }
    }
    Ok(records)
}

/// CVSS vectors and base scores, per scoring system.
fn metrics(
    cve: &serde_json::Value,
    subject: NodeRef,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let Some(metrics) = cve.get("metrics").or_else(|| cve.get("impact")) else {
        return Ok(Vec::new());
    };
    let Some(object) = metrics.as_object() else {
        return Ok(Vec::new());
    };

    let mut records = Vec::new();
    for (system, entries) in object {
        // 2.0 gives an array per system; 1.1 gives a single object. Both are walked as a list.
        let list: Vec<&serde_json::Value> = entries
            .as_array()
            .map(|array| array.iter().collect())
            .unwrap_or_else(|| vec![entries]);

        for entry in list {
            let data = entry.get("cvssData").unwrap_or(entry);
            if let Some(vector) = text_at(data, "vectorString") {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(&format!("vuln.cvss.{system}.vector"), &vector, field_limit)?,
                    origin.clone(),
                ))));
            }
            // A base score is only meaningful next to the system that produced it, which is why the
            // attribute name carries the system rather than the score standing alone.
            if let Some(score) = data.get("baseScore").and_then(serde_json::Value::as_f64) {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(
                        &format!("vuln.cvss.{system}.base_score"),
                        &format!("{score}"),
                        field_limit,
                    )?,
                    origin.clone(),
                ))));
            }
            if let Some(severity) = text_at(data, "baseSeverity") {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(
                        &format!("vuln.cvss.{system}.base_severity"),
                        &severity,
                        field_limit,
                    )?,
                    origin.clone(),
                ))));
            }
        }
    }
    Ok(records)
}

/// Reference URLs, capped by the shared helper.
fn references(
    cve: &serde_json::Value,
    shape: FeedShape,
    vulnerability_id: brolga_model::Id<brolga_model::Entity>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let list = match shape {
        FeedShape::Api20 => vuln::array_at(cve, "references").to_vec(),
        FeedShape::Feed11 => cve
            .get("references")
            .map(|r| vuln::array_at(r, "reference_data").to_vec())
            .unwrap_or_default(),
    };
    let urls: Vec<String> = list
        .iter()
        .filter_map(|entry| text_at(entry, "url"))
        .collect();
    let (claims, _) = vuln::reference_claims(vulnerability_id, &urls, origin, field_limit)?;
    Ok(claims
        .into_iter()
        .map(|claim| ParsedRecord::Claim(Box::new(claim)))
        .collect())
}

/// Walk `configurations`, minting a package per `vulnerable: true` CPE.
fn configurations(
    cve: &serde_json::Value,
    shape: FeedShape,
    vulnerability_id: brolga_model::Id<brolga_model::Entity>,
    vulnerability_name: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    // 2.0: `cve.configurations[].nodes[]`. 1.1: `cve.configurations.nodes[]`.
    let configurations = match shape {
        FeedShape::Api20 => vuln::array_at(cve, "configurations").to_vec(),
        FeedShape::Feed11 => cve
            .get("configurations")
            .map(|value| vec![value.clone()])
            .unwrap_or_default(),
    };

    let mut matches: Vec<&serde_json::Value> = Vec::new();
    let mut owned: Vec<serde_json::Value> = Vec::new();
    for configuration in &configurations {
        collect_matches(configuration, 0, &mut owned);
    }
    matches.extend(owned.iter());

    if matches.len() > MAX_AFFECTED {
        return Err(ParseError::new(format!(
            "the item names {} CPE matches, over the {MAX_AFFECTED} limit",
            matches.len()
        )));
    }

    let mut records = Vec::new();
    for entry in matches {
        let Some(criteria) = text_at(entry, "criteria").or_else(|| text_at(entry, "cpe23Uri"))
        else {
            continue;
        };
        let Ok(cpe) = canon::ident::cpe(&criteria) else {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                NodeRef::Entity(vulnerability_id),
                attribute("nvd.unusable_cpe", &criteria, field_limit)?,
                origin.clone(),
            ))));
            continue;
        };
        let cpe = cpe.into_value();

        // A `vulnerable: false` match is a platform condition, not an affected product. Recording it
        // as one would turn "vulnerable only when running on Windows" into "Windows is vulnerable".
        let vulnerable = entry
            .get("vulnerable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !vulnerable {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                NodeRef::Entity(vulnerability_id),
                attribute("vuln.runs_on", &cpe, field_limit)?,
                origin.clone(),
            ))));
            continue;
        }

        // The CPE's own product and version fields are the package's name and version. Split on the
        // unescaped colons of the 2.3 formatted string: part 4 is product, part 5 is version.
        let components: Vec<&str> = cpe.split(':').collect();
        let vendor = components.get(3).copied().unwrap_or("*");
        let product = components.get(4).copied().unwrap_or("*");
        let version = components.get(5).copied().unwrap_or("*");
        // `*` is CPE's wildcard, meaning "any version". Stored as an empty version so the package is
        // the unversioned product, matching how OSV names one.
        let version = if version == "*" || version == "-" {
            ""
        } else {
            version
        };

        let (package, package_claims) = vuln::package_entity(
            None,
            "cpe",
            &format!("{vendor}:{product}"),
            version,
            origin,
            field_limit,
        )?;
        let package_id = package.id;
        for claim in package_claims {
            records.push(ParsedRecord::Claim(Box::new(claim)));
        }
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            NodeRef::Entity(package_id),
            attribute("package.cpe", &cpe, field_limit)?,
            origin.clone(),
        ))));

        // The version bounds NVD states next to the CPE, as text. See the module documentation for
        // why they are not turned into comparisons.
        let bounds: Vec<String> = [
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        ]
        .iter()
        .filter_map(|field| text_at(entry, field).map(|value| format!("{field} {value}")))
        .collect();
        if !bounds.is_empty() {
            records.push(ParsedRecord::Claim(Box::new(vuln::affected_range(
                package_id,
                vulnerability_name,
                &format!("CPE: {}", bounds.join(", ")),
                origin,
                field_limit,
            )?)));
        }

        records.push(ParsedRecord::Relationship(Box::new(vuln::affects(
            vulnerability_id,
            package_id,
            origin,
        ))));
        records.push(ParsedRecord::Entity(Box::new(package)));
    }
    Ok(records)
}

/// Collect every `cpeMatch`/`cpe_match` entry from a nested node tree, bounded by depth.
///
/// The `AND`/`OR` operators are not preserved — see the module documentation. Depth is bounded so a
/// hostile document cannot cause unbounded recursion.
fn collect_matches(node: &serde_json::Value, depth: usize, out: &mut Vec<serde_json::Value>) {
    if depth > MAX_NODE_DEPTH || out.len() > MAX_AFFECTED {
        return;
    }
    for key in ["cpeMatch", "cpe_match"] {
        for entry in vuln::array_at(node, key) {
            out.push(entry.clone());
        }
    }
    for key in ["nodes", "children"] {
        for child in vuln::array_at(node, key) {
            collect_matches(child, depth.saturating_add(1), out);
        }
    }
}
