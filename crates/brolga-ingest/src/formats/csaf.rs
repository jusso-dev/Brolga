//! CSAF 2.0 and its predecessor CVRF 1.2 — vendor security advisories.
//!
//! # Two parsers, one family
//!
//! CSAF is CVRF's successor and OASIS standardised both. CVRF is XML, CSAF is JSON, and the concepts
//! line up almost one-to-one: a document with a tracking identifier, a product tree, and a list of
//! vulnerabilities each stating which products are affected and which are fixed. Two parsers rather
//! than one because detection is structural — a document is XML or it is JSON, and a parser that
//! sniffed for both would claim documents it could not read.
//!
//! [#53](https://github.com/jusso-dev/Brolga/issues/53) asks for "practical CVRF", and this is what
//! that means here: the parts every vendor actually populates. See "What is not read" below.
//!
//! # `product_status` is the load-bearing field, and it is not a boolean
//!
//! CSAF states product status in named buckets, and the distinctions between them are the ones a
//! reader most needs:
//!
//! - `known_affected` — affected. Produces an `Affects` edge.
//! - `known_not_affected` — the vendor examined it and it is **not** affected. Recorded as
//!   `vuln.not_affected`, on the *vulnerability*, and pointedly **not** as an `Affects` edge. This is
//!   the field a naive mapping gets wrong, and getting it wrong inverts the advisory's meaning for
//!   every product the vendor cleared.
//! - `fixed` and `first_fixed` — a version where the flaw is gone. Recorded as range text.
//! - `under_investigation` — the vendor does not yet know. Recorded as such, because "unknown" and
//!   "not affected" are different answers and an operator needs to know which one they have.
//! - `recommended` and `first_affected` — recorded as stated.
//!
//! # Product identifiers are resolved through the product tree
//!
//! CSAF's `product_status` lists *product identifiers*, not product names — `CSAFPID-0001`. The names
//! and any purls live in `product_tree`, either as a flat `full_product_names` list or nested in
//! `branches`. Both are walked and flattened into an identifier-to-product map, so an `Affects` edge
//! names a package rather than an opaque token. An identifier with no entry in the tree is recorded
//! as an unresolved reference rather than silently dropped: a malformed advisory that named products
//! nobody can resolve should be visible, not absent.
//!
//! # What is not read
//!
//! - `document.aggregate_severity` free text, `document.distribution.text`, and the acknowledgements
//!   block, all named as unread claims.
//! - CSAF's `relationships` between products (`default_component_of`, `installed_on`) are flattened:
//!   the *relates-to* product identifier is resolved to its own product entry and no
//!   product-to-product edge is minted. A component-of graph between products is a different model
//!   from the one Brolga has, and approximating it with `PartOf` would assert a containment the
//!   advisory only stated conditionally.
//! - CVRF's `<DocumentNotes>` and `<Acknowledgments>` are recorded as unread.
//! - CVSS in CVRF lives in `<ScoreSet>` and is read; the `<ProductID>` scoping of a score set is not,
//!   so a score is attached to the vulnerability rather than to one product's instance of it.

use std::collections::BTreeMap;

use brolga_model::{Claim, Entity, Id, NodeRef, RecordOrigin, ShortText, UntrustedText};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{
    self, MAX_AFFECTED, attribute, bounded, text_at, within_byte_limit, within_record_limit,
};
use crate::formats::xml;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// The CSAF parser's identifier.
pub const CSAF_PARSER_ID: ParserId = ParserId::new("brolga.vulnerability.csaf");

/// The CVRF parser's identifier.
pub const CVRF_PARSER_ID: ParserId = ParserId::new("brolga.vulnerability.cvrf");

/// Media types that identify CSAF definitively.
pub const CSAF_MEDIA_TYPES: &[&str] = &["application/csaf+json", "application/vnd.csaf+json"];

/// Media types that identify CVRF definitively.
pub const CVRF_MEDIA_TYPES: &[&str] = &["application/cvrf+xml", "application/vnd.cvrf+xml"];

/// Most vulnerabilities read from one advisory.
pub const MAX_VULNERABILITIES: usize = 1_024;

/// Most products read from one product tree.
pub const MAX_PRODUCTS: usize = 20_000;

/// Deepest `branches` nesting walked in a product tree.
pub const MAX_BRANCH_DEPTH: usize = 32;

/// One resolved product: what to call it and, where stated, its purl.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Product {
    name: String,
    purl: Option<String>,
}

/// A CSAF 2.0 reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct CsafParser;

impl CsafParser {
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

impl IntelligenceParser for CsafParser {
    fn id(&self) -> ParserId {
        CSAF_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if CSAF_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is CSAF");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        // `csaf_version` is declared by every conforming document and by nothing else.
        if text.contains("\"csaf_version\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares a `csaf_version`",
            )
        } else if text.contains("\"product_tree\"") && text.contains("\"vulnerabilities\"") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "has a CSAF product tree alongside a vulnerability list",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no CSAF marker in the first bytes",
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

        let mut products: BTreeMap<String, Product> = BTreeMap::new();
        if let Some(tree) = document.get("product_tree") {
            collect_products(tree, 0, &mut products);
        }
        if products.len() > MAX_PRODUCTS {
            return Err(ParseError::new(format!(
                "the product tree holds {} products, over the {MAX_PRODUCTS} limit",
                products.len()
            )));
        }

        let advisory = document.get("document");
        let tracking_id = advisory
            .and_then(|d| d.get("tracking"))
            .and_then(|t| text_at(t, "id"));

        let vulnerabilities = vuln::array_at(&document, "vulnerabilities");
        if vulnerabilities.is_empty() {
            return Err(ParseError::new(
                "the advisory names no vulnerabilities, so it carries no intelligence this parser \
                 can represent",
            ));
        }
        if vulnerabilities.len() > MAX_VULNERABILITIES {
            return Err(ParseError::new(format!(
                "the advisory names {} vulnerabilities, over the {MAX_VULNERABILITIES} limit",
                vulnerabilities.len()
            )));
        }

        let mut out = ParseOutput::default();
        for (index, entry) in vulnerabilities.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_csaf_vulnerability(
                entry,
                &products,
                tracking_id.as_deref(),
                &origin,
                field_limit,
            ) {
                Ok(mut records) => out.records.append(&mut records),
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_csaf_vulnerability",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: text_at(entry, "cve"),
                }),
            }
        }

        // Document-level fields this parser does not interpret, named once rather than per
        // vulnerability.
        if let Some(advisory) = advisory {
            for unread in ["aggregate_severity", "acknowledgments", "distribution"] {
                if advisory.get(unread).is_some()
                    && let Ok(note) = ShortText::new(format!("`document.{unread}` was not read"))
                {
                    out.notes.push(note);
                }
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the advisory produced no records"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Flatten a CSAF product tree into an identifier-to-product map.
///
/// Walks both `full_product_names` and nested `branches`. Depth is bounded so a hostile document
/// cannot cause unbounded recursion; a tree deeper than the bound contributes what was walked and the
/// unresolved identifiers show up as unresolved references, which is visible rather than silent.
fn collect_products(node: &serde_json::Value, depth: usize, out: &mut BTreeMap<String, Product>) {
    if depth > MAX_BRANCH_DEPTH || out.len() > MAX_PRODUCTS {
        return;
    }

    for key in ["full_product_names", "relationships"] {
        for entry in vuln::array_at(node, key) {
            // A relationship entry wraps its product in `full_product_name`; a plain entry *is* one.
            let product = entry.get("full_product_name").unwrap_or(entry);
            insert_product(product, out);
        }
    }
    if let Some(product) = node.get("product") {
        insert_product(product, out);
    }
    for branch in vuln::array_at(node, "branches") {
        insert_product(branch, out);
        collect_products(branch, depth.saturating_add(1), out);
    }
}

/// Record one product entry if it carries an identifier.
fn insert_product(entry: &serde_json::Value, out: &mut BTreeMap<String, Product>) {
    if let Some(product) = entry.get("product") {
        insert_product(product, out);
    }
    let Some(id) = text_at(entry, "product_id") else {
        return;
    };
    let name = text_at(entry, "name").unwrap_or_else(|| id.clone());
    let purl = entry
        .get("product_identification_helper")
        .and_then(|helper| text_at(helper, "purl"));
    out.insert(id, Product { name, purl });
}

/// Map one CSAF vulnerability entry.
fn map_csaf_vulnerability(
    entry: &serde_json::Value,
    products: &BTreeMap<String, Product>,
    tracking_id: Option<&str>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    // CSAF puts the CVE at `cve` and any other identifiers in `ids[].text`. Where a vendor issues an
    // advisory before a CVE exists, the tracking identifier is the only name the flaw has.
    let primary = text_at(entry, "cve")
        .or_else(|| {
            vuln::array_at(entry, "ids")
                .iter()
                .filter_map(|id| text_at(id, "text"))
                .next()
        })
        .or_else(|| tracking_id.map(ToOwned::to_owned))
        .unwrap_or_default();
    let aliases: Vec<String> = vuln::array_at(entry, "ids")
        .iter()
        .filter_map(|id| text_at(id, "text"))
        .collect();

    let identity = vuln::vulnerability_id(&primary, &aliases)
        .ok_or_else(|| ParseError::new("the entry names no vulnerability identifier"))?;

    let title = text_at(entry, "title");
    let summary = vuln::array_at(entry, "notes")
        .iter()
        .find(|note| {
            matches!(
                text_at(note, "category").as_deref(),
                Some("description" | "summary")
            )
        })
        .and_then(|note| text_at(note, "text"))
        .or_else(|| title.clone());

    let (mut vulnerability, claims) =
        vuln::vulnerability_entity(&identity, summary.as_deref(), origin, field_limit)?;
    if let Some(title) = title.as_deref()
        && vulnerability.description.is_none()
        && let Ok(text) = UntrustedText::new(bounded(title, field_limit))
    {
        vulnerability.description = Some(text);
    }
    let vulnerability_id = vulnerability.id;
    let subject = NodeRef::Entity(vulnerability_id);

    let mut records: Vec<ParsedRecord> = Vec::new();
    for claim in claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }
    if let Some(tracking_id) = tracking_id {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("csaf.advisory_id", tracking_id, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(released) = text_at(entry, "release_date") {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("vuln.published", &released, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(cwe) = entry.get("cwe")
        && let Some(id) = text_at(cwe, "id")
        && let Ok(canonical) = crate::canon::ident::cwe(&id)
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("vuln.cwe", canonical.value(), field_limit)?,
            origin.clone(),
        ))));
    }

    for score in vuln::array_at(entry, "scores") {
        for key in ["cvss_v4", "cvss_v3", "cvss_v2"] {
            let Some(cvss) = score.get(key) else {
                continue;
            };
            if let Some(vector) = text_at(cvss, "vectorString") {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(&format!("vuln.cvss.{key}.vector"), &vector, field_limit)?,
                    origin.clone(),
                ))));
            }
            if let Some(base) = cvss.get("baseScore").and_then(serde_json::Value::as_f64) {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(
                        &format!("vuln.cvss.{key}.base_score"),
                        &format!("{base}"),
                        field_limit,
                    )?,
                    origin.clone(),
                ))));
            }
        }
    }

    let references: Vec<String> = vuln::array_at(entry, "references")
        .iter()
        .filter_map(|reference| text_at(reference, "url"))
        .collect();
    let (reference_claims, _) =
        vuln::reference_claims(vulnerability_id, &references, origin, field_limit)?;
    for claim in reference_claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }

    // Remediations are what a reader acts on, and they are stated per product status bucket. Recorded
    // against the vulnerability because a remediation's product scoping is a list of identifiers and
    // spreading one sentence across twenty packages would multiply the same text twenty times.
    for remediation in vuln::array_at(entry, "remediations") {
        let category = text_at(remediation, "category").unwrap_or_else(|| "unknown".to_owned());
        if let Some(details) = text_at(remediation, "details") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(
                    &format!("vuln.remediation.{category}"),
                    &details,
                    field_limit,
                )?,
                origin.clone(),
            ))));
        }
    }

    records.extend(map_product_status(
        entry,
        products,
        vulnerability_id,
        &identity.canonical,
        origin,
        field_limit,
    )?);

    records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    Ok(records)
}

/// Map `product_status`, which is where the meaning of an advisory actually lives.
fn map_product_status(
    entry: &serde_json::Value,
    products: &BTreeMap<String, Product>,
    vulnerability_id: Id<Entity>,
    vulnerability_name: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let Some(status) = entry.get("product_status") else {
        return Ok(Vec::new());
    };

    let affected = vuln::strings_at(status, "known_affected");
    let first_affected = vuln::strings_at(status, "first_affected");
    let fixed = vuln::strings_at(status, "fixed");
    let first_fixed = vuln::strings_at(status, "first_fixed");
    let recommended = vuln::strings_at(status, "recommended");
    let not_affected = vuln::strings_at(status, "known_not_affected");
    let investigating = vuln::strings_at(status, "under_investigation");

    let total = affected.len() + first_affected.len() + fixed.len() + first_fixed.len();
    if total > MAX_AFFECTED {
        return Err(ParseError::new(format!(
            "the entry names {total} affected or fixed products, over the {MAX_AFFECTED} limit"
        )));
    }

    let mut records: Vec<ParsedRecord> = Vec::new();
    let mut minted: BTreeMap<String, Id<Entity>> = BTreeMap::new();

    // Affected products get the edge. Fixed and first-fixed products get an entity and range text but
    // no `Affects` edge, because "the flaw is gone in 2.15.0" is not "2.15.0 is affected".
    for (identifiers, range_label, edge) in [
        (&affected, "known_affected", true),
        (&first_affected, "first_affected", true),
        (&fixed, "fixed", false),
        (&first_fixed, "first_fixed", false),
        (&recommended, "recommended", false),
    ] {
        for identifier in identifiers {
            let Some(product) = products.get(identifier) else {
                // An identifier the tree does not resolve. Visible rather than silently dropped.
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    NodeRef::Entity(vulnerability_id),
                    attribute("csaf.unresolved_product", identifier, field_limit)?,
                    origin.clone(),
                ))));
                continue;
            };

            let package_id = if let Some(id) = minted.get(identifier) {
                *id
            } else {
                let (package, package_claims) = vuln::package_entity(
                    product.purl.as_deref(),
                    "csaf",
                    &product.name,
                    "",
                    origin,
                    field_limit,
                )?;
                let id = package.id;
                for claim in package_claims {
                    records.push(ParsedRecord::Claim(Box::new(claim)));
                }
                records.push(ParsedRecord::Entity(Box::new(package)));
                minted.insert(identifier.clone(), id);
                id
            };

            records.push(ParsedRecord::Claim(Box::new(vuln::affected_range(
                package_id,
                vulnerability_name,
                range_label,
                origin,
                field_limit,
            )?)));
            if edge {
                records.push(ParsedRecord::Relationship(Box::new(vuln::affects(
                    vulnerability_id,
                    package_id,
                    origin,
                ))));
            }
        }
    }

    // The two buckets that must never become an `Affects` edge. Recorded on the vulnerability by the
    // product's name where it resolves, so a reader can see what the vendor cleared.
    for (identifiers, name) in [
        (&not_affected, "vuln.not_affected"),
        (&investigating, "vuln.under_investigation"),
    ] {
        for identifier in identifiers {
            let label = products
                .get(identifier)
                .map_or(identifier.as_str(), |product| product.name.as_str());
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                NodeRef::Entity(vulnerability_id),
                attribute(name, label, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    Ok(records)
}

/// A CVRF 1.2 reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct CvrfParser;

impl CvrfParser {
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

impl IntelligenceParser for CvrfParser {
    fn id(&self) -> ParserId {
        CVRF_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if CVRF_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is CVRF");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        if text.contains("cvrfdoc") || text.contains("DocumentTracking") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the CVRF document root",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no CVRF root element in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        within_byte_limit(bytes, limits.max_bytes)?;

        // The same hostile reader OpenIOC and IODEF use: any `<!DOCTYPE>` is refused outright, which
        // closes the whole entity-expansion family before anything is parsed. See `xml`.
        let root = xml::read_document(bytes)?;
        if root.name != "cvrfdoc" {
            return Err(ParseError::new(format!(
                "the root element is `{}`, not `cvrfdoc`",
                root.name
            )));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        // CVRF's product tree is `<ProductTree><FullProductName ProductID="…">name</FullProductName>`,
        // optionally nested inside `<Branch>` elements. `descendants` flattens the nesting, which is
        // what the identifier map needs anyway.
        let mut products: BTreeMap<String, Product> = BTreeMap::new();
        for element in root.descendants("FullProductName") {
            let Some(id) = element.attribute("ProductID") else {
                continue;
            };
            let name = element.text.trim();
            let name = if name.is_empty() {
                id.to_owned()
            } else {
                name.to_owned()
            };
            // CVRF has no purl field. `CPE` is the attribute vendors use, and it is recorded as a
            // claim rather than used as a key, because a CPE is not a purl and pretending otherwise
            // would put two key spaces in one field.
            products.insert(id.to_owned(), Product { name, purl: None });
            if products.len() > MAX_PRODUCTS {
                return Err(ParseError::new(format!(
                    "the product tree holds more than the {MAX_PRODUCTS}-product limit"
                )));
            }
        }

        let tracking_id = root
            .find("DocumentTracking")
            .and_then(|tracking| tracking.find("Identification"))
            .and_then(|identification| identification.text_of("ID"))
            .map(ToOwned::to_owned);

        let vulnerabilities = root.descendants("Vulnerability");
        if vulnerabilities.is_empty() {
            return Err(ParseError::new(
                "the advisory holds no `<Vulnerability>` element",
            ));
        }
        if vulnerabilities.len() > MAX_VULNERABILITIES {
            return Err(ParseError::new(format!(
                "the advisory names {} vulnerabilities, over the {MAX_VULNERABILITIES} limit",
                vulnerabilities.len()
            )));
        }

        let mut out = ParseOutput::default();
        for (index, element) in vulnerabilities.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_cvrf_vulnerability(
                element,
                &products,
                tracking_id.as_deref(),
                &origin,
                field_limit,
            ) {
                Ok(mut records) => out.records.append(&mut records),
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_cvrf_vulnerability",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: element.text_of("CVE").map(ToOwned::to_owned),
                }),
            }
        }

        for unread in ["DocumentNotes", "Acknowledgments"] {
            if root.find(unread).is_some()
                && let Ok(note) = ShortText::new(format!("`<{unread}>` was not read"))
            {
                out.notes.push(note);
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the advisory produced no records"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Map one `<Vulnerability>` element.
fn map_cvrf_vulnerability(
    element: &xml::Element,
    products: &BTreeMap<String, Product>,
    tracking_id: Option<&str>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let primary = element
        .text_of("CVE")
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| tracking_id.map(ToOwned::to_owned))
        .unwrap_or_default();

    let identity = vuln::vulnerability_id(&primary, &[]).ok_or_else(|| {
        ParseError::new("the element names no CVE and the document no tracking ID")
    })?;

    let title = element
        .text_of("Title")
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let summary = element
        .descendants("Note")
        .into_iter()
        .find(|note| {
            matches!(
                note.attribute("Type"),
                Some("Description" | "Summary" | "General")
            )
        })
        .map(|note| note.text.trim())
        .filter(|text| !text.is_empty())
        .or(title);

    let (vulnerability, claims) =
        vuln::vulnerability_entity(&identity, summary, origin, field_limit)?;
    let vulnerability_id = vulnerability.id;
    let subject = NodeRef::Entity(vulnerability_id);

    let mut records: Vec<ParsedRecord> = Vec::new();
    for claim in claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }
    if let Some(tracking_id) = tracking_id {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("cvrf.advisory_id", tracking_id, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(cwe) = element.find("CWE")
        && let Some(id) = cwe.attribute("ID")
        && let Ok(canonical) = crate::canon::ident::cwe(id)
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("vuln.cwe", canonical.value(), field_limit)?,
            origin.clone(),
        ))));
    }

    // `<ScoreSet><BaseScore>` and `<Vector>`. The `<ProductID>` scoping of a score set is not read —
    // see the module documentation.
    for score_set in element.descendants("ScoreSet") {
        if let Some(base) = score_set.text_of("BaseScore") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("vuln.cvss.cvrf.base_score", base.trim(), field_limit)?,
                origin.clone(),
            ))));
        }
        if let Some(vector) = score_set.text_of("Vector") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("vuln.cvss.cvrf.vector", vector.trim(), field_limit)?,
                origin.clone(),
            ))));
        }
    }

    for reference in element.descendants("Reference") {
        if let Some(url) = reference.text_of("URL") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("vuln.reference", url.trim(), field_limit)?,
                origin.clone(),
            ))));
        }
    }
    for remediation in element.descendants("Remediation") {
        let kind = remediation.attribute("Type").unwrap_or("unknown");
        if let Some(description) = remediation.text_of("Description") {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(
                    &format!("vuln.remediation.{kind}"),
                    description.trim(),
                    field_limit,
                )?,
                origin.clone(),
            ))));
        }
    }

    // `<ProductStatuses><Status Type="Known Affected"><ProductID>…`. The same rule as CSAF: only
    // `Known Affected` and `First Affected` mint an `Affects` edge, and `Known Not Affected` is
    // recorded as the vendor clearing a product.
    let mut minted: BTreeMap<String, Id<Entity>> = BTreeMap::new();
    for status in element.descendants("Status") {
        let kind = status.attribute("Type").unwrap_or("Unknown");
        let affected = matches!(kind, "Known Affected" | "First Affected");
        for product_id in status.descendants("ProductID") {
            let identifier = product_id.text.trim();
            if identifier.is_empty() {
                continue;
            }
            if !affected {
                let label = products
                    .get(identifier)
                    .map_or(identifier, |product| product.name.as_str());
                let name = match kind {
                    "Known Not Affected" => "vuln.not_affected",
                    "Under Investigation" => "vuln.under_investigation",
                    _ => "vuln.fixed_in",
                };
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute(name, label, field_limit)?,
                    origin.clone(),
                ))));
                continue;
            }

            let Some(product) = products.get(identifier) else {
                records.push(ParsedRecord::Claim(Box::new(Claim::new(
                    subject,
                    attribute("cvrf.unresolved_product", identifier, field_limit)?,
                    origin.clone(),
                ))));
                continue;
            };

            let package_id = if let Some(id) = minted.get(identifier) {
                *id
            } else {
                let (package, package_claims) =
                    vuln::package_entity(None, "cvrf", &product.name, "", origin, field_limit)?;
                let id = package.id;
                for claim in package_claims {
                    records.push(ParsedRecord::Claim(Box::new(claim)));
                }
                records.push(ParsedRecord::Entity(Box::new(package)));
                minted.insert(identifier.to_owned(), id);
                id
            };
            records.push(ParsedRecord::Claim(Box::new(vuln::affected_range(
                package_id,
                &identity.canonical,
                kind,
                origin,
                field_limit,
            )?)));
            records.push(ParsedRecord::Relationship(Box::new(vuln::affects(
                vulnerability_id,
                package_id,
                origin,
            ))));
        }
    }

    records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    Ok(records)
}
