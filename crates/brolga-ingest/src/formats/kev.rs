//! CISA's Known Exploited Vulnerabilities catalogue.
//!
//! # KEV presence is evidence with a date, never a universal exploit claim
//!
//! This is the one thing [#53](https://github.com/jusso-dev/Brolga/issues/53) states as an explicit
//! acceptance criterion, so it is worth being precise about what the distinction is and why it
//! matters enough to name in an issue.
//!
//! A KEV entry means: **CISA observed reliable evidence of exploitation in the wild, and recorded the
//! date they added it.** It does not mean the flaw is exploitable in every configuration, that every
//! deployment of the affected product is at risk, that exploitation is ongoing now, or that an
//! exploit is publicly available. Those are four different claims, and a store that collapsed KEV
//! membership into "exploited: true" would let a consumer read any of them out of it.
//!
//! So a KEV entry produces:
//!
//! - `kev.date_added` — the date CISA added it. **The load-bearing field.** It is what makes the
//!   claim time-bounded evidence rather than a standing property.
//! - `kev.catalog` — which catalogue said so, so a second exploitation source does not become
//!   indistinguishable from this one.
//! - `kev.due_date`, `kev.required_action`, `kev.ransomware_use`, `kev.notes` — recorded as written.
//!
//! And it deliberately does **not** produce:
//!
//! - A [`brolga_model::Disposition`]. A disposition is Brolga's assessment of whether something is
//!   malicious, and a vulnerability is not malicious — the software has a flaw. Marking a CVE
//!   `malicious` would put a flaw in the same bucket as a command-and-control address.
//! - An `Exploits` relationship. That edge means "this specific thing exploits that specific
//!   thing", and KEV names no exploiting party. Minting one with a fabricated actor on the other end
//!   would invent intelligence.
//! - Any confidence uplift on other claims about the CVE. Exploitation in the wild is evidence about
//!   the flaw's *use*, not about whether some other source's severity score is right.
//!
//! `knownRansomwareCampaignUse` is `"Known"` or `"Unknown"` in CISA's own data, and `"Unknown"` means
//! "we have not established it" rather than "no". It is recorded verbatim for exactly that reason:
//! mapping it to a boolean would turn an absence of evidence into evidence of absence.
//!
//! # The vendor and product are a package, loosely
//!
//! KEV gives `vendorProject` and `product` as free text — `Microsoft` / `Windows`, `Apache` /
//! `Log4j2` — with no version, no purl, and no CPE. That is enough to mint an unversioned package
//! entity and an `Affects` edge, and not enough to align it with the same product named by an SBOM.
//! The mapping is therefore recorded as approximate: `package.ecosystem` is `cisa-kev`, so a
//! consumer can tell a KEV-derived package from a purl-keyed one and not silently join them.

use brolga_model::{Claim, NodeRef, RecordOrigin, ShortText};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{self, attribute, text_at, within_byte_limit, within_record_limit};
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const KEV_PARSER_ID: ParserId = ParserId::new("brolga.vulnerability.cisa_kev");

/// Media types that identify the KEV catalogue definitively.
pub const KEV_MEDIA_TYPES: &[&str] = &["application/vnd.cisa.kev+json"];

/// The catalogue's own name, recorded so a second exploitation source stays distinguishable.
pub const CATALOGUE: &str = "CISA Known Exploited Vulnerabilities";

/// The ecosystem label used for KEV-derived packages.
///
/// Deliberately not a purl type. A KEV vendor and product cannot be aligned with a purl-keyed
/// package without guessing, and a label that looks like a purl type would invite exactly that.
pub const KEV_ECOSYSTEM: &str = "cisa-kev";

/// Most entries read from one catalogue file.
///
/// The catalogue holds roughly 1,200 entries as of this writing and grows by a few per week.
pub const MAX_ENTRIES: usize = 100_000;

/// A KEV catalogue reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct KevParser;

impl KevParser {
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

impl IntelligenceParser for KevParser {
    fn id(&self) -> ParserId {
        KEV_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if KEV_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is the CISA KEV catalogue",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // `catalogVersion` next to `vulnerabilities` is CISA's own envelope and appears in nothing
        // else. `knownRansomwareCampaignUse` is unique to KEV entries.
        if text.contains("\"catalogVersion\"") || text.contains("\"knownRansomwareCampaignUse\"") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the CISA KEV catalogue envelope",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no KEV catalogue marker in the first bytes",
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

        let entries = vuln::array_at(&document, "vulnerabilities");
        if entries.is_empty() {
            return Err(ParseError::new(
                "the catalogue holds no `vulnerabilities` array",
            ));
        }
        if entries.len() > MAX_ENTRIES {
            return Err(ParseError::new(format!(
                "the catalogue holds {} entries, over the {MAX_ENTRIES} limit",
                entries.len()
            )));
        }

        // The catalogue's own release date and version, recorded on every entry as the provenance of
        // the *catalogue snapshot* rather than of the individual observation.
        let released = text_at(&document, "dateReleased");
        let catalogue_version = text_at(&document, "catalogVersion");

        let mut out = ParseOutput::default();
        for (index, entry) in entries.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_entry(
                entry,
                released.as_deref(),
                catalogue_version.as_deref(),
                &origin,
                field_limit,
            ) {
                Ok(mut records) => out.records.append(&mut records),
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_kev_entry",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: text_at(entry, "cveID"),
                }),
            }
        }

        if !out.rejected.is_empty()
            && let Ok(note) = ShortText::new(format!(
                "{} catalogue entries were not mappable",
                out.rejected.len()
            ))
        {
            out.notes.push(note);
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// Map one catalogue entry.
///
/// The date is mandatory here, unlike most optional fields elsewhere: without it the record would
/// assert exploitation with no time bound, which is the claim this module exists to avoid making.
fn map_entry(
    entry: &serde_json::Value,
    released: Option<&str>,
    catalogue_version: Option<&str>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let cve =
        text_at(entry, "cveID").ok_or_else(|| ParseError::new("the entry names no `cveID`"))?;
    let identity = vuln::vulnerability_id(&cve, &[])
        .ok_or_else(|| ParseError::new("the entry's `cveID` is empty"))?;

    let date_added = text_at(entry, "dateAdded").ok_or_else(|| {
        ParseError::new(
            "the entry has no `dateAdded`; KEV membership without the date CISA recorded it would \
             be an unbounded exploitation claim, which this parser refuses to make",
        )
    })?;

    let summary = text_at(entry, "shortDescription");
    let (vulnerability, claims) =
        vuln::vulnerability_entity(&identity, summary.as_deref(), origin, field_limit)?;
    let vulnerability_id = vulnerability.id;
    let subject = NodeRef::Entity(vulnerability_id);

    let mut records: Vec<ParsedRecord> = Vec::new();
    for claim in claims {
        records.push(ParsedRecord::Claim(Box::new(claim)));
    }

    // The evidence, with its date. Not a disposition, not an `Exploits` edge — see the module
    // documentation for what each of those would wrongly assert.
    records.push(ParsedRecord::Claim(Box::new(Claim::new(
        subject,
        attribute("kev.date_added", &date_added, field_limit)?,
        origin.clone(),
    ))));
    records.push(ParsedRecord::Claim(Box::new(Claim::new(
        subject,
        attribute("kev.catalog", CATALOGUE, field_limit)?,
        origin.clone(),
    ))));

    for (field, name) in [
        ("vulnerabilityName", "kev.name"),
        ("dueDate", "kev.due_date"),
        ("requiredAction", "kev.required_action"),
        // Verbatim: `"Unknown"` means "not established", not "no".
        ("knownRansomwareCampaignUse", "kev.ransomware_use"),
        ("notes", "kev.notes"),
        ("cwes", "kev.cwes"),
    ] {
        if let Some(text) = text_at(entry, field) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }
    if let Some(released) = released {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("kev.catalog_released", released, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(version) = catalogue_version {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("kev.catalog_version", version, field_limit)?,
            origin.clone(),
        ))));
    }

    // The vendor and product, as an approximate package. See the module documentation for why the
    // ecosystem label is deliberately not a purl type.
    let vendor = text_at(entry, "vendorProject").unwrap_or_default();
    let product = text_at(entry, "product").unwrap_or_default();
    if !product.is_empty() {
        let name = if vendor.is_empty() {
            product.clone()
        } else {
            format!("{vendor} {product}")
        };
        let (package, package_claims) =
            vuln::package_entity(None, KEV_ECOSYSTEM, &name, "", origin, field_limit)?;
        let package_id = package.id;
        for claim in package_claims {
            records.push(ParsedRecord::Claim(Box::new(claim)));
        }
        records.push(ParsedRecord::Relationship(Box::new(vuln::affects(
            vulnerability_id,
            package_id,
            origin,
        ))));
        records.push(ParsedRecord::Entity(Box::new(package)));
    }

    records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    Ok(records)
}
