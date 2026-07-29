//! SARIF — static analysis results.
//!
//! # A SARIF result is a finding about *your* code, which is a different kind of thing
//!
//! Every other format in this milestone describes something in the world: a published flaw, a
//! catalogued exploit, an inventory of shipped software. A SARIF result describes an *analysis of a
//! specific codebase at a specific commit* — "this scanner, at this version, flagged line 42 of
//! `src/auth.rs` under rule `RUSTSEC-2021-0001`".
//!
//! That has two consequences for the mapping.
//!
//! **A rule is a detection, not a vulnerability.** `tool.driver.rules[]` describes what the scanner
//! looks for, which is exactly [`EntityKind::DetectionRule`] — the same kind a Sigma or YARA rule
//! becomes. A rule that carries a CVE or GHSA identifier in its `id` or `relationships` additionally
//! gets a [`EntityKind::Vulnerability`] entity and an `Indicates` edge, so a dependency-scanner SARIF
//! joins with the advisory data the other parsers in this milestone import. A rule with no such
//! identifier — a lint, a taint-analysis rule — stays a detection rule and mints no vulnerability,
//! because "the linter does not like this" is not a published flaw.
//!
//! **A result location is a file path, not an observable of the internet.** `src/auth.rs:42` becomes an
//! [`Observable::FilePath`]. It is deliberately *not* canonicalised as anything else: a SARIF URI can
//! be `file:///`, a relative path, or a `%`-escaped URI with a `uriBaseId` that resolves against a
//! base the document may not carry. Turning those into a URL observable would put source paths in the
//! same namespace as network locations.
//!
//! # `suppressions` and `baselineState` are read, and they matter
//!
//! A suppressed result is one somebody looked at and dismissed. A store that dropped suppressions
//! would report a triaged codebase as untriaged; one that ignored them would report dismissed findings
//! as live. Both are recorded: `sarif.suppressed` with the justification, and `sarif.baseline_state`
//! (`new`, `unchanged`, `updated`, `absent`), so "what is new since last run" survives the import.
//!
//! # What is not read
//!
//! - `codeFlows`, `graphs`, `stacks`, and `fixes` — the structured explanation of *how* a finding
//!   arises. It is the most valuable part of a SARIF file for a developer and the least
//!   representable in this model, which has no notion of a program path. Named as unread.
//! - `artifacts[].contents` — embedded source text. Deliberately not imported: it would put a copy of
//!   a customer's source into an intelligence store, which is a data-handling decision nobody made.
//! - `invocations[].commandLine` — the exact command run, which routinely carries tokens and internal
//!   paths. Named as unread for the same reason.
//! - `results[].relatedLocations` beyond the primary location.

use brolga_model::{
    Claim, Entity, EntityKind, Id, NodeRef, Observable, RecordOrigin, Relationship,
    RelationshipKind, ShortText, UntrustedText,
};

use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::formats::vuln::{
    self, MAX_RESULTS, attribute, bounded, text_at, within_byte_limit, within_record_limit,
};
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const SARIF_PARSER_ID: ParserId = ParserId::new("brolga.analysis.sarif");

/// Media types that identify SARIF definitively.
pub const SARIF_MEDIA_TYPES: &[&str] = &["application/sarif+json"];

/// Most runs read from one SARIF log.
pub const MAX_RUNS: usize = 64;

/// Most rules read from one run's tool driver.
pub const MAX_RULES: usize = 20_000;

/// A SARIF reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct SarifParser;

impl SarifParser {
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

impl IntelligenceParser for SarifParser {
    fn id(&self) -> ParserId {
        SARIF_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if SARIF_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is SARIF");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        // Either the `$schema` pointing at the SARIF schema, or `version` next to `runs`. Both are
        // required by the specification.
        if text.contains("sarif-schema")
            || (text.contains("\"runs\"") && text.contains("\"version\""))
        {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the SARIF schema or a versioned `runs` array",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no SARIF marker in the first bytes",
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

        let runs = vuln::array_at(&document, "runs");
        if runs.is_empty() {
            return Err(ParseError::new("the log holds no `runs` array"));
        }
        if runs.len() > MAX_RUNS {
            return Err(ParseError::new(format!(
                "the log holds {} runs, over the {MAX_RUNS} limit",
                runs.len()
            )));
        }

        let mut out = ParseOutput::default();
        for (index, run) in runs.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_run(run, &origin, field_limit) {
                Ok((mut records, notes)) => {
                    out.records.append(&mut records);
                    out.notes.extend(notes);
                }
                Err(error) => out.rejected.push(RejectedRecord {
                    reason_kind: "unmappable_sarif_run",
                    reason: error.to_string(),
                    offset: u64::try_from(index).ok(),
                    fragment: tool_name(run),
                }),
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new("the log produced no records"));
        }
        within_record_limit(out.records.len(), limits.max_records)?;
        Ok(out)
    }
}

/// The analysing tool's name, from `tool.driver.name`.
fn tool_name(run: &serde_json::Value) -> Option<String> {
    run.get("tool")
        .and_then(|tool| tool.get("driver"))
        .and_then(|driver| text_at(driver, "name"))
}

/// Map one run: its rules, then its results.
fn map_run(
    run: &serde_json::Value,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Vec<ParsedRecord>, Vec<ShortText>), ParseError> {
    let tool = tool_name(run).ok_or_else(|| {
        ParseError::new(
            "the run names no analysing tool, and a finding with no tool behind it cites nothing",
        )
    })?;
    let tool_version = run
        .get("tool")
        .and_then(|value| value.get("driver"))
        .and_then(|driver| text_at(driver, "version"));

    let driver_rules = run
        .get("tool")
        .and_then(|tool| tool.get("driver"))
        .map(|driver| vuln::array_at(driver, "rules"))
        .unwrap_or_default();
    if driver_rules.len() > MAX_RULES {
        return Err(ParseError::new(format!(
            "the run declares {} rules, over the {MAX_RULES} limit",
            driver_rules.len()
        )));
    }

    let mut records: Vec<ParsedRecord> = Vec::new();
    let mut notes: Vec<ShortText> = Vec::new();
    // Rule identifier to entity identifier, so a result can point at the rule that produced it
    // without re-deriving anything.
    let mut rules: std::collections::BTreeMap<String, Id<Entity>> =
        std::collections::BTreeMap::new();

    for rule in driver_rules {
        let Some(rule_id) = text_at(rule, "id") else {
            continue;
        };
        let (entity, mut rule_records) = map_rule(
            rule,
            &rule_id,
            &tool,
            tool_version.as_deref(),
            origin,
            field_limit,
        )?;
        rules.insert(rule_id, entity.id);
        records.append(&mut rule_records);
        records.push(ParsedRecord::Entity(Box::new(entity)));
    }

    let results = vuln::array_at(run, "results");
    if results.len() > MAX_RESULTS {
        return Err(ParseError::new(format!(
            "the run holds {} results, over the {MAX_RESULTS} limit",
            results.len()
        )));
    }

    for result in results {
        records.extend(map_result(result, &rules, &tool, origin, field_limit)?);
    }

    for unread in ["graphs", "invocations", "artifacts"] {
        if run.get(unread).is_some()
            && let Ok(note) = ShortText::new(format!("`{unread}` was not read"))
        {
            notes.push(note);
        }
    }

    Ok((records, notes))
}

/// Map one rule: a detection rule, plus a vulnerability entity where the rule names a published flaw.
fn map_rule(
    rule: &serde_json::Value,
    rule_id: &str,
    tool: &str,
    tool_version: Option<&str>,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<(Entity, Vec<ParsedRecord>), ParseError> {
    let name = text_at(rule, "name").unwrap_or_else(|| rule_id.to_owned());
    let display = UntrustedText::new(bounded(&format!("{tool}: {name}"), field_limit))
        .map_err(|error| ParseError::new(format!("unusable rule name: {error}")))?;

    // Keyed on the tool *and* the rule identifier. `CWE-89` from two different scanners are two
    // different rules with different logic, and merging them would attribute one tool's findings to
    // the other's rule.
    let id = Id::derive(&["sarif_rule", &tool.to_lowercase(), rule_id]);
    let mut entity = Entity::new(id, EntityKind::DetectionRule, display, origin.clone());

    let description = rule
        .get("fullDescription")
        .or_else(|| rule.get("shortDescription"))
        .and_then(|value| text_at(value, "text"));
    if let Some(description) = description
        && let Ok(text) = UntrustedText::new(bounded(&description, field_limit))
    {
        entity.description = Some(text);
    }

    let subject = NodeRef::Entity(id);
    let mut records: Vec<ParsedRecord> = vec![
        ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.rule_id", rule_id, field_limit)?,
            origin.clone(),
        ))),
        ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.tool", tool, field_limit)?,
            origin.clone(),
        ))),
    ];
    if let Some(version) = tool_version {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.tool_version", version, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(level) = rule
        .get("defaultConfiguration")
        .and_then(|configuration| text_at(configuration, "level"))
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.default_level", &level, field_limit)?,
            origin.clone(),
        ))));
    }
    if let Some(help) = text_at(rule, "helpUri") {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.help_uri", &help, field_limit)?,
            origin.clone(),
        ))));
    }
    for tag in rule
        .get("properties")
        .map(|properties| vuln::strings_at(properties, "tags"))
        .unwrap_or_default()
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.tag", &tag, field_limit)?,
            origin.clone(),
        ))));
    }

    // A rule whose identifier *is* a published flaw joins this scan with the advisory data. A rule
    // whose identifier is a lint name does not, and mints no vulnerability — see the module docs.
    if let Some(identity) = published_flaw(rule, rule_id) {
        let (vulnerability, vulnerability_claims) =
            vuln::vulnerability_entity(&identity, None, origin, field_limit)?;
        for claim in vulnerability_claims {
            records.push(ParsedRecord::Claim(Box::new(claim)));
        }
        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The rule's author asserts it finds this flaw. The same edge a Sigma rule gets for the
            // technique it detects.
            RelationshipKind::Indicates,
            subject,
            NodeRef::Entity(vulnerability.id),
            origin.clone(),
        ))));
        records.push(ParsedRecord::Entity(Box::new(vulnerability)));
    }

    Ok((entity, records))
}

/// Whether a rule names a published flaw, and under what identity.
///
/// A rule identifier is a published flaw when it canonicalises as a CVE, or when it carries an
/// advisory-family prefix. Everything else — `no-unused-vars`, `CA2000`, `S1234` — is a lint.
fn published_flaw(rule: &serde_json::Value, rule_id: &str) -> Option<vuln::VulnerabilityIdentity> {
    // A scanner may state the flaw in `properties` even when its rule identifier is its own. Both
    // `cve` and the common `security-severity`-adjacent conventions are checked.
    let mut candidates: Vec<String> = vec![rule_id.to_owned()];
    if let Some(properties) = rule.get("properties") {
        candidates.extend(vuln::strings_at(properties, "cve"));
        candidates.extend(vuln::strings_at(properties, "aliases"));
        if let Some(cve) = text_at(properties, "cve") {
            candidates.push(cve);
        }
    }

    let recognised: Vec<String> = candidates
        .into_iter()
        .filter(|value| {
            let upper = value.to_ascii_uppercase();
            crate::canon::ident::cve(value).is_ok()
                || upper.starts_with("GHSA-")
                || upper.starts_with("RUSTSEC-")
                || upper.starts_with("OSV-")
                || upper.starts_with("PYSEC-")
                || upper.starts_with("GO-")
        })
        .collect();

    let (primary, rest) = recognised.split_first()?;
    vuln::vulnerability_id(primary, rest)
}

/// Map one result: the finding, its location, and its triage state.
fn map_result(
    result: &serde_json::Value,
    rules: &std::collections::BTreeMap<String, Id<Entity>>,
    tool: &str,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, ParseError> {
    let rule_id = text_at(result, "ruleId");
    // A result whose rule was not declared in the driver still has a rule identifier. The entity is
    // derived the same way, so it lands on the declared rule if one appears in a later run.
    let rule_entity = rule_id.as_deref().map(|id| {
        rules
            .get(id)
            .copied()
            .unwrap_or_else(|| Id::derive(&["sarif_rule", &tool.to_lowercase(), id]))
    });

    let Some(rule_entity) = rule_entity else {
        return Ok(Vec::new());
    };
    let subject = NodeRef::Entity(rule_entity);
    let mut records: Vec<ParsedRecord> = Vec::new();

    if let Some(message) = result
        .get("message")
        .and_then(|value| text_at(value, "text"))
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.finding", &message, field_limit)?,
            origin.clone(),
        ))));
    }
    for (field, name) in [
        ("level", "sarif.level"),
        ("kind", "sarif.kind"),
        ("baselineState", "sarif.baseline_state"),
    ] {
        if let Some(text) = text_at(result, field) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute(name, &text, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // A suppressed result is one somebody triaged and dismissed. Recorded, because a store that
    // silently kept it would report dismissed findings as live.
    for suppression in vuln::array_at(result, "suppressions") {
        let kind = text_at(suppression, "kind").unwrap_or_else(|| "unknown".to_owned());
        let justification =
            text_at(suppression, "justification").unwrap_or_else(|| "none stated".to_owned());
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute(
                "sarif.suppressed",
                &format!("{kind}: {justification}"),
                field_limit,
            )?,
            origin.clone(),
        ))));
    }

    // The location. A file path observable, never a URL — see the module documentation.
    for location in vuln::array_at(result, "locations") {
        let Some(uri) = location
            .get("physicalLocation")
            .and_then(|physical| physical.get("artifactLocation"))
            .and_then(|artifact| text_at(artifact, "uri"))
        else {
            continue;
        };
        let line = location
            .get("physicalLocation")
            .and_then(|physical| physical.get("region"))
            .and_then(|region| region.get("startLine"))
            .and_then(serde_json::Value::as_u64);
        let label = match line {
            Some(line) => format!("{uri}:{line}"),
            None => uri.clone(),
        };

        let Ok(path) = ShortText::new(bounded(&label, ShortText::MAX_BYTES)) else {
            continue;
        };
        let observable = Observable::FilePath(path);
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("sarif.location", &label, field_limit)?,
            origin.clone(),
        ))));
        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The rule found something *at* this path. `LocatedAt` is the edge for "this thing is
            // situated there", which is what a finding's location is.
            RelationshipKind::LocatedAt,
            subject,
            NodeRef::Observable(observable.id()),
            origin.clone(),
        ))));
    }

    for unread in ["codeFlows", "stacks", "fixes"] {
        if result.get(unread).is_some() {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                attribute("sarif.unread_field", unread, field_limit)?,
                origin.clone(),
            ))));
        }
    }

    Ok(records)
}
