//! SARIF 2.1.0 — "applicable SARIF", which means it declines when it does not apply.
//!
//! # When a pack is a SARIF result, and when it is not
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) asks for "applicable SARIF", and the
//! applicability is the interesting part. SARIF describes **static analysis findings about a
//! codebase**: a tool, a rule, a result, a location in a file. That is a genuine fit for a pack about
//! a vulnerability or a software package — a CI job can annotate a pull request from it — and a poor
//! fit for a pack about a command-and-control address, which has no location in anybody's source tree.
//!
//! So this exporter reports its applicability rather than always producing something:
//!
//! - A pack whose subject or graph concerns a **vulnerability or a software package** exports as
//!   results with rules, which is what a code-scanning consumer expects.
//! - Any other pack still exports — refusing would leave a caller with nothing — but as a single
//!   `notification` rather than as results, and [`Exported::declared_losses`] says the pack was not
//!   the kind SARIF describes.
//!
//! The alternative, emitting a result with a fabricated file location, is worse than either. A SARIF
//! consumer draws an annotation at that location, and an annotation on a line that has nothing to do
//! with the finding trains people to ignore annotations.
//!
//! # No location is invented
//!
//! Every result here is a `result` with **no `locations` array**, which SARIF permits and which means
//! "this finding is about the run as a whole". A pack knows nothing about the consumer's file tree.
//! Inventing `src/main.rs:1` would be the single most misleading thing this crate could do.
//!
//! # `level` is a mapping, not a score
//!
//! `error` for malicious, `warning` for suspicious, `note` for everything else. A benign or unknown
//! subject is never `error`: a code-scanning consumer configured to fail a build on `error` would
//! block a pipeline on an indicator Brolga has no opinion about.

use brolga_model::{ContextPack, Disposition};
use serde_json::{Value, json};

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// This exporter's identifier.
pub const SARIF_ID: ExporterId = ExporterId::new("brolga.export.sarif");

/// The SARIF version the log declares.
pub const SARIF_VERSION: &str = "2.1.0";

/// The schema the log points at.
pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// The entity kinds that make a pack SARIF-shaped.
pub const CODE_KINDS: &[&str] = &["vulnerability", "software_package"];

/// What SARIF cannot carry, declared.
pub const LOSSES: &[&str] = &[
    "locations: a pack knows nothing about the consumer's file tree, and every result therefore \
     carries no `locations` array rather than a fabricated one",
    "the pack's graph structure, budget report, and expansion handles",
    "claim confidence and lifecycle status",
    "marking semantics: SARIF has no handling vocabulary, so markings appear as properties",
];

/// A SARIF writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct SarifExporter;

impl SarifExporter {
    /// Build one.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build one boxed.
    #[must_use]
    pub fn boxed() -> Box<dyn Exporter> {
        Box::new(Self)
    }
}

impl Exporter for SarifExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            SARIF_ID,
            1,
            "application/sarif+json",
            "sarif",
            Orientation::Machine,
            Lossiness::PartiallyLossless,
            "A SARIF 2.1.0 log, for a code-scanning consumer. Results carry no invented locations.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut losses: Vec<&'static str> = LOSSES.to_vec();
        let applicable = applies_to(pack);

        let mut rules: Vec<Value> = Vec::new();
        let mut results: Vec<Value> = Vec::new();
        let mut notifications: Vec<Value> = Vec::new();

        if applicable {
            // One rule per finding kind, one result per finding. A code-scanning consumer groups by
            // rule, so a pack with three findings of one kind should show one rule and three results.
            let mut seen: Vec<&str> = Vec::new();
            for finding in &pack.findings {
                let rule_id = finding.kind.as_str();
                if !seen.contains(&rule_id) {
                    seen.push(rule_id);
                    rules.push(json!({
                        "id": rule_id,
                        "name": rule_name(rule_id),
                        "shortDescription": {"text": format!("Brolga finding: {rule_id}")},
                        "fullDescription": {
                            "text": format!(
                                "A finding from a Brolga context pack about {} {}.",
                                pack.subject.kind.as_str(),
                                pack.subject.value.as_str()
                            )
                        },
                        "defaultConfiguration": {"level": level_for(pack.disposition)},
                        "properties": {
                            "tags": ["threat-intelligence", "brolga"],
                        },
                    }));
                }

                results.push(json!({
                    "ruleId": rule_id,
                    "level": level_for(pack.disposition),
                    "kind": result_kind(pack.disposition),
                    "message": {"text": finding.statement.as_str()},
                    // No `locations`. See the module documentation: a fabricated one is worse than
                    // none, and SARIF permits its absence.
                    "properties": {
                        "brolgaSubject": format!(
                            "{}:{}",
                            pack.subject.kind.as_str(),
                            pack.subject.value.as_str()
                        ),
                        "brolgaDisposition": pack.disposition.as_str(),
                        // Evidence survives, because a SARIF consumer showing a finding should be
                        // able to say where it came from.
                        "brolgaEvidence": finding
                            .evidence
                            .iter()
                            .map(|reference| reference.source_object_id.clone())
                            .collect::<Vec<_>>(),
                    },
                }));
            }

            if pack.findings.is_empty() {
                notifications.push(notification(
                    "note",
                    "The pack is SARIF-shaped but records no findings, so the run has no results.",
                ));
            }
        } else {
            // Not a code-scanning pack. Say so in the log itself rather than producing results a
            // consumer would draw annotations from.
            losses.push(
                "this pack is not about a vulnerability or a software package, so it exports as a \
                 notification rather than as results — a SARIF result about a network indicator has \
                 no location a code-scanning consumer could annotate",
            );
            notifications.push(notification(
                "note",
                &format!(
                    "This Brolga pack concerns {} {}, which SARIF does not describe. Disposition: \
                     {}. Exported as a notification rather than as results.",
                    pack.subject.kind.as_str(),
                    pack.subject.value.as_str(),
                    pack.disposition.as_str()
                ),
            ));
        }

        // Gaps become notifications too. A code-scanning consumer that saw only the results would read
        // the run as complete.
        for gap in &pack.gaps {
            notifications.push(notification(
                "note",
                &format!(
                    "Not known — {}: {}",
                    gap.subject.as_str(),
                    gap.detail.as_str()
                ),
            ));
        }
        if pack.policy.restricted {
            notifications.push(notification(
                "warning",
                "Material was withheld from this pack for policy reasons; the run is not complete.",
            ));
        }

        let log = json!({
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Brolga",
                        "informationUri": "https://github.com/jusso-dev/Brolga",
                        "version": env!("CARGO_PKG_VERSION"),
                        "rules": rules,
                    }
                },
                "invocations": [{
                    "executionSuccessful": true,
                    // No `commandLine`: it routinely carries tokens and internal paths, and an
                    // exporter has no business writing one.
                    "toolExecutionNotifications": notifications,
                }],
                "results": results,
                "properties": {
                    "brolgaSchemaVersion": brolga_model::SchemaTag::<ContextPack>::identifier(),
                    "brolgaFingerprint": pack.fingerprint,
                    "brolgaDetailLevel": pack.detail_level.as_str(),
                    "brolgaApplicable": applicable,
                },
            }],
        });

        let bytes = serde_json::to_vec_pretty(&log).map_err(|error| ExportError::Unencodable {
            exporter: SARIF_ID,
            reason: error.to_string(),
        })?;

        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: losses,
        })
    }
}

/// Whether SARIF is the right shape for this pack.
///
/// True when the subject or any entity in the graph concerns a vulnerability or a software package.
/// See the module documentation for why the answer is reported rather than assumed.
#[must_use]
pub fn applies_to(pack: &ContextPack) -> bool {
    if CODE_KINDS.contains(&pack.subject.kind.as_str()) {
        return true;
    }
    pack.graph
        .entities
        .iter()
        .any(|entity| CODE_KINDS.contains(&entity.kind.as_str()))
}

/// SARIF's `level` for a disposition.
///
/// A benign or unknown subject is never `error`: a consumer configured to fail a build on `error`
/// would block a pipeline on an indicator Brolga has no opinion about.
#[must_use]
pub const fn level_for(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Malicious => "error",
        Disposition::Suspicious => "warning",
        _ => "note",
    }
}

/// SARIF's `kind` for a disposition.
///
/// `informational` rather than `pass` for an unknown subject: `pass` asserts the check succeeded, and
/// no check was run.
#[must_use]
pub const fn result_kind(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Malicious | Disposition::Suspicious => "fail",
        Disposition::Benign => "pass",
        _ => "informational",
    }
}

/// A rule name in the form SARIF conventionally uses: `PascalCase`, no separators.
fn rule_name(id: &str) -> String {
    id.split(['_', '-', '.', ' '])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &characters.as_str().to_lowercase()
                }
                None => String::new(),
            }
        })
        .collect()
}

/// A tool-execution notification.
fn notification(level: &str, text: &str) -> Value {
    json!({
        "level": level,
        "message": {"text": text},
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** A benign or unknown subject never produces an `error`, so a code-scanning
    /// consumer cannot be made to fail a build on an indicator Brolga has no opinion about.
    #[test]
    fn only_a_malicious_subject_produces_an_error_level() {
        assert_eq!(level_for(Disposition::Malicious), "error");
        assert_eq!(level_for(Disposition::Suspicious), "warning");
        assert_eq!(level_for(Disposition::Benign), "note");
        assert_eq!(level_for(Disposition::Unknown), "note");
    }

    /// `pass` asserts a check succeeded. No check ran for an unknown subject.
    #[test]
    fn an_unknown_subject_is_informational_rather_than_a_pass() {
        assert_eq!(result_kind(Disposition::Unknown), "informational");
        assert_eq!(result_kind(Disposition::Benign), "pass");
        assert_eq!(result_kind(Disposition::Malicious), "fail");
    }

    #[test]
    fn a_rule_name_is_pascal_case() {
        assert_eq!(rule_name("known_exploited"), "KnownExploited");
        assert_eq!(rule_name("feed-disposition"), "FeedDisposition");
        assert_eq!(rule_name("single"), "Single");
    }

    #[test]
    fn the_declared_losses_say_no_location_is_invented() {
        let joined = LOSSES.join(" ");
        assert!(joined.contains("fabricated"), "{joined}");
        assert!(joined.contains("file tree"), "{joined}");
    }

    #[test]
    fn the_code_kinds_are_the_ones_sarif_describes() {
        assert!(CODE_KINDS.contains(&"vulnerability"));
        assert!(CODE_KINDS.contains(&"software_package"));
        assert!(!CODE_KINDS.contains(&"threat_actor"));
    }
}
