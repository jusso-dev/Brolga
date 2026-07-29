//! Sigma metadata and hunting packs — the two exports that stop short of being runnable.
//!
//! # Neither of these is a runnable rule, and that is deliberate
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) asks for "Sigma metadata" and "hunting
//! packs", and its non-goal says **no automatic SIEM execution**. Those two together describe
//! something specific: an artefact a detection engineer reads, edits, and then decides to deploy — not
//! one a pipeline pushes into a SIEM unattended.
//!
//! So [`SigmaMetadataExporter`] emits a Sigma document with a `detection` block that is **deliberately
//! incomplete**: it carries the observable and the `condition`, and it carries no `logsource`. A Sigma
//! rule without a log source does not run. That is not an oversight to be fixed later, it is the
//! stopping point, and the document says so in its own `description` and `status` fields so that a
//! human who opens the file learns it before a tool does.
//!
//! Why a log source cannot be filled in: it names a product, a service, and a category specific to the
//! deployment's own logging. Brolga does not know whether the operator's DNS logs come from Sysmon
//! event 22, a Zeek `dns.log`, or a cloud resolver, and a rule with a guessed log source either
//! matches nothing — a silent false negative in a detection pipeline — or matches the wrong field.
//! Emitting `status: experimental` and no log source makes the gap loud.
//!
//! # The hunting pack is a checklist, not a query
//!
//! [`HuntingPackExporter`] writes what an analyst hunts *with*: the indicators to look for, the
//! techniques to look at, the pivots to follow, and the gaps that tell them where the pack is blind.
//! No query language, for the same reason — a query is specific to a platform's schema, and a
//! generated one that silently returns nothing is worse than no query at all.
//!
//! # A rule identifier must be stable
//!
//! Sigma requires `id` to be a UUID that is globally unique and stable across edits. It is derived
//! from the pack's own content, so exporting the same pack twice produces the same rule rather than a
//! second copy of it in somebody's rule repository.

use brolga_model::{ContextPack, Disposition};

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// The Sigma metadata exporter's identifier.
pub const SIGMA_ID: ExporterId = ExporterId::new("brolga.export.sigma");

/// The hunting pack exporter's identifier.
pub const HUNTING_ID: ExporterId = ExporterId::new("brolga.export.hunt");

/// The Sigma field name each observable kind maps onto.
///
/// Log-source-independent field names only. `DestinationHostname` and `dns_query` are Sysmon and Zeek
/// spellings of the same idea, and choosing one would bake a log pipeline into the output — so the
/// generic Sigma taxonomy names are used, and the missing log source is what tells the engineer to
/// map them.
/// The labels are [`brolga_model::ObservableKind::as_str`]'s own, checked against it by
/// `every_mapped_kind_is_a_real_observable_kind`.
pub const SIGMA_FIELDS: &[(&str, &str)] = &[
    ("ipv4_address", "DestinationIp"),
    ("ipv6_address", "DestinationIp"),
    ("domain_name", "DestinationHostname"),
    ("url", "Url"),
    ("email_address", "SenderAddress"),
    ("file_hash", "Hashes"),
    ("file_name", "TargetFilename"),
    ("file_path", "TargetFilename"),
    ("registry_key", "TargetObject"),
    ("user_agent", "UserAgent"),
];

/// What a Sigma export deliberately does not carry.
pub const SIGMA_LOSSES: &[&str] = &[
    "the `logsource` block, deliberately: Brolga does not know the deployment's own logging, and a \
     guessed log source either matches nothing or matches the wrong field",
    "evidence references beyond the `references` list",
    "the pack's graph, budget, and exclusions",
    "claim confidence and status",
];

/// What a hunting pack does not carry.
pub const HUNT_LOSSES: &[&str] = &[
    "any executable query: a query is specific to a platform's schema, and a generated one that \
     silently returns nothing is worse than none",
    "the pack's structured fields; a hunting pack is a checklist for a person",
    "the budget report",
];

/// A Sigma metadata writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct SigmaMetadataExporter;

impl SigmaMetadataExporter {
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

impl Exporter for SigmaMetadataExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            SIGMA_ID,
            1,
            "application/x-sigma+yaml",
            "yml",
            Orientation::Human,
            Lossiness::Derived,
            "A Sigma document with no `logsource`, for a detection engineer to complete. Not runnable \
             as written.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let field = field_for(pack.subject.kind.as_str());
        let mut out = String::new();

        // A comment first, because it is what a person sees when they open the file — before any tool
        // reads the `status` field.
        out.push_str(
            "# NOT RUNNABLE AS WRITTEN. This document has no `logsource` block, so no Sigma backend\n\
             # will convert it into a query. That is deliberate: Brolga does not know which of your\n\
             # log sources carries this field, and a guessed one either matches nothing — a silent\n\
             # false negative — or matches the wrong field. Add a `logsource` and review the\n\
             # detection before deploying.\n\n",
        );

        out.push_str(&format!(
            "title: {}\n",
            yaml_scalar(&format!(
                "Brolga context: {} {}",
                pack.subject.kind.as_str(),
                pack.subject.value.as_str()
            ))
        ));
        out.push_str(&format!(
            "id: {}\n",
            rule_id(&pack.fingerprint, pack.subject.observable_id.as_str())
        ));
        // `experimental` rather than `stable`, because an incomplete rule is not stable and the field
        // is the one a rule-management tool reads.
        out.push_str("status: experimental\n");
        out.push_str(&format!(
            "description: {}\n",
            yaml_scalar(&description_of(pack))
        ));
        out.push_str(&format!("date: {}\n", yaml_scalar(&date_of(pack))));
        out.push_str("author: Brolga\n");

        if !pack.findings.is_empty() {
            out.push_str("references:\n");
            // The evidence, as references. A detection engineer asking "why does this rule exist?"
            // should be able to reach the source objects behind it.
            for finding in &pack.findings {
                for reference in &finding.evidence {
                    out.push_str(&format!(
                        "  - {}\n",
                        yaml_scalar(&reference.source_object_id)
                    ));
                }
            }
        }

        if !pack.graph.techniques.is_empty() {
            out.push_str("tags:\n");
            for technique in &pack.graph.techniques {
                // Sigma's own convention: lowercase, `attack.` prefixed.
                out.push_str(&format!(
                    "  - {}\n",
                    yaml_scalar(&format!("attack.{}", technique.as_str().to_lowercase()))
                ));
            }
        }

        // No `logsource`. Named in a comment where it would have gone, so its absence reads as a
        // decision rather than as a truncated file.
        out.push_str(
            "\n# logsource: intentionally absent. Add the product, service, or category\n\
                      # that carries the field below, then review.\n\n",
        );

        out.push_str("detection:\n");
        out.push_str("  selection:\n");
        match field {
            Some(field) => {
                out.push_str(&format!(
                    "    {field}: {}\n",
                    yaml_scalar(pack.subject.value.as_str())
                ));
            }
            None => {
                // No log-source-independent field for this kind. A commented placeholder rather than a
                // guessed field name: a wrong field silently matches nothing.
                out.push_str(&format!(
                    "    # no log-source-independent Sigma field for `{}`; name the field yourself\n\
                     \x20   # value: {}\n",
                    pack.subject.kind.as_str(),
                    yaml_scalar(pack.subject.value.as_str())
                ));
            }
        }
        out.push_str("  condition: selection\n");

        out.push_str(&format!("\nlevel: {}\n", sigma_level(pack.disposition)));

        let mut losses: Vec<&'static str> = SIGMA_LOSSES.to_vec();
        if field.is_none() {
            losses.push(
                "the subject's kind has no log-source-independent Sigma field, so the selection is a \
                 commented placeholder rather than a guessed field name",
            );
        }

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: losses,
        })
    }
}

/// A hunting pack writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct HuntingPackExporter;

impl HuntingPackExporter {
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

impl Exporter for HuntingPackExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            HUNTING_ID,
            1,
            "text/markdown",
            "md",
            Orientation::Human,
            Lossiness::Derived,
            "A hunt checklist: what to look for, where to look next, and where the pack is blind.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut out = String::new();

        out.push_str(&format!(
            "# Hunt: {} `{}`\n\n",
            crate::markdown::escape(pack.subject.kind.as_str()),
            crate::markdown::escape(pack.subject.value.as_str())
        ));
        out.push_str(&format!(
            "Disposition **{}**. This is a checklist for a person, not a query for a platform — see \
             the note at the end.\n\n",
            pack.disposition.as_str()
        ));

        out.push_str("## Look for\n\n");
        out.push_str(&format!(
            "- [ ] `{}` in {} telemetry\n",
            crate::markdown::escape(pack.subject.value.as_str()),
            field_for(pack.subject.kind.as_str()).map_or("the relevant", |_| "the corresponding")
        ));
        for claim in &pack.graph.claims {
            out.push_str(&format!(
                "- [ ] {} = `{}`\n",
                crate::markdown::escape(claim.predicate.as_str()),
                crate::markdown::escape(claim.object.as_str())
            ));
        }
        out.push('\n');

        if !pack.graph.techniques.is_empty() {
            out.push_str("## Techniques to consider\n\n");
            for technique in &pack.graph.techniques {
                out.push_str(&format!(
                    "- [ ] `{}`\n",
                    crate::markdown::escape(technique.as_str())
                ));
            }
            out.push('\n');
        }

        if !pack.graph.pivots.is_empty() {
            out.push_str("## Then look at\n\n");
            for pivot in &pack.graph.pivots {
                out.push_str(&format!(
                    "- [ ] `{}` — {}\n",
                    crate::markdown::escape(pivot.target.as_str()),
                    crate::markdown::escape(pivot.reason.as_str())
                ));
            }
            out.push('\n');
        }

        // The blind spots. A hunt that does not know where the intelligence stops will read absence of
        // evidence as evidence of absence, which is the commonest way a hunt reaches a wrong
        // conclusion.
        out.push_str("## Where this pack is blind\n\n");
        if pack.gaps.is_empty() && pack.exclusions.is_empty() {
            out.push_str("Nothing recorded. That is not the same as nothing missing.\n\n");
        } else {
            for gap in &pack.gaps {
                out.push_str(&format!(
                    "- **{}** — {}\n",
                    crate::markdown::escape(gap.subject.as_str()),
                    crate::markdown::escape(gap.detail.as_str())
                ));
            }
            for exclusion in &pack.exclusions {
                out.push_str(&format!(
                    "- **withheld: {}** — {}\n",
                    crate::markdown::escape(exclusion.category.as_str()),
                    crate::markdown::escape(exclusion.reason.as_str())
                ));
            }
            out.push('\n');
        }

        if !pack.findings.is_empty() {
            out.push_str("## Why\n\n");
            for finding in &pack.findings {
                let addresses: Vec<String> = finding
                    .evidence
                    .iter()
                    .map(|reference| format!("`{}`", reference.source_object_id))
                    .collect();
                out.push_str(&format!(
                    "- {} [evidence: {}]\n",
                    crate::markdown::escape(finding.statement.as_str()),
                    addresses.join(", ")
                ));
            }
            out.push('\n');
        }

        out.push_str(
            "---\n\nNo query is generated. A query is specific to a platform's schema, and a \
             generated one that silently returns nothing is worse than none — it reads as a hunt that \
             found nothing.\n",
        );

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: HUNT_LOSSES.to_vec(),
        })
    }
}

/// The Sigma field for an observable kind, where a log-source-independent one exists.
#[must_use]
pub fn field_for(kind: &str) -> Option<&'static str> {
    SIGMA_FIELDS
        .iter()
        .find(|(brolga, _)| *brolga == kind)
        .map(|(_, field)| *field)
}

/// Sigma's `level` for a disposition.
#[must_use]
pub const fn sigma_level(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Malicious => "high",
        Disposition::Suspicious => "medium",
        // A benign or unknown subject produces an informational rule. Not `low`: `low` still asks a
        // SIEM to alert, and there is nothing here to alert on.
        _ => "informational",
    }
}

/// The rule's stable identifier.
#[must_use]
pub fn rule_id(fingerprint: &str, observable_id: &str) -> String {
    // The model's own derivation; see `crate::misp::attribute_uuid` for why the marker type does
    // not matter here.
    // A bare hyphenated UUID: Sigma requires `id` to be one, and the model's `kind:uuid` display
    // form is not.
    brolga_model::Id::<brolga_model::Entity>::derive(&["sigma-export", fingerprint, observable_id])
        .as_uuid()
        .as_hyphenated()
        .to_string()
}

/// The description, which is where the incompleteness is stated in a field a tool reads.
fn description_of(pack: &ContextPack) -> String {
    let mut description = format!(
        "Generated from a Brolga context pack (fingerprint {}). NOT RUNNABLE: no logsource. ",
        pack.fingerprint
    );
    if let Some(finding) = pack.findings.first() {
        description.push_str(finding.statement.as_str());
    }
    description
}

/// The pack's generated-at date.
fn date_of(pack: &ContextPack) -> String {
    pack.metadata.generated_at.split_once('T').map_or_else(
        || pack.metadata.generated_at.clone(),
        |(date, _)| date.replace('-', "/"),
    )
}

/// A YAML scalar that cannot be misread, whatever it contains.
///
/// Always double-quoted with the escapes YAML defines. Not conditionally quoted: a value beginning
/// `*` is an alias reference, one beginning `&` is an anchor, `!` is a tag, and `-` starts a sequence
/// item. A pack quotes feeds, so any of those can arrive, and a rule for when to quote is a rule an
/// attacker formats around.
#[must_use]
pub fn yaml_scalar(value: &str) -> String {
    let mut out = String::with_capacity(value.len().saturating_add(2));
    out.push('"');
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** A feed cannot write YAML structure into a rule.
    #[test]
    fn a_feed_cannot_inject_yaml() {
        for hostile in [
            "*alias",
            "&anchor value",
            "!!python/object/apply:os.system",
            "value\nlogsource:\n  product: windows",
            "quote\" injected: true",
        ] {
            let scalar = yaml_scalar(hostile);
            assert!(scalar.starts_with('"') && scalar.ends_with('"'), "{scalar}");
            assert!(
                !scalar.contains('\n'),
                "a newline would let a feed add a key: {scalar}"
            );
        }
        // The one that matters most: a value cannot close its own quotes.
        let scalar = yaml_scalar("a\" b");
        assert_eq!(scalar, "\"a\\\" b\"");
    }

    /// The whole point of the Sigma exporter: the output is not runnable, and it says so.
    #[test]
    fn the_sigma_document_has_no_logsource_and_says_why() {
        // Asserted on the constants and the loss list, which are what a consumer reads. The full
        // document is checked in the integration tests, where a pack exists to render.
        let joined = SIGMA_LOSSES.join(" ");
        assert!(joined.contains("logsource"), "{joined}");
        assert!(joined.contains("deliberately"), "{joined}");
    }

    #[test]
    fn a_rule_identifier_is_stable_across_exports() {
        assert_eq!(rule_id("f", "o"), rule_id("f", "o"));
        assert_ne!(rule_id("f", "o"), rule_id("g", "o"));
    }

    /// A benign subject produces an informational rule, not a `low` one: `low` still asks a SIEM to
    /// alert, and there is nothing here to alert on.
    #[test]
    fn a_benign_subject_does_not_produce_an_alerting_level() {
        assert_eq!(sigma_level(Disposition::Malicious), "high");
        assert_eq!(sigma_level(Disposition::Suspicious), "medium");
        assert_eq!(sigma_level(Disposition::Benign), "informational");
        assert_eq!(sigma_level(Disposition::Unknown), "informational");
    }

    /// Every observable kind the model defines, by its own label.
    ///
    /// Listed from the enum's variants rather than from a string list, so a typo here is a compile
    /// error. `ObservableKind` has no `all()`, so this is the closest available thing — and what it
    /// checks is the property that matters: that a label this module maps is one the model produces.
    fn real_kinds() -> Vec<&'static str> {
        use brolga_model::ObservableKind as K;
        [
            K::Ipv4Address,
            K::Ipv6Address,
            K::IpRange,
            K::DomainName,
            K::Url,
            K::EmailAddress,
            K::FileHash,
            K::MacAddress,
            K::AutonomousSystemNumber,
            K::FileName,
            K::FilePath,
            K::MutexName,
            K::RegistryKey,
            K::UserAgent,
        ]
        .iter()
        .map(|kind| kind.as_str())
        .collect()
    }

    /// Every kind named here is one the model actually produces.
    #[test]
    fn every_mapped_kind_is_a_real_observable_kind() {
        let real = real_kinds();
        for (brolga, field) in SIGMA_FIELDS {
            assert!(
                real.contains(brolga),
                "`{brolga}` (mapped to `{field}`) is not an observable kind the model produces"
            );
        }
    }

    /// Sigma requires `id` to be a UUID.
    #[test]
    fn a_rule_identifier_is_a_bare_uuid() {
        let id = rule_id("f", "o");
        assert_eq!(id.len(), 36, "`{id}` is not a hyphenated UUID");
        assert!(!id.contains(':'), "{id}");
    }

    #[test]
    fn an_unmapped_kind_has_no_guessed_field() {
        assert_eq!(field_for("domain_name"), Some("DestinationHostname"));
        assert!(field_for("autonomous_system_number").is_none());
    }
}
