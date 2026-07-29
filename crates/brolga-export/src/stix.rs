//! STIX 2.1, as a bundle another platform can ingest.
//!
//! # This is a projection, not a translation, and the difference is the whole module
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) requires that "STIX and MISP exporters
//! document unmappable fields". That requirement exists because "export to STIX" *sounds* like a
//! change of encoding and is actually a change of model, and a consumer who does not know which
//! fields vanished will assume none did.
//!
//! STIX has no place for:
//!
//! - **A budget report.** STIX has no notion of a pack having been fitted to a token limit.
//! - **Exclusions and their reasons.** The nearest thing is a note, and putting "42 claims were
//!   withheld under policy" in a `note` object makes it prose rather than a field a consumer can
//!   branch on. It goes in a note anyway, because losing it entirely is worse — but the loss of
//!   *structure* is declared.
//! - **Gaps.** Same reasoning. A gap is Brolga saying "I do not know this", and STIX's vocabulary is
//!   built around asserting what is known.
//! - **Detail level and fingerprint.** Both are properties of a pack, and a bundle is not a pack.
//! - **Confidence on a relationship.** STIX puts `confidence` on an SDO, not on an SRO's meaning.
//!
//! # Deterministic identifiers, and why they are not random
//!
//! Every STIX object needs an `id` of the form `<type>--<uuid>`. The obvious implementation generates
//! a v4 UUID, and it is wrong here: exporting the same pack twice would produce two bundles that
//! differ in every identifier, so a consumer re-ingesting an unchanged pack would create a duplicate
//! of everything.
//!
//! So identifiers are derived deterministically from the pack's own content, via
//! [`brolga_model::Id::derive`], and rendered into the UUID shape STIX requires. The same pack always
//! exports as the same bundle — which also means this exporter needs no clock and no randomness, both
//! of which the [`crate::Exporter`] contract forbids.
//!
//! # `created` and `modified` come from the pack, not from now
//!
//! STIX requires both on every SDO. Using the current time would make the output non-deterministic
//! and would also be a lie: the objects describe what Brolga knew when the pack was built, and the
//! pack records when that was.
//!
//! # Nothing is published
//!
//! This writes bytes. It does not contact a TAXII server, and Brolga has no code that does — ADR 0005
//! makes the connector layer read-only. #54's non-goal says no upstream write-back, and the way that
//! is guaranteed is that there is nothing here to call.

use brolga_model::pack::{ClaimSummary, EntitySummary};
use brolga_model::{ContextPack, Disposition};
use serde_json::{Value, json};

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// This exporter's identifier.
pub const STIX_ID: ExporterId = ExporterId::new("brolga.export.stix");

/// The STIX version the bundle declares.
pub const STIX_VERSION: &str = "2.1";

/// What STIX cannot carry, declared.
///
/// Public because a consumer deciding whether STIX is the right export needs to read it before
/// choosing, not after diffing.
pub const LOSSES: &[&str] = &[
    "the budget report: STIX has no notion of a pack fitted to a token limit",
    "exclusion reasons as structured data; they become a `note` object, which is prose",
    "gaps as structured data, for the same reason",
    "the pack's detail level and fingerprint: a bundle is not a pack",
    "per-relationship confidence: STIX carries confidence on an object, not on an edge's meaning",
    "expansion handles, which are a Brolga concept with no STIX equivalent",
];

/// The observable kinds this exporter can write as a STIX Cyber-observable Object.
///
/// A kind absent from this list is exported as an `indicator` with a pattern instead, and the
/// substitution is noted — silently omitting the subject would produce a bundle about nothing.
/// The labels are [`brolga_model::ObservableKind::as_str`]'s own, checked against it by
/// `every_mapped_kind_is_a_real_observable_kind` — a guessed label would silently send every subject
/// down the fallback path, which is the sort of bug that produces a technically-valid bundle about
/// nothing.
pub const SCO_KINDS: &[(&str, &str, &str)] = &[
    ("ipv4_address", "ipv4-addr", "value"),
    ("ipv6_address", "ipv6-addr", "value"),
    ("domain_name", "domain-name", "value"),
    ("url", "url", "value"),
    ("email_address", "email-addr", "value"),
    ("file_name", "file", "name"),
    ("mac_address", "mac-addr", "value"),
    ("ip_range", "ipv4-addr", "value"),
];

/// A STIX 2.1 bundle writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct StixExporter;

impl StixExporter {
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

impl Exporter for StixExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            STIX_ID,
            1,
            "application/stix+json;version=2.1",
            "json",
            // Interchange, so it requires redistribution: a bundle exists to be handed to another
            // platform. See `Exporter::capability`.
            Orientation::Interchange,
            Lossiness::PartiallyLossless,
            "A STIX 2.1 bundle with deterministic identifiers, for another platform to ingest.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let stamp = &pack.metadata.generated_at;
        let mut objects: Vec<Value> = Vec::new();
        let mut losses: Vec<&'static str> = LOSSES.to_vec();

        // The subject, as an SCO where STIX has one for its kind.
        let subject_id = match sco_for(pack) {
            Some((stix_type, key, value)) => {
                let id = deterministic_id(stix_type, &[stix_type, &value]);
                objects.push(json!({
                    "type": stix_type,
                    "spec_version": STIX_VERSION,
                    "id": id,
                    key: value,
                }));
                id
            }
            None => {
                // No SCO for this kind. An indicator carrying a pattern is the honest fallback: it
                // says what was looked at without claiming a type STIX does not have.
                losses.push(
                    "the subject's observable kind has no STIX Cyber-observable Object, so it is \
                     exported as an `indicator` pattern instead",
                );
                let pattern = format!(
                    "[x-brolga:{} = '{}']",
                    pack.subject.kind.as_str(),
                    escape_pattern(pack.subject.value.as_str())
                );
                let id = deterministic_id("indicator", &["subject", &pattern]);
                objects.push(json!({
                    "type": "indicator",
                    "spec_version": STIX_VERSION,
                    "id": id,
                    "created": stamp,
                    "modified": stamp,
                    "name": pack.subject.value.as_str(),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": stamp,
                }));
                id
            }
        };

        // The disposition, as an indicator. Only when there is something to assert: an `unknown`
        // disposition is not a finding, and publishing one as an indicator would tell a consumer
        // Brolga had made a judgement it had not.
        if let Some(label) = indicator_label(pack.disposition) {
            let pattern = subject_pattern(pack);
            let id = deterministic_id("indicator", &["disposition", label, &pattern]);
            let mut indicator = json!({
                "type": "indicator",
                "spec_version": STIX_VERSION,
                "id": id,
                "created": stamp,
                "modified": stamp,
                "name": format!("{} {}", pack.subject.kind.as_str(), pack.subject.value.as_str()),
                "indicator_types": [label],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": stamp,
            });
            if !pack.findings.is_empty()
                && let Some(object) = indicator.as_object_mut()
            {
                // The findings' statements, joined, as the description. STIX has one description
                // field and a pack has many findings, so this is a genuine flattening.
                let described: Vec<&str> = pack
                    .findings
                    .iter()
                    .map(|finding| finding.statement.as_str())
                    .collect();
                object.insert("description".to_owned(), json!(described.join(" ")));
            }
            objects.push(indicator);
            objects.push(relationship("based-on", &id, &subject_id, stamp));
        }

        // Entities that map onto a STIX SDO. One that does not is skipped and named, rather than
        // exported under a type that means something else.
        let mut unmapped_kinds: Vec<String> = Vec::new();
        for entity in &pack.graph.entities {
            match sdo_type(entity) {
                Some(stix_type) => {
                    let id = deterministic_id(stix_type, &[stix_type, &entity.id]);
                    objects.push(json!({
                        "type": stix_type,
                        "spec_version": STIX_VERSION,
                        "id": id,
                        "created": stamp,
                        "modified": stamp,
                        "name": entity.name.as_str(),
                    }));
                    objects.push(relationship("related-to", &subject_id, &id, stamp));
                }
                None => unmapped_kinds.push(entity.kind.as_str().to_owned()),
            }
        }

        // ATT&CK techniques, as `attack-pattern` objects with an external reference — which is how
        // MITRE's own STIX represents them, so a consumer resolves them the usual way.
        for technique in &pack.graph.techniques {
            let id = deterministic_id("attack-pattern", &["attack", technique.as_str()]);
            objects.push(json!({
                "type": "attack-pattern",
                "spec_version": STIX_VERSION,
                "id": id,
                "created": stamp,
                "modified": stamp,
                "name": technique.as_str(),
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": technique.as_str(),
                }],
            }));
            objects.push(relationship("indicates", &subject_id, &id, stamp));
        }

        // Everything STIX has no field for goes into notes rather than being dropped. Prose is worse
        // than a field and much better than silence.
        let mut note_lines: Vec<String> = Vec::new();
        for claim in &pack.graph.claims {
            note_lines.push(claim_line(claim));
        }
        for gap in &pack.gaps {
            note_lines.push(format!(
                "Not known — {}: {}",
                gap.subject.as_str(),
                gap.detail.as_str()
            ));
        }
        for exclusion in &pack.exclusions {
            note_lines.push(format!(
                "Withheld — {} ({}){}",
                exclusion.category.as_str(),
                exclusion.reason.as_str(),
                exclusion
                    .dropped
                    .map(|count| format!(", {count} item(s)"))
                    .unwrap_or_default()
            ));
        }
        for contradiction in &pack.graph.contradictions {
            note_lines.push(format!(
                "Disputed — {}: `{}` against `{}`",
                contradiction.subject.as_str(),
                contradiction.left.as_str(),
                contradiction.right.as_str()
            ));
        }
        if !unmapped_kinds.is_empty() {
            unmapped_kinds.sort_unstable();
            unmapped_kinds.dedup();
            note_lines.push(format!(
                "Not exported — entity kinds with no STIX equivalent: {}",
                unmapped_kinds.join(", ")
            ));
        }
        if !note_lines.is_empty() {
            let content = note_lines.join("\n");
            let id = deterministic_id("note", &["note", &content]);
            objects.push(json!({
                "type": "note",
                "spec_version": STIX_VERSION,
                "id": id,
                "created": stamp,
                "modified": stamp,
                "abstract": "Brolga context that STIX 2.1 has no field for",
                "content": content,
                "object_refs": [subject_id],
            }));
        }

        // The bundle's own identifier is derived from the pack's fingerprint, so re-exporting an
        // unchanged pack produces a byte-identical bundle.
        let bundle_id = deterministic_id("bundle", &["bundle", &pack.fingerprint]);
        let bundle = json!({
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        });

        let bytes =
            serde_json::to_vec_pretty(&bundle).map_err(|error| ExportError::Unencodable {
                exporter: STIX_ID,
                reason: error.to_string(),
            })?;

        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: losses,
        })
    }
}

/// The STIX type, property name, and value for the pack's subject, where STIX has an SCO for it.
fn sco_for(pack: &ContextPack) -> Option<(&'static str, &'static str, String)> {
    let kind = pack.subject.kind.as_str();
    // IPv6 shares its Brolga kind with IPv4, so the address itself decides which STIX type applies.
    // Exporting an IPv6 address as `ipv4-addr` would be wrong in a way a consumer's validator catches
    // and a human might not.
    if kind == "ip_address" || kind == "ip-address" {
        let stix_type = if pack.subject.value.as_str().contains(':') {
            "ipv6-addr"
        } else {
            "ipv4-addr"
        };
        return Some((stix_type, "value", pack.subject.value.as_str().to_owned()));
    }
    SCO_KINDS
        .iter()
        .find(|(brolga, _, _)| *brolga == kind)
        .map(|(_, stix_type, key)| (*stix_type, *key, pack.subject.value.as_str().to_owned()))
}

/// A STIX pattern for the subject.
fn subject_pattern(pack: &ContextPack) -> String {
    let value = escape_pattern(pack.subject.value.as_str());
    match sco_for(pack) {
        Some((stix_type, key, _)) => format!("[{stix_type}:{key} = '{value}']"),
        None => format!("[x-brolga:{} = '{value}']", pack.subject.kind.as_str()),
    }
}

/// Escape a value for a STIX pattern string literal.
///
/// A single quote inside a pattern would close the literal, and a backslash would escape the next
/// character. A feed-supplied value containing either would otherwise produce a bundle that fails a
/// consumer's pattern parser — or, worse, one that parses as something else.
#[must_use]
pub fn escape_pattern(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// The STIX `indicator_types` label for a disposition, where one applies.
fn indicator_label(disposition: Disposition) -> Option<&'static str> {
    match disposition {
        Disposition::Malicious => Some("malicious-activity"),
        Disposition::Suspicious => Some("anomalous-activity"),
        Disposition::Benign => Some("benign"),
        // `unknown` is not a judgement, and publishing it as an indicator would tell a consumer
        // Brolga had reached a conclusion it had not. Skipped deliberately.
        _ => None,
    }
}

/// The STIX SDO type for an entity kind, where STIX has one.
fn sdo_type(entity: &EntitySummary) -> Option<&'static str> {
    match entity.kind.as_str() {
        "threat_actor" => Some("threat-actor"),
        "malware" => Some("malware"),
        "campaign" => Some("campaign"),
        "intrusion_set" => Some("intrusion-set"),
        "tool" => Some("tool"),
        "vulnerability" => Some("vulnerability"),
        "identity" | "organisation" | "organization" => Some("identity"),
        "location" => Some("location"),
        "attack_technique" => Some("attack-pattern"),
        "infrastructure" => Some("infrastructure"),
        // `asset`, `incident`, `detection_rule`, `software_package`, `sector` — no STIX 2.1 SDO, or
        // one whose meaning differs enough that using it would misinform. Named in a note instead.
        _ => None,
    }
}

/// A STIX relationship object.
fn relationship(kind: &str, source: &str, target: &str, stamp: &str) -> Value {
    let id = deterministic_id("relationship", &[kind, source, target]);
    json!({
        "type": "relationship",
        "spec_version": STIX_VERSION,
        "id": id,
        "created": stamp,
        "modified": stamp,
        "relationship_type": kind,
        "source_ref": source,
        "target_ref": target,
    })
}

/// One claim, as a note line.
fn claim_line(claim: &ClaimSummary) -> String {
    format!(
        "Claim — {} = {} ({}{})",
        claim.predicate.as_str(),
        claim.object.as_str(),
        claim.status.as_str(),
        claim
            .confidence
            .map(|score| format!(", confidence {score}"))
            .unwrap_or_default()
    )
}

/// A STIX identifier derived from content rather than generated.
///
/// `<type>--<uuid>`, where the UUID is the pack-derived identifier reshaped into the hyphenated form
/// STIX requires. Deterministic, so re-exporting an unchanged pack produces an identical bundle and a
/// consumer re-ingesting it creates no duplicates. See the module documentation.
#[must_use]
pub fn deterministic_id(stix_type: &str, parts: &[&str]) -> String {
    // The model's own derivation rather than a second one here: one algorithm cannot disagree with
    // itself. The marker type is irrelevant — only the UUID is used.
    //
    // `Id`'s `Display` is `<kind>:<uuid>`, so the UUID is taken from `as_uuid` rather than by parsing
    // the rendered form. STIX requires exactly `<type>--<uuid>`, and `indicator--entity:0123…` is not
    // that — it is the sort of thing that passes a `starts_with` check and fails a real validator.
    let uuid = brolga_model::Id::<brolga_model::Entity>::derive(parts)
        .as_uuid()
        .as_hyphenated()
        .to_string();
    format!("{stix_type}--{uuid}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_literal_cannot_be_closed_by_feed_text() {
        assert_eq!(escape_pattern("a'b"), "a\\'b");
        assert_eq!(escape_pattern("a\\b"), "a\\\\b");
        // The combination an attacker would actually try.
        let escaped = escape_pattern("' OR ipv4-addr:value = '");
        assert!(!escaped.contains("= '"), "{escaped}");
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

    /// **The criterion a validator would catch.** A STIX identifier is exactly `<type>--<uuid>`.
    #[test]
    fn an_identifier_is_a_type_and_a_bare_uuid() {
        let id = deterministic_id("indicator", &["a"]);
        let (kind, uuid) = id.split_once("--").expect("the STIX separator");
        assert_eq!(kind, "indicator");
        assert_eq!(uuid.len(), 36, "`{uuid}` is not a hyphenated UUID");
        assert_eq!(uuid.matches('-').count(), 4, "{uuid}");
        assert!(
            !uuid.contains(':'),
            "the model's `kind:uuid` form must not leak into a STIX id: {id}"
        );
    }

    /// Every kind named here is one the model actually produces. A guessed label would send every
    /// subject down the fallback path and produce a valid bundle about nothing.
    #[test]
    fn every_mapped_kind_is_a_real_observable_kind() {
        let real = real_kinds();
        for (brolga, stix, _) in SCO_KINDS {
            assert!(
                real.contains(brolga),
                "`{brolga}` (mapped to `{stix}`) is not an observable kind the model produces; \
                 known: {real:?}"
            );
        }
    }

    #[test]
    fn identifiers_are_deterministic_and_typed() {
        let first = deterministic_id("indicator", &["a", "b"]);
        let second = deterministic_id("indicator", &["a", "b"]);
        assert_eq!(first, second, "the same pack must export identically");
        assert!(first.starts_with("indicator--"), "{first}");
        assert_ne!(first, deterministic_id("indicator", &["a", "c"]));
        assert_ne!(
            first,
            deterministic_id("malware", &["a", "b"]),
            "the type must be part of the identifier"
        );
    }

    /// An `unknown` disposition is not a judgement, and must not be published as one.
    #[test]
    fn an_unknown_disposition_produces_no_indicator_label() {
        assert!(indicator_label(Disposition::Unknown).is_none());
        assert_eq!(
            indicator_label(Disposition::Malicious),
            Some("malicious-activity")
        );
    }

    #[test]
    fn the_declared_losses_name_the_budget_and_the_gaps() {
        let joined = LOSSES.join(" ");
        assert!(joined.contains("budget"), "{joined}");
        assert!(joined.contains("gaps"), "{joined}");
        assert!(joined.contains("handles"), "{joined}");
    }

    /// An entity kind with no STIX equivalent must be named, never exported under a type that means
    /// something else.
    #[test]
    fn an_entity_kind_with_no_stix_type_is_not_guessed_at() {
        let summary = |kind: &str| EntitySummary {
            id: "e".to_owned(),
            kind: brolga_model::ShortText::new(kind).unwrap(),
            name: brolga_model::UntrustedText::new("n").unwrap(),
            status: brolga_model::ShortText::new("active").unwrap(),
        };
        assert_eq!(sdo_type(&summary("malware")), Some("malware"));
        assert!(sdo_type(&summary("detection_rule")).is_none());
        assert!(sdo_type(&summary("software_package")).is_none());
    }
}
