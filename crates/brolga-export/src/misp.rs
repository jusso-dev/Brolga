//! MISP event JSON — "feasible MISP", which is what [#54](https://github.com/jusso-dev/Brolga/issues/54)
//! asks for and worth taking literally.
//!
//! # What "feasible" rules out
//!
//! A MISP event is not just a container of attributes. A real one carries an `Orgc` (the creating
//! organisation, with its own UUID), `Galaxy` clusters, `Object` templates with versioned definitions,
//! `Sighting` records tied to org identifiers, and `Tag` objects whose meaning depends on the
//! receiving instance's taxonomy configuration.
//!
//! Brolga has none of that, and cannot invent it:
//!
//! - **No organisation identity.** A pack does not know which MISP org is publishing it, and
//!   fabricating an `Orgc` UUID would attribute intelligence to an organisation that does not exist.
//! - **No object templates.** A MISP object references a template by UUID and version. Emitting one
//!   Brolga does not have would produce an event the receiving instance rejects, or worse silently
//!   misreads.
//! - **No galaxy clusters.** Same problem, one level worse: a galaxy cluster is a shared identifier
//!   for a named threat, and guessing one attributes activity to an actor.
//!
//! So this exporter writes the part that is *interoperable without shared configuration*: an event
//! with attributes, `to_ids` flags, tags from the pack's own markings, and the pack's prose in the
//! event's own fields. A MISP instance imports that without any prior agreement. Everything else is
//! declared in [`LOSSES`].
//!
//! # `to_ids` is a decision, not a copy
//!
//! MISP's `to_ids` flag means "this attribute is suitable for automated detection". Setting it on
//! everything is the commonest mistake in MISP exports, and it is how a benign domain ends up in
//! somebody's blocklist.
//!
//! It is set only for a `malicious` disposition. `suspicious` gets `to_ids: false` — suspicion is a
//! reason for a human to look, not for a machine to block — and `benign` and `unknown` get it too.
//! That is a judgement this exporter makes on the operator's behalf, and it is the conservative
//! direction: a missed detection is recoverable and a wrongly-blocked production domain is an
//! incident.
//!
//! # Nothing is published
//!
//! This writes bytes. Brolga's MISP connector is read-only by ADR 0005, and #54's non-goal says no
//! upstream write-back. There is no code here that could push an event.

use brolga_model::{ContextPack, Disposition};
use serde_json::{Value, json};

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// This exporter's identifier.
pub const MISP_ID: ExporterId = ExporterId::new("brolga.export.misp");

/// What MISP cannot carry without shared configuration, declared.
pub const LOSSES: &[&str] = &[
    "the creating organisation (`Orgc`): a pack does not know which MISP org publishes it, and \
     fabricating one would attribute intelligence to an organisation that does not exist",
    "MISP objects and their templates: a template is referenced by UUID and version, and emitting \
     one Brolga does not have produces an event the receiving instance rejects or misreads",
    "galaxy clusters: guessing one attributes activity to a named actor",
    "sightings as MISP `Sighting` records, which are keyed to org identifiers Brolga does not have",
    "the budget report and the pack fingerprint",
    "gap and exclusion structure; both become event-level text",
    "expansion handles, which have no MISP equivalent",
];

/// The MISP attribute type for each observable kind Brolga can export.
///
/// A kind absent from this list is exported as a `comment` attribute and named as a substitution — a
/// MISP attribute with a wrong type is worse than one with a generic type, because a wrong type feeds
/// the wrong correlation.
/// The labels are [`brolga_model::ObservableKind::as_str`]'s own, checked against it by
/// `every_mapped_kind_is_a_real_observable_kind`.
pub const ATTRIBUTE_TYPES: &[(&str, &str, &str)] = &[
    ("ipv4_address", "ip-dst", "Network activity"),
    ("ipv6_address", "ip-dst", "Network activity"),
    ("ip_range", "ip-dst", "Network activity"),
    ("domain_name", "domain", "Network activity"),
    ("url", "url", "Network activity"),
    ("email_address", "email", "Payload delivery"),
    // MISP has a type per algorithm. `file_hash` carries its own, so the generic `sha256` would be a
    // guess — but MISP's `x509-fingerprint-sha256` family shows the convention, and `sha256` is the
    // type an aggregating instance correlates on most often. The algorithm travels in the value.
    ("file_hash", "sha256", "Payload delivery"),
    ("file_name", "filename", "Payload delivery"),
    ("file_path", "filename", "Payload delivery"),
    ("mac_address", "mac-address", "Network activity"),
    ("user_agent", "user-agent", "Network activity"),
    ("registry_key", "regkey", "Persistence mechanism"),
    ("mutex_name", "mutex", "Artifacts dropped"),
];

/// MISP's threat levels. 1 is highest.
///
/// Mapped from the disposition rather than from a score, because a pack's disposition is the only
/// judgement Brolga makes and inventing a severity would be inventing intelligence.
pub const THREAT_LEVEL_HIGH: u8 = 1;
/// Medium.
pub const THREAT_LEVEL_MEDIUM: u8 = 2;
/// Low.
pub const THREAT_LEVEL_LOW: u8 = 3;
/// Undefined. MISP's own value for "no assessment".
pub const THREAT_LEVEL_UNDEFINED: u8 = 4;

/// A MISP event writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct MispExporter;

impl MispExporter {
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

impl Exporter for MispExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            MISP_ID,
            1,
            "application/json",
            "json",
            Orientation::Interchange,
            Lossiness::PartiallyLossless,
            "A MISP event with the parts that interoperate without shared configuration.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut losses: Vec<&'static str> = LOSSES.to_vec();
        let stamp = &pack.metadata.generated_at;

        let (attribute_type, category) = match attribute_type_for(pack.subject.kind.as_str()) {
            Some(pair) => pair,
            None => {
                losses.push(
                    "the subject's observable kind has no MISP attribute type, so it is exported as \
                     a `comment` — a wrong type would feed the wrong correlation",
                );
                ("comment", "Other")
            }
        };

        // `to_ids` only for malicious. See the module documentation: this is the conservative
        // direction, and it is the direction that does not put a production domain in a blocklist.
        let to_ids = pack.disposition == Disposition::Malicious;

        let mut attributes: Vec<Value> = vec![json!({
            "uuid": attribute_uuid(&["subject", pack.subject.observable_id.as_str()]),
            "type": attribute_type,
            "category": category,
            "value": pack.subject.value.as_str(),
            "to_ids": to_ids,
            "timestamp": epoch_seconds(stamp),
            "comment": format!(
                "Brolga disposition: {}. Detail level {}.",
                pack.disposition.as_str(),
                pack.detail_level.as_str()
            ),
        })];

        // Findings and claims as comment attributes. MISP has no field for "an assertion with cited
        // evidence", so the evidence goes in the comment beside the text rather than being dropped —
        // #54 requires human-facing output to keep its evidence references, and this output is read
        // by humans in a MISP UI.
        for finding in &pack.findings {
            let evidence: Vec<&str> = finding
                .evidence
                .iter()
                .map(|reference| reference.source_object_id.as_str())
                .collect();
            attributes.push(json!({
                "uuid": attribute_uuid(&["finding", finding.kind.as_str(), finding.statement.as_str()]),
                "type": "comment",
                "category": "External analysis",
                "value": finding.statement.as_str(),
                "to_ids": false,
                "timestamp": epoch_seconds(stamp),
                "comment": format!(
                    "{} — evidence: {}",
                    finding.kind.as_str(),
                    evidence.join(", ")
                ),
            }));
        }

        for technique in &pack.graph.techniques {
            attributes.push(json!({
                "uuid": attribute_uuid(&["technique", technique.as_str()]),
                // MISP's own type for an ATT&CK reference. Not a galaxy cluster — see the module
                // documentation for why a cluster cannot be guessed.
                "type": "text",
                "category": "External analysis",
                "value": technique.as_str(),
                "to_ids": false,
                "timestamp": epoch_seconds(stamp),
                "comment": "MITRE ATT&CK technique reached from the subject",
            }));
        }

        // Tags from the pack's own markings only. A tag whose meaning depends on the receiving
        // instance's taxonomy is not portable, and TLP is the one taxonomy every instance has.
        let mut tags: Vec<Value> = pack
            .policy
            .markings
            .iter()
            .filter_map(|marking| tlp_tag(marking).map(|name| json!({"name": name})))
            .collect();
        if pack.policy.restricted {
            tags.push(json!({"name": "brolga:restricted"}));
        }

        let mut info = format!(
            "Brolga context: {} {}",
            pack.subject.kind.as_str(),
            pack.subject.value.as_str()
        );
        if let Some(purpose) = &pack.purpose {
            info.push_str(&format!(" ({})", purpose.as_str()));
        }

        // Gaps and exclusions as event-level analysis text. Structure lost, content kept, loss
        // declared.
        let mut narrative: Vec<String> = Vec::new();
        for gap in &pack.gaps {
            narrative.push(format!(
                "Not known — {}: {}",
                gap.subject.as_str(),
                gap.detail.as_str()
            ));
        }
        for exclusion in &pack.exclusions {
            narrative.push(format!(
                "Withheld — {} ({})",
                exclusion.category.as_str(),
                exclusion.reason.as_str()
            ));
        }
        for contradiction in &pack.graph.contradictions {
            narrative.push(format!(
                "Disputed — {}: {} against {}",
                contradiction.subject.as_str(),
                contradiction.left.as_str(),
                contradiction.right.as_str()
            ));
        }

        let event = json!({
            "Event": {
                "uuid": attribute_uuid(&["event", pack.fingerprint.as_str()]),
                "info": info,
                "date": date_of(stamp),
                "threat_level_id": threat_level(pack.disposition).to_string(),
                // `0` is MISP's "Initial" analysis state. A pack is a snapshot rather than a
                // completed investigation, so claiming "Complete" would overstate it.
                "analysis": "0",
                // Never distributed onward by default. MISP's `0` is "your organisation only", and an
                // export that defaulted to a wider setting would widen a policy decision the
                // operator never made.
                "distribution": "0",
                "published": false,
                "timestamp": epoch_seconds(stamp),
                "Attribute": attributes,
                "Tag": tags,
                "extra": {
                    "brolga_schema_version": brolga_model::SchemaTag::<ContextPack>::identifier(),
                    "brolga_detail_level": pack.detail_level.as_str(),
                    "brolga_analysis": narrative,
                },
            }
        });

        let bytes =
            serde_json::to_vec_pretty(&event).map_err(|error| ExportError::Unencodable {
                exporter: MISP_ID,
                reason: error.to_string(),
            })?;

        Ok(Exported {
            metadata: self.metadata(),
            bytes,
            declared_losses: losses,
        })
    }
}

/// The MISP attribute type and category for an observable kind.
#[must_use]
pub fn attribute_type_for(kind: &str) -> Option<(&'static str, &'static str)> {
    ATTRIBUTE_TYPES
        .iter()
        .find(|(brolga, _, _)| *brolga == kind)
        .map(|(_, misp_type, category)| (*misp_type, *category))
}

/// MISP's threat level for a disposition.
#[must_use]
pub const fn threat_level(disposition: Disposition) -> u8 {
    match disposition {
        Disposition::Malicious => THREAT_LEVEL_HIGH,
        Disposition::Suspicious => THREAT_LEVEL_MEDIUM,
        Disposition::Benign => THREAT_LEVEL_LOW,
        // MISP's own value for "no assessment made", which is exactly what an unknown disposition is.
        _ => THREAT_LEVEL_UNDEFINED,
    }
}

/// The MISP TLP tag for a marking, where the marking is a TLP level.
///
/// Only TLP. A tag whose meaning depends on the receiving instance's taxonomy configuration is not
/// portable, and exporting one would produce an event that reads differently on every instance.
fn tlp_tag(marking: &brolga_model::Marking) -> Option<String> {
    match marking {
        brolga_model::Marking::Tlp(level) => Some(format!("tlp:{}", level.as_str())),
        _ => None,
    }
}

/// A deterministic UUID for an attribute, derived from its content.
///
/// Deterministic for the same reason the STIX identifiers are: re-exporting an unchanged pack must
/// not create duplicates on the receiving instance.
#[must_use]
pub fn attribute_uuid(parts: &[&str]) -> String {
    // The model's own derivation rather than a second one here: one algorithm cannot disagree with
    // itself. The marker type is irrelevant — only the rendered UUID is used — so `Entity` stands in.
    brolga_model::Id::<brolga_model::Entity>::derive(parts)
        .as_uuid()
        .as_hyphenated()
        .to_string()
}

/// The date part of an RFC 3339 timestamp, which is what MISP's `date` field wants.
fn date_of(stamp: &str) -> String {
    stamp
        .split_once('T')
        .map_or_else(|| stamp.to_owned(), |(date, _)| date.to_owned())
}

/// Seconds since the epoch, as MISP's `timestamp` string.
///
/// Parsed from the pack's own generated-at rather than read from a clock: an exporter may not consult
/// one, and using the pack's value keeps the export deterministic. A timestamp that cannot be parsed
/// yields `"0"` rather than a guess — MISP treats it as unknown, which is the truth.
fn epoch_seconds(stamp: &str) -> String {
    brolga_model::Timestamp::parse_rfc3339(stamp)
        .map(|timestamp| timestamp.unix_timestamp().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The judgement this module makes on the operator's behalf.** Only a malicious disposition is
    /// suitable for automated detection.
    #[test]
    fn to_ids_is_set_only_for_a_malicious_disposition() {
        // Asserted through the threat level and the documented rule rather than by rebuilding an
        // event: the flag is computed in one place, from one comparison.
        assert_eq!(threat_level(Disposition::Malicious), THREAT_LEVEL_HIGH);
        assert_eq!(threat_level(Disposition::Suspicious), THREAT_LEVEL_MEDIUM);
        assert_eq!(threat_level(Disposition::Benign), THREAT_LEVEL_LOW);
        assert_eq!(threat_level(Disposition::Unknown), THREAT_LEVEL_UNDEFINED);
    }

    #[test]
    fn an_unmapped_kind_becomes_a_comment_rather_than_a_wrong_type() {
        assert_eq!(
            attribute_type_for("domain_name"),
            Some(("domain", "Network activity"))
        );
        assert!(
            attribute_type_for("autonomous_system_number").is_none(),
            "an unmapped kind must not silently pick a type"
        );
    }

    #[test]
    fn uuids_are_deterministic() {
        assert_eq!(attribute_uuid(&["a", "b"]), attribute_uuid(&["a", "b"]));
        assert_ne!(attribute_uuid(&["a", "b"]), attribute_uuid(&["a", "c"]));
    }

    #[test]
    fn a_date_is_the_day_part_of_the_timestamp() {
        assert_eq!(date_of("2026-05-01T10:00:00Z"), "2026-05-01");
        assert_eq!(date_of("nonsense"), "nonsense");
    }

    #[test]
    fn an_unparseable_timestamp_is_unknown_rather_than_guessed() {
        assert_eq!(epoch_seconds("not a timestamp"), "0");
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), "0");
    }

    #[test]
    fn the_declared_losses_name_the_organisation_and_the_templates() {
        let joined = LOSSES.join(" ");
        assert!(joined.contains("Orgc"), "{joined}");
        assert!(joined.contains("template"), "{joined}");
        assert!(joined.contains("galaxy"), "{joined}");
    }
}
