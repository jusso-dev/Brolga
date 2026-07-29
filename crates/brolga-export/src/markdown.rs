//! The human and agent exports: Markdown, plain text, and an agent brief.
//!
//! # Every narrative keeps its evidence references
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) requires that "human narratives retain
//! evidence references", and it is the acceptance criterion most easily satisfied badly — by putting
//! a footnote marker in the prose and the sources in an appendix nobody reads.
//!
//! So the citation is inline, next to the sentence it supports: every finding and every
//! recommendation is followed by the content addresses of the source objects behind it, abbreviated
//! for reading but exact enough to hand back to `brolga show`. A reader who disbelieves a sentence
//! can check it from the same line.
//!
//! The pack's own rule is that no finding may exist without evidence, enforced by
//! [`brolga_model::ContextPack::validated`], so there is no case where this writer has nothing to
//! cite. If there were, the pack would not have been built.
//!
//! # No template engine
//!
//! Every line here is written by Rust code. #54's security note prohibits template execution, and the
//! reason is not hypothetical: a template language is a program stored in a data file, evaluated in a
//! process holding an intelligence database, and the input to that program includes feed text.
//!
//! The cost is that changing the wording means changing this file. That is the correct cost.
//!
//! # Untrusted text is rendered, not interpreted
//!
//! A pack quotes feeds. Feed text reaches the output verbatim except that Markdown's active
//! characters are escaped, so a feed cannot inject a heading, a link, or an image into a report an
//! analyst pastes into a ticket. The plain-text writer needs no escaping and does none.
//!
//! # The agent brief is a different document, not a shorter one
//!
//! An agent reading a pack has a token budget and no eyes. It does not need section headings, blank
//! lines, or a table of contents; it needs the disposition first, the gaps stated plainly so it does
//! not hallucinate over them, and the handles it can expand. So [`AgentBriefExporter`] is ordered by
//! what changes an answer rather than by what reads well.

use brolga_model::ContextPack;
use brolga_model::pack::EvidenceRef;

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// Markdown.
pub const MARKDOWN_ID: ExporterId = ExporterId::new("brolga.export.markdown");

/// Plain text.
pub const TEXT_ID: ExporterId = ExporterId::new("brolga.export.text");

/// A dense brief for a language model.
pub const AGENT_ID: ExporterId = ExporterId::new("brolga.export.brief");

/// How many characters of a content address to show inline.
///
/// Enough to be unambiguous in one pack and short enough to read in a sentence. The full address is
/// always in the evidence section, so nothing is lost — this is a display choice.
pub const ADDRESS_PREFIX: usize = 16;

/// What a narrative export cannot carry.
pub const NARRATIVE_LOSSES: &[&str] = &[
    "the exact schema version and fingerprint, which appear as text rather than as parseable fields",
    "the budget accounting beyond a one-line summary",
    "machine-readable structure: prose is not a schema, and its wording may change in any release",
];

/// Markdown, for a person.
#[derive(Debug, Default, Clone, Copy)]
pub struct MarkdownExporter;

impl MarkdownExporter {
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

impl Exporter for MarkdownExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            MARKDOWN_ID,
            1,
            "text/markdown",
            "md",
            Orientation::Human,
            Lossiness::Narrative,
            "A report a person reads, with every assertion's evidence cited on the same line.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut out = String::new();

        out.push_str(&format!(
            "# {} `{}`\n\n",
            pack.subject.kind.as_str(),
            escape(pack.subject.value.as_str())
        ));
        out.push_str(&format!(
            "**Disposition: {}.** Detail level {}, produced for `{}`.\n\n",
            pack.disposition.as_str(),
            pack.detail_level.as_str(),
            escape(cleared.identity_name())
        ));
        if pack.policy.restricted {
            // First thing after the disposition, because a reader deciding whether to forward this
            // needs it before they read anything worth forwarding.
            out.push_str(
                "> **Restricted.** Material was withheld from this pack for policy reasons. See \
                 *What was left out* below.\n\n",
            );
        }
        if !pack.policy.markings.is_empty() {
            out.push_str(&format!("Handling: {}\n\n", escape(&markings_line(pack))));
        }

        section(&mut out, "Findings", pack.findings.is_empty(), |out| {
            for finding in &pack.findings {
                out.push_str(&format!(
                    "- **{}** — {} {}\n",
                    escape(finding.kind.as_str()),
                    escape(finding.statement.as_str()),
                    citation(&finding.evidence)
                ));
            }
        });

        section(
            &mut out,
            "Recommendations",
            pack.recommendations.is_empty(),
            |out| {
                for recommendation in &pack.recommendations {
                    out.push_str(&format!(
                        "- **{}** — {} {}\n",
                        escape(recommendation.action.as_str()),
                        escape(recommendation.rationale.as_str()),
                        citation(&recommendation.evidence)
                    ));
                }
            },
        );

        section(
            &mut out,
            "Contradictions",
            pack.graph.contradictions.is_empty(),
            |out| {
                for contradiction in &pack.graph.contradictions {
                    out.push_str(&format!(
                        "- **{}**: `{}` against `{}` {}\n",
                        escape(contradiction.subject.as_str()),
                        escape(contradiction.left.as_str()),
                        escape(contradiction.right.as_str()),
                        citation(&contradiction.evidence)
                    ));
                }
            },
        );

        section(
            &mut out,
            "What is connected",
            pack.graph.entities.is_empty() && pack.graph.claims.is_empty(),
            |out| {
                for entity in &pack.graph.entities {
                    out.push_str(&format!(
                        "- {} **{}** ({})\n",
                        escape(entity.kind.as_str()),
                        escape(entity.name.as_str()),
                        escape(entity.status.as_str())
                    ));
                }
                for claim in &pack.graph.claims {
                    let confidence = claim
                        .confidence
                        .map(|score| format!(", confidence {score}"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "- {} = `{}` ({}{}) {}\n",
                        escape(claim.predicate.as_str()),
                        escape(claim.object.as_str()),
                        escape(claim.status.as_str()),
                        escape(&confidence),
                        citation(&claim.evidence)
                    ));
                }
            },
        );

        if !pack.graph.techniques.is_empty() {
            out.push_str("## Techniques\n\n");
            let list: Vec<String> = pack
                .graph
                .techniques
                .iter()
                .map(|technique| format!("`{}`", escape(technique.as_str())))
                .collect();
            out.push_str(&format!("{}\n\n", list.join(", ")));
        }

        section(
            &mut out,
            "Where to look next",
            pack.graph.pivots.is_empty(),
            |out| {
                for pivot in &pack.graph.pivots {
                    out.push_str(&format!(
                        "- `{}` — {}\n",
                        escape(pivot.target.as_str()),
                        escape(pivot.reason.as_str())
                    ));
                }
            },
        );

        // Gaps and exclusions are not an appendix. A report that lists only what is known reads as
        // complete, and the whole design of a pack is that it refuses to.
        out.push_str("## What is not known\n\n");
        if pack.gaps.is_empty() {
            out.push_str("No gaps were recorded.\n\n");
        } else {
            for gap in &pack.gaps {
                out.push_str(&format!(
                    "- **{}** — {}\n",
                    escape(gap.subject.as_str()),
                    escape(gap.detail.as_str())
                ));
            }
            out.push('\n');
        }

        out.push_str("## What was left out\n\n");
        if pack.exclusions.is_empty() {
            out.push_str("Nothing was excluded.\n\n");
        } else {
            for exclusion in &pack.exclusions {
                let count = exclusion
                    .dropped
                    .map(|count| format!(" ({count} item(s))"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "- **{}** — {}{}\n",
                    escape(exclusion.category.as_str()),
                    escape(exclusion.reason.as_str()),
                    escape(&count)
                ));
            }
            out.push('\n');
        }

        if !pack.handles.is_empty() {
            out.push_str(&format!(
                "## Expandable\n\n{} handle(s) can be expanded to canonical records or original \
                 bytes, each a separate authorisation decision.\n\n",
                pack.handles.len()
            ));
        }

        out.push_str(&format!(
            "---\n\nPack `{}` (`{}`), fingerprint `{}`, generated {}.\n",
            escape(&schema_tag()),
            escape(pack.detail_level.as_str()),
            escape(&pack.fingerprint),
            escape(&pack.metadata.generated_at)
        ));

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: NARRATIVE_LOSSES.to_vec(),
        })
    }
}

/// Plain text, for a terminal or an email.
#[derive(Debug, Default, Clone, Copy)]
pub struct TextExporter;

impl TextExporter {
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

impl Exporter for TextExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            TEXT_ID,
            1,
            "text/plain",
            "txt",
            Orientation::Human,
            Lossiness::Narrative,
            "The same report without markup, for a terminal or an email body.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut out = String::new();

        out.push_str(&format!(
            "{} {}\n{}\n\n",
            pack.subject.kind.as_str(),
            pack.subject.value.as_str(),
            "=".repeat(pack.subject.kind.as_str().len() + pack.subject.value.as_str().len() + 1)
        ));
        out.push_str(&format!(
            "Disposition: {}\nDetail level: {}\nProduced for: {}\n",
            pack.disposition.as_str(),
            pack.detail_level.as_str(),
            cleared.identity_name()
        ));
        if pack.policy.restricted {
            out.push_str("RESTRICTED: material was withheld for policy reasons.\n");
        }
        if !pack.policy.markings.is_empty() {
            out.push_str(&format!("Handling: {}\n", markings_line(pack)));
        }
        out.push('\n');

        // No escaping: plain text has no active characters, and escaping it would corrupt the very
        // feed text a reader is trying to see.
        for (heading, lines) in [
            ("FINDINGS", finding_lines(pack)),
            ("RECOMMENDATIONS", recommendation_lines(pack)),
            ("NOT KNOWN", gap_lines(pack)),
            ("LEFT OUT", exclusion_lines(pack)),
        ] {
            out.push_str(&format!("{heading}\n"));
            if lines.is_empty() {
                out.push_str("  (none)\n");
            } else {
                for line in lines {
                    out.push_str(&format!("  {line}\n"));
                }
            }
            out.push('\n');
        }

        out.push_str(&format!(
            "Pack {} fingerprint {} generated {}\n",
            schema_tag(),
            pack.fingerprint,
            pack.metadata.generated_at
        ));

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: NARRATIVE_LOSSES.to_vec(),
        })
    }
}

/// A dense brief for a language model.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentBriefExporter;

impl AgentBriefExporter {
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

impl Exporter for AgentBriefExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            AGENT_ID,
            1,
            "text/plain",
            "txt",
            Orientation::Agent,
            Lossiness::Compressed,
            "A dense brief ordered by what changes an answer, for a model with a token budget.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut out = String::new();

        // Disposition first. It is the single fact most likely to change what the agent does.
        out.push_str(&format!(
            "SUBJECT {} {}\nDISPOSITION {}\nLEVEL {}\n",
            pack.subject.kind.as_str(),
            pack.subject.value.as_str(),
            pack.disposition.as_str(),
            pack.detail_level.as_str()
        ));

        // Gaps second, and this is deliberate. An agent that does not know what is missing fills the
        // hole with plausible text, and a confidently wrong answer about an indicator is worse than
        // an admitted gap. Putting them above the findings makes them impossible to skip.
        if pack.gaps.is_empty() {
            out.push_str("UNKNOWN none-recorded\n");
        } else {
            for gap in &pack.gaps {
                out.push_str(&format!(
                    "UNKNOWN {} :: {}\n",
                    gap.subject.as_str(),
                    gap.detail.as_str()
                ));
            }
        }
        if pack.policy.restricted {
            out.push_str("WITHHELD policy-restricted; this brief is not the whole picture\n");
        }

        for finding in &pack.findings {
            out.push_str(&format!(
                "FINDING {} :: {} :: {}\n",
                finding.kind.as_str(),
                finding.statement.as_str(),
                evidence_list(&finding.evidence)
            ));
        }
        for recommendation in &pack.recommendations {
            out.push_str(&format!(
                "ACTION {} :: {} :: {}\n",
                recommendation.action.as_str(),
                recommendation.rationale.as_str(),
                evidence_list(&recommendation.evidence)
            ));
        }
        for contradiction in &pack.graph.contradictions {
            out.push_str(&format!(
                "DISPUTED {} :: {} | {}\n",
                contradiction.subject.as_str(),
                contradiction.left.as_str(),
                contradiction.right.as_str()
            ));
        }
        for claim in &pack.graph.claims {
            out.push_str(&format!(
                "CLAIM {} = {}{}\n",
                claim.predicate.as_str(),
                claim.object.as_str(),
                claim
                    .confidence
                    .map(|score| format!(" (confidence {score})"))
                    .unwrap_or_default()
            ));
        }
        for technique in &pack.graph.techniques {
            out.push_str(&format!("TECHNIQUE {}\n", technique.as_str()));
        }
        for pivot in &pack.graph.pivots {
            out.push_str(&format!(
                "PIVOT {} :: {}\n",
                pivot.target.as_str(),
                pivot.reason.as_str()
            ));
        }
        // What it can ask for next, which is the difference between a compressed answer and a
        // truncated one.
        for handle in &pack.handles {
            out.push_str(&format!(
                "EXPANDABLE {} {}\n",
                handle.target_kind.as_str(),
                handle.target
            ));
        }

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: vec![
                "the pack's structure: this is a flat line-oriented brief, not a schema",
                "the budget report",
                "entity and relationship detail beyond the claims that mention them",
            ],
        })
    }
}

/// Write a heading, and say "none" rather than omitting an empty section.
///
/// An omitted section reads as an oversight; an explicit "none recorded" reads as an answer. The
/// difference matters most for the sections a reader is checking *for* absence.
fn section(out: &mut String, heading: &str, empty: bool, write: impl FnOnce(&mut String)) {
    out.push_str(&format!("## {heading}\n\n"));
    if empty {
        out.push_str("None recorded.\n\n");
        return;
    }
    write(out);
    out.push('\n');
}

/// Inline citation for a list of evidence.
fn citation(evidence: &[EvidenceRef]) -> String {
    if evidence.is_empty() {
        // Unreachable for a validated pack — `ContextPack::validated` refuses a finding with no
        // evidence — but stated rather than asserted, because a panic is not a way to render.
        return "*(no evidence recorded)*".to_owned();
    }
    let addresses: Vec<String> = evidence
        .iter()
        .map(|reference| format!("`{}`", abbreviate(&reference.source_object_id)))
        .collect();
    format!("[evidence: {}]", addresses.join(", "))
}

/// The same, unadorned, for the line-oriented writers.
fn evidence_list(evidence: &[EvidenceRef]) -> String {
    if evidence.is_empty() {
        return "no-evidence".to_owned();
    }
    evidence
        .iter()
        .map(|reference| abbreviate(&reference.source_object_id))
        .collect::<Vec<_>>()
        .join(",")
}

/// Shorten a content address for reading, keeping its algorithm prefix.
///
/// `sha256:0123456789abcdef…` rather than a bare truncation, so a reader can tell what it is and
/// still paste it into `brolga show` after expanding it from the pack.
fn abbreviate(address: &str) -> String {
    let (prefix, digest) = address.split_once(':').unwrap_or(("", address));
    let short: String = digest.chars().take(ADDRESS_PREFIX).collect();
    if prefix.is_empty() {
        short
    } else {
        format!("{prefix}:{short}")
    }
}

/// The pack schema tag, as text.
///
/// `SchemaTag` is a zero-sized marker whose value carries no data — the tag is a property of the
/// type — so it is read from the type rather than from the field.
fn schema_tag() -> String {
    brolga_model::SchemaTag::<ContextPack>::identifier()
}

/// The handling line, from the pack's markings.
///
/// Rendered from each marking's own vocabulary rather than through `Debug`, which would print
/// `Tlp(Green)` — a Rust type name in a document an analyst forwards.
fn markings_line(pack: &ContextPack) -> String {
    let mut parts: Vec<String> = pack.policy.markings.iter().map(marking_label).collect();
    if parts.is_empty() {
        parts.push("unmarked".to_owned());
    }
    parts.join(", ")
}

/// One marking, in the vocabulary its own standard uses.
#[must_use]
pub fn marking_label(marking: &brolga_model::Marking) -> String {
    match marking {
        brolga_model::Marking::Tlp(level) => format!("TLP:{}", level.as_str().to_uppercase()),
        // `PapLevel` has no `as_str`, so the variant name is uppercased. Not `Debug` on the whole
        // marking, which would print `Pap(Amber)`.
        brolga_model::Marking::Pap(level) => {
            format!("PAP:{}", format!("{level:?}").to_uppercase())
        }
        brolga_model::Marking::Handling(text) => format!("handling: {}", text.as_str()),
        brolga_model::Marking::Attribution(text) => format!("attribution: {}", text.as_str()),
        // A marking this build does not know reaches nobody by policy, and here it is named rather
        // than dropped: a reader must not think an unrecognised caveat was absent.
        _ => "an unrecognised handling caveat".to_owned(),
    }
}

fn finding_lines(pack: &ContextPack) -> Vec<String> {
    pack.findings
        .iter()
        .map(|finding| {
            format!(
                "{}: {} [evidence: {}]",
                finding.kind.as_str(),
                finding.statement.as_str(),
                evidence_list(&finding.evidence)
            )
        })
        .collect()
}

fn recommendation_lines(pack: &ContextPack) -> Vec<String> {
    pack.recommendations
        .iter()
        .map(|recommendation| {
            format!(
                "{}: {} [evidence: {}]",
                recommendation.action.as_str(),
                recommendation.rationale.as_str(),
                evidence_list(&recommendation.evidence)
            )
        })
        .collect()
}

fn gap_lines(pack: &ContextPack) -> Vec<String> {
    pack.gaps
        .iter()
        .map(|gap| format!("{}: {}", gap.subject.as_str(), gap.detail.as_str()))
        .collect()
}

fn exclusion_lines(pack: &ContextPack) -> Vec<String> {
    pack.exclusions
        .iter()
        .map(|exclusion| {
            format!(
                "{}: {}{}",
                exclusion.category.as_str(),
                exclusion.reason.as_str(),
                exclusion
                    .dropped
                    .map(|count| format!(" ({count})"))
                    .unwrap_or_default()
            )
        })
        .collect()
}

/// Escape Markdown's active characters.
///
/// A pack quotes feeds, and a feed must not be able to inject a heading, a link, an image, or a code
/// fence into a report an analyst pastes into a ticket. `<` and `>` go too, because Markdown passes
/// raw HTML through.
///
/// # What is deliberately *not* escaped, and why that is safe
///
/// `#`, `-`, `+`, and `.` are Markdown's **block** markers: they mean something only at the start of a
/// line. Escaping them everywhere makes an address render as `203\.0\.113\.42` and an identity as
/// `local\-operator`, which is unreadable — and unreadability in a human-facing report is a real cost,
/// not a cosmetic one.
///
/// They are safe to leave alone because **the newline is neutralised first**: every value reaches the
/// output on a line this writer began, so a feed cannot get a character into the first column. That is
/// the invariant the whole escaping scheme rests on, and it is why `\n` is handled here rather than
/// left to the caller.
#[must_use]
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            // Inline-active in any column: emphasis, code, links, images, tables, raw HTML.
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '<' | '>' => {
                out.push('\\');
                out.push(character);
            }
            // A newline inside a value would end the list item it sits in, turning one bullet into
            // two and attributing the second to nobody — and it is what would let a block marker
            // reach the first column. This is the load-bearing arm.
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** A feed cannot inject structure into a report.
    #[test]
    fn feed_text_cannot_inject_markdown_structure() {
        let hostile = "# Heading\n[click](http://attacker.invalid)\n![img](x)\n```code```";
        let escaped = escape(hostile);

        // The invariant is that no *inline-active* character is unescaped, and that no newline
        // survives — the second is what stops a block marker reaching the first column.
        for active in ['[', ']', '`', '*', '_', '<', '>', '|'] {
            assert!(
                !unescaped(&escaped, active),
                "`{active}` reached the output unescaped: {escaped}"
            );
        }
        assert!(
            !escaped.contains('\n') && !escaped.contains('\r'),
            "a newline would split a list item and let a `#` reach the first column: {escaped}"
        );
        // A link cannot form, because its brackets are escaped even though its parentheses are not.
        assert!(!escaped.contains("[click]"), "{escaped}");
    }

    /// Whether `needle` appears without a preceding backslash.
    fn unescaped(value: &str, needle: char) -> bool {
        let mut previous = None;
        for character in value.chars() {
            if character == needle && previous != Some('\\') {
                return true;
            }
            previous = Some(character);
        }
        false
    }

    #[test]
    fn raw_html_is_escaped_too() {
        let escaped = escape("<script>alert(1)</script>");
        assert!(!escaped.contains("<script>"), "{escaped}");
        assert!(!unescaped(&escaped, '<'), "{escaped}");
    }

    /// The readability half of the trade: an address and a hyphenated name come through intact.
    #[test]
    fn block_markers_are_left_alone_so_ordinary_values_stay_readable() {
        assert_eq!(escape("203.0.113.42"), "203.0.113.42");
        assert_eq!(escape("local-operator"), "local-operator");
        assert_eq!(escape("CVE-2021-44228"), "CVE-2021-44228");
    }

    #[test]
    fn markings_render_in_their_own_vocabulary_rather_than_as_rust() {
        use brolga_model::{Marking, TlpLevel};
        let label = marking_label(&Marking::Tlp(TlpLevel::Green));
        assert_eq!(label, "TLP:GREEN");
        assert!(!label.contains("Tlp("), "{label}");
    }

    #[test]
    fn an_address_keeps_its_algorithm_prefix_when_abbreviated() {
        let full = "sha256:0123456789abcdef0123456789abcdef";
        let short = abbreviate(full);
        assert!(short.starts_with("sha256:"), "{short}");
        assert!(short.len() < full.len(), "{short}");
        assert!(
            full.starts_with(&short),
            "the prefix must be a real prefix: {short}"
        );
    }

    #[test]
    fn an_address_with_no_prefix_still_abbreviates() {
        assert_eq!(abbreviate("abcdef"), "abcdef");
    }

    #[test]
    fn a_citation_lists_every_source_object() {
        let evidence = vec![
            EvidenceRef::new("sha256:aaaaaaaaaaaaaaaaaaaa"),
            EvidenceRef::new("sha256:bbbbbbbbbbbbbbbbbbbb"),
        ];
        let citation = citation(&evidence);
        assert!(citation.contains("sha256:aaaa"), "{citation}");
        assert!(citation.contains("sha256:bbbb"), "{citation}");
    }
}
