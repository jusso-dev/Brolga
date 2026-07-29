//! Graphviz DOT, for looking at a pack rather than reading it.
//!
//! # Derived, not lossy — and the distinction matters
//!
//! This is [`Lossiness::Derived`] rather than `PartiallyLossless`, because the difference is not that
//! fields were dropped. It is that fields were *invented*: a pack has no notion of a node shape, a
//! colour, or a layout, and this exporter chooses all three. A consumer must not read a red node as
//! something the intelligence said.
//!
//! What the colours mean is therefore documented as data, in [`DISPOSITION_COLOUR`], so a reader can
//! check the legend against the code.
//!
//! # DOT is a language, and a feed must not be able to write in it
//!
//! A node label goes inside quotes in the DOT source. A feed-supplied value containing a quote closes
//! the label, and everything after it is parsed as DOT — which can add nodes, add edges, or set
//! attributes including ones that make `dot` read a file.
//!
//! So every label is escaped: backslash and quote are escaped, and a newline becomes `\n` inside the
//! literal rather than a real line break. `escape_label` is the only way a value reaches the output,
//! and `a_feed_cannot_inject_dot_syntax` is the test that says so.
//!
//! # Identifiers are indices, not values
//!
//! Node names are `n0`, `n1`, `n2`. Not the entity identifiers, and definitely not the values —
//! because a DOT node name has its own lexical rules, and deriving one from untrusted text is a second
//! injection surface for no benefit. The value appears in the *label*, which is quoted and escaped.

use std::collections::BTreeMap;

use brolga_model::Disposition;

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// This exporter's identifier.
pub const DOT_ID: ExporterId = ExporterId::new("brolga.export.dot");

/// The colour each disposition is drawn in.
///
/// Documented as data so the legend a reader sees and the code that draws it cannot disagree. These
/// are a rendering choice and carry no meaning the intelligence asserted.
pub const DISPOSITION_COLOUR: &[(&str, &str)] = &[
    ("malicious", "#c62828"),
    ("suspicious", "#ef6c00"),
    ("benign", "#2e7d32"),
    ("unknown", "#616161"),
];

/// The colour an entity node is drawn in.
pub const ENTITY_COLOUR: &str = "#1565c0";

/// The colour a technique node is drawn in.
pub const TECHNIQUE_COLOUR: &str = "#6a1b9a";

/// The colour a pivot node is drawn in.
pub const PIVOT_COLOUR: &str = "#00838f";

/// Most nodes drawn.
///
/// A graph beyond this is unreadable rather than informative, and the omission is declared. Rendering
/// ten thousand nodes produces an image nobody can use and a `dot` process that takes minutes.
pub const MAX_NODES: usize = 500;

/// What DOT invents or omits, declared.
pub const LOSSES: &[&str] = &[
    "node shapes and colours are this exporter's choices, not statements the intelligence made",
    "evidence references: a DOT graph has nowhere to cite a source object",
    "claim confidence, status, and the pack's findings and recommendations",
    "the budget report, the gaps, and the exclusions",
    "layout: the arrangement is Graphviz's, and it carries no meaning",
];

/// A Graphviz DOT writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct DotExporter;

impl DotExporter {
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

impl Exporter for DotExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            DOT_ID,
            1,
            "text/vnd.graphviz",
            "dot",
            Orientation::Human,
            Lossiness::Derived,
            "A Graphviz graph of the pack's neighbourhood. Shapes and colours are this exporter's.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut out = String::new();
        let mut losses: Vec<&'static str> = LOSSES.to_vec();

        out.push_str("digraph brolga {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [style=filled, fontname=\"sans-serif\", fontcolor=\"#ffffff\"];\n");
        out.push_str("  edge [fontname=\"sans-serif\", fontsize=10];\n\n");

        // The subject, drawn distinctly because everything else is positioned relative to it.
        let subject_colour = colour_for(pack.disposition);
        out.push_str(&format!(
            "  n0 [label=\"{}\\n{}\", shape=doubleoctagon, fillcolor=\"{}\"];\n",
            escape_label(pack.subject.value.as_str()),
            escape_label(pack.subject.kind.as_str()),
            subject_colour
        ));

        // Node names are indices, never derived from untrusted text. See the module documentation.
        let mut next = 1usize;
        let mut names: BTreeMap<String, String> = BTreeMap::new();
        let mut truncated = false;

        for entity in &pack.graph.entities {
            if next > MAX_NODES {
                truncated = true;
                break;
            }
            let name = format!("n{next}");
            next = next.saturating_add(1);
            out.push_str(&format!(
                "  {name} [label=\"{}\\n{}\", shape=box, fillcolor=\"{ENTITY_COLOUR}\"];\n",
                escape_label(entity.name.as_str()),
                escape_label(entity.kind.as_str())
            ));
            names.insert(entity.id.clone(), name.clone());
            out.push_str(&format!("  n0 -> {name} [label=\"related\"];\n"));
        }

        for technique in &pack.graph.techniques {
            if next > MAX_NODES {
                truncated = true;
                break;
            }
            let name = format!("n{next}");
            next = next.saturating_add(1);
            out.push_str(&format!(
                "  {name} [label=\"{}\", shape=hexagon, fillcolor=\"{TECHNIQUE_COLOUR}\"];\n",
                escape_label(technique.as_str())
            ));
            out.push_str(&format!("  n0 -> {name} [label=\"indicates\"];\n"));
        }

        for pivot in &pack.graph.pivots {
            if next > MAX_NODES {
                truncated = true;
                break;
            }
            let name = format!("n{next}");
            next = next.saturating_add(1);
            out.push_str(&format!(
                "  {name} [label=\"{}\", shape=ellipse, style=\"filled,dashed\", \
                 fillcolor=\"{PIVOT_COLOUR}\"];\n",
                escape_label(pivot.target.as_str())
            ));
            out.push_str(&format!(
                "  n0 -> {name} [label=\"pivot\", style=dashed];\n"
            ));
        }

        // Relationships between nodes the graph already holds. An edge to a node that was not drawn is
        // skipped rather than creating a mystery node with no label.
        out.push('\n');
        for relationship in &pack.graph.relationships {
            let (Some(source), Some(target)) = (
                names.get(&relationship.source),
                names.get(&relationship.target),
            ) else {
                continue;
            };
            out.push_str(&format!(
                "  {source} -> {target} [label=\"{}\"];\n",
                escape_label(relationship.kind.as_str())
            ));
        }

        if truncated {
            losses.push("nodes beyond the drawing limit; a graph that large is unreadable rather than informative");
            out.push_str(&format!(
                "\n  truncated [label=\"more than {MAX_NODES} nodes; graph truncated\", \
                 shape=note, fillcolor=\"#424242\"];\n"
            ));
        }

        // The legend, so a reader is not left inferring what a colour means. It is a subgraph so
        // Graphviz keeps it out of the main layout.
        out.push_str("\n  subgraph cluster_legend {\n");
        out.push_str("    label=\"legend (a rendering choice, not intelligence)\";\n");
        out.push_str("    fontname=\"sans-serif\";\n");
        out.push_str("    node [shape=plaintext, fillcolor=\"#ffffff\", fontcolor=\"#000000\"];\n");
        for (index, (name, colour)) in DISPOSITION_COLOUR.iter().enumerate() {
            out.push_str(&format!(
                "    legend{index} [label=\"{name}\", fontcolor=\"{colour}\"];\n"
            ));
        }
        out.push_str("  }\n");

        out.push_str("}\n");

        Ok(Exported {
            metadata: self.metadata(),
            bytes: out.into_bytes(),
            declared_losses: losses,
        })
    }
}

/// The colour for a disposition.
#[must_use]
pub fn colour_for(disposition: Disposition) -> &'static str {
    DISPOSITION_COLOUR
        .iter()
        .find(|(name, _)| *name == disposition.as_str())
        .map_or("#616161", |(_, colour)| *colour)
}

/// Escape a value for a DOT quoted label.
///
/// The only route by which a value reaches the output. A quote would close the label and let a feed
/// write DOT; a real newline would end the statement.
#[must_use]
pub fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // `\n` as two characters inside the literal, which Graphviz renders as a line break —
            // rather than a real newline, which would end the statement.
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** A feed cannot write DOT.
    #[test]
    fn a_feed_cannot_inject_dot_syntax() {
        let hostile = "x\", shape=none]; evil [label=\"pwned\"]; a -> b [label=\"";
        let escaped = escape_label(hostile);

        // The invariant is not "the output contains no DOT-looking text" — `]; evil [` inside a
        // quoted label is harmless. It is that **no quote is unescaped**, because an unescaped quote
        // is the only way to leave the label and reach the parser.
        assert_eq!(
            escaped.matches("\\\"").count(),
            hostile.matches('"').count(),
            "a quote reached the output unescaped: {escaped}"
        );
        assert!(
            !unescaped_quote(&escaped),
            "an unescaped quote would close the label: {escaped}"
        );
    }

    /// Whether a string holds a `"` that is not preceded by a `\`.
    ///
    /// The property that decides whether a label can be escaped from: counting quotes is not enough,
    /// because `\\"` is an escaped backslash followed by a live quote.
    fn unescaped_quote(value: &str) -> bool {
        let mut backslashes = 0usize;
        for character in value.chars() {
            match character {
                '\\' => backslashes = backslashes.saturating_add(1),
                '"' if backslashes.is_multiple_of(2) => return true,
                _ => backslashes = 0,
            }
        }
        false
    }

    #[test]
    fn a_newline_becomes_a_label_break_rather_than_a_statement_break() {
        let escaped = escape_label("one\ntwo");
        assert_eq!(escaped, "one\\ntwo");
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn a_backslash_cannot_escape_the_closing_quote() {
        // `x\` would otherwise become `"x\"` — a label whose closing quote is escaped, swallowing the
        // rest of the file.
        assert_eq!(escape_label("x\\"), "x\\\\");
    }

    #[test]
    fn every_disposition_has_a_colour_and_an_unknown_one_falls_back() {
        for (name, colour) in DISPOSITION_COLOUR {
            assert!(colour.starts_with('#'), "{name} has no hex colour");
        }
        assert_eq!(colour_for(Disposition::Malicious), "#c62828");
        assert_eq!(colour_for(Disposition::Unknown), "#616161");
    }

    #[test]
    fn the_declared_losses_say_the_colours_are_not_intelligence() {
        let joined = LOSSES.join(" ");
        assert!(
            joined.contains("not statements the intelligence made"),
            "{joined}"
        );
        assert!(joined.contains("evidence"), "{joined}");
    }
}
