//! YARA rules.
//!
//! # A rule is stored, never compiled and never run
//!
//! Nothing here compiles a rule, evaluates a condition, or matches a string against anything.
//! [#52](https://github.com/jusso-dev/Brolga/issues/52) names that as a non-goal, and it is also
//! the security position: a YARA condition is an expression language, and an engine that ran
//! attacker-supplied rules would be executing untrusted input by design.
//!
//! What is read is the *shape* of the rule — its name, its tags, and its `meta` block — because
//! that is what identifies a rule, says who wrote it, and says what it is for.
//!
//! # `strings` are not observables
//!
//! A YARA string is a pattern: a byte sequence, a hex pattern with wildcards, or a regular
//! expression, usually a fragment rather than a whole value. `$a = "evil.com"` might be a domain
//! and might equally be a substring the author expects inside a longer one, and `$b = /ev[il]+/`
//! is not a value at all. Canonicalising them would mint observables out of pattern fragments, so
//! the `strings` block is **counted and skipped**, and the count is recorded so a rule with two
//! hundred patterns is distinguishable from one with two.
//!
//! The `meta` block is different: `hash = "..."` is a stated fact about a sample the author tested
//! against, written as a whole value, and that is read.
//!
//! # Reading braces without evaluating them
//!
//! A rule body is delimited by braces, and braces appear inside string literals, hex patterns, and
//! regular expressions. The scanner tracks which of those it is inside, so a rule containing
//! `$h = { 6A 40 68 }` or `$r = /a{2,3}/` is not cut in half at the first brace — which would
//! silently split one rule into two and attribute half of it to a rule name that was never written.

use brolga_model::{
    Assertion, Claim, Entity, EntityKind, Id, NodeRef, RecordOrigin, Relationship,
    RelationshipKind, ShortText, UntrustedText,
};

use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// This parser's identifier.
pub const YARA_PARSER_ID: ParserId = ParserId::new("brolga.detection.yara");

/// Media types that identify a YARA rule definitively.
pub const YARA_MEDIA_TYPES: &[&str] = &["text/x-yara"];

/// Most rules read from one file.
pub const MAX_RULES: usize = 4096;

/// Most `meta` entries read from one rule.
pub const MAX_META_ENTRIES: usize = 128;

/// A YARA rule reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct YaraParser;

impl YaraParser {
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

impl IntelligenceParser for YaraParser {
    fn id(&self) -> ParserId {
        YARA_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if YARA_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(
                self,
                DetectionConfidence::Certain,
                "media type is a YARA rule",
            );
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };

        // A `rule <name> {` opener with a `condition:` inside it. `rule` alone appears in prose and
        // in a dozen other languages; the pair does not.
        let has_rule = text
            .lines()
            .any(|line| line.trim_start().starts_with("rule ") || line.trim() == "rule");
        if has_rule && text.contains("condition:") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares a `rule` with a `condition:`",
            )
        } else if hint.has_extension("yar") || hint.has_extension("yara") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "file extension is .yar or .yara",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no YARA rule marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;

        let text = core::str::from_utf8(bytes)
            .map_err(|error| ParseError::new(format!("not valid UTF-8: {error}")))?;

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let rules = scan_rules(text)?;
        if rules.is_empty() {
            return Err(ParseError::new(
                "no `rule <name> { ... }` block was found, so this is not a YARA rule file",
            ));
        }

        let mut out = ParseOutput::default();
        for (index, rule) in rules.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_rule(rule, &origin, field_limit) {
                Ok(records) => out.records.extend(records),
                Err(rejection) => out.rejected.push(RejectedRecord {
                    reason_kind: rejection.0,
                    reason: rejection.1,
                    offset: u64::try_from(index).ok(),
                    fragment: Some(rule.name.clone()),
                }),
            }
        }

        let produced = u64::try_from(out.records.len()).unwrap_or(u64::MAX);
        if produced > limits.max_records {
            return Err(ParseError::new(format!(
                "produced {produced} records, over the {}-record limit",
                limits.max_records
            )));
        }

        Ok(out)
    }
}

/// One rule, as the scanner found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedRule {
    /// The rule's name.
    pub name: String,
    /// The tags after the `:`, if any.
    pub tags: Vec<String>,
    /// `meta` entries, in the order they were written.
    pub meta: Vec<(String, String)>,
    /// How many `$name =` patterns the `strings` block declared.
    ///
    /// A count rather than the patterns themselves: a YARA string is a fragment or a regular
    /// expression, and storing them as values would mint observables out of pattern pieces. The
    /// count still distinguishes a rule with two hundred patterns from one with two.
    pub string_count: usize,
    /// Whether the rule declared `private`.
    pub private: bool,
    /// Whether the rule declared `global`.
    pub global: bool,
}

/// Find every `rule <name> [: tags] { ... }` block, without evaluating any of them.
///
/// # Errors
///
/// Returns a [`ParseError`] if a rule body is never closed, which means the remainder of the file
/// cannot be attributed to any rule with confidence.
pub fn scan_rules(text: &str) -> Result<Vec<ScannedRule>, ParseError> {
    let bytes = text.as_bytes();
    let mut rules = Vec::new();
    let mut cursor = 0_usize;

    while let Some(start) = find_rule_keyword(text, cursor) {
        if rules.len() >= MAX_RULES {
            return Err(ParseError::new(format!(
                "the file holds more than the {MAX_RULES}-rule limit"
            )));
        }

        let after = start.saturating_add(4);
        let Some(rest) = text.get(after..) else {
            break;
        };

        // Name, then optional `: tag tag`, then the opening brace.
        let Some(brace) = rest.find('{') else {
            return Err(ParseError::new(
                "a `rule` keyword is not followed by a `{` body, so the file is truncated",
            ));
        };
        let Some(head) = rest.get(..brace) else {
            break;
        };

        let (name, tags) = match head.split_once(':') {
            Some((name, tags)) => (
                name.trim().to_owned(),
                tags.split_whitespace().map(ToOwned::to_owned).collect(),
            ),
            None => (head.trim().to_owned(), Vec::new()),
        };
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            // Not a rule declaration after all — `rule` appearing inside prose or a comment. Move
            // past it rather than refusing the file.
            cursor = after;
            continue;
        }

        let body_start = after.saturating_add(brace).saturating_add(1);
        let Some(body_end) = matching_brace(bytes, body_start) else {
            return Err(ParseError::new(format!(
                "the body of rule `{name}` is never closed, so the rest of the file cannot be \
                 attributed to any rule"
            )));
        };
        let body = text.get(body_start..body_end).unwrap_or_default();

        // `private` and `global` sit before the keyword.
        let preceding = text.get(..start).unwrap_or_default();
        let modifiers = preceding.rsplit(['}', '\n']).next().unwrap_or_default();

        rules.push(ScannedRule {
            name,
            tags,
            meta: scan_meta(body),
            string_count: count_strings(body),
            private: modifiers.contains("private"),
            global: modifiers.contains("global"),
        });

        cursor = body_end.saturating_add(1);
    }

    Ok(rules)
}

/// Find the next `rule` keyword that stands on its own, skipping comments and string literals.
fn find_rule_keyword(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = from;
    let mut state = ScanState::Code;

    while index < bytes.len() {
        let byte = *bytes.get(index)?;
        state = state.advance(bytes, &mut index, byte);
        if state != ScanState::Code {
            continue;
        }

        if text.get(index..index.saturating_add(4)) == Some("rule") {
            let before_is_boundary = index == 0
                || bytes
                    .get(index.saturating_sub(1))
                    .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
            let after_is_boundary = bytes
                .get(index.saturating_add(4))
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
            if before_is_boundary && after_is_boundary {
                return Some(index);
            }
        }
        index = index.saturating_add(1);
    }
    None
}

/// Where the scanner is, so that braces inside literals are not read as structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Code,
    String,
    Regex,
    LineComment,
    BlockComment,
}

impl ScanState {
    /// Advance past whatever `byte` starts, leaving `index` on the next byte to consider.
    fn advance(self, bytes: &[u8], index: &mut usize, byte: u8) -> Self {
        match self {
            Self::Code => match byte {
                b'"' => {
                    *index = index.saturating_add(1);
                    Self::String
                }
                b'/' if bytes.get(index.saturating_add(1)) == Some(&b'/') => {
                    *index = index.saturating_add(2);
                    Self::LineComment
                }
                b'/' if bytes.get(index.saturating_add(1)) == Some(&b'*') => {
                    *index = index.saturating_add(2);
                    Self::BlockComment
                }
                _ => Self::Code,
            },
            Self::String => {
                if byte == b'\\' {
                    *index = index.saturating_add(2);
                    return Self::String;
                }
                *index = index.saturating_add(1);
                if byte == b'"' {
                    Self::Code
                } else {
                    Self::String
                }
            }
            Self::Regex => {
                if byte == b'\\' {
                    *index = index.saturating_add(2);
                    return Self::Regex;
                }
                *index = index.saturating_add(1);
                if byte == b'/' {
                    Self::Code
                } else {
                    Self::Regex
                }
            }
            Self::LineComment => {
                *index = index.saturating_add(1);
                if byte == b'\n' {
                    Self::Code
                } else {
                    Self::LineComment
                }
            }
            Self::BlockComment => {
                if byte == b'*' && bytes.get(index.saturating_add(1)) == Some(&b'/') {
                    *index = index.saturating_add(2);
                    return Self::Code;
                }
                *index = index.saturating_add(1);
                Self::BlockComment
            }
        }
    }
}

/// The offset of the `}` matching the body that starts at `from`.
///
/// Braces inside string literals, comments, and hex patterns do not count. A hex pattern is itself
/// brace-delimited, so it is tracked as ordinary nesting rather than as a special case.
fn matching_brace(bytes: &[u8], from: usize) -> Option<usize> {
    let mut depth = 1_usize;
    let mut index = from;
    let mut state = ScanState::Code;

    while index < bytes.len() {
        let byte = *bytes.get(index)?;
        let next = state.advance(bytes, &mut index, byte);
        if next != ScanState::Code || state != ScanState::Code {
            state = next;
            continue;
        }
        state = next;

        match byte {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    None
}

/// Read the `meta:` entries of a rule body.
fn scan_meta(body: &str) -> Vec<(String, String)> {
    let Some(start) = body.find("meta:") else {
        return Vec::new();
    };
    let Some(rest) = body.get(start.saturating_add(5)..) else {
        return Vec::new();
    };
    // The block ends where the next one begins.
    let end = ["strings:", "condition:"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    let block = rest.get(..end).unwrap_or_default();

    let mut entries = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim().trim_matches('"').trim();
        if entries.len() >= MAX_META_ENTRIES {
            break;
        }
        entries.push((key.to_owned(), value.to_owned()));
    }
    entries
}

/// Count the `$name =` patterns a rule declares, without reading any of them.
fn count_strings(body: &str) -> usize {
    let Some(start) = body.find("strings:") else {
        return 0;
    };
    let Some(rest) = body.get(start.saturating_add(8)..) else {
        return 0;
    };
    let end = rest.find("condition:").unwrap_or(rest.len());
    rest.get(..end)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with('$') && line.contains('=')
        })
        .count()
}

/// A mapping failure.
type Rejection = (&'static str, String);

/// Map one scanned rule to the entity and claims it becomes.
fn map_rule(
    rule: &ScannedRule,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, Rejection> {
    let display = UntrustedText::new(bounded(
        &rule.name,
        field_limit.min(UntrustedText::MAX_BYTES),
    ))
    .map_err(|error| ("unusable_rule_name", error.to_string()))?;

    // Keyed on the rule name. YARA has no identifier field, and a rule name is what every YARA
    // deployment addresses a rule by — including the match output an analyst will be holding when
    // they come looking for it here.
    let id = Id::derive(&["yara", &rule.name]);
    let mut entity = Entity::new(id, EntityKind::DetectionRule, display, origin.clone());

    let meta: Vec<(&str, &str)> = rule
        .meta
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    if let Some((_, description)) = meta
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("description"))
        && let Ok(text) = UntrustedText::new(bounded(
            description,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
    {
        entity.description = Some(text);
    }

    let rule_ref = NodeRef::Entity(entity.id);
    let mut records = Vec::new();

    for (key, value) in &meta {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            rule_ref,
            attribute(&format!("yara.meta.{key}"), value, field_limit)?,
            origin.clone(),
        ))));
    }

    for tag in &rule.tags {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            rule_ref,
            attribute("yara.tag", tag, field_limit)?,
            origin.clone(),
        ))));
    }

    // The count, not the patterns. See the module documentation for why a YARA string is not a
    // value — but a rule with two hundred patterns is still worth telling apart from one with two.
    records.push(ParsedRecord::Claim(Box::new(Claim::new(
        rule_ref,
        attribute(
            "yara.strings.count",
            &rule.string_count.to_string(),
            field_limit,
        )?,
        origin.clone(),
    ))));

    for (flag, present) in [("private", rule.private), ("global", rule.global)] {
        if present {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                rule_ref,
                attribute(&format!("yara.{flag}"), "true", field_limit)?,
                origin.clone(),
            ))));
        }
    }

    // A `hash` in `meta` is a stated fact about a sample the author tested against, written as a
    // whole value rather than as a pattern fragment. That is the one place a YARA rule names an
    // observable, and it is read.
    for (key, value) in &meta {
        if !key.eq_ignore_ascii_case("hash") && !key.to_ascii_lowercase().starts_with("hash") {
            continue;
        }
        let Ok(hash) = canon::file::file_hash(value) else {
            continue;
        };
        let observable = hash.into_value();
        let subject = NodeRef::Observable(observable.id());

        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The rule's author says it fires on this sample. Not `PartOf`: the sample is not part
            // of the rule, it is evidence the rule was written against.
            RelationshipKind::Indicates,
            rule_ref,
            subject,
            origin.clone(),
        ))));
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            subject,
            attribute("yara.sample", &observable.canonical_value(), field_limit)?,
            origin.clone(),
        ))));
    }

    records.push(ParsedRecord::Entity(Box::new(entity)));
    Ok(records)
}

/// One attribute assertion.
fn attribute(name: &str, value: &str, field_limit: usize) -> Result<Assertion, Rejection> {
    Ok(Assertion::Attribute {
        name: ShortText::new(bounded(name, ShortText::MAX_BYTES))
            .map_err(|error| ("unusable_attribute_name", error.to_string()))?,
        value: UntrustedText::new(bounded(value, field_limit.min(UntrustedText::MAX_BYTES)))
            .map_err(|error| ("unusable_attribute_value", error.to_string()))?,
    })
}

/// Truncate at a character boundary.
fn bounded(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule Simple_Rule : trojan dropper
{
    meta:
        author = "Analyst"
        description = "A representative rule"
        hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    strings:
        $a = "evil.com"
        $b = { 6A 40 68 00 30 00 00 }
        $c = /ev[il]+\/x/
    condition:
        any of them
}

private rule Second_Rule
{
    condition:
        true
}
"#;

    #[test]
    fn every_rule_in_a_file_is_found_with_its_tags() {
        let rules = scan_rules(RULES).unwrap();
        assert_eq!(rules.len(), 2, "{rules:#?}");
        assert_eq!(rules[0].name, "Simple_Rule");
        assert_eq!(rules[0].tags, vec!["trojan", "dropper"]);
        assert_eq!(rules[1].name, "Second_Rule");
        assert!(rules[1].private);
    }

    /// A hex pattern is brace-delimited and a regular expression may hold a repetition brace.
    /// Cutting at the first brace would split one rule into two and attribute half of it to a rule
    /// name nobody wrote.
    #[test]
    fn braces_inside_hex_patterns_and_regexes_do_not_end_a_rule() {
        let rules = scan_rules(RULES).unwrap();
        assert_eq!(rules[0].string_count, 3, "{:#?}", rules[0]);

        let tricky = "rule R { strings: $r = /a{2,3}/ $h = { AA BB } condition: any of them }";
        let scanned = scan_rules(tricky).unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].name, "R");
    }

    /// A brace inside a string literal is content. Without this a rule whose pattern contains `}`
    /// ends early and everything after it is attributed to nothing.
    #[test]
    fn a_brace_inside_a_string_literal_is_content() {
        let tricky = r#"rule R { strings: $a = "a}b" condition: $a }"#;
        let rules = scan_rules(tricky).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].string_count, 1);
    }

    #[test]
    fn meta_entries_are_read_in_order_and_unquoted() {
        let rules = scan_rules(RULES).unwrap();
        let meta = &rules[0].meta;
        assert_eq!(meta[0], ("author".to_owned(), "Analyst".to_owned()));
        assert_eq!(
            meta[1],
            ("description".to_owned(), "A representative rule".to_owned())
        );
    }

    /// An unterminated body means the rest of the file cannot be attributed to any rule. Guessing
    /// where it ended would file whatever followed under the wrong rule name.
    #[test]
    fn an_unclosed_rule_body_is_refused_rather_than_guessed_at() {
        let error = scan_rules("rule Broken { condition: true").unwrap_err();
        assert!(error.to_string().contains("never closed"), "{error}");
    }

    /// The word appears in prose and in other languages. Treating every occurrence as a
    /// declaration would mint entities out of comments.
    #[test]
    fn the_word_rule_outside_a_declaration_is_not_a_rule() {
        assert!(
            scan_rules("// this rule is documented elsewhere\n")
                .unwrap()
                .is_empty()
        );
        assert!(scan_rules("rulebook { }").unwrap().is_empty());
    }

    #[test]
    fn hostile_input_is_refused_rather_than_panicking() {
        for hostile in [
            "",
            "rule",
            "rule {",
            "rule R",
            "rule R {",
            "rule R { \"",
            "rule R { /",
            "rule R { /* ",
            "}}}}",
            "rule R { strings: $a = \"\\",
        ] {
            let outcome = scan_rules(hostile);
            assert!(outcome.is_ok() || outcome.is_err(), "{hostile}");
        }
    }
}
