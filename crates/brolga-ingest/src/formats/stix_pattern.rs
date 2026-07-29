//! STIX patterning expressions, for the narrow subset Brolga can represent.
//!
//! # Why this refuses far more than it accepts
//!
//! A STIX `indicator` carries its observables inside a `pattern`, and the patterning language is a
//! whole expression grammar: boolean operators, comparison operators other than equality, set
//! membership, regular-expression matching, observation qualifiers, and object paths with indices
//! and dereferences. Brolga's canonical model holds *one observable per claim*, and there is no
//! honest way to represent most of that grammar in it.
//!
//! So this module maps one shape — a single bracketed observation expression holding `=`
//! comparisons against object paths Brolga has canonicalisers for, joined by `OR` if there is more
//! than one — and returns an error naming the construct for everything else.
//!
//! **Partial extraction is the failure mode this exists to prevent.** Pulling `1.2.3.4` out of
//! `[ipv4-addr:value = '1.2.3.4' AND network-traffic:dst_port = 4444]` produces a claim about the
//! address alone, which is a *broader* statement than the indicator made — the publisher asserted
//! the pair, not the address. `AND` is therefore refused whole, and so is any expression this
//! module cannot represent in full. Half a pattern is worse than none, because a quarantined
//! indicator is visible in the diagnostics and a silently widened one is indistinguishable from
//! intelligence.
//!
//! # `OR` is represented, with its hedge attached
//!
//! A disjunction is the one boolean form that fans out. `[a OR b]` becomes an observable for `a`
//! and an observable for `b`, because a disjunctive indicator is overwhelmingly how feeds publish a
//! list — a set of C2 addresses under one assessment — and refusing them would leave most of a
//! STIX feed unread.
//!
//! It is still a *widening*: the publisher said one of these matched, and Brolga records a claim
//! about each. That is a deliberate trade, and the information needed to weigh it is kept rather
//! than discarded — every claim carries the whole pattern text and the count of alternatives it
//! came from, so a consumer can tell a lone assertion from one alternative out of fifty. Nothing
//! downstream has to reconstruct what the publisher hedged.

use core::fmt;

use brolga_model::observable::{HashAlgorithm, Observable};

use crate::canon;

/// Longest pattern scanned.
///
/// Checked before tokenising, so a pathological pattern is refused rather than walked. Comfortably
/// above any pattern that maps to a single comparison.
pub const MAX_PATTERN_BYTES: usize = 4096;

/// The patterning language Brolga reads, as spelled in an indicator's `pattern_type`.
pub const STIX_PATTERN_TYPE: &str = "stix";

/// Most alternatives accepted from one disjunction.
///
/// Every alternative becomes its own set of claims, so a disjunction is a record-amplification
/// shape as well as a hedge. The bound is generous for a published address list and small enough
/// that one object cannot make thousands of records. Over it the pattern is refused whole rather
/// than truncated — a truncated disjunction is exactly the partial extraction this module refuses.
pub const MAX_ALTERNATIVES: usize = 64;

/// Why a pattern could not be represented.
///
/// Carries the offending construct separately from the sentence, so a caller can quarantine with a
/// reason that names it rather than with a generic "could not parse".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    construct: String,
    detail: String,
}

impl PatternError {
    fn new(construct: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            construct: construct.into(),
            detail: detail.into(),
        }
    }

    /// The construct that was not understood.
    #[must_use]
    pub fn construct(&self) -> &str {
        &self.construct
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Every observable a pattern asserts, or an error naming why it holds none Brolga can read.
///
/// One entry for a plain comparison, one per alternative for a disjunction. Duplicated
/// alternatives collapse — a publisher who wrote the same address twice named one address — and
/// order follows the pattern, so the result is deterministic.
///
/// Never empty on success: a pattern that named nothing is an error, not an empty vector, so a
/// caller cannot silently treat "understood, asserts nothing" as "understood".
///
/// # Errors
///
/// [`PatternError`] whenever the pattern is anything other than one bracketed observation
/// expression of `=` comparisons joined by `OR`, against supported object paths whose values
/// canonicalise.
pub fn observables_of(pattern: &str) -> Result<Vec<Observable>, PatternError> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(PatternError::new(
            "an over-long pattern",
            format!(
                "the pattern is {} bytes, over the {MAX_PATTERN_BYTES}-byte limit, and is not \
                 scanned",
                pattern.len()
            ),
        ));
    }

    let tokens = tokenize(pattern)?;
    let comparisons = comparisons_of(&tokens)?;

    let mut observables: Vec<Observable> = Vec::with_capacity(comparisons.len());
    for (path, value) in &comparisons {
        let observable = observable_of_comparison(path, value)?;
        // Deduplicated by identity rather than by spelling: two alternatives that canonicalise to
        // one observable *are* one alternative, and counting them twice would overstate the hedge
        // the caller records alongside the claims.
        if !observables
            .iter()
            .any(|existing| existing.id() == observable.id())
        {
            observables.push(observable);
        }
    }

    Ok(observables)
}

/// A lexical token of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// `[`
    Open,
    /// `]`
    Close,
    /// A single-quoted string literal, unescaped.
    Quoted(String),
    /// A bare run of path characters.
    Word(String),
    /// A reserved word of the patterning language, upper-cased.
    Keyword(String),
    /// An operator or punctuation character.
    Symbol(String),
}

impl Token {
    /// How this token reads in a diagnostic.
    fn describe(&self) -> String {
        match self {
            Self::Open => "`[`".to_owned(),
            Self::Close => "`]`".to_owned(),
            Self::Quoted(value) => format!("the string literal `{value}`"),
            Self::Word(word) | Self::Keyword(word) | Self::Symbol(word) => format!("`{word}`"),
        }
    }
}

/// The reserved words of the patterning language.
///
/// Recognised so that a pattern using one is quarantined *naming it*, rather than having it glued
/// onto an object path and rejected as an unrecognised path — which would tell an operator to look
/// at the wrong thing.
const KEYWORDS: &[&str] = &[
    "AND",
    "OR",
    "NOT",
    "FOLLOWEDBY",
    "LIKE",
    "MATCHES",
    "ISSUBSET",
    "ISSUPERSET",
    "IN",
    "EXISTS",
    "REPEATS",
    "TIMES",
    "WITHIN",
    "SECONDS",
    "START",
    "STOP",
];

/// Characters that end a bare word.
fn is_delimiter(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '\'' | '[' | ']' | '(' | ')' | '=' | '!' | '<' | '>' | ','
        )
}

/// Split a pattern into tokens.
///
/// String literals are scanned as literals, so a `]`, an `AND`, or a `'` inside a quoted value is
/// content rather than structure. Getting that wrong is how a pattern-aware parser ends up
/// mis-reading an indicator whose value happens to contain punctuation.
fn tokenize(pattern: &str) -> Result<Vec<Token>, PatternError> {
    let mut tokens = Vec::new();
    let mut characters = pattern.chars().peekable();

    while let Some(character) = characters.next() {
        match character {
            character if character.is_whitespace() => {}
            '[' => tokens.push(Token::Open),
            ']' => tokens.push(Token::Close),
            '\'' => {
                let mut value = String::new();
                let mut closed = false;
                while let Some(inner) = characters.next() {
                    match inner {
                        '\\' => match characters.next() {
                            Some(escaped @ ('\'' | '\\')) => value.push(escaped),
                            // Any other escape is left as written. Interpreting escapes Brolga does
                            // not define would change the value the publisher asserted.
                            Some(other) => {
                                value.push('\\');
                                value.push(other);
                            }
                            None => break,
                        },
                        '\'' => {
                            closed = true;
                            break;
                        }
                        other => value.push(other),
                    }
                }
                if !closed {
                    return Err(PatternError::new(
                        "an unterminated string literal",
                        "the pattern ends inside a quoted value, so what it asserts cannot be read",
                    ));
                }
                tokens.push(Token::Quoted(value));
            }
            '=' => tokens.push(Token::Symbol("=".to_owned())),
            '!' | '<' | '>' => {
                let mut symbol = String::from(character);
                if characters.peek() == Some(&'=') {
                    characters.next();
                    symbol.push('=');
                }
                tokens.push(Token::Symbol(symbol));
            }
            '(' | ')' | ',' => tokens.push(Token::Symbol(character.to_string())),
            other => {
                let mut word = String::from(other);
                while let Some(&next) = characters.peek() {
                    if is_delimiter(next) {
                        break;
                    }
                    word.push(next);
                    characters.next();
                }
                if KEYWORDS
                    .iter()
                    .any(|keyword| keyword.eq_ignore_ascii_case(&word))
                {
                    tokens.push(Token::Keyword(word.to_ascii_uppercase()));
                } else {
                    tokens.push(Token::Word(word));
                }
            }
        }
    }

    Ok(tokens)
}

/// Read the comparisons a representable pattern holds, as `(object path, value)` pairs.
///
/// One pair for a plain comparison, one per alternative for an `OR` chain. Every alternative must
/// parse; the first that does not aborts the whole pattern, because representing the rest would be
/// the partial extraction this module exists to refuse.
fn comparisons_of(tokens: &[Token]) -> Result<Vec<(String, String)>, PatternError> {
    let mut index = 0;

    match tokens.first() {
        Some(Token::Open) => index += 1,
        Some(Token::Keyword(word)) => return Err(unsupported_keyword(word)),
        Some(other) => {
            return Err(PatternError::new(
                other.describe(),
                format!(
                    "the pattern starts with {} rather than a bracketed observation expression; \
                     Brolga represents `[<object-path> = '<value>']`, optionally `OR`-joined, and \
                     nothing else",
                    other.describe()
                ),
            ));
        }
        None => {
            return Err(PatternError::new(
                "an empty pattern",
                "the pattern holds no observation expression at all",
            ));
        }
    }

    let mut comparisons = Vec::new();
    loop {
        let (path, value) = comparison_at(tokens, &mut index)?;
        comparisons.push((path, value));

        if comparisons.len() > MAX_ALTERNATIVES {
            return Err(PatternError::new(
                "an over-long disjunction",
                format!(
                    "the pattern joins more than {MAX_ALTERNATIVES} alternatives with `OR`; it is \
                     refused whole rather than truncated, because a truncated disjunction asserts \
                     a different set from the one published"
                ),
            ));
        }

        match tokens.get(index) {
            // `OR` is the one boolean form that fans out. See the module documentation for why it
            // is a widening Brolga accepts and `AND` is not.
            Some(Token::Keyword(word)) if word == "OR" => index += 1,
            Some(Token::Close) => {
                index += 1;
                break;
            }
            Some(Token::Keyword(word)) => return Err(unsupported_keyword(word)),
            Some(other) => {
                return Err(PatternError::new(
                    other.describe(),
                    format!(
                        "the observation expression continues past a comparison with {}; a pattern \
                         is either represented whole or quarantined, never partially extracted",
                        other.describe()
                    ),
                ));
            }
            None => {
                return Err(PatternError::new(
                    "an unclosed observation expression",
                    "the pattern ends without a closing `]`",
                ));
            }
        }
    }

    match tokens.get(index) {
        None => Ok(comparisons),
        Some(Token::Keyword(word)) => Err(unsupported_keyword(word)),
        Some(Token::Open) => Err(PatternError::new(
            "more than one observation expression",
            "the pattern holds several bracketed expressions; the operator joining them says how \
             they relate in time or sequence, which Brolga's model has no form for, so \
             representing them as unrelated alternatives would lose what the indicator asserted",
        )),
        Some(other) => Err(PatternError::new(
            other.describe(),
            format!(
                "the pattern continues past its closing `]` with {}",
                other.describe()
            ),
        )),
    }
}

/// Read one `<object-path> = '<value>'` comparison, advancing past it.
fn comparison_at(tokens: &[Token], index: &mut usize) -> Result<(String, String), PatternError> {
    // The object path. A hash key is itself quoted — `file:hashes.'SHA-256'` — so a quoted token
    // before the operator is part of the path rather than the compared value, and is re-rendered
    // with its quotes so the two spellings of a key stay distinguishable.
    let mut path = String::new();
    loop {
        match tokens.get(*index) {
            Some(Token::Word(word)) => {
                path.push_str(word);
                *index += 1;
            }
            Some(Token::Quoted(segment)) => {
                path.push('\'');
                path.push_str(segment);
                path.push('\'');
                *index += 1;
            }
            Some(Token::Symbol(symbol)) if symbol == "=" => break,
            Some(Token::Symbol(symbol)) => return Err(unsupported_operator(symbol)),
            Some(Token::Keyword(word)) => return Err(unsupported_keyword(word)),
            Some(Token::Open) => {
                return Err(PatternError::new(
                    "a nested observation expression",
                    "the pattern opens a second `[` before a comparison is complete",
                ));
            }
            Some(Token::Close) | None => {
                return Err(PatternError::new(
                    "a comparison with no `=`",
                    "the observation expression holds a term with no `=` comparison, so it asserts \
                     nothing Brolga can key an observable on",
                ));
            }
        }
    }

    if path.is_empty() {
        return Err(PatternError::new(
            "a comparison with no object path",
            "the comparison has nothing on the left of its `=`",
        ));
    }
    *index += 1;

    let value = match tokens.get(*index) {
        Some(Token::Quoted(value)) => value.clone(),
        Some(other) => {
            return Err(PatternError::new(
                other.describe(),
                format!(
                    "the comparison is against {} rather than a quoted value; Brolga only reads \
                     comparisons against string literals",
                    other.describe()
                ),
            ));
        }
        None => {
            return Err(PatternError::new(
                "a comparison with no value",
                "the pattern ends after its `=`",
            ));
        }
    };
    *index += 1;

    Ok((path, value))
}

/// The error for a reserved word Brolga does not implement.
fn unsupported_keyword(word: &str) -> PatternError {
    PatternError::new(
        format!("`{word}`"),
        format!(
            "the pattern uses `{word}`, which Brolga does not represent; it is quarantined whole \
             rather than partially extracted, because half a pattern asserts something the \
             publisher did not"
        ),
    )
}

/// The error for a comparison operator other than equality.
fn unsupported_operator(symbol: &str) -> PatternError {
    PatternError::new(
        format!("`{symbol}`"),
        format!(
            "the comparison operator `{symbol}` has no canonical equivalent; Brolga keys an \
             observable on a value that *is* something, and `{symbol}` does not name one"
        ),
    )
}

/// Canonicalise a comparison through the shared canonicalisers.
///
/// The same functions the MISP parser calls, deliberately: an address published as a MISP attribute
/// and the same address published inside a STIX pattern must derive one observable identifier, or
/// the two feeds populate the graph twice and a lookup finds half of what is held.
fn observable_of_comparison(path: &str, value: &str) -> Result<Observable, PatternError> {
    let normalised = path.to_ascii_lowercase();

    let canonical = match normalised.as_str() {
        "ipv4-addr:value" | "ipv6-addr:value" => canon::net::ip_address(value),
        "domain-name:value" => canon::net::domain_name(value),
        "url:value" => canon::net::url(value),
        "email-addr:value" => canon::net::email_address(value),
        other => {
            let Some(algorithm) = hash_algorithm_of(other) else {
                return Err(PatternError::new(
                    format!("`{path}`"),
                    format!(
                        "the object path `{path}` is not one Brolga canonicalises; it maps \
                         `ipv4-addr:value`, `ipv6-addr:value`, `domain-name:value`, `url:value`, \
                         `email-addr:value`, and `file:hashes.'<algorithm>'`"
                    ),
                ));
            };
            // The path states the algorithm, so it is passed through rather than inferred from the
            // digest's length — length cannot tell SHA-256 from any other 32-byte digest.
            canon::file::file_hash_with_algorithm(algorithm, value)
        }
    };

    canonical
        .map(canon::Canonical::into_value)
        .map_err(|error| {
            PatternError::new(
                format!("`{path}`"),
                format!("the value compared against `{path}` does not canonicalise: {error}"),
            )
        })
}

/// The hash algorithm a `file:hashes.…` path names, in the spellings STIX and feeds both use.
fn hash_algorithm_of(path: &str) -> Option<HashAlgorithm> {
    let key = path.strip_prefix("file:hashes.")?.trim_matches('\'');
    match key {
        "md5" => Some(HashAlgorithm::Md5),
        "sha-1" | "sha1" => Some(HashAlgorithm::Sha1),
        "sha-256" | "sha256" => Some(HashAlgorithm::Sha256),
        "sha-512" | "sha512" => Some(HashAlgorithm::Sha512),
        _ => None,
    }
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

    fn error(pattern: &str) -> PatternError {
        observables_of(pattern).expect_err("the pattern must be refused")
    }

    /// The one observable a non-disjunctive pattern names.
    fn observable_of(pattern: &str) -> Result<Observable, PatternError> {
        let mut observables = observables_of(pattern)?;
        assert_eq!(observables.len(), 1, "{pattern} named several observables");
        Ok(observables.remove(0))
    }

    #[test]
    fn every_supported_comparison_form_yields_its_observable() {
        for (pattern, expected) in [
            ("[ipv4-addr:value = '192.0.2.1']", "ipv4_address:192.0.2.1"),
            (
                "[ipv6-addr:value = '2001:0DB8::0001']",
                "ipv6_address:2001:db8::1",
            ),
            (
                "[domain-name:value = 'EXAMPLE.COM.']",
                "domain_name:example.com",
            ),
            (
                "[url:value = 'https://example.com/a']",
                "url:https://example.com/a",
            ),
            (
                "[email-addr:value = 'Bob@EXAMPLE.com']",
                "email_address:Bob@example.com",
            ),
        ] {
            let observable = observable_of(pattern).expect(pattern);
            assert_eq!(observable.to_string(), expected, "{pattern}");
        }
    }

    #[test]
    fn a_hash_comparison_takes_its_algorithm_from_the_path_rather_than_the_length() {
        let sha256 = "a".repeat(64);
        for path in [
            "file:hashes.'SHA-256'",
            "file:hashes.SHA-256",
            "FILE:HASHES.'sha256'",
        ] {
            let pattern = format!("[{path} = '{sha256}']");
            let observable = observable_of(&pattern).expect(&pattern);
            assert_eq!(observable.to_string(), format!("file_hash:sha256:{sha256}"));
        }

        let md5 = "b".repeat(32);
        let observable = observable_of(&format!("[file:hashes.'MD5' = '{md5}']")).unwrap();
        assert_eq!(observable.to_string(), format!("file_hash:md5:{md5}"));

        let sha1 = "c".repeat(40);
        let observable = observable_of(&format!("[file:hashes.'SHA-1' = '{sha1}']")).unwrap();
        assert_eq!(observable.to_string(), format!("file_hash:sha1:{sha1}"));
    }

    #[test]
    fn whitespace_and_quoting_do_not_change_what_a_pattern_means() {
        let spaced = observable_of("[  ipv4-addr:value   =   '192.0.2.1'  ]").unwrap();
        let tight = observable_of("[ipv4-addr:value='192.0.2.1']").unwrap();
        assert_eq!(spaced.id(), tight.id());
    }

    /// The acceptance criterion this module exists for. Each of these must name what it did not
    /// understand, because "could not parse" sends an operator looking at the wrong thing.
    #[test]
    fn an_unrepresentable_pattern_is_refused_naming_the_construct() {
        for (pattern, named) in [
            (
                "[ipv4-addr:value = '192.0.2.1' AND ipv4-addr:value = '192.0.2.2']",
                "AND",
            ),
            ("[ipv4-addr:value != '192.0.2.1']", "!="),
            ("[ipv4-addr:value > '192.0.2.1']", ">"),
            ("[domain-name:value LIKE 'exa%']", "LIKE"),
            ("[domain-name:value MATCHES 'exa.*']", "MATCHES"),
            ("[network-traffic:dst_port = '4444']", "network-traffic"),
            ("[file:name = 'invoice.exe']", "file:name"),
            ("[file:hashes.'SHA3-256' = 'abcd']", "SHA3-256"),
            (
                "[ipv4-addr:value = '192.0.2.1'] FOLLOWEDBY [ipv4-addr:value = '192.0.2.2']",
                "FOLLOWEDBY",
            ),
            ("[ipv4-addr:value = '192.0.2.1'] REPEATS 3 TIMES", "REPEATS"),
        ] {
            let error = error(pattern);
            assert!(
                error.to_string().contains(named),
                "`{pattern}` must name `{named}`, said: {error}"
            );
        }
    }

    /// Two bracketed expressions is the case the criterion calls out by name: represent both or
    /// quarantine, never the first one alone. Unlike an `OR` inside one expression, the operator
    /// between two of them says how they relate in time, which has no canonical form.
    #[test]
    fn several_observation_expressions_are_quarantined_rather_than_reduced_to_the_first() {
        let error = error("[ipv4-addr:value = '192.0.2.1'][domain-name:value = 'example.com']");
        assert_eq!(error.construct(), "more than one observation expression");
    }

    /// A disjunction is the one boolean form that fans out, because a published address list is
    /// overwhelmingly how feeds spell one. Every alternative is represented, or none is.
    #[test]
    fn a_disjunction_yields_every_alternative_in_order() {
        let observables = observables_of(
            "[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.2' OR \
             domain-name:value = 'EXAMPLE.COM']",
        )
        .unwrap();

        let rendered: Vec<String> = observables.iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered,
            vec![
                "ipv4_address:192.0.2.1",
                "ipv4_address:192.0.2.2",
                "domain_name:example.com",
            ]
        );
    }

    /// Alternatives that canonicalise to one observable *are* one alternative. Counting them twice
    /// would overstate the hedge a caller records alongside the claims.
    #[test]
    fn alternatives_that_canonicalise_alike_collapse_to_one() {
        let observables = observables_of(
            "[domain-name:value = 'EXAMPLE.COM.' OR domain-name:value = 'example.com']",
        )
        .unwrap();
        assert_eq!(observables.len(), 1);
    }

    /// One unrepresentable alternative refuses the whole pattern. Keeping the rest would publish a
    /// narrower set than the indicator named, silently.
    #[test]
    fn one_bad_alternative_refuses_the_whole_disjunction() {
        let unmapped_path = error("[ipv4-addr:value = '192.0.2.1' OR file:name = 'invoice.exe']");
        assert!(
            unmapped_path.to_string().contains("file:name"),
            "{unmapped_path}"
        );

        let bad_value =
            error("[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = 'not an address']");
        assert!(
            bad_value.to_string().contains("does not canonicalise"),
            "{bad_value}"
        );
    }

    /// `AND` still refuses. A conjunction asserts the terms *together*, and one term alone is a
    /// broader claim than the publisher made — the opposite of the `OR` case.
    #[test]
    fn a_conjunction_is_still_refused_whole() {
        let error = error("[ipv4-addr:value = '192.0.2.1' AND ipv4-addr:value = '192.0.2.2']");
        assert_eq!(error.construct(), "`AND`");
    }

    /// Every alternative becomes its own claims, so a disjunction is an amplification shape as well
    /// as a hedge. It is refused whole rather than truncated.
    #[test]
    fn an_over_long_disjunction_is_refused_rather_than_truncated() {
        let terms: Vec<String> = (0..=MAX_ALTERNATIVES)
            .map(|index| format!("domain-name:value = 'host{index}.example.com'"))
            .collect();
        let error = error(&format!("[{}]", terms.join(" OR ")));
        assert_eq!(error.construct(), "an over-long disjunction");
    }

    #[test]
    fn a_value_that_does_not_canonicalise_is_refused_rather_than_stored_raw() {
        let error = error("[ipv4-addr:value = 'not an address']");
        assert!(
            error.to_string().contains("does not canonicalise"),
            "{error}"
        );
    }

    /// Structure inside a string literal is content. A parser that scanned for `]` or `AND` textually
    /// would mis-read exactly these.
    #[test]
    fn punctuation_inside_a_value_is_not_read_as_structure() {
        let observable = observable_of("[url:value = 'https://example.com/a?q=1&r=AND]']").unwrap();
        let rendered = observable.to_string();
        assert!(
            rendered.starts_with("url:https://example.com/a?q=1"),
            "{rendered}"
        );
        assert!(rendered.contains("r=AND"), "{rendered}");
    }

    #[test]
    fn a_malformed_pattern_is_refused_rather_than_panicking() {
        for pattern in [
            "",
            "[",
            "]",
            "[]",
            "[ipv4-addr:value =",
            "[ipv4-addr:value = 'unterminated",
            "ipv4-addr:value = '192.0.2.1'",
            "[= '192.0.2.1']",
            "[[ipv4-addr:value = '192.0.2.1']]",
        ] {
            assert!(
                observable_of(pattern).is_err(),
                "`{pattern}` must be refused"
            );
        }
    }

    #[test]
    fn an_over_long_pattern_is_refused_before_it_is_scanned() {
        let pattern = format!("[ipv4-addr:value = '{}']", "a".repeat(MAX_PATTERN_BYTES));
        let error = error(&pattern);
        assert_eq!(error.construct(), "an over-long pattern");
    }
}
