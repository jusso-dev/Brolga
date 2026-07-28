//! Parsing YAML and JSON into layers, with bounds applied before anything is trusted.
//!
//! # Order of operations
//!
//! A configuration file is operator-supplied, but "operator-supplied" is not "trusted": it arrives
//! from a mounted volume, a deployment pipeline, or a repository that more people can write to than
//! anyone remembers. So the checks run cheapest-first, and each one runs *before* the step it
//! protects:
//!
//! 1. **Size**, before the parser allocates anything.
//! 2. **Anchors and aliases**, before the parser expands them — see below.
//! 3. **Depth**, on the untyped value, before typed deserialisation recurses through it.
//! 4. **Shape**, per layer, with the path of any offending field.
//!
//! # Why anchors and aliases are rejected outright
//!
//! YAML aliases expand at parse time, and nesting them multiplies: the "billion laughs" document is
//! about a kilobyte of text that expands to gigabytes of memory. A size limit does not help, because
//! the input really is small. The parser this crate uses offers no way to cap expansion.
//!
//! Brolga's configuration has no use for anchors, so they are rejected before parsing, by a scanner
//! that understands quoting and comments well enough not to trip over a `*` inside a string. An
//! operator who genuinely wants a literal `&` or `*` at the start of a value quotes it, and the
//! error message says so.
//!
//! # A note on the YAML dependency
//!
//! `serde_yaml_ng` pulls in `unsafe-libyaml`, a transliteration of the C library that contains a
//! great deal of `unsafe`. Brolga's own crates forbid `unsafe`; a dependency is a different
//! question, and this one is the maintained option with a permissive licence that `cargo deny`
//! accepts. The mitigation is the order above — bounded size and no alias expansion mean the parser
//! sees a small, flat-ish document — and the exposure is recorded here so the threat-model work in
//! [#8](https://github.com/jusso-dev/Brolga/issues/8) inherits it rather than rediscovering it.

use serde_json::Value;

use crate::error::{ConfigError, ConfigPath, Result, preview};
use crate::layer::{Layer, LayerId};

/// Largest configuration document, in bytes.
///
/// Generous for a hand-written file and small enough that parsing one cannot be a denial of
/// service on its own.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// Deepest structure a configuration document may contain.
///
/// Checked on the untyped value, before typed deserialisation recurses through it, so a
/// pathological document cannot exhaust the stack inside serde.
pub const MAX_CONFIG_DEPTH: usize = 32;

/// Which parser to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Format {
    /// YAML 1.2.
    Yaml,
    /// JSON.
    Json,
}

impl Format {
    /// Guess from a filename extension, defaulting to YAML.
    ///
    /// YAML is a superset of JSON in practice, so a misidentified `.json` file still parses. The
    /// reverse is not true, which is why YAML is the default rather than JSON.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        if path
            .rsplit('.')
            .next()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            Self::Json
        } else {
            Self::Yaml
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Yaml => "YAML",
            Self::Json => "JSON",
        }
    }
}

/// Parse a configuration document into an untyped value, applying every bound.
///
/// # Errors
///
/// Returns [`ConfigError::TooLarge`] beyond [`MAX_CONFIG_BYTES`], [`ConfigError::Invalid`] if the
/// document uses YAML anchors or aliases, [`ConfigError::Syntax`] if it does not parse,
/// [`ConfigError::TooDeep`] beyond [`MAX_CONFIG_DEPTH`], and [`ConfigError::Invalid`] if the
/// document's root is not a mapping.
pub fn parse_document(text: &str, format: Format) -> Result<Value> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            max: MAX_CONFIG_BYTES,
            actual: text.len(),
        });
    }

    if format == Format::Yaml
        && let Some(found) = find_anchor_or_alias(text)
    {
        return Err(ConfigError::Invalid {
            path: ConfigPath::root(),
            reason: format!(
                "YAML anchors and aliases are not permitted, because alias expansion is unbounded; found {found:?}. Quote the value if the character is meant literally."
            ),
        });
    }

    let value: Value = match format {
        Format::Yaml => serde_yaml_ng::from_str(text).map_err(|error| ConfigError::Syntax {
            format: format.label(),
            path: ConfigPath::root(),
            reason: error.to_string(),
        })?,
        Format::Json => serde_json::from_str(text).map_err(|error| ConfigError::Syntax {
            format: format.label(),
            path: ConfigPath::root(),
            reason: error.to_string(),
        })?,
    };

    check_depth(&value, &ConfigPath::root(), 0)?;

    if !value.is_object() {
        return Err(ConfigError::Invalid {
            path: ConfigPath::root(),
            reason: format!(
                "a configuration document must be a mapping of settings, found {}",
                describe(&value),
            ),
        });
    }

    Ok(value)
}

/// Parse a document into a named layer.
///
/// # Errors
///
/// As [`parse_document`].
pub fn parse_layer(name: &str, text: &str, format: Format) -> Result<Layer> {
    let values = parse_document(text, format)?;
    Ok(Layer::new(LayerId::File(name.to_owned()), values))
}

/// Deserialise a merged document into a typed value, with the path of any offending field.
///
/// # Errors
///
/// Returns [`ConfigError::UnknownField`], [`ConfigError::Missing`], or [`ConfigError::Invalid`],
/// each naming the setting that caused it. The path comes from `serde_path_to_error`, so it is the
/// real location rather than a guess.
pub fn deserialize_typed<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    let mut track = serde_path_to_error::Track::new();
    let deserializer = serde_path_to_error::Deserializer::new(value, &mut track);

    match T::deserialize(deserializer) {
        Ok(typed) => Ok(typed),
        Err(error) => {
            let path = ConfigPath::new(dotted(&track.path().to_string()));
            Err(classify(&error.to_string(), path))
        }
    }
}

/// Turn a `serde_path_to_error` path into the dotted form used in diagnostics.
fn dotted(path: &str) -> String {
    if path == "." {
        String::new()
    } else {
        path.replace('[', ".").replace(']', "")
    }
}

/// Map a serde message onto the most specific error variant it supports.
///
/// serde reports these as strings, so this is string matching — but on serde's own stable phrasing,
/// not on user input, and every branch falls back to a correct-if-less-specific variant.
fn classify(message: &str, path: ConfigPath) -> ConfigError {
    if let Some(field) = message
        .strip_prefix("unknown field `")
        .and_then(|rest| rest.split('`').next())
    {
        // `serde_path_to_error` includes the offending key in the path, which would render as
        // `unknown field "pth" at storage.sqlite.pth`. Strip it so the path names the *container*
        // the operator has to look in, and the field is named once.
        let container = path
            .as_str()
            .strip_suffix(field)
            .map(|prefix| ConfigPath::new(prefix.trim_end_matches('.')))
            .unwrap_or(path);

        return ConfigError::UnknownField {
            path: container,
            field: field.to_owned(),
            suggestion: closest_known_field(message, field),
        };
    }

    if let Some(field) = message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.split('`').next())
    {
        return ConfigError::Missing {
            path: if path.is_root() {
                ConfigPath::new(field)
            } else {
                path.child(field)
            },
        };
    }

    ConfigError::Invalid {
        path,
        reason: message.to_owned(),
    }
}

/// Pick the closest expected field from serde's "expected one of" list.
///
/// A suggestion is only offered when it is close enough to be plausibly the intended key. Offering
/// the nearest of a dozen unrelated names is worse than offering none: it sends the operator to
/// change a line that was never the problem.
fn closest_known_field(message: &str, field: &str) -> Option<String> {
    // serde phrases the expected set as "expected one of `a`, `b`, `c`" for three or more and
    // "expected `a` or `b`" for two, so the candidates are read as backtick-quoted tokens rather
    // than by matching one of those sentences. The first quoted token is the offending field
    // itself and is skipped.
    let expected = message.split_once("expected ")?.1;

    expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .filter(|candidate| !candidate.is_empty() && candidate != field)
        .map(|candidate| {
            let distance = edit_distance(field, &candidate);
            (distance, candidate)
        })
        .filter(|(distance, candidate)| *distance <= threshold(candidate))
        .min_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
        .map(|(_, candidate)| candidate)
}

/// How far a suggestion may be from the typed key, scaled to the key's length.
///
/// A three-character key with two edits is a different key; a twenty-character key with two edits is
/// a typo.
fn threshold(candidate: &str) -> usize {
    match candidate.len() {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

/// Levenshtein distance, iterative with two rows.
fn edit_distance(left: &str, right: &str) -> usize {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();

    if left.is_empty() {
        return right.len();
    }
    if right.is_empty() {
        return left.len();
    }

    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0_usize; right.len().saturating_add(1)];

    for (i, left_char) in left.iter().enumerate() {
        if let Some(first) = current.first_mut() {
            *first = i.saturating_add(1);
        }
        for (j, right_char) in right.iter().enumerate() {
            let substitution_cost = usize::from(left_char != right_char);
            let deletion = previous
                .get(j.saturating_add(1))
                .copied()
                .unwrap_or(usize::MAX);
            let insertion = current.get(j).copied().unwrap_or(usize::MAX);
            let substitution = previous
                .get(j)
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(substitution_cost);

            if let Some(slot) = current.get_mut(j.saturating_add(1)) {
                *slot = deletion
                    .saturating_add(1)
                    .min(insertion.saturating_add(1))
                    .min(substitution);
            }
        }
        core::mem::swap(&mut previous, &mut current);
    }

    previous.last().copied().unwrap_or(0)
}

/// Check nesting depth on the untyped value.
fn check_depth(value: &Value, path: &ConfigPath, depth: usize) -> Result<()> {
    if depth > MAX_CONFIG_DEPTH {
        return Err(ConfigError::TooDeep {
            path: path.clone(),
            max: MAX_CONFIG_DEPTH,
            actual: depth,
        });
    }

    match value {
        Value::Object(map) => {
            for (key, child) in map {
                check_depth(child, &path.child(key), depth.saturating_add(1))?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                check_depth(
                    child,
                    &path.child(&index.to_string()),
                    depth.saturating_add(1),
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "a mapping",
    }
}

/// Find a YAML anchor definition or alias reference outside quotes and comments.
///
/// Returns a short preview of the offending token, so the diagnostic can point at it.
///
/// The scanner is intentionally simple, and it is *conservative in the safe direction*: it may
/// reject an exotic unquoted value that happens to look like an anchor, and the fix for that is to
/// quote the value, which the error says. It will not miss a real anchor, which is the direction
/// that matters.
fn find_anchor_or_alias(text: &str) -> Option<String> {
    for line in text.lines() {
        let mut in_single = false;
        let mut in_double = false;
        let mut previous: Option<char> = None;

        for (index, ch) in line.char_indices() {
            match ch {
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single && previous != Some('\\') => in_double = !in_double,
                '#' if !in_single && !in_double => break,
                '&' | '*' if !in_single && !in_double => {
                    // An anchor or alias sits at the start of a value: after a colon, a dash, a
                    // comma, an opening bracket, or at the start of the line.
                    let at_value_start = previous.is_none_or(|previous| {
                        matches!(previous, ' ' | '\t' | ':' | '-' | ',' | '[' | '{')
                    });
                    let names_something = line
                        .get(index.saturating_add(1)..)
                        .and_then(|rest| rest.chars().next())
                        .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_');

                    if at_value_start && names_something {
                        let token: String = line
                            .get(index..)
                            .unwrap_or_default()
                            .chars()
                            .take(16)
                            .collect();
                        return Some(preview(&token));
                    }
                }
                _ => {}
            }
            previous = Some(ch);
        }
    }
    None
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
    use crate::model::BrolgaConfig;

    #[test]
    fn parses_equivalent_yaml_and_json_to_the_same_value() {
        let yaml = "storage:\n  sqlite:\n    path: brolga.sqlite\n";
        let json = r#"{"storage": {"sqlite": {"path": "brolga.sqlite"}}}"#;
        assert_eq!(
            parse_document(yaml, Format::Yaml).unwrap(),
            parse_document(json, Format::Json).unwrap(),
        );
    }

    #[test]
    fn a_document_larger_than_the_limit_is_rejected_before_parsing() {
        let oversized = format!("key: \"{}\"", "a".repeat(MAX_CONFIG_BYTES));
        assert!(matches!(
            parse_document(&oversized, Format::Yaml),
            Err(ConfigError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_billion_laughs_document_is_rejected_before_it_expands() {
        // About a kilobyte of text that expands to gigabytes. A size limit does not catch it,
        // because the input genuinely is small.
        let bomb = r"
a: &a ['lol','lol','lol','lol','lol','lol','lol','lol','lol']
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: [*h,*h,*h,*h,*h,*h,*h,*h,*h]
";
        let error = parse_document(bomb, Format::Yaml).unwrap_err();
        assert!(error.to_string().contains("anchors and aliases"), "{error}");
    }

    #[test]
    fn a_single_anchor_is_rejected_too() {
        assert!(parse_document("a: &anchor value\nb: *anchor\n", Format::Yaml).is_err());
        assert!(parse_document("a: &anchor value\n", Format::Yaml).is_err());
    }

    #[test]
    fn quoted_and_commented_ampersands_are_not_anchors() {
        // A scanner that tripped over these would make legitimate values unwritable.
        for benign in [
            "name: \"Tom & Jerry\"\n",
            "name: 'star * value'\n",
            "name: value # see &notes\n",
            "glob: \"*.json\"\n",
            "name: a&b\n",
            "name: 2 * 3\n",
        ] {
            assert!(
                parse_document(benign, Format::Yaml).is_ok(),
                "expected {benign:?} to parse"
            );
        }
    }

    #[test]
    fn a_document_deeper_than_the_limit_is_rejected() {
        let mut json = String::from("1");
        for _ in 0..=MAX_CONFIG_DEPTH + 2 {
            json = format!("{{\"a\":{json}}}");
        }
        let error = parse_document(&json, Format::Json).unwrap_err();
        assert!(matches!(error, ConfigError::TooDeep { .. }), "{error:?}");
        // The diagnostic names where the limit was hit, not merely that it was.
        assert!(error.path().is_some_and(|path| path.as_str().contains('a')));
    }

    #[test]
    fn a_document_at_the_depth_limit_is_accepted() {
        let mut json = String::from("1");
        for _ in 0..MAX_CONFIG_DEPTH - 1 {
            json = format!("{{\"a\":{json}}}");
        }
        assert!(parse_document(&format!("{{\"root\":{json}}}"), Format::Json).is_ok());
    }

    #[test]
    fn a_document_that_is_not_a_mapping_is_rejected_clearly() {
        for hostile in ["- a\n- b\n", "just a string\n", "42\n", "null\n"] {
            let error = parse_document(hostile, Format::Yaml).unwrap_err();
            assert!(
                error.to_string().contains("must be a mapping"),
                "expected a clear message for {hostile:?}, got: {error}"
            );
        }
    }

    #[test]
    fn malformed_documents_produce_a_syntax_error_naming_the_format() {
        let error = parse_document("{unclosed: ", Format::Json).unwrap_err();
        assert!(
            matches!(error, ConfigError::Syntax { format: "JSON", .. }),
            "{error:?}"
        );

        let error = parse_document("a:\n  - b\n c: broken indent\n", Format::Yaml).unwrap_err();
        assert!(
            matches!(error, ConfigError::Syntax { format: "YAML", .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_unknown_field_is_reported_with_its_path_and_a_suggestion() {
        let mut value = serde_json::to_value(BrolgaConfig::defaults().unwrap()).unwrap();
        value["storage"]["sqlite"]["pth"] = serde_json::json!("x");

        let error = deserialize_typed::<BrolgaConfig>(&value).unwrap_err();
        match error {
            ConfigError::UnknownField {
                ref path,
                ref field,
                ref suggestion,
            } => {
                assert_eq!(path.as_str(), "storage.sqlite");
                assert_eq!(field, "pth");
                assert_eq!(suggestion.as_deref(), Some("path"));
            }
            other => panic!("expected an unknown-field error, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_value_is_reported_with_its_path() {
        let mut value = serde_json::to_value(BrolgaConfig::defaults().unwrap()).unwrap();
        value["logging"]["level"] = serde_json::json!("shouty");

        let error = deserialize_typed::<BrolgaConfig>(&value).unwrap_err();
        assert_eq!(
            error.path().map(ConfigPath::as_str),
            Some("logging.level"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_field_is_reported_with_its_path() {
        let mut value = serde_json::to_value(BrolgaConfig::defaults().unwrap()).unwrap();
        value["storage"].as_object_mut().unwrap().remove("backend");

        let error = deserialize_typed::<BrolgaConfig>(&value).unwrap_err();
        assert!(
            error
                .path()
                .is_some_and(|path| path.as_str().contains("backend")),
            "{error}"
        );
    }

    #[test]
    fn a_suggestion_is_withheld_when_nothing_is_close_enough() {
        // Sending an operator to change a line that was never the problem is worse than no hint.
        assert_eq!(
            closest_known_field(
                "unknown field `zzzzzzzzzz`, expected one of `path`, `busy_timeout_ms`",
                "zzzzzzzzzz"
            ),
            None,
        );
        assert_eq!(
            closest_known_field(
                "unknown field `pth`, expected one of `path`, `busy_timeout_ms`",
                "pth"
            ),
            Some("path".to_owned()),
        );
    }

    #[test]
    fn edit_distance_is_correct_on_the_usual_cases() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("a", ""), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("path", "path"), 0);
        assert_eq!(edit_distance("pth", "path"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("backedn", "backend"), 2);
    }

    #[test]
    fn format_is_guessed_from_the_extension_and_defaults_to_yaml() {
        assert_eq!(Format::from_path("brolga.json"), Format::Json);
        assert_eq!(Format::from_path("brolga.JSON"), Format::Json);
        assert_eq!(Format::from_path("brolga.yaml"), Format::Yaml);
        assert_eq!(Format::from_path("brolga.yml"), Format::Yaml);
        assert_eq!(Format::from_path("brolga"), Format::Yaml);
    }

    #[test]
    fn a_parsed_layer_records_where_it_came_from() {
        let layer = parse_layer(
            "/etc/brolga.yaml",
            "logging:\n  level: debug\n",
            Format::Yaml,
        )
        .unwrap();
        assert_eq!(layer.id, LayerId::File("/etc/brolga.yaml".to_owned()));
        assert_eq!(layer.values["logging"]["level"], serde_json::json!("debug"));
    }
}
