//! Transforms: a closed list of named string operations.
//!
//! # Why this is a list and not a language
//!
//! [#47](https://github.com/jusso-dev/Brolga/issues/47) requires that transform functions come from
//! an allow-list, that no dynamic code execution exists, and that expressions have cost limits. The
//! way to satisfy all three at once is for there to be no expressions: a transform is a *variant of
//! an enum*, and a mapping naming one that does not exist fails to deserialise.
//!
//! Every transform here is:
//!
//! - **Pure** — a function from one string to one string. No I/O, no clock, no host state, no
//!   secrets, nothing outside its argument.
//! - **Total** — it cannot fail. A transform that does not apply returns its input unchanged. This is
//!   deliberate: a chain that could fail halfway would need error handling in the mapping format,
//!   which needs conditionals, which is the language this module exists without.
//! - **Bounded** — output length is capped at [`MAX_OUTPUT_BYTES`], chains at [`MAX_CHAIN`], and the
//!   only transform that can grow its input ([`Transform::Replace`]) is bounded by that cap.
//!
//! # `Undefang` earns its place
//!
//! Most of this list is obvious string work. `undefang` is the one that is domain-specific, and it is
//! here because defanged indicators are what analysts actually paste: `hxxp://evil[.]example`,
//! `1.2.3.4[.]5`, `user[at]example[dot]com`. Without it, every feed of copy-pasted indicators needs a
//! preprocessing step outside Brolga, and a mapping engine that cannot read the commonest real-world
//! shape of an indicator list is not much of one.
//!
//! It reverses only unambiguous defanging: bracketed and parenthesised separators, and the `hxxp`
//! scheme mangling. It does **not** guess at `dot`/`at` spelled as words without brackets, because
//! `department.of.transport` contains `of` and a rule that rewrote bare words would corrupt ordinary
//! text.

use serde::{Deserialize, Serialize};

/// Most transforms in one field's chain.
pub const MAX_CHAIN: usize = 8;

/// Longest a transform's output may be.
///
/// A transform chain runs per field per record, so an unbounded growth factor here multiplies across
/// a whole document. `Replace` is the only variant that can grow its input, and this is what stops it.
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024;

/// Every transform name this build accepts, for diagnostics and explain output.
///
/// Derived by hand from the enum below, and checked against it by
/// `the_documented_allow_list_matches_the_enum` so the two cannot drift.
pub const ALLOWED: &[&str] = &[
    "trim",
    "lowercase",
    "uppercase",
    "strip_prefix",
    "strip_suffix",
    "replace",
    "split_take",
    "substring",
    "undefang",
    "collapse_whitespace",
];

/// Why a transform was refused at validation time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransformError {
    /// A transform's argument was unusable.
    #[error("the `{transform}` transform {reason}")]
    Argument {
        /// Which transform.
        transform: &'static str,
        /// What was wrong with it.
        reason: String,
    },
}

/// One named string operation.
///
/// Internally tagged on `op`, so a transform reads as a self-describing map with named arguments:
///
/// ```yaml
/// transforms:
///   - op: undefang
///   - op: replace
///     from: "_"
///     to: "-"
/// ```
///
/// Named arguments rather than positional pairs, because `[",", 1]` needs the documentation open to
/// read and `separator: ","` / `index: 1` does not. Internally tagged rather than externally, because
/// YAML represents an externally tagged enum as a `!Tag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Transform {
    /// Remove leading and trailing whitespace.
    Trim,
    /// ASCII-lowercase. Deliberately ASCII: Unicode case folding is locale-dependent, and an
    /// identifier that changed meaning with the host's locale would not be canonical.
    Lowercase,
    /// ASCII-uppercase, for the same reason.
    Uppercase,
    /// Remove a leading string, if present.
    StripPrefix {
        /// The prefix to remove.
        prefix: String,
    },
    /// Remove a trailing string, if present.
    StripSuffix {
        /// The suffix to remove.
        suffix: String,
    },
    /// Replace every occurrence.
    Replace {
        /// What to look for.
        from: String,
        /// What to put in its place.
        to: String,
    },
    /// Split on a separator and take one part.
    ///
    /// An index past the end yields the input unchanged rather than an empty string, because a field
    /// that sometimes has fewer parts is an ordinary feed and losing the value would be worse than
    /// keeping it whole.
    SplitTake {
        /// The separator.
        separator: String,
        /// Which part, counting from zero.
        index: usize,
    },
    /// Take a byte range, clamped to the input and to a character boundary.
    Substring {
        /// Where to start, in bytes.
        start: usize,
        /// How many bytes.
        length: usize,
    },
    /// Reverse unambiguous indicator defanging. See the module documentation for what it will not do.
    Undefang,
    /// Collapse every run of whitespace to a single space, and trim.
    CollapseWhitespace,
}

impl Transform {
    /// This transform's name, as it appears in a mapping and in explain output.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Trim => "trim",
            Self::Lowercase => "lowercase",
            Self::Uppercase => "uppercase",
            Self::StripPrefix { .. } => "strip_prefix",
            Self::StripSuffix { .. } => "strip_suffix",
            Self::Replace { .. } => "replace",
            Self::SplitTake { .. } => "split_take",
            Self::Substring { .. } => "substring",
            Self::Undefang => "undefang",
            Self::CollapseWhitespace => "collapse_whitespace",
        }
    }

    /// Check this transform's arguments before it ever runs.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError`] if an argument would make the transform meaningless — an empty
    /// separator, an empty `replace` source, a zero-length substring.
    pub fn validate(&self) -> Result<(), TransformError> {
        match self {
            Self::StripPrefix { prefix: value } | Self::StripSuffix { suffix: value }
                if value.is_empty() =>
            {
                Err(TransformError::Argument {
                    transform: self.name(),
                    reason: "was given an empty string, which would strip nothing".to_owned(),
                })
            }
            Self::Replace { from, .. } if from.is_empty() => Err(TransformError::Argument {
                transform: "replace",
                reason: "was given an empty search string, which has no defined meaning".to_owned(),
            }),
            Self::SplitTake { separator, .. } if separator.is_empty() => {
                Err(TransformError::Argument {
                    transform: "split_take",
                    reason: "was given an empty separator".to_owned(),
                })
            }
            Self::Substring { length, .. } if *length == 0 => Err(TransformError::Argument {
                transform: "substring",
                reason: "was given a zero length, which always yields an empty value".to_owned(),
            }),
            _ => Ok(()),
        }
    }

    /// Apply this transform.
    ///
    /// Total by construction: a transform that does not apply returns its input. Output is truncated
    /// to [`MAX_OUTPUT_BYTES`] at a character boundary.
    #[must_use]
    pub fn apply(&self, value: &str) -> String {
        let out = match self {
            Self::Trim => value.trim().to_owned(),
            Self::Lowercase => value.to_ascii_lowercase(),
            Self::Uppercase => value.to_ascii_uppercase(),
            Self::StripPrefix { prefix } => value
                .strip_prefix(prefix.as_str())
                .unwrap_or(value)
                .to_owned(),
            Self::StripSuffix { suffix } => value
                .strip_suffix(suffix.as_str())
                .unwrap_or(value)
                .to_owned(),
            Self::Replace { from, to } => {
                if from.is_empty() {
                    value.to_owned()
                } else {
                    value.replace(from.as_str(), to)
                }
            }
            Self::SplitTake { separator, index } => {
                if separator.is_empty() {
                    value.to_owned()
                } else {
                    value
                        .split(separator.as_str())
                        .nth(*index)
                        .unwrap_or(value)
                        .to_owned()
                }
            }
            Self::Substring { start, length } => substring(value, *start, *length),
            Self::Undefang => undefang(value),
            Self::CollapseWhitespace => value.split_whitespace().collect::<Vec<_>>().join(" "),
        };
        bounded(&out)
    }
}

/// Apply a chain in order.
///
/// The chain is truncated at [`MAX_CHAIN`] rather than failing, because [`super::Mapping::validate`]
/// already refuses a longer one and a second failure path here would be unreachable code pretending
/// to be a safety net.
#[must_use]
pub fn apply_chain(transforms: &[Transform], value: &str) -> String {
    let mut current = value.to_owned();
    for transform in transforms.iter().take(MAX_CHAIN) {
        current = transform.apply(&current);
    }
    current
}

/// Take a byte range, clamped to the input and to character boundaries.
fn substring(value: &str, start: usize, length: usize) -> String {
    if start >= value.len() {
        return String::new();
    }
    let mut begin = start;
    while begin < value.len() && !value.is_char_boundary(begin) {
        begin = begin.saturating_add(1);
    }
    let mut end = begin.saturating_add(length).min(value.len());
    while end > begin && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(begin..end).unwrap_or_default().to_owned()
}

/// The unambiguous defanging patterns, longest first so that `[dot]` is matched before `[.]` cannot
/// interfere, and so `hxxps` is matched before `hxxp`.
const DEFANGED: &[(&str, &str)] = &[
    ("[dot]", "."),
    ("(dot)", "."),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[@]", "@"),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[//]", "//"),
];

/// The defanged URL schemes, matched case-insensitively.
///
/// Case-insensitively because a defanged indicator is usually copied out of a report, and reports
/// shout: `HXXP://`, `hXXp://`, and `hxxp://` are all in circulation. The replacement is always
/// lowercase, because a URL scheme is case-insensitive by specification and the canonicaliser
/// lowercases it anyway.
///
/// Longest first, so `hxxps` is matched before `hxxp` would take its prefix.
const DEFANGED_SCHEMES: &[(&str, &str)] = &[("hxxps://", "https://"), ("hxxp://", "http://")];

/// Reverse unambiguous defanging.
fn undefang(value: &str) -> String {
    let mut current = value.to_owned();
    for (from, to) in DEFANGED_SCHEMES {
        current = replace_ignoring_case(&current, from, to);
    }
    for (from, to) in DEFANGED {
        if current.contains(from) {
            current = current.replace(from, to);
        }
    }
    current
}

/// Replace every case-insensitive occurrence of `needle`.
///
/// Hand-rolled rather than reached for from a regex crate: the whole point of this module is that a
/// transform's cost is obvious, and this is one linear scan with no backtracking. ASCII-lowercasing
/// both sides is sound here because every needle is ASCII.
fn replace_ignoring_case(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_owned();
    }
    let lowered = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();

    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(found) = lowered.get(cursor..).and_then(|rest| rest.find(&needle)) {
        let start = cursor.saturating_add(found);
        out.push_str(haystack.get(cursor..start).unwrap_or_default());
        out.push_str(replacement);
        cursor = start.saturating_add(needle.len());
    }
    out.push_str(haystack.get(cursor..).unwrap_or_default());
    out
}

/// Truncate to [`MAX_OUTPUT_BYTES`] at a character boundary.
fn bounded(value: &str) -> String {
    if value.len() <= MAX_OUTPUT_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_OUTPUT_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.get(..end).unwrap_or_default().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The criterion.** The documented allow-list is the enum, so a reader of the documentation and
    /// a reader of the code learn the same thing.
    #[test]
    fn the_documented_allow_list_matches_the_enum() {
        let every = [
            Transform::Trim,
            Transform::Lowercase,
            Transform::Uppercase,
            Transform::StripPrefix {
                prefix: "x".to_owned(),
            },
            Transform::StripSuffix {
                suffix: "x".to_owned(),
            },
            Transform::Replace {
                from: "a".to_owned(),
                to: "b".to_owned(),
            },
            Transform::SplitTake {
                separator: ",".to_owned(),
                index: 0,
            },
            Transform::Substring {
                start: 0,
                length: 1,
            },
            Transform::Undefang,
            Transform::CollapseWhitespace,
        ];
        let mut names: Vec<&str> = every.iter().map(Transform::name).collect();
        names.sort_unstable();
        let mut allowed = ALLOWED.to_vec();
        allowed.sort_unstable();
        assert_eq!(names, allowed);
    }

    /// **The criterion.** A name that is not on the list does not deserialise, so a mapping cannot
    /// reach a transform this build does not have.
    #[test]
    fn a_transform_outside_the_allow_list_does_not_deserialise() {
        for attempt in ["exec", "shell", "read_file", "http_get", "eval"] {
            let document = format!(r#"{{"op":"{attempt}"}}"#);
            assert!(
                serde_json::from_str::<Transform>(&document).is_err(),
                "`{attempt}` must not deserialise"
            );
        }
        // And the shapes a caller might try to smuggle one in as.
        assert!(serde_json::from_str::<Transform>(r#"{"op":"exec","cmd":"rm -rf /"}"#).is_err());
        assert!(serde_json::from_str::<Transform>(r#"{"exec":"rm -rf /"}"#).is_err());
        assert!(serde_json::from_str::<Transform>(r#""exec""#).is_err());
    }

    #[test]
    fn a_transform_reads_as_a_tagged_map_with_named_arguments() {
        assert_eq!(
            serde_json::from_str::<Transform>(r#"{"op":"trim"}"#).unwrap(),
            Transform::Trim
        );
        assert_eq!(
            serde_json::from_str::<Transform>(r#"{"op":"strip_prefix","prefix":"urn:"}"#).unwrap(),
            Transform::StripPrefix {
                prefix: "urn:".to_owned()
            }
        );
        assert_eq!(
            serde_json::from_str::<Transform>(r#"{"op":"replace","from":"a","to":"b"}"#).unwrap(),
            Transform::Replace {
                from: "a".to_owned(),
                to: "b".to_owned()
            }
        );
        // And the same documents in YAML, which is what an operator actually writes.
        assert_eq!(
            serde_norway::from_str::<Transform>("op: split_take\nseparator: \":\"\nindex: 1\n")
                .unwrap(),
            Transform::SplitTake {
                separator: ":".to_owned(),
                index: 1
            }
        );
    }

    #[test]
    fn every_transform_does_what_its_name_says() {
        assert_eq!(Transform::Trim.apply("  a  "), "a");
        assert_eq!(Transform::Lowercase.apply("AbC"), "abc");
        assert_eq!(Transform::Uppercase.apply("AbC"), "ABC");
        assert_eq!(
            Transform::StripPrefix {
                prefix: "urn:".to_owned()
            }
            .apply("urn:x"),
            "x"
        );
        assert_eq!(
            Transform::StripSuffix {
                suffix: ".".to_owned()
            }
            .apply("example."),
            "example"
        );
        assert_eq!(
            Transform::Replace {
                from: "_".to_owned(),
                to: "-".to_owned()
            }
            .apply("a_b_c"),
            "a-b-c"
        );
        assert_eq!(
            Transform::SplitTake {
                separator: ":".to_owned(),
                index: 1
            }
            .apply("host:1.2.3.4"),
            "1.2.3.4"
        );
        assert_eq!(
            Transform::Substring {
                start: 0,
                length: 3
            }
            .apply("abcdef"),
            "abc"
        );
        assert_eq!(Transform::CollapseWhitespace.apply(" a \n\t b "), "a b");
    }

    /// **The criterion.** A transform is total: one that does not apply returns its input rather than
    /// failing, because a failing chain would need conditionals in the mapping format.
    #[test]
    fn a_transform_that_does_not_apply_returns_its_input() {
        assert_eq!(
            Transform::StripPrefix {
                prefix: "nope".to_owned()
            }
            .apply("value"),
            "value"
        );
        assert_eq!(
            Transform::SplitTake {
                separator: ",".to_owned(),
                index: 9
            }
            .apply("a,b"),
            "a,b",
            "an index past the end keeps the value whole rather than emptying it"
        );
        assert_eq!(
            Transform::Substring {
                start: 99,
                length: 3
            }
            .apply("abc"),
            ""
        );
    }

    #[test]
    fn substring_lands_on_character_boundaries() {
        // Three bytes per character. A range that would split one is clamped inwards.
        assert_eq!(
            Transform::Substring {
                start: 0,
                length: 4
            }
            .apply("日本語"),
            "日"
        );
        assert_eq!(
            Transform::Substring {
                start: 1,
                length: 5
            }
            .apply("日本語"),
            "本"
        );
    }

    #[test]
    fn undefang_reverses_the_unambiguous_patterns() {
        assert_eq!(
            Transform::Undefang.apply("hxxp://evil[.]example[.]com"),
            "http://evil.example.com"
        );
        assert_eq!(Transform::Undefang.apply("hXXps://a(dot)b"), "https://a.b");
        assert_eq!(
            Transform::Undefang.apply("HXXP://SHOUTY[.]EXAMPLE"),
            "http://SHOUTY.EXAMPLE",
            "a report that shouts is still a report; only the scheme is lowercased"
        );
        assert_eq!(
            Transform::Undefang.apply("user[at]example[dot]com"),
            "user@example.com"
        );
    }

    /// The bare-word case, which `undefang` must leave alone: rewriting `of` or `dot` outside
    /// brackets would corrupt ordinary text.
    #[test]
    fn undefang_leaves_bare_words_alone() {
        assert_eq!(
            Transform::Undefang.apply("department.of.transport"),
            "department.of.transport"
        );
        assert_eq!(
            Transform::Undefang.apply("evil dot example dot com"),
            "evil dot example dot com",
            "a bare `dot` is not unambiguous defanging"
        );
    }

    /// **The criterion.** Output is bounded, including from the one transform that can grow its
    /// input.
    #[test]
    fn replace_cannot_grow_output_without_bound() {
        let input = "a".repeat(4_096);
        let grown = Transform::Replace {
            from: "a".to_owned(),
            to: "bbbbbbbbbb".to_owned(),
        }
        .apply(&input);
        assert!(
            grown.len() <= MAX_OUTPUT_BYTES,
            "output grew to {} bytes",
            grown.len()
        );
    }

    #[test]
    fn a_chain_applies_in_order_and_is_capped() {
        let chain = vec![Transform::Undefang, Transform::Trim, Transform::Lowercase];
        assert_eq!(
            apply_chain(&chain, "  HXXP://EVIL[.]EXAMPLE  "),
            "http://evil.example"
        );

        let long: Vec<Transform> = (0..MAX_CHAIN + 5)
            .map(|_| Transform::Replace {
                from: "a".to_owned(),
                to: "aa".to_owned(),
            })
            .collect();
        // The cap is what stops a chain from being a growth loop; the value is bounded regardless.
        assert!(apply_chain(&long, "a").len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn meaningless_arguments_are_refused_at_validation_time() {
        for transform in [
            Transform::StripPrefix {
                prefix: String::new(),
            },
            Transform::StripSuffix {
                suffix: String::new(),
            },
            Transform::Replace {
                from: String::new(),
                to: "x".to_owned(),
            },
            Transform::SplitTake {
                separator: String::new(),
                index: 0,
            },
            Transform::Substring {
                start: 0,
                length: 0,
            },
        ] {
            assert!(
                transform.validate().is_err(),
                "{transform:?} should be refused"
            );
        }
        assert!(Transform::Trim.validate().is_ok());
    }
}
