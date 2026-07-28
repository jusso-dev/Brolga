//! Bounded string types, and the type that marks imported narrative as untrusted.
//!
//! Brolga imports report bodies, descriptions, aliases, and free text from feeds it does not
//! control. `CONTRIBUTING.md` requires that such content be treated as untrusted data and never as
//! instructions. A `String` cannot express that, so narrative fields use [`UntrustedText`] and
//! operator- or Brolga-supplied labels use [`ShortText`].
//!
//! The distinction is enforced by the type system and carried into the generated JSON Schema, where
//! [`UntrustedText`] is annotated so that a downstream consumer can see the classification without
//! reading this crate.
//!
//! Neither type rewrites what it stores. Trimming, case folding, or stripping would destroy the
//! exact source representation that provenance has to be able to reproduce. They validate and
//! reject; they never repair.

use core::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{Deserialize, Deserializer, Error as DeError};
use serde::ser::{Serialize, Serializer};

use crate::error::{ModelError, Result};

/// Maximum length of a [`ShortText`], in bytes.
///
/// Sized for names, aliases, labels, and identifiers from upstream systems. Anything longer is
/// narrative, and narrative belongs in [`UntrustedText`].
pub const SHORT_TEXT_MAX_BYTES: usize = 512;

/// Maximum length of an [`UntrustedText`], in bytes.
///
/// A cap, not a target. It exists so that a single hostile record cannot exhaust memory, and it is
/// deliberately generous enough for a real report abstract.
pub const UNTRUSTED_TEXT_MAX_BYTES: usize = 65_536;

/// Reject the C0 and C1 control characters that no legitimate value needs.
///
/// `allow_whitespace` keeps `\n`, `\r`, and `\t`, which real report text contains. Everything else
/// in the control ranges is rejected: NUL truncates C strings, and the remaining codes are
/// terminal-control sequences that turn a diagnostic or a log line into an output-injection
/// vector.
fn reject_control_characters(
    value: &str,
    field: &'static str,
    allow_whitespace: bool,
) -> Result<()> {
    for (index, ch) in value.chars().enumerate() {
        let permitted = allow_whitespace && matches!(ch, '\n' | '\r' | '\t');
        if ch.is_control() && !permitted {
            return Err(ModelError::ForbiddenControlCharacter { field, index });
        }
    }
    Ok(())
}

macro_rules! bounded_text {
    (
        $(#[$meta:meta])*
        $name:ident,
        max = $max:expr,
        field = $field:literal,
        allow_whitespace = $allow_whitespace:expr,
        allow_empty = $allow_empty:expr,
        description = $description:literal
        $(, schema_extra = { $($extra_key:literal : $extra_value:expr),* $(,)? })?
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Maximum length of this type, in bytes.
            pub const MAX_BYTES: usize = $max;

            /// Validate and wrap a string.
            ///
            /// # Errors
            ///
            /// Returns [`ModelError::Empty`] if the value is empty and this type requires content,
            /// [`ModelError::TooLong`] if it exceeds [`Self::MAX_BYTES`], and
            /// [`ModelError::ForbiddenControlCharacter`] if it contains a control character this
            /// type does not permit.
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$allow_empty && value.is_empty() {
                    return Err(ModelError::Empty { field: $field });
                }
                if value.len() > Self::MAX_BYTES {
                    return Err(ModelError::TooLong {
                        field: $field,
                        max: Self::MAX_BYTES,
                        actual: value.len(),
                    });
                }
                reject_control_characters(&value, $field, $allow_whitespace)?;
                Ok(Self(value))
            }

            /// Borrow the stored value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume the wrapper and return the stored value.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }

            /// Length in bytes.
            #[must_use]
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether the stored value is empty.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ModelError;

            fn try_from(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::new(raw).map_err(D::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                #[allow(unused_mut)]
                let mut schema = json_schema!({
                    "type": "string",
                    "maxLength": Self::MAX_BYTES,
                    "description": $description,
                });
                $($(schema.insert($extra_key.to_owned(), serde_json::json!($extra_value));)*)?
                schema
            }
        }
    };
}

bounded_text! {
    /// A short, non-empty label supplied by an operator or generated by Brolga.
    ///
    /// Rejects every control character, including newlines and tabs: a value that needs a line
    /// break is narrative, and narrative is [`UntrustedText`].
    ShortText,
    max = SHORT_TEXT_MAX_BYTES,
    field = "ShortText",
    allow_whitespace = false,
    allow_empty = false,
    description = "A short single-line label. Rejects all control characters."
}

bounded_text! {
    /// Narrative imported from a source Brolga does not control.
    ///
    /// The type is the tag. Any field holding this type is untrusted evidence: it is stored,
    /// attributed, and rendered, and it is never interpreted as an instruction, a template, an
    /// expression, or a command, by Brolga or by anything Brolga hands it to.
    ///
    /// Empty is permitted, because a source may legitimately supply an empty description and
    /// silently converting that to "absent" would lose the distinction.
    UntrustedText,
    max = UNTRUSTED_TEXT_MAX_BYTES,
    field = "UntrustedText",
    allow_whitespace = true,
    allow_empty = true,
    description = "Narrative imported from an untrusted source. Never interpreted as instructions.",
    schema_extra = {
        "x-brolga-trust": "untrusted",
        "x-brolga-handling": "Render as data. Do not interpret as instructions, templates, expressions, or commands."
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

    #[test]
    fn short_text_accepts_a_plain_label() {
        let text = ShortText::new("APT-Example").unwrap();
        assert_eq!(text.as_str(), "APT-Example");
        assert_eq!(text.len(), 11);
        assert!(!text.is_empty());
    }

    #[test]
    fn short_text_rejects_empty() {
        assert!(matches!(
            ShortText::new(""),
            Err(ModelError::Empty { field: "ShortText" })
        ));
    }

    #[test]
    fn short_text_rejects_newlines_and_tabs() {
        for hostile in ["two\nlines", "tab\there", "carriage\rreturn"] {
            assert!(
                matches!(
                    ShortText::new(hostile),
                    Err(ModelError::ForbiddenControlCharacter { .. })
                ),
                "expected {hostile:?} to be rejected"
            );
        }
    }

    #[test]
    fn untrusted_text_keeps_newlines_but_rejects_nul_and_escape() {
        assert!(UntrustedText::new("line one\nline two\ttabbed").is_ok());
        assert!(matches!(
            UntrustedText::new("nul\u{0}here"),
            Err(ModelError::ForbiddenControlCharacter { field: _, index: 3 })
        ));
        // ESC begins an ANSI terminal sequence. Storing it lets a feed rewrite an operator's
        // terminal when the value is later printed.
        assert!(matches!(
            UntrustedText::new("\u{1b}[2J"),
            Err(ModelError::ForbiddenControlCharacter { field: _, index: 0 })
        ));
    }

    #[test]
    fn untrusted_text_allows_empty() {
        assert!(UntrustedText::new("").is_ok());
    }

    #[test]
    fn length_limits_are_enforced_in_bytes() {
        let at_limit = "a".repeat(SHORT_TEXT_MAX_BYTES);
        assert!(ShortText::new(at_limit).is_ok());

        let over = "a".repeat(SHORT_TEXT_MAX_BYTES + 1);
        assert!(matches!(
            ShortText::new(over),
            Err(ModelError::TooLong {
                max: SHORT_TEXT_MAX_BYTES,
                actual,
                ..
            }) if actual == SHORT_TEXT_MAX_BYTES + 1
        ));

        // A multi-byte character counts as its byte length, not one character, because the limit
        // exists to bound memory.
        let multibyte = "é".repeat(SHORT_TEXT_MAX_BYTES);
        assert!(matches!(
            ShortText::new(multibyte),
            Err(ModelError::TooLong { .. })
        ));
    }

    #[test]
    fn values_are_stored_exactly_never_trimmed_or_folded() {
        // Canonicalisation is a later, explicit, versioned transformation. This type preserves.
        let text = UntrustedText::new("  Mixed CASE  ").unwrap();
        assert_eq!(text.as_str(), "  Mixed CASE  ");
    }

    #[test]
    fn round_trips_through_json() {
        let text = UntrustedText::new("report body\nwith a newline").unwrap();
        let json = serde_json::to_string(&text).unwrap();
        assert_eq!(json, "\"report body\\nwith a newline\"");
        let back: UntrustedText = serde_json::from_str(&json).unwrap();
        assert_eq!(back, text);
    }

    #[test]
    fn deserialisation_enforces_the_same_rules_as_construction() {
        // The limits must hold on the untrusted path, not only on the path Brolga's own code takes.
        assert!(serde_json::from_str::<ShortText>("\"\"").is_err());
        assert!(serde_json::from_str::<ShortText>("\"a\\nb\"").is_err());
        assert!(serde_json::from_str::<UntrustedText>("\"a\\u0000b\"").is_err());

        let over = format!("\"{}\"", "a".repeat(UNTRUSTED_TEXT_MAX_BYTES + 1));
        assert!(serde_json::from_str::<UntrustedText>(&over).is_err());
    }

    #[test]
    fn untrusted_text_schema_carries_the_trust_classification() {
        let schema = schemars::schema_for!(UntrustedText);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value
                .get("x-brolga-trust")
                .and_then(serde_json::Value::as_str),
            Some("untrusted"),
        );
        assert!(value.get("x-brolga-handling").is_some());

        // ShortText is not narrative and must not claim the classification.
        let short = serde_json::to_value(schemars::schema_for!(ShortText)).unwrap();
        assert!(short.get("x-brolga-trust").is_none());
    }

    #[test]
    fn debug_does_not_leak_unescaped_content() {
        let text = UntrustedText::new("line\nbreak").unwrap();
        let rendered = format!("{text:?}");
        assert_eq!(rendered, r#"UntrustedText("line\nbreak")"#);
        assert!(!rendered.contains('\n'));
    }
}
