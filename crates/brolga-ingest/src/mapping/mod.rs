//! Declarative mappings: reading a format nobody wrote a parser for.
//!
//! # The problem this solves, and the one it refuses to
//!
//! Every organisation has a feed nobody else has — an internal JSON export, a CSV from a vendor
//! whose schema is in a PDF, an XML dump from a device management console. Writing a Rust parser for
//! each is not viable, so the alternative most tools reach for is an embedded scripting language.
//!
//! That alternative is what this module exists to avoid. A mapping here is **data, not code**:
//! declarative, validated before it runs, bounded in what it can touch, and incapable of expressing
//! a loop. [#47](https://github.com/jusso-dev/Brolga/issues/47)'s acceptance criteria say it
//! plainly — no shell, no filesystem, no network, no dynamic code, no arbitrary Rust — and its
//! non-goal says no Turing-complete expression language. Those are the same requirement stated twice,
//! and the way to satisfy both is for the mapping format to have no mechanism that could grow into
//! one.
//!
//! So there is no expression evaluator. There are *paths*, which select values, and *transforms*,
//! which are a closed list of named string operations. A mapping cannot branch, cannot loop, cannot
//! call anything, and cannot name a transform that is not in [`transform::ALLOWED`]. Adding a
//! capability means editing this crate and shipping a release — which is the point.
//!
//! # A mapping is about one observable per record
//!
//! Exactly one field must be marked `subject: true`, and its target must be an observable. Everything
//! else in the record becomes a claim about that observable.
//!
//! This is a real constraint rather than an implementation shortcut. A record with no subject is a
//! bag of strings with nothing to attach them to, and a record with two subjects is ambiguous about
//! which one the other fields describe — "confidence 90" attached to both an IP address and a domain
//! asserts something nobody wrote down. Making it explicit and singular means a mapping either says
//! what its records are about or fails validation.
//!
//! # What a mapping deliberately cannot do
//!
//! **Mint entities.** An entity needs a canonical identity rule for its kind, and letting a mapping
//! create entities from arbitrary strings would let one feed put thousands of near-duplicate hubs in
//! the middle of the graph — `Acme Corp`, `ACME Corp.`, `acme corp` as three actors. Observables have
//! canonicalisers that make identity a function of the value; entity names do not.
//!
//! **Mint relationships.** Same reason, one step worse: an edge between two invented entities is a
//! claim about the world that no source made.
//!
//! Both are recorded here as refused rather than merely absent, because "the mapping engine does not
//! do that yet" and "the mapping engine will not do that" are different promises, and the second one
//! is the one being made.
//!
//! # Everything is bounded before it runs
//!
//! [`Mapping::validate`] runs at load time and rejects a mapping that could not be executed safely,
//! rather than discovering it mid-document: an unknown transform, a path with recursive descent, a
//! record count over the ceiling, a missing or duplicated subject. `brolga mapping validate` is that
//! function, and `brolga mapping explain` prints what a valid mapping will do — including what it
//! will refuse — so an operator can read the behaviour without ingesting anything.

pub mod engine;
pub mod path;
pub mod transform;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use engine::{Explanation, MappedParser};
pub use path::{Path, PathError, PathLimits};
pub use transform::{Transform, TransformError};

/// The mapping document's schema tag.
///
/// A mapping must declare it. A document that does not is refused rather than read on a guess: a
/// mapping is executed against untrusted input, and executing one whose vintage is unknown means not
/// knowing which rules were in force when it was written.
pub const MAPPING_SCHEMA: &str = "brolga.mapping/1.0";

/// The schema tags this build accepts.
///
/// A list rather than a single constant, so that a minor revision can be accepted alongside its
/// predecessor without a flag day.
pub const ACCEPTED_SCHEMAS: &[&str] = &[MAPPING_SCHEMA];

/// Most fields one mapping may declare.
pub const MAX_FIELDS: usize = 256;

/// Most filters one mapping may declare.
pub const MAX_FILTERS: usize = 64;

/// The largest record ceiling a mapping may ask for.
///
/// A mapping states its own `max_records`, and this is the ceiling on what it may state. Without it,
/// a mapping could raise its own limits, which would make the limit a suggestion.
pub const MAX_RECORD_CEILING: u64 = 5_000_000;

/// What went wrong with a mapping document.
///
/// Every variant names the field and says what would have been acceptable, because a validation
/// error an operator cannot act on is a failure of the validator rather than of the mapping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MappingError {
    /// The document was not readable as YAML or JSON.
    #[error("the mapping is not readable: {0}")]
    Unreadable(String),
    /// The document declared no schema tag, or one this build does not accept.
    #[error(
        "the mapping declares `schema_version: {found}`; this build accepts {accepted}. A mapping \
         whose vintage is unknown is refused rather than read on a guess"
    )]
    UnknownSchema {
        /// What the document said.
        found: String,
        /// What this build would have accepted.
        accepted: String,
    },
    /// A required top-level field was missing or empty.
    #[error("the mapping has no `{field}`, which every mapping must state")]
    Missing {
        /// The field name.
        field: &'static str,
    },
    /// A field's target, path, or transform list was unusable.
    #[error("field `{field}`: {reason}")]
    Field {
        /// Which field, by its path.
        field: String,
        /// What was wrong.
        reason: String,
    },
    /// A path could not be parsed, or asked for something paths cannot express.
    #[error("path `{path}`: {source}")]
    Path {
        /// The path as written.
        path: String,
        /// Why it was refused.
        #[source]
        source: PathError,
    },
    /// A transform was not on the allow-list.
    #[error(transparent)]
    Transform(#[from] TransformError),
    /// No field, or more than one, was marked as the record's subject.
    #[error(
        "the mapping marks {count} fields `subject: true`; exactly one is required. A record with \
         no subject has nothing to attach its claims to, and one with two is ambiguous about which \
         the other fields describe"
    )]
    Subject {
        /// How many were marked.
        count: usize,
    },
    /// The subject field's target was not an observable.
    #[error(
        "the subject field `{field}` targets {target}, but a subject must be an observable — it is \
         the thing the record is about, and only an observable has a canonicaliser that makes \
         identity a function of the value"
    )]
    SubjectNotObservable {
        /// Which field.
        field: String,
        /// What it targeted instead.
        target: String,
    },
    /// A limit exceeded the ceiling this build enforces.
    #[error(
        "`{field}` is {stated}, over the {ceiling} this build enforces; a mapping may lower its own \
         limits and never raise them"
    )]
    LimitTooHigh {
        /// Which limit.
        field: &'static str,
        /// What the mapping asked for.
        stated: u64,
        /// The ceiling.
        ceiling: u64,
    },
    /// The mapping declared more fields or filters than are permitted.
    #[error("the mapping declares {count} {what}, over the {limit} limit")]
    TooMany {
        /// How many.
        count: usize,
        /// Of what.
        what: &'static str,
        /// The limit.
        limit: usize,
    },
    /// Two fields target the same attribute name, so one would silently shadow the other.
    #[error(
        "two fields both target the attribute `{name}`. One would silently overwrite the other, so \
         the duplication is refused rather than resolved by declaration order"
    )]
    DuplicateAttribute {
        /// The attribute name.
        name: String,
    },
}

/// What shape the source document is in.
///
/// Declared rather than sniffed. A mapping is written against a known feed, and a mapping that
/// guessed the shape could apply JSON paths to a CSV file and silently produce nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceShape {
    /// A JSON document.
    Json,
    /// Delimited text with a header row.
    Csv,
    /// An XML document. Any `<!DOCTYPE>` is refused before parsing, as everywhere else in this crate.
    Xml,
}

impl SourceShape {
    /// A stable label for diagnostics and explain output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Xml => "xml",
        }
    }
}

/// Where a field's value ends up in the canonical model.
///
/// Internally tagged on `type`, so a target reads as a self-describing map in both YAML and JSON:
///
/// ```yaml
/// target:
///   type: observable
///   kind: ip-address
/// ```
///
/// Internally tagged rather than externally: YAML represents an externally tagged enum as a `!Tag`,
/// which is a serialisation detail an operator writing a mapping by hand should not have to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Target {
    /// Canonicalise as a named observable kind.
    ///
    /// The kind must be one of [`OBSERVABLE_KINDS`]. Naming the kind rather than inferring it is what
    /// turns a guess into a statement: a mapping author who writes `ip-address` has said what the
    /// column is, and a value that is not one is a rejection rather than a silent reclassification.
    Observable {
        /// Which observable kind.
        kind: String,
    },
    /// Try every canonicaliser and accept only an unambiguous single match.
    ///
    /// For a column whose kind genuinely varies — a mixed `indicator` column. A value that two
    /// canonicalisers accept is refused with the list of what it could have been, never guessed.
    Infer,
    /// A named attribute claim about the record's subject.
    Attribute {
        /// The attribute name.
        name: String,
    },
    /// A disposition claim about the record's subject.
    ///
    /// The value is matched against a closed set of truthy and falsy spellings; anything else is a
    /// rejection. A disposition is the single most consequential claim in the model, and inferring
    /// one from an unrecognised string would be the worst place in the system to guess.
    Disposition,
    /// Read the value and discard it.
    ///
    /// Useful for documenting that a column was considered and deliberately not imported, which is
    /// the difference between a mapping that covers a feed and one that merely runs against it.
    Ignore,
}

impl Target {
    /// A stable label for diagnostics and explain output.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Observable { kind } => format!("observable:{kind}"),
            Self::Infer => "observable:infer".to_owned(),
            Self::Attribute { name } => format!("attribute:{name}"),
            Self::Disposition => "disposition".to_owned(),
            Self::Ignore => "ignore".to_owned(),
        }
    }
}

/// The observable kinds a mapping may name.
///
/// The same labels the flat-format inference uses, so a mapping and an inferred column produce the
/// same observable for the same value rather than two spellings of one thing.
pub const OBSERVABLE_KINDS: &[&str] = &[
    "ip-address",
    "ip-range",
    "domain-name",
    "url",
    "email-address",
    "file-hash",
    "file-name",
    "file-path",
];

/// One field of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct FieldMapping {
    /// Where to find the value.
    pub path: String,
    /// Where the value goes.
    pub target: Target,
    /// Named string operations, applied in order.
    #[serde(default)]
    pub transforms: Vec<Transform>,
    /// A value to use when the path selects nothing or an empty string.
    #[serde(default)]
    pub default: Option<String>,
    /// Whether a record missing this field is a rejection.
    ///
    /// Defaults to false: a feed with an optional column is the ordinary case, and a mapping that
    /// made everything mandatory would reject most of a real document.
    #[serde(default)]
    pub required: bool,
    /// Whether this field is the thing the record is about. Exactly one field must set it.
    #[serde(default)]
    pub subject: bool,
}

/// How a filter compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FilterOp {
    /// The selected value equals the stated one, case-sensitively.
    Equals,
    /// It does not.
    NotEquals,
    /// The path selects a non-empty value.
    Present,
    /// The path selects nothing, or an empty string.
    Absent,
    /// The value begins with the stated string.
    StartsWith,
    /// The value contains the stated string.
    Contains,
}

impl FilterOp {
    /// A stable label for explain output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::NotEquals => "not_equals",
            Self::Present => "present",
            Self::Absent => "absent",
            Self::StartsWith => "starts_with",
            Self::Contains => "contains",
        }
    }

    /// Whether this operator needs a `value` to compare against.
    #[must_use]
    pub const fn needs_value(self) -> bool {
        !matches!(self, Self::Present | Self::Absent)
    }
}

/// A condition a record must satisfy to be mapped at all.
///
/// Filters are conjunctive: every filter must hold. There is no `or`, and no nesting, because a
/// boolean combinator tree is the first step towards the expression language this module exists
/// without. A feed needing disjunction needs two mappings, which is a legible way to say the same
/// thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Filter {
    /// Where to find the value to test.
    pub path: String,
    /// How to compare.
    pub op: FilterOp,
    /// What to compare against. Required for every operator except `present` and `absent`.
    #[serde(default)]
    pub value: Option<String>,
}

/// The bounds a mapping runs under.
///
/// Stated in the mapping so an operator can lower them for an untrusted feed, and ceilinged by this
/// build so a mapping cannot raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Limits {
    /// Most records read from one document.
    #[serde(default = "default_max_records")]
    pub max_records: u64,
    /// Most nodes any single path evaluation may visit.
    #[serde(default = "default_max_nodes")]
    pub max_nodes: u64,
}

const fn default_max_records() -> u64 {
    100_000
}

const fn default_max_nodes() -> u64 {
    100_000
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: default_max_records(),
            max_nodes: default_max_nodes(),
        }
    }
}

/// A complete mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Mapping {
    /// The schema tag. Must be one of [`ACCEPTED_SCHEMAS`].
    pub schema_version: String,
    /// A stable identifier for this mapping.
    ///
    /// Stamped into the transformation chain of every record the mapping produces, so renaming one
    /// orphans the provenance of everything it ever mapped. Treat it as a compatibility surface.
    pub id: String,
    /// What this mapping is for, in a sentence.
    #[serde(default)]
    pub description: Option<String>,
    /// The mapping's own version.
    ///
    /// Incremented whenever the mapping's output changes for any input, for the same reason a
    /// parser's version is: the number appears in provenance, and a changed mapping that kept its
    /// number makes two different results indistinguishable.
    #[serde(default = "default_version")]
    pub version: u32,
    /// What shape the source document is in.
    pub source: SourceShape,
    /// The path selecting one record each.
    ///
    /// For CSV this is ignored — a row is a record — and stating it is an error, because a mapping
    /// that appeared to select rows by path would mislead its next reader.
    #[serde(default)]
    pub records: Option<String>,
    /// The delimiter, for a CSV source. Defaults to a comma.
    #[serde(default)]
    pub delimiter: Option<char>,
    /// Conditions every record must satisfy.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// The fields.
    pub fields: Vec<FieldMapping>,
    /// The bounds this mapping runs under.
    #[serde(default)]
    pub limits: Limits,
}

const fn default_version() -> u32 {
    1
}

impl Mapping {
    /// Read a mapping from bytes, then validate it.
    ///
    /// One function rather than two, because a `Mapping` that has not been validated is a footgun:
    /// it deserialises fine and fails somewhere in the middle of a document. Loading and validating
    /// together means every `Mapping` a caller holds is one that can be run.
    ///
    /// YAML and JSON are both accepted through the same reader — YAML 1.2 is a JSON superset, so a
    /// JSON mapping needs no separate path.
    ///
    /// # Errors
    ///
    /// Returns [`MappingError`] if the document is unreadable or does not validate.
    pub fn load(bytes: &[u8]) -> Result<Self, MappingError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|error| MappingError::Unreadable(format!("not valid UTF-8: {error}")))?;
        let mapping: Self = serde_norway::from_str(text)
            .map_err(|error| MappingError::Unreadable(error.to_string()))?;
        mapping.validate()?;
        Ok(mapping)
    }

    /// Check everything that can be checked without a document to run against.
    ///
    /// # Errors
    ///
    /// Returns the first [`MappingError`] found. First rather than all: a mapping with a bad schema
    /// tag will produce a cascade of downstream complaints, and the tag is the one to fix.
    pub fn validate(&self) -> Result<(), MappingError> {
        if !ACCEPTED_SCHEMAS.contains(&self.schema_version.as_str()) {
            return Err(MappingError::UnknownSchema {
                found: self.schema_version.clone(),
                accepted: ACCEPTED_SCHEMAS.join(", "),
            });
        }
        if self.id.trim().is_empty() {
            return Err(MappingError::Missing { field: "id" });
        }
        if self.fields.is_empty() {
            return Err(MappingError::Missing { field: "fields" });
        }
        if self.fields.len() > MAX_FIELDS {
            return Err(MappingError::TooMany {
                count: self.fields.len(),
                what: "fields",
                limit: MAX_FIELDS,
            });
        }
        if self.filters.len() > MAX_FILTERS {
            return Err(MappingError::TooMany {
                count: self.filters.len(),
                what: "filters",
                limit: MAX_FILTERS,
            });
        }
        if self.limits.max_records > MAX_RECORD_CEILING {
            return Err(MappingError::LimitTooHigh {
                field: "limits.max_records",
                stated: self.limits.max_records,
                ceiling: MAX_RECORD_CEILING,
            });
        }
        if self.limits.max_nodes > path::MAX_NODE_CEILING {
            return Err(MappingError::LimitTooHigh {
                field: "limits.max_nodes",
                stated: self.limits.max_nodes,
                ceiling: path::MAX_NODE_CEILING,
            });
        }

        // A CSV row is a record. A `records` path against CSV would look like it selected rows and
        // would in fact do nothing, which is worse than being refused.
        if self.source == SourceShape::Csv && self.records.is_some() {
            return Err(MappingError::Field {
                field: "records".to_owned(),
                reason: "a CSV row is a record, so `records` must be omitted for a CSV source"
                    .to_owned(),
            });
        }
        if self.source != SourceShape::Csv && self.delimiter.is_some() {
            return Err(MappingError::Field {
                field: "delimiter".to_owned(),
                reason: format!(
                    "`delimiter` applies to a CSV source, not to {}",
                    self.source.as_str()
                ),
            });
        }
        if let Some(records) = &self.records {
            Path::parse(records).map_err(|source| MappingError::Path {
                path: records.clone(),
                source,
            })?;
        }

        for filter in &self.filters {
            Path::parse(&filter.path).map_err(|source| MappingError::Path {
                path: filter.path.clone(),
                source,
            })?;
            if filter.op.needs_value() && filter.value.is_none() {
                return Err(MappingError::Field {
                    field: filter.path.clone(),
                    reason: format!(
                        "the `{}` filter needs a `value` to compare against",
                        filter.op.as_str()
                    ),
                });
            }
            if !filter.op.needs_value() && filter.value.is_some() {
                return Err(MappingError::Field {
                    field: filter.path.clone(),
                    reason: format!(
                        "the `{}` filter takes no `value`; one was given, which would be silently \
                         ignored",
                        filter.op.as_str()
                    ),
                });
            }
        }

        let mut subjects = 0usize;
        let mut attributes: BTreeSet<&str> = BTreeSet::new();
        for field in &self.fields {
            Path::parse(&field.path).map_err(|source| MappingError::Path {
                path: field.path.clone(),
                source,
            })?;

            if field.transforms.len() > transform::MAX_CHAIN {
                return Err(MappingError::Field {
                    field: field.path.clone(),
                    reason: format!(
                        "declares {} transforms, over the {} limit",
                        field.transforms.len(),
                        transform::MAX_CHAIN
                    ),
                });
            }
            for entry in &field.transforms {
                entry.validate()?;
            }

            match &field.target {
                Target::Observable { kind } => {
                    if !OBSERVABLE_KINDS.contains(&kind.as_str()) {
                        return Err(MappingError::Field {
                            field: field.path.clone(),
                            reason: format!(
                                "`{kind}` is not an observable kind this build knows. Available: {}",
                                OBSERVABLE_KINDS.join(", ")
                            ),
                        });
                    }
                }
                Target::Attribute { name } => {
                    if name.trim().is_empty() {
                        return Err(MappingError::Field {
                            field: field.path.clone(),
                            reason: "an attribute target needs a name".to_owned(),
                        });
                    }
                    if !attributes.insert(name.as_str()) {
                        return Err(MappingError::DuplicateAttribute { name: name.clone() });
                    }
                }
                Target::Infer | Target::Disposition | Target::Ignore => {}
            }

            if field.subject {
                subjects = subjects.saturating_add(1);
                if !matches!(field.target, Target::Observable { .. } | Target::Infer) {
                    return Err(MappingError::SubjectNotObservable {
                        field: field.path.clone(),
                        target: field.target.as_str(),
                    });
                }
            }
        }

        if subjects != 1 {
            return Err(MappingError::Subject { count: subjects });
        }

        Ok(())
    }

    /// The field marked as the record's subject.
    ///
    /// # Panics
    ///
    /// Does not panic on a validated mapping: [`Self::validate`] guarantees exactly one. Returns
    /// `None` rather than panicking if called on an unvalidated one.
    #[must_use]
    pub fn subject_field(&self) -> Option<&FieldMapping> {
        self.fields.iter().find(|field| field.subject)
    }

    /// Bounds for path evaluation under this mapping.
    #[must_use]
    pub const fn path_limits(&self) -> PathLimits {
        PathLimits {
            max_nodes: self.limits.max_nodes,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A minimal valid mapping, as a document rather than a constructed struct: the document is what
    /// an operator writes, so it is what the tests exercise.
    const MINIMAL: &str = r#"
schema_version: brolga.mapping/1.0
id: example-feed
source: json
records: data[*]
fields:
  - path: indicator
    target:
      type: observable
      kind: ip-address
    subject: true
"#;

    #[test]
    fn a_minimal_mapping_loads_and_validates() {
        let mapping = Mapping::load(MINIMAL.as_bytes()).unwrap();
        assert_eq!(mapping.id, "example-feed");
        assert_eq!(mapping.source, SourceShape::Json);
        assert_eq!(
            mapping.version, 1,
            "the version defaults rather than failing"
        );
        assert!(mapping.subject_field().is_some());
    }

    #[test]
    fn json_is_read_by_the_same_loader_as_yaml() {
        let json = r#"{"schema_version":"brolga.mapping/1.0","id":"j","source":"json",
                       "records":"data[*]",
                       "fields":[{"path":"i","target":{"type":"observable","kind":"url"},
                                  "subject":true}]}"#;
        assert!(Mapping::load(json.as_bytes()).is_ok());
    }

    #[test]
    fn a_mapping_with_no_schema_tag_this_build_knows_is_refused() {
        let document = MINIMAL.replace("brolga.mapping/1.0", "brolga.mapping/9.9");
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            matches!(error, MappingError::UnknownSchema { .. }),
            "{error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("refused rather than read on a guess"),
            "{error}"
        );
    }

    /// **The criterion.** A mapping either says what its records are about or fails validation.
    #[test]
    fn a_mapping_must_name_exactly_one_subject() {
        let none = MINIMAL.replace("    subject: true\n", "");
        assert!(matches!(
            Mapping::load(none.as_bytes()).unwrap_err(),
            MappingError::Subject { count: 0 }
        ));

        let two = format!(
            "{MINIMAL}{}",
            concat!(
                "  - path: other\n",
                "    target:\n",
                "      type: observable\n",
                "      kind: url\n",
                "    subject: true\n",
            )
        );
        assert!(matches!(
            Mapping::load(two.as_bytes()).unwrap_err(),
            MappingError::Subject { count: 2 }
        ));
    }

    #[test]
    fn a_subject_that_is_not_an_observable_is_refused() {
        let document = MINIMAL.replace(
            "      type: observable\n      kind: ip-address",
            "      type: attribute\n      name: something",
        );
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            matches!(error, MappingError::SubjectNotObservable { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn an_unknown_observable_kind_is_refused_and_lists_the_known_ones() {
        let document = MINIMAL.replace("kind: ip-address", "kind: mood-ring");
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("ip-address"), "{error}");
    }

    /// **The criterion.** A mapping may lower its own limits and never raise them.
    #[test]
    fn a_mapping_cannot_raise_its_own_limits() {
        let document = format!("{MINIMAL}limits:\n  max_records: 999999999\n");
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            matches!(
                error,
                MappingError::LimitTooHigh {
                    field: "limits.max_records",
                    ..
                }
            ),
            "{error:?}"
        );

        let lowered = format!("{MINIMAL}limits:\n  max_records: 10\n");
        assert_eq!(
            Mapping::load(lowered.as_bytes())
                .unwrap()
                .limits
                .max_records,
            10,
            "lowering must be allowed; that is the point of stating it"
        );
    }

    #[test]
    fn two_fields_targeting_one_attribute_name_is_refused() {
        let document = format!(
            "{MINIMAL}  - path: a\n    target:\n      type: attribute\n      name: dup\n  \
             - path: b\n    target:\n      type: attribute\n      name: dup\n"
        );
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            matches!(error, MappingError::DuplicateAttribute { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_csv_mapping_stating_a_record_path_is_refused() {
        let document = MINIMAL.replace("source: json", "source: csv");
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("a CSV row is a record"),
            "{error}"
        );
    }

    #[test]
    fn a_delimiter_on_a_non_csv_source_is_refused_rather_than_ignored() {
        let document = format!("{MINIMAL}delimiter: \";\"\n");
        let error = Mapping::load(document.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("applies to a CSV source"),
            "{error}"
        );
    }

    #[test]
    fn a_filter_operator_and_its_value_must_agree() {
        let needs = format!("{MINIMAL}filters:\n  - path: type\n    op: equals\n");
        assert!(
            Mapping::load(needs.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("needs a `value`")
        );

        let takes_none =
            format!("{MINIMAL}filters:\n  - path: type\n    op: present\n    value: something\n");
        assert!(
            Mapping::load(takes_none.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("takes no `value`")
        );
    }

    #[test]
    fn an_unknown_top_level_field_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` throughout: a typo in a mapping that silently did nothing would be
        // the worst failure mode this format could have.
        let document = format!("{MINIMAL}oops: true\n");
        assert!(matches!(
            Mapping::load(document.as_bytes()).unwrap_err(),
            MappingError::Unreadable(_)
        ));
    }
}
