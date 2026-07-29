//! Bounded paths: the only way a mapping selects a value.
//!
//! # A path is not a query language
//!
//! JSONPath, XPath, and JMESPath all have filter predicates, function calls, and recursive descent.
//! Each of those is a step towards evaluation cost that cannot be read off the expression, and
//! recursive descent in particular (`..`) walks a document of unknown depth looking for a name —
//! which is exactly the unbounded behaviour [#47](https://github.com/jusso-dev/Brolga/issues/47)
//! requires not to exist.
//!
//! So this is a deliberately small grammar:
//!
//! ```text
//! path    := segment ( '.' segment )*
//! segment := name | name '[' index ']' | name '[*]' | '[' index ']' | '[*]'
//! index   := digits
//! name    := any run of characters other than '.' '[' ']'
//! ```
//!
//! A leading `$.` is accepted and ignored, because everyone writes one.
//!
//! What is refused, by name rather than by accident: `..` (recursive descent), `[?(…)]` (filter
//! predicates), `[a,b]` (unions), `[1:3]` (slices), and `@` (the current-node reference that filter
//! expressions need). Each returns an error naming the construct, so an operator who pastes a
//! JSONPath expression learns what to remove instead of watching it match nothing.
//!
//! # Bounds are structural and enforced
//!
//! - **Segments** are capped at [`MAX_SEGMENTS`], so a path is short enough to read.
//! - **Wildcards** are capped at [`MAX_WILDCARDS`]. Two nested wildcards over a large document is a
//!   product, and three is a product of products. Two is enough for every real feed shape — a list
//!   of records each holding a list of values — and the cap is what makes the cost of a path
//!   estimable from the path itself.
//! - **Nodes visited** are counted during evaluation against a ceiling the mapping states and
//!   [`MAX_NODE_CEILING`] bounds. Evaluation stops and reports rather than continuing, because a
//!   truncated result silently understates a document.
//!
//! # Three document shapes, one path type
//!
//! The same parsed path evaluates against JSON ([`Path::select_json`]), an XML element tree
//! ([`Path::select_xml`]), and a CSV row ([`Path::select_row`]). The semantics differ where the
//! shapes genuinely differ — an XML segment may name an attribute with `@name`, and a CSV path is a
//! single column name or index — but the parse and the bounds are shared, so a mapping author learns
//! one syntax.

use crate::formats::xml::Element;

/// Most segments in one path.
pub const MAX_SEGMENTS: usize = 16;

/// Most wildcards in one path.
pub const MAX_WILDCARDS: usize = 2;

/// The largest node ceiling a mapping may state for one path evaluation.
pub const MAX_NODE_CEILING: u64 = 5_000_000;

/// Longest a single path string may be.
pub const MAX_PATH_BYTES: usize = 512;

/// Why a path was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// The path was empty.
    #[error("a path cannot be empty")]
    Empty,
    /// The path was longer than [`MAX_PATH_BYTES`].
    #[error("a path may be at most {MAX_PATH_BYTES} bytes; this one is {length}")]
    TooLong {
        /// How long it was.
        length: usize,
    },
    /// More segments than [`MAX_SEGMENTS`].
    #[error("a path may have at most {MAX_SEGMENTS} segments; this one has {count}")]
    TooManySegments {
        /// How many.
        count: usize,
    },
    /// More wildcards than [`MAX_WILDCARDS`].
    #[error(
        "a path may have at most {MAX_WILDCARDS} wildcards; this one has {count}. Each wildcard \
         multiplies the work, and capping them is what makes a path's cost readable from the path"
    )]
    TooManyWildcards {
        /// How many.
        count: usize,
    },
    /// The path used a construct this grammar does not have.
    ///
    /// Named rather than reported as a syntax error, because the commonest way to reach this is to
    /// paste a JSONPath expression, and "recursive descent is not supported" is actionable where
    /// "unexpected character" is not.
    #[error(
        "`{construct}` is not part of this path grammar: {reason}. See the module documentation for \
         the complete grammar"
    )]
    Unsupported {
        /// The construct, as written.
        construct: &'static str,
        /// Why it is absent.
        reason: &'static str,
    },
    /// A bracket was unbalanced, or its contents were not an index or `*`.
    #[error("`{fragment}` is not a valid `[index]` or `[*]`")]
    MalformedIndex {
        /// The offending fragment.
        fragment: String,
    },
    /// A segment was empty, as in `a..b` written accidentally or `a.`.
    #[error("a path has an empty segment; `{path}` has a `.` with nothing after it")]
    EmptySegment {
        /// The path as written.
        path: String,
    },
}

/// How many nodes an evaluation may visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathLimits {
    /// The ceiling on nodes visited by one evaluation.
    pub max_nodes: u64,
}

impl Default for PathLimits {
    fn default() -> Self {
        Self { max_nodes: 100_000 }
    }
}

/// What a segment selects from its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// A named child. In XML, a `@`-prefixed name selects an attribute.
    Name(String),
    /// One element of a sequence.
    Index(usize),
    /// Every element of a sequence.
    Wildcard,
}

/// A parsed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    steps: Vec<Step>,
    source: String,
}

impl Path {
    /// Parse a path, refusing anything outside the grammar.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] naming what was wrong and, for an unsupported construct, what it was.
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(PathError::Empty);
        }
        if trimmed.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong {
                length: trimmed.len(),
            });
        }

        // Named refusals first, so a pasted JSONPath expression produces a useful error rather than
        // a confusing one. Order matters: `..` must be caught before segment splitting turns it into
        // an empty segment.
        for (construct, marker, reason) in [
            (
                "..",
                "..",
                "recursive descent walks a document of unknown depth, so its cost cannot be bounded \
                 from the expression",
            ),
            (
                "[?(",
                "[?(",
                "filter predicates are an expression language, which this format deliberately does \
                 not have",
            ),
            (
                "@",
                "@.",
                "the current-node reference exists only to be used inside filter predicates",
            ),
        ] {
            if trimmed.contains(marker) {
                return Err(PathError::Unsupported { construct, reason });
            }
        }

        // A slice is a colon *inside brackets*. Checked structurally rather than by searching for a
        // bare `:`, because a JSON key may legitimately contain one and refusing every such key to
        // catch a slice would be a false positive an operator could not work around.
        if slices(trimmed) {
            return Err(PathError::Unsupported {
                construct: "[start:end]",
                reason: "array slices select a range whose size is not stated; use an index or a \
                         wildcard",
            });
        }

        let body = trimmed
            .strip_prefix("$.")
            .or_else(|| trimmed.strip_prefix('$'))
            .unwrap_or(trimmed);
        if body.is_empty() {
            return Err(PathError::Empty);
        }

        let mut steps: Vec<Step> = Vec::new();
        let mut wildcards = 0usize;

        for segment in body.split('.') {
            if segment.is_empty() {
                return Err(PathError::EmptySegment {
                    path: trimmed.to_owned(),
                });
            }

            // A segment is a name, optionally followed by one or more bracket groups: `items[0][*]`.
            let (name, mut rest) = match segment.find('[') {
                Some(position) => (
                    segment.get(..position).unwrap_or_default(),
                    segment.get(position..).unwrap_or_default(),
                ),
                None => (segment, ""),
            };
            if !name.is_empty() {
                if name.contains(']') {
                    return Err(PathError::MalformedIndex {
                        fragment: segment.to_owned(),
                    });
                }
                steps.push(Step::Name(name.to_owned()));
            }

            while !rest.is_empty() {
                let close = rest.find(']').ok_or_else(|| PathError::MalformedIndex {
                    fragment: segment.to_owned(),
                })?;
                let inner = rest.get(1..close).unwrap_or_default();
                rest = rest.get(close.saturating_add(1)..).unwrap_or_default();

                if inner == "*" {
                    wildcards = wildcards.saturating_add(1);
                    steps.push(Step::Wildcard);
                } else if inner.contains(',') {
                    return Err(PathError::Unsupported {
                        construct: "[a,b]",
                        reason: "a union selects several things at once; name them as separate \
                                 fields instead",
                    });
                } else {
                    let index: usize = inner.parse().map_err(|_| PathError::MalformedIndex {
                        fragment: segment.to_owned(),
                    })?;
                    steps.push(Step::Index(index));
                }
            }
        }

        if steps.is_empty() {
            return Err(PathError::Empty);
        }
        if steps.len() > MAX_SEGMENTS {
            return Err(PathError::TooManySegments { count: steps.len() });
        }
        if wildcards > MAX_WILDCARDS {
            return Err(PathError::TooManyWildcards { count: wildcards });
        }

        Ok(Self {
            steps,
            source: trimmed.to_owned(),
        })
    }

    /// The path as written, for diagnostics and explain output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// How many wildcards this path has, for explain output.
    #[must_use]
    pub fn wildcards(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| matches!(step, Step::Wildcard))
            .count()
    }

    /// Whether this path selects at most one value.
    ///
    /// A path with no wildcard does. Used by the engine to tell "this field has one value" from "this
    /// field is a list", without having to evaluate it first.
    #[must_use]
    pub fn is_singular(&self) -> bool {
        self.wildcards() == 0
    }

    /// Select every JSON value this path reaches.
    ///
    /// Returns `Err` with the number of nodes visited if the ceiling was reached. An error rather
    /// than a truncated list: a partial result would silently understate the document, and a caller
    /// that could not tell the difference would report a short answer as a complete one.
    ///
    /// # Errors
    ///
    /// Returns the node count if evaluation exceeded `limits.max_nodes`.
    pub fn select_json<'a>(
        &self,
        root: &'a serde_json::Value,
        limits: PathLimits,
    ) -> Result<Vec<&'a serde_json::Value>, u64> {
        let mut current: Vec<&serde_json::Value> = vec![root];
        let mut visited: u64 = 1;

        for step in &self.steps {
            let mut next: Vec<&serde_json::Value> = Vec::new();
            for value in current {
                match step {
                    Step::Name(name) => {
                        if let Some(child) = value.get(name.as_str()) {
                            next.push(child);
                        }
                    }
                    Step::Index(index) => {
                        if let Some(child) = value.get(*index) {
                            next.push(child);
                        }
                    }
                    Step::Wildcard => {
                        if let Some(array) = value.as_array() {
                            next.extend(array.iter());
                        } else if let Some(object) = value.as_object() {
                            // A wildcard over an object yields its values. Feeds keyed by identifier
                            // — `{"1.2.3.4": {...}}` — are common enough that refusing this would
                            // send an operator back to reshaping files by hand.
                            next.extend(object.values());
                        }
                    }
                }
                visited = visited.saturating_add(1);
                if visited > limits.max_nodes {
                    return Err(visited);
                }
            }
            visited = visited.saturating_add(u64::try_from(next.len()).unwrap_or(u64::MAX));
            if visited > limits.max_nodes {
                return Err(visited);
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }

        Ok(current)
    }

    /// Select every string this path reaches in a JSON document.
    ///
    /// Numbers and booleans are rendered rather than skipped: a feed that writes a confidence as `90`
    /// and one that writes it as `"90"` are saying the same thing, and a mapping author should not
    /// have to know which. An object or an array selects nothing — a structure is not a value.
    ///
    /// # Errors
    ///
    /// Returns the node count if evaluation exceeded `limits.max_nodes`.
    pub fn select_json_strings(
        &self,
        root: &serde_json::Value,
        limits: PathLimits,
    ) -> Result<Vec<String>, u64> {
        Ok(self
            .select_json(root, limits)?
            .into_iter()
            .filter_map(scalar_string)
            .collect())
    }

    /// Select every string this path reaches in an XML element tree.
    ///
    /// A `@`-prefixed segment selects an attribute of the current element. A plain segment selects
    /// child elements by name; a wildcard after it selects all of them rather than the first. A
    /// segment reaching an element yields that element's text.
    ///
    /// # Errors
    ///
    /// Returns the node count if evaluation exceeded `limits.max_nodes`.
    pub fn select_xml(&self, root: &Element, limits: PathLimits) -> Result<Vec<String>, u64> {
        // Children of one name are collected per step, and a wildcard means "keep all of them"
        // rather than "descend into each". Without a wildcard a named step takes the first match,
        // which is what a singular path means.
        let mut current: Vec<&Element> = vec![root];
        let mut visited: u64 = 1;
        let mut attribute: Option<String> = None;

        for step in &self.steps {
            if attribute.is_some() {
                // An attribute is a leaf. A path continuing past one is a path that cannot match.
                return Ok(Vec::new());
            }
            let mut next: Vec<&Element> = Vec::new();
            match step {
                Step::Name(name) => {
                    if let Some(stripped) = name.strip_prefix('@') {
                        attribute = Some(stripped.to_owned());
                        continue;
                    }
                    for element in &current {
                        for child in &element.children {
                            if child.name == *name {
                                next.push(child);
                            }
                        }
                        visited = visited.saturating_add(
                            u64::try_from(element.children.len()).unwrap_or(u64::MAX),
                        );
                        if visited > limits.max_nodes {
                            return Err(visited);
                        }
                    }
                    // A named step with no following wildcard is singular: the first match.
                    next.truncate(if self.is_singular() { 1 } else { next.len() });
                }
                Step::Index(index) => {
                    if let Some(element) = current.get(*index) {
                        next.push(element);
                    }
                    visited = visited.saturating_add(1);
                }
                Step::Wildcard => {
                    // The wildcard keeps whatever the previous named step collected. It exists in an
                    // XML path to say "all of these", which is the choice the previous step deferred.
                    next = current.clone();
                }
            }
            if visited > limits.max_nodes {
                return Err(visited);
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }

        if let Some(name) = attribute {
            return Ok(current
                .into_iter()
                .filter_map(|element| element.attribute(&name).map(ToOwned::to_owned))
                .filter(|value| !value.trim().is_empty())
                .collect());
        }

        Ok(current
            .into_iter()
            .map(|element| element.text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .collect())
    }

    /// Select the elements this path reaches, rather than their text.
    ///
    /// What a record selector needs: an XML mapping's `records` path picks the elements each of which
    /// is one record, and the field paths then run relative to each. Separate from [`Self::select_xml`]
    /// because that one is for reading a *value*, and an element is not one.
    ///
    /// # Errors
    ///
    /// Returns the node count if evaluation exceeded `limits.max_nodes`.
    pub fn select_elements<'a>(
        &self,
        root: &'a Element,
        limits: PathLimits,
    ) -> Result<Vec<&'a Element>, u64> {
        let mut current: Vec<&Element> = vec![root];
        let mut visited: u64 = 1;

        for step in &self.steps {
            let mut next: Vec<&Element> = Vec::new();
            match step {
                Step::Name(name) => {
                    if name.starts_with('@') {
                        // An attribute is not an element, so a record selector naming one selects
                        // nothing rather than silently selecting its parent.
                        return Ok(Vec::new());
                    }
                    for element in &current {
                        for child in &element.children {
                            if child.name == *name {
                                next.push(child);
                            }
                        }
                        visited = visited.saturating_add(
                            u64::try_from(element.children.len()).unwrap_or(u64::MAX),
                        );
                        if visited > limits.max_nodes {
                            return Err(visited);
                        }
                    }
                }
                Step::Index(index) => {
                    if let Some(element) = current.get(*index) {
                        next.push(element);
                    }
                    visited = visited.saturating_add(1);
                }
                Step::Wildcard => next = current.clone(),
            }
            if visited > limits.max_nodes {
                return Err(visited);
            }
            current = next;
            if current.is_empty() {
                break;
            }
        }

        Ok(current)
    }

    /// Select a value from a CSV row by column name or index.
    ///
    /// A CSV path is one segment: a header name, or `[n]` for a positional column. Anything longer is
    /// a path that cannot match a flat row, and it selects nothing rather than being an error — a
    /// mapping shared between a JSON and a CSV feed should not fail to load against one of them.
    #[must_use]
    pub fn select_row(&self, headers: &[String], row: &[String]) -> Option<String> {
        let [step] = self.steps.as_slice() else {
            return None;
        };
        let value = match step {
            Step::Name(name) => {
                let index = headers.iter().position(|header| header == name)?;
                row.get(index)?
            }
            Step::Index(index) => row.get(*index)?,
            Step::Wildcard => return None,
        };
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }
}

/// Whether a path contains a bracketed slice.
fn slices(path: &str) -> bool {
    let mut inside = false;
    for character in path.chars() {
        match character {
            '[' => inside = true,
            ']' => inside = false,
            ':' if inside => return true,
            _ => {}
        }
    }
    false
}

/// Render a JSON scalar as a string; a structure yields nothing.
fn scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        // `null` is an explicit absence, and rendering it as `"null"` would turn one into a value.
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
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

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn the_grammar_parses_what_it_documents() {
        for path in [
            "a",
            "a.b.c",
            "$.a.b",
            "$a",
            "items[0]",
            "items[*]",
            "a.items[*].value",
            "[0]",
            "[*]",
            "matrix[0][1]",
            "@type",
        ] {
            assert!(Path::parse(path).is_ok(), "`{path}` should parse");
        }
    }

    /// **The criterion.** Recursive descent does not exist, and saying so is the error message.
    #[test]
    fn recursive_descent_is_refused_by_name() {
        let error = Path::parse("$..value").unwrap_err();
        assert!(matches!(
            error,
            PathError::Unsupported {
                construct: "..",
                ..
            }
        ));
        assert!(error.to_string().contains("unknown depth"), "{error}");
    }

    #[test]
    fn every_expression_language_construct_is_refused_by_name() {
        for (path, construct) in [
            ("items[?(@.type=='x')]", "[?("),
            ("items[0,1]", "[a,b]"),
            ("items[1:3]", "[start:end]"),
        ] {
            let error = Path::parse(path).unwrap_err();
            match error {
                PathError::Unsupported {
                    construct: found, ..
                } => {
                    assert_eq!(found, construct, "`{path}`");
                }
                other => panic!("`{path}` gave {other:?}"),
            }
        }
    }

    #[test]
    fn wildcards_are_capped() {
        assert!(Path::parse("a[*].b[*]").is_ok());
        let error = Path::parse("a[*].b[*].c[*]").unwrap_err();
        assert!(matches!(error, PathError::TooManyWildcards { count: 3 }));
        assert!(error.to_string().contains("multiplies the work"), "{error}");
    }

    #[test]
    fn segments_are_capped_and_length_is_capped() {
        let long: String = (0..MAX_SEGMENTS + 2)
            .map(|n| format!("s{n}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(matches!(
            Path::parse(&long).unwrap_err(),
            PathError::TooManySegments { .. }
        ));

        let huge = "a".repeat(MAX_PATH_BYTES + 1);
        assert!(matches!(
            Path::parse(&huge).unwrap_err(),
            PathError::TooLong { .. }
        ));
    }

    /// A colon in a key is legitimate; only a bracketed one is a slice. Refusing every key with a
    /// colon to catch a slice would be a false positive nobody could work around.
    #[test]
    fn a_colon_in_a_key_is_not_a_slice() {
        assert!(Path::parse("urn:example.value").is_ok());
        assert!(Path::parse("items[1:3]").is_err());
    }

    #[test]
    fn a_malformed_bracket_is_refused() {
        for path in ["a[", "a[b]", "a]b"] {
            assert!(Path::parse(path).is_err(), "`{path}` should be refused");
        }
    }

    #[test]
    fn json_selection_walks_names_indices_and_wildcards() {
        let document = json(r#"{"data":[{"v":"1.2.3.4"},{"v":"5.6.7.8"}]}"#);
        let limits = PathLimits::default();

        assert_eq!(
            Path::parse("data[0].v")
                .unwrap()
                .select_json_strings(&document, limits)
                .unwrap(),
            vec!["1.2.3.4"]
        );
        assert_eq!(
            Path::parse("data[*].v")
                .unwrap()
                .select_json_strings(&document, limits)
                .unwrap(),
            vec!["1.2.3.4", "5.6.7.8"]
        );
        assert!(
            Path::parse("data[*].missing")
                .unwrap()
                .select_json_strings(&document, limits)
                .unwrap()
                .is_empty()
        );
    }

    /// A feed keyed by identifier is common enough that a wildcard over an object must work.
    #[test]
    fn a_wildcard_over_an_object_yields_its_values() {
        let document = json(r#"{"by_ip":{"1.2.3.4":{"score":9},"5.6.7.8":{"score":3}}}"#);
        let mut scores = Path::parse("by_ip[*].score")
            .unwrap()
            .select_json_strings(&document, PathLimits::default())
            .unwrap();
        scores.sort_unstable();
        assert_eq!(scores, vec!["3", "9"]);
    }

    /// A number and a string spelling of the same value are the same fact.
    #[test]
    fn numbers_and_booleans_render_but_structures_and_nulls_do_not() {
        let document = json(r#"{"n":90,"s":"90","b":true,"z":null,"o":{},"a":[]}"#);
        let limits = PathLimits::default();
        let one = |path: &str| {
            Path::parse(path)
                .unwrap()
                .select_json_strings(&document, limits)
                .unwrap()
        };
        assert_eq!(one("n"), one("s"));
        assert_eq!(one("b"), vec!["true"]);
        assert!(
            one("z").is_empty(),
            "`null` is an absence, not the text `null`"
        );
        assert!(one("o").is_empty());
        assert!(one("a").is_empty());
    }

    /// **The criterion.** Evaluation is bounded, and reaching the bound is an error rather than a
    /// short answer.
    #[test]
    fn exceeding_the_node_ceiling_is_an_error_not_a_truncated_result() {
        let values: Vec<serde_json::Value> = (0..1_000)
            .map(|n| serde_json::json!({"v": n.to_string()}))
            .collect();
        let document = serde_json::json!({"data": values});

        let path = Path::parse("data[*].v").unwrap();
        assert!(
            path.select_json(&document, PathLimits { max_nodes: 50 })
                .is_err(),
            "a partial result would silently understate the document"
        );
        assert!(
            path.select_json(&document, PathLimits { max_nodes: 100_000 })
                .is_ok()
        );
    }

    #[test]
    fn a_csv_path_selects_by_header_name_or_position() {
        let headers = vec!["indicator".to_owned(), "score".to_owned()];
        let row = vec!["1.2.3.4".to_owned(), "90".to_owned()];

        assert_eq!(
            Path::parse("indicator").unwrap().select_row(&headers, &row),
            Some("1.2.3.4".to_owned())
        );
        assert_eq!(
            Path::parse("[1]").unwrap().select_row(&headers, &row),
            Some("90".to_owned())
        );
        assert_eq!(
            Path::parse("absent").unwrap().select_row(&headers, &row),
            None
        );
        // A nested path against a flat row selects nothing rather than failing.
        assert_eq!(Path::parse("a.b").unwrap().select_row(&headers, &row), None);
    }

    #[test]
    fn an_xml_path_selects_text_and_attributes() {
        let document = br#"<feed><item type="bad"><value>1.2.3.4</value></item>
                           <item type="good"><value>5.6.7.8</value></item></feed>"#;
        let root = crate::formats::xml::read_document(document).unwrap();
        let limits = PathLimits::default();

        assert_eq!(
            Path::parse("item.value")
                .unwrap()
                .select_xml(&root, limits)
                .unwrap(),
            vec!["1.2.3.4"],
            "a path with no wildcard is singular"
        );
        assert_eq!(
            Path::parse("item[*].value")
                .unwrap()
                .select_xml(&root, limits)
                .unwrap(),
            vec!["1.2.3.4", "5.6.7.8"]
        );
        assert_eq!(
            Path::parse("item.@type")
                .unwrap()
                .select_xml(&root, limits)
                .unwrap(),
            vec!["bad"]
        );
    }

    #[test]
    fn a_path_continuing_past_an_attribute_selects_nothing() {
        let root = crate::formats::xml::read_document(br#"<a b="c"><d>e</d></a>"#).unwrap();
        assert!(
            Path::parse("@b.d")
                .unwrap()
                .select_xml(&root, PathLimits::default())
                .unwrap()
                .is_empty(),
            "an attribute is a leaf"
        );
    }
}
