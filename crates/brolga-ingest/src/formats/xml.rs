//! OpenIOC and IODEF documents, over a deliberately hostile XML reader.
//!
//! # Entity expansion is not merely disabled, a DTD is refused
//!
//! [#52](https://github.com/jusso-dev/Brolga/issues/52) requires XML entity expansion to be off.
//! This module goes further and **refuses any document carrying a `<!DOCTYPE>` at all**, because
//! "expansion is off" is a property of a reader's configuration and "there is no DTD" is a property
//! of the document. The first has to stay true through every future change to the reader; the second
//! is checked once, before anything is parsed.
//!
//! That closes the whole family at once — billion laughs and quadratic blowup, which need internal
//! entities; XXE file disclosure and SSRF, which need external ones; and parameter-entity variants
//! of both. A legitimate OpenIOC or IODEF document does not carry a DTD, so nothing an operator
//! actually receives is lost.
//!
//! Bounds on top of that: element count, nesting depth, attribute count, and text length, all
//! checked while reading rather than after building a tree.
//!
//! # What the two formats become
//!
//! - **OpenIOC** — the `<ioc>` is a definition of how to find something, so it becomes an
//!   [`EntityKind::DetectionRule`]. An `<IndicatorItem>` under `condition="is"` names a whole value
//!   and yields an observable; `contains`, `isnot`, and the negated forms are *predicates* over a
//!   set and are named as unread rather than mined for a value they do not state.
//! - **IODEF** — an `<Incident>` is a discrete event under investigation, which is exactly
//!   [`EntityKind::Incident`]. Its `<Address>` elements become observables tied to it.
//!
//! Neither format's free text is interpreted. A `<Description>` is evidence, recorded verbatim.

use std::collections::BTreeMap;

use brolga_model::{
    Assertion, Claim, Entity, EntityKind, Id, NodeRef, Observable, RecordOrigin, Relationship,
    RelationshipKind, ShortText, UntrustedText,
};
use quick_xml::events::Event;

use crate::canon;
use crate::detect::{Candidate, DetectionConfidence, FormatHint};
use crate::error::ParseError;
use crate::parser::{
    IntelligenceParser, ParseContext, ParseOutput, ParsedRecord, ParserId, RejectedRecord,
    candidate,
};

/// The OpenIOC parser's identifier.
pub const OPENIOC_PARSER_ID: ParserId = ParserId::new("brolga.xml.openioc");

/// The IODEF parser's identifier.
pub const IODEF_PARSER_ID: ParserId = ParserId::new("brolga.xml.iodef");

/// Media types that identify OpenIOC definitively.
pub const OPENIOC_MEDIA_TYPES: &[&str] = &["application/x-openioc+xml"];

/// Media types that identify IODEF definitively.
pub const IODEF_MEDIA_TYPES: &[&str] = &["application/iodef+xml"];

/// Deepest element nesting read.
pub const MAX_XML_DEPTH: usize = 64;

/// Most elements read from one document.
pub const MAX_XML_ELEMENTS: usize = 100_000;

/// Longest text content kept for one element.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Most attributes read from one element.
pub const MAX_ATTRIBUTES: usize = 64;

// ---------------------------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------------------------

/// One element of a parsed document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// The local name, with any namespace prefix removed.
    ///
    /// Prefixes are a document's private choice — `iodef:Incident` and `Incident` are the same
    /// element under different bindings — so matching on the prefixed form would make the mapping
    /// depend on which prefix a publisher happened to pick.
    pub name: String,
    /// Attributes, by local name.
    pub attributes: BTreeMap<String, String>,
    /// Direct text content, trimmed.
    pub text: String,
    /// Child elements, in document order.
    pub children: Vec<Element>,
}

impl Element {
    /// The first descendant with this local name, breadth-first.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Self> {
        self.descendants(name).into_iter().next()
    }

    /// Every descendant with this local name, in document order.
    #[must_use]
    pub fn descendants(&self, name: &str) -> Vec<&Self> {
        let mut found = Vec::new();
        let mut queue: Vec<&Self> = self.children.iter().collect();
        let mut index = 0;
        while index < queue.len() {
            let Some(element) = queue.get(index) else {
                break;
            };
            if element.name == name {
                found.push(*element);
            }
            let children: Vec<&Self> = element.children.iter().collect();
            queue.extend(children);
            index = index.saturating_add(1);
        }
        found
    }

    /// The trimmed text of the first descendant with this local name.
    #[must_use]
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.find(name)
            .map(|element| element.text.as_str())
            .filter(|text| !text.is_empty())
    }

    /// An attribute by local name.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }
}

/// Read a document into an element tree, refusing anything that carries a DTD.
///
/// # Errors
///
/// Returns a [`ParseError`] for a `<!DOCTYPE>`, for malformed XML, or for a document over the
/// depth, element-count, or attribute bounds.
pub fn read_document(bytes: &[u8]) -> Result<Element, ParseError> {
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let config = reader.config_mut();
    config.trim_text(true);
    // A well-formed document is required. Recovering from mismatched tags would mean guessing where
    // an element ended, and an `<Address>` attributed to the wrong `<Incident>` is worse than a
    // refused document.
    config.check_end_names = true;

    let mut buffer = Vec::new();
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut elements = 0_usize;

    loop {
        buffer.clear();
        match reader.read_event_into(&mut buffer) {
            Err(error) => {
                return Err(ParseError::new(format!("not well-formed XML: {error}")));
            }
            Ok(Event::Eof) => break,

            // The whole point. A document with no DTD cannot expand an entity, internal or
            // external, so billion laughs, quadratic blowup, and XXE are all closed here rather
            // than by a reader setting that some later change might flip back.
            Ok(Event::DocType(_)) => {
                return Err(ParseError::new(
                    "the document carries a `<!DOCTYPE>`; Brolga refuses any XML with a DTD, \
                     because a DTD is what entity-expansion and external-entity attacks need and \
                     no legitimate OpenIOC or IODEF document has one",
                ));
            }

            Ok(Event::Start(start)) => {
                elements = elements.saturating_add(1);
                if elements > MAX_XML_ELEMENTS {
                    return Err(ParseError::new(format!(
                        "the document holds more than {MAX_XML_ELEMENTS} elements"
                    )));
                }
                if stack.len() > MAX_XML_DEPTH {
                    return Err(ParseError::new(format!(
                        "the document nests deeper than {MAX_XML_DEPTH} elements"
                    )));
                }
                stack.push(element_of(&start)?);
            }
            Ok(Event::Empty(start)) => {
                elements = elements.saturating_add(1);
                if elements > MAX_XML_ELEMENTS {
                    return Err(ParseError::new(format!(
                        "the document holds more than {MAX_XML_ELEMENTS} elements"
                    )));
                }
                let element = element_of(&start)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(element);
                }
            }
            Ok(Event::End(_)) => {
                if stack.len() <= 1 {
                    return Err(ParseError::new(
                        "an end tag closes an element that never opened",
                    ));
                }
                let Some(element) = stack.pop() else { break };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(element);
                }
            }
            Ok(Event::Text(text)) => {
                let decoded = text
                    .decode()
                    .map_err(|error| ParseError::new(format!("undecodable text: {error}")))?;
                if let Some(current) = stack.last_mut() {
                    if current.text.len().saturating_add(decoded.len()) > MAX_TEXT_BYTES {
                        return Err(ParseError::new(format!(
                            "an element's text is over the {MAX_TEXT_BYTES}-byte limit"
                        )));
                    }
                    current.text.push_str(decoded.trim());
                }
            }
            // CDATA is text. Comments and processing instructions are not content and are skipped.
            Ok(Event::CData(data)) => {
                let decoded = data
                    .decode()
                    .map_err(|error| ParseError::new(format!("undecodable CDATA: {error}")))?;
                if let Some(current) = stack.last_mut() {
                    if current.text.len().saturating_add(decoded.len()) > MAX_TEXT_BYTES {
                        return Err(ParseError::new(format!(
                            "an element's text is over the {MAX_TEXT_BYTES}-byte limit"
                        )));
                    }
                    current.text.push_str(decoded.trim());
                }
            }
            Ok(_) => {}
        }
    }

    if stack.len() != 1 {
        return Err(ParseError::new(
            "the document ends with elements still open, so it is truncated",
        ));
    }
    let mut root = stack.pop().unwrap_or_default();
    // The synthetic outer element holds exactly one real root in a well-formed document.
    if root.children.len() == 1
        && let Some(actual) = root.children.pop()
    {
        return Ok(actual);
    }
    Err(ParseError::new(
        "the document has no single root element, so it is not XML Brolga can read",
    ))
}

/// Build one element from a start tag, stripping namespace prefixes.
fn element_of(start: &quick_xml::events::BytesStart<'_>) -> Result<Element, ParseError> {
    let name = local_name(start.name().as_ref());
    let mut attributes = BTreeMap::new();

    for (index, attribute) in start.attributes().enumerate() {
        if index >= MAX_ATTRIBUTES {
            return Err(ParseError::new(format!(
                "an element carries more than {MAX_ATTRIBUTES} attributes"
            )));
        }
        let attribute =
            attribute.map_err(|error| ParseError::new(format!("unreadable attribute: {error}")))?;
        let key = local_name(attribute.key.as_ref());
        // Resolves the five predefined XML entities only. A custom entity cannot exist here,
        // because a document declaring one carries a DTD and was refused above; `Implicit1_0` is
        // the version to normalise under when no declaration named one, which is every document
        // that reaches this point.
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|error| ParseError::new(format!("unreadable attribute value: {error}")))?;
        attributes.insert(key, value.into_owned());
    }

    Ok(Element {
        name,
        attributes,
        text: String::new(),
        children: Vec::new(),
    })
}

/// The part of a qualified name after any `:` prefix.
fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or(&text).to_owned()
}

// ---------------------------------------------------------------------------------------------
// OpenIOC
// ---------------------------------------------------------------------------------------------

/// An OpenIOC reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenIocParser;

impl OpenIocParser {
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

impl IntelligenceParser for OpenIocParser {
    fn id(&self) -> ParserId {
        OPENIOC_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if OPENIOC_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is OpenIOC");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        if text.contains("schemas.mandiant.com") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares the OpenIOC namespace",
            )
        } else if text.contains("<ioc") && text.contains("IndicatorItem") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "declares an `<ioc>` holding `IndicatorItem` elements",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no OpenIOC marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        let root = read_document(bytes)?;
        if root.name != "ioc" {
            return Err(ParseError::new(format!(
                "the root element is `{}` rather than `ioc`, so this is not OpenIOC",
                root.name
            )));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        context
            .check_cancelled()
            .map_err(|error| ParseError::new(error.to_string()))?;

        let mut out = ParseOutput::default();
        map_openioc(&root, &origin, field_limit, &mut out)?;

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

/// Map an `<ioc>` to the detection rule and observables it defines.
fn map_openioc(
    root: &Element,
    origin: &RecordOrigin,
    field_limit: usize,
    out: &mut ParseOutput,
) -> Result<(), ParseError> {
    let identifier = root
        .attribute("id")
        .map(ToOwned::to_owned)
        .or_else(|| root.text_of("short_description").map(ToOwned::to_owned))
        .ok_or_else(|| {
            ParseError::new("the `<ioc>` has neither an `id` nor a `short_description`")
        })?;

    let title = root
        .text_of("short_description")
        .unwrap_or(identifier.as_str());
    let name = UntrustedText::new(bounded(title, field_limit.min(UntrustedText::MAX_BYTES)))
        .map_err(|error| ParseError::new(format!("unusable `short_description`: {error}")))?;

    // The `<ioc>` id is a GUID the author minted for this definition, which is what every OpenIOC
    // consumer addresses it by.
    let id = Id::derive(&["openioc", &identifier]);
    let mut rule = Entity::new(id, EntityKind::DetectionRule, name, origin.clone());
    if let Some(description) = root.text_of("description")
        && let Ok(text) = UntrustedText::new(bounded(
            description,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
    {
        rule.description = Some(text);
    }

    let rule_ref = NodeRef::Entity(rule.id);
    for field in ["authored_by", "authored_date", "last-modified"] {
        if let Some(text) = root.text_of(field)
            && let Ok(assertion) = attribute(&format!("openioc.{field}"), text, field_limit)
        {
            out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
                rule_ref,
                assertion,
                origin.clone(),
            ))));
        }
    }

    let mut unread: Vec<String> = Vec::new();
    let mut observables: Vec<Observable> = Vec::new();

    for item in root.descendants("IndicatorItem") {
        let condition = item.attribute("condition").unwrap_or("is");
        let Some(context_element) = item.find("Context") else {
            continue;
        };
        let search = context_element.attribute("search").unwrap_or_default();
        let content = item.text_of("Content").unwrap_or_default();
        if search.is_empty() || content.is_empty() {
            continue;
        }

        // `is` states a whole value. `contains`, `isnot`, `matches`, and the negated forms describe
        // a *set* of values, and taking the operand as an observable would record a value the
        // author never said was the artefact.
        if !condition.eq_ignore_ascii_case("is") {
            unread.push(format!("{search} (condition `{condition}`)"));
            continue;
        }
        let Some(canonicaliser) = openioc_canonicaliser(search) else {
            unread.push(search.to_owned());
            continue;
        };
        match canonicaliser(content) {
            Ok(canonical) => {
                let observable = canonical.into_value();
                if !observables
                    .iter()
                    .any(|existing| existing.id() == observable.id())
                {
                    observables.push(observable);
                }
            }
            Err(error) => unread.push(format!("{search} ({error})")),
        }
    }

    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());
        out.records
            .push(ParsedRecord::Relationship(Box::new(Relationship::new(
                RelationshipKind::Indicates,
                rule_ref,
                subject,
                origin.clone(),
            ))));
        if let Ok(assertion) = attribute(
            "openioc.indicator",
            &observable.canonical_value(),
            field_limit,
        ) {
            out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                assertion,
                origin.clone(),
            ))));
        }
    }

    if !unread.is_empty() {
        unread.sort_unstable();
        unread.dedup();
        if let Ok(assertion) = attribute("openioc.unread", &unread.join(", "), field_limit) {
            out.records.push(ParsedRecord::Claim(Box::new(Claim::new(
                rule_ref,
                assertion,
                origin.clone(),
            ))));
        }
    }

    if observables.is_empty() && unread.is_empty() {
        out.rejected.push(RejectedRecord {
            reason_kind: "no_indicator_items",
            reason: "the `<ioc>` defines no `IndicatorItem` Brolga can read".to_owned(),
            offset: None,
            fragment: Some(bounded(&identifier, 200)),
        });
    }

    out.records.push(ParsedRecord::Entity(Box::new(rule)));
    Ok(())
}

/// Which canonicaliser an OpenIOC `search` path names.
fn openioc_canonicaliser(search: &str) -> Option<canon::Canonicaliser> {
    Some(match search.trim() {
        "Network/DNS" | "DnsEntryItem/Host" | "DnsEntryItem/RecordName" => canon::net::domain_name,
        "Network/URI" | "UrlHistoryItem/URL" | "Network/String" => canon::net::url,
        "PortItem/remoteIP" | "PortItem/localIP" | "Network/IP" | "RouteEntryItem/Destination" => {
            canon::net::ip_address
        }
        "FileItem/Md5sum" | "FileItem/Sha1sum" | "FileItem/Sha256sum" | "DriverItem/Md5sum" => {
            canon::file::file_hash
        }
        "FileItem/FileName" | "DriverItem/DriverName" | "ProcessItem/name" => {
            canon::file::file_name
        }
        "Email/From" | "Email/To" => canon::net::email_address,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------
// IODEF
// ---------------------------------------------------------------------------------------------

/// An IODEF reader, covering RFC 5070 (1.x) and RFC 7970 (2.x).
#[derive(Debug, Default, Clone, Copy)]
pub struct IodefParser;

impl IodefParser {
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

impl IntelligenceParser for IodefParser {
    fn id(&self) -> ParserId {
        IODEF_PARSER_ID
    }

    fn version(&self) -> u32 {
        1
    }

    fn detect(&self, hint: &FormatHint<'_>) -> Candidate {
        if IODEF_MEDIA_TYPES.contains(&hint.media_type()) {
            return candidate(self, DetectionConfidence::Certain, "media type is IODEF");
        }
        let Some(text) = hint.prefix_str() else {
            return candidate(
                self,
                DetectionConfidence::Declined,
                "input is not valid UTF-8",
            );
        };
        if text.contains("IODEF-Document") {
            candidate(
                self,
                DetectionConfidence::Certain,
                "declares an `IODEF-Document`",
            )
        } else if text.contains("iodef") && text.contains("<Incident") {
            candidate(
                self,
                DetectionConfidence::Strong,
                "declares IODEF incidents",
            )
        } else {
            candidate(
                self,
                DetectionConfidence::Declined,
                "no IODEF marker in the first bytes",
            )
        }
    }

    fn parse(&self, context: &ParseContext, bytes: &[u8]) -> Result<ParseOutput, ParseError> {
        let limits = context.limits().input;
        let root = read_document(bytes)?;
        if root.name != "IODEF-Document" {
            return Err(ParseError::new(format!(
                "the root element is `{}` rather than `IODEF-Document`",
                root.name
            )));
        }

        let origin = context
            .record_origin()
            .map_err(|error| ParseError::new(format!("could not build provenance: {error}")))?;
        let field_limit = usize::try_from(limits.max_field_bytes).unwrap_or(usize::MAX);

        let incidents = root.descendants("Incident");
        if u64::try_from(incidents.len()).unwrap_or(u64::MAX) > limits.max_records {
            return Err(ParseError::new(format!(
                "the document holds {} incidents, over the {}-record limit",
                incidents.len(),
                limits.max_records
            )));
        }

        let mut out = ParseOutput::default();
        for (index, incident) in incidents.iter().enumerate() {
            context
                .check_cancelled()
                .map_err(|error| ParseError::new(error.to_string()))?;

            match map_incident(incident, &origin, field_limit) {
                Ok(records) => out.records.extend(records),
                Err(rejection) => out.rejected.push(RejectedRecord {
                    reason_kind: rejection.0,
                    reason: rejection.1,
                    offset: u64::try_from(index).ok(),
                    fragment: None,
                }),
            }
        }

        if out.records.is_empty() && out.rejected.is_empty() {
            return Err(ParseError::new(
                "the document holds no `<Incident>`, so it reports nothing",
            ));
        }
        Ok(out)
    }
}

/// Map one `<Incident>`.
fn map_incident(
    incident: &Element,
    origin: &RecordOrigin,
    field_limit: usize,
) -> Result<Vec<ParsedRecord>, (&'static str, String)> {
    let Some(incident_id) = incident.find("IncidentID") else {
        return Err((
            "missing_incident_id",
            "the `<Incident>` has no `<IncidentID>`, which is the only thing that identifies it"
                .to_owned(),
        ));
    };

    // The CSIRT name plus its own number. An incident number is unique to the team that issued it,
    // and two teams both numbering an incident `1` reported two incidents.
    let authority = incident_id.attribute("name").unwrap_or("unnamed-csirt");
    let number = incident_id.text.as_str();
    if number.is_empty() {
        return Err((
            "empty_incident_id",
            "the `<IncidentID>` has no number".to_owned(),
        ));
    }

    let display = UntrustedText::new(bounded(
        &format!("{authority} incident {number}"),
        field_limit.min(UntrustedText::MAX_BYTES),
    ))
    .map_err(|error| ("unusable_incident_id", error.to_string()))?;

    let id = Id::derive(&["iodef", &authority.to_lowercase(), number]);
    let mut entity = Entity::new(id, EntityKind::Incident, display, origin.clone());
    if let Some(description) = incident.text_of("Description")
        && let Ok(text) = UntrustedText::new(bounded(
            description,
            field_limit.min(UntrustedText::MAX_BYTES),
        ))
    {
        entity.description = Some(text);
    }

    let incident_ref = NodeRef::Entity(entity.id);
    let mut records = Vec::new();

    for (element, name) in [
        ("ReportTime", "iodef.report_time"),
        ("StartTime", "iodef.start_time"),
        ("EndTime", "iodef.end_time"),
    ] {
        if let Some(text) = incident.text_of(element)
            && let Ok(assertion) = attribute(name, text, field_limit)
        {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                incident_ref,
                assertion,
                origin.clone(),
            ))));
        }
    }

    // `purpose` and an `Impact` severity are the reporter's own characterisation. Recorded as what
    // they are, and never mapped to a `Disposition`: "high impact" describes the effect on the
    // reporting party, not whether an address is malicious.
    if let Some(purpose) = incident.attribute("purpose")
        && let Ok(assertion) = attribute("iodef.purpose", purpose, field_limit)
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            incident_ref,
            assertion,
            origin.clone(),
        ))));
    }
    if let Some(severity) = incident
        .find("Impact")
        .and_then(|impact| impact.attribute("severity"))
        && let Ok(assertion) = attribute("iodef.impact.severity", severity, field_limit)
    {
        records.push(ParsedRecord::Claim(Box::new(Claim::new(
            incident_ref,
            assertion,
            origin.clone(),
        ))));
    }

    let mut observables: Vec<Observable> = Vec::new();
    let mut unread: Vec<String> = Vec::new();

    for address in incident.descendants("Address") {
        let category = address.attribute("category").unwrap_or_default();
        let value = address.text.as_str();
        if value.is_empty() {
            continue;
        }
        let Some(canonicaliser) = iodef_canonicaliser(category) else {
            unread.push(format!("Address category `{category}`"));
            continue;
        };
        match canonicaliser(value) {
            Ok(canonical) => {
                let observable = canonical.into_value();
                if !observables
                    .iter()
                    .any(|existing| existing.id() == observable.id())
                {
                    observables.push(observable);
                }
            }
            Err(error) => unread.push(format!("Address `{category}` ({error})")),
        }
    }

    for observable in &observables {
        let subject = NodeRef::Observable(observable.id());
        records.push(ParsedRecord::Relationship(Box::new(Relationship::new(
            // The artefact was part of the incident. Not `Indicates`: an address appearing in a
            // report is not by itself evidence the incident happened.
            RelationshipKind::PartOf,
            subject,
            incident_ref,
            origin.clone(),
        ))));
        if let Ok(assertion) =
            attribute("iodef.address", &observable.canonical_value(), field_limit)
        {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                subject,
                assertion,
                origin.clone(),
            ))));
        }
    }

    if !unread.is_empty() {
        unread.sort_unstable();
        unread.dedup();
        if let Ok(assertion) = attribute("iodef.unread", &unread.join(", "), field_limit) {
            records.push(ParsedRecord::Claim(Box::new(Claim::new(
                incident_ref,
                assertion,
                origin.clone(),
            ))));
        }
    }

    records.push(ParsedRecord::Entity(Box::new(entity)));
    Ok(records)
}

/// Which canonicaliser an IODEF `Address` category names.
fn iodef_canonicaliser(category: &str) -> Option<canon::Canonicaliser> {
    Some(match category.trim() {
        "ipv4-addr" | "ipv6-addr" => canon::net::ip_address,
        "ipv4-net" | "ipv6-net" => canon::net::ip_range,
        "e-mail" => canon::net::email_address,
        "site-uri" | "url" => canon::net::url,
        // `asn`, `mac`, `atm`, and the `-net-mask` forms have canonical shapes Brolga does not read
        // from this element yet; naming them beats silently producing nothing.
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------------

/// One attribute assertion.
fn attribute(name: &str, value: &str, field_limit: usize) -> Result<Assertion, ParseError> {
    Ok(Assertion::Attribute {
        name: ShortText::new(bounded(name, ShortText::MAX_BYTES))
            .map_err(|error| ParseError::new(error.to_string()))?,
        value: UntrustedText::new(bounded(value, field_limit.min(UntrustedText::MAX_BYTES)))
            .map_err(|error| ParseError::new(error.to_string()))?,
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

    /// The billion-laughs shape. It needs a DTD to declare its entities, and a document with a DTD
    /// never reaches the parser at all.
    #[test]
    fn a_document_declaring_entities_is_refused_before_anything_is_expanded() {
        let bomb = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<ioc><short_description>&lol1;</short_description></ioc>"#;

        let error = read_document(bomb.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("DOCTYPE"), "{error}");
    }

    /// The external-entity shape. Same DTD, same refusal — and the refusal is what stops a parse
    /// from reading a local file or making a network request.
    #[test]
    fn an_external_entity_reference_is_refused_with_the_dtd_that_declares_it() {
        let xxe = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<ioc><description>&xxe;</description></ioc>"#;

        assert!(read_document(xxe.as_bytes()).is_err());
    }

    /// A prefix is a document's private choice. Matching the prefixed form would make the mapping
    /// depend on which one a publisher happened to pick.
    #[test]
    fn namespace_prefixes_do_not_change_which_elements_are_found() {
        let prefixed = r#"<iodef:IODEF-Document xmlns:iodef="urn:ietf:params:xml:ns:iodef-1.0">
  <iodef:Incident><iodef:IncidentID name="csirt.example.com">7</iodef:IncidentID></iodef:Incident>
</iodef:IODEF-Document>"#;

        let root = read_document(prefixed.as_bytes()).unwrap();
        assert_eq!(root.name, "IODEF-Document");
        assert_eq!(root.find("IncidentID").map(|e| e.text.as_str()), Some("7"));
    }

    #[test]
    fn a_document_nested_past_the_depth_limit_is_refused() {
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_XML_DEPTH + 5),
            "</a>".repeat(MAX_XML_DEPTH + 5)
        );
        let error = read_document(deep.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("nests deeper"), "{error}");
    }

    #[test]
    fn malformed_xml_is_refused_rather_than_recovered_from() {
        for hostile in [
            "",
            "<",
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "not xml at all",
            "<?xml version=\"1.0\"?>",
        ] {
            assert!(read_document(hostile.as_bytes()).is_err(), "{hostile}");
        }
    }

    /// `contains` describes a set of values. Taking its operand as an observable would record a
    /// value the author never said was the artefact.
    #[test]
    fn only_the_is_condition_states_a_whole_value() {
        assert!(openioc_canonicaliser("Network/DNS").is_some());
        assert!(openioc_canonicaliser("ProcessItem/arguments").is_none());
    }

    #[test]
    fn an_iodef_address_category_brolga_does_not_read_is_named_rather_than_guessed() {
        assert!(iodef_canonicaliser("ipv4-addr").is_some());
        assert!(iodef_canonicaliser("ipv4-net").is_some());
        assert!(iodef_canonicaliser("asn").is_none());
        assert!(iodef_canonicaliser("mac").is_none());
    }
}
