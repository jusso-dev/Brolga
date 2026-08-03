//! Exporters: turning a context pack into bytes somebody else's tool can read.
//!
//! # The one structural decision
//!
//! [#54](https://github.com/jusso-dev/Brolga/issues/54) requires that policy run **after format
//! selection and before bytes emit**. That ordering is not a coding convention here, it is the shape
//! of the API: an [`Exporter`] cannot be called with a [`ContextPack`]. It can only be called with a
//! [`Cleared`], and the only way to construct a `Cleared` is [`clear`], which runs the policy
//! decision. There is no `Exporter::emit(&ContextPack)` to forget to guard.
//!
//! The ordering matters because **which capability an export requires depends on the format
//! chosen**. Rendering a pack as Markdown for the operator who asked for it is a read. Rendering it
//! as a STIX bundle produces an interchange artefact whose entire purpose is to be handed to another
//! platform, and that is redistribution — a different decision, under different markings. A gate
//! that ran before format selection could not tell the two apart, so it would have to demand the
//! stronger capability for everything, and an operator would be unable to read their own pack as
//! text without redistribution rights.
//!
//! # Every exporter declares what it costs you
//!
//! [`ExportMetadata`] carries a version, an [`Orientation`], and a [`Lossiness`]. All three are
//! required, and the trait has no default for any of them.
//!
//! `Lossiness` is the one that earns its place. "Export to STIX" sounds like a translation and is
//! actually a projection: STIX has no place to put a pack's budget report, its exclusions, or the
//! reasons behind its gaps. A consumer round-tripping through STIX and finding those absent should
//! have been told in advance, and [`Exported::declared_losses`] is where they were.
//!
//! # What an exporter cannot do
//!
//! - **No templating engine.** Every writer here is hand-written. A template language is a program
//!   inside a data file, evaluated in a process holding an intelligence database, and #54's security
//!   note prohibits exactly that.
//! - **No filesystem, no network, no clock.** An exporter is a pure function from a cleared pack to
//!   bytes. It cannot read a file, so it cannot emit one it was not given; it cannot open a socket,
//!   so it cannot exfiltrate what it was handed.
//! - **No path emission.** Nothing in an export names a directory on the host. A pack cites source
//!   objects by content address, and a content address is not a location.
//! - **No secret can reach the output**, because no exporter is given one. The pack is the whole
//!   input, and a pack has never held a credential.
//!
//! # Formula injection is a real vulnerability, not a formatting nit
//!
//! `csv` prefixes any value beginning `=`, `+`, `-`, `@`, a tab, or a carriage return with a single
//! quote. A CSV of threat intelligence is opened in a spreadsheet by definition, and a cell reading
//! `=cmd|'/c calc'!A0` executes on open in several of them. The value came from a feed; the feed is
//! untrusted; the consumer is a spreadsheet. See [`csv`] for the whole argument.

#![forbid(unsafe_code)]

pub mod json;
pub mod markdown;
pub mod stix;

use std::collections::BTreeMap;

use brolga_config::policy::{Capability, Decision, PolicyIdentity, decide};
use brolga_model::ContextPack;
use serde::Serialize;

/// An exporter's stable identifier.
///
/// Conventionally `brolga.export.<format>`. A compatibility surface: it names the format in a
/// command line, an API request, and a stored artefact's metadata, so renaming one breaks all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExporterId(&'static str);

impl ExporterId {
    /// Wrap a static identifier.
    #[must_use]
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Borrow it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for ExporterId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Who an export is for.
///
/// Not decoration. It decides how a consumer should treat the bytes: a `Machine` export is a
/// contract that a parser can rely on, a `Human` one is prose that may be reworded in a patch
/// release, and an `Agent` one is shaped for a token budget rather than for either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Orientation {
    /// A schema a program parses. Its shape is a compatibility surface.
    Machine,
    /// Prose a person reads. Wording is not a compatibility surface.
    Human,
    /// Shaped for a language model's context window: dense, ordered by importance.
    Agent,
    /// A format another intelligence platform ingests.
    ///
    /// Distinct from [`Self::Machine`] because its purpose is to leave this organisation, which is a
    /// policy question rather than a formatting one. See [`Exporter::capability`].
    Interchange,
}

impl Orientation {
    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Interchange => "interchange",
        }
    }
}

/// How much of the pack survives the export.
///
/// Ordered from most faithful to least, so a caller choosing between formats can compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Lossiness {
    /// Every field survives, and the export deserialises back to an equal pack.
    ///
    /// The strongest claim available, and the only one that is *tested* by a round trip. An exporter
    /// declaring this and failing `every_lossless_exporter_round_trips` is a bug in the exporter, not
    /// in the test.
    Lossless,
    /// Every field survives, but the encoding does not deserialise back through `serde` alone.
    ///
    /// A stream of separate documents, for instance: all of the content, none of the container.
    LosslessStructural,
    /// Some fields have no place to go, and the export says which.
    ///
    /// [`Exported::declared_losses`] is non-empty for any exporter at this level, checked by
    /// `a_partially_lossless_export_names_what_it_dropped`.
    PartiallyLossless,
    /// Content was condensed rather than dropped: several items became one summary.
    Compressed,
    /// Content was computed from the pack rather than taken from it.
    ///
    /// A DOT graph is derived: the pack has no notion of a node shape, and the exporter invented one.
    Derived,
    /// Prose. Faithful in meaning, not in structure.
    Narrative,
}

impl Lossiness {
    /// A stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lossless => "lossless",
            Self::LosslessStructural => "lossless_structural",
            Self::PartiallyLossless => "partially_lossless",
            Self::Compressed => "compressed",
            Self::Derived => "derived",
            Self::Narrative => "narrative",
        }
    }

    /// Whether an exporter at this level must enumerate what it dropped.
    #[must_use]
    pub const fn must_declare_losses(self) -> bool {
        matches!(
            self,
            Self::PartiallyLossless | Self::Compressed | Self::Derived
        )
    }
}

/// What an exporter is, declared rather than inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ExportMetadata {
    /// The exporter's identifier.
    pub id: ExporterId,
    /// Its algorithm version. Bumped whenever its output changes for any input.
    pub version: u32,
    /// The media type the bytes are.
    pub media_type: &'static str,
    /// The conventional file extension, without a dot.
    pub extension: &'static str,
    /// Who the output is for.
    pub orientation: Orientation,
    /// How much of the pack survives.
    pub lossiness: Lossiness,
    /// One sentence on what it produces.
    pub summary: &'static str,
}

/// Why an export failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// Policy refused the release.
    ///
    /// Carries every denial rather than the first, because an operator who has to widen an
    /// authorisation needs the whole list.
    #[error("policy refused this export: {}", .denials.join("; "))]
    Denied {
        /// Every rule that refused.
        denials: Vec<String>,
    },
    /// No exporter is registered under that name.
    #[error("no exporter named `{requested}`; available: {}", .available.join(", "))]
    UnknownFormat {
        /// What was asked for.
        requested: String,
        /// What exists.
        available: Vec<String>,
    },
    /// The pack could not be encoded in this format.
    #[error("`{exporter}` could not encode the pack: {reason}")]
    Unencodable {
        /// Which exporter.
        exporter: ExporterId,
        /// Why.
        reason: String,
    },
}

/// A pack that has passed a policy decision for one specific format.
///
/// The only way to get one is [`clear`]. That is the whole point: an [`Exporter`] takes a `Cleared`
/// rather than a `ContextPack`, so there is no way to reach an exporter without a decision having
/// been made, and no way to make the decision without knowing which format it was for.
///
/// Borrowed rather than owned so that clearing is free and a caller can export one pack to several
/// formats — each with its own decision, which is correct, because each format may need a different
/// capability.
#[derive(Debug, Clone, Copy)]
pub struct Cleared<'pack> {
    pack: &'pack ContextPack,
    identity_name: &'pack str,
    capability: Capability,
}

impl<'pack> Cleared<'pack> {
    /// The pack.
    #[must_use]
    pub const fn pack(&self) -> &'pack ContextPack {
        self.pack
    }

    /// Who the decision was made for, for an export that records it.
    #[must_use]
    pub const fn identity_name(&self) -> &'pack str {
        self.identity_name
    }

    /// Which capability the decision granted.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }
}

/// Run the policy decision for one pack and one exporter.
///
/// The capability required comes from the *exporter*, not from the caller — see
/// [`Exporter::capability`] and the module documentation for why that is the only ordering that
/// distinguishes reading your own pack from handing it to somebody else.
///
/// # Errors
///
/// Returns [`ExportError::Denied`] carrying every denial, when the identity may not have these bytes
/// in this format.
pub fn clear<'pack>(
    pack: &'pack ContextPack,
    identity: &'pack PolicyIdentity,
    exporter: &dyn Exporter,
) -> Result<Cleared<'pack>, ExportError> {
    let capability = exporter.capability();
    let decision: Decision = decide(identity, &pack.policy.markings, capability);
    if !decision.allowed {
        return Err(ExportError::Denied {
            denials: decision
                .denials
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        });
    }
    Ok(Cleared {
        pack,
        identity_name: &identity.name,
        capability,
    })
}

/// Bytes an exporter produced, with what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Exported {
    /// What the exporter was.
    pub metadata: ExportMetadata,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// What did not survive, named.
    ///
    /// Non-empty for any exporter whose [`Lossiness::must_declare_losses`] is true. A format that
    /// drops a field silently is one a consumer trusts wrongly.
    pub declared_losses: Vec<&'static str>,
}

impl Exported {
    /// The bytes as text, where they are text.
    ///
    /// Every exporter in this crate emits UTF-8, so this is `Some` for all of them. It returns an
    /// `Option` rather than panicking because that is a property of the current set and not of the
    /// trait.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.bytes).ok()
    }
}

/// A format a pack can be written as.
///
/// # Contract
///
/// - [`Self::metadata`] must be pure and constant. It is documentation the code cannot contradict.
/// - [`Self::emit`] must not panic, read a file, open a socket, consult a clock, or evaluate a
///   template. It is a pure function from a cleared pack to bytes.
/// - An exporter whose lossiness requires declared losses must return them non-empty.
pub trait Exporter: Send + Sync {
    /// What this exporter is.
    fn metadata(&self) -> ExportMetadata;

    /// Which capability an export in this format requires.
    ///
    /// Defaulted on [`Orientation`] rather than left to each implementation, so that a new
    /// interchange format cannot be added without a redistribution requirement by simply forgetting
    /// to state one. An exporter with an unusual need overrides it deliberately.
    fn capability(&self) -> Capability {
        match self.metadata().orientation {
            // An interchange artefact exists to be handed to another platform. That is
            // redistribution, whatever the operator intends to do with the file.
            Orientation::Interchange => Capability::Redistribute,
            Orientation::Machine | Orientation::Human | Orientation::Agent => Capability::Read,
        }
    }

    /// Write the pack.
    ///
    /// # Errors
    ///
    /// Returns [`ExportError::Unencodable`] if the pack cannot be represented, which for most
    /// formats cannot happen and for the interchange ones means the pack's subject has no equivalent.
    fn emit(&self, cleared: &Cleared<'_>) -> Result<Exported, ExportError>;
}

/// Every exporter this build ships.
///
/// A registry rather than a free function per format, so that "which formats exist" is answerable
/// from the binary rather than from a document that drifts.
#[derive(Default)]
pub struct ExporterRegistry {
    exporters: BTreeMap<&'static str, Box<dyn Exporter>>,
}

impl core::fmt::Debug for ExporterRegistry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExporterRegistry")
            .field("names", &self.names())
            .finish()
    }
}

impl ExporterRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exporters: BTreeMap::new(),
        }
    }

    /// Every exporter this build ships, registered.
    ///
    /// One place, so a second interface cannot end up offering a different set of formats from the
    /// first — the sort of divergence nobody notices until a script works against the CLI and not
    /// against the API.
    #[must_use]
    pub fn shipped() -> Self {
        let mut registry = Self::new();
        for exporter in [
            json::PackJsonExporter::boxed(),
            json::CompactJsonExporter::boxed(),
            json::YamlExporter::boxed(),
            json::JsonLinesExporter::boxed(),
            stix::StixExporter::boxed(),
            markdown::MarkdownExporter::boxed(),
            markdown::TextExporter::boxed(),
            markdown::AgentBriefExporter::boxed(),
        ] {
            registry.register(exporter);
        }
        registry
    }

    /// Add one. A second exporter under the same name replaces the first.
    pub fn register(&mut self, exporter: Box<dyn Exporter>) {
        let id = exporter.metadata().id;
        self.exporters.insert(short_name(id), exporter);
    }

    /// The short names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.exporters.keys().copied().collect()
    }

    /// Every exporter's metadata, sorted by name.
    #[must_use]
    pub fn metadata(&self) -> Vec<ExportMetadata> {
        self.exporters
            .values()
            .map(|exporter| exporter.metadata())
            .collect()
    }

    /// Look one up by short name — `json`, `stix`, `markdown`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn Exporter> {
        self.exporters.get(name).map(Box::as_ref)
    }

    /// Select a format, clear it through policy, and emit — in that order.
    ///
    /// The whole point of the crate's shape, in one function: format first, because the format
    /// decides the capability; then the decision; then the bytes.
    ///
    /// # Errors
    ///
    /// - [`ExportError::UnknownFormat`] if no exporter has that name.
    /// - [`ExportError::Denied`] if policy refuses.
    /// - [`ExportError::Unencodable`] if the pack cannot be written in that format.
    pub fn export(
        &self,
        name: &str,
        pack: &ContextPack,
        identity: &PolicyIdentity,
    ) -> Result<Exported, ExportError> {
        let exporter = self.get(name).ok_or_else(|| ExportError::UnknownFormat {
            requested: name.to_owned(),
            available: self.names().iter().map(|name| (*name).to_owned()).collect(),
        })?;
        let cleared = clear(pack, identity, exporter)?;
        exporter.emit(&cleared)
    }
}

/// The short name for an exporter identifier: the part after the last dot.
///
/// `brolga.export.stix` is `stix` on a command line. Derived rather than declared twice, so the two
/// cannot disagree.
fn short_name(id: ExporterId) -> &'static str {
    id.as_str().rsplit('.').next().unwrap_or(id.as_str())
}

/// Build metadata, so every exporter states all seven fields and none can be defaulted by omission.
#[must_use]
pub const fn metadata(
    id: ExporterId,
    version: u32,
    media_type: &'static str,
    extension: &'static str,
    orientation: Orientation,
    lossiness: Lossiness,
    summary: &'static str,
) -> ExportMetadata {
    ExportMetadata {
        id,
        version,
        media_type,
        extension,
        orientation,
        lossiness,
        summary,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_short_name_is_the_last_segment() {
        assert_eq!(short_name(ExporterId::new("brolga.export.stix")), "stix");
        assert_eq!(short_name(ExporterId::new("plain")), "plain");
    }

    #[test]
    fn lossiness_orders_most_faithful_first() {
        assert!(Lossiness::Lossless < Lossiness::PartiallyLossless);
        assert!(Lossiness::PartiallyLossless < Lossiness::Narrative);
    }

    /// An interchange format requires redistribution by default, so a new one cannot be added without
    /// the stronger requirement by simply forgetting to state it.
    #[test]
    fn interchange_orientation_requires_redistribution_by_default() {
        let registry = ExporterRegistry::shipped();
        for exporter in registry.exporters.values() {
            let metadata = exporter.metadata();
            if metadata.orientation == Orientation::Interchange {
                assert_eq!(
                    exporter.capability(),
                    Capability::Redistribute,
                    "`{}` is interchange and must require redistribution",
                    metadata.id
                );
            }
        }
    }
}
