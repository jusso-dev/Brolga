//! The context pack: what Brolga answers with, as a versioned public type.
//!
//! # Why this is a model type rather than an API struct
//!
//! A pack is the thing a consumer stores, diffs, and acts on. Kelpie keeps one against a case;
//! Tawny compares two. Both need it to be versioned, schema-published, and identical whether it
//! arrived over HTTP, over MCP, or out of a CLI. A struct that existed only inside the HTTP layer
//! would be a different type on each surface the moment a second one appeared.
//!
//! # Every summary carries its evidence, and that is enforced rather than expected
//!
//! [`Finding`] and [`Recommendation`] both hold a non-empty `evidence` list, and
//! [`ContextPack::validated`] refuses a pack where one is empty. An assertion an analyst cannot
//! trace to a retained source object is one they cannot defend, and enrichment that cannot be
//! defended is worse than none — so "must cite evidence" is a validation error, not a convention.
//!
//! # The fingerprint answers "is this the same answer?", not "was this the same request?"
//!
//! Two packs built from the same graph, for the same subject, under the same profile, have the same
//! fingerprint — even if they were built a week apart by different processes. That is what makes a
//! pack cacheable and a diff meaningful.
//!
//! So the fingerprint is computed over the *content* and excludes everything runtime-only:
//! [`PackMetadata::generated_at`], [`PackMetadata::request_id`], [`PackMetadata::build_duration_ms`],
//! and [`PackMetadata::brolga_version`]. Those are recorded — an operator needs them — but they are
//! recorded *outside* the fingerprint's input, and [`FINGERPRINT_EXCLUDED`] names them so the
//! exclusion is documentation a consumer can read rather than a comment in this file.
//!
//! Including the timestamp would make every pack unique, which sounds harmless and quietly destroys
//! every use the fingerprint has.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};
use crate::marking::MarkingSet;
use crate::provenance::ContentHash;
use crate::status::Disposition;
use crate::text::{ShortText, UntrustedText};
use crate::version::{SchemaTag, VersionedSchema};

/// The metadata fields deliberately outside the fingerprint's input.
///
/// Published as data so a consumer can state what it is relying on, rather than trusting a sentence
/// in documentation that may drift from the code. The
/// `the_fingerprint_ignores_exactly_the_documented_runtime_fields` test walks this list.
/// Longest a single field may be at a summary level.
///
/// Not a byte budget — that is the budget engine's job. This is the line between "a summary of a
/// record" and "the record", and it exists so the distinction is enforced rather than intended.
pub const SUMMARY_FIELD_LIMIT: usize = 2048;

/// The metadata fields deliberately outside the fingerprint's input.
///
/// Published as data so a consumer can state what it is relying on, rather than trusting a sentence
/// in documentation that may drift from the code.
pub const FINGERPRINT_EXCLUDED: &[&str] = &[
    "generated_at",
    "request_id",
    "build_duration_ms",
    "brolga_version",
];

/// How much of a pack was asked for.
///
/// # The levels are a contract, not a hint
///
/// `L0` through `L2` are *summaries*: they never carry a raw canonical record or a source object,
/// however much budget remains. That is the point of asking for one — a consumer requesting `L1`
/// has decided it does not want to parse records, and a level that sometimes returned them would
/// make every consumer defensive about a shape it asked not to receive.
///
/// `L4` and `L5` are the opposite: `L4` returns complete canonical records and `L5` returns the
/// exact retained source bytes. Both are reached by *expanding a handle*, not by asking for a
/// bigger pack — see [`ExpansionHandle`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
// Renamed one by one rather than by a `rename_all` rule. `snake_case` turns `L1` into `l1`, and the
// level is a *label* consumers were told about in upper case — a casing change is a breaking wire
// change for something that reads like a formatting detail.
#[non_exhaustive]
pub enum DetailLevel {
    /// The disposition alone, with its evidence references. Nothing else.
    #[serde(rename = "L0")]
    L0,
    /// A disposition and its immediate findings.
    #[serde(rename = "L1")]
    L1,
    /// Adds related entities and relationships.
    #[serde(rename = "L2")]
    L2,
    /// Adds contradictions, clusters, and pivots.
    #[serde(rename = "L3")]
    L3,
    /// Complete canonical records, reached by expanding a handle.
    #[serde(rename = "L4")]
    L4,
    /// The exact retained source objects, reached by expanding a handle.
    #[serde(rename = "L5")]
    L5,
}

impl DetailLevel {
    /// Every level.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::L0, Self::L1, Self::L2, Self::L3, Self::L4, Self::L5]
    }

    /// Whether this level may carry raw canonical records or source objects.
    ///
    /// `false` for `L0` through `L2`. A consumer asking for a summary has decided it does not want
    /// to parse records, and a level that sometimes returned them would make every consumer
    /// defensive about a shape it asked not to receive.
    #[must_use]
    pub const fn permits_raw_objects(self) -> bool {
        matches!(self, Self::L3 | Self::L4 | Self::L5)
    }

    /// Whether this level is reached by expanding a handle rather than by requesting a pack.
    ///
    /// `L4` and `L5` return whole records and original bytes. Serving them from an ordinary pack
    /// request would mean one authorisation decision covering an unbounded amount of source
    /// material; an expansion is one decision per object, re-checked at the moment it is made.
    #[must_use]
    pub const fn requires_expansion(self) -> bool {
        matches!(self, Self::L4 | Self::L5)
    }

    /// The wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
            Self::L4 => "L4",
            Self::L5 => "L5",
        }
    }
}

impl core::fmt::Display for DetailLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why something was left out.
///
/// A closed vocabulary rather than free text, because a consumer has to *branch* on it: a pack
/// truncated by a budget can be re-requested with a larger one, and a pack truncated by policy
/// cannot. A string would make those look the same to anything but a human.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExclusionReason {
    /// A budget was reached.
    BudgetExhausted,
    /// A handling marking forbade release to this recipient.
    PolicyRestricted,
    /// The detail level requested does not include this category.
    BelowDetailLevel,
    /// Brolga can produce this but has not implemented it yet.
    NotImplemented,
}

impl ExclusionReason {
    /// Every reason.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::BudgetExhausted,
            Self::PolicyRestricted,
            Self::BelowDetailLevel,
            Self::NotImplemented,
        ]
    }

    /// The wire discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetExhausted => "budget_exhausted",
            Self::PolicyRestricted => "policy_restricted",
            Self::BelowDetailLevel => "below_detail_level",
            Self::NotImplemented => "not_implemented",
        }
    }

    /// Whether asking again with a larger budget could change the answer.
    ///
    /// The question a consumer actually has. A policy restriction never becomes available by
    /// retrying, and retrying it is how a client turns a refusal into a loop.
    #[must_use]
    pub const fn is_retryable_with_more_budget(self) -> bool {
        matches!(self, Self::BudgetExhausted)
    }
}

impl core::fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pointer to the retained original a claim came from.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// The retained source object's content address.
    pub source_object_id: String,
    /// Which record within it, where the pack can be that specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
}

impl EvidenceRef {
    /// Point at a source object.
    #[must_use]
    pub fn new(source_object_id: impl Into<String>) -> Self {
        Self {
            source_object_id: source_object_id.into(),
            record_id: None,
        }
    }

    /// The same reference, narrowed to one record.
    #[must_use]
    pub fn for_record(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }
}

/// Something the pack asserts, with the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// A stable machine key for what kind of finding this is.
    pub kind: ShortText,
    /// The finding, in the source's own words where it has any.
    ///
    /// [`UntrustedText`] because it may quote a feed. A consumer rendering a pack is rendering
    /// somebody else's text, and the type says so.
    pub statement: UntrustedText,
    /// Where it came from. Never empty — see [`ContextPack::validated`].
    pub evidence: Vec<EvidenceRef>,
}

/// Something the pack suggests doing, with the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    /// A stable machine key for the recommended action.
    pub action: ShortText,
    /// Why.
    pub rationale: UntrustedText,
    /// Where it came from. Never empty.
    pub evidence: Vec<EvidenceRef>,
}

/// Something Brolga does not know.
///
/// Stated rather than left to be inferred from an empty array. "No claims" and "claims withheld"
/// and "nothing was looked for" are three different answers and an absent field is all of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    /// What is missing.
    pub subject: ShortText,
    /// Why it is missing, in a form a human reads.
    pub detail: UntrustedText,
}

/// Something left out of the pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    /// Which category was dropped.
    pub category: ShortText,
    /// Why, from a closed vocabulary a consumer can branch on.
    pub reason: ExclusionReason,
    /// How many items, where the count is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
}

/// A budget, as requested or as consumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Approximate tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// Serialised bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Objects of any kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<u64>,
    /// Relationships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationships: Option<u64>,
    /// Traversal depth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// Wall-clock milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<u64>,
}

/// What the pack was allowed and what it cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetReport {
    /// What the consumer asked for.
    pub requested: Budget,
    /// What was actually spent.
    pub consumed: Budget,
    /// Whether a budget stopped the pack short.
    ///
    /// A separate flag rather than something to infer by comparing the two. A consumer that has to
    /// derive "was this truncated?" from six optional numbers will eventually derive it wrongly,
    /// and the failure mode is treating a partial answer as a complete one.
    pub exhausted: bool,
}

/// The policy context a pack was produced under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyContext {
    /// Who the pack was produced for, if the caller identified a recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<ShortText>,
    /// The markings that reached the pack's contents.
    ///
    /// Always serialised, empty or not. An absent field would read as "unmarked", and unmarked and
    /// unknown are different states — the second is the one that should stop a release.
    pub markings: MarkingSet,
    /// Whether anything was withheld for policy reasons.
    ///
    /// Duplicated from [`Exclusion`] deliberately: a consumer deciding whether it may forward a
    /// pack should not have to scan a list to find out, and a boolean it can check is one it will
    /// actually check.
    pub restricted: bool,
}

/// Runtime facts about how a pack was produced.
///
/// Every field here is **outside** the fingerprint. See the module documentation and
/// [`FINGERPRINT_EXCLUDED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    /// When the pack was built, as RFC 3339.
    pub generated_at: String,
    /// The request that produced it, for correlating with a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// How long it took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_duration_ms: Option<u64>,
    /// Which Brolga produced it.
    pub brolga_version: String,
    /// The graph version it was built against, so two packs can be told apart by what they saw.
    ///
    /// Inside the fingerprint, unlike its neighbours: a pack built against a different graph is a
    /// different answer even if it happens to say the same thing.
    pub graph_version: u64,
}

/// What was asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSubject {
    /// The observable kind.
    pub kind: ShortText,
    /// The canonical value, which may differ from what the caller sent.
    pub value: ShortText,
    /// The canonical observable identifier.
    pub observable_id: String,
}

/// A named thing connected to the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntitySummary {
    /// The entity id.
    pub id: String,
    /// Its kind.
    pub kind: ShortText,
    /// Its name, as published.
    pub name: UntrustedText,
    /// Its lifecycle status — a revoked entity is still an answer, but a different one.
    pub status: ShortText,
}

/// An assertion about the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimSummary {
    /// What is asserted.
    pub predicate: ShortText,
    /// What it is asserted about.
    pub object: UntrustedText,
    /// The asserted status.
    pub status: ShortText,
    /// Confidence, where the source expressed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// Where it came from.
    pub evidence: Vec<EvidenceRef>,
}

/// An edge at the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationshipSummary {
    /// The relationship kind.
    pub kind: ShortText,
    /// The source node.
    pub source: String,
    /// The target node.
    pub target: String,
    /// Its lifecycle status.
    pub status: ShortText,
}

/// An observation of the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SightingSummary {
    /// How many times.
    pub count: u64,
    /// The start of the observation window, as RFC 3339.
    pub first_seen: String,
    /// The end of it.
    pub last_seen: String,
    /// Who observed it, where the source said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer: Option<String>,
}

/// Two claims that cannot both be right.
///
/// Surfaced rather than resolved. The canonical model keeps contradictions on purpose, and a pack
/// that silently picked a winner would throw away the one signal telling an analyst to look.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Contradiction {
    /// What the disagreement is about.
    pub subject: ShortText,
    /// One position.
    pub left: UntrustedText,
    /// The other.
    pub right: UntrustedText,
    /// Evidence for both, so an analyst can weigh them.
    pub evidence: Vec<EvidenceRef>,
}

/// Somewhere else worth looking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pivot {
    /// The observable or entity to look at next.
    pub target: ShortText,
    /// Why it is worth looking at.
    pub reason: UntrustedText,
}

/// The graph around the subject.
///
/// Every collection is always serialised, empty or not. An absent array and an empty one mean
/// different things — "none held" and "not gathered" — and only one of them means the consumer has
/// seen everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackGraph {
    /// Named things connected to the subject.
    pub entities: Vec<EntitySummary>,
    /// Assertions about it.
    pub claims: Vec<ClaimSummary>,
    /// Edges at it.
    pub relationships: Vec<RelationshipSummary>,
    /// Observations of it.
    pub sightings: Vec<SightingSummary>,
    /// ATT&CK technique identifiers reached from it.
    pub techniques: Vec<ShortText>,
    /// Groupings a compression pass produced, once one exists.
    pub clusters: Vec<ShortText>,
    /// Disagreements worth surfacing.
    pub contradictions: Vec<Contradiction>,
    /// Where to look next.
    pub pivots: Vec<Pivot>,
}

/// A pointer a consumer can hand back to ask for more about one item.
///
/// # Why a handle rather than "just ask for L5"
///
/// A pack request is one authorisation decision. If it could return source objects, that decision
/// would cover an unbounded amount of original material — every byte behind every claim. An
/// expansion is one decision about one object, made at the moment it is asked for, against the
/// policy in force *then* rather than whenever the pack was built.
///
/// That matters because packs are stored. A pack from last month sitting in a case file must not
/// be a standing grant to material the caller's authorisation no longer covers, and it is not: the
/// handle carries no content and no permission, only enough to identify what was being asked about.
///
/// # Bound to the graph it was issued against
///
/// [`Self::graph_version`] records what the pack saw. An expansion served from a graph that has
/// moved since is answering about a different state, and a consumer diffing two expansions would
/// see changes it could not attribute. The handle does not forbid that — it makes it *visible*, so
/// the decision belongs to whoever is comparing rather than to whoever happened to hold the handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpansionHandle {
    /// What can be expanded: a canonical record identifier, or a source object address.
    pub target: String,
    /// What kind of thing the target names.
    pub target_kind: ShortText,
    /// The deepest level this handle can be expanded to.
    ///
    /// Advisory to the *consumer* and not a grant: the server re-checks policy on expansion
    /// regardless, and a handle claiming `L5` gets whatever the caller is entitled to at that
    /// moment. Present so a client can avoid a request it knows will be refused, not so it can
    /// make one it should not.
    pub max_level: DetailLevel,
    /// The graph version the issuing pack was built against.
    pub graph_version: u64,
    /// When the handle was issued, as RFC 3339.
    pub issued_at: String,
}

impl ExpansionHandle {
    /// Point at something expandable.
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        target_kind: ShortText,
        max_level: DetailLevel,
        graph_version: u64,
        issued_at: impl Into<String>,
    ) -> Self {
        Self {
            target: target.into(),
            target_kind,
            max_level,
            graph_version,
            issued_at: issued_at.into(),
        }
    }

    /// Whether the graph has moved since this handle was issued.
    ///
    /// Not an error by itself. An expansion against a moved graph is a legitimate thing to want —
    /// it is the current truth about the same object — but a consumer comparing two expansions
    /// needs to know whether it is comparing content or comparing time.
    #[must_use]
    pub const fn is_stale_against(&self, current_graph_version: u64) -> bool {
        current_graph_version != self.graph_version
    }
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPack {
    /// In-payload schema version. Always serialised.
    pub schema_version: SchemaTag<Self>,
    /// A content fingerprint over everything except the documented runtime metadata.
    pub fingerprint: String,
    /// What was asked about, canonicalised.
    pub subject: PackSubject,
    /// The purpose the consumer declared, where it declared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<ShortText>,
    /// The detail level actually served, which may be lower than the one requested.
    pub detail_level: DetailLevel,
    /// What Brolga makes of the subject.
    pub disposition: Disposition,
    /// The graph around the subject.
    pub graph: PackGraph,
    /// Handles for expanding individual items to their canonical records or original bytes.
    ///
    /// Always serialised, empty or not. An absent array would read as "nothing can be expanded",
    /// which is a different statement from "this level issues no handles".
    #[serde(default)]
    pub handles: Vec<ExpansionHandle>,
    /// What the pack asserts. Each carries its own evidence.
    pub findings: Vec<Finding>,
    /// What the pack suggests. Each carries its own evidence.
    pub recommendations: Vec<Recommendation>,
    /// What Brolga does not know. Always serialised, empty or not.
    pub gaps: Vec<Gap>,
    /// What was deliberately left out. Always serialised, empty or not.
    pub exclusions: Vec<Exclusion>,
    /// What was allowed and what it cost.
    pub budget: BudgetReport,
    /// The policy context it was produced under.
    pub policy: PolicyContext,
    /// Runtime facts, outside the fingerprint.
    pub metadata: PackMetadata,
}

impl VersionedSchema for ContextPack {
    const SCHEMA_NAME: &'static str = "brolga.context_pack";
    // Bumped for `handles` and for the `L0`/`L4`/`L5` detail levels. Both are additive: an optional
    // field with a default, and variants on a `#[non_exhaustive]` enum.
    const SCHEMA_MINOR: u16 = 1;
}

impl ContextPack {
    /// Check the invariants the field types cannot express, and compute the fingerprint.
    ///
    /// # Errors
    ///
    /// [`ModelError::InvalidValue`] if a finding or recommendation cites no evidence, or if the
    /// pack claims a policy restriction it does not list an exclusion for.
    pub fn validated(mut self) -> Result<Self> {
        for finding in &self.findings {
            if finding.evidence.is_empty() {
                return Err(ModelError::invalid(
                    "ContextPack",
                    format_args!(
                        "the finding `{}` cites no evidence; an assertion an analyst cannot trace \
                         to a source is one they cannot defend",
                        finding.kind.as_str()
                    ),
                ));
            }
        }
        for recommendation in &self.recommendations {
            if recommendation.evidence.is_empty() {
                return Err(ModelError::invalid(
                    "ContextPack",
                    format_args!(
                        "the recommendation `{}` cites no evidence",
                        recommendation.action.as_str()
                    ),
                ));
            }
        }

        // A pack that says it withheld something must say what. Otherwise `restricted` is a warning
        // with no way to act on it, and a consumer cannot tell a marking it could satisfy from one
        // it never will.
        if self.policy.restricted
            && !self
                .exclusions
                .iter()
                .any(|exclusion| exclusion.reason == ExclusionReason::PolicyRestricted)
        {
            return Err(ModelError::invalid(
                "ContextPack",
                "the pack is marked policy-restricted but lists no policy exclusion saying what \
                 was withheld",
            ));
        }

        // Likewise the other way: an exhausted budget must be visible as an exclusion, or a
        // truncated pack reads as a complete one.
        if self.budget.exhausted
            && !self
                .exclusions
                .iter()
                .any(|exclusion| exclusion.reason == ExclusionReason::BudgetExhausted)
        {
            return Err(ModelError::invalid(
                "ContextPack",
                "the pack reports an exhausted budget but lists no budget exclusion saying what \
                 was dropped",
            ));
        }

        // A summary level must stay a summary. A consumer that asked for `L1` because it does not
        // want to parse records should never have to defend against receiving them.
        if !self.detail_level.permits_raw_objects() && !self.graph.claims.is_empty() {
            for claim in &self.graph.claims {
                if claim.object.as_str().len() > SUMMARY_FIELD_LIMIT {
                    return Err(ModelError::invalid(
                        "ContextPack",
                        format_args!(
                            "`{}` is a summary level but carries a {}-byte claim value; summary \
                             levels never carry raw record content",
                            self.detail_level,
                            claim.object.as_str().len()
                        ),
                    ));
                }
            }
        }

        // `L4` and `L5` are reached by expanding a handle, not by asking for a bigger pack. A pack
        // claiming to *be* one would mean a single authorisation decision covering unbounded
        // source material.
        if self.detail_level.requires_expansion() {
            return Err(ModelError::invalid(
                "ContextPack",
                format_args!(
                    "`{}` is reached by expanding a handle rather than by serving a pack at that \
                     level",
                    self.detail_level
                ),
            ));
        }

        self.fingerprint = self.compute_fingerprint();
        Ok(self)
    }

    /// The content fingerprint, over everything but the documented runtime metadata.
    ///
    /// # Panics
    ///
    /// Does not panic. Serialising a pack whose fields are all serialisable cannot fail, and the
    /// fallible path is handled rather than unwrapped.
    #[must_use]
    pub fn compute_fingerprint(&self) -> String {
        // Serialised through `serde_json::Value` so field order is the struct's, deterministically,
        // rather than whatever a map iteration happened to produce.
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);

        if let Some(object) = value.as_object_mut() {
            // The fingerprint is over the *answer*. Its own value cannot be part of its input.
            object.remove("fingerprint");

            if let Some(metadata) = object.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                for field in FINGERPRINT_EXCLUDED {
                    metadata.remove(*field);
                }
            }
        }

        ContentHash::of(value.to_string().as_bytes()).to_string()
    }

    /// Whether this pack says the same thing as another, ignoring when either was produced.
    #[must_use]
    pub fn says_the_same_as(&self, other: &Self) -> bool {
        self.compute_fingerprint() == other.compute_fingerprint()
    }

    /// Every evidence reference the pack cites, deduplicated.
    ///
    /// What a caller needs to fetch the originals behind an answer, which is the whole point of
    /// citing them.
    #[must_use]
    pub fn evidence(&self) -> Vec<EvidenceRef> {
        let mut seen: BTreeMap<(String, Option<String>), EvidenceRef> = BTreeMap::new();
        for reference in self
            .findings
            .iter()
            .flat_map(|finding| &finding.evidence)
            .chain(
                self.recommendations
                    .iter()
                    .flat_map(|recommendation| &recommendation.evidence),
            )
        {
            seen.insert(
                (
                    reference.source_object_id.clone(),
                    reference.record_id.clone(),
                ),
                reference.clone(),
            );
        }
        seen.into_values().collect()
    }
}

impl<'de> Deserialize<'de> for ContextPack {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            schema_version: SchemaTag<ContextPack>,
            fingerprint: String,
            subject: PackSubject,
            #[serde(default)]
            purpose: Option<ShortText>,
            detail_level: DetailLevel,
            disposition: Disposition,
            graph: PackGraph,
            #[serde(default)]
            handles: Vec<ExpansionHandle>,
            findings: Vec<Finding>,
            recommendations: Vec<Recommendation>,
            gaps: Vec<Gap>,
            exclusions: Vec<Exclusion>,
            budget: BudgetReport,
            policy: PolicyContext,
            metadata: PackMetadata,
        }

        let raw = Raw::deserialize(deserializer)?;
        let declared = raw.fingerprint.clone();

        let pack = Self {
            schema_version: raw.schema_version,
            fingerprint: raw.fingerprint,
            subject: raw.subject,
            purpose: raw.purpose,
            detail_level: raw.detail_level,
            disposition: raw.disposition,
            graph: raw.graph,
            handles: raw.handles,
            findings: raw.findings,
            recommendations: raw.recommendations,
            gaps: raw.gaps,
            exclusions: raw.exclusions,
            budget: raw.budget,
            policy: raw.policy,
            metadata: raw.metadata,
        }
        .validated()
        .map_err(D::Error::custom)?;

        // The fingerprint is recomputed on the way in and compared. A pack whose declared
        // fingerprint disagrees with its contents has been edited in transit or produced by
        // something that computes it differently, and either way a consumer caching on it would
        // cache the wrong thing under the right key.
        if pack.fingerprint != declared {
            return Err(D::Error::custom(format!(
                "the pack's fingerprint `{declared}` does not match its contents `{}`",
                pack.fingerprint
            )));
        }
        Ok(pack)
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

    fn short(value: &str) -> ShortText {
        ShortText::new(value).unwrap()
    }

    fn untrusted(value: &str) -> UntrustedText {
        UntrustedText::new(value).unwrap()
    }

    fn pack() -> ContextPack {
        ContextPack {
            schema_version: SchemaTag::new(),
            fingerprint: String::new(),
            subject: PackSubject {
                kind: short("ipv4_address"),
                value: short("203.0.113.42"),
                observable_id: "obs-1".to_owned(),
            },
            purpose: Some(short("triage")),
            detail_level: DetailLevel::L1,
            disposition: Disposition::Malicious,
            graph: PackGraph::default(),
            handles: Vec::new(),
            findings: vec![Finding {
                kind: short("disposition"),
                statement: untrusted("Published as a C2 address."),
                evidence: vec![EvidenceRef::new("sha256:abc")],
            }],
            recommendations: vec![],
            gaps: vec![],
            exclusions: vec![],
            budget: BudgetReport {
                requested: Budget::default(),
                consumed: Budget::default(),
                exhausted: false,
            },
            policy: PolicyContext {
                recipient: None,
                markings: MarkingSet::empty(),
                restricted: false,
            },
            metadata: PackMetadata {
                generated_at: "2024-01-01T00:00:00Z".to_owned(),
                request_id: Some("req-1".to_owned()),
                build_duration_ms: Some(12),
                brolga_version: "0.1.0".to_owned(),
                graph_version: 7,
            },
        }
        .validated()
        .unwrap()
    }

    /// **The criterion.** An assertion an analyst cannot trace to a retained source is one they
    /// cannot defend, so citing nothing is a validation error rather than a style problem.
    #[test]
    fn a_finding_or_recommendation_with_no_evidence_is_refused() {
        let mut bare = pack();
        bare.findings[0].evidence.clear();
        let error = bare.validated().unwrap_err();
        assert!(error.to_string().contains("cites no evidence"), "{error}");

        let mut bare = pack();
        bare.recommendations.push(Recommendation {
            action: short("block"),
            rationale: untrusted("because"),
            evidence: vec![],
        });
        assert!(bare.validated().is_err());
    }

    /// **The criterion.** Two packs saying the same thing about the same graph must fingerprint
    /// alike however far apart they were built. Including the timestamp would make every pack
    /// unique, which sounds harmless and destroys every use the fingerprint has.
    #[test]
    fn the_fingerprint_ignores_exactly_the_documented_runtime_fields() {
        let first = pack();

        let mut later = pack();
        later.metadata.generated_at = "2025-12-31T23:59:59Z".to_owned();
        later.metadata.request_id = Some("a-completely-different-request".to_owned());
        later.metadata.build_duration_ms = Some(99_999);
        later.metadata.brolga_version = "9.9.9".to_owned();
        let later = later.validated().unwrap();

        assert_eq!(first.fingerprint, later.fingerprint);
        assert!(first.says_the_same_as(&later));

        // And the list is the whole list: every field named in it must actually be a field of the
        // metadata object, or the documentation is describing something that does not exist.
        let serialised = serde_json::to_value(&first.metadata).unwrap();
        for field in FINGERPRINT_EXCLUDED {
            assert!(
                serialised.get(*field).is_some(),
                "`{field}` is documented as excluded but is not a metadata field"
            );
        }
    }

    /// A pack built against a different graph is a different answer even if it says the same words.
    #[test]
    fn the_graph_version_is_inside_the_fingerprint() {
        let first = pack();
        let mut moved = pack();
        moved.metadata.graph_version = 8;
        let moved = moved.validated().unwrap();

        assert_ne!(first.fingerprint, moved.fingerprint);
    }

    /// Content changes change the fingerprint. Without this the whole thing is decorative.
    #[test]
    fn a_different_answer_fingerprints_differently() {
        let first = pack();

        let mut other = pack();
        other.disposition = Disposition::Benign;
        assert_ne!(first.fingerprint, other.validated().unwrap().fingerprint);

        let mut extra = pack();
        extra.gaps.push(Gap {
            subject: short("sightings"),
            detail: untrusted("none held"),
        });
        assert_ne!(first.fingerprint, extra.validated().unwrap().fingerprint);
    }

    /// **The criterion.** A truncated pack that reads as a complete one is the failure this exists
    /// to prevent, in both directions.
    #[test]
    fn an_exhausted_budget_or_a_restriction_must_say_what_it_dropped() {
        let mut truncated = pack();
        truncated.budget.exhausted = true;
        let error = truncated.clone().validated().unwrap_err();
        assert!(error.to_string().contains("no budget exclusion"), "{error}");

        truncated.exclusions.push(Exclusion {
            category: short("relationships"),
            reason: ExclusionReason::BudgetExhausted,
            dropped: Some(12),
        });
        assert!(truncated.validated().is_ok());

        let mut withheld = pack();
        withheld.policy.restricted = true;
        assert!(withheld.clone().validated().is_err());

        withheld.exclusions.push(Exclusion {
            category: short("claims"),
            reason: ExclusionReason::PolicyRestricted,
            dropped: None,
        });
        assert!(withheld.validated().is_ok());
    }

    /// A consumer has to branch on why something was dropped: a budget can be raised, a policy
    /// restriction cannot, and retrying the second is how a client turns a refusal into a loop.
    #[test]
    fn only_a_budget_exclusion_is_worth_retrying() {
        assert!(ExclusionReason::BudgetExhausted.is_retryable_with_more_budget());
        for reason in [
            ExclusionReason::PolicyRestricted,
            ExclusionReason::BelowDetailLevel,
            ExclusionReason::NotImplemented,
        ] {
            assert!(!reason.is_retryable_with_more_budget(), "{reason}");
        }
    }

    /// **The criterion.** A pack must survive a round trip through JSON unchanged.
    #[test]
    fn a_pack_round_trips_through_json() {
        let original = pack();
        let json = serde_json::to_string(&original).unwrap();
        let back: ContextPack = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    /// **The criterion.** A consumer that asked for a summary should never have to defend against
    /// receiving records it asked not to receive.
    #[test]
    fn a_summary_level_never_carries_raw_record_content() {
        for level in [DetailLevel::L0, DetailLevel::L1, DetailLevel::L2] {
            assert!(!level.permits_raw_objects(), "{level}");

            let mut bulky = pack();
            bulky.detail_level = level;
            bulky.graph.claims.push(ClaimSummary {
                predicate: short("raw"),
                object: untrusted(&"x".repeat(SUMMARY_FIELD_LIMIT + 1)),
                status: short("active"),
                confidence: None,
                evidence: vec![EvidenceRef::new("sha256:abc")],
            });

            let error = bulky.validated().unwrap_err();
            assert!(error.to_string().contains("summary level"), "{error}");
        }

        assert!(DetailLevel::L3.permits_raw_objects());
    }

    /// **The criterion.** `L4` and `L5` are reached by expanding a handle. Serving them as a pack
    /// would make one authorisation decision cover an unbounded amount of source material.
    #[test]
    fn the_expansion_levels_cannot_be_served_as_a_pack() {
        for level in [DetailLevel::L4, DetailLevel::L5] {
            assert!(level.requires_expansion(), "{level}");

            let mut deep = pack();
            deep.detail_level = level;
            let error = deep.validated().unwrap_err();
            assert!(error.to_string().contains("expanding a handle"), "{error}");
        }

        for level in [
            DetailLevel::L0,
            DetailLevel::L1,
            DetailLevel::L2,
            DetailLevel::L3,
        ] {
            assert!(!level.requires_expansion(), "{level}");
        }
    }

    /// A handle carries no content and no permission — only enough to identify what was asked
    /// about. A stored pack must not be a standing grant to material the caller's authorisation no
    /// longer covers.
    #[test]
    fn a_handle_carries_no_content_and_no_permission() {
        let handle = ExpansionHandle::new(
            "claim-1",
            short("claim"),
            DetailLevel::L5,
            7,
            "2024-01-01T00:00:00Z",
        );

        let json = serde_json::to_value(&handle).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "graph_version",
                "issued_at",
                "max_level",
                "target",
                "target_kind"
            ],
            "a handle must not gain a field that could carry content or a grant"
        );
    }

    /// An expansion against a moved graph is legitimate, but a consumer diffing two of them needs
    /// to know whether it is comparing content or comparing time.
    #[test]
    fn a_handle_reports_whether_the_graph_has_moved_since_it_was_issued() {
        let handle = ExpansionHandle::new(
            "claim-1",
            short("claim"),
            DetailLevel::L4,
            7,
            "2024-01-01T00:00:00Z",
        );

        assert!(!handle.is_stale_against(7));
        assert!(handle.is_stale_against(8));
    }

    /// Handles ride inside the fingerprint: a pack offering different expansions is a different
    /// answer.
    #[test]
    fn handles_are_part_of_what_a_pack_says() {
        let plain = pack();

        let mut offered = pack();
        offered.handles.push(ExpansionHandle::new(
            "claim-1",
            short("claim"),
            DetailLevel::L4,
            7,
            "2024-01-01T00:00:00Z",
        ));
        let offered = offered.validated().unwrap();

        assert_ne!(plain.fingerprint, offered.fingerprint);
    }

    /// A pack edited in transit must not deserialise. A consumer caching on the fingerprint would
    /// otherwise cache the wrong contents under the right key.
    #[test]
    fn a_pack_whose_fingerprint_disagrees_with_its_contents_is_refused() {
        let mut json = serde_json::to_value(pack()).unwrap();
        json["disposition"] = serde_json::json!("benign");

        let error = serde_json::from_value::<ContextPack>(json).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[test]
    fn a_pack_rejects_a_wrong_schema_version_and_unknown_fields() {
        let base = serde_json::to_value(pack()).unwrap();

        let mut wrong = base.clone();
        wrong["schema_version"] = serde_json::json!("brolga.entity/1.0");
        assert!(serde_json::from_value::<ContextPack>(wrong).is_err());

        let mut extra = base;
        extra["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ContextPack>(extra).is_err());
    }

    /// Fetching the originals behind an answer is the whole point of citing them.
    #[test]
    fn the_evidence_of_a_pack_is_collected_and_deduplicated() {
        let mut wide = pack();
        wide.findings.push(Finding {
            kind: short("corroboration"),
            statement: untrusted("Also published by a second source."),
            evidence: vec![
                EvidenceRef::new("sha256:abc"),
                EvidenceRef::new("sha256:def").for_record("claim-9"),
            ],
        });
        let wide = wide.validated().unwrap();

        let evidence = wide.evidence();
        assert_eq!(evidence.len(), 2, "{evidence:?}");
        assert!(evidence.iter().any(|r| r.record_id.is_some()));
    }

    /// An absent field would read as "unmarked", and unmarked and unknown are different states —
    /// the second is the one that should stop a release.
    #[test]
    fn markings_gaps_and_exclusions_are_always_serialised() {
        let json = serde_json::to_value(pack()).unwrap();
        assert_eq!(json["policy"]["markings"], serde_json::json!([]));
        assert_eq!(json["gaps"], serde_json::json!([]));
        assert_eq!(json["exclusions"], serde_json::json!([]));
        assert_eq!(
            json["schema_version"],
            serde_json::json!("brolga.context_pack/1.1")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod all_variants_tests {
    use super::{DetailLevel, ExclusionReason};

    /// See `entity.rs`: the wildcard-free `match` makes a new variant a build failure rather than a
    /// silently unreachable value.
    #[test]
    fn every_variant_appears_in_all() {
        for level in DetailLevel::all() {
            match level {
                DetailLevel::L0
                | DetailLevel::L1
                | DetailLevel::L2
                | DetailLevel::L3
                | DetailLevel::L4
                | DetailLevel::L5 => {}
            }
        }
        assert_eq!(DetailLevel::all().len(), 6);

        for reason in ExclusionReason::all() {
            match reason {
                ExclusionReason::BudgetExhausted
                | ExclusionReason::PolicyRestricted
                | ExclusionReason::BelowDetailLevel
                | ExclusionReason::NotImplemented => {}
            }
        }
        assert_eq!(ExclusionReason::all().len(), 4);
    }
}
