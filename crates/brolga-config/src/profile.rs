//! Context profiles: what an operator wants a pack to keep, without writing Rust.
//!
//! # A profile expresses priorities, and it cannot express a computation
//!
//! [#28](https://github.com/jusso-dev/Brolga/issues/28) names "no arbitrary scripting in profile
//! expressions" as a non-goal, and the shape here is that non-goal made structural: a profile is
//! weights, lists, and numbers. There is no expression type, no callback, and nothing that
//! evaluates a string. A profile that could compute would be a program running inside a
//! configuration file, in a process holding an intelligence database.
//!
//! # Hard rules are not high scores
//!
//! [`Preservation`] rules are **absolute**. A ranking pass may reorder anything it likes and a
//! budget may drop anything it must, but neither may drop a section a profile marked preserved:
//! [`ContextProfile::may_drop`] answers `false` and nothing negotiates with it.
//!
//! Expressing preservation as "a very large weight" is the obvious alternative and is wrong. A
//! weight competes, and something that competes eventually loses — to a tighter budget, to a
//! bigger weight somebody added later, to a scoring change nobody connected to this. An operator
//! who says "always keep the markings" means always.
//!
//! # A profile cannot widen what a caller may see
//!
//! Profiles select *among things the caller is already entitled to*. There is no field for a
//! marking, a recipient, or an authorisation, so no profile can grant access — the worst a
//! misconfigured one can do is ask for less. That is deliberate: a profile is the most-edited file
//! in a deployment, and the most-edited file should not be able to widen a policy decision.
//!
//! # Evaluation is deterministic
//!
//! Resolution walks inheritance in a fixed order, sorts every collection, and rejects a cycle
//! rather than following it. Two runs over one profile set produce one plan, and
//! [`ContextProfile::fingerprint`] is that plan's identity — so a pack can name the profile that
//! produced it and a reviewer can tell whether it has changed since.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// The schema this profile format is published under.
pub const PROFILE_SCHEMA: &str = "brolga.context_profile/1.0";

/// A section of a context pack a profile can talk about.
///
/// A closed vocabulary rather than free strings, because a typo in a profile must be an error an
/// operator sees at load time rather than a rule that silently never matches. A profile naming
/// `relationshps` should not quietly preserve nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Section {
    /// The disposition and its findings.
    Findings,
    /// Named entities around the subject.
    Entities,
    /// Assertions about the subject.
    Claims,
    /// Edges at the subject.
    Relationships,
    /// Observations.
    Sightings,
    /// ATT&CK techniques.
    Techniques,
    /// Groupings produced by a compression pass.
    Clusters,
    /// Disagreements worth surfacing.
    Contradictions,
    /// Where to look next.
    Pivots,
    /// Evidence references.
    Evidence,
    /// Handling markings.
    Markings,
    /// What Brolga does not know.
    Gaps,
}

impl Section {
    /// Every section.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Findings,
            Self::Entities,
            Self::Claims,
            Self::Relationships,
            Self::Sightings,
            Self::Techniques,
            Self::Clusters,
            Self::Contradictions,
            Self::Pivots,
            Self::Evidence,
            Self::Markings,
            Self::Gaps,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::Entities => "entities",
            Self::Claims => "claims",
            Self::Relationships => "relationships",
            Self::Sightings => "sightings",
            Self::Techniques => "techniques",
            Self::Clusters => "clusters",
            Self::Contradictions => "contradictions",
            Self::Pivots => "pivots",
            Self::Evidence => "evidence",
            Self::Markings => "markings",
            Self::Gaps => "gaps",
        }
    }

    /// Sections no profile may drop, whatever it says.
    ///
    /// Evidence, markings, and gaps are not content — they are what makes content *usable*. A pack
    /// without evidence cannot be defended, one without markings cannot be safely forwarded, and
    /// one without gaps reads as complete when it is not. An operator optimising for size would
    /// reach for exactly these three, and the floor exists so they cannot.
    #[must_use]
    pub const fn always_preserved() -> &'static [Self] {
        &[Self::Evidence, Self::Markings, Self::Gaps]
    }

    /// Whether this section is below the floor.
    #[must_use]
    pub fn is_always_preserved(self) -> bool {
        Self::always_preserved().contains(&self)
    }
}

impl core::fmt::Display for Section {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a profile does about a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Preservation {
    /// Always present, whatever a budget or a score says.
    Required,
    /// Included if it fits, ranked against everything else.
    Preferred,
    /// Never included.
    Excluded,
}

/// A weight, from 0 to 100.
///
/// Bounded on construction rather than clamped in use. An operator who wrote `1000` meant
/// something, and silently treating it as 100 makes their profile behave differently from what
/// they wrote with nothing to tell them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Weight(u8);

impl Weight {
    /// The neutral weight.
    pub const NEUTRAL: Self = Self(50);

    /// Build one.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::WeightOutOfRange`] above 100.
    pub const fn new(value: u8) -> Result<Self, ProfileError> {
        if value > 100 {
            return Err(ProfileError::WeightOutOfRange { value });
        }
        Ok(Self(value))
    }

    /// The weight.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Weight {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// What a profile can be wrong about.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// A weight above 100.
    #[error("`{value}` is not a weight; weights run from 0 to 100")]
    WeightOutOfRange {
        /// What was written.
        value: u8,
    },

    /// A profile inherits from one that does not exist.
    #[error("`{profile}` inherits from `{parent}`, which is not a profile")]
    UnknownParent {
        /// The profile.
        profile: String,
        /// The parent it named.
        parent: String,
    },

    /// Inheritance forms a cycle.
    #[error("`{profile}` inherits from itself through {chain}")]
    InheritanceCycle {
        /// Where the cycle was found.
        profile: String,
        /// The chain, for a diagnostic.
        chain: String,
    },

    /// A section is both required and excluded.
    ///
    /// The error #28 asks to be raised **before retrieval**: a profile that cannot be satisfied
    /// should fail at load, not produce a pack that quietly honours whichever rule was evaluated
    /// last.
    #[error("`{profile}` both requires and excludes `{section}`, which cannot both be true")]
    Contradictory {
        /// The profile.
        profile: String,
        /// The section.
        section: Section,
    },

    /// A profile excludes a section that may never be dropped.
    #[error(
        "`{profile}` excludes `{section}`, which is never droppable: a pack without it cannot be \
         defended, safely forwarded, or read as incomplete"
    )]
    ExcludesFloor {
        /// The profile.
        profile: String,
        /// The section.
        section: Section,
    },

    /// The budget allocation does not add up.
    #[error("`{profile}` allocates {total}% of its budget; allocations must not exceed 100%")]
    OverAllocated {
        /// The profile.
        profile: String,
        /// What it allocated.
        total: u32,
    },

    /// A profile has no name.
    #[error("a profile has no name")]
    Unnamed,
}

/// An operator's statement about what a pack should keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProfile {
    /// The schema this profile is written against.
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Its name, which is also what a request asks for by `purpose`.
    pub name: String,
    /// What it is for, in a sentence.
    #[serde(default)]
    pub description: String,
    /// A profile to inherit from.
    ///
    /// Single rather than multiple. Multiple inheritance needs a precedence rule, every precedence
    /// rule surprises somebody, and a profile is read by operators under time pressure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherits: Option<String>,
    /// What to do about each section. Sections not named take [`Preservation::Preferred`].
    #[serde(default)]
    pub sections: BTreeMap<Section, Preservation>,
    /// How much each section is worth when ranking under a budget.
    #[serde(default)]
    pub weights: BTreeMap<Section, Weight>,
    /// What share of the budget each section may take, as a percentage.
    #[serde(default)]
    pub allocation: BTreeMap<Section, u32>,
    /// Environments this profile is relevant to, empty meaning all of them.
    #[serde(default)]
    pub environments: BTreeSet<String>,
}

fn default_schema() -> String {
    PROFILE_SCHEMA.to_owned()
}

impl ContextProfile {
    /// A profile with nothing said about it.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema: default_schema(),
            name: name.into(),
            description: String::new(),
            inherits: None,
            sections: BTreeMap::new(),
            weights: BTreeMap::new(),
            allocation: BTreeMap::new(),
            environments: BTreeSet::new(),
        }
    }

    /// What this profile says about a section.
    #[must_use]
    pub fn preservation(&self, section: Section) -> Preservation {
        if section.is_always_preserved() {
            return Preservation::Required;
        }
        self.sections
            .get(&section)
            .copied()
            .unwrap_or(Preservation::Preferred)
    }

    /// Whether a budget or a ranking pass may drop this section.
    ///
    /// The single question the rest of the engine asks. A hard rule is answered here rather than
    /// by comparing weights, so there is no arithmetic that could tip it.
    #[must_use]
    pub fn may_drop(&self, section: Section) -> bool {
        matches!(
            self.preservation(section),
            Preservation::Preferred | Preservation::Excluded
        ) && !section.is_always_preserved()
    }

    /// The weight of a section when ranking.
    #[must_use]
    pub fn weight(&self, section: Section) -> Weight {
        self.weights
            .get(&section)
            .copied()
            .unwrap_or(Weight::NEUTRAL)
    }

    /// Whether this profile applies in an environment.
    #[must_use]
    pub fn applies_in(&self, environment: &str) -> bool {
        self.environments.is_empty() || self.environments.contains(environment)
    }

    /// Check the profile can be satisfied at all.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Contradictory`], [`ProfileError::ExcludesFloor`],
    /// [`ProfileError::OverAllocated`], or [`ProfileError::Unnamed`].
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.name.trim().is_empty() {
            return Err(ProfileError::Unnamed);
        }

        for (section, preservation) in &self.sections {
            if *preservation == Preservation::Excluded && section.is_always_preserved() {
                return Err(ProfileError::ExcludesFloor {
                    profile: self.name.clone(),
                    section: *section,
                });
            }
        }

        let total: u32 = self.allocation.values().copied().sum();
        if total > 100 {
            return Err(ProfileError::OverAllocated {
                profile: self.name.clone(),
                total,
            });
        }

        Ok(())
    }

    /// A digest of what this profile will do, so a pack can name the profile that produced it.
    ///
    /// Over the *resolved* rules rather than the file: two profiles that inherit differently but
    /// resolve to the same behaviour produce the same fingerprint, which is what makes it useful
    /// for answering "has the plan changed?" rather than "has the text changed?".
    ///
    /// The name and description are excluded for the same reason — renaming a profile does not
    /// change what it does.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut rendered = String::new();
        for section in Section::all() {
            rendered.push_str(&format!(
                "{}={:?}:{};",
                section,
                self.preservation(*section),
                self.weight(*section).get()
            ));
        }
        for (section, share) in &self.allocation {
            rendered.push_str(&format!("alloc:{section}={share};"));
        }
        for environment in &self.environments {
            rendered.push_str(&format!("env:{environment};"));
        }
        brolga_model::provenance::ContentHash::of_str(&rendered).to_string()
    }

    /// What this profile will do, as a list a human reads.
    ///
    /// The `context explain-plan` output. Ordered by section so two runs print the same thing, and
    /// stating the *reason* alongside the action — an operator debugging a profile needs to know
    /// whether a section survived because they asked for it or because it is below the floor.
    #[must_use]
    pub fn explain(&self) -> Vec<PlanStep> {
        Section::all()
            .iter()
            .map(|section| {
                let preservation = self.preservation(*section);
                let reason = if section.is_always_preserved() {
                    PlanReason::Floor
                } else if self.sections.contains_key(section) {
                    PlanReason::Profile
                } else {
                    PlanReason::Default
                };
                PlanStep {
                    section: *section,
                    action: match preservation {
                        Preservation::Required => PlanAction::Include,
                        Preservation::Preferred => PlanAction::Rank,
                        Preservation::Excluded => PlanAction::Exclude,
                    },
                    reason,
                    weight: self.weight(*section).get(),
                    allocation: self.allocation.get(section).copied(),
                }
            })
            .collect()
    }
}

/// What a plan does to a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlanAction {
    /// Always present.
    Include,
    /// Ranked against everything else and included if it fits.
    Rank,
    /// Never present.
    Exclude,
}

/// Why a plan does what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlanReason {
    /// The section is below the floor and no profile may drop it.
    Floor,
    /// The profile said so.
    Profile,
    /// Nothing said anything, so the default applies.
    Default,
}

/// One line of an explain-plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    /// Which section.
    pub section: Section,
    /// What happens to it.
    pub action: PlanAction,
    /// Why.
    pub reason: PlanReason,
    /// Its ranking weight.
    pub weight: u8,
    /// Its budget share, where the profile set one.
    pub allocation: Option<u32>,
}

/// Every profile a deployment has, with inheritance resolved.
#[derive(Debug, Clone, Default)]
pub struct ProfileSet {
    profiles: BTreeMap<String, ContextProfile>,
}

impl ProfileSet {
    /// The profiles Brolga ships, one per purpose the README names.
    ///
    /// Every one is editable: they are ordinary profiles, defined here so a deployment that writes
    /// none still has a sensible answer for each purpose, and so an operator editing one starts
    /// from something rather than a blank file.
    #[must_use]
    pub fn built_in() -> Self {
        let mut set = Self::default();
        for (name, description, required, excluded) in BUILT_IN {
            let mut profile = ContextProfile::new(*name);
            profile.description = (*description).to_owned();
            for section in *required {
                profile.sections.insert(*section, Preservation::Required);
            }
            for section in *excluded {
                profile.sections.insert(*section, Preservation::Excluded);
            }
            set.profiles.insert((*name).to_owned(), profile);
        }
        set
    }

    /// Add a profile, replacing one of the same name.
    pub fn insert(&mut self, profile: ContextProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Every profile name, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }

    /// A profile by name, without inheritance resolved.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ContextProfile> {
        self.profiles.get(name)
    }

    /// Resolve a profile, applying inheritance and validating the result.
    ///
    /// # Errors
    ///
    /// [`ProfileError::UnknownParent`], [`ProfileError::InheritanceCycle`], or whatever
    /// [`ContextProfile::validate`] finds — all of them *before* any retrieval happens, which is
    /// what #28 asks for. A profile that cannot be satisfied should fail at load rather than
    /// produce a pack that honours whichever rule was evaluated last.
    pub fn resolve(&self, name: &str) -> Result<ContextProfile, ProfileError> {
        // The chain, parent-first, so a child's rules are applied last and win.
        let mut chain: Vec<&ContextProfile> = Vec::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut current = self
            .profiles
            .get(name)
            .ok_or_else(|| ProfileError::UnknownParent {
                profile: name.to_owned(),
                parent: name.to_owned(),
            })?;

        loop {
            if !seen.insert(current.name.as_str()) {
                let mut names: Vec<&str> = chain.iter().map(|p| p.name.as_str()).collect();
                names.push(current.name.as_str());
                return Err(ProfileError::InheritanceCycle {
                    profile: name.to_owned(),
                    chain: names.join(" -> "),
                });
            }
            chain.push(current);

            let Some(parent) = current.inherits.as_deref() else {
                break;
            };
            current = self
                .profiles
                .get(parent)
                .ok_or_else(|| ProfileError::UnknownParent {
                    profile: current.name.clone(),
                    parent: parent.to_owned(),
                })?;
        }

        let mut resolved = ContextProfile::new(name);
        // Parent first: the chain was built child-to-parent, so it is applied in reverse and the
        // child's own rules land last.
        for profile in chain.iter().rev() {
            if !profile.description.is_empty() {
                resolved.description.clone_from(&profile.description);
            }
            resolved.sections.extend(profile.sections.iter());
            resolved.weights.extend(profile.weights.iter());
            resolved.allocation.extend(profile.allocation.iter());
            resolved
                .environments
                .extend(profile.environments.iter().cloned());
        }

        // Checked after inheritance, not before: a parent requiring a section and a child excluding
        // it is only contradictory once they are combined, and that is exactly the case an operator
        // will hit and struggle to see.
        for (section, preservation) in &resolved.sections {
            if *preservation == Preservation::Required
                && resolved.sections.get(section) == Some(&Preservation::Excluded)
            {
                return Err(ProfileError::Contradictory {
                    profile: name.to_owned(),
                    section: *section,
                });
            }
        }

        resolved.validate()?;
        Ok(resolved)
    }

    /// Validate every profile, returning every problem rather than the first.
    ///
    /// An operator fixing a configuration file wants the whole list. Returning one error at a time
    /// turns one edit into five round trips.
    #[must_use]
    pub fn validate_all(&self) -> Vec<ProfileError> {
        self.profiles
            .keys()
            .filter_map(|name| self.resolve(name).err())
            .collect()
    }
}

/// The shipped profiles: name, description, required sections, excluded sections.
type BuiltIn = (
    &'static str,
    &'static str,
    &'static [Section],
    &'static [Section],
);

/// One per purpose the README names.
const BUILT_IN: &[BuiltIn] = &[
    (
        "incident_triage",
        "Decide quickly whether an alert matters.",
        &[Section::Findings, Section::Claims],
        &[Section::Clusters],
    ),
    (
        "threat_hunting",
        "Find where else to look.",
        &[Section::Pivots, Section::Relationships, Section::Techniques],
        &[],
    ),
    (
        "malware_analysis",
        "Understand a sample and what it touches.",
        &[Section::Relationships, Section::Techniques],
        &[],
    ),
    (
        "actor_research",
        "Build a picture of who is doing this.",
        &[
            Section::Entities,
            Section::Relationships,
            Section::Contradictions,
        ],
        &[],
    ),
    (
        "vulnerability_prioritisation",
        "Decide what to fix first.",
        &[Section::Findings, Section::Entities],
        &[Section::Sightings],
    ),
    (
        "executive_briefing",
        "Say what happened, briefly, with sources.",
        &[Section::Findings],
        &[Section::Claims, Section::Relationships, Section::Techniques],
    ),
    (
        "detection_engineering",
        "Turn intelligence into a detection.",
        &[Section::Techniques, Section::Claims],
        &[],
    ),
    (
        "exposure_assessment",
        "Work out what of ours is reachable.",
        &[Section::Entities, Section::Relationships],
        &[],
    ),
    (
        "supply_chain_investigation",
        "Trace a dependency or a supplier.",
        &[Section::Entities, Section::Relationships, Section::Pivots],
        &[],
    ),
    (
        "case_enrichment",
        "Add what is known to an existing case.",
        &[Section::Findings, Section::Claims, Section::Sightings],
        &[],
    ),
    (
        "raw_research",
        "Everything, unranked. The profile that hides nothing.",
        &[
            Section::Findings,
            Section::Entities,
            Section::Claims,
            Section::Relationships,
            Section::Sightings,
            Section::Techniques,
            Section::Contradictions,
            Section::Pivots,
        ],
        &[],
    ),
];

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// **The criterion.** Every purpose the README names has a shipped profile, and every one of
    /// them is an ordinary editable profile rather than something hard-coded.
    #[test]
    fn every_named_purpose_has_an_editable_default() {
        let set = ProfileSet::built_in();
        for name in [
            "incident_triage",
            "threat_hunting",
            "malware_analysis",
            "actor_research",
            "vulnerability_prioritisation",
            "executive_briefing",
            "detection_engineering",
            "exposure_assessment",
            "supply_chain_investigation",
            "case_enrichment",
            "raw_research",
        ] {
            let profile = set.get(name).unwrap_or_else(|| panic!("{name} is missing"));
            assert!(!profile.description.is_empty(), "{name} has no description");
            assert!(set.resolve(name).is_ok(), "{name} does not resolve");
        }
        assert_eq!(set.names().len(), 11);
    }

    /// **The criterion.** A hard rule is absolute. Expressing preservation as a very large weight
    /// is the obvious alternative and is wrong: a weight competes, and something that competes
    /// eventually loses.
    #[test]
    fn a_required_section_cannot_be_dropped_whatever_its_weight() {
        let mut profile = ContextProfile::new("test");
        profile
            .sections
            .insert(Section::Claims, Preservation::Required);
        // A weight of zero, which under any scoring scheme is the first thing to go.
        profile
            .weights
            .insert(Section::Claims, Weight::new(0).unwrap());

        assert!(!profile.may_drop(Section::Claims));
        assert_eq!(
            profile.preservation(Section::Claims),
            Preservation::Required
        );
    }

    /// Evidence, markings, and gaps are what make content usable. An operator optimising for size
    /// would reach for exactly these, and the floor exists so they cannot.
    #[test]
    fn the_floor_sections_cannot_be_excluded_by_any_profile() {
        for section in Section::always_preserved() {
            let mut profile = ContextProfile::new("greedy");
            profile.sections.insert(*section, Preservation::Excluded);

            let error = profile.validate().unwrap_err();
            assert!(
                matches!(error, ProfileError::ExcludesFloor { .. }),
                "{section} was excludable: {error}"
            );

            // And even if one were constructed anyway, the query answers correctly.
            assert!(!profile.may_drop(*section));
            assert_eq!(profile.preservation(*section), Preservation::Required);
        }
    }

    /// **The criterion.** An impossible profile must fail before retrieval, not produce a pack that
    /// honours whichever rule was evaluated last.
    #[test]
    fn an_impossible_profile_explains_itself_before_any_retrieval() {
        let mut over = ContextProfile::new("greedy");
        over.allocation.insert(Section::Claims, 80);
        over.allocation.insert(Section::Relationships, 40);
        let error = over.validate().unwrap_err();
        assert!(error.to_string().contains("120%"), "{error}");

        let unnamed = ContextProfile::new("   ");
        assert_eq!(unnamed.validate().unwrap_err(), ProfileError::Unnamed);
    }

    #[test]
    fn a_weight_outside_the_range_is_refused_rather_than_clamped() {
        assert!(Weight::new(101).is_err());
        assert!(Weight::new(100).is_ok());
        assert!(serde_json::from_str::<Weight>("250").is_err());
        assert_eq!(serde_json::from_str::<Weight>("7").unwrap().get(), 7);
    }

    /// A child's rules win, and a parent's survive where the child says nothing.
    #[test]
    fn inheritance_applies_the_parent_first_and_the_child_last() {
        let mut set = ProfileSet::default();

        let mut parent = ContextProfile::new("base");
        parent
            .sections
            .insert(Section::Claims, Preservation::Required);
        parent
            .sections
            .insert(Section::Sightings, Preservation::Required);
        set.insert(parent);

        let mut child = ContextProfile::new("narrow");
        child.inherits = Some("base".to_owned());
        child
            .sections
            .insert(Section::Sightings, Preservation::Excluded);
        set.insert(child);

        let resolved = set.resolve("narrow").unwrap();
        assert_eq!(
            resolved.preservation(Section::Claims),
            Preservation::Required
        );
        assert_eq!(
            resolved.preservation(Section::Sightings),
            Preservation::Excluded,
            "the child overrides the parent"
        );
    }

    /// A cycle is refused rather than followed, because following one does not terminate.
    #[test]
    fn an_inheritance_cycle_is_refused_naming_the_chain() {
        let mut set = ProfileSet::default();

        let mut first = ContextProfile::new("a");
        first.inherits = Some("b".to_owned());
        set.insert(first);

        let mut second = ContextProfile::new("b");
        second.inherits = Some("a".to_owned());
        set.insert(second);

        let error = set.resolve("a").unwrap_err();
        assert!(
            matches!(error, ProfileError::InheritanceCycle { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("a -> b"), "{error}");
    }

    #[test]
    fn inheriting_from_a_profile_that_does_not_exist_names_it() {
        let mut set = ProfileSet::default();
        let mut orphan = ContextProfile::new("orphan");
        orphan.inherits = Some("nowhere".to_owned());
        set.insert(orphan);

        let error = set.resolve("orphan").unwrap_err();
        assert!(error.to_string().contains("nowhere"), "{error}");
    }

    /// **The criterion.** The plan lists what happens to every section, and why — an operator
    /// debugging a profile needs to know whether a section survived because they asked for it or
    /// because it is below the floor.
    #[test]
    fn the_explain_plan_lists_every_section_with_an_action_and_a_reason() {
        let mut profile = ContextProfile::new("test");
        profile
            .sections
            .insert(Section::Claims, Preservation::Required);
        profile
            .sections
            .insert(Section::Clusters, Preservation::Excluded);

        let plan = profile.explain();
        assert_eq!(plan.len(), Section::all().len());

        let step = |section: Section| {
            *plan
                .iter()
                .find(|step| step.section == section)
                .unwrap_or_else(|| panic!("{section} missing from the plan"))
        };

        assert_eq!(step(Section::Claims).action, PlanAction::Include);
        assert_eq!(step(Section::Claims).reason, PlanReason::Profile);

        assert_eq!(step(Section::Clusters).action, PlanAction::Exclude);

        assert_eq!(step(Section::Evidence).action, PlanAction::Include);
        assert_eq!(
            step(Section::Evidence).reason,
            PlanReason::Floor,
            "an operator must be able to see this was not their doing"
        );

        assert_eq!(step(Section::Entities).action, PlanAction::Rank);
        assert_eq!(step(Section::Entities).reason, PlanReason::Default);
    }

    /// **The criterion.** Two runs over one profile produce one plan.
    #[test]
    fn evaluation_is_deterministic() {
        let set = ProfileSet::built_in();
        for name in set.names() {
            let first = set.resolve(name).unwrap();
            let second = set.resolve(name).unwrap();
            assert_eq!(first, second, "{name}");
            assert_eq!(first.explain(), second.explain(), "{name}");
            assert_eq!(first.fingerprint(), second.fingerprint(), "{name}");
        }
    }

    /// The fingerprint is over what a profile *does*. Renaming one does not change its behaviour,
    /// and a fingerprint that moved on a rename would answer the wrong question.
    #[test]
    fn the_fingerprint_tracks_behaviour_rather_than_text() {
        let mut first = ContextProfile::new("one");
        first
            .sections
            .insert(Section::Claims, Preservation::Required);

        let mut renamed = first.clone();
        renamed.name = "two".to_owned();
        renamed.description = "a completely different sentence".to_owned();

        assert_eq!(first.fingerprint(), renamed.fingerprint());

        let mut changed = first.clone();
        changed
            .sections
            .insert(Section::Claims, Preservation::Excluded);
        assert_ne!(first.fingerprint(), changed.fingerprint());
    }

    /// A profile selects among things a caller may already see. There is no field for a marking, a
    /// recipient, or an authorisation, so no profile can widen access.
    #[test]
    fn a_profile_has_no_field_that_could_widen_access() {
        let profile = ContextProfile::new("test");
        let json = serde_json::to_value(&profile).unwrap();
        let object = json.as_object().unwrap();

        for forbidden in [
            "recipient",
            "authorisation",
            "authorization",
            "tlp",
            "clearance",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "`{forbidden}` would let the most-edited file in a deployment widen a policy \
                 decision"
            );
        }
        // And the whole field set is the one this test knows about, so adding one is a decision.
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "allocation",
                "description",
                "environments",
                "name",
                "schema",
                "sections",
                "weights"
            ]
        );
    }

    #[test]
    fn a_profile_applies_everywhere_unless_it_names_environments() {
        let mut profile = ContextProfile::new("test");
        assert!(profile.applies_in("production"));

        profile.environments.insert("lab".to_owned());
        assert!(profile.applies_in("lab"));
        assert!(!profile.applies_in("production"));
    }

    /// An operator fixing a configuration file wants the whole list, not one error at a time.
    #[test]
    fn validating_a_set_reports_every_problem_rather_than_the_first() {
        let mut set = ProfileSet::default();

        let mut over = ContextProfile::new("over");
        over.allocation.insert(Section::Claims, 200);
        set.insert(over);

        let mut orphan = ContextProfile::new("orphan");
        orphan.inherits = Some("nowhere".to_owned());
        set.insert(orphan);

        assert_eq!(set.validate_all().len(), 2);
        assert!(ProfileSet::built_in().validate_all().is_empty());
    }

    #[test]
    fn a_profile_round_trips_through_json_and_refuses_unknown_fields() {
        let mut profile = ContextProfile::new("test");
        profile
            .sections
            .insert(Section::Claims, Preservation::Required);
        profile
            .weights
            .insert(Section::Claims, Weight::new(90).unwrap());

        let json = serde_json::to_string(&profile).unwrap();
        let back: ContextProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, profile);

        assert!(
            serde_json::from_str::<ContextProfile>(r#"{"name":"x","script":"1+1"}"#).is_err(),
            "a profile must not accept a field that looks like an expression"
        );
    }

    /// A typo must be an error an operator sees, not a rule that silently never matches.
    #[test]
    fn an_unknown_section_name_is_refused() {
        assert!(serde_json::from_str::<Section>("\"relationshps\"").is_err());
        assert!(serde_json::from_str::<Section>("\"claims\"").is_ok());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod all_variants_tests {
    use super::Section;

    #[test]
    fn every_section_appears_in_all() {
        for section in Section::all() {
            match section {
                Section::Findings
                | Section::Entities
                | Section::Claims
                | Section::Relationships
                | Section::Sightings
                | Section::Techniques
                | Section::Clusters
                | Section::Contradictions
                | Section::Pivots
                | Section::Evidence
                | Section::Markings
                | Section::Gaps => {}
            }
        }
        assert_eq!(Section::all().len(), 12);
    }
}
