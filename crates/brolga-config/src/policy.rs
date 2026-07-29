//! Who is asking, what they may see, and why something was withheld.
//!
//! # Deny by default, and an unknown recipient is not a permitted one
//!
//! Every decision starts from refusal and is widened by an explicit statement.
//! [`PolicyIdentity::anonymous`] — the identity a caller who identified nothing gets — may see
//! `TLP:CLEAR` and nothing else.
//!
//! The tempting alternative is to treat an unidentified caller as a local operator with full
//! access, on the grounds that local use is the common case. That is exactly backwards: the
//! *authenticated network* caller is the one whose identity is known, and the unidentified one is
//! the one nothing is known about. A default that grants everything to whoever says least is a
//! default that gets exploited by the path nobody tested.
//!
//! Local CLI use gets its access from [`PolicyIdentity::local_operator`] — a *stated* identity,
//! constructed on purpose, rather than from an absence of information.
//!
//! # A denial explains the rule and never the content
//!
//! [`Denial`] names the marking that stopped release and the identity that lacked it. It never
//! carries the withheld value, the claim, or the source text. An error message is the thing most
//! likely to reach a log file, a ticket, or a screenshot, and a denial that quoted what it was
//! protecting would be a disclosure channel that only triggers on the material worth protecting.
//!
//! # Why this lives beside the profiles rather than in `brolga-security`
//!
//! [ADR 0001](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0001-workspace-boundaries-and-public-interface-versioning.md)
//! §1 makes `brolga-security` a leaf crate with no first-party dependencies, and a policy decision
//! is made over [`Marking`]s — which are model types. Policy therefore sits here, with the other
//! rules an operator writes down, rather than amending that boundary to reach a type.
//!
//! # Redistribution is a second decision
//!
//! Being allowed to *see* something is not being allowed to pass it on.
//! [`Capability::Redistribute`] is separate from [`Capability::Read`], and an attribution marking
//! is checked at redistribution rather than at read — a caveat that says "cite the source if you
//! share this" constrains sharing, not looking.

use std::collections::BTreeSet;

use brolga_model::{Marking, MarkingSet, PapLevel, TlpLevel};

/// What a caller is allowed to do at all.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    /// Read a context pack.
    Read,
    /// Expand a handle to a canonical record.
    ExpandCanonical,
    /// Expand a handle to the original source bytes.
    ///
    /// Separate from [`Self::ExpandCanonical`] because they are different disclosures. A canonical
    /// record is Brolga's reading of a source; the source is somebody else's material, under
    /// somebody else's licence.
    ExpandSource,
    /// Pass material on to a third party.
    Redistribute,
}

impl Capability {
    /// Every capability.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Read,
            Self::ExpandCanonical,
            Self::ExpandSource,
            Self::Redistribute,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ExpandCanonical => "expand_canonical",
            Self::ExpandSource => "expand_source",
            Self::Redistribute => "redistribute",
        }
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentity {
    /// A name for the caller, for a decision record.
    pub name: String,
    /// The highest TLP level this identity may receive.
    pub max_tlp: TlpLevel,
    /// The highest PAP level this identity may act on.
    pub max_pap: PapLevel,
    /// What it may do.
    pub capabilities: BTreeSet<Capability>,
    /// Handling caveats this identity has been cleared for.
    ///
    /// A caveat Brolga does not recognise is not satisfiable by anybody, which is the safe reading:
    /// an unrecognised instruction may say anything, and guessing that it permits release is the
    /// one guess that cannot be taken back.
    pub cleared_handling: BTreeSet<String>,
    /// The environment this identity operates in.
    pub environment: String,
}

impl PolicyIdentity {
    /// The identity a caller who identified nothing gets.
    ///
    /// `TLP:CLEAR`, read only. See the module documentation for why this is not "everything".
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            name: "anonymous".to_owned(),
            max_tlp: TlpLevel::Clear,
            max_pap: PapLevel::Clear,
            capabilities: BTreeSet::from([Capability::Read]),
            cleared_handling: BTreeSet::new(),
            environment: "unknown".to_owned(),
        }
    }

    /// The identity a local CLI operator gets.
    ///
    /// Full access, because somebody with the database file already has the database file — a
    /// policy that withheld `TLP:RED` from the person holding the SQLite file would be theatre.
    ///
    /// Stated as an identity rather than inferred from an absence of authentication, so the grant
    /// is visible in a decision record and the network path cannot reach it by simply not
    /// identifying itself.
    #[must_use]
    pub fn local_operator() -> Self {
        Self {
            name: "local-operator".to_owned(),
            max_tlp: TlpLevel::Red,
            max_pap: PapLevel::Red,
            capabilities: Capability::all().iter().copied().collect(),
            cleared_handling: BTreeSet::new(),
            environment: "local".to_owned(),
        }
    }

    /// Build a named identity, starting from anonymous.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::anonymous()
        }
    }

    /// Raise the TLP ceiling.
    #[must_use]
    pub const fn with_max_tlp(mut self, level: TlpLevel) -> Self {
        self.max_tlp = level;
        self
    }

    /// Raise the PAP ceiling.
    #[must_use]
    pub const fn with_max_pap(mut self, level: PapLevel) -> Self {
        self.max_pap = level;
        self
    }

    /// Grant a capability.
    #[must_use]
    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Clear this identity for a named handling caveat.
    #[must_use]
    pub fn cleared_for(mut self, caveat: impl Into<String>) -> Self {
        self.cleared_handling.insert(caveat.into());
        self
    }

    /// Set the environment.
    #[must_use]
    pub fn in_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = environment.into();
        self
    }

    /// Whether this identity holds a capability.
    #[must_use]
    pub fn can(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Why something was withheld.
///
/// Names the rule and the identity. Never the content — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denial {
    /// The material's TLP level is above the identity's ceiling.
    #[error(
        "withheld from `{identity}`: the material is TLP:{marking} and this identity is cleared to \
         TLP:{ceiling}"
    )]
    TlpAboveCeiling {
        /// Who asked.
        identity: String,
        /// The material's level.
        marking: String,
        /// What they are cleared for.
        ceiling: String,
    },

    /// The material's PAP level is above the identity's ceiling.
    #[error(
        "withheld from `{identity}`: the material is PAP:{marking} and this identity is cleared to \
         PAP:{ceiling}"
    )]
    PapAboveCeiling {
        /// Who asked.
        identity: String,
        /// The material's level.
        marking: String,
        /// What they are cleared for.
        ceiling: String,
    },

    /// A handling caveat this identity is not cleared for.
    #[error(
        "withheld from `{identity}`: the material carries the handling caveat `{caveat}`, which \
         this identity is not cleared for"
    )]
    HandlingNotCleared {
        /// Who asked.
        identity: String,
        /// The caveat's name, which is the source's own label rather than its content.
        caveat: String,
    },

    /// The identity lacks the capability for this operation.
    #[error("`{identity}` does not hold the `{capability}` capability")]
    MissingCapability {
        /// Who asked.
        identity: String,
        /// What was needed.
        capability: Capability,
    },

    /// Redistribution requires attribution the caller has not undertaken to provide.
    #[error(
        "`{identity}` may read this but not redistribute it: the source requires attribution, and \
         redistribution is a separate decision from reading"
    )]
    AttributionRequired {
        /// Who asked.
        identity: String,
    },
}

impl Denial {
    /// A short machine-readable kind, for a decision record.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::TlpAboveCeiling { .. } => "tlp_above_ceiling",
            Self::PapAboveCeiling { .. } => "pap_above_ceiling",
            Self::HandlingNotCleared { .. } => "handling_not_cleared",
            Self::MissingCapability { .. } => "missing_capability",
            Self::AttributionRequired { .. } => "attribution_required",
        }
    }
}

/// What a policy check decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the material may be released.
    pub allowed: bool,
    /// Every rule that refused, where it did.
    pub denials: Vec<Denial>,
}

impl Decision {
    /// A permitted release.
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            denials: Vec::new(),
        }
    }

    /// Whether anything refused.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        !self.allowed
    }

    /// The reasons, as machine-readable kinds.
    #[must_use]
    pub fn kinds(&self) -> Vec<&'static str> {
        self.denials.iter().map(Denial::kind).collect()
    }
}

/// How the TLP levels order.
///
/// `AMBER+STRICT` sits **above** `AMBER` and below `RED`: it is amber with the onward-sharing
/// permission removed, so an identity cleared only to amber must not receive it. Ordering them as
/// equal is the mistake this function exists to prevent — the whole difference between the two is
/// a restriction, and treating a restriction as equivalent to its absence releases material to
/// exactly the recipients it was marked to exclude.
const fn tlp_rank(level: TlpLevel) -> u8 {
    match level {
        TlpLevel::Clear => 0,
        TlpLevel::Green => 1,
        TlpLevel::Amber => 2,
        TlpLevel::AmberStrict => 3,
        TlpLevel::Red => 4,
        // `TlpLevel` is `#[non_exhaustive]`. A level this build does not know ranks *above* red,
        // so it is released to nobody. Any other default would release material under a marking
        // whose meaning this build cannot read.
        _ => u8::MAX,
    }
}

/// How the PAP levels order.
const fn pap_rank(level: PapLevel) -> u8 {
    match level {
        PapLevel::Clear => 0,
        PapLevel::Green => 1,
        PapLevel::Amber => 2,
        PapLevel::Red => 3,
        // As above: unknown ranks highest and reaches nobody.
        _ => u8::MAX,
    }
}

/// Decide whether an identity may receive material carrying these markings.
///
/// `capability` is what the caller is trying to do. Reading and redistributing are separate
/// decisions over the same markings, because being allowed to see something is not being allowed
/// to pass it on.
///
/// Every failing rule is reported rather than the first. An operator fixing an identity's clearance
/// wants the whole list, and returning one at a time turns one fix into several round trips.
#[must_use]
pub fn decide(
    identity: &PolicyIdentity,
    markings: &MarkingSet,
    capability: Capability,
) -> Decision {
    let mut denials = Vec::new();

    if !identity.can(capability) {
        denials.push(Denial::MissingCapability {
            identity: identity.name.clone(),
            capability,
        });
    }

    for marking in markings.iter() {
        match marking {
            Marking::Tlp(level) if tlp_rank(*level) > tlp_rank(identity.max_tlp) => {
                denials.push(Denial::TlpAboveCeiling {
                    identity: identity.name.clone(),
                    marking: level.as_str().to_owned(),
                    ceiling: identity.max_tlp.as_str().to_owned(),
                });
            }
            Marking::Pap(level) if pap_rank(*level) > pap_rank(identity.max_pap) => {
                denials.push(Denial::PapAboveCeiling {
                    identity: identity.name.clone(),
                    marking: format!("{level:?}").to_lowercase(),
                    ceiling: format!("{:?}", identity.max_pap).to_lowercase(),
                });
            }
            // Deny-by-default. An unrecognised caveat may say anything, and guessing that it
            // permits release is the one guess that cannot be taken back.
            Marking::Handling(caveat) if !identity.cleared_handling.contains(caveat.as_str()) => {
                denials.push(Denial::HandlingNotCleared {
                    identity: identity.name.clone(),
                    caveat: caveat.as_str().to_owned(),
                });
            }
            Marking::Attribution(_) if capability == Capability::Redistribute => {
                // Checked at redistribution, not at read. A caveat that says "cite the source if
                // you share this" constrains sharing, not looking.
                denials.push(Denial::AttributionRequired {
                    identity: identity.name.clone(),
                });
            }
            _ => {}
        }
    }

    Decision {
        allowed: denials.is_empty(),
        denials,
    }
}

/// Split a set of items into what may be released and what was withheld.
///
/// Returns the permitted items and one denial per withheld item, so a caller can both serve what it
/// may and say how much it could not. A filter that silently dropped the rest would produce a pack
/// that reads as complete.
pub fn partition<'a, T>(
    identity: &PolicyIdentity,
    items: &'a [T],
    capability: Capability,
    markings_of: impl for<'b> Fn(&'b T) -> &'b MarkingSet,
) -> (Vec<&'a T>, Vec<Denial>) {
    let mut allowed = Vec::new();
    let mut denials = Vec::new();

    for item in items {
        let decision = decide(identity, markings_of(item), capability);
        if decision.allowed {
            allowed.push(item);
        } else {
            denials.extend(decision.denials);
        }
    }

    (allowed, denials)
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
    use brolga_model::ShortText;

    fn tlp(level: TlpLevel) -> MarkingSet {
        let mut set = MarkingSet::empty();
        set.insert(Marking::Tlp(level));
        set
    }

    /// **The criterion.** Every level, in both directions.
    #[test]
    fn every_tlp_level_releases_to_its_own_ceiling_and_no_higher() {
        let levels = [
            TlpLevel::Clear,
            TlpLevel::Green,
            TlpLevel::Amber,
            TlpLevel::AmberStrict,
            TlpLevel::Red,
        ];

        for (material_index, material) in levels.iter().enumerate() {
            for (ceiling_index, ceiling) in levels.iter().enumerate() {
                let identity = PolicyIdentity::named("test").with_max_tlp(*ceiling);
                let decision = decide(&identity, &tlp(*material), Capability::Read);

                assert_eq!(
                    decision.allowed,
                    material_index <= ceiling_index,
                    "TLP:{material:?} to a TLP:{ceiling:?} identity"
                );
            }
        }
    }

    /// **The criterion, and the one most easily got wrong.** `AMBER+STRICT` is amber with the
    /// onward-sharing permission removed. Treating it as equal to amber releases material to
    /// exactly the recipients it was marked to exclude.
    #[test]
    fn amber_strict_is_above_amber_rather_than_equal_to_it() {
        let amber_identity = PolicyIdentity::named("partner").with_max_tlp(TlpLevel::Amber);

        assert!(decide(&amber_identity, &tlp(TlpLevel::Amber), Capability::Read).allowed);
        assert!(
            !decide(
                &amber_identity,
                &tlp(TlpLevel::AmberStrict),
                Capability::Read
            )
            .allowed,
            "an amber-cleared identity must not receive amber+strict"
        );

        let strict_identity = PolicyIdentity::named("internal").with_max_tlp(TlpLevel::AmberStrict);
        assert!(
            decide(
                &strict_identity,
                &tlp(TlpLevel::AmberStrict),
                Capability::Read
            )
            .allowed
        );
        assert!(
            !decide(&strict_identity, &tlp(TlpLevel::Red), Capability::Read).allowed,
            "and must still not receive red"
        );
    }

    /// A default that grants everything to whoever says least is a default that gets exploited by
    /// the path nobody tested.
    #[test]
    fn an_unidentified_caller_gets_clear_and_nothing_more() {
        let anonymous = PolicyIdentity::anonymous();

        assert!(decide(&anonymous, &tlp(TlpLevel::Clear), Capability::Read).allowed);
        for level in [
            TlpLevel::Green,
            TlpLevel::Amber,
            TlpLevel::AmberStrict,
            TlpLevel::Red,
        ] {
            assert!(
                !decide(&anonymous, &tlp(level), Capability::Read).allowed,
                "{level:?} reached an unidentified caller"
            );
        }

        // And it can do nothing but read.
        assert!(anonymous.can(Capability::Read));
        for capability in [
            Capability::ExpandCanonical,
            Capability::ExpandSource,
            Capability::Redistribute,
        ] {
            assert!(!anonymous.can(capability), "{capability}");
        }
    }

    /// Local access is a stated identity, not an absence of authentication — so the network path
    /// cannot reach it by simply not identifying itself.
    #[test]
    fn local_access_is_granted_by_a_stated_identity_rather_than_by_silence() {
        let local = PolicyIdentity::local_operator();
        assert!(decide(&local, &tlp(TlpLevel::Red), Capability::ExpandSource).allowed);

        assert_ne!(
            PolicyIdentity::anonymous().max_tlp,
            local.max_tlp,
            "the two must not be the same identity by another name"
        );
    }

    /// **The criterion.** A denial names the rule and the identity, and never the material.
    #[test]
    fn a_denial_explains_the_rule_without_leaking_the_content() {
        let identity = PolicyIdentity::named("partner").with_max_tlp(TlpLevel::Green);
        let mut markings = tlp(TlpLevel::Red);
        markings.insert(Marking::Handling(
            ShortText::new("do-not-share-with-vendor-x").unwrap(),
        ));

        let decision = decide(&identity, &markings, Capability::Read);
        assert!(decision.is_denied());

        let rendered = decision
            .denials
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");

        // The rule and the identity are named.
        assert!(rendered.contains("partner"), "{rendered}");
        assert!(rendered.contains("red"), "{rendered}");
        // The caveat's *label* is named — it is the source's own handling instruction, and an
        // operator cannot act on "a caveat" — but nothing else about the material is.
        assert!(
            rendered.contains("do-not-share-with-vendor-x"),
            "{rendered}"
        );

        assert_eq!(
            decision.kinds(),
            vec!["tlp_above_ceiling", "handling_not_cleared"]
        );
    }

    /// An operator fixing a clearance wants the whole list, not one round trip per rule.
    #[test]
    fn every_failing_rule_is_reported_rather_than_the_first() {
        let identity = PolicyIdentity::named("limited").with_max_tlp(TlpLevel::Clear);
        let mut markings = tlp(TlpLevel::Red);
        markings.insert(Marking::Pap(PapLevel::Red));
        markings.insert(Marking::Handling(ShortText::new("caveat").unwrap()));

        let decision = decide(&identity, &markings, Capability::ExpandSource);
        assert_eq!(decision.denials.len(), 4, "{:?}", decision.kinds());
        assert!(decision.kinds().contains(&"missing_capability"));
    }

    /// An unrecognised caveat may say anything, and guessing that it permits release is the one
    /// guess that cannot be taken back.
    #[test]
    fn an_unrecognised_handling_caveat_denies_by_default() {
        let mut markings = MarkingSet::empty();
        markings.insert(Marking::Handling(ShortText::new("licence-xyz").unwrap()));

        let uncleared = PolicyIdentity::named("a").with_max_tlp(TlpLevel::Red);
        assert!(!decide(&uncleared, &markings, Capability::Read).allowed);

        let cleared = uncleared.clone().cleared_for("licence-xyz");
        assert!(decide(&cleared, &markings, Capability::Read).allowed);
    }

    /// Being allowed to see something is not being allowed to pass it on.
    #[test]
    fn attribution_constrains_redistribution_rather_than_reading() {
        let mut markings = MarkingSet::empty();
        markings.insert(Marking::Attribution(
            ShortText::new("Example CERT").unwrap(),
        ));

        let identity = PolicyIdentity::named("reader")
            .with_max_tlp(TlpLevel::Red)
            .with_capability(Capability::Redistribute);

        assert!(
            decide(&identity, &markings, Capability::Read).allowed,
            "attribution does not stop reading"
        );
        let redistribution = decide(&identity, &markings, Capability::Redistribute);
        assert!(redistribution.is_denied());
        assert_eq!(redistribution.kinds(), vec!["attribution_required"]);
    }

    /// Reading a canonical record and reading the original bytes are different disclosures: one is
    /// Brolga's reading of a source, the other is somebody else's material under their licence.
    #[test]
    fn expanding_to_source_is_a_separate_capability_from_expanding_to_canonical() {
        let identity = PolicyIdentity::named("analyst")
            .with_max_tlp(TlpLevel::Red)
            .with_capability(Capability::ExpandCanonical);

        assert!(decide(&identity, &MarkingSet::empty(), Capability::ExpandCanonical).allowed);
        assert!(!decide(&identity, &MarkingSet::empty(), Capability::ExpandSource).allowed);
    }

    /// **The criterion.** A filter that silently dropped the rest would produce a pack that reads
    /// as complete.
    #[test]
    fn partitioning_reports_what_was_withheld_as_well_as_what_was_served() {
        struct Item {
            markings: MarkingSet,
        }

        let items = vec![
            Item {
                markings: tlp(TlpLevel::Clear),
            },
            Item {
                markings: tlp(TlpLevel::Red),
            },
            Item {
                markings: tlp(TlpLevel::Green),
            },
        ];

        let identity = PolicyIdentity::named("partner").with_max_tlp(TlpLevel::Green);
        let (allowed, denials) =
            partition(&identity, &items, Capability::Read, |item| &item.markings);

        assert_eq!(allowed.len(), 2);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].kind(), "tlp_above_ceiling");
    }

    /// Unmarked material is releasable to anybody who can read at all — but only because *nothing*
    /// restricted it, which is a different state from a marking nobody understood.
    #[test]
    fn unmarked_material_is_released_and_an_unknown_caveat_is_not() {
        let anonymous = PolicyIdentity::anonymous();
        assert!(decide(&anonymous, &MarkingSet::empty(), Capability::Read).allowed);

        let mut odd = MarkingSet::empty();
        odd.insert(Marking::Handling(ShortText::new("unknown").unwrap()));
        assert!(!decide(&anonymous, &odd, Capability::Read).allowed);
    }

    #[test]
    fn every_capability_has_a_distinct_name_and_appears_in_all() {
        let mut names: Vec<&str> = Capability::all().iter().map(|c| c.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);

        for capability in Capability::all() {
            match capability {
                Capability::Read
                | Capability::ExpandCanonical
                | Capability::ExpandSource
                | Capability::Redistribute => {}
            }
        }
    }
}
