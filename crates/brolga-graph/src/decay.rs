//! Temporal state and versioned decay: how a record's standing falls with age, and what it must
//! never fall to.
//!
//! # Why this owns freshness outright
//!
//! [`confidence`](crate::confidence) used to carry its own banded step function over an
//! observation's age, and its documentation said this issue would take it over. It has. There is
//! now one curve, described by one [`DecayPolicy`], and
//! [`ConfidencePolicy::recency_score`](crate::confidence::ConfidencePolicy::recency_score)
//! delegates to it. Two notions of freshness would drift the first time somebody tuned one of them,
//! and an analyst comparing a ranked list against a confidence figure would be comparing two
//! different opinions about the same day.
//!
//! # Decay is a pure function of age and policy
//!
//! Nothing here reads the clock. The caller passes `now`, every arithmetic step is integer, and no
//! collection iterated on the scoring path is hash-ordered. That is not fastidiousness: a scorer
//! that reads the clock cannot be tested for determinism, cannot be replayed against last month's
//! database, and cannot be shown to have produced the figure that is stored beside it.
//!
//! [`DecayEvaluator`] is that pure function. [`DecayLedger`] wraps it and is the only thing here
//! that holds state — the state each subject was last seen in, so that a change of state can be
//! *recorded* rather than inferred from a number that moved.
//!
//! # Nothing decays to zero
//!
//! Every profile has a floor, and [`DecayProfile::half_life`] raises a configured floor of nought
//! to [`DecayProfile::RETENTION_FLOOR`]. A standing of zero is what "never asserted" looks like once
//! it is rendered as a number, and the two must not be confusable: an indicator that has aged out
//! was observed by somebody, and one that was never asserted was not. The distinction lives in the
//! type — [`DecayAssessment::standing`] is `None` only for [`DecayState::Undated`], and is a number
//! at or above the floor for everything else.
//!
//! # Decay moves ranking inputs, not records
//!
//! [`DecayAssessment`] carries [`DecayAssessment::asserted`] — what the source said — beside
//! [`DecayAssessment::ranking_input`], which is what a prioritised queue should sort on. Ageing
//! never rewrites the first, never changes a [`LifecycleStatus`], and never deletes anything.
//! [#23](https://github.com/jusso-dev/Brolga/issues/23)'s non-goal is explicit that historical data
//! is not deleted on account of decay, and a decay step that edited a source record would be that
//! deletion spread over time.
//!
//! # Normalising to UTC does not mean discarding what the source wrote
//!
//! [`SourceInstant`] keeps the source's own rendering beside the canonical UTC value the arithmetic
//! uses, built on [`Timestamp::parse_rfc3339_with_original`]. `2026-03-01T09:00:00+11:00` and
//! `2026-02-28T22:00:00Z` are the same instant and decay identically, and the offset a source chose
//! is still evidence about that source.
//!
//! # A caller-supplied timestamp cannot buy freshness
//!
//! The issue's security note. An anchor dated after `now` would otherwise let a source hold its own
//! records permanently fresh by writing tomorrow's date, so by default such an anchor is refused
//! and the next one in the policy's order is tried. Accepting it is
//! [`FutureDating::Accepted`] — an explicit, digested, recorded policy decision rather than a
//! default.
//!
//! # Every decision is a record
//!
//! ADR 0004 §2. Each assessment carries what it measured, from which instant, what it decided,
//! which `(algorithm, version)` decided it, under which policy digest, and why — and the reasons
//! are authored `&'static str`, never interpolated from feed content. A derived decision names no
//! actor and no policy context; those columns stay `None` rather than being filled with "system",
//! which would make an unattributed decision indistinguishable from an attributed one.

use std::collections::BTreeMap;

use brolga_model::{
    ConfidenceScore, ContentHash, LifecycleStatus, ModelError, TemporalState, Timestamp,
};

/// This algorithm's identifier, stamped into every assessment and transition it produces.
///
/// A compatibility surface under ADR 0001 §6: changing what this `(id, version)` pair computes for
/// the same inputs *under the same policy* is a breaking change.
pub const DECAY_ALGORITHM: &str = "brolga.decay.half-life";

/// This algorithm's version.
///
/// Bump when the *shape* of the computation changes — a different anchor rule, a different curve, a
/// changed treatment of undated records. Changing a half-life or a floor is a policy change, not an
/// algorithm change, and is carried by [`DecayPolicy::digest`] instead.
pub const DECAY_ALGORITHM_VERSION: u32 = 1;

/// Seconds in a day, for the age arithmetic.
const SECONDS_PER_DAY: i64 = 86_400;

/// An instant as the source wrote it, beside the canonical UTC value.
///
/// Normalising to UTC is lossy: the offset a source chose and the subsecond precision it used are
/// both discarded, and both can be evidence about the source. `brolga-model`'s
/// [`Timestamp::parse_rfc3339_with_original`] exists so a caller cannot normalise without being
/// handed the original to keep, and this type is where the graph layer keeps it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceInstant {
    canonical: Timestamp,
    original: Option<String>,
}

impl SourceInstant {
    /// Parse a source's RFC 3339 text, keeping it beside the canonical value it normalises to.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidValue`] if the text is not a valid RFC 3339 timestamp. The
    /// model's error quotes a truncated, escaped preview rather than the raw bytes.
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let (canonical, original) = Timestamp::parse_rfc3339_with_original(value)?;
        Ok(Self {
            canonical,
            original: Some(bounded(&original)),
        })
    }

    /// An instant whose source rendering was not retained.
    ///
    /// Used where the timestamp reaches this layer already canonicalised — from the database, or
    /// from [`TemporalState`], which is deliberately the lossy half of the model's pair. The
    /// absence is visible rather than being papered over with the canonical rendering, because
    /// "the source wrote `Z`" and "nobody kept what the source wrote" are different facts.
    #[must_use]
    pub const fn canonical_only(canonical: Timestamp) -> Self {
        Self {
            canonical,
            original: None,
        }
    }

    /// The UTC instant the arithmetic uses.
    #[must_use]
    pub const fn canonical(&self) -> Timestamp {
        self.canonical
    }

    /// Exactly what the source wrote, where it was retained.
    #[must_use]
    pub fn original(&self) -> Option<&str> {
        self.original.as_deref()
    }
}

/// Which of a record's instants the age is measured from.
///
/// Ordered by the policy rather than fixed here, because which instant means "how old is this?"
/// depends on the feed. A blocklist's `last_seen` is the observation; a report's `published` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DecayAnchor {
    /// When the subject was observed, as the source states it.
    Observed,
    /// The most recent observation recorded against the record.
    LastSeen,
    /// When the source published the record.
    Published,
    /// When the source last changed the record.
    Modified,
    /// When the source first created the record.
    Created,
    /// The earliest observation recorded against the record.
    FirstSeen,
}

impl DecayAnchor {
    /// Every anchor this build knows, in the default order of preference.
    ///
    /// Exposed so a policy that reorders them cannot silently omit one, and so a test can assert
    /// that every anchor is reachable.
    pub const ALL: [Self; 6] = [
        Self::Observed,
        Self::LastSeen,
        Self::Published,
        Self::Modified,
        Self::Created,
        Self::FirstSeen,
    ];

    /// A stable label, written to the database and rendered in explanations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::LastSeen => "last_seen",
            Self::Published => "published",
            Self::Modified => "modified",
            Self::Created => "created",
            Self::FirstSeen => "first_seen",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "observed" => Some(Self::Observed),
            "last_seen" => Some(Self::LastSeen),
            "published" => Some(Self::Published),
            "modified" => Some(Self::Modified),
            "created" => Some(Self::Created),
            "first_seen" => Some(Self::FirstSeen),
            _ => None,
        }
    }
}

impl core::fmt::Display for DecayAnchor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a timestamp dated after the evaluation instant may be believed.
///
/// The issue's security note in one field. A source that dates its own records in the future would
/// otherwise hold them permanently fresh, and no amount of provenance makes that arithmetic true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[non_exhaustive]
pub enum FutureDating {
    /// A future-dated anchor is refused and the next anchor is tried. The default.
    #[default]
    Rejected,
    /// A future-dated anchor is used, at no age. An explicit operator decision, carried in the
    /// policy digest so a figure computed under it is distinguishable.
    Accepted,
}

impl FutureDating {
    /// A stable label, for the policy digest and for explanations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Accepted => "accepted",
        }
    }
}

impl core::fmt::Display for FutureDating {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How fast one kind of record loses standing, and how much it keeps regardless.
///
/// A half-life rather than a fixed lifetime because ageing is not a cliff: a ninety-day-old
/// observation of a still-live artefact is weaker evidence than a fresh one, not *no* evidence.
/// The floor is what stops that reasoning running off the end into a zero nobody asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecayProfile {
    half_life_days: u32,
    floor: u8,
    never: bool,
}

impl DecayProfile {
    /// The lowest standing any decaying profile may reach.
    ///
    /// One, not nought. A zero standing renders identically to "never asserted", and this module's
    /// whole purpose is to keep an indicator that has aged out apart from one nobody ever claimed.
    pub const RETENTION_FLOOR: u8 = 1;

    /// The shortest half-life a profile may declare.
    ///
    /// A half-life of nought days is a division by zero dressed as a configuration value, and the
    /// honest reading of "halve it every no time at all" is "expire it immediately", which is
    /// [`Self::never`]'s opposite and should be written as a one-day half-life if it is meant.
    pub const MINIMUM_HALF_LIFE_DAYS: u32 = 1;

    /// A profile that halves a record's standing every `half_life_days`, never below `floor`.
    ///
    /// Both arguments are clamped rather than refused: `half_life_days` to at least
    /// [`Self::MINIMUM_HALF_LIFE_DAYS`] and `floor` to at least [`Self::RETENTION_FLOOR`]. The
    /// clamp is not silent — the effective values are what [`DecayPolicy::digest`] covers and what
    /// [`DecayAssessment`] reports, so an operator who configured a floor of nought can see that
    /// they did not get one.
    #[must_use]
    pub const fn half_life(half_life_days: u32, floor: u8) -> Self {
        let half_life_days = if half_life_days < Self::MINIMUM_HALF_LIFE_DAYS {
            Self::MINIMUM_HALF_LIFE_DAYS
        } else {
            half_life_days
        };
        let floor = if floor < Self::RETENTION_FLOOR {
            Self::RETENTION_FLOOR
        } else if floor > 100 {
            100
        } else {
            floor
        };
        Self {
            half_life_days,
            floor,
            never: false,
        }
    }

    /// A profile that never loses standing with age.
    ///
    /// For subjects where age is not evidence of anything. A file digest names a fixed sequence of
    /// bytes; those bytes are exactly as malicious in five years as they were on the day somebody
    /// looked at them, and decaying the claim would be decaying a statement about arithmetic.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            half_life_days: 0,
            floor: 100,
            never: true,
        }
    }

    /// Whether this profile is exempt from decay.
    #[must_use]
    pub const fn never_decays(self) -> bool {
        self.never
    }

    /// The effective half-life in whole days. Zero for a profile that never decays.
    #[must_use]
    pub const fn half_life_days(self) -> u32 {
        self.half_life_days
    }

    /// The effective floor.
    #[must_use]
    pub const fn floor(self) -> u8 {
        self.floor
    }

    /// The standing that survives a given age, in `0..=100`.
    ///
    /// Integer throughout, so the same age gives the same answer on every machine: whole half-lives
    /// are a right shift, and the part-way point is a straight line between the rung above and the
    /// rung below. A straight line inside the band rather than a true exponential because it is
    /// explainable to the analyst it affects — "two half-lives down, and a third of the way into the
    /// next" — and because the difference from a floating-point exponential is smaller than the
    /// confidence of any input feeding it.
    #[must_use]
    pub fn standing_after(self, age_in_days: u32) -> u8 {
        if self.never {
            return 100;
        }
        let half_life = u64::from(self.half_life_days.max(Self::MINIMUM_HALF_LIFE_DAYS));
        let age = u64::from(age_in_days);
        let whole = age.checked_div(half_life).unwrap_or(0);
        let remainder = age.checked_rem(half_life).unwrap_or(0);

        let shift = u32::try_from(whole).unwrap_or(u32::MAX);
        let upper = 100_u64.checked_shr(shift).unwrap_or(0);
        let lower = upper.checked_div(2).unwrap_or(0);
        let within = upper
            .saturating_sub(lower)
            .saturating_mul(remainder)
            .checked_div(half_life)
            .unwrap_or(0);

        let value = upper.saturating_sub(within).min(100);
        // A clamp rather than an unwrap: this crate does not panic on arithmetic, and the value is
        // already bounded above, so the fallible conversion is unreachable and handled anyway.
        u8::try_from(value).unwrap_or(100).max(self.floor)
    }
}

impl Default for DecayProfile {
    fn default() -> Self {
        Self::half_life(90, 10)
    }
}

/// Everything an operator can change about how standing falls with age.
///
/// Every collection is ordered, so [`Self::digest`] depends on the configuration and not on
/// insertion order or hash seeding: two deployments configured the same way produce the same digest
/// and therefore the same figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecayPolicy {
    revision: u32,
    default_profile: DecayProfile,
    profiles: BTreeMap<String, DecayProfile>,
    anchors: Vec<DecayAnchor>,
    dormant_at_or_below: u8,
    future_dating: FutureDating,
}

impl DecayPolicy {
    /// The starting policy.
    ///
    /// Every number here is a default for an operator to change, and every one of them is visible
    /// in the assessment it produces. None of it is a finding about any source or any indicator.
    ///
    /// The per-kind half-lives say only how quickly each kind of artefact tends to stop being the
    /// thing that was observed: addresses are reassigned in weeks, domains are held for longer,
    /// autonomous system numbers change hands rarely, and a file digest never changes at all —
    /// which is why it is the one kind exempt by default.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            revision: 1,
            default_profile: DecayProfile::half_life(90, 10),
            profiles: BTreeMap::from([
                ("ipv4_address".to_owned(), DecayProfile::half_life(14, 5)),
                ("ipv6_address".to_owned(), DecayProfile::half_life(14, 5)),
                ("ip_range".to_owned(), DecayProfile::half_life(60, 10)),
                ("url".to_owned(), DecayProfile::half_life(30, 5)),
                ("domain_name".to_owned(), DecayProfile::half_life(45, 10)),
                ("email_address".to_owned(), DecayProfile::half_life(90, 10)),
                // A digest names a fixed sequence of bytes. Age says nothing about it.
                ("file_hash".to_owned(), DecayProfile::never()),
                (
                    "autonomous_system_number".to_owned(),
                    DecayProfile::half_life(365, 20),
                ),
                ("mutex_name".to_owned(), DecayProfile::half_life(365, 20)),
                ("registry_key".to_owned(), DecayProfile::half_life(365, 20)),
            ]),
            anchors: DecayAnchor::ALL.to_vec(),
            dormant_at_or_below: 25,
            future_dating: FutureDating::Rejected,
        }
    }

    /// Set the operator's revision label.
    ///
    /// Part of the digest, so bumping it alone forces a recalculation. That is deliberate: an
    /// operator who wants everything recomputed should not have to perturb a half-life to get it.
    #[must_use]
    pub fn with_revision(mut self, revision: u32) -> Self {
        self.revision = revision;
        self
    }

    /// Set the profile used for kinds with no profile of their own.
    #[must_use]
    pub fn with_default_profile(mut self, profile: DecayProfile) -> Self {
        self.default_profile = profile;
        self
    }

    /// Set one kind's profile, replacing any it already had.
    #[must_use]
    pub fn with_profile(mut self, kind: &str, profile: DecayProfile) -> Self {
        self.profiles.insert(kind.to_owned(), profile);
        self
    }

    /// Exempt one kind from decay entirely.
    #[must_use]
    pub fn with_never_decay(self, kind: &str) -> Self {
        self.with_profile(kind, DecayProfile::never())
    }

    /// Set the order in which a record's instants are tried as the age anchor.
    ///
    /// An empty order leaves the default in place rather than making every record undatable, which
    /// would turn a configuration slip into a silent loss of every decay figure in the deployment.
    #[must_use]
    pub fn with_anchors(mut self, anchors: Vec<DecayAnchor>) -> Self {
        if !anchors.is_empty() {
            self.anchors = anchors;
        }
        self
    }

    /// Set the standing at or below which a record is dormant.
    #[must_use]
    pub fn with_dormant_at_or_below(mut self, standing: u8) -> Self {
        self.dormant_at_or_below = standing.min(100);
        self
    }

    /// Decide whether a timestamp dated after the evaluation instant may be believed.
    #[must_use]
    pub fn with_future_dating(mut self, future_dating: FutureDating) -> Self {
        self.future_dating = future_dating;
        self
    }

    /// The operator's revision label.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// The order in which instants are tried as the age anchor.
    #[must_use]
    pub fn anchors(&self) -> &[DecayAnchor] {
        &self.anchors
    }

    /// The standing at or below which a record is dormant.
    #[must_use]
    pub const fn dormant_at_or_below(&self) -> u8 {
        self.dormant_at_or_below
    }

    /// Whether a future-dated anchor may be believed.
    #[must_use]
    pub const fn future_dating(&self) -> FutureDating {
        self.future_dating
    }

    /// The profile for a kind, falling back to the default where the kind has none.
    ///
    /// An unrecognised kind takes the default rather than being exempted. Exemption is a decision
    /// an operator makes in the open; it must not be what a typo buys.
    #[must_use]
    pub fn profile_for(&self, kind: Option<&str>) -> DecayProfile {
        kind.and_then(|kind| self.profiles.get(kind))
            .copied()
            .unwrap_or(self.default_profile)
    }

    /// The standing a record of the given kind retains at the given age.
    ///
    /// The single curve. [`crate::confidence::ConfidencePolicy::recency_score`] calls this rather
    /// than keeping a second opinion about what "old" means.
    #[must_use]
    pub fn standing_after(&self, kind: Option<&str>, age_in_days: u32) -> u8 {
        self.profile_for(kind).standing_after(age_in_days)
    }

    /// A digest of the whole configuration.
    ///
    /// Recorded on every assessment so a figure can be shown to have been computed under a
    /// configuration that no longer applies. Deterministic: fixed field order, and every collection
    /// iterated here is ordered.
    #[must_use]
    pub fn digest(&self) -> ContentHash {
        let mut material = format!(
            "brolga.decay.policy/1\nrevision={}\ndormant_at_or_below={}\nfuture_dating={}\ndefault={}\nprofiles=",
            self.revision,
            self.dormant_at_or_below,
            self.future_dating,
            rendered_profile(self.default_profile),
        );
        for (kind, profile) in &self.profiles {
            material.push_str(kind);
            material.push(':');
            material.push_str(&rendered_profile(*profile));
            material.push('\u{1f}');
        }
        material.push_str("\nanchors=");
        for anchor in &self.anchors {
            material.push_str(anchor.as_str());
            material.push(',');
        }
        ContentHash::of(material.as_bytes())
    }
}

impl Default for DecayPolicy {
    fn default() -> Self {
        Self::defaults()
    }
}

/// A profile, rendered for the policy digest.
fn rendered_profile(profile: DecayProfile) -> String {
    if profile.never_decays() {
        return "never".to_owned();
    }
    format!("{}d/floor{}", profile.half_life_days(), profile.floor())
}

/// Every instant a record carries, each keeping the source's own rendering.
///
/// The four questions are not interchangeable, exactly as
/// [`TemporalState`] says: creation, modification, and publication are about the *record*;
/// observation and the seen pair are about the *subject*; the validity window is about the
/// *assertion*. An indicator last seen a year ago may still be valid, and one seen this morning may
/// already have expired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordTimeline {
    /// When the source created the record.
    pub created: Option<SourceInstant>,
    /// When the source last changed the record.
    pub modified: Option<SourceInstant>,
    /// When the source published the record.
    pub published: Option<SourceInstant>,
    /// When the source states it observed the subject.
    pub observed: Option<SourceInstant>,
    /// The earliest observation recorded against the record.
    pub first_seen: Option<SourceInstant>,
    /// The most recent observation recorded against the record.
    pub last_seen: Option<SourceInstant>,
    /// The start of the window in which the assertion is held to apply.
    pub valid_from: Option<SourceInstant>,
    /// The end of that window.
    pub valid_until: Option<SourceInstant>,
}

impl RecordTimeline {
    /// A timeline that knows nothing.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            created: None,
            modified: None,
            published: None,
            observed: None,
            first_seen: None,
            last_seen: None,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Build from the model's [`TemporalState`].
    ///
    /// The source renderings are absent, because `TemporalState` is deliberately the lossy half of
    /// the model's pair and never carried them. A caller that still has the source's text should
    /// set the fields directly with [`SourceInstant::parse`] rather than going through here.
    #[must_use]
    pub fn from_temporal(temporal: &TemporalState) -> Self {
        Self {
            created: None,
            modified: None,
            published: None,
            observed: None,
            first_seen: temporal.first_seen.map(SourceInstant::canonical_only),
            last_seen: temporal.last_seen.map(SourceInstant::canonical_only),
            valid_from: temporal.valid_from.map(SourceInstant::canonical_only),
            valid_until: temporal.valid_until.map(SourceInstant::canonical_only),
        }
    }

    /// The model's view of this timeline, for the checks the model already owns.
    ///
    /// Round-tripped through the canonical values rather than reimplemented, so
    /// [`TemporalState::is_expired_at`] stays the one answer to "has the window closed?".
    #[must_use]
    pub fn temporal_state(&self) -> TemporalState {
        TemporalState {
            first_seen: self.first_seen.as_ref().map(SourceInstant::canonical),
            last_seen: self.last_seen.as_ref().map(SourceInstant::canonical),
            valid_from: self.valid_from.as_ref().map(SourceInstant::canonical),
            valid_until: self.valid_until.as_ref().map(SourceInstant::canonical),
        }
    }

    /// The instant one anchor names, where the record carries it.
    #[must_use]
    pub fn instant(&self, anchor: DecayAnchor) -> Option<&SourceInstant> {
        match anchor {
            DecayAnchor::Observed => self.observed.as_ref(),
            DecayAnchor::LastSeen => self.last_seen.as_ref(),
            DecayAnchor::Published => self.published.as_ref(),
            DecayAnchor::Modified => self.modified.as_ref(),
            DecayAnchor::Created => self.created.as_ref(),
            DecayAnchor::FirstSeen => self.first_seen.as_ref(),
        }
    }
}

/// What state a record's standing is in.
///
/// The reasons a record is not simply live are kept apart, for the same reason
/// [`LifecycleStatus`] keeps them apart: "was withdrawn", "ran out", "was replaced", and "has grown
/// old" are four different statements, and an analyst reading a lowered figure needs to know which
/// applies. Collapsing them into a number is how "we no longer believe this" turns into "this is
/// stale".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DecayState {
    /// No instant this policy will believe, so no age can be measured and no standing is asserted.
    ///
    /// **Not** the same as having decayed to nothing. This record was never dated; a dormant one
    /// was observed by somebody on a day they wrote down.
    Undated,
    /// Within its curve, above the dormancy threshold.
    Live,
    /// Aged past the dormancy threshold. Retained at its floor, never deleted and never zeroed.
    Dormant,
    /// Exempt from decay by policy, so age does not lower it.
    Exempt,
    /// The publisher withdrew the assertion. It was wrong, not merely old.
    Revoked,
    /// The asserted validity window has closed. The claim was right and is no longer current.
    Expired,
    /// A later record replaced this one. The subject is still described, by something else.
    Superseded,
}

impl DecayState {
    /// Every state this build knows.
    pub const ALL: [Self; 7] = [
        Self::Undated,
        Self::Live,
        Self::Dormant,
        Self::Exempt,
        Self::Revoked,
        Self::Expired,
        Self::Superseded,
    ];

    /// Whether the record still counts as current for ranking.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Live | Self::Exempt)
    }

    /// Whether anybody ever asserted this record at a measurable time.
    ///
    /// The distinction the floor exists to protect: `false` only for [`Self::Undated`].
    #[must_use]
    pub const fn is_dated(self) -> bool {
        !matches!(self, Self::Undated)
    }

    /// A stable label, written to the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undated => "undated",
            Self::Live => "live",
            Self::Dormant => "dormant",
            Self::Exempt => "exempt",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    /// Parse a label read back from the database.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "undated" => Some(Self::Undated),
            "live" => Some(Self::Live),
            "dormant" => Some(Self::Dormant),
            "exempt" => Some(Self::Exempt),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

impl core::fmt::Display for DecayState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything the evaluator needs about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecayInputs {
    /// What is being evaluated, as a stable rendering — normally a canonical record identifier.
    pub subject: String,
    /// The kind of subject, which selects the half-life profile. `None` takes the default.
    pub kind: Option<String>,
    /// Every instant the record carries.
    pub timeline: RecordTimeline,
    /// Whether the assertion still stands, as the record itself says.
    ///
    /// Read, never written. Decay does not move a record's lifecycle status; a status is something
    /// a publisher or an analyst asserts, and ageing is not either of them.
    pub status: LifecycleStatus,
    /// The instant to evaluate against. **Always supplied by the caller.**
    ///
    /// There is no clock read anywhere below this field. A figure that cannot be reproduced by
    /// naming the instant it was computed at cannot be replayed, diffed, or defended.
    pub now: Timestamp,
    /// What the source asserted about this record's confidence, where it asserted anything.
    pub asserted: Option<ConfidenceScore>,
    /// Whether this particular record is exempt from decay, whatever its kind's profile says.
    ///
    /// For the analyst decision "this one does not age" — a pinned indicator, a standing
    /// allow-list entry. Per-record rather than per-kind, and separate from the kind profile so an
    /// operator can tell which of the two exempted a given record.
    pub exempt: bool,
}

impl DecayInputs {
    /// Inputs that know nothing about a subject except its identifier and the evaluation instant.
    ///
    /// Every instant starts absent, so an assessment built from this reports
    /// [`DecayState::Undated`] rather than a confident zero.
    #[must_use]
    pub fn undated(subject: &str, now: Timestamp) -> Self {
        Self {
            subject: bounded(subject),
            kind: None,
            timeline: RecordTimeline::unknown(),
            status: LifecycleStatus::Active,
            now,
            asserted: None,
            exempt: false,
        }
    }
}

/// A decay figure with everything behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecayAssessment {
    /// What was evaluated.
    pub subject: String,
    /// The kind whose profile was used, where one was given.
    pub kind: Option<String>,
    /// What state the record's standing is in.
    pub state: DecayState,
    /// Which instant the age was measured from, where one was believed.
    pub anchor: Option<DecayAnchor>,
    /// That instant, canonicalised to UTC.
    pub anchored_at: Option<Timestamp>,
    /// Exactly what the source wrote for that instant, where it was retained.
    ///
    /// Kept because normalising to UTC discards the offset a source chose, and the offset is itself
    /// evidence about the source. Bounded and stripped of control characters, because it is
    /// rendered to operators.
    pub anchor_as_written: Option<String>,
    /// The age in whole days, where an age could be measured.
    pub age_in_days: Option<u32>,
    /// How much of the record's standing survives, in `0..=100`.
    ///
    /// `None` **only** for [`DecayState::Undated`]. Everything else is at or above
    /// [`Self::floor`], because a zero is what "never asserted" looks like once it is a number.
    pub standing: Option<u8>,
    /// The floor in force, below which the standing could not fall.
    pub floor: u8,
    /// The half-life in force, in whole days. `None` where the profile never decays.
    pub half_life_days: Option<u32>,
    /// What the source asserted. **Never rewritten by decay.**
    pub asserted: Option<ConfidenceScore>,
    /// The figure a prioritised queue should sort on.
    ///
    /// `None` where nothing was asserted or nothing could be measured — an omitted input, not a
    /// zero. Where the source asserted anything above nought, this stays above nought too: an aged
    /// record is weak evidence, not absent evidence.
    pub ranking_input: Option<ConfidenceScore>,
    /// Whether some instant on this record was dated after the evaluation instant.
    ///
    /// Recorded whether or not the policy believed it, because a source that dates its records in
    /// the future is a fact about the source that an operator should be able to find.
    pub future_dated: bool,
    /// Why the state and the standing are what they are, in authored words.
    ///
    /// `&'static str`, never interpolated from feed content.
    pub reason: &'static str,
    /// The measurement behind the figure — an age, an anchor, a half-life.
    ///
    /// Bounded and stripped of control characters, because it is rendered to operators.
    pub evidence: Option<String>,
    /// Which algorithm computed this.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// The policy revision in force.
    pub policy_revision: u32,
    /// The digest of the policy in force.
    pub policy_digest: ContentHash,
}

impl DecayAssessment {
    /// Whether this figure was computed under the given policy and this build's algorithm.
    #[must_use]
    pub fn is_current_under(&self, policy: &DecayPolicy) -> bool {
        self.algorithm == DECAY_ALGORITHM
            && self.algorithm_version == DECAY_ALGORITHM_VERSION
            && self.policy_digest == policy.digest()
    }

    /// Whether this figure must be recomputed before it can be compared with a fresh one.
    ///
    /// The other half of "configuration changes produce versioned recalculation": a stored figure
    /// carries the digest that produced it, so a half-life change makes every figure computed under
    /// the old curve visibly stale instead of silently incomparable.
    #[must_use]
    pub fn needs_recalculation(&self, policy: &DecayPolicy) -> bool {
        !self.is_current_under(policy)
    }

    /// Whether the source's figure survived the evaluation untouched.
    ///
    /// Always true. Exposed as an assertion a caller can make in its own tests rather than a
    /// property it has to take on trust from this module's documentation.
    #[must_use]
    pub fn source_figure_untouched(&self, inputs: &DecayInputs) -> bool {
        self.asserted == inputs.asserted
    }

    /// A full explanation, for an operator.
    ///
    /// Every line is authored text or a bounded measurement.
    #[must_use]
    pub fn explain(&self) -> String {
        let standing = self
            .standing
            .map_or_else(|| "no standing".to_owned(), |value| value.to_string());
        let mut lines = vec![format!(
            "{} = {standing} ({}) by {} v{} under policy revision {}",
            self.subject, self.state, self.algorithm, self.algorithm_version, self.policy_revision,
        )];

        if let (Some(anchor), Some(at)) = (self.anchor, self.anchored_at) {
            let written = self
                .anchor_as_written
                .as_ref()
                .map_or_else(String::new, |text| format!(" as written: {text}"));
            lines.push(format!("  anchor = {anchor} at {at}{written}"));
        }

        if let Some(evidence) = &self.evidence {
            lines.push(format!("  measured: {evidence}"));
        }

        if self.future_dated {
            lines.push(
                "  an instant on this record is dated after the evaluation time; whether such an \
                 instant was believed is the policy's decision, and the fact that a source wrote \
                 one is kept either way"
                    .to_owned(),
            );
        }

        lines.push(format!("  reason: {}", self.reason));

        if let (Some(asserted), Some(ranking)) = (self.asserted, self.ranking_input) {
            lines.push(format!(
                "  the source asserted {asserted}; ranking uses {ranking}, and the source's figure \
                 is unchanged"
            ));
        }

        lines.join("\n")
    }
}

/// A recorded change of decay state.
///
/// ADR 0004 §2 applied to the one thing about decay that is not a pure function of the present: a
/// record becoming dormant, or becoming live again, is an event, and an event that is only visible
/// as a number that moved is an event nobody can search for, alert on, or audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    /// The record whose state changed.
    pub subject: String,
    /// What it was.
    pub from: DecayState,
    /// What it became.
    pub to: DecayState,
    /// When the change was recorded — the caller's evaluation instant, never a clock read.
    pub at: Timestamp,
    /// Whether this is a record returning to life after having stopped being current.
    ///
    /// The issue's "reactivation produces a recorded state transition", made a queryable flag
    /// rather than something a reader has to infer by comparing two state labels.
    pub reactivation: bool,
    /// Why, in authored words.
    pub reason: &'static str,
    /// Which algorithm decided.
    pub algorithm: &'static str,
    /// That algorithm's version.
    pub algorithm_version: u32,
    /// The digest of the policy in force when it was decided.
    pub policy_digest: ContentHash,
}

impl StateTransition {
    /// A one-line explanation, for a queue a person reads.
    #[must_use]
    pub fn explain(&self) -> String {
        format!(
            "{}: {} -> {} at {} — {}",
            self.subject, self.from, self.to, self.at, self.reason
        )
    }
}

/// Computes decay figures under one policy.
///
/// Holds nothing but the policy. Every method is a pure function of its arguments, which is what
/// makes a stored figure replayable: given the inputs, the policy, and the algorithm version, the
/// same number comes back.
#[derive(Debug, Clone, Default)]
pub struct DecayEvaluator {
    policy: DecayPolicy,
}

impl DecayEvaluator {
    /// An evaluator under the starting policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An evaluator under an operator's policy.
    #[must_use]
    pub const fn with_policy(policy: DecayPolicy) -> Self {
        Self { policy }
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &DecayPolicy {
        &self.policy
    }

    /// Evaluate one record.
    ///
    /// Deterministic for fixed inputs: the anchor order is a `Vec` the policy fixes, the profile
    /// lookup is a `BTreeMap`, the arithmetic is integer, and `now` is an argument rather than a
    /// reading. Two runs a week apart with the same `now` give byte-identical assessments.
    #[must_use]
    pub fn evaluate(&self, inputs: &DecayInputs) -> DecayAssessment {
        let kind = inputs.kind.as_deref();
        let profile = if inputs.exempt {
            DecayProfile::never()
        } else {
            self.policy.profile_for(kind)
        };
        let anchored = self.anchor(&inputs.timeline, inputs.now);
        let future_dated = self.any_instant_in_future(&inputs.timeline, inputs.now);

        let (state, standing, reason) = self.decide(inputs, profile, anchored.as_ref());

        let evidence = anchored.as_ref().map(|anchored| {
            bounded(&format!(
                "{} days old, anchored on {}, {}",
                anchored.age_in_days,
                anchored.anchor,
                rendered_profile(profile),
            ))
        });

        DecayAssessment {
            subject: inputs.subject.clone(),
            kind: inputs.kind.clone(),
            state,
            anchor: anchored.as_ref().map(|anchored| anchored.anchor),
            anchored_at: anchored.as_ref().map(|anchored| anchored.at),
            anchor_as_written: anchored
                .as_ref()
                .and_then(|anchored| anchored.as_written.clone()),
            age_in_days: anchored.as_ref().map(|anchored| anchored.age_in_days),
            standing,
            floor: profile.floor(),
            half_life_days: if profile.never_decays() {
                None
            } else {
                Some(profile.half_life_days())
            },
            asserted: inputs.asserted,
            ranking_input: ranking_input(inputs.asserted, standing),
            future_dated,
            reason,
            evidence,
            algorithm: DECAY_ALGORITHM,
            algorithm_version: DECAY_ALGORITHM_VERSION,
            policy_revision: self.policy.revision,
            policy_digest: self.policy.digest(),
        }
    }

    /// The state, the standing, and the reason for all three.
    ///
    /// Ordered deliberately. Withdrawal is checked before expiry because "the publisher says this
    /// was wrong" is a stronger statement than "the window closed", and both are checked before the
    /// curve because a record that is not current should not be described as merely old. Exemption
    /// comes after all of them: a profile that says "age does not lower this" says nothing about a
    /// publisher withdrawing it.
    fn decide(
        &self,
        inputs: &DecayInputs,
        profile: DecayProfile,
        anchored: Option<&Anchored>,
    ) -> (DecayState, Option<u8>, &'static str) {
        if inputs.status == LifecycleStatus::Revoked {
            return (
                DecayState::Revoked,
                Some(profile.floor()),
                "the publisher withdrew this assertion; it was wrong rather than merely old, it is \
                 retained as history, and it is not the same state as having run out of validity",
            );
        }

        if inputs.status == LifecycleStatus::Superseded {
            return (
                DecayState::Superseded,
                Some(profile.floor()),
                "a later record replaced this one; the subject is still described, by something \
                 else, so this record's age is not what lowered it",
            );
        }

        if inputs.status == LifecycleStatus::Expired
            || inputs.timeline.temporal_state().is_expired_at(inputs.now)
        {
            return (
                DecayState::Expired,
                Some(profile.floor()),
                "the asserted validity window has closed; the claim was right and is no longer \
                 current, which is a different statement from the publisher withdrawing it",
            );
        }

        if profile.never_decays() {
            return (
                DecayState::Exempt,
                Some(100),
                "policy exempts this record from decay, so its age does not lower it; age is only \
                 evidence where the thing observed can stop being the thing observed",
            );
        }

        let Some(anchored) = anchored else {
            return (
                DecayState::Undated,
                None,
                "no instant on this record can be believed, so no age can be measured and no \
                 standing is asserted; this is not a decayed figure of nought, and a record nobody \
                 dated must stay distinguishable from one that has aged out",
            );
        };

        let standing = profile.standing_after(anchored.age_in_days);
        if standing <= self.policy.dormant_at_or_below {
            return (
                DecayState::Dormant,
                Some(standing),
                "the record has aged past the dormancy threshold; it is held at its floor rather \
                 than deleted or zeroed, because an indicator that has aged out is still an \
                 indicator somebody once observed",
            );
        }

        (
            DecayState::Live,
            Some(standing),
            "the record is within its decay curve: one half-life halves what remains of its \
             standing, and the standing never falls below the policy's floor",
        )
    }

    /// The first instant in the policy's anchor order that the policy will believe.
    ///
    /// A future-dated instant is skipped under [`FutureDating::Rejected`] rather than clamped to no
    /// age, because clamping is exactly the bypass the issue's security note names: a source that
    /// writes tomorrow's date would otherwise be handed maximum freshness for ever.
    fn anchor(&self, timeline: &RecordTimeline, now: Timestamp) -> Option<Anchored> {
        for anchor in &self.policy.anchors {
            let Some(instant) = timeline.instant(*anchor) else {
                continue;
            };
            let at = instant.canonical();
            if at > now && self.policy.future_dating == FutureDating::Rejected {
                continue;
            }
            return Some(Anchored {
                anchor: *anchor,
                at,
                as_written: instant.original().map(bounded),
                age_in_days: age_in_days(at, now),
            });
        }
        None
    }

    /// Whether any instant on the record is dated after the evaluation instant.
    fn any_instant_in_future(&self, timeline: &RecordTimeline, now: Timestamp) -> bool {
        DecayAnchor::ALL
            .iter()
            .filter_map(|anchor| timeline.instant(*anchor))
            .any(|instant| instant.canonical() > now)
    }
}

/// The instant the age was measured from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Anchored {
    anchor: DecayAnchor,
    at: Timestamp,
    as_written: Option<String>,
    age_in_days: u32,
}

/// Tracks each subject's decay state so a change of state can be recorded.
///
/// The evaluator is pure and therefore cannot notice that anything changed — it has no yesterday.
/// This does: it remembers the state each subject was last evaluated in and emits a
/// [`StateTransition`] when that state moves, which is what makes "reactivation produces a recorded
/// state transition" a record rather than a diff somebody has to compute.
///
/// Deterministic by construction: the states are a `BTreeMap` and the transitions are a `Vec` in
/// evaluation order, so replaying the same evaluations in the same order yields the same ledger.
#[derive(Debug, Clone, Default)]
pub struct DecayLedger {
    evaluator: DecayEvaluator,
    states: BTreeMap<String, DecayState>,
    transitions: Vec<StateTransition>,
}

impl DecayLedger {
    /// A ledger that has evaluated nothing, under the starting policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A ledger under an operator's policy.
    #[must_use]
    pub fn with_policy(policy: DecayPolicy) -> Self {
        Self {
            evaluator: DecayEvaluator::with_policy(policy),
            states: BTreeMap::new(),
            transitions: Vec::new(),
        }
    }

    /// Seed a subject's last known state, from storage.
    ///
    /// Without this, a restart would forget that a record was dormant and the reactivation that
    /// follows would be recorded as a first sighting. An audit trail that resets when the process
    /// does is not one.
    pub fn seed_state(&mut self, subject: &str, state: DecayState) {
        self.states.insert(bounded(subject), state);
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &DecayPolicy {
        self.evaluator.policy()
    }

    /// The state a subject was last evaluated in.
    #[must_use]
    pub fn state_of(&self, subject: &str) -> Option<DecayState> {
        self.states.get(subject).copied()
    }

    /// Every transition recorded, in evaluation order.
    #[must_use]
    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }

    /// Every transition that returned a record to life.
    #[must_use]
    pub fn reactivations(&self) -> Vec<&StateTransition> {
        self.transitions
            .iter()
            .filter(|transition| transition.reactivation)
            .collect()
    }

    /// Evaluate a record and record any change of state.
    ///
    /// The figure itself comes from the pure [`DecayEvaluator`]; the only thing this adds is the
    /// comparison against what was recorded before. The first evaluation of a subject establishes
    /// its state without emitting a transition, because a transition needs something to have moved
    /// from — use [`Self::seed_state`] when restoring known states from storage.
    pub fn evaluate(&mut self, inputs: &DecayInputs) -> DecayAssessment {
        let assessment = self.evaluator.evaluate(inputs);
        let previous = self
            .states
            .insert(assessment.subject.clone(), assessment.state);

        if let Some(previous) = previous
            && previous != assessment.state
        {
            self.transitions.push(StateTransition {
                subject: assessment.subject.clone(),
                from: previous,
                to: assessment.state,
                at: inputs.now,
                reactivation: !previous.is_live() && assessment.state.is_live(),
                reason: transition_reason(previous, assessment.state),
                algorithm: DECAY_ALGORITHM,
                algorithm_version: DECAY_ALGORITHM_VERSION,
                policy_digest: assessment.policy_digest,
            });
        }

        assessment
    }
}

/// Why a state changed, in authored words.
///
/// A table rather than an interpolation, so the reason attached to a stored transition is a string
/// this repository wrote and an operator can search for.
///
/// Deliberately without a wildcard arm. A new [`DecayState`] should fail to compile here rather
/// than quietly acquiring a generic explanation, because "the state changed" is not a reason.
const fn transition_reason(from: DecayState, to: DecayState) -> &'static str {
    match (from, to) {
        (DecayState::Dormant, DecayState::Live | DecayState::Exempt) => {
            "a record that had aged into dormancy is current again; the reactivation is recorded \
             rather than the standing quietly climbing back, because a figure that moves without \
             an event behind it is one nobody can account for"
        }
        (_, DecayState::Live | DecayState::Exempt) => {
            "a record that was not current is current again; the transition is recorded so that \
             nobody has to infer it from a number that changed"
        }
        (_, DecayState::Dormant) => {
            "the record's standing has fallen to the dormancy threshold; it is retained at its \
             floor rather than deleted or zeroed"
        }
        (_, DecayState::Revoked) => {
            "the publisher withdrew this assertion; it was wrong rather than merely old"
        }
        (_, DecayState::Expired) => {
            "the asserted validity window has closed; the claim was right and is no longer current"
        }
        (_, DecayState::Superseded) => {
            "a later record replaced this one; the subject is still described, by something else"
        }
        (_, DecayState::Undated) => {
            "no instant on this record can be believed any longer, so no age can be measured; this \
             is not the same as the record having aged out"
        }
    }
}

/// The figure a prioritised queue should sort on.
///
/// `None` where either half is missing, because an omitted input is not a zero — the same rule
/// [`crate::confidence`] applies to an unknown component. Where the source asserted anything above
/// nought, the result stays above nought: an aged record is weak evidence, and nought is what
/// "nobody asserted this" looks like once it is a number.
fn ranking_input(
    asserted: Option<ConfidenceScore>,
    standing: Option<u8>,
) -> Option<ConfidenceScore> {
    let asserted = asserted?;
    let standing = standing?;
    let scaled = u32::from(asserted.get())
        .saturating_mul(u32::from(standing))
        .checked_div(100)
        .unwrap_or(0);
    let floored = if asserted.get() > 0 { scaled.max(1) } else { 0 };
    // A clamp rather than an unwrap: this crate does not panic on arithmetic, the value is already
    // bounded above by `asserted`, so the fallible conversions are unreachable — and if a future
    // change makes one reachable, falling back to the source's own figure understates the decay
    // rather than crashing on it.
    let scaled = u8::try_from(floored.min(100)).unwrap_or(asserted.get());
    Some(ConfidenceScore::new(scaled).unwrap_or(asserted))
}

/// Whole days between an instant and the evaluation time.
///
/// Clamped at zero: an instant later than `now` has no age, and treating it as negative would make
/// the record fresher than one observed this morning. Whether such an instant is believed at all is
/// [`FutureDating`]'s decision, not this function's.
///
/// Shared with [`crate::confidence`] so there is one answer to "how old is this?" as well as one
/// answer to "how much does that cost it".
#[must_use]
pub fn age_in_days(from: Timestamp, now: Timestamp) -> u32 {
    let seconds = now
        .unix_timestamp()
        .saturating_sub(from.unix_timestamp())
        .max(0);
    let days = seconds.checked_div(SECONDS_PER_DAY).unwrap_or(0);
    u32::try_from(days).unwrap_or(u32::MAX)
}

/// Bound an excerpt and strip control characters.
///
/// Assessments and transitions are rendered to operators through terminals, and a measurement or a
/// source's own timestamp text carrying escape sequences must not reach one intact.
fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
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

    fn at(value: &str) -> Timestamp {
        Timestamp::parse_rfc3339(value).unwrap()
    }

    fn now() -> Timestamp {
        at("2026-07-29T00:00:00Z")
    }

    /// The curve has to actually halve. If it does not, "half-life" is a label on an arbitrary
    /// slope and an operator setting thirty days gets something else.
    #[test]
    fn one_half_life_halves_the_standing_and_two_quarter_it() {
        let profile = DecayProfile::half_life(30, 1);
        assert_eq!(profile.standing_after(0), 100);
        assert_eq!(profile.standing_after(30), 50);
        assert_eq!(profile.standing_after(60), 25);
        assert_eq!(profile.standing_after(90), 12);
    }

    /// The curve must never climb with age, or a record could get fresher by sitting still.
    #[test]
    fn the_curve_never_rises_as_a_record_ages() {
        let profile = DecayProfile::half_life(7, 1);
        let mut previous = 101_u8;
        for age in 0..400 {
            let standing = profile.standing_after(age);
            assert!(standing <= previous, "rose at {age} days");
            previous = standing;
        }
    }

    /// A floor of nought renders identically to "never asserted". The clamp is what keeps the two
    /// apart, and it must not be possible to configure it away.
    #[test]
    fn a_configured_floor_of_nought_is_raised_to_the_retention_floor() {
        let profile = DecayProfile::half_life(1, 0);
        assert_eq!(profile.floor(), DecayProfile::RETENTION_FLOOR);
        assert_eq!(
            profile.standing_after(u32::MAX),
            DecayProfile::RETENTION_FLOOR
        );
        assert!(profile.standing_after(100_000) > 0);
    }

    /// A half-life of nought days is a division by zero dressed as configuration.
    #[test]
    fn a_half_life_of_nought_days_is_raised_rather_than_dividing_by_zero() {
        let profile = DecayProfile::half_life(0, 10);
        assert_eq!(
            profile.half_life_days(),
            DecayProfile::MINIMUM_HALF_LIFE_DAYS
        );
        assert_eq!(profile.standing_after(0), 100);
        assert_eq!(profile.standing_after(1), 50);
    }

    /// Exemption must not be what a typo buys: an unrecognised kind takes the default profile.
    #[test]
    fn an_unrecognised_kind_decays_on_the_default_profile_rather_than_being_exempted() {
        let policy = DecayPolicy::defaults();
        assert!(!policy.profile_for(Some("not_a_kind")).never_decays());
        assert_eq!(
            policy.profile_for(Some("not_a_kind")),
            policy.profile_for(None)
        );
    }

    /// The policy is configuration, and configuration that cannot be identified cannot be shown to
    /// have changed.
    #[test]
    fn changing_any_part_of_the_policy_changes_its_digest() {
        let base = DecayPolicy::defaults();
        assert_eq!(base.digest(), DecayPolicy::defaults().digest());

        assert_ne!(base.digest(), base.clone().with_revision(2).digest());
        assert_ne!(
            base.digest(),
            base.clone()
                .with_profile("domain_name", DecayProfile::half_life(7, 10))
                .digest()
        );
        assert_ne!(
            base.digest(),
            base.clone().with_never_decay("domain_name").digest()
        );
        assert_ne!(
            base.digest(),
            base.clone().with_dormant_at_or_below(50).digest()
        );
        assert_ne!(
            base.digest(),
            base.clone()
                .with_future_dating(FutureDating::Accepted)
                .digest()
        );
        assert_ne!(
            base.digest(),
            base.clone()
                .with_anchors(vec![DecayAnchor::Created, DecayAnchor::LastSeen])
                .digest()
        );
    }

    /// Declaration order must not change the digest, or two identically configured deployments
    /// would look different.
    #[test]
    fn the_policy_digest_does_not_depend_on_the_order_profiles_were_declared() {
        let base = DecayPolicy::defaults();
        let one = base
            .clone()
            .with_profile("aaa", DecayProfile::half_life(3, 5))
            .with_profile("zzz", DecayProfile::half_life(9, 5));
        let other = base
            .with_profile("zzz", DecayProfile::half_life(9, 5))
            .with_profile("aaa", DecayProfile::half_life(3, 5));
        assert_eq!(one.digest(), other.digest());
    }

    /// An empty anchor order would make every record undatable, which turns a configuration slip
    /// into a silent loss of every decay figure in the deployment.
    #[test]
    fn an_empty_anchor_order_leaves_the_default_in_place() {
        let policy = DecayPolicy::defaults().with_anchors(Vec::new());
        assert_eq!(policy.anchors(), DecayAnchor::ALL);
    }

    /// Labels are written to the database, so they are a compatibility surface.
    #[test]
    fn every_state_and_anchor_label_round_trips_and_an_unknown_one_is_refused() {
        for state in DecayState::ALL {
            assert_eq!(DecayState::from_str_opt(state.as_str()), Some(state));
        }
        assert_eq!(DecayState::from_str_opt("probably_stale"), None);

        for anchor in DecayAnchor::ALL {
            assert_eq!(DecayAnchor::from_str_opt(anchor.as_str()), Some(anchor));
        }
        assert_eq!(DecayAnchor::from_str_opt("whenever"), None);
    }

    /// An instant later than the evaluation time has no age. Whether it is believed at all is the
    /// policy's decision; the arithmetic must not go negative either way.
    #[test]
    fn an_instant_after_the_evaluation_time_has_no_age() {
        assert_eq!(age_in_days(at("2030-01-01T00:00:00Z"), now()), 0);
        assert_eq!(age_in_days(at("2026-07-22T00:00:00Z"), now()), 7);
    }

    /// A record that was never asserted has no standing at all, and one that has aged out has a
    /// standing at its floor. Collapsing the two is what this module exists to prevent.
    #[test]
    fn an_undated_record_has_no_standing_and_an_aged_out_one_has_its_floor() {
        let evaluator = DecayEvaluator::new();

        let undated = evaluator.evaluate(&DecayInputs::undated("subject-1", now()));
        assert_eq!(undated.state, DecayState::Undated);
        assert_eq!(undated.standing, None);
        assert!(!undated.state.is_dated());

        let mut ancient = DecayInputs::undated("subject-2", now());
        ancient.timeline.last_seen =
            Some(SourceInstant::canonical_only(at("1990-01-01T00:00:00Z")));
        let ancient = evaluator.evaluate(&ancient);
        assert_eq!(ancient.state, DecayState::Dormant);
        assert_eq!(ancient.standing, Some(ancient.floor));
        assert!(ancient.standing.unwrap_or(0) > 0);
        assert!(ancient.state.is_dated());
    }

    /// Evaluating the same inputs twice must give the same answer down to the last field, or
    /// nothing downstream can cache, compare, or diff a figure.
    #[test]
    fn evaluating_the_same_inputs_twice_gives_an_identical_assessment() {
        let evaluator = DecayEvaluator::new();
        let mut inputs = DecayInputs::undated("subject-1", now());
        inputs.kind = Some("domain_name".to_owned());
        inputs.timeline.last_seen = Some(SourceInstant::canonical_only(at("2026-05-01T00:00:00Z")));
        inputs.asserted = ConfidenceScore::new(80).ok();

        assert_eq!(evaluator.evaluate(&inputs), evaluator.evaluate(&inputs));
    }
}
