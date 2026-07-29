//! Append-only audit events: who asked for what, and what happened.
//!
//! # Fail-closed on the decisions that matter, fail-open on the rest
//!
//! An audit record that cannot be written leaves a gap, and a gap in an audit log is
//! indistinguishable from nothing having happened. So [`AuditEvent::is_security_relevant`] splits
//! the events into two:
//!
//! - **Security-relevant** — a policy denial, an expansion of source material, a credential
//!   failure. If one of these cannot be written, the operation it describes **must not proceed**.
//!   Serving material whose disclosure could not be recorded is how a breach becomes unprovable.
//! - **Everything else** — a routine read, a stats query. If one cannot be written, the operation
//!   proceeds and the failure is surfaced. Refusing to answer a stats query because a disk is full
//!   converts a monitoring problem into an outage.
//!
//! [`FailurePolicy`] makes that split the caller's to apply, and names it, so an operator reading a
//! deployment can see which way it falls rather than inferring it from behaviour under failure —
//! which is the worst possible time to learn it.
//!
//! # Nothing an event carries can be a disclosure
//!
//! An audit log is read by more people than the data it describes, kept longer, and shipped to
//! systems with different access rules. So an event records **hashes and identifiers, never
//! content**: the subject is a canonical identifier, the source is a content address, and the
//! outcome is a code.
//!
//! [`AuditEvent::new`] cannot be given a body, and no field is free text a caller controls. That is
//! deliberate — an audit type that accepted a `details: String` would collect source content within
//! a release, because somebody would reasonably put the useful thing there.
//!
//! # Cardinality is bounded
//!
//! Metric labels come from a closed vocabulary. A label derived from a subject value would give a
//! metrics backend one time series per observable, which is how a monitoring system falls over
//! because somebody ingested a feed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The largest number of distinct values a metric label may take.
///
/// Enforced rather than documented. A label that can take an unbounded number of values is a
/// denial-of-service against the monitoring system, delivered by ordinary use.
pub const MAX_LABEL_CARDINALITY: usize = 64;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// A context pack was produced.
    ContextRead,
    /// A handle was expanded to a canonical record.
    ExpandCanonical,
    /// A handle was expanded to original source bytes.
    ExpandSource,
    /// Records were ingested.
    Ingest,
    /// An upstream connector fetched.
    Fetch,
    /// A policy rule refused something.
    PolicyDenied,
    /// A credential was rejected.
    AuthenticationFailed,
    /// Configuration changed.
    ConfigurationChanged,
}

impl AuditAction {
    /// Every action.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::ContextRead,
            Self::ExpandCanonical,
            Self::ExpandSource,
            Self::Ingest,
            Self::Fetch,
            Self::PolicyDenied,
            Self::AuthenticationFailed,
            Self::ConfigurationChanged,
        ]
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextRead => "context_read",
            Self::ExpandCanonical => "expand_canonical",
            Self::ExpandSource => "expand_source",
            Self::Ingest => "ingest",
            Self::Fetch => "fetch",
            Self::PolicyDenied => "policy_denied",
            Self::AuthenticationFailed => "authentication_failed",
            Self::ConfigurationChanged => "configuration_changed",
        }
    }

    /// Whether losing this event's record would matter.
    ///
    /// True for anything that discloses material or refuses to. Serving source bytes whose
    /// disclosure could not be recorded is how a breach becomes unprovable; failing to record a
    /// stats query is a monitoring problem.
    #[must_use]
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ExpandCanonical
                | Self::ExpandSource
                | Self::PolicyDenied
                | Self::AuthenticationFailed
                | Self::ConfigurationChanged
        )
    }
}

impl core::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Outcome {
    /// It succeeded.
    Allowed,
    /// Policy refused it.
    Denied,
    /// It failed for a reason that is not policy.
    Failed,
}

impl Outcome {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// What to do when an audit record cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FailurePolicy {
    /// Refuse the operation. The default for security-relevant events.
    Closed,
    /// Proceed, and surface the failure.
    Open,
}

impl FailurePolicy {
    /// The policy for an action, under Brolga's documented default.
    ///
    /// Named as a function rather than left to each call site, so "which way does this fall?" has
    /// one answer that a reader can check — instead of being a property of whichever branch
    /// happened to be taken.
    #[must_use]
    pub const fn for_action(action: AuditAction) -> Self {
        if action.is_security_relevant() {
            Self::Closed
        } else {
            Self::Open
        }
    }

    /// Whether an operation may proceed when its audit write failed.
    #[must_use]
    pub const fn permits_proceeding(self) -> bool {
        matches!(self, Self::Open)
    }
}

/// One thing that happened, recorded without recording what it was about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// When, as RFC 3339.
    pub at: String,
    /// The request this belongs to.
    pub request_id: String,
    /// Who asked. A policy identity name, never a credential.
    pub actor: String,
    /// What they did.
    pub action: AuditAction,
    /// How it went.
    pub outcome: Outcome,
    /// What it was about, as a canonical identifier or content address.
    ///
    /// An identifier, never a value. A canonical observable id is a digest — recording it lets an
    /// investigator correlate without the log itself disclosing which address was looked up.
    pub resource: String,
    /// The policy rule that decided, where one did.
    ///
    /// A rule *kind* from a closed vocabulary, not a message. A message would eventually carry the
    /// thing it refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// The schema version in force.
    pub schema_version: String,
    /// The Brolga build.
    pub brolga_version: String,
    /// The graph version at the time.
    pub graph_version: u64,
}

impl AuditEvent {
    /// Record an event.
    ///
    /// There is no parameter for a body, a message, or a value. An audit type that accepted one
    /// would collect source content inside a release, because somebody would reasonably put the
    /// useful thing there.
    #[must_use]
    pub fn new(
        at: impl Into<String>,
        request_id: impl Into<String>,
        actor: impl Into<String>,
        action: AuditAction,
        outcome: Outcome,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            at: at.into(),
            request_id: request_id.into(),
            actor: actor.into(),
            action,
            outcome,
            resource: resource.into(),
            policy_rule: None,
            schema_version: String::new(),
            brolga_version: String::new(),
            graph_version: 0,
        }
    }

    /// Name the policy rule that decided.
    #[must_use]
    pub fn by_rule(mut self, rule: impl Into<String>) -> Self {
        self.policy_rule = Some(rule.into());
        self
    }

    /// Record the versions in force.
    #[must_use]
    pub fn with_versions(
        mut self,
        schema_version: impl Into<String>,
        brolga_version: impl Into<String>,
        graph_version: u64,
    ) -> Self {
        self.schema_version = schema_version.into();
        self.brolga_version = brolga_version.into();
        self.graph_version = graph_version;
        self
    }

    /// Whether losing this record would matter.
    #[must_use]
    pub const fn is_security_relevant(&self) -> bool {
        self.action.is_security_relevant()
    }

    /// The failure policy for this event.
    #[must_use]
    pub const fn failure_policy(&self) -> FailurePolicy {
        FailurePolicy::for_action(self.action)
    }

    /// Whether every required field is populated.
    ///
    /// An event missing its actor or its versions is one nobody can reconstruct a decision from,
    /// and is worse than no event because it looks like a record.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.at.is_empty()
            && !self.request_id.is_empty()
            && !self.actor.is_empty()
            && !self.resource.is_empty()
            && !self.schema_version.is_empty()
            && !self.brolga_version.is_empty()
    }
}

/// A metric label whose values are bounded.
///
/// A label derived from a subject value would give a metrics backend one time series per
/// observable, which is how a monitoring system falls over because somebody ingested a feed. This
/// counts distinct values and refuses past [`MAX_LABEL_CARDINALITY`], so the failure is a rejected
/// label rather than a dead dashboard.
#[derive(Debug, Clone, Default)]
pub struct BoundedLabels {
    seen: BTreeMap<String, BTreeMap<String, u64>>,
}

impl BoundedLabels {
    /// A fresh counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a label value, returning whether it was accepted.
    ///
    /// A rejected value is not an error to propagate — the operation being measured is fine. It is
    /// a signal that somebody is labelling by something unbounded, and the metric stops growing
    /// rather than the process stopping.
    pub fn observe(&mut self, label: &str, value: &str) -> bool {
        let values = self.seen.entry(label.to_owned()).or_default();

        if let Some(count) = values.get_mut(value) {
            *count = count.saturating_add(1);
            return true;
        }
        if values.len() >= MAX_LABEL_CARDINALITY {
            return false;
        }
        values.insert(value.to_owned(), 1);
        true
    }

    /// How many distinct values a label has taken.
    #[must_use]
    pub fn cardinality(&self, label: &str) -> usize {
        self.seen.get(label).map_or(0, BTreeMap::len)
    }

    /// Whether a label has reached its ceiling.
    #[must_use]
    pub fn is_saturated(&self, label: &str) -> bool {
        self.cardinality(label) >= MAX_LABEL_CARDINALITY
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

    fn event(action: AuditAction) -> AuditEvent {
        AuditEvent::new(
            "2024-01-01T00:00:00Z",
            "req-1",
            "analyst",
            action,
            Outcome::Allowed,
            "observable:abc",
        )
        .with_versions("brolga.context_pack/1.1", "0.1.0", 7)
    }

    /// **The criterion.** An event missing its actor or versions is one nobody can reconstruct a
    /// decision from, and is worse than no event because it looks like a record.
    #[test]
    fn an_event_carries_every_required_field() {
        let complete = event(AuditAction::ContextRead);
        assert!(complete.is_complete());

        let json = serde_json::to_value(&complete).unwrap();
        for field in [
            "at",
            "request_id",
            "actor",
            "action",
            "outcome",
            "resource",
            "schema_version",
            "brolga_version",
            "graph_version",
        ] {
            assert!(json.get(field).is_some(), "`{field}` is missing");
        }

        let mut missing = complete;
        missing.actor = String::new();
        assert!(!missing.is_complete());
    }

    /// **The criterion.** An audit log is read by more people than the data it describes, kept
    /// longer, and shipped elsewhere. An event that accepted a body would collect source content
    /// inside a release, because somebody would reasonably put the useful thing there.
    #[test]
    fn an_event_has_no_field_that_could_carry_content() {
        let json = serde_json::to_value(event(AuditAction::ExpandSource)).unwrap();
        let object = json.as_object().unwrap();

        for forbidden in [
            "body",
            "content",
            "details",
            "message",
            "value",
            "payload",
            "secret",
            "token",
            "credential",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "`{forbidden}` would let an audit log collect what it is auditing"
            );
        }

        // And the whole field set is the one this test knows about, so adding one is a decision.
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "action",
                "actor",
                "at",
                "brolga_version",
                "graph_version",
                "outcome",
                "request_id",
                "resource",
                "schema_version"
            ]
        );
    }

    /// **The criterion.** Which way a failure falls must be readable from the code, not learned
    /// from behaviour under failure — the worst possible time to learn it.
    #[test]
    fn the_failure_policy_is_closed_for_disclosures_and_open_for_routine_reads() {
        for action in [
            AuditAction::ExpandCanonical,
            AuditAction::ExpandSource,
            AuditAction::PolicyDenied,
            AuditAction::AuthenticationFailed,
            AuditAction::ConfigurationChanged,
        ] {
            assert!(action.is_security_relevant(), "{action}");
            assert_eq!(FailurePolicy::for_action(action), FailurePolicy::Closed);
            assert!(
                !FailurePolicy::for_action(action).permits_proceeding(),
                "{action} must not proceed unrecorded"
            );
        }

        for action in [
            AuditAction::ContextRead,
            AuditAction::Ingest,
            AuditAction::Fetch,
        ] {
            assert!(!action.is_security_relevant(), "{action}");
            assert!(
                FailurePolicy::for_action(action).permits_proceeding(),
                "{action} must not become an outage because a disk filled"
            );
        }
    }

    /// Expanding to source material is the case the fail-closed rule exists for: serving bytes
    /// whose disclosure could not be recorded is how a breach becomes unprovable.
    #[test]
    fn an_unrecorded_source_expansion_may_not_proceed() {
        let expansion = event(AuditAction::ExpandSource);
        assert!(expansion.is_security_relevant());
        assert!(!expansion.failure_policy().permits_proceeding());
    }

    /// **The criterion.** A label derived from a subject value gives a metrics backend one series
    /// per observable, which is how a monitoring system falls over because somebody ingested a
    /// feed.
    #[test]
    fn label_cardinality_is_bounded_and_the_metric_stops_rather_than_the_process() {
        let mut labels = BoundedLabels::new();

        for index in 0..MAX_LABEL_CARDINALITY {
            assert!(
                labels.observe("subject", &format!("observable-{index}")),
                "value {index} was rejected early"
            );
        }
        assert!(labels.is_saturated("subject"));

        // The next distinct value is refused...
        assert!(!labels.observe("subject", "one-too-many"));
        assert_eq!(labels.cardinality("subject"), MAX_LABEL_CARDINALITY);

        // ...but a value already seen still counts, so an existing series keeps working.
        assert!(labels.observe("subject", "observable-0"));

        // And a different label has its own budget.
        assert!(labels.observe("action", "context_read"));
        assert_eq!(labels.cardinality("action"), 1);
    }

    /// A closed vocabulary is what keeps action and outcome labels bounded by construction.
    #[test]
    fn action_and_outcome_labels_are_bounded_by_construction() {
        let mut labels = BoundedLabels::new();
        for action in AuditAction::all() {
            assert!(labels.observe("action", action.as_str()));
        }
        assert!(
            labels.cardinality("action") < MAX_LABEL_CARDINALITY,
            "the whole vocabulary must fit inside one label's budget"
        );

        for outcome in [Outcome::Allowed, Outcome::Denied, Outcome::Failed] {
            assert!(labels.observe("outcome", outcome.as_str()));
        }
        assert_eq!(labels.cardinality("outcome"), 3);
    }

    /// A denial records which rule refused, as a kind rather than a message — a message would
    /// eventually carry the thing it refused.
    #[test]
    fn a_denial_records_the_rule_kind_rather_than_a_message() {
        let denial = event(AuditAction::PolicyDenied).by_rule("tlp_above_ceiling");
        assert_eq!(denial.policy_rule.as_deref(), Some("tlp_above_ceiling"));

        let rendered = serde_json::to_string(&denial).unwrap();
        assert!(!rendered.contains("withheld"), "{rendered}");
        assert!(!rendered.contains("203.0.113"), "{rendered}");
    }

    #[test]
    fn an_event_round_trips_and_refuses_unknown_fields() {
        let original = event(AuditAction::ContextRead);
        let json = serde_json::to_string(&original).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);

        assert!(
            serde_json::from_str::<AuditEvent>(
                r#"{"at":"t","request_id":"r","actor":"a","action":"ingest","outcome":"allowed",
                    "resource":"x","schema_version":"s","brolga_version":"b","graph_version":0,
                    "body":"leaked"}"#
            )
            .is_err(),
            "an event must not accept a field that could carry content"
        );
    }

    #[test]
    fn every_action_appears_in_all_and_has_a_distinct_name() {
        let mut names: Vec<&str> = AuditAction::all().iter().map(|a| a.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);

        for action in AuditAction::all() {
            match action {
                AuditAction::ContextRead
                | AuditAction::ExpandCanonical
                | AuditAction::ExpandSource
                | AuditAction::Ingest
                | AuditAction::Fetch
                | AuditAction::PolicyDenied
                | AuditAction::AuthenticationFailed
                | AuditAction::ConfigurationChanged => {}
            }
        }
    }
}
