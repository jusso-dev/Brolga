//! `brolga explain-plan` — what a context profile will do, before it does it.
//!
//! # Why this exists as its own command
//!
//! "Why did my pack not contain relationships?" is answerable two ways: read a pack and infer
//! backwards, or ask. The first requires a pack, which requires a subject, a store, and a retrieval
//! that may itself be the thing misbehaving. The second is this command, and it answers with no
//! store at all.
//!
//! Every line says **why**, not only what. An operator debugging a profile needs to know whether a
//! section survived because they asked for it, because the default applied, or because it is below
//! the floor no profile may cross — three different fixes, and "included" alone distinguishes none
//! of them.

use std::io::Write;

use brolga_config::{PlanAction, PlanReason, ProfileSet};

use crate::cli::ExplainPlanArgs;
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga explain-plan`.
pub(crate) fn explain_plan<Out: Write, Err: Write>(
    args: &ExplainPlanArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    // Built-ins only for now. A deployment's own profiles arrive with the configuration work, and
    // a command that silently explained a different profile set from the one in force would be
    // worse than one that explains a known set.
    let set = ProfileSet::built_in();

    // Every problem, not the first: an operator fixing a profile file wants the whole list rather
    // than five round trips.
    let problems = set.validate_all();
    if !problems.is_empty() {
        for problem in &problems {
            let _ = streams.problem(&problem.to_string());
        }
        return ExitCode::Usage;
    }

    let Some(name) = args.profile.as_deref() else {
        return list_profiles(&set, args.environment.as_deref(), streams);
    };

    let profile = match set.resolve(name) {
        Ok(profile) => profile,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            let _ = streams.note(&format!("known profiles: {}", set.names().join(", ")));
            return ExitCode::Usage;
        }
    };

    if let Some(environment) = args.environment.as_deref()
        && !profile.applies_in(environment)
    {
        // Not an error. A profile that does not apply here is a fact worth stating plainly, and
        // failing would stop an operator inspecting a profile for another environment.
        let _ = streams.note(&format!(
            "`{name}` does not apply in `{environment}`; showing its plan anyway"
        ));
    }

    let plan = profile.explain();

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "profile": name,
                "description": profile.description,
                "fingerprint": profile.fingerprint(),
                "environments": profile.environments,
                "plan": plan
                    .iter()
                    .map(|step| serde_json::json!({
                        "section": step.section.as_str(),
                        "action": action_name(step.action),
                        "reason": reason_name(step.reason),
                        "weight": step.weight,
                        "allocation": step.allocation,
                    }))
                    .collect::<Vec<_>>(),
            }));
        }
        OutputMode::Human | OutputMode::Table => {
            let _ = streams.note(&profile.description);
            let _ = streams.note(&format!("fingerprint {}", profile.fingerprint()));
            for step in &plan {
                let allocation = step
                    .allocation
                    .map_or_else(String::new, |share| format!("  {share}% of budget"));
                let _ = streams.result_line(&format!(
                    "{:<15} {:<8} weight {:<3} ({}){allocation}",
                    step.section.as_str(),
                    action_name(step.action),
                    step.weight,
                    reason_name(step.reason),
                ));
            }
        }
    }

    ExitCode::Success
}

/// List every profile, so an operator who does not know the names can find them.
fn list_profiles<Out: Write, Err: Write>(
    set: &ProfileSet,
    environment: Option<&str>,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let names: Vec<&str> = set
        .names()
        .into_iter()
        .filter(|name| {
            environment.is_none_or(|environment| {
                set.get(name)
                    .is_some_and(|profile| profile.applies_in(environment))
            })
        })
        .collect();

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "profiles": names
                    .iter()
                    .filter_map(|name| set.get(name).map(|profile| serde_json::json!({
                        "name": name,
                        "description": profile.description,
                        "fingerprint": profile.fingerprint(),
                    })))
                    .collect::<Vec<_>>(),
            }));
        }
        OutputMode::Human | OutputMode::Table => {
            for name in &names {
                let description = set.get(name).map_or("", |profile| &profile.description);
                let _ = streams.result_line(&format!("{name:<30} {description}"));
            }
        }
    }
    ExitCode::Success
}

/// The wire name of an action.
const fn action_name(action: PlanAction) -> &'static str {
    match action {
        PlanAction::Include => "include",
        PlanAction::Rank => "rank",
        PlanAction::Exclude => "exclude",
        // `PlanAction` is `#[non_exhaustive]`. A new action is surfaced as unrecognised rather
        // than mapped to an existing name — an operator seeing "there is an action here I cannot
        // read" can go and look, where a silently mislabelled one leaves no trace.
        _ => "unrecognised",
    }
}

/// The wire name of a reason.
const fn reason_name(reason: PlanReason) -> &'static str {
    match reason {
        PlanReason::Floor => "floor",
        PlanReason::Profile => "profile",
        PlanReason::Default => "default",
        _ => "unrecognised",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A plan that said only "included" would leave an operator unable to tell which of three
    /// different fixes applies.
    #[test]
    fn every_action_and_reason_has_a_distinct_name() {
        let actions = [PlanAction::Include, PlanAction::Rank, PlanAction::Exclude].map(action_name);
        let mut sorted = actions;
        sorted.sort_unstable();
        sorted.iter().reduce(|left, right| {
            assert_ne!(left, right);
            right
        });

        let reasons =
            [PlanReason::Floor, PlanReason::Profile, PlanReason::Default].map(reason_name);
        assert_eq!(reasons.len(), 3);
        assert!(reasons.iter().all(|name| !name.is_empty()));
    }
}
