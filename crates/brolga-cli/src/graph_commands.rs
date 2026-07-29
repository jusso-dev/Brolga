//! The commands that read the graph.
//!
//! Everything here already existed in `brolga-graph` before this module did. Deduplication,
//! resolution, contradiction, decay, traversal, and checkpoints all shipped across `v0.3.0` as
//! library code that no command reached — and a capability nobody can reach from a terminal is a
//! capability nobody can evaluate.
//!
//! # A budget is always stated, never assumed
//!
//! Every walk carries depth, node, edge, and fan-out budgets, and the result says **which one**
//! stopped it. A truncated neighbourhood looks exactly like a small one, so a command that quietly
//! returned the first two hundred records of a large neighbourhood would be answering a different
//! question from the one asked, and would look like it had answered the right one.

use std::io::Write;
use std::path::Path;

use brolga_graph::checkpoint::{CheckpointRequest, DeltaLimits, capture, compare};
use brolga_graph::{Checkpoint, TraversalLimits, TraversalRequest, traverse};
use brolga_model::{Entity, EntityKind, Id, LifecycleStatus, NodeRef, Timestamp};
use brolga_security::CancellationToken;
use brolga_storage::{
    CheckpointSummary, EntityQuery, IntelligenceStore, Page, SqliteStore, StorageError, StoreRead,
};

use crate::cli::{
    CheckpointDiffArgs, CheckpointRemoveArgs, CheckpointTakeArgs, NeighboursArgs, SearchArgs,
};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga search`.
pub(crate) fn search<Out: Write, Err: Write>(
    args: &SearchArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let mut query = EntityQuery::unfiltered();
    for name in &args.kinds {
        match parse_kind(name) {
            Some(kind) => {
                query = query.with_kind(kind);
            }
            None => {
                let _ = streams.problem(&format!(
                    "`{}` is not an entity kind; try one of: {}",
                    sanitise(name),
                    kind_names().join(", ")
                ));
                return ExitCode::Usage;
            }
        }
    }

    for name in &args.statuses {
        match parse_status(name) {
            Some(status) => {
                query = query.with_status(status);
            }
            None => {
                let _ = streams.problem(&format!(
                    "`{}` is not a lifecycle status; try one of: {}",
                    sanitise(name),
                    status_names().join(", ")
                ));
                return ExitCode::Usage;
            }
        }
    }

    let page = Page::new(args.limit, args.offset);

    let found = match store.search_entities(&query, page) {
        Ok(found) => found,
        Err(error) => return storage_failure(&error, streams),
    };

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let entries: Vec<serde_json::Value> = found
                .iter()
                .map(|entity| {
                    serde_json::json!({
                        "id": entity.id.to_string(),
                        "kind": entity.kind.as_str(),
                        "name": entity.name.as_str(),
                        "status": entity.status.as_str(),
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({ "entities": entries }));
            ExitCode::Success
        }
        OutputMode::Table => {
            let rows: Vec<Vec<String>> = found
                .iter()
                .map(|entity| {
                    vec![
                        entity.id.to_string(),
                        entity.kind.as_str().to_owned(),
                        entity.status.as_str().to_owned(),
                        entity.name.as_str().to_owned(),
                    ]
                })
                .collect();
            let _ = streams.result_table(&["ID", "KIND", "STATUS", "NAME"], &rows);
            ExitCode::Success
        }
        OutputMode::Human => {
            if found.is_empty() {
                let _ = streams.result_line("no entities matched");
                return ExitCode::Success;
            }
            for entity in &found {
                let _ = streams.result_line(&format!(
                    "{}  {:<18} {:<10} {}",
                    entity.id,
                    entity.kind.as_str(),
                    entity.status.as_str(),
                    entity.name.as_str()
                ));
            }
            ExitCode::Success
        }
    }
}

/// `brolga neighbours`.
pub(crate) fn neighbours<Out: Write, Err: Write>(
    args: &NeighboursArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let Some(start) = parse_node(&args.id) else {
        let _ = streams.problem(&format!(
            "`{}` is not a Brolga identifier; they look like `entity:<uuid>`",
            sanitise(&args.id)
        ));
        return ExitCode::Usage;
    };

    let limits = TraversalLimits::new(args.depth, args.max_nodes, args.max_edges, args.max_fan_out);
    let request = TraversalRequest::starting_at(start).with_limits(limits);

    let walked = match traverse(&store, request, &CancellationToken::never_cancelled()) {
        Ok(walked) => walked,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return ExitCode::Failure;
        }
    };

    // Every budget that fired, named. A caller that cannot tell a complete answer from a truncated
    // one will treat a truncated neighbourhood as a small one.
    let stopped: Vec<String> = walked
        .truncated
        .iter()
        .map(|reason| format!("{reason:?}").to_lowercase())
        .collect();

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let nodes: Vec<serde_json::Value> = walked
                .nodes
                .iter()
                .map(|reached| {
                    serde_json::json!({
                        "node": reached.node.to_string(),
                        "depth": reached.depth,
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({
                "start": args.id,
                "nodes": nodes,
                "edges": walked.edges.len(),
                "edges_examined": walked.edges_examined,
                "withheld_by_policy": walked.withheld_by_policy,
                "truncated_by": stopped,
                "complete": stopped.is_empty(),
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            for reached in &walked.nodes {
                let _ = streams.result_line(&format!("{:>2}  {}", reached.depth, reached.node));
            }
            let _ = streams.result_line(&format!(
                "{} record(s), {} edge(s)",
                walked.nodes.len(),
                walked.edges.len()
            ));
            if stopped.is_empty() {
                let _ = streams.note("the walk reached the whole neighbourhood");
            } else {
                // Not a note: an operator who misses this reads a partial answer as a complete one.
                let _ = streams.problem(&format!(
                    "truncated by {} — this is part of the neighbourhood, not all of it",
                    stopped.join(", ")
                ));
            }
            ExitCode::Success
        }
    }
}

/// `brolga checkpoint take`.
pub(crate) fn checkpoint_take<Out: Write, Err: Write>(
    args: &CheckpointTakeArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mut store = match open(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let Some(start) = parse_node(&args.from) else {
        let _ = streams.problem(&format!(
            "`{}` is not a Brolga identifier",
            sanitise(&args.from)
        ));
        return ExitCode::Usage;
    };

    let request = CheckpointRequest::over(
        TraversalRequest::starting_at(start)
            .with_limits(TraversalLimits::new(args.depth, 5_000, 20_000, 500)),
        now(),
    );

    let taken = match capture(&store, request, &CancellationToken::never_cancelled()) {
        Ok(taken) => taken,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return ExitCode::Failure;
        }
    };

    let summary = summary_of(&args.name, &taken);
    let Ok(document) = serde_json::to_value(&taken) else {
        let _ = streams.problem("the checkpoint could not be encoded");
        return ExitCode::Failure;
    };

    let created = match store.transaction(|write| write.put_checkpoint(&summary, &document)) {
        Ok(created) => created,
        Err(error) => return storage_failure(&error, streams),
    };

    // A baseline that did not reach the whole neighbourhood will report records as added when the
    // next capture reaches further. Said loudly, because it silently poisons every later delta.
    if !taken.is_complete() {
        let _ = streams.problem(
            "this baseline was truncated by a budget; deltas against it will report records as \
             added when a later capture reaches further",
        );
    }

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "name": args.name,
                "created": created,
                "records": taken.len(),
                "graph_version": taken.graph_version,
                "fingerprint": taken.fingerprint().to_string(),
                "complete": taken.is_complete(),
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            let _ = streams.result_line(&format!(
                "{} {} — {} record(s) at graph version {}",
                if created { "took" } else { "moved" },
                args.name,
                taken.len(),
                taken.graph_version
            ));
            ExitCode::Success
        }
    }
}

/// `brolga checkpoint list`.
pub(crate) fn checkpoint_list<Out: Write, Err: Write>(
    database: &Path,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open(database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let listed = match store.list_checkpoints() {
        Ok(listed) => listed,
        Err(error) => return storage_failure(&error, streams),
    };

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let entries: Vec<serde_json::Value> = listed
                .iter()
                .map(|summary| {
                    serde_json::json!({
                        "name": summary.name,
                        "graph_version": summary.graph_version,
                        "captured_at": summary.captured_at,
                        "algorithm_version": summary.algorithm_version,
                        "truncated": summary.truncated,
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({ "checkpoints": entries }));
            ExitCode::Success
        }
        OutputMode::Table => {
            let rows: Vec<Vec<String>> = listed
                .iter()
                .map(|summary| {
                    vec![
                        summary.name.clone(),
                        summary.graph_version.to_string(),
                        summary.captured_at.clone(),
                        if summary.truncated { "yes" } else { "no" }.to_owned(),
                    ]
                })
                .collect();
            let _ = streams.result_table(&["NAME", "GRAPH", "CAPTURED", "TRUNCATED"], &rows);
            ExitCode::Success
        }
        OutputMode::Human => {
            if listed.is_empty() {
                let _ = streams.result_line("no baselines stored");
                return ExitCode::Success;
            }
            for summary in &listed {
                let _ = streams.result_line(&format!(
                    "{:<24} graph v{:<8} {}{}",
                    summary.name,
                    summary.graph_version,
                    summary.captured_at,
                    if summary.truncated {
                        "  (truncated)"
                    } else {
                        ""
                    }
                ));
            }
            ExitCode::Success
        }
    }
}

/// `brolga checkpoint diff`.
pub(crate) fn checkpoint_diff<Out: Write, Err: Write>(
    args: &CheckpointDiffArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let before = match load(&store, &args.before, streams) {
        Ok(checkpoint) => checkpoint,
        Err(code) => return code,
    };
    let after = match load(&store, &args.after, streams) {
        Ok(checkpoint) => checkpoint,
        Err(code) => return code,
    };

    let delta = match compare(
        &before,
        &after,
        DeltaLimits::default(),
        &CancellationToken::never_cancelled(),
    ) {
        Ok(delta) => delta,
        Err(error) => {
            // A refusal is the point, not a failure to be worked around: comparing two differently
            // shaped baselines would report a mass deletion that never happened.
            let _ = streams.problem(&error.to_string());
            return ExitCode::Failure;
        }
    };

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let changes: Vec<serde_json::Value> = delta
                .changes
                .iter()
                .map(|change| {
                    serde_json::json!({
                        "record": change.key.to_string(),
                        "category": change.category.as_str(),
                        "reason": change.reason,
                        // Which facets moved, and what they were. "Changed" without this is not
                        // actionable: an operator cannot tell a re-attested source from a renamed
                        // actor, and those call for very different responses.
                        "facets": change
                            .facets
                            .iter()
                            .map(|facet| facet.as_str())
                            .collect::<Vec<_>>(),
                        "evidence": change
                            .evidence
                            .iter()
                            .map(|moved| {
                                serde_json::json!({
                                    "facet": moved.facet.as_str(),
                                    "before": moved.before,
                                    "after": moved.after,
                                })
                            })
                            .collect::<Vec<_>>(),
                        "successors": change
                            .successors
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({
                "before": args.before,
                "after": args.after,
                "changes": changes,
                "unchanged": delta.unchanged,
                "compared": delta.compared,
                "complete": delta.is_complete(),
                "attributable_to_version_change": delta.attributable_to_version_change(),
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            if delta.changes.is_empty() {
                let _ = streams.result_line(&format!(
                    "nothing material changed — {} record(s) compared",
                    delta.compared
                ));
                return ExitCode::Success;
            }
            for change in &delta.changes {
                let facets: Vec<&str> = change.facets.iter().map(|f| f.as_str()).collect();
                let _ = streams.result_line(&format!(
                    "{:<12} {}{}",
                    change.category.as_str(),
                    change.key,
                    if facets.is_empty() {
                        String::new()
                    } else {
                        // The facet is what makes the line actionable: a moved `sources` facet is a
                        // re-attestation, a moved `names` facet is somebody renaming an actor, and
                        // an operator responds to those very differently.
                        format!("  [{}]", facets.join(", "))
                    }
                ));
                for successor in &change.successors {
                    let _ = streams.result_line(&format!("             -> {successor}"));
                }
            }
            let _ = streams.result_line(&format!(
                "{} change(s), {} unchanged",
                delta.changes.len(),
                delta.unchanged
            ));
            if delta.attributable_to_version_change() {
                // Otherwise an upgrade reads as a wave of new intelligence.
                let _ = streams.problem(
                    "an algorithm or configuration version moved between these baselines; some of \
                     this is the upgrade rather than new intelligence",
                );
            }
            ExitCode::Success
        }
    }
}

/// `brolga checkpoint remove`.
pub(crate) fn checkpoint_remove<Out: Write, Err: Write>(
    args: &CheckpointRemoveArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mut store = match open(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    match store.transaction(|write| write.delete_checkpoint(&args.name)) {
        Ok(true) => {
            let _ = streams.result_line(&format!("removed {}", args.name));
            ExitCode::Success
        }
        Ok(false) => {
            let _ = streams.problem("no baseline under that name");
            ExitCode::Failure
        }
        Err(error) => storage_failure(&error, streams),
    }
}

/// Load a stored checkpoint by name.
fn load<Out: Write, Err: Write>(
    store: &SqliteStore,
    name: &str,
    streams: &mut Streams<Out, Err>,
) -> Result<Checkpoint, ExitCode> {
    let document = match store.get_checkpoint(name) {
        Ok(Some(document)) => document,
        Ok(None) => {
            let _ = streams.problem(&format!("no baseline named `{}`", sanitise(name)));
            return Err(ExitCode::Failure);
        }
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return Err(ExitCode::Storage);
        }
    };

    serde_json::from_value(document).map_err(|error| {
        let _ = streams.problem(&format!(
            "the stored baseline `{}` could not be decoded by this build: {error}",
            sanitise(name)
        ));
        ExitCode::Storage
    })
}

/// Everything storage needs to refuse an unusable baseline without decoding it.
fn summary_of(name: &str, taken: &Checkpoint) -> CheckpointSummary {
    CheckpointSummary {
        name: name.to_owned(),
        shape: taken.shape.to_string(),
        graph_version: taken.graph_version,
        algorithm: taken.algorithm.to_owned(),
        algorithm_version: taken.algorithm_version,
        captured_at: taken.captured_at.to_rfc3339(),
        truncated: !taken.is_complete(),
    }
}

/// Open and migrate a store.
fn open<Out: Write, Err: Write>(
    path: &Path,
    streams: &mut Streams<Out, Err>,
) -> Result<SqliteStore, ExitCode> {
    let mut store = SqliteStore::open(path, brolga_storage::sqlite::DEFAULT_BUSY_TIMEOUT_MS)
        .map_err(|error| {
            let _ = streams.problem(&format!("cannot open {}: {error}", path.display()));
            ExitCode::Storage
        })?;
    store.migrate().map_err(|error| {
        let _ = streams.problem(&format!("cannot migrate {}: {error}", path.display()));
        ExitCode::Storage
    })?;
    Ok(store)
}

/// Parse a node identifier from the command line.
fn parse_node(value: &str) -> Option<NodeRef> {
    let (kind, _) = value.split_once(':')?;
    match kind {
        "entity" => Some(NodeRef::Entity(Id::<Entity>::parse(value).ok()?)),
        _ => None,
    }
}

/// Every entity kind's name, for a diagnostic that says what *is* accepted.
fn kind_names() -> Vec<&'static str> {
    EntityKind::all().iter().map(|kind| kind.as_str()).collect()
}

/// Parse an entity kind, accepting the spelling `brolga search` prints.
fn parse_kind(value: &str) -> Option<EntityKind> {
    let wanted = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    EntityKind::all()
        .iter()
        .find(|kind| kind.as_str() == wanted)
        .copied()
}

/// Every lifecycle status's name.
fn status_names() -> Vec<&'static str> {
    LifecycleStatus::all()
        .iter()
        .map(|status| status.as_str())
        .collect()
}

/// Parse a lifecycle status.
fn parse_status(value: &str) -> Option<LifecycleStatus> {
    let wanted = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    LifecycleStatus::all()
        .iter()
        .find(|status| status.as_str() == wanted)
        .copied()
}

/// The current instant.
fn now() -> Timestamp {
    Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc())
}

/// Report a storage failure consistently.
fn storage_failure<Out: Write, Err: Write>(
    error: &StorageError,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let _ = streams.problem(&error.to_string());
    ExitCode::Storage
}

/// Strip control characters from a value echoed back in a diagnostic.
fn sanitise(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect()
}
