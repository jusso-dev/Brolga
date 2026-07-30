//! `brolga context` — what Brolga knows about one observable.
//!
//! # The same pack the API serves
//!
//! Assembly lives in `brolga_graph::assemble`, and this command calls it. A CLI that built its own
//! pack would eventually disagree with the HTTP one, and the disagreement would surface in front of
//! an analyst comparing a terminal to a case file.
//!
//! # A local operator, stated rather than assumed
//!
//! Somebody running this command holds the database file, so withholding TLP:RED from them would be
//! theatre. The access is granted through `PolicyIdentity::local_operator` — a named identity that
//! appears in the pack's `policy.recipient` — rather than by skipping the policy check, so the
//! decision is visible in the output and the code path is the same one the server uses.

use std::io::Write;

use brolga_config::PolicyIdentity;
use brolga_graph::assemble::{AssemblyRequest, Gathered};
use brolga_graph::subject;
use brolga_model::pack::DetailLevel;
use brolga_model::{NodeRef, Timestamp};
use brolga_storage::store::{Direction, EdgeQuery, Page};
use brolga_storage::{OpenedStore, StoreRead};

use crate::cli::ContextArgs;
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};
use crate::store_commands::open_store;

/// `brolga context`.
pub(crate) fn context<Out: Write, Err: Write>(
    args: &ContextArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let observable = match subject::resolve(&args.kind, &args.value) {
        Ok(observable) => observable,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return ExitCode::Usage;
        }
    };

    let Some(detail_level) = parse_level(&args.detail_level) else {
        let _ = streams.problem(&format!(
            "`{}` is not a detail level. L0 through L3 are served as packs; L4 and L5 are reached \
             by expanding a handle",
            args.detail_level
        ));
        return ExitCode::Usage;
    };

    let mut store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let gathered = match gather(&mut store, &observable, args) {
        Ok(gathered) => gathered,
        Err(message) => {
            let _ = streams.problem(&message);
            return ExitCode::Storage;
        }
    };

    let graph_version = store.graph_version().unwrap_or(0);

    let request = AssemblyRequest {
        observable,
        detail_level,
        purpose: args.purpose.clone(),
        // Stated, not assumed. See the module documentation.
        identity: PolicyIdentity::local_operator(),
        max_objects: args.max_objects,
        max_relationships: args.max_relationships,
        now: Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc()),
        graph_version,
        request_id: None,
    };

    let pack = match brolga_graph::assemble::build(&request, &gathered) {
        Ok(pack) => pack,
        Err(reason) => {
            // A pack that fails its own validation is a bug in Brolga, not in the request. Serving
            // the half-built one would publish exactly what validation exists to prevent.
            let _ = streams.problem(&format!("could not assemble a context pack: {reason}"));
            return ExitCode::Failure;
        }
    };

    // `--format` writes the pack in an export format instead of printing it. The policy decision is
    // made inside the export, after the format is known — see `brolga_export` for why that ordering is
    // the only one that distinguishes reading your own pack from handing it to somebody else.
    if let Some(format) = args.format.as_deref() {
        let registry = brolga_export::ExporterRegistry::shipped();
        return match registry.export(format, &pack, &PolicyIdentity::local_operator()) {
            Ok(exported) => {
                // Bytes to stdout, unchanged. An export is somebody else's input, so nothing is
                // appended, wrapped, or re-encoded.
                if streams.write_result_bytes(&exported.bytes).is_err() {
                    return ExitCode::Io;
                }
                // What it cost goes to stderr, so a shell redirect captures the artefact and the
                // operator still learns what is missing from it.
                for loss in &exported.declared_losses {
                    let _ = streams.note(&format!("not carried by `{format}`: {loss}"));
                }
                ExitCode::Success
            }
            Err(error) => {
                let _ = streams.problem(&error.to_string());
                match error {
                    brolga_export::ExportError::UnknownFormat { .. } => ExitCode::Usage,
                    brolga_export::ExportError::Denied { .. } => ExitCode::PolicyDenied,
                    brolga_export::ExportError::Unencodable { .. } => ExitCode::Failure,
                    _ => ExitCode::Failure,
                }
            }
        };
    }

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::to_value(&pack).unwrap_or_default());
        }
        OutputMode::Human | OutputMode::Table => {
            let _ = streams.result_line(&format!(
                "{} {}  —  {}",
                pack.subject.kind.as_str(),
                pack.subject.value.as_str(),
                pack.disposition
            ));
            for finding in &pack.findings {
                let _ = streams.result_line(&format!(
                    "  {}  ({} source{})",
                    finding.statement.as_str(),
                    finding.evidence.len(),
                    if finding.evidence.len() == 1 { "" } else { "s" }
                ));
            }
            for claim in &pack.graph.claims {
                let _ = streams.result_line(&format!(
                    "  {} = {}",
                    claim.predicate.as_str(),
                    claim.object.as_str()
                ));
            }
            // Gaps and exclusions go to stderr: they are commentary on the answer rather than the
            // answer, and `--quiet` should be able to silence them without silencing the finding.
            for gap in &pack.gaps {
                let _ = streams.note(&format!("gap: {}", gap.detail.as_str()));
            }
            for exclusion in &pack.exclusions {
                let _ = streams.note(&format!(
                    "excluded {}: {}",
                    exclusion.category.as_str(),
                    exclusion.reason.as_str()
                ));
            }
        }
    }

    ExitCode::Success
}

/// Read everything the pack is assembled from, in one lock.
///
/// One acquisition for the whole pack: a pack assembled from several reads could describe a graph
/// that never existed at any instant, which is not something a case should be enriched with.
fn gather(
    store: &mut OpenedStore,
    observable: &brolga_model::Observable,
    args: &ContextArgs,
) -> Result<Gathered, String> {
    let node = NodeRef::Observable(observable.id());
    let objects = u32::try_from(args.max_objects).unwrap_or(u32::MAX);
    let edges_limit = u32::try_from(args.max_relationships).unwrap_or(u32::MAX);

    let claims = store
        .claims_about(&node, Page::first(objects))
        .map_err(|error| error.to_string())?;
    let edges = store
        .edges_at(
            &EdgeQuery::at(node, Direction::Either),
            Page::first(edges_limit),
        )
        .map_err(|error| error.to_string())?;
    let sightings = store
        .sightings_of(&node, Page::first(objects))
        .map_err(|error| error.to_string())?;

    let mut entities = Vec::new();
    for edge in &edges {
        for end in [edge.source, edge.target] {
            if let NodeRef::Entity(id) = end
                && let Some(entity) = store.get_entity(id).map_err(|error| error.to_string())?
            {
                entities.push(entity);
            }
        }
    }
    entities.sort_by_key(|entity| entity.id.to_string());
    entities.dedup_by_key(|entity| entity.id.to_string());

    Ok(Gathered {
        claims,
        edges,
        sightings,
        entities,
    })
}

/// Read a detail level, refusing the ones that are not served as packs.
fn parse_level(value: &str) -> Option<DetailLevel> {
    match value.trim().to_ascii_uppercase().as_str() {
        "L0" => Some(DetailLevel::L0),
        "L1" => Some(DetailLevel::L1),
        "L2" => Some(DetailLevel::L2),
        "L3" => Some(DetailLevel::L3),
        // L4 and L5 are deliberately absent. They are reached by expanding a handle, and accepting
        // them here would produce a pack that fails its own validation — an internal error for what
        // is really a usage mistake.
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The levels served as packs, and the ones that are not.
    #[test]
    fn only_the_pack_levels_are_accepted() {
        for level in ["L0", "L1", "L2", "L3", "l1"] {
            assert!(parse_level(level).is_some(), "{level}");
        }
        for level in ["L4", "L5", "L6", "", "one"] {
            assert!(
                parse_level(level).is_none(),
                "`{level}` must not be accepted as a pack level"
            );
        }
    }
}
