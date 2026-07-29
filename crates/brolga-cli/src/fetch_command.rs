//! `brolga fetch` — retrieve intelligence from a remote TAXII server.
//!
//! # The two things this command says out loud
//!
//! **What it refused.** A policy denial is reported as a refusal by Brolga, not as a failure of the
//! server, because those send an operator to completely different places. `--allow-private` and
//! `--allow-http` exist so that turning a control off is a visible decision on a command line
//! rather than a default somebody inherits.
//!
//! **Whether it finished.** A run stopped by `--max-pages`, by a timeout, or by a failure reports
//! `partial` or `failed` rather than a count that looks like success. "Stopped early" and "up to
//! date" are different facts and only one of them means the feed has nothing new — a summary that
//! blurred them would let a sync quietly stop working.

use std::io::Write;

use brolga_connectors::{
    ConnectorError, FeedRef, PolicyTransport, SyncOptions, SyncReport, TaxiiClient, sync_collection,
};
use brolga_ingest::{IngestMode, Pipeline};
use brolga_model::Timestamp;
use brolga_model::provenance::SensitiveText;
use brolga_security::{CancellationToken, NetworkPolicy, ResourceLimits};

use crate::cli::FetchArgs;
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};
use crate::store_commands::{open_store, registry};

/// The environment variable a TAXII credential is read from.
///
/// An environment variable rather than a flag: a credential on a command line is in the shell
/// history, in `ps` output, and in any process listing the machine keeps.
pub(crate) const TOKEN_VARIABLE: &str = "BROLGA_TAXII_TOKEN";

/// `brolga fetch`.
pub(crate) fn fetch<Out: Write, Err: Write>(
    args: &FetchArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let policy = NetworkPolicy {
        allow_plaintext_http: args.allow_http,
        allow_private_addresses: args.allow_private,
        // Deliberately not reachable from any flag on this command. An operator enabling internal
        // fetches is not thereby asking to let a feed read instance credentials, and a flag that
        // permitted it would eventually be pasted from a forum post.
        allow_cloud_metadata: false,
        ..NetworkPolicy::strict()
    };

    let transport = PolicyTransport::new(policy);
    let authorization = std::env::var(TOKEN_VARIABLE).ok().and_then(|token| {
        SensitiveText::new(if token.starts_with("Bearer ") {
            token
        } else {
            format!("Bearer {token}")
        })
        .ok()
    });

    let mut client = TaxiiClient::new(&transport).with_authorization(authorization);

    let discovery = match client.discover(&args.url) {
        Ok(discovery) => discovery,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return exit_for(&error);
        }
    };

    let _ = streams.note(&format!(
        "discovered {} — TAXII {}, {} API root(s)",
        discovery.title,
        discovery.version,
        discovery.api_roots.len()
    ));

    // The default root where the server named one. A server advertising several and no default is
    // ambiguous, and reading them all would multiply the work an operator asked for.
    let api_root = discovery
        .default_api_root
        .clone()
        .or_else(|| discovery.api_roots.first().cloned())
        .unwrap_or_else(|| args.url.clone());

    let collections = match client.collections(&api_root) {
        Ok(collections) => collections,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return exit_for(&error);
        }
    };

    let wanted: Vec<_> = if args.collections.is_empty() {
        collections
            .iter()
            .filter(|collection| collection.can_read)
            .cloned()
            .collect()
    } else {
        collections
            .iter()
            .filter(|collection| args.collections.contains(&collection.id))
            .cloned()
            .collect()
    };

    // Naming a collection the server does not offer is a mistake worth reporting rather than an
    // empty run: the operator has a typo or the wrong server, and a silent success hides both.
    for requested in &args.collections {
        if !collections
            .iter()
            .any(|collection| &collection.id == requested)
        {
            let _ = streams.problem(&format!(
                "`{requested}` is not a collection this server offers"
            ));
            return ExitCode::Usage;
        }
    }

    if args.discover_only {
        return report_discovery(&discovery, &collections, streams);
    }

    if wanted.is_empty() {
        let _ = streams.problem("the server offers no readable collection");
        return ExitCode::Usage;
    }

    let mut store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let pipeline = Pipeline::new(registry(), ResourceLimits::defaults())
        // Permissive, because a page a server sent is a page whose readable part is worth keeping —
        // and the parts that are not readable are quarantined with a reason rather than dropped.
        // Strict would make one unmappable object cost the whole page.
        .in_mode(IngestMode::Permissive);

    let cancel = match args.timeout_seconds {
        Some(seconds) => CancellationToken::with_budget(core::time::Duration::from_secs(seconds)),
        None => CancellationToken::never_cancelled(),
    };

    let options = SyncOptions::default()
        .with_page_size(args.page_size)
        .with_max_pages(args.max_pages)
        .with_etag(!args.no_etag);

    let now = Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc());

    let mut reports = Vec::new();
    let mut failed = None;

    for collection in &wanted {
        let _ = streams.note(&format!("{} — {}", collection.id, collection.title));

        match sync_collection(
            &client,
            &mut store,
            &pipeline,
            FeedRef::new(&api_root, &collection.id),
            now,
            options,
            &cancel,
        ) {
            Ok(report) => reports.push(report),
            Err(error) => {
                let _ = streams.problem(&error.to_string());
                failed = Some(error);
                // Later collections are not attempted. A policy refusal or a bad credential
                // applies to all of them, and hammering the rest of a server after the first
                // failure is the shape of an accidental denial of service.
                break;
            }
        }
    }

    report_fetch(&reports, failed.as_ref(), streams)
}

/// Report what a server offers, without fetching anything.
fn report_discovery<Out: Write, Err: Write>(
    discovery: &brolga_connectors::Discovery,
    collections: &[brolga_connectors::Collection],
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "title": discovery.title,
                "taxii_version": discovery.version.as_str(),
                "api_roots": discovery.api_roots,
                "default_api_root": discovery.default_api_root,
                "collections": collections
                    .iter()
                    .map(|collection| serde_json::json!({
                        "id": collection.id,
                        "title": collection.title,
                        "can_read": collection.can_read,
                    }))
                    .collect::<Vec<_>>(),
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            for collection in collections {
                let readable = if collection.can_read {
                    "read"
                } else {
                    "no read"
                };
                let _ = streams.result_line(&format!(
                    "{}  {}  ({readable})",
                    collection.id, collection.title
                ));
            }
            ExitCode::Success
        }
    }
}

/// Report what a run did.
fn report_fetch<Out: Write, Err: Write>(
    reports: &[SyncReport],
    failed: Option<&ConnectorError>,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let pages: usize = reports.iter().map(|report| report.pages).sum();
    let objects: usize = reports.iter().map(|report| report.objects).sum();
    let inserted: u64 = reports.iter().map(|report| report.inserted).sum();
    let quarantined: u64 = reports.iter().map(|report| report.quarantined).sum();
    let complete = failed.is_none() && reports.iter().all(SyncReport::is_complete);

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "collections": reports
                    .iter()
                    .map(|report| serde_json::json!({
                        "feed": report.feed,
                        "pages": report.pages,
                        "objects": report.objects,
                        "inserted": report.inserted,
                        "quarantined": report.quarantined,
                        "not_modified": report.not_modified,
                        "status": report.cursor.last_status.as_str(),
                        "added_after": report.cursor.added_after,
                    }))
                    .collect::<Vec<_>>(),
                "pages": pages,
                "objects": objects,
                "inserted": inserted,
                "quarantined": quarantined,
                "complete": complete,
            }));
        }
        OutputMode::Human | OutputMode::Table => {
            for report in reports {
                let _ = streams.result_line(&format!(
                    "{}  {} page(s), {} object(s), {} stored, {} quarantined — {}",
                    report.feed,
                    report.pages,
                    report.objects,
                    report.inserted,
                    report.quarantined,
                    report.cursor.last_status,
                ));
            }
            if !complete {
                // Said explicitly, because a count that looks healthy after a partial run is how a
                // sync quietly stops working.
                let _ = streams.note(
                    "the run did not cover every feed in full; the stored cursor resumes where it \
                     stopped",
                );
            }
        }
    }

    match failed {
        Some(error) => exit_for(error),
        None => ExitCode::Success,
    }
}

/// Map a connector failure onto the exit-code registry.
///
/// The registry is a compatibility surface, so a script branches on the code rather than the
/// message. A policy refusal is a *usage* problem — the operator has to decide to permit it — and a
/// server outage is not.
fn exit_for(error: &ConnectorError) -> ExitCode {
    match error {
        ConnectorError::Denied { .. } | ConnectorError::MalformedUrl { .. } => ExitCode::Usage,
        ConnectorError::Storage { .. } => ExitCode::Storage,
        ConnectorError::Cancelled => ExitCode::Cancelled,
        ConnectorError::Transport { .. }
        | ConnectorError::Status { .. }
        | ConnectorError::ResponseTooLarge { .. }
        | ConnectorError::MalformedResponse { .. }
        | ConnectorError::VersionNotNegotiated { .. } => ExitCode::Io,
        _ => ExitCode::Io,
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

    /// A refusal is the operator's decision to revisit; an outage is somebody else's problem. A
    /// script branching on the exit code has to be able to tell them apart.
    #[test]
    fn a_policy_refusal_and_a_server_outage_get_different_exit_codes() {
        let denied = ConnectorError::Denied {
            url: "https://x.example".to_owned(),
            reason: "loopback".to_owned(),
        };
        let outage = ConnectorError::Transport {
            url: "https://x.example".to_owned(),
            reason: "connection reset".to_owned(),
        };
        assert_eq!(exit_for(&denied), ExitCode::Usage);
        assert_eq!(exit_for(&outage), ExitCode::Io);
        assert_ne!(exit_for(&denied), exit_for(&outage));
    }
}
