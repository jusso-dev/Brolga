//! `brolga fetch` — pull intelligence from OpenCTI (primary) or TAXII.
//!
//! # Primary source: OpenCTI
//!
//! The product job is to normalise and serve TI that already lives in an OpenCTI instance.
//! GraphQL poll uses each object's `toStix` rendering so the same STIX parser handles OpenCTI and
//! file imports. TAXII remains available for STIX collections that are not OpenCTI-backed.
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
    ConnectorError, FeedRef, OpenCtiClient, OpenCtiInstance, PolicyTransport, SyncOptions,
    SyncReport, TaxiiClient, sync_collection, sync_opencti,
};
use brolga_ingest::{IngestMode, Pipeline};
use brolga_model::Timestamp;
use brolga_model::provenance::SensitiveText;
use brolga_security::{CancellationToken, NetworkPolicy, ResourceLimits};

use crate::cli::{FetchArgs, FetchSource, OpenCtiArgs, TaxiiArgs};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};
use crate::store_commands::{open_store, registry};

/// The environment variable a TAXII credential is read from.
///
/// An environment variable rather than a flag: a credential on a command line is in the shell
/// history, in `ps` output, and in any process listing the machine keeps.
pub(crate) const TOKEN_VARIABLE: &str = "BROLGA_TAXII_TOKEN";

/// The environment variable an OpenCTI API token is read from.
pub(crate) const OPENCTI_TOKEN_VARIABLE: &str = "BROLGA_OPENCTI_TOKEN";

/// `brolga fetch`.
pub(crate) fn fetch<Out: Write, Err: Write>(
    args: &FetchArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match &args.source {
        FetchSource::Opencti(opencti) => fetch_opencti(args, opencti, streams),
        FetchSource::Taxii(taxii) => fetch_taxii(args, taxii, streams),
    }
}

/// `brolga fetch opencti`.
fn fetch_opencti<Out: Write, Err: Write>(
    args: &FetchArgs,
    opencti: &OpenCtiArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let Some(token) = std::env::var(OPENCTI_TOKEN_VARIABLE)
        .ok()
        .and_then(|token| SensitiveText::new(token).ok())
    else {
        let _ = streams.problem(&format!(
            "no API token: set {OPENCTI_TOKEN_VARIABLE}. A token is not accepted as a flag, \
             because a credential on a command line is in the shell history and in any process \
             listing"
        ));
        return ExitCode::Usage;
    };

    let name = opencti
        .name
        .clone()
        .unwrap_or_else(|| host_of(&opencti.url).unwrap_or_else(|| opencti.url.clone()));

    let transport = PolicyTransport::new(policy_for(args));
    let client = OpenCtiClient::new(&transport);
    let instance = OpenCtiInstance::new(name.clone(), opencti.url.clone(), token);

    match client.version(&instance) {
        Ok(version) => {
            let _ = streams.note(&format!("{name} — OpenCTI {version}"));
        }
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return exit_for(&error);
        }
    }

    let mut store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let now = Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc());
    let outcome = sync_opencti(
        &client,
        &mut store,
        &pipeline_for(),
        &instance,
        now,
        options_for(args),
        &cancel_for(args),
    );

    match outcome {
        Ok(report) => report_fetch(args.source.as_str(), &[report], None, streams),
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            report_fetch(args.source.as_str(), &[], Some(&error), streams)
        }
    }
}

/// The network policy a run of either connector operates under.
fn policy_for(args: &FetchArgs) -> NetworkPolicy {
    NetworkPolicy {
        allow_plaintext_http: args.allow_http,
        allow_private_addresses: args.allow_private,
        // Deliberately not reachable from any flag on this command. An operator enabling internal
        // fetches is not thereby asking to let a feed read instance credentials, and a flag that
        // permitted it would eventually be pasted from a forum post.
        allow_cloud_metadata: false,
        ..NetworkPolicy::strict()
    }
}

/// The sync bounds a run of either connector operates under.
fn options_for(args: &FetchArgs) -> SyncOptions {
    SyncOptions::default()
        .with_page_size(args.page_size)
        .with_max_pages(args.max_pages)
        .with_etag(!args.no_etag)
}

/// The cancellation token a run of either connector operates under.
fn cancel_for(args: &FetchArgs) -> CancellationToken {
    match args.timeout_seconds {
        Some(seconds) => CancellationToken::with_budget(core::time::Duration::from_secs(seconds)),
        None => CancellationToken::never_cancelled(),
    }
}

/// The ingestion pipeline a run of either connector feeds.
///
/// Permissive, because a page a server sent is a page whose readable part is worth keeping — and
/// the parts that are not readable are quarantined with a reason rather than dropped. Strict would
/// make one unmappable object cost the whole page.
fn pipeline_for() -> Pipeline {
    Pipeline::new(registry(), ResourceLimits::defaults()).in_mode(IngestMode::Permissive)
}

/// The host of a URL, for naming an instance that was not named.
fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// `brolga fetch taxii`.
fn fetch_taxii<Out: Write, Err: Write>(
    args: &FetchArgs,
    taxii: &TaxiiArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let transport = PolicyTransport::new(policy_for(args));
    let authorization = std::env::var(TOKEN_VARIABLE).ok().and_then(|token| {
        SensitiveText::new(if token.starts_with("Bearer ") {
            token
        } else {
            format!("Bearer {token}")
        })
        .ok()
    });

    let mut client = TaxiiClient::new(&transport).with_authorization(authorization);

    let discovery = match client.discover(&taxii.url) {
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
        .unwrap_or_else(|| taxii.url.clone());

    let collections = match client.collections(&api_root) {
        Ok(collections) => collections,
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            return exit_for(&error);
        }
    };

    let wanted: Vec<_> = if taxii.collections.is_empty() {
        collections
            .iter()
            .filter(|collection| collection.can_read)
            .cloned()
            .collect()
    } else {
        collections
            .iter()
            .filter(|collection| taxii.collections.contains(&collection.id))
            .cloned()
            .collect()
    };

    // Naming a collection the server does not offer is a mistake worth reporting rather than an
    // empty run: the operator has a typo or the wrong server, and a silent success hides both.
    for requested in &taxii.collections {
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

    if taxii.discover_only {
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

    let pipeline = pipeline_for();
    let cancel = cancel_for(args);
    let options = options_for(args);

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

    report_fetch(args.source.as_str(), &reports, failed.as_ref(), streams)
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
    connector: &str,
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
                // Named, so a script consuming both connectors can tell which one produced a
                // summary without inferring it from the shape of the feed keys.
                "connector": connector,
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
