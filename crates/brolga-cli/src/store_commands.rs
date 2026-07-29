//! The commands that actually do something to a store.
//!
//! Everything these call already existed as library code before this module did. `brolga ingest`
//! exited `5` not because ingestion was unbuilt but because nothing connected the binary to it, and
//! a capability nobody can reach from a terminal is a capability nobody can evaluate.
//!
//! # Where the safe defaults live
//!
//! In the library, not here. Strict mode, source retention, resource limits, and referential
//! integrity are all defaults of `brolga-ingest` and `brolga-storage`; this module chooses nothing
//! on its own behalf. A flag can *relax* a default — `--mode permissive`, `--no-retain` — and each
//! is named so the relaxation is obvious at the call site rather than buried in a config file.
//!
//! # stdout is results, stderr is everything else
//!
//! Enforced by [`Streams`], not by convention here. `--output json` puts one machine-readable
//! object on stdout and nothing else, so `brolga ingest … --output json | jq` needs no filtering.

use std::io::Write;
use std::path::Path;

use brolga_ingest::formats::{delimited, misp, stix};
use brolga_ingest::{
    Document, DocumentReport, IngestError, IngestMode, IngestReport, ParserRegistry, Pipeline,
};
use brolga_model::provenance::{MediaType, SourceOrigin};
use brolga_model::{ContentHash, Timestamp};
use brolga_security::{CancellationToken, ResourceLimits};
use brolga_storage::{IntelligenceStore, Page, RecordKind, SqliteStore, StorageError, StoreRead};

use crate::cli::{IngestArgs, Mode, QuarantineArgs, ShowArgs};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// Every parser this build can select from.
///
/// One place, so a second interface cannot end up supporting a different set of formats from the
/// CLI — the sort of divergence nobody notices until a file parses in one and not the other.
#[must_use]
pub(crate) fn registry() -> ParserRegistry {
    let mut registry = ParserRegistry::new();
    registry.register(stix::StixParser::boxed());
    registry.register(misp::MispParser::boxed());
    registry.register(delimited::DelimitedParser::boxed());
    registry.register(delimited::JsonLinesParser::boxed());
    registry
}

/// `brolga ingest`.
pub(crate) fn ingest<Out: Write, Err: Write>(
    args: &IngestArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mut documents = Vec::new();
    for path in &args.paths {
        match std::fs::read(path) {
            Ok(bytes) => documents.push((path.clone(), bytes)),
            Err(error) => {
                let _ = streams.problem(&format!("cannot read {}: {error}", path.display()));
                return ExitCode::Io;
            }
        }
    }

    let mode = match args.mode {
        Mode::Strict => IngestMode::Strict,
        Mode::Permissive => IngestMode::Permissive,
    };

    let mut pipeline = Pipeline::new(registry(), ResourceLimits::defaults()).in_mode(mode);
    if args.no_retain {
        pipeline = pipeline.without_retaining_sources();
    }

    let cancel = match args.timeout_seconds {
        Some(seconds) => CancellationToken::with_budget(core::time::Duration::from_secs(seconds)),
        None => CancellationToken::never_cancelled(),
    };

    let offered: Vec<Document<'_>> = documents
        .iter()
        .map(|(path, bytes)| document_for(path, bytes))
        .collect();

    // A dry run exercises the same detection, parsing, and validation as a real one. One that took
    // a shortcut would answer a different question from the one the operator asked.
    if args.dry_run {
        let mut prepared = Vec::new();
        for document in &offered {
            match pipeline.prepare(document, &cancel) {
                Ok(report) => prepared.push(report),
                Err(error) => {
                    let _ = streams.problem(&error.to_string());
                    return exit_for(&error);
                }
            }
        }
        return report_dry_run(&prepared, streams);
    }

    let mut store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    match pipeline.ingest_batch(&mut store, &offered, &cancel) {
        Ok(report) => report_ingest(&report, streams),
        Err(error) => {
            let _ = streams.problem(&error.to_string());
            exit_for(&error)
        }
    }
}

/// `brolga stats`.
pub(crate) fn stats<Out: Write, Err: Write>(
    database: &Path,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open_store(database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let kinds = [
        ("entities", RecordKind::Entity),
        ("relationships", RecordKind::Relationship),
        ("claims", RecordKind::Claim),
        ("sightings", RecordKind::Sighting),
        ("source_objects", RecordKind::SourceObject),
    ];

    let mut counts = Vec::new();
    for (label, kind) in kinds {
        match store.count(kind) {
            Ok(count) => counts.push((label, count)),
            Err(error) => return storage_failure(&error, streams),
        }
    }

    let graph_version = match store.graph_version() {
        Ok(version) => version,
        Err(error) => return storage_failure(&error, streams),
    };
    let retained = store.source_blob_count().unwrap_or(0);
    let retained_bytes = store.source_blob_stored_bytes().unwrap_or(0);
    let distinct_problems = store.quarantine_count().unwrap_or(0);
    let occurrences = store.quarantine_occurrences().unwrap_or(0);

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let mut object = serde_json::Map::new();
            for (label, count) in &counts {
                object.insert((*label).to_owned(), serde_json::json!(count));
            }
            object.insert("graph_version".to_owned(), serde_json::json!(graph_version));
            object.insert("retained_sources".to_owned(), serde_json::json!(retained));
            object.insert(
                "retained_bytes".to_owned(),
                serde_json::json!(retained_bytes),
            );
            object.insert(
                "quarantined".to_owned(),
                serde_json::json!(distinct_problems),
            );
            object.insert(
                "quarantine_occurrences".to_owned(),
                serde_json::json!(occurrences),
            );
            let _ = streams.result_json(&serde_json::Value::Object(object));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            for (label, count) in &counts {
                let _ = streams.result_line(&format!("{label:<16} {count}"));
            }
            let _ = streams.result_line(&format!("{:<16} {graph_version}", "graph version"));
            let _ = streams.result_line(&format!(
                "{:<16} {retained} ({retained_bytes} bytes stored)",
                "retained"
            ));
            // Both numbers, because "12 problems" and "12 problems seen 400 times" call for
            // different responses.
            let _ = streams.result_line(&format!(
                "{:<16} {distinct_problems} distinct, {occurrences} occurrence(s)",
                "quarantined"
            ));
            ExitCode::Success
        }
    }
}

/// `brolga show`.
pub(crate) fn show<Out: Write, Err: Write>(
    args: &ShowArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    // The identifier carries its own kind, so the caller never has to say which table to look in —
    // `brolga show entity:…` is the whole interface.
    let Some((kind, _)) = args.id.split_once(':') else {
        let _ = streams.problem(&format!(
            "`{}` is not a Brolga identifier; they look like `entity:<uuid>`",
            sanitise(&args.id)
        ));
        return ExitCode::Usage;
    };

    let found = match kind {
        "entity" => fetch(store.get_entity_json(&args.id)),
        "relationship" => fetch(store.get_relationship_json(&args.id)),
        "claim" => fetch(store.get_claim_json(&args.id)),
        "sighting" => fetch(store.get_sighting_json(&args.id)),
        // `SourceObject::ID_KIND` is "source", not "source_object" — the table is named one way
        // and the identifier the other. Accepting both, because an operator reading `brolga stats`
        // sees the table name and will type it.
        "source" | "source_object" => fetch(store.get_source_object_json(&args.id)),
        other => {
            let _ = streams.problem(&format!(
                "`{}` is not a record kind Brolga stores",
                sanitise(other)
            ));
            return ExitCode::Usage;
        }
    };

    match found {
        Ok(Some(value)) => {
            let _ = streams.result_json(&value);
            ExitCode::Success
        }
        Ok(None) => {
            let _ = streams.problem("no record with that identifier");
            ExitCode::Failure
        }
        Err(error) => storage_failure(&error, streams),
    }
}

/// `brolga quarantine`.
pub(crate) fn quarantine<Out: Write, Err: Write>(
    args: &QuarantineArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let Some(source) = args.source.as_deref() else {
        let _ = streams.problem(
            "quarantine is indexed by source; pass --source <digest> from `brolga sources`",
        );
        return ExitCode::Usage;
    };

    let Ok(hash) = source.parse::<ContentHash>() else {
        let _ = streams.problem(&format!(
            "`{}` is not a content digest; they look like `sha256:<hex>`",
            sanitise(source)
        ));
        return ExitCode::Usage;
    };

    let records = match store.quarantined_for_source(&hash) {
        Ok(records) => records,
        Err(error) => return storage_failure(&error, streams),
    };

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let entries: Vec<serde_json::Value> = records
                .iter()
                .map(|record| {
                    serde_json::json!({
                        "id": record.id,
                        "parser": record.parser,
                        "parser_version": record.parser_version,
                        "stage": record.stage.as_str(),
                        "reason_kind": record.reason_kind,
                        "reason": record.reason,
                        "byte_offset": record.byte_offset,
                        "fragment": record.fragment,
                        "occurrences": record.occurrences,
                        "first_seen_at": record.first_seen_at,
                        "last_seen_at": record.last_seen_at,
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({ "quarantined": entries }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            if records.is_empty() {
                let _ = streams.result_line("nothing quarantined from that source");
                return ExitCode::Success;
            }
            for record in &records {
                let _ = streams.result_line(&format!(
                    "{} [{}] {} (x{})",
                    record.parser, record.reason_kind, record.reason, record.occurrences
                ));
                if let Some(fragment) = &record.fragment {
                    let _ = streams.result_line(&format!("    {fragment}"));
                }
            }
            ExitCode::Success
        }
    }
}

/// `brolga sources`.
pub(crate) fn sources<Out: Write, Err: Write>(
    database: &Path,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let store = match open_store(database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let objects = match store.list_source_objects(Page::default()) {
        Ok(objects) => objects,
        Err(error) => return storage_failure(&error, streams),
    };

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let entries: Vec<serde_json::Value> = objects
                .iter()
                .map(|object| {
                    serde_json::json!({
                        "id": object.id.to_string(),
                        "content_hash": object.content_hash.to_string(),
                        "media_type": object.media_type.as_str(),
                        "byte_length": object.byte_length,
                        "retrieved_at": object.retrieved_at.to_rfc3339(),
                        "origin": object.origin.kind_str(),
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({ "sources": entries }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            if objects.is_empty() {
                let _ = streams.result_line("no source objects retained");
                return ExitCode::Success;
            }
            for object in &objects {
                let _ = streams.result_line(&format!(
                    "{}  {:>9} bytes  {}",
                    object.content_hash,
                    object.byte_length,
                    object.media_type.as_str()
                ));
            }
            ExitCode::Success
        }
    }
}

/// Open and migrate a store, reporting failure the same way everywhere.
fn open_store<Out: Write, Err: Write>(
    path: &Path,
    streams: &mut Streams<Out, Err>,
) -> Result<SqliteStore, ExitCode> {
    let mut store = SqliteStore::open(path, brolga_storage::sqlite::DEFAULT_BUSY_TIMEOUT_MS)
        .map_err(|error| {
            let _ = streams.problem(&format!("cannot open {}: {error}", path.display()));
            ExitCode::Storage
        })?;

    // Migrating on open rather than behind a separate command. An operator who has to remember to
    // run a migration eventually will not, and the failure then surfaces much later as a confusing
    // query error rather than as a migration error.
    store.migrate().map_err(|error| {
        let _ = streams.problem(&format!("cannot migrate {}: {error}", path.display()));
        ExitCode::Storage
    })?;
    Ok(store)
}

/// Build a document from a file, letting detection decide the format.
///
/// The media type is deliberately vague. The file name is a hint and the bytes are the evidence;
/// asserting a media type from an extension would let a mislabelled file outrank what it contains.
fn document_for<'a>(path: &'a Path, bytes: &'a [u8]) -> Document<'a> {
    Document {
        bytes,
        media_type: octet_stream(),
        file_name: path.file_name().and_then(|name| name.to_str()),
        origin: SourceOrigin::LocalFile {
            path: brolga_model::provenance::SensitiveText::new(path.display().to_string())
                .unwrap_or_else(|_| local_file_fallback()),
        },
        retrieved_at: now(),
    }
}

/// The current instant.
fn now() -> Timestamp {
    Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc())
}

/// Report a dry run.
fn report_dry_run<Out: Write, Err: Write>(
    reports: &[DocumentReport],
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let records: usize = reports.iter().map(DocumentReport::record_count).sum();
    let rejected: usize = reports.iter().map(|report| report.rejected.len()).sum();

    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let documents: Vec<serde_json::Value> = reports
                .iter()
                .map(|report| {
                    serde_json::json!({
                        "content_hash": report.content_hash.to_string(),
                        "parser": report.parser.as_str(),
                        "selection": report.selection,
                        "records": report.records.len(),
                        "rejected": report.rejected.len(),
                    })
                })
                .collect();
            let _ = streams.result_json(&serde_json::json!({
                "dry_run": true,
                "documents": documents,
                "records": records,
                "rejected": rejected,
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            for report in reports {
                let _ = streams.note(&report.selection);
                for rejection in &report.rejected {
                    let _ = streams.note(&format!(
                        "    rejected [{}] {}",
                        rejection.reason_kind, rejection.reason
                    ));
                }
            }
            let _ = streams.result_line(&format!(
                "dry run: nothing written. {records} record(s) would land, {rejected} would be quarantined"
            ));
            ExitCode::Success
        }
    }
}

/// Report a completed ingest.
fn report_ingest<Out: Write, Err: Write>(
    report: &IngestReport,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match streams.mode() {
        OutputMode::Json | OutputMode::Yaml | OutputMode::Jsonl => {
            let _ = streams.result_json(&serde_json::json!({
                "mode": report.mode.as_str(),
                "offered": report.total,
                "accepted": report.accepted(),
                "inserted": report.inserted,
                "updated": report.updated,
                "unchanged": report.unchanged,
                "rejected": report.rejected,
                "newly_quarantined": report.newly_quarantined,
                "retained_sources": report.retained_sources,
                "deduplicated_sources": report.deduplicated_sources,
                "reconciles": report.reconciles(),
            }));
            ExitCode::Success
        }
        OutputMode::Human | OutputMode::Table => {
            // Which parser read which file is commentary, so it goes to stderr and `--quiet`
            // silences it. The summary is the result.
            for document in &report.documents {
                let _ = streams.note(&document.selection);
            }
            let _ = streams.result_line(&report.summary());
            ExitCode::Success
        }
    }
}

/// Unwrap a stored JSON document.
fn fetch(
    found: Result<Option<serde_json::Value>, StorageError>,
) -> Result<Option<serde_json::Value>, StorageError> {
    found
}

/// Map an ingestion failure onto the exit-code registry.
///
/// The registry is a compatibility surface, so a script branches on the code rather than on the
/// message. A cancelled run and a storage failure are different problems and get different codes.
fn exit_for(error: &IngestError) -> ExitCode {
    match error {
        IngestError::Cancelled { .. } => ExitCode::Cancelled,
        IngestError::Storage { .. } => ExitCode::Storage,
        _ => ExitCode::Failure,
    }
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
///
/// An identifier arrives on the command line, which is not trusted input when the caller is another
/// program.
fn sanitise(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect()
}

/// `application/octet-stream`, which is a compile-time-known-good literal.
fn octet_stream() -> MediaType {
    MediaType::new("application/octet-stream").unwrap_or_else(|_| octet_stream())
}

/// A placeholder path, for the case where a real path is not representable.
fn local_file_fallback() -> brolga_model::provenance::SensitiveText {
    brolga_model::provenance::SensitiveText::new("<unrepresentable path>")
        .unwrap_or_else(|_| local_file_fallback())
}
