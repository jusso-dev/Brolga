//! `brolga export formats` — what each format costs you, before you pick one.
//!
//! # Why this is a command rather than a documentation page
//!
//! The lossiness of an export is the thing a caller most needs and is least likely to look up. "Export
//! to STIX" reads like a change of encoding; it is a change of model, and the fields that vanish are
//! not obvious from the name.
//!
//! So the list is generated from the exporters themselves, which means it cannot drift from what the
//! binary actually does — and it names what each format *needs*, because an export that requires
//! redistribution will be refused for an identity that only holds read, and finding that out from a
//! table beats finding it out from an error.

use std::io::Write;

use brolga_export::ExporterRegistry;

use crate::cli::ExportCommand;
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga export`.
pub(crate) fn export<Out: Write, Err: Write>(
    command: &ExportCommand,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match command {
        ExportCommand::Formats => formats(streams),
    }
}

/// `brolga export formats`.
fn formats<Out: Write, Err: Write>(streams: &mut Streams<Out, Err>) -> ExitCode {
    let registry = ExporterRegistry::shipped();

    if streams.mode() != OutputMode::Human && streams.mode() != OutputMode::Table {
        let rows: Vec<serde_json::Value> = registry
            .names()
            .iter()
            .zip(registry.metadata())
            .map(|(name, metadata)| {
                let capability = registry
                    .get(name)
                    .map(|exporter| exporter.capability())
                    .map_or_else(
                        || "unknown".to_owned(),
                        |capability| capability.as_str().to_owned(),
                    );
                serde_json::json!({
                    "name": name,
                    "id": metadata.id.as_str(),
                    "version": metadata.version,
                    "media_type": metadata.media_type,
                    "extension": metadata.extension,
                    "orientation": metadata.orientation.as_str(),
                    "lossiness": metadata.lossiness.as_str(),
                    "requires": capability,
                    "summary": metadata.summary,
                })
            })
            .collect();
        let _ = streams.result_json(&serde_json::json!({"formats": rows}));
        return ExitCode::Success;
    }

    for (name, metadata) in registry.names().iter().zip(registry.metadata()) {
        let capability = registry
            .get(name)
            .map_or("unknown", |exporter| exporter.capability().as_str());
        let _ = streams.result_line(&format!(
            "{name:<10} {:<12} {:<20} needs {:<13} .{}",
            metadata.orientation.as_str(),
            metadata.lossiness.as_str(),
            capability,
            metadata.extension
        ));
        let _ = streams.result_line(&format!("           {}", metadata.summary));
    }

    // Where to read the rest. The per-format loss lists are long enough that printing all of them
    // would bury the table they belong to.
    let _ = streams.note(
        "lossiness: `lossless` round-trips; `partially_lossless`, `compressed`, and `derived` each \
         declare what they dropped or invented, and an export reports them alongside its bytes.",
    );
    ExitCode::Success
}
