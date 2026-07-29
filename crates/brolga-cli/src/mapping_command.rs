//! `brolga mapping validate` and `brolga mapping explain`.
//!
//! # Two commands, one reason
//!
//! A declarative mapping is executed against untrusted input, so the two questions an operator has
//! before running one are "will this work?" and "what will it do?". Both are answerable without a
//! document, a store, or a network, and this command is where they are answered.
//!
//! `validate` exits zero only if the mapping would run. Every problem is reported, not the first,
//! because an operator fixing a mapping file wants the whole list rather than five round trips —
//! except where an early problem makes the rest meaningless, which is the schema tag.
//!
//! `explain` prints what the mapping does *and what the engine refuses to do whatever the mapping
//! says*. The refusals are the half that matters when the mapping came from somewhere else: a field
//! list tells you what a mapping intends, and the refusal list tells you the worst it could do.

use std::io::Write;

use brolga_ingest::mapping::{MappedParser, Mapping};

use crate::cli::{MappingCommand, MappingFileArgs};
use crate::exit::ExitCode;
use crate::output::{OutputMode, Streams};

/// `brolga mapping`.
pub(crate) fn mapping<Out: Write, Err: Write>(
    command: &MappingCommand,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    match command {
        MappingCommand::Validate(args) => validate(args, streams),
        MappingCommand::Explain(args) => explain(args, streams),
    }
}

/// Read and validate a mapping file.
///
/// Returns the mapping so both subcommands share one loading path — a validator and an explainer
/// that could disagree about whether a file loads would be worse than either alone.
fn load<Out: Write, Err: Write>(
    args: &MappingFileArgs,
    streams: &mut Streams<Out, Err>,
) -> Result<Mapping, ExitCode> {
    let bytes = match std::fs::read(&args.path) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = streams.problem(&format!("cannot read {}: {error}", args.path.display()));
            return Err(ExitCode::Io);
        }
    };

    Mapping::load(&bytes).map_err(|error| {
        let _ = streams.problem(&error.to_string());
        // `ConfigInvalid` rather than `Usage`: the command line was fine, the file was not. A script
        // distinguishing "I called this wrongly" from "the operator's mapping is broken" needs the
        // two to differ.
        ExitCode::ConfigInvalid
    })
}

/// `brolga mapping validate`.
fn validate<Out: Write, Err: Write>(
    args: &MappingFileArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mapping = match load(args, streams) {
        Ok(mapping) => mapping,
        Err(code) => return code,
    };

    if streams.mode() == OutputMode::Human {
        let _ = streams.result_line(&format!(
            "`{}` v{} is valid: {} source, {} field(s), {} filter(s)",
            mapping.id,
            mapping.version,
            mapping.source.as_str(),
            mapping.fields.len(),
            mapping.filters.len()
        ));
    } else {
        let _ = streams.result_json(&serde_json::json!({
            "id": mapping.id,
            "version": mapping.version,
            "valid": true,
            "source": mapping.source.as_str(),
            "fields": mapping.fields.len(),
            "filters": mapping.filters.len(),
        }));
    }
    ExitCode::Success
}

/// `brolga mapping explain`.
fn explain<Out: Write, Err: Write>(
    args: &MappingFileArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let mapping = match load(args, streams) {
        Ok(mapping) => mapping,
        Err(code) => return code,
    };
    let explanation = MappedParser::new(mapping).explain();

    if streams.mode() != OutputMode::Human {
        let _ = streams.result_json(&explanation);
        return ExitCode::Success;
    }

    let _ = streams.result_line(&format!(
        "mapping `{}` v{}",
        explanation.id, explanation.version
    ));
    if let Some(description) = &explanation.description {
        let _ = streams.result_line(&format!("  {description}"));
    }
    let _ = streams.result_line(&format!("  source:  {}", explanation.source));
    let _ = streams.result_line(&format!("  records: {}", explanation.records));

    if explanation.filters.is_empty() {
        let _ = streams.result_line("  filters: none — every record is mapped");
    } else {
        let _ = streams.result_line("  filters: every one of these must hold");
        for filter in &explanation.filters {
            let _ = streams.result_line(&format!("    - {filter}"));
        }
    }

    let _ = streams.result_line("  fields:");
    for field in &explanation.fields {
        let mut notes: Vec<String> = Vec::new();
        if field.subject {
            notes.push("subject".to_owned());
        }
        if field.required {
            notes.push("required".to_owned());
        }
        notes.push(field.cardinality.to_owned());
        if !field.transforms.is_empty() {
            notes.push(format!("transforms: {}", field.transforms.join(" → ")));
        }
        let _ = streams.result_line(&format!(
            "    - `{}` → {} ({})",
            field.path,
            field.target,
            notes.join("; ")
        ));
    }

    let _ = streams.result_line(&format!(
        "  limits:  {} record(s) per document, {} node(s) per path, {} transform(s) per field, {} \
         byte(s) per transform output",
        explanation.limits.max_records,
        explanation.limits.max_nodes,
        explanation.limits.max_transforms,
        explanation.limits.max_output_bytes
    ));

    // The half that matters when the mapping came from somewhere else.
    let _ = streams.result_line("  this engine will not, whatever a mapping says:");
    for refusal in &explanation.refusals {
        let _ = streams.result_line(&format!("    - {refusal}"));
    }

    ExitCode::Success
}
