//! The ingestion pipeline: explicit stages, recorded metrics, one transaction per batch.
//!
//! The pipeline exists so that the things every format needs done identically are done in one
//! place: limits before a parser allocates, a source object addressed by the bytes as retrieved, a
//! transformation chain stamped with every stage, validation before anything reaches storage, and a
//! deterministic write order.
//!
//! A parser that wanted to skip any of those would have to change this file, in a diff, rather than
//! by omission in a new module nobody diffed against the others.

use brolga_model::{
    ContentHash, Id, ShortText, SourceObject, Timestamp, TransformationChain, TransformationStage,
    TransformationStep,
    provenance::{MediaType, SourceOrigin},
};
use brolga_security::{CancellationToken, ResourceLimits};
use brolga_storage::{
    BlobOutcome, BlobRequest, IntelligenceStore, RetentionClass, StoreWrite, UpsertOutcome,
};

use crate::detect::FormatHint;
use crate::error::{IngestError, Result};
use crate::parser::{ParseContext, ParsedRecord, ParserId};
use crate::registry::ParserRegistry;

/// The pipeline's own algorithm version.
///
/// Stamped into every transformation step the pipeline contributes. Bump it when the pipeline's
/// *output* changes for some input — a new stage, a different canonical ordering — because the
/// version is what lets two differing results from "the same pipeline" be told apart afterwards.
pub const PIPELINE_VERSION: u32 = 1;

/// One document offered for ingestion.
#[derive(Debug, Clone)]
pub struct Document<'a> {
    /// The bytes exactly as retrieved. Hashed before anything touches them.
    pub bytes: &'a [u8],
    /// The media type it was offered under. Advisory; detection may disagree.
    pub media_type: MediaType,
    /// The file name, where there is one. Used only as a detection hint.
    pub file_name: Option<&'a str>,
    /// Where it came from.
    pub origin: SourceOrigin,
    /// When it was retrieved.
    pub retrieved_at: Timestamp,
}

/// What one stage did.
///
/// Every stage produces one of these, including the ones that change nothing, because a stage
/// missing from a report is indistinguishable from a stage that ran and did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageMetrics {
    /// Which stage.
    pub stage: TransformationStage,
    /// Records entering the stage.
    pub records_in: u64,
    /// Records leaving it.
    pub records_out: u64,
    /// Bytes the stage considered, where that is meaningful.
    pub bytes_considered: u64,
}

/// What happened to one document.
#[derive(Debug, Clone)]
pub struct DocumentReport {
    /// The content-addressed source object for the document.
    pub source_object: Id<SourceObject>,
    /// Its digest.
    pub content_hash: ContentHash,
    /// The parser that read it.
    pub parser: ParserId,
    /// That parser's version at the time.
    pub parser_version: u32,
    /// Why that parser and not another.
    pub selection: String,
    /// Every stage, in order.
    pub stages: Vec<StageMetrics>,
    /// The transformation chain stamped onto records from this document.
    pub chain: TransformationChain,
    /// Anything the parser wanted the operator to know.
    pub notes: Vec<ShortText>,
    /// The canonical records, in the deterministic order they will be written.
    pub records: Vec<ParsedRecord>,
}

impl DocumentReport {
    /// How many records the document produced.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// The chain fingerprint, which is independent of the clock.
    ///
    /// Two runs over the same bytes with the same parser version produce the same fingerprint, so
    /// this is what a caller compares to answer "did anything about how we read this change?".
    #[must_use]
    pub fn chain_fingerprint(&self) -> ContentHash {
        self.chain.fingerprint()
    }
}

/// What happened to a batch.
#[derive(Debug, Clone, Default)]
pub struct IngestReport {
    /// One entry per document, in the order the documents were offered.
    pub documents: Vec<DocumentReport>,
    /// Records written for the first time.
    pub inserted: u64,
    /// Records that already existed and changed.
    pub updated: u64,
    /// Records that already existed and did not change.
    pub unchanged: u64,
    /// Source objects written.
    pub source_objects: u64,
    /// Original source objects whose bytes were retained for the first time.
    pub retained_sources: u64,
    /// Original source objects whose bytes were already retained.
    pub deduplicated_sources: u64,
}

impl IngestReport {
    /// Total records persisted.
    #[must_use]
    pub const fn persisted(&self) -> u64 {
        self.inserted.saturating_add(self.updated)
    }

    /// Every stage metric across every document, in document then stage order.
    #[must_use]
    pub fn stages(&self) -> Vec<&StageMetrics> {
        self.documents
            .iter()
            .flat_map(|document| document.stages.iter())
            .collect()
    }
}

/// The ingestion pipeline.
#[derive(Debug)]
pub struct Pipeline {
    registry: ParserRegistry,
    limits: ResourceLimits,
    retention: Option<RetentionClass>,
}

impl Pipeline {
    /// Build a pipeline over a registry, with the given limits.
    ///
    /// Retains original source bytes under [`RetentionClass::Standard`]. Evidence retention is the
    /// default because a canonical record whose source was discarded cannot be argued about later:
    /// a disagreement with an upstream platform becomes unresolvable.
    #[must_use]
    pub const fn new(registry: ParserRegistry, limits: ResourceLimits) -> Self {
        Self {
            registry,
            limits,
            retention: Some(RetentionClass::Standard),
        }
    }

    /// Set the retention class for original source bytes.
    #[must_use]
    pub const fn retaining(mut self, retention: RetentionClass) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Ingest without retaining original bytes.
    ///
    /// For a caller that has already retained them, or that is deliberately processing without
    /// keeping evidence. Named so that reading the call site makes the loss obvious.
    #[must_use]
    pub const fn without_retaining_sources(mut self) -> Self {
        self.retention = None;
        self
    }

    /// The retention class in force, if any.
    #[must_use]
    pub const fn retention(&self) -> Option<RetentionClass> {
        self.retention
    }

    /// Build a pipeline with the safe default limits.
    #[must_use]
    pub const fn with_defaults(registry: ParserRegistry) -> Self {
        Self::new(registry, ResourceLimits::defaults())
    }

    /// The registry this pipeline selects from.
    #[must_use]
    pub const fn registry(&self) -> &ParserRegistry {
        &self.registry
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Run detection, parsing, validation, and canonicalisation over one document.
    ///
    /// Persists nothing. Separated from [`Self::ingest_batch`] so that a caller can inspect what
    /// would be written — and so that a parse failure in a batch is attributable to the document
    /// that caused it rather than to the batch.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::DocumentTooLarge`] before any parser runs,
    /// [`IngestError::UnknownFormat`] or [`IngestError::AmbiguousFormat`] from selection,
    /// [`IngestError::ParserFailed`] from the parser, [`IngestError::TooManyRecords`] if it
    /// overran the record limit, [`IngestError::InvalidRecord`] if it emitted something the model
    /// rejects, and [`IngestError::Cancelled`] if the token expired between stages.
    pub fn prepare(
        &self,
        document: &Document<'_>,
        cancel: &CancellationToken,
    ) -> Result<DocumentReport> {
        cancel.check()?;

        let byte_length =
            u64::try_from(document.bytes.len()).map_err(|_| IngestError::DocumentTooLarge {
                actual: u64::MAX,
                limit: self.limits.input.max_bytes,
            })?;

        // Before selection, before parsing, before any allocation proportional to the input. A
        // parser never sees a document it should not have been offered.
        if byte_length > self.limits.input.max_bytes {
            return Err(IngestError::DocumentTooLarge {
                actual: byte_length,
                limit: self.limits.input.max_bytes,
            });
        }

        let mut stages = Vec::new();

        // ---- Retrieval -------------------------------------------------------------------
        // The digest is over the bytes as retrieved. Computing it after any normalisation would
        // produce a hash addressing something nobody ever received.
        let content_hash = ContentHash::of(document.bytes);
        let source_object = SourceObject::new(
            content_hash,
            document.media_type.clone(),
            byte_length,
            document.retrieved_at,
            document.origin.clone(),
        )
        .validated()?;
        stages.push(StageMetrics {
            stage: TransformationStage::Retrieval,
            records_in: 0,
            records_out: 0,
            bytes_considered: byte_length,
        });

        let mut chain = TransformationChain::single(step(
            TransformationStage::Retrieval,
            "brolga.ingest.retrieval",
        )?)?;

        // ---- Detection -------------------------------------------------------------------
        cancel.check()?;
        let hint = FormatHint::new(
            document.media_type.as_str(),
            document.file_name,
            document.bytes,
            byte_length,
        );
        let selection = self.registry.select(&hint)?;
        let chosen = selection.chosen().parser;
        let chosen_version = selection.chosen().parser_version;
        stages.push(StageMetrics {
            stage: TransformationStage::Detection,
            records_in: 0,
            records_out: 0,
            bytes_considered: u64::try_from(hint.prefix().len()).unwrap_or(byte_length),
        });
        chain.push(step(
            TransformationStage::Detection,
            "brolga.ingest.detection",
        )?)?;

        // ---- Parsing ---------------------------------------------------------------------
        cancel.check()?;
        let parser = self
            .registry
            .get(chosen)
            .ok_or_else(|| IngestError::ParserFailed {
                parser: chosen,
                offset: None,
                detail: "the selected parser is no longer registered".to_owned(),
            })?;

        chain.push(TransformationStep::new(
            TransformationStage::Parsing,
            ShortText::new(chosen.as_str())?,
            chosen_version,
        ))?;

        let context = ParseContext::new(
            self.limits,
            cancel.clone(),
            document.media_type.clone(),
            document.retrieved_at,
            document.origin.clone(),
            source_object.id,
            chain.clone(),
        );

        // ADR 0003 §2: there is no `catch_unwind` here and there deliberately is not one. Release
        // builds set `panic = "abort"`, so a wrapper would contain nothing while looking like it
        // did. A parser signals failure by returning, and is stopped from panicking by the
        // workspace lints and by the property test that drives arbitrary bytes through every
        // registered parser.
        let output =
            parser
                .parse(&context, document.bytes)
                .map_err(|error| IngestError::ParserFailed {
                    parser: chosen,
                    offset: error.offset,
                    detail: error.detail,
                })?;

        let produced = u64::try_from(output.records.len()).unwrap_or(u64::MAX);
        if produced > self.limits.input.max_records {
            return Err(IngestError::TooManyRecords {
                parser: chosen,
                actual: produced,
                limit: self.limits.input.max_records,
            });
        }
        stages.push(StageMetrics {
            stage: TransformationStage::Parsing,
            records_in: 0,
            records_out: produced,
            bytes_considered: byte_length,
        });

        // ---- Validation ------------------------------------------------------------------
        cancel.check()?;
        let mut records = Vec::with_capacity(output.records.len());
        for (index, record) in output.records.into_iter().enumerate() {
            records.push(validate(chosen, index, record)?);
        }
        let validated = u64::try_from(records.len()).unwrap_or(u64::MAX);
        stages.push(StageMetrics {
            stage: TransformationStage::Validation,
            records_in: produced,
            records_out: validated,
            bytes_considered: 0,
        });
        chain.push(step(
            TransformationStage::Validation,
            "brolga.ingest.validation",
        )?)?;

        // ---- Canonicalisation ------------------------------------------------------------
        // The deterministic order. Everything downstream — the write sequence, the report, any
        // comparison between two runs — depends on this being a function of the records rather
        // than of the order the parser happened to emit them in.
        cancel.check()?;
        records.sort_by_key(ParsedRecord::sort_key);
        stages.push(StageMetrics {
            stage: TransformationStage::Canonicalisation,
            records_in: validated,
            records_out: validated,
            bytes_considered: 0,
        });
        chain.push(step(
            TransformationStage::Canonicalisation,
            "brolga.ingest.canonicalisation",
        )?)?;

        Ok(DocumentReport {
            source_object: source_object.id,
            content_hash,
            parser: chosen,
            parser_version: chosen_version,
            selection: selection.explain(),
            stages,
            chain,
            notes: output.notes,
            records,
        })
    }

    /// Ingest a batch of documents.
    ///
    /// Every document is prepared first, then the whole batch is written in **one** transaction. A
    /// failure anywhere — a bad document, an expired deadline, a storage error — leaves the store
    /// exactly as it was. A half-written batch is worse than a rejected one: it looks like a
    /// success to anything that only counts rows.
    ///
    /// # Errors
    ///
    /// Any error from [`Self::prepare`], or [`IngestError::Storage`] if the transaction could not
    /// be committed. In every case nothing has been written.
    pub fn ingest_batch<S: IntelligenceStore + ?Sized>(
        &self,
        store: &mut S,
        documents: &[Document<'_>],
        cancel: &CancellationToken,
    ) -> Result<IngestReport> {
        let mut reports = Vec::with_capacity(documents.len());
        for document in documents {
            reports.push(self.prepare(document, cancel)?);
        }

        // The last check before the transaction opens. Cancelling mid-write would roll back
        // anyway, but not opening the transaction at all is cheaper and clearer in the log.
        cancel.check()?;

        let sources = self.source_objects_for(documents, &reports)?;
        let mut report = IngestReport {
            documents: reports,
            ..IngestReport::default()
        };

        let retention = self.retention;
        let originals = originals_for(documents);

        let counts = store.transaction(|writer| {
            let mut counts = Counts::default();

            // Evidence first, inside the same transaction as everything derived from it. A
            // canonical record that commits alongside a reference to bytes that were refused is a
            // dangling reference nothing later can repair, so the refusal has to be able to take
            // the whole batch with it.
            if let Some(retention) = retention {
                for (hash, bytes) in &originals {
                    let request = BlobRequest::new(
                        bytes,
                        retention,
                        format!("ingested source object {hash}"),
                    );
                    if writer.put_source_blob(&request)? == BlobOutcome::Deduplicated {
                        counts.deduplicated_sources = counts.deduplicated_sources.saturating_add(1);
                    } else {
                        counts.retained_sources = counts.retained_sources.saturating_add(1);
                    }
                }
            }

            for source in &sources {
                writer.upsert_source_object(source)?;
                counts.source_objects = counts.source_objects.saturating_add(1);
            }
            for document in &report.documents {
                for record in &document.records {
                    counts.record(write(writer, record)?);
                }
            }
            Ok(counts)
        })?;

        report.inserted = counts.inserted;
        report.updated = counts.updated;
        report.unchanged = counts.unchanged;
        report.source_objects = counts.source_objects;
        report.retained_sources = counts.retained_sources;
        report.deduplicated_sources = counts.deduplicated_sources;
        Ok(report)
    }

    /// Rebuild the source objects for a prepared batch, in the order they will be written.
    ///
    /// Sorted by identifier, and de-duplicated: offering the same bytes twice in one batch is a
    /// normal thing for a feed to do, and it addresses one source object, not two.
    fn source_objects_for(
        &self,
        documents: &[Document<'_>],
        reports: &[DocumentReport],
    ) -> Result<Vec<SourceObject>> {
        let mut sources: Vec<SourceObject> = Vec::with_capacity(documents.len());
        for (document, report) in documents.iter().zip(reports.iter()) {
            let byte_length = u64::try_from(document.bytes.len()).unwrap_or(u64::MAX);
            sources.push(
                SourceObject::new(
                    report.content_hash,
                    document.media_type.clone(),
                    byte_length,
                    document.retrieved_at,
                    document.origin.clone(),
                )
                .validated()?,
            );
        }
        sources.sort_by_key(|source| source.id.to_string());
        sources.dedup_by_key(|source| source.id.to_string());
        Ok(sources)
    }
}

/// Running totals inside the transaction.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    inserted: u64,
    updated: u64,
    unchanged: u64,
    source_objects: u64,
    retained_sources: u64,
    deduplicated_sources: u64,
}

impl Counts {
    fn record(&mut self, outcome: UpsertOutcome) {
        match outcome {
            UpsertOutcome::Inserted => self.inserted = self.inserted.saturating_add(1),
            UpsertOutcome::Updated => self.updated = self.updated.saturating_add(1),
            UpsertOutcome::Unchanged => self.unchanged = self.unchanged.saturating_add(1),
            // `UpsertOutcome` is `#[non_exhaustive]`. A new variant must not be silently counted
            // as one of the existing three, so it counts as nothing and the totals under-report
            // rather than mislead. Adding a variant should also update this arm.
            _ => {}
        }
    }
}

/// Write one record through the backend-neutral writer.
fn write(
    writer: &mut dyn StoreWrite,
    record: &ParsedRecord,
) -> core::result::Result<UpsertOutcome, brolga_storage::StorageError> {
    match record {
        ParsedRecord::Entity(value) => writer.upsert_entity(value),
        ParsedRecord::Relationship(value) => writer.upsert_relationship(value),
        ParsedRecord::Claim(value) => writer.upsert_claim(value),
        ParsedRecord::Sighting(value) => writer.upsert_sighting(value),
    }
}

/// Validate one record, attributing a failure to the parser and position that produced it.
fn validate(parser: ParserId, index: usize, record: ParsedRecord) -> Result<ParsedRecord> {
    let invalid = |source| IngestError::InvalidRecord {
        parser,
        index,
        source,
    };
    Ok(match record {
        ParsedRecord::Entity(value) => {
            ParsedRecord::Entity(Box::new((*value).validated().map_err(invalid)?))
        }
        ParsedRecord::Relationship(value) => {
            ParsedRecord::Relationship(Box::new((*value).validated().map_err(invalid)?))
        }
        ParsedRecord::Claim(value) => {
            ParsedRecord::Claim(Box::new((*value).validated().map_err(invalid)?))
        }
        ParsedRecord::Sighting(value) => {
            ParsedRecord::Sighting(Box::new((*value).validated().map_err(invalid)?))
        }
    })
}

/// A pipeline-contributed transformation step.
fn step(
    stage: TransformationStage,
    algorithm: &str,
) -> core::result::Result<TransformationStep, brolga_model::ModelError> {
    Ok(TransformationStep::new(
        stage,
        ShortText::new(algorithm)?,
        PIPELINE_VERSION,
    ))
}

/// The distinct original byte strings in a batch, keyed by address.
///
/// De-duplicated within the batch before the transaction opens: a feed offering the same file twice
/// in one call addresses one blob, and issuing two writes for it would make the report say two
/// things arrived when one did.
fn originals_for(documents: &[Document<'_>]) -> Vec<(ContentHash, Vec<u8>)> {
    let mut originals: Vec<(ContentHash, Vec<u8>)> = Vec::with_capacity(documents.len());
    for document in documents {
        let hash = ContentHash::of(document.bytes);
        if !originals.iter().any(|(seen, _)| *seen == hash) {
            originals.push((hash, document.bytes.to_vec()));
        }
    }
    originals.sort_by_key(|(hash, _)| hash.to_string());
    originals
}
