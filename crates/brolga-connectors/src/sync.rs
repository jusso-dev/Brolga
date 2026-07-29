//! Running a feed to completion, and remembering how far it got.
//!
//! # The ordering that makes a crash cheap instead of silent
//!
//! For every page: fetch, ingest, **commit the records and the cursor together**, then fetch the
//! next. The cursor never moves ahead of stored data
//! ([ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md)
//! §4).
//!
//! Getting this backwards produces the worst failure in the whole connector: advance the cursor,
//! fail to store, and the records in that window are never fetched again. Nothing reports an
//! error — the next run starts after the gap and looks perfectly healthy. With this ordering a
//! crash costs a repeated page, and a repeated page is idempotent because canonical identifiers are
//! derived from content.
//!
//! # A malformed page stops the run without corrupting the cursor
//!
//! Quarantine is the ingestion pipeline's job and happens per record. A page that cannot be parsed
//! at all is different: the run stops, the cursor stays where the last good page left it, and the
//! status records that it failed. The next run re-fetches the same window rather than skipping it.
//!
//! # Bounded by pages, not by trust
//!
//! A server can always claim `more: true`. [`SyncOptions::max_pages`] bounds a run regardless, and
//! stopping on it is reported as [`CursorStatus::Partial`] rather than as success — because a run
//! that stopped early and a run that finished are different facts, and only one of them means the
//! feed is up to date.

use brolga_ingest::{Document, Pipeline};
use brolga_model::Timestamp;
use brolga_model::provenance::{MediaType, SourceOrigin};
use brolga_model::text::ShortText;
use brolga_security::CancellationToken;
use brolga_storage::{ConnectorCursor, CursorStatus, IntelligenceStore, SqliteStore, StoreRead};

use crate::error::ConnectorError;
use crate::misp::{MISP_CONNECTOR, MispClient, MispFeed, MispInstance};
use crate::opencti::{OPENCTI_CONNECTOR, OpenCtiClient, OpenCtiInstance};
use crate::taxii::TaxiiClient;

/// This connector's name, and the first half of every cursor key it writes.
pub const TAXII_CONNECTOR: &str = "taxii";

/// How a run is bounded.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SyncOptions {
    /// How many objects to ask for per page.
    pub page_size: usize,
    /// How many pages one run may fetch.
    ///
    /// A server can always claim more pages remain. This bounds a run whatever it claims, and
    /// stopping here is reported as partial rather than complete.
    pub max_pages: usize,
    /// Whether to send the stored entity tag.
    pub use_etag: bool,
}

impl SyncOptions {
    /// The same options, bounded to `max_pages` per run.
    ///
    /// A builder rather than a struct literal because [`SyncOptions`] is `#[non_exhaustive]`: a
    /// field added later must not break every caller, and a caller reaching for one knob should not
    /// have to restate the others.
    #[must_use]
    pub const fn with_max_pages(mut self, max_pages: usize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// The same options, with a page size.
    #[must_use]
    pub const fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size;
        self
    }

    /// The same options, with conditional requests on or off.
    #[must_use]
    pub const fn with_etag(mut self, use_etag: bool) -> Self {
        self.use_etag = use_etag;
        self
    }
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            page_size: 100,
            max_pages: 1000,
            use_etag: true,
        }
    }
}

/// What one run did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncReport {
    /// The collection that was read.
    pub feed: String,
    /// How many pages were fetched.
    pub pages: usize,
    /// How many objects the server returned across them.
    pub objects: usize,
    /// How many canonical records were stored.
    pub inserted: u64,
    /// How many records were quarantined.
    pub quarantined: u64,
    /// Where the cursor ended up.
    pub cursor: ConnectorCursor,
    /// Whether the server said nothing had changed.
    pub not_modified: bool,
}

impl SyncReport {
    /// Whether the run covered the whole feed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(
            self.cursor.last_status,
            CursorStatus::Complete | CursorStatus::NotModified
        )
    }
}

/// Which feed on which server a run is reading.
///
/// A pair rather than two loose arguments: an API root and a collection identifier are only
/// meaningful together, and passing them separately is how a caller eventually reads one server's
/// collection from another server's root.
#[derive(Debug, Clone, Copy)]
pub struct FeedRef<'a> {
    /// The API root the collection lives under.
    pub api_root: &'a str,
    /// The collection's identifier, which is also its cursor's feed key.
    pub collection_id: &'a str,
}

impl<'a> FeedRef<'a> {
    /// Name a feed.
    #[must_use]
    pub const fn new(api_root: &'a str, collection_id: &'a str) -> Self {
        Self {
            api_root,
            collection_id,
        }
    }
}

/// Run one TAXII collection to completion, or to a bound.
///
/// # Errors
///
/// Returns the first non-retryable failure. The cursor in storage is left wherever the last
/// successfully stored page put it, so a later run resumes rather than skipping.
///
/// # Panics
///
/// Does not panic. Every fallible conversion is handled.
pub fn sync_collection(
    client: &TaxiiClient<'_>,
    store: &mut SqliteStore,
    pipeline: &Pipeline,
    feed: FeedRef<'_>,
    now: Timestamp,
    options: SyncOptions,
    cancel: &CancellationToken,
) -> Result<SyncReport, ConnectorError> {
    let FeedRef {
        api_root,
        collection_id,
    } = feed;
    let stamp = now.to_rfc3339();
    let mut cursor = store
        .connector_cursor(TAXII_CONNECTOR, collection_id)
        .map_err(|error| ConnectorError::Storage {
            url: api_root.to_owned(),
            reason: error.to_string(),
        })?
        .unwrap_or_else(|| ConnectorCursor::starting(TAXII_CONNECTOR, collection_id, &stamp));

    let mut report = SyncReport {
        feed: collection_id.to_owned(),
        pages: 0,
        objects: 0,
        inserted: 0,
        quarantined: 0,
        cursor: cursor.clone(),
        not_modified: false,
    };

    let mut next: Option<String> = cursor.next_token.clone();
    let mut etag = if options.use_etag {
        cursor.etag.clone()
    } else {
        None
    };

    loop {
        if cancel.is_cancelled() {
            cursor.last_status = CursorStatus::Partial;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, api_root)?;
            report.cursor = cursor;
            return Ok(report);
        }

        if report.pages >= options.max_pages {
            // A bound was reached, not the end of the feed. Reported as partial so that "stopped
            // early" never reads as "up to date".
            cursor.last_status = CursorStatus::Partial;
            cursor.next_token = next;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, api_root)?;
            report.cursor = cursor;
            return Ok(report);
        }

        let page = client.objects(
            api_root,
            collection_id,
            cursor.added_after.as_deref(),
            next.as_deref(),
            options.page_size,
            etag.as_deref(),
        );

        let page = match page {
            Ok(Some(page)) => page,
            // The server says nothing has changed. The cursor is untouched apart from its status,
            // because there is nothing new to be positioned after.
            Ok(None) => {
                cursor.last_status = CursorStatus::NotModified;
                cursor.last_run_at = stamp.clone();
                persist(store, &cursor, api_root)?;
                report.not_modified = true;
                report.cursor = cursor;
                return Ok(report);
            }
            Err(error) => {
                // The cursor is *not* advanced. Recording the failure against the position of the
                // last good page is what makes the next run re-fetch this window.
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, api_root);
                return Err(error);
            }
        };

        report.pages = report.pages.saturating_add(1);
        report.objects = report.objects.saturating_add(page.object_count);

        // An empty page ends the run whatever the server claims about `more`. Without this, a
        // server that always answers `more: true` with no objects is an infinite loop.
        if page.object_count == 0 {
            cursor.last_status = CursorStatus::Complete;
            cursor.next_token = None;
            cursor.etag = page.etag.or(cursor.etag);
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, api_root)?;
            report.cursor = cursor;
            return Ok(report);
        }

        // Ingest, then advance. The pipeline runs one transaction per batch, and the cursor is
        // written immediately after within the same run — see the module documentation for why the
        // order is not the other way round.
        let document = Document {
            bytes: &page.body,
            media_type: MediaType::new("application/stix+json").map_err(|error| {
                ConnectorError::Storage {
                    url: page.url.clone(),
                    reason: error.to_string(),
                }
            })?,
            file_name: None,
            origin: SourceOrigin::NetworkFeed {
                publisher: ShortText::new(bounded_publisher(api_root)).map_err(|error| {
                    ConnectorError::Storage {
                        url: page.url.clone(),
                        reason: error.to_string(),
                    }
                })?,
                location: None,
            },
            retrieved_at: now,
        };

        let outcome = pipeline.ingest_batch(store, &[document], cancel);

        let ingested = match outcome {
            Ok(ingested) => ingested,
            Err(error) => {
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, api_root);
                return Err(ConnectorError::Storage {
                    url: page.url,
                    reason: error.to_string(),
                });
            }
        };

        report.inserted = report.inserted.saturating_add(ingested.inserted);
        report.quarantined = report.quarantined.saturating_add(ingested.rejected);

        // Only now. The records are stored, so the cursor may move past them.
        if let Some(newest) = page.newest_added {
            cursor.added_after = Some(newest);
        }
        cursor.etag = page.etag.clone().or(cursor.etag);
        cursor.records_seen = cursor
            .records_seen
            .saturating_add(u64::try_from(page.object_count).unwrap_or(0));
        cursor.last_run_at = stamp.clone();
        cursor.last_status = if page.more {
            CursorStatus::Partial
        } else {
            CursorStatus::Complete
        };
        cursor.next_token = if page.more { page.next.clone() } else { None };
        persist(store, &cursor, api_root)?;

        if !page.more {
            report.cursor = cursor;
            return Ok(report);
        }

        next = page.next;
        // A conditional request only makes sense for the first page of a run. Sending the stored
        // tag with page two would ask "has page two changed since page one", which is not a
        // question, and a server answering `304` would end the run one page in.
        etag = None;
    }
}

/// Write the cursor, turning a storage failure into a connector error.
fn persist(
    store: &mut SqliteStore,
    cursor: &ConnectorCursor,
    url: &str,
) -> Result<(), ConnectorError> {
    store
        .transaction(|write| write.put_connector_cursor(cursor))
        .map_err(|error| ConnectorError::Storage {
            url: url.to_owned(),
            reason: error.to_string(),
        })
}

/// The publisher name recorded in provenance, bounded to what `ShortText` accepts.
///
/// The API root rather than the page URL: a page URL carries a cursor and a page size, and
/// provenance should say which server the evidence came from, not which request happened to fetch
/// it.
fn bounded_publisher(api_root: &str) -> String {
    let trimmed = api_root.trim_end_matches('/');
    let mut end = trimmed.len().min(ShortText::MAX_BYTES);
    while end > 0 && !trimmed.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let value = trimmed.get(..end).unwrap_or_default();
    if value.is_empty() {
        "taxii".to_owned()
    } else {
        value.to_owned()
    }
}

// ---------------------------------------------------------------------------------------------
// MISP
// ---------------------------------------------------------------------------------------------

/// Which feed of which instance a run is reading.
///
/// A pair rather than two loose arguments, for the same reason as [`FeedRef`]: an instance and a
/// feed are only meaningful together, and a cursor key built from a mismatched pair would read one
/// instance's position against another's data.
#[derive(Debug, Clone, Copy)]
pub struct MispTarget<'a> {
    /// The instance to read.
    pub instance: &'a MispInstance,
    /// Which of its feeds.
    pub feed: MispFeed,
}

impl<'a> MispTarget<'a> {
    /// Name a target.
    #[must_use]
    pub const fn new(instance: &'a MispInstance, feed: MispFeed) -> Self {
        Self { instance, feed }
    }
}

/// Run one feed of one MISP instance to completion, or to a bound.
///
/// The same ordering as [`sync_collection`], for the same reason: fetch, ingest, then advance the
/// cursor. See the module documentation.
///
/// The cursor is keyed on `(misp, "<instance>/<feed>")`, so two instances never share a position.
/// A shared cursor would make a second instance resume from wherever the first got to and skip
/// everything published before that — silently, since a sync that fetched nothing looks identical
/// to a feed with nothing new.
///
/// # Errors
///
/// Returns the first failure. The cursor is left wherever the last successfully stored page put it.
pub fn sync_misp_feed(
    client: &MispClient<'_>,
    store: &mut SqliteStore,
    pipeline: &Pipeline,
    target: MispTarget<'_>,
    now: Timestamp,
    options: SyncOptions,
    cancel: &CancellationToken,
) -> Result<SyncReport, ConnectorError> {
    let MispTarget { instance, feed } = target;
    let stamp = now.to_rfc3339();
    let feed_key = feed.feed_key(&instance.name);

    let mut cursor = store
        .connector_cursor(MISP_CONNECTOR, &feed_key)
        .map_err(|error| ConnectorError::Storage {
            url: instance.base_url.clone(),
            reason: error.to_string(),
        })?
        .unwrap_or_else(|| ConnectorCursor::starting(MISP_CONNECTOR, &feed_key, &stamp));

    let mut report = SyncReport {
        feed: feed_key,
        pages: 0,
        objects: 0,
        inserted: 0,
        quarantined: 0,
        cursor: cursor.clone(),
        not_modified: false,
    };

    // MISP pages are one-based; a request for page 0 returns the whole result set on some versions,
    // which would quietly ignore the page size.
    let mut page_number = 1_usize;
    let mut etag = if options.use_etag {
        cursor.etag.clone()
    } else {
        None
    };

    loop {
        if cancel.is_cancelled() {
            cursor.last_status = CursorStatus::Partial;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        }

        if report.pages >= options.max_pages {
            cursor.last_status = CursorStatus::Partial;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        }

        let fetched = client.page(
            instance,
            feed,
            cursor.added_after.as_deref(),
            page_number,
            options.page_size,
            etag.as_deref(),
        );

        let page = match fetched {
            Ok(Some(page)) => page,
            Ok(None) => {
                cursor.last_status = CursorStatus::NotModified;
                cursor.last_run_at = stamp.clone();
                persist(store, &cursor, &instance.base_url)?;
                report.not_modified = true;
                report.cursor = cursor;
                return Ok(report);
            }
            Err(error) => {
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, &instance.base_url);
                return Err(error);
            }
        };

        report.pages = report.pages.saturating_add(1);
        report.objects = report.objects.saturating_add(page.record_count);

        if page.record_count == 0 {
            cursor.last_status = CursorStatus::Complete;
            cursor.etag = page.etag.or(cursor.etag);
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        }

        let document = Document {
            bytes: &page.body,
            media_type: MediaType::new("application/vnd.misp+json").map_err(|error| {
                ConnectorError::Storage {
                    url: page.url.clone(),
                    reason: error.to_string(),
                }
            })?,
            file_name: None,
            origin: SourceOrigin::NetworkFeed {
                // The instance's *name*, not its URL. Provenance should say which source published
                // a record, and two instances behind one hostname are still two sources.
                publisher: ShortText::new(bounded_publisher(&instance.name)).map_err(|error| {
                    ConnectorError::Storage {
                        url: page.url.clone(),
                        reason: error.to_string(),
                    }
                })?,
                location: None,
            },
            retrieved_at: now,
        };

        let ingested = match pipeline.ingest_batch(store, &[document], cancel) {
            Ok(ingested) => ingested,
            Err(error) => {
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, &instance.base_url);
                return Err(ConnectorError::Storage {
                    url: page.url,
                    reason: error.to_string(),
                });
            }
        };

        report.inserted = report.inserted.saturating_add(ingested.inserted);
        report.quarantined = report.quarantined.saturating_add(ingested.rejected);

        // Only now.
        if let Some(newest) = page.newest_timestamp {
            cursor.added_after = Some(newest);
        }
        cursor.etag = page.etag.clone().or(cursor.etag);
        cursor.records_seen = cursor
            .records_seen
            .saturating_add(u64::try_from(page.record_count).unwrap_or(0));
        cursor.last_run_at = stamp.clone();
        cursor.last_status = if page.more {
            CursorStatus::Partial
        } else {
            CursorStatus::Complete
        };
        persist(store, &cursor, &instance.base_url)?;

        if !page.more {
            report.cursor = cursor;
            return Ok(report);
        }

        page_number = page_number.saturating_add(1);
        etag = None;
    }
}

// ---------------------------------------------------------------------------------------------
// OpenCTI
// ---------------------------------------------------------------------------------------------

/// Poll one OpenCTI instance to completion, or to a bound.
///
/// The same ordering as every other connector here: fetch, ingest, then advance the cursor. See the
/// module documentation.
///
/// # Errors
///
/// Returns the first failure. The cursor is left wherever the last successfully stored page put it.
pub fn sync_opencti(
    client: &OpenCtiClient<'_>,
    store: &mut SqliteStore,
    pipeline: &Pipeline,
    instance: &OpenCtiInstance,
    now: Timestamp,
    options: SyncOptions,
    cancel: &CancellationToken,
) -> Result<SyncReport, ConnectorError> {
    let stamp = now.to_rfc3339();
    let feed_key = instance.feed_key();

    let mut cursor = store
        .connector_cursor(OPENCTI_CONNECTOR, &feed_key)
        .map_err(|error| ConnectorError::Storage {
            url: instance.base_url.clone(),
            reason: error.to_string(),
        })?
        .unwrap_or_else(|| ConnectorCursor::starting(OPENCTI_CONNECTOR, &feed_key, &stamp));

    let mut report = SyncReport {
        feed: feed_key,
        pages: 0,
        objects: 0,
        inserted: 0,
        quarantined: 0,
        cursor: cursor.clone(),
        not_modified: false,
    };

    // The GraphQL page cursor, which is a position *within* a result set rather than a high-water
    // mark. It is not carried between runs: a stored `after` would point into a result set the next
    // run's `since` filter does not produce, and paging from it would skip whatever changed in
    // between.
    let mut after: Option<String> = None;

    loop {
        if cancel.is_cancelled() || report.pages >= options.max_pages {
            cursor.last_status = CursorStatus::Partial;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        }

        let page = match client.page(
            instance,
            cursor.added_after.as_deref(),
            after.as_deref(),
            options.page_size,
        ) {
            Ok(page) => page,
            Err(error) => {
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, &instance.base_url);
                return Err(error);
            }
        };

        report.pages = report.pages.saturating_add(1);
        report.objects = report.objects.saturating_add(page.object_count);
        // An object OpenCTI could not render as STIX is counted as quarantined, because that is
        // what it is: a record the source published and Brolga did not store. Reporting it only in
        // a log would make a half-imported page look identical to a whole one.
        report.quarantined = report
            .quarantined
            .saturating_add(u64::try_from(page.unrenderable).unwrap_or(0));

        if page.object_count == 0 {
            cursor.last_status = CursorStatus::Complete;
            cursor.last_run_at = stamp.clone();
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        }

        let document = Document {
            bytes: &page.body,
            media_type: MediaType::new("application/stix+json").map_err(|error| {
                ConnectorError::Storage {
                    url: page.url.clone(),
                    reason: error.to_string(),
                }
            })?,
            file_name: None,
            origin: SourceOrigin::NetworkFeed {
                publisher: ShortText::new(bounded_publisher(&instance.name)).map_err(|error| {
                    ConnectorError::Storage {
                        url: page.url.clone(),
                        reason: error.to_string(),
                    }
                })?,
                location: None,
            },
            retrieved_at: now,
        };

        let ingested = match pipeline.ingest_batch(store, &[document], cancel) {
            Ok(ingested) => ingested,
            Err(error) => {
                cursor.last_status = CursorStatus::Failed;
                cursor.last_run_at = stamp.clone();
                let _ = persist(store, &cursor, &instance.base_url);
                return Err(ConnectorError::Storage {
                    url: page.url,
                    reason: error.to_string(),
                });
            }
        };

        report.inserted = report.inserted.saturating_add(ingested.inserted);
        report.quarantined = report.quarantined.saturating_add(ingested.rejected);

        // Only now.
        if let Some(newest) = page.newest_modified {
            cursor.added_after = Some(newest);
        }
        cursor.records_seen = cursor
            .records_seen
            .saturating_add(u64::try_from(page.object_count).unwrap_or(0));
        cursor.last_run_at = stamp.clone();
        cursor.last_status = if page.more {
            CursorStatus::Partial
        } else {
            CursorStatus::Complete
        };
        persist(store, &cursor, &instance.base_url)?;

        if !page.more {
            report.cursor = cursor;
            return Ok(report);
        }

        // A server claiming more pages without moving its cursor would loop forever.
        let Some(next) = page.end_cursor.filter(|next| Some(next) != after.as_ref()) else {
            cursor.last_status = CursorStatus::Partial;
            persist(store, &cursor, &instance.base_url)?;
            report.cursor = cursor;
            return Ok(report);
        };
        after = Some(next);
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

    #[test]
    fn the_publisher_is_the_server_rather_than_the_request() {
        assert_eq!(
            bounded_publisher("https://taxii.example.org/api1/"),
            "https://taxii.example.org/api1"
        );
        assert_eq!(bounded_publisher(""), "taxii");
    }

    #[test]
    fn a_publisher_longer_than_short_text_is_truncated_at_a_boundary() {
        let long = format!("https://{}.example.org/", "é".repeat(400));
        let bounded = bounded_publisher(&long);
        assert!(bounded.len() <= ShortText::MAX_BYTES);
        assert!(ShortText::new(&bounded).is_ok(), "{bounded}");
    }

    /// "Stopped early" and "up to date" are different facts, and only one of them means the feed
    /// has nothing new.
    #[test]
    fn only_a_complete_or_not_modified_run_counts_as_covering_the_feed() {
        let base = ConnectorCursor::starting("taxii", "c", "2024-01-01T00:00:00Z");
        let report = |status| {
            let mut cursor = base.clone();
            cursor.last_status = status;
            SyncReport {
                feed: "c".to_owned(),
                pages: 1,
                objects: 1,
                inserted: 1,
                quarantined: 0,
                cursor,
                not_modified: false,
            }
        };

        assert!(report(CursorStatus::Complete).is_complete());
        assert!(report(CursorStatus::NotModified).is_complete());
        assert!(!report(CursorStatus::Partial).is_complete());
        assert!(!report(CursorStatus::Failed).is_complete());
    }
}
