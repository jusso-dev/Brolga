//! The entry points every fuzz target calls, and the corpus replay calls too.
//!
//! # Why the bodies live here rather than in the targets
//!
//! A `fuzz_target!` body only ever runs under `cargo fuzz`, which needs nightly. If the interesting
//! logic lived there, then on a stable toolchain — which is what CI uses, and what
//! [ADR 0002](../../docs/adr/0002-raise-msrv-to-1-88-for-a-security-advisory.md) pins the MSRV job to
//! — nothing would check that the harness still compiles or that the checked-in corpus still goes
//! through it. The harness would rot, silently, until somebody next installed nightly.
//!
//! So each target is three lines around a call into this module, and `tests/corpus.rs` replays every
//! checked-in seed through **the same functions** on stable. The two cannot diverge, because there is
//! only one body.
//!
//! # The properties, and why each is more than "does not crash"
//!
//! "No panic" is the baseline and it is worth having — ADR 0003 §2 makes panicking an unsupported way
//! to reject input, and `panic = "abort"` in release means a parser panic kills the process. But a
//! fuzzer that only checks for crashes finds only crashes, and the bugs that matter here are quieter:
//!
//! - A canonicaliser that is **not idempotent** produces a different identifier on re-ingest, so one
//!   indicator becomes two observables and correlation stops working. Nothing crashes.
//! - A canonical value carrying a **control character** is an injection surface everywhere it is
//!   rendered — a table, a log line, a pack an analyst pastes into a ticket.
//! - An **escaper that lets one character through** is an injection into whatever parses the output:
//!   a spreadsheet's formula evaluator, a Markdown renderer, Graphviz, a YAML reader.
//! - A **mapping that loads without validating** would fail partway through a document instead of at
//!   load time, which is the whole safety argument for the mapping engine.
//!
//! Each is asserted below, so a fuzzer can actually find them.
//!
//! # Nothing here reads a file, opens a socket, or writes anything
//!
//! Every function takes bytes and returns. That is what makes the corpus replay safe to run in CI and
//! what keeps a fuzz finding reproducible from the input alone.

use brolga_ingest::canon;
use brolga_ingest::detect::FormatHint;
use brolga_ingest::formats::{delimited, sigma, stix, stix_pattern};
use brolga_ingest::mapping::Mapping;
use brolga_ingest::{Document, IngestMode, ParserRegistry, Pipeline};
use brolga_model::provenance::{MediaType, SourceOrigin};
use brolga_model::{ShortText, Timestamp};
use brolga_security::CancellationToken;

/// The media types each input is offered under.
///
/// Several rather than one, because detection consults the media type and a parser reached only via a
/// declared type would otherwise never be fuzzed. `application/octet-stream` forces content sniffing;
/// the others take the media-type shortcut.
pub const MEDIA_TYPES: &[&str] = &[
    "application/octet-stream",
    "text/plain",
    "application/json",
    "application/xml",
];

/// Every parser this build ships.
///
/// The same set the binary registers. Built per call rather than cached: a fuzz iteration must not
/// inherit state from the previous one, or a finding becomes unreproducible.
#[must_use]
pub fn shipping_registry() -> ParserRegistry {
    let mut registry = ParserRegistry::new();
    registry.register(stix::StixParser::boxed());
    registry.register(delimited::DelimitedParser::boxed());
    registry.register(delimited::JsonLinesParser::boxed());
    registry.register(sigma::SigmaParser::boxed());
    registry
}

/// Offer the bytes to every parser, under every media type.
///
/// Returns how many of the attempts produced a document report, which the caller ignores — the value
/// exists so the work cannot be optimised away.
pub fn parse_with_every_parser(data: &[u8]) -> usize {
    let mut accepted = 0usize;
    for media_type in MEDIA_TYPES {
        let Ok(media_type) = MediaType::new(*media_type) else {
            continue;
        };
        let Ok(publisher) = ShortText::new("fuzz") else {
            continue;
        };
        let document = Document {
            bytes: data,
            media_type,
            file_name: None,
            origin: SourceOrigin::NetworkFeed {
                publisher,
                location: None,
            },
            retrieved_at: Timestamp::unix_epoch(),
        };

        // Permissive, so a malformed record is quarantined rather than failing the document — which
        // exercises the rejection path as well as the acceptance one.
        let pipeline = Pipeline::with_defaults(shipping_registry()).in_mode(IngestMode::Permissive);
        if pipeline
            .prepare(&document, &CancellationToken::never_cancelled())
            .is_ok()
        {
            accepted = accepted.saturating_add(1);
        }
    }

    // Detection on its own, too: `prepare` stops at the first claim, so a parser that declines is
    // never asked twice and its `detect` is the only code of it that runs.
    let hint = FormatHint::new(
        "application/octet-stream",
        Some("fuzz.bin"),
        data,
        u64::try_from(data.len()).unwrap_or(u64::MAX),
    );
    let registry = shipping_registry();
    let first = registry.candidates(&hint);
    let second = registry.candidates(&hint);
    assert_eq!(
        first.len(),
        second.len(),
        "detection is not deterministic for one input"
    );

    accepted
}

/// Run every canonicaliser, and check idempotency and output cleanliness.
///
/// # What is compared
///
/// [`brolga_model::Observable::canonical_value`], not the observable's `Display`. `Display` renders
/// `file_path:posix:/etc/passwd` — a *typed* form, for a human — and feeding that back in would
/// canonicalise the type prefix as part of the value. Comparing display forms reports every
/// canonicaliser as non-idempotent, which is an oracle bug rather than a finding.
///
/// # No input appears in a failure message
///
/// Every assertion below names the canonicaliser and the lengths involved, never the value. A fuzz
/// oracle's message reaches a public CI log, and a corpus seed is by construction a hostile input — a
/// crash report carrying one is a working exploit published where anybody can read it. libFuzzer writes
/// the crashing input to its own artefact file, which is where it belongs: on the machine running the
/// fuzzer, not in a log.
///
/// # Panics
///
/// Panics — deliberately, because this is a fuzz oracle — if a canonicaliser is not idempotent or emits
/// a control character. Both are silent correctness bugs that no crash would reveal.
pub fn canonicalise_every_way(text: &str) {
    // `file_path` is checked separately below. Its canonical value carries a `posix:`/`windows:`
    // prefix that is Brolga's own and is not part of any path, so re-feeding the whole string
    // canonicalises the prefix as part of the value. That is intended — the flavour is what stops a
    // Windows path colliding with a POSIX one — and it means the naive idempotency oracle does not
    // apply. The body-stability property that *does* apply is asserted at the end.
    for (label, canonicalise) in canonicalisers()
        .into_iter()
        .filter(|(label, _)| *label != "file_path")
    {
        let Ok(first) = canonicalise(text) else {
            continue;
        };
        // The re-ingestable string, not the display form. See the note above.
        let canonical = first.value().canonical_value();

        // Idempotency: canonicalising a canonical value returns it unchanged. A canonicaliser that is
        // not idempotent gives one indicator two identifiers across re-ingests.
        match canonicalise(&canonical) {
            Ok(second) => {
                let again = second.value().canonical_value();
                assert!(
                    canonical == again,
                    "`{label}` is not idempotent: a {}-byte input canonicalised to {} bytes and then \
                     to {} bytes",
                    text.len(),
                    canonical.len(),
                    again.len()
                );
            }
            Err(_) => panic!(
                "`{label}` accepted a {}-byte input and then refused its own {}-byte output",
                text.len(),
                canonical.len()
            ),
        }

        // A canonical value is rendered in tables, logs, and packs. One carrying a terminal escape is
        // an injection surface in all three.
        assert!(
            !canonical.chars().any(char::is_control),
            "`{label}` produced a control character from a {}-byte input",
            text.len()
        );
    }

    // `file_path`, on its own terms: canonicalising the *body* of a canonical path reproduces the
    // same canonical path. Same guarantee, stated for the shape the value actually has.
    if let Ok(once) = canon::file::file_path(text) {
        let canonical = once.value().canonical_value();
        let body = canonical
            .strip_prefix("posix:")
            .or_else(|| canonical.strip_prefix("windows:"))
            .unwrap_or_default();
        if !body.is_empty()
            && let Ok(twice) = canon::file::file_path(body)
        {
            assert!(
                canonical == twice.value().canonical_value(),
                "`file_path` is not stable on its own body, from a {}-byte input",
                text.len()
            );
        }
        assert!(
            !canonical.chars().any(char::is_control),
            "`file_path` produced a control character from a {}-byte input",
            text.len()
        );
    }

    // The identifier canonicalisers, which return strings rather than observables.
    for (label, canonicalise) in identifier_canonicalisers() {
        let Ok(first) = canonicalise(text) else {
            continue;
        };
        let canonical = first.into_value();
        match canonicalise(&canonical) {
            Ok(second) => {
                let again = second.into_value();
                assert!(
                    canonical == again,
                    "`{label}` is not idempotent for a {}-byte input",
                    text.len()
                );
            }
            Err(_) => panic!(
                "`{label}` refused its own {}-byte output",
                canonical.len()
            ),
        }
        assert!(
            !canonical.chars().any(char::is_control),
            "`{label}` produced a control character from a {}-byte input",
            text.len()
        );
    }
}

/// The observable canonicalisers, by name.
#[must_use]
pub fn canonicalisers() -> Vec<(&'static str, canon::Canonicaliser)> {
    vec![
        ("ip_address", canon::net::ip_address),
        ("ip_range", canon::net::ip_range),
        ("domain_name", canon::net::domain_name),
        ("url", canon::net::url),
        ("email_address", canon::net::email_address),
        ("any_network", canon::net::any_network),
        ("file_hash", canon::file::file_hash),
        ("file_name", canon::file::file_name),
        ("file_path", canon::file::file_path),
    ]
}

/// The identifier canonicalisers, by name.
type IdentifierCanonicaliser = fn(&str) -> Result<canon::Canonical<String>, canon::CanonError>;

/// The identifier canonicalisers, by name.
#[must_use]
pub fn identifier_canonicalisers() -> Vec<(&'static str, IdentifierCanonicaliser)> {
    vec![
        ("cve", canon::ident::cve),
        ("cwe", canon::ident::cwe),
        ("attack_id", canon::ident::attack_id),
        ("cpe", canon::ident::cpe),
        ("package_url", canon::ident::package_url),
        ("container_image", canon::ident::container_image),
        ("cloud_resource", canon::ident::cloud_resource),
        ("kubernetes_resource", canon::ident::kubernetes_resource),
    ]
}

/// Read a STIX pattern, and check that reading it twice gives the same answer.
///
/// # Panics
///
/// Panics if the reader is not deterministic, or if a pattern it accepted names no observable — an
/// accepted pattern that yields nothing is a pattern the caller would treat as empty rather than as
/// unreadable, which loses an indicator silently.
pub fn read_stix_pattern(text: &str) {
    let first = stix_pattern::observables_of(text);
    let second = stix_pattern::observables_of(text);

    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(
                first.len(),
                second.len(),
                "the pattern reader is not deterministic for a {}-byte input",
                text.len()
            );
            assert!(
                !first.is_empty(),
                "the reader accepted a {}-byte pattern and named no observable, which a caller \
                 would read as an empty indicator rather than an unreadable one",
                text.len()
            );
        }
        (Err(_), Err(_)) => {}
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => panic!(
            "the pattern reader disagreed with itself for a {}-byte input",
            text.len()
        ),
    }
}

/// Load a mapping document.
///
/// # Panics
///
/// Panics if a mapping loads and then fails its own validation, because `Mapping::load` validates and
/// the engine's whole safety argument is that a loaded mapping is a runnable one.
pub fn load_mapping(data: &[u8]) {
    let Ok(mapping) = Mapping::load(data) else {
        return;
    };
    assert!(
        mapping.validate().is_ok(),
        "a mapping loaded and then failed its own validation: {}",
        mapping.id
    );
    // A loaded mapping names exactly one subject; the validator guarantees it, and the engine relies
    // on it rather than re-checking per record.
    assert!(
        mapping.subject_field().is_some(),
        "a validated mapping has no subject field: {}",
        mapping.id
    );
}

/// Run every export escaper, and check that its own invariant holds.
///
/// # Panics
///
/// Panics if an escaper lets through the character it exists to neutralise. Each is the single point
/// at which feed text reaches a language another program parses.
pub fn escape_every_way(text: &str) {
    use brolga_export::{markdown, stix};

    // Markdown: no unescaped inline-active character, and no newline — the second is what stops a
    // block marker reaching the first column.
    let rendered = markdown::escape(text);
    for active in ['[', ']', '`', '*', '_', '<', '>', '|'] {
        assert!(
            !has_unescaped(&rendered, active),
            "`{active}` is unescaped in Markdown output, from a {}-byte input",
            text.len()
        );
    }
    assert!(
        !rendered.contains('\n') && !rendered.contains('\r'),
        "a newline survived Markdown escaping, from a {}-byte input",
        text.len()
    );

    // STIX pattern: no unescaped single quote, which would close the literal.
    let pattern = stix::escape_pattern(text);
    assert!(
        !has_unescaped(&pattern, '\''),
        "a STIX pattern literal can be closed early, from a {}-byte input",
        text.len()
    );
}

/// Whether `needle` appears in `value` without an odd-length run of backslashes before it.
///
/// Counting escapes rather than looking at the single preceding character, because `\\"` is an escaped
/// backslash followed by a *live* quote — the case a naive check misses and an attacker uses.
#[must_use]
pub fn has_unescaped(value: &str, needle: char) -> bool {
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        if character == needle && backslashes.is_multiple_of(2) {
            return true;
        }
        backslashes = 0;
    }
    false
}
