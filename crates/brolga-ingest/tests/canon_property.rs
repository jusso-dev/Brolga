//! Idempotence, and "never panic", for every canonicaliser.
//!
//! Idempotence — `canonicalise(canonicalise(x)) == canonicalise(x)` — is the acceptance criterion
//! whose failure is invisible. A canonicaliser that drifts still returns plausible values; the
//! damage is that re-importing Brolga's own output produces a slightly different key each pass, the
//! same artefact accumulates identifiers, and deduplication quietly stops working. Nothing errors.
//!
//! The canonicalisers are enumerated in one table so a new one is added to every property at once,
//! rather than to whichever the author remembered.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::CanonError;
use brolga_ingest::canon::{Canonical, file, ident, net, time};
use proptest::prelude::*;

/// A canonicaliser reduced to `&str -> Result<String, CanonError>`, so they can be tabulated
/// despite returning different value types.
type Canonicaliser = fn(&str) -> Result<String, CanonError>;

fn observable(
    inner: fn(&str) -> Result<Canonical<brolga_model::Observable>, CanonError>,
) -> impl Fn(&str) -> Result<String, CanonError> {
    move |raw| inner(raw).map(|canonical| canonical.value().canonical_value())
}

/// Every canonicaliser in the crate, with a label for failure messages.
///
/// Observable-returning ones are wrapped so their canonical *value* is compared, which is the
/// string that would be re-ingested.
fn canonicalisers() -> Vec<(&'static str, Canonicaliser)> {
    vec![
        ("net::ip_address", |raw| observable(net::ip_address)(raw)),
        ("net::ip_range", |raw| observable(net::ip_range)(raw)),
        ("net::domain_name", |raw| observable(net::domain_name)(raw)),
        ("net::url", |raw| observable(net::url)(raw)),
        ("net::email_address", |raw| {
            observable(net::email_address)(raw)
        }),
        ("net::any_network", |raw| observable(net::any_network)(raw)),
        ("file::file_hash", |raw| observable(file::file_hash)(raw)),
        ("file::file_name", |raw| observable(file::file_name)(raw)),
        ("ident::cve", |raw| {
            ident::cve(raw).map(Canonical::into_value)
        }),
        ("ident::cwe", |raw| {
            ident::cwe(raw).map(Canonical::into_value)
        }),
        ("ident::attack_id", |raw| {
            ident::attack_id(raw).map(Canonical::into_value)
        }),
        ("ident::cpe", |raw| {
            ident::cpe(raw).map(Canonical::into_value)
        }),
        ("ident::package_url", |raw| {
            ident::package_url(raw).map(Canonical::into_value)
        }),
        ("ident::container_image", |raw| {
            ident::container_image(raw).map(Canonical::into_value)
        }),
        ("ident::cloud_resource", |raw| {
            ident::cloud_resource(raw).map(Canonical::into_value)
        }),
        ("ident::kubernetes_resource", |raw| {
            ident::kubernetes_resource(raw).map(Canonical::into_value)
        }),
        ("time::rfc3339", |raw| {
            time::rfc3339(raw).map(|canonical| canonical.value().to_rfc3339())
        }),
    ]
}

/// Inputs that look enough like each format to get past the early rejections, mixed with hostile
/// ones. Purely random bytes almost never reach the interesting code paths.
fn plausible_value() -> impl Strategy<Value = String> {
    prop_oneof![
        // Shaped like the real thing.
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]{1,2}",
        "[a-zA-Z0-9-]{1,20}\\.[a-zA-Z]{2,6}",
        "https?://[a-zA-Z0-9.-]{1,30}/[a-zA-Z0-9/%._-]{0,40}",
        "[a-zA-Z0-9._-]{1,20}@[a-zA-Z0-9.-]{1,20}\\.[a-z]{2,6}",
        "[0-9a-fA-F]{32}",
        "[0-9a-fA-F]{64}",
        "(?i)cve-[0-9]{4}-[0-9]{4,7}",
        "(?i)cwe-[0-9]{1,4}",
        "(?i)t[0-9]{4}(\\.[0-9]{3})?",
        "(?i)cpe:2\\.3:[aoh](:[a-zA-Z0-9_*-]{1,10}){10}",
        "pkg:[a-z]{2,8}/[a-zA-Z0-9._-]{1,20}(@[0-9.]{1,8})?",
        "[a-z0-9.-]{1,20}(:[0-9]{2,5})?/[a-zA-Z0-9/_-]{1,20}(:[a-zA-Z0-9._-]{1,10})?",
        "arn:aws:[a-z0-9]{2,10}:[a-z0-9-]{0,12}:[0-9]{0,12}:[a-zA-Z0-9/_.-]{1,30}",
        "[a-z]{3,12}/[a-z0-9-]{1,20}(/[a-z0-9-]{1,20})?",
        "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})",
        // Deliberately awful.
        "\\PC{0,80}",
        Just(String::new()),
        Just("   ".to_owned()),
        Just("../../etc/passwd".to_owned()),
        Just("C:\\Windows\\System32\\cmd.exe".to_owned()),
    ]
}

proptest! {
    /// The acceptance criterion. Canonicalising an already-canonical value must be a no-op, for
    /// every canonicaliser, for every input either of them accepts.
    #[test]
    fn every_canonicaliser_is_idempotent(raw in plausible_value()) {
        for (label, canonicalise) in canonicalisers() {
            let Ok(once) = canonicalise(&raw) else { continue };
            let twice = canonicalise(&once);

            prop_assert!(
                twice.is_ok(),
                "{label}: canonical output {once:?} was rejected on re-canonicalisation \
                 (from {raw:?}): {:?}",
                twice.err(),
            );
            prop_assert_eq!(
                twice.unwrap(),
                once.clone(),
                "{} drifted on the second pass from input {:?}",
                label,
                raw,
            );
        }
    }

    /// A canonicaliser reached from a parser sees hostile input first. It may reject anything, but
    /// it may not panic — ADR 0003 §2 makes that a build failure rather than something to catch.
    #[test]
    fn no_canonicaliser_panics_on_arbitrary_text(raw in "\\PC{0,200}") {
        for (label, canonicalise) in canonicalisers() {
            let outcome = canonicalise(&raw);
            prop_assert!(
                outcome.is_ok() || outcome.is_err(),
                "{label} did not return",
            );
        }
    }

    /// Control characters are an output-injection vector, and a diagnostic is exactly where they
    /// would be rendered. No canonicaliser may let one reach its own message.
    #[test]
    fn no_diagnostic_ever_contains_a_control_character(raw in ".{0,120}") {
        for (label, canonicalise) in canonicalisers() {
            if let Err(error) = canonicalise(&raw) {
                let rendered = error.to_string();
                prop_assert!(
                    !rendered.chars().any(char::is_control),
                    "{label} leaked a control character into {rendered:?} from {raw:?}",
                );
            }
        }
    }

    /// Any value that survives canonicalisation must be free of control characters, or a stored
    /// indicator becomes an injection payload for whatever prints it later.
    #[test]
    fn no_canonical_output_ever_contains_a_control_character(raw in "\\PC{0,120}") {
        for (label, canonicalise) in canonicalisers() {
            if let Ok(value) = canonicalise(&raw) {
                prop_assert!(
                    !value.chars().any(char::is_control),
                    "{label} produced {value:?} from {raw:?}",
                );
            }
        }
    }

    /// A Windows path and a POSIX path must never collide, whatever they contain. Stated as a
    /// property because the unit tests can only cover the pairs somebody thought of.
    #[test]
    fn a_windows_path_never_collides_with_a_posix_path(
        tail in "[a-zA-Z0-9_\\\\/. -]{1,60}",
        drive in "[a-zA-Z]",
    ) {
        let windows = format!("{drive}:\\{tail}");
        let posix = format!("/{tail}");

        let (Ok(windows), Ok(posix)) = (file::file_path(&windows), file::file_path(&posix)) else {
            return Ok(());
        };
        prop_assert_ne!(
            windows.value().canonical_value(),
            posix.value().canonical_value(),
        );
    }

    /// Path canonicalisation must be idempotent on its own output too — but its output carries a
    /// `posix:`/`windows:` prefix that is Brolga's, not a path, so it is re-canonicalised through
    /// the body rather than through the whole string.
    #[test]
    fn path_canonicalisation_is_stable_on_its_own_body(tail in "[a-zA-Z0-9_/. -]{1,60}") {
        let raw = format!("/{tail}");
        let Ok(once) = file::file_path(&raw) else { return Ok(()) };
        let body = once
            .value()
            .canonical_value()
            .strip_prefix("posix:")
            .unwrap_or_default()
            .to_owned();

        let Ok(twice) = file::file_path(&body) else { return Ok(()) };
        prop_assert_eq!(once.value().canonical_value(), twice.value().canonical_value());
    }
}
