//! Replay the checked-in seed corpus through every fuzz entry point, on a stable toolchain.
//!
//! # Why this test exists at all
//!
//! `cargo fuzz` needs nightly. CI builds on stable, and the MSRV job builds on 1.88.0. So without this
//! file, a stable CI run would check nothing about the harness: not that it compiles, not that the
//! corpus is still readable, not that the oracles still hold. The harness would rot silently until
//! somebody next installed nightly, which for a fuzzing harness is the normal outcome and the reason
//! most of them are broken.
//!
//! This runs on every push, through the same functions the fuzz targets call, so there is exactly one
//! body per property and it is exercised whether or not anyone runs a fuzzer.
//!
//! # What a failure here reports
//!
//! The seed's **name**, never its bytes. [#56](https://github.com/jusso-dev/Brolga/issues/56) requires
//! that CI publish actionable failures without leaking fixture content, and a fuzz corpus is exactly
//! the material that must not appear in a public build log: a seed is a hostile input, and a crash
//! report containing one is a working exploit published in a log anybody can read.
//!
//! A name and a byte length are enough to reproduce locally, which is what actionable means.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// Where the seeds live.
///
/// Shared with `brolga-ingest`'s property tests rather than duplicated: two copies of a corpus is two
/// corpora, and the one nobody updates is the one that stops finding things.
fn corpus_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/brolga-ingest/tests/fixtures/fuzz-seeds")
}

/// Every seed, as a name and its bytes.
///
/// The `README.md` in the directory is skipped: it documents the corpus rather than being part of it.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let directory = corpus_directory();
    let entries = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("the seed corpus must exist at {}: {error}", directory.display()));

    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in entries {
        let entry = entry.expect("a readable directory entry");
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if name == "README.md" || !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("seed `{name}` must be readable: {error}")
        });
        seeds.push((name, bytes));
    }
    seeds.sort_by(|left, right| left.0.cmp(&right.0));
    seeds
}

/// A failure line that names the seed and its size, and nothing else.
///
/// The whole point: reproducible without publishing the input.
fn describe(name: &str, bytes: &[u8]) -> String {
    format!(
        "seed `{name}` ({} bytes) — reproduce with: cargo test --manifest-path fuzz/Cargo.toml",
        bytes.len()
    )
}

/// **The criterion.** The corpus is checked in and non-trivial.
///
/// A harness with an empty corpus finds nothing on its first run and reports success, which is the
/// worst possible combination.
#[test]
fn the_seed_corpus_is_checked_in() {
    let seeds = seeds();
    assert!(
        seeds.len() >= 20,
        "the corpus holds {} seeds; it is meant to cover one branch per parser",
        seeds.len()
    );
    for (name, bytes) in &seeds {
        assert!(!bytes.is_empty(), "seed `{name}` is empty");
    }
}

/// **The criterion.** No untrusted fixture causes a panic, through the widest entry point.
#[test]
fn no_seed_panics_any_parser() {
    for (name, bytes) in seeds() {
        // `catch_unwind` so one bad seed reports its own name rather than aborting the run at the
        // first failure — the whole list is more useful than the first entry.
        let result = std::panic::catch_unwind(|| {
            let _ = brolga_fuzz::parse_with_every_parser(&bytes);
        });
        assert!(result.is_ok(), "{}", describe(&name, &bytes));
    }
}

/// Canonicalisation holds its oracles over every seed.
#[test]
fn no_seed_breaks_canonicalisation() {
    for (name, bytes) in seeds() {
        let Ok(text) = core::str::from_utf8(&bytes) else {
            continue;
        };
        let owned = text.to_owned();
        let result = std::panic::catch_unwind(move || brolga_fuzz::canonicalise_every_way(&owned));
        assert!(result.is_ok(), "{}", describe(&name, &bytes));
    }
}

/// The pattern reader holds its oracles over every seed.
#[test]
fn no_seed_breaks_the_pattern_reader() {
    for (name, bytes) in seeds() {
        let Ok(text) = core::str::from_utf8(&bytes) else {
            continue;
        };
        let owned = text.to_owned();
        let result = std::panic::catch_unwind(move || brolga_fuzz::read_stix_pattern(&owned));
        assert!(result.is_ok(), "{}", describe(&name, &bytes));
    }
}

/// Mapping loading holds its oracle over every seed.
#[test]
fn no_seed_breaks_mapping_loading() {
    for (name, bytes) in seeds() {
        let owned = bytes.clone();
        let result = std::panic::catch_unwind(move || brolga_fuzz::load_mapping(&owned));
        assert!(result.is_ok(), "{}", describe(&name, &bytes));
    }
}

/// The export escapers hold their invariants over every seed.
#[test]
fn no_seed_escapes_an_export_escaper() {
    for (name, bytes) in seeds() {
        let Ok(text) = core::str::from_utf8(&bytes) else {
            continue;
        };
        let owned = text.to_owned();
        let result = std::panic::catch_unwind(move || brolga_fuzz::escape_every_way(&owned));
        assert!(result.is_ok(), "{}", describe(&name, &bytes));
    }
}

/// The oracles are not vacuous: they reject input that genuinely violates them.
///
/// A test suite whose assertions can never fire is a test suite that passes forever. This feeds each
/// escaper's own worst case through and checks the invariant *would* have caught a regression.
#[test]
fn the_escaping_oracles_are_not_vacuous() {
    // `has_unescaped` is the load-bearing helper. If it always returned false, every escaping oracle
    // would pass regardless.
    assert!(
        brolga_fuzz::has_unescaped("a\"b", '"'),
        "a bare quote must count as unescaped"
    );
    assert!(
        !brolga_fuzz::has_unescaped("a\\\"b", '"'),
        "an escaped quote must not"
    );
    assert!(
        brolga_fuzz::has_unescaped("a\\\\\"b", '"'),
        "an escaped backslash followed by a live quote must count — this is the case a naive check \
         misses and an attacker uses"
    );
}

/// The hostile strings, run explicitly as well as through the corpus.
///
/// The corpus covers parser branches; these cover the escapers, whose worst inputs are not documents.
#[test]
fn the_known_hostile_strings_are_still_neutralised() {
    for hostile in [
        "=cmd|'/c calc'!A0",
        "-1+cmd|'/c calc'!A0",
        "@SUM(A1)",
        "x\", shape=none]; evil [label=\"pwned\"]; a -> b [label=\"",
        "# heading\n[click](http://attacker.invalid)\n<script>x</script>",
        "*alias\nlogsource:\n  product: windows",
        "' OR ipv4-addr:value = '",
        "\\\\\" escaped-backslash-then-quote",
    ] {
        brolga_fuzz::escape_every_way(hostile);
    }
}
