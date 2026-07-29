# The fuzzing harness

```bash
# On stable: replay the checked-in corpus through every entry point. This is what CI runs.
cargo test --manifest-path fuzz/Cargo.toml

# On nightly: the real thing.
cargo install cargo-fuzz
cargo fuzz build
cargo fuzz run ingest_any crates/brolga-ingest/tests/fixtures/fuzz-seeds -- -max_total_time=60
```

## Targets

| Target | Covers | Oracles beyond "no crash" |
| --- | --- | --- |
| `ingest_any` | Every shipping parser, via the registry, under four media types | Detection is deterministic for one input |
| `canonicalise` | Every observable and identifier canonicaliser | Idempotency; no control character in a canonical value |
| `stix_pattern` | The STIX pattern reader, reached directly | Determinism; an accepted pattern names an observable |
| `mapping_document` | Declarative mapping loading | A mapping that loads is one that validated |
| `export_escaping` | The CSV, Markdown, DOT, Sigma-YAML, and STIX-pattern escapers | Each escaper's own injection invariant |

`ingest_any` iterates the registry rather than a list, so a parser added later is fuzzed the moment it
is registered.

## Why the bodies are in `src/lib.rs` and the targets are three lines each

A `fuzz_target!` body only runs under `cargo fuzz`, which needs nightly. CI builds on stable and the
MSRV job builds on 1.88.0, so logic living in a target would be checked by nothing on an ordinary run:
not that it compiles, not that the corpus is readable, not that the oracles still hold. The harness
would rot until somebody next installed nightly — which, for a fuzzing harness, is the usual outcome.

`tests/corpus.rs` replays every seed through **the same functions** on stable, so there is one body per
property and it runs on every push.

## Why this crate is outside the workspace

`cargo-fuzz` needs nightly and `libfuzzer-sys`, which brings a C toolchain. A workspace member would
pull both into every `cargo build` and into the MSRV job. `Cargo.toml`'s `exclude` keeps them out, and
`libfuzzer-sys` is additionally behind a `fuzzing` feature so the corpus replay does not need it.

There is no committed `fuzz/Cargo.lock`, deliberately — so `libfuzzer-sys` cannot enter the shipped
lockfile, and the `--locked` jobs keep meaning what they say.

## A failure never prints the input

Every oracle names the canonicaliser or the escaper and the byte lengths involved, never the value.
A corpus seed is by construction a hostile input, and a crash report carrying one is a working exploit
published in a log anybody can read. libFuzzer writes the crashing input to `fuzz/artifacts/`, which is
where it belongs: on the machine running the fuzzer. CI uploads that directory as a private artefact on
failure rather than echoing it.

The name and the length are enough to reproduce locally, which is what actionable means.

## The corpus

`crates/brolga-ingest/tests/fixtures/fuzz-seeds/` — shared with the ingest property tests rather than
duplicated, because two copies of a corpus is two corpora and the one nobody updates is the one that
stops finding things. See its `README.md` for what each seed covers.

Adding a seed needs no code change: `tests/corpus.rs` reads the directory.
