# Brolga roadmap

Status: `v0.1.0 — Foundation` is complete; `v0.2.0 — Core ingestion` is in progress — the parser registry and pipeline exist, no format parser does. GitHub milestones and issues are the source of work status.

## Release sequence

### v0.1.0 — Foundation — complete

Establish workspace architecture, canonical and provenance models, configuration, schemas, SQLite storage, CLI shell, logging, security limits, CI, and contribution gates.

Exit gate: public foundations compile across supported targets, migrations and schemas are versioned, hostile input limits are defined, and no interface claims unsupported behaviour.

#### Exit gate: demonstrated

Each clause, and what demonstrates it. Every claim below is a command that was run or a test that
exists, not a description of intent.

**"Public foundations compile across supported targets."**

CI builds and tests the workspace on `ubuntu-latest`, `macos-latest`, and `windows-latest`, with
default features *and* with `--all-features`, plus a release-profile build and a binary smoke run on
each. A separate job pins the toolchain to the declared MSRV of 1.88.0, which is what turns the
number in `rust-version` into a fact rather than a guess — and it earned its place immediately,
catching a transitive build script that needed a newer compiler.

**"Migrations and schemas are versioned."**

Every applied migration's checksum is recorded and re-verified on every start-up, so editing a
released migration fails at the next run instead of silently producing two deployments that report
the same schema version with different schemas. Every top-level canonical type carries a
`schema_version` *in the payload*; a major-version mismatch is an error, not a best-effort parse.
JSON Schema documents carry a matching versioned `$id`. Configuration carries a `version`. Exit codes
are pinned by test. Algorithm identity travels in the provenance chain as
`(algorithm, algorithm_version)`.

**"Hostile input limits are defined."**

`brolga-security` holds them, as a layer-0 crate so that every future consumer shares one definition
rather than drifting apart. Each is bounded on both sides — zero disables a protection, `u64::MAX`
is not a limit — and a test walks every bound in the crate, so a limit added later cannot skip the
check. [docs/THREAT-MODEL.md](THREAT-MODEL.md) covers all ten boundaries in
[docs/ARCHITECTURE.md](ARCHITECTURE.md) and states the residual risks rather than implying there are
none.

**"No interface claims unsupported behaviour."**

`brolga ingest` and `brolga context` exist and exit `5`, naming the milestone that implements them,
with nothing written to stdout. This is checked on all three platforms in CI. The README states
plainly what does *not* work yet. `SourceObject` stores evidence metadata and says so; it does not
imply the bytes are retained. Full-text search is documented as a plan, not shipped as a stub.

#### Clean-checkout verification

Run against a fresh clone, not the working tree:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | pass |
| `cargo build --locked --workspace` | pass |
| `cargo test --locked --workspace` | pass |
| `cargo test --locked --workspace --all-features` | pass — **485 tests** |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --all-features` | pass |
| `cargo metadata --locked` | pass |
| `cargo deny check licenses advisories bans sources` | pass |
| `cargo build --locked --workspace --release` | pass |
| `brolga --version`, `exit-codes`, `doctor`, `ingest` | pass — `ingest` exits 5, stdout empty |

Linux and Windows results, and the pinned-MSRV build, come from CI; the table above was produced on
macOS.

#### What this milestone deliberately did not do

No parser, connector, HTTP service, MCP server, compression engine, plugin host, or exporter. No
entity resolution and no confidence aggregation — the model records components and provenance so
that those decisions can later be made *and explained*, rather than being made now and rationalised
afterwards.

### v0.2.0 — Core ingestion

Add bounded parser pipeline, quarantine, source retention, deterministic observable canonicalisation, STIX 2.1 and ATT&CK, MISP JSON, CSV, NDJSON, and plain-text ingestion.

Exit gate: required initial formats have fixtures, strict and permissive modes are observable, malformed records are retained in quarantine, and every canonical record links to originals.

### v0.3.0 — Intelligence graph

Persist entities, relationships, claims, sightings, provenance, deduplication decisions, resolution candidates, contradictions, temporal state, confidence components, safe traversal, and checkpoints.

Exit gate: every merge, duplicate, contradiction, confidence change, and graph delta is deterministic and explainable.

### v0.4.0 — Compression engine

Implement context-pack schema, profiles, ranking, clustering, condensation, budgets, progressive disclosure, expansion, fingerprints, and quality metrics.

Exit gate: deterministic golden packs remain within declared budget tolerance while retaining required evidence, contradictions, markings, exact observables, and exclusions.

### v0.5.0 — Agent interfaces

Complete CLI workflows, local HTTP API, OpenAPI, authenticated network access, MCP stdio intent tools, policy enforcement, auditing, metrics, and end-to-end demonstration.

Exit gate: CLI, HTTP, and MCP produce schema-equivalent policy-safe packs and can expand selected output back to canonical and source evidence.

### v0.6.0 — Connectors

Add read-only MISP, TAXII 2.0/2.1, and OpenCTI connectors with incremental checkpoints, pagination, TLS, proxies, bounded retries, and SSRF controls.

Exit gate: mock-server integration tests prove correct incremental retrieval, failure recovery, provenance, and no upstream writes.

### v0.7.0 — Extension system

Add stable plugin SDK, declarative mappings, WIT ABI, capability-limited WebAssembly host, optional LLM proposal interface, and plugin examples.

Exit gate: plugins run without filesystem or network access by default, remain bounded, declare compatibility and capabilities, and cannot bypass policy.

### v1.0.0 — Stable release

Finish required parsers and exporters, PostgreSQL, safe query language, fuzzing, property and integration tests, measured benchmarks, full documentation, release hardening, and acceptance audit.

Exit gate: all initial acceptance criteria have evidence; Linux, macOS, and Windows builds pass; benchmark claims are reproducible; no placeholder production code or undocumented untrusted-input panic path remains.

## Dependency order

```text
v0.1.0 Foundation
  -> v0.2.0 Core ingestion
  -> v0.3.0 Intelligence graph
  -> v0.4.0 Compression engine
  -> v0.5.0 Agent interfaces

v0.2.0 Core ingestion
  -> v0.6.0 Connectors

v0.1.0 Foundation
  -> v0.7.0 Extension system

v0.5.0 + v0.6.0 + v0.7.0
  -> v1.0.0 Stable release
```

Work may overlap only where issue dependencies allow it. Milestone labels communicate product area; milestones communicate release gates.

## Cross-cutting release rules

- No silent loss, unexplained merge, hidden contradiction, invented intelligence, or unsupported format claim.
- No external network call, upstream mutation, plugin capability, or model-provider transfer without explicit configuration and policy.
- No raw source dump to agents by default.
- Every public schema, protocol, ABI, migration, algorithm, and checkpoint representation is versioned.
- Every performance statement comes from a checked-in methodology and reproducible measurement.
- Security, provenance, policy, deterministic golden tests, and documentation are part of each feature, not deferred cleanup.
