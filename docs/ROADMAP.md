# Brolga roadmap

Status: `v0.1.0 — Foundation`, `v0.2.0 — Core ingestion`, and `v0.3.0 — Intelligence graph` are complete; `v0.4.0` has not started. `brolga ingest`, `stats`, `show`, `sources`, and `quarantine` work; the graph layer is library code with no command reaching it, which is #34. GitHub milestones and issues are the source of work status.

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

### v0.2.0 — Core ingestion — complete

Add bounded parser pipeline, quarantine, source retention, deterministic observable canonicalisation, STIX 2.1 and ATT&CK, MISP JSON, CSV, NDJSON, and plain-text ingestion.

Exit gate: required initial formats have fixtures, strict and permissive modes are observable, malformed records are retained in quarantine, and every canonical record links to originals.

#### Exit gate: demonstrated

Each clause, and what demonstrates it. As with `v0.1.0`, every claim below is a test that exists or
a command that was run.

**"Required initial formats have fixtures."**

Twelve fixture files across three corpora: a STIX 2.1 bundle carrying SDOs, SCOs, SROs and a marking
definition, an ATT&CK enterprise shape, a bare unwrapped STIX object; a MISP event with nested
objects, tags and a galaxy, a warning list, a feed `response` array; and CSV with a byte-order mark,
CRLF-terminated CSV, TSV, a plain-text indicator list, NDJSON with a deliberately malformed line, and
a JSON array. Each is ingested by a test that asserts exact counts rather than "more than zero".

**"Strict and permissive modes are observable."**

`IngestMode::Strict` is the default and refuses a batch containing anything it cannot accept —
writing no records, no source objects, and no retained evidence, asserted against a real database.
`Permissive` persists the acceptable records and quarantines the rest. The report says which mode
produced it, and its counts reconcile: accepted plus rejected equals offered, with a debug assertion
on the invariant and a summary that prints its zeroes.

**"Malformed records are retained in quarantine."**

A quarantine row records what was rejected, which parser rejected it, at which stage, for what typed
reason, at what offset, with a bounded control-character-free excerpt. Its identity derives from the
rejection rather than the attempt, so re-importing a broken feed updates one row and increments an
occurrence count instead of appending. Fragments are stripped of control characters on the way in,
because a quarantine table is read through terminals.

**"Every canonical record links to originals."**

Every record carries source-derived provenance citing the content-addressed source object it was
parsed from, asserted per record for all three formats. The original bytes are retained, deduplicated
by digest, verified on retrieval against the address they were filed under, and released only by an
explicit audited decision. MISP attributes additionally carry a `part-of` edge to the event that
published them.

**Not claimed.** `brolga ingest` exits `5`. Every parser is library code and no CLI command drives
one; the command surface is #34, in `v0.5.0`.

### v0.3.0 — Intelligence graph — complete

Persist entities, relationships, claims, sightings, provenance, deduplication decisions, resolution candidates, contradictions, temporal state, confidence components, safe traversal, and checkpoints.

Exit gate: every merge, duplicate, contradiction, confidence change, and graph delta is deterministic and explainable.

#### Exit gate: demonstrated

Each clause, and the test that holds it. As with `v0.1.0` and `v0.2.0`, every claim below is a test
that exists rather than a description of intent.

**"Every merge … is deterministic and explainable."**

A merge requires a `Decisive` signal, and no name-based matcher can produce one — so "never merge on
name similarity alone" holds by construction rather than by a check somebody could forget. Decisive
means identity an external authority assigned: the same canonical identifier, the same external
identifier in the same namespace, or an alias somebody declared and signed. `"Lazarus"` the actor and
`"Lazarus"` the malware family are both real, and a merge is close to irreversible in practice once
claims and sightings are attributed to one identity.

An analyst rejection outranks even a decisive signal and is symmetric, so the next import cannot
re-propose the merge with its arguments swapped. Actor and policy context are preconditions on every
manual operation, a refused operation is not recorded at all, and withdrawal is a recorded operation
rather than a deletion. Merges take the **union** of markings, never the intersection — merging AMBER
into CLEAR and keeping CLEAR would silently declassify the evidence.

**"Every duplicate … is deterministic and explainable."**

Five verdicts, of which exactly one increases corroboration — asserted by a test, because a second
one appearing later would inflate every downstream score invisibly. The rule that does most of the
work: byte-identical content from two publishers is a **copy, not corroboration**, because two
analysts writing independently do not produce identical whitespace, field order, and timestamps. One
upstream mirrored by five aggregators stays a single source. Updates append rather than overwrite.

**"Every contradiction … is deterministic and explainable."**

Narrative claims are never compared, nor are claims in different predicate slots or about different
subjects — three tests, because #21's non-goals forbid fuzzy matching and #22 must not smuggle one
in. A contested claim is penalised rather than suppressed, and the report keeps the pairs that agreed
alongside the pairs that conflicted. A publisher revising or withdrawing its own claim is not a
contradiction.

Attribute contradictions detect **nothing by default**: shipping a guessed list of single-valued
attributes would be inventing intelligence, so they require an operator declaration.

**"Every confidence change … is deterministic and explainable."**

Every component carries a score, a weight, and a reason, and the overall figure is the weighted mean
of the components it lists. A mirrored feed scores as one source, wired to the deduplicator's
judgement rather than to a second opinion. An analyst override replaces the figure and leaves what
the sources support intact, recorded as its own row with its actor and authority.

Decay owns freshness outright — `confidence` delegates rather than keeping a second notion of what
"old" means. Standing never rises with age, swept across eight half-lives and six floors at every age
to five half-lives, and **nothing decays to nought**: an indicator that has aged out was observed by
somebody, and one that was never asserted was not. Retuning a half-life makes stored confidence
figures stale exactly as retuning a weight does.

**"Every graph delta is deterministic and explainable."**

Material state is eight named facets, and what is excluded is written down with a reason and walked
by a test — the observation window above all, because "we saw it again" is not "something changed".
A no-op re-import produces an **empty** delta. Traversal is held to depth, node, edge, and fan-out
budgets plus a cancellation token, and reports which one stopped it, because a truncated
neighbourhood looks exactly like a small one. Search takes typed predicates and never a
caller-composed string; a SQL payload in a record's name is stored and traversed as content.

Checkpoints survive the process that took them, and a delta against a reloaded baseline equals one
against the in-memory original.

**Not claimed.** No command reaches any of this. `brolga-cli` does not depend on `brolga-graph`, so
the graph layer is a Rust library and nothing else — that is #34, in `v0.5.0`. `brolga context`
still exits `5`.

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
