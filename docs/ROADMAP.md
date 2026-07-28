# Brolga roadmap

Status: approved implementation plan pending execution. GitHub milestones and issues are the source of work status.

## Release sequence

### v0.1.0 — Foundation

Establish workspace architecture, canonical and provenance models, configuration, schemas, SQLite storage, CLI shell, logging, security limits, CI, and contribution gates.

Exit gate: public foundations compile across supported targets, migrations and schemas are versioned, hostile input limits are defined, and no interface claims unsupported behaviour.

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
