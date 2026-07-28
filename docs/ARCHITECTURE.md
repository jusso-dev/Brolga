# Architecture plan

Status: accepted. The `v0.1.0` crates exist and follow it; the later crates are planned. Where this document and an [ADR](adr/README.md) disagree, the ADR wins.

## Core flow

```text
untrusted input
  -> bounded detection and parsing
  -> validation or quarantine
  -> deterministic normalisation and canonicalisation
  -> entity resolution, deduplication, and correlation
  -> provenance-aware persistence and indexing
  -> policy-filtered retrieval
  -> ranked structural compression
  -> versioned context pack
  -> CLI, HTTP, MCP, library, or exporter
```

Original source objects remain addressable throughout this flow. Compression changes representation and selection, never source history.

## Planned workspace boundaries

This is the target layout for the finished product, not the starting point. The crates actually
created in `v0.1.0`, their layers, and the rules for introducing the rest are fixed by
[ADR 0001](adr/0001-workspace-boundaries-and-public-interface-versioning.md). Where the two
disagree, the ADR wins.

```text
crates/
  brolga-model          versioned canonical types and schemas
  brolga-core           orchestration and shared application services
  brolga-ingest         parser traits, registry, pipeline, and quarantine
  brolga-normalise      canonicalisation and deterministic resolution
  brolga-graph          graph operations, deduplication, and correlation
  brolga-compress       ranking, clustering, budgeting, and context packs
  brolga-policy         markings, authorisation, and output decisions
  brolga-storage        storage traits, SQLite, and PostgreSQL
  brolga-query          safe structured query model and parser
  brolga-export         versioned exporters
  brolga-mcp            MCP transports and intent-level tools
  brolga-api            HTTP API and OpenAPI
  brolga-cli            primary `brolga` binary
  brolga-plugin-sdk     Rust traits and WebAssembly ABI types
  brolga-test-support   fixtures, builders, and deterministic harnesses
```

Final crate boundaries required an architecture decision in milestone `v0.1.0`. That decision is
[ADR 0001](adr/0001-workspace-boundaries-and-public-interface-versioning.md), which creates seven
crates for `v0.1.0` — `brolga-model`, `brolga-security`, `brolga-config`, `brolga-storage`,
`brolga-core`, `brolga-cli`, and `brolga-test-support` — and introduces the remainder in the
milestone that first needs each one.

## Dependency rules

- Crates occupy numbered layers and may depend only on strictly lower layers, which makes dependency cycles structurally impossible. Layer assignments are in [ADR 0001](adr/0001-workspace-boundaries-and-public-interface-versioning.md).
- Source adapters depend on canonical interfaces; canonical types never depend on STIX, MISP, TAXII, or vendor models.
- Storage, token estimation, policy, parsing, scoring, compression, and export use explicit traits.
- Interface crates call application services; they do not reimplement intelligence decisions.
- Policy evaluation occurs before context selection and before export.
- Generated narrative always references evidence and records its generation method.
- LLM providers remain optional, disabled by default, and outside deterministic core behaviour.
- Native shared-library loading is excluded from default extension design.

## Trust boundaries

Primary boundaries are imported content, archives, XML, mappings, connector URLs and responses, local API callers, network MCP callers, plugins, exporters, and optional model providers.

Each boundary needs explicit size, time, depth, capability, redirect, address, credential, and output-policy controls. Those controls, the attackers they defend against, and the residual risks are in [docs/THREAT-MODEL.md](THREAT-MODEL.md); the types that make them enforceable are in `brolga-security`.

## Determinism

A fixed input dataset, configuration, plugin set, algorithm versions, request, and checkpoint should produce the same content-pack fingerprint. Runtime metadata such as generation time must be isolated from deterministic content.

## Persistence

Canonical records and source objects are separate. Source objects use content addressing and compression. Relational adjacency tables and bounded recursive queries provide initial graph operations. Dedicated graph infrastructure is not required.
