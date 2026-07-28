# Architecture plan

Status: proposed. Product implementation has not started.

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

Final crate boundaries require an architecture decision in milestone `v0.1.0`.

## Dependency rules

- Source adapters depend on canonical interfaces; canonical types never depend on STIX, MISP, TAXII, or vendor models.
- Storage, token estimation, policy, parsing, scoring, compression, and export use explicit traits.
- Interface crates call application services; they do not reimplement intelligence decisions.
- Policy evaluation occurs before context selection and before export.
- Generated narrative always references evidence and records its generation method.
- LLM providers remain optional, disabled by default, and outside deterministic core behaviour.
- Native shared-library loading is excluded from default extension design.

## Trust boundaries

Primary boundaries are imported content, archives, XML, mappings, connector URLs and responses, local API callers, network MCP callers, plugins, exporters, and optional model providers.

Each boundary needs explicit size, time, depth, capability, redirect, address, credential, and output-policy controls. Detailed controls belong in threat-model and security-foundation issues.

## Determinism

A fixed input dataset, configuration, plugin set, algorithm versions, request, and checkpoint should produce the same content-pack fingerprint. Runtime metadata such as generation time must be isolated from deterministic content.

## Persistence

Canonical records and source objects are separate. Source objects use content addressing and compression. Relational adjacency tables and bounded recursive queries provide initial graph operations. Dedicated graph infrastructure is not required.
