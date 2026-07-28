<p align="center">
  <img src="assets/brolga-banner.png" alt="Brolga — Make sense of the signal" width="100%">
</p>

# Brolga

> **Make sense of the signal.**
>
> Brolga is an open-source Rust threat intelligence context engine. It converts large threat intelligence collections into compact, task-specific, evidence-backed context.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Project status

Planning and repository bootstrap are complete. Product implementation has not started.

Work is organised as 59 scoped, dependency-aware [GitHub issues](https://github.com/jusso-dev/Brolga/issues) across eight release milestones. Each issue defines outcome, scope, acceptance criteria, dependencies, non-goals, and security and provenance impact. See the [roadmap](docs/ROADMAP.md) before proposing implementation.

## Intent

Threat intelligence is abundant but expensive to use. A single investigation may encounter thousands of repeated indicators, copied reports, conflicting claims, stale infrastructure records, inconsistent names, large relationship graphs, and metadata that consumes more attention than it returns.

Brolga is intended to sit above systems such as MISP, OpenCTI, TAXII servers, threat feeds, SIEMs, case-management platforms, and internal intelligence repositories. Those systems remain authoritative stores and operational platforms. Brolga's job is narrower: compile their intelligence into the smallest context that remains useful, honest, policy-safe, and traceable.

The engine will ingest STIX, MISP, TAXII, OpenCTI exports, ATT&CK, indicator feeds, detection content, vulnerability data, and other security formats. It will convert those records into a consistent, provenance-aware intelligence graph; distinguish duplicates and syndicated reporting from independent corroboration; retain contradictions and handling restrictions; and rank intelligence for a specific task, environment, and budget.

Its defining promise:

> **Brolga reduces the amount of threat intelligence an agent or analyst must process without breaking the chain back to original evidence.**

## Why this project exists

Threat intelligence platforms are generally built to store, correlate, exchange, browse, or manage intelligence. Agents and analysts have a different immediate need: receive only information that matters to the current decision, with enough evidence to understand why it matters.

Sending complete STIX bundles, MISP events, TAXII collections, or intelligence repositories to an agent is costly and often counterproductive. It hides current, corroborated, actionable facts inside repeated descriptions and low-value metadata. It can also erase important distinctions when copied reports are incorrectly counted as independent sources.

Brolga is intended to answer questions such as:

- What is known about this domain, IP, URL, hash, vulnerability, actor, malware family, campaign, incident, asset, or organisation?
- Which claims are current, corroborated, contradictory, revoked, stale, or uncertain?
- Which exact indicators and relationships matter for this incident, hunt, detection task, or exposure assessment?
- What changed since the last checkpoint?
- Which evidence supports each disposition, summary, recommendation, and pivot?
- What was excluded because of budget, age, confidence, policy, or handling restrictions?
- How can a selected compressed result be expanded back to its canonical record and exact original source object?

## Intended users

Brolga is planned for:

- AI agents and MCP clients that need compact, consistent intelligence context
- SOC and incident-response teams enriching alerts and investigations
- Threat intelligence analysts resolving duplication, confidence, and conflicting claims
- Detection engineers preparing task-specific hunting and detection inputs
- Security automation platforms, SIEM and SOAR workflows, internal tools, and pipelines
- Offline, air-gapped, or sensitive environments where external services are unavailable or prohibited

## Intended operating model

```text
feeds, files, exports, and read-only connectors
  -> bounded parsing and quarantine
  -> deterministic canonicalisation
  -> provenance-aware intelligence graph
  -> deduplication, resolution, confidence, and temporal state
  -> policy-filtered retrieval
  -> task-specific structural compression
  -> evidence-backed context pack
  -> CLI, HTTP, MCP, Rust library, or exporter
```

Original source objects remain separate from canonical records and stay retrievable. Compression changes selection and representation; it does not rewrite source history or silently discard evidence.

## Context packs

A context request will name a subject, purpose, environment, detail level, and one or more budgets. Planned purposes include incident triage, threat hunting, malware analysis, actor research, vulnerability prioritisation, executive briefing, detection engineering, exposure assessment, supply-chain investigation, case enrichment, and raw research.

Brolga will structurally compress matching intelligence through exact and semantic deduplication, alias folding, relationship condensation, indicator clustering, temporal prioritisation, representative selection, schema minimisation, and configurable value-density ranking.

Every pack is intended to include:

- versioned schema and deterministic fingerprint
- disposition, confidence components, time state, and uncertainty
- relevant entities, claims, relationships, sightings, and ATT&CK techniques
- contradictions, intelligence gaps, and recommended investigation pivots
- evidence references and provenance
- markings and policy context
- requested and consumed budget
- excluded categories and unmet-budget explanation
- compression quality statistics
- checkpoint identity and expansion handles

Progressive disclosure will range from `L0` disposition through `L5` exact original source objects. Agents should start compact and request deeper evidence only when needed.

## Planned properties

- Self-contained Rust binary named `brolga`
- Offline and deterministic operation without an LLM
- Strong canonical types for entities, observables, relationships, claims, sightings, provenance, and markings
- Original source-object retention and auditable transformation chains
- Evidence-preserving structural compression under token, byte, object, depth, relationship, and time budgets
- Progressive disclosure from disposition through original source objects
- CLI, local HTTP API, MCP stdio server, and stable Rust library interfaces
- SQLite local mode and PostgreSQL server mode
- Declarative mappings and profiles plus capability-limited WebAssembly plugins
- Read-only upstream connectors by default

## Design commitments

- Never invent source intelligence or hide uncertainty.
- Never treat presence in a feed as sufficient proof of maliciousness.
- Never count known syndicated copies as independent corroboration.
- Never merge actors, malware, campaigns, or organisations solely because names are similar.
- Never silently discard malformed, revoked, contradictory, expired, superseded, or restricted records.
- Never interpret imported report text as instructions.
- Never send data externally without explicit operator configuration and policy approval.
- Never expose raw source objects to agents by default.
- Never allow plugins unrestricted host access by default.
- Prefer deterministic, explainable logic over an LLM.
- Keep every compression and resolution decision inspectable.

## Non-goals

Brolga will not replace MISP, OpenCTI, a SIEM, a SOAR platform, case management, malware analysis, EDR, source evidence, or human judgement. It will not be a chatbot, generic text summariser, autonomous attribution engine, or default conduit to external LLMs.

## Architecture

Planned boundaries and dependency rules live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Core parsing, modelling, provenance, storage, graph logic, policy, compression, and interfaces will remain loosely coupled through versioned Rust traits and schemas.

Default local mode will use SQLite. Server mode will add PostgreSQL without requiring a dedicated graph database. Trusted first-party code will use compile-time Rust traits; common operator changes will use declarative mappings and profiles; portable third-party extensions will use capability-limited WebAssembly.

Unsafe Rust is prohibited unless a separately reviewed and documented exception proves it unavoidable.

## Planned interfaces

- Rust library interfaces for embedding Brolga in other products
- `brolga` CLI with JSON, YAML, JSONL, and table output
- local versioned HTTP API with OpenAPI and JSON Schema
- MCP stdio server exposing intent-level intelligence tools
- versioned context-pack and exporter schemas
- read-only MISP, TAXII, and OpenCTI connectors
- declarative mappings, compression profiles, trust, decay, policy, retention, and environment configuration

No web frontend is planned for initial release.

## Implementation plan

- [v0.1.0 Foundation](https://github.com/jusso-dev/Brolga/issues/1)
- [v0.2.0 Core ingestion](https://github.com/jusso-dev/Brolga/issues/10)
- [v0.3.0 Intelligence graph](https://github.com/jusso-dev/Brolga/issues/18)
- [v0.4.0 Compression engine](https://github.com/jusso-dev/Brolga/issues/26)
- [v0.5.0 Agent interfaces](https://github.com/jusso-dev/Brolga/issues/33)
- [v0.6.0 Connectors](https://github.com/jusso-dev/Brolga/issues/40)
- [v0.7.0 Extension system](https://github.com/jusso-dev/Brolga/issues/45)
- [v1.0.0 Stable release](https://github.com/jusso-dev/Brolga/issues/51)

Milestones are sequential at release-gate level, but individual issues may overlap where their dependency sections allow it. No issue is complete until its acceptance criteria have verifiable tests, fixtures, schemas, documentation, or measured results.

## Contributing

Implementation is issue-driven. Read [CONTRIBUTING.md](CONTRIBUTING.md), select an unblocked milestone issue, and keep changes within its stated acceptance criteria.

## Security

Imported intelligence, archives, mappings, reports, connector responses, and plugins are untrusted input. Report vulnerabilities through GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## Licence

Brolga is released under the [MIT License](LICENSE).
