# Brolga

> Brolga is an open-source Rust threat intelligence context engine. It converts large threat intelligence collections into compact, task-specific, evidence-backed context.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Project status

Planning and repository bootstrap are complete. Product implementation has not started.

Work is organised as dependency-aware GitHub issues across eight release milestones. See the [roadmap](docs/ROADMAP.md) before proposing implementation.

## Purpose

Brolga will ingest STIX, MISP, TAXII, OpenCTI exports, ATT&CK, indicator feeds, detection content, vulnerability data, and other security formats. It will convert those records into a consistent, provenance-aware intelligence graph; remove duplicated and stale noise; and compile task-specific context packs for agents, analysts, investigations, hunting, and security automation.

Its defining property:

> Brolga reduces the amount of threat intelligence an agent or analyst must process without breaking the chain back to original evidence.

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

## Non-goals

Brolga will not replace MISP, OpenCTI, a SIEM, a SOAR platform, case management, malware analysis, EDR, source evidence, or human judgement. It will not be a chatbot, generic text summariser, autonomous attribution engine, or default conduit to external LLMs.

## Architecture

Planned boundaries and dependency rules live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). They remain proposals until their foundation issues are accepted.

## Contributing

Implementation is issue-driven. Read [CONTRIBUTING.md](CONTRIBUTING.md), select an unblocked milestone issue, and keep changes within its stated acceptance criteria.

## Security

Imported intelligence, archives, mappings, reports, connector responses, and plugins are untrusted input. Report vulnerabilities through GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## Licence

Brolga is released under the [MIT License](LICENSE).
