<p align="center">
  <img src="assets/brolga-banner.png" alt="Brolga — Make sense of the signal" width="100%">
</p>

# Brolga

> **Make sense of the signal.**
>
> Brolga is an open-source Rust threat intelligence context engine. It converts large threat intelligence collections into compact, task-specific, evidence-backed context.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Project status

**`v0.1.0 — Foundation` is complete.** The foundations exist and are tested; the intelligence capabilities they exist to support do not yet.

What works today:

- A versioned canonical model — entities, observables, relationships, claims, sightings, markings, and confidence components — with JSON Schemas and round-trip tests.
- A provenance model: content-addressed source objects, transformation chains carrying algorithm versions, evidence references, and the original values that canonicalisation replaced.
- Layered YAML and JSON configuration with path-specific diagnostics, deterministic fingerprints, and secret *references* rather than secret values.
- Transactional SQLite storage with checksum-verified migrations, WAL, and backend-neutral traits that accept no arbitrary SQL.
- A `brolga` binary with a stable exit-code registry, a strict stdout/stderr split, and structured diagnostics.
- Shared trust classification, resource limits, cancellation, and outbound network policy, backed by a [threat model](docs/THREAT-MODEL.md).
- Cross-platform CI on Linux, macOS, and Windows, with licence, advisory, and supply-chain gates.

What `v0.1.0` did not include: ingestion, the intelligence graph, compression, context packs, the HTTP API, the MCP server, connectors, and plugins. Ingestion arrived in `v0.2.0` — see below. The rest have not.

**`v0.2.0 — Core ingestion` is complete.** STIX 2.1 and MITRE ATT&CK, MISP events and warning
lists, and CSV/TSV/JSON/NDJSON/plain-text feeds all parse into canonical records, with original
source bytes retained content-addressed, strict and permissive modes, and a quarantine that keeps
what it could not accept.

**`brolga ingest` works.** Point it at a STIX 2.1 bundle, a MISP export, or a CSV/NDJSON/plain-text
indicator list and the records land in a local SQLite database, with the original bytes retained
content-addressed and anything unreadable kept in quarantine with a reason.

```console
$ brolga ingest bundle.json event.json indicators.txt --mode permissive
permissive ingest: 39 offered, 37 accepted (37 new, 0 updated, 0 unchanged), 2 rejected
(2 newly quarantined), 3 source object(s) retained, 0 already held

$ brolga stats
entities         5
relationships    10
claims           22
sightings        0
source_objects   3
graph version    37
retained         3 (1649 bytes stored)
quarantined      2 distinct, 2 occurrence(s)
```

`brolga show <id>` returns a stored record with its full provenance chain, `brolga sources` lists
retained originals, and `brolga quarantine --source <digest>` shows what was refused and why. Every
command takes `--output json`, which puts exactly one object on stdout so it pipes into `jq`.

**`v0.3.0 — Intelligence graph` is complete.** Deduplication that tells a syndicated copy from
independent corroboration, entity resolution that refuses to merge on a name, contradiction
detection with explainable confidence components, configurable temporal decay, bounded traversal and
typed search, and checkpoints with material deltas. Every decision it makes is a record carrying what
was compared, which algorithm and version decided it, and why.

The graph is reachable from the binary. `brolga search` finds entities by typed filters,
`brolga neighbours` walks out from one within a stated budget, and `brolga checkpoint take|diff`
answers "what changed since last week" — a delta that reports only *material* change, so a re-import
of the same file reports nothing.

```console
$ brolga search --kind intrusion_set
entity:8fd8cd7f-…  intrusion_set  active  Bunyip Panda

$ brolga neighbours entity:8fd8cd7f-… --depth 2
 0  entity:8fd8cd7f-…
 1  entity:1059cc07-…
 1  entity:cee261e1-…
3 record(s), 2 edge(s)

$ brolga checkpoint take monday --from entity:8fd8cd7f-…
$ brolga checkpoint diff monday friday
changed  entity/entity:8fd8cd7f-…  [names, sources]
changed  entity/entity:cee261e1-…  [sources]
```

Every change names the **facets** that moved, because "changed" on its own cannot tell a re-attested
source from a renamed actor, and those call for different responses.

**`brolga context` still exits `5`.** The compression engine is `v0.4.0`. There is no HTTP API, no
MCP server, no connector, and nothing fetches a feed on a schedule — ingestion reads files you give
it. This README will not pretend otherwise.

Work continues as scoped, dependency-aware [GitHub issues](https://github.com/jusso-dev/Brolga/issues) across eight release milestones. Each defines outcome, scope, acceptance criteria, dependencies, non-goals, and security and provenance impact. See the [roadmap](docs/ROADMAP.md) before proposing implementation.

## Try it

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

brolga init            # write a starter brolga.yaml
brolga doctor          # check this installation can do its job

# Ingest whatever you have. Format is detected per file.
brolga ingest my-bundle.json my-feed.csv --mode permissive

brolga stats                                  # what landed
brolga sources                                # the originals, retained by digest
brolga quarantine --source sha256:<digest>    # what was refused, and why
brolga show entity:<uuid>                     # one record, with its provenance chain
```

`--mode strict` is the default and refuses the whole batch if anything cannot be read, so a partial
import is never mistaken for a complete one. `--dry-run` parses and reports without writing.
`--output json` puts one object on stdout for `jq`.

`brolga config explain` shows every resolved setting and which layer supplied it. `brolga exit-codes` prints the exit-code registry from the build you are running. See [docs/CLI.md](docs/CLI.md).

## Run it

There is a container image and a Compose file for running Brolga on your own infrastructure, with
the database on a volume you control and a directory you drop feeds into.

```bash
mkdir -p feeds
docker compose build
docker compose run --rm brolga doctor
```

Brolga is mostly a command that runs and exits — `docker compose run` is the normal way to ingest
and query — with one exception: `brolga serve` runs a read-only HTTP API so other services can
pull context from it. The image runs as a non-root user and pins both its base images by digest.
Ingestion still makes no outbound connection and can be run with no network at all.

The API defaults to loopback and **refuses to start** on an address reachable from another host
unless a token is configured. See [docs/API.md](docs/API.md).

[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) is the operator's guide: build, first run, ingesting a
file, where the SQLite database lives, how to back it up without the WAL catching you out, and an
explicit list of what is not reachable yet.

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

## Properties

Shipped in `v0.1.0`:

- Self-contained Rust binary named `brolga`
- Offline and deterministic operation without an LLM — no network client, no model provider, and no random or clock-based identifier anywhere in the canonical model
- Strong canonical types for entities, observables, relationships, claims, sightings, provenance, and markings
- Auditable transformation chains recording algorithm versions, and the original values canonicalisation replaced
- SQLite local mode
- Stable Rust library interfaces for the crates above

Planned, and not yet implemented:

- Original source-object *retention* — the metadata and content addressing exist; storing and retrieving the bytes does not
- Evidence-preserving structural compression under token, byte, object, depth, relationship, and time budgets
- Progressive disclosure from disposition through original source objects
- Local HTTP API and MCP stdio server
- PostgreSQL server mode
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

Boundaries and dependency rules live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), decided by [ADR 0001](docs/adr/0001-workspace-boundaries-and-public-interface-versioning.md). Core parsing, modelling, provenance, storage, graph logic, policy, compression, and interfaces will remain loosely coupled through versioned Rust traits and schemas.

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

- [v0.1.0 Foundation](https://github.com/jusso-dev/Brolga/issues/1) — **complete**
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

Imported intelligence, archives, mappings, reports, connector responses, and plugins are untrusted input. [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) records the boundaries, the controls, what is deliberately out of scope, and the residual risks.

Report vulnerabilities through GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## Licence

Brolga is released under the [MIT License](LICENSE).
