<p align="center">
  <img src="assets/brolga-banner.png" alt="Brolga — Make sense of the signal" width="100%">
</p>

# Brolga

> **Normalize threat feeds. Serve the result.**
>
> Brolga is a Rust threat-intelligence normalizer: pull STIX / TAXII / OpenCTI / MISP / flat feeds,
> store one canonical graph in SQLite, query and serve it.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

| Job | How |
| --- | --- |
| Ingest files | STIX 2.x, MISP events, Sigma rules, CSV/TSV/JSON/NDJSON (+ declarative mappings for other shapes) |
| Pull remotes | TAXII 2.0/2.1, OpenCTI, MISP — **read-only** |
| Store | Local SQLite (optional PostgreSQL with `--features postgres`) |
| Query | `context`, `search`, `show`, `stats`, `sources`, `quarantine` |
| Serve | Read-only HTTP API (`brolga serve`) |
| Export | Pack JSON, STIX, MISP, Markdown / text |

**Not supported** (by design): publishing back to platforms, running YARA/Sigma as a scanner,
evaluating vuln version ranges, Wasm plugins, or LLM proposals.

## Quick start

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

brolga ingest examples/demo/feed.json examples/demo/rule.yml --mode permissive
brolga stats
brolga context ip 203.0.113.42

# Remote feeds (needs network + trust config)
# brolga fetch taxii --url https://… 
# brolga fetch opencti --url https://…

# Serve the store over HTTP
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
brolga serve --database brolga.sqlite
```

Nothing in the demo fixtures reaches a network — TEST-NET-3 addresses and reserved docs domains only.

## Core loop

```text
files / TAXII / OpenCTI / MISP
        │
        ▼
   normalize → canonical entities, claims, relationships
        │
        ▼
   SQLite (source bytes retained, content-addressed)
        │
        ├─► CLI: context / search / show
        └─► HTTP API: brolga serve
```

## Docker

```bash
cp .env.example .env
printf 'BROLGA_API_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
docker compose build
docker compose run --rm brolga doctor
docker compose run --rm brolga ingest /feeds/demo-misp.json /feeds/demo-sigma.yml --mode permissive
docker compose run --rm brolga context ip 203.0.113.42
docker compose --profile serve up -d brolga-api
```

## Docs

- [CLI](docs/CLI.md) — command reference
- [Architecture](docs/ARCHITECTURE.md) — crate layout (historical ADRs still under `docs/adr/`)
- [Deployment](docs/DEPLOYMENT.md) — homelab / compose
- [Threat model](docs/THREAT-MODEL.md)

## Status

Slimmed toward a single product job: **normalize TI feeds and serve them**. Optional surfaces
(plugins, LLM proposals, MCP, YARA/OpenIOC/vuln/SBOM parsers, CSV/DOT/SARIF exporters) were removed
from the default tree so the binary and the mental model stay small.

## License

MIT — see [LICENSE](LICENSE).
