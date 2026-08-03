<p align="center">
  <img src="assets/brolga-banner.png" alt="Brolga — Make sense of the signal" width="100%">
</p>

# Brolga

> **Normalize OpenCTI (and STIX) into a local store. Serve the result.**
>
> Brolga sits next to your OpenCTI instance: pull entities as STIX, keep a compact local SQLite
> store with provenance, query and serve context for operators and tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

| Job | How |
| --- | --- |
| **Primary source** | **OpenCTI** — GraphQL poll (`toStix` → STIX parser), cursor resume |
| Secondary remotes | TAXII 2.0/2.1 collections (read-only) |
| File ingest | STIX 2.x bundles, flat CSV/TSV/JSON/NDJSON, Sigma rules |
| Store | Local SQLite (optional PostgreSQL with `--features postgres`) |
| Query | `context`, `search`, `show`, `stats`, `sources`, `quarantine` |
| Serve | Read-only HTTP API (`brolga serve`) |
| Export | Pack JSON, STIX, Markdown / text |

**Not supported** (by design): MISP in any form, writing back to OpenCTI, running detection engines
as a scanner, Wasm plugins, or LLM proposals.

## Quick start — OpenCTI

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

export BROLGA_OPENCTI_TOKEN="your-opencti-api-token"

brolga fetch opencti https://opencti.example.org \
  --name my-opencti \
  --allow-private

brolga stats
brolga context ip 203.0.113.42

export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
brolga serve --database brolga.sqlite
```

## Offline demo (no network)

```bash
brolga ingest examples/demo/feed.json examples/demo/rule.yml --mode permissive
brolga stats
brolga context ip 203.0.113.42
```

Fixtures use TEST-NET-3 / reserved docs domains only. `feed.json` is a STIX 2.1 bundle; `rule.yml`
is Sigma — both meet on `203.0.113.42`.

## Core loop

```text
OpenCTI instance ──GraphQL toStix──┐
                                   ├──► normalize (STIX) ──► SQLite ──► CLI / serve
TAXII / STIX files ────────────────┘
```

## Docker

```bash
cp .env.example .env
printf 'BROLGA_API_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env

docker compose build
docker compose run --rm brolga doctor
docker compose run --rm brolga ingest /feeds/demo-stix.json /feeds/demo-sigma.yml --mode permissive
docker compose --profile serve up -d brolga-api
```

## Docs

- [CLI](docs/CLI.md) — command reference
- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Threat model](docs/THREAT-MODEL.md)

## License

MIT — see [LICENSE](LICENSE).
