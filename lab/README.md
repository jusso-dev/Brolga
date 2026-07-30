# Brolga threat-feed lab (#60)

Reproducible Docker Compose environment for ingesting representative intelligence and proving
normalised, evidence-backed output.

## Modes

| Profile | Purpose | Network |
| --- | --- | --- |
| `fixtures` (default path) | Offline deterministic fixtures | feed-simulator only |
| `postgres` | Optional PostgreSQL for storage smoke | published loopback |
| Root compose `serve` | HTTP API (homelab) | loopback by default |

Live public feeds and operator connectors are **not** enabled by default (ADR 0001 §3, threat model).

## Quick start (fixtures) — one happy path

From the repository root, on a machine with Docker Compose v2 and ~2 GB free for the image build.

**Remote Docker context** (e.g. `DOCKER_CONTEXT=homelab`): fixtures and scripts are **baked into**
the lab images — no host bind mounts — so the path works over SSH.

```bash
# 1) Build the production binary image (repo root Dockerfile)
docker compose -f lab/docker-compose.yml --profile fixtures build  # needs brolga:lab first:
docker build -t brolga:lab -f Dockerfile .
docker compose -f lab/docker-compose.yml --profile fixtures build

docker compose -f lab/docker-compose.yml --profile fixtures up -d feed-simulator brolga
docker compose -f lab/docker-compose.yml --profile fixtures run --rm ingest-once
docker compose -f lab/docker-compose.yml --profile fixtures run --rm demo

# Artefacts live in the named volume brolga-lab_lab-output (not a host path on remote engines):
docker run --rm -v brolga-lab_lab-output:/output:ro alpine:3.22 cat /output/stats.json
```

Or abort when the one-shot chain finishes:

```bash
docker compose -f lab/docker-compose.yml --profile fixtures up --build --abort-on-container-exit
```

Artefacts land under `lab/output/` (gitignored; regenerated each run).

### What success looks like

- `lab/output/stats.json` — non-zero entities/claims after ingest
- `lab/output/demo-context-ip.json` — pack for `203.0.113.42` (MISP + Sigma meet)
- `lab/output/quarantine.json` — malformed fixture counted, not dropped
- `lab/output/demo-sources.json` — retained original source objects

### Homelab operator path (root compose)

Separate from the lab profile — production-shaped SQLite volume + optional API:

```bash
mkdir -p feeds
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"   # or copy .env.example → .env
docker compose build
docker compose run --rm brolga doctor
docker compose run --rm brolga ingest /feeds/demo-misp.json /feeds/demo-sigma.yml --mode permissive
docker compose run --rm brolga context ip 203.0.113.42
docker compose --profile serve up -d brolga-api
curl -s localhost:8787/api/v1/health
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" localhost:8787/api/v1/stats
```

PostgreSQL overlay (optional):

```bash
export BROLGA_POSTGRES_PASSWORD=lab-only-not-a-secret
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
  --profile serve --profile postgres up -d --build
```

## Fixture coverage (current)

Checked-in samples under `lab/fixtures/` (copied from test/demo corpora; synthetic / redistributable):

| Path | Format family |
| --- | --- |
| `demo/feed.json` + `demo/rule.yml` | MISP event + Sigma (README journey) |
| `plain/iocs.txt` | plain-text IoC list |
| `csv/indicators.csv` | CSV indicators |
| `json/*`, `ndjson/*`, `flat/*` | JSON array, NDJSON, TSV |
| `stix/*` | STIX 2.0 / 2.1 / ATT&CK snippets |
| `misp/*` | MISP event + warning list |
| `detection/*` | Sigma + YARA |
| `telemetry/events.log` | CEF/LEEF/syslog style |
| `xml/*` | OpenIOC + IODEF |
| `vulnerability/*` | KEV, OSV, SARIF, CycloneDX |
| `malformed/not-json.txt` | quarantine path |

Not yet in fixture mode (still library/test covered, not wired here): full CSAF/CVRF/NVD matrix,
connector simulation (MISP/TAXII/OpenCTI mocks), `live-public`, `operator-connectors`. See issue #60.

## PostgreSQL lab profile

```bash
export BROLGA_POSTGRES_PASSWORD=lab-only-not-a-secret
docker compose -f lab/docker-compose.yml --profile postgres up -d postgres
# postgres://brolga:${BROLGA_POSTGRES_PASSWORD}@127.0.0.1:5432/brolga
```

Default lab ingest still uses SQLite on the `brolga-data` volume. Root
`docker-compose.postgres.yml` is the operator server-mode path.

## Security notes

- No API keys or live-feed tokens in this tree.
- Fixture mode makes **no** unexpected egress (simulator is the only HTTP peer; ingest uses bind mounts).
- Destructive reset is documented below and is not automatic.

## Reset

```bash
docker compose -f lab/docker-compose.yml --profile fixtures down
docker volume rm lab_brolga-data   # destructive: deletes the lab database volume
rm -rf lab/output/*
```

## Related

- Root [`docker-compose.yml`](../docker-compose.yml) — operator homelab (`doctor` / `serve`)
- [`docker-compose.postgres.yml`](../docker-compose.postgres.yml) — PostgreSQL overlay
- [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md)
- Issue [#60](https://github.com/jusso-dev/Brolga/issues/60)
