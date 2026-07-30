# Brolga threat-feed lab (#60)

Reproducible Docker Compose environment for ingesting representative intelligence and proving
normalised, evidence-backed output.

## Modes

| Profile | Purpose | Network |
| --- | --- | --- |
| `fixtures` (default path) | Offline deterministic fixtures | feed-simulator only |
| `postgres` | Optional PostgreSQL store for #55 | internal |
| `serve` | Existing HTTP API profile (root compose) | published loopback |

Live public feeds and operator connectors are **not** enabled by default (ADR 0001 §3, threat model).

## Quick start (fixtures)

From the repository root:

```bash
# Build image + start feed simulator + ingest fixtures + run demo checks
docker compose -f lab/docker-compose.yml --profile fixtures up --build --abort-on-container-exit
```

Artefacts land under `lab/output/` (gitignored samples are regenerated each run).

### Manual steps

```bash
docker compose -f lab/docker-compose.yml --profile fixtures up -d --build feed-simulator brolga
docker compose -f lab/docker-compose.yml run --rm ingest-once
docker compose -f lab/docker-compose.yml run --rm demo
```

## Fixture coverage (initial)

Deterministic samples under `lab/fixtures/`:

| Path | Format family |
| --- | --- |
| `plain/iocs.txt` | plain-text IoC list |
| `csv/indicators.csv` | CSV indicators |
| `json/bundle.json` | JSON array of simple indicators |
| `stix/attack-snippet.json` | STIX 2.1 bundle snippet |
| `malformed/not-json.txt` | quarantine / failure path |

This is the **scaffold** for full v1.0 format matrix coverage; expand fixtures as parsers claim support.

## PostgreSQL profile

```bash
export BROLGA_POSTGRES_PASSWORD=lab-only-not-a-secret
docker compose -f lab/docker-compose.yml --profile postgres up -d postgres
# Connection string for library tests:
# postgres://brolga:${BROLGA_POSTGRES_PASSWORD}@localhost:5432/brolga
```

Migrate with the library (`brolga-storage` feature `postgres`) or future CLI flag. Default lab ingest
still uses SQLite on the `brolga-data` volume.

## Security notes

- No API keys or live-feed tokens in this tree.
- Fixture mode makes **no** unexpected egress (simulator is the only HTTP peer).
- Destructive reset is documented below and is not automatic.

## Reset

```bash
docker compose -f lab/docker-compose.yml --profile fixtures down
docker volume rm lab_brolga-data   # destructive: deletes the lab database volume
rm -rf lab/output/*
```

## Related

- Root [`docker-compose.yml`](../docker-compose.yml) — operator homelab (`doctor` / `serve`)
- [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md)
- Issue [#60](https://github.com/jusso-dev/Brolga/issues/60)
