# Deploying Brolga

This is how to run Brolga on your own infrastructure, in a container, with the database on a
volume you control. Written for a homelab: one host, one operator, no orchestrator.

## What this product is

Brolga is a **STIX normalizer + local store + context API**. One image, two shapes:

| Shape | Compose service | Role |
| --- | --- | --- |
| **CLI** | `brolga` | `docker compose run --rm brolga <cmd>` — ingest, fetch, query |
| **HTTP API** | `brolga-api` (profile `serve`) | Long-running read-only server for other products |

Same SQLite volume. CLI writes; API reads (and needs WAL write access).

**Primary TI source:** an **OpenCTI instance you host yourself**. Brolga does **not** ship or start
OpenCTI. Pull with `brolga fetch opencti` (needs network + `BROLGA_OPENCTI_TOKEN`). Secondary:
TAXII collections and local STIX / flat / Sigma files.

**Not in this product:** MISP, plugins, LLM, MCP, web UI, scheduled polling.

## What this deploys

A single image containing the `brolga` binary. Default CLI service has **no network** and exits after
one command. The API service is a daemon behind `docker compose --profile serve`.

```bash
docker compose run --rm brolga <command>          # one-shot CLI
docker compose --profile serve up -d brolga-api   # HTTP server
```

## Prerequisites

- Docker with Compose v2 and BuildKit. BuildKit is the default in current Docker; the build uses
  cache mounts and will not work without it.
- About 2 GB of memory available to the build. Compiling the workspace in release mode is by far
  the most expensive thing in this document.
- No network access at runtime. The container is given none — see
  [Hardening](#hardening-and-what-it-costs).

## Build

```bash
git clone https://github.com/jusso-dev/Brolga.git
cd Brolga
mkdir -p feeds
docker compose build
```

The result is roughly a 20 MB image. Two things account for that:

- **The runtime layer carries no toolchain.** The build is multi-stage. The Rust compiler, the C
  toolchain that SQLite's bundled source needs, and the registry cache all stay in the builder
  stage and are discarded.
- **Both base images are pinned by digest**, not by tag, so a rebuild six months from now
  produces the same layers underneath your binary rather than whatever `alpine:3.22` has become.
  The digests are multi-architecture indexes; amd64 and arm64 hosts both resolve correctly from
  the same pin.

The one input a digest does not pin is the `apk add build-base` in the builder stage, which
resolves against Alpine's repositories at build time. The `Dockerfile` says so rather than
implying the build is hermetic.

`--locked` is passed to `cargo build`, so the image is built from the dependency versions in
`Cargo.lock` — the ones the repository has actually tested — and the build fails rather than
silently resolving something newer.

## First run

```bash
docker compose run --rm brolga doctor
```

`doctor` checks what you would otherwise discover one failure at a time: configuration parses,
configuration validates, storage opens, migrations apply, records are countable. Every check runs
even after an earlier one fails, so you get the whole picture in one go. It exits `0` when all
pass and `3` otherwise.

A first run on a fresh volume creates and migrates the database, and looks like this:

```text
    ok  configuration files: 0 file(s) parsed
    ok  configuration: valid, fingerprint 3949b0a20cc6
    ok  storage: schema version 5, migrated
    ok  stored entities: 0

4 check(s), 0 failed. Correlation id b53eec4e4a5b4f759546bd753fb80e7e.
```

`0 file(s) parsed` is not a problem. Brolga has built-in defaults for every setting and does not
require a configuration file at all.

## End-to-end homelab (SQLite + API)

Copy-paste path from a clean checkout. Needs Docker Compose v2 and ~2 GB free for the release
build. Secrets stay on the host (`.env` is gitignored).

```bash
cp .env.example .env
# edit BROLGA_API_TOKEN to ≥16 random characters, or:
printf 'BROLGA_API_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env

mkdir -p feeds
docker compose build
docker compose run --rm brolga doctor
# Image ships demo files at /feeds/…; host drop dir is /feeds-host (see compose).
docker compose run --rm brolga ingest \
  /feeds/demo-stix.json /feeds/demo-sigma.yml --mode permissive
docker compose run --rm brolga context ip 203.0.113.42
docker compose --profile serve up -d brolga-api
set -a; . ./.env; set +a
curl -s localhost:8787/api/v1/health
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" localhost:8787/api/v1/stats
```

Multi-format offline lab (issue #60 fixtures): see [`lab/README.md`](../lab/README.md).

PostgreSQL instead of SQLite:

```bash
export BROLGA_POSTGRES_PASSWORD=change-me
# reuse BROLGA_API_TOKEN from .env
docker compose -f docker-compose.yml -f docker-compose.postgres.yml \
  --profile serve --profile postgres up -d --build
# doctor reads storage path from config (default SQLite). Open postgres via any store command:
docker compose -f docker-compose.yml -f docker-compose.postgres.yml run --rm brolga \
  stats --database "postgres://brolga:${BROLGA_POSTGRES_PASSWORD}@postgres:5432/brolga"
```

## Configuration, if you want it

Brolga does **not** search for a configuration file. There is no `/etc/brolga/brolga.yaml` that is
picked up implicitly, because a tool that silently changes behaviour based on a file you did not
mention is a tool you cannot reason about. Every layer is named on the command line with
`--config`, and later files override earlier ones.

The container's working directory is `/data`, which is the volume, so relative paths land on the
volume without any flag:

```bash
docker compose run --rm brolga init                              # writes /data/brolga.yaml
docker compose run --rm brolga -c brolga.yaml config validate
docker compose run --rm brolga -c brolga.yaml config explain --changed-only
```

`config explain` reports which layer supplied each setting, which is the question you actually
have when a layered configuration surprises you. `init` refuses to overwrite an existing file
unless `--force` is given.

Editing the file means editing it on the volume. The easiest route is to write it on the host and
copy it in — see [Reading and writing the volume](#reading-and-writing-the-volume).

## Ingesting a file

Brolga accepts:

| Input | How |
| --- | --- |
| **OpenCTI** | `brolga fetch opencti https://…` (GraphQL → `toStix`) |
| **TAXII 2.0/2.1** | `brolga fetch taxii https://…` |
| **STIX 2.0/2.1** files | `brolga ingest bundle.json` |
| Flat feeds | CSV / TSV / JSON / NDJSON / plain-text indicators |
| Sigma rules | Stored as `detection_rule` entities — **never executed** |
| Custom shapes | `brolga ingest … --mapping mapping.yml` |

Format is detected per file. Default mode is **strict** (any unreadable record fails the batch).
`--mode permissive` keeps what parsed and quarantines the rest.

Drop files into `feeds/` next to `docker-compose.yml` (host mount → `/feeds-host`). Image demos live
at `/feeds/demo-stix.json` and `/feeds/demo-sigma.yml`.

```bash
docker compose run --rm brolga ingest /feeds/demo-stix.json /feeds/demo-sigma.yml --mode permissive
# host files:
docker compose run --rm brolga ingest /feeds-host/my-bundle.json --mode permissive
```

## Reading what is in the store

```bash
docker compose run --rm brolga stats
docker compose run --rm brolga sources
docker compose run --rm brolga show <id>
docker compose run --rm brolga quarantine --source <digest>
```

Everything takes `--output json`, and stdout carries only the result. Diagnostics, progress, and
errors go to stderr without exception, so this is safe:

```bash
docker compose run --rm brolga --output json stats | jq .
```

## Where the database lives

Inside the container, `/data/brolga.sqlite`. `/data` is the named volume `brolga_brolga-data` —
Compose prefixes the project name from the `name:` key in `docker-compose.yml`.

```bash
docker volume inspect brolga_brolga-data --format '{{.Mountpoint}}'
```

On a Linux host that is a real path you can read directly. On macOS or Windows it is a path inside
the Docker VM and the host cannot see it, so use the container-based recipes below rather than
reaching for the mount point.

A named volume was chosen over a bind mount deliberately. SQLite depends on POSIX advisory locking
behaving correctly, and a bind mount into a virtualised filesystem is the classic way to discover
that it does not. Named volumes stay inside the engine's own filesystem.

### Reading and writing the volume

```bash
# Copy a configuration file in.
docker run --rm -v brolga_brolga-data:/data -v "$PWD:/host" \
  --user 65532:65532 \
  alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  cp /host/brolga.yaml /data/brolga.yaml

# Look at what is there.
docker run --rm -v brolga_brolga-data:/data:ro \
  alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  ls -la /data
```

`--user 65532:65532` matches the uid the image runs as. Writing to the volume as root leaves files
Brolga cannot open, and that failure shows up much later than the mistake.

## Backing it up

**Read this section before writing a backup script.** SQLite in WAL mode does not behave the way
"just copy the file" assumes.

Brolga opens the database with `journal_mode = WAL`, so readers do not block the writer and the
writer does not block readers. The cost is that the database is not one file. It is up to three:

| File | What it holds |
| --- | --- |
| `brolga.sqlite` | The main database |
| `brolga.sqlite-wal` | Committed transactions not yet folded back into the main file |
| `brolga.sqlite-shm` | A shared-memory index into the WAL. Rebuildable; never worth copying |

The consequence: **copying `brolga.sqlite` on its own can give you a database missing the most
recent commits, or an internally inconsistent one if a write was in flight.** The backup will
often open without complaint, which is what makes this worth stating plainly — you find out at
restore time.

Brolga's shape makes this easy to get right. Because every command exits, a clean shutdown
checkpoints the WAL back into the main file and removes the `-wal` and `-shm` files. So when no
Brolga container is running, there is usually nothing but `brolga.sqlite` on the volume, and
copying it is correct.

"Usually" is doing real work in that sentence. If a process was killed, or a run is still in
progress, the `-wal` file will be there and it will matter. Two safe options:

**Copy everything, with nothing running.** Simple, and correct whether or not a `-wal` survives.

```bash
docker compose down                       # make sure nothing is mid-command
mkdir -p backups
docker run --rm \
  -v brolga_brolga-data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  tar -czf "/backup/brolga-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" -C /data .
```

**Or use SQLite's own online backup**, which is safe against a concurrent writer and does the
checkpointing for you. It needs an `sqlite3` binary; the Brolga image does not ship one, on purpose
— a database shell inside the runtime image is a way to modify the store without leaving a trace in
provenance.

```bash
docker run --rm -v brolga_brolga-data:/data -v "$PWD/backups:/backup" \
  --entrypoint sh \
  alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /data/brolga.sqlite ".backup /backup/brolga.sqlite"'
```

Note this one mounts the volume writable: an online backup checkpoints the WAL, which is a write.

### Restoring

Stop everything, then unpack into an empty volume:

```bash
docker compose down
docker volume rm brolga_brolga-data
docker volume create brolga_brolga-data
docker run --rm -v brolga_brolga-data:/data -v "$PWD/backups:/backup" \
  --user 65532:65532 \
  alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce \
  tar -xzf /backup/brolga-<timestamp>.tar.gz -C /data
docker compose run --rm brolga doctor
```

`doctor` afterwards is not a formality. Every applied migration's checksum is recorded and
re-verified at start-up, so a restored database that does not match the schema the binary expects
fails there rather than halfway through your next import.

## Hardening, and what it costs

The Compose file applies more than the usual defaults, and each one is a claim about Brolga that
is currently true:

| Setting | Why |
| --- | --- |
| `network_mode: none` | Default CLI service makes no outbound connections. File ingest needs none. Connectors (`brolga fetch`) need a network — drop this line or use a one-off `docker run` with a network when fetching. |
| `read_only: true` | Everything Brolga writes is on the volume. The image layers never need to change. |
| `tmpfs: /tmp` | SQLite falls back to temporary files for large sorts, and a read-only root would otherwise fail there under load rather than during a test. |
| `cap_drop: ALL` | The binary opens files and writes a database. It needs no capability at all. |
| `no-new-privileges` | There is no setuid binary in the image and there should be no way to acquire one. |
| `user 65532` | A fixed numeric uid, so the volume's ownership stays meaningful across rebuilds and so a Kubernetes `runAsUser` has a number to use. |
| `mem_limit`, `pids_limit` | A parser handling untrusted input is exactly where a resource ceiling belongs. These are generous for a homelab; Brolga applies its own configured limits well below them. |

`restart: "no"` is deliberate and is the one that surprises people. A restart policy exists to
bring a crashed daemon back. Applied to a command that is meant to exit, it reads a successful run
as a fault and restarts it for ever. If you want Brolga to run on a schedule, use the host's
scheduler — systemd timer or cron — invoking `docker compose run --rm brolga ...`. There is nothing
inside Brolga that runs anything on a timer.

## Multiple writers

Do not run two Brolga commands against the same database at once. SQLite permits it and the busy
timeout will absorb short overlaps, but a homelab has no reason to find the edges of that. Run
imports one at a time.

## What is and is not reachable

### Works in the image

- **CLI:** `ingest`, `fetch` (OpenCTI / TAXII — needs network; default CLI service is `network_mode: none`, so use a one-off with network or run fetch on the host binary), `stats`, `sources`, `show`, `quarantine`, `search`, `neighbours`, `checkpoint`, `context`, `export`, `mapping`.
- **HTTP API:** Compose profile `serve` → `brolga-api` on host port `8787`. See [Running the HTTP API](#running-the-http-api) and [API.md](API.md).
- **PostgreSQL (optional):** build with `BROLGA_FEATURES=postgres` + `docker-compose.postgres.yml`.

### You host separately

- **OpenCTI** — Brolga only *consumes* it. Install [OpenCTI](https://docs.opencti.io/) (or use an existing instance), create an API token, set `BROLGA_OPENCTI_TOKEN`, then `brolga fetch opencti …`.
- **Host scheduler** for periodic fetch (`cron` / systemd timer calling `docker compose run … fetch`).

### Not provided

- No MISP, no web UI, no Prometheus exporter, no built-in polling, no publish-back to OpenCTI.

### Lab / offline demo

[`lab/`](../lab/) — multi-format fixtures without a network.

## Troubleshooting

**`doctor` exits `3`.** Configuration failed to load or validate. Run
`docker compose run --rm brolga -c brolga.yaml config validate` — it reports *every* problem in one
pass, each naming the setting's dotted path.

**A command exits `4`.** Storage could not be opened, migrated, read, or written. Usually a
permissions problem on the volume: check that `/data` is owned by `65532`.

**A command exits `5`.** The command exists but this build does not implement it. That is a
version mismatch, not an outage — the message names the milestone.

**Any other exit code.** Read them from the binary you are actually running, rather than from a
table that may have drifted:

```bash
docker compose run --rm brolga --output json exit-codes
```

## See also

- [docs/CLI.md](CLI.md) — the output contract, exit codes, global options, and every command
- [docs/ROADMAP.md](ROADMAP.md) — what each milestone delivers and what its exit gate demands
- [docs/THREAT-MODEL.md](THREAT-MODEL.md) — trust boundaries, controls, and residual risks

## What has and has not been verified

Stated because a deployment guide that quietly mixes tested and untested steps is worse than one
that admits the difference.

**Verified by running:** the image builds on `linux/arm64` and is about 20 MB; `docker compose
config`; `--version`, `doctor`, `init`, `config validate`, and `config explain` through
`compose run`; `docker compose up` running `doctor` and exiting without restarting; the volume
holding `brolga.sqlite` owned by the non-root user, with a read-only root filesystem, no network,
and all capabilities dropped; and the `tar` backup recipe.

**Also verified, in the image rather than natively:** ingesting STIX + Sigma demo fixtures, then
reading them back with `stats` / `context` and serving `/api/v1/*` from `brolga-api`.

**Not verified:**

- **The `linux/amd64` build.** Only arm64 was built. The base images are pinned to multi-arch
  indexes, but that is not evidence the amd64 manifest compiles. The release-smoke job in CI does
  build and run the binary on `ubuntu-latest`, which is amd64 — but natively, not in this image.
- The `sqlite3 ".backup"` alternative, the restore-from-tar sequence, and copying a config into the
  volume. Written from the same primitives as the recipes that were executed, and not themselves run.

## Running the HTTP API

Read-only server for other products on your LAN. Routes and auth: [API.md](API.md).

### Loopback only (default)

```bash
cp .env.example .env
printf 'BROLGA_API_TOKEN=%s\n' "$(openssl rand -hex 32)" > .env
docker compose --profile serve up -d brolga-api
curl -s localhost:8787/api/v1/health
```

### Homelab / LAN (other machines)

Publish on all interfaces so services on the same network can call Brolga:

```bash
# in .env
BROLGA_API_TOKEN=<at least 16 random chars>
BROLGA_API_BIND=0.0.0.0
```

```bash
docker compose --profile serve up -d --build brolga-api
```

From another host:

```bash
curl -s http://192.168.1.19:8787/api/v1/health
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" \
  http://192.168.1.19:8787/api/v1/stats
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"kind":"ip","value":"203.0.113.42"}}' \
  http://192.168.1.19:8787/api/v1/context
```

`BROLGA_API_TOKEN` is **required** when binding off loopback. Compose fails to render without it;
the process exits 3 rather than serving an open database.

### Token

```bash
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
```

Clients send `Authorization: Bearer <token>`. `/api/v1/health` needs no token.

### Share the database with the CLI

```bash
docker compose run --rm brolga ingest /feeds/demo-stix.json --mode permissive
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" localhost:8787/api/v1/stats
```

One writer at a time for ingest; the API may serve during a single ingest.

### Pulling from OpenCTI into this host

CLI default service has `network_mode: none`. For fetch, give the one-off a network:

```bash
export BROLGA_OPENCTI_TOKEN=…   # never on the CLI flags
docker compose run --rm --network bridge brolga \
  fetch opencti https://opencti.example.org --name lab-octi --allow-private
```

(Adjust URL/network policy for your OpenCTI placement.)

## Audit events

Every disclosure decision is recorded. An event carries **hashes and identifiers, never content**:
the subject is a canonical identifier, the source is a content address, the outcome is a code, and
the policy rule is a kind from a closed vocabulary.

There is deliberately no field for a body, a message, or a value. An audit log is read by more
people than the data it describes, kept longer, and shipped to systems with different access rules —
a type that accepted a `details` string would collect source content inside a release, because
somebody would reasonably put the useful thing there.

### Fail-open and fail-closed

A gap in an audit log is indistinguishable from nothing having happened, so which way a write
failure falls is decided per action rather than globally:

| Action | If the audit write fails |
| --- | --- |
| `expand_canonical`, `expand_source` | **Refuse.** Serving material whose disclosure could not be recorded is how a breach becomes unprovable. |
| `policy_denied`, `authentication_failed` | **Refuse.** |
| `configuration_changed` | **Refuse.** |
| `context_read`, `ingest`, `fetch` | **Proceed**, and surface the failure. Refusing a read because a disk is full converts a monitoring problem into an outage. |

`FailurePolicy::for_action` is the single place that decides, so an operator can read which way a
deployment falls instead of learning it from behaviour under failure — the worst possible time.

### Metric cardinality

Labels come from closed vocabularies and are bounded at 64 distinct values each. A label derived
from a subject value would give a metrics backend one time series per observable, which is how a
monitoring system falls over because somebody ingested a feed.

Past the ceiling the **label** is refused, not the operation: the thing being measured is fine, and
the metric stops growing rather than the process stopping. Values already seen keep counting, so
existing series continue to work.
