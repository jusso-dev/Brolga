# Deploying Brolga

This is how to run Brolga on your own infrastructure, in a container, with the database on a
volume you control. It is written for a homelab: one host, one operator, no orchestrator.

Read [What is not reachable](#what-is-not-reachable) before you plan anything around this. Brolga
is early, and the shape of what it can and cannot do is unusual enough to be worth knowing up
front.

## What this deploys

A single image containing the `brolga` binary and nothing else that matters. There is no server,
no scheduler, and no background process: every Brolga command opens the database, does one thing,
writes its result to stdout, and exits. A container that "is running Brolga" is a container part
way through one command.

That is why `docker compose up` is not the normal way to use this. The normal way is:

```bash
docker compose run --rm brolga <command>
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

Brolga reads STIX 2.0 and 2.1 and ATT&CK bundles, MISP events, warning lists and feed exports,
Sigma rules, YARA rules, OpenIOC definitions, IODEF incident documents, CEF/LEEF/syslog telemetry,
and CSV/TSV/JSON/NDJSON/plain-text indicator lists. It also reads vulnerability and software
intelligence: OSV records, NVD JSON in both the 2.0 API and retired 1.1 feed shapes, CSAF 2.0 and
CVRF 1.2 vendor advisories, the CISA KEV catalogue, CycloneDX and SPDX JSON bills of materials, and
SARIF static-analysis results. Format is detected per file from its contents,
so a mixed batch is fine and a mislabelled extension does not mislead it.

A vulnerability is keyed on its CVE wherever one is named — including when it is named only in an
advisory's alias list — so the same flaw published as a GHSA record, an NVD entry, and a KEV listing
is one entity with all three sources' claims on it. A package is keyed on its package URL, so a
component named by an SBOM and the same component named by an advisory meet.

Two things Brolga deliberately does not do with this data. It does not compare versions: an affected
range is stored as published, and deciding whether an installed version falls inside it needs a
per-ecosystem comparator that Brolga does not have. And a CISA KEV listing is recorded as *dated
evidence from a named catalogue* — never as a disposition, and never as an exploitation relationship —
because KEV membership means CISA saw exploitation in the wild on a date, not that every deployment
of the affected product is exploitable now.

Detection content — Sigma, YARA, OpenIOC, and SARIF analysis rules — becomes `detection_rule` entities. Brolga **stores rules
and never runs them**: no condition is evaluated, no string is matched, no query is translated. A
rule's detection logic is read only where it names a whole value under plain equality, and every
field that was not read is recorded so `brolga show` can say why a rule contributed no observables.

XML documents carrying a `<!DOCTYPE>` are refused outright rather than parsed with entity expansion
turned off. A DTD is what entity-expansion and external-entity attacks need, and no legitimate
OpenIOC, IODEF, or CVRF document has one.

Drop files into the `feeds/` directory next to `docker-compose.yml`. It is bind-mounted at
`/feeds` **read-only**, because Brolga only ever reads them and a writable mount would let a bug
in an import path damage your own copy of the evidence.

```bash
cp ~/Downloads/threat-bundle.json feeds/
docker compose run --rm brolga ingest /feeds/threat-bundle.json
```

The default mode is strict: a batch
containing anything Brolga cannot accept fails as a whole and writes nothing, because a partial
import is very easily mistaken for a complete one. When you would rather keep what parsed:

```bash
docker compose run --rm brolga ingest --mode permissive /feeds/*.json
```

Permissive persists the acceptable records and quarantines the rest — it does not discard them.
`brolga quarantine` lists what was rejected, which parser rejected it, at which stage, and why.

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
| `network_mode: none` | Brolga makes no outbound connections. Nothing fetches, polls, or reports. Removing the network enforces that rather than documenting it. Connectors arrive in `v0.6.0`; revisit then, and not before. |
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

## What is not reachable

This is the section to read before building anything on top of Brolga. None of the following
exists in the current release, and no container configuration will make it appear:

- **No HTTP API.** There is no port to expose and nothing listens. The Compose file publishes no
  ports because there is nothing to publish. Planned for `v0.5.0`.
- **No MCP server.** An MCP stdio server is planned for `v0.5.0`. Nothing in this image speaks MCP.
- **No connectors.** There is no MISP, TAXII, or OpenCTI client. Brolga will not reach out to any
  upstream platform. Planned for `v0.6.0`.
- **No scheduled or automatic fetching.** Nothing polls, nothing refreshes, nothing runs on a
  timer. Every import is an operator running a command against a file that operator supplied.
- **`brolga context` exits `5`.** Context packs — the compression engine, budgets, progressive
  disclosure, the thing the project exists to do — are `v0.4.0`. The command is declared so that a
  script written against a later Brolga fails with a message naming the milestone rather than an
  unhelpful "unrecognised subcommand". It writes nothing to stdout.
- **No plugins and no declarative mappings.** `v0.7.0`.
- **No PostgreSQL.** SQLite is the only backend. Server mode is `v1.0.0`.
- **No web interface.** None is planned for the initial release.
- **No metrics endpoint, no Prometheus exporter, no structured audit sink.** Diagnostics go to
  stderr, and `--log-format json` gives you one object per line for a log collector to pick up.

What you can dogfood today is the part below the compression engine: get real feeds in, see what
canonicalised, see what was rejected and why, and see the original bytes that every record was
derived from. That is a genuinely useful thing to run against your own data, and it is the part
the project has evidence for.

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

**Also verified, in the image rather than natively:** ingesting a STIX 2.1 bundle, a MISP event and
a plain indicator list in one batch — 37 records accepted, 3 source objects retained, 2 quarantined
with their reasons — then reading them back with `stats`, `sources`, and `quarantine` from separate
containers against the same volume. The output is identical to the native binary's. `id` inside the
container reports `uid=65532(brolga)`, and the same run succeeds under `--read-only --network none
--cap-drop ALL`.

**Not verified:**

- **The `linux/amd64` build.** Only arm64 was built. The base images are pinned to multi-arch
  indexes, but that is not evidence the amd64 manifest compiles. The release-smoke job in CI does
  build and run the binary on `ubuntu-latest`, which is amd64 — but natively, not in this image.
- The `sqlite3 ".backup"` alternative, the restore-from-tar sequence, and copying a config into the
  volume. Written from the same primitives as the recipes that were executed, and not themselves run.

## Running the HTTP API

Brolga's other shape: a read-only server that other services pull context from. See
[docs/API.md](API.md) for the routes and the response contract.

```bash
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
docker compose --profile serve up -d brolga-api
```

It is behind a Compose profile, so a bare `docker compose up` still runs `doctor` and exits rather
than quietly starting a daemon.

### The token is required, not optional

`BROLGA_API_TOKEN` has no default and no fallback. Compose refuses to render the file without it,
and the server exits 3 rather than starting — a missing token is a failed deployment rather than an
open database.

```console
$ docker compose --profile serve up -d brolga-api
required variable BROLGA_API_TOKEN is missing a value: set BROLGA_API_TOKEN to a token of at
least 16 characters
```

### Who can reach it

The published port binds the host's loopback by default. To let other machines reach it:

```bash
export BROLGA_API_BIND=0.0.0.0
docker compose --profile serve up -d brolga-api
```

Publishing to every interface is deliberately something you have to type. Note that the container's
own `--bind 0.0.0.0` is not the boundary — the container's network namespace is, and the published
port is what crosses it.

### Checking it

```bash
curl -s localhost:8787/api/v1/health                                   # no token needed
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" \
     localhost:8787/api/v1/stats | jq .data
```

`/health` is exempt from authentication so a probe does not fail when the token rotates. Everything
else returns 401 without a valid token.

### Sharing the database with the CLI

Both services use the `brolga-data` volume, so ingest with the command-line service and the running
API sees the result:

```bash
docker compose run --rm brolga ingest /feeds/bundle.json --mode permissive
curl -s -H "Authorization: Bearer $BROLGA_API_TOKEN" localhost:8787/api/v1/stats | jq .data
```

SQLite allows one writer and many readers, so an ingest running while the API serves is fine. Two
ingests at once are not — the second waits on the busy timeout and then fails.

### What the container gives up

Read-only root filesystem, every capability dropped, `no-new-privileges`, non-root user, 1 GB
memory, 256 processes. The API makes no outbound connections; unlike the command-line service it
cannot use `network_mode: none`, because it has to answer on a port.

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
