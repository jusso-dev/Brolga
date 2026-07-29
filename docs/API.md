# The HTTP API

Brolga serves a versioned, **read-only** HTTP API so that other services can pull context from it.

```bash
brolga serve --database brolga.sqlite
# serving brolga.sqlite on http://127.0.0.1:8787/api/v1 (loopback, no token required)
```

## Why read-only

Ingestion stays on the CLI, where the operator running it chose the source. A read-only surface is
one that cannot be talked into rewriting the graph by a service that was only meant to look at it,
and "which of my three integrations corrupted the graph" is not a question worth having to answer.

## Why a server at all

Three services pulling from one Brolga cannot each shell out to the CLI over a shared SQLite file:
SQLite has one writer, the binary would have to be installed everywhere, and every consumer would
need filesystem access to the database. One process owns the file and answers questions about it.

## Binding and authentication

| Bind | Token | Result |
|---|---|---|
| `127.0.0.1:8787` (default) | none | Serves |
| `127.0.0.1:8787` | set | Serves, token required |
| Anything else | none | **Refuses to start** |
| Anything else | set | Serves, token required |

The refusal is on the *address*, not on anyone's belief about the network. "It is only on the LAN"
and "there is a firewall in front of it" are claims the process cannot verify and which stop being
true without anyone editing the config.

`0.0.0.0` and `::` count as reachable. They read as "no particular address" and bind every
interface the host has.

```console
$ brolga serve --bind 0.0.0.0:8787
refusing to bind 0.0.0.0:8787: it is reachable from other hosts and no token is configured.
Set a token, or bind 127.0.0.1. Set BROLGA_API_TOKEN to a token of at least 16 characters.
$ echo $?
3
```

### The token

Set `BROLGA_API_TOKEN`. An environment variable rather than a flag, because a flag lands in the
process table where every other user on the host can read it, and in the shell history of whoever
typed it.

```bash
export BROLGA_API_TOKEN="$(openssl rand -hex 32)"
brolga serve --bind 0.0.0.0:8787
```

Requirements: at least 16 characters, printable ASCII, no spaces. A token with a space in it is
silently truncated at the space by some clients, which authenticates a prefix of the secret.

Clients present it as a bearer token:

```bash
curl -H "Authorization: Bearer $BROLGA_API_TOKEN" http://brolga:8787/api/v1/stats
```

`/api/v1/health` is exempt. A liveness probe that needs a credential reports a working process as
dead whenever the token is rotated, and the response reveals nothing that having the port open does
not.

## Routes

All under `/api/v1`.

| Route | Returns |
|---|---|
| `GET /health` | Liveness. Does not touch the store. |
| `GET /ready` | Readiness. Reads the schema version — the store must have migrated. |
| `GET /stats` | Counts of every record kind, from a single consistent read. |
| `GET /entities` | Search. `?kind=`, `?status=`, `?current=`, `?limit=`, `?offset=` |
| `GET /entities/{id}` | One entity, with its full provenance chain. |
| `GET /entities/{id}/neighbours` | Relationships at that entity. `?direction=outgoing\|incoming\|both` |

### Paging

`?limit=` is clamped to 1000 rather than refused, so "give me everything" pages instead of failing.
A full page comes back with a `next_offset`; the absence of one means the end.

```bash
curl -s "localhost:8787/api/v1/entities?limit=100" | jq -r '.next_offset // "end"'
```

A `next_offset` means "there may be more", not "there is more" — the last full page yields a
cursor to an empty one. That is cheaper than the alternative, which silently truncates the answer.

## Response shape

Every successful body:

```json
{
  "schema": "brolga.api.v1/1.0",
  "data": { },
  "next_offset": 100
}
```

Every failure:

```json
{
  "schema": "brolga.api.error/1.0",
  "error": { "code": "not_found", "message": "entity entity:… was not found" },
  "request_id": "0278fc9b-2954-4915-9590-444bb828c759"
}
```

Branch on `code`, never on `message`. The codes are a compatibility surface; the messages are not.

| `code` | Status | Meaning |
|---|---|---|
| `bad_request` | 400 | A parameter was malformed. The message lists the valid values. |
| `unauthorized` | 401 | No token, or the wrong one. |
| `not_found` | 404 | No such record, or no such route. |
| `payload_too_large` | 413 | Body over the limit. |
| `timeout` | 504 | The request ran past its deadline. |
| `internal` | 500 | Something failed you cannot act on. Quote the `request_id`. |

A storage failure is always `internal`. Storage errors name files, SQL fragments, and migration
state; the detail is logged against the request id rather than returned.

### Request ids

Every response carries `x-request-id`, including ones produced by the timeout and body-limit layers
that never reach a handler — which is exactly when you need it.

### Schema versions

`brolga.api.v1/1.0` and `brolga.api.error/1.0` are compatibility surfaces under
[ADR 0001 §6](adr/0001-repository-charter.md). Adding a field does not move a version; removing
one, renaming one, or changing a type does. They are versioned separately so that error handling
does not need revisiting because a search result grew a field.

Check the version rather than assuming it:

```bash
schema=$(curl -s localhost:8787/api/v1/stats | jq -r .schema)
case "$schema" in
  brolga.api.v1/1.*) ;;
  *) echo "unsupported Brolga API schema: $schema" >&2; exit 1 ;;
esac
```

## Limits

| Limit | Default | Flag |
|---|---|---|
| Request body | 1 MiB | — |
| Request deadline | 10s | `--timeout-seconds` |
| Page size | 1000 | — |

## Integrating

The consumers this was built for, and the route each starts from:

- **Kelpie** enriching a case: `GET /entities?kind=…` to match, then
  `GET /entities/{id}/neighbours` to expand. Entities carry their full provenance chain, so a case
  can cite where a claim came from rather than asserting it.
- **Muster** agents answering a question: `GET /entities` with a filter, `GET /stats` first to
  decide whether this Brolga knows anything relevant.
- **Tawny** generating a case from an endpoint detection: `GET /entities?kind=malware_family` or
  `?kind=attack_technique`, then neighbours to decide whether the detection is worth a case.

All three are pull consumers over the same read-only surface, which is why it is a server rather
than three copies of the CLI sharing a database file.
