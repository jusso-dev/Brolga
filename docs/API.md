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
| `POST /context` | **The context pack.** What is known about one observable. |

### `POST /context`

The route Brolga exists for. A consumer holds one observable — an address from a firewall log, a
hash from an endpoint detection — and asks what is known about it.

```bash
curl -s -X POST localhost:8787/api/v1/context \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $BROLGA_API_TOKEN" \
  -d '{"subject":{"kind":"ip","value":"203.0.113.42"},"purpose":"case_enrichment"}'
```

```json
{
  "schema_version": "brolga.context_pack/1.0",
  "subject": { "kind": "ipv4_address", "value": "203.0.113.42" },
  "observable_id": "observable:7168327b-…",
  "detail_level": "L1",
  "disposition": "malicious",
  "entities": [ { "id": "entity:9c8e…", "kind": "report", "name": "C2 infrastructure", "status": "active" } ],
  "claims": [ { "predicate": "disposition", "object": "malicious", "status": "active" } ],
  "relationships": [ { "kind": "part_of", "source": "observable:7168…", "target": "entity:9c8e…", "status": "active" } ],
  "evidence": [ { "source_object_id": "source:12fc…" } ],
  "gaps": [ "no sightings recorded; Brolga cannot say when this was last seen" ],
  "exclusions": [],
  "budget": { "requested": {}, "consumed": { "max_objects": 2, "max_relationships": 1 } }
}
```

#### Subject kinds

`ip`, `ipv4`, `ipv6`, `domain`, `hostname`, `url`, `file_hash`, `md5`, `sha1`, `sha256`, `email`.

Spelling does not matter: whitespace, letter case, and IPv6 abbreviation are all normalised, and
`ip` resolves to the same observable as `ipv4`/`ipv6`. A digest may be bare or carry its algorithm
(`md5:d41d8…`), and a stated algorithm always beats inference from length.

The pack echoes the **canonical** subject, which may differ from what you sent. Cache by that, not
by what you asked with.

#### `disposition`

`malicious`, `suspicious`, `allow_listed`, `benign`, or `unknown` — the strongest *currently
standing* disposition claimed about the subject.

**`unknown` means Brolga has not heard of it. It does not mean benign.** Treating the two alike
closes alerts that should have been raised. Withdrawn claims are ignored rather than counted, and
an observable whose claims have all been retracted reports `unknown` and says so in `gaps`.

#### `gaps` and `exclusions`

`gaps` is what Brolga does not know, stated rather than left to be inferred from an empty array.
`exclusions` is what was deliberately left out — a budget that truncated the answer says so, because
a silently truncated pack reads as a complete one.

`exclusions[].reason` is a **closed vocabulary**, not prose, because a consumer has to branch on it:

| Reason | Retrying with a larger budget helps |
| --- | --- |
| `budget_exhausted` | yes |
| `policy_restricted` | no |
| `below_detail_level` | no |
| `not_implemented` | no |

A free-text reason would make those indistinguishable to anything but a human, and retrying a policy
refusal is how a client turns a refusal into a loop.

`budget.exhausted` is a separate boolean rather than something to infer by comparing `requested` and
`consumed`. A consumer that has to derive "was this truncated?" from six optional numbers will
eventually derive it wrongly, and the failure mode is treating a partial answer as a complete one.
A pack that reports an exhausted budget and lists no budget exclusion fails validation.

#### `findings` and evidence

Every entry in `findings` and `recommendations` carries a non-empty `evidence` array. That is
enforced by the schema's validation, not left to convention: an assertion an analyst cannot trace to
a retained source object is one they cannot defend, and enrichment that cannot be defended is worse
than none. A pack whose finding cites nothing is rejected rather than served.

#### `fingerprint`

A digest over the pack's **content**. Two packs built from the same graph, for the same subject,
under the same profile fingerprint alike however far apart they were built — which is what makes a
pack cacheable and a diff between two of them meaningful.

Deliberately outside the fingerprint's input, and published as `FINGERPRINT_EXCLUDED` so a consumer
can state what it relies on: `generated_at`, `request_id`, `build_duration_ms`, `brolga_version`.
Including the timestamp would make every pack unique, which sounds harmless and destroys every use
the fingerprint has.

`metadata.graph_version` **is** inside it. A pack built against a different graph is a different
answer even when it says the same words.

The fingerprint is recomputed on deserialisation and compared against the declared value. A pack
edited in transit does not parse, so a consumer caching on the fingerprint cannot cache the wrong
contents under the right key.

#### Detail levels

`detail_level` is accepted but only `L1` is served. The pack reports the level **actually served**
and notes the difference in `exclusions`, so a consumer is never told it received depth it did not.

#### Where observables come from

Observables reach Brolga through MISP attributes and through STIX `indicator` patterns. Both paths
run the value through the same canonicalisers, so one address published by both feeds is one
observable in the graph rather than two — a lookup finds everything held about it, not half.

The STIX side maps `=` comparisons against `ipv4-addr:value`, `ipv6-addr:value`,
`domain-name:value`, `url:value`, `email-addr:value`, or `file:hashes.'<algorithm>'`, joined by
`OR` if there is more than one. Any other pattern — `AND`, `FOLLOWEDBY`, an operator other than
`=`, an object path with no canonicaliser, several bracketed expressions, a `pattern_type` other
than `stix`, or a `pattern_version` outside 2.x — is quarantined with a reason naming the
construct, never partially extracted. Half a pattern asserts something broader than the publisher
did, which is worse than an unparsed one; a quarantined indicator is at least visible in
`brolga quarantine`.

A disjunction fans out to a claim per alternative, because a published address list is how feeds
spell one. That is a widening — the publisher said *one of* these matched — so every resulting
claim carries the whole pattern text and a `stix.indicator.alternatives` count, and a consumer can
tell a lone assertion from one alternative out of fifty without re-parsing anything. Ordinary
single-observable indicators carry no count.

`indicator_types` reaches the pack's `disposition` only where it states an assessment
(`malicious-activity`, `benign`, `anomalous-activity`, `compromised`). A descriptive label such as
`anonymization` or `attribution` is recorded as a claim and asserts no disposition, because
presence in a feed is not evidence of maliciousness. `valid_from` and `valid_until` become the
claim's validity window, and the indicator's `name` and `description` are kept as evidence.

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
