# ADR 0004 — The graph crate boundary

- Status: accepted
- Date: 2026-07-29
- Milestone: `v0.3.0 — Intelligence graph`
- Issue: [#20](https://github.com/jusso-dev/Brolga/issues/20)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1, as
  [0003](0003-ingestion-crate-boundary-and-parser-panic-policy.md) already did. Every other section
  of ADR 0001 stands unchanged.

## Context

`v0.3.0` is seven issues that are all the same kind of thing: deciding what the accumulated records
*mean*. Deduplication ([#20](https://github.com/jusso-dev/Brolga/issues/20)), entity resolution
([#21](https://github.com/jusso-dev/Brolga/issues/21)), contradiction detection
([#22](https://github.com/jusso-dev/Brolga/issues/22)), temporal decay
([#23](https://github.com/jusso-dev/Brolga/issues/23)), traversal
([#24](https://github.com/jusso-dev/Brolga/issues/24)), and checkpoints
([#25](https://github.com/jusso-dev/Brolga/issues/25)).

None of them belongs where the existing crates are.

`brolga-storage` is deliberately "backend-neutral traits, migration runner, SQLite backend". Putting
a deduplication *algorithm* there would make the storage layer opinionated about meaning, and would
mean a future PostgreSQL backend ([#55](https://github.com/jusso-dev/Brolga/issues/55)) had to
re-implement or inherit it.

`brolga-ingest` is upstream of the graph. Deduplication runs over records that are already
persisted, from many imports, and making ingestion depend on that inverts the direction.

## Decision

### 1. One new crate: `brolga-graph`

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-graph` | Deduplication, entity resolution, contradiction detection, confidence components, temporal state and decay, bounded traversal, checkpoints and deltas | `brolga-model`, `brolga-security`, `brolga-storage` |

It sits above `brolga-storage` and beside `brolga-ingest`, which it does **not** depend on and which
does not depend on it. A parser and a deduplicator have no business knowing about each other: one
turns bytes into records, the other decides what a pile of records means.

`v0.3.0`'s six implementation issues are modules inside it, for the same reason `v0.2.0`'s parsers
are modules inside `brolga-ingest` — they share types heavily and none of them is independently
shippable.

### 2. Every decision this crate makes is a record, not a side effect

A deduplication that silently collapses two records leaves nobody able to answer "why is there one
of these?". So each decision type in this crate persists **what it decided, what it compared, which
algorithm and version decided it, and why** — and that is a requirement on the crate rather than a
feature of one module, because the same obligation recurs in resolution, contradiction, and decay.

This is what [#20](https://github.com/jusso-dev/Brolga/issues/20)'s "every decision exposes inputs,
algorithm version, and reasons" asks for, generalised to the milestone that follows it.

## Alternatives rejected

**Put it in `brolga-storage`.** Rejected above: it makes the storage layer opinionated about
meaning, and burdens the second backend.

**Put it in `brolga-ingest`.** Rejected: the dependency direction is wrong, and it would make a
parser crate grow a graph algorithm.

**Finally build `brolga-core` and put it there.** Tempting, because ADR 0001 §1 named that crate and
ADR 0003 recorded that it was never built. Rejected: `brolga-core` was specified as "application
services and orchestration shared by every interface", and graph algorithms are neither. Building it
now with the wrong contents would make the name wrong rather than making the table true. It remains
unbuilt until there is a second interface to orchestrate for — realistically the HTTP API,
[#35](https://github.com/jusso-dev/Brolga/issues/35).

## Consequences

- The workspace has seven crates; ADR 0001 §1's table remains the *permitted* set, per ADR 0003.
- `brolga-cli` will eventually depend on this crate. It does not yet, because no command reaches
  graph behaviour ([#34](https://github.com/jusso-dev/Brolga/issues/34)).
- Decision records are a compatibility surface under ADR 0001 §6, carrying an
  `(algorithm_id, algorithm_version)` pair. Changing what an existing pair decides for the same
  inputs is a breaking change; adding a new algorithm id is not.
