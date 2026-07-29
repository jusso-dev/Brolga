# ADR 0005 — The connector crate boundary, and how an outbound fetch is constrained

- Status: accepted
- Date: 2026-07-29
- Milestone: `v0.6.0 — Connectors`
- Issues: [#44](https://github.com/jusso-dev/Brolga/issues/44),
  [#42](https://github.com/jusso-dev/Brolga/issues/42)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1, as
  [0003](0003-ingestion-crate-boundary-and-parser-panic-policy.md) and
  [0004](0004-graph-crate-boundary.md) already did. Every other section of ADR 0001 stands
  unchanged.
- Records a project-wide exception: **a network call in a default build**, which
  [the ADR rules](README.md#rules) require to be decided here rather than in a code comment.

## Context

`v0.6.0` is three connectors — MISP ([#41](https://github.com/jusso-dev/Brolga/issues/41)), TAXII
([#42](https://github.com/jusso-dev/Brolga/issues/42)), OpenCTI
([#43](https://github.com/jusso-dev/Brolga/issues/43)) — over a shared safety, scheduling, and
sync-state framework ([#44](https://github.com/jusso-dev/Brolga/issues/44)).

Every one of them does the same thing Brolga has never done before: **it originates an outbound
request to an address a configuration file names.** Until now every byte Brolga read was handed to
it. That is a different threat model, and it is the reason this needs a record rather than a module.

None of the existing crates should hold it:

- `brolga-ingest` is deliberately "bytes in, canonical records out". ADR 0003 §1 made a parser
  unable to decide whether it should run, apply limits, or touch storage — precisely so those
  cannot be weakened by leaving something out. A parser that could also *fetch* would be able to
  reach the network from inside the one component that handles the most hostile input in the
  system.
- `brolga-graph` is downstream of persistence and has no business knowing where records came from.
- `brolga-security` holds the *policy* — `NetworkPolicy`, its SSRF classification, its redirect
  rules — and must keep holding only policy. A crate that both defines what is permitted and
  performs the action cannot be audited by reading one file.
- `brolga-storage` is backend-neutral traits and a migration runner. A sync cursor is state a
  connector owns; the table it lives in is storage's.

## Decision

### 1. One new crate: `brolga-connectors`

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-connectors` | Outbound retrieval, transport policy enforcement, sync state and cursors, retry and backoff, per-protocol clients (TAXII first) | `brolga-model`, `brolga-security`, `brolga-storage`, `brolga-ingest` |

It sits **above** `brolga-ingest` and depends on it, because a connector's job ends by handing bytes
to the ingestion pipeline. The dependency does not run the other way and never will: ingestion must
remain runnable with no network stack present at all, which is what keeps the parser fuzzing story
honest.

`brolga-cli` depends on `brolga-connectors`. Nothing else does.

### 2. A connector never opens a socket directly

All retrieval goes through one `Transport` trait. The only implementation that touches a network is
`PolicyTransport`, which wraps an HTTP agent and applies `brolga_security::NetworkPolicy` **itself**,
per request and per redirect hop.

This exists so the security-relevant code is one type rather than a habit. A protocol client — the
TAXII client, and later the MISP and OpenCTI ones — is written against the trait and *cannot* reach
the network another way, so reviewing outbound safety means reviewing one file rather than every
connector anybody adds later.

It also makes the protocol clients testable without a network at all: the test suite injects a
transport backed by a mock server, and no test in the workspace performs a real DNS lookup or opens
an outbound connection.

### 3. Redirects are resolved by us, never by the HTTP agent

The agent is configured with redirect-following **disabled**, and each hop is followed manually
after `NetworkPolicy::permits_redirect` and a fresh address check.

An agent that follows redirects internally re-resolves the target and connects before any of our
code sees it, which makes every SSRF control decorative: a server answers `302` to
`http://169.254.169.254/`, the agent fetches it, and the policy that would have refused that address
never ran. Following hops ourselves costs a loop and is the difference between a control and a
comment.

Each hop is checked in full — scheme, then every address the host resolves to — because a host that
resolved publicly on the first request may resolve differently on the second.

### 4. The sync cursor is advanced only after a page is durably stored

A connector's cursor (`added_after`, an ETag, a pagination token) is written in the **same
transaction** as the records that page produced, and only after ingestion of that page succeeded.

The failure this prevents is silent and permanent: advance the cursor first, fail to store, and the
records in that window are never fetched again. Nothing reports an error — the next run simply
starts after the gap. Storing the cursor with the data makes a crash cost a repeated page, which is
idempotent, instead of a hole nobody can see.

A malformed response therefore quarantines and leaves the cursor where it was, which is
[#42](https://github.com/jusso-dev/Brolga/issues/42)'s "malformed server responses quarantine
without corrupting checkpoint" stated as a storage property rather than as care.

### 5. Connectors are read-only, and that is structural

The `Transport` trait exposes retrieval only. There is no method that sends a body. A future
publishing connector is a new decision and a new ADR, not a method added to this trait — the
roadmap's "keep upstream connectors read-only by default" is worth more as a shape than as a
default somebody can flip.

### 6. Credentials never enter a record, a log line, or an error

A connector's credential is `SensitiveText`, which the provenance model already uses for paths, and
is passed to the transport rather than stored on the client. Error messages name the URL and the
status; they never include a header. A `SourceOrigin::NetworkFeed` records the publisher and the
location, which is what an analyst needs to defend a finding, and nothing that would let a leaked
database hand somebody a working token.

## Alternatives rejected

**A module inside `brolga-ingest`.** Rejected on ADR 0003 §1's own reasoning: it would give the
component handling the most hostile input in the system the ability to originate requests, and it
would make "ingestion needs no network" false. The fuzzing story depends on that staying true.

**A crate per protocol — `brolga-taxii`, `brolga-misp`, `brolga-opencti`.** Rejected as premature.
The three share transport, retry, cursor storage, and policy; splitting them now would either
duplicate that or need a fourth crate to hold it, which is this crate under a different name. If a
protocol later needs a genuinely incompatible dependency set, splitting is still available and the
`Transport` boundary is where it would split.

**Letting the HTTP agent follow redirects.** Rejected in §3. It is the difference between an SSRF
control and an SSRF comment.

**A feature flag making the network optional.** Rejected. A `network` feature that defaults off
produces a binary whose `brolga fetch` fails at runtime with a build-configuration error, and one
that defaults on is the current decision with extra machinery. The exception is recorded here
instead, which is what the ADR rules ask for.

## Consequences accepted

- **Brolga now makes outbound requests in a default build.** That is a real change to what
  installing it means, and it is why this record exists. It happens only when an operator runs a
  fetch command or configures a connector; nothing in `brolga ingest`, `brolga serve`, or any query
  path opens a connection.
- **A new dependency tree.** `ureq` with `rustls`, chosen over `reqwest` for a substantially smaller
  transitive surface and for not pulling an async runtime into a crate that has no other use for
  one. Ingestion is synchronous, so a blocking client is the honest shape.
- **Mock-server tests bind loopback sockets.** They use port 0 and are self-contained, but the test
  suite is no longer purely computational.
- **Sync state means a storage migration.** Connector cursors need a table, and the migration runner
  now carries a change that a rollback would have to consider.
