# ADR 0006 — A closed set of query bodies, for GraphQL sources

- Status: accepted
- Date: 2026-07-29
- Milestone: `v0.6.0 — Connectors`
- Issue: [#43](https://github.com/jusso-dev/Brolga/issues/43)
- Amends: [ADR 0005](0005-connector-crate-boundary-and-outbound-network-policy.md) §5. Every other
  section of 0005 stands unchanged, including §2 (one outbound path), §3 (redirects are ours), §4
  (the cursor never moves ahead of stored data), and §6 (credentials never enter a record).

## Context

ADR 0005 §5 made read-only *structural*: `Transport` exposes retrieval and has no method that sends
a body, so a publishing connector would be a new decision rather than a method somebody added.

That held for TAXII, which is entirely `GET`. It held for MISP too, at a cost paid deliberately —
[#41](https://github.com/jusso-dev/Brolga/issues/41) uses MISP's path-parameter `GET` form instead
of the `POST` its documentation shows, and says so.

OpenCTI does not offer that escape. Its API is GraphQL at a single `POST /graphql` endpoint, and
the query travels in the body. There is no URL form that expresses it. So §5 as written makes
[#43](https://github.com/jusso-dev/Brolga/issues/43) unimplementable.

The obvious fix — add a general `post` to `Transport` — throws away exactly what §5 bought. A
transport that can send an arbitrary body to an arbitrary URL is a transport that can mutate, and
"we only call it with queries" is a convention rather than a property.

## Decision

### 1. `Transport` gains one method, and the set of bodies it can send is closed

    fn fetch_query(&self, request: &QueryRequest<'_>) -> Result<Response, ConnectorError>;

`QueryRequest` **cannot hold caller-supplied text.** It holds a `QueryOperation`, which is an enum
whose every variant maps to a GraphQL document that is a `&'static str` compiled into Brolga. There
is no constructor that takes a `String`, and none will be added without superseding this record.

So the guarantee changes shape rather than weakening. Before: *no body can be sent*. Now: *only
bodies Brolga's own source contains can be sent, and none of them is a mutation.* Both are
properties of the type rather than of anybody's care, and the second is what
[#43](https://github.com/jusso-dev/Brolga/issues/43) asks for when it says queries must be "fixed or
allowlisted rather than caller-supplied GraphQL" — an allowlist that cannot be appended to at
runtime is the strongest reading of that requirement available.

### 2. A test asserts no operation is a mutation

Every variant of `QueryOperation` is walked and its document checked: it must begin with the `query`
keyword and must not contain `mutation` or `subscription`. A future contributor adding a mutation to
the enum fails that test rather than shipping it.

That is a belt-and-braces check on top of the type, and it is worth having precisely because the
type stops a *caller* from supplying a mutation but does not stop the crate itself from containing
one.

### 3. Everything else about the outbound path is unchanged

`fetch_query` goes through the same `PolicyTransport`, the same per-request and per-hop SSRF checks,
the same manual redirect handling, and the same response bound. It is a second method on one
audited type, not a second path.

A redirect answering a query is **not** followed with the body re-sent. It is refused. Re-posting a
body to a location a server chose is how a query aimed at a configured endpoint ends up delivered
somewhere else, and no legitimate GraphQL endpoint answers a query with a redirect.

## Alternatives rejected

**A general `post` method.** Rejected as above: it converts a property into a convention. The whole
value of §5 was that a publishing connector required a decision, and a general `post` makes it
require only a caller.

**GraphQL over `GET` with `?query=`.** Genuinely attractive: the GraphQL spec and Apollo both refuse
mutations over `GET`, so the server would enforce read-only alongside us, and §5 would survive
untouched. Rejected because it depends on the deployment: OpenCTI does not document `GET` support,
an operator's reverse proxy may drop long query strings, and a connector that works against some
OpenCTI installations and not others is worse than one that needs a recorded decision. The
server-side property is still worth something and is noted here so a future revisit starts from it.

**A separate `MutatingTransport` trait that nothing implements.** Rejected as theatre. It documents
an intention without constraining anything, and the next contributor implements it.

**Skipping GraphQL and importing only OpenCTI's STIX exports.** This is a real option and is
*partly* taken — the export path needs no GraphQL at all, and it is implemented. Rejected as the
whole answer because incremental polling is the difference between a connector and a manual import,
and [#43](https://github.com/jusso-dev/Brolga/issues/43) asks for both.

## Consequences accepted

- **The blanket "no body" property is gone**, replaced by a narrower one. Anybody auditing outbound
  writes now reads `QueryOperation` as well as `Transport`, and this record exists so they know to.
- **Adding a query is a source change**, not configuration. An operator who wants a field Brolga does
  not request cannot add it without a build. That is the cost of the allowlist being closed, and it
  is the intended cost.
- **Query complexity is bounded by what is compiled in**, which means Brolga cannot issue a
  pathological query by accident — but also cannot adapt one to a server that limits differently.
