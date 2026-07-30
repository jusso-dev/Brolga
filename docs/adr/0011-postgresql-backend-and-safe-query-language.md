# ADR 0011 — PostgreSQL backend and safe query language

- Status: accepted
- Date: 2026-07-30
- Milestone: `v1.0.0 — Stable release`
- Issue: [#55](https://github.com/jusso-dev/Brolga/issues/55)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1 (introduces
  `brolga-query`) and §3 (`postgres` feature becomes a real subsystem, not only a reserved name).

## Context

v1.0 needs an optional server-mode store and a human query syntax that cannot become SQL injection.
Storage traits already forbid arbitrary SQL ([`brolga-storage`](../../crates/brolga-storage/src/lib.rs)).
What was missing is a second backend and a parser that *compiles into* those traits.

## Decision

### 1. `brolga-query` (layer 1)

| Crate | Responsibility | May depend on |
| --- | --- | --- |
| `brolga-query` | Lexer, parser, AST, limits, and compilation to typed storage filters | `brolga-model`, `brolga-storage` (query types only) |

It does **not** open a database or build SQL strings. The only compile target is
[`EntityQuery`](../../crates/brolga-storage/src/store.rs) / related typed filters. Arbitrary SQL,
function calls outside a closed set, and unbounded nesting are hard parse errors with spans.

### 2. PostgreSQL is feature `postgres` on `brolga-storage`

- Off by default (ADR 0001 §3). Enabling it pulls a PostgreSQL client; default builds stay SQLite-only.
- Same migration *identifiers and checksums* as SQLite: SQL is dialect-adapted at apply time, not a
  second history. Editing a released migration still fails on checksum mismatch on either backend.
- Rollback is **documented restore from backup / re-migrate empty**, not reverse migrations — same
  immutability rule as SQLite (ADR 0001 §6).

### 3. Shared store contract

Behavioural tests that assert IntelligenceStore semantics run against SQLite always, and against
PostgreSQL when `BROLGA_POSTGRES_URL` (or an equivalent lab service) is present. A backend that
cannot pass the contract is not “done”.

### 4. Query limits are first-class

Parse/compile enforce: max tokens, max AST depth, max result `limit`, max duration literals, and a
closed field/operator set. Cost estimates are advisory until a planner exists; hard caps are not.

## Consequences

- Operators can keep SQLite for offline/air-gap; PostgreSQL is optional server mode.
- CLI/API/MCP can accept either JSON filter bodies or query strings that compile to the same types.
- Residual risk: dialect translation bugs — mitigated by dual-backend contract tests and checksum
  immutability of migration *source* strings (SQLite form remains canonical for hashing).
