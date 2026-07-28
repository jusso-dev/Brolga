# ADR 0003 — The ingestion crate boundary, and how a parser is stopped from panicking

- Status: accepted
- Date: 2026-07-29
- Milestone: `v0.2.0 — Core ingestion`
- Issue: [#11](https://github.com/jusso-dev/Brolga/issues/11)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1, which permits
  no crate outside its table without an amendment. Every other section of ADR 0001 stands unchanged.

## Context

ADR 0001 §1 fixed the `v0.1.0` workspace and said plainly that "no other crate may be added during
this milestone without amending this ADR". `v0.1.0` is closed. `v0.2.0` needs somewhere to put
parsers, and [#11](https://github.com/jusso-dev/Brolga/issues/11) needs that decision made before it
writes a trait, not after.

Two things have to be settled together, because the second one constrains where the first can live.

### What ADR 0001 §1 actually shipped

Its table lists seven crates. Five exist: `brolga-model`, `brolga-security`, `brolga-config`,
`brolga-storage`, `brolga-cli`. **`brolga-core` and `brolga-test-support` were never created.**

That is not a violation of the "no other crate may be added" rule — nothing extra was added — but the
table is written as a description of what the workspace contains, and it does not describe it. The
work that `brolga-core` was to hold (application services and orchestration shared by every
interface) turned out not to exist yet at `v0.1.0`: the CLI's commands are thin enough to sit in
`brolga-cli`, and inventing an orchestration crate with nothing to orchestrate is the speculative
abstraction ADR 0001 §1 was written to avoid.

### Parsers cannot be prevented from panicking by wishing

[#11](https://github.com/jusso-dev/Brolga/issues/11) requires that "no parser panic crosses the
application boundary". The obvious reading is `catch_unwind` around each parser call.

**That does not work in this workspace.** `[profile.release]` sets `panic = "abort"`, so in a release
build there is no unwind to catch and `catch_unwind` is dead code. A panicking parser terminates the
process. Wrapping the call would produce a containment guarantee that holds in `cargo test` and
evaporates in the shipped binary — the most dangerous kind, because the tests would pass.

[docs/THREAT-MODEL.md](../THREAT-MODEL.md) already took the other position: "A panic on hostile input
is a denial of service. The workspace denies `unwrap_used`, `expect_used`, `panic`,
`indexing_slicing`, `as_conversions`, and the lossy-cast family in production code, so reaching for
one is a build failure rather than a review finding."

## Decision

### 1. One new crate: `brolga-ingest`

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-ingest` | Parser trait and registry, format detection, the ingestion pipeline and its stages, ingestion diagnostics and metrics | `brolga-model`, `brolga-security`, `brolga-config`, `brolga-storage` |

It sits above the four `v0.1.0` leaf crates and below `brolga-cli`. It may not depend on
`brolga-cli`, and no `v0.1.0` crate may depend on it — the dependency direction of ADR 0001 §2 is
unchanged, this crate is simply a new layer above it.

Individual format parsers — STIX, MISP, CSV — are **not** separate crates. They are modules inside
`brolga-ingest`, because a parser that cannot be selected by the registry is not reachable, and a
crate boundary between the registry and the things it registers buys nothing while forcing the trait
to be public API earlier than it is stable. This is revisited if and when a parser needs to ship
separately from the binary, which is really [#46](https://github.com/jusso-dev/Brolga/issues/46)'s
plugin ABI question, not this one.

`brolga-core` and `brolga-test-support` remain unbuilt, and ADR 0001 §1's table should be read as the
permitted set rather than the present set. Neither is created speculatively here. When orchestration
genuinely spans two interfaces — realistically at the HTTP API,
[#35](https://github.com/jusso-dev/Brolga/issues/35) — `brolga-core` gets built then, by whoever has
the second caller in front of them.

### 2. Parser panics are prevented, not caught

`panic = "abort"` stays. `catch_unwind` is not used, and the pipeline does not pretend to contain a
panic it cannot contain.

The guarantee is instead constructed from four things, none of which is a code review:

1. **The trait cannot signal failure by panicking.** `IntelligenceParser::parse` returns
   `Result<ParseOutput, ParseError>`; there is no path where a panic is the intended way to reject
   input.
2. **Panicking constructs fail the build.** The workspace-level denies on `unwrap_used`,
   `expect_used`, `panic`, `indexing_slicing`, `integer_division`, and the cast family apply to
   `brolga-ingest` like every other crate. A parser reaching for `unwrap` does not merit a comment;
   it does not compile under CI.
3. **Every parser is fuzzed against its own registration.** A property test drives arbitrary bytes
   through detection and parsing for every registered parser and asserts the outcome is `Ok` or
   `Err`, never a panic. It runs against the registry, so registering a parser enrols it
   automatically rather than requiring somebody to remember to add a test.
4. **Limits are applied by the pipeline, before the parser sees anything.** Byte length, record
   count, nesting depth, field size, and the cancellation deadline are enforced by
   `brolga-ingest`, not delegated to each parser. The commonest way a parser panics on hostile input
   — unbounded recursion, unbounded allocation — is unreachable because the input never gets that
   far.

## Alternatives rejected

**Switch `[profile.release]` to `panic = "unwind"` and use `catch_unwind`.** This would be real
containment, and it is the correct answer for *third-party* parsers. It was rejected for `v0.2.0`
because every parser in this milestone is first-party code compiled into the binary and subject to
(2) above, so it buys containment against our own lint-enforced code while costing binary size, some
optimisation, and a direct contradiction of a threat-model paragraph that is otherwise correct.
Buying it now would also make it tempting to treat `catch_unwind` as the guarantee and let (2) rot.

**A separate crate per format.** Rejected above: cost now, benefit at
[#46](https://github.com/jusso-dev/Brolga/issues/46).

**Build `brolga-core` now so the ADR 0001 table becomes true.** Rejected. Making a document accurate
by writing an empty crate is the wrong direction; the document is amended instead.

## Consequences

- **A first-party parser that panics still aborts the process.** That is a bug of the same severity
  as a panic anywhere else in Brolga, caught by lints and property tests, and it is not silently
  downgraded to a caught error. Accepted deliberately.
- **A third-party parser is not contained by any of this.** Points (1)–(4) are properties of code we
  compile. The WebAssembly plugin host,
  [#48](https://github.com/jusso-dev/Brolga/issues/48), is where containment becomes a real
  boundary, because instance isolation enforces it rather than a lint. **`panic = "abort"` must be
  revisited in that issue**, and this ADR is the record that the question was deferred rather than
  missed.
- Ingestion diagnostics can name the failing parser and stage, because failure is a value the
  pipeline receives rather than an unwind it intercepts.
- ADR 0001 §1's table is now the permitted set. A future crate still needs an amendment.
