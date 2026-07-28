# ADR 0002 — Raise the MSRV to 1.88.0 to take a security fix

- Status: accepted
- Date: 2026-07-28
- Milestone: `v0.1.0 — Foundation`
- Issue: [#9](https://github.com/jusso-dev/Brolga/issues/9)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §4. Every other
  section of ADR 0001 stands unchanged.

## Context

ADR 0001 §4 set the MSRV at 1.85.0, the floor for edition 2024, and required that raising it "be
justified by a concrete need, not by convenience".

The first run of the supply-chain gate added by [#9](https://github.com/jusso-dev/Brolga/issues/9)
failed:

```text
error[vulnerability]: Denial of Service via Stack Exhaustion
  time 0.3.45
  ID: RUSTSEC-2026-0009
  Solution: Upgrade to >=0.3.47
```

The advisory describes unbounded recursion in `time`'s RFC 2822 parser: hostile input using
deprecated RFC 2822 features can exhaust the stack. The fix landed in `time` 0.3.47, which raises
that crate's own MSRV to 1.88.0. Cargo had therefore been resolving `time` to 0.3.45 — the newest
release compatible with our declared 1.85.0 floor — which is precisely the vulnerable version.

This is a direct conflict between the declared MSRV and a security fix, and the gate found it on
its first run rather than after a release.

## Decision

**Raise the workspace MSRV to 1.88.0 and take `time` 0.3.54.**

`rust-version` in the workspace manifest becomes `1.88.0`, and the pinned CI job that proves the
MSRV moves with it.

Everything else in ADR 0001 §4 is unchanged: edition 2024, stable-only, `Cargo.lock` committed,
`--locked` builds, and the rule that a raise needs a justification and a version bump.

## Alternatives rejected

**File an advisory exception and stay on 1.85.0.** Brolga parses RFC 3339 and never calls `time`'s
RFC 2822 parser, so the vulnerable code path is unreachable from our code today. An
`[advisories].ignore` entry would have been defensible on those grounds.

It was rejected because the argument is fragile in exactly the way that matters. "Unreachable
today" is a property of current call sites, not of the dependency, and nothing would fail if a
later parser — `v0.2.0` adds several — called the RFC 2822 path. The exception would sit in
`deny.toml` asserting a safety property that no test enforces, and the reviewer at that later date
would have to reconstruct today's reasoning from a one-line `reason` field. Taking the patched
version removes the question instead of documenting an answer to it.

**Pin `time` and vendor the patch.** ADR 0001 §7 prohibits vendored forks and patch sections, for
good reasons that this situation does not change.

**Drop `time` for `std::time`.** `std::time` has no calendar arithmetic and no RFC 3339 parsing, so
this would mean writing a date-time parser. Writing a date-time parser to avoid a date-time parser's
CVE is not a trade that improves anything.

## Consequences

- Toolchains older than 1.88.0 can no longer build Brolga. 1.88.0 predates this decision by more
  than a year, and no consumer exists yet, so the practical cost is zero and it will never be lower
  than it is now.
- `time` moves 0.3.45 → 0.3.54, `time-core` 0.1.7 → 0.1.9, `time-macros` 0.2.25 → 0.2.32, and
  `num-conv` 0.1.0 → 0.2.2. All are patch or minor updates within the same major version.
- The MSRV is now further above the edition-2024 floor, so a future dependency needing 1.86.0 or
  1.87.0 no longer forces a decision.

## Note on process

ADR 0001 requires that an accepted ADR not be edited to change its decision, and that a superseding
record be written instead. This is that record. It amends one clause rather than superseding the
whole ADR, because the other six sections are unaffected and rewriting them would obscure what
actually changed.

The general lesson is worth recording separately from the specific bump: **a declared MSRV is a
constraint on which security fixes are reachable.** A floor low enough to be inconvenient is also a
floor low enough to pin a dependency to a vulnerable release, silently, with no signal other than a
supply-chain gate that someone remembered to add.
