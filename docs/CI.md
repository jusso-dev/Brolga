# Continuous integration and repository quality gates

CI is defined in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and the dependency policy
it enforces is in [`deny.toml`](../deny.toml). The reasoning behind both is
[ADR 0001](adr/0001-workspace-boundaries-and-public-interface-versioning.md), as amended by
[ADR 0002](adr/0002-raise-msrv-to-1-88-for-a-security-advisory.md); this document describes the
mechanism.

## What runs, and when

CI runs on every pull request and on every push to `main`. Runs on a pull request branch are
cancelled when a newer commit arrives; runs on `main` are not, because a cancelled run leaves no
record of whether that commit was green.

| Job | Platform | What it proves |
| --- | --- | --- |
| `format` | Linux | `cargo fmt --all -- --check`. Formatting is not a review topic. |
| `lint` | Linux | `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`. Covers tests and examples, and proves the reserved optional features still compile. |
| `test` | Linux, macOS, Windows | Builds default features, then runs the suite with default features, with all features, and the doc tests. |
| `msrv` | Linux | `cargo check` on a toolchain pinned to exactly 1.88.0. |
| `docs` | Linux | `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS: -D warnings`. |
| `supply-chain` | Linux | `cargo deny check licenses advisories bans sources`. |
| `lockfile` | Linux | `cargo metadata --locked` fails if `Cargo.lock` is out of date with the manifests. |
| `smoke` | Linux, macOS, Windows | Builds the release profile and **runs the binary**: `--version`, a real command whose JSON reaches stdout, and an unimplemented command that must exit `5` with an empty stdout. Uploads the artefact. |
| `ci-passed` | Linux | Aggregates every job above into one required check. |

Rust warnings fail everywhere: `RUSTFLAGS: -D warnings` and `RUSTDOCFLAGS: -D warnings` are set at
the workflow level, so a warning in a build script or in rustdoc fails the run just as one in our
own code does. `cargo deny` sets its severities per check in `deny.toml` instead — see below.

### Why default features are built separately

`--all-features` alone would let the default build break unnoticed. ADR 0001 §3 requires a plain
`cargo build` to produce a useful, lean binary, so the matrix builds and tests that configuration
before it tests the maximal one.

### Why `test` does not fail fast

`fail-fast: false`. A platform-specific failure is what a three-platform matrix exists to find, and
cancelling the other two hides whether the failure *is* platform-specific.

## The `brolga` binary

The `smoke` job builds the release profile and then *runs* the binary on all three platforms. The
distinction matters: the release profile sets `lto`, `codegen-units = 1`, `strip`, and
`panic = "abort"`, and a binary that links under those settings is not necessarily a binary that
starts. A missing symbol, a broken panic-strategy interaction, or a platform-specific path bug links
perfectly and fails on first use.

Three checks, on every platform:

1. `brolga --version` — the process starts.
2. `brolga --output json exit-codes` — the command tree, output modes, and the stdout/stderr split
   survived the release profile, and the result really is parseable JSON on stdout.
3. `brolga ingest x` — an unimplemented command exits `5`, writes **nothing** to stdout, and
   explains itself on stderr. That is the contract a pipeline depends on, so it is checked
   per-platform rather than assumed from a unit test.

The built binary is uploaded as an artefact per platform, with `if-no-files-found: error` so a
silently missing binary fails the job rather than producing an empty artefact.

CI does not publish a release; releasing is out of scope for `v0.1.0`.

## Supply-chain policy

[`deny.toml`](../deny.toml) enforces four checks across five target triples with `all-features`
enabled, because a crate can pull a differently licensed or differently vulnerable dependency on one
platform only.

- **Licences.** An allow-list. `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`,
  `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`, `CC0-1.0`, `MPL-2.0`. Everything
  else is denied, so the copyleft prohibition needs no separate list to maintain. Brolga ships
  under MIT and must remain redistributable under it.
- **Advisories.** The build fails on any RustSec advisory or unmaintained crate in the tree.
- **Bans.** Wildcard requirements are denied. A small deny-list covers crates superseded by the
  standard library at our MSRV or by a crate the workspace already uses. Duplicate major versions
  are reported but do not fail: at the time of writing, `syn` 2 and `syn` 3 both appear through
  proc-macro crates we do not control, and failing on that would mean blocking on somebody else's
  release schedule or maintaining a `skip` list that hides real duplication alongside unavoidable
  duplication.

CI deliberately does **not** pass `--deny warnings` to `cargo deny`. Severity is set per check in
`deny.toml`, where it is reviewable, rather than by a blanket flag that cannot tell "a crate is
unmaintained" from "two proc-macro crates disagree about a `syn` major version". Vulnerabilities are
errors regardless of that flag.
- **Sources.** crates.io only. Git dependencies, patched dependencies, and vendored forks are
  denied, because none of them is visible in published metadata and all of them make the tree
  unreviewable by someone who does not already know they are there.

### A note on reproducibility

Pinning the `cargo-deny` action pins the *tool*, not the *advisory data*. An advisory published
today can fail a build that passed yesterday, on an unchanged commit. That is intended: the only
alternative is shipping a known vulnerability quietly. When it happens, fix the dependency or file
an exception — do not pin the database.

## Exception process

Both `[advisories].ignore` and `[licenses].exceptions` in `deny.toml` are empty. An entry in either
is a dated, expiring, reviewed decision recorded in the repository, never an ad-hoc CI suppression
and never a `continue-on-error` on the job.

To request one:

1. Open a pull request that changes **only** `deny.toml`. Bundling an exception into a feature
   branch means it is reviewed as a side effect of something else.
2. The entry's `reason` must state four things: the advisory or licence, why no compliant
   alternative exists, what compensating control limits the exposure, and a review date.
3. A denied licence — `GPL-*`, `AGPL-*`, `LGPL-*`, `SSPL`, `BUSL`, or any proprietary or
   source-available licence — has **no** exception path. Find another dependency or write the
   functionality.
4. Revisit every live exception at its review date. An exception with a passed review date is
   itself a defect.

## Action pinning

Every third-party action is pinned to a full 40-character commit SHA with the human-readable
version in a trailing comment. A tag is mutable: `v4` can be repointed at new code by anyone who can
push a tag to that repository, and a supply-chain attack on a popular action is a supply-chain
attack on everyone who trusts its tag.

Pins in use:

| Action | Version | SHA |
| --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `dtolnay/rust-toolchain` | `stable` branch | `4cda84d5c5c54efe2404f9d843567869ab1699d4` |
| `Swatinem/rust-cache` | v2.9.1 | `c19371144df3bb44fab255c43d04cbc2ab54d1c4` |
| `EmbarkStudios/cargo-deny-action` | v2.1.1 | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |
| `actions/upload-artifact` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

When updating a pin, resolve the SHA yourself rather than trusting a bot's summary:

```bash
gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.sha,.object.type'
# If the type is "tag" it is an annotated tag; dereference it to the commit:
gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha
```

## Token permissions

`permissions: contents: read` is set at the workflow level, so a job added later cannot silently
inherit more. No job writes to the repository, comments on a pull request, or publishes anything. A
job that genuinely needs more must request it at the job level, where the elevation is visible in
review.

Workflows here never run with `pull_request_target`, so a fork's pull request cannot reach
repository secrets. Nothing in CI reads a secret.

## Branch protection

CI is only a gate if `main` requires it. These settings are **not** configured by this repository's
code and must be applied by someone with admin access, under
**Settings → Branches → Branch protection rules** (or a repository ruleset) for `main`:

- **Require a pull request before merging.** Direct pushes to `main` bypass every check here.
- **Require status checks to pass before merging**, and select **`CI passed`** — the single
  aggregate job. Selecting it rather than the individual jobs means adding a job later does not
  require editing repository settings, and, more importantly, a *skipped* job cannot be mistaken
  for a passing one: `ci-passed` treats `skipped` and `cancelled` as failures.
- **Require branches to be up to date before merging.** Two pull requests that pass individually can
  fail together.
- **Require conversation resolution before merging.**
- **Do not allow bypassing the above settings**, including for administrators.
- **Restrict force pushes** and **restrict deletions** on `main`.

Verify what is currently applied:

```bash
gh api repos/jusso-dev/Brolga/branches/main/protection
gh api repos/jusso-dev/Brolga/rulesets
```

At the time this document was written, both return no protection. Until that changes, CI reports
results but does not enforce them.

## Reproducing CI locally

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo doc --locked --workspace --no-deps --all-features
cargo metadata --locked --format-version 1 > /dev/null
cargo deny check licenses advisories bans sources --deny warnings
cargo build --locked --workspace --release
```

`cargo deny` is not part of a default Rust installation:

```bash
cargo install cargo-deny --locked
```

The MSRV job cannot be reproduced without `rustup`, which is how a toolchain is pinned to an exact
version:

```bash
rustup toolchain install 1.88.0
cargo +1.88.0 check --locked --workspace --all-features
```
