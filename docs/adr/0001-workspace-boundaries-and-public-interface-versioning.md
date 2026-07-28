# ADR 0001 — Cargo workspace boundaries and public interface versioning

- Status: accepted
- Date: 2026-07-28
- Milestone: `v0.1.0 — Foundation`
- Issue: [#2](https://github.com/jusso-dev/Brolga/issues/2)
- Supersedes: nothing
- Amends: the "Planned workspace boundaries" section of [docs/ARCHITECTURE.md](../ARCHITECTURE.md)

## Context

[docs/ARCHITECTURE.md](../ARCHITECTURE.md) lists a fifteen-crate target layout for the finished
product. That layout is a destination, not a starting point. Creating fifteen crates before any
behaviour exists would publish empty compatibility surfaces, invite dependency cycles, and force
speculative abstraction that later milestones would have to unpick.

At the same time, several decisions cannot be deferred. Crate boundaries determine which code may
depend on which; feature defaults determine what a plain `cargo build` ships; and public interface
versioning rules must exist *before* the first schema, migration, algorithm, or exit code is
written, because retrofitting version identifiers onto already-serialised data is a breaking change.

This ADR freezes those decisions so that [#3](https://github.com/jusso-dev/Brolga/issues/3) and
later foundation issues can create the workspace without re-litigating architecture per pull
request.

## Decision

### 1. Crate boundaries for `v0.1.0`

The `v0.1.0` workspace contains exactly these first-party crates. No other crate may be added
during this milestone without amending this ADR.

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-model` | Versioned canonical types, identifiers, markings, provenance, transformation chains, JSON Schema generation | *(none)* |
| `brolga-security` | Trust classification, resource-limit types, cancellation and timeout model, redaction primitives | *(none)* |
| `brolga-config` | Layered declarative configuration, schema generation, semantic validation, fingerprints, secret references | `brolga-model`, `brolga-security` |
| `brolga-storage` | Backend-neutral storage traits, migration runner, SQLite backend | `brolga-model`, `brolga-security` |
| `brolga-core` | Application services and orchestration shared by every interface | `brolga-model`, `brolga-security`, `brolga-config`, `brolga-storage` |
| `brolga-cli` | The `brolga` binary: command tree, output modes, exit codes, diagnostics | `brolga-core`, `brolga-model`, `brolga-security`, `brolga-config` |
| `brolga-test-support` | Deterministic fixtures, builders, and harnesses. Never a runtime dependency of a shipped crate | `brolga-model`, `brolga-security` |

Two crates in this list are not in the `docs/ARCHITECTURE.md` layout, and the deviation is
deliberate:

- **`brolga-security`** exists because [#8](https://github.com/jusso-dev/Brolga/issues/8) requires
  resource limits, trust classification, and cancellation to be *shared* by parsers, archives,
  graph traversal, connectors, plugins, and context generation. Those consumers live in different
  layers across five later milestones. Placing the limit types in `brolga-core` would force every
  future leaf crate to depend on orchestration, which inverts the dependency direction. It is a
  leaf crate with no first-party dependencies precisely so that anything may depend on it.
- **`brolga-config`** exists because [#5](https://github.com/jusso-dev/Brolga/issues/5) requires
  configuration schema generation and validation to be usable by `brolga-cli` (`config validate`,
  `config explain`) without pulling in storage. `docs/ARCHITECTURE.md` did not name a home for it.

Crates named in `docs/ARCHITECTURE.md` but **not** created in this milestone —
`brolga-ingest`, `brolga-normalise`, `brolga-graph`, `brolga-compress`, `brolga-policy`,
`brolga-query`, `brolga-export`, `brolga-mcp`, `brolga-api`, `brolga-plugin-sdk` — are introduced
by the milestone that first needs them, under the same rules as below. Their absence now is not a
statement that they will not exist.

### 2. Dependency direction and cycle prohibition

Crates occupy numbered layers. **A crate may depend only on crates in a strictly lower layer.**

```text
layer 3   brolga-cli
layer 2   brolga-core
layer 1   brolga-config    brolga-storage
layer 0   brolga-model     brolga-security
```

Rules:

- Same-layer first-party dependencies are prohibited. `brolga-config` must not depend on
  `brolga-storage`, and `brolga-model` must not depend on `brolga-security`, even though both
  pairs sit adjacent.
- Cycles are therefore structurally impossible, not merely discouraged. Cargo rejects cycles among
  normal dependencies, but it permits a `dev-dependencies` cycle; the layering rule closes that
  gap. A crate's `dev-dependencies` are bound by the same layer rule, with the single exception of
  `brolga-test-support`, which any crate above layer 0 may use as a dev-dependency.
- Later crates are assigned a layer when they are introduced. Source-format adapters
  (`brolga-ingest`, `brolga-export`, connectors) depend on canonical interfaces; canonical types
  never depend on STIX, MISP, TAXII, OpenCTI, or any vendor model. This preserves the
  `docs/ARCHITECTURE.md` dependency rule.
- Interface crates (`brolga-cli`, and later `brolga-api`, `brolga-mcp`) call application services.
  They do not reimplement intelligence decisions, and they are never depended upon by lower layers.
- Enforcement is by review plus the `cargo deny check bans` configuration and the layering test
  described in "Verification" below. A violation fails CI; it is not a style preference.

### 3. Default feature policy

- The workspace uses Cargo `resolver = "3"`.
- **A default `cargo build` produces a useful, offline, deterministic `brolga` binary with local
  SQLite storage and nothing else.** It must not compile an HTTP server, an MCP transport, a
  WebAssembly runtime, a PostgreSQL driver, or any model-provider client.
- Every optional subsystem is an additive, off-by-default Cargo feature. Reserved names, owned by
  the milestone that implements them: `postgres` (v1.0.0), `http-api` (v0.5.0), `mcp` (v0.5.0),
  `plugins` (v0.7.0), `llm` (v0.7.0). Declaring the name here prevents two milestones from
  inventing different spellings.
- Features are **additive only**. A feature may never remove an item, change a function signature,
  weaken a security default, or alter deterministic output. Enabling every feature must still
  compile and pass tests, which is what `--all-features` in CI checks.
- No `default = ["full"]` convenience feature, and no feature that transitively enables network
  access. Optional model providers stay disabled by default and outside deterministic core
  behaviour.
- Optional dependencies use the explicit `dep:` syntax so that a feature name and a dependency name
  are never silently coupled.

### 4. Rust version policy

- Edition: **2024**.
- MSRV: **1.85.0**, declared as `rust-version` in the workspace package metadata and verified by a
  dedicated CI job pinned to that exact toolchain.
- Brolga tracks Rust **stable**. Nightly-only features, nightly-only lints, and
  `#![feature(...)]` are prohibited in first-party crates.
- Raising the MSRV is a deliberate, reviewed change: it requires a changelog entry and, once the
  project reaches 1.0.0, a minor version bump. Before 1.0.0 it requires a minor version bump of the
  workspace version. An MSRV raise must be justified by a concrete need, not by convenience.
- `Cargo.lock` is committed, because the workspace ships a binary. CI verifies the lockfile is
  up to date with `--locked` and that it needs no network mutation during a build.

### 5. Unsafe code

- Every first-party crate root declares `#![forbid(unsafe_code)]`. `forbid`, not `deny`, so that no
  inner module can re-permit it with a local `#[allow]`.
- An exception requires its own ADR that records why a safe formulation is unavailable, the
  invariants the unsafe block relies on, the reviewer, and the test or verification evidence.
  Exceptions are confined to a dedicated crate; they are never scattered through a general crate.
- `cargo deny` and CI check that the `forbid` attribute is present in every crate root, so removing
  it is a visible, failing change rather than a silent one.

### 6. Public compatibility surfaces and their versioning rules

Every surface below is a public compatibility promise. Each has an explicit, machine-readable
version and a stated rule for what may change. Nothing on this list may ship without its version
identifier already present.

| Surface | Version carrier | Compatible change | Breaking change |
| --- | --- | --- | --- |
| Rust library API | Crate SemVer (unified workspace version) | Adding items; adding enum variants only on `#[non_exhaustive]` enums | Removing or renaming items; changing signatures; narrowing types |
| Serialised canonical schemas | `schema_version` field holding `brolga.<name>/<major>.<minor>` | Adding an optional field; adding a variant to a `#[non_exhaustive]` enum | Removing or renaming a field; changing a type; making an optional field required |
| JSON Schema documents | `$id` ending in the same `brolga.<name>/<major>.<minor>` | Loosening validation | Tightening validation; removing a definition |
| Configuration format | Top-level `version` field | Adding an optional key with a safe default | Removing a key; changing a default that alters behaviour or weakens a limit |
| Storage migrations | Zero-padded monotonic id, `NNNN_snake_case_name` | Appending a new migration | Editing or reordering a released migration |
| Algorithms (hashing, canonicalisation, fingerprints, ranking, compression) | `(algorithm_id, algorithm_version)` recorded in the provenance transformation chain | Adding a new algorithm id | Changing the output of an existing `(id, version)` pair |
| CLI surface | Binary SemVer plus the exit-code registry | Adding a command, subcommand, or flag; adding a new exit code | Removing or renaming a command or flag; changing an existing exit code's meaning; changing the stdout/stderr split |
| Plugin ABI (deferred to v0.7.0) | WIT world `brolga:plugin@<major>.<minor>.<patch>` | Additive interface growth within a major | Any change to an existing exported or imported function |

Cross-cutting rules:

- **A version identifier is data, not documentation.** It is emitted in the serialised payload, not
  only recorded in a document, so that a consumer can branch on it without out-of-band knowledge.
- Producing a payload whose `schema_version` major differs from the one the code implements is an
  error, never a best-effort parse.
- Deterministic content and runtime metadata stay separate. Generation timestamps, host names, and
  request identifiers must not contribute to any fingerprint.
- Two independently versioned surfaces never share one version number. The crate version does not
  imply the schema version, and the schema version does not imply the migration id.
- Deprecation before removal: a surface is marked deprecated with a documented replacement for at
  least one minor release before it is removed, and removal happens only in a major release.

### 7. Dependency, licence, and supply-chain policy

New dependencies are reviewed, not merely added. A pull request that introduces one states why it
is needed, what it replaces, and what it pulls in transitively.

- **Allowed licences** (permissive, or weak-copyleft used unmodified): `MIT`, `Apache-2.0`,
  `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`,
  `CC0-1.0`, `MPL-2.0`.
- **Denied licences**, with no exception path: `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `LGPL-2.1`,
  `LGPL-3.0`, `SSPL-1.0`, `BUSL-1.1`, and any non-OSI proprietary or source-available licence.
  Brolga ships under MIT and must remain redistributable under it.
- **Advisories**: `cargo deny check advisories` fails CI on any known vulnerability or on an
  unmaintained crate in the dependency graph.
- **Bans**: duplicate major versions of the same crate are a warning to be justified, not silently
  accepted; `cargo deny check bans` also enforces the layering rule from section 2 through
  explicit deny entries.
- **Sources**: only the crates.io registry. Git dependencies, path dependencies outside the
  workspace, patch sections, and vendored forks are prohibited.
- **Supply chain**: `Cargo.lock` committed; CI builds `--locked`; dependency-update pull requests
  are separate from behaviour changes and never bundled into a feature branch.
- **Exception process**: a required dependency that fails licence or advisory policy may be
  admitted only through a dated, expiring entry in `deny.toml` that names the advisory or licence,
  the justification, the compensating control, and a review date. The exception is visible in the
  repository; it is never an ad-hoc CI suppression.
- Preference order when a capability is needed: standard library, then an existing workspace
  dependency, then a well-maintained crate with a small transitive tree, then a new dependency.
  Avoid crates that require `build.rs` network access, bundle prebuilt binaries, or need a C
  toolchain unless there is no viable pure-Rust option.

## Verification

These rules are checked mechanically, not by memory:

- `cargo tree` layering assertions and `deny.toml` `bans` entries reject an upward or same-layer
  first-party dependency.
- `cargo deny check licenses advisories bans sources` runs in CI.
- `cargo build --locked` and `cargo build --locked --all-features` run on Linux, macOS, and Windows.
- A dedicated CI job pinned to `1.85.0` proves the MSRV claim. The MSRV is not asserted in prose
  alone.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` treats warnings as
  failures.
- Round-trip and schema tests assert that every serialised public payload carries its version
  identifier.

## Consequences

**Accepted:**

- Seven crates instead of fifteen means later milestones will split crates. Splitting a crate that
  has no external consumers is cheap; merging a premature abstraction that already has consumers is
  not. The layering rule makes each split mechanical.
- A leaf `brolga-security` crate means limit types are defined before most of their consumers
  exist, so some limits will be added later. That is preferable to every future crate depending on
  orchestration to read a byte cap.
- MSRV 1.85.0 excludes older toolchains. Edition 2024 requires it, and pinning the floor makes the
  claim testable.
- Committing `Cargo.lock` means dependency updates are explicit pull requests. That is the point.

**Rejected alternatives:**

- *Create all fifteen crates now.* Publishes empty compatibility surfaces and invites speculative
  abstraction, contrary to the `v0.1.0` non-goals.
- *Single crate with modules, split later.* Module boundaries do not enforce dependency direction;
  a cycle between two modules is invisible to Cargo. The layering guarantee would be aspirational.
- *Put resource limits in `brolga-core`.* Inverts the dependency direction for every future leaf
  consumer of those limits.
- *One version number for everything.* Couples the crate version to the on-disk schema and to
  migration ids, so an unrelated code release would imply a data-format change.
