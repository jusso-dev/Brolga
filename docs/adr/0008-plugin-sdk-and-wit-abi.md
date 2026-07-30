# ADR 0008 — The plugin SDK crate boundary, and a WIT ABI that cannot smuggle host access

- Status: accepted
- Date: 2026-07-30
- Milestone: `v0.7.0 — Extension system`
- Issue: [#46](https://github.com/jusso-dev/Brolga/issues/46)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1, as
  0003–0007 already did for their crates. Every other section of 0001 stands, including §2's
  layering rule and §6's Plugin ABI versioning row.
- Records: the **types and ABI only** — no WebAssembly runtime, no native shared-library loader.
  The host is [#48](https://github.com/jusso-dev/Brolga/issues/48).

## Context

`v0.7.0` needs third-party extension without arbitrary native code or unrestricted host access.
[#47](https://github.com/jusso-dev/Brolga/issues/47) already shipped declarative mappings (data, not
code). What remains is a **portable plugin surface**: Rust contracts for trusted first-party code,
a versioned WIT world for portable modules, a manifest that declares capabilities and
compatibility, and structured errors when any of that is wrong.

None of the existing crates should hold this:

- `brolga-ingest` / `brolga-export` own *first-party* parsers and exporters. Putting the third-party
  ABI there would couple every plugin author to the full domain pipeline and invite leaking store
  handles, policy evaluators, or network transports into the guest boundary.
- `brolga-security` holds limit and trust *types*. It must not grow plugin manifests or WIT
  documents — those are product surfaces, not security primitives.
- `brolga-cli` is an interface crate. It may *validate* a manifest; it must not become the home of
  the ABI.

ADR 0001 §6 already reserved the Plugin ABI versioning rule:
`brolga:plugin@<major>.<minor>.<patch>`, additive within a major, breaking on any change to an
existing import or export. This ADR names the crate that owns that surface and the rules that keep
it from becoming a host-internals dump.

## Decision

### 1. One new crate: `brolga-plugin-sdk`

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-plugin-sdk` | Plugin manifests, capability vocabulary, extension-point contracts, WIT ABI types, structured plugin errors | `brolga-model`, `brolga-security` |

Layer **1** under ADR 0001 §2: above model and security, same layer as config and storage, **not**
depending on either (same-layer ban). It deliberately does **not** depend on ingest, export, graph,
storage, connectors, config, API, or CLI.

That dependency cut is the acceptance criterion "SDK does not expose host internals by default"
made structural: there is no type path from a plugin contract to a store, a transport, a policy
decision, or a CLI stream.

`brolga-cli` depends on `brolga-plugin-sdk` for `plugin validate` / `plugin explain`. The future
host crate or module (#48) will depend on it too. Nothing else needs to for this issue.

### 2. The WIT world is data in this crate; execution is not

The world lives at `crates/brolga-plugin-sdk/wit/world.wit` and is versioned as
`brolga:plugin@0.1.0` (constant `PLUGIN_ABI_VERSION` in Rust, kept equal by test).

This issue ships the world and the Rust types that mirror it. It does **not** load components,
allocate fuel, or open a WASI context. That is #48. Shipping the ABI first means #48 cannot invent
a second surface under deadline, and plugin authors can write against a frozen contract while the
host is still empty.

Default host imports for the world are **empty**. A plugin that needs filesystem or network must
declare a capability in its manifest; the host (later) maps grants to imports. An empty import set
is the security property, not a comment in a README.

### 3. One invoke envelope, many extension points

Every extension point — parser, normaliser, enricher, resolver, scorer, confidence, decay,
compression, token, policy, storage, exporter, profile, connector — is a closed enum member with
its own contract major.minor and a deterministic JSON request/response body.

The portable call shape is:

```text
call(extension, contract_version, request_bytes) -> result<response_bytes, plugin_error>
```

Extension-specific Rust traits exist for ergonomics in first-party and test code. They serialise to
the same envelope. Unknown extension names and unknown contract majors fail clearly; they are never
best-efforted.

### 4. Capabilities are a closed, scoped vocabulary with no wildcards

A plugin lists zero or more capabilities. The empty list is the default and means pure compute:
no filesystem, no network, no wall clock, no entropy from the host.

Each capability is concrete and scoped (`read-filesystem` with a path prefix, `network-egress` with
a host and optional port). There is no `*`, no `admin`, no `bypass-policy`, and no way to request
"whatever the host has". A manifest that includes an unknown capability name fails to load.

Capability grants are **declarations**. This crate does not enforce them at runtime; the host does.
What the SDK guarantees is that a plugin cannot *name* an implicit wildcard.

### 5. Policy and storage contracts cannot become authority

Two extension points look dangerous if read as "the plugin decides":

- **`policy`** — plugins may *propose* or *annotate*; they never produce a binding
  authorisation decision. The host's policy evaluator remains the only path that can clear output
  (ADR 0007). Plugin output is `TrustLevel::Untrusted` per the threat model.
- **`storage`** — plugins may transform or validate serialised records. They never receive a
  database handle, migration runner, or filesystem path unless an explicit capability was granted
  *and* the host mapped it (host work).

These constraints are written into the contract docs and the manifest explain output so an operator
evaluating a third-party plugin sees the refusals, not only the capabilities.

### 6. The `plugins` Cargo feature remains reserved for the host

ADR 0001 §3 reserved `plugins` for the WebAssembly runtime. That name still means the *host*, not
this SDK. `brolga-plugin-sdk` is always built: manifests and the ABI are useful offline and must not
pull a runtime into a default `cargo build`. #48 enables execution behind the feature.

## Consequences

- A third-party author can depend on `brolga-plugin-sdk` (or only the WIT file) without linking
  storage, connectors, or the CLI.
- #48 has a fixed world, a fixed capability enum, and a fixed manifest schema to implement against.
- Adding an extension point or a capability is a deliberate change to a closed enum plus, for the
  portable surface, a WIT revision under ADR 0001 §6.
- Native shared-library loading remains out of scope; nothing in this crate provides a `dlopen`
  path.
- **Accepted residual risk:** a malicious or buggy *first-party* implementor of a Rust trait can
  still do anything the process can do. The SDK is not a sandbox. Containment for untrusted modules
  is the WebAssembly host's job (#48).
