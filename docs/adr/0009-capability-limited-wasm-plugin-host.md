# ADR 0009 — A capability-limited WebAssembly plugin host

- Status: accepted
- Date: 2026-07-30
- Milestone: `v0.7.0 — Extension system`
- Issue: [#48](https://github.com/jusso-dev/Brolga/issues/48)
- Amends: [ADR 0001](0001-workspace-boundaries-and-public-interface-versioning.md) §1 (new crate)
  and §3 (`plugins` feature now names a real subsystem). Depends on
  [ADR 0008](0008-plugin-sdk-and-wit-abi.md).
- Records: **Wasmtime is the only WebAssembly engine**, and it is compiled only behind the
  off-by-default `plugins` / `runtime` features so a default `cargo build` stays offline and free of
  a runtime (ADR 0001 §3).

## Context

[#46](https://github.com/jusso-dev/Brolga/issues/46) shipped types, manifests, capabilities, and the
WIT world `brolga:plugin@0.1.0` with **empty host imports**. That is the contract. This record is the
engine that loads a component against that contract without giving it ambient authority.

Threat model B8: a plugin author is an adversary; plugin output is `TrustLevel::Untrusted`; memory,
fuel, and wall-clock must bound every call; policy is never delegated to the guest.

## Decision

### 1. New crate: `brolga-plugin-host` (layer 2)

| Crate | Responsibility | May depend on (first-party) |
| --- | --- | --- |
| `brolga-plugin-host` | Load WIT components, enforce capability grants, fuel/memory/time, audit metadata for a call | `brolga-plugin-sdk`, `brolga-model`, `brolga-security` |

Layer 2: above the SDK (layer 1). It does **not** depend on storage, connectors, ingest, export, or
CLI. The host receives bytes and returns bytes; wiring into the pipeline is a later caller's job.

### 2. Feature flags

| Feature | Where | Effect |
| --- | --- | --- |
| `runtime` | `brolga-plugin-host` | Compiles Wasmtime and the execute path |
| `plugins` | `brolga-cli` (and later interface crates) | Enables `brolga-plugin-host` with `runtime` |

Default features stay empty. Validation of on-disk packages (manifest + digest check) is available
without `runtime`. Instantiating a component requires `runtime`.

`--all-features` CI therefore builds the host; a plain `cargo build` does not.

### 3. Default sandbox is empty imports + hard resource caps

- No WASI filesystem, sockets, clocks, or random by default.
- Engine config: fuel enabled, epoch interruption or store limits for wall time, memory limit per
  instance.
- A component that **imports** anything outside the empty `plugin` world is refused at load time
  when no matching capability grant exists (and today no grant maps to an import yet — FS/network
  grants are recorded for audit and blocked until an explicit future world revision wires them).

### 4. Operator grants intersect plugin requests

A plugin's declared capabilities are a **request**. The host holds an operator grant set. Execution
uses the intersection. A request not covered by a grant is a load error, not a silent drop.

Grants are path- or host-scoped, matching ADR 0008's capability vocabulary. Wildcards remain
unrepresentable.

### 5. Identity enters reproducibility metadata

Every successful load records: plugin name, plugin version, ABI version, content digest
(algorithm + hex), granted capabilities, and limit snapshot. Callers attach that set to pack
fingerprints and audit events; the host itself does not write to storage.

### 6. Guest failure terminates only the call

Trap, fuel exhaustion, epoch interrupt, and guest `plugin-error` become `HostError` values. They
must not unwind past the host API. With workspace `panic = "abort"`, the host still avoids panicking
on guest faults by treating Wasmtime results as `Result`.

## Consequences

- #50 can ship example components against a real load path.
- Native `dlopen` remains absent.
- Wiring `plugins` into ingest/export registries is follow-on work; this issue is the sandbox and
  invoke path.
- **Accepted residual risk:** Wasmtime bugs are supply-chain risk; version pins and `cargo deny`
  apply. Capability-to-import mapping for FS/network is intentionally not fully wired in the first
  cut — grants exist and are enforced as "not yet mappable ⇒ refuse if requested without a future
  import bridge", so an operator cannot believe a grant gave access it did not.
