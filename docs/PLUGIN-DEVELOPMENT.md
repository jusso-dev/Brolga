# Plugin development guide

How to build, validate, and publish a Brolga plugin under the v0.7 extension system
([#46](https://github.com/jusso-dev/Brolga/issues/46)–[#50](https://github.com/jusso-dev/Brolga/issues/50),
ADR 0008 / 0009).

## What a plugin is

A plugin is:

1. A **manifest** (`brolga.plugin.manifest/1.0`) — name, version, API range, extension points,
   capabilities (default empty = pure compute).
2. A **WebAssembly component** exporting world `brolga:plugin@0.1.0` (`manifest` + `invoke`).
3. Optional operator configuration described by `configuration_schema` (JSON Schema).

There is **no default native `dlopen` path**. Host imports are empty unless a future capability
grant maps them; the fixtures ship with none.

## Shipped examples

| Path | Role |
| --- | --- |
| `examples/plugins/parser-manifest.yml` | Manifest-only parser (validate / explain) |
| `examples/plugins/exporter-manifest.yml` | Manifest-only exporter (validate / explain) |
| `examples/plugins/echo/` | Runnable pure-compute **parser** package |
| `examples/plugins/exporter/` | Runnable pure-compute **exporter** package |
| `plugins/echo-guest/` | Guest source for both packages (workspace-excluded) |

```bash
# Manifest only (default binary)
brolga plugin validate examples/plugins/parser-manifest.yml
brolga plugin explain  examples/plugins/exporter-manifest.yml

# Execute (host + Wasmtime; off by default)
cargo build -p brolga-cli --features plugins
brolga plugin run examples/plugins/echo --extension parser --contract 1.0
brolga plugin run examples/plugins/exporter --extension exporter --contract 1.0
```

## Target and toolchain

Use **`wasm32-unknown-unknown`**, not wasip1. WASI pulls host imports the empty-import host
refuses.

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-component
cd plugins/echo-guest
cargo component build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/echo_guest.wasm \
  ../../examples/plugins/echo/component.wasm
cp target/wasm32-unknown-unknown/release/echo_guest.wasm \
  ../../examples/plugins/exporter/component.wasm
```

Clean-checkout CI and operators load the **checked-in** `component.wasm` files; rebuild only when
WIT or guest logic changes.

## Version negotiation

| Surface | Versioning |
| --- | --- |
| WIT package | `brolga:plugin@0.1.0` — additive within major; changing an existing import/export is a major bump (ADR 0001 §6, ADR 0008) |
| Manifest `api` | Range of ABI versions the plugin speaks (e.g. `0.1.0` or `>=0.1.0,<0.2.0`) |
| Extension `contract_version` | Per-point `major.minor`; host refuses a newer minor than it implements or a different major |

Unknown extension names and unsupported contract majors must fail with a structured
`plugin-error` (`code` + `message`), never hang or guess.

## Extension contracts (summary)

### Parser

- Input: host-bounded document bytes (`ParseRequest`).
- Output: JSON records (`ParseResponse`); host re-validates against `brolga-model`.
- **Originals and transformations stay on the host.** The plugin does not own provenance storage;
  it must not claim to replace the original feed.

### Exporter

- Input: a **policy-cleared** pack only (`ExporterPluginRequest`). The host runs the ADR 0007 gate
  *before* building the request. Guests never call `clear`.
- Output: bytes + `media_type` + **required** `lossiness`
  (`lossless` | `partially_lossless` | `compressed` | `derived`) and optional `declared_losses`.

### Policy extension (if used)

May **propose** only. Cannot clear export or override markings.

## Capabilities and security checklist

Before publishing a plugin:

- [ ] `capabilities: []` unless a scoped grant is **justified** and documented for operators.
- [ ] No secrets in manifests, components, or config examples.
- [ ] Treat all request bodies and config as **untrusted**.
- [ ] Bound request size and refuse oversize with `limit-exceeded`.
- [ ] Fail closed on unknown extension / unsupported contract.
- [ ] Exporters declare lossiness; never imply silent losslessness when fields drop.
- [ ] Do not embed host paths or credentials in error messages.
- [ ] Operator review: capability requests, API range, and formats before install.
- [ ] Prefer pure compute; network/filesystem are host decisions, not guest defaults.

Fixed host refusals (always true, whatever the manifest claims):

- no native shared-library loading
- no FS/network without scoped grants
- policy extensions are advisory only
- plugin output is untrusted until host validation

## Errors

Guest failures use WIT `plugin-error`:

| Code (examples) | Meaning |
| --- | --- |
| `unknown-extension` | Extension name not implemented |
| `unsupported-contract` | Contract major/minor this guest rejects |
| `limit-exceeded` | Request too large or other budget |

Host maps these to CLI failure exits; do not panic across the ABI.

## Testing

```bash
# Manifest validation (SDK + CLI)
cargo test -p brolga-plugin-sdk
brolga plugin validate examples/plugins/echo/manifest.yml

# Host + fixture (feature-gated)
cargo test -p brolga-plugin-host --features runtime
cargo build -p brolga-cli --features plugins
brolga plugin run examples/plugins/echo --extension parser --contract 1.0
brolga plugin run examples/plugins/exporter --extension exporter --contract 1.0
```

Deterministic golden tests should use checked-in wasm + fixed request bodies. Do not require live
network or model providers for plugin tests.

## Publication

1. Ship `manifest.yml` + `component.wasm` (and optional README) as a package directory.
2. Pin `api` and every `contract_version` deliberately.
3. Document capability requests and lossiness for exporters.
4. Operators install under their plugin root; host validates before any `invoke.call`.

There is **no marketplace** and no automatic third-party install in this milestone.

## Related

- ADR 0008 — SDK / WIT ABI
- ADR 0009 — capability-limited Wasm host
- ADR 0007 — export policy gate
- `docs/CLI.md` — `brolga plugin` commands
- `crates/brolga-plugin-sdk/wit/world.wit` — ABI source of truth
