# echo-guest

Minimal pure-compute Brolga plugin component used as a CI / example fixture (#48, #50).

Implements **parser** and **exporter** contracts at `1.0` with empty capabilities.

## Build

Requires `cargo-component` and the `wasm32-unknown-unknown` target (not wasip1 — wasip1
pulls WASI imports that the empty-import host refuses).

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

Checked-in `examples/plugins/*/component.wasm` files are what CI and operators load.
Rebuild and re-commit when the WIT world or guest logic changes.

## Contract

Exports `brolga:plugin@0.1.0` world `plugin` with no imports.

See [docs/PLUGIN-DEVELOPMENT.md](../../docs/PLUGIN-DEVELOPMENT.md).
