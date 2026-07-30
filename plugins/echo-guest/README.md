# echo-guest

Minimal pure-compute Brolga plugin component used as a CI fixture.

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
```

The checked-in `examples/plugins/echo/component.wasm` is the artifact CI tests load.
Rebuild and re-commit when the WIT world or guest logic changes.

## Contract

Exports `brolga:plugin@0.1.0` world `plugin` with no imports.
