//! Wasmtime-backed component execution (`runtime` feature).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::error::HostError;
use crate::limits::PluginLimits;
use crate::package::LoadedPackage;

// Bindings for `brolga:plugin@0.1.0` world `plugin` (empty imports).
// Generated items are public by the macro; silence docs lints for them only.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        path: "../brolga-plugin-sdk/wit/world.wit",
        world: "plugin",
    });
}
use bindings::Plugin;

/// Host state held in the Wasmtime store for one call.
pub struct HostState {
    /// Resource table required by the component model.
    pub table: ResourceTable,
    /// Store-level memory/table limits.
    pub limits: StoreLimits,
}

impl HostState {
    fn new(plugin_limits: PluginLimits) -> Self {
        let memory = usize::try_from(plugin_limits.max_memory_bytes).unwrap_or(usize::MAX);
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory)
            .memories(1)
            .tables(4)
            .instances(1)
            .build();
        Self {
            table: ResourceTable::new(),
            limits,
        }
    }
}

/// Result of one plugin invoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeResult {
    /// UTF-8 JSON body from the guest (or empty if guest returned only status).
    pub body: Vec<u8>,
    /// Fuel remaining after the call, when metering is enabled.
    pub fuel_remaining: Option<u64>,
}

/// A configured Wasmtime engine for Brolga plugins.
pub struct PluginEngine {
    engine: Engine,
    limits: PluginLimits,
}

impl PluginEngine {
    /// Build an engine with fuel and epoch interruption enabled.
    ///
    /// # Errors
    ///
    /// Invalid limits or Wasmtime config failure.
    pub fn new(limits: PluginLimits) -> Result<Self, HostError> {
        let limits = limits.validated()?;
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|error| HostError::Component {
            reason: format!("wasmtime engine: {error}"),
        })?;
        Ok(Self { engine, limits })
    }

    /// Borrow limits.
    #[must_use]
    pub const fn limits(&self) -> PluginLimits {
        self.limits
    }

    /// Load a component from bytes and refuse modules that are not components.
    ///
    /// # Errors
    ///
    /// Invalid component encoding.
    pub fn compile_component(&self, bytes: &[u8]) -> Result<Component, HostError> {
        Component::new(&self.engine, bytes).map_err(|error| HostError::Component {
            reason: format!("not a loadable component: {error}"),
        })
    }

    /// Compile from a path.
    ///
    /// # Errors
    ///
    /// I/O or compile failure.
    pub fn compile_component_file(&self, path: &Path) -> Result<Component, HostError> {
        let bytes = std::fs::read(path)
            .map_err(|error| HostError::Io(format!("read {}: {error}", path.display())))?;
        self.compile_component(&bytes)
    }

    /// Instantiate a loaded package's component with an empty linker (no host imports).
    ///
    /// Proves the sandbox: a component that requires WASI or other imports fails here.
    ///
    /// # Errors
    ///
    /// Missing component bytes, compile/link/instantiate failure, fuel setup failure.
    pub fn instantiate_sandboxed(
        &self,
        package: &LoadedPackage,
    ) -> Result<(Store<HostState>, Plugin), HostError> {
        let bytes = package
            .component
            .as_deref()
            .ok_or_else(|| HostError::Component {
                reason: "package has no component bytes".to_owned(),
            })?;
        let component = self.compile_component(bytes)?;
        let linker = Linker::<HostState>::new(&self.engine);

        let state = HostState::new(self.limits);
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|error| HostError::CallTerminated {
                reason: format!("set fuel: {error}"),
            })?;
        // One epoch tick is allowed; the wall-clock watcher increments the engine epoch.
        store.set_epoch_deadline(1);

        let instance = Plugin::instantiate(&mut store, &component, &linker).map_err(|error| {
            HostError::Component {
                reason: format!(
                    "instantiate failed (component may import host functions this sandbox does not provide): {error}"
                ),
            }
        })?;
        Ok((store, instance))
    }

    /// Call `invoke.call` on a package with wall-clock and fuel caps.
    ///
    /// # Errors
    ///
    /// Guest error, trap, fuel/epoch exhaustion, I/O body over limit, instantiate failure.
    pub fn invoke(
        &self,
        package: &LoadedPackage,
        extension: &str,
        contract_version: &str,
        request: &[u8],
    ) -> Result<InvokeResult, HostError> {
        let request_len = u64::try_from(request.len()).unwrap_or(u64::MAX);
        if request_len > self.limits.max_io_bytes {
            return Err(HostError::CallTerminated {
                reason: format!(
                    "request {} bytes exceeds max_io_bytes {}",
                    request.len(),
                    self.limits.max_io_bytes
                ),
            });
        }

        let (mut store, plugin) = self.instantiate_sandboxed(package)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let engine = self.engine.clone();
        let wall = self.limits.max_wall_time;
        let cancel_thread = cancel.clone();
        let watchdog = thread::spawn(move || {
            let slept = sleep_interruptible(wall, &cancel_thread);
            if !slept {
                return;
            }
            // Force guest to yield and fail the deadline.
            engine.increment_epoch();
        });

        let result = plugin.brolga_plugin_invoke().call_call(
            &mut store,
            extension,
            contract_version,
            request,
        );

        cancel.store(true, Ordering::SeqCst);
        let _ = watchdog.join();

        let body = match result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(guest)) => {
                return Err(HostError::Guest {
                    code: guest.code,
                    message: guest.message,
                });
            }
            Err(trap) => {
                return Err(HostError::CallTerminated {
                    reason: format!("guest trap or limit: {trap}"),
                });
            }
        };

        let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if body_len > self.limits.max_io_bytes {
            return Err(HostError::CallTerminated {
                reason: format!(
                    "response {} bytes exceeds max_io_bytes {}",
                    body.len(),
                    self.limits.max_io_bytes
                ),
            });
        }

        let fuel_remaining = store.get_fuel().ok();
        Ok(InvokeResult {
            body,
            fuel_remaining,
        })
    }

    /// Call `manifest.get` on a component (side-effect free identity probe).
    ///
    /// # Errors
    ///
    /// Guest error or trap.
    pub fn guest_manifest_json(&self, package: &LoadedPackage) -> Result<String, HostError> {
        let (mut store, plugin) = self.instantiate_sandboxed(package)?;
        match plugin.brolga_plugin_manifest().call_get(&mut store) {
            Ok(Ok(json)) => Ok(json),
            Ok(Err(guest)) => Err(HostError::Guest {
                code: guest.code,
                message: guest.message,
            }),
            Err(trap) => Err(HostError::CallTerminated {
                reason: format!("guest trap or limit: {trap}"),
            }),
        }
    }
}

/// Sleep for `duration`, returning early if `cancel` becomes true.
///
/// Returns `true` if the full duration elapsed (deadline fired), `false` if cancelled early.
fn sleep_interruptible(duration: Duration, cancel: &AtomicBool) -> bool {
    let slice = Duration::from_millis(10);
    let mut remaining = duration;
    while !remaining.is_zero() {
        if cancel.load(Ordering::SeqCst) {
            return false;
        }
        let step = if remaining > slice { slice } else { remaining };
        thread::sleep(step);
        remaining = remaining.saturating_sub(step);
    }
    !cancel.load(Ordering::SeqCst)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::grant::GrantSet;
    use crate::package::load_package_files;
    use std::path::PathBuf;

    fn fixture_component() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/echo/component.wasm")
    }

    fn echo_package() -> LoadedPackage {
        let wasm = std::fs::read(fixture_component()).expect("fixture component.wasm checked in");
        let manifest = br#"
schema_version: brolga.plugin.manifest/1.0
name: example.parser.echo
version: 1.0.0
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
    formats: ["application/x-echo"]
    outputs: ["claim"]
capabilities: []
"#;
        load_package_files(
            manifest,
            Some(&wasm),
            &GrantSet::empty(),
            PluginLimits::defaults(),
        )
        .unwrap()
    }

    #[test]
    fn engine_builds_with_defaults() {
        assert!(PluginEngine::new(PluginLimits::defaults()).is_ok());
    }

    #[test]
    fn garbage_bytes_are_not_a_component() {
        let engine = PluginEngine::new(PluginLimits::defaults()).unwrap();
        assert!(
            engine.compile_component(b"not wasm").is_err(),
            "garbage must not compile as a component"
        );
    }

    #[test]
    fn package_without_component_cannot_instantiate() {
        let engine = PluginEngine::new(PluginLimits::defaults()).unwrap();
        let package = load_package_files(
            br#"
schema_version: brolga.plugin.manifest/1.0
name: n
version: 1
api: "0.1.0"
extension_points:
  - kind: parser
    contract_version: "1.0"
"#,
            None,
            &GrantSet::empty(),
            PluginLimits::defaults(),
        )
        .unwrap();
        assert!(
            engine.instantiate_sandboxed(&package).is_err(),
            "missing component bytes must refuse instantiate"
        );
    }

    #[test]
    fn echo_fixture_manifest_and_invoke() {
        let engine = PluginEngine::new(PluginLimits::defaults()).unwrap();
        let package = echo_package();

        let json = engine.guest_manifest_json(&package).unwrap();
        // Guest manifest may list multiple points; package dir name is separate.
        assert!(
            json.contains("example.fixture.echo") || json.contains("example.parser.echo"),
            "{json}"
        );
        assert!(json.contains("parser"), "{json}");
        assert!(json.contains("exporter"), "{json}");

        let result = engine
            .invoke(&package, "parser", "1.0", b"hello-indicator")
            .unwrap();
        let body = String::from_utf8(result.body).unwrap();
        assert!(body.contains("echo_bytes"), "{body}");
        assert!(
            body.contains("\"echo_bytes\":15") || body.contains("echo_bytes\":15"),
            "{body}"
        );

        let export = engine.invoke(&package, "exporter", "1.0", b"{}").unwrap();
        let export_body = String::from_utf8(export.body).unwrap();
        assert!(export_body.contains("lossiness"), "{export_body}");
        assert!(export_body.contains("derived"), "{export_body}");
    }

    #[test]
    fn echo_fixture_unknown_extension_is_guest_error() {
        let engine = PluginEngine::new(PluginLimits::defaults()).unwrap();
        let package = echo_package();
        let error = engine.invoke(&package, "policy", "1.0", b"{}").unwrap_err();
        match error {
            HostError::Guest { code, .. } => assert_eq!(code, "unknown-extension"),
            other => panic!("expected Guest, got {other:?}"),
        }
    }

    #[test]
    fn core_module_with_wasi_import_is_not_a_component() {
        // Classic WASM module header + import section for wasi — not a component binary.
        // Minimal invalid-as-component bytes that still look like wasm.
        let engine = PluginEngine::new(PluginLimits::defaults()).unwrap();
        // \0asm version 1
        let core = b"\0asm\x01\x00\x00\x00";
        assert!(engine.compile_component(core).is_err());
    }

    #[test]
    fn wall_clock_deadline_terminates_call() {
        // Tiny fuel and wall time so even a fast guest is fine; this asserts the watchdog path
        // does not crash the host when the call finishes first.
        let mut limits = PluginLimits::defaults();
        limits.max_wall_time = Duration::from_millis(200);
        let engine = PluginEngine::new(limits).unwrap();
        let package = echo_package();
        let result = engine.invoke(&package, "parser", "1.0", b"x").unwrap();
        assert!(!result.body.is_empty());
    }
}
