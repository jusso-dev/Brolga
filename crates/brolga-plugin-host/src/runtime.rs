//! Wasmtime-backed component execution (`runtime` feature).

use std::path::Path;

use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::error::HostError;
use crate::limits::PluginLimits;
use crate::package::LoadedPackage;

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
        // No reference types / WASI / threads needed for the empty world.
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
    ) -> Result<(Store<HostState>, wasmtime::component::Instance), HostError> {
        let bytes = package
            .component
            .as_deref()
            .ok_or_else(|| HostError::Component {
                reason: "package has no component bytes".to_owned(),
            })?;
        let component = self.compile_component(bytes)?;
        let linker = Linker::<HostState>::new(&self.engine);
        // Intentionally empty: no WASI, no clocks, no filesystem.

        let state = HostState::new(self.limits);
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|error| HostError::CallTerminated {
                reason: format!("set fuel: {error}"),
            })?;
        // Epoch deadline: guest yields when the host increments the epoch (caller-driven for now).
        store.set_epoch_deadline(1);

        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|error| HostError::Component {
                reason: format!(
                    "instantiate failed (component may import host functions this sandbox does not provide): {error}"
                ),
            })?;
        Ok((store, instance))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::grant::GrantSet;
    use crate::package::load_package_files;

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
}
