//! What every handler shares.

use std::sync::Mutex;

use brolga_storage::StorageError;

use crate::config::ApiConfig;

/// Why a read did not happen.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadFailed {
    /// The store itself failed.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A previous request panicked while holding the store, so its state is not trustworthy.
    ///
    /// Unreachable in a release build, where `panic = "abort"` means a panic takes the process
    /// with it and there is nothing left to poison. It is reachable in tests, and answering an
    /// honest 500 is better than unwrapping — which would turn one panicking request into a
    /// permanently broken server.
    #[error("the store is unavailable after an earlier failure")]
    Unavailable,
}

/// The store and the configuration, shared across requests.
///
/// Generic over the store so the routes can be tested against any [`StoreRead`], and so nothing
/// here depends on the backend being SQLite.
///
/// # Why a mutex
///
/// A `rusqlite` connection holds a `RefCell` and is therefore `Send` but not `Sync`, so it cannot
/// be shared across the request handlers directly. The connection is serialised behind a mutex
/// rather than pooled, because these are millisecond reads against a local file and a pool would
/// add a failure mode — connections that disagree about the schema version mid-migration — to buy
/// throughput no homelab deployment needs. If this ever serves enough traffic to contend, the fix
/// is a read pool behind the same [`ApiState::read`] signature, and no handler changes.
///
/// The guard is never held across an `await`: [`ApiState::read`] takes a synchronous closure, so
/// the lock is released before the handler yields.
///
/// [`StoreRead`]: brolga_storage::store::StoreRead
#[derive(Debug)]
pub struct ApiState<S> {
    store: Mutex<S>,
    config: ApiConfig,
}

impl<S> ApiState<S> {
    /// Build the shared state.
    #[must_use]
    pub const fn new(store: S, config: ApiConfig) -> Self {
        Self {
            store: Mutex::new(store),
            config,
        }
    }

    /// Read from the store.
    ///
    /// # Errors
    ///
    /// Returns [`ReadFailed::Storage`] if the store failed, or [`ReadFailed::Unavailable`] if an
    /// earlier request panicked while holding it.
    pub fn read<T, F>(&self, read: F) -> Result<T, ReadFailed>
    where
        F: FnOnce(&S) -> Result<T, StorageError>,
    {
        let store = self.store.lock().map_err(|_| ReadFailed::Unavailable)?;
        read(&store).map_err(ReadFailed::Storage)
    }

    /// The configuration the server was built with.
    #[must_use]
    pub const fn config(&self) -> &ApiConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_read_returns_what_the_closure_returns() {
        let state = ApiState::new(41_u32, ApiConfig::loopback(0));
        let value = state.read(|store| Ok(store + 1)).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn a_storage_failure_is_reported_as_one() {
        let state = ApiState::new((), ApiConfig::loopback(0));
        let result: Result<(), _> = state.read(|()| {
            Err(StorageError::Query {
                operation: "test",
                reason: "no".to_owned(),
            })
        });
        assert!(matches!(result, Err(ReadFailed::Storage(_))));
    }

    /// The lock is taken and released per read, so a second read after the first succeeds. A guard
    /// held longer than the closure would deadlock the second request rather than serialise it.
    #[test]
    fn successive_reads_do_not_deadlock() {
        let state = ApiState::new(1_u32, ApiConfig::loopback(0));
        assert!(state.read(|store| Ok(*store)).is_ok());
        assert!(state.read(|store| Ok(*store)).is_ok());
    }
}
