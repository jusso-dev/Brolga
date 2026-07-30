//! What every handler shares.

use std::sync::{Arc, Mutex};

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
/// # Why `spawn_blocking`
///
/// Store backends are synchronous. The PostgreSQL client (`postgres` crate) owns an internal
/// Tokio runtime and calls `block_on` on every query; doing that on an axum worker panics with
/// "Cannot start a runtime from within a runtime". [`ApiState::read`] therefore runs the
/// closure on Tokio's blocking pool, where nesting a client runtime is safe. SQLite pays the
/// same hop; the cost is noise next to network I/O.
///
/// [`StoreRead`]: brolga_storage::store::StoreRead
#[derive(Debug)]
pub struct ApiState<S> {
    store: Arc<Mutex<S>>,
    config: ApiConfig,
}

impl<S> ApiState<S> {
    /// The policy identity a request to this server is served under.
    ///
    /// A loopback server with no configured credential is a local operator: somebody who can reach
    /// it can already read the database file, and withholding `TLP:RED` from the holder of the
    /// SQLite file would be theatre.
    ///
    /// **Everything else is anonymous.** A server bound off-host requires a credential to start at
    /// all, and until authentication resolves that credential to a named identity, the caller is
    /// treated as having identified nothing. That direction matters: an unidentified caller must
    /// never out-rank an authenticated one by saying less.
    #[must_use]
    pub fn policy_identity(&self) -> brolga_config::PolicyIdentity {
        if self.config.address().ip().is_loopback() && self.config.credential().is_none() {
            brolga_config::PolicyIdentity::local_operator()
        } else {
            brolga_config::PolicyIdentity::anonymous().in_environment("network")
        }
    }
    /// Build the shared state.
    #[must_use]
    pub fn new(store: S, config: ApiConfig) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            config,
        }
    }

    /// The configuration the server was built with.
    #[must_use]
    pub const fn config(&self) -> &ApiConfig {
        &self.config
    }
}

impl<S: Send + 'static> ApiState<S> {
    /// Read from the store on the blocking pool.
    ///
    /// # Errors
    ///
    /// Returns [`ReadFailed::Storage`] if the store failed, or [`ReadFailed::Unavailable`] if an
    /// earlier request panicked while holding it or the blocking task joined with an error.
    pub async fn read<T, F>(&self, read: F) -> Result<T, ReadFailed>
    where
        F: FnOnce(&S) -> Result<T, StorageError> + Send + 'static,
        T: Send + 'static,
    {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let store = store.lock().map_err(|_| ReadFailed::Unavailable)?;
            read(&store).map_err(ReadFailed::Storage)
        })
        .await
        .map_err(|_| ReadFailed::Unavailable)?
    }

    /// Synchronous read for unit tests (no async runtime required).
    ///
    /// # Errors
    ///
    /// Same as [`Self::read`].
    pub fn read_sync<T, F>(&self, read: F) -> Result<T, ReadFailed>
    where
        F: FnOnce(&S) -> Result<T, StorageError>,
    {
        let store = self.store.lock().map_err(|_| ReadFailed::Unavailable)?;
        read(&store).map_err(ReadFailed::Storage)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_read_returns_what_the_closure_returns() {
        let state = ApiState::new(41_u32, ApiConfig::loopback(0));
        let value = state.read_sync(|store| Ok(store + 1)).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn a_storage_failure_is_reported_as_one() {
        let state = ApiState::new((), ApiConfig::loopback(0));
        let result: Result<(), _> = state.read_sync(|()| {
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
        assert!(state.read_sync(|store| Ok(*store)).is_ok());
        assert!(state.read_sync(|store| Ok(*store)).is_ok());
    }
}
