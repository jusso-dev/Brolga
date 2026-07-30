//! Resource caps for a single plugin instance / call.

use core::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::HostError;

/// Limits applied to every plugin call.
///
/// Exhaustion terminates **only the call** ([#48](https://github.com/jusso-dev/Brolga/issues/48)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginLimits {
    /// Max linear memory in bytes for the instance (Wasmtime store limit).
    pub max_memory_bytes: u64,
    /// Fuel units consumed by guest execution. Zero is refused — that would disable the meter.
    pub max_fuel: u64,
    /// Wall-clock budget for one call.
    pub max_wall_time: Duration,
    /// Max bytes of request or response body the host will pass or accept.
    pub max_io_bytes: u64,
}

impl PluginLimits {
    /// Safe defaults for untrusted third-party components.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            // 16 MiB guest memory.
            max_memory_bytes: 16 * 1024 * 1024,
            // Enough for modest pure-compute; tuned later with benchmarks.
            max_fuel: 1_000_000_000,
            max_wall_time: Duration::from_secs(5),
            max_io_bytes: 8 * 1024 * 1024,
        }
    }

    /// Validate ranges.
    ///
    /// # Errors
    ///
    /// Zero or absurd values.
    pub fn validated(self) -> Result<Self, HostError> {
        if self.max_memory_bytes < 64 * 1024 {
            return Err(HostError::Limits(
                "max_memory_bytes must be at least 64 KiB".to_owned(),
            ));
        }
        if self.max_memory_bytes > 512 * 1024 * 1024 {
            return Err(HostError::Limits(
                "max_memory_bytes must be at most 512 MiB".to_owned(),
            ));
        }
        if self.max_fuel == 0 {
            return Err(HostError::Limits(
                "max_fuel must be non-zero; zero disables metering".to_owned(),
            ));
        }
        if self.max_wall_time.is_zero() {
            return Err(HostError::Limits(
                "max_wall_time must be non-zero".to_owned(),
            ));
        }
        if self.max_wall_time > Duration::from_secs(300) {
            return Err(HostError::Limits(
                "max_wall_time must be at most 300 seconds".to_owned(),
            ));
        }
        if self.max_io_bytes < 1024 {
            return Err(HostError::Limits(
                "max_io_bytes must be at least 1 KiB".to_owned(),
            ));
        }
        Ok(self)
    }
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        assert!(PluginLimits::defaults().validated().is_ok());
    }

    #[test]
    fn zero_fuel_refused() {
        let mut limits = PluginLimits::defaults();
        limits.max_fuel = 0;
        assert!(limits.validated().is_err());
    }
}
