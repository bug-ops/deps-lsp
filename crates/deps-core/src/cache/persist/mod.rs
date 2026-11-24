//! Disk persistence for the registry HTTP cache (spec 051).

#![expect(dead_code, reason = "wired by PR-B, #700")]

mod dir;
#[cfg(test)]
mod dir_tests;
mod format;
#[cfg(test)]
mod format_tests;
mod freshness;
#[cfg(test)]
mod freshness_tests;
mod key;
#[cfg(test)]
mod key_tests;
#[cfg(test)]
mod target_tests;

use crate::net_policy::EnvSource;
use crate::policy_config::CachePersistence;
use dir::CacheDir;
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub use key::persistable_hosts;

/// The persistence tier resolved from configuration.
///
/// `Disk` carries the already-validated cache root, so holding one proves the directory could be
/// resolved; every failure to resolve it degrades to `Memory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PersistenceTarget {
    /// Memory only.
    Memory,
    /// Memory plus the disk tier rooted at the given cache directory.
    Disk(CacheDir),
}

impl PersistenceTarget {
    /// Resolves `config` against `env`.
    ///
    /// `Disk` with an unresolvable user cache directory falls back to `Memory` and logs a single
    /// warning; no other path logs.
    pub(crate) fn from_config(config: CachePersistence, env: &impl EnvSource) -> Self {
        match config {
            CachePersistence::Memory => Self::Memory,
            CachePersistence::Disk => match CacheDir::user_default(env) {
                Ok(dir) => Self::Disk(dir),
                Err(error) => {
                    tracing::warn!(%error, "disk cache unavailable, using memory only");
                    Self::Memory
                }
            },
        }
    }
}
