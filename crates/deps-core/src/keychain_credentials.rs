//! Live state of the opt-in macOS Keychain credential setting.
//!
//! [`KeychainCredentialsHandle`] holds the current [`KeychainCredentials`] value together with a
//! [`KeychainGeneration`] that advances whenever the value changes, as one atomic unit, so a
//! reader can never pair a new setting with an old generation. It also carries the channel on
//! which a credential consumer announces a late-resolved credential, and a list of observers
//! told synchronously about each change (so memoized secrets are dropped at once).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError, Weak};

use tokio::sync::broadcast;

use crate::policy_config::KeychainCredentials;

const RESOLVED_CAPACITY: usize = 8;

/// How many times the Keychain setting has changed value; memoized credentials are valid for
/// exactly one generation.
///
/// # Examples
///
/// ```
/// use deps_core::keychain_credentials::KeychainGeneration;
///
/// assert!(KeychainGeneration::INITIAL < KeychainGeneration::INITIAL.next());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeychainGeneration(u64);

impl KeychainGeneration {
    /// The generation of a handle that never changed.
    pub const INITIAL: Self = Self(0);

    /// The generation after one more change.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// The setting and its generation, read in one atomic load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainSnapshot {
    /// The setting at that instant.
    pub setting: KeychainCredentials,
    /// The generation at that instant.
    pub generation: KeychainGeneration,
}

impl KeychainSnapshot {
    const ENABLED_BIT: u64 = 1;

    const fn pack(self) -> u64 {
        let enabled = match self.setting {
            KeychainCredentials::Enabled => Self::ENABLED_BIT,
            KeychainCredentials::Disabled => 0,
        };
        (self.generation.0 << 1) | enabled
    }

    const fn unpack(packed: u64) -> Self {
        Self {
            setting: if packed & Self::ENABLED_BIT == 0 {
                KeychainCredentials::Disabled
            } else {
                KeychainCredentials::Enabled
            },
            generation: KeychainGeneration(packed >> 1),
        }
    }
}

/// A holder of per-setting state (such as memoized credentials) that must be dropped as soon as
/// the setting changes, not at its next use.
pub trait KeychainGenerationObserver: Send + Sync {
    /// Called synchronously from [`KeychainCredentialsHandle::set`] after the handle moved to
    /// `generation`.
    fn generation_advanced(&self, generation: KeychainGeneration);
}

/// Live-updatable, `Arc`-shareable handle to the current [`KeychainCredentials`] setting.
///
/// The setting and its generation live in one `AtomicU64`, so [`Self::snapshot`] is never torn:
/// a consumer that starts a lookup for a setting value always tags it with that value's own
/// generation.
///
/// # Examples
///
/// ```
/// use deps_core::keychain_credentials::KeychainCredentialsHandle;
/// use deps_core::policy_config::KeychainCredentials;
///
/// let handle = KeychainCredentialsHandle::new(KeychainCredentials::Disabled);
/// let before = handle.generation();
/// handle.set(KeychainCredentials::Enabled);
/// assert_eq!(handle.get(), KeychainCredentials::Enabled);
/// assert_ne!(handle.generation(), before);
///
/// let unchanged = handle.generation();
/// handle.set(KeychainCredentials::Enabled);
/// assert_eq!(handle.generation(), unchanged);
/// ```
///
/// An observer learns of each change as it happens:
///
/// ```
/// use deps_core::keychain_credentials::{
///     KeychainCredentialsHandle, KeychainGeneration, KeychainGenerationObserver,
/// };
/// use deps_core::policy_config::KeychainCredentials;
/// use std::sync::{Arc, Mutex};
///
/// struct Latest(Mutex<KeychainGeneration>);
/// impl KeychainGenerationObserver for Latest {
///     fn generation_advanced(&self, generation: KeychainGeneration) {
///         *self.0.lock().unwrap() = generation;
///     }
/// }
///
/// let handle = KeychainCredentialsHandle::default();
/// let observer = Arc::new(Latest(Mutex::new(KeychainGeneration::INITIAL)));
/// handle.register_observer(Arc::downgrade(&observer) as _);
/// handle.set(KeychainCredentials::Enabled);
/// assert_eq!(*observer.0.lock().unwrap(), KeychainGeneration::INITIAL.next());
/// ```
#[derive(Debug)]
pub struct KeychainCredentialsHandle {
    state: AtomicU64,
    resolved: broadcast::Sender<()>,
    observers: Mutex<Vec<Weak<dyn KeychainGenerationObserver>>>,
}

impl KeychainCredentialsHandle {
    /// Creates a handle initialized to `initial`, at [`KeychainGeneration::INITIAL`].
    #[must_use]
    pub fn new(initial: KeychainCredentials) -> Self {
        let snapshot = KeychainSnapshot {
            setting: initial,
            generation: KeychainGeneration::INITIAL,
        };
        Self {
            state: AtomicU64::new(snapshot.pack()),
            resolved: broadcast::channel(RESOLVED_CAPACITY).0,
            observers: Mutex::default(),
        }
    }

    /// Registers `observer`, notified on every actual change of the setting for as long as it is
    /// alive. Held weakly, so registering never extends its lifetime.
    pub fn register_observer(&self, observer: Weak<dyn KeychainGenerationObserver>) {
        self.observers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(observer);
    }

    /// The setting and generation, consistent with each other.
    #[must_use]
    pub fn snapshot(&self) -> KeychainSnapshot {
        KeychainSnapshot::unpack(self.state.load(Ordering::SeqCst))
    }

    /// The current setting.
    #[must_use]
    pub fn get(&self) -> KeychainCredentials {
        self.snapshot().setting
    }

    /// The current generation.
    #[must_use]
    pub fn generation(&self) -> KeychainGeneration {
        self.snapshot().generation
    }

    /// Updates the setting; advances the generation only when the value changes, then notifies
    /// the observers synchronously.
    pub fn set(&self, value: KeychainCredentials) {
        let changed = self
            .state
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |packed| {
                let current = KeychainSnapshot::unpack(packed);
                (current.setting != value).then(|| {
                    KeychainSnapshot {
                        setting: value,
                        generation: current.generation.next(),
                    }
                    .pack()
                })
            })
            .map(|previous| KeychainSnapshot::unpack(previous).generation.next());
        let Ok(generation) = changed else {
            return;
        };
        let observers: Vec<_> = {
            let mut guard = self
                .observers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            guard.retain(|observer| observer.strong_count() > 0);
            guard.iter().filter_map(Weak::upgrade).collect()
        };
        for observer in observers {
            observer.generation_advanced(generation);
        }
    }

    /// Subscribes to "a credential resolved after a caller gave up waiting" events. A lagged
    /// receiver should treat that the same as one event.
    #[must_use]
    pub fn subscribe_resolved(&self) -> broadcast::Receiver<()> {
        self.resolved.subscribe()
    }

    /// The sending half, for the consumer that resolves credentials.
    #[must_use]
    pub fn resolved_sender(&self) -> broadcast::Sender<()> {
        self.resolved.clone()
    }
}

impl Default for KeychainCredentialsHandle {
    fn default() -> Self {
        Self::new(KeychainCredentials::default())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn snapshot_round_trips_through_the_packed_form() {
        for setting in [KeychainCredentials::Disabled, KeychainCredentials::Enabled] {
            let snapshot = KeychainSnapshot {
                setting,
                generation: KeychainGeneration(12345),
            };
            assert_eq!(KeychainSnapshot::unpack(snapshot.pack()), snapshot);
        }
    }

    /// Toggles alternate Disabled/Enabled from generation 0, so an odd generation must always
    /// pair with `Enabled`; two separate atomics would let a reader see the new setting with the
    /// old generation.
    #[test]
    fn a_reader_never_observes_a_setting_paired_with_another_generation() {
        let handle = Arc::new(KeychainCredentialsHandle::default());
        let writer = {
            let handle = Arc::clone(&handle);
            std::thread::spawn(move || {
                for step in 0..20_000 {
                    handle.set(if step % 2 == 0 {
                        KeychainCredentials::Enabled
                    } else {
                        KeychainCredentials::Disabled
                    });
                }
            })
        };
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let handle = Arc::clone(&handle);
                std::thread::spawn(move || {
                    for _ in 0..50_000 {
                        let snapshot = handle.snapshot();
                        let odd = snapshot.generation.0 % 2 == 1;
                        assert_eq!(
                            odd,
                            snapshot.setting == KeychainCredentials::Enabled,
                            "torn read: {snapshot:?}"
                        );
                    }
                })
            })
            .collect();
        writer.join().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
    }

    #[test]
    fn observers_are_told_only_about_real_changes_and_dead_ones_are_dropped() {
        struct Count(AtomicU64);
        impl KeychainGenerationObserver for Count {
            fn generation_advanced(&self, _generation: KeychainGeneration) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let handle = KeychainCredentialsHandle::default();
        let observer = Arc::new(Count(AtomicU64::new(0)));
        handle.register_observer(Arc::downgrade(&observer) as _);
        handle.set(KeychainCredentials::Disabled);
        assert_eq!(observer.0.load(Ordering::SeqCst), 0);
        handle.set(KeychainCredentials::Enabled);
        handle.set(KeychainCredentials::Enabled);
        assert_eq!(observer.0.load(Ordering::SeqCst), 1);
        drop(observer);
        handle.set(KeychainCredentials::Disabled);
        assert!(handle.observers.lock().unwrap().is_empty());
    }
}
