//! Seqlock-style epoch over a configuration apply (#1799).
//!
//! `workspace/didChangeConfiguration` swaps the shared `DepsConfig` and then mirrors derived
//! values onto `ServerState` (registry policy, license policy, typosquat/gossip/OSV flags). A
//! diagnostics generation that reads both halves can observe one config's `DepsConfig` with
//! another's mirrored flags. The epoch is odd while an apply is in flight and even otherwise:
//! a reader waits for an even value, records it, and re-checks it before publishing, so any
//! apply that overlapped the generation is detected and the generation redone.

use tokio::sync::watch;

/// A snapshot of the config-apply counter; even means no apply is in flight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ConfigEpoch(u64);

impl ConfigEpoch {
    /// Whether no config apply was in flight when this value was read.
    pub(crate) const fn is_settled(self) -> bool {
        self.0.is_multiple_of(2)
    }
}

/// The shared counter behind [`ConfigEpoch`], bumped only through [`ConfigApplyGuard`].
#[derive(Debug)]
pub(crate) struct ConfigEpochCell {
    tx: watch::Sender<ConfigEpoch>,
}

impl Default for ConfigEpochCell {
    fn default() -> Self {
        Self {
            tx: watch::Sender::new(ConfigEpoch::default()),
        }
    }
}

impl ConfigEpochCell {
    /// The current epoch, possibly mid-apply.
    pub(crate) fn current(&self) -> ConfigEpoch {
        *self.tx.borrow()
    }

    /// Waits until no apply is in flight and returns that settled epoch.
    pub(crate) async fn settled(&self) -> ConfigEpoch {
        let mut rx = self.tx.subscribe();
        // The sender lives in `self`, so `wait_for` cannot observe a closed channel.
        rx.wait_for(|epoch| epoch.is_settled())
            .await
            .map_or_else(|_| self.current(), |epoch| *epoch)
    }

    /// Marks an apply as in flight until the returned guard drops.
    pub(super) fn begin_apply(&self) -> ConfigApplyGuard<'_> {
        self.tx.send_modify(|epoch| {
            if epoch.is_settled() {
                epoch.0 = epoch.0.wrapping_add(1);
            }
        });
        ConfigApplyGuard { cell: self }
    }
}

/// Keeps the epoch odd for as long as it lives, and restores it to even on drop, including
/// when the apply panics, so readers can never wait on a wedged epoch.
#[derive(Debug)]
#[must_use = "the epoch is settled again as soon as the guard drops"]
pub(crate) struct ConfigApplyGuard<'a> {
    cell: &'a ConfigEpochCell,
}

impl Drop for ConfigApplyGuard<'_> {
    fn drop(&mut self) {
        self.cell.tx.send_modify(|epoch| {
            if !epoch.is_settled() {
                epoch.0 = epoch.0.wrapping_add(1);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn apply_moves_epoch_odd_then_to_a_new_even_value() {
        let cell = ConfigEpochCell::default();
        let before = cell.current();
        assert!(before.is_settled());
        let guard = cell.begin_apply();
        assert!(!cell.current().is_settled());
        drop(guard);
        let after = cell.current();
        assert!(after.is_settled());
        assert_ne!(before, after);
    }

    #[test]
    fn begin_apply_while_in_flight_keeps_the_epoch_odd_and_settles_once() {
        let cell = ConfigEpochCell::default();
        let first = cell.begin_apply();
        let in_flight = cell.current();
        let second = cell.begin_apply();
        assert_eq!(cell.current(), in_flight, "a nested begin must not move it");
        drop(second);
        assert!(cell.current().is_settled());
        drop(first);
        assert!(cell.current().is_settled());
    }

    #[test]
    fn epoch_wraps_around_without_panicking() {
        let cell = ConfigEpochCell {
            tx: watch::Sender::new(ConfigEpoch(u64::MAX - 1)),
        };
        drop(cell.begin_apply());
        assert_eq!(cell.current(), ConfigEpoch(0));
        assert!(cell.current().is_settled());
    }

    #[test]
    fn panicking_apply_still_settles_the_epoch() {
        let cell = ConfigEpochCell::default();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cell.begin_apply();
            panic!("apply failed");
        }));
        assert!(unwound.is_err());
        assert!(cell.current().is_settled());
    }

    #[tokio::test]
    async fn settled_blocks_until_the_guard_drops() {
        let cell = std::sync::Arc::new(ConfigEpochCell::default());
        let guard = cell.begin_apply();
        let waiter = {
            let cell = std::sync::Arc::clone(&cell);
            tokio::spawn(async move { cell.settled().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "settled() must wait during an apply");
        drop(guard);
        let epoch = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("settled() must wake once the apply ends")
            .expect("waiter task");
        assert!(epoch.is_settled());
    }
}
