//! Crate-private plumbing for joining concurrent callers on one in-flight computation.
//!
//! A leader installs a [`watch`] channel under its key, every other caller for that key
//! follows the same channel, and the leader's [`InFlightGuard`] removes the claim on every exit
//! path. Shared by the deps.dev memo (`deps_dev::memo`) and the interactive registry await
//! (`lsp_helpers::interactive_fetch`), which differ only in the payload and in what a follower
//! does with it.

use std::hash::Hash;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::watch;

/// A watch-channel payload: "leader hasn't finished yet" vs. "leader finished with `T`". A
/// dedicated enum rather than `Option<T>` so a caller's own `Option` return value keeps its
/// meaning distinct from the pending state.
#[derive(Debug, Clone)]
pub(crate) enum Slot<T> {
    /// The leader's work has not completed (or panicked) yet.
    Pending,
    /// The leader's work completed with this value.
    Ready(T),
}

/// Releases an in-flight claim on drop — including on panic or cancellation — so a claim can
/// never leak and permanently block later callers for the same key.
///
/// Declare it after the claim's [`watch::Sender`]: locals drop in reverse order, so the entry is
/// removed before the sender wakes followers, and a promoted follower never re-joins the dead
/// channel.
pub(crate) struct InFlightGuard<'a, K: Hash + Eq, W> {
    map: &'a DashMap<K, W>,
    key: K,
}

impl<'a, K: Hash + Eq, W> InFlightGuard<'a, K, W> {
    /// Guards the claim `key` holds in `map`.
    pub(crate) const fn new(map: &'a DashMap<K, W>, key: K) -> Self {
        Self { map, key }
    }
}

impl<K: Hash + Eq, W> Drop for InFlightGuard<'_, K, W> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// Either claims `key` as the leader (installing a fresh, `Pending` channel) or joins as a
/// follower of whichever channel the current leader already installed — a plain, synchronous
/// function so the returned [`Entry`] guard is dropped before the caller ever reaches an
/// `.await` (this workspace's `clippy.toml` denies holding one across an await point on
/// principle, regardless of whether a given case is provably safe).
pub(crate) fn claim_or_follow<K, T>(
    in_flight: &DashMap<K, watch::Receiver<Slot<T>>>,
    key: K,
) -> Result<watch::Sender<Slot<T>>, watch::Receiver<Slot<T>>>
where
    K: Hash + Eq,
{
    match in_flight.entry(key) {
        Entry::Occupied(occupied) => Err(occupied.get().clone()),
        Entry::Vacant(vacant) => {
            let (tx, rx) = watch::channel(Slot::Pending);
            vacant.insert(rx);
            Ok(tx)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    type Flights = DashMap<&'static str, watch::Receiver<Slot<u32>>>;

    #[test]
    fn the_first_caller_leads_and_later_callers_follow_the_same_channel() {
        let flights = Flights::new();

        let sender = claim_or_follow(&flights, "key").expect("the first caller claims the key");
        let receiver = claim_or_follow(&flights, "key").expect_err("a second caller follows");

        assert_matches!(&*receiver.borrow(), Slot::Pending);
        sender.send_replace(Slot::Ready(7));
        assert_matches!(&*receiver.borrow(), Slot::Ready(7));
    }

    #[test]
    fn distinct_keys_each_get_a_leader() {
        let flights = Flights::new();

        assert!(claim_or_follow(&flights, "a").is_ok());
        assert!(claim_or_follow(&flights, "b").is_ok());
        assert_eq!(flights.len(), 2);
    }

    #[tokio::test]
    async fn dropping_the_guard_and_sender_wakes_followers_and_frees_the_key() {
        let flights = Flights::new();
        let sender = claim_or_follow(&flights, "key").expect("leader");
        let mut receiver = claim_or_follow(&flights, "key").expect_err("follower");
        {
            let _guard = InFlightGuard::new(&flights, "key");
            drop(sender);
        }

        assert!(
            receiver.changed().await.is_err(),
            "a follower sees its leader vanish"
        );
        assert!(flights.is_empty(), "the claim was released");
        assert!(
            claim_or_follow(&flights, "key").is_ok(),
            "a promoted follower can claim the key again"
        );
    }

    #[test]
    fn the_guard_releases_its_claim_on_drop_even_when_the_leader_panics() {
        let flights = Flights::new();
        let _sender = claim_or_follow(&flights, "key").expect("leader");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = InFlightGuard::new(&flights, "key");
            panic!("leader failed");
        }));

        assert!(outcome.is_err());
        assert!(flights.is_empty());
    }
}
