//! Crate-private plumbing for joining concurrent callers on one in-flight computation.
//!
//! [`claim_or_follow`] makes the first caller for a key its [`Leader`] and every other caller a
//! [`Follower`] of the leader's [`watch`] channel. The leader handle owns both halves of the
//! claim, so the entry is released before followers wake on every exit path, and no caller can
//! get that order wrong. Shared by the deps.dev memo (`deps_dev::memo`) and the interactive
//! registry await (`lsp_helpers::interactive_fetch`), which differ only in the payload and in
//! what a follower does with it.

use std::hash::Hash;

use dashmap::mapref::entry::Entry;
use dashmap::{DashMap, DashSet};
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

/// The in-flight claims of one flight kind: key to the leader's channel.
pub(crate) type FlightMap<K, T> = DashMap<K, watch::Receiver<Slot<T>>>;

/// A collection of in-flight claims an [`InFlightGuard`] can release a key from.
pub(crate) trait ReleaseClaim<K> {
    /// Removes `key`'s claim.
    fn release(&self, key: &K);
}

impl<K: Hash + Eq, W> ReleaseClaim<K> for DashMap<K, W> {
    fn release(&self, key: &K) {
        self.remove(key);
    }
}

impl<K: Hash + Eq> ReleaseClaim<K> for DashSet<K> {
    fn release(&self, key: &K) {
        self.remove(key);
    }
}

/// Releases an in-flight claim on drop, including on panic or cancellation, so a claim can
/// never leak and permanently block later callers for the same key.
pub(crate) struct InFlightGuard<'a, K, C: ReleaseClaim<K>> {
    claims: &'a C,
    key: K,
}

impl<'a, K, C: ReleaseClaim<K>> InFlightGuard<'a, K, C> {
    /// Guards the claim `key` holds in `claims`.
    pub(crate) const fn new(claims: &'a C, key: K) -> Self {
        Self { claims, key }
    }
}

impl<K, C: ReleaseClaim<K>> Drop for InFlightGuard<'_, K, C> {
    fn drop(&mut self) {
        self.claims.release(&self.key);
    }
}

/// The caller that runs the work for a key.
///
/// Dropping it, finished or not, releases the claim first and then drops the sender, so a
/// follower woken by the vanished leader finds the key free and a promoted follower never
/// re-joins the dead channel. The field order is that drop order.
pub(crate) struct Leader<'a, K: Hash + Eq, T> {
    _claim: InFlightGuard<'a, K, FlightMap<K, T>>,
    sender: watch::Sender<Slot<T>>,
}

impl<K: Hash + Eq, T> Leader<'_, K, T> {
    /// Hands `value` to every follower and releases the claim.
    pub(crate) fn publish(self, value: T) {
        self.sender.send_replace(Slot::Ready(value));
    }
}

/// A caller waiting on a leader's result.
pub(crate) struct Follower<T>(watch::Receiver<Slot<T>>);

impl<T> From<watch::Receiver<Slot<T>>> for Follower<T> {
    fn from(receiver: watch::Receiver<Slot<T>>) -> Self {
        Self(receiver)
    }
}

impl<T: Clone + Send + Sync> Follower<T> {
    /// Waits for the leader's value, or returns `None` when the leader vanished (panicked or
    /// was cancelled) without publishing one.
    pub(crate) async fn wait(mut self) -> Option<T> {
        loop {
            if let Slot::Ready(value) = &*self.0.borrow_and_update() {
                return Some(value.clone());
            }
            if self.0.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// Whether the caller leads `key` or follows whoever already does.
pub(crate) enum Claim<'a, K: Hash + Eq, T> {
    Leader(Leader<'a, K, T>),
    Follower(Follower<T>),
}

/// Either claims `key` as the leader (installing a fresh, `Pending` channel) or joins as a
/// follower of whichever channel the current leader already installed. A plain, synchronous
/// function so the map's [`Entry`] guard is dropped before the caller ever reaches an `.await`
/// (this workspace's `clippy.toml` denies holding one across an await point on principle,
/// regardless of whether a given case is provably safe).
pub(crate) fn claim_or_follow<K, T>(in_flight: &FlightMap<K, T>, key: K) -> Claim<'_, K, T>
where
    K: Hash + Eq + Clone,
{
    match in_flight.entry(key.clone()) {
        Entry::Occupied(occupied) => Claim::Follower(Follower(occupied.get().clone())),
        Entry::Vacant(vacant) => {
            let (sender, receiver) = watch::channel(Slot::Pending);
            vacant.insert(receiver);
            Claim::Leader(Leader {
                _claim: InFlightGuard::new(in_flight, key),
                sender,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Flights = FlightMap<&'static str, u32>;

    fn leader<'a>(flights: &'a Flights, key: &'static str) -> Leader<'a, &'static str, u32> {
        match claim_or_follow(flights, key) {
            Claim::Leader(leader) => leader,
            Claim::Follower(_) => panic!("expected to lead {key}"),
        }
    }

    fn follower(flights: &Flights, key: &'static str) -> Follower<u32> {
        match claim_or_follow(flights, key) {
            Claim::Follower(follower) => follower,
            Claim::Leader(_) => panic!("expected to follow {key}"),
        }
    }

    #[tokio::test]
    async fn the_first_caller_leads_and_later_callers_receive_its_value() {
        let flights = Flights::new();

        let leader = leader(&flights, "key");
        let first = follower(&flights, "key");
        let second = follower(&flights, "key");
        leader.publish(7);

        assert_eq!(first.wait().await, Some(7));
        assert_eq!(second.wait().await, Some(7));
        assert!(flights.is_empty(), "publishing releases the claim");
    }

    #[test]
    fn distinct_keys_each_get_a_leader() {
        let flights = Flights::new();

        let _a = leader(&flights, "a");
        let _b = leader(&flights, "b");
        assert_eq!(flights.len(), 2);
    }

    #[tokio::test]
    async fn dropping_the_leader_wakes_followers_after_freeing_the_key() {
        let flights = Flights::new();
        let leader = leader(&flights, "key");
        let follower = follower(&flights, "key");
        drop(leader);

        assert_eq!(
            follower.wait().await,
            None,
            "a follower sees its leader vanish"
        );
        assert!(flights.is_empty(), "the claim was released");
        assert!(
            matches!(claim_or_follow(&flights, "key"), Claim::Leader(_)),
            "a promoted follower can claim the key again"
        );
    }

    /// A reader holding the claim's shard blocks its removal. While it does, dropping the leader
    /// must not wake a follower: the claim is released first, then the sender is dropped, so a
    /// woken follower always finds the key free.
    #[tokio::test]
    async fn followers_are_woken_only_after_the_claim_is_released() {
        use std::sync::mpsc;
        use std::time::Duration;

        let flights: &'static Flights = Box::leak(Box::new(Flights::new()));
        let leader = leader(flights, "key");
        let mut waiting = Box::pin(follower(flights, "key").wait());

        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let reader = std::thread::spawn(move || {
            let guard = flights.get(&"key");
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        held_rx.recv().unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let dropper = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            drop(leader);
        });
        started_rx.recv().unwrap();

        tokio::select! {
            woken = &mut waiting => panic!("follower woke ({woken:?}) while the claim was still held"),
            () = tokio::time::sleep(Duration::from_millis(200)) => {}
        }

        release_tx.send(()).unwrap();
        assert_eq!(waiting.await, None);
        assert!(matches!(claim_or_follow(flights, "key"), Claim::Leader(_)));
        reader.join().unwrap();
        dropper.join().unwrap();
    }

    #[test]
    fn the_leader_releases_its_claim_even_when_it_panics() {
        let flights = Flights::new();

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _leader = leader(&flights, "key");
            panic!("leader failed");
        }));

        assert!(outcome.is_err());
        assert!(flights.is_empty());
    }

    #[test]
    fn a_guard_releases_a_set_claim_on_drop() {
        let claims: DashSet<&str> = DashSet::new();
        claims.insert("key");
        {
            let _guard = InFlightGuard::new(&claims, "key");
        }
        assert!(claims.is_empty());
    }
}
