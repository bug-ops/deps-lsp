//! The source-qualified failure memo behind [`InteractiveFetchGate`].

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::key::LookupKey;
use super::{InteractiveFetchGate, NoLiveList};
use crate::cache_policy::evict_expired_then_oldest_at;

/// How long a failed or timed-out lookup keeps interactive requests off the registry.
pub(super) const INTERACTIVE_FAILURE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on memo entries, so a manifest with thousands of failing dependencies cannot
/// grow the memo without bound.
pub(super) const INTERACTIVE_MEMO_CAP: usize = 1024;

/// Provenance of a memo record: a record inferred from the background outcomes must stop
/// applying once those outcomes clear, an interactive one is authoritative until its TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordState {
    SeededFromOutcome,
    /// An interactive await errored or elapsed. Always served back as
    /// [`NoLiveList::Unverified`]: only the request that received the error itself may
    /// fail open, so a recovered registry re-enables the yank filter within the TTL.
    InteractiveFailed,
    /// A live await succeeded while the background outcomes still report a failure for the
    /// package: it keeps those stale outcomes from re-seeding a degrade until they refresh.
    InteractiveSucceeded,
}

#[derive(Debug)]
pub(super) struct InteractiveRecord {
    state: RecordState,
    recorded_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FastFail {
    Seeded,
    Memo,
    /// Another lookup kind of the same package on the same route already failed interactively.
    Route,
}

impl FastFail {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Seeded => "seeded from background outcome",
            Self::Memo => "interactive failure memo",
            Self::Route => "interactive failure of the package's version list",
        }
    }
}

#[derive(Debug)]
pub(super) enum Decision {
    Live,
    Degrade(NoLiveList, FastFail),
}

impl InteractiveFetchGate {
    /// The memo's verdict for `lookup`: its own slot first, then the slot of any kind its
    /// policy honors (an interactive failure only; a seeded record never crosses kinds).
    pub(super) fn decide(
        &self,
        lookup: &Arc<LookupKey>,
        background_failure_known: bool,
        generation: u64,
        now: Instant,
    ) -> Decision {
        let own = self.decide_slot(lookup, background_failure_known, generation, now);
        if let Decision::Degrade(..) = own {
            return own;
        }
        let Some(honored) = lookup.kind().memo_policy().honors else {
            return own;
        };
        if self.interactive_failure_active(&lookup.in_slot(honored), now) {
            Decision::Degrade(NoLiveList::Unverified, FastFail::Route)
        } else {
            own
        }
    }

    fn interactive_failure_active(&self, key: &LookupKey, now: Instant) -> bool {
        self.memo.get(key).is_some_and(|record| {
            record.state == RecordState::InteractiveFailed
                && now.saturating_duration_since(record.recorded_at) < INTERACTIVE_FAILURE_TTL
        })
    }

    fn decide_slot(
        &self,
        lookup: &Arc<LookupKey>,
        background_failure_known: bool,
        generation: u64,
        now: Instant,
    ) -> Decision {
        let existing = self
            .memo
            .get(&**lookup)
            .map(|record| (record.state, record.recorded_at));
        match existing {
            Some((state, recorded_at))
                if now.saturating_duration_since(recorded_at) < INTERACTIVE_FAILURE_TTL =>
            {
                match state {
                    RecordState::SeededFromOutcome if background_failure_known => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
                    }
                    // A shared key's seed may be another manifest's: only the TTL retires it.
                    RecordState::SeededFromOutcome => Decision::Live,
                    RecordState::InteractiveFailed => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Memo)
                    }
                    RecordState::InteractiveSucceeded => Decision::Live,
                }
            }
            Some(_) => Decision::Live,
            None if background_failure_known => {
                self.record(lookup, RecordState::SeededFromOutcome, generation);
                Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
            }
            None => Decision::Live,
        }
    }

    fn insert(&self, key: &Arc<LookupKey>, state: RecordState, now: Instant) {
        evict_expired_then_oldest_at(
            &self.memo,
            INTERACTIVE_MEMO_CAP,
            now,
            |record| record.recorded_at,
            |_| INTERACTIVE_FAILURE_TTL,
        );
        self.memo.insert(
            Arc::clone(key),
            InteractiveRecord {
                state,
                recorded_at: now,
            },
        );
    }

    /// Writes `state` unless [`Self::invalidate_all`] ran since `generation` was read.
    pub(super) fn record(&self, key: &Arc<LookupKey>, state: RecordState, generation: u64) {
        self.insert(key, state, super::now());
        // Re-checked after the insert: an invalidation between a pre-check and the insert
        // would otherwise leave a stale record behind.
        if self.generation.load(Ordering::SeqCst) != generation {
            self.memo.remove(&**key);
        }
    }

    /// Drops a record that a live answer made moot. The common case has none, and a miss must
    /// not take a shard write lock.
    pub(super) fn forget_record(&self, key: &LookupKey) {
        if self.memo.contains_key(key) {
            self.memo.remove(key);
        }
    }
}
