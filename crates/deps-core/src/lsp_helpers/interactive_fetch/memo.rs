//! The source-qualified failure memo behind [`InteractiveFetchGate`].

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::key::InteractiveFetchKey;
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
}

impl FastFail {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Seeded => "seeded from background outcome",
            Self::Memo => "interactive failure memo",
        }
    }
}

#[derive(Debug)]
pub(super) enum Decision {
    Live,
    Degrade(NoLiveList, FastFail),
}

impl InteractiveFetchGate {
    pub(super) fn decide(
        &self,
        key: &InteractiveFetchKey,
        background_failure_known: bool,
        generation: u64,
        now: Instant,
    ) -> Decision {
        let existing = self
            .memo
            .get(key)
            .map(|record| (record.state, record.recorded_at));
        match existing {
            Some((state, recorded_at))
                if now.saturating_duration_since(recorded_at) < INTERACTIVE_FAILURE_TTL =>
            {
                match state {
                    RecordState::SeededFromOutcome if background_failure_known => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
                    }
                    RecordState::SeededFromOutcome => {
                        // The background fetch has since succeeded (or been cleared).
                        self.memo.remove_if(key, |_, record| {
                            record.state == RecordState::SeededFromOutcome
                        });
                        Decision::Live
                    }
                    RecordState::InteractiveFailed => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Memo)
                    }
                    RecordState::InteractiveSucceeded => Decision::Live,
                }
            }
            Some(_) => Decision::Live,
            None if background_failure_known => {
                self.record(key, RecordState::SeededFromOutcome, generation);
                Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
            }
            None => Decision::Live,
        }
    }

    fn insert(&self, key: InteractiveFetchKey, state: RecordState, now: Instant) {
        evict_expired_then_oldest_at(
            &self.memo,
            INTERACTIVE_MEMO_CAP,
            now,
            |record| record.recorded_at,
            |_| INTERACTIVE_FAILURE_TTL,
        );
        self.memo.insert(
            key,
            InteractiveRecord {
                state,
                recorded_at: now,
            },
        );
    }

    /// Writes `state` unless [`Self::invalidate_all`] ran since `generation` was read.
    pub(super) fn record(&self, key: &InteractiveFetchKey, state: RecordState, generation: u64) {
        self.insert(key.clone(), state, super::now());
        // Re-checked after the insert: an invalidation between a pre-check and the insert
        // would otherwise leave a stale record behind.
        if self.generation.load(Ordering::SeqCst) != generation {
            self.memo.remove(key);
        }
    }
}
