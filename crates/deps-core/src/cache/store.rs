//! Entry storage, cache keys, byte accounting, and eviction for `HttpCache`.

use super::CacheTier;
use super::HttpCache;
use super::MAX_CACHE_BYTES;
use super::MAX_CACHE_ENTRIES;
use super::MAX_CACHEABLE_ENTRY_BYTES;
use super::auth::KeyAuth;
use super::response::CachedResponse;
use crate::cache_policy::CACHE_EVICTION_PERCENTAGE;
use bytes::Bytes;
use std::borrow::Cow;
use std::sync::atomic::Ordering;
use std::time::Instant;

impl HttpCache {
    /// Byte length of [`Self::BASELINE_AUTH_KEY_PREFIX`], the variant tag and the 16-digit id
    /// field.
    const BASELINE_AUTH_KEY_HEAD_LEN: usize = 1 + 1 + 16;

    /// Computes the cache-map key for `url` under `tier` — `Cow::Borrowed(url)` for an
    /// anonymous, unpartitioned [`CacheTier::Baseline`] request (allocation-free, and identical
    /// to every entry this cache wrote before this policy-tier split existed), or a prefixed
    /// owned key otherwise.
    ///
    /// [`CacheTier::WorkspaceDeclared`] folds in a policy digit so a policy tightening can never
    /// serve a body fetched under a looser policy (C5): the digit comes from `tier`'s own
    /// snapshot — the exact same value the paired [`Transport`]'s [`AddrGuard`] enforced for
    /// this request, taken together at [`Transport::workspace`] construction time — never a
    /// separate live `self.policy` read, which would open a read-skew window between the guard
    /// that let a fetch through and the key that fetch's body gets stored under.
    ///
    /// Callers must compute this once per request and thread the result through, never
    /// recompute mid-request — a policy flip between two recomputations would read and write
    /// under different keys for what should be one atomic operation.
    ///
    /// `auth` is folded in for [`CacheTier::Pinned`] and [`CacheTier::Baseline`], always with a
    /// one-char variant tag (`A` credentialed, `U` anonymous) ahead of the partition, so the
    /// same [`CredentialPartition`] used with and without a credential yields two entries. A
    /// partition is encoded as a tag (`0`/`1`) before a fixed-width hex field rather than a `0`
    /// sentinel: [`auth_digest`] is a non-cryptographic hash, so
    /// `Some(0)` is a legitimate digest (issue #1025). Every field is fixed width, so no tag or
    /// field can be confused with part of another field or `url`.
    pub(super) fn cache_key<'a>(
        &self,
        url: &'a str,
        tier: CacheTier,
        auth: KeyAuth,
    ) -> Cow<'a, str> {
        match tier {
            CacheTier::Baseline => match auth {
                KeyAuth::Anonymous(None) => Cow::Borrowed(url),
                KeyAuth::Anonymous(Some(partition)) => Cow::Owned(format!(
                    "{}U{:016x}{url}",
                    Self::BASELINE_AUTH_KEY_PREFIX,
                    partition.get()
                )),
                KeyAuth::Credential(partition) => Cow::Owned(format!(
                    "{}A{:016x}{url}",
                    Self::BASELINE_AUTH_KEY_PREFIX,
                    partition.get()
                )),
            },
            CacheTier::WorkspaceDeclared(snapshot) => {
                Cow::Owned(format!("{}{}{url}", Self::WS_KEY_PREFIX, snapshot.to_u8()))
            }
            CacheTier::Pinned { digest } => {
                let (partition_tag, id) = match auth {
                    KeyAuth::Anonymous(None) => ('0', 0),
                    KeyAuth::Anonymous(Some(p)) | KeyAuth::Credential(p) => ('1', p.get()),
                };
                let variant_tag = if auth.is_credentialed() { 'A' } else { 'U' };
                Cow::Owned(format!(
                    "{}{digest:016x}{partition_tag}{id:016x}{variant_tag}{url}",
                    Self::PINNED_KEY_PREFIX,
                ))
            }
        }
    }

    /// Inserts (or replaces) a cache entry, keeping [`Self::total_bytes`] in sync.
    ///
    /// `DashMap::insert` returns the replaced value, if any, so the byte
    /// delta is computed from a single insert rather than a separate
    /// lookup-then-insert (which would race with concurrent writers).
    ///
    /// A body larger than [`MAX_CACHEABLE_ENTRY_BYTES`] is not inserted at
    /// all (the caller already has it from the network response; only
    /// caching is skipped), and any stale entry previously cached for this
    /// URL is dropped rather than left to serve increasingly outdated data.
    pub(super) fn store_entry(&self, url: String, response: CachedResponse) {
        let new_len = response.body.len();

        if new_len > MAX_CACHEABLE_ENTRY_BYTES {
            if let Some((_, old)) = self.entries.remove(&url) {
                self.total_bytes
                    .fetch_sub(old.body.len(), Ordering::Relaxed);
            }
            return;
        }

        let old_len = self
            .entries
            .insert(url, response)
            .map_or(0, |old| old.body.len());
        self.total_bytes.fetch_add(new_len, Ordering::Relaxed);
        self.total_bytes.fetch_sub(old_len, Ordering::Relaxed);
    }

    /// Clears all cached entries.
    ///
    /// This removes all cached responses, forcing the next request for
    /// any URL to fetch fresh data from the network.
    pub fn clear(&self) {
        self.entries.clear();
        self.total_bytes.store(0, Ordering::Relaxed);
    }

    /// Drops every baseline-tier entry whose URL starts with `url_prefix`, returning how many.
    ///
    /// For a caller whose request credential or trust changed: drops bare-URL entries and
    /// `auth_id`-partitioned ones alike, as memory hygiene for bodies fetched under a state that
    /// no longer applies.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::cache::HttpCache;
    ///
    /// assert_eq!(HttpCache::new().evict_url_prefix("https://registry.example/api/"), 0);
    /// ```
    pub fn evict_url_prefix(&self, url_prefix: &str) -> usize {
        self.evict_entries_where(|key| {
            let url = if key.starts_with(Self::BASELINE_AUTH_KEY_PREFIX) {
                key.get(Self::BASELINE_AUTH_KEY_HEAD_LEN..)
            } else {
                Some(key)
            };
            url.is_some_and(|url| url.starts_with(url_prefix))
        })
    }

    /// Removes every entry whose key satisfies `matches`, keeping [`Self::total_bytes`] in sync;
    /// returns how many were removed.
    pub(super) fn evict_entries_where(&self, matches: impl Fn(&str) -> bool) -> usize {
        let mut freed_bytes = 0usize;
        let mut evicted = 0usize;
        self.entries.retain(|key, value| {
            let drop_entry = matches(key);
            if drop_entry {
                freed_bytes += value.body.len();
                evicted += 1;
            }
            !drop_entry
        });
        self.total_bytes.fetch_sub(freed_bytes, Ordering::Relaxed);
        evicted
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total bytes retained across all cached response bodies.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Evicts the oldest cache entries when either capacity limit is reached.
    ///
    /// When the entry count is at or over `MAX_CACHE_ENTRIES`, evicts at
    /// least `CACHE_EVICTION_PERCENTAGE`% of entries (by count). Note this
    /// is a *fix*, not a preserved behavior: the original count-only
    /// eviction built its bounded min-heap with an inverted comparison
    /// (`peek()` returns the oldest entry, but the old code treated it as
    /// the newest-of-the-oldest-so-far and only replaced it when a *newer*
    /// candidate came along that was still older than it — backwards), so
    /// it evicted roughly the first `target_removals` entries in DashMap
    /// hash-iteration order, not the oldest ones. This version evicts
    /// genuinely oldest-first.
    ///
    /// Independently, if the tracked byte total is over [`MAX_CACHE_BYTES`]
    /// — which can happen with far fewer than `MAX_CACHE_ENTRIES` entries if
    /// a few responses are large — eviction keeps removing the next-oldest
    /// entries until the byte budget is satisfied too. A cache that is over
    /// the byte budget but well under the entry-count threshold only evicts
    /// as many entries as the byte budget requires, not a fixed count-based
    /// batch.
    ///
    /// Builds a min-heap over all entry keys by `fetched_at` (O(N)), then
    /// pops the oldest one at a time (O(R log N) for R removals) — unlike a
    /// heap bounded to a fixed top-K, the removal count isn't known upfront
    /// since it depends on the byte budget as well as the count target.
    ///
    /// Every byte-count adjustment here is a relative `fetch_sub` applied to
    /// exactly the entry [`DashMap::remove`] actually returned — never a
    /// snapshot-then-absolute-`store` of a locally computed total. The
    /// latter would silently discard any [`Self::store_entry`] delta that
    /// lands between this method's start and its end (lost-update race), and
    /// under adversarial timing could even underflow `total_bytes` to
    /// `usize::MAX`, permanently wedging every future request into
    /// evicting the entire cache. Reading `total_bytes` fresh on every loop
    /// iteration (rather than maintaining a local mirror) keeps this
    /// correct under concurrent `evict_entries`/`store_entry` calls: two
    /// callers can race to remove the same key — the second `remove` simply
    /// returns `None` and is a no-op, not a double-subtraction.
    pub(super) fn evict_entries(&self) {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let count_target_removals = if self.entries.len() >= MAX_CACHE_ENTRIES {
            (MAX_CACHE_ENTRIES / CACHE_EVICTION_PERCENTAGE).max(1)
        } else {
            0
        };

        let mut oldest: BinaryHeap<Reverse<(Instant, String)>> = self
            .entries
            .iter()
            .map(|entry| Reverse((entry.value().fetched_at, entry.key().clone())))
            .collect();

        let mut removed = 0usize;

        while removed < count_target_removals
            || self.total_bytes.load(Ordering::Relaxed) > MAX_CACHE_BYTES
        {
            let Some(Reverse((_, url))) = oldest.pop() else {
                break;
            };
            if let Some((_, old)) = self.entries.remove(&url) {
                self.total_bytes
                    .fetch_sub(old.body.len(), Ordering::Relaxed);
            }
            removed += 1;
        }

        tracing::debug!(
            "evicted {removed} cache entries ({} bytes remaining)",
            self.total_bytes.load(Ordering::Relaxed)
        );
    }

    /// Benchmark-only helper: Direct cache lookup without network requests.
    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn get_for_bench(&self, url: &str) -> Option<Bytes> {
        self.entries.get(url).map(|entry| entry.body.clone())
    }

    /// Benchmark-only helper: Direct cache insertion.
    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn insert_for_bench(&self, url: String, response: CachedResponse) {
        self.store_entry(url, response);
    }
}
