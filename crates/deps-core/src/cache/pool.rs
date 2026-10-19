//! Transport pool and registry-policy handling for `HttpCache`.

use super::CacheTier;
use super::HttpCache;
use super::transport::Transport;
use super::transport::pinned_digest;
use crate::net_policy::{TrustedPrefix, WorkspaceRegistryAccess};
#[cfg(test)]
use std::sync::atomic::Ordering;

impl HttpCache {
    /// Returns the transport scoped to `trusted_origin`, building and pooling one on first use.
    ///
    /// The `get` fast path (a shared read lock) serves the common case — a `trusted_origin`
    /// already pooled — without ever taking `trusted_clients`' write-capable `entry` lock;
    /// `entry().or_insert_with()` only runs on a miss, so two callers racing on the same new
    /// origin still only ever build and store one [`Transport`] for it, not one each.
    pub(super) fn transport_for_origin(&self, trusted_origin: &TrustedPrefix) -> Transport {
        let key = (trusted_origin.clone(), CacheTier::Baseline);
        if let Some(existing) = self.trusted_clients.get(&key) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(key)
            .or_insert_with(|| Transport::origin_pinned(trusted_origin))
            .clone()
    }

    /// Like [`Self::transport_for_origin`], but for an origin-pinned, connect-address-guarded
    /// [`CacheTier::Pinned`] transport (issue #561/#562) — building and pooling one on first
    /// use, keyed by `(trusted_origin, CacheTier::Pinned { .. })` so an authenticated and
    /// unauthenticated transport for the same origin share one pool entry; the credential state
    /// lives in the request's [`RequestAuth`](super::RequestAuth), not the transport.
    pub(super) fn transport_for_pinned(&self, trusted_origin: &TrustedPrefix) -> Transport {
        let snapshot = self.policy.snapshot();
        let digest = pinned_digest(trusted_origin, snapshot.level);
        let key = (trusted_origin.clone(), CacheTier::Pinned { digest });
        if let Some(existing) = self.trusted_clients.get(&key) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(key)
            .or_insert_with(|| {
                Transport::origin_pinned_guarded(trusted_origin, snapshot, self.policy.egress())
            })
            .clone()
    }

    /// Updates the policy governing [`Self::get_cached_workspace`], rebuilding the workspace
    /// transport field (and so its cache-key namespace and guard together) when
    /// `value` actually differs from the current setting — a no-op call does not rebuild, so a
    /// caller that re-applies an unchanged configuration does not pay for a fresh `Client` and
    /// its connection pool.
    ///
    /// Effective for every [`Self::get_cached_workspace`] call after this returns. Note this
    /// only gates *future* fetches: an `All -> PublicOnly`/`Off` tightening does not purge
    /// already-registered `deps-cargo` alternate-registry clients resolved under the looser
    /// policy (pre-existing, documented on [`crate::net_policy::RegistryAccessPolicy::set`]).
    ///
    /// Unlike that pre-existing gap, every `CacheTier::Pinned` cache entry (issue #561/#562)
    /// **is** purged on every actual policy transition, along with every pinned-tier pooled
    /// `Transport` — substantially narrowing the `All -> PublicOnly -> All` round-trip hole for
    /// credential-carrying entries specifically (NFR-004): re-namespacing alone (as the
    /// pre-existing workspace-tier digit prefix does) would leave an old-era authenticated
    /// body reachable once the policy round-trips back to a value whose digest happens to
    /// collide again. Not an absolute close: a fetch already in flight when the transition
    /// happens can still land its response and re-insert an old-era key after the purge —
    /// harmless (readable only under the era it was legitimately fetched in), just not
    /// prevented by this purge alone.
    pub fn set_registry_policy(&self, value: WorkspaceRegistryAccess) {
        if self.policy.get() == value {
            return;
        }
        self.policy.set(value);
        let rebuilt = Transport::workspace(&self.policy);
        #[expect(
            clippy::expect_used,
            reason = "poisoned only if another thread panicked while holding the lock — see \
                      the matching justification on get_cached_workspace_with_headers above"
        )]
        {
            *self
                .workspace
                .write()
                .expect("workspace transport lock poisoned") = rebuilt;
        }
        #[cfg(test)]
        self.workspace_rebuilds.fetch_add(1, Ordering::Relaxed);

        self.evict_entries_where(|key| key.starts_with(Self::PINNED_KEY_PREFIX));
        self.trusted_clients
            .retain(|(_, tier), _| !matches!(tier, CacheTier::Pinned { .. }));
    }
}
