//! Cached, pinned, workspace, and transport-only fetch paths of `HttpCache`.

use super::CacheTier;
use super::HttpCache;
use super::MAX_CACHE_BYTES;
use super::MAX_CACHE_ENTRIES;
use super::auth::KeyAuth;
use super::auth::RateLimitRevocation;
use super::auth::RequestAuth;
use super::auth::RequestHeader;
use super::auth::WireHeader;
use super::auth::accept_headers;
use super::auth::apply_request_headers;
use super::auth::wire_accept_headers;
use super::auth::wire_headers;
use super::body::BodyLimit;
use super::body::read_body_capped;
use super::errors::http_status_error;
use super::errors::send_error;
use super::guard::ensure_https;
use super::response::CachedResponse;
use super::response::CredentialPartition;
use super::response::ResponseValidators;
use super::response::RevalidationFailure;
use super::transport::Transport;
use crate::endpoint_contact::{note_request, note_response};
use crate::error::{DepsError, Result};
use crate::net_policy::TrustedPrefix;
use crate::redact::RedactedUrl;
use bytes::Bytes;
use reqwest::{RequestBuilder, Response, StatusCode, header};
use serde::Serialize;
use std::sync::atomic::Ordering;

/// Sends `request`, recording the arrival of any response for the interactive fetch gate's
/// breaker evidence (see [`crate::endpoint_contact`]).
async fn send_noted(request: RequestBuilder, url: &str) -> Result<Response> {
    // TODO(#1857): a stalled body after headers reads as Responded; track body progress if mirrors stall mid-stream
    let response = request.send().await.map_err(|e| send_error(url, e))?;
    note_response();
    Ok(response)
}

impl HttpCache {
    /// Tells the policy a request is about to leave over a guarded transport, so the startup
    /// proxy notice is shown only to setups that actually connect directly.
    fn note_guarded(&self, transport: &Transport) {
        match transport.tier {
            CacheTier::Baseline => {}
            CacheTier::WorkspaceDeclared(_) | CacheTier::Pinned { .. } => {
                self.policy.note_guarded_request();
            }
        }
    }

    /// The prefix marking a workspace-tier cache key, chosen as a control character that can
    /// never appear at the start of a URL string this module writes: production code paths
    /// only ever write keys derived from this function, which are either the bare URL (starting
    /// `https://`, or — test cfgs only — `http://` on loopback) or this prefix followed by a
    /// policy digit. No in-process caller other than [`Self::insert_for_bench`] (a
    /// `#[doc(hidden)]` test/bench helper that accepts a caller-chosen key) can write an
    /// arbitrary key, so a `Baseline`-tier and `WorkspaceDeclared`-tier entry can never collide
    /// in production use.
    pub(super) const WS_KEY_PREFIX: char = '\u{1}';

    /// The prefix marking a [`CacheTier::Pinned`]-tier cache key (issue #561/#562) — distinct
    /// from [`Self::WS_KEY_PREFIX`] so the two namespaces can never collide, chosen as another
    /// control character no URL string this module writes can start with.
    pub(super) const PINNED_KEY_PREFIX: char = '\u{2}';

    /// The prefix marking a [`CacheTier::Baseline`] key partitioned by a caller-supplied
    /// `auth_id`, followed by that id as 16 fixed-width hex digits and then the URL. Distinct
    /// from [`Self::WS_KEY_PREFIX`] and [`Self::PINNED_KEY_PREFIX`], so it can collide with
    /// neither them nor a bare-URL key.
    pub(super) const BASELINE_AUTH_KEY_PREFIX: char = '\u{3}';

    /// Retrieves data from URL with intelligent caching.
    ///
    /// On first request, fetches data from the network and caches it.
    /// On subsequent requests, performs a conditional GET request using
    /// cached ETag or Last-Modified headers. If the server responds with
    /// 304 Not Modified, returns the cached data. Otherwise, fetches and
    /// caches the new data.
    ///
    /// If the conditional request fails due to network errors, falls back
    /// to the cached data (stale-while-revalidate pattern).
    ///
    /// # Returns
    ///
    /// Returns `Bytes` containing the response body. Multiple calls for the
    /// same URL return cheap clones (reference counting) without copying data.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::RegistryError` if the initial fetch fails and no
    /// cached data exists, `DepsError::HttpStatus` if the server returns a
    /// non-2xx status on that initial fetch, or `DepsError::ResponseTooLarge`
    /// if the response body exceeds the configured size cap.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_core::cache::HttpCache;
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let data = cache.get_cached("https://example.com/api/data").await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached(&self, url: &str) -> Result<Bytes> {
        self.get_cached_with_headers(url, &[]).await
    }

    /// Returns the cached body for `url` without making any network request.
    ///
    /// Unlike `get_cached`'s own stale-while-revalidate fallback (the `Err` arm of
    /// `conditional_request_with_headers`'s match in `get_cached_via`), this
    /// is reachable even when a caller wraps `get_cached` in a short outer timeout: a
    /// hung conditional request that never resolves within that timeout gets its whole
    /// future cancelled, so `get_cached`'s internal fallback logic never runs and the
    /// caller sees a timeout instead of stale data. A caller in that position can call
    /// this instead — a synchronous map lookup, no I/O — to serve the last known-good
    /// body itself. Returns `None` if `url` has never been successfully cached.
    ///
    /// The returned body carries no age bound: this bypasses `get_cached`'s own
    /// freshness/revalidation logic entirely, so a caller that surfaces this body to
    /// the user (e.g. inserting it into a manifest edit) should treat it as
    /// arbitrarily stale, not just-expired.
    ///
    /// Reads the baseline (unprefixed) cache-key namespace only (see `Self::cache_key`, private) — a
    /// body fetched via [`Self::get_cached_workspace`] is never visible through this method.
    #[must_use]
    pub fn peek_cached(&self, url: &str) -> Option<Bytes> {
        self.entries.get(url).map(|r| r.body.clone())
    }

    /// Fetches a URL with additional request headers, using the cache.
    ///
    /// Works the same as `get_cached` but injects extra content-negotiation headers into every
    /// request. A credential never travels here: see [`Self::get_cached_trusted_origin`].
    ///
    /// # Errors
    ///
    /// Returns `DepsError::RegistryError` if the initial fetch fails and no
    /// cached data exists, `DepsError::HttpStatus` if the server returns a
    /// non-2xx status on that initial fetch, or `DepsError::ResponseTooLarge`
    /// if the response body exceeds the configured size cap.
    pub async fn get_cached_with_headers(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
    ) -> Result<Bytes> {
        let headers = wire_headers(extra_headers, &RequestAuth::ANONYMOUS);
        self.get_cached_via(
            url,
            &headers,
            &self.baseline,
            KeyAuth::ANONYMOUS,
            RevalidationFailure::ServeStale,
            RateLimitRevocation::default(),
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached`], but confines every redirect hop to `trusted_origin` via
    /// [`TrustedPrefix::permits`] (origin equality plus a path-segment-boundary prefix check,
    /// e.g. against `https://api.nuget.org/v3/registration5-gz/`), and optionally sends a
    /// credential.
    ///
    /// This is the only cached API besides [`Self::get_cached_pinned`] that accepts a credential:
    /// the transport stops following before a cross-origin hop would ever be sent, so a header
    /// carrying a token cannot be forwarded to an attacker-controlled host by a hostile
    /// redirect. `auth` splits the cache by credential state — a credentialed body is stored
    /// under its own partition and never served to an anonymous request, even after the token
    /// is removed. `accept` is an optional content-negotiating `Accept` value.
    ///
    /// The block only surfaces as an error on a cold cache: like [`Self::get_cached`]'s own
    /// stale-while-revalidate fallback, a warm entry for `url` still returns the last
    /// known-good body instead of propagating a blocked-redirect `HttpStatus` from a
    /// revalidation attempt. A 401/403 on a credentialed revalidation evicts the entry instead.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::cache::{CredentialHeader, HttpCache, RequestAuth};
    /// use deps_core::net_policy::TrustedPrefix;
    /// use deps_core::secret::{Redacted, bearer_auth_header};
    ///
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let prefix = TrustedPrefix::parse("https://index.mycorp.dev/").unwrap();
    /// let token = bearer_auth_header(&Redacted::new("secret-token".to_string()));
    /// let data = cache
    ///     .get_cached_trusted_origin(
    ///         "https://index.mycorp.dev/se/rd/serde",
    ///         &prefix,
    ///         RequestAuth::credential(CredentialHeader::Authorization(&token), &prefix),
    ///         None,
    ///     )
    ///     .await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached_trusted_origin(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
    ) -> Result<Bytes> {
        self.get_cached_trusted_origin_response(
            url,
            trusted_origin,
            auth,
            accept,
            RevalidationFailure::ServeStale,
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached_trusted_origin`], but returns the whole [`CachedResponse`] (body
    /// plus `ETag`, `Last-Modified` and `Link`) instead of the body alone. For a caller that
    /// must inspect response headers, e.g. to detect a paginated list.
    ///
    /// `on_revalidation_failure` decides whether a failed revalidation of a stored entry
    /// serves that entry or fails the call.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached_trusted_origin`], plus the revalidation error under
    /// [`RevalidationFailure::Fail`].
    pub async fn get_cached_trusted_origin_response(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
        on_revalidation_failure: RevalidationFailure,
    ) -> Result<CachedResponse> {
        auth.ensure_within(url, trusted_origin)?;
        let transport = self.transport_for_origin(trusted_origin);
        let headers = wire_headers(&accept_headers(accept), &auth);
        self.get_cached_via(
            url,
            &headers,
            &transport,
            auth.key_auth(),
            on_revalidation_failure,
            auth.rate_limit(),
        )
        .await
    }

    /// Reads the stored entry of a credentialed [`Self::get_cached_trusted_origin`] request
    /// without sending anything, for a caller that must answer from the cache while it cannot
    /// obtain the credential (the offline Keychain case).
    ///
    /// Never touches the network and never consults the offline switch, so it cannot send an
    /// unauthenticated request for a credentialed resource whatever the switch says.
    ///
    /// # Errors
    ///
    /// Returns [`DepsError::Offline`] when nothing is stored under `partition`.
    pub fn peek_credentialed_trusted_origin(
        &self,
        url: &str,
        partition: CredentialPartition,
    ) -> Result<CachedResponse> {
        let key = self.cache_key(url, CacheTier::Baseline, KeyAuth::Credential(partition));
        self.entries
            .get(key.as_ref())
            .map(|entry| entry.clone())
            .ok_or_else(|| DepsError::Offline {
                url: RedactedUrl::new(url),
            })
    }

    /// Like [`Self::get_cached_trusted_origin`], but for an origin-pinned,
    /// connect-address-guarded `CacheTier::Pinned` transport (issue #561/#562) instead of the
    /// baseline-guarded one — the only sanctioned way to send a credential to a
    /// workspace-declared host. `auth` partitions the cache exactly as it does there.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_pinned(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
    ) -> Result<Bytes> {
        self.get_cached_pinned_response(
            url,
            trusted_origin,
            auth,
            accept,
            RevalidationFailure::ServeStale,
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached_pinned`], but returns the whole [`CachedResponse`] (body plus
    /// `ETag`, `Last-Modified` and `Link`) instead of the body alone.
    ///
    /// `on_revalidation_failure` decides whether a failed revalidation of a stored entry
    /// serves that entry or fails the call.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`], plus the revalidation error under
    /// [`RevalidationFailure::Fail`].
    pub async fn get_cached_pinned_response(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
        on_revalidation_failure: RevalidationFailure,
    ) -> Result<CachedResponse> {
        auth.ensure_within(url, trusted_origin)?;
        let transport = self.transport_for_pinned(trusted_origin);
        let headers = wire_headers(&accept_headers(accept), &auth);
        self.get_cached_via(
            url,
            &headers,
            &transport,
            auth.key_auth(),
            on_revalidation_failure,
            auth.rate_limit(),
        )
        .await
    }

    /// Like [`Self::get_cached`], but for Cargo's workspace-declared-registry requests: routes
    /// through the workspace transport field, whose guard enforces the live
    /// [`crate::net_policy::WorkspaceRegistryAccess`] policy on both the resolved connect-time
    /// address (issue #455) and any redirect hop, and keys the entry under a
    /// policy-scoped namespace (see `Self::cache_key`, private) distinct from every other method on
    /// this cache.
    ///
    /// This gives the *resolved address* the same policy scrutiny `deps_cargo::config::RegistryIndex::new`
    /// already gives the declared URL string at parse time — it does **not**
    /// re-check the initial request URL itself: a caller passing an IP-literal `url` whose
    /// class the policy would reject connects anyway, since `hyper-util`'s connector parses an
    /// IP literal directly and never calls the configured resolver (see
    /// `BlockedAddrResolver`'s docs, private). `RegistryIndex::new` is the sole, by-design gate for
    /// that residual — every caller of this method already went through it.
    ///
    /// If an entry is already cached, a revalidation failure — including a guard rejection
    /// from a since-rebound or since-tightened-policy address — falls back to serving the
    /// cached body, logging only a `tracing::warn!` (pre-existing behavior, unrelated to
    /// this method). This is not a bypass — no new connection to the blocked address is
    /// made — but it means such a block is invisible to the caller whenever an entry already
    /// exists for that URL.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::HttpCache;
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let policy = Arc::new(RegistryAccessPolicy::default());
    /// let cache = HttpCache::with_policy(policy);
    /// let data = cache
    ///     .get_cached_workspace("https://index.mycorp.dev/se/rd/serde")
    ///     .await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached_workspace(&self, url: &str) -> Result<Bytes> {
        self.get_cached_workspace_with_headers(url, &[]).await
    }

    /// Like [`Self::get_cached_workspace`], but additionally forwards `extra_headers` to the
    /// underlying request — the headered form needed by a registry client whose
    /// workspace-declared fetch requires a non-default header (e.g. `deps-npm`'s abbreviated-
    /// packument `Accept` header for an alternate npm registry).
    ///
    /// # Security
    ///
    /// `extra_headers` are attached to the **initial** request only. The workspace transport
    /// pins by [`crate::net_policy::HostClass`], not origin — unlike
    /// [`Self::get_cached_trusted_origin`], which exists precisely to close this
    /// gap for a caller that needs it — so a cross-origin redirect hop to any other
    /// policy-permitted host is followed with `extra_headers` re-sent by reqwest's default
    /// redirect policy. **This method must never carry a credential.** Harmless for its
    /// current sole caller (a fixed `Accept` header), but directly load-bearing for any
    /// future auth-wiring work: reach for [`Self::get_cached_trusted_origin`]
    /// instead if a header ever needs to stay pinned to one origin.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_workspace_with_headers(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
    ) -> Result<Bytes> {
        #[expect(
            clippy::expect_used,
            reason = "poisoned only if another thread already panicked holding the lock — \
                      propagate via panic, matching RwLock's poisoning contract"
        )]
        let transport = self
            .workspace
            .read()
            .expect("workspace transport lock poisoned")
            .clone();
        self.get_cached_via(
            url,
            &wire_accept_headers(extra_headers),
            &transport,
            KeyAuth::ANONYMOUS,
            RevalidationFailure::ServeStale,
            RateLimitRevocation::default(),
        )
        .await
        .map(|response| response.body)
    }

    /// The credential state in `auth` is meaningful only under [`CacheTier::Pinned`] and
    /// [`CacheTier::Baseline`] — every other tier ignores it (see [`Self::cache_key`]'s docs).
    #[tracing::instrument(
        name = "get_cached_via",
        skip(self, extra_headers, transport, auth, on_revalidation_failure, rate_limit),
        fields(url = %RedactedUrl::new(url), cache = tracing::field::Empty)
    )]
    pub(super) async fn get_cached_via(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        auth: KeyAuth,
        on_revalidation_failure: RevalidationFailure,
        rate_limit: RateLimitRevocation,
    ) -> Result<CachedResponse> {
        if self.entries.len() >= MAX_CACHE_ENTRIES
            || self.total_bytes.load(Ordering::Relaxed) >= MAX_CACHE_BYTES
        {
            self.evict_entries();
        }

        let offline = self.is_offline();
        // `offline` forces `cache_enabled` true (S1 fix): otherwise `cache.enabled: false`
        // would leave nothing to serve offline for a URL fetched while caching was disabled.
        // See `Self::set_offline`'s docs.
        let cache_enabled = self.cache_enabled.load(Ordering::Relaxed) || offline;

        // Computed once and threaded through every call — recomputing mid-request could read
        // and write under different keys (see `Self::cache_key`'s docs).
        let cache_key = self.cache_key(url, transport.tier, auth);

        if !cache_enabled {
            // Explicit, not `Empty`: an empty `cache` field would be indistinguishable from
            // broken instrumentation (#756 S3) on a path that's neither a hit nor a miss.
            tracing::Span::current().record("cache", "disabled");
            return self
                .transport_only_response_via(url, extra_headers, BodyLimit::DEFAULT, transport)
                .await;
        }

        // Clone+drop the Ref immediately: holding it across `.await` can deadlock a concurrent
        // task needing write access to the same shard.
        if let Some(cached) = self.entries.get(cache_key.as_ref()).map(|r| r.clone()) {
            if offline {
                // Skips the conditional-request attempt: `ensure_online` would block it and
                // fall back to this same body anyway, just with a spurious warn + wasted
                // allocation. The only branch below that is a genuine zero-network "hit"
                // (#756 S3); every other branch still issued a request.
                tracing::Span::current().record("cache", "hit");
                return Ok(cached);
            }
            match self
                .conditional_request_with_headers(
                    url,
                    &cached,
                    extra_headers,
                    transport,
                    &cache_key,
                )
                .await
            {
                // 304: a round trip happened but no body was re-transferred — distinct from
                // `hit` (no request) and `refreshed` (full re-fetch).
                Ok(None) => {
                    tracing::Span::current().record("cache", "revalidated");
                    return Ok(cached);
                }
                // Stale entry cost a full re-fetch, same as a miss — must not report as a hit.
                Ok(Some(refreshed)) => {
                    tracing::Span::current().record("cache", "refreshed");
                    return Ok(refreshed);
                }
                Err(e) => {
                    debug_assert!(
                        !matches!(
                            &e,
                            DepsError::RateLimited {
                                source_status: None,
                                ..
                            }
                        ),
                        "a RateLimited reaching this eviction guard must always carry \
                         source_status — only http_status_error's confirmed-evidence branch \
                         produces RateLimited here; None would silently bypass FR-015/NFR-004 \
                         eviction on a genuine 401/403 credential-revocation signal"
                    );
                    // FR-015/NFR-004: a 401/403 revalidation of a *credentialed* entry
                    // must evict rather than serve the possibly-revoked
                    // credential's last-known-good body — an anonymous request keeps the
                    // stale-while-revalidate fallback unchanged.
                    //
                    // On a pinned tier, `RateLimited { source_status: Some(401 | 403), .. }`
                    // evicts too (see `RateLimitRevocation::revokes_credential`)
                    // (#1295 critic C1): `e` is always this match's own
                    // `conditional_request_with_headers`'s `Err`, whose only source of that
                    // variant is `http_status_error`'s confirmed-evidence branch — without this
                    // arm, a confirmed-evidence 403 would silently bypass eviction and keep
                    // serving the possibly-revoked credential's stale body. Deliberately
                    // narrowed to `source_status` 401/403 only, not a bare `RateLimited { .. }`
                    // (critic N1 regression fix): `confirmed_rate_limit_exhaustion` also
                    // classifies a 429 this way, but a 429 is mere throttling, not a
                    // credential-revocation signal — NFR-004's scope is "401/403", and evicting
                    // on 429 would drop a still-good cached body the client can no longer
                    // re-fetch until the throttle clears, purely because of a signal unrelated
                    // to the credential's validity.
                    if auth.is_credentialed() && rate_limit.revokes_credential(&e) {
                        if let Some((_, old)) = self.entries.remove(cache_key.as_ref()) {
                            self.total_bytes
                                .fetch_sub(old.body.len(), Ordering::Relaxed);
                        }
                        tracing::Span::current().record("cache", "evicted");
                        // #756 round 2 S1: never interpolate `e` — its `Display`/`Debug` embed
                        // the raw unredacted `url`, defeating this span's `RedactedUrl` field.
                        // `safe_tracing_summary` extracts only the safe status+cause instead.
                        let (status, cause) = e.safe_tracing_summary();
                        tracing::warn!(
                            status = ?status,
                            cause,
                            "evicting authenticated cache entry after revalidation failure"
                        );
                        return Err(e);
                    }
                    if on_revalidation_failure == RevalidationFailure::Fail {
                        tracing::Span::current().record("cache", "revalidation-failed");
                        return Err(e);
                    }
                    tracing::Span::current().record("cache", "stale-fallback");
                    // Same rationale as above: no `e` interpolation.
                    let (status, cause) = e.safe_tracing_summary();
                    tracing::warn!(
                        status = ?status,
                        cause,
                        "conditional request failed, using cache"
                    );
                    return Ok(cached);
                }
            }
        }

        tracing::Span::current().record("cache", "miss");
        self.fetch_and_store_with_headers(url, extra_headers, transport, &cache_key)
            .await
    }

    /// Performs conditional HTTP request using cached validation headers.
    ///
    /// Sends `If-None-Match` (ETag) and/or `If-Modified-Since` headers
    /// to check if the cached content is still valid.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(CachedResponse))` - Server returned 200 OK with new content
    /// - `Ok(None)` - Server returned 304 Not Modified (cache is valid)
    /// - `Err(_)` - Network or HTTP error occurred
    async fn conditional_request_with_headers(
        &self,
        url: &str,
        cached: &CachedResponse,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        cache_key: &str,
    ) -> Result<Option<CachedResponse>> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        note_request();
        self.note_guarded(transport);
        transport.preflight(url).await?;
        let mut request = apply_request_headers(transport.client.get(url), extra_headers);
        if let Some(etag) = &cached.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &cached.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
        }

        let response = send_noted(request, url).await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;
        let fresh = validators.into_response(body);
        self.store_entry(cache_key.to_string(), fresh.clone());

        Ok(Some(fresh))
    }

    /// Fetches a fresh response from the network and stores it in the cache.
    ///
    /// This method bypasses the cache and always makes a network request.
    /// The response is stored with its ETag and Last-Modified headers for
    /// future conditional requests.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx status code
    /// (or `DepsError::RateLimited` when that status is a 403 with confirmed
    /// `X-RateLimit-Remaining: 0` evidence — see [`http_status_error`], #1295),
    /// `DepsError::RegistryError` if the network request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub(super) async fn fetch_and_store_with_headers(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        cache_key: &str,
    ) -> Result<CachedResponse> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        note_request();
        self.note_guarded(transport);
        transport.preflight(url).await?;
        // #756 security follow-up (S-A): `RedactedUrl`, not the raw `url` — this is the
        // direct callee of the now-hardened `get_cached_via`, and at `debug`
        // level, which is this project's own continuous-improvement convention
        // (`RUST_LOG=debug`).
        tracing::debug!(
            extra_headers = extra_headers.len(),
            "fetching fresh: {}",
            RedactedUrl::new(url)
        );

        let request = apply_request_headers(transport.client.get(url), extra_headers);

        let response = send_noted(request, url).await?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;
        let fresh = validators.into_response(body);
        self.store_entry(cache_key.to_string(), fresh.clone());

        Ok(fresh)
    }

    /// POSTs `body` as JSON and returns the response body.
    ///
    /// Deliberately does not cache: the OSV batch endpoint is a POST with a
    /// request-body-dependent response and sends no `ETag`/`Last-Modified`
    /// validators, so entry-map caching would be meaningless here — every
    /// call reuses the client, HTTPS enforcement, size cap, and timeout
    /// (via `read_body_capped`) without touching the entry map or
    /// [`Self::total_bytes`].
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn post_json<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<Bytes> {
        self.post_json_via(url, body, BodyLimit::DEFAULT, &self.baseline)
            .await
    }

    /// Same as [`Self::post_json`], but additionally takes an explicit [`BodyLimit`]
    /// (rather than the hardcoded [`BodyLimit::DEFAULT`]) and confines every redirect hop to
    /// `trusted_origin` via [`crate::net_policy::is_trusted_prefix`] — the same guarantee
    /// [`Self::get_transport_only_with_headers_limited_trusted_origin`] gives the GET path.
    ///
    /// [`Self::post_json`] itself has neither of these: it sends through
    /// `Self::baseline`'s client (the generic, non-origin-pinned redirect policy) and
    /// always caps the response at [`BodyLimit::DEFAULT`] (32 MiB) regardless of how much
    /// smaller a caller's own payloads actually are — a gap for a caller (deps.dev's GOSSIP
    /// batch endpoint) whose response is expected to be a few KB and whose request body
    /// carries every declared dependency's name, where an unconfined redirect is a bigger
    /// concern than for `post_json`'s existing callers.
    ///
    /// # Errors
    ///
    /// Same as [`Self::post_json`].
    pub async fn post_json_limited_trusted_origin<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
        limit: BodyLimit,
        trusted_origin: &TrustedPrefix,
    ) -> Result<Bytes> {
        let transport = self.transport_for_origin(trusted_origin);
        self.post_json_via(url, body, limit, &transport).await
    }

    /// Shared POST body for [`Self::post_json`] and [`Self::post_json_limited_trusted_origin`]
    /// — mirrors [`Self::transport_only_via`]'s role on the GET path exactly: both public POST
    /// methods differ only in which `client` (origin-pinned or not) and [`BodyLimit`] they pass
    /// in, so this is the single place that sends the request, checks the status, and reads the
    /// capped body.
    ///
    /// # Errors
    ///
    /// Same as [`Self::post_json`].
    #[tracing::instrument(
        skip(self, body, transport),
        fields(url = %RedactedUrl::new(url))
    )]
    async fn post_json_via<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<Bytes> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        note_request();
        self.note_guarded(transport);
        transport.preflight(url).await?;

        let response = send_noted(transport.client.post(url).json(body), url).await?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        read_body_capped(url, response, limit).await
    }

    /// GETs `url` and returns the response body, bypassing the entry-map
    /// cache entirely — reuses the client, HTTPS enforcement, size cap, and
    /// timeout, exactly like [`Self::post_json`], but for a plain GET.
    ///
    /// For a caller whose own values are already cached elsewhere (e.g.
    /// `OsvClient`'s record cache, validated by a `modified` timestamp
    /// rather than `ETag`/`Last-Modified`): reusing [`Self::get_cached`]
    /// there would double-cache every fetched record in *this* cache's byte
    /// budget too, competing with registry responses for it even though
    /// nothing here ever reads that cached copy back.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn get_transport_only(&self, url: &str) -> Result<Bytes> {
        self.get_transport_only_with_headers(url, &[]).await
    }

    /// Same as [`Self::get_transport_only`], but injects extra request headers (e.g. a
    /// content-negotiating `Accept`) — mirrors how [`Self::get_cached_with_headers`] relates
    /// to [`Self::get_cached`].
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn get_transport_only_with_headers(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
    ) -> Result<Bytes> {
        self.get_transport_only_with_headers_limited(url, extra_headers, BodyLimit::DEFAULT)
            .await
    }

    /// Same as [`Self::get_transport_only_with_headers`], but takes an explicit
    /// [`BodyLimit`] instead of the [`BodyLimit::DEFAULT`] (`MAX_RESPONSE_BYTES`) cap.
    ///
    /// For a caller whose response is legitimately larger than every other registry
    /// payload — e.g. `deps-pypi`'s full Simple API project index — without weakening
    /// the cap every other caller of this cache relies on. `BodyLimit` clamps at
    /// construction, so this can never be widened past `ABSOLUTE_MAX_RESPONSE_BYTES`
    /// regardless of what the caller passes in.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_transport_only_with_headers`].
    pub async fn get_transport_only_with_headers_limited(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
    ) -> Result<Bytes> {
        self.transport_only_via(url, extra_headers, limit, &self.baseline)
            .await
    }

    /// Same as [`Self::get_transport_only_with_headers_limited`], but additionally
    /// stops any redirect hop that does not match `trusted_origin` via
    /// [`crate::net_policy::is_trusted_prefix`]
    /// (see [`Self::get_cached_trusted_origin`], which applies the identical policy
    /// to the entry-cached path). For a caller carrying a materially larger
    /// [`BodyLimit`] than [`BodyLimit::DEFAULT`] — the bigger the budget, the more
    /// worth pinning the origin an arbitrary cross-host redirect could point it at.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_transport_only_with_headers_limited`].
    pub async fn get_transport_only_with_headers_limited_trusted_origin(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
        trusted_origin: &TrustedPrefix,
    ) -> Result<Bytes> {
        let transport = self.transport_for_origin(trusted_origin);
        self.transport_only_via(url, extra_headers, limit, &transport)
            .await
    }

    /// Note: "transport" here means "bypasses the entry-map cache" (see this method's
    /// callers' docs) — a different axis from the [`Transport`] type, which pairs a `Client`
    /// with its [`CacheTier`]. The name predates that type and is kept as-is to avoid
    /// churning every `get_transport_only*` call site for a naming collision that causes no
    /// actual ambiguity at the call sites themselves.
    #[tracing::instrument(
        skip(self, extra_headers, limit, transport),
        fields(url = %RedactedUrl::new(url))
    )]
    async fn transport_only_via(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<Bytes> {
        self.transport_only_response_via(url, &wire_accept_headers(extra_headers), limit, transport)
            .await
            .map(|response| response.body)
    }

    /// [`Self::transport_only_via`] that also keeps the response validators and `Link` header.
    async fn transport_only_response_via(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<CachedResponse> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        note_request();
        self.note_guarded(transport);
        transport.preflight(url).await?;

        let request = apply_request_headers(transport.client.get(url), extra_headers);

        let response = send_noted(request, url).await?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, limit).await?;
        Ok(validators.into_response(body))
    }
}
