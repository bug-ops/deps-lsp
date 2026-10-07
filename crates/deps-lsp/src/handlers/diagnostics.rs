//! Diagnostics handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::config_epoch::ConfigEpoch;
use crate::document::{
    DocStamp, PrefetchVisibility, PublishTicket, ServerState, ensure_document_loaded,
};
use deps_core::policy_config::{GossipChecks, OsvChecks, TyposquatChecks};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Diagnostic, Uri};

/// Floor under the dependency/concurrency-scaled ceiling (issue #632 critic S1): keeps a
/// small `fetch_timeout_secs` or a small manifest from producing an unrealistically tight
/// ceiling.
pub(crate) const MIN_LOADING_CEILING: Duration = Duration::from_secs(120);

/// Ceiling on the dependency/concurrency-scaled result (issue #636 critic S1): without this,
/// a large manifest combined with a low `max_concurrent_fetches` (both user-configurable, down
/// to `C=1`) produces an unbounded ceiling — e.g. `C=1`, `T=300s`, 300 dependencies scales to a
/// ~50-hour ceiling. The ceiling is the *only* mechanism that recovers a document from a
/// background fetch task that hangs without panicking (a panic is already handled by
/// `spawn_background_task`'s supervisor), so an unbounded value reinstates issue #632's
/// stuck-forever shape for exactly the manifests this fix targets. 30 minutes is a deliberate
/// prefer-recovery-over-waiting tradeoff: past this point, forcing `Failed` and falling
/// through to cached data is judged better than continuing to wait, even though a legitimate
/// (very large manifest, very low concurrency) fetch could still be in flight — issue #636
/// itself notes that undershooting the ceiling is low-impact and self-corrects once the
/// background fetch completes.
pub(crate) const MAX_LOADING_CEILING: Duration = Duration::from_mins(30);

/// Computes how long a document may stay in [`deps_core::LoadingState::Loading`] before
/// diagnostics generation gives up waiting and forces it to `Failed`, falling through to
/// whatever cache is already available (issue #632).
///
/// Models the actual worst case: a single package fetch can take up to roughly
/// `2 * fetch_timeout_secs` (the primary registry call plus its own timeout-bounded
/// `get_latest_matching_from` fallback — see `document::fetch::fetch_and_classify_package`),
/// run `max_concurrent_fetches`-wide via `buffer_unordered` — so `dep_count` dependencies
/// take roughly `ceil(dep_count / max_concurrent_fetches) * 2 * fetch_timeout_secs` even when
/// nothing is wrong (issue #636: a fixed multiplier under-counted this for a low
/// `max_concurrent_fetches` combined with a non-trivial dependency count — e.g. `C=1`,
/// `T=10s`, 10 dependencies legitimately needs 200s). The result is clamped between
/// [`MIN_LOADING_CEILING`] and [`MAX_LOADING_CEILING`], so this exists to recover from a
/// background task that never reaches `set_loaded`/`set_failed` (a hang the per-package
/// timeout alone doesn't cover, e.g. a `DashMap` deadlock), not to model the exact fetch
/// duration.
///
/// `dep_count` is an *upper bound* on the number of packages in the in-flight fetch, not
/// necessarily its exact size: the two call sites that actually drive this check
/// (`handle_diagnostics` and the lock-file-change refresh in `server.rs`) don't know the
/// current fetch's real batch size, so they deliberately over-approximate using the
/// document's full manifest dependency count — a document left `Loading` by e.g. a 1-dependency
/// incremental fetch on a 300-dependency manifest gets a 300-dependency ceiling. This is
/// conservative (a looser ceiling), never unsafe.
pub(crate) fn loading_ceiling(
    fetch_timeout_secs: u64,
    dep_count: usize,
    max_concurrent_fetches: usize,
) -> Duration {
    let batches = dep_count.div_ceil(max_concurrent_fetches.max(1));
    let worst_case_secs = u64::try_from(batches)
        .unwrap_or(u64::MAX)
        .saturating_mul(2)
        .saturating_mul(fetch_timeout_secs);
    Duration::from_secs(worst_case_secs).clamp(MIN_LOADING_CEILING, MAX_LOADING_CEILING)
}

/// Returns the number of dependencies declared in `uri`'s currently loaded parse result, or
/// `0` if the document isn't loaded or has no parse result yet.
///
/// Shared by every call site that needs [`loading_ceiling`]'s conservative, manifest-wide
/// `dep_count` upper bound (see that function's doc comment) rather than a specific fetch
/// batch's real size — currently [`handle_diagnostics`] and the lock-file-change diagnostics
/// refresh in `server.rs`.
pub(crate) fn document_dependency_count(state: &ServerState, uri: &Uri) -> usize {
    state
        .with_document(uri, |doc| {
            doc.parse_result().map_or(0, |p| p.dependencies().len())
        })
        .unwrap_or(0)
}

/// Config values needed to generate and publish diagnostics, snapshotted from `DepsConfig`
/// once per generation so the caller never has to hold the config lock itself (mirrors
/// `document::lifecycle::ChangeTaskConfig`'s own snapshot-once rationale). Shared by every
/// diagnostics call site (issue #1399): the push-path sites publish through
/// [`publish_document_diagnostics`], and the pull-diagnostics path ([`handle_diagnostics`])
/// builds one directly (overriding only `severities`, see that function's doc).
///
/// Built only by [`Self::capture`] (#1799), which records the [`ConfigEpoch`] and the
/// [`DocStamp`] the generation reads, so [`publish_document_diagnostics`] can tell whether a
/// config apply or a document change overlapped it.
///
/// Every config-derived gate a generation consults (typosquat, GOSSIP, license policy,
/// vulnerability visibility) is copied out of the same `DepsConfig` read guard (#1815), so a
/// generation reads exactly one config by construction; the `ServerState` mirrors of these
/// gates serve only the prefetch spawners.
#[derive(Debug, Clone)]
pub(crate) struct DiagnosticsSnapshot {
    pub(crate) freshness: deps_core::FreshnessSettings,
    severities: deps_core::DiagnosticSeverities,
    network: deps_core::NetworkMode,
    typosquat: TyposquatChecks,
    gossip: GossipChecks,
    license_policy: Arc<deps_core::LicensePolicy>,
    pub(crate) fetch_timeout_secs: u64,
    pub(crate) max_concurrent_fetches: usize,
    epoch: ConfigEpoch,
    stamp: Option<DocStamp>,
}

impl DiagnosticsSnapshot {
    /// Snapshots the live [`DepsConfig`] for `uri`, first waiting for any in-flight config
    /// apply so the epoch recorded here is a settled one (#1799).
    pub(crate) async fn capture(
        state: &ServerState,
        uri: &Uri,
        config: &RwLock<DepsConfig>,
    ) -> Self {
        let epoch = state.settled_config_epoch().await;
        let stamp = state.document_stamp(uri);
        let config = config.read().await;
        Self {
            freshness: config.policy.freshness.to_freshness(),
            severities: config.policy.diagnostics.to_severities(),
            network: config.policy.network.mode(),
            typosquat: config.policy.typosquat_checks(),
            gossip: config.policy.gossip_checks(),
            license_policy: Arc::new(config.policy.license_policy.to_policy()),
            fetch_timeout_secs: config.policy.cache.fetch_timeout_secs,
            max_concurrent_fetches: config.policy.cache.max_concurrent_fetches,
            epoch,
            stamp,
        }
    }

    /// Whether neither a config apply nor a change to `uri`'s document state happened since
    /// this snapshot was captured.
    fn is_current(&self, state: &ServerState, uri: &Uri) -> bool {
        state.config_epoch() == self.epoch && state.document_stamp(uri) == self.stamp
    }

    /// Replaces the severities, for tests.
    ///
    /// [`Self::osv_checks`] is computed from the severities, so it follows the override.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn with_severities(
        mut self,
        severities: deps_core::DiagnosticSeverities,
    ) -> Self {
        self.severities = severities;
        self
    }

    /// The OSV gate for this snapshot's severities and network mode.
    pub(crate) const fn osv_checks(&self) -> OsvChecks {
        OsvChecks::resolve(self.severities.vulnerabilities_enabled, self.network)
    }

    /// Whether already-fetched advisories render, from `vulnerabilities_enabled` alone
    /// (#1819): offline keeps showing cached advisories, unlike [`Self::osv_checks`].
    const fn vulnerability_visibility(&self) -> PrefetchVisibility {
        PrefetchVisibility::from_enabled(self.severities.vulnerabilities_enabled)
    }

    /// Replaces the typosquat gate, for tests.
    #[cfg(all(test, feature = "npm"))]
    #[must_use]
    pub(crate) const fn with_typosquat_checks(mut self, checks: TyposquatChecks) -> Self {
        self.typosquat = checks;
        self
    }

    /// Replaces the license policy, for tests.
    #[cfg(all(test, feature = "cargo"))]
    #[must_use]
    pub(crate) fn with_license_policy(mut self, policy: deps_core::LicensePolicy) -> Self {
        self.license_policy = Arc::new(policy);
        self
    }

    /// Builds a snapshot from explicit values (inactive typosquat/GOSSIP gates, empty license
    /// policy), for tests that drive diagnostics generation.
    #[cfg(all(test, any(feature = "cargo", feature = "npm")))]
    pub(crate) fn for_test(
        freshness: deps_core::FreshnessSettings,
        severities: deps_core::DiagnosticSeverities,
        network: deps_core::NetworkMode,
    ) -> Self {
        let inactive = deps_core::policy_config::PolicyConfig::default();
        Self {
            freshness,
            severities,
            network,
            typosquat: inactive.typosquat_checks(),
            gossip: inactive.gossip_checks(),
            license_policy: Arc::new(deps_core::LicensePolicy::default()),
            fetch_timeout_secs: 0,
            max_concurrent_fetches: 1,
            epoch: ConfigEpoch::default(),
            stamp: None,
        }
    }
}

/// How many times [`publish_document_diagnostics`] regenerates after an overlapping config
/// apply or document change before it publishes what it has, bounding starvation under a
/// continuous burst.
const MAX_PUBLISH_ATTEMPTS: u32 = 8;

/// Generates diagnostics for `uri` under the live `config` and publishes them to `client` —
/// the one publish path for every push-path diagnostics refresh (issue #1399, #1799).
///
/// A generation that overlapped a config apply ([`ServerState::config_epoch`]) or a change to
/// the document's own state ([`DocStamp`]) is regenerated rather than published or dropped:
/// publishing it would let an older config land after a newer one, and dropping it would leave
/// a document whose own fetch-completion publish was the only one pending with no diagnostics.
/// The currency check, the claim on the document's publish order and the send all happen under
/// one config read guard, so no config apply can slip in between them.
///
/// `dep_count` varies per call site: a manifest-wide count for a fresh open or a lockfile-change
/// refresh, or a fetch-batch size for a change-path refresh that only fetched a subset of
/// dependencies — see [`loading_ceiling`]'s doc for why this matters.
pub(crate) async fn publish_document_diagnostics(
    state: &Arc<ServerState>,
    client: &Client,
    uri: &Uri,
    config: &RwLock<DepsConfig>,
    dep_count: usize,
) {
    publish_with(state, client, uri, config, |snapshot| async move {
        let ceiling = loading_ceiling(
            snapshot.fetch_timeout_secs,
            dep_count,
            snapshot.max_concurrent_fetches,
        );
        generate_diagnostics_internal(Arc::clone(state), uri, &snapshot, ceiling).await
    })
    .await;
}

/// [`publish_document_diagnostics`] over an injectable generator, so the retry and ordering
/// rules are testable without a registry-backed document.
async fn publish_with<F, Fut>(
    state: &ServerState,
    client: &Client,
    uri: &Uri,
    config: &RwLock<DepsConfig>,
    generate: F,
) where
    F: FnMut(DiagnosticsSnapshot) -> Fut,
    Fut: std::future::Future<Output = Vec<Diagnostic>>,
{
    let generated = generate_until_current(state, uri, config, generate).await;
    if !generated.current {
        tracing::debug!(
            ?uri,
            "diagnostics kept racing config/document changes; publishing the latest \
             generation and asking for a republish"
        );
        state.request_republish();
    }
    // A regeneration that meets a document another task just set to `Loading` returns an empty
    // set; publishing it would blank diagnostics the loading document's own fetch task is about
    // to replace.
    if generated.retried
        && state
            .with_document(uri, |doc| {
                doc.loading_state() == deps_core::LoadingState::Loading
            })
            .unwrap_or(false)
    {
        return;
    }
    if !state.claim_publish(uri, generated.ticket) {
        tracing::debug!(?uri, "a later diagnostics generation already published");
        return;
    }
    // The config read guard is still held here so no apply can start before the send is queued.
    // A client that stops draining must not wedge config applies (and, behind a queued writer,
    // every other config reader), so the send is bounded.
    let sent = send_bounded(
        client.publish_diagnostics(uri.clone(), generated.value, None),
        PUBLISH_SEND_TIMEOUT,
    )
    .await;
    if !sent {
        tracing::warn!(
            ?uri,
            "client did not accept publishDiagnostics in time; dropped it"
        );
    }
}

/// Longest a diagnostics publish may hold the config read guard waiting on the client.
const PUBLISH_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs `send`, giving up after `limit`; `true` when it completed.
async fn send_bounded(send: impl std::future::Future<Output = ()>, limit: Duration) -> bool {
    tokio::time::timeout(limit, send).await.is_ok()
}

/// The outcome of [`generate_until_current`]. Holds the config read guard the currency check
/// ran under, so the caller sends before any config apply can start.
struct Generated<'a, T> {
    value: T,
    /// Whether `value` was generated from state no config apply or document change overtook;
    /// `false` only after [`MAX_PUBLISH_ATTEMPTS`] consecutive overlaps.
    current: bool,
    /// Whether this is not the first generation attempt.
    retried: bool,
    ticket: PublishTicket,
    _config: tokio::sync::RwLockReadGuard<'a, DepsConfig>,
}

/// Runs `generate` on a fresh [`DiagnosticsSnapshot`] until one run finishes without a config
/// apply or document change having overtaken it, or [`MAX_PUBLISH_ATTEMPTS`] runs were spent.
///
/// The ticket is drawn immediately before `generate` is first polled, with no yield before the
/// document's signals are read, so ticket order is signal-read order.
async fn generate_until_current<'a, T, F, Fut>(
    state: &ServerState,
    uri: &Uri,
    config: &'a RwLock<DepsConfig>,
    mut generate: F,
) -> Generated<'a, T>
where
    F: FnMut(DiagnosticsSnapshot) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let mut attempt = 1;
    loop {
        let snapshot = DiagnosticsSnapshot::capture(state, uri, config).await;
        let ticket = state.next_publish_ticket();
        let value = generate(snapshot.clone()).await;
        let guard = config.read().await;
        let current = snapshot.is_current(state, uri);
        if current || attempt == MAX_PUBLISH_ATTEMPTS {
            return Generated {
                value,
                current,
                retried: attempt > 1,
                ticket,
                _config: guard,
            };
        }
        attempt += 1;
    }
}

/// Handles diagnostic requests using trait-based delegation.
#[tracing::instrument(
    skip(state, client, full_config),
    fields(uri = ?uri, ecosystem = tracing::field::Empty)
)]
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Uri,
    client: Client,
    full_config: Arc<RwLock<DepsConfig>>,
) -> Vec<Diagnostic> {
    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&full_config)).await {
        tracing::warn!("Could not load document for diagnostics: {:?}", uri);
        return vec![];
    }

    // Cheap DashMap shard lookup, not a registry fetch — records `ecosystem` once known
    // rather than force-resolving it early, like the other handlers (#756).
    if let Some(ecosystem_id) = state.with_document(uri, |doc| doc.ecosystem) {
        tracing::Span::current().record("ecosystem", ecosystem_id.id());
    }

    // Captured once, so severities, gates and the license policy all come from one config
    // read (#1815); the pull path has no separately captured severities to mix in.
    let snapshot = DiagnosticsSnapshot::capture(&state, uri, &full_config).await;

    let dep_count = document_dependency_count(&state, uri);
    let ceiling = loading_ceiling(
        snapshot.fetch_timeout_secs,
        dep_count,
        snapshot.max_concurrent_fetches,
    );

    generate_diagnostics_internal(state, uri, &snapshot, ceiling).await
}

/// Internal diagnostic generation without cold start support.
///
/// This is used when we know the document is already loaded (e.g., from background tasks).
/// Shared by every reachable path to diagnostics generation — the `textDocument/diagnostic`
/// pull path ([`handle_diagnostics`]) and every push-path background refresh
/// (`document::lifecycle`'s fetch-completion refreshes, `server.rs`'s lockfile-change
/// refresh) — so all of them evaluate the license policy identically (issue #660/#661
/// critic C1). Earlier revisions split this into a policy-blind `generate_diagnostics_internal`
/// plus a `generate_diagnostics_with_license_policy` variant only `handle_diagnostics`
/// called, threading `Option<&LicensePolicy>` as a caller-supplied parameter — that design
/// followed a false analogy to [`deps_core::VersionData::trust`]'s hover-only scope: `trust`
/// is safe hover-only because hover has exactly one producer per request, but diagnostics
/// has multiple producers all replacing the same client-visible `publish_diagnostics` set,
/// so a caller-scoped policy meant the license diagnostic flickered in and out on every
/// edit and was invisible to push-only clients. The policy now travels in the
/// [`DiagnosticsSnapshot`] (#1815), captured with every other gate from one config read, so no
/// call site needs a signature change.
pub(crate) async fn generate_diagnostics_internal(
    state: Arc<ServerState>,
    uri: &Uri,
    snapshot: &DiagnosticsSnapshot,
    loading_ceiling: Duration,
) -> Vec<Diagnostic> {
    let freshness = snapshot.freshness;
    let severities = snapshot.severities;
    let network = snapshot.network;
    let snapshot_osv_checks = snapshot.osv_checks();
    let vulnerability_visibility = snapshot.vulnerability_visibility();
    // Skip diagnostics while versions are loading, up to `loading_ceiling` (#632): if the
    // background fetch task panicked without reaching `set_loaded`/`set_failed`, `loading_state`
    // would stay `Loading` forever and permanently suppress diagnostics. Past the ceiling, force
    // `Failed` *before* extraction (critic M1/S2) — a read-only fallthrough would leave
    // `loading_state` stuck and `outcomes` empty, misrendering unresolved deps as "Unknown
    // package" instead of "lookup could not be determined". `loading_duration()` is always
    // `Some` here: `LoadPhase` (#1514) couples the `Loading` state and its start instant in one
    // field, so `loading_state() == Loading` structurally guarantees a recorded start time.
    let past_ceiling = state
        .with_document(uri, |doc| {
            doc.loading_state() == deps_core::LoadingState::Loading
                && doc.loading_duration().is_some_and(|d| d >= loading_ceiling)
        })
        .unwrap_or(false);
    if past_ceiling {
        tracing::warn!(
            "Loading exceeded ceiling ({:?}) for {:?}; forcing Failed and falling through \
             to diagnostics with available cache",
            loading_ceiling,
            uri
        );
        state.force_document_failed_with_not_attempted(uri);
    }

    // Release the DashMap shard `Ref` before awaiting (#333): `with_document` only hands
    // `extract` a borrowed `&DocumentState` synchronously, so it can't leak across the await below.
    let Some(extracted) = state.with_document(uri, |doc| {
        let Some(ecosystem) = state.ecosystem_registry.get(doc.ecosystem) else {
            tracing::warn!("Ecosystem not found for diagnostics: {}", doc.ecosystem);
            return None;
        };

        // The ceiling check above already forced a stuck document out of `Loading`, so
        // this only ever suppresses a document that is genuinely, recently loading.
        if doc.loading_state() == deps_core::LoadingState::Loading {
            return None;
        }

        let parse_result = doc.parse_result_arc()?;
        // Issue #1437 security review N1 (impl-critic extended scope) / issue #1456 spec
        // 072's identical rationale for GOSSIP: a live `did_change_configuration` disabling
        // either feature, or a transition to offline, must stop rendering a previously-
        // populated typosquat/gossip map immediately, not just stop refreshing it. Read
        // here, in the same synchronous closure as the document snapshot itself (both under
        // the same DashMap shard lock, with no `.await` between them), rather than before
        // `with_document` or after it returns — this is at least as tight a window against a
        // concurrent flag flip as the pre-refactor read site (right after releasing this
        // same lock), and tighter than reading before entering the closure would be.
        let online = network.is_online();
        let typosquat_visibility =
            PrefetchVisibility::from_enabled(snapshot.typosquat.is_active() && online);
        let gossip_visibility =
            PrefetchVisibility::from_enabled(snapshot.gossip.is_active() && online);
        let signals = doc
            .signals
            .snapshot()
            .with_resolved_version_candidates()
            .with_vulnerabilities(vulnerability_visibility)
            .with_latest_status(snapshot_osv_checks)
            .with_outcomes()
            .with_license_prefetch()
            .with_typosquat_prefetch(typosquat_visibility)
            .with_gossip_prefetch(gossip_visibility)
            .finish();
        Some((ecosystem, doc.ecosystem, parse_result, signals))
    }) else {
        tracing::warn!("Document not found for diagnostics: {:?}", uri);
        return vec![];
    };

    let Some((ecosystem, ecosystem_id, parse_result, signals)) = extracted else {
        return vec![];
    };

    // Issue #660/#661 critic C1: policy is read from `ServerState`, not a caller-supplied
    // parameter, so every call site evaluates it identically — see this function's doc comment.
    //
    // Unreachable in practice (the URI already converted in `ensure_document_loaded`);
    // handled defensively rather than unwrapped.
    let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(uri) else {
        tracing::warn!("URI is not representable as a url::Url: {:?}", uri);
        return vec![];
    };

    let version_data = signals
        .version_data()
        .with_ecosystem(ecosystem_id)
        .with_network(network)
        .with_license_source(ecosystem.license_source())
        .with_license_policy(&snapshot.license_policy);

    let domain_diagnostics = ecosystem
        .generate_diagnostics(
            parse_result.as_ref(),
            version_data,
            &domain_uri,
            freshness,
            severities,
        )
        .await;
    domain_diagnostics
        .into_iter()
        .map(crate::lsp_types_interop::to_lsp_diagnostic)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiagnosticsConfig;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;

    /// #1774: the pull path overrides severities after the snapshot is built, so the OSV gate
    /// must follow the override and the snapshot's own network mode, never a stale copy.
    #[tokio::test]
    async fn snapshot_osv_checks_follows_severities_override_and_network() {
        let state = ServerState::new();
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));
        let mut offline_config = DepsConfig::default();
        offline_config.policy.network.offline = true;
        let offline_config = RwLock::new(offline_config);
        let online_config = RwLock::new(DepsConfig::default());
        let mut diagnostics = DiagnosticsConfig::default();
        diagnostics.vulnerabilities_enabled = true;
        let enabled = diagnostics.to_severities();
        let offline = DiagnosticsSnapshot::capture(&state, &uri, &offline_config)
            .await
            .with_severities(enabled);
        assert!(!offline.osv_checks().is_active());

        diagnostics.vulnerabilities_enabled = false;
        let disabled = diagnostics.to_severities();
        let online = DiagnosticsSnapshot::capture(&state, &uri, &online_config)
            .await
            .with_severities(disabled);
        assert!(!online.osv_checks().is_active());

        let online = DiagnosticsSnapshot::capture(&state, &uri, &online_config)
            .await
            .with_severities(enabled);
        assert!(online.osv_checks().is_active());
    }

    /// Resolves a real `crossenv`/`cross-env` typosquat signal through a mocked deps.dev
    /// server, for tests that need a genuine signal without hand-constructing
    /// `TyposquatSignal` (it's `#[non_exhaustive]`, deliberately not publicly constructible)
    /// and without re-deriving the mock setup at every call site.
    #[cfg(feature = "npm")]
    async fn resolve_test_crossenv_typosquat_signal(
        ecosystem: &dyn deps_core::Ecosystem,
        parse_result: &dyn deps_core::ParseResult,
    ) -> std::collections::HashMap<deps_core::PackageName, deps_core::TyposquatSignal> {
        let mut server = mockito::Server::new_async().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "crossenv"}, "packages": [{"packageKey": {"name": "cross-env"}}]}"#,
            )
            .create_async()
            .await;
        let _declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/crossenv")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 3}"#)
            .create_async()
            .await;
        let _candidate_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/cross-env")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "7.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _candidate_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/cross-env/versions/7.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 900}"#)
            .create_async()
            .await;

        let mocked_deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let outcome = deps_core::lsp_helpers::fetch_typosquat_signals(
            deps_core::EcosystemId::Npm,
            parse_result,
            ecosystem.formatter(),
            deps_core::NetworkMode::Online,
            Some(&mocked_deps_dev),
        )
        .await;
        assert!(
            !outcome.signals.is_empty(),
            "pre-fetch must have resolved a signal"
        );
        outcome.signals
    }

    /// The typosquat gate of an otherwise default (online) policy.
    #[cfg(feature = "npm")]
    fn typosquat_checks(enabled: bool) -> TyposquatChecks {
        deps_core::policy_config::PolicyConfig {
            typosquat: deps_core::policy_config::TyposquatConfig::new().with_enabled(enabled),
            ..deps_core::policy_config::PolicyConfig::default()
        }
        .typosquat_checks()
    }

    #[test]
    fn test_loading_ceiling_small_manifest_hits_floor() {
        // A small manifest under default concurrency stays well under
        // `MIN_LOADING_CEILING` — the floor must win.
        assert_eq!(loading_ceiling(10, 1, 20), Duration::from_secs(120));
        assert_eq!(loading_ceiling(1, 1, 20), Duration::from_secs(120));
    }

    #[test]
    fn test_loading_ceiling_scales_with_dependency_count_and_concurrency() {
        // Issue #636: a low `max_concurrent_fetches` combined with a non-trivial
        // dependency count must scale the ceiling past the floor —
        // ceil(10 / 1) * 2 * 10s = 200s.
        assert_eq!(loading_ceiling(10, 10, 1), Duration::from_secs(200));
        // ceil(21 / 20) * 2 * 5s = 20s, still under the floor.
        assert_eq!(loading_ceiling(5, 21, 20), Duration::from_secs(120));
        // ceil(41 / 20) * 2 * 5s = 30s, still under the floor.
        assert_eq!(loading_ceiling(5, 41, 20), Duration::from_secs(120));
    }

    #[test]
    fn test_loading_ceiling_zero_dependencies_hits_floor() {
        assert_eq!(loading_ceiling(50, 0, 20), Duration::from_secs(120));
    }

    #[test]
    fn test_loading_ceiling_zero_max_concurrent_fetches_does_not_panic() {
        // Defensive: `max_concurrent_fetches` is clamped to >= 1 by
        // `config::deserialize_max_concurrent`, but this free function must not panic
        // (integer division by zero) if ever called with an un-clamped value directly.
        assert_eq!(loading_ceiling(10, 10, 0), Duration::from_secs(200));
    }

    /// Issue #636 critic S1: an unbounded ceiling would reinstate issue #632's
    /// stuck-forever shape for a large manifest under low concurrency (the ceiling is the
    /// only mechanism recovering a hung, non-panicking background task) — `MAX_LOADING_CEILING`
    /// must cap the result regardless of how large `dep_count / max_concurrent_fetches` gets.
    #[test]
    fn test_loading_ceiling_caps_at_max_loading_ceiling() {
        // C=1, T=300s, 300 dependencies -> uncapped would be 300 * 2 * 300s = 50 hours.
        assert_eq!(loading_ceiling(300, 300, 1), MAX_LOADING_CEILING);
        // Defaults (C=20, T=10s) with a very large manifest also hits the cap.
        assert_eq!(loading_ceiling(10, 2000, 20), MAX_LOADING_CEILING);
    }

    /// Issue #1437 NFR-002 (perf-review finding): diagnostics generation must never
    /// `.await` a deps.dev fan-out inline — `VersionData::typosquat_prefetch` is read
    /// synchronously from `PackageSignals::typosquats`, populated ahead of time by a
    /// background prefetch (`document::typosquat::run_typosquat_prefetch`), never fetched
    /// on this path. Proven here by enabling the feature, populating `doc.signals.typosquats`
    /// directly (bypassing the prefetch entirely, simulating "prefetch already
    /// completed"), and wrapping the call in a deliberately tiny timeout: if a future
    /// regression reintroduced an inline deps.dev `.await` here, this would either hang
    /// against the real `https://api.deps.dev` `state.deps_dev` still points at (never
    /// otherwise reached in this test) or blow well past the timeout.
    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_generate_diagnostics_internal_typosquat_prefetch_is_synchronous() {
        use crate::document::DocumentState;

        // See the comment in `test_unknown_package_uses_configured_severity` on why this
        // guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/package.json");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Npm)
            .unwrap();
        let content = r#"{"dependencies": {"crossenv": "1.0.0"}}"#.to_string();
        let parse_result = ecosystem
            .parse_manifest(&content, &url)
            .await
            .expect("Failed to parse manifest");

        // Resolved through a mocked server, the same way
        // `document::typosquat::run_typosquat_prefetch` resolves it in production — the
        // network round trip happens here, in setup, *before* the timed call below, never
        // inside `generate_diagnostics_internal` itself.
        let typosquats =
            resolve_test_crossenv_typosquat_signal(ecosystem.as_ref(), parse_result.as_ref()).await;

        let mut doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            "crossenv".into(),
            deps_core::PackageVersions::latest_only("1.0.0"),
        );
        doc_state.update_cached_versions(cached);
        doc_state.set_loaded();
        doc_state.merge_typosquats(typosquats);
        state.update_document(uri.clone(), doc_state);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    deps_core::DiagnosticSeverities::default(),
                    deps_core::NetworkMode::Online,
                )
                .with_typosquat_checks(typosquat_checks(true)),
                MIN_LOADING_CEILING,
            ),
        )
        .await
        .expect(
            "generate_diagnostics_internal must never block on a deps.dev fan-out \
             (NFR-002) — it timed out, which means the typosquat prefetch is (again) \
             being awaited inline on this path",
        );

        assert!(
            result.iter().any(|d| matches!(
                &d.code,
                Some(tower_lsp_server::ls_types::NumberOrString::String(code))
                    if code == deps_core::lsp_helpers::TYPOSQUAT_DIAGNOSTIC_CODE
            )),
            "expected a typosquat diagnostic from the pre-populated `doc.signals.typosquats` map, \
             got: {result:?}"
        );
    }

    /// Issue #1437 security review N1: a live `did_change_configuration` disabling
    /// `policy.typosquat.enabled` must stop the diagnostic from rendering immediately
    /// (FR-009), not just stop the background prefetch from refreshing it — a signal
    /// resolved *while the feature was enabled* must not keep appearing in `doc.signals.typosquats`
    /// after it's turned off, simulated here by disabling only *after* populating the map
    /// directly (bypassing the prefetch, which would itself never repopulate once
    /// disabled — this test isolates the read-side half of the fix).
    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_generate_diagnostics_internal_typosquat_disabled_suppresses_stale_signal() {
        use crate::document::DocumentState;

        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/package.json");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Npm)
            .unwrap();
        let content = r#"{"dependencies": {"crossenv": "1.0.0"}}"#.to_string();
        let parse_result = ecosystem
            .parse_manifest(&content, &url)
            .await
            .expect("Failed to parse manifest");

        let typosquats =
            resolve_test_crossenv_typosquat_signal(ecosystem.as_ref(), parse_result.as_ref()).await;

        let mut doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            "crossenv".into(),
            deps_core::PackageVersions::latest_only("1.0.0"),
        );
        doc_state.update_cached_versions(cached);
        doc_state.set_loaded();
        doc_state.merge_typosquats(typosquats);
        state.update_document(uri.clone(), doc_state);

        let result = generate_diagnostics_internal(
            Arc::clone(&state),
            &uri,
            &DiagnosticsSnapshot::for_test(
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
                deps_core::NetworkMode::Online,
            )
            .with_typosquat_checks(typosquat_checks(false)),
            MIN_LOADING_CEILING,
        )
        .await;

        assert!(
            !result.iter().any(|d| matches!(
                &d.code,
                Some(tower_lsp_server::ls_types::NumberOrString::String(code))
                    if code == deps_core::lsp_helpers::TYPOSQUAT_DIAGNOSTIC_CODE
            )),
            "a stale `doc.signals.typosquats` entry must not render once the feature is disabled, \
             got: {result:?}"
        );
    }

    /// Issue #1437 impl-critic N1 (extending security's N1 to the offline case): a stale
    /// `doc.signals.typosquats` entry — resolved while online — must also stop rendering the moment
    /// the server goes offline, same rationale as the disabled case above, checked via the
    /// `offline` parameter `generate_diagnostics_internal` already threads through (still
    /// enabled the whole time, unlike the sibling test).
    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_generate_diagnostics_internal_offline_suppresses_stale_signal() {
        use crate::document::DocumentState;

        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/package.json");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Npm)
            .unwrap();
        let content = r#"{"dependencies": {"crossenv": "1.0.0"}}"#.to_string();
        let parse_result = ecosystem
            .parse_manifest(&content, &url)
            .await
            .expect("Failed to parse manifest");

        let typosquats =
            resolve_test_crossenv_typosquat_signal(ecosystem.as_ref(), parse_result.as_ref()).await;

        let mut doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            "crossenv".into(),
            deps_core::PackageVersions::latest_only("1.0.0"),
        );
        doc_state.update_cached_versions(cached);
        doc_state.set_loaded();
        doc_state.merge_typosquats(typosquats);
        state.update_document(uri.clone(), doc_state);

        // `policy.typosquat.enabled` stays `true` — only `offline` (the argument
        // `generate_diagnostics_internal` already threads through) flips.
        let result = generate_diagnostics_internal(
            Arc::clone(&state),
            &uri,
            &DiagnosticsSnapshot::for_test(
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
                deps_core::NetworkMode::Offline,
            )
            .with_typosquat_checks(typosquat_checks(true)),
            MIN_LOADING_CEILING,
        )
        .await;

        assert!(
            !result.iter().any(|d| matches!(
                &d.code,
                Some(tower_lsp_server::ls_types::NumberOrString::String(code))
                    if code == deps_core::lsp_helpers::TYPOSQUAT_DIAGNOSTIC_CODE
            )),
            "a stale `doc.signals.typosquats` entry must not render while offline, got: {result:?}"
        );
    }

    /// Issue #1819: the advisory toggle and offline mode over a document with an already
    /// fetched advisory.
    #[cfg(feature = "cargo")]
    mod vulnerability_toggle {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, UpgradeStatus,
            VulnSeverity, VulnerabilityMap,
        };

        const ADVISORY_ID: &str = "RUSTSEC-2020-0071";

        async fn state_with_advisory() -> (Arc<ServerState>, Uri) {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"0.9.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("failed to parse manifest");
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                deps_core::PackageName::from("serde"),
                deps_core::PackageVersions::latest_only("0.9.0"),
            );
            doc_state.update_cached_versions(cached);
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                deps_core::test_util::vuln_key("serde"),
                ScanOutcome::Vulnerable(
                    DependencyVulnerabilities::new(Capped::new(
                        vec![Arc::new(
                            Advisory::new(
                                ADVISORY_ID.to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.0.5")]),
                        )],
                        1,
                    ))
                    .with_fix_target_status(UpgradeStatus::CandidateClean {
                        version: deps_core::ConcreteVersion::new("1.0.5"),
                    }),
                ),
            );
            doc_state.signals.vulnerabilities = vulnerabilities;
            doc_state.set_loaded();
            state.update_document(uri.clone(), doc_state);
            (state, uri)
        }

        async fn advisory_rendered(
            state: &Arc<ServerState>,
            uri: &Uri,
            vulnerabilities_enabled: bool,
            network: deps_core::NetworkMode,
        ) -> bool {
            let mut diagnostics = DiagnosticsConfig::default();
            diagnostics.vulnerabilities_enabled = vulnerabilities_enabled;
            let result = generate_diagnostics_internal(
                Arc::clone(state),
                uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    diagnostics.to_severities(),
                    network,
                ),
                MIN_LOADING_CEILING,
            )
            .await;
            result.iter().any(|d| {
                matches!(
                    &d.code,
                    Some(tower_lsp_server::ls_types::NumberOrString::String(code))
                        if code == ADVISORY_ID
                )
            })
        }

        #[tokio::test]
        async fn disabling_hides_cached_advisories_and_re_enabling_shows_them() {
            let (state, uri) = state_with_advisory().await;
            let online = deps_core::NetworkMode::Online;
            assert!(advisory_rendered(&state, &uri, true, online).await);
            assert!(!advisory_rendered(&state, &uri, false, online).await);
            assert!(advisory_rendered(&state, &uri, true, online).await);
        }

        /// The pull path reads one config: toggling it between requests changes the advisory
        /// set, never a mix of the old severities and the new gates (#1815).
        #[tokio::test]
        async fn pull_path_follows_the_config_it_captured() {
            let (state, uri) = state_with_advisory().await;
            let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();
            for enabled in [true, false, true] {
                config
                    .write()
                    .await
                    .policy
                    .diagnostics
                    .vulnerabilities_enabled = enabled;
                let result = handle_diagnostics(
                    Arc::clone(&state),
                    &uri,
                    client.clone(),
                    Arc::clone(&config),
                )
                .await;
                let shown = result.iter().any(|d| {
                    matches!(
                        &d.code,
                        Some(tower_lsp_server::ls_types::NumberOrString::String(code))
                            if code == ADVISORY_ID
                    )
                });
                assert_eq!(shown, enabled);
            }
        }

        #[tokio::test]
        async fn offline_keeps_rendering_cached_advisories() {
            let (state, uri) = state_with_advisory().await;
            assert!(advisory_rendered(&state, &uri, true, deps_core::NetworkMode::Offline).await);
            assert!(!advisory_rendered(&state, &uri, false, deps_core::NetworkMode::Offline).await);
        }
    }

    /// Issue #1815: a generation reads the config gates from its snapshot, never from the
    /// `ServerState` mirrors, which a later config apply may already have moved.
    #[tokio::test]
    async fn capture_ignores_the_state_mirrors() {
        let state = ServerState::new();
        state.set_license_policy(deps_core::LicensePolicy::new(
            Vec::new(),
            vec!["GPL-3.0".to_string()],
        ));
        let uri = epoch_test_uri();
        let snapshot =
            DiagnosticsSnapshot::capture(&state, &uri, &RwLock::new(DepsConfig::default())).await;
        assert!(snapshot.license_policy.is_empty());
        assert!(!snapshot.typosquat.is_active());
        assert!(!snapshot.gossip.is_active());
    }

    #[tokio::test]
    async fn capture_copies_the_gates_of_the_config_it_read() {
        let state = ServerState::new();
        let mut config = DepsConfig::default();
        config.policy.license_policy = deps_core::policy_config::LicensePolicyConfig::new()
            .with_deny(vec!["GPL-3.0".to_string()]);
        let snapshot =
            DiagnosticsSnapshot::capture(&state, &epoch_test_uri(), &RwLock::new(config)).await;
        assert!(!snapshot.license_policy.is_empty());
    }

    fn epoch_test_uri() -> Uri {
        crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri("/test/Cargo.toml"))
    }

    /// Runs an empty config apply: the epoch goes odd and then to a new even value.
    async fn apply_empty_config_change(state: &ServerState, config: &RwLock<DepsConfig>) {
        let guard = config.write().await;
        drop(state.begin_config_apply(&guard));
    }

    #[tokio::test]
    async fn snapshot_is_stale_after_a_config_apply() {
        let state = ServerState::new();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();

        let snapshot = DiagnosticsSnapshot::capture(&state, &uri, &config).await;
        assert!(snapshot.is_current(&state, &uri));

        apply_empty_config_change(&state, &config).await;
        assert!(!snapshot.is_current(&state, &uri));
    }

    #[tokio::test]
    async fn snapshot_is_stale_after_the_document_changes() {
        use crate::document::DocumentState;

        let state = ServerState::new();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();
        let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
        doc.set_version(Some(1));
        state.update_document(uri.clone(), doc.clone());

        let snapshot = DiagnosticsSnapshot::capture(&state, &uri, &config).await;
        assert!(snapshot.is_current(&state, &uri));

        doc.set_version(Some(2));
        state.update_document(uri.clone(), doc);
        assert!(!snapshot.is_current(&state, &uri));
    }

    #[tokio::test]
    async fn capture_waits_for_an_in_flight_config_apply() {
        let state = Arc::new(ServerState::new());
        let config = Arc::new(RwLock::new(DepsConfig::default()));
        let uri = epoch_test_uri();

        let guard = config.write().await;
        let apply = state.begin_config_apply(&guard);
        drop(guard);
        let capture = tokio::spawn({
            let (state, config, uri) = (Arc::clone(&state), Arc::clone(&config), uri.clone());
            async move { DiagnosticsSnapshot::capture(&state, &uri, &config).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !capture.is_finished(),
            "capture must not read config while an apply is in flight"
        );

        drop(apply);
        let snapshot = tokio::time::timeout(Duration::from_secs(2), capture)
            .await
            .expect("capture must resume once the apply settles")
            .expect("capture task");
        assert!(snapshot.is_current(&state, &uri));
    }

    #[tokio::test]
    async fn generation_is_redone_when_a_config_apply_overtakes_it() {
        let state = ServerState::new();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let generated = generate_until_current(&state, &uri, &config, |_snapshot| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (state, config) = (&state, &config);
            async move {
                if call == 0 {
                    apply_empty_config_change(state, config).await;
                }
                call
            }
        })
        .await;

        assert_eq!(generated.value, 1, "the second generation is the one kept");
        assert!(generated.current);
    }

    #[tokio::test]
    async fn exhausted_retries_request_a_republish_from_the_worker() {
        let state = ServerState::new();
        let (client, _) = create_test_client_and_config();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();

        publish_with(&state, &client, &uri, &config, |_snapshot| {
            let (state, config) = (&state, &config);
            async move {
                apply_empty_config_change(state, config).await;
                Vec::new()
            }
        })
        .await;

        tokio::time::timeout(Duration::from_millis(200), state.republish_requested())
            .await
            .expect("an exhausted publish must wake the republish worker");
    }

    #[tokio::test]
    async fn settled_generation_does_not_request_a_republish() {
        let state = ServerState::new();
        let (client, _) = create_test_client_and_config();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();
        open_empty_document(&state, &uri);

        publish_with(&state, &client, &uri, &config, |_snapshot| async {
            Vec::new()
        })
        .await;

        assert!(state.has_published(&uri));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.republish_requested())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn retry_that_meets_a_loading_document_stays_silent() {
        use crate::document::DocumentState;

        let state = ServerState::new();
        let (client, _) = create_test_client_and_config();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();
        let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
        doc.set_loading();
        state.update_document(uri.clone(), doc);
        let calls = std::sync::atomic::AtomicU32::new(0);

        publish_with(&state, &client, &uri, &config, |_snapshot| {
            let first = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            let (state, config) = (&state, &config);
            async move {
                if first {
                    apply_empty_config_change(state, config).await;
                }
                Vec::new()
            }
        })
        .await;

        assert!(
            !state.has_published(&uri),
            "an empty set from a retry must not replace a loading document's diagnostics"
        );
    }

    #[tokio::test]
    async fn older_generation_cannot_publish_after_a_newer_one() {
        let state = ServerState::new();
        let uri = epoch_test_uri();
        open_empty_document(&state, &uri);
        let older = state.next_publish_ticket();
        let newer = state.next_publish_ticket();

        assert!(state.claim_publish(&uri, newer));
        assert!(!state.claim_publish(&uri, older));
        assert!(state.claim_publish(&uri, state.next_publish_ticket()));
    }

    /// N3: a generation still in flight when its document closes must not leave a claim behind.
    #[tokio::test]
    async fn claim_for_a_closed_document_is_not_retained() {
        let state = ServerState::new();
        let uri = epoch_test_uri();
        open_empty_document(&state, &uri);
        assert!(state.claim_publish(&uri, state.next_publish_ticket()));
        assert!(state.has_published(&uri));

        let in_flight = state.next_publish_ticket();
        state.remove_document(&uri);
        assert!(!state.has_published(&uri));
        assert!(state.claim_publish(&uri, in_flight));
        assert!(
            !state.has_published(&uri),
            "a late claim must not re-insert after the document was removed"
        );
    }

    /// I1: a client that never drains the send must not hold the config guard forever.
    #[tokio::test]
    async fn stuck_send_is_abandoned_after_the_limit() {
        let sent = send_bounded(std::future::pending::<()>(), Duration::from_millis(50)).await;
        assert!(!sent);
        assert!(send_bounded(async {}, Duration::from_millis(50)).await);
    }

    /// I1: while the (bounded) send runs, the config guard is held, so an apply queues behind it
    /// instead of slipping in between the currency check and the send.
    #[tokio::test]
    async fn config_apply_waits_for_the_publish_guard() {
        let config = RwLock::new(DepsConfig::default());
        let state = ServerState::new();
        let uri = epoch_test_uri();
        let generated = generate_until_current(&state, &uri, &config, |_snapshot| async {}).await;
        assert!(generated.current);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), config.write())
                .await
                .is_err()
        );
        drop(generated);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), config.write())
                .await
                .is_ok()
        );
    }

    fn open_empty_document(state: &ServerState, uri: &Uri) {
        state.update_document(
            uri.clone(),
            crate::document::DocumentState::new_without_parse_result(
                EcosystemId::Cargo,
                String::new(),
            ),
        );
    }

    #[tokio::test]
    async fn generation_stops_retrying_after_the_attempt_cap() {
        let state = ServerState::new();
        let config = RwLock::new(DepsConfig::default());
        let uri = epoch_test_uri();
        let calls = std::sync::atomic::AtomicU32::new(0);

        let generated = generate_until_current(&state, &uri, &config, |_snapshot| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (state, config) = (&state, &config);
            async move {
                apply_empty_config_change(state, config).await;
                call
            }
        })
        .await;

        assert_eq!(generated.value, MAX_PUBLISH_ATTEMPTS - 1);
        assert!(!generated.current);
    }

    #[tokio::test]
    async fn test_handle_diagnostics_missing_document() {
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let (client, full_config) = create_test_client_and_config();
        let result = handle_diagnostics(state, &uri, client, full_config).await;
        assert!(result.is_empty());
    }

    /// #333 liveness regression: `handle_diagnostics` must release the DashMap shard
    /// `Ref` on the document *before* awaiting `Ecosystem::generate_diagnostics`, so a
    /// concurrent `documents.get_mut` on the same URI (e.g. a `didChange`) is never
    /// blocked behind an in-flight (or stuck) diagnostics generation.
    ///
    /// `BlockingEcosystem::generate_diagnostics` waits on a `Barrier` before blocking
    /// forever (`std::future::pending`), standing in for an override that performs real
    /// I/O — the worst case for a shard `Ref` held across the call. The test only
    /// proceeds to race the writer once that future has demonstrably started executing
    /// (via the barrier); a concurrent write racing here must complete almost
    /// immediately, proving the `Ref` was already dropped before the call was awaited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_document_write_not_blocked_by_in_flight_diagnostics() {
        use crate::document::DocumentState;
        use crate::test_utils::blocking_ecosystem::{
            BlockingEcosystem, BlockingHook, MockParseResult,
        };
        use deps_core::ParseResult;
        use tokio::sync::Barrier;

        let state = Arc::new(ServerState::new());
        let started = Arc::new(Barrier::new(2));
        state
            .ecosystem_registry
            .register(Arc::new(BlockingEcosystem {
                started: Arc::clone(&started),
                hook: BlockingHook::Diagnostics,
            }));

        let url = deps_core::test_util::test_uri("/test/Cargo.toml");

        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let (client, full_config) = create_test_client_and_config();

        let handler_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move { handle_diagnostics(state, &uri, client, full_config).await }
        });

        // Block until `generate_diagnostics` has actually started (barrier) before racing
        // the writer; timeout so a regression that never reaches the await hangs loudly instead of forever.
        tokio::time::timeout(std::time::Duration::from_secs(5), started.wait())
            .await
            .expect("handle_diagnostics did not reach generate_diagnostics within 5s");

        // Spawned as its own task deliberately — see completion.rs's #319 test for why
        // `DashMap::get_mut` needs a real async yield point to race the timeout.
        let write_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                state.documents.get_mut(&uri).unwrap().set_loading();
            }
        });
        let write_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), write_task).await;

        handler_task.abort();

        assert!(
            write_result.is_ok(),
            "#333 regression: a concurrent documents.get_mut on the same URI must not \
             block on an in-flight generate_diagnostics call — the DashMap shard Ref \
             must be dropped before the call is awaited, not after it"
        );
    }

    // Severity wiring tests (issue #224): confirm `DiagnosticsConfig`'s
    // outdated/unknown severity fields actually reach the emitted diagnostics,
    // and that default config preserves the pre-existing hardcoded severities.
    #[cfg(feature = "cargo")]
    mod severity_wiring_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::diagnostic::Severity;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::DiagnosticSeverity;

        #[tokio::test]
        async fn test_unknown_package_uses_configured_severity() {
            // Held per fs_probe::snapshot_guard's doc: parse_manifest touches fs_probe and
            // this test shares a binary with document/loader.rs's diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let config = DiagnosticsConfig::new().with_unknown_severity(Severity::Error);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            full_config.write().await.policy.diagnostics = config;
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
        }

        #[tokio::test]
        async fn test_unknown_package_default_severity_unchanged() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::WARNING));
        }

        #[tokio::test]
        async fn test_outdated_dependency_uses_configured_severity() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let config = DiagnosticsConfig::new().with_outdated_severity(Severity::Error);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            // `available` must include "1.0.0" alongside "2.0.0" — a `latest_only` list with
            // just "2.0.0" would make "1.0.0" look unsatisfiable and fire WARNING instead of HINT/ERROR.
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "2.0.0".into(),
                    std::sync::Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            full_config.write().await.policy.diagnostics = config;
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
            assert!(result[0].message.contains("Newer version available"));
        }

        #[tokio::test]
        async fn test_outdated_dependency_default_severity_unchanged() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            // See the sibling test above for why `available` must include "1.0.0", not
            // just "2.0.0".
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "2.0.0".into(),
                    std::sync::Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::HINT));
        }

        #[tokio::test]
        async fn test_unsatisfiable_requirement_uses_configured_severity() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let config = DiagnosticsConfig::new().with_unsatisfiable_severity(Severity::Error);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "1.0.214".into(),
                    std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            full_config.write().await.policy.diagnostics = config;
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1);
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
            assert!(result[0].message.contains("No published version satisfies"));
        }
    }

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        /// Issue #636 tester finding: `handle_diagnostics`'s existing coverage only ever
        /// used a single-dependency fixture, so nothing proved `document_dependency_count`
        /// actually reads the document's real dependency count rather than e.g. always `0`.
        #[tokio::test]
        async fn test_document_dependency_count_reflects_real_dependency_count() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content =
                "[dependencies]\nserde = \"1.0\"\ntokio = \"1.0\"\nanyhow = \"1.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");
            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            assert_eq!(document_dependency_count(&state, &uri), 3);
        }

        #[tokio::test]
        async fn test_document_dependency_count_missing_document_is_zero() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            assert_eq!(document_dependency_count(&state, &uri), 0);
        }

        #[tokio::test]
        async fn test_document_dependency_count_no_parse_result_is_zero() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            assert_eq!(document_dependency_count(&state, &uri), 0);
        }

        #[tokio::test]
        async fn test_handle_diagnostics() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = r#"[dependencies]
serde = "1.0.0"
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, client, full_config).await;
        }

        #[tokio::test]
        async fn test_handle_diagnostics_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;
            assert!(result.is_empty());
        }

        /// Issue #632: a document stuck in `Loading` past `loading_ceiling` must fall
        /// through to diagnostics generated from whatever cache is already available,
        /// instead of returning nothing forever (e.g. a background fetch task that
        /// panicked without reaching `set_loaded`/`set_failed`).
        #[tokio::test]
        async fn test_generate_diagnostics_internal_falls_through_after_loading_ceiling_exceeded() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "2.0.0".into(),
                    std::sync::Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            doc_state.set_loading();
            state.update_document(uri.clone(), doc_state);

            // Let real elapsed time exceed a deliberately tiny ceiling.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            let result = generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    deps_core::DiagnosticSeverities::default(),
                    deps_core::NetworkMode::Online,
                ),
                std::time::Duration::from_millis(1),
            )
            .await;

            assert_eq!(
                result.len(),
                1,
                "expected the outdated diagnostic to render from cache once the loading \
                 ceiling is exceeded, got: {result:?}"
            );

            // Critic M1: the fallthrough must repair `loading_state`, not just read past it —
            // otherwise other handlers keep believing it's still loading and the warning refires.
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.loading_state(), deps_core::LoadingState::Failed);
        }

        /// Issue #632 critic S2: forcing a stuck-`Loading` document to `Failed` must seed
        /// a `NotAttempted` fetch-failure finding for every dependency with neither a
        /// cached nor a lockfile-resolved version — otherwise the unknown-package rule
        /// renders it as "Unknown package" (a registry lookup that never happened looks
        /// identical to one that came back empty), turning a silently suppressed
        /// diagnostic into a misleading one.
        #[tokio::test]
        async fn test_generate_diagnostics_internal_ceiling_exceeded_seeds_not_attempted_instead_of_unknown_package()
         {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            // No cached_versions/resolved_versions seeded for "serde" at all — the exact
            // "never actually fetched" shape S2 covers.
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.set_loading();
            state.update_document(uri.clone(), doc_state);

            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            let result = generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    deps_core::DiagnosticSeverities::default(),
                    deps_core::NetworkMode::Online,
                ),
                std::time::Duration::from_millis(1),
            )
            .await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic, got: {result:?}"
            );
            assert!(
                result[0].message.contains("could not be determined"),
                "expected the 'lookup could not be determined' message, got: {:?}",
                result[0].message
            );
            assert!(
                !result[0].message.contains("Unknown package"),
                "a dependency that was never actually fetched must not render as 'Unknown \
                 package', got: {:?}",
                result[0].message
            );

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.loading_state(), deps_core::LoadingState::Failed);
        }

        /// Issue #632 companion: within the ceiling, the pre-existing suppression must
        /// still apply — no diagnostics render for a document that is still legitimately
        /// loading.
        #[tokio::test]
        async fn test_generate_diagnostics_internal_still_suppressed_within_loading_ceiling() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.set_loading();
            state.update_document(uri.clone(), doc_state);

            let result = generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    deps_core::DiagnosticSeverities::default(),
                    deps_core::NetworkMode::Online,
                ),
                std::time::Duration::from_secs(60),
            )
            .await;

            assert!(
                result.is_empty(),
                "expected diagnostics to stay suppressed within the loading ceiling, got: \
                 {result:?}"
            );
        }

        /// End-to-end coverage for issue #206's unsatisfiable-requirement diagnostic,
        /// through the real `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `CargoFormatter::compile_bounded_requirement` path
        /// (not just the pure `requirement_is_unsatisfiable` function).
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_requirement_yields_one_warning() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "1.0.214".into(),
                    std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1, "expected exactly one diagnostic");
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert!(result[0].message.contains("No published version satisfies"));
            assert!(
                !result
                    .iter()
                    .any(|d| d.message.contains("Newer version available")),
                "the unsatisfiable WARNING must replace the outdated HINT, not add to it"
            );
        }

        /// SC-005: an empty `available` list (still loading, or a registry that never
        /// populated it) must suppress the check entirely rather than treating "nothing
        /// fetched yet" as "nothing published".
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_requirement_empty_available_yields_nothing()
        {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"99\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::latest_without_list("1.0.214"),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;
            assert!(
                !result
                    .iter()
                    .any(|d| d.message.contains("No published version satisfies")),
                "an empty available list must suppress the unsatisfiable check, got: {result:?}"
            );
        }

        /// NFR-004: a satisfiable-but-outdated dependency alongside an unsatisfiable one
        /// must still get its usual "Newer version available" HINT.
        #[tokio::test]
        async fn test_handle_diagnostics_unsatisfiable_and_outdated_side_by_side() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"99\"\ntokio = \"1.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "1.0.214".into(),
                    std::sync::Arc::from(vec!["1.0.214".into()]),
                ),
            );
            cached.insert(
                "tokio".into(),
                deps_core::PackageVersions::new(
                    "2.0.0".into(),
                    // Includes an older version satisfying "^1.0" so this is genuinely
                    // outdated-but-satisfiable, not unsatisfiable.
                    std::sync::Arc::from(vec!["2.0.0".into(), "1.5.0".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 2, "expected one warning and one hint");
            assert!(
                result
                    .iter()
                    .any(|d| d.message.contains("No published version satisfies"))
            );
            assert!(
                result
                    .iter()
                    .any(|d| d.message.contains("Newer version available"))
            );
        }

        /// End-to-end coverage for issue #247: a dependency pinned to an exact version that
        /// the registry reports as yanked must produce the yanked diagnostic through the real
        /// `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `CargoFormatter::compile_bounded_requirement` path —
        /// the same live path the LSP server actually calls, not just the pure
        /// `requirement_matches_only_yanked` function.
        #[tokio::test]
        async fn test_handle_diagnostics_yanked_only_match_yields_one_warning() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let content = "[dependencies]\nserde = \"=1.0.213\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::new(
                    "1.0.214".into(),
                    std::sync::Arc::from(vec!["1.0.214".into(), "1.0.213".into()]),
                )
                .with_yanked(std::sync::Arc::from(vec![(
                    "1.0.213".into(),
                    deps_core::RemovalStatus::Yanked,
                )])),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(result.len(), 1, "expected exactly one diagnostic");
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert_eq!(
                result[0].message,
                "This version has been yanked; latest is 1.0.214"
            );
        }
    }

    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::DiagnosticMessages;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Npm)
                .unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, client, full_config).await;
        }

        /// #436 S1 regression: after #436 narrowed npm's fix to only suppress the
        /// manifest-requirement-level yanked diagnostic (`NpmFormatter::yanked_diagnostic_applies_to`
        /// now unconditionally `false`), the independent #263 in-use-version yanked diagnostic
        /// must still fire through the real `DocumentState` -> `Ecosystem::generate_diagnostics`
        /// -> `generate_diagnostics_from_cache` path — the same live path the LSP server
        /// actually calls, using the real `NpmFormatter`/`NpmRegistry`-backed npm ecosystem
        /// (not a generic `MockRegistry`).
        ///
        /// Mirrors the canonical `npm deprecate left-pad@"<1.0.2" "..."` scenario: the
        /// manifest declares a range (`^1.0.0`), `latest` (1.0.2) is clean, but the
        /// lockfile-resolved in-use version (1.0.1) is flagged. This is exactly the coverage
        /// the critic's S1 finding said `Registry::reports_yanked() == false` would have
        /// silently killed had npm's first #436 pass gone unrevised.
        #[tokio::test]
        async fn test_handle_diagnostics_in_use_version_yanked_still_fires_post_436() {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Npm)
                .unwrap();
            let content = r#"{"dependencies": {"left-pad": "^1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "left-pad".into(),
                deps_core::PackageVersions::new(
                    "1.0.2".into(),
                    std::sync::Arc::from(vec!["1.0.2".into(), "1.0.1".into(), "1.0.0".into()]),
                ),
            );
            doc_state.update_cached_versions(cached);

            // Lockfile resolves the "^1.0.0" range to the old, flagged 1.0.1 — `latest`
            // itself is clean, so this is only reachable via the lockfile-resolved
            // in-use-version check (#263), not the manifest-requirement check (#247).
            let mut resolved = std::collections::HashMap::new();
            resolved.insert("left-pad".into(), "1.0.1".into());
            doc_state
                .set_resolved_versions_without_bump(resolved, std::collections::HashMap::new());

            doc_state.replace_outcomes(deps_core::DependencyOutcomes::new().with_yanked(
                "left-pad",
                ("1.0.1".into(), deps_core::RemovalStatus::AdvisoryDeprecated),
            ));

            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic, got {result:?}"
            );
            assert_eq!(
                result[0].severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
            );
            assert_eq!(
                result[0].message,
                format!("{} (1.0.1)", deps_npm::NpmFormatter.yanked_message())
            );
        }

        /// #436 S1 companion: the manifest-requirement-level yanked diagnostic (#247) must
        /// stay suppressed for npm even for an exact-pin requirement — the one shape the
        /// pre-#436 restriction still let through. Deliberately isolated from the #263 path
        /// (no `resolved_versions`/`yanked_versions` set) so this proves
        /// `NpmFormatter::yanked_diagnostic_applies_to`'s unconditional `false` is doing real
        /// work here, not merely benefiting from the `yanked_263_diagnostic_pushed` dedup
        /// guard the sibling test above would also satisfy on its own.
        #[tokio::test]
        async fn test_handle_diagnostics_manifest_requirement_yanked_stays_suppressed_for_exact_pin()
         {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Npm)
                .unwrap();
            // Bare exact pin (npm's ordinary package.json style, no `=` marker) — the
            // shape `yanked_diagnostic_applies_to` still allowed through pre-#436.
            let content = r#"{"dependencies": {"old-pkg": "1.0.1"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "old-pkg".into(),
                // The pin is satisfiable only by a flagged version — pre-#436, this
                // exact shape fired the #247 "yanked" diagnostic.
                deps_core::PackageVersions::new(
                    "1.0.1".into(),
                    std::sync::Arc::from(vec!["1.0.1".into()]),
                )
                .with_yanked(std::sync::Arc::from(vec![(
                    "1.0.1".into(),
                    deps_core::RemovalStatus::AdvisoryDeprecated,
                )])),
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — the #263 in-use-version path has
            // nothing to match against, isolating this assertion to the #247 path alone.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert!(
                result.is_empty(),
                "expected no diagnostics for an exact pin satisfiable only by a flagged \
                 version — the #247 manifest-requirement diagnostic must stay suppressed for \
                 npm regardless of requirement shape (#436), got {result:?}"
            );
        }
    }

    #[cfg(feature = "deno")]
    mod deno_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::DiagnosticMessages;

        /// #448 regression: mirrors npm_tests'
        /// `test_handle_diagnostics_manifest_requirement_yanked_stays_suppressed_for_exact_pin`
        /// through the real `DocumentState` -> `Ecosystem::generate_diagnostics` ->
        /// `generate_diagnostics_from_cache` -> `DenoFormatter::yanked_diagnostic_applies_to`
        /// path — an exact-pin `npm:` specifier in `deno.json` satisfiable only by a flagged
        /// version must NOT surface the #247 manifest-requirement yanked diagnostic, exactly
        /// like the equivalent `package.json` dependency (fixes the #436 M1 divergence).
        #[tokio::test]
        async fn test_handle_diagnostics_npm_scheme_exact_pin_yanked_stays_suppressed() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/deno.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Deno)
                .unwrap();
            let content = r#"{"imports": {"lodash": "npm:lodash@4.17.20"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "npm:lodash".into(),
                // The pin is satisfiable only by a flagged version — for `package.json`
                // this exact shape used to fire the #247 "yanked" diagnostic pre-#436.
                deps_core::PackageVersions::new(
                    "4.17.20".into(),
                    std::sync::Arc::from(vec!["4.17.20".into()]),
                )
                .with_yanked(std::sync::Arc::from(vec![(
                    "4.17.20".into(),
                    deps_core::RemovalStatus::AdvisoryDeprecated,
                )])),
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — isolates this assertion to the #247
            // manifest-requirement path, same as the npm companion test.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert!(
                result.is_empty(),
                "expected no diagnostics for an exact-pin npm: specifier satisfiable only by a \
                 flagged version — the #247 manifest-requirement diagnostic must stay \
                 suppressed for deno's npm: scheme (#448), got {result:?}"
            );
        }

        /// #448/#454: an exact-pin `jsr:` specifier satisfiable only by a flagged version
        /// fires the #247 diagnostic, proving the scheme split actually discriminates
        /// `jsr:` from `npm:` end-to-end, not just in the isolated
        /// `yanked_diagnostic_applies_to` unit tests.
        #[tokio::test]
        async fn test_handle_diagnostics_jsr_scheme_exact_pin_yanked_still_fires() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/deno.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Deno)
                .unwrap();
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "jsr:@std/fs".into(),
                deps_core::PackageVersions::new(
                    "1.0.1".into(),
                    std::sync::Arc::from(vec!["1.0.1".into(), "1.0.0".into()]),
                )
                .with_yanked(std::sync::Arc::from(vec![(
                    "1.0.0".into(),
                    deps_core::RemovalStatus::Yanked,
                )])),
            );
            doc_state.update_cached_versions(cached);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected the #247 diagnostic to still fire for an exact-pin jsr: specifier, \
                 got {result:?}"
            );
            assert_eq!(
                result[0].message,
                format!(
                    "{}; latest is 1.0.1",
                    deps_deno::DenoFormatter.yanked_message()
                )
            );
        }

        /// #454: the actual bug fix, proven end-to-end — a `jsr:` *range* requirement
        /// satisfiable only by yanked versions must now surface the #247
        /// manifest-requirement diagnostic too, matching Cargo/PyPI/Dart's behavior for the
        /// equivalent case (previously this was silent: `yanked_diagnostic_applies_to`
        /// rejected any non-exact-pin `jsr:` requirement). Exactly one diagnostic fires,
        /// confirming this does not double up with any package-level deprecation (#205)
        /// signal — deno has no such diagnostic for `jsr:` in the first place.
        #[tokio::test]
        async fn test_handle_diagnostics_jsr_scheme_range_yanked_only_now_fires() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/deno.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Deno)
                .unwrap();
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0.0"}}"#.to_string();
            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Deno, content, parse_result);

            let mut cached = std::collections::HashMap::new();
            cached.insert(
                "jsr:@std/fs".into(),
                // Every version matching "^1.0.0" is yanked — the concrete #454 bug
                // scenario, which previously produced zero diagnostic signal.
                deps_core::PackageVersions::new(
                    "1.0.1".into(),
                    std::sync::Arc::from(vec!["1.0.1".into(), "1.0.0".into()]),
                )
                .with_yanked(std::sync::Arc::from(vec![
                    ("1.0.1".into(), deps_core::RemovalStatus::Yanked),
                    ("1.0.0".into(), deps_core::RemovalStatus::Yanked),
                ])),
            );
            doc_state.update_cached_versions(cached);
            // No `resolved_versions`/`yanked_versions` — isolates this assertion to the #247
            // manifest-requirement path, same as the sibling exact-pin test.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic for a jsr: range satisfiable only by yanked \
                 versions (#454), got {result:?}"
            );
            assert_eq!(
                result[0].message,
                format!(
                    "{}; latest is 1.0.1",
                    deps_deno::DenoFormatter.yanked_message()
                )
            );
        }
    }

    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/pyproject.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Pypi)
                .unwrap();
            let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#
            .to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &url)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Pypi, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, client, full_config).await;
        }
    }

    // License-policy diagnostic tests (issue #661)
    #[cfg(feature = "cargo")]
    mod license_policy_tests {
        use super::*;
        use crate::config::LicensePolicyConfig;
        use crate::document::DocumentState;
        use deps_core::{EcosystemId, PackageName, ParseResult};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{DiagnosticSeverity, NumberOrString};

        async fn cargo_parse_result(
            state: &ServerState,
            uri: &url::Url,
            content: &str,
        ) -> Box<dyn ParseResult> {
            // See the comment in `test_unknown_package_uses_configured_severity` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap()
                .parse_manifest(content, uri)
                .await
                .expect("failed to parse manifest")
        }

        /// Sets up a document with `serde`'s license pre-fetched, ready for
        /// `handle_diagnostics` — the real `ServerState`/`DocumentState`/`DepsConfig` path
        /// (`textDocument/diagnostic` pull), not a pure-function shortcut, so this proves
        /// the end-to-end wiring (`generate_diagnostics_internal` ->
        /// `VersionData::with_license_policy`/`with_license_prefetch` ->
        /// `apply_license_policy_rule`) actually works, not just `deps_core::licenses`'
        /// own unit tests.
        ///
        /// Sets the policy via `ServerState::set_license_policy` (issue #660/#661 critic
        /// C1), mirroring what `Backend::initialize`/`did_change_configuration` do in
        /// production — `handle_diagnostics` no longer reads `DepsConfig::license_policy`
        /// directly.
        async fn setup(
            license: &str,
            allow: Vec<String>,
            deny: Vec<String>,
        ) -> (Arc<ServerState>, Uri, Client, Arc<RwLock<DepsConfig>>) {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result = cargo_parse_result(&state, &url, &content).await;

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                deps_core::PackageVersions::latest_only("1.0.0"),
            );
            doc_state.update_cached_versions(cached_versions);
            let mut licenses = HashMap::new();
            licenses.insert(PackageName::from("serde"), vec![license.to_string()]);
            doc_state.update_licenses(licenses);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let policy_config = LicensePolicyConfig::new().with_allow(allow).with_deny(deny);
            state.set_license_policy(policy_config.to_policy());
            full_config.write().await.policy.license_policy = policy_config;

            (state, uri, client, full_config)
        }

        #[tokio::test]
        async fn empty_policy_produces_no_diagnostics() {
            let (state, uri, client, full_config) = setup("GPL-3.0", Vec::new(), Vec::new()).await;

            let result = handle_diagnostics(state, &uri, client, full_config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn denied_license_produces_error_diagnostic() {
            let (state, uri, client, full_config) =
                setup("GPL-3.0", Vec::new(), vec!["GPL-3.0".to_string()]).await;

            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic, got: {result:?}"
            );
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
            assert_eq!(result[0].message, "serde: GPL-3.0 denied by policy");
            assert_eq!(
                result[0].code,
                Some(NumberOrString::String(
                    deps_core::LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE.into()
                ))
            );
        }

        #[tokio::test]
        async fn not_allowed_license_produces_warning_diagnostic() {
            let (state, uri, client, full_config) =
                setup("ISC", vec!["MIT".to_string()], Vec::new()).await;

            let result = handle_diagnostics(state, &uri, client, full_config).await;

            assert_eq!(
                result.len(),
                1,
                "expected exactly one diagnostic, got: {result:?}"
            );
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::WARNING));
            assert_eq!(
                result[0].message,
                "serde: ISC not on the allowed license list"
            );
        }

        #[tokio::test]
        async fn compliant_license_produces_no_diagnostic() {
            let (state, uri, client, full_config) =
                setup("MIT", vec!["MIT".to_string()], vec!["GPL-3.0".to_string()]).await;

            let result = handle_diagnostics(state, &uri, client, full_config).await;
            assert!(result.is_empty(), "got: {result:?}");
        }

        /// A dependency this feature has no license data for (not in the pre-fetch map —
        /// e.g. an ecosystem/tier the background pre-fetch doesn't cover yet) must never
        /// be treated as a violation (NFR-003 graceful degradation).
        #[tokio::test]
        async fn dependency_with_no_known_license_produces_no_diagnostic() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result = cargo_parse_result(&state, &url, &content).await;
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                deps_core::PackageVersions::latest_only("1.0.0"),
            );
            doc_state.update_cached_versions(cached_versions);
            // No `update_licenses` call — `licenses` stays empty.
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let policy_config = LicensePolicyConfig::new().with_allow(vec!["MIT".to_string()]);
            state.set_license_policy(policy_config.to_policy());
            full_config.write().await.policy.license_policy = policy_config;

            let result = handle_diagnostics(state, &uri, client, full_config).await;
            assert!(result.is_empty(), "got: {result:?}");
        }

        /// Issue #660/#661 critic C1 regression: the push path — `generate_diagnostics_internal`,
        /// called directly by every background-refresh call site in `document::lifecycle`/
        /// `server.rs` with no `Option<&LicensePolicy>` parameter — must evaluate the same
        /// policy as the pull path (`handle_diagnostics`), both reading
        /// the policy from the `DiagnosticsSnapshot`. Before this fix, only `handle_diagnostics` ever
        /// saw a configured policy.
        #[tokio::test]
        async fn push_path_also_evaluates_license_policy() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result = cargo_parse_result(&state, &url, &content).await;

            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                deps_core::PackageVersions::latest_only("1.0.0"),
            );
            doc_state.update_cached_versions(cached_versions);
            let mut licenses = HashMap::new();
            licenses.insert(PackageName::from("serde"), vec!["GPL-3.0".to_string()]);
            doc_state.update_licenses(licenses);
            state.update_document(uri.clone(), doc_state);

            let result = generate_diagnostics_internal(
                Arc::clone(&state),
                &uri,
                &DiagnosticsSnapshot::for_test(
                    deps_core::FreshnessSettings::default(),
                    deps_core::DiagnosticSeverities::default(),
                    deps_core::NetworkMode::Online,
                )
                .with_license_policy(deps_core::LicensePolicy::new(
                    Vec::new(),
                    vec!["GPL-3.0".to_string()],
                )),
                std::time::Duration::from_secs(60),
            )
            .await;

            assert_eq!(
                result.len(),
                1,
                "expected the license-policy diagnostic to fire on the push path too, got: \
                 {result:?}"
            );
            assert_eq!(result[0].severity, Some(DiagnosticSeverity::ERROR));
        }
    }
}
