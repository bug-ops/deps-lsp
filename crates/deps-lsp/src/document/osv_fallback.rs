//! Phase B's OSV round for the newest eligible version under a held `latest`, so a version
//! diagnostics would name is verified the same way `latest` itself is.

use super::state::ServerState;
use deps_core::lsp_helpers::cooldown_fallback_view;
use deps_core::native_cooldown::native_cooldowns_by_name;
use deps_core::osv::{LatestStatusMap, VulnKeys};
use deps_core::{
    CachedVersionsMap, GossipFindings, NormalizedName, ParsedManifest, PublishTime,
    ResolvedCandidatesMap, ResolvedVersionsMap,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tower_lsp_server::ls_types::Uri;

/// The document data the fallback view is built from, read in the same guard as phase B's own
/// targets.
pub(super) struct FallbackViewInputs {
    pub(super) manifest: Arc<dyn ParsedManifest>,
    pub(super) cached_versions: CachedVersionsMap,
    pub(super) resolved_versions: ResolvedVersionsMap,
    pub(super) resolved_version_candidates: Arc<ResolvedCandidatesMap>,
    pub(super) gossip_findings: HashMap<NormalizedName, GossipFindings>,
}

/// Checks the newest eligible versions of held dependencies against OSV before `deadline`.
///
/// Returns `None` when no dependency names such a version.
pub(super) async fn run_fallback_check(
    state: &ServerState,
    uri: &Uri,
    deadline: Instant,
    vuln_keys: &VulnKeys,
    inputs: &FallbackViewInputs,
) -> Option<LatestStatusMap> {
    let manifest = inputs.manifest.as_ref();
    let gossip = state
        .gossip_checks()
        .is_active()
        .then_some(&inputs.gossip_findings);
    let view = cooldown_fallback_view(
        &inputs.cached_versions,
        &inputs.resolved_versions,
        &inputs.resolved_version_candidates,
        &native_cooldowns_by_name(manifest),
        gossip,
        state.freshness(),
        PublishTime::now(),
    );
    let substituted = view.iter().any(|(name, versions)| {
        inputs
            .cached_versions
            .get(name)
            .is_none_or(|cached| cached.latest != versions.latest)
    });
    if !substituted {
        return None;
    }

    let candidate_tags = deps_engine::classify::osv::candidate_tag_sources(manifest, vuln_keys);
    let (targets, mut status) = deps_engine::classify::osv::build_latest_check_targets(
        manifest,
        &view,
        vuln_keys,
        &candidate_tags,
    );
    if targets.is_empty() {
        tracing::debug!(?uri, "no OSV target for any newest eligible version");
        return Some(status);
    }
    let timeout = deadline.saturating_duration_since(Instant::now());
    status.extend(
        state
            .osv
            .check_candidates(manifest.ecosystem_id(), &targets, timeout)
            .await,
    );
    Some(status)
}

#[cfg(test)]
#[cfg(feature = "cargo")]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::{CooldownFallback, PackageVersions};
    use deps_core::osv::{OsvClient, UpgradeStatus};
    use deps_core::{CooldownWindow, FreshnessSettings};
    use std::assert_matches;
    use std::time::Duration;

    const ADVISORY: &str = "MAL-2026-00001";

    /// A document locked at `serde 1.0.0` whose `latest` (3.0.0, just published) is held and
    /// whose newest eligible version is 2.0.0.
    async fn held_serde(server: &mockito::ServerGuard) -> (ServerState, Uri, FallbackViewInputs) {
        let mut state = ServerState::new();
        state.osv = Arc::new(OsvClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        state.set_freshness(FreshnessSettings::Enabled {
            cooldown: CooldownWindow::from_secs(3_600),
        });

        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem = state
            .ecosystem_registry
            .for_uri(&url)
            .expect("Cargo ecosystem");
        let manifest: Arc<dyn ParsedManifest> = Arc::from(
            ecosystem
                .parse_manifest("[dependencies]\nserde = \"1.0.0\"\n", &url)
                .await
                .expect("parses"),
        );
        let name = NormalizedName::for_test("serde");
        let versions = PackageVersions::new(
            "3.0.0".into(),
            Arc::from(vec!["3.0.0".into(), "2.0.0".into(), "1.0.0".into()]),
        )
        .with_published_at(PublishTime::now())
        .with_cooldown_fallback(CooldownFallback::new(
            "2.0.0".into(),
            PublishTime::from_unix_secs(1_000),
        ));
        let inputs = FallbackViewInputs {
            manifest,
            cached_versions: HashMap::from([(name.clone(), versions)]),
            resolved_versions: HashMap::from([(name, "1.0.0".into())]),
            resolved_version_candidates: Arc::default(),
            gossip_findings: HashMap::new(),
        };
        (state, uri, inputs)
    }

    async fn check(
        state: &ServerState,
        uri: &Uri,
        inputs: &FallbackViewInputs,
    ) -> Option<LatestStatusMap> {
        let vuln_keys = inputs
            .manifest
            .vulnerability_keys(&inputs.resolved_versions, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        run_fallback_check(state, uri, deadline, &vuln_keys, inputs).await
    }

    /// A batch mock that only answers a query for the version that would be named.
    async fn batch_for_eligible(
        server: &mut mockito::ServerGuard,
        status: usize,
        body: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", "/v1/querybatch")
            .match_body(mockito::Matcher::Regex(r#""version":"2\.0\.0""#.into()))
            .with_status(status)
            .with_body(body)
            .expect_at_least(1)
            .create_async()
            .await
    }

    #[tokio::test]
    async fn a_clean_eligible_version_is_reported_clean() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut server = mockito::Server::new_async().await;
        let batch = batch_for_eligible(&mut server, 200, r#"{"results":[{}]}"#).await;
        let (state, uri, inputs) = held_serde(&server).await;

        let status = check(&state, &uri, &inputs).await.expect("held");

        batch.assert_async().await;
        assert_matches!(
            status.values().collect::<Vec<_>>().as_slice(),
            [UpgradeStatus::CandidateClean { version }] if version == "2.0.0"
        );
    }

    #[tokio::test]
    async fn a_flagged_eligible_version_is_reported_vulnerable() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut server = mockito::Server::new_async().await;
        let body = format!(
            r#"{{"results":[{{"vulns":[{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z"}}]}}]}}"#
        );
        let batch = batch_for_eligible(&mut server, 200, &body).await;
        let _record = server
            .mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
            .with_status(200)
            .with_body(format!(
                r#"{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z","summary":"s",
                "affected":[{{"package":{{"name":"serde","ecosystem":"crates.io"}},
                "ranges":[{{"type":"SEMVER","events":[{{"introduced":"2.0.0"}}]}}]}}]}}"#
            ))
            .create_async()
            .await;
        let (state, uri, inputs) = held_serde(&server).await;

        let status = check(&state, &uri, &inputs).await.expect("held");

        batch.assert_async().await;
        assert_matches!(
            status.values().collect::<Vec<_>>().as_slice(),
            [UpgradeStatus::CandidateVulnerable { version, .. }] if version == "2.0.0"
        );
    }

    #[tokio::test]
    async fn an_unavailable_osv_leaves_the_eligible_version_unverified() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut server = mockito::Server::new_async().await;
        let batch = batch_for_eligible(&mut server, 500, "").await;
        let (state, uri, inputs) = held_serde(&server).await;

        let status = check(&state, &uri, &inputs).await.expect("held");

        batch.assert_async().await;
        assert_matches!(
            status.values().collect::<Vec<_>>().as_slice(),
            [UpgradeStatus::CandidateUnverified { version, .. }] if version == "2.0.0"
        );
    }

    #[tokio::test]
    async fn nothing_held_runs_no_round() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let server = mockito::Server::new_async().await;
        let (state, uri, inputs) = held_serde(&server).await;
        state.set_freshness(FreshnessSettings::Disabled);

        assert!(check(&state, &uri, &inputs).await.is_none());
    }
}
