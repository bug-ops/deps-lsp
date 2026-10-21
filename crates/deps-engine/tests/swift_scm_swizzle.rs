//! Spec 088 SC-005 end to end: a SwiftPM dependency swapped to its registry identity keeps its
//! source repository's license-policy findings and OSV scan target.
//!
//! Drives the real Swift ecosystem against mock servers: the user-tier registry answers the
//! `identifiers` lookup, the pre-fetch probe re-parses, the shared tier-3 license pre-fetch asks
//! GitHub for the repository's license, and the shared diagnostics pass evaluates the policy.

// #689: `clippy.toml`'s `allow-unwrap-in-tests` covers the `#[test]` function, not the setup
// helper, which unwraps known-good temp-directory I/O.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use deps_core::config_trust::OperatorPath;
use deps_core::diagnostic::DiagnosticKind;
use deps_core::lsp_helpers::{
    DiagnosticSeverities, LatestVerdict, PackageVersions, VersionData, latest_verdict,
};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::osv::{
    LatestStatusMap, OsvClient, ScanOutcome, StructuralSkipReason, UpgradeStatus, vuln_key_for,
};
use deps_core::policy_config::{FetchConcurrency, FetchTimeout, ScmToRegistry};
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, FreshnessSettings, HttpCache, LicensePolicy,
    NetworkMode, NormalizedName, PackageKey, PublishTime,
};
use deps_engine::classify::license::prefetch_tier3_licenses;
use deps_engine::classify::osv::build_scan_targets;
use deps_engine::classify::resolved::load_resolved_versions;
use deps_engine::probe::parse_with_pre_fetch_probes;
use deps_swift::config::UserConfigPath;
use deps_swift::{ScmToRegistryHandle, SwiftEcosystem, SwiftParseContext, SwiftRegistry};
use mockito::Matcher;

const MANIFEST: &str = r#".package(url: "https://github.com/Apple/Swift-NIO", from: "2.0.0")"#;

struct Setup {
    _dir: tempfile::TempDir,
    ecosystem: Arc<dyn Ecosystem>,
    uri: url::Url,
}

fn setup(registry_url: &str, github_url: &str, mode: ScmToRegistry) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let user_file = dir.path().join("user-registries.json");
    std::fs::write(
        &user_file,
        format!(r#"{{"registries": {{"[default]": {{"url": "{registry_url}"}}}}, "version": 1}}"#),
    )
    .unwrap();
    let context = SwiftParseContext::new(
        Arc::new(RegistryAccessPolicy::default()),
        Arc::default(),
        UserConfigPath::Path(OperatorPath::for_test(&user_file)),
        None,
    )
    .with_scm_to_registry(Arc::new(ScmToRegistryHandle::new(mode)));
    let registry = Arc::new(SwiftRegistry::for_test(
        Arc::new(HttpCache::new()),
        github_url,
    ));
    Setup {
        uri: url::Url::from_file_path(dir.path().join("Package.swift")).unwrap(),
        ecosystem: Arc::new(SwiftEcosystem::with_context(registry, context)),
        _dir: dir,
    }
}

#[tokio::test]
async fn swapped_dependency_keeps_osv_target_and_license_policy_findings() {
    let mut registry = mockito::Server::new_async().await;
    let mut github = mockito::Server::new_async().await;
    let identifiers = registry
        .mock("GET", "/identifiers")
        .match_query(Matcher::UrlEncoded(
            "url".into(),
            "https://github.com/Apple/Swift-NIO".into(),
        ))
        .with_status(200)
        .with_body(r#"{"identifiers": ["apple.swift-nio"]}"#)
        .expect(1)
        .create_async()
        .await;
    let license = github
        .mock("GET", "/repos/Apple/Swift-NIO")
        .with_status(200)
        .with_body(r#"{"license": {"spdx_id": "GPL-3.0"}}"#)
        .expect(1)
        .create_async()
        .await;
    let setup = setup(&registry.url(), &github.url(), ScmToRegistry::Replace);

    let (parsed, report) =
        parse_with_pre_fetch_probes(&setup.ecosystem, MANIFEST, &setup.uri, NetworkMode::Online)
            .await
            .unwrap();
    assert_eq!(report.effect, deps_core::lsp_helpers::ProbeEffect::Reparse);
    let dependencies = parsed.dependencies();
    assert_eq!(dependencies[0].name().as_str(), "apple.swift-nio");

    let key = NormalizedName::for_test("apple.swift-nio");
    let resolved = HashMap::from([(key.clone(), ConcreteVersion::from("2.65.0"))]);
    let candidates = HashMap::new();

    let (targets, skipped) = build_scan_targets(
        parsed.as_ref(),
        &resolved,
        &candidates,
        setup.ecosystem.formatter(),
        EcosystemId::Swift,
    );
    assert!(
        skipped.is_empty(),
        "swapped dependency must stay scannable: {skipped:?}"
    );
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].osv_name.name().as_str(),
        "github.com/Apple/Swift-NIO",
        "OSV is queried under the repository, case preserved"
    );

    let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);
    let fetched = prefetch_tier3_licenses(
        setup.ecosystem.as_ref(),
        parsed.as_ref(),
        &resolved,
        &candidates,
        &policy,
        FetchTimeout::DEFAULT,
        FetchConcurrency::DEFAULT,
    )
    .await;
    assert_eq!(
        fetched.licenses.get(&key),
        Some(&vec!["GPL-3.0".to_string()]),
        "requested under owner/repo, stored under the dependency's own key"
    );

    let cached = HashMap::from([(key, PackageVersions::latest_only("2.65.0"))]);
    let diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
        parsed.as_ref(),
        VersionData::new(&cached, &resolved)
            .with_license_prefetch(&fetched.licenses)
            .with_license_policy(&policy),
        setup.ecosystem.formatter(),
        &setup.uri,
        FreshnessSettings::default(),
        DiagnosticSeverities::default(),
        PublishTime::now(),
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| matches!(d.kind(), DiagnosticKind::LicensePolicy)),
        "the deny-list must fire for the swapped dependency: {diagnostics:?}"
    );

    identifiers.assert_async().await;
    license.assert_async().await;
}

async fn identifiers_mock(registry: &mut mockito::ServerGuard) -> mockito::Mock {
    registry
        .mock("GET", "/identifiers")
        .match_query(Matcher::UrlEncoded(
            "url".into(),
            "https://github.com/Apple/Swift-NIO".into(),
        ))
        .with_status(200)
        .with_body(r#"{"identifiers": ["apple.swift-nio"]}"#)
        .create_async()
        .await
}

/// US-003 / SC-005: the same advisory is reported before and after the swap, because OSV is
/// asked about the same repository name (case preserved) either way.
#[tokio::test]
async fn the_same_advisory_matches_before_and_after_the_swap() {
    let mut registry = mockito::Server::new_async().await;
    let github = mockito::Server::new_async().await;
    let _identifiers = identifiers_mock(&mut registry).await;
    let mut osv = mockito::Server::new_async().await;
    let batch = osv
        .mock("POST", "/v1/querybatch")
        .match_body(Matcher::Regex(r#""name":"github\.com/Apple/Swift-NIO""#.into()))
        .with_status(200)
        .with_body(
            r#"{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","modified":"2023-01-01T00:00:00Z"}]}]}"#,
        )
        .expect(2)
        .create_async()
        .await;
    let _record = osv
        .mock("GET", "/v1/vulns/GHSA-aaaa-bbbb-cccc")
        .with_status(200)
        .with_body(
            r#"{"id":"GHSA-aaaa-bbbb-cccc","modified":"2023-01-01T00:00:00Z","summary":"s",
               "database_specific":{"severity":"HIGH"},
               "affected":[{"package":{"name":"github.com/Apple/Swift-NIO","ecosystem":"SwiftURL"},
                 "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.70.0"}]}]}]}"#,
        )
        .expect_at_least(1)
        .create_async()
        .await;
    let key = NormalizedName::for_test("apple/swift-nio");
    let resolved = HashMap::from([(key, ConcreteVersion::from("2.65.0"))]);
    let candidates = HashMap::new();

    let mut advisories = Vec::new();
    for mode in [ScmToRegistry::Disabled, ScmToRegistry::Replace] {
        let setup = setup(&registry.url(), &github.url(), mode);
        let (parsed, _) = parse_with_pre_fetch_probes(
            &setup.ecosystem,
            MANIFEST,
            &setup.uri,
            NetworkMode::Online,
        )
        .await
        .unwrap();
        let name = parsed.dependencies()[0].name().as_str().to_string();
        let resolved = if mode == ScmToRegistry::Replace {
            assert_eq!(name, "apple.swift-nio");
            HashMap::from([(
                NormalizedName::for_test("apple.swift-nio"),
                ConcreteVersion::from("2.65.0"),
            )])
        } else {
            resolved.clone()
        };
        let (targets, _) = build_scan_targets(
            parsed.as_ref(),
            &resolved,
            &candidates,
            setup.ecosystem.formatter(),
            EcosystemId::Swift,
        );
        assert_eq!(targets.len(), 1, "{mode:?}");
        assert_eq!(
            targets[0].osv_name.name().as_str(),
            "github.com/Apple/Swift-NIO",
            "{mode:?}"
        );
        // A fresh client per mode, so the second scan reaches the mock instead of the query cache.
        let client = OsvClient::for_test(Arc::new(HttpCache::new()), osv.url());
        let outcomes = client
            .scan(EcosystemId::Swift, &targets, Duration::from_secs(5))
            .await;
        let Some(ScanOutcome::Vulnerable(found)) = outcomes.get(&targets[0].key) else {
            panic!("{mode:?}: expected a vulnerable outcome, got {outcomes:?}");
        };
        advisories.push(
            found
                .advisories
                .items()
                .iter()
                .map(|advisory| advisory.id().as_str().to_string())
                .collect::<Vec<_>>(),
        );
    }

    assert_eq!(advisories[0], advisories[1]);
    assert_eq!(advisories[0], ["GHSA-aaaa-bbbb-cccc"]);
    batch.assert_async().await;
}

/// FR-023 / SC-006: until phase B records an answer for the swapped dependency, its latest
/// verdict is `Unverified` (never the fail-open `NotApplicable`), including when a structural
/// skip recorded while it was still a source-control dependency is left in the map.
#[tokio::test]
async fn a_swapped_dependency_is_unverified_until_phase_b_answers() {
    let mut registry = mockito::Server::new_async().await;
    let github = mockito::Server::new_async().await;
    let _identifiers = identifiers_mock(&mut registry).await;
    let setup = setup(&registry.url(), &github.url(), ScmToRegistry::Replace);
    let (parsed, _) =
        parse_with_pre_fetch_probes(&setup.ecosystem, MANIFEST, &setup.uri, NetworkMode::Online)
            .await
            .unwrap();
    let dependencies = parsed.dependencies();
    let dep = dependencies[0];
    let formatter = setup.ecosystem.formatter();
    let package_key = PackageKey::new(dep.name(), formatter);
    let vuln_key = vuln_key_for(dep, None, formatter);
    let verdict = |map: &LatestStatusMap| {
        latest_verdict(Some(map), dep, None, &package_key, "2.65.0", formatter)
    };

    assert_eq!(verdict(&LatestStatusMap::new()), LatestVerdict::Unverified);

    let stale = LatestStatusMap::from([(
        vuln_key.clone(),
        UpgradeStatus::StructurallyUnchecked(StructuralSkipReason::NonRegistrySource),
    )]);
    assert_eq!(verdict(&stale), LatestVerdict::Unverified);

    let answered = LatestStatusMap::from([(
        vuln_key,
        UpgradeStatus::CandidateClean {
            version: ConcreteVersion::from("2.65.0"),
        },
    )]);
    assert_eq!(verdict(&answered), LatestVerdict::Verified);
}

/// FR-018 (live finding): a `remoteSourceControl` pin, spelled with different case and a `.git`
/// suffix, gives the swapped dependency its in-use version.
#[tokio::test]
async fn a_source_control_pin_gives_the_swapped_dependency_its_in_use_version() {
    let mut registry = mockito::Server::new_async().await;
    let github = mockito::Server::new_async().await;
    let _identifiers = identifiers_mock(&mut registry).await;
    let setup = setup(&registry.url(), &github.url(), ScmToRegistry::Replace);
    std::fs::write(
        setup
            .uri
            .to_file_path()
            .unwrap()
            .with_file_name("Package.resolved"),
        r#"{"version": 2, "pins": [{"identity": "swift-nio", "kind": "remoteSourceControl",
            "location": "https://github.com/apple/swift-nio.git",
            "state": {"version": "2.65.0", "revision": "abc"}}]}"#,
    )
    .unwrap();
    let cache = Arc::new(deps_core::lockfile::LockFileCache::new());

    let before = load_resolved_versions(&setup.uri, &cache, setup.ecosystem.as_ref())
        .await
        .into_maps()
        .0;
    assert!(!before.contains_key(&NormalizedName::for_test("apple.swift-nio")));

    parse_with_pre_fetch_probes(&setup.ecosystem, MANIFEST, &setup.uri, NetworkMode::Online)
        .await
        .unwrap();
    let after = load_resolved_versions(&setup.uri, &cache, setup.ecosystem.as_ref())
        .await
        .into_maps()
        .0;

    assert_eq!(
        after.get(&NormalizedName::for_test("apple.swift-nio")),
        Some(&ConcreteVersion::from("2.65.0"))
    );
    assert_eq!(
        after.get(&NormalizedName::for_test("apple/swift-nio")),
        Some(&ConcreteVersion::from("2.65.0")),
        "the source-control name still resolves for a dependency that stays on source control"
    );
}
