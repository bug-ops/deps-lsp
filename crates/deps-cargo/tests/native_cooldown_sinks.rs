//! #1982 / spec 099 Phase 1 acceptance: the read-time native gate (`NativeGate`) and its
//! explain-only effect on diagnostics, hover and the update planners, driven through the real
//! Cargo ecosystem with a controllable clock (`VersionData::with_now`, plan v4 item 6).
//!
//! Scenario: `rmcp = "=3.8.0"`, `[registry] global-min-publish-age = "7 days"`, registry list
//! `3.9.0` (published 3 days before `T0`) and `3.8.0` (long ago).

#![cfg(feature = "lsp-responses")]
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::assert_matches;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use deps_cargo::CargoEcosystem;
use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::CargoParseContext;
use deps_core::edit::{UnplannableReason, UpdateCandidate};
use deps_core::lsp_helpers::{DiagnosticSeverities, LockCandidates};
use deps_core::native_cooldown::{NativeGate, NativeHold};
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, FreshnessSettings, HttpCache, NetworkMode, PackageKey,
    PackageName, PackageVersions, ParsedManifest, PublishTime, VersionData,
};
use tower_lsp_server::ls_types::Position;
use url::Url;

const DAY: i64 = 86_400;
const T0: i64 = 1_800_000_000;
const MANIFEST: &str = "[dependencies]\nrmcp = \"=3.8.0\"\n";
const HELD_NOTE: &str = "excluded by cargo registry.global-min-publish-age = 7 days";

fn t(secs: i64) -> PublishTime {
    PublishTime::from_unix_secs(secs)
}

fn cv(raw: &str) -> ConcreteVersion {
    ConcreteVersion::new(raw)
}

struct Fx {
    _dir: tempfile::TempDir,
    uri: Url,
    manifest: Box<dyn ParsedManifest>,
}

/// Hover fetches the live list regardless of the network mode: point the registry at a
/// refused loopback port so the tests stay hermetic and fall back to the cached data.
const UNREACHABLE_MIRROR: &str = "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+http://127.0.0.1:1/\"\n";

async fn fixture(config: Option<&str>) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    write(
        &root.join(".cargo/config.toml"),
        &format!("{UNREACHABLE_MIRROR}{}", config.unwrap_or_default()),
    );
    let path = root.join("Cargo.toml");
    write(&path, MANIFEST);
    let uri = Url::from_file_path(&path).unwrap();
    let ctx = CargoParseContext::new(
        Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
        Arc::new(ConfigFileCache::new()),
    )
    .with_native_cooldown(NativeCooldownMode::Honor);
    let eco = Arc::new(CargoEcosystem::with_context(
        Arc::new(HttpCache::new()),
        ctx,
    ));
    let manifest = Ecosystem::parse_manifest(eco, MANIFEST, &uri)
        .await
        .unwrap();
    Fx {
        _dir: dir,
        uri,
        manifest,
    }
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

const WINDOW_CONFIG: &str = "[registry]\nglobal-min-publish-age = \"7 days\"\n";

/// Registry data: `3.9.0` published `3 * DAY` before `T0`, `3.8.0` published 100 days before.
fn registry_data(
    fx: &Fx,
    latest_published: Option<i64>,
) -> HashMap<deps_core::NormalizedName, PackageVersions> {
    let key = PackageKey::new(&PackageName::new("rmcp"), fx.manifest.formatter());
    let mut versions = PackageVersions::new(cv("3.9.0"), Arc::from(vec![cv("3.9.0"), cv("3.8.0")]));
    if let Some(published) = latest_published {
        versions = versions
            .with_published_at(t(published))
            .with_publish_times(Arc::from(vec![Some(t(published)), Some(t(T0 - 100 * DAY))]));
    }
    HashMap::from([(key.normalized().clone(), versions)])
}

struct Locks {
    resolved: HashMap<deps_core::NormalizedName, ConcreteVersion>,
    candidates: HashMap<deps_core::NormalizedName, LockCandidates>,
}

fn locks(fx: &Fx, resolved: &str, all: &[&str]) -> Locks {
    let key = PackageKey::new(&PackageName::new("rmcp"), fx.manifest.formatter());
    Locks {
        resolved: HashMap::from([(key.normalized().clone(), cv(resolved))]),
        candidates: HashMap::from([(
            key.normalized().clone(),
            LockCandidates::from(all.iter().map(|v| cv(v)).collect::<Vec<_>>()),
        )]),
    }
}

fn data<'a>(
    cached: &'a HashMap<deps_core::NormalizedName, PackageVersions>,
    locks: &'a Locks,
    now: i64,
) -> VersionData<'a> {
    VersionData::new(cached, &locks.resolved)
        .with_resolved_version_candidates(&locks.candidates)
        .with_ecosystem(EcosystemId::Cargo)
        .with_network(NetworkMode::Offline)
        .with_now(t(now))
}

async fn diagnostics(fx: &Fx, versions: VersionData<'_>) -> Vec<String> {
    fx.manifest
        .generate_diagnostics(
            versions,
            &fx.uri,
            FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        )
        .await
        .iter()
        .map(|d| d.message().to_owned())
        .collect()
}

async fn hover(fx: &Fx, versions: VersionData<'_>) -> String {
    let hover = fx
        .manifest
        .generate_hover(Position::new(1, 2), versions, FreshnessSettings::default())
        .await;
    hover
        .expect("hover on dependency name")
        .markdown()
        .to_owned()
}

/// Guards "stays eligible" tests against passing vacuously: with publish times, the plain
/// lock and the same instant, the latest must be reported held.
async fn assert_control_is_held(fx: &Fx) {
    let cached = registry_data(fx, Some(T0 - 3 * DAY));
    let l = locks(fx, "3.8.0", &["3.8.0"]);
    let messages = diagnostics(fx, data(&cached, &l, T0)).await;
    assert_eq!(
        held_notes(&messages).len(),
        1,
        "control must be held: {messages:?}"
    );
}

fn held_notes(messages: &[String]) -> Vec<&String> {
    messages.iter().filter(|m| m.contains(HELD_NOTE)).collect()
}

fn planned_count(fx: &Fx, versions: VersionData<'_>) -> usize {
    fx.manifest
        .collect_update_candidates(MANIFEST, versions)
        .iter()
        .filter(|c| matches!(c, UpdateCandidate::Planned(_)))
        .count()
}

// ---- NativeGate ----------------------------------------------------------------------------

#[tokio::test]
async fn native_gate_for_dependency_is_none_without_a_window() {
    let fx = fixture(None).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    let versions = data(&cached, &l, T0);
    let key = PackageKey::new(&PackageName::new("rmcp"), fx.manifest.formatter());
    let mut seen = 0;
    fx.manifest.for_each_formatted_dependency(&mut |dep| {
        seen += 1;
        assert!(NativeGate::for_dependency(dep.dependency(), &key, &versions).is_none());
    });
    assert_eq!(seen, 1);
}

#[tokio::test]
async fn native_gate_excludes_within_window_and_releases_exactly_at_min_age() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    let published = T0 - 3 * DAY;
    let cached = registry_data(&fx, Some(published));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    let versions = data(&cached, &l, T0);
    let key = PackageKey::new(&PackageName::new("rmcp"), fx.manifest.formatter());
    fx.manifest.for_each_formatted_dependency(&mut |dep| {
        let gate = NativeGate::for_dependency(dep.dependency(), &key, &versions).expect("window");
        let v = cv("3.9.0");
        let p = Some(t(published));
        assert!(gate.excludes(p, &v, t(published + 7 * DAY - 1)));
        assert!(
            !gate.excludes(p, &v, t(published + 7 * DAY)),
            "exactly min age is eligible"
        );
        assert_eq!(
            gate.hold(p, &v, t(published + 7 * DAY - 10)),
            Some(NativeHold::For(10))
        );
        assert_eq!(gate.hold(p, &v, t(published + 7 * DAY)), None);
        assert!(
            !gate.excludes(None, &v, t(published)),
            "no publish time is eligible"
        );
        assert!(
            gate.excludes(Some(t(T0 + 1000)), &v, t(T0)),
            "future publish time is excluded"
        );
    });
}

// ---- diagnostics / hover / planners: explain-only -----------------------------------------

#[tokio::test]
async fn held_latest_is_explained_in_the_outdated_diagnostic_and_hover_names_the_true_latest() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);

    let messages = diagnostics(&fx, data(&cached, &l, T0)).await;
    let held = held_notes(&messages);
    assert_eq!(held.len(), 1, "{messages:?}");
    assert!(
        held[0].contains("3.9.0") && held[0].contains("eligible in"),
        "{held:?}"
    );

    let hover = hover(&fx, data(&cached, &l, T0)).await;
    assert!(
        hover.contains(HELD_NOTE) && hover.contains("eligible in"),
        "{hover}"
    );
    assert!(
        hover.contains("**Latest**: `3.9.0`"),
        "latest is never rewritten: {hover}"
    );
}

#[tokio::test]
async fn held_latest_is_never_planned_and_is_reported_as_within_native_cooldown() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    let candidates = fx
        .manifest
        .collect_update_candidates(MANIFEST, data(&cached, &l, T0));
    assert_eq!(candidates.len(), 1);
    assert_matches!(
        &candidates[0],
        UpdateCandidate::Unplannable {
            reason: UnplannableReason::WithinNativeCooldown,
            ..
        }
    );
    assert!(
        fx.manifest
            .collect_update_all_edits(MANIFEST, data(&cached, &l, T0))
            .is_empty()
    );
}

#[tokio::test]
async fn single_instant_flips_diagnostic_hover_candidates_and_lens_together() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    let published = T0 - 3 * DAY;
    let cached = registry_data(&fx, Some(published));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);

    let before = T0;
    let after = published + 7 * DAY;
    assert_eq!(
        held_notes(&diagnostics(&fx, data(&cached, &l, before)).await).len(),
        1
    );
    assert!(
        hover(&fx, data(&cached, &l, before))
            .await
            .contains(HELD_NOTE)
    );
    assert_eq!(planned_count(&fx, data(&cached, &l, before)), 0);
    assert!(
        fx.manifest
            .collect_update_all_edits(MANIFEST, data(&cached, &l, before))
            .is_empty()
    );

    assert!(held_notes(&diagnostics(&fx, data(&cached, &l, after)).await).is_empty());
    assert!(
        !hover(&fx, data(&cached, &l, after))
            .await
            .contains(HELD_NOTE)
    );
    assert_eq!(planned_count(&fx, data(&cached, &l, after)), 1);
    assert_eq!(
        fx.manifest
            .collect_update_all_edits(MANIFEST, data(&cached, &l, after))
            .len(),
        1
    );
}

#[tokio::test]
async fn version_without_publish_time_is_eligible() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    assert_control_is_held(&fx).await;
    let cached = registry_data(&fx, None);
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    assert!(held_notes(&diagnostics(&fx, data(&cached, &l, T0)).await).is_empty());
    assert_eq!(planned_count(&fx, data(&cached, &l, T0)), 1);
}

#[tokio::test]
async fn version_listed_in_the_lock_file_stays_eligible() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    assert_control_is_held(&fx).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.9.0", &["3.9.0"]);
    assert!(held_notes(&diagnostics(&fx, data(&cached, &l, T0)).await).is_empty());
    assert!(!hover(&fx, data(&cached, &l, T0)).await.contains(HELD_NOTE));
}

/// FR-006: a transitive duplicate (candidates only, not the collapsed resolved version).
#[tokio::test]
async fn version_present_only_among_lock_candidates_stays_eligible() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    assert_control_is_held(&fx).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.8.0", &["3.8.0", "3.9.0"]);
    assert!(held_notes(&diagnostics(&fx, data(&cached, &l, T0)).await).is_empty());
    assert_eq!(planned_count(&fx, data(&cached, &l, T0)), 1);
}

/// S2: the lock set is read at read time, never captured at fetch time.
#[tokio::test]
async fn lock_change_without_refetch_lifts_the_hold_everywhere() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let old_lock = locks(&fx, "3.8.0", &["3.8.0"]);
    let new_lock = locks(&fx, "3.9.0", &["3.9.0"]);

    assert_eq!(
        held_notes(&diagnostics(&fx, data(&cached, &old_lock, T0)).await).len(),
        1
    );
    assert!(
        hover(&fx, data(&cached, &old_lock, T0))
            .await
            .contains(HELD_NOTE)
    );

    assert!(held_notes(&diagnostics(&fx, data(&cached, &new_lock, T0)).await).is_empty());
    assert!(
        !hover(&fx, data(&cached, &new_lock, T0))
            .await
            .contains(HELD_NOTE)
    );
}

#[tokio::test]
async fn no_window_output_is_identical_whatever_the_publish_times() {
    let fx = fixture(None).await;
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    let with_times = registry_data(&fx, Some(T0 - 3 * DAY));
    let without_times = registry_data(&fx, None);
    let a = diagnostics(&fx, data(&with_times, &l, T0)).await;
    let b = diagnostics(&fx, data(&without_times, &l, T0)).await;
    assert_eq!(a, b);
    assert!(held_notes(&a).is_empty());
}

#[tokio::test]
async fn only_the_held_latest_is_gated_an_older_registry_version_is_not_reported_held() {
    let fx = fixture(Some(WINDOW_CONFIG)).await;
    assert_control_is_held(&fx).await;
    let cached = registry_data(&fx, Some(T0 - 3 * DAY));
    let l = locks(&fx, "3.8.0", &["3.8.0"]);
    let messages = diagnostics(&fx, data(&cached, &l, T0)).await;
    assert!(
        messages
            .iter()
            .all(|m| !m.contains("3.8.0") || !m.contains(HELD_NOTE)),
        "{messages:?}"
    );
}
