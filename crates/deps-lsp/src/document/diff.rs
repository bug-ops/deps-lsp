//! Dependency diffing and cache reconciliation between successive
//! parses of a manifest.

use super::state::{DocumentState, ServerState};
use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::FetchFailure;
use deps_core::PackageName;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};
use tower_lsp_server::ls_types::Uri;

/// Preserves cached version data from old document state to new state.
/// Called during document updates to avoid re-fetching versions for unchanged deps.
pub(crate) fn preserve_cache(new_state: &mut DocumentState, old_state: &DocumentState) {
    tracing::trace!(
        cached = old_state.cached_versions.len(),
        resolved = old_state.resolved_versions.len(),
        vulnerabilities = old_state.vulnerabilities.len(),
        outcomes_yanked = old_state.outcomes.yanked_count(),
        outcomes_deprecated = old_state.outcomes.deprecation_count(),
        outcomes_fetch_failed = old_state.outcomes.fetch_failure_count(),
        "preserving version cache"
    );
    new_state
        .cached_versions
        .clone_from(&old_state.cached_versions);
    new_state
        .resolved_versions
        .clone_from(&old_state.resolved_versions);
    // Must travel with `resolved_versions` (issue #649 critic S1): a per-occurrence
    // resolution that only preserved the collapsed map while resetting this sibling to
    // empty would silently reintroduce the mis-attribution bug for the ~100ms debounce +
    // lockfile-reload window on every keystroke, since `resolve_occurrence_version` only
    // consults the candidates map when it is populated.
    new_state
        .resolved_version_candidates
        .clone_from(&old_state.resolved_version_candidates);
    // Must also travel with `resolved_versions` (issue #1395 bidirectional-race finding):
    // `resolved_versions_generation` is a per-document epoch counter guarding
    // `run_osv_phase_b_and_commit`'s staleness check — resetting it to 0 on every
    // keystroke-triggered rebuild (DocumentState is rebuilt on every change, not mutated
    // in place) would desync it from the `resolved_versions` value it's meant to guard,
    // letting an in-flight scan's stale generation snapshot coincidentally match the
    // freshly-reset counter and commit over newer data, or a fresh scan's post-bump
    // generation collide with an unrelated earlier scan's snapshot.
    new_state.resolved_versions_generation = old_state.resolved_versions_generation;
    // DocumentState is rebuilt on every change, so without this the OSV scan
    // result would be wiped on every keystroke — `run_osv_scan` overwrites it
    // once the (cheap, cache-backed) rescan completes, see §4.
    new_state
        .vulnerabilities
        .clone_from(&old_state.vulnerabilities);
    // Same rationale as `vulnerabilities` above — without this the yanked/deprecation/
    // fetch-failure diagnostics would flicker off on every keystroke until the next fetch
    // (or, for a registry-outage package, flip back to a misleading "Unknown package"
    // diagnostic until the next fetch cycle re-populates it, #267).
    new_state.outcomes.clone_from(&old_state.outcomes);
    // Same rationale again (issue #660): without this, a tier-3 ecosystem's hover
    // license would flicker off on every keystroke until `run_license_prefetch`'s next
    // background pass re-populates it.
    new_state.licenses.clone_from(&old_state.licenses);
    // Same rationale again (issue #1437): without this, the typosquat diagnostic would
    // flicker off on every keystroke until `run_typosquat_prefetch`'s next background pass
    // re-populates it.
    new_state.typosquats.clone_from(&old_state.typosquats);
}

/// Drops previously cached version and fetch-failure data ahead of a forced re-fetch
/// (`RefetchPolicy::AllDependencies`, issue #592): the routing itself changed, so data
/// obtained under the old routing can no longer be vouched for. Leaves
/// `resolved_versions` (lockfile-derived, registry-independent) and `vulnerabilities`
/// (OSV is registry-independent) untouched — dropping either would flicker diagnostics
/// off for no security benefit.
///
/// **Critic S1 fix**: every dependency in `deps_to_fetch` is marked
/// [`FetchFailure::NotAttempted`] rather than left with no outcome entry at all. The gap
/// this closes: the real fetch this drop precedes doesn't complete synchronously (it's
/// behind a 100ms debounce plus network latency), so a concurrent or subsequent plain edit
/// with unchanged content (`RefetchPolicy::Diff`, empty diff) can commit and
/// `preserve_cache` forward the just-cleared state before the fetch ever merges real
/// results. Without a placeholder, that commit's `outcomes` would have no entry at all for
/// the dropped dependency — indistinguishable from "checked, nothing found" — and
/// `handlers::diagnostics`' R5 rule renders that as the misleading "Unknown package"
/// instead of "registry lookup failed" (the same class of bug #267 introduced
/// `fetch_failed` to prevent in the first place). The placeholder is superseded the moment
/// the real fetch completes: `merge_registry_fetch_result` calls `set_fetch_failure`
/// (unconditional overwrite) for a genuine failure or inserts into `cached_versions` for a
/// success, and a dependency with a `cached_versions` entry never reaches the R5 rule this
/// placeholder guards regardless of what `outcomes` still says.
pub(crate) fn drop_cache_for_forced_refetch(
    doc: &mut DocumentState,
    deps_to_fetch: &[PackageName],
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    doc.cached_versions.clear();
    doc.outcomes.clear_all_fetch_failures();
    for name in deps_to_fetch {
        doc.outcomes.set_fetch_failure_if_absent(
            formatter.normalize_package_name(name),
            FetchFailure::NotAttempted,
        );
    }
}

/// Diff between old and new dependency sets.
///
/// `version_changed` exists because [`Self::added`]/[`Self::removed`] alone
/// are name-set diffs: editing a dependency's version requirement in place
/// (e.g. `time = "0.1.43"` -> `"0.1.44"`) changes neither set, so gating the
/// OSV rescan on `added` alone would silently skip re-scanning the one
/// dependency whose version just changed (critique S1).
#[derive(Debug, Clone, Default)]
pub(crate) struct DependencyDiff {
    pub(crate) added: Vec<PackageName>,
    pub(crate) removed: Vec<PackageName>,
    pub(crate) version_changed: Vec<PackageName>,
}

impl DependencyDiff {
    /// `old`/`new` map each dependency name to the declared version
    /// requirements (`Dependency::version_requirement()`) of *every*
    /// occurrence of that name at parse time — not a single collapsed value.
    /// A name can appear more than once within a manifest: the same crate
    /// declared under both `[dependencies]`/`[dev-dependencies]`, or under
    /// two different `[target.'cfg(...)'.dependencies]` blocks (see #394).
    /// Comparing the full per-name `Vec` rather than a name-keyed single
    /// requirement ensures an edit to *any* occurrence changes the value the
    /// diff compares, instead of silently no-opping when a HashMap collapse
    /// would have kept the "winning" occurrence's requirement unchanged.
    ///
    /// Occurrence order within a `Vec` is deterministic per parser but is
    /// **not** necessarily document/source order — e.g. `deps-cargo` walks
    /// `toml_span::Table`, a `BTreeMap` ordered by key, so multiple
    /// `[target.*]` blocks come out sorted by their cfg-expression string,
    /// not by which one appears first in the file. This only affects which
    /// index an occurrence lands at (never which name it's grouped under),
    /// so it cannot cause a missed or misattributed diff — see
    /// `dependency_version_map`'s doc for the consequence of reordering
    /// across an edit.
    pub(crate) fn compute(
        old: &HashMap<PackageName, Vec<Option<VersionReq>>>,
        new: &HashMap<PackageName, Vec<Option<VersionReq>>>,
    ) -> Self {
        let old_names: HashSet<&PackageName> = old.keys().collect();
        let new_names: HashSet<&PackageName> = new.keys().collect();

        let added = new_names
            .difference(&old_names)
            .map(|s| (*s).clone())
            .collect();
        let removed = old_names
            .difference(&new_names)
            .map(|s| (*s).clone())
            .collect();
        let version_changed = new_names
            .intersection(&old_names)
            .filter(|name| old.get(**name) != new.get(**name))
            .map(|s| (*s).clone())
            .collect();

        Self {
            added,
            removed,
            version_changed,
        }
    }

    /// Whether the registry fetch (and therefore the yanked-version probe,
    /// #233) has any reason to run: a new dependency, or an existing one
    /// whose declared version changed. A version-only edit still needs the
    /// fetch — the "latest" value itself does not change, but a dependency
    /// edited from a safe pin to a yanked one (or vice versa) must be
    /// re-probed against its new in-use version, and any stale finding
    /// against the *old* version must not linger (security F1 / impl-critic
    /// S1).
    #[cfg(all(test, feature = "cargo"))]
    pub(crate) fn needs_fetch(&self) -> bool {
        !self.added.is_empty() || !self.version_changed.is_empty()
    }

    /// Whether the OSV rescan (§4) has any reason to run: a new dependency,
    /// or an existing one whose declared version changed. Identical to
    /// `Self::needs_fetch` today (both gate on `added`/`version_changed`);
    /// kept as separate methods since they answer different questions and
    /// could diverge again if either gate changes independently.
    pub(crate) fn needs_osv_rescan(&self) -> bool {
        !self.added.is_empty() || !self.version_changed.is_empty()
    }
}

/// Which of `deps` had their in-use version newly resolved or changed by a lock-file-only
/// reload (no manifest edit, so no [`DependencyDiff`] exists to consult) — the
/// `handle_lockfile_change` counterpart of [`DependencyDiff::needs_osv_rescan`] (issue
/// #1395). Empty means no dependency's in-use version moved.
///
/// Compares each dependency *occurrence* via [`deps_core::lsp_helpers::resolve_in_use_version`]
/// — the exact same policy OSV target selection ([`deps_engine::classify::osv::build_scan_targets`])
/// consults — rather than a raw `dep.name()` lookup against the collapsed `resolved_versions`
/// map (issue #1395 critic S1). A raw-name lookup misses two real cases: an ecosystem whose
/// lock file key is normalized differently from the manifest's declared name (e.g. Poetry's
/// `Django` manifest key vs. `poetry.lock`'s PEP 503-normalized `django`), and a name with
/// more than one retained lock-file entry (issue #649), where the collapsed `resolved_versions`
/// value is an arbitrary "highest" pick that can stay unchanged while the occurrence's own
/// per-requirement-disambiguated selection moves.
///
/// `old_resolved`/`old_candidates` and `new_resolved`/`new_candidates` are a document's
/// [`super::state::DocumentState::resolved_versions`]/[`super::state::DocumentState::resolved_version_candidates`]
/// before and after [`super::state::DocumentState::update_resolved_versions`].
///
/// The returned names are also what [`reload_resolved_versions`] evicts from
/// [`super::state::DocumentState::licenses`] (issue #1424): a dependency whose in-use version
/// just moved can no longer vouch for its previously cached license.
pub(crate) fn resolved_versions_changed(
    deps: &[&dyn Dependency],
    old_resolved: &HashMap<PackageName, ConcreteVersion>,
    old_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    new_resolved: &HashMap<PackageName, ConcreteVersion>,
    new_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem_id: EcosystemId,
) -> Vec<PackageName> {
    deps.iter()
        .filter_map(|dep| {
            let normalized = formatter.normalize_package_name(dep.name());
            let old = deps_core::lsp_helpers::resolve_in_use_version(
                *dep,
                &normalized,
                old_resolved,
                Some(old_candidates),
                formatter,
                ecosystem_id,
            );
            let new = deps_core::lsp_helpers::resolve_in_use_version(
                *dep,
                &normalized,
                new_resolved,
                Some(new_candidates),
                formatter,
                ecosystem_id,
            );
            (old != new).then(|| dep.name().clone())
        })
        .collect()
}

/// Writes a freshly-reloaded `resolved_versions`/`resolved_version_candidates` pair into
/// `uri`'s document and reports whether a resolved-version move was detected — shared by
/// `server::handle_lockfile_change` and `document::lifecycle::run_document_change_task`
/// (issue #1398/#1399 code review: keeps their drift-detection-and-write sequence from
/// silently diverging, exactly the bug class #1398/#1399 themselves exist to close).
///
/// Both callers only ever call this once they already know the reload itself succeeded
/// (`lockfile_reload_ok` on the lock-file-watcher path, the debounced-edit path's own
/// equivalent check) — a caller that hasn't reached that point yet simply doesn't call this
/// function at all, rather than calling it with a flag telling it to skip its own drift
/// comparison. Returns whether a resolved-version move was detected.
///
/// Deliberately does **not** bump `resolved_versions_generation` itself (issue #1407
/// code-review reconciliation with #1410): the bump decision needs the caller's own
/// manifest-diff-level trigger too (`document::lifecycle::change_task_triggers`'
/// `diff_needs_rescan`), not just this function's own drift verdict, and — since #1407 —
/// also needs an ecosystem/license-policy gate this generic diff-and-write primitive has
/// no business knowing about. Every caller must compute its own bump-worthiness from this
/// return value (typically via `change_task_triggers`) and call
/// `DocumentState::bump_resolved_generation` itself.
///
/// The drift comparison runs under a *shared* read lock on the document (via
/// [`ServerState::with_document`]), not the exclusive lock the write below needs — issue
/// #1399 code-review finding: [`resolved_versions_changed`] allocates and compares once per
/// dependency, which would otherwise hold an exclusive DashMap shard lock (blocking every
/// other document sharing that shard, including concurrent hover/completion reads) for the
/// duration. The write itself (unconditional map replace) still happens under one exclusive
/// lock acquisition, so `resolved_versions` can never desync relative to *this* call's own
/// write — a concurrent writer for the same URI landing between the read and the write can
/// only make this call's drift verdict imprecise, a narrow, already-tolerated window (see
/// `server::handle_lockfile_change`'s critic M4 "Known limitation" comment for the same class
/// of tolerated staleness), never violate that invariant.
///
/// Also evicts [`super::state::DocumentState::licenses`] for every dependency whose in-use
/// version moved, but only for an ecosystem whose
/// <code>ecosystem.[license_source](deps_core::Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// is `true` (issue #1424, resolving the prior `TODO(critic)` on
/// [`super::state::DocumentState::merge_licenses`]) — done synchronously, in the same write
/// that lands the fresh resolved-version maps, so a subsequent tier-3 re-fetch that fails
/// this round leaves the license correctly absent instead of silently misattributing the
/// *previous* version's license to the new one. Deliberately **not** evicted for a
/// `RegistryDeclaredSpdx` ecosystem (PyPI/Composer's tier-1 backfill, `merge_licenses`'s
/// other caller): that license is the registry's latest-matching pick, not tied to the
/// resolved version in the first place, and — unlike the tier-3 case — is never re-fetched
/// on a lock-file-only change (`change_task_triggers`' `requires_dedicated_fetch` gate), so
/// evicting it here would just delete valid, still-displayable data with nothing to
/// repopulate it until the next manifest edit or document reopen.
pub(crate) fn reload_resolved_versions(
    uri: &Uri,
    state: &ServerState,
    ecosystem: &dyn Ecosystem,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
) -> bool {
    let changed_names: Vec<PackageName> = state
        .with_document(uri, |doc| {
            doc.parse_result().map(|parse_result| {
                let deps = parse_result.dependencies();
                resolved_versions_changed(
                    &deps,
                    &doc.resolved_versions,
                    &doc.resolved_version_candidates,
                    resolved_versions,
                    resolved_version_candidates,
                    ecosystem.formatter(),
                    ecosystem.ecosystem_id(),
                )
            })
        })
        .flatten()
        .unwrap_or_default();

    if let Some(mut doc) = state.documents.get_mut(uri) {
        if ecosystem.license_source().requires_dedicated_fetch() {
            doc.evict_licenses(&changed_names);
        }
        doc.set_resolved_versions_without_bump(
            resolved_versions.clone(),
            resolved_version_candidates.clone(),
        );
    }

    !changed_names.is_empty()
}

// The single `incremental_fetch_tests` module below is gated on `feature = "cargo"` (it
// parses Cargo.toml manifests), and it is `mod tests`'s only content — so these imports (used
// exclusively by that module) are unused, and this whole module unreachable, without it.
#[cfg(all(test, feature = "cargo"))]
mod tests {
    use super::super::state::ServerState;
    use super::*;
    use deps_core::ConcreteVersion;
    use deps_core::DependencyOutcomes;
    use deps_core::Deprecation;
    use deps_core::EcosystemId;
    use deps_core::PackageVersions;
    use deps_core::RemovalStatus;
    use deps_engine::classify::resolved::dependency_version_map;
    use std::assert_matches;
    use std::sync::Arc;

    mod incremental_fetch_tests {
        use super::*;

        #[tokio::test]
        async fn test_preserve_cached_versions_on_change() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `ecosystem.parse_manifest` (cargo)
            // transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".into(), PackageVersions::latest_only("1.0.210"));
                doc.cached_versions
                    .insert("tokio".into(), PackageVersions::latest_only("1.40.0"));
                doc.resolved_versions
                    .insert("serde".into(), "1.0.195".into());
                doc.resolved_versions
                    .insert("tokio".into(), "1.35.0".into());
            }

            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(doc.cached_versions.len(), 2);
                assert_eq!(doc.resolved_versions.len(), 2);
            }

            let content2 = r#"[dependencies]
serde = "1.0.210"
tokio = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(
                    doc.cached_versions.len(),
                    2,
                    "Cached versions should be preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("serde").map(|v| v.latest.as_str()),
                    Some("1.0.210"),
                    "serde cache preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("tokio").map(|v| v.latest.as_str()),
                    Some("1.40.0"),
                    "tokio cache preserved"
                );
                assert_eq!(
                    doc.resolved_versions.len(),
                    2,
                    "Resolved versions should be preserved"
                );
            }
        }

        /// Regression guard for issue #649 critic finding S1: `resolved_version_candidates`
        /// must travel with `resolved_versions` through `preserve_cache`, not reset to empty
        /// on every keystroke — a desync here would silently reintroduce #649's
        /// mis-attribution bug for the debounce + lockfile-reload window between each edit
        /// and `run_document_change_task`'s repopulation of the candidates map.
        #[tokio::test]
        async fn test_preserve_cache_carries_resolved_version_candidates_across_edit() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
serde_old = { package = "serde", version = "0.9" }
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Manually populate the candidates map (simulating a completed lockfile load).
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.resolved_versions
                    .insert("serde".into(), "1.0.219".into());
                doc.resolved_version_candidates
                    .insert("serde".into(), vec!["0.9.15".into(), "1.0.219".into()]);
            }

            // Trivial re-edit (whitespace-only) — this must not reset the candidates map.
            let content2 = r#"[dependencies]
serde = "1.0"
serde_old = { package = "serde", version = "0.9" }

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            assert_eq!(
                doc_state2.resolved_version_candidates.get("serde"),
                Some(&vec![
                    ConcreteVersion::from("0.9.15"),
                    ConcreteVersion::from("1.0.219")
                ]),
                "resolved_version_candidates must survive preserve_cache alongside resolved_versions"
            );
        }

        /// Regression guard for issue #1395's bidirectional-generation-race finding:
        /// `resolved_versions_generation` must travel with `resolved_versions` through
        /// `preserve_cache`, exactly like `resolved_version_candidates` above — resetting
        /// it to 0 on every keystroke-triggered `DocumentState` rebuild would desync it
        /// from the value it's meant to guard, undermining `run_osv_phase_b_and_commit`'s
        /// staleness check across an edit.
        #[tokio::test]
        async fn test_preserve_cache_carries_resolved_versions_generation_across_edit() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            let generation_before = {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_resolved_versions(
                    HashMap::from([(PackageName::new("serde"), ConcreteVersion::from("1.0.210"))]),
                    HashMap::new(),
                    state.next_resolved_versions_generation(),
                );
                doc.resolved_versions_generation
            };
            assert!(
                !generation_before.is_initial(),
                "the bump above must have taken effect"
            );

            // Trivial re-edit (whitespace-only) — this must not reset the generation counter.
            let content2 = r#"[dependencies]
serde = "1.0"

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            assert_eq!(
                doc_state2.resolved_versions_generation, generation_before,
                "resolved_versions_generation must survive preserve_cache alongside \
                 resolved_versions, not reset to 0 on every rebuild"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_carries_vulnerabilities_across_edit() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use deps_core::osv::{ScanOutcome, VulnerabilityMap};

            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            let mut vulns = VulnerabilityMap::new();
            vulns.insert(deps_core::test_util::vuln_key("time"), ScanOutcome::Clean);
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_vulnerabilities(vulns);
            }

            // A whitespace-only edit: DocumentState is rebuilt from scratch,
            // which would silently wipe `vulnerabilities` on every keystroke
            // without preserve_cache carrying it through (§4).
            let content2 = r#"[dependencies]
time = "0.1.43"

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.vulnerabilities
                    .get(&deps_core::test_util::vuln_key("time")),
                Some(ScanOutcome::Clean)
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_carries_yanked_versions_across_edit() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_yanked(
                    "time",
                    (ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked),
                ));
            }

            // A whitespace-only edit: DocumentState is rebuilt from scratch,
            // which would silently flicker the yanked diagnostic off on
            // every keystroke without preserve_cache carrying it through.
            let content2 = r#"[dependencies]
time = "0.1.43"

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.outcomes.yanked("time"),
                Some(&(ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked))
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_carries_deprecations_across_edit() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_deprecation(
                    "time",
                    Deprecation {
                        reason: Some("archived".to_string()),
                        replacement: None,
                    },
                ));
            }

            // A whitespace-only edit: DocumentState is rebuilt from scratch, which
            // would silently flicker the deprecation diagnostic off on every keystroke
            // without preserve_cache carrying it through.
            let content2 = r#"[dependencies]
time = "0.1.43"

"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.outcomes.deprecation("time"),
                Some(&Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: None,
                })
            );
        }

        #[tokio::test]
        async fn test_deprecations_pruned_on_dependency_removal_by_normalized_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_deprecation(
                    "time",
                    Deprecation {
                        reason: Some("archived".to_string()),
                        replacement: None,
                    },
                ));
            }

            let content2 = r#"[dependencies]
serde = "1.0"
"#;
            let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                [("serde", None), ("time", None)]
                    .into_iter()
                    .map(|(n, r)| (PackageName::new(n), vec![r]))
                    .collect();
            let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                std::iter::once((PackageName::new("serde"), vec![None])).collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for removed_dep in &diff.removed {
                doc_state2
                    .outcomes
                    .remove(&formatter.normalize_package_name(removed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.deprecation("time").is_none(),
                "removed dependency's deprecation entry must be pruned"
            );
        }

        /// Regression guard for issue #649 critic finding S1: `resolved_version_candidates`
        /// is raw-`dep.name()`-keyed exactly like `resolved_versions`, so it must be pruned
        /// on dependency removal the same way, not left holding a stale candidates list for
        /// a name no longer in the manifest.
        #[tokio::test]
        async fn test_resolved_version_candidates_pruned_on_dependency_removal() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
serde_old = { package = "serde", version = "0.9" }
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.resolved_versions
                    .insert("serde".into(), "1.0.219".into());
                doc.resolved_version_candidates
                    .insert("serde".into(), vec!["0.9.15".into(), "1.0.219".into()]);
            }

            // Both manifest entries removed — `serde`'s candidates must be pruned along
            // with `resolved_versions`, not left behind as stale data.
            let content2 = "[dependencies]\n";
            let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                std::iter::once((PackageName::new("serde"), vec![None])).collect();
            let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> = HashMap::new();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("serde")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            for removed_dep in &diff.removed {
                doc_state2.cached_versions.remove(removed_dep);
                doc_state2.resolved_versions.remove(removed_dep);
                doc_state2.resolved_version_candidates.remove(removed_dep);
            }

            assert!(
                !doc_state2.resolved_version_candidates.contains_key("serde"),
                "removed dependency's candidates entry must be pruned"
            );
        }

        /// D2 invariant: unlike `yanked_versions`, a #205 finding is package-level, not
        /// tied to the declared version — editing which version is pinned must NOT
        /// drop it, mirroring the deliberate absence of a
        /// `diff.version_changed`-triggered prune in `handle_document_change`.
        #[tokio::test]
        async fn test_deprecations_survive_version_change_unlike_yanked_versions() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "0.1.44"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(
                    DependencyOutcomes::new()
                        .with_yanked("time", ("0.1.44".into(), RemovalStatus::Yanked))
                        .with_deprecation(
                            "time",
                            Deprecation {
                                reason: Some("archived".to_string()),
                                replacement: None,
                            },
                        ),
                );
            }

            // Edit the pin from a yanked version to a safe one — the *version-level*
            // yanked finding is stale and must be dropped, but the *package-level*
            // deprecation finding is not tied to which version is pinned.
            let content2 = r#"[dependencies]
time = "0.1.43"
"#;
            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            doc_state2.outcomes.clear_yanked("time");

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.yanked("time").is_none(),
                "the stale version-level yanked finding must be dropped"
            );
            assert_eq!(
                doc.outcomes.deprecation("time"),
                Some(&Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: None,
                }),
                "the package-level deprecation finding must survive a version-only edit"
            );
        }

        /// Mirrors `test_deprecations_survive_version_change_unlike_yanked_versions` for
        /// `fetch_failed` (#267): the `version_changed` loop in `handle_document_change`
        /// clears both `yanked` and `fetch_failed` together (lifecycle.rs, right above
        /// `deps_to_fetch.extend`), never `deprecation`. With all three channels set on
        /// the same normalized name, a version-only edit must clear the first two and
        /// leave the deprecation finding untouched.
        #[tokio::test]
        async fn test_fetch_failed_and_yanked_cleared_but_deprecation_survives_version_change() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "0.1.44"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(
                    DependencyOutcomes::new()
                        .with_yanked("time", ("0.1.44".into(), RemovalStatus::Yanked))
                        .with_fetch_failure("time", FetchFailure::Transient)
                        .with_deprecation(
                            "time",
                            Deprecation {
                                reason: Some("archived".to_string()),
                                replacement: None,
                            },
                        ),
                );
            }

            let content2 = r#"[dependencies]
time = "0.1.43"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for changed_dep in &diff.version_changed {
                let normalized = formatter.normalize_package_name(changed_dep);
                doc_state2.outcomes.clear_yanked(&normalized);
                doc_state2.outcomes.clear_fetch_failure(&normalized);
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.yanked("time").is_none(),
                "the stale version-level yanked finding must be dropped"
            );
            assert!(
                doc.outcomes.fetch_failure("time").is_none(),
                "the stale fetch-failure finding must be dropped"
            );
            assert_eq!(
                doc.outcomes.deprecation("time"),
                Some(&Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: None,
                }),
                "the package-level deprecation finding must survive a version-only edit"
            );
        }

        #[tokio::test]
        async fn test_yanked_versions_pruned_on_dependency_removal_by_normalized_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_yanked(
                    "time",
                    (ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked),
                ));
            }

            let content2 = r#"[dependencies]
serde = "1.0"
"#;
            let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                [("serde", None), ("time", None)]
                    .into_iter()
                    .map(|(n, r)| (PackageName::new(n), vec![r]))
                    .collect();
            let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                std::iter::once((PackageName::new("serde"), vec![None])).collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for removed_dep in &diff.removed {
                doc_state2
                    .outcomes
                    .remove(&formatter.normalize_package_name(removed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.yanked("time").is_none(),
                "removed dependency's yanked entry must be pruned"
            );
        }

        #[tokio::test]
        async fn test_yanked_versions_pruned_on_version_change_by_normalized_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Security F1 / impl-critic S1 (false positive direction):
            // editing a dependency from a yanked pin to a safe one, with no
            // lock file, must not leave the stale yanked diagnostic
            // anchored on the new version's range. Editing in place (not
            // add+remove) means the pruning loop for `diff.removed` alone
            // would miss this — the name never leaves `diff.removed`, it's
            // in `diff.version_changed` instead.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
time = "=0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // `time` was found yanked at its old pin, "=0.1.43".
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_yanked(
                    "time",
                    (ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked),
                ));
            }

            // Edited to a different, safe pin — same dependency, in place.
            let content2 = r#"[dependencies]
time = "=0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            let formatter = ecosystem.formatter();
            for changed_dep in &diff.version_changed {
                doc_state2
                    .outcomes
                    .clear_yanked(&formatter.normalize_package_name(changed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.yanked("time").is_none(),
                "stale yanked entry against the OLD version must not survive an in-place edit"
            );
        }

        #[tokio::test]
        async fn test_fetch_failed_pruned_on_dependency_removal_by_normalized_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Mirrors `test_yanked_versions_pruned_on_dependency_removal_by_normalized_name`
            // for `fetch_failed` (#267): a stale fetch-error marker for a
            // dependency the user has since deleted must not linger.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(
                    DependencyOutcomes::new().with_fetch_failure("time", FetchFailure::Transient),
                );
            }

            let content2 = r#"[dependencies]
serde = "1.0"
"#;
            let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                [("serde", None), ("time", None)]
                    .into_iter()
                    .map(|(n, r)| (PackageName::new(n), vec![r]))
                    .collect();
            let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                std::iter::once((PackageName::new("serde"), vec![None])).collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.removed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            // Preserved before pruning: proves `preserve_cache` itself
            // carries `fetch_failed` across the edit, not just the final
            // (already-pruned) state below.
            assert!(
                doc_state2.outcomes.fetch_failure("time").is_some(),
                "preserve_cache must carry fetch_failed across an edit"
            );

            let formatter = ecosystem.formatter();
            for removed_dep in &diff.removed {
                doc_state2
                    .outcomes
                    .remove(&formatter.normalize_package_name(removed_dep));
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.outcomes.fetch_failure("time").is_none(),
                "removed dependency's fetch_failed entry must be pruned"
            );
        }

        #[test]
        fn test_deps_to_fetch_includes_version_changed_dependencies() {
            // Security F1 (false negative direction): editing a dependency
            // from a safe pin to a yanked one, with no lock file, must
            // still trigger the registry fetch (and therefore the probe) —
            // otherwise the yanked pin is never checked at all, since
            // `deps_to_fetch.is_empty()` would skip the fetch entirely if
            // it only ever contained `diff.added`.
            let old = versions(&[("time", Some("=0.1.44"))]);
            let new = versions(&[("time", Some("=0.1.43"))]);

            let diff = DependencyDiff::compute(&old, &new);
            assert!(diff.added.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);
            assert!(
                diff.needs_fetch(),
                "a version-only edit must trigger the registry fetch"
            );

            // Mirrors the production construction at the `deps_to_fetch`
            // site in `handle_document_change`.
            let mut deps_to_fetch = diff.added;
            deps_to_fetch.extend(diff.version_changed);
            assert_eq!(
                deps_to_fetch,
                vec![PackageName::new("time")],
                "the version-changed dependency must be included in the fetch list"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_yanked_versions_stale_after_lockfile_only_change() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // R3 (accepted, not fixed): the yanked map is computed during the
            // registry fetch. A didChange that adds no dependencies skips the
            // fetch entirely, so `preserve_cache` carries the *old* yanked
            // map forward verbatim even if a lockfile edited underneath (e.g.
            // `cargo update` pulling in a newly-yanked release) would have
            // changed the answer. This documents the existing behavior,
            // identical to `cached_versions`' staleness.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Stale: `time` was yanked as of the last fetch.
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.replace_outcomes(DependencyOutcomes::new().with_yanked(
                    "time",
                    (ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked),
                ));
            }

            // Identical manifest content re-parsed (as happens on a
            // didChangeWatchedFiles-less lockfile edit that doesn't touch the
            // manifest text) — no dependency added or removed, so the real
            // handler would skip the registry fetch and never re-run the
            // yanked probe.
            let parse_result2 = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result2,
            );
            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }
            state.update_document(uri.clone(), doc_state2);

            // The stale entry survives verbatim — even if `time` were
            // un-yanked (or a different version newly yanked) in the
            // lockfile in the meantime, nothing here would know.
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.outcomes.yanked("time"),
                Some(&(ConcreteVersion::new("0.1.43"), RemovalStatus::Yanked))
            );
        }

        #[tokio::test]
        async fn test_first_open_has_empty_cache() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                0,
                "First open should have empty cache"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_on_parse_failure() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".into(), PackageVersions::latest_only("1.0.210"));
            }

            let content2 = r#"[dependencies
serde = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.ok();
            assert!(
                parse_result2.is_none(),
                "Parse should fail for invalid TOML"
            );

            let mut doc_state2 =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, content2.to_string());

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                1,
                "Cache should be preserved on parse failure"
            );
            assert_eq!(
                doc.cached_versions.get("serde").map(|v| v.latest.as_str()),
                Some("1.0.210")
            );
        }

        fn versions(
            pairs: &[(&str, Option<&str>)],
        ) -> HashMap<PackageName, Vec<Option<VersionReq>>> {
            pairs
                .iter()
                .map(|(name, req)| (PackageName::new(*name), vec![req.map(VersionReq::new)]))
                .collect()
        }

        #[test]
        fn test_dependency_diff_detects_additions() {
            let old = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);
            let new = versions(&[
                ("serde", Some("1.0")),
                ("tokio", Some("1.0")),
                ("anyhow", Some("1.0")),
            ]);

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 1);
            assert!(diff.added.contains(&PackageName::new("anyhow")));
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
            assert!(diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_detects_removals() {
            let old = versions(&[
                ("serde", Some("1.0")),
                ("tokio", Some("1.0")),
                ("anyhow", Some("1.0")),
            ]);
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert_eq!(diff.removed.len(), 1);
            assert!(diff.removed.contains(&PackageName::new("anyhow")));
            assert!(!diff.needs_fetch());
            assert!(!diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_no_changes() {
            let old = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert!(diff.version_changed.is_empty());
            assert!(!diff.needs_fetch());
            assert!(!diff.needs_osv_rescan());
        }

        #[test]
        fn test_dependency_diff_empty_to_new() {
            let old: HashMap<PackageName, Vec<Option<VersionReq>>> = HashMap::new();
            let new = versions(&[("serde", Some("1.0")), ("tokio", Some("1.0"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 2);
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
        }

        #[test]
        fn test_dependency_diff_detects_version_change_without_name_set_change() {
            // Regression guard for critique S1: editing only a dependency's
            // version must be detected even though the name set is unchanged.
            let old = versions(&[("time", Some("0.1.43"))]);
            let new = versions(&[("time", Some("0.1.44"))]);

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);
            assert!(
                diff.needs_fetch(),
                "a version-only edit must still trigger the registry fetch, \
                 so the yanked probe re-runs against the new version"
            );
            assert!(
                diff.needs_osv_rescan(),
                "a version-only edit must still trigger an OSV rescan"
            );
        }

        #[tokio::test]
        async fn test_dependency_version_map_tracks_both_occurrences_of_duplicate_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Regression guard for #394: `time` appears under both
            // `[dependencies]` and `[dev-dependencies]` with different
            // requirements. A name-keyed `HashMap<PackageName, Option<VersionReq>>`
            // would silently collapse this to one entry (whichever section's
            // entry iterates last); `dependency_version_map` must instead
            // keep one requirement per occurrence.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();

            let content = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            assert_eq!(
                parse_result.dependencies().len(),
                2,
                "both `[dependencies]` and `[dev-dependencies]` occurrences of `time` must parse"
            );

            let deps = dependency_version_map(parse_result.as_ref());
            let time_reqs = deps
                .get(&PackageName::new("time"))
                .expect("duplicated name must still be present in the map");
            assert_eq!(
                time_reqs,
                &vec![
                    Some(VersionReq::new("0.1.43")),
                    Some(VersionReq::new("0.1.44")),
                ],
                "both occurrences' version requirements must be tracked, not just the last one"
            );
        }

        #[tokio::test]
        async fn test_dependency_diff_detects_edit_to_first_occurrence_of_duplicate_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Regression guard for #394: editing the *first* (`[dependencies]`)
            // occurrence of a duplicated name, while the second
            // (`[dev-dependencies]`) occurrence stays unchanged, must still
            // produce a non-empty diff. Under the pre-fix name-only HashMap,
            // the unchanged second occurrence "won" the collapse in both the
            // old and new maps, so this edit was silently invisible to
            // `DependencyDiff` — the registry fetch and OSV rescan never ran.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();

            let content1 = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );

            let content2 = r#"[dependencies]
time = "0.1.50"

[dev-dependencies]
time = "0.1.44"
"#;
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );

            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(
                diff.version_changed,
                vec![PackageName::new("time")],
                "editing the losing (first) occurrence of a duplicated name must be detected"
            );
            assert!(diff.needs_fetch());
            assert!(diff.needs_osv_rescan());
        }

        #[tokio::test]
        async fn test_dependency_diff_detects_edit_to_second_occurrence_of_duplicate_name() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // Mirrors the previous test in the opposite direction: editing
            // the *second* (`[dev-dependencies]`) occurrence, with the first
            // (`[dependencies]`) occurrence unchanged, must also be detected
            // — confirming the fix is not merely order-dependent.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();

            let content1 = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );

            let content2 = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.60"
"#;
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );

            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(
                diff.version_changed,
                vec![PackageName::new("time")],
                "editing the winning (second) occurrence of a duplicated name must be detected"
            );
            assert!(diff.needs_fetch());
            assert!(diff.needs_osv_rescan());
        }

        #[tokio::test]
        async fn test_dependency_diff_detects_edit_to_duplicate_name_across_target_blocks() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // #394's own headline reproduction: `time` declared under two
            // different `[target.'cfg(...)'.dependencies]` blocks (reachable
            // since #396's target-table parsing fix), pinned to different
            // versions. Also the only scenario that exercises the ordering
            // nuance noted on `dependency_version_map`'s doc: `deps-cargo`
            // walks a `BTreeMap`, so `cfg(unix)` (declared second, below)
            // sorts *before* `cfg(windows)` (declared first, above) in
            // `pr.dependencies()` — the fix must not depend on occurrences
            // appearing in source order to detect the edit correctly.
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();

            let content1 = r#"[target.'cfg(windows)'.dependencies]
time = "0.1.44"

[target.'cfg(unix)'.dependencies]
time = "0.1.43"
"#;
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            assert_eq!(
                parse_result1.dependencies().len(),
                2,
                "both target-block occurrences of `time` must parse"
            );
            let old_deps = dependency_version_map(parse_result1.as_ref());
            assert_eq!(
                old_deps.get(&PackageName::new("time")).map(Vec::len),
                Some(2),
                "duplicate-name occurrences under different target blocks must be tracked \
                 per-occurrence, not collapsed to one entry"
            );

            // Edit only the `cfg(unix)` occurrence's version.
            let content2 = r#"[target.'cfg(windows)'.dependencies]
time = "0.1.44"

[target.'cfg(unix)'.dependencies]
time = "0.1.50"
"#;
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &url)
                    .await
                    .unwrap()
                    .as_ref(),
            );

            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(
                diff.version_changed,
                vec![PackageName::new("time")],
                "editing one target-block occurrence of a duplicated name must still \
                 produce a non-empty diff, even though the other occurrence's \
                 requirement (\"0.1.44\") is unchanged"
            );
            assert!(diff.needs_fetch());
            assert!(diff.needs_osv_rescan());
        }

        #[tokio::test]
        async fn test_cache_pruned_on_dependency_removal() {
            // See the comment in `test_preserve_cached_versions_on_change` on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
anyhow = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &url).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions.insert(
                    PackageName::new("serde"),
                    PackageVersions::latest_only("1.0.210"),
                );
                doc.cached_versions.insert(
                    PackageName::new("tokio"),
                    PackageVersions::latest_only("1.40.0"),
                );
                doc.cached_versions.insert(
                    PackageName::new("anyhow"),
                    PackageVersions::latest_only("1.0.89"),
                );
            }

            let content2 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            let old_deps: HashMap<PackageName, Vec<Option<VersionReq>>> =
                ["serde", "tokio", "anyhow"]
                    .iter()
                    .map(|s| (PackageName::new(*s), vec![None]))
                    .collect();
            let new_deps: HashMap<PackageName, Vec<Option<VersionReq>>> = ["serde", "tokio"]
                .iter()
                .map(|s| (PackageName::new(*s), vec![None]))
                .collect();
            let diff = DependencyDiff::compute(&old_deps, &new_deps);

            let parse_result2 = ecosystem.parse_manifest(content2, &url).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            for removed_dep in &diff.removed {
                doc_state2.cached_versions.remove(removed_dep);
            }

            state.update_document(uri.clone(), doc_state2);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                2,
                "anyhow should be removed from cache"
            );
            assert!(doc.cached_versions.contains_key("serde"));
            assert!(doc.cached_versions.contains_key("tokio"));
            assert!(!doc.cached_versions.contains_key("anyhow"));
        }

        /// Issue #1424 (impl-critic round 2, S1): for a `RegistryDeclaredSpdx` ecosystem
        /// (Cargo), a resolved-version move must NOT evict `DocumentState::licenses` — that
        /// license source is the registry's latest-matching pick, not tied to the resolved
        /// version, and is never re-fetched on a lock-file-only reload, so evicting it here
        /// would just delete valid, still-displayable data with nothing to repopulate it.
        #[tokio::test]
        async fn test_reload_resolved_versions_keeps_license_for_non_tier3_ecosystem() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content = r#"[dependencies]
time = "0.1"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Cargo)
                .unwrap();
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.resolved_versions
                    .insert(PackageName::new("time"), ConcreteVersion::from("0.1.43"));
                doc.merge_licenses(HashMap::from([(
                    PackageName::new("time"),
                    vec!["MIT".to_string()],
                )]));
            }

            // `cargo update` moves `time` to a new resolved version.
            let new_resolved: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("time"), ConcreteVersion::from("0.1.44")))
                    .collect();
            let no_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = HashMap::new();

            let changed = reload_resolved_versions(
                &uri,
                &state,
                ecosystem.as_ref(),
                &new_resolved,
                &no_candidates,
            );

            assert!(changed, "the version move must be detected");
            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses.contains_key(&PackageName::new("time")),
                "Cargo's registry-declared license must survive a resolved-version move, \
                 since it isn't tied to the resolved version and nothing would repopulate \
                 it if evicted here"
            );
        }

        /// Issue #1424 (impl-critic round 2, S1): for a tier-3, dedicated-fetch ecosystem
        /// (Dart), a resolved-version move must evict `DocumentState::licenses` for the
        /// moved dependency, not leave it under its (unversioned) name key — otherwise a
        /// subsequent license re-fetch that fails this round would leave the *previous*
        /// version's license visibly misattributed to the new one (the prior
        /// `TODO(critic)` on `DocumentState::merge_licenses`).
        #[cfg(feature = "dart")]
        #[tokio::test]
        async fn test_reload_resolved_versions_evicts_stale_license_for_tier3_ecosystem() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let content = "dependencies:\n  http: ^1.0.0\n";

            let ecosystem = state
                .ecosystem_registry
                .get(deps_core::EcosystemId::Dart)
                .unwrap();
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.resolved_versions
                    .insert(PackageName::new("http"), ConcreteVersion::from("1.2.0"));
                doc.merge_licenses(HashMap::from([(
                    PackageName::new("http"),
                    vec!["BSD-3-Clause".to_string()],
                )]));
            }

            // A `pubspec.lock` update moves `http` to a new resolved version. The tier-3
            // license re-fetch this move would trigger is never simulated here (and, in
            // particular, never called again) — exactly the "re-fetch fails/doesn't run
            // this round" half of the bug.
            let new_resolved: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("http"), ConcreteVersion::from("1.3.0")))
                    .collect();
            let no_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = HashMap::new();

            let changed = reload_resolved_versions(
                &uri,
                &state,
                ecosystem.as_ref(),
                &new_resolved,
                &no_candidates,
            );

            assert!(changed, "the version move must be detected");
            let doc = state.get_document(&uri).unwrap();
            assert!(
                !doc.licenses.contains_key(&PackageName::new("http")),
                "a moved dependency's stale license must be evicted for a tier-3 \
                 (dedicated-fetch) ecosystem, not left misattributed to its new resolved \
                 version"
            );
        }

        struct StubDependency {
            name: PackageName,
            version_req: Option<VersionReq>,
        }
        impl Dependency for StubDependency {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> deps_core::position::Range {
                deps_core::position::Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<deps_core::position::Range> {
                None
            }
            fn source(&self) -> deps_core::parser::DependencySource {
                deps_core::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        const IDENTITY_FORMATTER: deps_core::test_util::StubFormatter =
            deps_core::test_util::StubFormatter::new().with_package_url_prefix("");

        /// Mimics a PEP 503-normalizing ecosystem (PyPI/Poetry, Composer): lowercases the
        /// manifest-declared name the way the real lock-file key is produced.
        const LOWERCASE_FORMATTER: deps_core::test_util::StubFormatter =
            deps_core::test_util::StubFormatter::new()
                .with_package_url_prefix("")
                .with_lowercase_names();

        /// Regression guard for issue #1395: `handle_lockfile_change` has no
        /// `DependencyDiff` to consult (the manifest text is untouched), so it must detect
        /// a newly-resolved or changed in-use version itself via `resolved_versions_changed`.
        #[test]
        fn test_resolved_versions_changed_detects_new_and_changed_resolutions() {
            let time = StubDependency {
                name: PackageName::new("time"),
                version_req: None,
            };
            let serde = StubDependency {
                name: PackageName::new("serde"),
                version_req: None,
            };
            let deps: Vec<&dyn Dependency> = vec![&time, &serde];
            let formatter = IDENTITY_FORMATTER;
            let no_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = HashMap::new();

            // `time` newly resolved (no lock file entry before `cargo generate-lockfile`).
            let old: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("serde"), ConcreteVersion::from("1.0.210")))
                    .collect();
            let new: HashMap<PackageName, ConcreteVersion> = [
                (PackageName::new("serde"), "1.0.210".into()),
                (PackageName::new("time"), "0.1.43".into()),
            ]
            .into_iter()
            .collect();
            assert!(
                !resolved_versions_changed(
                    &deps,
                    &old,
                    &no_candidates,
                    &new,
                    &no_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "a dependency newly gaining a resolved version must be detected"
            );

            // `cargo update` moves `time` to a different resolved version.
            let old: HashMap<PackageName, ConcreteVersion> = [
                (PackageName::new("serde"), "1.0.210".into()),
                (PackageName::new("time"), "0.1.43".into()),
            ]
            .into_iter()
            .collect();
            let new: HashMap<PackageName, ConcreteVersion> = [
                (PackageName::new("serde"), "1.0.210".into()),
                (PackageName::new("time"), "0.1.44".into()),
            ]
            .into_iter()
            .collect();
            assert!(
                !resolved_versions_changed(
                    &deps,
                    &old,
                    &no_candidates,
                    &new,
                    &no_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "a dependency's resolved version changing must be detected"
            );

            // Identical resolutions for every one of this document's own dependencies.
            assert!(
                resolved_versions_changed(
                    &deps,
                    &new,
                    &no_candidates,
                    &new.clone(),
                    &no_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "no change for this document's dependencies must not trigger a rescan"
            );

            // An unrelated package (not one of `deps`) changing must not trigger a rescan,
            // since only entries for this document's own dependencies are consulted.
            let old: HashMap<PackageName, ConcreteVersion> = [
                (PackageName::new("serde"), "1.0.210".into()),
                (PackageName::new("time"), "0.1.43".into()),
                (PackageName::new("unrelated"), "2.0.0".into()),
            ]
            .into_iter()
            .collect();
            let new: HashMap<PackageName, ConcreteVersion> = [
                (PackageName::new("serde"), "1.0.210".into()),
                (PackageName::new("time"), "0.1.43".into()),
                (PackageName::new("unrelated"), "3.0.0".into()),
            ]
            .into_iter()
            .collect();
            assert!(
                resolved_versions_changed(
                    &deps,
                    &old,
                    &no_candidates,
                    &new,
                    &no_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "an unrelated transitive package's version moving must not trigger a rescan \
                 for a document that doesn't declare it"
            );
        }

        /// A dependency that had a resolved version and loses it (e.g. its `[[package]]`
        /// entry is dropped from a hand-edited or corrupted lock file) must be treated as a
        /// change like any other, not silently ignored.
        #[test]
        fn test_resolved_versions_changed_detects_lost_resolution() {
            let time = StubDependency {
                name: PackageName::new("time"),
                version_req: None,
            };
            let deps: Vec<&dyn Dependency> = vec![&time];
            let formatter = IDENTITY_FORMATTER;
            let no_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = HashMap::new();

            let old: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("time"), ConcreteVersion::from("0.1.43")))
                    .collect();
            let new: HashMap<PackageName, ConcreteVersion> = HashMap::new();

            assert!(
                !resolved_versions_changed(
                    &deps,
                    &old,
                    &no_candidates,
                    &new,
                    &no_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "a dependency losing its resolved version must be detected as a change"
            );
        }

        /// Regression guard for issue #1395 critic S1(a): a raw `dep.name()` lookup against
        /// the collapsed `resolved_versions` map misses a dependency whose lock-file key is
        /// normalized differently from its manifest-declared spelling (e.g. Poetry's
        /// `Django` manifest key vs. `poetry.lock`'s PEP 503-normalized `django`).
        /// `resolved_versions_changed` must consult the *normalized* name, exactly like OSV
        /// target selection does.
        #[test]
        fn test_resolved_versions_changed_detects_normalized_name_mismatch() {
            let django = StubDependency {
                name: PackageName::new("Django"),
                version_req: None,
            };
            let deps: Vec<&dyn Dependency> = vec![&django];
            let formatter = LOWERCASE_FORMATTER;
            let no_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = HashMap::new();

            // The lock file resolves under the normalized key, never the raw manifest
            // spelling — a raw `old.get(dep.name())`/`new.get(dep.name())` lookup would
            // see `None` on both sides forever and never detect this.
            let old: HashMap<PackageName, ConcreteVersion> = HashMap::new();
            let new: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("django"), ConcreteVersion::from("4.2.0")))
                    .collect();

            assert!(
                !resolved_versions_changed(
                    &deps,
                    &old,
                    &no_candidates,
                    &new,
                    &no_candidates,
                    &formatter,
                    EcosystemId::Pypi,
                )
                .is_empty(),
                "a dependency newly resolved under its normalized lock-file key must be \
                 detected"
            );
        }

        /// Regression guard for issue #1395 critic S1(b): the collapsed `resolved_versions`
        /// map only ever holds the *highest* of a name's retained lock-file entries (issue
        /// #649), so it can stay unchanged across a `cargo update` that only moves the
        /// direct dependency's own lower-pinned entry while a higher transitive entry for
        /// the same name is untouched. `resolved_versions_changed` must disambiguate by the
        /// occurrence's own requirement via `resolved_version_candidates`, the same way OSV
        /// target selection does, instead of missing the change entirely.
        #[test]
        fn test_resolved_versions_changed_detects_multi_candidate_occurrence_change() {
            let time = StubDependency {
                name: PackageName::new("time"),
                version_req: Some(VersionReq::new("0.1")),
            };
            let deps: Vec<&dyn Dependency> = vec![&time];
            let formatter = IDENTITY_FORMATTER;

            // The collapsed value is always the highest retained entry (0.3.36, a
            // transitive dependency's pin) and never changes across the update below.
            let resolved: HashMap<PackageName, ConcreteVersion> =
                std::iter::once((PackageName::new("time"), ConcreteVersion::from("0.3.36")))
                    .collect();

            let old_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = std::iter::once((
                PackageName::new("time"),
                vec![
                    ConcreteVersion::from("0.1.43"),
                    ConcreteVersion::from("0.3.36"),
                ],
            ))
            .collect();
            // `cargo update -p time@0.1.43` moves only the direct dependency's own entry.
            let new_candidates: HashMap<PackageName, Vec<ConcreteVersion>> = std::iter::once((
                PackageName::new("time"),
                vec![
                    ConcreteVersion::from("0.1.45"),
                    ConcreteVersion::from("0.3.36"),
                ],
            ))
            .collect();

            assert!(
                !resolved_versions_changed(
                    &deps,
                    &resolved,
                    &old_candidates,
                    &resolved,
                    &new_candidates,
                    &formatter,
                    EcosystemId::Cargo,
                )
                .is_empty(),
                "the direct dependency's own per-occurrence resolution moving \
                 (0.1.43 -> 0.1.45) must be detected even though the collapsed \
                 resolved_versions value (the highest entry, 0.3.36) stays unchanged"
            );
        }
    }
}
