//! Dependency diffing and cache reconciliation between successive
//! parses of a manifest.

use super::state::DocumentState;
use deps_core::Deprecation;
use deps_core::FetchFailure;
use deps_core::PackageName;
use deps_core::VersionReq;
use std::collections::{HashMap, HashSet};

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

/// Merges a partial fetch's #205 deprecation findings into `doc.outcomes`' deprecation
/// channel (incremental didChange path — S1).
///
/// Without the clearing half of this (S1), a package that stops being deprecated
/// (`npm deprecate pkg ""`) would keep a stale finding for the document's lifetime —
/// nothing else ever removes one (a package-level finding does not become stale on a
/// version-only edit — see the comment above `diff.version_changed`'s pruning loop in
/// `handle_document_change`).
///
/// `fetched_names` — every raw package name successfully fetched this round (i.e. the
/// keys of `fetch_result.versions`, captured before it is consumed) — must clear any
/// previously-recorded finding when `fetched_deprecations` has no entry for it ("fetched
/// and clean"); a name *not* fetched this round (untouched by `deps_to_fetch`) must not
/// be touched at all, which is why this takes the explicit fetched-name list rather than
/// iterating `doc.outcomes` itself.
pub(crate) fn merge_deprecations_after_fetch(
    doc: &mut DocumentState,
    fetched_names: &[PackageName],
    mut fetched_deprecations: HashMap<PackageName, Deprecation>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    // I2: decided per *normalized* name in one pass, not applied incrementally per raw
    // name — `fetched_names` iterates a `HashMap`'s keys, so its order is unspecified,
    // and two raw names that normalize to the same key (e.g. Composer's case-insensitive
    // `require` keys) would otherwise let "insert B's finding, then clear it because A
    // (processed after) had none" flip on iteration order alone. Collecting first means
    // "any fetched raw name under this key reported a finding" wins deterministically,
    // regardless of which one is visited first.
    let mut per_normalized: HashMap<String, Option<Deprecation>> = HashMap::new();
    for name in fetched_names {
        let normalized = formatter.normalize_package_name(name);
        let found = fetched_deprecations.remove(name);
        let entry = per_normalized.entry(normalized).or_insert(None);
        if entry.is_none() {
            *entry = found;
        }
    }
    for (normalized, deprecation) in per_normalized {
        match deprecation {
            Some(deprecation) => {
                doc.outcomes.set_deprecation(normalized, deprecation);
            }
            None => {
                doc.outcomes.clear_deprecation(&normalized);
            }
        }
    }
}

/// Merges a partial fetch's #550 no-comparable-versions findings into `doc.outcomes`'
/// corresponding channel (incremental didChange path).
///
/// Package-level, like [`merge_deprecations_after_fetch`] (not tied to the declared
/// version, unlike `yanked`/`fetch_failure` — see the `diff.version_changed` pruning
/// loop in `handle_document_change` for why those two, but not this one, are cleared
/// on a version-only edit): if a package's registry situation improves between fetches
/// (a real tag gets published), a stale marker must not survive for the document's
/// lifetime.
///
/// `attempted_names` — every raw package name a fetch was actually attempted for this
/// round (`dep_sources`' keys, captured before it is consumed) — rather than
/// [`merge_deprecations_after_fetch`]'s `fetched_names` (`fetch_result.versions`'
/// keys): a no-comparable-versions package is by definition never a member of
/// `fetch_result.versions`, so deriving "attempted" from that map's keys would miss
/// every package this function exists to clear or set.
pub(crate) fn merge_no_comparable_versions_after_fetch(
    doc: &mut DocumentState,
    attempted_names: &[PackageName],
    mut fetched_no_comparable_versions: HashSet<PackageName>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    // Same normalized-name dedup rationale as `merge_deprecations_after_fetch` (I2):
    // decided per normalized name in one pass so two raw names sharing a normalized
    // key can't flip the outcome based on `attempted_names`' unspecified iteration
    // order.
    let mut per_normalized: HashMap<String, bool> = HashMap::new();
    for name in attempted_names {
        let normalized = formatter.normalize_package_name(name);
        let found = fetched_no_comparable_versions.remove(name);
        let entry = per_normalized.entry(normalized).or_insert(false);
        *entry = *entry || found;
    }
    for (normalized, found) in per_normalized {
        if found {
            doc.outcomes.set_no_comparable_versions(normalized);
        } else {
            doc.outcomes.clear_no_comparable_versions(&normalized);
        }
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
    #[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::super::resolved::dependency_version_map;
    use super::super::state::ServerState;
    use super::*;
    use deps_core::ConcreteVersion;
    use deps_core::DependencyOutcomes;
    use deps_core::EcosystemId;
    use deps_core::PackageVersions;
    use deps_core::RemovalStatus;
    use std::assert_matches;
    use std::sync::Arc;

    // Phase 1: Cache Preservation Tests
    #[cfg(feature = "cargo")]
    mod incremental_fetch_tests {
        use super::*;

        #[tokio::test]
        async fn test_preserve_cached_versions_on_change() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Initial document with 2 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Manually populate cache (simulating background fetch)
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

            // Verify cache populated
            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(doc.cached_versions.len(), 2);
                assert_eq!(doc.resolved_versions.len(), 2);
            }

            // Change document (modify serde version)
            let content2 = r#"[dependencies]
serde = "1.0.210"
tokio = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache preserved after update
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
serde_old = { package = "serde", version = "0.9" }
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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

        #[tokio::test]
        async fn test_preserve_cache_carries_vulnerabilities_across_edit() {
            use deps_core::osv::{ScanOutcome, VulnerabilityMap};

            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            let mut vulns = VulnerabilityMap::new();
            vulns.insert("time".to_string(), ScanOutcome::Clean);
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
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            assert_matches!(doc.vulnerabilities.get("time"), Some(ScanOutcome::Clean));
        }

        #[tokio::test]
        async fn test_preserve_cache_carries_yanked_versions_across_edit() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
serde_old = { package = "serde", version = "0.9" }
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.44"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "0.1.44"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
                    .parse_manifest(content1, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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

        /// T4 (C3): a deprecation finding recorded on the full-fetch path must survive
        /// a partial didChange fetch that does not re-fetch that package.
        #[test]
        fn test_merge_deprecations_after_fetch_retains_finding_for_name_not_refetched() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let formatter = ecosystem.formatter();
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.outcomes.set_deprecation(
                "vendor/a".to_string(),
                Deprecation {
                    reason: None,
                    replacement: Some("vendor/a2".to_string()),
                },
            );

            // Only "vendor/b" was fetched this round (e.g. a new dependency added by
            // the edit); "vendor/a" was untouched.
            let mut fetched = HashMap::new();
            fetched.insert(
                PackageName::new("vendor/b"),
                Deprecation {
                    reason: Some("abandoned".to_string()),
                    replacement: None,
                },
            );
            merge_deprecations_after_fetch(
                &mut doc,
                &[PackageName::new("vendor/b")],
                fetched,
                formatter,
            );

            assert_eq!(
                doc.outcomes.deprecation("vendor/a"),
                Some(&Deprecation {
                    reason: None,
                    replacement: Some("vendor/a2".to_string()),
                }),
                "a finding for a name not in this round's fetch must survive untouched"
            );
            assert_eq!(
                doc.outcomes.deprecation("vendor/b"),
                Some(&Deprecation {
                    reason: Some("abandoned".to_string()),
                    replacement: None,
                })
            );
        }

        /// T5 (S1): a package that stops being deprecated must have its finding
        /// cleared once re-fetched clean — distinct from a name simply not fetched
        /// this round (T4), which must be left untouched.
        #[test]
        fn test_merge_deprecations_after_fetch_clears_finding_when_refetched_clean() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let formatter = ecosystem.formatter();
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.outcomes.set_deprecation(
                "vendor/a".to_string(),
                Deprecation {
                    reason: None,
                    replacement: None,
                },
            );

            // "vendor/a" was re-fetched this round and no longer reports a finding.
            merge_deprecations_after_fetch(
                &mut doc,
                &[PackageName::new("vendor/a")],
                HashMap::new(),
                formatter,
            );

            assert!(
                doc.outcomes.deprecation("vendor/a").is_none(),
                "a name that was fetched and produced no finding must be cleared"
            );
        }

        /// I2: two raw names that normalize to the same key (Composer's `normalize_package_name`
        /// lowercases, so `"Vendor/Package"` and `"vendor/package"` collide) must merge
        /// deterministically — a finding under either raw name must survive regardless of
        /// `fetched_names`' (unspecified `HashMap::keys()`) iteration order.
        #[test]
        fn test_merge_deprecations_after_fetch_is_order_independent_across_normalization_collision()
        {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("composer").unwrap();
            let formatter = ecosystem.formatter();

            for names in [
                [
                    PackageName::new("vendor/package"),
                    PackageName::new("Vendor/Package"),
                ],
                [
                    PackageName::new("Vendor/Package"),
                    PackageName::new("vendor/package"),
                ],
            ] {
                let mut doc =
                    DocumentState::new_without_parse_result(EcosystemId::Composer, String::new());

                let mut fetched = HashMap::new();
                fetched.insert(
                    PackageName::new("Vendor/Package"),
                    Deprecation {
                        reason: None,
                        replacement: Some("vendor/other".to_string()),
                    },
                );
                // "vendor/package" (lowercase) is fetched too and reports no finding.

                merge_deprecations_after_fetch(&mut doc, &names, fetched, formatter);

                assert_eq!(
                    doc.outcomes.deprecation("vendor/package"),
                    Some(&Deprecation {
                        reason: None,
                        replacement: Some("vendor/other".to_string()),
                    }),
                    "a finding under either raw name sharing a normalized key must survive, \
                     regardless of fetch order: {names:?}"
                );
            }
        }

        /// Regression for critic finding C3 (#550): `merge_no_comparable_versions_after_fetch`'s
        /// `found == true` branch (`set_no_comparable_versions`) had zero coverage — mirrors
        /// `test_merge_deprecations_after_fetch_retains_finding_for_name_not_refetched`, but
        /// for the *first-time-set* case: a package attempted this round whose fetch
        /// genuinely found zero comparable versions must be recorded, and an unrelated
        /// package not attempted this round must be left untouched either way.
        #[test]
        fn test_merge_no_comparable_versions_after_fetch_sets_finding_for_newly_flagged_name() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let formatter = ecosystem.formatter();
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());

            // "vendor/b" was attempted this round (e.g. a new dependency added by the
            // edit) and its fetch genuinely succeeded with zero comparable versions;
            // "vendor/a" was not attempted at all.
            let mut fetched = HashSet::new();
            fetched.insert(PackageName::new("vendor/b"));
            merge_no_comparable_versions_after_fetch(
                &mut doc,
                &[PackageName::new("vendor/b")],
                fetched,
                formatter,
            );

            assert!(
                doc.outcomes.no_comparable_versions("vendor/b"),
                "a package whose fetch was attempted and found zero comparable versions \
                 this round must be recorded"
            );
            assert!(
                !doc.outcomes.no_comparable_versions("vendor/a"),
                "a package never attempted this round must not be flagged"
            );
        }

        /// Regression for critic finding C3 (#550): the literal "package no longer has
        /// zero-comparable-versions on a subsequent fetch" scenario — e.g.
        /// `dtolnay/rust-toolchain` eventually publishes a real `v1.2.3` tag. Mirrors
        /// `test_merge_deprecations_after_fetch_clears_finding_when_refetched_clean`.
        #[test]
        fn test_merge_no_comparable_versions_after_fetch_clears_finding_when_refetched_with_versions()
         {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let formatter = ecosystem.formatter();
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.outcomes
                .set_no_comparable_versions("vendor/a".to_string());

            // "vendor/a" was re-fetched this round and this time resolved a real
            // version, so it's absent from the fetched-flags set.
            merge_no_comparable_versions_after_fetch(
                &mut doc,
                &[PackageName::new("vendor/a")],
                HashSet::new(),
                formatter,
            );

            assert!(
                !doc.outcomes.no_comparable_versions("vendor/a"),
                "a package that was attempted and this time resolved a real version must \
                 have its stale marker cleared, or R5e would keep suppressing Unknown \
                 package diagnostics for a name that could now legitimately need one"
            );
        }

        /// A finding for a name not attempted this round (e.g. an unrelated dependency
        /// untouched by a partial didChange fetch) must survive untouched — distinct
        /// from the clear-on-refetch case above.
        #[test]
        fn test_merge_no_comparable_versions_after_fetch_retains_finding_for_name_not_attempted() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let formatter = ecosystem.formatter();
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.outcomes
                .set_no_comparable_versions("vendor/a".to_string());

            // Only "vendor/b" was attempted this round; "vendor/a" was untouched.
            merge_no_comparable_versions_after_fetch(
                &mut doc,
                &[PackageName::new("vendor/b")],
                HashSet::new(),
                formatter,
            );

            assert!(
                doc.outcomes.no_comparable_versions("vendor/a"),
                "a finding for a name not attempted this round must survive untouched"
            );
        }

        #[tokio::test]
        async fn test_yanked_versions_pruned_on_dependency_removal_by_normalized_name() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            // Security F1 / impl-critic S1 (false positive direction):
            // editing a dependency from a yanked pin to a safe one, with no
            // lock file, must not leave the stale yanked diagnostic
            // anchored on the new version's range. Editing in place (not
            // add+remove) means the pruning loop for `diff.removed` alone
            // would miss this — the name never leaves `diff.removed`, it's
            // in `diff.version_changed` instead.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
time = "=0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
                    .parse_manifest(content1, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let new_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content2, &uri)
                    .await
                    .unwrap()
                    .as_ref(),
            );
            let diff = DependencyDiff::compute(&old_deps, &new_deps);
            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert_eq!(diff.version_changed, vec![PackageName::new("time")]);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            // Mirrors `test_yanked_versions_pruned_on_dependency_removal_by_normalized_name`
            // for `fetch_failed` (#267): a stale fetch-error marker for a
            // dependency the user has since deleted must not linger.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content1 = r#"[dependencies]
serde = "1.0"
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
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
            // R3 (accepted, not fixed): the yanked map is computed during the
            // registry fetch. A didChange that adds no dependencies skips the
            // fetch entirely, so `preserve_cache` carries the *old* yanked
            // map forward verbatim even if a lockfile edited underneath (e.g.
            // `cargo update` pulling in a newly-yanked release) would have
            // changed the answer. This documents the existing behavior,
            // identical to `cached_versions`' staleness.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content = r#"[dependencies]
time = "0.1.43"
"#;
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content, &uri).await.unwrap();
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
            let parse_result2 = ecosystem.parse_manifest(content, &uri).await.unwrap();
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            // First open: cache should be empty (no old state to preserve)
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                0,
                "First open should have empty cache"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_on_parse_failure() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Valid initial document
            let content1 = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Populate cache
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".into(), PackageVersions::latest_only("1.0.210"));
            }

            // Invalid TOML (parse will fail)
            let content2 = r#"[dependencies
serde = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.ok();
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

            // Cache should be preserved despite parse failure
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
            // Regression guard for #394: `time` appears under both
            // `[dependencies]` and `[dev-dependencies]` with different
            // requirements. A name-keyed `HashMap<PackageName, Option<VersionReq>>`
            // would silently collapse this to one entry (whichever section's
            // entry iterates last); `dependency_version_map` must instead
            // keep one requirement per occurrence.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();

            let content = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
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
            // Regression guard for #394: editing the *first* (`[dependencies]`)
            // occurrence of a duplicated name, while the second
            // (`[dev-dependencies]`) occurrence stays unchanged, must still
            // produce a non-empty diff. Under the pre-fix name-only HashMap,
            // the unchanged second occurrence "won" the collapse in both the
            // old and new maps, so this edit was silently invisible to
            // `DependencyDiff` — the registry fetch and OSV rescan never ran.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();

            let content1 = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &uri)
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
                    .parse_manifest(content2, &uri)
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
            // Mirrors the previous test in the opposite direction: editing
            // the *second* (`[dev-dependencies]`) occurrence, with the first
            // (`[dependencies]`) occurrence unchanged, must also be detected
            // — confirming the fix is not merely order-dependent.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();

            let content1 = r#"[dependencies]
time = "0.1.43"

[dev-dependencies]
time = "0.1.44"
"#;
            let old_deps = dependency_version_map(
                ecosystem
                    .parse_manifest(content1, &uri)
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
                    .parse_manifest(content2, &uri)
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
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();

            let content1 = r#"[target.'cfg(windows)'.dependencies]
time = "0.1.44"

[target.'cfg(unix)'.dependencies]
time = "0.1.43"
"#;
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
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
                    .parse_manifest(content2, &uri)
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
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Initial document with 3 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
anyhow = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content1.to_string(),
                parse_result1,
            );
            state.update_document(uri.clone(), doc_state1);

            // Populate cache for all 3 deps
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

            // Remove anyhow from manifest
            let content2 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            // Compute diff and apply cache pruning
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

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content2.to_string(),
                parse_result2,
            );

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            // Prune removed dependencies
            for removed_dep in &diff.removed {
                doc_state2.cached_versions.remove(removed_dep);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache was pruned
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
    }
}
