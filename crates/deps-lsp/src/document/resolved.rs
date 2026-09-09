//! Lock-file and in-use dependency version resolution.

use super::state::ServerState;
use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::PackageVersions;
use deps_core::VersionReq;
use deps_core::lsp_helpers::in_use_version;
use std::collections::HashMap;
use tower_lsp_server::ls_types::Uri;

/// Resolves the typed `EcosystemId` for an ecosystem trait object.
///
/// `ecosystem.id()` always originates from a statically registered ecosystem
/// (see `crate::register_ecosystems`), so parsing it back to `EcosystemId` can
/// only fail on an internal registration bug, not on user input.
#[allow(clippy::expect_used)] // safe per the invariant documented above
pub(crate) fn resolve_ecosystem_id(ecosystem: &dyn Ecosystem) -> EcosystemId {
    ecosystem
        .id()
        .parse()
        .expect("ecosystem.id() must be a registered EcosystemId")
}

/// Whether a reparse should only re-fetch what `DependencyDiff` calls for, or force a
/// full re-fetch of every dependency regardless of diff (issue #592).
///
/// A config change that alters registry *routing* (`registries.workspace_registries`,
/// `registries.nuget_user_profile_sources`) feeds `DependencyDiff::compute` an unchanged
/// dependency set — the manifest didn't change, only where its dependencies resolve from —
/// so the default `Self::Diff` policy's `deps_to_fetch` would stay empty and
/// `run_document_change_task`'s `deps_to_fetch.is_empty()` early return would leave the
/// document displaying versions resolved under the *old* routing indefinitely (the same bug
/// class #424 already documents for `minimum-stability`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefetchPolicy {
    /// Re-fetch only what `DependencyDiff` calls for (added / version-changed dependencies)
    /// — correct for every real document edit, where the diff already answers "what needs
    /// re-checking".
    Diff,
    /// Force a re-fetch of every dependency in the new parse result, and drop any
    /// previously cached version/fetch-failure data before doing so (in
    /// `fetch_registry_versions_for_change`) — the routing itself changed, so data
    /// obtained under the old routing can no longer be vouched for.
    AllDependencies,
}

/// Builds `dep_name -> [in_use_version, ...]` (§4.5/§4.6) for every
/// dependency with a known in-use version, for the yanked-check probe in
/// `fetch_latest_versions_parallel`. Skips non-registry dependencies
/// (git/path forks, step 0 of `build_scan_targets`'s ladder) so a patched
/// fork is never flagged for a registry version it does not contain.
///
/// One entry per *occurrence* of a name, not a single collapsed value: the
/// same dependency name can appear more than once in a manifest (the same
/// crate under `[dependencies]`/`[dev-dependencies]` or multiple
/// `[target.'cfg(...)'.dependencies]` blocks — #394). A HashMap keyed by
/// name alone would silently drop all but the last occurrence's in-use
/// version from the yanked probe below.
pub(crate) fn collect_in_use_versions(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> HashMap<PackageName, Vec<String>> {
    let mut map: HashMap<PackageName, Vec<String>> = HashMap::new();
    for dep in parse_result
        .dependencies()
        .into_iter()
        .filter(|dep| formatter.source_is_public_registry_content(&dep.source()))
    {
        let normalized_name = formatter.normalize_package_name(dep.name());
        if let Some(v) = in_use_version(
            dep,
            &normalized_name,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        ) {
            map.entry(dep.name().clone()).or_default().push(v);
        }
    }
    map
}

/// Builds `name -> [version_requirement, ...]` for every dependency in `pr`,
/// one entry per occurrence, the shape `DependencyDiff::compute` needs. A
/// `HashMap<PackageName, Option<VersionReq>>` (single value per name) would
/// silently collapse a duplicate name to its last occurrence, losing any
/// edit made to an earlier one (#394).
///
/// Occurrence order is whatever `pr.dependencies()` returns, which for
/// `deps-cargo` is *not* document order for multiple `[target.*]` blocks
/// (see `DependencyDiff::compute`'s doc). A consequence worth knowing: if
/// an edit only renames a `[target.'cfg(...)'.dependencies]` expression
/// (no version change), that occurrence can sort into a different position
/// in the new `Vec` than the old one, so `old.get(name) != new.get(name)`
/// trips even though every individual version requirement is unchanged —
/// a spurious but harmless `version_changed` (one extra registry
/// refetch/OSV rescan for that name, never a missed or misattributed one).
pub(crate) fn dependency_version_map(
    pr: &dyn deps_core::ParseResult,
) -> HashMap<PackageName, Vec<Option<VersionReq>>> {
    let mut map: HashMap<PackageName, Vec<Option<VersionReq>>> = HashMap::new();
    for d in pr.dependencies() {
        map.entry(d.name().clone())
            .or_default()
            .push(d.version_requirement().cloned());
    }
    map
}

/// Builds a `cached_versions` map from lock-file-resolved versions, ahead of any registry
/// fetch.
///
/// `available` is deliberately left empty (`PackageVersions::latest_without_list`, not a
/// plausible-looking one-element list) — this runs before any registry fetch, and
/// `requirement_is_unsatisfiable` treats an empty `available` as "still loading, skip"
/// (FR-004). Using `latest_only` here instead would populate a bogus single-entry list and
/// let the unsatisfiable-requirement check compute a false verdict on every document open,
/// before the fetch that's supposed to suppress it has a chance to run.
pub(crate) fn cached_versions_from_lockfile(
    resolved: &HashMap<PackageName, ConcreteVersion>,
) -> HashMap<PackageName, PackageVersions> {
    resolved
        .iter()
        .map(|(name, version)| {
            (
                name.clone(),
                PackageVersions::latest_without_list(version.clone()),
            )
        })
        .collect()
}

/// Splits a parsed [`deps_core::lockfile::ResolvedPackages`] into the collapsed
/// `dep_name -> version` map (`ResolvedPackages::iter`, unchanged FR-005 fast path) and a
/// sibling `dep_name -> [version, ...]` map (issue #649) holding every retained lock-file
/// entry for names with more than one — built from `ResolvedPackages::iter_all`, and
/// deliberately omitting a single-occurrence name entirely (NFR-003: the common case never
/// pays for a candidates-map lookup).
///
/// Shared by [`load_resolved_versions`] and `DepsLanguageServer`'s watched-lock-file-change
/// handler (`server.rs`) — both re-parse a lock file and need the identical split.
pub(crate) fn split_resolved_packages(
    resolved: &deps_core::lockfile::ResolvedPackages,
) -> (
    HashMap<PackageName, ConcreteVersion>,
    HashMap<PackageName, Vec<ConcreteVersion>>,
) {
    let versions = resolved
        .iter()
        .map(|(name, pkg)| (PackageName::new(name.as_str()), pkg.version.clone().into()))
        .collect();
    let candidates = resolved
        .iter_all()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, versions)| {
            (
                PackageName::new(name.as_str()),
                versions
                    .iter()
                    .map(|pkg| ConcreteVersion::from(pkg.version.clone()))
                    .collect(),
            )
        })
        .collect();
    (versions, candidates)
}

/// Loads resolved versions from lock file for a given manifest URI.
///
/// Uses the ecosystem's lockfile provider to parse the lock file, then
/// [`split_resolved_packages`]. Both returned maps are empty if no lock file is found or
/// parsing fails.
pub(crate) async fn load_resolved_versions(
    uri: &Uri,
    state: &ServerState,
    ecosystem: &dyn Ecosystem,
) -> (
    HashMap<PackageName, ConcreteVersion>,
    HashMap<PackageName, Vec<ConcreteVersion>>,
) {
    let lock_provider = match ecosystem.lockfile_provider() {
        Some(p) => p,
        None => {
            tracing::debug!("No lock file provider for ecosystem {}", ecosystem.id());
            return (HashMap::new(), HashMap::new());
        }
    };

    let lockfile_path = match lock_provider.locate_lockfile(uri) {
        Some(path) => path,
        None => {
            tracing::debug!("No lock file found for {:?}", uri);
            return (HashMap::new(), HashMap::new());
        }
    };

    match state
        .lockfile_cache
        .get_or_parse(lock_provider.as_ref(), &lockfile_path)
        .await
    {
        Ok(resolved) => {
            tracing::info!(
                "Loaded {} resolved versions from {}",
                resolved.len(),
                lockfile_path.display()
            );
            split_resolved_packages(&resolved)
        }
        Err(e) => {
            tracing::warn!("Failed to parse lock file: {}", e);
            (HashMap::new(), HashMap::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N5 regression guard: the lock-file-population path must build every
    /// `PackageVersions` with an **empty** `available` list, never a populated one — an
    /// empty `available` is what makes `requirement_is_unsatisfiable`'s FR-004 guard
    /// suppress the check before any registry fetch has run. This is the exact function
    /// `handle_document_open`'s background task calls, so a regression here (e.g.
    /// swapping `latest_without_list` for `latest_only`) is caught directly, without
    /// racing the background task.
    #[test]
    fn test_cached_versions_from_lockfile_has_empty_available() {
        let mut resolved = HashMap::new();
        resolved.insert(PackageName::new("serde"), "1.0.195".into());
        resolved.insert(PackageName::new("tokio"), "1.35.0".into());

        let cached = cached_versions_from_lockfile(&resolved);

        assert_eq!(cached.len(), 2);
        let serde = cached.get(&PackageName::new("serde")).unwrap();
        assert_eq!(serde.latest, "1.0.195");
        assert!(
            serde.available.is_empty(),
            "lock-file-populated entries must have an empty available list, got: {:?}",
            serde.available
        );
        // Issue #227 C3: a locked/pinned version's age is not actionable, so this
        // instant-display path must never attach a stale `published_at` — there is no
        // second parallel map here that could drift out of sync with `latest`, since
        // both live on the same `PackageVersions` entry.
        assert_eq!(serde.published_at, None);
        let tokio = cached.get(&PackageName::new("tokio")).unwrap();
        assert_eq!(tokio.latest, "1.35.0");
        assert!(tokio.available.is_empty());
        assert_eq!(tokio.published_at, None);
    }

    #[test]
    fn test_cached_versions_from_lockfile_empty_input_is_empty_output() {
        let resolved = HashMap::new();
        assert!(cached_versions_from_lockfile(&resolved).is_empty());
    }
}
