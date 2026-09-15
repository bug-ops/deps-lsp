//! Editor-only reparse policy for lock-file and in-use dependency version resolution.
//!
//! The pure classification helpers this file used to hold (`collect_in_use_versions`,
//! `dependency_version_map`, `cached_versions_from_lockfile`, `split_resolved_packages`,
//! `load_resolved_versions`) moved to `deps_engine::classify::resolved` (issue #1059) — they
//! decide a verdict from data already in hand and know nothing about editor reparse triggers.

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
