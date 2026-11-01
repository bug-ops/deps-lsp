//! Merging a completed registry fetch's deprecation and lookup-miss findings
//! into a document's outcome map.
//!
//! Extracted from `deps-lsp`'s `document/diff.rs` (issue #1059): both functions here decide
//! what a fetch result means for `DependencyOutcomes`, not how or when to fetch — editor-only
//! cache reconciliation (`preserve_cache`, `drop_cache_for_forced_refetch`) stays in `deps-lsp`
//! since it mutates `DocumentState` fields these functions never touch.

use deps_core::Deprecation;
use deps_core::NormalizedName;
use deps_core::lsp_helpers::{DependencyOutcomes, LookupMiss};
use std::collections::HashMap;

/// Merges a partial fetch's #205 deprecation findings into `outcomes`' deprecation channel
/// (incremental didChange path — S1).
///
/// Without the clearing half of this (S1), a package that stops being deprecated
/// (`npm deprecate pkg ""`) would keep a stale finding for the document's lifetime —
/// nothing else ever removes one (a package-level finding does not become stale on a
/// version-only edit — see the comment above `diff.version_changed`'s pruning loop in
/// `deps-lsp`'s `handle_document_change`).
///
/// `fetched_names` — every normalized package name successfully fetched this round (i.e. the
/// keys of `fetch_result.versions`, captured before it is consumed) — must clear any
/// previously-recorded finding when `fetched_deprecations` has no entry for it ("fetched
/// and clean"); a name *not* fetched this round (untouched by `deps_to_fetch`) must not
/// be touched at all, which is why this takes the explicit fetched-name list rather than
/// iterating `outcomes` itself.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::DependencyOutcomes;
/// use deps_core::{Deprecation, NormalizedName};
/// use deps_engine::classify::diff::merge_deprecations_after_fetch;
/// use std::collections::HashMap;
///
/// let old_finding = NormalizedName::for_test("old-finding");
/// let mut outcomes = DependencyOutcomes::new();
/// outcomes.set_deprecation(
///     old_finding.clone(),
///     Deprecation { reason: None, replacement: None },
/// );
///
/// // "old-finding" was re-fetched this round and no longer reports a finding, so its
/// // stale marker is cleared; a name never touched by this round's fetch is left alone.
/// merge_deprecations_after_fetch(&mut outcomes, &[old_finding.clone()], HashMap::new());
///
/// assert!(outcomes.deprecation(&old_finding).is_none());
/// ```
pub fn merge_deprecations_after_fetch(
    outcomes: &mut DependencyOutcomes,
    fetched_names: &[NormalizedName],
    mut fetched_deprecations: HashMap<NormalizedName, Deprecation>,
) {
    for name in fetched_names {
        outcomes.clear_deprecation(name);
    }
    for name in fetched_names {
        if let Some(deprecation) = fetched_deprecations.remove(name) {
            outcomes.set_deprecation(name.clone(), deprecation);
        }
    }
}

/// Merges a partial fetch's lookup-miss findings (#550, #1891) into `outcomes`' corresponding
/// channel (incremental didChange path).
///
/// Package-level, like [`merge_deprecations_after_fetch`] (not tied to the declared
/// version, unlike `yanked`/`fetch_failure` — see the `diff.version_changed` pruning
/// loop in `deps-lsp`'s `handle_document_change` for why those two, but not this one, are
/// cleared on a version-only edit): if a package's registry situation improves between
/// fetches (a real tag gets published), a stale marker must not survive for the document's
/// lifetime.
///
/// `attempted_names` — every normalized package name a fetch was actually attempted for this
/// round (`dep_sources`' keys, captured before it is consumed) — rather than
/// [`merge_deprecations_after_fetch`]'s `fetched_names` (`fetch_result.versions`'
/// keys): a missed package is by definition never a member of `fetch_result.versions`, so
/// deriving "attempted" from that map's keys would miss every package this function exists
/// to clear or set. A name's previous miss is replaced, so `NotFound` and
/// `NoComparableVersions` can switch between fetches.
///
/// # Examples
///
/// ```
/// use deps_core::NormalizedName;
/// use deps_core::lsp_helpers::{DependencyOutcomes, LookupMiss};
/// use deps_engine::classify::diff::merge_lookup_misses_after_fetch;
/// use std::collections::HashMap;
///
/// let toolchain = NormalizedName::for_test("dtolnay-rust-toolchain");
/// let mut outcomes = DependencyOutcomes::new();
/// let mut fetched = HashMap::new();
/// fetched.insert(toolchain.clone(), LookupMiss::NoComparableVersions);
///
/// merge_lookup_misses_after_fetch(&mut outcomes, &[toolchain.clone()], fetched);
///
/// assert_eq!(
///     outcomes.lookup_miss(&toolchain),
///     Some(LookupMiss::NoComparableVersions)
/// );
/// ```
pub fn merge_lookup_misses_after_fetch(
    outcomes: &mut DependencyOutcomes,
    attempted_names: &[NormalizedName],
    fetched_lookup_misses: HashMap<NormalizedName, LookupMiss>,
) {
    for name in attempted_names {
        outcomes.clear_lookup_miss(name);
    }
    for name in attempted_names {
        if let Some(miss) = fetched_lookup_misses.get(name) {
            outcomes.set_lookup_miss(name.clone(), *miss);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(spelling: &str) -> NormalizedName {
        NormalizedName::for_test(spelling)
    }

    fn deprecation(replacement: &str) -> Deprecation {
        Deprecation {
            reason: None,
            replacement: Some(replacement.to_string()),
        }
    }

    /// T4 (C3): a deprecation finding recorded on the full-fetch path must survive
    /// a partial didChange fetch that does not re-fetch that package.
    #[test]
    fn test_merge_deprecations_after_fetch_retains_finding_for_name_not_refetched() {
        let mut outcomes = DependencyOutcomes::new();
        outcomes.set_deprecation(name("vendor/a"), deprecation("vendor/a2"));

        // Only "vendor/b" was fetched this round (e.g. a new dependency added by
        // the edit); "vendor/a" was untouched.
        let mut fetched = HashMap::new();
        fetched.insert(
            name("vendor/b"),
            Deprecation {
                reason: Some("abandoned".to_string()),
                replacement: None,
            },
        );
        merge_deprecations_after_fetch(&mut outcomes, &[name("vendor/b")], fetched);

        assert_eq!(
            outcomes.deprecation(&name("vendor/a")),
            Some(&deprecation("vendor/a2")),
            "a finding for a name not in this round's fetch must survive untouched"
        );
        assert_eq!(
            outcomes.deprecation(&name("vendor/b")),
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
        let mut outcomes = DependencyOutcomes::new();
        outcomes.set_deprecation(
            name("vendor/a"),
            Deprecation {
                reason: None,
                replacement: None,
            },
        );

        merge_deprecations_after_fetch(&mut outcomes, &[name("vendor/a")], HashMap::new());

        assert!(
            outcomes.deprecation(&name("vendor/a")).is_none(),
            "a name that was fetched and produced no finding must be cleared"
        );
    }

    /// A repeated name in `fetched_names` must not let a later iteration clear what an
    /// earlier one set.
    #[test]
    fn test_merge_deprecations_after_fetch_is_idempotent_for_repeated_names() {
        let mut outcomes = DependencyOutcomes::new();
        let mut fetched = HashMap::new();
        fetched.insert(name("vendor/package"), deprecation("vendor/other"));

        merge_deprecations_after_fetch(
            &mut outcomes,
            &[name("vendor/package"), name("vendor/package")],
            fetched,
        );

        assert_eq!(
            outcomes.deprecation(&name("vendor/package")),
            Some(&deprecation("vendor/other"))
        );
    }

    /// A package attempted this round whose lookup missed must be recorded, and an
    /// unrelated package not attempted this round must be left untouched.
    #[test]
    fn test_merge_lookup_misses_after_fetch_sets_finding_for_newly_flagged_name() {
        let mut outcomes = DependencyOutcomes::new();
        let mut fetched = HashMap::new();
        fetched.insert(name("vendor/b"), LookupMiss::NoComparableVersions);
        merge_lookup_misses_after_fetch(&mut outcomes, &[name("vendor/b")], fetched);

        assert_eq!(
            outcomes.lookup_miss(&name("vendor/b")),
            Some(LookupMiss::NoComparableVersions)
        );
        assert_eq!(outcomes.lookup_miss(&name("vendor/a")), None);
    }

    /// A package that later resolves a real version must have its stale miss cleared.
    #[test]
    fn test_merge_lookup_misses_after_fetch_clears_finding_when_refetched_with_versions() {
        let mut outcomes = DependencyOutcomes::new();
        outcomes.set_lookup_miss(name("vendor/a"), LookupMiss::NotFound);

        merge_lookup_misses_after_fetch(&mut outcomes, &[name("vendor/a")], HashMap::new());

        assert_eq!(outcomes.lookup_miss(&name("vendor/a")), None);
    }

    /// A finding for a name not attempted this round must survive untouched.
    #[test]
    fn test_merge_lookup_misses_after_fetch_retains_finding_for_name_not_attempted() {
        let mut outcomes = DependencyOutcomes::new();
        outcomes.set_lookup_miss(name("vendor/a"), LookupMiss::NotFound);

        merge_lookup_misses_after_fetch(&mut outcomes, &[name("vendor/b")], HashMap::new());

        assert_eq!(
            outcomes.lookup_miss(&name("vendor/a")),
            Some(LookupMiss::NotFound)
        );
    }

    /// The previous miss kind is replaced when the next fetch reports the other kind.
    #[test]
    fn test_merge_lookup_misses_after_fetch_switches_kind() {
        let mut outcomes = DependencyOutcomes::new();
        outcomes.set_lookup_miss(name("vendor/a"), LookupMiss::NotFound);
        let mut fetched = HashMap::new();
        fetched.insert(name("vendor/a"), LookupMiss::NoComparableVersions);

        merge_lookup_misses_after_fetch(&mut outcomes, &[name("vendor/a")], fetched);

        assert_eq!(
            outcomes.lookup_miss(&name("vendor/a")),
            Some(LookupMiss::NoComparableVersions)
        );
    }
}
