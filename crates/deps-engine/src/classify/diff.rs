//! Merging a completed registry fetch's deprecation and no-comparable-versions findings
//! into a document's outcome map.
//!
//! Extracted from `deps-lsp`'s `document/diff.rs` (issue #1059): both functions here decide
//! what a fetch result means for `DependencyOutcomes`, not how or when to fetch — editor-only
//! cache reconciliation (`preserve_cache`, `drop_cache_for_forced_refetch`) stays in `deps-lsp`
//! since it mutates `DocumentState` fields these functions never touch.

use deps_core::Deprecation;
use deps_core::PackageName;
use deps_core::lsp_helpers::DependencyOutcomes;
use std::collections::{HashMap, HashSet};

/// Merges a partial fetch's #205 deprecation findings into `outcomes`' deprecation channel
/// (incremental didChange path — S1).
///
/// Without the clearing half of this (S1), a package that stops being deprecated
/// (`npm deprecate pkg ""`) would keep a stale finding for the document's lifetime —
/// nothing else ever removes one (a package-level finding does not become stale on a
/// version-only edit — see the comment above `diff.version_changed`'s pruning loop in
/// `deps-lsp`'s `handle_document_change`).
///
/// `fetched_names` — every raw package name successfully fetched this round (i.e. the
/// keys of `fetch_result.versions`, captured before it is consumed) — must clear any
/// previously-recorded finding when `fetched_deprecations` has no entry for it ("fetched
/// and clean"); a name *not* fetched this round (untouched by `deps_to_fetch`) must not
/// be touched at all, which is why this takes the explicit fetched-name list rather than
/// iterating `outcomes` itself.
///
/// # Examples
///
/// ```
/// use deps_core::Deprecation;
/// use deps_core::lsp_helpers::{
///     DependencyOutcomes, DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming,
///     PackageRendering, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::{ConcreteVersion, PackageName};
/// use deps_engine::classify::diff::merge_deprecations_after_fetch;
/// use std::collections::HashMap;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// let mut outcomes = DependencyOutcomes::new();
/// outcomes.set_deprecation(
///     "old-finding".to_string(),
///     Deprecation { reason: None, replacement: None },
/// );
///
/// // "old-finding" was re-fetched this round and no longer reports a finding, so its
/// // stale marker is cleared; a name never touched by this round's fetch is left alone.
/// merge_deprecations_after_fetch(
///     &mut outcomes,
///     &[PackageName::new("old-finding")],
///     HashMap::new(),
///     &SimpleFormatter,
/// );
///
/// assert!(outcomes.deprecation("old-finding").is_none());
/// ```
pub fn merge_deprecations_after_fetch(
    outcomes: &mut DependencyOutcomes,
    fetched_names: &[PackageName],
    mut fetched_deprecations: HashMap<PackageName, Deprecation>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    // I2: decide per normalized name in one pass, not incrementally per raw name — raw
    // names sharing a normalized key (e.g. Composer's case-insensitive `require`) would
    // otherwise flip the outcome based on `fetched_names`' unspecified HashMap iteration order.
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
                outcomes.set_deprecation(normalized, deprecation);
            }
            None => {
                outcomes.clear_deprecation(&normalized);
            }
        }
    }
}

/// Merges a partial fetch's #550 no-comparable-versions findings into `outcomes`'
/// corresponding channel (incremental didChange path).
///
/// Package-level, like [`merge_deprecations_after_fetch`] (not tied to the declared
/// version, unlike `yanked`/`fetch_failure` — see the `diff.version_changed` pruning
/// loop in `deps-lsp`'s `handle_document_change` for why those two, but not this one, are
/// cleared on a version-only edit): if a package's registry situation improves between
/// fetches (a real tag gets published), a stale marker must not survive for the document's
/// lifetime.
///
/// `attempted_names` — every raw package name a fetch was actually attempted for this
/// round (`dep_sources`' keys, captured before it is consumed) — rather than
/// [`merge_deprecations_after_fetch`]'s `fetched_names` (`fetch_result.versions`'
/// keys): a no-comparable-versions package is by definition never a member of
/// `fetch_result.versions`, so deriving "attempted" from that map's keys would miss
/// every package this function exists to clear or set.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DependencyOutcomes, DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming,
///     PackageRendering, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::{ConcreteVersion, PackageName};
/// use deps_engine::classify::diff::merge_no_comparable_versions_after_fetch;
/// use std::collections::HashSet;
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// let mut outcomes = DependencyOutcomes::new();
/// let mut fetched = HashSet::new();
/// fetched.insert(PackageName::new("dtolnay-rust-toolchain"));
///
/// merge_no_comparable_versions_after_fetch(
///     &mut outcomes,
///     &[PackageName::new("dtolnay-rust-toolchain")],
///     fetched,
///     &SimpleFormatter,
/// );
///
/// assert!(outcomes.no_comparable_versions("dtolnay-rust-toolchain"));
/// ```
pub fn merge_no_comparable_versions_after_fetch(
    outcomes: &mut DependencyOutcomes,
    attempted_names: &[PackageName],
    mut fetched_no_comparable_versions: HashSet<PackageName>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) {
    // Same normalized-name dedup rationale as `merge_deprecations_after_fetch` (I2).
    let mut per_normalized: HashMap<String, bool> = HashMap::new();
    for name in attempted_names {
        let normalized = formatter.normalize_package_name(name);
        let found = fetched_no_comparable_versions.remove(name);
        let entry = per_normalized.entry(normalized).or_insert(false);
        *entry = *entry || found;
    }
    for (normalized, found) in per_normalized {
        if found {
            outcomes.set_no_comparable_versions(normalized);
        } else {
            outcomes.clear_no_comparable_versions(&normalized);
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::super::*;
        use crate::setup::CargoFormatter;

        /// T4 (C3): a deprecation finding recorded on the full-fetch path must survive
        /// a partial didChange fetch that does not re-fetch that package.
        #[test]
        fn test_merge_deprecations_after_fetch_retains_finding_for_name_not_refetched() {
            let formatter = CargoFormatter;
            let mut outcomes = DependencyOutcomes::new();
            outcomes.set_deprecation(
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
                &mut outcomes,
                &[PackageName::new("vendor/b")],
                fetched,
                &formatter,
            );

            assert_eq!(
                outcomes.deprecation("vendor/a"),
                Some(&Deprecation {
                    reason: None,
                    replacement: Some("vendor/a2".to_string()),
                }),
                "a finding for a name not in this round's fetch must survive untouched"
            );
            assert_eq!(
                outcomes.deprecation("vendor/b"),
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
            let formatter = CargoFormatter;
            let mut outcomes = DependencyOutcomes::new();
            outcomes.set_deprecation(
                "vendor/a".to_string(),
                Deprecation {
                    reason: None,
                    replacement: None,
                },
            );

            // "vendor/a" was re-fetched this round and no longer reports a finding.
            merge_deprecations_after_fetch(
                &mut outcomes,
                &[PackageName::new("vendor/a")],
                HashMap::new(),
                &formatter,
            );

            assert!(
                outcomes.deprecation("vendor/a").is_none(),
                "a name that was fetched and produced no finding must be cleared"
            );
        }

        /// Regression for critic finding C3 (#550): `merge_no_comparable_versions_after_fetch`'s
        /// `found == true` branch (`set_no_comparable_versions`) had zero coverage — mirrors
        /// `test_merge_deprecations_after_fetch_retains_finding_for_name_not_refetched`, but
        /// for the *first-time-set* case: a package attempted this round whose fetch
        /// genuinely found zero comparable versions must be recorded, and an unrelated
        /// package not attempted this round must be left untouched either way.
        #[test]
        fn test_merge_no_comparable_versions_after_fetch_sets_finding_for_newly_flagged_name() {
            let formatter = CargoFormatter;
            let mut outcomes = DependencyOutcomes::new();

            // "vendor/b" was attempted this round (e.g. a new dependency added by the
            // edit) and its fetch genuinely succeeded with zero comparable versions;
            // "vendor/a" was not attempted at all.
            let mut fetched = HashSet::new();
            fetched.insert(PackageName::new("vendor/b"));
            merge_no_comparable_versions_after_fetch(
                &mut outcomes,
                &[PackageName::new("vendor/b")],
                fetched,
                &formatter,
            );

            assert!(
                outcomes.no_comparable_versions("vendor/b"),
                "a package whose fetch was attempted and found zero comparable versions \
                 this round must be recorded"
            );
            assert!(
                !outcomes.no_comparable_versions("vendor/a"),
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
            let formatter = CargoFormatter;
            let mut outcomes = DependencyOutcomes::new();
            outcomes.set_no_comparable_versions("vendor/a".to_string());

            // "vendor/a" was re-fetched this round and this time resolved a real
            // version, so it's absent from the fetched-flags set.
            merge_no_comparable_versions_after_fetch(
                &mut outcomes,
                &[PackageName::new("vendor/a")],
                HashSet::new(),
                &formatter,
            );

            assert!(
                !outcomes.no_comparable_versions("vendor/a"),
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
            let formatter = CargoFormatter;
            let mut outcomes = DependencyOutcomes::new();
            outcomes.set_no_comparable_versions("vendor/a".to_string());

            // Only "vendor/b" was attempted this round; "vendor/a" was untouched.
            merge_no_comparable_versions_after_fetch(
                &mut outcomes,
                &[PackageName::new("vendor/b")],
                HashSet::new(),
                &formatter,
            );

            assert!(
                outcomes.no_comparable_versions("vendor/a"),
                "a finding for a name not attempted this round must survive untouched"
            );
        }
    }

    // Sibling to `cargo_tests` above (not nested inside it) so this test is reachable under
    // `--features composer` alone.
    #[cfg(feature = "composer")]
    mod composer_tests {
        use super::super::*;
        use crate::setup::ComposerFormatter;

        /// I2: two raw names that normalize to the same key (Composer's `normalize_package_name`
        /// lowercases, so `"Vendor/Package"` and `"vendor/package"` collide) must merge
        /// deterministically — a finding under either raw name must survive regardless of
        /// `fetched_names`' (unspecified `HashMap::keys()`) iteration order.
        #[test]
        fn test_merge_deprecations_after_fetch_is_order_independent_across_normalization_collision()
        {
            let formatter = ComposerFormatter;

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
                let mut outcomes = DependencyOutcomes::new();

                let mut fetched = HashMap::new();
                fetched.insert(
                    PackageName::new("Vendor/Package"),
                    Deprecation {
                        reason: None,
                        replacement: Some("vendor/other".to_string()),
                    },
                );
                // "vendor/package" (lowercase) is fetched too and reports no finding.

                merge_deprecations_after_fetch(&mut outcomes, &names, fetched, &formatter);

                assert_eq!(
                    outcomes.deprecation("vendor/package"),
                    Some(&Deprecation {
                        reason: None,
                        replacement: Some("vendor/other".to_string()),
                    }),
                    "a finding under either raw name sharing a normalized key must survive, \
                     regardless of fetch order: {names:?}"
                );
            }
        }
    }
}
