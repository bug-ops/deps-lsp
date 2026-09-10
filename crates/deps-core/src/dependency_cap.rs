//! Per-document ceiling on tracked dependencies (#796).
//!
//! Nothing upstream of [`crate::ecosystem::Ecosystem::parse_manifest`] bounds dependency
//! *count* the way `deps_lsp::document::loader::MAX_FILE_SIZE` bounds file *size*: every
//! dependency a parser finds becomes an entry in several `DocumentState` maps (cached
//! versions, resolved versions, outcomes, licenses, vulnerabilities) and one outbound
//! registry request, so both memory and outbound request volume scale linearly with a
//! number an untrusted manifest's author controls. Two layers enforce the ceiling:
//!
//! 1. **[`DependencyBudget`]** (the primary fix, #796 critic finding C1) is threaded
//!    through each ecosystem crate's own dependency-collecting loop(s), so the backing
//!    `Vec` a concrete `ParseResult` retains for the life of the document — e.g.
//!    `NpmParseResult.dependencies` — never grows past the cap in the first place. An
//!    earlier version of this fix truncated only the `Vec<&dyn Dependency>`
//!    [`ParseResult::dependencies`] returns, *after* the full oversized backing
//!    collection had already been built and retained — measured to still cost ~0.9KB of
//!    sustained RSS per *declared* (not tracked) dependency, fully attacker-controlled.
//!    Each ecosystem's own manifest-format parser (`toml-span`/`serde_json`/`quick-xml`/
//!    `yaml-rust2`) still builds one in-memory AST of the whole input before dependency
//!    extraction runs — that transient cost is bounded by
//!    `deps_lsp::document::loader::MAX_FILE_SIZE`, the same way it always was, and is not
//!    what this ceiling targets.
//! 2. **[`crate::dependency_cap::cap_dependencies`]**, applied once in
//!    [`crate::ecosystem::parse_manifest_blocking`]
//!    (the single chokepoint every ecosystem's parse result flows through), is a
//!    belt-and-braces backstop: if a well-behaved ecosystem's own budget already holds it
//!    at or under the cap, this is a no-op pass-through (one cheap `.len()` check, no
//!    allocation); it only does real work — bounding the *view* `dependencies()` returns
//!    and thus the registry fetch fan-out — if some ecosystem parser is ever added or
//!    changed without wiring in [`DependencyBudget`].

use std::any::Any;
use std::path::Path;

use tower_lsp_server::ls_types::{Range, Uri};

use crate::ecosystem::{Dependency, ParseResult};
use crate::net_policy::HostClass;

/// Maximum number of dependencies [`ParseResult::dependencies`] returns for one open
/// document, enforced by [`cap_dependencies`].
///
/// Hardcoded rather than exposed as a `deps-lsp` config setting, mirroring
/// `deps_lsp::document::loader::MAX_FILE_SIZE`'s own "security limit, not a user
/// preference" reasoning: the largest real-world manifests (large monorepo
/// `package.json`/`Cargo.toml` files) sit in the low hundreds of dependencies, so this
/// leaves generous headroom while still bounding the pathological/adversarial case — a
/// manifest with hundreds of thousands of declarations (#796's measured repro: a 6.92MB
/// `package.json` with 330,000 unique deps drove peak RSS to 850MB and would have fanned
/// out roughly 480,000 registry requests at the 10MB file-size cap).
pub const MAX_DEPENDENCIES_PER_DOCUMENT: usize = 5000;

/// Bounds how many dependencies an ecosystem's own manifest parser retains.
///
/// Checked once per manifest entry, before the (potentially expensive:
/// name/range/version-requirement/...) `Dependency` struct for it is built into its
/// concrete `Vec<XDependency>` — never truncated after the fact.
///
/// Each ecosystem crate constructs one `DependencyBudget::new(MAX_DEPENDENCIES_PER_DOCUMENT)`
/// at the top of its parse entry point and threads `&mut` it through every dependency-
/// collecting loop that manifest format has (a manifest can declare dependencies across
/// several sections/targets — e.g. Cargo's `[dependencies]`/`[dev-dependencies]`/
/// `[build-dependencies]`, each possibly repeated per `[target.<spec>]` — all sharing the
/// same budget, since the ceiling is per-document, not per-section). Call [`Self::allow`]
/// as the first thing in the loop body, before doing any other per-entry work, and only
/// build/push the entry when it returns `true`.
///
/// # Examples
///
/// ```
/// use deps_core::dependency_cap::DependencyBudget;
///
/// let mut budget = DependencyBudget::new(2);
/// assert!(budget.allow());
/// assert!(budget.allow());
/// assert!(!budget.allow(), "third entry exceeds the cap of 2");
///
/// assert_eq!(budget.truncation(), Some((2, 3)));
/// ```
#[derive(Debug)]
pub struct DependencyBudget {
    kept: usize,
    total: usize,
    cap: usize,
}

impl DependencyBudget {
    /// Builds a fresh budget allowing at most `cap` dependencies to be kept.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            kept: 0,
            total: 0,
            cap,
        }
    }

    /// Call once per dependency entry the parser encounters, before building/pushing its
    /// `Dependency` struct. Returns `true` while the budget still has room — build and push
    /// the entry only when this returns `true`; when it returns `false`, skip the
    /// (potentially expensive) struct construction entirely rather than building it only
    /// to discard it.
    pub const fn allow(&mut self) -> bool {
        self.total += 1;
        if self.kept < self.cap {
            self.kept += 1;
            true
        } else {
            false
        }
    }

    /// `Some((kept, total))` once more entries were seen than the budget allowed; `None` if
    /// every entry seen so far fit within the cap. Read by each ecosystem's `ParseResult`
    /// to populate [`ParseResult::dependency_truncation`].
    #[must_use]
    pub const fn truncation(&self) -> Option<(usize, usize)> {
        if self.total > self.cap {
            Some((self.kept, self.total))
        } else {
            None
        }
    }
}

/// Truncates `inner`'s dependencies to at most `cap`, if it has more than that; returns
/// `inner` unchanged otherwise.
///
/// The overwhelming majority of real manifests never approach the ceiling, so this only
/// allocates a wrapper on the rare oversized document — the common path pays only the one
/// `dependencies().len()` call needed to decide whether wrapping is necessary.
///
/// # Examples
///
/// ```
/// use deps_core::dependency_cap::{MAX_DEPENDENCIES_PER_DOCUMENT, cap_dependencies};
/// use deps_core::ecosystem::ParseResult;
/// # use deps_core::test_util::stub_parse_result_with_dependencies;
///
/// let inner = stub_parse_result_with_dependencies(MAX_DEPENDENCIES_PER_DOCUMENT + 1);
/// let capped: Box<dyn ParseResult> = cap_dependencies(inner, MAX_DEPENDENCIES_PER_DOCUMENT);
///
/// assert_eq!(capped.dependencies().len(), MAX_DEPENDENCIES_PER_DOCUMENT);
/// assert_eq!(
///     capped.dependency_truncation(),
///     Some((MAX_DEPENDENCIES_PER_DOCUMENT, MAX_DEPENDENCIES_PER_DOCUMENT + 1))
/// );
/// ```
#[must_use]
pub fn cap_dependencies(inner: Box<dyn ParseResult>, cap: usize) -> Box<dyn ParseResult> {
    let total = inner.dependencies().len();
    if total <= cap {
        return inner;
    }
    Box::new(DependencyCappedParseResult { inner, cap, total })
}

/// [`ParseResult`] wrapper produced by [`cap_dependencies`] once a manifest's dependency
/// count exceeds [`MAX_DEPENDENCIES_PER_DOCUMENT`].
///
/// Delegates every method to `inner` except [`ParseResult::dependencies`] (truncated) and
/// [`ParseResult::dependency_truncation`] (reports what was truncated, read by
/// `deps_core::lsp_helpers::diagnostics`' informational notice). `as_any` delegates
/// straight to `inner.as_any()` rather than returning `self` — this wrapper's own type is
/// never what callers downcast to, so an ecosystem-specific read through `ParseResult`
/// (e.g. Composer's `minimum_stability`) keeps working unchanged on a capped document.
///
/// This delegation means a caller that downcasts via `as_any()` and reads a concrete
/// ecosystem type's own `pub dependencies` field directly (bypassing this wrapper's
/// truncated [`ParseResult::dependencies`]) sees whatever that field holds. As long as
/// every ecosystem wires in [`DependencyBudget`] at its own collection loop (module doc,
/// point 1 — true for all 14 as of #796), that field is itself already capped, so this is
/// not a bypass in practice; it would only become one for an ecosystem parser added
/// without a budget, in which case this wrapper's truncated view is the sole enforcement
/// point for such a downcast-based reader.
struct DependencyCappedParseResult {
    inner: Box<dyn ParseResult>,
    cap: usize,
    total: usize,
}

impl ParseResult for DependencyCappedParseResult {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        let mut deps = self.inner.dependencies();
        deps.truncate(self.cap);
        deps
    }

    fn workspace_root(&self) -> Option<&Path> {
        self.inner.workspace_root()
    }

    fn uri(&self) -> &Uri {
        self.inner.uri()
    }

    fn blocked_registries(&self) -> Vec<(Range, HostClass, String)> {
        self.inner.blocked_registries()
    }

    fn as_any(&self) -> &dyn Any {
        self.inner.as_any()
    }

    fn dependency_truncation(&self) -> Option<(usize, usize)> {
        Some((self.cap, self.total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::stub_parse_result_with_dependencies;

    #[test]
    fn cap_dependencies_truncates_when_over_the_ceiling() {
        let inner = stub_parse_result_with_dependencies(12);
        let capped = cap_dependencies(inner, 10);

        assert_eq!(capped.dependencies().len(), 10);
        assert_eq!(capped.dependency_truncation(), Some((10, 12)));
    }

    #[test]
    fn cap_dependencies_leaves_a_document_at_the_ceiling_untouched() {
        let inner = stub_parse_result_with_dependencies(10);
        let capped = cap_dependencies(inner, 10);

        assert_eq!(capped.dependencies().len(), 10);
        assert_eq!(
            capped.dependency_truncation(),
            None,
            "a document exactly at the ceiling must not be reported as truncated"
        );
    }

    #[test]
    fn cap_dependencies_leaves_a_document_under_the_ceiling_untouched() {
        let inner = stub_parse_result_with_dependencies(3);
        let capped = cap_dependencies(inner, 10);

        assert_eq!(capped.dependencies().len(), 3);
        assert_eq!(capped.dependency_truncation(), None);
    }

    #[test]
    fn capped_dependencies_keep_their_original_identity() {
        let inner = stub_parse_result_with_dependencies(5);
        let capped = cap_dependencies(inner, 2);

        let names: Vec<_> = capped
            .dependencies()
            .iter()
            .map(|d| d.name().to_string())
            .collect();
        assert_eq!(names, vec!["dep-0", "dep-1"]);
    }

    #[test]
    fn budget_allows_up_to_the_cap_and_refuses_beyond_it() {
        let mut budget = DependencyBudget::new(3);
        assert!(budget.allow());
        assert!(budget.allow());
        assert!(budget.allow());
        assert!(!budget.allow());
        assert!(!budget.allow());

        assert_eq!(budget.truncation(), Some((3, 5)));
    }

    #[test]
    fn budget_at_exactly_the_cap_reports_no_truncation() {
        let mut budget = DependencyBudget::new(3);
        assert!(budget.allow());
        assert!(budget.allow());
        assert!(budget.allow());

        assert_eq!(budget.truncation(), None);
    }

    #[test]
    fn budget_under_the_cap_reports_no_truncation() {
        let mut budget = DependencyBudget::new(10);
        assert!(budget.allow());

        assert_eq!(budget.truncation(), None);
    }

    #[test]
    fn budget_of_zero_refuses_every_entry() {
        let mut budget = DependencyBudget::new(0);
        assert!(!budget.allow());
        assert!(!budget.allow());

        assert_eq!(budget.truncation(), Some((0, 2)));
    }
}
