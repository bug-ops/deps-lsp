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
//! 2. **[`crate::ecosystem::ParsedManifest`]**, which
//!    [`crate::ecosystem::parse_manifest_blocking`] returns for every ecosystem's parse result
//!    (the single chokepoint), is a belt-and-braces backstop: if a well-behaved ecosystem's own
//!    budget already holds it at or under the cap, its view equals the parse result's own; it
//!    only does real work — bounding the *view* `dependencies()` returns and thus the registry
//!    fetch fan-out — if some ecosystem parser is ever added or changed without wiring in
//!    [`DependencyBudget`].

#[cfg(doc)]
use crate::ecosystem::ParseResult;

/// Maximum number of dependencies [`ParseResult::dependencies`] returns for one open
/// document, enforced by [`crate::ecosystem::ParsedManifest`].
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

#[cfg(test)]
mod tests {
    use super::*;

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
