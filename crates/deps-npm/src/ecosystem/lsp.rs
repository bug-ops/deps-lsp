//! LSP-only completion/hover support for npm (issue #1137, catalog hover).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use std::time::Duration;

use super::NpmDependency;
use crate::catalog_usage::{CatalogUsageIndex, Completeness};
use crate::types::NpmDependencyOrigin;

/// How long a hover waits for the workspace member walk before omitting the "Used by" line;
/// the walk keeps running and the next hover finds it cached.
pub(super) const CATALOG_USAGE_WAIT_BUDGET: Duration = Duration::from_millis(700);

/// Leading version-constraint operators stripped from a completion prefix before
/// matching it against registry versions: `node-semver`'s caret, tilde, comparison, and
/// wildcard operators. No `!` — `node-semver` ranges have no `!=` operator (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['^', '~', '=', '<', '>', '*'];

/// Renders the `**Override**` hover line naming the packages and range an `overrides:` entry is
/// limited to, or `None` for any other dependency.
pub(super) fn override_hover_line(dep: &NpmDependency) -> Option<String> {
    use deps_core::lsp_helpers::{markdown_code_span, truncate_for_diagnostic};

    let NpmDependencyOrigin::Override { selector } = &dep.origin else {
        return None;
    };
    let mut scope = String::new();
    for parent in selector.parents() {
        scope.push_str(parent.as_str());
        scope.push_str(" > ");
    }
    scope.push_str(dep.name.as_str());
    if let Some(range) = selector.target_selector() {
        scope.push('@');
        scope.push_str(range.as_str());
    }
    let bounded =
        truncate_for_diagnostic(&scope, deps_core::lsp_helpers::MAX_DIAGNOSTIC_VALUE_CHARS);
    let scope = deps_core::net_policy::sanitize_invisible(&bounded);
    Some(format!("\n**Override**: {}\n", markdown_code_span(&scope)))
}

/// Renders the `**Catalog**` hover line for `dep`, or `None` for a non-catalog dependency.
///
/// `` `catalog:react17` → `^17.0.2` `` when resolved; the outcome's own message otherwise
/// (including [`crate::catalog::CatalogOutcome::NonSemverEntry`], which gets no diagnostic but
/// still deserves a hover explanation of why no version comparison ran).
pub(super) fn catalog_hover_line(dep: &NpmDependency) -> Option<String> {
    let origin = dep.catalog_ref()?;
    Some(format!(
        "\n**Catalog**: {}\n",
        origin.hover_detail(dep.name.as_str())
    ))
}

/// Renders the `**Used by**` hover line for a catalog entry, or `None` for any other dependency
/// (and for a truncated walk that found no reference, where no claim can be made).
pub(super) fn catalog_usage_line(dep: &NpmDependency, index: &CatalogUsageIndex) -> Option<String> {
    let NpmDependencyOrigin::CatalogEntry { id, .. } = &dep.origin else {
        return None;
    };
    let count = index.count(id, &dep.name);
    let line = match (count, index.completeness()) {
        (0, Completeness::Complete) => "Not referenced by any workspace package".to_string(),
        (0, Completeness::Truncated) => return None,
        (n, Completeness::Complete) => format!("**Used by** {n} workspace {}", packages(n)),
        (n, Completeness::Truncated) => {
            format!("**Used by** at least {n} workspace {}", packages(n))
        }
    };
    Some(format!("\n{line}\n"))
}

const fn packages(count: usize) -> &'static str {
    if count == 1 { "package" } else { "packages" }
}
