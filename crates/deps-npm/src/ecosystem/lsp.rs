//! LSP-only completion/hover support for npm (issue #1137, catalog hover).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use super::NpmDependency;

/// Leading version-constraint operators stripped from a completion prefix before
/// matching it against registry versions: `node-semver`'s caret, tilde, comparison, and
/// wildcard operators. No `!` — `node-semver` ranges have no `!=` operator (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['^', '~', '=', '<', '>', '*'];

/// Renders the `**Catalog**` hover line for `dep`, or `None` for a non-catalog dependency.
///
/// `` `catalog:react17` → `^17.0.2` `` when resolved; the outcome's own message otherwise
/// (including [`crate::catalog::CatalogOutcome::NonSemverEntry`], which gets no diagnostic but
/// still deserves a hover explanation of why no version comparison ran).
pub(super) fn catalog_hover_line(dep: &NpmDependency) -> Option<String> {
    let origin = dep.catalog.as_ref()?;
    Some(format!(
        "\n**Catalog**: {}\n",
        origin.hover_detail(dep.name.as_str())
    ))
}
