//! LSP-only completion/hover support for NuGet (issue #1137, #451 follow-up).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use std::collections::HashSet;

/// Leading version-constraint operators stripped from a completion prefix before
/// matching it against registry versions: the two range delimiters
/// `version::parse_range` accepts (`[1.0,2.0)`) —
/// `deps_core::interval::BracketStyle::Standard`, no reversed-bracket form (NuGet spec
/// §2). A bare version (no leading bracket, including `1.0.*` floating versions) is a
/// floor, not a range, and has no operator to strip. Originally left empty, which meant
/// a completion prefix like `"[2.2"` was never stripped down to `"2.2"` and so never
/// prefix-matched any real version (#1137 critic S1).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['[', '('];

/// Bounds `NuGetEcosystem::generate_hover`'s `unlisted_versions` fetch (S4, #451
/// follow-up) — mirrors `deps_core::lsp_helpers::hover`'s own private `HOVER_FALLBACK_TIMEOUT`
/// for its analogous fallback fetch: hover responses must return quickly, and without this
/// bound a pathological feed's registration-hive walk could run unbounded.
pub(super) const HOVER_UNLISTED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Injects a `*(unlisted)*` marker into each `"- \`VERSION\` ..."` "Recent versions" bullet
/// line whose version is in `unlisted`, right after the version literal and before any
/// existing tag (`*(latest)*`, an age suffix, ...) — matching the position/spacing
/// `formatter.yanked_label()` occupies for other ecosystems' `*(yanked)*` markers. Lines
/// that don't match the bullet format (the `**Latest**`/`**Requirement**` lines, the footer)
/// pass through unchanged.
// `tick` comes from `find('`')`, an ASCII byte, so both slice bounds are always char
// boundaries.
#[allow(clippy::string_slice)]
pub(super) fn annotate_unlisted_versions(markdown: &str, unlisted: &HashSet<String>) -> String {
    let mut out = String::with_capacity(markdown.len() + unlisted.len() * 14);
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let matched = body.strip_prefix("- `").and_then(|rest| {
            let tick = rest.find('`')?;
            Some((&rest[..tick], &rest[tick + 1..]))
        });
        match matched {
            Some((version, rest)) if unlisted.contains(version) => {
                out.push_str("- `");
                out.push_str(version);
                out.push_str("` *(unlisted)*");
                out.push_str(rest);
            }
            _ => out.push_str(body),
        }
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}
