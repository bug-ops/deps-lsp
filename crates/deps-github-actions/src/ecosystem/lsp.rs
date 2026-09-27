//! LSP-only completion/code-action support for GitHub Actions (issues #473/#633/#1138/#1182).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use tower_lsp_server::ls_types::{CodeAction, Position, TextEdit};

use super::{
    GithubActionsDependency, GithubActionsFormatter, MUTABLE_REF_PIN_DIAGNOSTIC_CODE,
    ParseResultTrait, PinStyle, Url,
};

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions. Empty: a `uses:` ref is a bare tag/branch/SHA, with no
/// comparison/caret/tilde operator syntax (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &[];

/// Whether `position` sits strictly past a comment-annotated SHA pin's own ref text —
/// see `GithubActionsEcosystem::generate_completions`'s doc for why this check exists
/// (issue #1182) and why it cannot be a check on the extracted completion prefix.
///
/// Finds the dependency whose (deliberately widened) `version_range` contains
/// `position` and, only when it is a [`PinStyle::Sha`] with a `comment_tag` (the one
/// form where `version_range` extends past the ref's own text), compares `position`
/// against the SHA's own end column — [`crate::types::sha_pin_raw_sha`]'s length, added
/// to the range's start — rather than the range's own (widened) end. A position exactly
/// at that column (cursor immediately after the last SHA character, still typing it) is
/// deliberately *not* past it, so a commentless SHA pin's ordinary end-of-ref position is
/// unaffected; a [`PinStyle::Sha`] with no `comment_tag` has no widened tail at all
/// (`sha_pin_raw_sha` still resolves it, but its `version_range` already ends exactly at
/// the SHA's own end, so this predicate can never fire for it).
pub(super) fn position_past_sha_pin_own_ref(
    parse_result: &dyn ParseResultTrait,
    position: Position,
) -> bool {
    let position: deps_core::position::Position = position.into();
    parse_result.dependencies().into_iter().any(|dep| {
        let Some(range) = dep.version_range() else {
            return false;
        };
        if !deps_core::position_in_range(position, range) {
            return false;
        }
        let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
            return false;
        };
        if !matches!(
            gha_dep.pin,
            Some(PinStyle::Sha {
                comment_tag: Some(_)
            })
        ) {
            return false;
        }
        let Some(sha) = crate::types::sha_pin_raw_sha(gha_dep) else {
            return false;
        };
        let Ok(sha_len) = u32::try_from(sha.len()) else {
            return false;
        };
        position.character > range.start.character.saturating_add(sha_len)
    })
}

/// Builds the "Pin `{name}` to commit SHA" quickfix (issue #473, US-002) for the
/// `PinStyle::Tag` dependency at `position`, if `GithubActionsFormatter::sha_pin_replacement_for`
/// resolves its current tag against the shared `TagIndex`.
///
/// Returns `None` (no destructive/no-op edit, FR-005) when the dependency at `position`
/// is not `PinStyle::Tag`, has no `version_range`, or the `TagIndex` lookup misses (cache
/// miss — e.g. the document was opened before the registry fetch completed).
///
/// Deliberately **not** widened to `is_registry_confirmed_tag`'s `PinStyle::Branch`
/// case the way `mutable_ref_pin_diagnostics` is (#551 plan): FR-005/plan §11 (see
/// `test_build_sha_pin_action_no_quickfix_for_branch_pin`) already forbids this
/// quickfix for a `PinStyle::Branch` step even when a same-named `TagIndex` entry
/// exists, since git permits a branch and a tag to share one name and GitHub's own
/// `uses:` ref resolution for that collision is undocumented — an *automated edit*
/// that silently pins to the tag's commit could pin to a different commit than the
/// ref actually resolves to at run time. A diagnostic's advisory text carries no such
/// risk (pinning to *some* SHA is safer than a moving ref either way), but this
/// destructive edit keeps the stricter, pre-#551 guard.
///
/// Delegates entirely to [`deps_core::lsp_helpers::build_sha_pin_action`] (issue #1138) via
/// [`GithubActionsFormatter`]'s [`deps_core::lsp_helpers::ShaPinning`] impl, which carries
/// this guard.
pub(super) fn build_sha_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Url,
    formatter: &GithubActionsFormatter,
) -> Option<CodeAction> {
    deps_core::lsp_helpers::build_sha_pin_action(
        parse_result,
        position,
        uri,
        formatter,
        MUTABLE_REF_PIN_DIAGNOSTIC_CODE,
    )
}

/// Builds one [`TextEdit`] per `PinStyle::Tag` step in `parse_result` resolvable to a
/// commit SHA via `formatter`'s `TagIndex` — the bulk counterpart to
/// [`build_sha_pin_action`]'s single-step quickfix (issue #633). A step with no
/// resolvable `TagIndex` entry (cache miss) is silently skipped, exactly like that
/// quickfix's own withholding behavior — never blocking on, or triggering, a fetch.
pub(super) fn collect_pin_all_to_sha_edits(
    parse_result: &dyn ParseResultTrait,
    formatter: &GithubActionsFormatter,
) -> Vec<TextEdit> {
    let edits: Vec<TextEdit> = parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| deps_core::lsp_helpers::sha_pin_text_edit(formatter, dep))
        .collect();
    deps_core::lsp_helpers::dedup_overlapping_edits(edits, "collect_pin_all_to_sha_edits")
}
