//! LSP-only completion/code-action support for GitHub Actions (issues #473/#633/#1138/#1182).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use deps_core::lsp_helpers::{CommentCheck, PackageRendering};
use tower_lsp_server::ls_types::{CodeAction, Position, TextEdit};

use super::{
    GithubActionsDependency, GithubActionsFormatter, MUTABLE_REF_PIN_DIAGNOSTIC_CODE,
    ParseResultTrait, Url,
};

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions. Empty: a `uses:` ref is a bare tag/branch/SHA, with no
/// comparison/caret/tilde operator syntax (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &[];

/// Whether `position` sits strictly past a comment-annotated SHA pin's own ref text —
/// see `GithubActionsEcosystem::generate_completions`'s doc for why this check exists
/// (issue #1182) and why it cannot be a check on the extracted completion prefix.
///
/// Only a [`PinStyle::Sha`] with a `comment` has a `version_range` extending past the ref, so
/// only there is `position` compared against the SHA's own end column (range start plus SHA
/// length). A position exactly at that column (still typing the SHA) is not past it.
pub(super) fn position_past_sha_pin_own_ref(
    parse_result: &dyn ParseResultTrait,
    position: Position,
) -> bool {
    let position: deps_core::position::Position = position.into();
    parse_result.dependencies().into_iter().any(|dep| {
        let Some(range) = dep.version_range() else {
            return false;
        };
        let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
            return false;
        };
        gha_dep.sha_comment().is_some()
            && deps_core::lsp_helpers::position_past_sha(range, position)
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

/// Builds the "Correct version comment" quickfix (#1734) for the SHA pin at `position` whose
/// trailing `# tag` comment names a different tag than the one the pinned commit carries.
///
/// Locates the pin and its [`CommentCheck`] mismatch, then delegates to the shared
/// [`deps_core::lsp_helpers::build_sha_comment_fix_action`].
pub(super) fn build_sha_comment_fix_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Url,
    formatter: &GithubActionsFormatter,
) -> Option<CodeAction> {
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position.into()))?;
    let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
    let CommentCheck::Mismatch(mismatch) = formatter.sha_comment_check(gha_dep)? else {
        return None;
    };
    deps_core::lsp_helpers::build_sha_comment_fix_action(
        uri,
        gha_dep.version_range?,
        gha_dep.sha_comment()?.pin_comment(),
        &mismatch,
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
