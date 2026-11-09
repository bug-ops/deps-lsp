//! The git-tags extension shared by the GitHub Actions and GitLab CI ecosystems.
//!
//! Both ecosystems append the same SHA-comment-mismatch and unknown-ref diagnostics, and the
//! matching quick fixes, after the shared generators ran. They differ only in how a dependency
//! exposes its pin and reaches its tag index, which [`GitTagsPinning`] captures; the selection
//! and composition live here once so a fix lands in both (#1983).

use crate::diagnostic::{Diagnostic, Severity};
#[cfg(feature = "lsp-responses")]
use crate::position::Position;

#[cfg(feature = "lsp-responses")]
use super::build_sha_comment_fix_action;
use super::{
    CommentCheck, CommitSha, DependencyFormatter, DiagnosticSeverities, ShaPinComment,
    UnknownRefTarget, sha_comment_mismatch_diagnostic, unknown_ref_diagnostics,
};
use crate::Dependency;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::CodeAction;

/// How a git-tags ecosystem's formatter reads a dependency's SHA pin and tag index.
///
/// Implementors guarantee that [`Self::unknown_ref_target`] selects the same index for a pin
/// whether the diagnostic or its quick fix asks (#1781), and that [`Self::sha_comment_check`],
/// [`Self::pinned_commit`] and [`Self::sha_pin_comment`] describe the same SHA pin. Callers
/// may assume every method is a pure, non-blocking read of already-fetched state.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::GitTagsPinning;
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// // The stub formatter reads every dependency as neither a SHA pin nor a tag pin.
/// let formatter = StubFormatter::DEFAULT;
/// let dep = StubDependency::new("actions/checkout");
/// assert!(formatter.sha_comment_check(&dep).is_none());
/// assert!(formatter.pinned_commit(&dep).is_none());
/// assert!(formatter.sha_pin_comment(&dep).is_none());
/// assert!(formatter.unknown_ref_target(&dep).is_none());
/// ```
pub trait GitTagsPinning: DependencyFormatter {
    /// Whether the SHA pin's trailing `# tag` comment agrees with the tag index; `None` when
    /// `dep` is not a SHA pin.
    fn sha_comment_check(&self, dep: &Self::Dep) -> Option<CommentCheck>;

    /// The commit `dep` is pinned to, when it is a SHA pin.
    fn pinned_commit(&self, dep: &Self::Dep) -> Option<CommitSha>;

    /// The trailing comment of `dep`'s SHA pin, if it has one.
    fn sha_pin_comment<'a>(&self, dep: &'a Self::Dep) -> Option<&'a ShaPinComment>;

    /// The tag pin `dep` and the index that can speak for it; `None` when `dep` is not a tag
    /// pin or its repository's tags have not been fetched.
    fn unknown_ref_target<'a>(&self, dep: &'a Self::Dep) -> Option<UnknownRefTarget<'a>>;
}

/// One SHA-comment-mismatch diagnostic per SHA pin whose trailing `# tag` comment provably
/// names a different commit than the pinned SHA.
///
/// Silent for a confirmed, absent or unverifiable (cold or truncated index) comment.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::sha_comment_mismatch_diagnostics;
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// let deps = [StubDependency::new("actions/checkout")];
/// let diagnostics =
///     sha_comment_mismatch_diagnostics(&deps, &StubFormatter::DEFAULT, Severity::Warning);
/// assert!(diagnostics.is_empty());
/// ```
#[must_use]
pub fn sha_comment_mismatch_diagnostics<F: GitTagsPinning>(
    deps: &[F::Dep],
    formatter: &F,
    severity: Severity,
) -> Vec<Diagnostic> {
    deps.iter()
        .filter_map(|dep| {
            let CommentCheck::Mismatch(mismatch) = formatter.sha_comment_check(dep)? else {
                return None;
            };
            let comment = formatter.sha_pin_comment(dep)?;
            Some(sha_comment_mismatch_diagnostic(
                dep.version_range()?,
                dep.name(),
                &formatter.pinned_commit(dep)?,
                &comment.tag,
                &mismatch,
                severity,
            ))
        })
        .collect()
}

/// The SHA-comment-mismatch and unknown-ref diagnostics of a git-tags ecosystem, in that
/// order.
///
/// Neither is gated on the mutable-ref-pin switch: each fires only for a provable problem.
///
/// # Examples
///
/// ```
/// use deps_core::DiagnosticSeverities;
/// use deps_core::lsp_helpers::git_tags_diagnostics;
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// let deps = [StubDependency::new("actions/checkout")];
/// let diagnostics =
///     git_tags_diagnostics(&deps, &StubFormatter::DEFAULT, DiagnosticSeverities::default());
/// assert!(diagnostics.is_empty());
/// ```
#[must_use]
pub fn git_tags_diagnostics<F: GitTagsPinning>(
    deps: &[F::Dep],
    formatter: &F,
    severities: DiagnosticSeverities,
) -> Vec<Diagnostic> {
    let mut out =
        sha_comment_mismatch_diagnostics(deps, formatter, severities.sha_comment_mismatch);
    out.extend(unknown_ref_diagnostics(
        deps,
        severities.unknown_ref,
        |dep| formatter.unknown_ref_target(dep),
    ));
    out
}

/// The dependency of `deps` that `position` is on, per `is_position_on_dependency`.
#[cfg(feature = "lsp-responses")]
fn dependency_at<'a, F: GitTagsPinning>(
    deps: &'a [F::Dep],
    formatter: &F,
    position: Position,
) -> Option<&'a F::Dep> {
    deps.iter()
        .find(|dep| formatter.is_position_on_dependency(dep, position))
}

/// The "Correct version comment" quick fix (#1734) for the SHA pin at `position` whose
/// trailing `# tag` comment names another tag of the pinned commit.
///
/// Offered exactly where [`sha_comment_mismatch_diagnostics`] reports, since both read the
/// same [`GitTagsPinning::sha_comment_check`].
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::git_tags_sha_comment_fix_action;
/// use deps_core::position::Position;
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// let deps = [StubDependency::new("actions/checkout")];
/// let uri = url::Url::parse("file:///repo/.github/workflows/ci.yml").unwrap();
/// let action = git_tags_sha_comment_fix_action(
///     &deps,
///     &StubFormatter::DEFAULT,
///     Position::new(0, 0),
///     &uri,
/// );
/// assert!(action.is_none());
/// ```
#[cfg(feature = "lsp-responses")]
#[cfg_attr(docsrs, doc(cfg(feature = "lsp-responses")))]
#[must_use]
pub fn git_tags_sha_comment_fix_action<F: GitTagsPinning>(
    deps: &[F::Dep],
    formatter: &F,
    position: Position,
    uri: &url::Url,
) -> Option<CodeAction> {
    let dep = dependency_at(deps, formatter, position)?;
    let CommentCheck::Mismatch(mismatch) = formatter.sha_comment_check(dep)? else {
        return None;
    };
    build_sha_comment_fix_action(
        uri,
        dep.version_range()?,
        formatter.sha_pin_comment(dep)?,
        &mismatch,
    )
}

/// The "Change ref to published tag" quick fix (#1781) for the tag pin at `position` whose
/// ref the repository's complete tag list proves unpublished.
///
/// Selects the pin through the same [`GitTagsPinning::unknown_ref_target`] the diagnostic
/// uses, so the two can never pick different indexes.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::git_tags_unknown_ref_fix_action;
/// use deps_core::position::Position;
/// use deps_core::test_util::{StubDependency, StubFormatter};
///
/// let deps = [StubDependency::new("actions/checkout")];
/// let uri = url::Url::parse("file:///repo/.github/workflows/ci.yml").unwrap();
/// let action = git_tags_unknown_ref_fix_action(
///     &deps,
///     &StubFormatter::DEFAULT,
///     Position::new(0, 0),
///     &uri,
/// );
/// assert!(action.is_none());
/// ```
#[cfg(feature = "lsp-responses")]
#[cfg_attr(docsrs, doc(cfg(feature = "lsp-responses")))]
#[must_use]
pub fn git_tags_unknown_ref_fix_action<F: GitTagsPinning>(
    deps: &[F::Dep],
    formatter: &F,
    position: Position,
    uri: &url::Url,
) -> Option<CodeAction> {
    let dep = dependency_at(deps, formatter, position)?;
    formatter.unknown_ref_target(dep)?.fix_action(uri)
}
