//! The `unknown-ref` diagnostic (#1766), shared by every git-tags-datasource ecosystem (GitHub
//! Actions, GitLab CI).
//!
//! Reports a tag pin whose ref is a full release no published tag matches
//! ([`super::UnpublishedRef::Release`]): the workflow would fail to resolve it at runtime. A
//! partial shape (`v1`, `v5.x`, `v3-node20`) may be a documented branch pin, so it is never
//! reported; the status of such a pin is decided separately (see
//! [`super::UnpublishedRef::cap_status`]).

use std::sync::Arc;

use super::sanitize_and_truncate_for_diagnostic;
use super::{MAX_DIAGNOSTIC_VALUE_CHARS, TagIndex, UnpublishedRef, redact_name_for_diagnostic};
use crate::PackageName;
use crate::diagnostic::{Diagnostic, DiagnosticKind, Severity};
use crate::position::{Position, Range};
use crate::{Dependency, ParseResult};

use super::EcosystemFormatter;

#[cfg(feature = "lsp-responses")]
use super::{is_tag_shaped, single_file_edit};
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, WorkspaceEdit};

/// Stable [`Diagnostic::code`] of the unknown-ref diagnostic (#1766).
pub const UNKNOWN_REF_DIAGNOSTIC_CODE: &str = "unknown-ref";

/// Builds the unknown-ref [`Diagnostic`] for a pin at `range` written as `written`, a full
/// release that no published tag of `name` matches.
///
/// `written` and `name` come from the manifest and are sanitized and bounded here.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::{UNKNOWN_REF_DIAGNOSTIC_CODE, unknown_ref_diagnostic};
/// use deps_core::position::{Position, Range};
///
/// let range = Range::new(Position::new(0, 10), Position::new(0, 15));
/// let diagnostic =
///     unknown_ref_diagnostic(range, &PackageName::new("actions/checkout"), "4.3.1", Severity::Warning);
/// assert_eq!(diagnostic.code(), Some(UNKNOWN_REF_DIAGNOSTIC_CODE));
/// assert!(diagnostic.message().contains("`4.3.1` is not a published tag"));
/// ```
#[must_use]
pub fn unknown_ref_diagnostic(
    range: Range,
    name: &PackageName,
    written: &str,
    severity: Severity,
) -> Diagnostic {
    let name = redact_name_for_diagnostic(name);
    let written = sanitize_and_truncate_for_diagnostic(written, MAX_DIAGNOSTIC_VALUE_CHARS);
    Diagnostic::new(
        DiagnosticKind::UnknownRef,
        range,
        format!("`{written}` is not a published tag of {name}"),
    )
    .with_severity(severity)
}

/// The unknown-ref [`Diagnostic`] for a tag pin `written` at `range`, when `index` proves it
/// unpublished.
///
/// Only a full release ([`UnpublishedRef::Release`]) is reported; `None` for a partial shape (it
/// may be a branch), a listed tag, and an index that cannot prove absence.
///
/// The shared tail of every git-tags ecosystem's diagnostics pass: the ecosystem only decides
/// which pins are tag pins and which index serves them.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::{CommitSha, TagIndex, unknown_ref_diagnostic_for};
/// use deps_core::position::Range;
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = TagIndex::from_tags([("v4.3.1", &sha)]);
/// let name = PackageName::new("actions/checkout");
/// let report = |written| {
///     unknown_ref_diagnostic_for(&index, &name, written, Range::default(), Severity::Warning)
/// };
/// assert!(report("4.3.1").is_some());
/// assert!(report("v40").is_none());
/// assert!(report("v4.3.1").is_none());
/// ```
#[must_use]
pub fn unknown_ref_diagnostic_for(
    index: &TagIndex,
    name: &PackageName,
    written: &str,
    range: Range,
    severity: Severity,
) -> Option<Diagnostic> {
    match index.unpublished_tag_ref(written)? {
        UnpublishedRef::Release => Some(unknown_ref_diagnostic(range, name, written, severity)),
        UnpublishedRef::Partial => None,
    }
}

/// The dependency of `parse_result` that `position` is on, per
/// `is_position_on_dependency`.
///
/// The shared first step of every per-position quick fix of a git-tags ecosystem.
#[must_use]
pub fn dependency_at_position<'a>(
    parse_result: &'a dyn ParseResult,
    position: Position,
    formatter: &dyn EcosystemFormatter,
) -> Option<&'a dyn Dependency> {
    parse_result
        .dependencies()
        .into_iter()
        .find(|dep| formatter.is_position_on_dependency(*dep, position))
}

/// A tag pin together with the tag index that can speak for it.
///
/// The one input both the unknown-ref diagnostic and its quick fix are derived from, so the two
/// can never select different indexes for the same pin (#1781).
///
/// Each git-tags ecosystem builds it from its own tag-pinned dependency
/// (`unknown_ref_target`), deciding which index serves the pin; the shared tail lives here.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use deps_core::PackageName;
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::{CommitSha, TagIndex, UnknownRefTarget};
/// use deps_core::position::Range;
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = Arc::new(TagIndex::from_tags([("v4.3.1", &sha)]));
/// let target = UnknownRefTarget::new(index, "4.3.1", Range::default());
/// let name = PackageName::new("actions/checkout");
/// assert!(target.diagnostic(&name, Severity::Warning).is_some());
/// ```
#[derive(Debug, Clone)]
pub struct UnknownRefTarget<'a> {
    index: Arc<TagIndex>,
    written: &'a str,
    range: Range,
}

impl<'a> UnknownRefTarget<'a> {
    /// Pairs the `written` ref spanning exactly `range` with the `index` that serves it.
    #[must_use]
    pub const fn new(index: Arc<TagIndex>, written: &'a str, range: Range) -> Self {
        Self {
            index,
            written,
            range,
        }
    }

    /// The unknown-ref [`Diagnostic`] for this pin, when its index proves it unpublished. See
    /// [`unknown_ref_diagnostic_for`].
    #[must_use]
    pub fn diagnostic(&self, name: &PackageName, severity: Severity) -> Option<Diagnostic> {
        unknown_ref_diagnostic_for(&self.index, name, self.written, self.range, severity)
    }

    /// The quick fix for [`Self::diagnostic`], when exactly one published tag matches. See
    /// [`build_unknown_ref_fix_action`].
    #[cfg(feature = "lsp-responses")]
    #[cfg_attr(docsrs, doc(cfg(feature = "lsp-responses")))]
    #[must_use]
    pub fn fix_action(&self, uri: &url::Url) -> Option<CodeAction> {
        build_unknown_ref_fix_action(uri, self.range, &self.index, self.written)
    }
}

/// One unknown-ref [`Diagnostic`] (#1766) per dependency of `parse_result` whose
/// [`UnknownRefTarget`] proves its ref unpublished.
///
/// `target` is the ecosystem's only decision: which dependencies are tag pins and which tag
/// list serves them (`None` for a SHA or branch pin, a pin without a position, and a cold index
/// or one served by an endpoint that cannot prove a tag absent). Silent for a partial shape and
/// for an index that cannot prove absence, see [`unknown_ref_diagnostic_for`].
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::{CommitSha, TagIndex, UnknownRefTarget, unknown_ref_diagnostics};
/// use deps_core::parser::DependencySource;
/// use deps_core::position::Range;
/// use deps_core::{Dependency, PackageName, ParseResult, VersionReq};
///
/// struct Step(PackageName);
/// impl Dependency for Step {
///     fn name(&self) -> &PackageName { &self.0 }
///     fn name_range(&self) -> Range { Range::default() }
///     fn version_requirement(&self) -> Option<&VersionReq> { None }
///     fn version_range(&self) -> Option<Range> { None }
///     fn source(&self) -> DependencySource { DependencySource::Registry }
///     fn as_any(&self) -> &dyn std::any::Any { self }
/// }
///
/// struct Workflow(url::Url, Vec<Step>);
/// impl ParseResult for Workflow {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.1.iter().map(|s| s as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> { None }
///     fn uri(&self) -> &url::Url { &self.0 }
///     fn as_any(&self) -> &dyn std::any::Any { self }
/// }
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = Arc::new(TagIndex::from_tags([("v4.3.1", &sha)]));
/// let workflow = Workflow(
///     url::Url::parse("file:///ci.yml").unwrap(),
///     vec![Step(PackageName::new("actions/checkout"))],
/// );
/// let found = unknown_ref_diagnostics(&workflow, Severity::Warning, |_dep| {
///     Some(UnknownRefTarget::new(Arc::clone(&index), "4.3.1", Range::default()))
/// });
/// assert_eq!(found.len(), 1);
/// ```
#[must_use]
pub fn unknown_ref_diagnostics(
    parse_result: &dyn ParseResult,
    severity: Severity,
    target: impl for<'a> Fn(&'a dyn Dependency) -> Option<UnknownRefTarget<'a>>,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| target(dep)?.diagnostic(dep.name(), severity))
        .collect()
}

/// Builds the "Change ref to published tag" quickfix (#1781) for a tag pin `written` spanning
/// `version_range` that `index` proves unpublished.
///
/// The edit replaces the whole ref with the published spelling resolved through
/// [`TagIndex::release_tag`] (`4.3.1` -> `v4.3.1`). `None` unless all of these hold, so the fix
/// is offered exactly where [`unknown_ref_diagnostic_for`] reports and never guesses:
/// - the index proves `written` is an unpublished full release ([`UnpublishedRef::Release`]);
/// - exactly one published tag matches (`release_tag` is `None` when the matching spellings
///   point at different commits);
/// - the tag differs from `written`, is tag-shaped, and survives sanitization unchanged.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommitSha, TagIndex, build_unknown_ref_fix_action};
/// use deps_core::position::{Position, Range};
///
/// let uri = url::Url::parse("file:///repo/ci.yml").unwrap();
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = TagIndex::from_tags([("v4.3.1", &sha)]);
/// let range = Range::new(Position::new(0, 25), Position::new(0, 30));
///
/// let action = build_unknown_ref_fix_action(&uri, range, &index, "4.3.1").unwrap();
/// assert_eq!(action.title, "Change ref to published tag `v4.3.1`");
/// assert!(build_unknown_ref_fix_action(&uri, range, &index, "v4.3.1").is_none());
/// assert!(build_unknown_ref_fix_action(&uri, range, &index, "v9.9.9").is_none());
/// ```
#[cfg(feature = "lsp-responses")]
#[cfg_attr(docsrs, doc(cfg(feature = "lsp-responses")))]
#[must_use]
pub fn build_unknown_ref_fix_action(
    uri: &url::Url,
    version_range: Range,
    index: &TagIndex,
    written: &str,
) -> Option<CodeAction> {
    if index.unpublished_tag_ref(written) != Some(UnpublishedRef::Release) {
        return None;
    }
    let tag = index.release_tag(written)?;
    if tag == written
        || !is_tag_shaped(tag)
        || sanitize_and_truncate_for_diagnostic(tag, MAX_DIAGNOSTIC_VALUE_CHARS) != tag
    {
        return None;
    }
    let changes = single_file_edit(uri, version_range, tag.to_string());
    Some(CodeAction {
        title: format!("Change ref to published tag `{tag}`"),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [UNKNOWN_REF_DIAGNOSTIC_CODE],
            "diagnostic_range": tower_lsp_server::ls_types::Range::from(version_range),
        })),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::Position;

    fn diagnostic(written: &str) -> Diagnostic {
        unknown_ref_diagnostic(
            Range::new(Position::new(1, 2), Position::new(1, 8)),
            &PackageName::new("owner/repo"),
            written,
            Severity::Error,
        )
    }

    struct StubDep(PackageName);

    impl Dependency for StubDep {
        fn name(&self) -> &PackageName {
            &self.0
        }
        fn name_range(&self) -> Range {
            Range::default()
        }
        fn version_requirement(&self) -> Option<&crate::VersionReq> {
            None
        }
        fn version_range(&self) -> Option<Range> {
            None
        }
        fn source(&self) -> crate::parser::DependencySource {
            crate::parser::DependencySource::Registry
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct StubParse {
        uri: url::Url,
        deps: Vec<StubDep>,
    }

    impl ParseResult for StubParse {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            self.deps.iter().map(|d| d as &dyn Dependency).collect()
        }
        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }
        fn uri(&self) -> &url::Url {
            &self.uri
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn helper_reports_only_pins_the_callback_serves_and_the_index_disproves() {
        let sha = super::super::CommitSha::parse(&"a".repeat(40)).unwrap();
        let index = Arc::new(TagIndex::from_tags([("v4.3.1", &sha)]));
        let parse = StubParse {
            uri: url::Url::parse("file:///ci.yml").unwrap(),
            deps: ["missing", "listed", "branch", "unserved"]
                .map(|n| StubDep(PackageName::new(n)))
                .into(),
        };
        let found = unknown_ref_diagnostics(&parse, Severity::Warning, |dep| {
            let written = match dep.name().as_str() {
                "missing" => "4.3.2",
                "listed" => "v4.3.1",
                "branch" => "v40",
                _ => return None,
            };
            Some(UnknownRefTarget::new(
                Arc::clone(&index),
                written,
                Range::new(Position::new(3, 1), Position::new(3, 6)),
            ))
        });
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].message(),
            "`4.3.2` is not a published tag of missing"
        );
        assert_eq!(found[0].severity, Some(Severity::Warning));
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn carries_code_severity_and_range() {
        let d = diagnostic("4.3.1");
        assert_eq!(d.code(), Some(UNKNOWN_REF_DIAGNOSTIC_CODE));
        assert_eq!(d.severity, Some(Severity::Error));
        assert_eq!(d.message(), "`4.3.1` is not a published tag of owner/repo");
    }

    #[test]
    fn hostile_ref_text_is_sanitized_and_bounded() {
        let long = format!("v1.0.0-{}", "x".repeat(MAX_DIAGNOSTIC_VALUE_CHARS * 2));
        assert!(diagnostic(&long).message().chars().count() < long.chars().count());
        let bidi = diagnostic("v1.0.0\u{202E}x");
        assert!(!bidi.message().contains('\u{202E}'), "{}", bidi.message());
    }

    #[cfg(feature = "lsp-responses")]
    mod fix_action {
        use super::*;
        use crate::lsp_helpers::CommitSha;

        fn sha(c: char) -> CommitSha {
            CommitSha::parse(&c.to_string().repeat(40)).unwrap()
        }

        fn uri() -> url::Url {
            url::Url::parse("file:///repo/ci.yml").unwrap()
        }

        fn fix(index: &TagIndex, written: &str) -> Option<CodeAction> {
            build_unknown_ref_fix_action(&uri(), Range::default(), index, written)
        }

        #[test]
        fn rewrites_to_the_single_published_spelling() {
            let index = TagIndex::from_tags([("v4.3.1", &sha('a'))]);
            let action = fix(&index, "4.3.1").unwrap();
            let edits = action.edit.unwrap().changes.unwrap();
            let edit = &edits.values().next().unwrap()[0];
            assert_eq!(edit.new_text, "v4.3.1");
            assert_eq!(
                action.data.unwrap()["diagnostic_codes"][0],
                UNKNOWN_REF_DIAGNOSTIC_CODE
            );
        }

        #[test]
        fn withheld_when_the_ref_is_listed_partial_or_absent() {
            let index = TagIndex::from_tags([("v4.3.1", &sha('a'))]);
            assert!(fix(&index, "v4.3.1").is_none());
            assert!(fix(&index, "v40").is_none());
            assert!(fix(&index, "v9.9.9").is_none());
        }

        #[test]
        fn withheld_when_matching_spellings_name_different_commits() {
            let ambiguous = TagIndex::from_tags([("v5.0.0", &sha('a')), ("5.0.0", &sha('b'))]);
            assert!(fix(&ambiguous, "V5.0.0").is_none());
        }

        #[test]
        fn withheld_on_a_truncated_or_empty_index() {
            let truncated = TagIndex::from_tags([("v4.3.1", &sha('a'))])
                .with_coverage(crate::pagination::ListCoverage::Truncated);
            assert!(fix(&truncated, "4.3.1").is_none());
            assert!(fix(&TagIndex::default(), "4.3.1").is_none());
        }

        #[test]
        fn target_derives_diagnostic_and_fix_from_the_same_index() {
            let index = Arc::new(TagIndex::from_tags([("v4.3.1", &sha('a'))]));
            let target = UnknownRefTarget::new(index, "4.3.1", Range::default());
            assert!(
                target
                    .diagnostic(&PackageName::new("owner/repo"), Severity::Warning)
                    .is_some()
            );
            assert!(target.fix_action(&uri()).is_some());
        }
    }
}
