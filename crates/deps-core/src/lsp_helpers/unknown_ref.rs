//! The `unknown-ref` diagnostic (#1766), shared by every git-tags-datasource ecosystem (GitHub
//! Actions, GitLab CI).
//!
//! Reports a tag pin whose ref is a full release no published tag matches
//! ([`super::UnpublishedRef::Release`]): the workflow would fail to resolve it at runtime. A
//! partial shape (`v1`, `v5.x`, `v3-node20`) may be a documented branch pin, so it is never
//! reported; the status of such a pin is decided separately (see
//! [`super::UnpublishedRef::cap_status`]).

use super::sanitize_and_truncate_for_diagnostic;
use super::{MAX_DIAGNOSTIC_VALUE_CHARS, TagIndex, UnpublishedRef, redact_name_for_diagnostic};
use crate::PackageName;
use crate::diagnostic::{Diagnostic, Severity};
use crate::position::Range;

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
        range,
        format!("`{written}` is not a published tag of {name}"),
    )
    .with_severity(severity)
    .with_code(UNKNOWN_REF_DIAGNOSTIC_CODE)
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
}
