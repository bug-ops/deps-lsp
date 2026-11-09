//! Shared builder for the mutable-ref-pin diagnostic of the git-tags-shaped ecosystems
//! (GitHub Actions, GitLab CI).
//!
//! Each ecosystem decides which dependencies are diagnosable and whether a quickfix exists;
//! this module owns the message text, name/ref sanitization and diagnostic kind, so the two
//! wordings cannot drift.

use crate::PackageName;
use crate::diagnostic::{Diagnostic, DiagnosticKind, GitTagsPlatform, Severity};
use crate::position::Range;

use super::diagnostics::{
    MAX_DIAGNOSTIC_VALUE_CHARS, redact_name_for_diagnostic, sanitize_and_truncate_for_diagnostic,
};

const MANUAL_EDIT_SUFFIX: &str = " (manual edit — no automated fix available for this ref)";

/// What a diagnosable dependency is, which selects the platform and the noun in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSubject {
    /// A GitHub Actions `uses:` step.
    GithubAction,
    /// A GitLab CI `project:` include.
    GitlabProject,
    /// A GitLab CI `component:` include.
    GitlabComponent,
}

impl PinSubject {
    const fn platform(self) -> GitTagsPlatform {
        match self {
            Self::GithubAction => GitTagsPlatform::GithubActions,
            Self::GitlabProject | Self::GitlabComponent => GitTagsPlatform::GitlabCi,
        }
    }
}

/// The kind of GitLab CI include carrying a floating (`latest` / partial-version) ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitlabInclude {
    /// A `project:` include.
    Project,
    /// A `component:` include.
    Component,
}

impl GitlabInclude {
    const fn noun(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Component => "component",
        }
    }
}

/// Whether a "Pin to commit SHA" quickfix is offered for the dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixAvailability {
    /// The code action will be offered, so the message carries no manual-edit note.
    Automated,
    /// No automated fix, so the message says the edit is manual.
    ManualOnly,
}

/// One mutable-ref finding, ready to be rendered by [`Self::into_diagnostic`].
#[derive(Debug, Clone, Copy)]
pub enum MutableRefPin<'a> {
    /// A GitLab `project:` include without any `ref:`, which defaults to the mutable default
    /// branch; anchored on the project name since there is no ref span.
    MissingRef {
        /// The project the include names.
        name: &'a PackageName,
        /// Where the diagnostic points.
        anchor: Range,
    },
    /// A fixed ref (a tag, or a branch the registry confirms is also a published tag) that
    /// can be moved.
    Ref {
        /// What carries the ref.
        subject: PinSubject,
        /// The dependency name.
        name: &'a PackageName,
        /// Where the diagnostic points: the ref's version span.
        anchor: Range,
        /// The ref as written; sanitized and truncated when rendered.
        ref_text: &'a str,
        /// Whether a quickfix is offered.
        fix: FixAvailability,
    },
    /// A GitLab `latest` or partial-version ref, which resolves to whichever release currently
    /// matches rather than a fixed version.
    Floating {
        /// What carries the ref.
        include: GitlabInclude,
        /// The dependency name.
        name: &'a PackageName,
        /// Where the diagnostic points: the ref's version span.
        anchor: Range,
        /// The ref as written; sanitized and truncated when rendered.
        ref_text: &'a str,
        /// Whether a quickfix is offered.
        fix: FixAvailability,
    },
}

impl MutableRefPin<'_> {
    /// Renders the finding as a [`DiagnosticKind::MutableRefPin`] diagnostic at `severity`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::diagnostic::Severity;
    /// use deps_core::lsp_helpers::{FixAvailability, MutableRefPin, PinSubject};
    /// use deps_core::position::{Position, Range};
    ///
    /// let name = PackageName::new("actions/checkout");
    /// let range = Range::new(Position::new(0, 0), Position::new(0, 2));
    /// let diagnostic = MutableRefPin::Ref {
    ///     subject: PinSubject::GithubAction,
    ///     name: &name,
    ///     anchor: range,
    ///     ref_text: "v4",
    ///     fix: FixAvailability::Automated,
    /// }
    /// .into_diagnostic(Severity::Hint);
    /// assert!(diagnostic.message().contains("mutable tag ref `v4`"));
    /// ```
    #[must_use]
    pub fn into_diagnostic(self, severity: Severity) -> Diagnostic {
        let (platform, anchor, message) = match self {
            Self::MissingRef { name, anchor } => {
                let name = redact_name_for_diagnostic(name);
                (
                    GitTagsPlatform::GitlabCi,
                    anchor,
                    format!(
                        "{name} project has no `ref:`; GitLab CI defaults to the project's \
                         default branch, which is mutable — add an explicit `ref:` pinned \
                         to a tag or commit SHA (manual edit — no automated fix available)"
                    ),
                )
            }
            Self::Ref {
                subject,
                name,
                anchor,
                ref_text,
                fix,
            } => (
                subject.platform(),
                anchor,
                ref_message(subject, name, ref_text, fix),
            ),
            Self::Floating {
                include,
                name,
                anchor,
                ref_text,
                fix,
            } => (
                GitTagsPlatform::GitlabCi,
                anchor,
                floating_message(include, name, ref_text, fix),
            ),
        };
        Diagnostic::new(DiagnosticKind::MutableRefPin(platform), anchor, message)
            .with_severity(severity)
    }
}

const fn suffix(fix: FixAvailability) -> &'static str {
    match fix {
        FixAvailability::Automated => "",
        FixAvailability::ManualOnly => MANUAL_EDIT_SUFFIX,
    }
}

fn ref_message(
    subject: PinSubject,
    name: &PackageName,
    ref_text: &str,
    fix: FixAvailability,
) -> String {
    let name = redact_name_for_diagnostic(name);
    let tag = sanitize_and_truncate_for_diagnostic(ref_text, MAX_DIAGNOSTIC_VALUE_CHARS);
    let suffix = suffix(fix);
    match subject {
        PinSubject::GithubAction => format!(
            "{name} is pinned to the mutable tag ref `{tag}`; pin to a full commit SHA to \
             guard against tag mutation{suffix}"
        ),
        PinSubject::GitlabProject => format!(
            "{name} project is pinned to the mutable ref `{tag}`; pin to a full commit SHA to \
             guard against ref mutation{suffix}"
        ),
        PinSubject::GitlabComponent => format!(
            "{name} component is pinned to the mutable ref `{tag}`; pin to a full commit SHA \
             to guard against ref mutation{suffix}"
        ),
    }
}

fn floating_message(
    include: GitlabInclude,
    name: &PackageName,
    ref_text: &str,
    fix: FixAvailability,
) -> String {
    let name = redact_name_for_diagnostic(name);
    let tag = sanitize_and_truncate_for_diagnostic(ref_text, MAX_DIAGNOSTIC_VALUE_CHARS);
    let noun = include.noun();
    let suffix = suffix(fix);
    format!(
        "{name} {noun} is pinned to `{tag}`, which always resolves to whichever release \
         currently matches rather than a fixed version; pin to an exact release and commit \
         SHA to guard against ref mutation{suffix}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::Position;

    fn range() -> Range {
        Range::new(Position::new(0, 0), Position::new(0, 4))
    }

    fn name(raw: &str) -> PackageName {
        PackageName::new(raw)
    }

    fn fixed(
        subject: PinSubject,
        name: &PackageName,
        ref_text: &str,
        fix: FixAvailability,
    ) -> Diagnostic {
        MutableRefPin::Ref {
            subject,
            name,
            anchor: range(),
            ref_text,
            fix,
        }
        .into_diagnostic(Severity::Hint)
    }

    fn floating(include: GitlabInclude, fix: FixAvailability) -> Diagnostic {
        MutableRefPin::Floating {
            include,
            name: &name("o/r"),
            anchor: range(),
            ref_text: "v1",
            fix,
        }
        .into_diagnostic(Severity::Hint)
    }

    #[test]
    fn github_tag_message_matches_legacy_wording() {
        let d = fixed(
            PinSubject::GithubAction,
            &name("o/r"),
            "v1",
            FixAvailability::Automated,
        );
        assert_eq!(
            d.message(),
            "o/r is pinned to the mutable tag ref `v1`; pin to a full commit SHA to guard \
             against tag mutation"
        );
        assert_eq!(
            d.kind(),
            &DiagnosticKind::MutableRefPin(GitTagsPlatform::GithubActions)
        );
    }

    #[test]
    fn github_manual_only_carries_suffix() {
        let d = fixed(
            PinSubject::GithubAction,
            &name("o/r"),
            "v1",
            FixAvailability::ManualOnly,
        );
        assert!(d.message().ends_with(MANUAL_EDIT_SUFFIX));
    }

    #[test]
    fn gitlab_messages_carry_noun_and_ref_wording() {
        let d = fixed(
            PinSubject::GitlabProject,
            &name("o/r"),
            "v1",
            FixAvailability::ManualOnly,
        );
        assert_eq!(
            d.message(),
            "o/r project is pinned to the mutable ref `v1`; pin to a full commit SHA to guard \
             against ref mutation (manual edit — no automated fix available for this ref)"
        );
        let d = fixed(
            PinSubject::GitlabComponent,
            &name("o/r"),
            "v1",
            FixAvailability::Automated,
        );
        assert!(
            d.message()
                .starts_with("o/r component is pinned to the mutable ref `v1`")
        );
        let d = floating(GitlabInclude::Component, FixAvailability::Automated);
        assert_eq!(
            d.message(),
            "o/r component is pinned to `v1`, which always resolves to whichever release \
             currently matches rather than a fixed version; pin to an exact release and commit \
             SHA to guard against ref mutation"
        );
        assert_eq!(
            d.kind(),
            &DiagnosticKind::MutableRefPin(GitTagsPlatform::GitlabCi)
        );
        let d = floating(GitlabInclude::Project, FixAvailability::ManualOnly);
        assert!(d.message().starts_with("o/r project is pinned to `v1`"));
        assert!(d.message().ends_with(MANUAL_EDIT_SUFFIX));
    }

    #[test]
    fn ref_text_is_sanitized_and_truncated() {
        let long = format!("v{}", "9".repeat(MAX_DIAGNOSTIC_VALUE_CHARS * 2));
        let d = fixed(
            PinSubject::GithubAction,
            &name("o/r"),
            &long,
            FixAvailability::Automated,
        );
        let expected = sanitize_and_truncate_for_diagnostic(&long, MAX_DIAGNOSTIC_VALUE_CHARS);
        assert!(expected.chars().count() < long.chars().count());
        assert!(d.message().contains(&format!("`{expected}`")));
        assert!(!d.message().contains(&long));

        let d = fixed(
            PinSubject::GitlabProject,
            &name("o/r"),
            "v1\u{202e}\nx",
            FixAvailability::Automated,
        );
        assert!(!d.message().contains('\u{202e}'));
        assert!(!d.message().contains('\n'));
    }

    #[test]
    fn name_is_redacted() {
        let secret = name("https://user:hunter2@example.com/o/r");
        let expected = redact_name_for_diagnostic(&secret);
        assert!(!expected.contains("hunter2"));
        let d = fixed(
            PinSubject::GithubAction,
            &secret,
            "v1",
            FixAvailability::Automated,
        );
        assert!(d.message().starts_with(&expected));

        let m = MutableRefPin::MissingRef {
            name: &secret,
            anchor: range(),
        }
        .into_diagnostic(Severity::Hint);
        assert!(!m.message().contains("hunter2"));
    }

    #[test]
    fn missing_ref_wording_intentionally_differs_from_manual_edit_suffix() {
        let n = name("g/p");
        let d = MutableRefPin::MissingRef {
            name: &n,
            anchor: range(),
        }
        .into_diagnostic(Severity::Warning);
        assert!(d.message().starts_with("g/p project has no `ref:`"));
        assert!(
            d.message()
                .ends_with("(manual edit — no automated fix available)")
        );
        assert!(!d.message().contains(MANUAL_EDIT_SUFFIX));
    }
}
