//! Protocol-agnostic diagnostic types (issue #1083, spec 064).
//!
//! [`crate::diagnostic::Diagnostic`], [`crate::diagnostic::Severity`],
//! [`crate::diagnostic::RelatedInformation`], and [`crate::diagnostic::CodeDescription`] are
//! the domain-level replacement for `tower_lsp_server::ls_types::{Diagnostic,
//! DiagnosticSeverity, DiagnosticRelatedInformation, CodeDescription}` in
//! [`crate::lsp_helpers::generate_diagnostics_from_cache`]'s and
//! [`crate::ecosystem::Ecosystem::generate_diagnostics`]'s return value: field-for-field
//! equivalent, but this module carries no dependency on `tower-lsp-server`, so a consumer that
//! only needs parsed diagnostic data (e.g. `deps-cli`) never has to name an LSP-protocol type
//! or link `tower-lsp-server` to run `check`.
//!
//! `deps-lsp` converts a [`crate::diagnostic::Diagnostic`] (and its nested types) into the
//! matching `ls_types` type at its own boundary (`crates/deps-lsp/src/lsp_types_interop.rs`)
//! — the same shape [`crate::position`] already established for `Position`/`Range` (see that
//! module's docs for why the conversion lives in `deps-lsp` rather than here for
//! `url::Url`-carrying types).

use crate::lsp_helpers::{
    DEPRECATED_DIAGNOSTIC_CODE, LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE,
    SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE, TYPOSQUAT_DIAGNOSTIC_CODE, UNKNOWN_REF_DIAGNOSTIC_CODE,
    UNSATISFIABLE_DIAGNOSTIC_CODE,
};
use crate::osv::OsvId;
use crate::position::Range;

/// Wire code of GitHub Actions' mutable-ref-pin diagnostic.
pub const GITHUB_ACTIONS_MUTABLE_REF_PIN_DIAGNOSTIC_CODE: &str = "mutable-ref-pin";

/// Wire code of GitLab CI's mutable-ref-pin diagnostic.
pub const GITLAB_CI_MUTABLE_REF_PIN_DIAGNOSTIC_CODE: &str = "gitlab-ci-mutable-ref-pin";

/// Wire code of GitLab CI's unresolved-instance-host notice.
pub const GITLAB_CI_UNRESOLVED_HOST_DIAGNOSTIC_CODE: &str = "unresolved-gitlab-host";

/// Git-tag-pinning CI platform a mutable-ref-pin diagnostic was raised for.
///
/// A dedicated two-variant enum rather than [`crate::EcosystemId`], which would admit
/// ecosystems that have no mutable-ref-pin diagnostic at all.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::{DiagnosticKind, GitTagsPlatform};
///
/// let kind = DiagnosticKind::MutableRefPin(GitTagsPlatform::GitlabCi);
/// assert_eq!(kind.code(), Some("gitlab-ci-mutable-ref-pin"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitTagsPlatform {
    /// GitHub Actions workflows.
    GithubActions,
    /// GitLab CI/CD pipelines.
    GitlabCi,
}

/// What a [`Diagnostic`] reports, set by the producer.
///
/// Exhaustive (no `#[non_exhaustive]`) on purpose: every consumer that classifies diagnostics
/// (e.g. `deps-cli check`'s `--fail-on` categories) matches it without a wildcard arm, so a new
/// kind fails to compile until every classifier has decided what to do with it (#1784). The
/// wire [`Self::code`] is derived from the kind, never set independently.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::DiagnosticKind;
/// use deps_core::osv::OsvId;
///
/// let advisory = DiagnosticKind::Advisory(OsvId::parse("GHSA-xxxx-yyyy-zzzz").unwrap());
/// assert_eq!(advisory.code(), Some("GHSA-xxxx-yyyy-zzzz"));
/// assert_eq!(DiagnosticKind::Outdated.code(), None);
/// assert_eq!(DiagnosticKind::Unsatisfiable.code(), Some("unsatisfiable-requirement"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiagnosticKind {
    /// A newer version than the requirement admits is available.
    Outdated,
    /// The requirement already admits a latest version OSV flags as vulnerable/malicious.
    FlaggedLatest,
    /// The OSV check for the requirement's admitted latest version could not be completed.
    UnverifiedLatest,
    /// The resolved or only-matching version is yanked.
    Yanked,
    /// One OSV advisory affecting the resolved version.
    Advisory(OsvId),
    /// The trailing "+N more advisories" summary line.
    AdvisoryOverflow,
    /// The requirement matches no published version.
    Unsatisfiable,
    /// The declared license violates the configured policy.
    LicensePolicy,
    /// The package is deprecated.
    Deprecated,
    /// The package name resembles a far more popular one.
    Typosquat,
    /// A mutable git ref (branch or floating tag) is pinned instead of a commit.
    MutableRefPin(GitTagsPlatform),
    /// A SHA pin whose trailing version comment disagrees with the pinned commit.
    ShaCommentMismatch,
    /// A git ref that does not exist upstream.
    UnknownRef,
    /// GitLab CI's instance host is unset or invalid.
    UnresolvedGitlabHost,
    /// An informational or failure notice with no machine-readable code: unknown package, fetch
    /// failure, offline/blocked-registry/dependency-count notices.
    Notice,
}

impl DiagnosticKind {
    /// Returns the stable machine-readable wire code for this kind, if it has one.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::DiagnosticKind;
    ///
    /// assert_eq!(DiagnosticKind::Typosquat.code(), Some("typosquat-suspect"));
    /// assert_eq!(DiagnosticKind::Notice.code(), None);
    /// ```
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Advisory(id) => Some(id.as_str()),
            Self::Unsatisfiable => Some(UNSATISFIABLE_DIAGNOSTIC_CODE),
            Self::LicensePolicy => Some(LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE),
            Self::Deprecated => Some(DEPRECATED_DIAGNOSTIC_CODE),
            Self::Typosquat => Some(TYPOSQUAT_DIAGNOSTIC_CODE),
            Self::MutableRefPin(GitTagsPlatform::GithubActions) => {
                Some(GITHUB_ACTIONS_MUTABLE_REF_PIN_DIAGNOSTIC_CODE)
            }
            Self::MutableRefPin(GitTagsPlatform::GitlabCi) => {
                Some(GITLAB_CI_MUTABLE_REF_PIN_DIAGNOSTIC_CODE)
            }
            Self::ShaCommentMismatch => Some(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE),
            Self::UnknownRef => Some(UNKNOWN_REF_DIAGNOSTIC_CODE),
            Self::UnresolvedGitlabHost => Some(GITLAB_CI_UNRESOLVED_HOST_DIAGNOSTIC_CODE),
            Self::Outdated
            | Self::FlaggedLatest
            | Self::UnverifiedLatest
            | Self::Yanked
            | Self::AdvisoryOverflow
            | Self::Notice => None,
        }
    }
}

/// A diagnostic severity level, field-for-field identical to
/// `tower_lsp_server::ls_types::DiagnosticSeverity`'s four defined values, but carrying no
/// dependency on `tower-lsp-server`.
///
/// `Deserialize` is deliberately as permissive as `ls_types::DiagnosticSeverity` itself
/// (`#[serde(transparent)]` over a bare `i32`, which accepts *any* integer with no
/// validation at all) — see this type's `Deserialize` impl doc for why an out-of-range
/// integer clamps to the nearest defined variant instead of failing deserialization.
///
/// Declaration order doubles as the canonical severity ordering (`Error` most severe,
/// `Hint` least) — the single source of truth every ranking/sorting call site in the
/// workspace should derive from via `Ord`/`PartialOrd` rather than hand-rolling its own
/// numeric rank (issue #1532 code-review finding 1: two independently hand-rolled, oppositely
/// signed rank functions had drifted apart before this derive was added).
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::Severity;
///
/// let severity = Severity::Warning;
/// assert_eq!(severity, Severity::Warning);
/// assert_ne!(severity, Severity::Error);
///
/// // `Error` is the most severe, `Hint` the least — matches the LSP wire ordering
/// // (`Severity`'s `Serialize` impl uses the same `1..=4` encoding).
/// assert!(Severity::Error < Severity::Warning);
/// assert!(Severity::Warning < Severity::Information);
/// assert!(Severity::Information < Severity::Hint);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Reports an error.
    Error,
    /// Reports a warning.
    Warning,
    /// Reports information.
    Information,
    /// Reports a hint.
    Hint,
}

// Manual `Serialize`/`Deserialize` (rather than a derive) so the wire representation stays
// the LSP protocol's own `1..=4` integer encoding (`tower_lsp_server::ls_types::DiagnosticSeverity`
// is `#[serde(transparent)]` over `i32`) — `crate::policy_config::DiagnosticsConfig`'s existing
// JSON config schema and tests already depend on this exact numbering, and this type replaces
// `ls_types::DiagnosticSeverity` as that struct's field type.
impl serde::Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: i32 = match self {
            Self::Error => 1,
            Self::Warning => 2,
            Self::Information => 3,
            Self::Hint => 4,
        };
        serializer.serialize_i32(value)
    }
}

/// Deliberately infallible for any `i32` input, mirroring
/// `tower_lsp_server::ls_types::DiagnosticSeverity`'s own `#[serde(transparent)]` newtype
/// over `i32` — the LSP protocol places no validation on this field either, so a value
/// outside `1..=4` was never a deserialization error before this domain type replaced
/// `ls_types::DiagnosticSeverity` as `DiagnosticsConfig`'s field type (issue #1083).
///
/// Rejecting out-of-range values here instead would be a real regression: `DepsConfig`
/// (`deps-lsp/src/server.rs`'s `parse_config`) and `deps-cli`'s config loader both
/// deserialize a much larger struct in one shot, so a single out-of-range severity would
/// fail the *entire* config update — exactly the failure mode `#[serde(deny_unknown_fields)]`
/// exists to prevent for a different class of mistake, reintroduced here through a
/// stricter-than-the-protocol enum. Out-of-range values instead clamp to the nearest
/// defined variant: `<= 1` and negative values clamp to [`Self::Error`] (fail safe — never
/// silently downgrade a possibly-important severity), `>= 4` clamps to [`Self::Hint`].
impl<'de> serde::Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match i32::deserialize(deserializer)? {
            ..=1 => Self::Error,
            2 => Self::Warning,
            3 => Self::Information,
            4.. => Self::Hint,
        })
    }
}

/// An advisory/rule URL attached to a `Diagnostic`'s `code`, field-for-field identical to
/// `tower_lsp_server::ls_types::CodeDescription` but carrying no dependency on
/// `tower-lsp-server`.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::CodeDescription;
/// use url::Url;
///
/// let href = Url::parse("https://osv.dev/GHSA-xxxx").unwrap();
/// let code_description = CodeDescription::new(href.clone());
/// assert_eq!(code_description.href, href);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDescription {
    /// URI describing the diagnostic's code, e.g. an OSV advisory page.
    pub href: url::Url,
}

impl CodeDescription {
    /// Builds a [`CodeDescription`] from its `href` field.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must call this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::CodeDescription;
    /// use url::Url;
    ///
    /// let code_description = CodeDescription::new(Url::parse("https://example.com").unwrap());
    /// assert_eq!(code_description.href.as_str(), "https://example.com/");
    /// ```
    #[must_use]
    pub const fn new(href: url::Url) -> Self {
        Self { href }
    }
}

/// A related location and message attached to a [`Diagnostic`].
///
/// Field-for-field identical to `tower_lsp_server::ls_types::DiagnosticRelatedInformation` but
/// with its nested `Location` flattened in and `Location::uri` typed as `url::Url` instead of
/// `ls_types::Uri` (matching #1071's file-identity approach for
/// [`crate::ecosystem::ParseResult::uri`]).
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::RelatedInformation;
/// use deps_core::position::{Position, Range};
/// use url::Url;
///
/// let related = RelatedInformation::new(
///     Url::parse("file:///Cargo.toml").unwrap(),
///     Range::new(Position::new(0, 0), Position::new(0, 4)),
///     "also declared here",
/// );
/// assert_eq!(related.message(), "also declared here");
/// ```
///
/// # The sanitization backstop this design relies on (issue #1280)
///
/// `message` is private — the only way to build a `RelatedInformation` from outside this
/// crate is through [`Self::new`], which sanitizes it. Setting `message` directly fails to
/// compile (the field does not exist from outside this crate):
///
/// ```compile_fail
/// use deps_core::diagnostic::RelatedInformation;
/// use deps_core::position::{Position, Range};
/// use url::Url;
///
/// let mut related = RelatedInformation::new(
///     Url::parse("file:///Cargo.toml").unwrap(),
///     Range::new(Position::new(0, 0), Position::new(0, 1)),
///     "safe",
/// );
/// related.message = "raw".to_string();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedInformation {
    /// File the related location is in.
    pub uri: url::Url,
    /// Span within [`Self::uri`].
    pub range: Range,
    message: String,
}

impl RelatedInformation {
    /// Builds a [`RelatedInformation`] from its `uri`/`range`/`message` fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must call this constructor to build a new value.
    ///
    /// `message` is sanitized through an internal markdown-unsafe-character filter (#1276)
    /// on this constructor path, on top of (not instead of) producer-side sanitization. This
    /// is a real guarantee, not just a best-effort backstop (#1280): [`Self::message`] is
    /// private, so [`Self::new`] is the only way to set it, and there is no setter that
    /// bypasses sanitization. The filter is idempotent, so callers that already sanitized
    /// their input are unaffected.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::RelatedInformation;
    /// use deps_core::position::{Position, Range};
    /// use url::Url;
    ///
    /// let related = RelatedInformation::new(
    ///     Url::parse("file:///Cargo.toml").unwrap(),
    ///     Range::new(Position::new(1, 0), Position::new(1, 4)),
    ///     "duplicate entry",
    /// );
    /// assert_eq!(related.range.start.line, 1);
    /// ```
    #[must_use]
    pub fn new(uri: url::Url, range: Range, message: impl Into<String>) -> Self {
        Self {
            uri,
            range,
            message: crate::lsp_helpers::replace_markdown_unsafe_chars(&message.into()),
        }
    }

    /// Returns the sanitized message describing the relation.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::RelatedInformation;
    /// use deps_core::position::{Position, Range};
    /// use url::Url;
    ///
    /// let related = RelatedInformation::new(
    ///     Url::parse("file:///Cargo.toml").unwrap(),
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "also declared here",
    /// );
    /// assert_eq!(related.message(), "also declared here");
    /// ```
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A single diagnostic finding.
///
/// Field-for-field identical to `tower_lsp_server::ls_types::Diagnostic`'s commonly used
/// subset but carrying no dependency on `tower-lsp-server`. Returned by
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] and
/// [`crate::ecosystem::Ecosystem::generate_diagnostics`].
///
/// `deps-lsp` converts this into `tower_lsp_server::ls_types::Diagnostic` at its own boundary
/// (`crates/deps-lsp/src/lsp_types_interop.rs`); `deps-cli` consumes it directly to build its
/// `check` output without ever naming an `ls_types` type.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::{Diagnostic, DiagnosticKind, Severity};
/// use deps_core::position::{Position, Range};
///
/// let diagnostic = Diagnostic::new(
///     DiagnosticKind::Unsatisfiable,
///     Range::new(Position::new(0, 0), Position::new(0, 10)),
///     "no version matches",
/// )
/// .with_severity(Severity::Hint);
///
/// assert_eq!(diagnostic.message(), "no version matches");
/// assert_eq!(diagnostic.severity, Some(Severity::Hint));
/// assert_eq!(diagnostic.kind(), &DiagnosticKind::Unsatisfiable);
/// assert_eq!(diagnostic.code(), Some("unsatisfiable-requirement"));
/// ```
///
/// # The sanitization backstop this design relies on (issue #1280)
///
/// `message` and `kind` are private, and `Self` does not implement `Default` — the only way
/// to build or mutate a `Diagnostic` from outside this crate is through [`Self::new`] and the
/// `with_*` builders, every one of which sanitizes the value it sets. The wire `code` is
/// derived from `kind`, so it is always a static sentinel or a validated [`OsvId`] (#1785).
/// Each of the following fails to compile:
///
/// Setting `message` directly (the field does not exist from outside this crate):
///
/// ```compile_fail
/// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
/// use deps_core::position::{Position, Range};
///
/// let mut d = Diagnostic::new(
///     DiagnosticKind::Notice,
///     Range::new(Position::new(0, 0), Position::new(0, 1)),
///     "safe",
/// );
/// d.message = "raw".to_string();
/// ```
///
/// Setting `kind` directly:
///
/// ```compile_fail
/// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
/// use deps_core::position::{Position, Range};
///
/// let mut d = Diagnostic::new(
///     DiagnosticKind::Notice,
///     Range::new(Position::new(0, 0), Position::new(0, 1)),
///     "safe",
/// );
/// d.kind = DiagnosticKind::Outdated;
/// ```
///
/// Constructing via `Default` (not implemented):
///
/// ```compile_fail
/// use deps_core::diagnostic::Diagnostic;
///
/// let _d = Diagnostic::default();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Span the diagnostic applies to.
    pub range: Range,
    /// Severity, if classified.
    pub severity: Option<Severity>,
    kind: DiagnosticKind,
    /// Advisory/rule URL for `code`, e.g. an OSV advisory page.
    pub code_description: Option<CodeDescription>,
    message: String,
    /// Other locations related to this diagnostic, e.g. sibling occurrences of a blocked
    /// registry.
    pub related_information: Option<Vec<RelatedInformation>>,
}

impl Diagnostic {
    /// Builds a [`Diagnostic`] from its `kind`/`range`/`message` fields, with every other field
    /// left unset. Chain the `with_*` builders to set them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must call this constructor to build a new value.
    ///
    /// `message` is sanitized through an internal markdown-unsafe-character filter (#1276)
    /// on this constructor path, on top of (not instead of) producer-side sanitization. This
    /// is a real guarantee, not just a best-effort backstop (#1280): [`Self`] does not
    /// implement `Default`, [`Self::message`] is private, and there is no setter that
    /// bypasses sanitization — [`Self::new`] is the only way to set it. The filter is
    /// idempotent, so callers that already sanitized their input are unaffected;
    /// length-capping (e.g. `MAX_DIAGNOSTIC_NAME_CHARS`) stays producer-side and is not
    /// duplicated here.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     DiagnosticKind::Notice,
    ///     Range::new(Position::new(2, 0), Position::new(2, 6)),
    ///     "package not found",
    /// );
    /// assert_eq!(diagnostic.severity, None);
    /// ```
    #[must_use]
    pub fn new(kind: DiagnosticKind, range: Range, message: impl Into<String>) -> Self {
        Self {
            range,
            severity: None,
            kind,
            code_description: None,
            message: crate::lsp_helpers::replace_markdown_unsafe_chars(&message.into()),
            related_information: None,
        }
    }

    /// Returns the sanitized, human-readable diagnostic message.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     DiagnosticKind::Notice,
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "package not found",
    /// );
    /// assert_eq!(diagnostic.message(), "package not found");
    /// ```
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns what this diagnostic reports.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     DiagnosticKind::Yanked,
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "yanked",
    /// );
    /// assert_eq!(diagnostic.kind(), &DiagnosticKind::Yanked);
    /// ```
    #[must_use]
    pub const fn kind(&self) -> &DiagnosticKind {
        &self.kind
    }

    /// Returns the stable machine-readable code derived from [`Self::kind`] (e.g.
    /// `"unsatisfiable-requirement"`), if the kind has one.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::{Diagnostic, DiagnosticKind};
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     DiagnosticKind::Deprecated,
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "deprecated",
    /// );
    /// assert_eq!(diagnostic.code(), Some("deprecated-package"));
    /// ```
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.kind.code()
    }

    /// Overrides [`Self::severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Overrides [`Self::code_description`]. See [`Self::new`].
    #[must_use]
    pub fn with_code_description(mut self, code_description: CodeDescription) -> Self {
        self.code_description = Some(code_description);
        self
    }

    /// Overrides [`Self::related_information`]. See [`Self::new`].
    #[must_use]
    pub fn with_related_information(
        mut self,
        related_information: Vec<RelatedInformation>,
    ) -> Self {
        self.related_information = Some(related_information);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_builder_sets_all_fields() {
        use crate::position::Position;

        let href = url::Url::parse("https://osv.dev/GHSA-xxxx").unwrap();
        let related_uri = url::Url::parse("file:///Cargo.toml").unwrap();
        let diagnostic = Diagnostic::new(
            DiagnosticKind::Advisory(OsvId::parse("GHSA-xxxx").unwrap()),
            Range::new(Position::new(0, 0), Position::new(0, 4)),
            "vulnerable",
        )
        .with_severity(Severity::Error)
        .with_code_description(CodeDescription::new(href.clone()))
        .with_related_information(vec![RelatedInformation::new(
            related_uri.clone(),
            Range::new(Position::new(1, 0), Position::new(1, 4)),
            "also here",
        )]);

        assert_eq!(diagnostic.severity, Some(Severity::Error));
        assert_eq!(diagnostic.code(), Some("GHSA-xxxx"));
        assert_eq!(diagnostic.code_description.as_ref().unwrap().href, href);
        let related = diagnostic.related_information.as_ref().unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].uri, related_uri);
        assert_eq!(related[0].message(), "also here");
    }

    #[test]
    fn test_diagnostic_new_leaves_optional_fields_unset() {
        use crate::position::Position;

        let diagnostic = Diagnostic::new(
            DiagnosticKind::Notice,
            Range::new(Position::new(0, 0), Position::new(0, 1)),
            "message",
        );
        assert_eq!(diagnostic.severity, None);
        assert_eq!(diagnostic.code(), None);
        assert_eq!(diagnostic.code_description, None);
        assert_eq!(diagnostic.related_information, None);
    }

    #[test]
    fn test_severity_serialize_matches_lsp_wire_encoding() {
        assert_eq!(serde_json::to_string(&Severity::Error).unwrap(), "1");
        assert_eq!(serde_json::to_string(&Severity::Warning).unwrap(), "2");
        assert_eq!(serde_json::to_string(&Severity::Information).unwrap(), "3");
        assert_eq!(serde_json::to_string(&Severity::Hint).unwrap(), "4");
    }

    #[test]
    fn test_severity_deserialize_accepts_every_valid_value() {
        assert_eq!(
            serde_json::from_str::<Severity>("1").unwrap(),
            Severity::Error
        );
        assert_eq!(
            serde_json::from_str::<Severity>("2").unwrap(),
            Severity::Warning
        );
        assert_eq!(
            serde_json::from_str::<Severity>("3").unwrap(),
            Severity::Information
        );
        assert_eq!(
            serde_json::from_str::<Severity>("4").unwrap(),
            Severity::Hint
        );
    }

    #[test]
    fn test_severity_roundtrips_through_serialize_deserialize() {
        for severity in [
            Severity::Error,
            Severity::Warning,
            Severity::Information,
            Severity::Hint,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            assert_eq!(serde_json::from_str::<Severity>(&json).unwrap(), severity);
        }
    }

    /// #1276: `Diagnostic::new` is a defense-in-depth backstop on its own constructor
    /// path — a bidi-override character in `message` must not survive construction through
    /// `new`, even without an explicit producer-side call to `replace_markdown_unsafe_chars`.
    #[test]
    fn test_diagnostic_new_sanitizes_bidi_override_in_message() {
        use crate::position::Position;

        let diagnostic = Diagnostic::new(
            DiagnosticKind::Notice,
            Range::new(Position::new(0, 0), Position::new(0, 1)),
            "vulnerable\u{202E}gnp.sj",
        );
        assert_eq!(diagnostic.message(), "vulnerable gnp.sj");
    }

    #[test]
    fn test_kind_code_matches_wire_sentinels() {
        assert_eq!(
            DiagnosticKind::MutableRefPin(GitTagsPlatform::GithubActions).code(),
            Some("mutable-ref-pin")
        );
        assert_eq!(
            DiagnosticKind::MutableRefPin(GitTagsPlatform::GitlabCi).code(),
            Some("gitlab-ci-mutable-ref-pin")
        );
        assert_eq!(
            DiagnosticKind::UnresolvedGitlabHost.code(),
            Some("unresolved-gitlab-host")
        );
        assert_eq!(
            DiagnosticKind::ShaCommentMismatch.code(),
            Some("sha-comment-mismatch")
        );
        assert_eq!(DiagnosticKind::UnknownRef.code(), Some("unknown-ref"));
        assert_eq!(
            DiagnosticKind::LicensePolicy.code(),
            Some("license-policy-violation")
        );
        for kind in [
            DiagnosticKind::Outdated,
            DiagnosticKind::FlaggedLatest,
            DiagnosticKind::UnverifiedLatest,
            DiagnosticKind::Yanked,
            DiagnosticKind::AdvisoryOverflow,
            DiagnosticKind::Notice,
        ] {
            assert_eq!(kind.code(), None);
        }
    }

    /// #1276: same backstop applies to `RelatedInformation::new`.
    #[test]
    fn test_related_information_new_sanitizes_bidi_override_in_message() {
        use crate::position::Position;

        let related = RelatedInformation::new(
            url::Url::parse("file:///Cargo.toml").unwrap(),
            Range::new(Position::new(0, 0), Position::new(0, 1)),
            "also here\u{202E}gnp.sj",
        );
        assert_eq!(related.message(), "also here gnp.sj");
    }

    /// #1083 critic S1: an out-of-range integer must never fail deserialization — it must
    /// clamp to the nearest defined variant instead, exactly like
    /// `tower_lsp_server::ls_types::DiagnosticSeverity`'s own permissive `#[serde(transparent)]`
    /// `i32` newtype. Rejecting it here would fail an entire `DepsConfig`/`deps-cli` config
    /// deserialization over one out-of-range field.
    #[test]
    fn test_severity_deserialize_clamps_out_of_range_values_instead_of_failing() {
        assert_eq!(
            serde_json::from_str::<Severity>("0").unwrap(),
            Severity::Error
        );
        assert_eq!(
            serde_json::from_str::<Severity>("-5").unwrap(),
            Severity::Error
        );
        assert_eq!(
            serde_json::from_str::<Severity>("5").unwrap(),
            Severity::Hint
        );
        assert_eq!(
            serde_json::from_str::<Severity>("999").unwrap(),
            Severity::Hint
        );
    }
}
