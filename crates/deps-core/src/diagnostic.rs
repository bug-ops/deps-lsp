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

use crate::position::Range;

/// A diagnostic severity level, field-for-field identical to
/// `tower_lsp_server::ls_types::DiagnosticSeverity`'s four defined values, but carrying no
/// dependency on `tower-lsp-server`.
///
/// `Deserialize` is deliberately as permissive as `ls_types::DiagnosticSeverity` itself
/// (`#[serde(transparent)]` over a bare `i32`, which accepts *any* integer with no
/// validation at all) — see this type's `Deserialize` impl doc for why an out-of-range
/// integer clamps to the nearest defined variant instead of failing deserialization.
///
/// # Examples
///
/// ```
/// use deps_core::diagnostic::Severity;
///
/// let severity = Severity::Warning;
/// assert_eq!(severity, Severity::Warning);
/// assert_ne!(severity, Severity::Error);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
/// use deps_core::diagnostic::{Diagnostic, Severity};
/// use deps_core::position::{Position, Range};
///
/// let diagnostic = Diagnostic::new(
///     Range::new(Position::new(0, 0), Position::new(0, 10)),
///     "newer version available",
/// )
/// .with_severity(Severity::Hint)
/// .with_code("outdated");
///
/// assert_eq!(diagnostic.message(), "newer version available");
/// assert_eq!(diagnostic.severity, Some(Severity::Hint));
/// assert_eq!(diagnostic.code(), Some("outdated"));
/// ```
///
/// # The sanitization backstop this design relies on (issue #1280)
///
/// `message` and `code` are private, and `Self` does not implement `Default` — the only way
/// to build or mutate a `Diagnostic` from outside this crate is through [`Self::new`] and the
/// `with_*` builders, every one of which sanitizes the value it sets. Each of the following
/// fails to compile:
///
/// Setting `message` directly (the field does not exist from outside this crate):
///
/// ```compile_fail
/// use deps_core::diagnostic::Diagnostic;
/// use deps_core::position::{Position, Range};
///
/// let mut d = Diagnostic::new(Range::new(Position::new(0, 0), Position::new(0, 1)), "safe");
/// d.message = "raw".to_string();
/// ```
///
/// Setting `code` directly:
///
/// ```compile_fail
/// use deps_core::diagnostic::Diagnostic;
/// use deps_core::position::{Position, Range};
///
/// let mut d = Diagnostic::new(Range::new(Position::new(0, 0), Position::new(0, 1)), "safe");
/// d.code = Some("raw".to_string());
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
    code: Option<String>,
    /// Advisory/rule URL for `code`, e.g. an OSV advisory page.
    pub code_description: Option<CodeDescription>,
    message: String,
    /// Other locations related to this diagnostic, e.g. sibling occurrences of a blocked
    /// registry.
    pub related_information: Option<Vec<RelatedInformation>>,
}

impl Diagnostic {
    /// Builds a [`Diagnostic`] from its `range`/`message` fields, with every other field left
    /// unset. Chain the `with_*` builders to set them.
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
    /// use deps_core::diagnostic::Diagnostic;
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     Range::new(Position::new(2, 0), Position::new(2, 6)),
    ///     "package not found",
    /// );
    /// assert_eq!(diagnostic.severity, None);
    /// ```
    #[must_use]
    pub fn new(range: Range, message: impl Into<String>) -> Self {
        Self {
            range,
            severity: None,
            code: None,
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
    /// use deps_core::diagnostic::Diagnostic;
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "package not found",
    /// );
    /// assert_eq!(diagnostic.message(), "package not found");
    /// ```
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the stable machine-readable code identifying the diagnostic kind (e.g.
    /// `"unsatisfiable-requirement"`), if set.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::diagnostic::Diagnostic;
    /// use deps_core::position::{Position, Range};
    ///
    /// let diagnostic = Diagnostic::new(
    ///     Range::new(Position::new(0, 0), Position::new(0, 1)),
    ///     "package not found",
    /// )
    /// .with_code("unknown-package");
    /// assert_eq!(diagnostic.code(), Some("unknown-package"));
    /// ```
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// Overrides [`Self::severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Overrides the diagnostic's `code` (see [`Self::code`]). See [`Self::new`].
    ///
    /// `code` is sanitized through the same markdown-unsafe-character filter as `message`
    /// (#1280) — it reaches the same client-visible sinks (the editor's Problems panel,
    /// SARIF `ruleId`), so it gets the same defense-in-depth guarantee, on top of (not
    /// instead of) producer-side validation.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(crate::lsp_helpers::replace_markdown_unsafe_chars(
            &code.into(),
        ));
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
            Range::new(Position::new(0, 0), Position::new(0, 4)),
            "vulnerable",
        )
        .with_severity(Severity::Error)
        .with_code("GHSA-xxxx")
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
            Range::new(Position::new(0, 0), Position::new(0, 1)),
            "vulnerable\u{202E}gnp.sj",
        );
        assert_eq!(diagnostic.message(), "vulnerable gnp.sj");
    }

    /// #1280: `with_code` gets the same sanitization backstop as `message` — a `code` value
    /// reaches the same client-visible sinks (Problems panel, SARIF `ruleId`).
    #[test]
    fn test_diagnostic_with_code_sanitizes_bidi_override() {
        use crate::position::Position;

        let diagnostic = Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 1)),
            "vulnerable",
        )
        .with_code("GHSA-xxxx\u{202E}gnp.sj");
        assert_eq!(diagnostic.code(), Some("GHSA-xxxx gnp.sj"));
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
