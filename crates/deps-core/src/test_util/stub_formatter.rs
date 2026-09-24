//! [`StubFormatter`]: a const-constructible `EcosystemFormatter` test double.

use crate::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementResolution, SourcePolicy,
};
use crate::{ConcreteVersion, Dependency, PackageName};

/// A `Copy`, const-constructible test double implementing every
/// [`EcosystemFormatter`](crate::lsp_helpers::EcosystemFormatter) sub-trait through five knobs.
///
/// Replaces a hand-rolled `struct MockFormatter` + seven trait impls at call sites that only
/// need one of a small, recurring set of non-default behaviors. Each knob toggles exactly one
/// method away from its trait default:
/// - [`with_quoted_text_edit`](Self::with_quoted_text_edit): wraps the formatted version in
///   `"..."` instead of the bare string.
/// - [`with_lowercase_names`](Self::with_lowercase_names): normalizes package names to
///   lowercase instead of leaving them as-is.
/// - [`with_package_url_prefix`](Self::with_package_url_prefix): changes the URL prefix the
///   package name is appended to (default: `"https://example.com/"`).
/// - [`with_manifest_requirement_as_resolved_version`](Self::with_manifest_requirement_as_resolved_version):
///   reports the manifest requirement itself as the resolved version, mirroring `GoFormatter`.
/// - [`with_alternate_registry_resolution`](Self::with_alternate_registry_resolution): widens
///   [`SourcePolicy::can_resolve_source`] to accept `AlternateRegistry` sources.
///
/// Public-API `///` doctests that illustrate implementing [`EcosystemFormatter`](crate::lsp_helpers::EcosystemFormatter)
/// from scratch (e.g. `deps_engine::classify::resolved::collect_in_use_versions`'s example)
/// intentionally keep their own hand-rolled formatter — this type is a `test-util`-only
/// fixture, not the public teaching example, so migrating those sites is out of scope.
///
/// Because instances are consumed as `&dyn EcosystemFormatter` behind rvalue static promotion
/// (`fn formatter(&self) -> &dyn EcosystemFormatter { &StubFormatter::DEFAULT }`), a value
/// built with a builder-method chain **must** be bound to a named `const` first — writing
/// `&StubFormatter::new().with_quoted_text_edit()` directly inline fails to compile with
/// `E0515` ("cannot return value referencing temporary value"), since a `const fn` call site
/// itself is not promoted the way a bare `const`/`static` path is. See the second example
/// below.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::PackageRendering;
/// use deps_core::test_util::StubFormatter;
///
/// // `DEFAULT` promotes directly: identity normalization, unquoted text edit,
/// // `https://example.com/` URL prefix.
/// let formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter = &StubFormatter::DEFAULT;
/// assert_eq!(
///     formatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
///     "1.2.3"
/// );
/// ```
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::PackageRendering;
/// use deps_core::test_util::StubFormatter;
///
/// // A builder chain must be bound to a named `const` before taking `&` to it —
/// // `&StubFormatter::new().with_quoted_text_edit()` inline here would fail to compile
/// // with E0515 (temporary value dropped while borrowed).
/// const F: StubFormatter = StubFormatter::new().with_quoted_text_edit();
/// let formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter = &F;
/// assert_eq!(
///     formatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
///     "\"1.2.3\""
/// );
/// ```
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is an independent, non-exclusive knob, not overlapping state a \
              two-variant enum could express more clearly"
)]
#[derive(Debug, Clone, Copy)]
pub struct StubFormatter {
    quoted_text_edit: bool,
    lowercase_names: bool,
    package_url_prefix: &'static str,
    manifest_requirement_as_resolved_version: bool,
    alternate_registry_resolution: bool,
}

impl StubFormatter {
    /// Equivalent to [`Self::new`], usable directly at a `&dyn EcosystemFormatter` call site
    /// (`&StubFormatter::DEFAULT`) since a `const` path promotes without a named binding.
    pub const DEFAULT: Self = Self::new();

    /// Builds a stub with every knob at its default: identity name normalization, an unquoted
    /// text edit, the `https://example.com/` URL prefix, and no widened resolution.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quoted_text_edit: false,
            lowercase_names: false,
            package_url_prefix: "https://example.com/",
            manifest_requirement_as_resolved_version: false,
            alternate_registry_resolution: false,
        }
    }

    /// [`PackageRendering::format_version_for_text_edit`] wraps its output in `"..."`.
    #[must_use]
    pub const fn with_quoted_text_edit(mut self) -> Self {
        self.quoted_text_edit = true;
        self
    }

    /// [`PackageNaming::normalize_package_name`] lowercases the name instead of leaving it
    /// as-is.
    #[must_use]
    pub const fn with_lowercase_names(mut self) -> Self {
        self.lowercase_names = true;
        self
    }

    /// [`PackageRendering::package_url`] uses `prefix` instead of the default
    /// `"https://example.com/"`.
    #[must_use]
    pub const fn with_package_url_prefix(mut self, prefix: &'static str) -> Self {
        self.package_url_prefix = prefix;
        self
    }

    /// [`RequirementResolution::manifest_requirement_is_resolved_version`] returns `true`,
    /// mirroring `GoFormatter`'s override.
    #[must_use]
    pub const fn with_manifest_requirement_as_resolved_version(mut self) -> Self {
        self.manifest_requirement_as_resolved_version = true;
        self
    }

    /// [`SourcePolicy::resolves_alternate_registry`] returns `true`, widening
    /// [`SourcePolicy::can_resolve_source`] to accept an `AlternateRegistry` source.
    #[must_use]
    pub const fn with_alternate_registry_resolution(mut self) -> Self {
        self.alternate_registry_resolution = true;
        self
    }
}

impl Default for StubFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageNaming for StubFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        if self.lowercase_names {
            name.as_str().to_lowercase()
        } else {
            name.as_str().to_string()
        }
    }
}

impl PackageRendering for StubFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        if self.quoted_text_edit {
            format!("\"{version}\"")
        } else {
            version.to_string()
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        format!("{}{}", self.package_url_prefix, name.as_str())
    }
}

impl RequirementResolution for StubFormatter {
    fn manifest_requirement_is_resolved_version(&self, dep: &dyn Dependency) -> bool {
        let _ = dep;
        self.manifest_requirement_as_resolved_version
    }
}

impl DiagnosticMessages for StubFormatter {}

impl DiagnosticPolicy for StubFormatter {}

impl SourcePolicy for StubFormatter {
    fn resolves_alternate_registry(&self) -> bool {
        self.alternate_registry_resolution
    }
}

impl OsvNaming for StubFormatter {}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::StubFormatter;
    use crate::lsp_helpers::{
        PackageNaming, PackageRendering, RequirementResolution, SourcePolicy,
    };
    use crate::parser::DependencySource;
    use crate::{ConcreteVersion, Dependency, PackageName};

    struct StubDep;
    impl Dependency for StubDep {
        fn name(&self) -> &PackageName {
            static NAME: std::sync::OnceLock<PackageName> = std::sync::OnceLock::new();
            NAME.get_or_init(|| PackageName::new("stub-dep"))
        }
        fn name_range(&self) -> crate::position::Range {
            crate::position::Range::default()
        }
        fn version_requirement(&self) -> Option<&crate::VersionReq> {
            None
        }
        fn version_range(&self) -> Option<crate::position::Range> {
            None
        }
        fn source(&self) -> DependencySource {
            DependencySource::Registry
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Locally re-implements every `EcosystemFormatter` default so a drift in the trait's own
    /// defaults (which `StubFormatter::DEFAULT` re-implements rather than inherits) becomes a
    /// visible test failure instead of silent divergence for every migrated call site.
    struct DefaultInheriting;
    impl PackageNaming for DefaultInheriting {}
    impl PackageRendering for DefaultInheriting {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name.as_str())
        }
    }
    impl RequirementResolution for DefaultInheriting {}
    impl crate::lsp_helpers::DiagnosticMessages for DefaultInheriting {}
    impl crate::lsp_helpers::DiagnosticPolicy for DefaultInheriting {}
    impl SourcePolicy for DefaultInheriting {}
    impl crate::lsp_helpers::OsvNaming for DefaultInheriting {}

    #[test]
    fn default_matches_trait_defaults() {
        let stub = StubFormatter::DEFAULT;
        let baseline = DefaultInheriting;
        let dep = StubDep;

        for name in ["Serde", "left-pad", "UPPER"] {
            let name = PackageName::new(name);
            assert_eq!(
                stub.normalize_package_name(&name),
                baseline.normalize_package_name(&name)
            );
        }
        assert_eq!(
            stub.manifest_requirement_is_resolved_version(&dep),
            baseline.manifest_requirement_is_resolved_version(&dep)
        );
        assert_eq!(
            stub.resolves_alternate_registry(),
            baseline.resolves_alternate_registry()
        );
        for source in [
            DependencySource::Registry,
            DependencySource::AlternateRegistry {
                index: "https://index.mycorp.dev".into(),
                mirrors_crates_io: false,
            },
        ] {
            assert_eq!(
                stub.can_resolve_source(&source),
                baseline.can_resolve_source(&source),
                "diverged for {source:?}"
            );
        }
    }

    #[test]
    fn default_is_unquoted_identity_example_com() {
        let stub = StubFormatter::DEFAULT;
        let name = PackageName::new("serde");
        assert_eq!(
            stub.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
            "1.2.3"
        );
        assert_eq!(stub.normalize_package_name(&name), "serde");
        assert_eq!(stub.package_url(&name), "https://example.com/serde");
        assert!(!stub.manifest_requirement_is_resolved_version(&StubDep));
        assert!(!stub.resolves_alternate_registry());
    }

    #[test]
    fn with_quoted_text_edit_wraps_in_quotes() {
        const F: StubFormatter = StubFormatter::new().with_quoted_text_edit();
        assert_eq!(
            F.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
            "\"1.2.3\""
        );
    }

    #[test]
    fn with_lowercase_names_normalizes_to_lowercase() {
        const F: StubFormatter = StubFormatter::new().with_lowercase_names();
        assert_eq!(
            F.normalize_package_name(&PackageName::new("Newtonsoft.Json")),
            "newtonsoft.json"
        );
    }

    #[test]
    fn with_package_url_prefix_overrides_default_prefix() {
        const F: StubFormatter =
            StubFormatter::new().with_package_url_prefix("https://pkg.go.dev/");
        assert_eq!(
            F.package_url(&PackageName::new("golang.org/x/text")),
            "https://pkg.go.dev/golang.org/x/text"
        );
    }

    #[test]
    fn with_manifest_requirement_as_resolved_version_reports_true() {
        const F: StubFormatter =
            StubFormatter::new().with_manifest_requirement_as_resolved_version();
        assert!(F.manifest_requirement_is_resolved_version(&StubDep));
    }

    #[test]
    fn with_alternate_registry_resolution_widens_can_resolve_source() {
        const F: StubFormatter = StubFormatter::new().with_alternate_registry_resolution();
        assert!(F.resolves_alternate_registry());
        assert!(F.can_resolve_source(&DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev".into(),
            mirrors_crates_io: false,
        }));
    }
}
