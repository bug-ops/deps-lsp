# Step 8: Implement the Formatter

Create the formatter in `formatter.rs`:

```rust
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementResolution, SourcePolicy,
};
use deps_core::{ConcreteVersion, PackageName};

// `EcosystemFormatter` is a blanket impl over these seven concern traits — never write
// `impl EcosystemFormatter for {Ecosystem}Formatter` directly. Implement only the trait
// that owns the behavior you need to customize; an empty body relies entirely on that
// trait's own default.
pub struct {Ecosystem}Formatter;

impl PackageNaming for {Ecosystem}Formatter {
    // Optional: lint manifest-declared names against this ecosystem's naming
    // rules. Default is always `Ok(())` — only override to warn on names the
    // ecosystem's own tooling would never accept (see `deps-npm`'s
    // `NpmFormatter` for a full example). Never used as a construction gate:
    // `PackageName::new` stays infallible regardless of this check.
    fn validate_package_name(&self, _name: &str) -> Result<(), deps_core::InvalidPackageName> {
        Ok(())
    }
}

impl PackageRendering for {Ecosystem}Formatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        // Format version string for use in code action text edits
        format!("\"{}\"", version)
    }

    fn package_url(&self, name: &PackageName) -> String {
        // `encode` guards the hostile-input-safety check `formatter_conformance!` generates
        // unconditionally for every invocation — an unencoded name fails that test.
        format!(
            "https://registry.example.com/packages/{}",
            urlencoding::encode(name.as_str())
        )
    }
}

impl RequirementResolution for {Ecosystem}Formatter {}

impl DiagnosticMessages for {Ecosystem}Formatter {}

impl DiagnosticPolicy for {Ecosystem}Formatter {}

impl SourcePolicy for {Ecosystem}Formatter {}

impl OsvNaming for {Ecosystem}Formatter {}
```

Replace hand-written `test_format_version`/`test_package_url` tests with one
`deps_core::formatter_conformance!` invocation (see
`templates/deps-ecosystem/src/formatter.rs.template` or `deps-github-actions/src/formatter.rs`
for a full example).

