//! Minimal, network-free test doubles for [`deps_core::Ecosystem`].
//!
//! Scoped to what this crate's own `classify::license` tests and downstream driving-adapter
//! regression tests (`deps-cli`'s `check_integration.rs`, issue #1133) need: a tier-3
//! ecosystem whose [`deps_core::Ecosystem::fetch_license`] is fully controllable (a canned
//! return value, or one that never resolves, to exercise
//! [`crate::classify::license::fetch_tier3_licenses`]'s timeout/concurrency/filter logic)
//! without ever touching a real registry.
//!
//! Mirrors `crates/deps-lsp/src/test_utils.rs`'s `BlockingEcosystem` precedent: only the
//! trait methods with no default implementation are overridden (`ecosystem_id`,
//! `display_name`, `manifest_filenames`, `parse_manifest`, `registry`, `formatter`,
//! `completion_insert_text`, `as_any`, plus `complete_version` when the `lsp-responses`
//! feature is active — see [`deps_core::ecosystem::Ecosystem`]'s trait doc for why that one
//! is feature-gated but still required). Every other `generate_*`/`complete_*` method keeps
//! the trait's own default.
//!
//! Exposed as `pub` (not `#[cfg(test)]`-only) behind the `test-util` feature so an external
//! crate's own test binary — which cannot see another crate's `#[cfg(test)]` items — can
//! still construct one; see `deps-core`'s own `test_util` module for the identical pattern
//! this one was copied from.

use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::LicenseSource;
use deps_core::Metadata;
use deps_core::PackageName;
use deps_core::ParseResult;
use deps_core::Registry;
use deps_core::VersionReq;
use deps_core::ecosystem::BoxFuture;
use deps_core::ecosystem::private::Sealed;
use deps_core::lsp_helpers::EcosystemFormatter;
use std::any::Any;
use std::sync::Arc;

/// No-op [`Registry`]: every method returns an empty/`None` success immediately, for an
/// [`Ecosystem`] test double whose registry is never meant to be exercised.
pub struct StubRegistry;

impl Registry for StubRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a VersionReq,
        _selection_context: &'a deps_core::SelectionContext,
    ) -> BoxFuture<'a, deps_core::Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move { Ok(None) })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The single dependency [`TestTier3Ecosystem::parse_manifest`] parses into: named
/// `"dep-0"`, an explicit `=`-pinned requirement (concrete under every ecosystem's
/// [`deps_core::lsp_helpers::in_use_version::concrete_pin_version`] policy, so
/// `resolve_in_use_version` succeeds with no lock file needed — see
/// [`crate::classify::license::tier3_license_targets`]).
struct StubDependency {
    name: PackageName,
    version_req: VersionReq,
}

impl deps_core::Dependency for StubDependency {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> deps_core::position::Range {
        deps_core::position::Range::default()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        Some(&self.version_req)
    }
    fn version_range(&self) -> Option<deps_core::position::Range> {
        None
    }
    fn source(&self) -> deps_core::parser::DependencySource {
        deps_core::parser::DependencySource::Registry
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct StubParseResult {
    dep: StubDependency,
    uri: url::Url,
}

impl ParseResult for StubParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        vec![&self.dep]
    }
    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
    fn uri(&self) -> &url::Url {
        &self.uri
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A tier-3 [`Ecosystem`] test double.
///
/// [`Ecosystem::fetch_license`] is fully controlled by the closure supplied at construction
/// — canned data, an empty result, or a future that never resolves (to exercise a caller's
/// own timeout).
///
/// [`Ecosystem::license_source`] always returns [`LicenseSource::DetectedSpdx`] (arbitrary
/// among the three `requires_dedicated_fetch() == true` variants — nothing in
/// `classify::license` branches on which one it is).
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_engine::classify::license::fetch_tier3_licenses;
/// use deps_engine::test_util::TestTier3Ecosystem;
///
/// #[tokio::main]
/// async fn main() {
///     let ecosystem = TestTier3Ecosystem::returning(vec!["MIT".to_string()]);
///     let targets = vec![(PackageName::new("pkg"), "1.0.0".to_string())];
///
///     let result = fetch_tier3_licenses(&ecosystem, targets, 10, 4).await;
///
///     assert_eq!(
///         result.licenses.get(&PackageName::new("pkg")),
///         Some(&vec!["MIT".to_string()])
///     );
///     assert_eq!(result.timed_out, 0);
/// }
/// ```
pub struct TestTier3Ecosystem {
    fetch_license_result: FetchLicenseBehavior,
}

/// What [`TestTier3Ecosystem::fetch_license`] does when called — see
/// [`TestTier3Ecosystem::returning`]/[`TestTier3Ecosystem::pending`].
enum FetchLicenseBehavior {
    /// Resolves immediately with this canned license list (possibly empty, to exercise a
    /// caller's empty-result filter).
    Returns(Vec<String>),
    /// Never resolves — the only way a caller's own `tokio::time::timeout` around
    /// [`Ecosystem::fetch_license`] can complete is by firing.
    Pending,
}

impl TestTier3Ecosystem {
    /// [`Ecosystem::fetch_license`] resolves immediately with `license` (an empty `Vec` is a
    /// valid, meaningful input — it exercises a caller's "filter out empty results" logic).
    #[must_use]
    pub const fn returning(license: Vec<String>) -> Self {
        Self {
            fetch_license_result: FetchLicenseBehavior::Returns(license),
        }
    }

    /// [`Ecosystem::fetch_license`] never resolves, for exercising a caller's own
    /// `tokio::time::timeout` around it.
    #[must_use]
    pub const fn pending() -> Self {
        Self {
            fetch_license_result: FetchLicenseBehavior::Pending,
        }
    }
}

impl Sealed for TestTier3Ecosystem {}

impl Ecosystem for TestTier3Ecosystem {
    fn ecosystem_id(&self) -> EcosystemId {
        EcosystemId::Dart
    }

    fn display_name(&self) -> &'static str {
        "test-tier3"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &[]
    }

    fn parse_manifest<'a>(
        &'a self,
        _content: &'a str,
        uri: &'a url::Url,
    ) -> BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>> {
        let uri = uri.clone();
        Box::pin(async move {
            Ok(Box::new(StubParseResult {
                dep: StubDependency {
                    name: PackageName::new("dep-0"),
                    version_req: VersionReq::new("=1.0.0"),
                },
                uri,
            }) as Box<dyn ParseResult>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        Arc::new(StubRegistry)
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &deps_core::test_util::StubFormatter::DEFAULT
    }

    fn completion_insert_text(&self, _metadata: &dyn Metadata) -> Option<String> {
        None
    }

    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        _package_name: PackageName,
        _prefix: String,
    ) -> BoxFuture<'a, deps_core::completion::Completions> {
        Box::pin(async move { deps_core::completion::Completions::default() })
    }

    fn fetch_license<'a>(
        &'a self,
        _name: &'a str,
        _version: &'a str,
    ) -> BoxFuture<'a, Vec<String>> {
        match &self.fetch_license_result {
            FetchLicenseBehavior::Returns(license) => {
                let license = license.clone();
                Box::pin(async move { license })
            }
            FetchLicenseBehavior::Pending => Box::pin(std::future::pending()),
        }
    }

    fn license_source(&self) -> LicenseSource {
        LicenseSource::DetectedSpdx
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
