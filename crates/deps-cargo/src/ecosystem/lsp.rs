//! LSP-only completion support for Cargo (spec FR-011/FR-012, issue #1137).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use tower_lsp_server::ls_types::{CompletionItem, Range};

use deps_core::Version;
use deps_core::completion::Completions;
use deps_core::parser::DependencySource;
use deps_core::{ParseResult as ParseResultTrait, Registry, Result};

use super::CargoEcosystem;

/// Leading version-constraint operators `semver::VersionReq` (Cargo's own requirement
/// grammar) accepts, stripped from a completion prefix before matching it against
/// registry versions. Includes the bare wildcard `*` (`VersionReq::new("*")` is a valid,
/// tested requirement — see `registry.rs`'s tests) alongside the comparison and
/// caret/tilde operators (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['^', '~', '=', '<', '>', '*'];

/// Maximum number of feature completions to show.
///
/// Unlike `MAX_COMPLETION_VERSIONS`, there is no rank-preserving bump logic here — the
/// filtered feature list is sorted alphabetically and simply truncated, with `is_incomplete`
/// set on the response when that truncates anything. A registry index entry is capped at
/// 32 MiB, but an unusual or hostile registry could still return an oversized `features` map
/// for a single crate; this bounds the LSP-visible blast radius.
const MAX_COMPLETION_FEATURES: usize = 5;

/// The source(s) a `CompletionContext::Version`/`Feature`'s bare `package_name` joins back
/// to within a manifest's already-parsed dependencies (spec FR-012).
enum CompletionSource {
    /// No dependency in the manifest has this exact name yet — most commonly because the
    /// user is still typing a brand-new dependency line, with `registry`/`registry-index`
    /// not yet present for the parser to classify. Callers fall back to the pre-existing
    /// crates.io-only behavior, unchanged.
    NotInManifest,
    /// Every occurrence of this name in the manifest agrees on one resolved source.
    Resolved(DependencySource),
    /// Two or more occurrences of this name resolve to different sources (the same
    /// ambiguity FR-011 covers for the background fetch) — callers must offer no
    /// completions at all rather than picking one arbitrarily.
    Ambiguous,
}

/// Joins `package_name` back to `parse_result.dependencies()` by name (spec FR-012).
fn resolve_completion_source(
    parse_result: &dyn ParseResultTrait,
    package_name: &deps_core::PackageName,
) -> CompletionSource {
    let mut sources = parse_result
        .dependencies()
        .into_iter()
        .filter(|d| d.name() == package_name)
        .map(deps_core::Dependency::source);

    let Some(first) = sources.next() else {
        return CompletionSource::NotInManifest;
    };
    if sources.all(|s| s == first) {
        CompletionSource::Resolved(first)
    } else {
        tracing::warn!(
            package = %package_name.for_tracing(),
            "ambiguous dependency source for version/feature completion; offering none"
        );
        CompletionSource::Ambiguous
    }
}

impl CargoEcosystem {
    pub(super) async fn complete_package_names(
        &self,
        prefix: &str,
        range: Range,
    ) -> Vec<CompletionItem> {
        // Package-name search is crates.io-only unconditionally (the sparse index protocol
        // has no search endpoint), so `self.registry`'s source-blind `search` already means
        // crates.io by construction.
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    /// Completes feature flags for a specific package.
    ///
    /// Fetches features from the latest stable version, routed by the source `package_name`
    /// resolves to in `parse_result` by name (spec FR-012) — unlike version completion
    /// (issue #593, position-based; see [`deps_core::Ecosystem::complete_version`]'s default
    /// implementation), this still joins by name via
    /// [`resolve_completion_source`]/[`CompletionSource`], so it keeps the same residual
    /// same-name-different-source `Ambiguous` gap #593 fixed for versions (not itself in
    /// #593's scope: `features_range`-based position routing for this method is a follow-up,
    /// not done here).
    pub(super) async fn complete_features(
        &self,
        parse_result: &dyn ParseResultTrait,
        package_name: &deps_core::PackageName,
        prefix: &str,
    ) -> Completions {
        use deps_core::completion::build_feature_completion;

        let versions_result: Result<Vec<Box<dyn Version>>> =
            match resolve_completion_source(parse_result, package_name) {
                CompletionSource::Ambiguous => return Completions::default(),
                CompletionSource::NotInManifest
                | CompletionSource::Resolved(DependencySource::Registry) => {
                    Registry::get_versions(self.registry.as_ref(), package_name).await
                }
                CompletionSource::Resolved(DependencySource::AlternateRegistry {
                    index, ..
                }) => match self.registry.alternate_client(&index) {
                    Some(client) => Registry::get_versions(client.as_ref(), package_name).await,
                    None => return Completions::default(),
                },
                CompletionSource::Resolved(_) => return Completions::default(),
            };

        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch versions for '{}': {}",
                    package_name.for_tracing(),
                    e
                );
                return Completions::default();
            }
        };

        let latest = match versions.iter().find(|v| v.is_stable()) {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "No stable version found for '{}'",
                    package_name.for_tracing()
                );
                return Completions::default();
            }
        };

        // `features()` comes back in HashMap iteration order (non-deterministic); sort so
        // truncation below keeps the same names across calls instead of an arbitrary subset.
        let mut features: Vec<String> = latest
            .features()
            .into_iter()
            .filter(|f| f.starts_with(prefix))
            .collect();
        features.sort_unstable();

        // Build safe items first, then cap: an unsafe name (rejected by
        // `build_feature_completion`'s `is_safe_feature_name` gate) must not count against the
        // cap, or a single malicious feature name could push a legitimate one out of the
        // response.
        let items: Vec<CompletionItem> = features
            .iter()
            .filter_map(|feature| build_feature_completion(feature, package_name, None))
            .collect();

        let is_incomplete = items.len() > MAX_COMPLETION_FEATURES;
        let items = items.into_iter().take(MAX_COMPLETION_FEATURES).collect();

        Completions::new(items).with_incomplete(is_incomplete)
    }
}
