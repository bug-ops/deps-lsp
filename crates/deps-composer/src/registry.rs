//! Packagist registry client.
//!
//! Provides access to the Packagist registry via:
//! - Package metadata API (<https://repo.packagist.org/p2/{vendor}/{package}.json>) for version lookups
//! - Search API (<https://packagist.org/search.json>) for package search
//!
//! The Packagist v2 API returns minified metadata where only the first version entry
//! is complete. Subsequent entries contain only changed fields and must be expanded
//! by inheriting from the previous complete entry.

use crate::types::{ComposerPackage, ComposerVersion};
use deps_core::{
    Deprecation, DepsError, HttpCache, Result, is_dot_segment, lsp_helpers::warn_rejected_value,
};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PACKAGIST_BASE: &str = "https://repo.packagist.org";
const PACKAGIST_SEARCH: &str = "https://packagist.org/search.json";
const PACKAGIST_WEB: &str = "https://packagist.org/packages";

/// Returns the URL for a package's page on packagist.org.
///
/// Packagist names are `vendor/package`; each segment is percent-encoded
/// individually so the `/` separator survives while any Markdown/URL-breaking
/// characters in a segment are escaped.
///
/// Display link only, never fetched by this process — unlike the `p2/{vendor}/{package}`
/// metadata-fetch URL, so it is deliberately not gated against a `.`/`..` segment (see
/// [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link scope split, #379).
pub fn package_url(name: &str) -> String {
    if let Some((vendor, package)) = name.split_once('/') {
        format!(
            "{PACKAGIST_WEB}/{}/{}",
            urlencoding::encode(vendor),
            urlencoding::encode(package)
        )
    } else {
        format!("{PACKAGIST_WEB}/{}", urlencoding::encode(name))
    }
}

/// Display name for Packagist used in not-found and API-response error messages.
pub const REGISTRY: &str = "Packagist";

/// Builds the Packagist v2 API request URL for `name`'s version metadata.
///
/// Packagist names are `vendor/package`; each segment is percent-encoded individually.
/// Callers must run [`reject_dot_segment`] first — a `vendor` of exactly `.`/`..` survives
/// encoding unchanged (`.` is an RFC 3986 unreserved character) and sits between two real
/// `/` separators here (`{base}/p2/{vendor}/{package}.json`), so it forms an exact
/// dot-segment that a URL parser's dot-segment normalization collapses, escaping the `/p2/`
/// prefix (#365). The unscoped `package` segment is glued directly onto `.json` with no
/// separator and cannot form an exact dot-segment this way, but is still gated for
/// consistency with every other ecosystem's blanket per-segment check.
fn p2_url(base: &str, name: &str) -> String {
    if let Some((vendor, package)) = name.split_once('/') {
        format!(
            "{base}/p2/{}/{}.json",
            urlencoding::encode(vendor),
            urlencoding::encode(package)
        )
    } else {
        format!("{base}/p2/{}.json", urlencoding::encode(name))
    }
}

/// Whether `name` (a bare package name, or `vendor/package` form) has a path segment that
/// is exactly `.`/`..`, mirroring `deps-npm`'s identical `has_dot_segment` for the same
/// vulnerability class.
fn has_dot_segment(name: &str) -> bool {
    if let Some((vendor, package)) = name.split_once('/') {
        return is_dot_segment(vendor) || is_dot_segment(package);
    }
    is_dot_segment(name)
}

/// Rejects a dot-segment `name` before it would reach [`p2_url`], as
/// `DepsError::PackageNotFound`.
fn reject_dot_segment(name: &str) -> Result<()> {
    if has_dot_segment(name) {
        warn_rejected_value("is_dot_segment", "Packagist p2 metadata request URL", name);
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    Ok(())
}

/// Composer's own wildcard-requirement existence-check ladder (#421 S2).
///
/// Deliberately does not reuse [`deps_core::select_latest_for_existence`]: that shared
/// ladder's rung 1 excludes both a prerelease *and* a flagged (`is_flagged()`) version, but
/// Composer's `abandoned` flag is package-level advisory data, not a per-version ranking
/// signal — `select_latest_matching`'s concrete-requirement branch already documents (#347)
/// that the newest version must resolve as latest regardless of its `abandoned` flag.
/// Reusing the shared ladder here would silently reintroduce npm's #338 NFR-002
/// "prefer non-deprecated" preference for Composer, which #347 deliberately opted out of.
///
/// So only rung 1 differs from the shared ladder (a stability-rank floor, `minimum_rank`,
/// rather than a flagged-or-prerelease boolean); rungs 2 and 3 are identical in effect since
/// `RemovalStatus::blocks_resolution()` is never true for Composer's `AdvisoryDeprecated`
/// status (see `reports_yanked` below).
///
/// This divergence is load-bearing, not a style preference, and must not be collapsed back
/// into a call to the shared ladder: for an abandoned package whose newest version is itself
/// below `minimum_rank`, the shared ladder's rung 1 (flagged-or-prerelease) rejects every
/// entry, and rung 2 (`blocks_resolution` only) then returns index 0 — the too-unstable
/// version — since `AdvisoryDeprecated` never blocks resolution. That silently reopens #421
/// for exactly the case this function exists to fix.
///
/// `minimum_rank` is the effective stability floor (see
/// [`effective_minimum_stability_rank`]) — rung 1 keeps only versions ranking at or above it,
/// rather than the fixed "must be fully stable" rule #421/#422 originally shipped, so a
/// manifest's `minimum-stability` (#424) can loosen this ladder too, not just the
/// concrete-requirement branch below.
fn select_latest_for_existence_composer<T>(
    versions: &[T],
    as_version: impl Fn(&T) -> &dyn deps_core::Version,
    minimum_rank: u8,
) -> Option<usize> {
    if versions.is_empty() {
        return None;
    }
    Some(
        versions
            .iter()
            .position(|v| {
                crate::formatter::composer_version_stability_rank(
                    as_version(v).version_string().as_str(),
                ) >= minimum_rank
            })
            .or_else(|| {
                versions
                    .iter()
                    .position(|v| !as_version(v).removal_status().blocks_resolution())
            })
            .unwrap_or(0),
    )
}

/// The loosest (lowest-ranked) per-dependency `@stability` flag found anywhere in a compound
/// `req_str` (#424 critique M1).
///
/// [`crate::formatter::strip_stability_flag`] applies `rfind('@')` to the *whole* string,
/// which only works for a single unadorned constraint like `^1.0@beta`. A compound
/// requirement splits into multiple constraint tokens — `||` (OR) and, within a
/// space-separated range, individual tokens like `>=1.0@dev` — and each token may carry its
/// own flag. `version_satisfies_requirement` already recurses per token to evaluate the
/// version range correctly; this mirrors that same split (flattened, since only "is there a
/// flag" is needed here, not per-branch matching) so `^1.0@beta || ^2.0` and
/// `>=1.0@dev <2.0` are not silently treated as flag-less.
///
/// Returns the *loosest* rank among every token's flag (if more than one token carries one):
/// this never wrongly excludes a version some branch's flag would admit — the final
/// `version_satisfies_requirement` call still narrows down to which branch, if any, actually
/// matches.
fn compound_stability_flag_rank(req_str: &str) -> Option<u8> {
    req_str
        .split("||")
        .flat_map(str::split_whitespace)
        .filter_map(|token| {
            let (_, flag) = crate::formatter::strip_stability_flag(token.trim());
            flag.map(crate::formatter::composer_stability_rank)
        })
        .min()
}

/// The effective Composer stability floor for one dependency's "latest version" selection,
/// ranked on [`crate::formatter::composer_stability_rank`]'s `dev < alpha < beta < RC <
/// stable` scale (#424).
///
/// Priority, highest first:
/// 1. An explicit per-dependency `@stability` flag anywhere in `req_str` (`^1.0@beta`, or
///    within a compound requirement like `>=1.0@dev <2.0`, see
///    [`compound_stability_flag_rank`]) — Composer lets a single dependency opt into a looser
///    (or stricter) floor than the project default.
/// 2. `req_str` itself naming an explicit prerelease version (an exact pin like
///    `2.0.0-beta1`, or a range whose bound does, see
///    [`crate::types::is_prerelease_marker`]) — kept from #421: an explicitly named unstable
///    version must still resolve, so this returns the loosest rank (`0`, dev) rather than
///    computing the pinned version's own rank, matching the pre-#424 "allow any prerelease"
///    behavior for this case exactly.
/// 3. `manifest_minimum` — the manifest's own `minimum-stability` field, when the caller has
///    one (`select_latest_matching_for_manifest`/`get_latest_matching_for_manifest`).
/// 4. [`crate::formatter::COMPOSER_STABLE_RANK`] — Composer's `minimum-stability: stable`
///    default, unchanged from #421/#422 for every caller with no manifest context.
pub(crate) fn effective_minimum_stability_rank(
    req_str: &str,
    manifest_minimum: Option<&str>,
) -> u8 {
    let trimmed = req_str.trim();
    if let Some(rank) = compound_stability_flag_rank(trimmed) {
        return rank;
    }
    if crate::types::is_prerelease_marker(trimmed) {
        return 0;
    }
    manifest_minimum.map_or(crate::formatter::COMPOSER_STABLE_RANK, |s| {
        crate::formatter::composer_stability_rank(s)
    })
}

/// Client for interacting with the Packagist registry.
///
/// Uses the Packagist v2 API for package metadata and search.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct PackagistRegistry {
    cache: Arc<HttpCache>,
    base: String,
}

impl PackagistRegistry {
    /// Creates a new Packagist registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_registry_base(cache, PACKAGIST_BASE.to_string())
    }

    /// Registry base URL — `PACKAGIST_BASE` in production, overridden to a mockito
    /// server URL in tests (mirrors `deps-npm`'s `with_registry_base`).
    fn with_registry_base(cache: Arc<HttpCache>, base: String) -> Self {
        Self { cache, base }
    }

    /// Fetches all versions for a package from the Packagist v2 API.
    ///
    /// Filters out dev versions (starting with `dev-` or ending with `-dev`).
    /// Returns versions in the order returned by the API (newest first).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request or JSON parsing fails.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<ComposerVersion>> {
        reject_dot_segment(name)?;
        let url = p2_url(&self.base, name);
        let data = self.cache.get_cached(&url).await?;
        parse_package_metadata(name, &data)
    }

    /// Finds the latest non-abandoned version satisfying the given requirement.
    ///
    /// Applies the same `minimum-stability: stable` default as
    /// [`Registry::select_latest_matching`](deps_core::Registry::select_latest_matching)
    /// (#421): an alpha/beta/RC release is excluded unless `req_str` itself is
    /// prerelease-bearing. Under a wildcard/empty `req_str` (see
    /// [`deps_core::is_existence_wildcard_str`]) this is an existence check, not an upgrade
    /// recommendation, so it falls back to [`deps_core::select_latest_for_existence`] —
    /// matching `deps-cargo`/`deps-pypi`/`deps-dart`/`deps-npm` — rather than returning `None`
    /// for a package whose only releases so far are all prerelease.
    ///
    /// Equivalent to
    /// [`get_latest_matching_for_manifest`](Self::get_latest_matching_for_manifest) with no
    /// manifest `minimum-stability` (`None`) — use that method instead when the caller has a
    /// parsed `composer.json` available (#424).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<ComposerVersion>> {
        self.get_latest_matching_impl(name, req_str, None).await
    }

    /// `composer.json`-aware counterpart of
    /// [`get_latest_matching`](Self::get_latest_matching): `minimum_stability` is the
    /// manifest's own top-level `minimum-stability` field
    /// ([`ComposerParseResult::minimum_stability`](crate::parser::ComposerParseResult::minimum_stability)),
    /// used as the default stability floor whenever `req_str` carries neither an explicit
    /// per-dependency `@stability` flag nor a directly pinned prerelease version — both of
    /// which still take priority over the manifest default, exactly as they do for
    /// [`get_latest_matching`](Self::get_latest_matching) (#424).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails.
    pub async fn get_latest_matching_for_manifest(
        &self,
        name: &str,
        req_str: &str,
        minimum_stability: Option<&str>,
    ) -> Result<Option<ComposerVersion>> {
        self.get_latest_matching_impl(name, req_str, minimum_stability)
            .await
    }

    async fn get_latest_matching_impl(
        &self,
        name: &str,
        req_str: &str,
        manifest_minimum: Option<&str>,
    ) -> Result<Option<ComposerVersion>> {
        let versions = self.get_versions(name).await?;

        let minimum_rank = effective_minimum_stability_rank(req_str, manifest_minimum);

        if deps_core::is_existence_wildcard_str(req_str) {
            let idx = select_latest_for_existence_composer(
                &versions,
                |v| v as &dyn deps_core::Version,
                minimum_rank,
            );
            return Ok(idx.and_then(|idx| versions.into_iter().nth(idx)));
        }

        let formatter = crate::formatter::ComposerFormatter;
        use deps_core::lsp_helpers::RequirementResolution;

        Ok(versions.into_iter().find(|v| {
            crate::formatter::composer_version_stability_rank(v.version.as_str()) >= minimum_rank
                && formatter.version_satisfies_requirement(&v.version, req_str)
        }))
    }

    /// `composer.json`-aware counterpart of
    /// [`Registry::select_latest_matching`](deps_core::Registry::select_latest_matching):
    /// `minimum_stability` is the manifest's own top-level `minimum-stability` field
    /// ([`ComposerParseResult::minimum_stability`](crate::parser::ComposerParseResult::minimum_stability)),
    /// used as the default stability floor whenever `req` carries neither an explicit
    /// per-dependency `@stability` flag nor a directly pinned prerelease version — both of
    /// which still take priority over the manifest default, exactly as they do for the plain
    /// trait method (#424).
    #[must_use]
    pub fn select_latest_matching_for_manifest(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
        minimum_stability: Option<&str>,
    ) -> Option<usize> {
        self.select_latest_matching_impl(versions, req, minimum_stability)
    }

    fn select_latest_matching_impl(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
        manifest_minimum: Option<&str>,
    ) -> Option<usize> {
        let minimum_rank = effective_minimum_stability_rank(req.as_str(), manifest_minimum);

        if deps_core::is_existence_wildcard(req) {
            return select_latest_for_existence_composer(versions, |v| v.as_ref(), minimum_rank);
        }

        let formatter = crate::formatter::ComposerFormatter;
        use deps_core::lsp_helpers::RequirementResolution;

        versions.iter().position(|v| {
            // Always true for Composer (`abandoned` maps to `AdvisoryDeprecated`, which
            // never blocks resolution) — kept to document the contract (#347).
            !v.removal_status().blocks_resolution()
                && crate::formatter::composer_version_stability_rank(v.version_string().as_str())
                    >= minimum_rank
                && formatter.version_satisfies_requirement(v.version_string(), req.as_str())
        })
    }

    /// Searches for packages by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request or JSON parsing fails.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<ComposerPackage>> {
        let url = format!(
            "{}?q={}&per_page={}",
            PACKAGIST_SEARCH,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Packagist v2 API response (outer wrapper).
#[derive(Deserialize)]
struct PackagistResponse {
    packages: std::collections::HashMap<String, Vec<MinifiedVersion>>,
}

/// Minified version entry from Packagist v2 API.
///
/// The v2 API returns only the first version as complete. Subsequent entries
/// contain only fields that changed from the previous entry.
///
/// `time` is deliberately excluded from this inheritance scheme (see
/// [`expand_minified_versions`]): every entry carries its own `time` (87/87
/// live-verified on `monolog/monolog`), and inheriting it across entries
/// would attribute one release's publish date to another.
#[derive(Deserialize, Clone, Default)]
struct MinifiedVersion {
    version: Option<String>,
    version_normalized: Option<String>,
    abandoned: Option<serde_json::Value>,
    /// Publish timestamp (RFC 3339, e.g. `"2026-01-02T08:56:05+00:00"`).
    #[serde(default)]
    time: Option<String>,
}

/// Expands minified Packagist v2 versions using field inheritance.
///
/// The v2 API compresses responses: only the first entry is complete.
/// Each subsequent entry inherits fields from the previous one and overrides
/// only the fields that changed. `time` is the one exception: it is read
/// only from the entry itself, never inherited, since a missing `time` means
/// the release genuinely has no known publish date, not that it shares the
/// previous release's date.
///
/// Dev versions (`dev-*` or `*-dev`) are filtered out.
fn expand_minified_versions(entries: Vec<MinifiedVersion>) -> Vec<ComposerVersion> {
    let mut result = Vec::new();
    let mut current = MinifiedVersion::default();

    for entry in entries {
        // `time` is not part of the inherited state; read it before `entry`
        // is partially consumed below.
        let published_at = entry
            .time
            .as_deref()
            .and_then(deps_core::PublishTime::parse_rfc3339);

        // Inherit previous state, then apply overrides
        if entry.version.is_some() {
            current.version = entry.version;
        }
        if entry.version_normalized.is_some() {
            current.version_normalized = entry.version_normalized;
        }
        if entry.abandoned.is_some() {
            current.abandoned = entry.abandoned;
        }

        let Some(ref version) = current.version else {
            continue;
        };

        // Filter dev versions
        if version.starts_with("dev-") || version.ends_with("-dev") {
            continue;
        }

        let abandoned = current
            .abandoned
            .as_ref()
            .is_some_and(|v| v.as_bool() == Some(true) || v.is_string());
        let deprecation = deprecation_from_abandoned(current.abandoned.as_ref());

        result.push(ComposerVersion {
            version: version.clone().into(),
            version_normalized: current
                .version_normalized
                .clone()
                .unwrap_or_else(|| version.clone()),
            abandoned,
            deprecation,
            published_at,
        });
    }

    result
}

/// Derives a #205 [`Deprecation`](deps_core::Deprecation) payload from Packagist's
/// `abandoned` field.
///
/// Packagist's `abandoned` is either absent/`false`/`null` (not abandoned), bare `true`
/// (abandoned, no known successor), or a string naming a replacement package — a
/// structured, registry-validated field, unlike npm's free-text `deprecated` message,
/// which is what makes Composer (and only Composer) safe to offer a rename quickfix for
/// (see `ComposerFormatter::supports_package_rename`).
///
/// M2: an all-whitespace replacement string produces a bare `Deprecation` (both fields
/// `None`) rather than one with an empty `replacement`, mirroring
/// `deps_npm::deprecation_from_message`'s empty-payload guard — though for Composer this
/// is defense-in-depth rather than an observed real-world case, since a real
/// `abandoned: true` already takes the same path.
fn deprecation_from_abandoned(abandoned: Option<&serde_json::Value>) -> Option<Deprecation> {
    let value = abandoned?;
    if value.as_bool() == Some(true) {
        return Some(Deprecation {
            reason: None,
            replacement: None,
        });
    }
    let replacement = value.as_str()?;
    Some(Deprecation {
        reason: None,
        replacement: (!replacement.trim().is_empty()).then(|| replacement.trim().to_string()),
    })
}

/// Parses Packagist v2 API response JSON.
fn parse_package_metadata(name: &str, data: &[u8]) -> Result<Vec<ComposerVersion>> {
    let response: PackagistResponse =
        deps_core::parse_json_checked(data).map_err(DepsError::Json)?;

    // Packagist uses lowercase package names as keys
    let key = name.to_lowercase();
    let entries = response.packages.get(&key).cloned().unwrap_or_default();

    Ok(expand_minified_versions(entries))
}

/// Packagist search API response.
#[derive(Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

/// Individual search result.
#[derive(Deserialize)]
struct SearchResult {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

/// Parses Packagist search API response.
fn parse_search_response(data: &[u8]) -> Result<Vec<ComposerPackage>> {
    let response: SearchResponse = deps_core::parse_json_checked(data).map_err(DepsError::Json)?;

    Ok(response
        .results
        .into_iter()
        .map(|r| ComposerPackage {
            name: r.name.into(),
            description: r.description,
            repository: r.repository,
            homepage: r.url,
            latest_version: r.version.unwrap_or_default().into(),
        })
        .collect())
}

impl deps_core::Registry for PackagistRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    /// Routes to [`PackagistRegistry::get_latest_matching_for_manifest`] — see that method
    /// for the full priority order. This is the trait-level hook a generic LSP fetch loop
    /// downcasting `Arc<dyn Registry>` cannot bypass by calling
    /// [`get_latest_matching`](Self::get_latest_matching) instead (#424 S1).
    fn get_latest_matching_with_context<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
        minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching_for_manifest(name.as_str(), req.as_str(), minimum_stability)
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let packages = self.search(query, limit).await?;
            Ok(packages
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    /// Picks the latest version satisfying `req`, applying Composer's default
    /// `minimum-stability: stable` semantics (#421): an alpha/beta/RC release is
    /// excluded from "latest" unless `req` itself names an unstable version (e.g. an
    /// exact `2.0.0-beta1` pin or a lower bound like `>=2.0.0-beta1`) — mirroring
    /// `deps-nuget`'s prerelease-bearing-requirement exception (`registry.rs`'s
    /// `pick_latest_matching`). `dev-*`/`*-dev` branches never reach here at all:
    /// `expand_minified_versions` already filters them out of every `Registry::get_versions`
    /// result.
    ///
    /// Under a wildcard/empty `req` (see [`deps_core::is_existence_wildcard`]) this is an
    /// existence check, not an upgrade recommendation, so it defers to
    /// `select_latest_for_existence_composer` instead — matching the *shape* of
    /// `deps-cargo`/`deps-pypi`/`deps-dart`/`deps-npm` (a package whose only releases so far
    /// are all prerelease still resolves to its newest one rather than `None`), while keeping
    /// Composer's own #347 ranking rule that `abandoned` never demotes a version.
    ///
    /// Does not read `composer.json`'s own `minimum-stability` field — this trait method has
    /// no manifest context to read it from. A caller with a parsed manifest available should
    /// use [`PackagistRegistry::select_latest_matching_for_manifest`] instead, which this
    /// method is equivalent to with no manifest `minimum-stability` (`None`) (#424).
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        self.select_latest_matching_impl(versions, req, None)
    }

    /// Routes to [`PackagistRegistry::select_latest_matching_for_manifest`] — the trait-level
    /// hook a generic LSP fetch loop downcasting `Arc<dyn Registry>` cannot bypass by calling
    /// the plain `select_latest_matching` instead (#424 S1).
    fn select_latest_matching_with_context(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
        minimum_stability: Option<&str>,
    ) -> Option<usize> {
        self.select_latest_matching_for_manifest(versions, req, minimum_stability)
    }

    // Packagist's `abandoned` is package-level, not per-version: `removal_status`
    // reports `AdvisoryDeprecated` for "this package is abandoned", inherited by
    // every version via the p2 minified-inheritance loop. Enabling the yanked
    // diagnostic here would fire on nearly every version of an abandoned package
    // (#233 R2, #205).
    fn reports_yanked(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url_preserves_vendor_package() {
        assert_eq!(
            package_url("symfony/console"),
            "https://packagist.org/packages/symfony/console"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_segments() {
        let url = package_url("evil)[/pkg](x");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<%>/pkg");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://packagist.org/packages/");
    }

    #[test]
    fn test_reject_dot_segment_rejects_bare_dot_dot() {
        assert!(reject_dot_segment("..").is_err());
    }

    #[test]
    fn test_reject_dot_segment_rejects_vendor_dot_dot() {
        assert!(reject_dot_segment("../evil").is_err());
    }

    #[test]
    fn test_reject_dot_segment_rejects_package_dot_dot() {
        assert!(reject_dot_segment("vendor/..").is_err());
    }

    #[test]
    fn test_reject_dot_segment_accepts_normal_names() {
        assert!(reject_dot_segment("monolog/monolog").is_ok());
        assert!(reject_dot_segment("symfony").is_ok());
    }

    /// Demonstrates the vulnerability `reject_dot_segment` exists to prevent: `p2_url`
    /// alone (with no caller-side guard) builds a URL that, once parsed, has already lost
    /// the `p2` path component for a `vendor` of exactly `..`.
    #[test]
    fn test_p2_url_bare_dot_dot_vendor_normalizes_above_p2_prefix() {
        let url = p2_url("https://repo.packagist.org", "../evil");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/evil.json",
            "parsed path: {}",
            parsed.path()
        );
    }

    /// #365 regression sweep: exercises the real production `reject_dot_segment` gate and
    /// `p2_url` sink together against the shared adversarial input set (varying vendor,
    /// then package), guarding against a 6th recurrence of the dot-segment defect class in
    /// this crate.
    #[test]
    fn test_p2_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                let name = format!("{seg}/package");
                reject_dot_segment(&name)
                    .ok()
                    .map(|()| p2_url("https://repo.packagist.org", &name))
            },
            "repo.packagist.org",
            "/p2/",
        );
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                let name = format!("vendor/{seg}");
                reject_dot_segment(&name)
                    .ok()
                    .map(|()| p2_url("https://repo.packagist.org", &name))
            },
            "repo.packagist.org",
            "/p2/",
        );
    }

    /// #365 end-to-end coverage (critic S2): exercises the real production
    /// `get_versions` — not a reimplemented gate+sink pair — proving the gate is actually
    /// wired into the call path a real completion/hover/diagnostic request would take. No
    /// mock is needed: the gate must reject before any network request is issued.
    ///
    /// Asserts the exact `PackageNotFound` variant (gate rejected before any request), not
    /// the broader `is_not_found()` (also true for a live 404 `HttpStatus`) — critic R1:
    /// `repo.packagist.org` 404ing for this path today would make a deleted gate go
    /// undetected by this test.
    #[tokio::test]
    async fn test_get_versions_rejects_vendor_dot_dot_as_not_found() {
        let registry = PackagistRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("../evil").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[test]
    fn test_expand_minified_versions_basic() {
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("2.0.0".into()),
                version_normalized: Some("2.0.0.0".into()),
                abandoned: None,
                time: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "3.0.0");
        assert_eq!(versions[1].version, "2.0.0");
        assert!(!versions[0].abandoned);
    }

    #[test]
    fn test_expand_minified_versions_field_inheritance() {
        // Second entry inherits version_normalized from first, only version changes
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("2.9.0".into()),
                version_normalized: None, // inherited
                abandoned: None,
                time: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[1].version, "2.9.0");
        assert_eq!(versions[1].version_normalized, "3.0.0.0"); // inherited
    }

    #[test]
    fn test_expand_minified_versions_filters_dev() {
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("dev-main".into()),
                version_normalized: None,
                abandoned: None,
                time: None,
            },
            MinifiedVersion {
                version: Some("2.0.0-dev".into()),
                version_normalized: None,
                abandoned: None,
                time: None,
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "3.0.0");
    }

    #[test]
    fn test_expand_minified_versions_abandoned() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: Some(serde_json::Value::String("Use other/package".into())),
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(versions[0].abandoned);
        assert_eq!(
            versions[0].deprecation,
            Some(Deprecation {
                reason: None,
                replacement: Some("Use other/package".to_string()),
            })
        );
    }

    /// #205: a bare `"abandoned": true` still fires — both `Deprecation` fields `None`
    /// (no known successor) — distinct from `Some` with an empty payload.
    #[test]
    fn test_expand_minified_versions_abandoned_true_has_no_replacement() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: Some(serde_json::Value::Bool(true)),
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(
            versions[0].deprecation,
            Some(Deprecation {
                reason: None,
                replacement: None,
            })
        );
    }

    /// #205 M2: an all-whitespace replacement string must not leak through as an empty,
    /// dangling `replacement` — the package is still abandoned (mirrors bare `true`).
    #[test]
    fn test_expand_minified_versions_abandoned_whitespace_replacement_is_none() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: Some(serde_json::Value::String("   ".into())),
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(
            versions[0].deprecation,
            Some(Deprecation {
                reason: None,
                replacement: None,
            })
        );
    }

    /// Not abandoned at all: no `Deprecation` payload.
    #[test]
    fn test_expand_minified_versions_not_abandoned_has_no_deprecation() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions[0].deprecation, None);
    }

    #[test]
    fn test_expand_minified_versions_with_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: Some("2026-01-02T08:56:05+00:00".into()),
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            deps_core::PublishTime::parse_rfc3339("2026-01-02T08:56:05+00:00")
        );
    }

    #[test]
    fn test_expand_minified_versions_without_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: None,
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_expand_minified_versions_with_malformed_time() {
        let entries = vec![MinifiedVersion {
            version: Some("3.0.0".into()),
            version_normalized: Some("3.0.0.0".into()),
            abandoned: None,
            time: Some("not-a-timestamp".into()),
        }];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed time degrades to None, not an error"
        );
    }

    #[test]
    fn test_expand_minified_versions_time_is_not_inherited() {
        // Correctness requirement: an entry with no `time` must yield `None`
        // for that entry, never the previous entry's `time` — unlike
        // `version_normalized`/`abandoned`, which do inherit.
        let entries = vec![
            MinifiedVersion {
                version: Some("3.0.0".into()),
                version_normalized: Some("3.0.0.0".into()),
                abandoned: None,
                time: Some("2026-01-02T08:56:05+00:00".into()),
            },
            MinifiedVersion {
                version: Some("2.9.0".into()),
                version_normalized: None, // inherited
                abandoned: None,
                time: None, // must NOT inherit the previous entry's time
            },
        ];

        let versions = expand_minified_versions(entries);
        assert_eq!(versions.len(), 2);
        assert!(versions[0].published_at.is_some());
        assert!(
            versions[1].published_at.is_none(),
            "time must not be inherited from the previous entry"
        );
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
  "results": [
    {
      "name": "symfony/console",
      "description": "Symfony Console Component",
      "version": "6.0.0",
      "url": "https://packagist.org/packages/symfony/console",
      "repository": "https://github.com/symfony/console"
    }
  ],
  "total": 1
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);

        let pkg = &packages[0];
        assert_eq!(pkg.name, "symfony/console");
        assert_eq!(pkg.description, Some("Symfony Console Component".into()));
        assert_eq!(pkg.latest_version, "6.0.0");
    }

    #[test]
    fn test_parse_search_response_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"results": [], "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_search_response(json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_search_response_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"results": [], "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_search_response(json.as_bytes()).is_err());
    }

    #[test]
    fn test_parse_package_metadata() {
        let json = r#"{
  "packages": {
    "monolog/monolog": [
      {
        "version": "3.0.0",
        "version_normalized": "3.0.0.0",
        "abandoned": null
      },
      {
        "version": "2.0.0",
        "version_normalized": "2.0.0.0"
      }
    ]
  }
}"#;

        let versions = parse_package_metadata("monolog/monolog", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "3.0.0");
    }

    #[test]
    fn test_parse_package_metadata_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `abandoned` value must be rejected by the
        // depth guard rather than handed to `serde_json::from_slice`.
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let deeply_nested = format!(
            r#"{{"packages":{{"monolog/monolog":[{{"version":"3.0.0","abandoned":{}1{}}}]}}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_package_metadata("monolog/monolog", deeply_nested.as_bytes()).is_err());
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        // Regression for #347's mixed case: the newest version is abandoned, an older
        // version is clean. Composer has no npm-style ranking preference for a
        // non-abandoned version over a newer abandoned one (unlike deps-npm's #338
        // NFR-002) — `abandoned` is advisory, not a hard removal from resolution, so
        // the newest version resolves as latest regardless of its abandoned flag.
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0".into(),
                version_normalized: "2.0.0.0".into(),
                abandoned: true,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_select_latest_matching_all_abandoned_still_resolves() {
        // Regression test for #347: an abandoned package's versions must
        // still resolve under a wildcard requirement — `abandoned` is
        // advisory, not a hard removal from resolution.
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0".into(),
                version_normalized: "2.0.0.0".into(),
                abandoned: true,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: true,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #347's other half (S2): the inherent `get_latest_matching` —
    /// the fetch loop's fallback when the pure list-based `select_latest_matching`
    /// pick finds nothing, and the path `diagnostics.rs`'s live-lookup exercises
    /// directly — must also resolve an all-abandoned package instead of treating it
    /// as non-existent. Mirrors `deps-npm`'s
    /// `test_get_latest_matching_wildcard_all_deprecated_returns_newest` shape.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_all_abandoned_still_resolves() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/abandoned-pkg.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/abandoned-pkg": [
                    {"version": "2.0.0", "version_normalized": "2.0.0.0", "abandoned": true},
                    {"version": "1.0.0", "version_normalized": "1.0.0.0", "abandoned": true}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("vendor/abandoned-pkg", "*")
            .await
            .unwrap();

        let version = latest.expect("an all-abandoned package still exists and resolves");
        assert_eq!(version.version, "2.0.0");
    }

    /// Regression for #421: `select_latest_matching` must not surface a real
    /// alpha/beta/RC release as "latest" for a loose requirement — Composer's default
    /// `minimum-stability: stable` excludes it even though it satisfies `>=1.0`.
    #[test]
    fn test_select_latest_matching_excludes_prerelease_for_loose_requirement() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0-beta1".into(),
                version_normalized: "2.0.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=1.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// Regression for #421: an explicit prerelease-bearing requirement (e.g. an exact
    /// `2.0.0-beta1` pin) must still resolve to that prerelease — the default stability
    /// filter only applies when the requirement itself does not name an unstable version.
    #[test]
    fn test_select_latest_matching_allows_prerelease_when_requirement_names_it() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0-beta1".into(),
                version_normalized: "2.0.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("2.0.0-beta1");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #421 (S2): the inherent `get_latest_matching` fetch-loop fallback
    /// must apply the same default stability filter as `select_latest_matching`.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_excludes_prerelease() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/pkg.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/pkg": [
                    {"version": "2.0.0-beta1", "version_normalized": "2.0.0.0-beta1"},
                    {"version": "1.5.0", "version_normalized": "1.5.0.0"}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("vendor/pkg", "*")
            .await
            .unwrap();

        let version = latest.expect("a package with a stable release still resolves");
        assert_eq!(version.version, "1.5.0");
    }

    /// Regression for #421 S1: the "is this requirement prerelease-bearing" check must use
    /// the same predicate as `Version::is_prerelease()`, including Composer's short `-a`/`-b`
    /// stability alias — not just `deps-core`'s default `-alpha`/`-beta`/`-rc` substrings.
    /// Before the fix, an exact `2.0.0-a1` pin was not recognized as prerelease-bearing even
    /// though the version it names (`2.0.0-a1`) is itself classified as a prerelease, making
    /// it impossible to ever satisfy.
    #[test]
    fn test_select_latest_matching_allows_short_alias_prerelease_when_requirement_names_it() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0-a1".into(),
                version_normalized: "2.0.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("2.0.0-a1");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #421 S1's exact measured case: a caret requirement whose lower bound
    /// is a short-alias prerelease (`^1.0.0-a1`) must also be recognized as
    /// prerelease-bearing, not just an exact pin.
    #[test]
    fn test_select_latest_matching_allows_short_alias_prerelease_with_caret_requirement() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![Box::new(ComposerVersion {
            version: "1.0.0-a1".into(),
            version_normalized: "1.0.0.0-alpha1".into(),
            abandoned: false,
            deprecation: None,
            published_at: None,
        })];
        let req = VersionReq::new("^1.0.0-a1");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #421 (M2): the async `get_latest_matching` fetch-loop fallback must
    /// also honor an explicit prerelease-bearing requirement, mirroring
    /// `test_select_latest_matching_allows_prerelease_when_requirement_names_it`.
    #[tokio::test]
    async fn test_get_latest_matching_allows_prerelease_when_requirement_names_it() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/pkg.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/pkg": [
                    {"version": "2.0.0-beta1", "version_normalized": "2.0.0.0-beta1"},
                    {"version": "1.5.0", "version_normalized": "1.5.0.0"}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("vendor/pkg", "2.0.0-beta1")
            .await
            .unwrap();

        let version = latest.expect("an explicit prerelease pin resolves to that prerelease");
        assert_eq!(version.version, "2.0.0-beta1");
    }

    /// Regression for #421 (S2): a package whose only releases so far are all prerelease
    /// must still resolve under a wildcard requirement — matching
    /// `deps-cargo`/`deps-pypi`/`deps-dart`/`deps-npm`'s existence-check behavior — instead
    /// of `select_latest_matching` returning `None` and the package appearing unresolvable.
    #[test]
    fn test_select_latest_matching_wildcard_prerelease_only_still_resolves() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0-beta2".into(),
                version_normalized: "2.0.0.0-beta2".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "2.0.0-beta1".into(),
                version_normalized: "2.0.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #421 (S2): the async `get_latest_matching` fetch-loop fallback must
    /// resolve a prerelease-only package under a wildcard requirement too, mirroring
    /// `test_select_latest_matching_wildcard_prerelease_only_still_resolves`.
    #[tokio::test]
    async fn test_get_latest_matching_wildcard_prerelease_only_still_resolves() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/prerelease-only.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/prerelease-only": [
                    {"version": "2.0.0-beta2", "version_normalized": "2.0.0.0-beta2"},
                    {"version": "2.0.0-beta1", "version_normalized": "2.0.0.0-beta1"}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching("vendor/prerelease-only", "*")
            .await
            .unwrap();

        let version = latest.expect("a prerelease-only package still exists and resolves");
        assert_eq!(version.version, "2.0.0-beta2");
    }

    // --- #424 S1: manifest-level `minimum-stability` threading ---

    fn stability_fixture() -> Vec<Box<dyn deps_core::Version>> {
        vec![
            Box::new(ComposerVersion {
                version: "2.0.0-alpha1".into(),
                version_normalized: "2.0.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "2.0.0-beta1".into(),
                version_normalized: "2.0.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ]
    }

    /// #424 S1: a manifest with `minimum-stability: beta` must resolve the newest release at
    /// or above beta (excluding alpha) as "latest", not fall back to the hardcoded
    /// `minimum-stability: stable` default that would exclude both prereleases.
    #[test]
    fn test_select_latest_matching_for_manifest_honors_looser_minimum_stability() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = stability_fixture();
        let req = deps_core::VersionReq::new("*");

        assert_eq!(
            registry.select_latest_matching_for_manifest(&versions, &req, Some("beta")),
            Some(1),
            "beta release should be latest under minimum-stability: beta"
        );
    }

    /// #424 S1: `minimum-stability: alpha` loosens the floor further still, all the way to
    /// the newest alpha.
    #[test]
    fn test_select_latest_matching_for_manifest_honors_alpha_minimum_stability() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = stability_fixture();
        let req = deps_core::VersionReq::new("*");

        assert_eq!(
            registry.select_latest_matching_for_manifest(&versions, &req, Some("alpha")),
            Some(0),
            "alpha release should be latest under minimum-stability: alpha"
        );
    }

    /// #424 S1: with no manifest `minimum-stability` (`None`), behavior must be byte-identical
    /// to the plain trait method — the hardcoded `stable` default from #421/#422.
    #[test]
    fn test_select_latest_matching_for_manifest_none_matches_default() {
        use deps_core::Registry;

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = stability_fixture();
        let req = deps_core::VersionReq::new("*");

        assert_eq!(
            registry.select_latest_matching_for_manifest(&versions, &req, None),
            registry.select_latest_matching(&versions, &req),
        );
    }

    /// #424 S1: `minimum-stability: stable` (explicit, not just absent) must behave exactly
    /// like the hardcoded default — Composer's own default value, spelled out.
    #[test]
    fn test_select_latest_matching_for_manifest_explicit_stable_excludes_prerelease() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = stability_fixture();
        let req = deps_core::VersionReq::new("*");

        assert_eq!(
            registry.select_latest_matching_for_manifest(&versions, &req, Some("stable")),
            Some(2),
        );
    }

    /// #424 S1: the async `get_latest_matching_for_manifest` fetch-loop entry point must
    /// apply the same manifest stability floor as the pure list-based
    /// `select_latest_matching_for_manifest`.
    #[tokio::test]
    async fn test_get_latest_matching_for_manifest_honors_looser_minimum_stability() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let registry = PackagistRegistry::with_registry_base(Arc::new(HttpCache::new()), base);

        server
            .mock("GET", "/p2/vendor/pkg.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"vendor/pkg": [
                    {"version": "2.0.0-beta1", "version_normalized": "2.0.0.0-beta1"},
                    {"version": "1.5.0", "version_normalized": "1.5.0.0"}
                ]}}"#,
            )
            .create_async()
            .await;

        let latest = registry
            .get_latest_matching_for_manifest("vendor/pkg", "*", Some("beta"))
            .await
            .unwrap();

        assert_eq!(
            latest.expect("beta release resolves").version,
            "2.0.0-beta1"
        );
    }

    // --- #424 S2: per-dependency `@stability` flags ---

    /// #424 S2: `^1.0@beta` must be recognized as a prerelease-bearing opt-in — a beta
    /// release satisfying the range must resolve as latest, not be excluded by the default
    /// stable-only filter.
    #[test]
    fn test_select_latest_matching_at_beta_flag_allows_beta() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-beta1".into(),
                version_normalized: "1.5.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@beta");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            Some(0),
            "beta release matching the range must resolve under an @beta opt-in"
        );
    }

    /// #424 S2: an `@beta` opt-in permits beta but not a *looser* alpha release — the flag
    /// sets a floor, not "allow everything unstable".
    #[test]
    fn test_select_latest_matching_at_beta_flag_excludes_alpha() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-alpha1".into(),
                version_normalized: "1.5.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@beta");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            Some(1),
            "alpha release must still be excluded under an @beta opt-in"
        );
    }

    /// #424 S2: `@stable` is recognized (parses cleanly, does not corrupt range matching) but
    /// is not itself a prerelease-bearing opt-in — it is Composer's own default spelled out
    /// explicitly, so an alpha/beta release must still be excluded.
    #[test]
    fn test_select_latest_matching_at_stable_flag_still_excludes_prerelease() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-beta1".into(),
                version_normalized: "1.5.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@stable");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #424 tester gap: `@RC` must be exercised end-to-end through `select_latest_matching`,
    /// not just unit-tested on `strip_stability_flag`/`composer_stability_rank` in isolation.
    /// An RC release matching the range must resolve, but a looser beta release must not.
    #[test]
    fn test_select_latest_matching_at_rc_flag_allows_rc_excludes_beta() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-beta1".into(),
                version_normalized: "1.5.0.0-beta1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.4.0-RC1".into(),
                version_normalized: "1.4.0.0-RC1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@RC");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            Some(1),
            "RC release must resolve, but a looser beta release must still be excluded"
        );
    }

    /// #424 tester gap: `@alpha` end-to-end — the loosest non-dev flag, so it must admit an
    /// alpha release too (dev-* branches are already filtered out of `get_versions` entirely,
    /// so `@alpha` and `@dev` are equivalent in practice for real numbered versions).
    #[test]
    fn test_select_latest_matching_at_alpha_flag_allows_alpha() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-alpha1".into(),
                version_normalized: "1.5.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@alpha");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// #424 tester gap: `@dev` end-to-end — admits a real numbered alpha/beta release too,
    /// since `@dev` ranks loosest (rank 0) and `dev-*` branch versions never reach this list.
    #[test]
    fn test_select_latest_matching_at_dev_flag_allows_alpha() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "1.5.0-alpha1".into(),
                version_normalized: "1.5.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.0.0".into(),
                version_normalized: "1.0.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("^1.0@dev");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    // --- #424 critique M1: compound requirements must not drop the `@flag` opt-in ---

    /// #424 critique M1: an `@flag` inside the first OR-branch of a compound requirement
    /// (`^1.0@beta || ^2.0`) must still be recognized, admitting a beta release matching that
    /// branch.
    #[test]
    fn test_select_latest_matching_at_flag_in_or_branch() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![Box::new(ComposerVersion {
            version: "1.5.0-beta1".into(),
            version_normalized: "1.5.0.0-beta1".into(),
            abandoned: false,
            deprecation: None,
            published_at: None,
        })];
        let req = VersionReq::new("^1.0@beta || ^2.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// #424 critique M1: an `@flag` inside one token of a space-separated AND range
    /// (`>=1.0@dev <2.0`) must still be recognized.
    #[test]
    fn test_select_latest_matching_at_flag_in_and_range() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![Box::new(ComposerVersion {
            version: "1.5.0-alpha1".into(),
            version_normalized: "1.5.0.0-alpha1".into(),
            abandoned: false,
            deprecation: None,
            published_at: None,
        })];
        let req = VersionReq::new(">=1.0@dev <2.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// #424 critique M1: `compound_stability_flag_rank` unit-level — confirms the loosest
    /// flag among multiple tokens wins, and that a flag-less compound requirement yields
    /// `None` (falling through to the next priority tier).
    #[test]
    fn test_compound_stability_flag_rank() {
        assert_eq!(
            compound_stability_flag_rank("^1.0@beta || ^2.0"),
            Some(crate::formatter::composer_stability_rank("beta"))
        );
        assert_eq!(
            compound_stability_flag_rank(">=1.0@dev <2.0"),
            Some(crate::formatter::composer_stability_rank("dev"))
        );
        assert_eq!(
            compound_stability_flag_rank("^1.0@alpha || ^2.0@RC"),
            Some(crate::formatter::composer_stability_rank("alpha")),
            "the loosest flag among branches must win"
        );
        assert_eq!(compound_stability_flag_rank("^1.0 || ^2.0"), None);
    }

    // --- #424 critique S2: separator-less short-alias (a/b) and dev, end-to-end ---

    /// #424 critique S2 gap: separator-less short alias `a1`/`b1` end-to-end through
    /// `select_latest_matching`, mirroring the existing separator-less-RC coverage.
    #[test]
    fn test_select_latest_matching_excludes_separatorless_short_alias() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0a1".into(),
                version_normalized: "2.0.0a1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=1.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #424 critique S2 gap: an exact separator-less short-alias pin (`2.0.0a1`) must resolve
    /// to itself — this is the exact case that was broken pre-fix (classifiers disagreed).
    #[test]
    fn test_select_latest_matching_allows_separatorless_short_alias_pin_when_requirement_names_it()
    {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0a1".into(),
                version_normalized: "2.0.0a1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("2.0.0a1");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// #424 critique S2 gap: separator-less `dev` suffix end-to-end.
    #[test]
    fn test_select_latest_matching_excludes_separatorless_dev_suffix() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0dev".into(),
                version_normalized: "2.0.0dev".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=1.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    // --- #424 critique C1: v-prefixed prereleases, end-to-end (CRITICAL regression) ---

    /// #424 critique C1: reproduces the live `sylius/sylius` regression — a `v`-prefixed
    /// alpha release must not be reported as "latest" ahead of an older `v`-prefixed stable
    /// release. Before the fix, `composer_version_stability_rank` swallowed the leading `v`
    /// as the qualifier word itself and ranked the alpha release as stable.
    #[test]
    fn test_select_latest_matching_v_prefixed_alpha_excluded_by_default() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "v2.3.0-alpha.1".into(),
                version_normalized: "2.3.0.0-alpha1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "v2.2.8".into(),
                version_normalized: "2.2.8.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            Some(1),
            "v2.2.8 (stable) must resolve as latest, not the v-prefixed alpha ahead of it"
        );
    }

    /// #424 critique C1: `symfony/*`-style data — a `v`-prefixed RC release ordered ahead of
    /// a `v`-prefixed stable release in the version list must still be excluded by the
    /// default stable-only filter for a concrete requirement.
    #[test]
    fn test_select_latest_matching_v_prefixed_rc_excluded_for_concrete_requirement() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "V3.0.0-RC1".into(),
                version_normalized: "3.0.0.0-RC1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "v2.9.0".into(),
                version_normalized: "2.9.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=2.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    // --- #424 S3: separator-less prerelease suffix consistency ---

    /// #424 S3: `1.0.0RC1` (no separator before `RC`) must be excluded from "latest" by the
    /// default stable-only filter exactly like its hyphenated form `1.0.0-RC1` — classified
    /// via the primary `is_prerelease_marker` path, independent of `version_normalized`.
    #[test]
    fn test_select_latest_matching_excludes_separatorless_rc_suffix() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0RC1".into(),
                // `version_normalized` deliberately left un-hyphenated (mirrors a Packagist
                // response that never expanded it) so the primary path must catch this alone.
                version_normalized: "2.0.0RC1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=1.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #424 S3: an exact separator-less pin (`2.0.0RC1`) must still be recognized as a
    /// prerelease-bearing requirement and resolve to itself — mirroring the hyphenated-pin
    /// case `test_select_latest_matching_allows_prerelease_when_requirement_names_it`.
    #[test]
    fn test_select_latest_matching_allows_separatorless_rc_pin_when_requirement_names_it() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.0.0RC1".into(),
                version_normalized: "2.0.0RC1".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "1.5.0".into(),
                version_normalized: "1.5.0.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("2.0.0RC1");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// #424 critique N3: a dot-separated qualifier (`2.6.3.alpha`, a live `api-platform/core`
    /// tag) must be excluded from "latest" by the default stable-only filter, exactly like the
    /// hyphenated/separator-less forms above.
    #[test]
    fn test_select_latest_matching_excludes_dot_separated_alpha_suffix() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.6.3.alpha".into(),
                version_normalized: "2.6.3.0-alpha".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "2.6.2".into(),
                version_normalized: "2.6.2.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new(">=2.0");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #424 critique N3: an exact pin naming the dot-separated prerelease form directly
    /// (`2.6.3.alpha`) must still resolve to itself — before the fix, `is_prerelease_marker`
    /// disagreed with `composer_version_stability_rank` on this exact shape, which is the
    /// #421 S1 failure mode (a pin that can never match its own version).
    #[test]
    fn test_select_latest_matching_allows_dot_separated_alpha_pin_when_requirement_names_it() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(ComposerVersion {
                version: "2.6.3.alpha".into(),
                version_normalized: "2.6.3.0-alpha".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
            Box::new(ComposerVersion {
                version: "2.6.2".into(),
                version_normalized: "2.6.2.0".into(),
                abandoned: false,
                deprecation: None,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("2.6.3.alpha");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_monolog_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let versions = registry.get_versions("monolog/monolog").await.unwrap();

        assert!(!versions.is_empty());
        assert!(
            versions
                .iter()
                .any(|v| v.version.as_str().starts_with("3."))
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = PackagistRegistry::new(cache);
        let results = registry.search("symfony", 5).await.unwrap();

        assert!(!results.is_empty());
    }
}
