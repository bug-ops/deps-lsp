//! JSR registry client and the scheme-dispatching Deno registry facade (D3).
//!
//! A Deno `imports` map mixes two registries in one file: `jsr:` specifiers resolve
//! against the JSR API (this module's [`JsrRegistry`]), and `npm:` specifiers reuse the
//! existing [`deps_npm::NpmRegistry`] unchanged. [`DenoRegistry`] is the single
//! `deps_core::Registry` implementation the ecosystem exposes; every method splits the
//! scheme off the incoming (already scheme-qualified, per D2) [`PackageName`] and
//! delegates to whichever half owns it.

use crate::specifier::{Scheme, is_dot_prefixed, split_scheme, split_scoped};
use crate::types::{DenoMetadata, JsrPackage, JsrVersion};
use deps_core::{
    DepsError, FreshnessSettings, HttpCache, Metadata, PackageName, Registry, Result, Version,
    VersionReq, lsp_helpers::warn_rejected_value,
};
use deps_npm::NpmRegistry;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

const JSR_BASE: &str = "https://jsr.io";
const JSR_API_BASE: &str = "https://api.jsr.io";

/// Display name for the JSR registry used in not-found error messages.
pub const REGISTRY: &str = "jsr";

/// Returns the URL for a JSR package's page on jsr.io.
///
/// Display link only, never fetched by this process — unlike `meta_json_url` (a fetch
/// sink), so it is deliberately not gated against a `.`/`..` scope or name segment (see
/// [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link scope split, #379).
/// `DenoFormatter::package_url` (the sole caller) already rejects a malformed/unscoped `jsr:`
/// specifier before reaching here (#378/#380 follow-up); this function itself is unchanged.
#[must_use]
pub fn jsr_package_url(scope: &str, name: &str) -> String {
    format!(
        "{JSR_BASE}/@{}/{}",
        urlencoding::encode(scope),
        urlencoding::encode(name)
    )
}

fn meta_json_url(base: &str, scope: &str, name: &str) -> String {
    format!(
        "{base}/@{}/{}/meta.json",
        urlencoding::encode(scope),
        urlencoding::encode(name)
    )
}

/// Upper bound on how many results [`JsrRegistry::search`] fetches from the wire before
/// reordering/truncating to the caller's requested `limit`, for a scope-qualified query
/// (N1). Bounds the request even if `limit` itself is large; JSR's search API returns
/// `total` (well beyond this) but a scope-qualified completion query never needs more than
/// a small over-fetch to find the exact-scope match within.
const MAX_SCOPE_SEARCH_OVERFETCH: usize = 40;

/// Splits a scope-qualified search query (`"@scope/pkg-prefix"`) into `(scope,
/// pkg_prefix)`. `pkg_prefix` may be empty if the caller hasn't typed a package-name
/// character yet (`"@std/"`). Returns `None` for an unscoped query (no leading `@`) or one
/// with no `/` yet (`"@std"` — still typing the scope, nothing to split on).
fn split_scope_query(query: &str) -> Option<(&str, &str)> {
    let after_at = query.strip_prefix('@')?;
    after_at.split_once('/')
}

/// Extracts the scope portion of a [`JsrPackage`]'s already scheme-qualified `name`
/// (`"jsr:@scope/pkg"`), or `""` if the name is unexpectedly not in that shape.
fn package_scope(pkg: &JsrPackage) -> &str {
    pkg.name
        .as_str()
        .strip_prefix("jsr:@")
        .and_then(|s| s.split_once('/'))
        .map_or("", |(scope, _)| scope)
}

/// Converts a 404 response into `DepsError::PackageNotFound`, passing through any other
/// error unchanged. Mirrors `deps-npm`'s `not_found_or` (`deps-npm/src/registry.rs`).
fn not_found_or(err: DepsError, full_name: &str) -> DepsError {
    if matches!(err, DepsError::HttpStatus { status: 404, .. }) {
        DepsError::PackageNotFound {
            package: full_name.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
}

/// Builds the error for a scheme-qualified name that could not be routed: an unknown or
/// missing scheme reaching a fetch method, or a scheme-qualified name with nothing after
/// it (`"npm:"`) — the latter is not merely defensive:
/// [`partial_name_range`](crate::specifier::partial_name_range) (#310) deliberately treats
/// a bare `"npm:"`/`"jsr:"` as a completion-eligible in-progress
/// dependency name while the user is mid-keystroke, so `rest.is_empty()` reaches this
/// facade's `npm:` arm in normal use (M2) and must be rejected here rather than turned
/// into a GET against the bare npm registry base URL.
fn unroutable(name: &PackageName) -> DepsError {
    DepsError::PackageNotFound {
        package: name.to_string(),
        registry: "deno",
    }
}

/// One JSR package version entry inside `meta.json`'s `versions` object.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct MetaVersionEntry {
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    created_at: Option<String>,
}

/// The subset of `https://jsr.io/@{scope}/{pkg}/meta.json` this client needs.
#[derive(Deserialize)]
struct MetaJson {
    versions: HashMap<String, MetaVersionEntry>,
}

/// One search result inside `https://api.jsr.io/packages?query=`'s `items` array.
#[derive(Deserialize)]
struct SearchItem {
    scope: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "latestVersion", default)]
    latest_version: Option<String>,
    #[serde(rename = "githubRepository", default)]
    github_repository: Option<GithubRepository>,
}

#[derive(Deserialize)]
struct GithubRepository {
    owner: String,
    name: String,
}

#[derive(Deserialize)]
struct SearchResponse {
    items: Vec<SearchItem>,
}

/// Client for the JSR registry (`jsr.io` for package metadata, `api.jsr.io` for search).
///
/// Both endpoints are keyless (live-verified 2026-08-24) and are fetched through the
/// shared `HttpCache`, so no TTL tuning is needed (NFR-001): JSR sends a strong `ETag`,
/// and `HttpCache` revalidates via `If-None-Match` on every call regardless of the
/// `Cache-Control: no-cache, no-store` header JSR also sends.
#[derive(Clone)]
pub struct JsrRegistry {
    cache: Arc<HttpCache>,
    base: String,
    api_base: String,
}

impl JsrRegistry {
    /// Creates a new JSR registry client with the given HTTP cache.
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_bases(cache, JSR_BASE.to_string(), JSR_API_BASE.to_string())
    }

    fn with_bases(cache: Arc<HttpCache>, base: String, api_base: String) -> Self {
        Self {
            cache,
            base,
            api_base,
        }
    }

    /// Fetches all versions of `@{scope}/{name}` from `meta.json`.
    ///
    /// Returns versions sorted newest-first (per `Registry::get_versions`' contract) —
    /// `meta.json`'s `versions` is a JSON *object*, and `serde_json` does not preserve
    /// insertion order here (`preserve_order` is enabled only for `deps-composer`), so an
    /// explicit semver-descending sort is required (C2).
    ///
    /// `published_at` is populated directly from this same response's per-version
    /// `createdAt` field — no extra request, unlike npm (D10).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, the response is not valid UTF-8/JSON,
    /// or the package does not exist (mapped to `DepsError::PackageNotFound`). Also
    /// returns `DepsError::PackageNotFound` up front, before any request is made, if
    /// `scope` or `name` starts with `.` (S-L1) — such a segment would otherwise let
    /// `url::Url::parse` normalize the request path away from the intended
    /// `/@scope/name/meta.json` shape.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_deno::registry::JsrRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = JsrRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("std", "fs").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, scope: &str, name: &str) -> Result<Vec<JsrVersion>> {
        let full_name = format!("@{scope}/{name}");
        // S-L1: a dot-prefixed segment must be rejected before it ever reaches
        // `meta_json_url` — `url::Url::parse` decodes percent-encoding before dot-segment
        // normalization, so encoding alone cannot prevent `..`/`.` from collapsing the
        // path away from the intended `/@scope/name` shape. This is the single choke point
        // for every `JsrRegistry::get_versions` caller (`DenoRegistry::get_versions`,
        // `get_versions_with`, `get_latest_matching`).
        if is_dot_prefixed(scope) || is_dot_prefixed(name) {
            warn_rejected_value("is_dot_prefixed", "jsr meta.json request URL", &full_name);
            return Err(DepsError::PackageNotFound {
                package: full_name,
                registry: REGISTRY,
            });
        }
        let url = meta_json_url(&self.base, scope, name);
        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| not_found_or(e, &full_name))?;
        parse_meta_json(&data)
    }

    /// Searches JSR for packages matching `query`.
    ///
    /// If `query` is scope-qualified (`"@scope/pkg-prefix"`), the scope is split off
    /// *before* hitting the wire and only the package-name portion is sent as the search
    /// text (N1): JSR's search API ranks purely by text relevance and ignores the scope
    /// portion of a scoped query entirely — live-verified 2026-08-24, `query=@std/fs`
    /// buries the exact `std/fs` match 17th of 20 results, and a `scope=` query parameter
    /// is accepted but has no effect on ranking. Results are then reordered so an exact
    /// scope match sorts first (a stable sort, so JSR's own relevance ranking is preserved
    /// within each group), restoring the ordering a caller completing a scoped specifier —
    /// the common case for JSR — actually needs.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response is not valid JSON.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_deno::registry::JsrRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = JsrRegistry::new(cache);
    ///
    /// let results = registry.search("fs", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<JsrPackage>> {
        let Some((scope, pkg_prefix)) = split_scope_query(query) else {
            return self.fetch_search(query, limit).await;
        };

        // No package-name text typed yet (`"@std/"`): search on the scope itself instead
        // of an empty string.
        let text_query = if pkg_prefix.is_empty() {
            scope
        } else {
            pkg_prefix
        };
        // R1: `usize::clamp(min, max)` panics if `min > max`, which a plain
        // `.clamp(limit, MAX_SCOPE_SEARCH_OVERFETCH)` would do for any `limit` above the
        // cap. `.min(MAX_SCOPE_SEARCH_OVERFETCH.max(limit))` can never invert: the upper
        // bound passed to `min` is itself widened to `limit` whenever `limit` exceeds the
        // cap, so this degrades to "no overfetch, just use `limit`" instead of panicking.
        let fetch_limit = limit
            .saturating_mul(4)
            .min(MAX_SCOPE_SEARCH_OVERFETCH.max(limit));

        let mut results = self.fetch_search(text_query, fetch_limit).await?;
        results.sort_by_key(|p| !package_scope(p).eq_ignore_ascii_case(scope));
        results.truncate(limit);
        Ok(results)
    }

    /// Issues the raw `api.jsr.io/packages?query=` request with no scope-aware
    /// post-processing. Used directly for an unscoped query, and as the underlying fetch
    /// for [`Self::search`]'s scope-qualified path.
    async fn fetch_search(&self, query: &str, limit: usize) -> Result<Vec<JsrPackage>> {
        let url = format!(
            "{}/packages?query={}&limit={}",
            self.api_base,
            urlencoding::encode(query),
            limit
        );
        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Parses `meta.json`'s `versions` object into a newest-first `Vec<JsrVersion>` (C2).
fn parse_meta_json(data: &[u8]) -> Result<Vec<JsrVersion>> {
    let meta: MetaJson = serde_json::from_slice(data)?;

    let mut versions_with_parsed: Vec<(JsrVersion, node_semver::Version)> = meta
        .versions
        .into_iter()
        .filter_map(|(version, entry)| {
            let parsed = node_semver::Version::parse(&version).ok()?;
            let published_at = entry
                .created_at
                .as_deref()
                .and_then(deps_core::PublishTime::parse_rfc3339);
            Some((
                JsrVersion {
                    version,
                    yanked: entry.yanked,
                    published_at,
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Parses `api.jsr.io/packages`'s search response into `JsrPackage`s, each already
/// scheme-qualified as `"jsr:@scope/name"` (D3).
fn parse_search_response(data: &[u8]) -> Result<Vec<JsrPackage>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .items
        .into_iter()
        .map(|item| {
            let repository = item
                .github_repository
                .map(|repo| format!("https://github.com/{}/{}", repo.owner, repo.name));
            let description = item.description.filter(|d| !d.is_empty());
            JsrPackage {
                name: PackageName::new(format!("jsr:@{}/{}", item.scope, item.name)),
                description,
                repository,
                documentation: None,
                latest_version: item.latest_version.unwrap_or_default(),
            }
        })
        .collect())
}

/// The `deps_core::Registry` implementation for Deno manifests (D3).
///
/// A dispatching facade holding a [`JsrRegistry`] plus a [`deps_npm::NpmRegistry`],
/// routed by the scheme carried inside every incoming [`PackageName`].
pub struct DenoRegistry {
    jsr: JsrRegistry,
    npm: NpmRegistry,
}

impl DenoRegistry {
    /// Creates a new Deno registry facade, building both halves from the same
    /// `Arc<HttpCache>` (M1) and a private `NpmRegistry` instance.
    ///
    /// This dedupes plain cached GETs — the abbreviated packument `get_versions` fetches,
    /// and the JSR endpoints — between `package.json` and `deno.json` for the same npm
    /// package. It does **not** dedupe the *separate* full-packument fetch npm's own
    /// freshness path (`fetch_publish_times`) issues when `freshness.enabled`: that path
    /// deliberately bypasses `HttpCache`'s entry map (`deps-npm/src/registry.rs`) and is
    /// memoized in a per-`NpmRegistry`-instance `DashMap`, and this constructor builds its
    /// own private `NpmRegistry` rather than sharing `NpmEcosystem`'s — so with freshness
    /// on, that one extra request is still duplicated for a package appearing in both
    /// manifests. Use [`Self::with_npm`] instead to avoid this (N4/#312).
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_npm(Arc::clone(&cache), NpmRegistry::new(cache))
    }

    /// Creates a new Deno registry facade sharing an existing [`NpmRegistry`] instance for
    /// its `npm:`-scheme half, instead of building a private one (N4/#312).
    ///
    /// `NpmRegistry` is cheaply `Clone` (its `HttpCache` and freshness-path publish-time
    /// map are both `Arc`-wrapped internally), so passing a clone of the same instance
    /// registered for the standalone npm ecosystem shares not just plain cached GETs
    /// (already covered by `cache`) but also the freshness path's full-packument fetch and
    /// its publish-time cache, for a package appearing in both `package.json` and
    /// `deno.json` (an `npm:`-specifier dependency). This is what `deps-lsp`'s ecosystem
    /// registration does when both the `npm` and `deno` features are enabled.
    #[must_use]
    pub fn with_npm(cache: Arc<HttpCache>, npm: NpmRegistry) -> Self {
        Self {
            jsr: JsrRegistry::new(cache),
            npm,
        }
    }
}

impl Registry for DenoRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn Version>>>> {
        Box::pin(async move {
            match split_scheme(name.as_str()) {
                Some((Scheme::Jsr, rest)) => {
                    let (scope, pkg) = split_scoped(rest).ok_or_else(|| unroutable(name))?;
                    let versions = self.jsr.get_versions(scope, pkg).await?;
                    Ok(versions
                        .into_iter()
                        .map(|v| Box::new(v) as Box<dyn Version>)
                        .collect())
                }
                Some((Scheme::Npm, rest)) => {
                    if rest.is_empty() {
                        return Err(unroutable(name));
                    }
                    let bare = PackageName::new(rest);
                    // S3: `NpmRegistry` has an *inherent* `get_versions` that shadows the
                    // trait method and silently drops `get_versions_with`'s freshness
                    // semantics if called via plain method syntax — UFCS forces the trait
                    // method.
                    Registry::get_versions(&self.npm, &bare).await
                }
                None => Err(unroutable(name)),
            }
        })
    }

    fn get_versions_with<'a>(
        &'a self,
        name: &'a PackageName,
        freshness: FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn Version>>>> {
        Box::pin(async move {
            match split_scheme(name.as_str()) {
                Some((Scheme::Npm, rest)) => {
                    if rest.is_empty() {
                        return Err(unroutable(name));
                    }
                    let bare = PackageName::new(rest);
                    Registry::get_versions_with(&self.npm, &bare, freshness).await
                }
                // JSR's `meta.json` already carries `createdAt` in the same response
                // `get_versions` fetches (D10) — no separate freshness request needed.
                _ => self.get_versions(name).await,
            }
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a PackageName,
        req: &'a VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn Version>>>> {
        Box::pin(async move {
            match split_scheme(name.as_str()) {
                Some((Scheme::Jsr, rest)) => {
                    let (scope, pkg) = split_scoped(rest).ok_or_else(|| unroutable(name))?;
                    let versions = self.jsr.get_versions(scope, pkg).await?;
                    let parsed_req = node_semver::Range::parse(req.as_str())
                        .map_err(|e| DepsError::InvalidVersionReq(e.to_string()))?;
                    Ok(versions
                        .into_iter()
                        .find(|v| {
                            node_semver::Version::parse(&v.version)
                                .is_ok_and(|ver| parsed_req.satisfies(&ver) && !v.yanked)
                        })
                        .map(|v| Box::new(v) as Box<dyn Version>))
                }
                Some((Scheme::Npm, rest)) => {
                    if rest.is_empty() {
                        return Err(unroutable(name));
                    }
                    let bare = PackageName::new(rest);
                    Registry::get_latest_matching(&self.npm, &bare, req).await
                }
                None => Err(unroutable(name)),
            }
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn Metadata>>>> {
        Box::pin(async move {
            match split_scheme(query) {
                Some((Scheme::Jsr, rest)) => {
                    let packages = self.jsr.search(rest, limit).await?;
                    Ok(packages
                        .into_iter()
                        .map(|p| Box::new(p) as Box<dyn Metadata>)
                        .collect())
                }
                Some((Scheme::Npm, rest)) => {
                    let results = Registry::search(&self.npm, rest, limit).await?;
                    Ok(results
                        .into_iter()
                        .map(|m| {
                            let prefixed = PackageName::new(format!("npm:{}", m.name()));
                            Box::new(DenoMetadata::new(prefixed, m)) as Box<dyn Metadata>
                        })
                        .collect())
                }
                // No scheme prefix on the query: never guess which registry to search.
                None => Ok(vec![]),
            }
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn Version>],
        req: &VersionReq,
    ) -> Option<usize> {
        // Name-free and pure `node_semver`: correct for both JSR (which mandates semver)
        // and npm version strings, so npm's implementation covers both without a
        // downcast. This deliberately includes npm's #338 wildcard fallback: an
        // all-yanked JSR package (like an all-deprecated npm package) resolves to its
        // newest yanked version rather than `None`/"Unknown package" — not a bug to
        // "fix" by special-casing JSR here, since the alternative reintroduces #338
        // for JSR specifically.
        self.npm.select_latest_matching(versions, req)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use deps_core::test_util::capture_tracing_output_async;

    #[test]
    fn test_jsr_package_url() {
        assert_eq!(jsr_package_url("std", "fs"), "https://jsr.io/@std/fs");
    }

    // --- S-L2: URL-encoding regressions, mirroring deps-npm's package_url/versions_url tests ---

    #[test]
    fn test_jsr_package_url_encodes_malicious_scope() {
        let url = jsr_package_url("evil)[pkg](https://evil.example", "x");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_jsr_package_url_encodes_malicious_name_segment() {
        let url = jsr_package_url("std", "evil)[pkg](https://evil.example");
        assert!(!url.contains(')'));
        assert!(!url.contains('('));
    }

    #[test]
    fn test_jsr_package_url_encodes_newline_and_percent() {
        let url = jsr_package_url("evil\n<%", "pkg");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_meta_json_url_encodes_malicious_segments() {
        // S-L1 trap: the original version of this test asserted `!url.contains("/../")`
        // on the *raw* string, which passed even while the bug was live, because
        // `urlencoding::encode` never puts a literal `/../` into the raw string — the
        // collapse happens later, inside `url::Url::parse`'s dot-segment normalization
        // (which runs *after* percent-decoding). This test only exercises `meta_json_url`
        // (unchanged by the S-L1 fix, which gates `JsrRegistry::get_versions` instead), so
        // it does not itself prove the fix works — see
        // `test_jsr_registry_get_versions_rejects_dot_prefixed_package_segment` and its
        // siblings below for that. It still asserts on the parsed path, not the raw
        // string, so it stays a meaningful check of `meta_json_url`'s own encoding.
        let url = meta_json_url(JSR_BASE, "evil/../secret?x=1#frag", "pkg");
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/@evil%2F..%2Fsecret%3Fx%3D1%23frag/pkg/meta.json"
        );
    }

    /// #365 regression sweep: exercises the real production pair (`is_dot_prefixed` gate +
    /// `meta_json_url` sink) against the shared adversarial input set (varying scope, then
    /// name), guarding against a 6th recurrence of #337's defect class.
    #[test]
    fn test_meta_json_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| (!is_dot_prefixed(seg)).then(|| meta_json_url(JSR_BASE, seg, "pkg")),
            "jsr.io",
            "/@",
        );
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| (!is_dot_prefixed(seg)).then(|| meta_json_url(JSR_BASE, "scope", seg)),
            "jsr.io",
            "/@",
        );
    }

    #[test]
    fn test_parse_meta_json_sorts_newest_first() {
        // C2: the raw object order below is deliberately NOT sorted, mirroring the live
        // `meta.json` shape (verified 2026-08-24) where `1.0.19` precedes `0.200.0`.
        let json = r#"{
  "versions": {
    "1.0.19": {"createdAt": "2025-07-01T07:43:44Z"},
    "0.200.0": {"createdAt": "2024-04-24T06:44:45Z"},
    "1.0.24": {"createdAt": "2026-05-26T09:57:22Z"},
    "0.229.0": {"yanked": true, "createdAt": "2024-04-29T17:22:46Z"},
    "1.0.9": {"createdAt": "2025-01-10T08:22:54Z"}
  }
}"#;

        let versions = parse_meta_json(json.as_bytes()).unwrap();
        let strings: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(
            strings,
            vec!["1.0.24", "1.0.19", "1.0.9", "0.229.0", "0.200.0"]
        );
    }

    #[test]
    fn test_parse_meta_json_yanked_and_published_at() {
        let json = r#"{
  "versions": {
    "1.0.0": {"createdAt": "2024-01-01T00:00:00Z"},
    "0.9.0": {"yanked": true, "createdAt": "2023-01-01T00:00:00Z"}
  }
}"#;

        let versions = parse_meta_json(json.as_bytes()).unwrap();
        let v1 = versions.iter().find(|v| v.version == "1.0.0").unwrap();
        assert!(!v1.yanked);
        assert!(v1.published_at.is_some());

        let v09 = versions.iter().find(|v| v.version == "0.9.0").unwrap();
        assert!(v09.yanked);
    }

    #[test]
    fn test_parse_meta_json_skips_non_semver_keys() {
        let json = r#"{
  "versions": {
    "1.0.0": {"createdAt": "2024-01-01T00:00:00Z"},
    "not-a-version": {"createdAt": "2024-01-01T00:00:00Z"}
  }
}"#;

        let versions = parse_meta_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
    }

    #[test]
    fn test_parse_search_response_prefixes_name_with_scheme_and_maps_github_repo() {
        let json = r#"{
  "items": [
    {
      "scope": "std",
      "name": "fs",
      "description": "File system utilities",
      "latestVersion": "1.0.24",
      "githubRepository": {"owner": "denoland", "name": "std"}
    }
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "jsr:@std/fs");
        assert_eq!(
            packages[0].description,
            Some("File system utilities".to_string())
        );
        assert_eq!(
            packages[0].repository,
            Some("https://github.com/denoland/std".to_string())
        );
        assert_eq!(packages[0].latest_version, "1.0.24");
    }

    #[test]
    fn test_parse_search_response_empty_description_becomes_none() {
        let json = r#"{
  "items": [
    {"scope": "anabranch", "name": "fs", "description": "", "latestVersion": "0.3.1"}
  ]
}"#;

        let packages = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(packages[0].description, None);
        assert_eq!(packages[0].repository, None);
    }

    #[test]
    fn test_not_found_or_maps_404() {
        let err = DepsError::HttpStatus {
            url: "https://jsr.io/@std/fs/meta.json".into(),
            status: 404,
        };
        let result = not_found_or(err, "@std/fs");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "@std/fs" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        let err = DepsError::HttpStatus {
            url: "https://jsr.io/@std/fs/meta.json".into(),
            status: 500,
        };
        let result = not_found_or(err, "@std/fs");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
    }

    // --- M2/#312: "npm:" alone (partial_name_range's in-progress name, #310) must not
    // become a GET against the bare npm registry base URL ---

    /// An `NpmRegistry` pointed at an address nothing listens on, so any request it
    /// actually issues fails with a connection error rather than silently succeeding —
    /// proof that the empty-name guard short-circuits before any network call.
    fn unreachable_npm(cache: Arc<HttpCache>) -> NpmRegistry {
        NpmRegistry::with_registry_base(cache, "http://127.0.0.1:1".to_string())
    }

    #[tokio::test]
    async fn test_deno_registry_get_versions_rejects_empty_npm_name() {
        let cache = Arc::new(HttpCache::new());
        let npm = unreachable_npm(Arc::clone(&cache));
        let registry = DenoRegistry::with_npm(cache, npm);

        let Err(err) = Registry::get_versions(&registry, &PackageName::new("npm:")).await else {
            panic!("expected an error for an empty npm: name");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: "deno",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_deno_registry_get_versions_with_rejects_empty_npm_name() {
        let cache = Arc::new(HttpCache::new());
        let npm = unreachable_npm(Arc::clone(&cache));
        let registry = DenoRegistry::with_npm(cache, npm);

        let Err(err) = Registry::get_versions_with(
            &registry,
            &PackageName::new("npm:"),
            FreshnessSettings::default(),
        )
        .await
        else {
            panic!("expected an error for an empty npm: name");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: "deno",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_deno_registry_get_latest_matching_rejects_empty_npm_name() {
        let cache = Arc::new(HttpCache::new());
        let npm = unreachable_npm(Arc::clone(&cache));
        let registry = DenoRegistry::with_npm(cache, npm);

        let Err(err) = Registry::get_latest_matching(
            &registry,
            &PackageName::new("npm:"),
            &VersionReq::new("*"),
        )
        .await
        else {
            panic!("expected an error for an empty npm: name");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: "deno",
                ..
            }
        ));
    }

    /// #341: the `npm:` arm forwards the bare name straight to `NpmRegistry::get_versions`
    /// via `Registry::get_versions` (UFCS), so npm's own dot-segment guard is reached
    /// without any deno-side change — `unreachable_npm` proves this by construction: a
    /// dot-segment name must fail before any network call, not merely fail eventually.
    #[tokio::test]
    async fn test_deno_registry_get_versions_rejects_dot_segment_npm_package() {
        let cache = Arc::new(HttpCache::new());
        let npm = unreachable_npm(Arc::clone(&cache));
        let registry = DenoRegistry::with_npm(cache, npm);

        let Err(err) = Registry::get_versions(&registry, &PackageName::new("npm:@a/..")).await
        else {
            panic!("expected an error for a dot-segment npm: package name");
        };
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn test_deno_registry_get_versions_dispatches_jsr_via_mock() {
        let mut server = mockito::Server::new_async().await;
        let cache = Arc::new(HttpCache::new());
        let jsr = JsrRegistry::with_bases(Arc::clone(&cache), server.url(), server.url());
        let registry = DenoRegistry {
            jsr,
            npm: NpmRegistry::new(cache),
        };

        let mock = server
            .mock("GET", "/@std/fs/meta.json")
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {"createdAt": "2024-01-01T00:00:00Z"}}}"#)
            .create_async()
            .await;

        let versions = Registry::get_versions(&registry, &PackageName::new("jsr:@std/fs"))
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_string(), "1.0.0");
        mock.assert_async().await;
    }

    // --- S-L1: dot-prefixed JSR segment must be rejected before building the URL ---

    /// `JsrRegistry` pointed at an address nothing listens on, so any request it actually
    /// issues fails with a connection error rather than silently succeeding — proof that
    /// the dot-prefix guard short-circuits before any network call.
    fn unreachable_jsr(cache: Arc<HttpCache>) -> JsrRegistry {
        JsrRegistry::with_bases(
            cache,
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
        )
    }

    #[tokio::test]
    async fn test_jsr_registry_get_versions_rejects_dot_prefixed_package_segment() {
        // The exploitable case: a `..`/`.` *package* segment would otherwise let
        // `url::Url::parse` normalize the request path away from `/@scope/pkg/meta.json`
        // to an unrelated URL (e.g. `/meta.json`). Must fail closed with `PackageNotFound`
        // instead of reaching the network.
        let registry = unreachable_jsr(Arc::new(HttpCache::new()));

        let err = registry.get_versions("std", "..").await.unwrap_err();
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));

        let err = registry.get_versions("std", ".").await.unwrap_err();
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_jsr_registry_get_versions_rejects_dot_prefixed_scope_segment() {
        // Defense in depth: a dot-prefixed *scope* segment cannot actually collapse the
        // URL (the literal `@` prefix makes it e.g. `@..`, not a dot-segment), but it is
        // still rejected directly by the `is_dot_prefixed` gate on principle.
        let registry = unreachable_jsr(Arc::new(HttpCache::new()));

        let err = registry.get_versions("..", "pkg").await.unwrap_err();
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_jsr_registry_get_versions_rejection_logs_warn_rejected_value() {
        // N1: the two tests above only prove the `Err` return value, not that
        // `warn_rejected_value` actually fires from this fetch-sink gate.
        let registry = unreachable_jsr(Arc::new(HttpCache::new()));
        let output = capture_tracing_output_async(async {
            let _ = registry.get_versions("std", "..").await;
        })
        .await;
        assert!(output.contains("is_dot_prefixed"), "output was: {output}");
        assert!(
            output.contains("jsr meta.json request URL"),
            "output was: {output}"
        );
    }

    #[tokio::test]
    async fn test_deno_registry_get_versions_rejects_dot_prefixed_jsr_package_via_mock() {
        // End-to-end through the `Registry` trait dispatch: `jsr:@scope/..` must return
        // `PackageNotFound` without ever issuing the `meta.json` request.
        let mut server = mockito::Server::new_async().await;
        let cache = Arc::new(HttpCache::new());
        let jsr = JsrRegistry::with_bases(Arc::clone(&cache), server.url(), server.url());
        let registry = DenoRegistry {
            jsr,
            npm: NpmRegistry::new(cache),
        };

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let Err(err) = Registry::get_versions(&registry, &PackageName::new("jsr:@std/..")).await
        else {
            panic!("expected an error for a dot-prefixed jsr: package segment");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));

        let Err(err) = Registry::get_versions_with(
            &registry,
            &PackageName::new("jsr:@std/.."),
            FreshnessSettings::default(),
        )
        .await
        else {
            panic!("expected an error for a dot-prefixed jsr: package segment");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));

        let Err(err) = Registry::get_latest_matching(
            &registry,
            &PackageName::new("jsr:@std/.."),
            &VersionReq::new("*"),
        )
        .await
        else {
            panic!("expected an error for a dot-prefixed jsr: package segment");
        };
        assert!(matches!(
            err,
            DepsError::PackageNotFound {
                registry: REGISTRY,
                ..
            }
        ));

        mock.assert_async().await;
    }

    // --- N1: scope-aware JSR search ---

    #[test]
    fn test_split_scope_query() {
        assert_eq!(split_scope_query("@std/fs"), Some(("std", "fs")));
        assert_eq!(split_scope_query("@std/f"), Some(("std", "f")));
        assert_eq!(split_scope_query("@std/"), Some(("std", "")));
        assert_eq!(split_scope_query("@std"), None);
        assert_eq!(split_scope_query("fs"), None);
    }

    #[test]
    fn test_package_scope_extracts_from_prefixed_name() {
        let pkg = JsrPackage {
            name: PackageName::new("jsr:@std/fs"),
            description: None,
            repository: None,
            documentation: None,
            latest_version: String::new(),
        };
        assert_eq!(package_scope(&pkg), "std");
    }

    #[tokio::test]
    async fn test_jsr_registry_search_scoped_query_sends_only_package_name_segment() {
        // N1: JSR's search API ranks purely by text relevance and ignores the scope
        // portion of a scoped query, so the scope must never reach `query=` on the wire.
        let mut server = mockito::Server::new_async().await;
        let registry =
            JsrRegistry::with_bases(Arc::new(HttpCache::new()), server.url(), server.url());

        let mock = server
            .mock("GET", "/packages")
            .match_query(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded(
                "query".into(),
                "fs".into(),
            )]))
            .with_status(200)
            .with_body(r#"{"items": [{"scope": "std", "name": "fs", "latestVersion": "1.0.24"}]}"#)
            .create_async()
            .await;

        let results = registry.search("@std/fs", 5).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "jsr:@std/fs");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jsr_registry_search_scoped_query_reorders_exact_scope_match_first() {
        // N1: the common case (`jsr:@std/fs`) must surface the exact-scope match first,
        // not buried behind unrelated packages that merely share the text query.
        let mut server = mockito::Server::new_async().await;
        let registry =
            JsrRegistry::with_bases(Arc::new(HttpCache::new()), server.url(), server.url());

        let body = r#"{"items": [
            {"scope": "other", "name": "fs", "latestVersion": "1.0.0"},
            {"scope": "another", "name": "fs-utils", "latestVersion": "3.0.0"},
            {"scope": "std", "name": "fs", "latestVersion": "2.0.0"}
        ]}"#;
        let mock = server
            .mock("GET", "/packages")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let results = registry.search("@std/fs", 2).await.unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "jsr:@std/fs");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jsr_registry_search_unscoped_query_unaffected() {
        let mut server = mockito::Server::new_async().await;
        let registry =
            JsrRegistry::with_bases(Arc::new(HttpCache::new()), server.url(), server.url());

        let mock = server
            .mock("GET", "/packages")
            .match_query(mockito::Matcher::UrlEncoded("query".into(), "fs".into()))
            .with_status(200)
            .with_body(r#"{"items": [{"scope": "std", "name": "fs", "latestVersion": "1.0.24"}]}"#)
            .create_async()
            .await;

        let results = registry.search("fs", 5).await.unwrap();

        assert_eq!(results.len(), 1);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jsr_registry_search_scoped_query_limit_above_overfetch_cap_does_not_panic() {
        // R1: `limit > MAX_SCOPE_SEARCH_OVERFETCH` used to invert a `usize::clamp`'s
        // min/max and panic. Must degrade to using `limit` directly instead.
        let mut server = mockito::Server::new_async().await;
        let registry =
            JsrRegistry::with_bases(Arc::new(HttpCache::new()), server.url(), server.url());

        let mock = server
            .mock("GET", "/packages")
            .match_query(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded(
                "limit".into(),
                "50".into(),
            )]))
            .with_status(200)
            .with_body(r#"{"items": [{"scope": "std", "name": "fs", "latestVersion": "1.0.24"}]}"#)
            .create_async()
            .await;

        let results = registry.search("@std/fs", 50).await.unwrap();

        assert_eq!(results.len(), 1);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_deno_registry_with_npm_shares_freshness_cache_across_instances() {
        // #312: DenoRegistry::with_npm must hold the caller-supplied NpmRegistry rather
        // than building its own, so a package appearing in both package.json (the
        // standalone npm ecosystem) and deno.json (an `npm:`-specifier dependency) shares
        // one freshness-path publish-time cache instead of refetching the full packument
        // per ecosystem instance.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let http_cache = Arc::new(HttpCache::new());
        let shared_npm = NpmRegistry::with_registry_base(Arc::clone(&http_cache), base);

        let abbrev_mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/vnd.npm.install-v1+json")
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}}}"#)
            .expect(2)
            .create_async()
            .await;
        let full_mock = server
            .mock("GET", "/widget")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(r#"{"time": {"1.0.0": "2020-01-01T00:00:00Z"}}"#)
            .expect(1)
            .create_async()
            .await;

        // Simulates package.json's standalone npm ecosystem instance.
        let npm_side = shared_npm.clone();
        let from_npm = Registry::get_versions_with(
            &npm_side,
            &PackageName::new("widget"),
            FreshnessSettings::default(),
        )
        .await
        .unwrap();
        assert!(from_npm[0].published_at().is_some());

        // Simulates deno.json's `npm:widget` dependency, sharing the SAME NpmRegistry
        // instance via `with_npm` — the full-packument fetch above must not repeat.
        let deno_registry = DenoRegistry::with_npm(Arc::clone(&http_cache), shared_npm);
        let from_deno = Registry::get_versions_with(
            &deno_registry,
            &PackageName::new("npm:widget"),
            FreshnessSettings::default(),
        )
        .await
        .unwrap();
        assert!(from_deno[0].published_at().is_some());

        abbrev_mock.assert_async().await;
        full_mock.assert_async().await;
    }

    #[tokio::test]
    #[ignore] // requires network access
    async fn test_deno_registry_get_versions_dispatches_npm_live() {
        // Exercises the npm arm's dispatch through `DenoRegistry::new`'s private
        // `NpmRegistry` end-to-end against the real registry; mockable dispatch via a
        // shared instance is covered by
        // `test_deno_registry_with_npm_shares_freshness_cache_across_instances` above.
        let cache = Arc::new(HttpCache::new());
        let registry = DenoRegistry::new(cache);
        let versions = Registry::get_versions(&registry, &PackageName::new("npm:react"))
            .await
            .unwrap();
        assert!(!versions.is_empty());
    }

    // --- Live registry verification (real network, run explicitly with `--ignored`) ---
    // Per `.claude/rules/continuous-improvement.md`'s Registry Integration Gate: confirms
    // this crate's parsing matches the actual live JSR response shape, not just the JSON
    // samples quoted in the architecture plan.

    #[tokio::test]
    #[ignore]
    async fn test_live_jsr_get_versions_std_fs() {
        let registry = JsrRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry.get_versions("std", "fs").await.unwrap();

        assert!(!versions.is_empty());
        // 1.0.24 is JSR's `@std/fs` latest as of 2026-08-24; live registry only ever adds
        // new versions above it, so a look-up here is a floor, not a fixed hit.
        assert!(versions.iter().any(|v| v.version == "1.0.24"));
        // At least one known-yanked version (0.229.0) must round-trip its yanked flag.
        assert!(versions.iter().any(|v| v.version == "0.229.0" && v.yanked));
        // Sorted newest-first (C2).
        let parsed: Vec<node_semver::Version> = versions
            .iter()
            .map(|v| node_semver::Version::parse(&v.version).unwrap())
            .collect();
        assert!(parsed.windows(2).all(|w| w[0] >= w[1]));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_jsr_search_fs() {
        let registry = JsrRegistry::new(Arc::new(HttpCache::new()));
        let results = registry.search("fs", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().all(|p| p.name.as_str().starts_with("jsr:@")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_jsr_search_scoped_query_ranks_exact_scope_first() {
        // N1: live-verified 2026-08-24 that an unfixed scoped query buries `@std/fs`
        // ~17th of 20 results; this must now come back first.
        let registry = JsrRegistry::new(Arc::new(HttpCache::new()));
        let results = registry.search("@std/fs", 5).await.unwrap();

        assert!(!results.is_empty());
        assert_eq!(results[0].name, "jsr:@std/fs");
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_jsr_get_versions_missing_package_is_not_found() {
        let registry = JsrRegistry::new(Arc::new(HttpCache::new()));
        let err = registry
            .get_versions("this-scope-does-not-exist-12345", "nope")
            .await
            .unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }
}
