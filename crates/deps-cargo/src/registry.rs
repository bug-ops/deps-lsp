//! crates.io registry client.
//!
//! Provides access to crates.io via:
//! - Sparse index protocol (<https://index.crates.io>) for version lookups
//! - REST API (<https://crates.io/api/v1>) for search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::CratesIoRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let registry = CratesIoRegistry::new(cache);
//!
//!     let versions = registry.get_versions("serde").await.unwrap();
//!     println!("Latest serde: {}", versions[0].num);
//! }
//! ```

use crate::types::{CargoVersion, CrateInfo};
use deps_core::{DepsError, HttpCache, Result, lsp_helpers::warn_rejected_value};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

const SPARSE_INDEX_BASE: &str = "https://index.crates.io";
const SEARCH_API_BASE: &str = "https://crates.io/api/v1";

/// Display name for crates.io used in not-found and API-response error messages.
pub const REGISTRY: &str = "crates.io";

/// Base URL for crate pages on crates.io
pub const CRATES_IO_URL: &str = "https://crates.io/crates";

/// Returns the URL for a crate's page on crates.io.
///
/// Display link only, never fetched by this process — unlike the sparse-index
/// registry-fetch URL (`sparse_index_path`), so it is deliberately not gated against a
/// `.`/`..` name (see [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link
/// scope split, #379).
pub fn crate_url(name: &str) -> String {
    format!("{CRATES_IO_URL}/{}", urlencoding::encode(name))
}

/// Whether `name` matches crates.io's actual crate-name charset (ASCII alphanumeric, `-`,
/// `_`) — stricter than [`deps_core::is_safe_package_name`], which permits `/`, `@`, `.`,
/// `:`, `~` to accommodate other ecosystems' scoped/namespaced names. `sparse_index_path`
/// performs no per-character encoding at all before splicing `name` into the request URL
/// (unlike every other ecosystem crate, which `urlencoding::encode`s each segment): a
/// `name` containing `/` or `.` is used as-is to build directory components, so a crafted
/// name like `../../etc/passwd` can inject arbitrary path segments, not just the narrower
/// exact-`.`/`..` case #341/#349/#357/#361 covered (#365 S1).
fn is_safe_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Rejects a `name` outside crates.io's crate-name charset before it would reach
/// [`sparse_index_path`], as `DepsError::PackageNotFound`.
fn reject_unsafe_crate_name(name: &str) -> Result<()> {
    if !is_safe_crate_name(name) {
        warn_rejected_value(
            "is_safe_crate_name",
            "crates.io sparse index request URL",
            name,
        );
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    Ok(())
}

/// Client for interacting with crates.io registry.
///
/// Uses the sparse index protocol for fast version lookups and the REST API
/// for package search. All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct CratesIoRegistry {
    cache: Arc<HttpCache>,
}

impl CratesIoRegistry {
    /// Creates a new registry client with the given HTTP cache.
    pub const fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a crate from the sparse index.
    ///
    /// Returns versions sorted newest-first. Includes yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("serde").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<CargoVersion>> {
        reject_unsafe_crate_name(name)?;
        let url = sparse_index_url(name);
        let data = self.cache.get_cached(&url).await?;

        parse_index_json(&data, name)
    }

    /// Finds the latest version matching the given semver requirement.
    ///
    /// Only returns non-yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Version requirement string is invalid semver
    /// - HTTP request fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("serde", "^1.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<CargoVersion>> {
        let versions = self.get_versions(name).await?;

        let req = req_str
            .parse::<VersionReq>()
            .map_err(|e| DepsError::InvalidVersionReq(e.to_string()))?;

        Ok(versions.into_iter().find(|v| {
            let version = v.num.parse::<Version>().ok();
            version.is_some_and(|ver| req.matches(&ver) && !v.yanked)
        }))
    }

    /// Searches for crates by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let results = registry.search("serde", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<CrateInfo>> {
        let url = format!(
            "{}/crates?q={}&per_page={}&sort=downloads",
            SEARCH_API_BASE,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Converts a crate name to its sparse index path.
///
/// Based on Cargo RFC 2789 specification:
/// - 1 char: "1/{name}"
/// - 2 chars: "2/{name}"
/// - 3 chars: "3/{first_char}/{name}"
/// - 4+ chars: "{first_2}/{next_2}/{name}"
///
/// Path segments are computed from the crate name's **character** count and
/// positions, not byte length/offsets — crate names may contain multi-byte
/// UTF-8 characters, and byte-index slicing could land mid-character and panic.
/// An empty name has no length-based segment and returns the empty string.
///
/// Callers must additionally run [`reject_unsafe_crate_name`] first: this function performs
/// no charset/encoding validation of `name` at all, so an unchecked `name` (any character,
/// including `.`/`..` or an embedded `/`) reaches this unfiltered and can inject arbitrary
/// path segments once spliced into the request URL (#365 S1) — the char-safe indexing above
/// only prevents a panic (#376), it does not validate `name`.
fn sparse_index_path(name: &str) -> String {
    let name_lower = name.to_lowercase();
    let chars: Vec<char> = name_lower.chars().collect();

    match chars.len() {
        0 => name_lower,
        1 => {
            let mut path = String::with_capacity(2 + name_lower.len());
            path.push_str("1/");
            path.push_str(&name_lower);
            path
        }
        2 => {
            let mut path = String::with_capacity(2 + name_lower.len());
            path.push_str("2/");
            path.push_str(&name_lower);
            path
        }
        3 => {
            let mut path = String::with_capacity(4 + name_lower.len());
            path.push_str("3/");
            path.push(chars[0]);
            path.push('/');
            path.push_str(&name_lower);
            path
        }
        _ => {
            let mut path = String::with_capacity(6 + name_lower.len());
            path.extend(chars[0..2].iter());
            path.push('/');
            path.extend(chars[2..4].iter());
            path.push('/');
            path.push_str(&name_lower);
            path
        }
    }
}

/// Builds the sparse index request URL for a crate's version metadata. Callers must run
/// [`reject_unsafe_crate_name`] first — `sparse_index_path` performs no encoding or
/// rejection of `name` at all, so an unchecked `name` (any character, including `.`/`..`
/// or an embedded `/`) reaches this unfiltered.
fn sparse_index_url(name: &str) -> String {
    let path = sparse_index_path(name);
    // Pre-allocate: SPARSE_INDEX_BASE (25 chars) + "/" + path
    let mut url = String::with_capacity(SPARSE_INDEX_BASE.len() + 1 + path.len());
    url.push_str(SPARSE_INDEX_BASE);
    url.push('/');
    url.push_str(&path);
    url
}

/// Entry in the sparse index (one line of newline-delimited JSON).
#[derive(Deserialize)]
struct IndexEntry {
    #[serde(rename = "vers")]
    version: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    features: HashMap<String, Vec<String>>,
    /// Publish timestamp (RFC 3339, e.g. `"2026-07-18T23:05:13Z"`).
    ///
    /// Absent on index entries older than the sparse index's rollout of this
    /// field; `#[serde(default)]` keeps such lines parseable.
    #[serde(default)]
    pubtime: Option<String>,
}

/// Parses newline-delimited JSON from sparse index.
fn parse_index_json(data: &[u8], _crate_name: &str) -> Result<Vec<CargoVersion>> {
    let content = std::str::from_utf8(data)
        .map_err(|e| DepsError::CacheError(format!("Invalid UTF-8: {e}")))?;

    // Parse versions once and cache the parsed Version for sorting
    let mut versions_with_parsed: Vec<(CargoVersion, Version)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let entry: IndexEntry = serde_json::from_str(line).ok()?;
            let parsed = entry.version.parse::<Version>().ok()?;
            let published_at = entry
                .pubtime
                .as_deref()
                .and_then(deps_core::PublishTime::parse_rfc3339);
            Some((
                CargoVersion {
                    num: entry.version,
                    yanked: entry.yanked,
                    features: entry.features,
                    published_at,
                },
                parsed,
            ))
        })
        .collect();

    // Sort using already-parsed versions (newest first)
    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    // Extract sorted versions
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Response from crates.io search API.
#[derive(Deserialize)]
struct SearchResponse {
    crates: Vec<SearchCrate>,
}

/// Crate entry in search response.
#[derive(Deserialize)]
struct SearchCrate {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
    max_version: String,
}

/// Parses JSON response from crates.io search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<CrateInfo>> {
    let response: SearchResponse = serde_json::from_slice(data)?;

    Ok(response
        .crates
        .into_iter()
        .map(|c| CrateInfo {
            name: c.name.into(),
            description: c.description,
            repository: c.repository,
            documentation: c.documentation,
            max_version: c.max_version,
        })
        .collect())
}

impl deps_core::Registry for CratesIoRegistry {
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

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        let parsed_req: VersionReq = req.as_str().parse().ok()?;
        versions.iter().position(|v| {
            v.version_string().parse::<Version>().is_ok_and(|ver| {
                parsed_req.matches(&ver) && !v.removal_status().blocks_resolution()
            })
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let results = self.search(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_index_path() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn test_sparse_index_path_uppercase() {
        assert_eq!(sparse_index_path("SERDE"), "se/rd/serde");
    }

    #[test]
    fn test_reject_unsafe_crate_name_rejects_bare_dot_dot() {
        assert!(reject_unsafe_crate_name("..").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_rejects_bare_dot() {
        assert!(reject_unsafe_crate_name(".").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_rejects_embedded_slash() {
        // S1 (impl-critic): `sparse_index_path` performs no per-character encoding, so a
        // `/` anywhere in `name` (not just a bare `.`/`..`) can inject path segments once
        // spliced into the request URL.
        assert!(reject_unsafe_crate_name("../../etc/passwd").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_accepts_normal_names() {
        assert!(reject_unsafe_crate_name("serde").is_ok());
        assert!(reject_unsafe_crate_name("serde_derive").is_ok());
        assert!(reject_unsafe_crate_name("actix-web").is_ok());
    }

    /// #376: `sparse_index_path`'s byte-index slicing (`name_lower[0..2]` etc.) panics on a
    /// non-ASCII crate name, since those indices can land mid-codepoint. `is_safe_crate_name`'s
    /// ASCII-alphanumeric-only allowlist blocks any non-ASCII input before it reaches that
    /// code, closing the panic as a side effect of the charset check — asserted directly here
    /// so a future narrowing of the allowlist's *intent* (without touching this exact
    /// assertion) can't silently reopen the panic with nothing to catch it.
    #[test]
    fn test_reject_unsafe_crate_name_rejects_non_ascii() {
        assert!(reject_unsafe_crate_name("日本").is_err());
    }

    /// Demonstrates the vulnerability `reject_unsafe_crate_name` exists to prevent:
    /// `sparse_index_url` alone (with no caller-side guard) builds a URL that, once parsed,
    /// has escaped the sparse index root entirely.
    #[test]
    fn test_sparse_index_url_bare_dot_dot_normalizes_above_root() {
        let url = sparse_index_url("..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/", "parsed path: {}", parsed.path());
    }

    /// Demonstrates the broader S1 vulnerability: an embedded `/` (not just a bare
    /// `.`/`..`) lets `sparse_index_url` alone build a URL whose path escapes to an
    /// attacker-influenced location, since no character in `name` is encoded.
    #[test]
    fn test_sparse_index_url_embedded_slash_escapes_root() {
        let url = sparse_index_url("../../etc/passwd");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/etc/passwd",
            "parsed path: {}",
            parsed.path()
        );
    }

    /// #365 regression sweep: exercises the real production `reject_unsafe_crate_name`
    /// gate and `sparse_index_url` sink together against the shared adversarial input set.
    /// Every entry is rejected by the charset-only gate before reaching the sink (none of
    /// `ADVERSARIAL_URL_SEGMENTS` is pure ASCII-alphanumeric/`-`/`_`), so this is a vacuous
    /// but still forward-looking regression guard: it would start exercising the
    /// host/prefix/survival assertions the moment the gate's charset is ever loosened.
    #[test]
    fn test_sparse_index_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                reject_unsafe_crate_name(seg)
                    .ok()
                    .map(|()| sparse_index_url(seg))
            },
            "index.crates.io",
            "/",
        );
    }

    #[test]
    fn test_parse_index_json() {
        let json = r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}
{"name":"serde","vers":"1.0.1","yanked":false,"features":{"derive":["serde_derive"]},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "serde").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "1.0.1");
        assert_eq!(versions[1].num, "1.0.0");
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_index_json_with_yanked() {
        let json = r#"{"name":"test","vers":"0.1.0","yanked":true,"features":{},"deps":[]}
{"name":"test","vers":"0.2.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions[1].yanked);
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "crates": [
                {
                    "name": "serde",
                    "description": "A serialization framework",
                    "repository": "https://github.com/serde-rs/serde",
                    "documentation": "https://docs.rs/serde",
                    "max_version": "1.0.214"
                }
            ]
        }"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "serde");
        assert_eq!(results[0].max_version, "1.0.214");
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_serde_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions = registry.get_versions("serde").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.num.starts_with("1.")));
    }

    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let results = registry.search("serde", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "serde"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_latest_matching_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let latest = registry.get_latest_matching("serde", "^1.0").await.unwrap();

        assert!(latest.is_some());
        let version = latest.unwrap();
        assert!(version.num.starts_with("1."));
        assert!(!version.yanked);
    }

    #[test]
    fn test_parse_index_json_empty() {
        let json = "";
        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_blank_lines() {
        let json = "\n\n\n";
        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_invalid_version() {
        let json = r#"{"name":"test","vers":"invalid","yanked":false,"features":{},"deps":[]}"#;
        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_mixed_valid_invalid() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[]}
{"name":"test","vers":"invalid","yanked":false,"features":{},"deps":[]}
{"name":"test","vers":"2.0.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "2.0.0");
        assert_eq!(versions[1].num, "1.0.0");
    }

    #[test]
    fn test_parse_index_json_with_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[],"pubtime":"2026-07-18T23:05:13Z"}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            Some(deps_core::PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").unwrap())
        );
    }

    #[test]
    fn test_parse_index_json_without_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_parse_index_json_with_malformed_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[],"pubtime":"not-a-timestamp"}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed pubtime degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_index_json_with_features() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{"default":["std"],"std":[]},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes(), "test").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].features.len(), 2);
        assert!(versions[0].features.contains_key("default"));
        assert!(versions[0].features.contains_key("std"));
    }

    #[test]
    fn test_parse_search_response_empty() {
        let json = r#"{"crates": []}"#;
        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_parse_search_response_missing_optional_fields() {
        let json = r#"{
            "crates": [
                {
                    "name": "minimal",
                    "max_version": "1.0.0"
                }
            ]
        }"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "minimal");
        assert_eq!(results[0].description, None);
        assert_eq!(results[0].repository, None);
    }

    #[test]
    fn test_sparse_index_path_single_char() {
        assert_eq!(sparse_index_path("x"), "1/x");
        assert_eq!(sparse_index_path("z"), "1/z");
    }

    #[test]
    fn test_sparse_index_path_two_chars() {
        assert_eq!(sparse_index_path("xy"), "2/xy");
        assert_eq!(sparse_index_path("ab"), "2/ab");
    }

    #[test]
    fn test_sparse_index_path_three_chars() {
        assert_eq!(sparse_index_path("xyz"), "3/x/xyz");
        assert_eq!(sparse_index_path("foo"), "3/f/foo");
    }

    #[test]
    fn test_sparse_index_path_long_name() {
        assert_eq!(
            sparse_index_path("very-long-crate-name"),
            "ve/ry/very-long-crate-name"
        );
    }

    #[test]
    fn test_sparse_index_path_numbers() {
        assert_eq!(sparse_index_path("1234"), "12/34/1234");
    }

    #[test]
    fn test_sparse_index_path_mixed_case() {
        assert_eq!(sparse_index_path("MyPackage"), "my/pa/mypackage");
        assert_eq!(sparse_index_path("UPPERCASE"), "up/pe/uppercase");
    }

    #[test]
    fn test_sparse_index_path_multibyte_one_char() {
        // "本" is 1 char / 3 bytes: byte-index slicing would panic here.
        assert_eq!(sparse_index_path("本"), "1/本");
    }

    #[test]
    fn test_sparse_index_path_multibyte_two_chars() {
        // "日本" is 2 chars / 6 bytes.
        assert_eq!(sparse_index_path("日本"), "2/日本");
    }

    #[test]
    fn test_sparse_index_path_multibyte_three_chars() {
        // "日本語" is 3 chars / 9 bytes. The old byte-length-keyed match would
        // have routed this to the 4+ arm's `name_lower[0..2]`, panicking at
        // byte index 2 (mid-character), not the 3-char arm.
        assert_eq!(sparse_index_path("日本語"), "3/日/日本語");
    }

    #[test]
    fn test_sparse_index_path_multibyte_four_plus_chars() {
        // "日本ab" is 4 chars with multi-byte characters in the first two.
        assert_eq!(sparse_index_path("日本ab"), "日本/ab/日本ab");
    }

    #[test]
    fn test_sparse_index_path_empty_name() {
        // 0 chars falls into the "4+" arm's slicing range; must not panic.
        assert_eq!(sparse_index_path(""), "");
    }

    #[test]
    fn test_crate_url() {
        assert_eq!(crate_url("serde"), "https://crates.io/crates/serde");
        assert_eq!(crate_url("tokio"), "https://crates.io/crates/tokio");
    }

    #[test]
    fn test_crate_url_with_hyphens() {
        assert_eq!(
            crate_url("serde-json"),
            "https://crates.io/crates/serde-json"
        );
    }

    #[test]
    fn test_crate_url_encodes_malicious_name() {
        let url = crate_url("evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_crate_url_encodes_newline_autolink_and_percent() {
        let url = crate_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_crate_url_empty_name() {
        assert_eq!(crate_url(""), "https://crates.io/crates/");
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = CratesIoRegistry::new(cache);
    }

    /// #365 end-to-end coverage (critic S2): exercises the real production
    /// `get_versions` — not a reimplemented gate+sink pair — proving the gate is actually
    /// wired into the call path a real completion/hover/diagnostic request would take. No
    /// mock is needed: the gate must reject before any network request is issued.
    ///
    /// Asserts the exact `PackageNotFound` variant (gate rejected before any request), not
    /// the broader `is_not_found()` (also true for a live 404 `HttpStatus`) — critic R1: a
    /// deleted gate here would still hit `index.crates.io` and get back a real (non-404)
    /// response that fails to parse as sparse-index JSON, so `is_not_found()` alone would
    /// not reliably catch the regression.
    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_as_not_found() {
        let registry = CratesIoRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("..").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_rejects_embedded_slash_as_not_found() {
        let registry = CratesIoRegistry::new(Arc::new(HttpCache::new()));
        let err = registry.get_versions("../../etc/passwd").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_registry_clone() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let _cloned = registry;
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0".into(),
                yanked: true,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0".into(),
                yanked: false,
                features: HashMap::new(),
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    #[test]
    fn test_select_latest_matching_all_yanked_returns_newest_yanked() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0".into(),
                yanked: true,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0".into(),
                yanked: true,
                features: HashMap::new(),
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_select_latest_matching_all_prerelease_returns_newest_prerelease() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0-beta.1".into(),
                yanked: false,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0-alpha.1".into(),
                yanked: false,
                features: HashMap::new(),
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }
}
