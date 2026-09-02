//! Generic sparse-index registry client.
//!
//! Implements Cargo's sparse index wire protocol (RFC 2789), shared by crates.io itself
//! and any alternate/private registry declared through `.cargo/config.toml`. Extracted
//! from `registry.rs` so [`crate::registry::CratesIoRegistry`] and the alternate-registry
//! router (`CargoRegistry`) both delegate to one implementation instead of duplicating the
//! index-path computation, JSON-lines parsing, and crate-name safety gate.
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::config::{IndexTrust, RegistryIndex};
//! use deps_cargo::sparse::SparseIndexClient;
//! use deps_core::HttpCache;
//! use deps_core::net_policy::RegistryAccessPolicy;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let policy = RegistryAccessPolicy::default();
//!     let index = RegistryIndex::new("https://index.crates.io", IndexTrust::Trusted, &policy).unwrap();
//!     let client = SparseIndexClient::new(index, cache);
//!
//!     let versions = client.get_versions("serde").await.unwrap();
//!     println!("Latest serde: {}", versions[0].num);
//! }
//! ```

use crate::config::{AuthToken, IndexTrust, RegistryIndex};
use crate::types::CargoVersion;
use deps_core::{DepsError, HttpCache, Result, lsp_helpers::warn_rejected_value};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Whether `name`'s character set matches crates.io's crate-name charset (ASCII
/// alphanumeric, `-`, `_`), non-empty — stricter than
/// [`deps_core::is_safe_package_name`], which permits `/`, `@`, `.`, `:`, `~` to
/// accommodate other ecosystems' scoped/namespaced names. Deliberately carries no
/// length bound of its own: [`is_safe_crate_name`] layers this crate's 128-byte
/// URL-safety cap on top, while `deps_cargo::formatter::CargoFormatter`'s
/// `validate_package_name` layers its own, stricter, diagnostic-accuracy length
/// check on top instead — bundling a length bound into this predicate would make
/// the latter unable to distinguish "bad charset" from "too long" for a name that
/// is both charset-valid and longer than crates.io's real limit (#382 follow-up).
pub(crate) fn is_safe_crate_name_charset(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Whether `name` is safe to splice into a sparse-index request URL:
/// [`is_safe_crate_name_charset`] plus a 128-byte length bound. [`sparse_index_path`]
/// performs no per-character encoding at all before splicing `name` into the request
/// URL (unlike every other ecosystem crate, which `urlencoding::encode`s each
/// segment): a `name` containing `/` or `.` is used as-is to build directory
/// components, so a crafted name like `../../etc/passwd` can inject arbitrary path
/// segments, not just the narrower exact-`.`/`..` case #341/#349/#357/#361 covered
/// (#365 S1). The 128-byte bound exists only to keep a pathological request URL
/// bounded — it is not crates.io's real publish-time length limit, so callers that
/// need an accurate "too long" diagnostic (see `is_safe_crate_name_charset`'s docs)
/// must not reuse this function for that purpose.
pub(crate) fn is_safe_crate_name(name: &str) -> bool {
    is_safe_crate_name_charset(name) && name.len() <= 128
}

/// Rejects a `name` outside crates.io's crate-name charset before it would reach
/// [`sparse_index_path`], as `DepsError::PackageNotFound`.
fn reject_unsafe_crate_name(name: &str, registry_display_name: &'static str) -> Result<()> {
    if !is_safe_crate_name(name) {
        warn_rejected_value("is_safe_crate_name", "sparse index request URL", name);
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: registry_display_name,
        });
    }
    Ok(())
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

/// Builds the sparse index request URL for a crate's version metadata, against
/// `base_url` (no trailing slash assumed either way). Callers must run
/// [`reject_unsafe_crate_name`] first — [`sparse_index_path`] performs no encoding or
/// rejection of `name` at all, so an unchecked `name` (any character, including `.`/`..`
/// or an embedded `/`) reaches this unfiltered.
fn sparse_index_url(base_url: &str, name: &str) -> String {
    let path = sparse_index_path(name);
    let base = base_url.trim_end_matches('/');
    let mut url = String::with_capacity(base.len() + 1 + path.len());
    url.push_str(base);
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

/// Parses newline-delimited JSON from a sparse index.
fn parse_index_json(data: &[u8]) -> Result<Vec<CargoVersion>> {
    let content = std::str::from_utf8(data)
        .map_err(|e| DepsError::CacheError(format!("Invalid UTF-8: {e}")))?;

    // Parse versions once and cache the parsed Version for sorting
    let mut versions_with_parsed: Vec<(CargoVersion, Version)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let entry: IndexEntry = deps_core::parse_json_checked(line.as_bytes()).ok()?;
            let parsed = entry.version.parse::<Version>().ok()?;
            let published_at = entry
                .pubtime
                .as_deref()
                .and_then(deps_core::PublishTime::parse_rfc3339);
            Some((
                CargoVersion {
                    num: entry.version.into(),
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

/// Client for one sparse-index registry — crates.io's own index or an alternate/private
/// one resolved from `.cargo/config.toml`.
///
/// Owns `base_url`/`sparse_index_path`/`parse_index_json` (moved from the pre-existing
/// crates.io-only client, not reimplemented), so every registry speaking this protocol
/// shares one parser and one crate-name safety gate.
#[derive(Clone)]
pub struct SparseIndexClient {
    base_url: String,
    cache: Arc<HttpCache>,
    /// Bearer token attached to every request, when present. See
    /// [`crate::config::ResolvedRegistryEntry::auth`] for the security invariant on how
    /// this is populated — this client has no opinion on that; it just attaches whatever
    /// it is given, over an origin-pinned transport ([`deps_core::HttpCache::get_cached_trusted_origin_with_headers`])
    /// so the header cannot survive a cross-origin redirect.
    auth: Option<AuthToken>,
    /// The [`IndexTrust`] tier `index` was validated under (issue #455, C2): governs which
    /// transport [`Self::fetch`] routes through — a `WorkspaceDeclared` index always goes
    /// through [`deps_core::HttpCache::get_cached_workspace`], regardless of whether `auth` is
    /// set, so its connect-time address is scrutinized by the live workspace-registry policy.
    trust: IndexTrust,
    /// Display name used in [`deps_core::DepsError::PackageNotFound`] messages.
    registry_display_name: &'static str,
}

impl SparseIndexClient {
    /// Creates a new unauthenticated sparse-index client for `index`.
    ///
    /// Takes a validated [`RegistryIndex`], not a bare `String` (plan-1b §1.2, critic S2):
    /// `RegistryIndex::new`'s [`crate::config::IndexTrust`]/policy gate is the *only* public
    /// constructor of a fetchable index URL, so this client cannot be built with one that
    /// skipped it.
    pub fn new(index: RegistryIndex, cache: Arc<HttpCache>) -> Self {
        Self {
            trust: index.trust(),
            base_url: index.as_str().to_string(),
            cache,
            auth: None,
            registry_display_name: "sparse index",
        }
    }

    /// Creates a new sparse-index client for `index`, attaching `auth` (if any) to
    /// every request as a `Bearer` `Authorization` header, and using
    /// `registry_display_name` in not-found error messages.
    pub fn with_auth(
        index: RegistryIndex,
        cache: Arc<HttpCache>,
        auth: Option<AuthToken>,
        registry_display_name: &'static str,
    ) -> Self {
        Self {
            trust: index.trust(),
            base_url: index.as_str().to_string(),
            cache,
            auth,
            registry_display_name,
        }
    }

    /// The [`IndexTrust`] tier this client's index was validated under.
    #[must_use]
    pub(crate) const fn trust(&self) -> IndexTrust {
        self.trust
    }

    /// Whether this client attaches a credential to its requests. Test/diagnostic-only: private
    /// fields are not visible from `registry.rs`, a sibling module, so `crate::registry`'s C3
    /// fold test needs this accessor to assert a credential was dropped, alongside
    /// [`Self::trust`].
    #[cfg(test)]
    pub(crate) fn has_auth(&self) -> bool {
        self.auth.is_some()
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
    /// # use deps_cargo::sparse::SparseIndexClient;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let policy = deps_core::net_policy::RegistryAccessPolicy::default();
    /// let index = deps_cargo::config::RegistryIndex::new(
    ///     "https://index.crates.io",
    ///     deps_cargo::config::IndexTrust::Trusted,
    ///     &policy,
    /// ).unwrap();
    /// let client = SparseIndexClient::new(index, cache);
    ///
    /// let versions = client.get_versions("serde").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<CargoVersion>> {
        reject_unsafe_crate_name(name, self.registry_display_name)?;
        let url = sparse_index_url(&self.base_url, name);
        let data = self.fetch(&url).await?;
        parse_index_json(&data)
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
            let version = v.num.as_str().parse::<Version>().ok();
            version.is_some_and(|ver| req.matches(&ver) && !v.yanked)
        }))
    }

    /// Routes the request through the transport matching [`Self::auth`] and [`Self::trust`]
    /// — the sole call site deciding between [`deps_core::HttpCache::get_cached`],
    /// [`deps_core::HttpCache::get_cached_trusted_origin_with_headers`], and (issue #455)
    /// [`deps_core::HttpCache::get_cached_workspace`], so the two
    /// [`Self::get_versions`]/pagination-free shape of this client never duplicates that
    /// branch.
    ///
    /// `(Some(_), WorkspaceDeclared)` is a fail-closed arm, not a routed request: every current
    /// [`RegistryIndex`] producer already prevents a `WorkspaceDeclared` index from carrying a
    /// credential (`config::finalize_source_replacement` drops it on a folded chain,
    /// `resolve_cargo_home_tier` only ever produces `Trusted`, and a plain workspace
    /// `[registries]`/`registry-index` resolution never attaches one) — this arm is
    /// defense-in-depth against a future producer regression, not a currently reachable path.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_versions`], plus `DepsError::CacheError` for the fail-closed arm.
    async fn fetch(&self, url: &str) -> Result<bytes::Bytes> {
        match (&self.auth, self.trust) {
            (Some(token), IndexTrust::Trusted) => {
                let header_value = format!("Bearer {}", token.as_str());
                self.cache
                    .get_cached_trusted_origin_with_headers(
                        url,
                        &self.base_url,
                        &[(reqwest::header::AUTHORIZATION, header_value.as_str())],
                    )
                    .await
            }
            (None, IndexTrust::Trusted) => self.cache.get_cached(url).await,
            (None, IndexTrust::WorkspaceDeclared) => self.cache.get_cached_workspace(url).await,
            (Some(_), IndexTrust::WorkspaceDeclared) => {
                tracing::error!(
                    url = %self.base_url,
                    "refusing to attach a credential to a workspace-declared registry index request"
                );
                Err(DepsError::CacheError(format!(
                    "refusing authenticated request to workspace-declared index {}",
                    self.base_url
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::RegistryAccessPolicy;

    /// Wraps `raw` into a [`RegistryIndex`] for test call sites, using an all-allow policy
    /// so a test's own choice of URL (including a loopback mockito URL) is never blocked —
    /// the policy gate itself is unit-tested directly in `config.rs`, not re-exercised here.
    fn test_index(raw: &str) -> RegistryIndex {
        let policy = RegistryAccessPolicy::default();
        RegistryIndex::new(raw, IndexTrust::Trusted, &policy).unwrap()
    }

    /// Like [`test_index`], but [`IndexTrust::WorkspaceDeclared`] — for issue #455's C2
    /// fail-closed/routing tests, which need a `WorkspaceDeclared` index specifically.
    fn test_workspace_index(raw: &str) -> RegistryIndex {
        let policy = RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::All);
        RegistryIndex::new(raw, IndexTrust::WorkspaceDeclared, &policy).unwrap()
    }

    /// Live-network smoke test against the real crates.io sparse index. Restored
    /// (review finding #8) after being dropped, undisclosed, during the extraction of
    /// this module out of `registry.rs`. `#[ignore]`d: not run in CI, only on demand.
    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_serde_versions() {
        let cache = Arc::new(HttpCache::new());
        let client = SparseIndexClient::new(test_index("https://index.crates.io"), cache);
        let versions = client.get_versions("serde").await.unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.num.as_str().starts_with("1.")));
    }

    /// Live-network smoke test against the real crates.io sparse index. Restored
    /// (review finding #8), same provenance as `test_fetch_real_serde_versions` above.
    #[tokio::test]
    #[ignore]
    async fn test_get_latest_matching_real() {
        let cache = Arc::new(HttpCache::new());
        let client = SparseIndexClient::new(test_index("https://index.crates.io"), cache);
        let latest = client.get_latest_matching("serde", "^1.0").await.unwrap();

        assert!(latest.is_some());
        let version = latest.unwrap();
        assert!(version.num.as_str().starts_with("1."));
        assert!(!version.yanked);
    }

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
        assert!(reject_unsafe_crate_name("..", "crates.io").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_rejects_bare_dot() {
        assert!(reject_unsafe_crate_name(".", "crates.io").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_rejects_embedded_slash() {
        // S1 (impl-critic): `sparse_index_path` performs no per-character encoding, so a
        // `/` anywhere in `name` (not just a bare `.`/`..`) can inject path segments once
        // spliced into the request URL.
        assert!(reject_unsafe_crate_name("../../etc/passwd", "crates.io").is_err());
    }

    #[test]
    fn test_reject_unsafe_crate_name_accepts_normal_names() {
        assert!(reject_unsafe_crate_name("serde", "crates.io").is_ok());
        assert!(reject_unsafe_crate_name("serde_derive", "crates.io").is_ok());
        assert!(reject_unsafe_crate_name("actix-web", "crates.io").is_ok());
    }

    /// #376: `sparse_index_path`'s byte-index slicing (`name_lower[0..2]` etc.) panics on a
    /// non-ASCII crate name, since those indices can land mid-codepoint. `is_safe_crate_name`'s
    /// ASCII-alphanumeric-only allowlist blocks any non-ASCII input before it reaches that
    /// code, closing the panic as a side effect of the charset check — asserted directly here
    /// so a future narrowing of the allowlist's *intent* (without touching this exact
    /// assertion) can't silently reopen the panic with nothing to catch it.
    #[test]
    fn test_reject_unsafe_crate_name_rejects_non_ascii() {
        assert!(reject_unsafe_crate_name("日本", "crates.io").is_err());
    }

    /// Demonstrates the vulnerability `reject_unsafe_crate_name` exists to prevent:
    /// `sparse_index_url` alone (with no caller-side guard) builds a URL that, once parsed,
    /// has escaped the sparse index root entirely.
    #[test]
    fn test_sparse_index_url_bare_dot_dot_normalizes_above_root() {
        let url = sparse_index_url("https://index.crates.io", "..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/", "parsed path: {}", parsed.path());
    }

    /// Demonstrates the broader S1 vulnerability: an embedded `/` (not just a bare
    /// `.`/`..`) lets `sparse_index_url` alone build a URL whose path escapes to an
    /// attacker-influenced location, since no character in `name` is encoded.
    #[test]
    fn test_sparse_index_url_embedded_slash_escapes_root() {
        let url = sparse_index_url("https://index.crates.io", "../../etc/passwd");
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
                reject_unsafe_crate_name(seg, "crates.io")
                    .ok()
                    .map(|()| sparse_index_url("https://index.crates.io", seg))
            },
            "index.crates.io",
            "/",
        );
    }

    #[test]
    fn test_sparse_index_url_trims_trailing_slash_on_base() {
        let with_slash = sparse_index_url("https://index.mycorp.dev/", "serde");
        let without_slash = sparse_index_url("https://index.mycorp.dev", "serde");
        assert_eq!(with_slash, without_slash);
        assert_eq!(with_slash, "https://index.mycorp.dev/se/rd/serde");
    }

    #[test]
    fn test_parse_index_json() {
        let json = r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}
{"name":"serde","vers":"1.0.1","yanked":false,"features":{"derive":["serde_derive"]},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "1.0.1");
        assert_eq!(versions[1].num, "1.0.0");
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_index_json_with_yanked() {
        let json = r#"{"name":"test","vers":"0.1.0","yanked":true,"features":{},"deps":[]}
{"name":"test","vers":"0.2.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions[1].yanked);
        assert!(!versions[0].yanked);
    }

    #[test]
    fn test_parse_index_json_empty() {
        let json = "";
        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_blank_lines() {
        let json = "\n\n\n";
        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_invalid_version() {
        let json = r#"{"name":"test","vers":"invalid","yanked":false,"features":{},"deps":[]}"#;
        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_index_json_mixed_valid_invalid() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[]}
{"name":"test","vers":"invalid","yanked":false,"features":{},"deps":[]}
{"name":"test","vers":"2.0.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "2.0.0");
        assert_eq!(versions[1].num, "1.0.0");
    }

    #[test]
    fn test_parse_index_json_with_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[],"pubtime":"2026-07-18T23:05:13Z"}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            Some(deps_core::PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").unwrap())
        );
    }

    #[test]
    fn test_parse_index_json_without_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_parse_index_json_with_malformed_pubtime() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{},"deps":[],"pubtime":"not-a-timestamp"}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed pubtime degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_index_json_with_features() {
        let json = r#"{"name":"test","vers":"1.0.0","yanked":false,"features":{"default":["std"],"std":[]},"deps":[]}"#;

        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].features.len(), 2);
        assert!(versions[0].features.contains_key("default"));
        assert!(versions[0].features.contains_key("std"));
    }

    #[test]
    fn test_parse_index_json_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"vers":"1.0.0","extra":{}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn test_parse_index_json_nesting_over_max_depth_line_skipped() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"vers":"1.0.0","extra":{}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let versions = parse_index_json(json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 0);
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

    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_as_not_found() {
        let client = SparseIndexClient::new(
            test_index("https://index.crates.io"),
            Arc::new(HttpCache::new()),
        );
        let err = client.get_versions("..").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_rejects_embedded_slash_as_not_found() {
        let client = SparseIndexClient::new(
            test_index("https://index.crates.io"),
            Arc::new(HttpCache::new()),
        );
        let err = client.get_versions("../../etc/passwd").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_from_mocked_sparse_index() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .create_async()
            .await;

        let client = SparseIndexClient::new(test_index(&server.url()), Arc::new(HttpCache::new()));
        let versions = client.get_versions("serde").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].num, "1.0.0");
    }

    #[tokio::test]
    async fn test_get_versions_with_auth_sends_authorization_header() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/se/rd/serde")
            .match_header("authorization", "Bearer secret-token")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .create_async()
            .await;

        let client = SparseIndexClient::with_auth(
            test_index(&server.url()),
            Arc::new(HttpCache::new()),
            Some(AuthToken::new("secret-token".to_string())),
            "my-corp",
        );
        let versions = client.get_versions("serde").await.unwrap();
        assert_eq!(versions.len(), 1);
    }

    // Issue #455, test-plan item 8 (C2 fail-closed): `(Some(auth), WorkspaceDeclared)` must
    // never send a request at all — the mockito mock asserting `expect(0)` proves no request
    // reached the network, not just that `get_versions` returned an error.
    #[tokio::test]
    async fn test_fetch_refuses_authenticated_workspace_declared_request() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .expect(0)
            .create_async()
            .await;

        let client = SparseIndexClient::with_auth(
            test_workspace_index(&server.url()),
            Arc::new(HttpCache::new()),
            Some(AuthToken::new("secret-token".to_string())),
            "workspace index",
        );
        let err = client.get_versions("serde").await.unwrap_err();
        assert!(matches!(err, DepsError::CacheError(_)));
        mock.assert_async().await;
    }

    // Issue #455, test-plan item 9 (C2 routing): a successful `(None, WorkspaceDeclared)` fetch
    // lands under the workspace cache-key namespace, not the baseline one — proven via the
    // public `peek_cached` API (which only ever reads the baseline namespace) rather than by
    // reaching into `HttpCache`'s private fields.
    #[tokio::test]
    async fn test_fetch_routes_workspace_declared_through_workspace_cache_namespace() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let client =
            SparseIndexClient::new(test_workspace_index(&server.url()), Arc::clone(&cache));
        let versions = client.get_versions("serde").await.unwrap();
        assert_eq!(versions.len(), 1);

        let index_url = format!("{}/se/rd/serde", server.url());
        assert!(
            cache.peek_cached(&index_url).is_none(),
            "a WorkspaceDeclared fetch must not land under the baseline (peek_cached-visible) \
             cache-key namespace"
        );
    }

    #[tokio::test]
    async fn test_get_latest_matching_via_sparse_client() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(
                "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false,\"features\":{},\"deps\":[]}\n\
                 {\"name\":\"serde\",\"vers\":\"2.0.0\",\"yanked\":false,\"features\":{},\"deps\":[]}",
            )
            .create_async()
            .await;

        let client = SparseIndexClient::new(test_index(&server.url()), Arc::new(HttpCache::new()));
        let latest = client.get_latest_matching("serde", "^1.0").await.unwrap();
        assert_eq!(latest.unwrap().num, "1.0.0");
    }
}
