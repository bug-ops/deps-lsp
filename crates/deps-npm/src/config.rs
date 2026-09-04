//! `.npmrc` discovery and `registry`/`@scope:registry` resolution.
//!
//! Resolves a dependency's npm registry the way npm itself does — a top-level `registry=`
//! override for unscoped dependencies, or an `@scope:registry=` entry for a scoped
//! dependency's own scope — by reading the same two-tier `.npmrc` hierarchy npm consults:
//! the project tier (walked from the opened `package.json`'s directory up to the filesystem
//! root, mirroring `deps-cargo`'s `.cargo/config.toml` ancestor walk) and the user tier
//! (`~/.npmrc`). The global tier (`$PREFIX/etc/npmrc`) is out of scope (spec FR-002/FR-014).
//!
//! # Security model (read before touching this module)
//!
//! A workspace's own `.npmrc` is attacker-controlled the moment a hostile repository is
//! cloned and opened — this LSP parses on file open, before any build ever runs. Phase 1
//! carries **no** authentication at all (spec Out of Scope), which closes the credential
//! half of the threat model this module would otherwise have to solve, but two things still
//! apply:
//!
//! - **No auth-shaped key is ever parsed** (FR-013/NFR-001). `parse_npmrc_raw` recognizes
//!   exactly two key shapes — `registry` and `@<scope>:registry` — and skips every other
//!   line outright. There is no `HashMap<String, String>` "everything else" table anywhere
//!   in this module for an `_authToken`/`_auth`/`_password`/`_authIdent`/`always-auth`/
//!   `//host/:_*` value to land in even accidentally. This is a structural guarantee, not a
//!   runtime filter — verified by this module's own NFR-001 test.
//! - **A literal `user:pass@`/`user@` written directly in a `registry=`/`@scope:registry=`
//!   value is redacted before it can leak** (M1 fix, mirroring `deps-pypi`'s own M1). No
//!   `${VAR}` expansion is needed for this case — a hostile `.npmrc` can write the credential
//!   straight into the raw value — so `resolve_entry` redacts it (see
//!   [`deps_core::net_policy::redact_userinfo`]) before it ever reaches a `tracing::warn!`
//!   call or [`InvalidEntry::raw`], which [`NpmConfig::resolve_source_for`] can surface as
//!   [`DependencySource::CustomRegistry`]'s `url` in hover/diagnostics text.
//! - **Internal-network reachability (SSRF-adjacent).** [`NpmRegistryIndex::new`] requires a
//!   [`deps_core::net_policy::RegistryAccessPolicy`] and checks every candidate against it —
//!   unlike Cargo's `$CARGO_HOME`-is-trusted split, npm's project and user tiers are
//!   policy-symmetric (spec NFR-003(a)): phase 1 has no credential provenance to protect, so
//!   there is no tier that is "the user's own configuration" in the way `$CARGO_HOME` is.
//!
//! See `specs/032-npm-npmrc-registry-support/spec.md` FR-001–FR-014 and
//! `specs/032-npm-npmrc-registry-support/plan.md` §1/§3/§6 for the design review this module
//! implements.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_core::PackageName;
use deps_core::net_policy::{
    HostClass, IndexUrlError, PolicyGate, RegistryAccessPolicy, redact_userinfo, validate_index_url,
};
use deps_core::parser::DependencySource;

/// Why a candidate `registry=`/`@scope:registry=` value failed [`NpmRegistryIndex::new`]'s
/// validation, or why expansion of a `${VAR}` placeholder inside it failed (FR-007).
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum NpmRegistryIndexError {
    /// The value did not parse as a URL at all.
    #[error("not a valid URL: {0}")]
    InvalidUrl(String),
    /// The URL's scheme is not `https` (the sole carve-out is a `cfg(test)`/`test-util`-only
    /// `http` loopback host — see [`NpmRegistryIndex::new`]).
    #[error("registry index must use https, got scheme {0:?}")]
    NotHttps(String),
    /// The URL carries a `user:pass@`/`user@` component.
    #[error("registry index URL must not carry userinfo")]
    UserInfoPresent,
    /// The candidate's host is blocked by the current
    /// [`deps_core::net_policy::WorkspaceRegistryAccess`] policy.
    #[error("registry index host class {class} blocked by registries.workspace_registries policy")]
    BlockedHost {
        /// The blocked host's classification.
        class: HostClass,
    },
    /// A `${VAR}` placeholder in the value names an environment variable that is not set
    /// (FR-007) — the whole value is invalid, never fetched as the literal
    /// `${VAR}`-containing string.
    #[error("environment variable {0:?} referenced in registry value is not set")]
    UndefinedEnvVar(String),
}

impl From<IndexUrlError> for NpmRegistryIndexError {
    fn from(error: IndexUrlError) -> Self {
        match error {
            IndexUrlError::InvalidUrl(raw) => Self::InvalidUrl(raw),
            IndexUrlError::NotHttps(scheme) => Self::NotHttps(scheme),
            IndexUrlError::UserInfoPresent => Self::UserInfoPresent,
            IndexUrlError::BlockedHost { class } => Self::BlockedHost { class },
        }
    }
}

/// A validated, normalized npm registry index URL.
///
/// `https`-only (the sole carve-out is a `cfg(test)`/`test-util`-only `http` loopback host),
/// no userinfo, and `classify_host`/[`RegistryAccessPolicy`]-gated. Deliberately has no
/// trust-tier concept (unlike `deps-cargo`'s `RegistryIndex`/`IndexTrust`) — npm phase 1
/// attaches no credential to any request, so there is nothing for a trust tier to gate.
///
/// Normalized so `https://npm.pkg.github.com/` and `https://npm.pkg.github.com` produce the
/// **same** [`Self::as_str`] output — one router entry, not two, and no doubled slash when a
/// caller splices a package path onto it (`{base}/{name}`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NpmRegistryIndex {
    /// The validated URL, normalized by stripping trailing `/` characters — see the type
    /// doc. Always the exact string returned by [`Self::as_str`].
    normalized: String,
}

impl NpmRegistryIndex {
    /// Validates, normalizes, and wraps `raw` — an already `${VAR}`-expanded candidate
    /// string (expansion happens in [`resolve`], before this is called).
    ///
    /// # Errors
    ///
    /// Returns [`NpmRegistryIndexError`] if `raw` does not parse as a URL, is not `https`
    /// (outside the `cfg(test)`/`test-util` loopback carve-out), carries a userinfo
    /// component, or resolves to a host class the current `policy` blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_npm::config::NpmRegistryIndex;
    ///
    /// let policy = RegistryAccessPolicy::default();
    /// assert!(NpmRegistryIndex::new("https://npm.pkg.github.com", &policy).is_ok());
    /// assert!(NpmRegistryIndex::new("http://npm.pkg.github.com", &policy).is_err());
    /// assert!(NpmRegistryIndex::new("https://user:pass@npm.example", &policy).is_err());
    /// ```
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, NpmRegistryIndexError> {
        Self::new_for_log(raw, raw, policy)
    }

    /// Like [`Self::new`], but validates `expanded` (the candidate to actually parse) while
    /// using `raw_for_log` — the pre-expansion `.npmrc` value — for every error payload and
    /// `tracing::warn!` call. [`Self::new`] passes the same string for both, since it has no
    /// separate pre-expansion form; [`resolve_entry`] passes the true `${VAR}`-expanded value
    /// alongside the original raw one, so a rejected candidate built from `${SOME_TOKEN}`
    /// never leaks that token's expanded value into a log line or an
    /// [`NpmRegistryIndexError::InvalidUrl`] payload — see this module's security-model doc.
    fn new_for_log(
        expanded: &str,
        raw_for_log: &str,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self, NpmRegistryIndexError> {
        let url = validate_index_url(expanded, raw_for_log, "npm", PolicyGate::Enforce(policy))?;
        let normalized = url.as_str().trim_end_matches('/').to_string();
        Ok(Self { normalized })
    }

    /// The normalized index URL — the canonical key for the router's `alternates` map and
    /// for [`DependencySource::AlternateRegistry`]'s `index`. Never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Display for NpmRegistryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `registry=`/`@scope:registry=` entry that was present in `.npmrc` but unusable.
///
/// Invalid URL, non-https, an undefined `${VAR}`, or policy-blocked. Carries the raw value
/// as written (never the expanded form, and with any literal userinfo redacted — see
/// [`deps_core::net_policy::redact_userinfo`]) so [`NpmConfig::resolve_source_for`] can build
/// [`DependencySource::CustomRegistry`] and so a warning can name what the user actually
/// wrote, never an expanded-but-rejected value that could leak an environment variable's
/// contents into the log, and never a literal credential the user wrote directly in `.npmrc`.
#[derive(Debug, Clone)]
pub struct InvalidEntry {
    /// The raw `.npmrc` value, unexpanded, with any literal userinfo redacted.
    pub raw: String,
    /// Why it was rejected.
    pub reason: NpmRegistryIndexError,
}

/// The merged, resolved view of a workspace's `.npmrc` hierarchy (project tier overrides
/// user tier). A plain lookup table with one resolution method — mirrors `deps-cargo`'s
/// `CargoConfig`.
#[derive(Debug, Default)]
pub struct NpmConfig {
    /// The top-level `registry=` override (FR-003), if any entry (valid or not) was found.
    registry: Option<Result<NpmRegistryIndex, InvalidEntry>>,
    /// `@scope:registry=` entries (FR-004), keyed by the scope **including** its leading
    /// `@`, byte-exact as written in `.npmrc` — no case folding. This matches npm's own
    /// literal `@${scope}:registry` key lookup: npm lowercases *package names* at publish
    /// time but never case-folds `.npmrc` keys, so folding here would resolve a registry npm
    /// itself would not.
    scoped_registries: HashMap<String, Result<NpmRegistryIndex, InvalidEntry>>,
}

impl NpmConfig {
    /// Resolves `package_name` straight to its final [`DependencySource`] (spec FR-003–006).
    ///
    /// - FR-004 > FR-003: a matching `@scope:registry=` entry — valid or not — wins outright
    ///   over the top-level `registry=` override for that dependency.
    /// - FR-005: no matching entry at all -> [`DependencySource::Registry`] (public default).
    /// - FR-006/FR-007/FR-008: a matching entry that is present but invalid, unexpandable, or
    ///   policy-blocked -> [`DependencySource::CustomRegistry`] — never a silent fall back to
    ///   [`DependencySource::Registry`] (the #248 regression class this closes for npm).
    #[must_use]
    pub fn resolve_source_for(&self, package_name: &PackageName) -> DependencySource {
        if let Some(scope) = scope_of(package_name.as_str())
            && let Some(result) = self.scoped_registries.get(scope)
        {
            return source_from_result(result);
        }
        match &self.registry {
            Some(result) => source_from_result(result),
            None => DependencySource::Registry,
        }
    }

    /// Every successfully resolved [`NpmRegistryIndex`] this config carries (the top-level
    /// override plus every scoped entry), deduplicated by [`NpmRegistryIndex::as_str`] — fed
    /// to `NpmRegistry::register_alternate` at parse time. An invalid/unresolved entry
    /// contributes nothing here: there is no client to register for it.
    #[must_use]
    pub fn resolved_registries(&self) -> Vec<NpmRegistryIndex> {
        let mut seen = std::collections::HashSet::new();
        self.registry
            .iter()
            .chain(self.scoped_registries.values())
            .filter_map(|result| result.as_ref().ok())
            .filter(|index| seen.insert(index.as_str().to_string()))
            .cloned()
            .collect()
    }
}

fn source_from_result(result: &Result<NpmRegistryIndex, InvalidEntry>) -> DependencySource {
    match result {
        Ok(index) => DependencySource::AlternateRegistry {
            index: index.as_str().to_string(),
            mirrors_crates_io: false,
        },
        Err(invalid) => DependencySource::CustomRegistry {
            url: invalid.raw.clone(),
        },
    }
}

/// The scope (including its leading `@`) of a package name, e.g. `"@myorg"` for
/// `"@myorg/pkg"`. `None` for an unscoped name.
fn scope_of(name: &str) -> Option<&str> {
    name.split_once('/')
        .map(|(scope, _)| scope)
        .filter(|scope| scope.starts_with('@'))
}

/// One `.npmrc` file's raw (unvalidated, unexpanded), recognized entries — see
/// [`parse_npmrc_raw`]'s doc for exactly which keys this can ever contain.
#[derive(Debug, Default, Clone)]
struct RawNpmrc {
    registry: Option<String>,
    scoped: HashMap<String, String>,
}

/// Parses one `.npmrc` file's content into its raw, unvalidated `registry`/
/// `@scope:registry` entries.
///
/// **Recognizes exactly two key shapes** — `registry` and `@<scope>:registry` — and skips
/// every other line outright, including every auth-shaped key (`_authToken`, `_auth`,
/// `_password`, `_authIdent`, `always-auth`, any `//<host>/:_*` scoped-credential key) and
/// every other npm config setting. This is the structural half of FR-013/NFR-001: there is
/// no code path in this function that can produce a value for anything but those two key
/// shapes.
///
/// Grammar (FR-001): npm's own `.npmrc` INI-like format — `key=value` or `key = value` one
/// per line, `#`/`;` as full-line comment markers, blank lines ignored. A line with no `=`
/// (or an unrecognized key) is skipped with a `tracing::warn!`; every other valid line still
/// applies.
fn parse_npmrc_raw(content: &str) -> RawNpmrc {
    let mut out = RawNpmrc::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            tracing::warn!(line, "skipping malformed .npmrc line: no '='");
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key == "registry" {
            out.registry = Some(value.to_string());
        } else if let Some(scope) = key
            .strip_suffix(":registry")
            .filter(|scope| scope.starts_with('@'))
        {
            out.scoped.insert(scope.to_string(), value.to_string());
        }
        // Every other key (including every auth-shaped one) is deliberately ignored — see
        // this function's doc.
    }
    out
}

/// Expands every `${VAR}` placeholder in `raw` from the process environment (FR-007).
///
/// Returns `Ok(expanded)` when every referenced variable is set (including the trivial case
/// of no `${...}` placeholder at all), or `Err(var_name)` naming the first undefined
/// variable encountered.
fn expand_env_vars(raw: &str) -> Result<String, String> {
    expand_env_vars_with(raw, |name| std::env::var(name).ok())
}

/// [`expand_env_vars`], but reading variables through `lookup` instead of
/// [`std::env::var`] directly — lets tests inject a fake environment instead of mutating the
/// real process environment (this workspace forbids `unsafe`, and Rust 2024 made
/// `std::env::set_var` an `unsafe fn`, so a test cannot do that mutation at all).
fn expand_env_vars_with(
    raw: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // No closing brace: keep the rest of the string literal, same as npm's own
            // parser does for a malformed placeholder.
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let var_name = &after[..end];
        match lookup(var_name) {
            Some(value) => out.push_str(&value),
            None => return Err(var_name.to_string()),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Expands and validates one raw `.npmrc` value, producing the [`NpmConfig`] entry FR-006's
/// fail-closed state needs on failure — a `tracing::warn!` naming the **raw**, unexpanded
/// value either way (an expanded-but-rejected value must never leak an environment
/// variable's contents into the log), with any literal `user:pass@`/`user@` userinfo written
/// directly in that raw value redacted first (M1 fix — see
/// [`deps_core::net_policy::redact_userinfo`]) — a hostile `.npmrc` can write a credential
/// straight into `registry=`/`@scope:registry=` with no `${VAR}` expansion involved.
fn resolve_entry(
    raw: &str,
    policy: &RegistryAccessPolicy,
) -> Result<NpmRegistryIndex, InvalidEntry> {
    match expand_env_vars(raw) {
        Ok(expanded) => NpmRegistryIndex::new_for_log(&expanded, raw, policy).map_err(|reason| {
            let redacted = redact_userinfo(raw);
            tracing::warn!(raw = %redacted, %reason, "npm registry index failed validation");
            InvalidEntry {
                raw: redacted,
                reason,
            }
        }),
        Err(var) => {
            let redacted = redact_userinfo(raw);
            tracing::warn!(
                raw = %redacted,
                var,
                "npm registry value references an undefined environment variable"
            );
            Err(InvalidEntry {
                raw: redacted,
                reason: NpmRegistryIndexError::UndefinedEnvVar(var),
            })
        }
    }
}

/// Upper bound on the project-tier ancestor walk depth, matching `deps-cargo`'s
/// `MAX_CONFIG_ANCESTOR_DEPTH`. `pub(crate)` so `crate::catalog::find_workspace_file` can
/// reuse the same bound for its own ancestor walk.
pub(crate) const MAX_CONFIG_ANCESTOR_DEPTH: usize = 64;

/// Per-`.npmrc`-file-path memoization (FR-012), mirroring `deps-cargo::config::ConfigFileCache`
/// exactly in shape.
///
/// Caches **raw, unvalidated** entries — `${VAR}` expansion, [`NpmRegistryIndex::new`]
/// validation, and policy gating all re-run **per parse** against these cached entries,
/// never cached themselves. This is what makes a `didChangeConfiguration` policy change, or
/// an environment-variable change, take effect immediately with no cache invalidation of its
/// own. There is no workspace-root key: npm has no workspace-root concept for config
/// discovery (`NpmParseResult::workspace_root()` returns `None`), and neither does Cargo's
/// config cache. A thin newtype over [`deps_core::MtimeFileCache`] — the mtime-gated caching
/// mechanism itself lives there, shared with `deps-cargo`.
#[derive(Debug)]
pub struct NpmConfigCache(deps_core::MtimeFileCache<RawNpmrc>);

impl Default for NpmConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmConfigCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self(deps_core::MtimeFileCache::new(
            deps_core::DEFAULT_MAX_CACHED_FILES,
            "npm config",
        ))
    }

    /// Returns `path`'s parsed contents, from cache if `path`'s mtime is unchanged, else
    /// re-reading and re-parsing. `None` if `path` does not exist, is not a regular file, or
    /// cannot be read.
    fn get_or_parse(&self, path: &Path) -> Option<Arc<RawNpmrc>> {
        self.0.get_or_parse(path, parse_npmrc_raw)
    }
}

/// Owned by `NpmEcosystem`, shared across every document it parses — the npm analogue of
/// `deps_cargo::parser::CargoParseContext`.
#[derive(Debug, Clone, Default)]
pub struct NpmParseContext {
    /// Gates every workspace-declared [`NpmRegistryIndex`] this parse constructs.
    pub policy: Arc<RegistryAccessPolicy>,
    /// Memoizes each distinct `.npmrc` file's raw, unvalidated contents across every parse
    /// that reads it.
    pub config_cache: Arc<NpmConfigCache>,
    /// Memoizes each distinct `pnpm-workspace.yaml` file's parsed catalogs across every parse
    /// that reads it (spec 046, NFR-001).
    pub workspace_cache: Arc<crate::catalog::PnpmWorkspaceCache>,
}

/// Resolves `manifest_dir`'s `.npmrc` hierarchy (project tier, ancestor-walked, plus the
/// user tier) into a merged [`NpmConfig`] (spec FR-002).
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::RegistryAccessPolicy;
/// use deps_npm::config::{NpmConfigCache, resolve};
/// use std::path::Path;
///
/// let cache = NpmConfigCache::new();
/// let policy = RegistryAccessPolicy::default();
/// let config = resolve(Path::new("/nonexistent/workspace"), &cache, &policy);
/// assert!(config.resolved_registries().is_empty());
/// ```
#[must_use]
pub fn resolve(
    manifest_dir: &Path,
    config_cache: &NpmConfigCache,
    policy: &RegistryAccessPolicy,
) -> NpmConfig {
    resolve_with_home(manifest_dir, config_cache, policy, dirs::home_dir())
}

/// [`resolve`], but taking the user-tier home directory explicitly instead of
/// [`dirs::home_dir`] — lets tests inject a fixture home directory.
fn resolve_with_home(
    manifest_dir: &Path,
    config_cache: &NpmConfigCache,
    policy: &RegistryAccessPolicy,
    home: Option<PathBuf>,
) -> NpmConfig {
    let user_npmrc_path = home.map(|h| h.join(".npmrc"));
    // M9: a project living under `$HOME` has `$HOME` as an ancestor, so the project-tier
    // walk below would otherwise find `~/.npmrc` a second time as a (wrongly
    // outranking-itself) workspace-tier entry. Deduped by canonicalized path so a symlinked
    // home is caught too, mirroring `deps-cargo::config::load_tiers`.
    let user_canonical = user_npmrc_path
        .as_deref()
        .and_then(|p| std::fs::canonicalize(p).ok());

    let mut registry_raw: Option<String> = None;
    let mut scoped_raw: HashMap<String, String> = HashMap::new();

    // FR-002: this ancestor walk is a deliberate superset of npm's own behavior (which reads
    // only the project-root `.npmrc`, not every ancestor) — chosen for monorepo ergonomics,
    // mirroring `deps-cargo`'s `.cargo/config.toml` discovery. Closest directory wins.
    let mut current = Some(manifest_dir);
    let mut depth = 0usize;
    while let Some(dir) = current {
        if depth >= MAX_CONFIG_ANCESTOR_DEPTH {
            break;
        }
        depth += 1;

        let candidate = dir.join(".npmrc");
        let is_user_tier_duplicate =
            std::fs::canonicalize(&candidate).ok().as_deref() == user_canonical.as_deref();
        if !is_user_tier_duplicate && let Some(parsed) = config_cache.get_or_parse(&candidate) {
            if registry_raw.is_none() {
                registry_raw.clone_from(&parsed.registry);
            }
            for (scope, raw) in &parsed.scoped {
                scoped_raw
                    .entry(scope.clone())
                    .or_insert_with(|| raw.clone());
            }
        }

        current = dir.parent();
    }

    if let Some(user_path) = user_npmrc_path.as_deref()
        && let Some(parsed) = config_cache.get_or_parse(user_path)
    {
        if registry_raw.is_none() {
            registry_raw.clone_from(&parsed.registry);
        }
        for (scope, raw) in &parsed.scoped {
            scoped_raw
                .entry(scope.clone())
                .or_insert_with(|| raw.clone());
        }
    }

    NpmConfig {
        registry: registry_raw.map(|raw| resolve_entry(&raw, policy)),
        scoped_registries: scoped_raw
            .into_iter()
            .map(|(scope, raw)| (scope, resolve_entry(&raw, policy)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::WorkspaceRegistryAccess;
    use std::assert_matches;
    use std::time::SystemTime;

    fn public_only_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly)
    }

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    fn off_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)
    }

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name)
    }

    // --- NpmRegistryIndex ---

    #[test]
    fn test_npm_registry_index_accepts_https() {
        let policy = all_policy();
        assert!(NpmRegistryIndex::new("https://npm.pkg.github.com", &policy).is_ok());
    }

    #[test]
    fn test_npm_registry_index_rejects_http_non_loopback() {
        let policy = all_policy();
        assert_matches!(
            NpmRegistryIndex::new("http://registry.example.com", &policy),
            Err(NpmRegistryIndexError::NotHttps(_))
        );
    }

    /// N-C1: even under the `cfg(test)`/`test-util` carve-out, a *non-loopback* `http` host
    /// (including a near-miss hostname) must still be rejected.
    #[test]
    fn test_npm_registry_index_rejects_http_near_miss_loopback() {
        let policy = all_policy();
        assert_matches!(
            NpmRegistryIndex::new("http://localhost.evil.com", &policy),
            Err(NpmRegistryIndexError::NotHttps(_))
        );
    }

    #[test]
    fn test_npm_registry_index_accepts_http_loopback_under_test_cfg() {
        let policy = all_policy();
        assert!(NpmRegistryIndex::new("http://127.0.0.1:4873", &policy).is_ok());
        assert!(NpmRegistryIndex::new("http://localhost:4873", &policy).is_ok());
    }

    #[test]
    fn test_npm_registry_index_rejects_userinfo() {
        let policy = all_policy();
        assert_matches!(
            NpmRegistryIndex::new("https://user:pass@npm.example", &policy),
            Err(NpmRegistryIndexError::UserInfoPresent)
        );
    }

    #[test]
    fn test_npm_registry_index_rejects_invalid_url() {
        let policy = all_policy();
        assert_matches!(
            NpmRegistryIndex::new("not-a-valid-url", &policy),
            Err(NpmRegistryIndexError::InvalidUrl(_))
        );
    }

    /// S5: `https://x/` and `https://x` normalize to one index, and neither carries a
    /// trailing slash — building `{base}/@scope/pkg` on top must not double the slash.
    #[test]
    fn test_npm_registry_index_normalizes_trailing_slash() {
        let policy = all_policy();
        let with_slash = NpmRegistryIndex::new("https://npm.pkg.github.com/", &policy).unwrap();
        let without_slash = NpmRegistryIndex::new("https://npm.pkg.github.com", &policy).unwrap();
        assert_eq!(with_slash, without_slash);
        assert_eq!(with_slash.as_str(), "https://npm.pkg.github.com");
        assert!(!with_slash.as_str().ends_with('/'));
    }

    /// FR-008 policy matrix: an `https` loopback index (so the scheme gate never fires)
    /// resolves under `all`, is blocked under `public_only`, and is blocked under `off`.
    #[test]
    fn test_npm_registry_index_policy_matrix() {
        assert!(NpmRegistryIndex::new("https://127.0.0.1:4873", &all_policy()).is_ok());
        assert_matches!(
            NpmRegistryIndex::new("https://127.0.0.1:4873", &public_only_policy()),
            Err(NpmRegistryIndexError::BlockedHost { .. })
        );
        assert_matches!(
            NpmRegistryIndex::new("https://127.0.0.1:4873", &off_policy()),
            Err(NpmRegistryIndexError::BlockedHost { .. })
        );
    }

    #[test]
    fn test_npm_registry_index_public_host_allowed_under_public_only() {
        let policy = public_only_policy();
        assert!(NpmRegistryIndex::new("https://npm.pkg.github.com", &policy).is_ok());
    }

    // --- parse_npmrc_raw (FR-001) ---

    #[test]
    fn test_parse_npmrc_raw_registry_and_scoped() {
        let content =
            "registry=https://npm.mycorp.example/\n@myorg:registry=https://npm.pkg.github.com/\n";
        let raw = parse_npmrc_raw(content);
        assert_eq!(raw.registry.as_deref(), Some("https://npm.mycorp.example/"));
        assert_eq!(
            raw.scoped.get("@myorg").map(String::as_str),
            Some("https://npm.pkg.github.com/")
        );
    }

    #[test]
    fn test_parse_npmrc_raw_comments_and_blank_lines() {
        let content = "# comment\n\n; also a comment\nregistry=https://npm.example/\n";
        let raw = parse_npmrc_raw(content);
        assert_eq!(raw.registry.as_deref(), Some("https://npm.example/"));
    }

    #[test]
    fn test_parse_npmrc_raw_spaced_equals() {
        let content = "registry = https://npm.example/\n";
        let raw = parse_npmrc_raw(content);
        assert_eq!(raw.registry.as_deref(), Some("https://npm.example/"));
    }

    #[test]
    fn test_parse_npmrc_raw_malformed_line_skipped_others_still_apply() {
        let content = "not-a-valid-line-no-equals\nregistry=https://npm.example/\n";
        let raw = parse_npmrc_raw(content);
        assert_eq!(raw.registry.as_deref(), Some("https://npm.example/"));
    }

    /// FR-013/NFR-001: every auth-shaped key shape is skipped entirely, never landing in the
    /// parsed struct in any form.
    #[test]
    fn test_parse_npmrc_raw_skips_auth_shaped_keys() {
        let content = concat!(
            "_authToken=super-secret-token\n",
            "_auth=another-secret\n",
            "_password=hunter2\n",
            "_authIdent=me:hunter2\n",
            "always-auth=true\n",
            "//registry.example.com/:_authToken=scoped-secret\n",
            "//registry.example.com/:_password=scoped-password\n",
            "registry=https://npm.example/\n",
        );
        let raw = parse_npmrc_raw(content);
        assert_eq!(raw.registry.as_deref(), Some("https://npm.example/"));
        assert!(raw.scoped.is_empty());

        // Structural guarantee: `RawNpmrc` (and therefore `NpmConfig`) has no field capable
        // of holding any of the values above at all — this assertion is the closest a test
        // can get to proving that without reading the source, by confirming none of the
        // secret strings appears anywhere in the parsed struct's debug output.
        //
        // The assert message deliberately names only the *label*, never the secret value
        // itself — echoing the literal fixture string into a panic/format output is exactly
        // the "secret in a log" pattern this test exists to rule out, and CodeQL's cleartext-
        // logging query flags it even in test code that's asserting the value's *absence*.
        let debug = format!("{raw:?}");
        for (label, secret) in [
            ("_authToken", "super-secret-token"),
            ("_auth", "another-secret"),
            ("_password", "hunter2"),
            ("scoped _authToken", "scoped-secret"),
            ("scoped _password", "scoped-password"),
        ] {
            assert!(
                !debug.contains(secret),
                "{label}'s value leaked into parsed config Debug output"
            );
        }
    }

    /// M6: scope keys are byte-exact, no case folding.
    #[test]
    fn test_parse_npmrc_raw_scope_key_no_case_folding() {
        let content = "@MyOrg:registry=https://npm.example/\n";
        let raw = parse_npmrc_raw(content);
        assert!(raw.scoped.contains_key("@MyOrg"));
        assert!(!raw.scoped.contains_key("@myorg"));
    }

    // --- expand_env_vars (FR-007) ---

    #[test]
    fn test_expand_env_vars_no_placeholder() {
        assert_eq!(
            expand_env_vars_with("https://npm.example/", |_| None),
            Ok("https://npm.example/".to_string())
        );
    }

    #[test]
    fn test_expand_env_vars_defined() {
        let result = expand_env_vars_with("${NPM_REGISTRY}/", |name| {
            (name == "NPM_REGISTRY").then(|| "https://npm.mycorp.example".to_string())
        });
        assert_eq!(result, Ok("https://npm.mycorp.example/".to_string()));
    }

    #[test]
    fn test_expand_env_vars_undefined() {
        let result = expand_env_vars_with("${UNDEFINED_VAR}", |_| None);
        assert_eq!(result, Err("UNDEFINED_VAR".to_string()));
    }

    // --- resolve_entry / NpmConfig::resolve_source_for (FR-003–008) ---

    #[test]
    fn test_resolve_entry_undefined_var_is_invalid() {
        let policy = all_policy();
        let result = resolve_entry("${UNDEFINED_VAR}", &policy);
        assert_matches!(
            result,
            Err(InvalidEntry {
                reason: NpmRegistryIndexError::UndefinedEnvVar(_),
                ..
            })
        );
        assert_eq!(result.unwrap_err().raw, "${UNDEFINED_VAR}");
    }

    /// S-1 regression: a rejected entry's error must report the raw `${VAR}`-referencing
    /// text, never the expanded value — an expanded value can carry an environment
    /// variable's contents (e.g. a token embedded in a query string), so leaking it into
    /// `NpmRegistryIndexError::BlockedHost`'s `tracing::warn!` or into `InvalidUrl`'s payload
    /// would defeat the whole point of never logging the expanded form (this module's
    /// security-model doc, `InvalidEntry`'s doc). `expand_env_vars` cannot be exercised here
    /// without mutating the real process environment (forbidden — see
    /// `expand_env_vars_with`'s doc), so this drives `new_for_log` directly with the two
    /// strings `resolve_entry` would have passed it after a real `${VAR}` expansion.
    #[test]
    fn test_new_for_log_blocked_host_reports_raw_not_expanded() {
        let expanded_secret = "https://127.0.0.1:9999/?token=super-secret-value";
        let raw_placeholder = "${SECRET_REGISTRY_URL}";
        let policy = public_only_policy();

        // `BlockedHost`'s own `Display` never carries the URL at all (only the host
        // class) — the actual leak this guards against is the `tracing::warn!` emitted
        // from inside `new_for_log`, so this must inspect the captured log line itself,
        // not just the returned error's rendering.
        let log = deps_core::test_util::capture_tracing_output(|| {
            let err = NpmRegistryIndex::new_for_log(expanded_secret, raw_placeholder, &policy)
                .unwrap_err();
            assert_matches!(err, NpmRegistryIndexError::BlockedHost { .. });
        });

        assert!(
            !log.contains("super-secret-value"),
            "leaked expanded secret into tracing output: {log:?}"
        );
        assert!(
            log.contains(raw_placeholder),
            "expected the raw placeholder in tracing output: {log:?}"
        );
    }

    #[test]
    fn test_new_for_log_invalid_url_reports_raw_not_expanded() {
        let expanded_secret = "not a valid url but contains super-secret-value";
        let raw_placeholder = "${SECRET_VAR}";
        let policy = all_policy();

        let err =
            NpmRegistryIndex::new_for_log(expanded_secret, raw_placeholder, &policy).unwrap_err();

        assert_eq!(
            err,
            NpmRegistryIndexError::InvalidUrl(raw_placeholder.to_string())
        );
        assert!(!err.to_string().contains("super-secret-value"));
    }

    /// #522: a literal `user:pass@` written directly in `.npmrc` (no `${VAR}` expansion
    /// involved) must never reach `resolve_entry`'s `tracing::warn!` line or
    /// `InvalidEntry::raw` unredacted — mirrors `deps-pypi`'s M1 fix test.
    #[test]
    fn test_resolve_entry_redacts_literal_userinfo_from_raw_and_log() {
        let policy = all_policy();
        let log = deps_core::test_util::capture_tracing_output(|| {
            let invalid = resolve_entry("https://user:hunter2@npm.example/", &policy).unwrap_err();
            assert_matches!(invalid.reason, NpmRegistryIndexError::UserInfoPresent);
            assert!(
                !invalid.raw.contains("hunter2"),
                "InvalidEntry::raw leaked the credential: {}",
                invalid.raw
            );
            assert!(
                !invalid.raw.contains("user:"),
                "InvalidEntry::raw leaked the username: {}",
                invalid.raw
            );
            assert!(
                invalid.raw.contains("npm.example"),
                "host should survive redaction"
            );
        });
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
    }

    /// S1: a userinfo-bearing `.npmrc` value that also fails `Url::parse` for an unrelated
    /// reason (an invalid port here) lands in `NpmRegistryIndexError::InvalidUrl`, not
    /// `UserInfoPresent` — this is the shape `redact_userinfo`'s original parse-gated no-op
    /// missed, so the credential must be checked in every channel: `InvalidEntry::raw`, the
    /// `%reason` `Display`, and the captured log.
    #[test]
    fn test_resolve_entry_redacts_literal_userinfo_from_unparseable_raw() {
        let policy = all_policy();
        let log = deps_core::test_util::capture_tracing_output(|| {
            let invalid =
                resolve_entry("https://user:hunter2@npm.example:99999/", &policy).unwrap_err();
            assert_matches!(invalid.reason, NpmRegistryIndexError::InvalidUrl(_));
            assert!(
                !invalid.raw.contains("hunter2"),
                "InvalidEntry::raw leaked the credential: {}",
                invalid.raw
            );
            assert!(
                !invalid.reason.to_string().contains("hunter2"),
                "reason Display leaked the credential: {}",
                invalid.reason
            );
        });
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
    }

    #[test]
    fn test_resolve_source_for_no_config_is_public_registry() {
        let config = NpmConfig::default();
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::Registry
        );
    }

    /// FR-003: a top-level override rewrites every unscoped dependency.
    #[test]
    fn test_resolve_source_for_top_level_override() {
        let policy = all_policy();
        let config = NpmConfig {
            registry: Some(resolve_entry("https://npm.mycorp.example", &policy)),
            scoped_registries: HashMap::new(),
        };
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.mycorp.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    /// FR-004/NFR-006: the scope-specific entry wins over a conflicting top-level override.
    #[test]
    fn test_resolve_source_for_scope_wins_over_top_level() {
        let policy = all_policy();
        let mut scoped = HashMap::new();
        scoped.insert(
            "@myorg".to_string(),
            resolve_entry("https://npm.pkg.github.com", &policy),
        );
        let config = NpmConfig {
            registry: Some(resolve_entry("https://npm.mycorp.example", &policy)),
            scoped_registries: scoped,
        };
        assert_eq!(
            config.resolve_source_for(&pkg("@myorg/internal-lib")),
            DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            }
        );
        // An unrelated scope, and an unscoped name, still fall through to the top-level
        // override (FR-005 does not apply here — that override *does* resolve).
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.mycorp.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    /// FR-005: a scope with no matching entry is the normal case, not FR-006's fail-closed
    /// one — falls through to the public registry when no top-level override exists either.
    #[test]
    fn test_resolve_source_for_unmatched_scope_falls_back_to_public() {
        let config = NpmConfig::default();
        assert_eq!(
            config.resolve_source_for(&pkg("@othersope/pkg")),
            DependencySource::Registry
        );
    }

    /// FR-006/US-004/SC-004: an invalid entry becomes `CustomRegistry`, never a silent
    /// fall-through to the public registry — the npm form of issue #248.
    #[test]
    fn test_resolve_source_for_invalid_scope_fails_closed() {
        let policy = all_policy();
        let mut scoped = HashMap::new();
        scoped.insert(
            "@myorg".to_string(),
            resolve_entry("not-a-valid-url", &policy),
        );
        let config = NpmConfig {
            registry: None,
            scoped_registries: scoped,
        };
        assert_eq!(
            config.resolve_source_for(&pkg("@myorg/internal-lib")),
            DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
    }

    #[test]
    fn test_resolved_registries_dedups_and_skips_invalid() {
        let policy = all_policy();
        let mut scoped = HashMap::new();
        scoped.insert(
            "@myorg".to_string(),
            resolve_entry("https://npm.pkg.github.com", &policy),
        );
        scoped.insert(
            "@other".to_string(),
            resolve_entry("https://npm.pkg.github.com/", &policy), // same index, trailing slash
        );
        scoped.insert("@bad".to_string(), resolve_entry("not-a-url", &policy));
        let config = NpmConfig {
            registry: Some(resolve_entry("https://npm.pkg.github.com", &policy)),
            scoped_registries: scoped,
        };
        let resolved = config.resolved_registries();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].as_str(), "https://npm.pkg.github.com");
    }

    // --- resolve / resolve_with_home (FR-002, M9) ---

    #[test]
    fn test_resolve_with_home_no_npmrc_anywhere_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(dir.path(), &cache, &policy, None);
        assert!(config.resolved_registries().is_empty());
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::Registry
        );
    }

    #[test]
    fn test_resolve_with_home_project_tier_applies() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".npmrc"),
            "registry=https://npm.mycorp.example\n",
        )
        .unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(dir.path(), &cache, &policy, None);
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.mycorp.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    /// FR-002: project tier overrides user tier.
    #[test]
    fn test_resolve_with_home_project_overrides_user() {
        let project_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().join(".npmrc"),
            "registry=https://npm.project.example\n",
        )
        .unwrap();
        std::fs::write(
            home_dir.path().join(".npmrc"),
            "registry=https://npm.user.example\n",
        )
        .unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(
            project_dir.path(),
            &cache,
            &policy,
            Some(home_dir.path().to_path_buf()),
        );
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.project.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    #[test]
    fn test_resolve_with_home_user_tier_applies_when_no_project_tier() {
        let project_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            home_dir.path().join(".npmrc"),
            "registry=https://npm.user.example\n",
        )
        .unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(
            project_dir.path(),
            &cache,
            &policy,
            Some(home_dir.path().to_path_buf()),
        );
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.user.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    /// M9: a project living directly under the (fixture) home directory must not
    /// double-count `~/.npmrc` as its own project-tier entry — deduped by canonicalized
    /// path, so the single file is read once and applied once.
    #[test]
    fn test_resolve_with_home_dedupes_ancestor_matching_user_tier() {
        let home_dir = tempfile::tempdir().unwrap();
        let project_dir = home_dir.path().join("project");
        std::fs::create_dir(&project_dir).unwrap();
        std::fs::write(
            home_dir.path().join(".npmrc"),
            "registry=https://npm.user.example\n",
        )
        .unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(
            &project_dir,
            &cache,
            &policy,
            Some(home_dir.path().to_path_buf()),
        );
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::AlternateRegistry {
                index: "https://npm.user.example".to_string(),
                mirrors_crates_io: false,
            }
        );
    }

    #[test]
    fn test_resolve_with_home_empty_npmrc_is_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".npmrc"), "# just a comment\n").unwrap();
        let cache = NpmConfigCache::new();
        let policy = all_policy();
        let config = resolve_with_home(dir.path(), &cache, &policy, None);
        assert_eq!(
            config.resolve_source_for(&pkg("express")),
            DependencySource::Registry
        );
    }

    // --- NpmConfigCache (FR-012/NFR-004) ---

    #[test]
    fn test_config_cache_reparses_after_mtime_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".npmrc");
        std::fs::write(&path, "registry=https://npm.one.example\n").unwrap();
        let cache = NpmConfigCache::new();
        let first = cache.get_or_parse(&path).unwrap();
        assert_eq!(first.registry.as_deref(), Some("https://npm.one.example"));

        // Ensure a distinguishable mtime on filesystems with coarse timestamp resolution.
        let future = SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(&path, "registry=https://npm.two.example\n").unwrap();
        // `File::open` is read-only, which lacks `FILE_WRITE_ATTRIBUTES` on Windows and
        // makes `set_modified` fail with `PermissionDenied`; open for write instead.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let second = cache.get_or_parse(&path).unwrap();
        assert_eq!(second.registry.as_deref(), Some("https://npm.two.example"));
        assert!(!Arc::ptr_eq(&first, &second));
    }
}
