//! `.cargo/config.toml` discovery and `[registries.*]` resolution.
//!
//! Resolves a Cargo `registry = "<alias>"` dependency's alias into a concrete, fetchable
//! sparse index URL by reading the same `.cargo/config.toml` hierarchy (and
//! `$CARGO_HOME/config.toml`) Cargo itself consults, plus the
//! `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN` environment variable overrides Cargo
//! documents.
//!
//! # Security model (read before touching this module)
//!
//! A workspace's own `Cargo.toml`/`.cargo/config.toml` is attacker-controlled the moment a
//! hostile repository is cloned and opened — this LSP parses on file open, before any
//! build ever runs. [`AuthToken`] must therefore never be attachable to a request whose
//! destination URL provenance traces to a workspace file. This is enforced **structurally**,
//! not by a runtime check:
//!
//! - `parse_workspace_registries` has no parameter, return type, or code path capable of
//!   producing `Some(AuthToken)` — every [`ResolvedRegistryEntry`] it builds hardcodes
//!   `auth: None`. There is no `token` field lookup anywhere in that function's body.
//! - Only `parse_cargo_home_registries` (fed `$CARGO_HOME/config.toml`'s content) and the
//!   environment-variable lookup in [`resolve`] ever construct `Some(AuthToken)`.
//! - [`Provenance`] exists purely for logging/diagnostics. Nothing in this crate branches
//!   on it to decide whether to attach a credential — grepping for `Provenance` outside
//!   this module should find no such branch (verified in this PR's security review).
//!
//! See spec `.local/specs/023-cargo-custom-registries/spec.md` FR-008/FR-009 and the design
//! review handoffs cited there for the two rounds of critique this boundary survived.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use toml_span::value::Table;

/// A registry bearer-token credential, redacted everywhere except the one call site that
/// formats it into an `Authorization` header.
///
/// Constructible only from within this module (see the module-level security-model docs) —
/// no other code path in this crate has the means to produce one. `Debug`/`Display` are
/// hand-implemented to redact the value so it cannot leak via a log line, a panic message,
/// or an error's `Display` output.
#[derive(Clone)]
pub struct AuthToken(String);

impl AuthToken {
    /// Wraps `token`. Kept `pub(crate)` rather than `pub`: the module-level security-model
    /// docs above are the enforcement, and widening this to `pub` would let any other crate
    /// construct one with no `Provenance` to account for at all.
    pub(crate) fn new(token: String) -> Self {
        Self(token)
    }

    /// The raw token value, for building an `Authorization` header. Never logged, printed,
    /// or otherwise surfaced — callers must not pass this to anything but a header value.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(***)")
    }
}

impl std::fmt::Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Where a [`ResolvedRegistryEntry`] came from.
///
/// **Diagnostics and logging only.** Never gates whether [`ResolvedRegistryEntry::auth`]
/// is populated — that is a structural property of which parsing function produced the
/// entry (see the module-level docs), not a runtime branch on this enum. A future change
/// that starts branching on this to decide whether to attach a credential reintroduces the
/// exact vulnerability class this design closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Resolved from `$CARGO_HOME/config.toml` or a `CARGO_REGISTRIES_*` environment
    /// variable — the user's own trusted environment, not something a cloned repository
    /// controls.
    CargoHome,
    /// Resolved from a `.cargo/config.toml` found while walking up from the opened
    /// manifest's directory — a file a repository being opened can fully control.
    Workspace,
}

/// Whether `url`'s host is loopback (`127.0.0.1`, `localhost`, or `::1`) with an `http`
/// scheme — the shape every `mockito::Server` binds to.
///
/// Only compiled into test builds (see [`RegistryIndex::new`]'s use of this): a
/// non-loopback host must never be allowed to bypass the https requirement, even under
/// `cfg(test)`/`test-util` — mirrors `deps_core::cache`'s identical `is_loopback_host`
/// precedent for `HttpCache::ensure_https`.
#[cfg(any(test, feature = "test-util"))]
fn is_loopback_url(url: &url::Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
}

/// A validated, `sparse+`-prefix-stripped sparse-index URL: `https` scheme, no userinfo.
///
/// Validated at construction so an invalid or unsafe URL (`http://`, a scheme other than
/// `sparse+https`, or one carrying a `user:pass@` component) can never reach a network call
/// — this is SSRF-adjacent input, since a workspace file controls a network destination
/// (spec NFR-002).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryIndex(url::Url);

/// Why a candidate index URL failed [`RegistryIndex::new`]'s validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryIndexError {
    /// The value did not parse as a URL at all (after stripping a `sparse+` prefix).
    #[error("not a valid URL: {0}")]
    InvalidUrl(String),
    /// The URL's scheme is not `https`.
    #[error("registry index must use https, got scheme {0:?}")]
    NotHttps(String),
    /// The URL carries a `user:pass@`/`user@` component.
    #[error("registry index URL must not carry userinfo")]
    UserInfoPresent,
}

impl RegistryIndex {
    /// Validates and wraps `raw` — a `registry-index` manifest value or a
    /// `.cargo/config.toml` `[registries.<name>].index` value, either optionally prefixed
    /// with `sparse+`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryIndexError`] if `raw` does not parse as a URL, is not `https`, or
    /// carries a userinfo component.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cargo::config::RegistryIndex;
    ///
    /// assert!(RegistryIndex::new("sparse+https://index.mycorp.dev").is_ok());
    /// assert!(RegistryIndex::new("http://index.mycorp.dev").is_err());
    /// assert!(RegistryIndex::new("https://user:pass@index.mycorp.dev").is_err());
    /// ```
    pub fn new(raw: &str) -> Result<Self, RegistryIndexError> {
        let stripped = raw.strip_prefix("sparse+").unwrap_or(raw);
        let url = url::Url::parse(stripped)
            .map_err(|_| RegistryIndexError::InvalidUrl(stripped.to_string()))?;
        let is_https = url.scheme() == "https";
        #[cfg(any(test, feature = "test-util"))]
        let is_https = is_https || is_loopback_url(&url);
        if !is_https {
            return Err(RegistryIndexError::NotHttps(url.scheme().to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RegistryIndexError::UserInfoPresent);
        }
        Ok(Self(url))
    }

    /// The validated URL as a string, with no trailing slash guarantee either way (callers
    /// splicing a path onto this must trim as needed — see `sparse::sparse_index_url`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for RegistryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One resolved `[registries.<name>]` entry.
#[derive(Debug, Clone)]
pub struct ResolvedRegistryEntry {
    /// The validated, fetchable index URL.
    pub index: RegistryIndex,
    /// The bearer token to attach to requests against `index`, if any. `Some` only when
    /// `provenance` is [`Provenance::CargoHome`] — see the module-level security-model
    /// docs for why this is a structural, not runtime, guarantee.
    pub auth: Option<AuthToken>,
    /// Where this entry was resolved from. Diagnostics/logging only.
    pub provenance: Provenance,
}

/// The merged, resolved view of a workspace's `.cargo/config.toml` hierarchy plus
/// `$CARGO_HOME/config.toml`, for the aliases a manifest actually referenced.
///
/// Built by [`resolve`] — this type itself is a plain lookup table with no resolution
/// logic of its own, so a caller holding one can check [`Self::get`] without needing to
/// know anything about tiers, precedence, or the environment.
#[derive(Debug, Default)]
pub struct CargoConfig {
    registries: HashMap<String, ResolvedRegistryEntry>,
}

impl CargoConfig {
    /// The resolved entry for `alias`, if it resolved successfully.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&ResolvedRegistryEntry> {
        self.registries.get(alias)
    }
}

/// Collects every `.cargo/config.toml` between `start_dir` and the filesystem root.
///
/// Ordered closest-to-`start_dir` first — Cargo's own config-merge order, where a value
/// from a closer directory takes precedence over one farther away.
///
/// Deliberately a separate walk from `crate::parser::find_workspace_root`'s (rather than
/// extending that function to also collect these paths): `find_workspace_root` runs
/// unconditionally for every `Cargo.toml` parse, so folding an unconditional
/// `.cargo/config.toml` existence check into it would regress spec NFR-004 (zero
/// additional filesystem reads when no dependency needs alternate-registry resolution).
/// This function is called lazily, only once a manifest is known to declare at least one
/// `registry`/`registry-index` value.
#[must_use]
pub fn discover_workspace_config_paths(start_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let candidate = dir.join(".cargo").join("config.toml");
        if candidate.is_file() {
            paths.push(candidate);
        }
        current = dir.parent();
    }
    paths
}

/// `$CARGO_HOME/config.toml`'s path, or `None` if `$CARGO_HOME` is not set.
///
/// Deliberately reads only the `CARGO_HOME` environment variable — no fallback to
/// `$HOME`/`%USERPROFILE%` when it is unset (spec FR-004), and no `dirs`/`home` crate
/// dependency added to compute one.
#[must_use]
pub fn cargo_home_config_path() -> Option<PathBuf> {
    cargo_home_config_path_with_env(|name| std::env::var_os(name))
}

/// [`cargo_home_config_path`], but reading the environment through `env` instead of
/// [`std::env::var_os`] directly — lets tests inject a fake environment instead of
/// mutating the real (`unsafe`-only, since Rust 2024) process environment.
fn cargo_home_config_path_with_env(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    env("CARGO_HOME").map(|home| PathBuf::from(home).join("config.toml"))
}

/// Parses a table value's `index` field into a validated [`RegistryIndex`], warning and
/// returning `None` on any failure (missing field, not a string, or failed validation).
fn parse_index_field(
    alias: &str,
    entry: &Table<'_>,
    warn_context: &'static str,
) -> Option<RegistryIndex> {
    let index_str = entry.get("index").and_then(|v| v.as_str())?;
    match RegistryIndex::new(index_str) {
        Ok(index) => Some(index),
        Err(error) => {
            tracing::warn!(alias, %error, warn_context, "registry index failed validation");
            None
        }
    }
}

/// Parses a workspace-declared `.cargo/config.toml`'s `[registries.<name>]` table into
/// index-only entries.
///
/// **Never reads a `token` field, under any key.** This is the structural half of the
/// auth-provenance guarantee described in the module docs: a workspace-sourced
/// [`ResolvedRegistryEntry`] is constructed with `auth: None` unconditionally, by a
/// function whose body contains no code path that could do otherwise.
fn parse_workspace_registries(content: &str) -> HashMap<String, ResolvedRegistryEntry> {
    let mut out = HashMap::new();
    if deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH).is_err() {
        tracing::warn!("skipping .cargo/config.toml: nesting depth exceeds maximum");
        return out;
    }
    let Ok(doc) = toml_span::parse(content) else {
        return out;
    };
    let Some(registries) = doc
        .as_table()
        .and_then(|t| t.get("registries"))
        .and_then(|v| v.as_table())
    else {
        return out;
    };
    for (key, value) in registries {
        let alias = key.name.to_string();
        let Some(entry) = value.as_table() else {
            continue;
        };
        if let Some(index) = parse_index_field(&alias, entry, "workspace") {
            out.insert(
                alias,
                ResolvedRegistryEntry {
                    index,
                    auth: None,
                    provenance: Provenance::Workspace,
                },
            );
        }
    }
    out
}

/// Parses `$CARGO_HOME/config.toml`'s `[registries.<name>]` table into entries carrying an
/// optional token from that same file's `token` field — the one function in this module
/// permitted to construct a populated [`AuthToken`], since its input is, by construction,
/// always `$CARGO_HOME`-sourced.
fn parse_cargo_home_registries(content: &str) -> HashMap<String, ResolvedRegistryEntry> {
    let mut out = HashMap::new();
    if deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH).is_err() {
        tracing::warn!("skipping $CARGO_HOME/config.toml: nesting depth exceeds maximum");
        return out;
    }
    let Ok(doc) = toml_span::parse(content) else {
        return out;
    };
    let Some(registries) = doc
        .as_table()
        .and_then(|t| t.get("registries"))
        .and_then(|v| v.as_table())
    else {
        return out;
    };
    for (key, value) in registries {
        let alias = key.name.to_string();
        let Some(entry) = value.as_table() else {
            continue;
        };
        let Some(index) = parse_index_field(&alias, entry, "cargo_home") else {
            continue;
        };
        let auth = entry
            .get("token")
            .and_then(|v| v.as_str())
            .map(|t| AuthToken::new(t.to_string()));
        out.insert(
            alias,
            ResolvedRegistryEntry {
                index,
                auth,
                provenance: Provenance::CargoHome,
            },
        );
    }
    out
}

/// Cargo's env-var naming convention for a registry setting: uppercase the alias and
/// replace every `-` with `_` (Cargo does the same substitution, which is exactly why two
/// spellings of "the same" alias can collide — see spec FR-015).
fn env_var_name(alias: &str, suffix: &str) -> String {
    let screaming = alias.to_uppercase().replace('-', "_");
    format!("CARGO_REGISTRIES_{screaming}_{suffix}")
}

/// Resolves `referenced_aliases` against the `.cargo/config.toml` hierarchy and
/// `$CARGO_HOME/config.toml`.
///
/// `referenced_aliases` is every distinct `registry = "<alias>"` value this manifest's
/// dependencies declared; `workspace_config_paths` comes from
/// [`discover_workspace_config_paths`] (closest-first); `cargo_home_config_path` from
/// [`cargo_home_config_path`]. Also applies `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN`
/// environment overrides.
///
/// # Precedence
///
/// For one alias: the closest workspace `.cargo/config.toml` entry wins outright — if it
/// resolves, the `$CARGO_HOME` tier (config file and environment variables alike) is never
/// consulted for that alias at all. This is a deliberate divergence from Cargo's own
/// env-beats-all-config-files precedence: since environment variables and
/// `$CARGO_HOME/config.toml` are folded into one `$CARGO_HOME`-provenance tier here, an
/// environment variable can never resurrect a credential for an alias a workspace file has
/// shadowed (spec FR-009/US-004) — see the module-level security-model docs.
///
/// # Examples
///
/// ```
/// use deps_cargo::config::resolve;
/// use std::collections::HashSet;
///
/// let aliases: HashSet<String> = std::iter::once("unconfigured".to_string()).collect();
/// let config = resolve(&aliases, &[], None);
/// assert!(config.get("unconfigured").is_none());
/// ```
#[must_use]
pub fn resolve(
    referenced_aliases: &HashSet<String>,
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&Path>,
) -> CargoConfig {
    resolve_with_env(
        referenced_aliases,
        workspace_config_paths,
        cargo_home_config_path,
        &|name| std::env::var(name).ok(),
    )
}

/// [`resolve`], but reading environment variables through `env` instead of
/// [`std::env::var`] directly — lets tests inject a fake environment instead of mutating
/// the real process environment (this workspace forbids `unsafe`, and Rust 2024 made
/// `std::env::set_var`/`remove_var` `unsafe fn`s, so a test cannot do that mutation at
/// all). Production callers always go through [`resolve`].
fn resolve_with_env(
    referenced_aliases: &HashSet<String>,
    workspace_config_paths: &[PathBuf],
    cargo_home_config_path: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> CargoConfig {
    // A project living under `$HOME` (the default `CARGO_HOME=~/.cargo` layout) has
    // `$HOME` as an ancestor directory, so `discover_workspace_config_paths`'s
    // unbounded upward walk finds `~/.cargo/config.toml` too — the *same file* as
    // `$CARGO_HOME/config.toml`. Left uncompared, that file would be double-counted as
    // a workspace-tier entry, which wins outright over the real `$CARGO_HOME` tier
    // (see the alias loop below) and silently drops its token: the registry still
    // resolves, just unauthenticated, so the bug looks like success. Comparing
    // canonicalized paths (not just string equality) also catches a symlinked
    // `$CARGO_HOME`.
    let cargo_home_canonical = cargo_home_config_path.and_then(|p| std::fs::canonicalize(p).ok());
    let workspace_tiers: Vec<HashMap<String, ResolvedRegistryEntry>> = workspace_config_paths
        .iter()
        .filter(|path| {
            std::fs::canonicalize(path).ok().as_deref() != cargo_home_canonical.as_deref()
        })
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|content| parse_workspace_registries(&content))
        .collect();

    let cargo_home_tier: HashMap<String, ResolvedRegistryEntry> = cargo_home_config_path
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|content| parse_cargo_home_registries(&content))
        .unwrap_or_default();

    // FR-015: two distinct alias spellings deriving the same env-var name (e.g.
    // "my-corp"/"my_corp" both -> CARGO_REGISTRIES_MY_CORP_INDEX) must not let either one
    // pick up an env override meant for the other. Detected once, up front, over the whole
    // referenced-alias set, rather than per-alias — a per-alias check would have nothing to
    // compare against.
    let mut env_name_to_aliases: HashMap<String, Vec<&String>> = HashMap::new();
    for alias in referenced_aliases {
        env_name_to_aliases
            .entry(env_var_name(alias, "INDEX"))
            .or_default()
            .push(alias);
    }
    let env_collided: HashSet<&str> = env_name_to_aliases
        .values()
        .filter(|aliases| aliases.len() > 1)
        .flat_map(|aliases| {
            let names: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
            tracing::warn!(
                aliases = ?names,
                "two aliases derive the same CARGO_REGISTRIES_*_INDEX/_TOKEN environment \
                 variable name; ignoring the environment override for all of them"
            );
            names
        })
        .collect();

    let mut registries = HashMap::new();
    for alias in referenced_aliases {
        if let Some(entry) = workspace_tiers.iter().find_map(|tier| tier.get(alias)) {
            registries.insert(alias.clone(), entry.clone());
            continue;
        }

        if let Some(entry) = resolve_cargo_home_tier(
            alias,
            &cargo_home_tier,
            !env_collided.contains(alias.as_str()),
            env,
        ) {
            registries.insert(alias.clone(), entry);
        }
    }

    CargoConfig { registries }
}

/// Resolves one alias against the `$CARGO_HOME` tier: an environment-variable override
/// first (when `env_allowed`), then `$CARGO_HOME/config.toml`'s own entry.
fn resolve_cargo_home_tier(
    alias: &str,
    cargo_home_tier: &HashMap<String, ResolvedRegistryEntry>,
    env_allowed: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<ResolvedRegistryEntry> {
    if env_allowed && let Some(index_override) = env(&env_var_name(alias, "INDEX")) {
        match RegistryIndex::new(&index_override) {
            Ok(index) => {
                let auth = env(&env_var_name(alias, "TOKEN"))
                    .map(AuthToken::new)
                    .or_else(|| {
                        cargo_home_tier
                            .get(alias)
                            .and_then(|entry| entry.auth.clone())
                    });
                return Some(ResolvedRegistryEntry {
                    index,
                    auth,
                    provenance: Provenance::CargoHome,
                });
            }
            Err(error) => {
                tracing::warn!(alias, %error, "CARGO_REGISTRIES_*_INDEX environment override failed validation");
            }
        }
    }

    let mut entry = cargo_home_tier.get(alias).cloned()?;
    if env_allowed && let Some(token_override) = env(&env_var_name(alias, "TOKEN")) {
        entry.auth = Some(AuthToken::new(token_override));
    }
    Some(entry)
}

/// Every distinct alias `dependencies` declares via `registry = "<alias>"`.
///
/// This is the input [`resolve`] needs to know which aliases are actually worth
/// resolving, so config discovery is skipped entirely (spec NFR-004) when this is empty.
#[must_use]
pub fn referenced_aliases(dependencies: &[crate::types::ParsedDependency]) -> HashSet<String> {
    dependencies
        .iter()
        .filter_map(|dep| match &dep.source {
            deps_core::parser::DependencySource::CustomRegistry { url } => Some(url.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_index_strips_sparse_prefix() {
        let index = RegistryIndex::new("sparse+https://index.mycorp.dev").unwrap();
        assert_eq!(index.as_str(), "https://index.mycorp.dev/");
    }

    #[test]
    fn test_registry_index_rejects_http() {
        assert!(matches!(
            RegistryIndex::new("http://index.mycorp.dev"),
            Err(RegistryIndexError::NotHttps(_))
        ));
    }

    #[test]
    fn test_registry_index_rejects_userinfo() {
        assert!(matches!(
            RegistryIndex::new("https://user:pass@index.mycorp.dev"),
            Err(RegistryIndexError::UserInfoPresent)
        ));
    }

    #[test]
    fn test_registry_index_rejects_bare_username() {
        assert!(matches!(
            RegistryIndex::new("https://user@index.mycorp.dev"),
            Err(RegistryIndexError::UserInfoPresent)
        ));
    }

    #[test]
    fn test_registry_index_rejects_invalid_url() {
        assert!(matches!(
            RegistryIndex::new("not a url"),
            Err(RegistryIndexError::InvalidUrl(_))
        ));
    }

    #[test]
    fn test_registry_index_accepts_https_without_sparse_prefix() {
        assert!(RegistryIndex::new("https://index.mycorp.dev").is_ok());
    }

    #[test]
    fn test_auth_token_debug_and_display_redact() {
        let token = AuthToken::new("super-secret-value".to_string());
        assert_eq!(format!("{token:?}"), "AuthToken(***)");
        assert_eq!(format!("{token}"), "***");
        assert!(!format!("{token:?}").contains("super-secret-value"));
    }

    #[test]
    fn test_parse_workspace_registries_never_populates_auth() {
        let content = r#"
[registries.my-corp]
index = "sparse+https://index.mycorp.dev"
token = "should-be-ignored"
"#;
        let result = parse_workspace_registries(content);
        let entry = result.get("my-corp").unwrap();
        assert!(
            entry.auth.is_none(),
            "workspace-sourced entry must never carry a token"
        );
        assert_eq!(entry.provenance, Provenance::Workspace);
    }

    #[test]
    fn test_parse_cargo_home_registries_reads_token() {
        let content = r#"
[registries.my-corp]
index = "sparse+https://index.mycorp.dev"
token = "secret-token"
"#;
        let result = parse_cargo_home_registries(content);
        let entry = result.get("my-corp").unwrap();
        assert_eq!(entry.auth.as_ref().unwrap().as_str(), "secret-token");
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    #[test]
    fn test_parse_registries_skips_invalid_index() {
        let content = r#"
[registries.my-corp]
index = "http://index.mycorp.dev"
"#;
        assert!(parse_workspace_registries(content).is_empty());
        assert!(parse_cargo_home_registries(content).is_empty());
    }

    #[test]
    fn test_parse_registries_malformed_toml_fails_closed() {
        let content = "this is [ not valid toml";
        assert!(parse_workspace_registries(content).is_empty());
        assert!(parse_cargo_home_registries(content).is_empty());
    }

    #[test]
    fn test_parse_registries_rejects_excessive_nesting() {
        let content = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        assert!(parse_workspace_registries(&content).is_empty());
        assert!(parse_cargo_home_registries(&content).is_empty());
    }

    #[test]
    fn test_discover_workspace_config_paths_finds_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let mid = root.path().join("mid");
        let leaf = mid.join("leaf");
        std::fs::create_dir_all(&leaf).unwrap();

        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.root-level]\nindex = \"sparse+https://root.example\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(mid.join(".cargo")).unwrap();
        std::fs::write(
            mid.join(".cargo/config.toml"),
            "[registries.mid-level]\nindex = \"sparse+https://mid.example\"\n",
        )
        .unwrap();

        let paths = discover_workspace_config_paths(&leaf);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], mid.join(".cargo/config.toml"), "closest first");
        assert_eq!(paths[1], root.path().join(".cargo/config.toml"));
    }

    #[test]
    fn test_discover_workspace_config_paths_empty_when_none_exist() {
        let root = tempfile::tempdir().unwrap();
        assert!(discover_workspace_config_paths(root.path()).is_empty());
    }

    #[test]
    fn test_cargo_home_config_path_none_when_unset() {
        assert!(cargo_home_config_path_with_env(|_| None).is_none());
    }

    #[test]
    fn test_cargo_home_config_path_some_when_set() {
        let path = cargo_home_config_path_with_env(|name| {
            (name == "CARGO_HOME").then(|| std::ffi::OsString::from("/home/user/.cargo"))
        });
        assert_eq!(path, Some(PathBuf::from("/home/user/.cargo/config.toml")));
    }

    #[test]
    fn test_resolve_workspace_wins_over_cargo_home() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://workspace.example\"\n",
        )
        .unwrap();

        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let config = resolve(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            Some(&cargo_home.path().join("config.toml")),
        );

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://workspace.example/");
        assert!(
            entry.auth.is_none(),
            "workspace-shadowed entry must never carry the cargo-home token"
        );
        assert_eq!(entry.provenance, Provenance::Workspace);
    }

    /// Regression: a project living under `$HOME` (the default `CARGO_HOME=~/.cargo`
    /// layout) has `discover_workspace_config_paths` walk right past `$HOME` and pick up
    /// `~/.cargo/config.toml` — the *same file* as `$CARGO_HOME/config.toml` — as a
    /// workspace-tier candidate. Before the canonicalized-path exclusion, that duplicate
    /// entry won the workspace-tier-always-wins precedence and silently dropped the
    /// token: the alias still resolved, just unauthenticated, which looks like success.
    #[test]
    fn test_resolve_home_nested_project_does_not_lose_cargo_home_token() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".cargo")).unwrap();
        let cargo_home_config = home.path().join(".cargo/config.toml");
        std::fs::write(
            &cargo_home_config,
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let project_dir = home.path().join("projects").join("myapp");
        std::fs::create_dir_all(&project_dir).unwrap();

        // The real discovery function, not a hand-picked path list: this is what
        // actually reproduces the bug — the ancestor walk from `project_dir` finds
        // `home/.cargo/config.toml` on the way up to the filesystem root.
        let workspace_paths = discover_workspace_config_paths(&project_dir);
        assert!(
            workspace_paths.contains(&cargo_home_config),
            "test setup must reproduce the ancestor-walk collision"
        );

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let config = resolve(&aliases, &workspace_paths, Some(&cargo_home_config));

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example/");
        assert_eq!(entry.provenance, Provenance::CargoHome);
        assert_eq!(
            entry.auth.as_ref().map(AuthToken::as_str),
            Some("real-token"),
            "the CARGO_HOME token must not be lost just because the project lives \
             under $HOME"
        );
    }

    #[test]
    fn test_resolve_falls_back_to_cargo_home_when_no_workspace_entry() {
        let cargo_home = tempfile::tempdir().unwrap();
        std::fs::write(
            cargo_home.path().join("config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://real.example\"\ntoken = \"real-token\"\n",
        )
        .unwrap();

        let aliases: HashSet<String> = std::iter::once("my-corp".to_string()).collect();
        let config = resolve(&aliases, &[], Some(&cargo_home.path().join("config.toml")));

        let entry = config.get("my-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://real.example/");
        assert_eq!(entry.auth.as_ref().unwrap().as_str(), "real-token");
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    #[test]
    fn test_resolve_unconfigured_alias_stays_unresolved() {
        let aliases: HashSet<String> = std::iter::once("unknown".to_string()).collect();
        let config = resolve(&aliases, &[], None);
        assert!(config.get("unknown").is_none());
    }

    #[test]
    fn test_resolve_env_var_index_override() {
        let aliases: HashSet<String> = std::iter::once("env-only-corp".to_string()).collect();
        let env = |name: &str| match name {
            "CARGO_REGISTRIES_ENV_ONLY_CORP_INDEX" => {
                Some("sparse+https://env.example".to_string())
            }
            "CARGO_REGISTRIES_ENV_ONLY_CORP_TOKEN" => Some("env-token".to_string()),
            _ => None,
        };

        let config = resolve_with_env(&aliases, &[], None, &env);
        let entry = config.get("env-only-corp").unwrap();
        assert_eq!(entry.index.as_str(), "https://env.example/");
        assert_eq!(entry.auth.as_ref().unwrap().as_str(), "env-token");
        assert_eq!(entry.provenance, Provenance::CargoHome);
    }

    /// FR-015: two distinct alias spellings deriving the same env-var name must both be
    /// skipped for env resolution, not have one arbitrarily win.
    #[test]
    fn test_resolve_env_var_name_collision_disables_both() {
        let aliases: HashSet<String> = ["my-corp".to_string(), "my_corp".to_string()]
            .into_iter()
            .collect();
        let env = |name: &str| {
            (name == "CARGO_REGISTRIES_MY_CORP_INDEX")
                .then(|| "sparse+https://ambiguous.example".to_string())
        };

        let config = resolve_with_env(&aliases, &[], None, &env);
        assert!(config.get("my-corp").is_none());
        assert!(config.get("my_corp").is_none());
    }

    /// The env-var TOKEN override must never resurrect a credential for an alias a
    /// workspace file has shadowed — the exact US-004 scenario, exercised through
    /// `resolve` end-to-end rather than only at the `parse_workspace_registries` unit level.
    #[test]
    fn test_resolve_env_token_never_attaches_to_workspace_shadowed_alias() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.github]\nindex = \"sparse+https://attacker.example\"\n",
        )
        .unwrap();

        let env = |name: &str| {
            (name == "CARGO_REGISTRIES_GITHUB_TOKEN").then(|| "legitimate-token".to_string())
        };

        let aliases: HashSet<String> = std::iter::once("github".to_string()).collect();
        let config = resolve_with_env(
            &aliases,
            &[root.path().join(".cargo/config.toml")],
            None,
            &env,
        );

        let entry = config.get("github").unwrap();
        assert_eq!(entry.index.as_str(), "https://attacker.example/");
        assert!(
            entry.auth.is_none(),
            "the legitimate env token must never attach to the attacker-controlled index"
        );
    }

    #[test]
    fn test_referenced_aliases_collects_custom_registry_urls() {
        use crate::types::{DependencySection, ParsedDependency};
        use deps_core::parser::DependencySource;
        use tower_lsp_server::ls_types::Range;

        let deps = vec![
            ParsedDependency {
                name: "a".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
                section: DependencySection::Dependencies,
            },
            ParsedDependency {
                name: "b".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::Registry,
                section: DependencySection::Dependencies,
            },
        ];

        let aliases = referenced_aliases(&deps);
        assert_eq!(aliases.len(), 1);
        assert!(aliases.contains("my-corp"));
    }
}
