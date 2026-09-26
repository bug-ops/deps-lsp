//! `CliConfig` and `deps.toml` loading.
//!
//! Reuses [`deps_core::policy_config::PolicyConfig`] — the same type `deps-lsp`'s
//! `DepsConfig` composes — so `deps-cli` never parses a second, independently-maintained
//! copy of the policy schema (constitution principle 1).

use deps_core::policy_config::{DiagnosticsConfig, PolicyConfig};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Default config file name looked up relative to the current working directory when
/// `--config` is not given (FR-014).
pub const DEFAULT_CONFIG_FILENAME: &str = "deps.toml";

/// Size cap on a `deps.toml` read, mirroring `main.rs`'s own manifest-read cap (10 MB) — a
/// config file has no legitimate reason to approach a manifest's own size budget.
const MAX_CONFIG_FILE_SIZE: u64 = 1_000_000;

/// `deps-cli`'s own top-level configuration, loaded from `deps.toml`.
///
/// Composes the same [`PolicyConfig`] `deps-lsp`'s `DepsConfig` does via `#[serde(flatten)]`,
/// reproducing that type's `deny_unknown_fields`/`flatten` asymmetry exactly: an unknown
/// top-level key rejects the whole file, but an unknown key nested inside a known section
/// (`[cache]`, `[network]`, ...) is tolerated for forward-compatibility (spec 062 plan.md §3,
/// verified by `deps-lsp`'s own `config.rs` tests).
#[non_exhaustive]
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CliConfig {
    /// The shared policy sections (diagnostics, cache, freshness, supply_chain, registries,
    /// network, license_policy).
    #[serde(flatten)]
    pub policy: PolicyConfig,
    /// The `[update]` section (#1119) — `deps-cli update`'s ignore rules. Honored only when
    /// loaded from an explicit `--config <path>`; never auto-discovered (FR-007) —
    /// [`safe_auto_discovered_config`] drops it by omission for the `check` auto-discovery
    /// path.
    #[serde(default)]
    pub update: UpdateConfig,
}

/// The `[update]` config section (#1119): `deps-cli update`'s ignore rules.
///
/// # Examples
///
/// ```
/// use deps_cli::config::UpdateConfig;
///
/// assert!(UpdateConfig::default().ignore.is_empty());
/// ```
#[non_exhaustive]
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// Dependencies (optionally scoped by update kind) `deps-cli update`'s default mode
    /// should skip.
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
}

/// One `[update].ignore` entry: a dependency name, optionally scoped to specific update
/// kinds.
///
/// `#[non_exhaustive]`: constructed only via deserialization (a future field addition should
/// not force every construction site to update).
///
/// # Examples
///
/// ```
/// use deps_cli::config::IgnoreRule;
///
/// let rule: IgnoreRule = serde_json::from_str(r#"{"name": "tokio"}"#).unwrap();
/// assert_eq!(rule.name, "tokio");
/// assert_eq!(rule.update_types, None);
/// ```
#[non_exhaustive]
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    /// The dependency name this rule matches, after
    /// [`deps_core::lsp_helpers::PackageNaming::normalize_package_name`] is applied to both
    /// sides (FR-006).
    pub name: String,
    /// The update kinds this rule matches. `None` matches every kind, including
    /// [`deps_core::edit::UpdateKind::Unknown`]; `Some(kinds)` matches the listed kinds
    /// **and** `Unknown` (fail-closed — FR-006: a rule that cannot confirm an update is
    /// below its stated threshold treats it as if it met the threshold).
    #[serde(default)]
    pub update_types: Option<Vec<UpdateTypeToken>>,
}

/// One `update_types` token in an `[update].ignore` entry.
#[non_exhaustive]
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateTypeToken {
    /// Matches [`deps_core::edit::UpdateKind::Major`].
    Major,
    /// Matches [`deps_core::edit::UpdateKind::Minor`].
    Minor,
    /// Matches [`deps_core::edit::UpdateKind::Patch`].
    Patch,
}

impl UpdateTypeToken {
    /// Whether this token matches `kind`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cli::config::UpdateTypeToken;
    /// use deps_core::edit::UpdateKind;
    ///
    /// assert!(UpdateTypeToken::Major.matches(UpdateKind::Major));
    /// assert!(!UpdateTypeToken::Major.matches(UpdateKind::Minor));
    /// ```
    #[must_use]
    pub fn matches(self, kind: deps_core::edit::UpdateKind) -> bool {
        matches!(
            (self, kind),
            (Self::Major, deps_core::edit::UpdateKind::Major)
                | (Self::Minor, deps_core::edit::UpdateKind::Minor)
                | (Self::Patch, deps_core::edit::UpdateKind::Patch)
        )
    }
}

/// Error loading or parsing a `deps.toml` file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading `path` failed for a reason other than "file does not exist" (which is not an
    /// error when no `--config` was given — see [`load`]).
    #[error("failed to read config file {path}: {source}")]
    Io {
        /// The config file path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `path` exceeds `MAX_CONFIG_FILE_SIZE`.
    #[error("config file {path} exceeds the {MAX_CONFIG_FILE_SIZE}-byte size cap")]
    TooLarge {
        /// The config file path.
        path: PathBuf,
    },
    /// `path`'s content is not valid TOML.
    #[error("failed to parse TOML in {path}: {message}")]
    Toml {
        /// The config file path.
        path: PathBuf,
        /// The underlying `toml_span::Error`'s `Display` text, redacted and bounded via
        /// [`deps_core::net_policy::redact_parse_error_for_log`] at construction time rather
        /// than stored raw — a duplicate-key/table parse error can embed a credential-shaped
        /// name verbatim (#1240), and `main.rs` renders this variant via `eprintln!("deps-cli:
        /// {error}")` straight to stderr/CI logs. Storing the already-redacted text (instead of
        /// the raw `toml_span::Error`) means every consumer of this variant is safe by
        /// construction, not just the current call site. Also used for
        /// [`deps_core::parse_toml_checked`]'s `NestingTooDeep` message (#1403) when `content`
        /// exceeds [`deps_core::MAX_TOML_NESTING_DEPTH`] before `toml_span::parse` ever runs.
        message: String,
    },
    /// `path` parsed as TOML but does not match [`CliConfig`]'s schema (an unknown top-level
    /// key, or a field of the wrong type).
    #[error("invalid configuration in {path}: {message}")]
    Deserialize {
        /// The config file path.
        path: PathBuf,
        /// The underlying `serde_json::Error`'s `Display` text, redacted and bounded via
        /// [`deps_core::net_policy::redact_parse_error_for_log`] at construction time rather
        /// than stored raw — `serde_json`'s "unknown field" and "invalid type" messages both
        /// embed the offending key or value verbatim, either of which can be credential-shaped
        /// (#1240 round 2), and `main.rs` renders this variant via `eprintln!("deps-cli:
        /// {error}")` straight to stderr/CI logs. Same fix as [`Self::Toml`], for the same
        /// reason: storing the already-redacted text means every consumer of this variant is
        /// safe by construction, not just the current call site.
        message: String,
    },
}

/// Loads [`CliConfig`] from `explicit_path`, or from [`DEFAULT_CONFIG_FILENAME`] inside
/// `default_dir` when `explicit_path` is `None`.
///
/// `default_dir` is the walked root (FR-014 says "at the walked root", not the process's own
/// CWD — spec 062 review S4): `deps-cli check /path/to/repo` run from elsewhere must still
/// pick up that repo's own `deps.toml`, not silently ignore it because the CLI happened to be
/// launched from a different directory.
///
/// A missing file is only an error when `explicit_path` was given explicitly (FR-014's "a
/// path given via `--config`" case) — the default-location lookup silently falls back to
/// [`CliConfig::default`] (mirroring `plan.md` §4's "default `./deps.toml` if present").
/// A file that exists but fails to parse is always an error (FR-016): unlike `deps-lsp`'s
/// live-reload path, a CLI run has no prior known-good configuration to keep.
///
/// **Security (F1/F1-follow-up, spec 062 review, P0/P1):** a `deps.toml` found by
/// *auto-discovery* (`explicit_path: None`) comes from the target being scanned, not from an
/// operator's own explicit choice — in a `git checkout && deps-cli check .`-shaped CI job,
/// that target can be an untrusted PR branch from a fork. Two live-verified attacks follow
/// from trusting it fully:
///
/// - **F1**: `registries.gitlab_instance_host` is the one host `GITLAB_TOKEN` is ever
///   attached to, and `registries.workspace_registries = "all"` lifts `net_policy`'s SSRF
///   gate for loopback/RFC1918/cloud-metadata hosts (credential exfiltration/SSRF).
/// - **F1-follow-up**: `diagnostics.{mutable_ref_pin,vulnerabilities}_enabled = false` or
///   `network.offline = true` silently disable the exact check that would have caught a
///   vulnerability the same PR introduces — defeating `check`'s CI-gating purpose without
///   touching a secret. A PR from a fork can introduce a vulnerable dependency *and* edit
///   `deps.toml` in the same PR to turn off the check that would have caught it.
///
/// [`safe_auto_discovered_config`] applies to an auto-discovered file only; an explicitly-given
/// `--config` *is* the operator's own choice and is trusted as written.
///
/// # Errors
///
/// Returns [`ConfigError`] if the file cannot be read (and was explicitly requested), is
/// too large, is not valid TOML, or does not match [`CliConfig`]'s schema.
pub fn load(explicit_path: Option<&Path>, default_dir: &Path) -> Result<CliConfig, ConfigError> {
    let (path, required): (PathBuf, bool) = match explicit_path {
        Some(path) => (path.to_path_buf(), true),
        None => (default_dir.join(DEFAULT_CONFIG_FILENAME), false),
    };

    let content = match deps_core::fs_probe::read_to_string_capped(&path, MAX_CONFIG_FILE_SIZE) {
        Ok(Some(content)) => content,
        Ok(None) => return Err(ConfigError::TooLarge { path }),
        Err(source) if !required && source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CliConfig::default());
        }
        Err(source) => return Err(ConfigError::Io { path, source }),
    };

    let config = parse(&content, &path)?;
    if !required {
        for section in ignored_sections(&config.policy) {
            eprintln!(
                "deps-cli: warning: {path}'s [{section}] section was auto-discovered, not given via --config, and is ignored — see `deps_cli::config::safe_auto_discovered_config`'s doc for why",
                path = crate::sanitize::sanitize_path_for_display(&path).display(),
            );
        }
        return Ok(safe_auto_discovered_config(config));
    }
    Ok(config)
}

/// Reduces a [`CliConfig`] loaded from an *auto-discovered* `deps.toml` to only the fields
/// that cannot weaken what `--fail-on` observes (spec 062 review, F1 follow-up).
///
/// Widened one level from a `PolicyConfig`-only allowlist (#1329) so a `CliConfig` field
/// added later (like [`CliConfig::update`]) is safe-by-default under auto-discovery rather
/// than attacker-controlled by default, without needing its own explicit reset.
///
/// Built as an **allowlist** (what to *keep* from `parsed`) rather than a blocklist (what to
/// reset), deliberately: F1's first fix reset only `registries` and was proven, in the very
/// next review round, to have missed `diagnostics.*_enabled` and `network.offline` — an
/// enumerate-the-dangerous-fields approach already failed once on this exact code path. An
/// allowlist fails closed instead: a field added later defaults to `CliConfig::default`'s
/// (safe) value here automatically, rather than silently staying attacker-controlled until
/// someone notices and adds it to a reset list.
///
/// The only fields kept from `parsed`: `policy.diagnostics`'s six `*_severity` values. These
/// are purely cosmetic (`table`/`json` severity display) —
/// [`crate::report::FailOnPolicy::matches`] checks a finding's `Category`, never its
/// severity, so no severity value can suppress or weaken a `--fail-on` match. Everything else
/// reverts to its default: `policy.diagnostics.{mutable_ref_pin,vulnerabilities}_enabled`
/// (the two direct "disable the check" levers), `policy.cache.*` (a low `fetch_timeout_secs`
/// can induce spurious fetch failures that mask a real finding as an unresolved lookup
/// instead), `policy.freshness.*` and `policy.license_policy.{allow,deny}` (both change what
/// counts as a violation), `policy.supply_chain.enabled` (moot for `deps-cli` today —
/// `VersionData.trust` is hover-only and never set here — reset anyway for uniformity),
/// `policy.network.offline` (F1-follow-up: silently suppresses every registry/OSV-derived
/// finding), `policy.registries.*` (F1), and `update.ignore` (FR-007 — provably a no-op
/// regardless: `update` never auto-discovers a config at all, so `check`'s own auto-discovery
/// path — the only caller of this function — never renders `[update].ignore` in the first
/// place; dropped here anyway so the allowlist stays the single source of truth for what an
/// auto-discovered file can influence).
#[must_use]
pub fn safe_auto_discovered_config(parsed: CliConfig) -> CliConfig {
    CliConfig {
        policy: PolicyConfig {
            diagnostics: DiagnosticsConfig::new()
                .with_outdated_severity(parsed.policy.diagnostics.outdated_severity)
                .with_unknown_severity(parsed.policy.diagnostics.unknown_severity)
                .with_yanked_severity(parsed.policy.diagnostics.yanked_severity)
                .with_unsatisfiable_severity(parsed.policy.diagnostics.unsatisfiable_severity)
                .with_deprecated_severity(parsed.policy.diagnostics.deprecated_severity)
                .with_mutable_ref_pin_severity(parsed.policy.diagnostics.mutable_ref_pin_severity),
            ..PolicyConfig::default()
        },
        ..CliConfig::default()
    }
}

/// Names every section of `policy` that differs from [`PolicyConfig::default`] outside the
/// always-kept severity fields — used only to print a specific, per-section warning when
/// [`load`] ignores an auto-discovered file's non-cosmetic settings, so this is visible in CI
/// logs even if a future `PolicyConfig` field is missed by [`safe_auto_discovered_config`]'s
/// allowlist (same "defense in depth" spirit as `report.rs`'s diagnostic-code-list doc).
fn ignored_sections(policy: &PolicyConfig) -> Vec<&'static str> {
    let default = PolicyConfig::default();
    let mut sections = Vec::new();

    if policy.diagnostics.mutable_ref_pin_enabled != default.diagnostics.mutable_ref_pin_enabled
        || policy.diagnostics.vulnerabilities_enabled != default.diagnostics.vulnerabilities_enabled
    {
        sections.push("diagnostics");
    }
    if policy.cache.enabled != default.cache.enabled
        || policy.cache.fetch_timeout_secs != default.cache.fetch_timeout_secs
        || policy.cache.max_concurrent_fetches != default.cache.max_concurrent_fetches
    {
        sections.push("cache");
    }
    if policy.freshness.enabled != default.freshness.enabled
        || policy.freshness.cooldown_secs != default.freshness.cooldown_secs
    {
        sections.push("freshness");
    }
    if policy.supply_chain.enabled != default.supply_chain.enabled {
        sections.push("supply_chain");
    }
    if policy.registries.workspace_registries != default.registries.workspace_registries
        || policy.registries.nuget_user_profile_sources
            != default.registries.nuget_user_profile_sources
        || policy.registries.gitlab_instance_host != default.registries.gitlab_instance_host
    {
        sections.push("registries");
    }
    if policy.network.offline != default.network.offline {
        sections.push("network");
    }
    if policy.license_policy.allow != default.license_policy.allow
        || policy.license_policy.deny != default.license_policy.deny
    {
        sections.push("license_policy");
    }
    // Issue #1456, spec 072, FR-010/M14: `deps-cli` GOSSIP parity was dropped from this
    // issue's scope (near-zero practical value — see spec 072 §9's N1) — a `[gossip]`
    // section now at least surfaces this "no effect" warning instead of being silently
    // accepted, mirroring every other section here.
    if policy.gossip.enabled != default.gossip.enabled {
        sections.push("gossip");
    }

    sections
}

/// Parses `content` as TOML and deserializes it into [`CliConfig`].
///
/// Goes through [`deps_core::parse_toml_checked`] (this project's TOML parser of record) and
/// then bridges the parsed [`toml_span::Value`] into [`CliConfig`] via its `serde::Deserialize`
/// impl (`toml_span::Value` implements `serde::Serialize` under its own `serde` feature) — so
/// `deps-cli` reuses `PolicyConfig`'s existing `Deserialize` impl instead of writing a
/// second, `toml_span::Deserialize`-based one.
fn parse(content: &str, path: &Path) -> Result<CliConfig, ConfigError> {
    let value = deps_core::parse_toml_checked(content).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        message: deps_core::net_policy::redact_parse_error_for_log(&source.to_string())
            .into_owned(),
    })?;
    let json = serde_json::to_value(&value).map_err(|source| ConfigError::Deserialize {
        path: path.to_path_buf(),
        message: deps_core::net_policy::redact_parse_error_for_log(&source.to_string())
            .into_owned(),
    })?;
    serde_json::from_value(json).map_err(|source| ConfigError::Deserialize {
        path: path.to_path_buf(),
        message: deps_core::net_policy::redact_parse_error_for_log(&source.to_string())
            .into_owned(),
    })
}

/// Fuzz-only entry point for [`parse`] (issue #1404), using a fixed dummy path since the
/// fuzz target only supplies file content. Gated on the `fuzzing` Cargo feature (never
/// enabled by this crate's own default set) so this stays out of the crate's public API
/// surface in a normal build.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_config(content: &str) {
    let _ = parse(content, Path::new(DEFAULT_CONFIG_FILENAME));
}

/// Applies `--offline`/`--cooldown` CLI overrides onto a loaded [`CliConfig`] for this run
/// only (FR-015).
///
/// `--offline`'s presence forces `network.offline = true` (a bare on/off flag has no way to
/// express "explicitly false", so absence never overrides a `deps.toml`-configured `true`
/// back to `false`); `--cooldown`, when given, replaces `freshness.cooldown_secs` outright.
pub fn apply_overrides(
    mut config: CliConfig,
    offline: deps_core::NetworkMode,
    cooldown: Option<u64>,
) -> CliConfig {
    if offline == deps_core::NetworkMode::Offline {
        config.policy.network.offline = true;
    }
    if let Some(cooldown_secs) = cooldown {
        config.policy.freshness.cooldown_secs = cooldown_secs;
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp_toml(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create temp file");
        file.write_all(content.as_bytes()).expect("write temp file");
        file
    }

    /// Issue #1456, spec 072, M14: a `[gossip]` section differing from default must warn
    /// via `ignored_sections`, since `deps-cli` has no GOSSIP behavior at all (FR-010
    /// dropped) — otherwise it would be silently accepted with no effect.
    #[test]
    fn test_ignored_sections_includes_gossip_when_enabled() {
        let mut policy = PolicyConfig::default();
        policy.gossip.enabled = true;
        assert!(ignored_sections(&policy).contains(&"gossip"));
    }

    #[test]
    fn test_ignored_sections_omits_gossip_when_default() {
        let policy = PolicyConfig::default();
        assert!(!ignored_sections(&policy).contains(&"gossip"));
    }

    #[test]
    fn test_load_missing_default_file_returns_defaults() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let config = load(None, dir.path()).expect("missing default file is not an error");
        assert_eq!(
            config.policy.network.offline,
            PolicyConfig::default().network.offline
        );
    }

    #[test]
    fn test_load_missing_explicit_path_is_an_error() {
        let missing = PathBuf::from("/nonexistent/path/to/deps.toml");
        let result = load(Some(&missing), Path::new("."));
        assert!(matches!(result, Err(ConfigError::Io { .. })));
    }

    #[test]
    fn test_load_valid_toml_parses_policy_sections() {
        let file = write_temp_toml(
            r"
            [network]
            offline = true

            [freshness]
            cooldown_secs = 60
            ",
        );
        let config = load(Some(file.path()), Path::new(".")).expect("valid TOML must parse");
        assert!(config.policy.network.offline);
        assert_eq!(config.policy.freshness.cooldown_secs, 60);
    }

    #[test]
    fn test_load_malformed_toml_is_an_error() {
        let file = write_temp_toml("this is not [ valid toml");
        let result = load(Some(file.path()), Path::new("."));
        assert!(matches!(result, Err(ConfigError::Toml { .. })));
    }

    /// #1403: a deeply nested `deps.toml` (auto-discovered from an untrusted checkout) must be
    /// rejected via `ConfigError`, not fed straight to `toml_span::parse` and overflow the
    /// stack (SIGABRT, exit 134) — mirrors `deps-cargo`'s `Cargo.lock` regression test for the
    /// same class of bug.
    #[test]
    fn test_load_excessively_nested_toml_is_rejected_not_stack_overflow() {
        let depth = deps_core::MAX_TOML_NESTING_DEPTH + 1;
        let content = format!("x = {}1{}\n", "{a=".repeat(depth), "}".repeat(depth));
        let file = write_temp_toml(&content);
        let result = load(Some(file.path()), Path::new("."));
        let Err(ConfigError::Toml { message, .. }) = result else {
            panic!("expected ConfigError::Toml, got {result:?}");
        };
        assert!(
            message.contains("nesting depth"),
            "expected a nesting-depth message, got: {message}"
        );
    }

    /// #1240: a duplicate table whose name is credential-shaped must not leak the credential
    /// into `ConfigError::Toml`'s stored message, which `main.rs` prints straight to stderr.
    #[test]
    fn test_load_duplicate_table_toml_error_redacts_credential() {
        let file = write_temp_toml(
            r#"
["https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x"]
a = 1
["https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x"]
b = 2
"#,
        );
        let result = load(Some(file.path()), Path::new("."));
        let message = result.unwrap_err().to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    #[test]
    fn test_load_duplicate_table_toml_error_benign_name_unchanged() {
        let content = r"
[serde]
a = 1
[serde]
b = 2
";
        let file = write_temp_toml(content);

        // Derived from the raw parse, not hardcoded, so assert_eq! gates a redaction regression (#1240 M5).
        let raw_err = toml_span::parse(content).unwrap_err();
        let expected = format!(
            "failed to parse TOML in {}: {raw_err}",
            file.path().display()
        );

        let result = load(Some(file.path()), Path::new("."));
        assert_eq!(result.unwrap_err().to_string(), expected);
    }

    #[test]
    fn test_load_unknown_top_level_key_is_rejected() {
        let file = write_temp_toml("totally_unknown_key = true\n");
        let result = load(Some(file.path()), Path::new("."));
        assert!(matches!(result, Err(ConfigError::Deserialize { .. })));
    }

    /// #1240 round 2: an unknown top-level key whose *name* is credential-shaped must not leak
    /// the credential into `ConfigError::Deserialize`'s stored message — `serde_json`'s "unknown
    /// field" message embeds the key verbatim, and this is actually easier to trigger than the
    /// `ConfigError::Toml` duplicate-key case (round 1): one bad key, no duplicate needed.
    #[test]
    fn test_load_unknown_field_credential_shaped_name_redacted() {
        let file = write_temp_toml(
            "\"https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x\" = true\n",
        );
        let message = load(Some(file.path()), Path::new("."))
            .unwrap_err()
            .to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    /// #1240 round 2: a wrong-typed field *value* that happens to be credential-shaped must not
    /// leak either — `serde_json`'s "invalid type" message embeds the offending value verbatim.
    #[test]
    fn test_load_wrong_typed_value_credential_shaped_string_redacted() {
        let file = write_temp_toml(
            r#"
            [cache]
            enabled = "https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x"
            "#,
        );
        let message = load(Some(file.path()), Path::new("."))
            .unwrap_err()
            .to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    #[test]
    fn test_load_unknown_field_benign_name_unchanged() {
        let content = "totally_unknown_key = true\n";
        let file = write_temp_toml(content);

        // Derived from the raw serde_json round-trip, not hardcoded, so assert_eq! gates a redaction regression.
        let value = toml_span::parse(content).unwrap();
        let json = serde_json::to_value(&value).unwrap();
        let raw_err = serde_json::from_value::<CliConfig>(json).unwrap_err();
        let expected = format!(
            "invalid configuration in {}: {raw_err}",
            file.path().display()
        );

        let message = load(Some(file.path()), Path::new("."))
            .unwrap_err()
            .to_string();
        assert_eq!(message, expected);
    }

    #[test]
    fn test_load_unknown_key_nested_in_known_section_is_tolerated() {
        let file = write_temp_toml(
            r#"
            [network]
            offline = true
            future_field = "ignored"
            "#,
        );
        let config = load(Some(file.path()), Path::new("."))
            .expect("nested unknown key must not reject the payload");
        assert!(config.policy.network.offline);
    }

    /// Regression test for S4 (spec 062 review): auto-discovery must resolve against the
    /// given `default_dir` (the walked root), not the process's own CWD.
    ///
    /// Uses a severity field as the signal (not `network.offline` — that's one of the
    /// fields `safe_auto_discovered_config` now resets, see the F1-follow-up tests below;
    /// a severity value is always kept, so it stays a valid probe for *which file* was
    /// actually read).
    #[test]
    fn test_load_auto_discovery_resolves_against_given_default_dir_not_cwd() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "[diagnostics]\noutdated_severity = 1\n",
        )
        .expect("write deps.toml");
        // Deliberately does NOT chdir anywhere near `dir` — if `load` fell back to CWD this
        // would find nothing and return defaults instead.
        let config = load(None, dir.path()).expect("deps.toml in default_dir must be found");
        assert_eq!(
            config.policy.diagnostics.outdated_severity,
            deps_core::diagnostic::Severity::Error
        );
    }

    /// Regression test for F1 (spec 062 review, P0 security): an auto-discovered
    /// `deps.toml`'s `registries` section (the credential/SSRF-relevant one) must never take
    /// effect — only an explicitly-given `--config` file is trusted for it.
    #[test]
    fn test_load_auto_discovered_registries_section_is_ignored() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            r#"
            [registries]
            gitlab_instance_host = "attacker-host.invalid"
            workspace_registries = "all"
            "#,
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        assert_eq!(config.policy.registries.gitlab_instance_host, "");
        assert_eq!(
            config.policy.registries.workspace_registries,
            deps_core::policy_config::WorkspaceRegistriesSetting::PublicOnly
        );
    }

    /// Regression test for the F1 follow-up (spec 062 review, P1): an auto-discovered
    /// `deps.toml` must not be able to disable the two diagnostic kinds that gate
    /// `--fail-on mutable-ref`/no-vulnerability-scan-at-all.
    #[test]
    fn test_load_auto_discovered_diagnostics_enabled_flags_are_ignored() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            r"
            [diagnostics]
            mutable_ref_pin_enabled = false
            vulnerabilities_enabled = false
            ",
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        assert!(config.policy.diagnostics.mutable_ref_pin_enabled);
        assert!(config.policy.diagnostics.vulnerabilities_enabled);
    }

    /// Regression test for the F1 follow-up: an auto-discovered `deps.toml` must not be able
    /// to force the whole run offline, which would silently suppress every
    /// registry/OSV-derived finding and make the default `--fail-on` policy unable to fire.
    #[test]
    fn test_load_auto_discovered_network_offline_is_ignored() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "[network]\noffline = true\n",
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        assert!(!config.policy.network.offline);
    }

    /// Regression test for the F1 follow-up: `freshness`/`license_policy`/`cache`/
    /// `supply_chain` all change what counts as a violation or can induce spurious fetch
    /// failures, so an auto-discovered file must not control any of them either.
    #[test]
    fn test_load_auto_discovered_remaining_gate_relevant_sections_are_ignored() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            r#"
            [freshness]
            cooldown_secs = 0

            [license_policy]
            allow = ["GPL-3.0"]

            [cache]
            fetch_timeout_secs = 1

            [supply_chain]
            enabled = false
            "#,
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        let default = PolicyConfig::default();
        assert_eq!(
            config.policy.freshness.cooldown_secs,
            default.freshness.cooldown_secs
        );
        assert_eq!(
            config.policy.license_policy.allow,
            default.license_policy.allow
        );
        assert_eq!(
            config.policy.cache.fetch_timeout_secs,
            default.cache.fetch_timeout_secs
        );
        assert_eq!(
            config.policy.supply_chain.enabled,
            default.supply_chain.enabled
        );
    }

    /// The one allowed exception: a severity value has no effect on `--fail-on` matching
    /// ([`crate::report::FailOnPolicy::matches`] checks `Category`, never severity), so it
    /// is kept from an auto-discovered file.
    #[test]
    fn test_load_auto_discovered_severity_values_are_kept() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            "[diagnostics]\nyanked_severity = 4\n",
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        assert_eq!(
            config.policy.diagnostics.yanked_severity,
            deps_core::diagnostic::Severity::Hint
        );
    }

    /// Companion to the test above: an explicitly-given `--config` *is* the operator's own
    /// choice, so its `registries` section is trusted as written.
    #[test]
    fn test_load_explicit_config_registries_section_is_trusted() {
        let file = write_temp_toml(
            r#"
            [registries]
            gitlab_instance_host = "gitlab.mycorp.dev"
            "#,
        );
        let config = load(Some(file.path()), Path::new("."))
            .expect("explicit config with a registries section must load");
        assert_eq!(
            config.policy.registries.gitlab_instance_host,
            "gitlab.mycorp.dev"
        );
    }

    #[test]
    fn test_apply_overrides_offline_flag_forces_true() {
        let config = apply_overrides(CliConfig::default(), deps_core::NetworkMode::Offline, None);
        assert!(config.policy.network.offline);
    }

    #[test]
    fn test_apply_overrides_offline_absent_keeps_file_value() {
        let mut base = CliConfig::default();
        base.policy.network.offline = true;
        let config = apply_overrides(base, deps_core::NetworkMode::Online, None);
        assert!(
            config.policy.network.offline,
            "absent flag must not clear a file-set true"
        );
    }

    #[test]
    fn test_apply_overrides_cooldown_replaces_file_value() {
        let mut base = CliConfig::default();
        base.policy.freshness.cooldown_secs = 999;
        let config = apply_overrides(base, deps_core::NetworkMode::Online, Some(42));
        assert_eq!(config.policy.freshness.cooldown_secs, 42);
    }

    #[test]
    fn test_apply_overrides_no_cooldown_keeps_file_value() {
        let mut base = CliConfig::default();
        base.policy.freshness.cooldown_secs = 999;
        let config = apply_overrides(base, deps_core::NetworkMode::Online, None);
        assert_eq!(config.policy.freshness.cooldown_secs, 999);
    }

    // --- [update] section (#1119, T006) ---

    #[test]
    fn test_load_auto_discovered_update_ignore_is_dropped() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILENAME),
            r#"
            [diagnostics]
            yanked_severity = 4

            [[update.ignore]]
            name = "tokio"
            update_types = ["major"]
            "#,
        )
        .expect("write deps.toml");
        let config = load(None, dir.path()).expect("auto-discovered file must still load");
        assert!(
            config.update.ignore.is_empty(),
            "an auto-discovered [update].ignore must never take effect"
        );
        // The allowlisted severity field must still survive, proving the whole file wasn't
        // silently dropped.
        assert_eq!(
            config.policy.diagnostics.yanked_severity,
            deps_core::diagnostic::Severity::Hint
        );
    }

    #[test]
    fn test_load_explicit_config_update_ignore_is_trusted_verbatim() {
        let file = write_temp_toml(
            r#"
            [[update.ignore]]
            name = "tokio"
            update_types = ["major"]

            [[update.ignore]]
            name = "legacy-thing"
            "#,
        );
        let config = load(Some(file.path()), Path::new("."))
            .expect("explicit --config must load [update].ignore verbatim");
        assert_eq!(config.update.ignore.len(), 2);
        assert_eq!(config.update.ignore[0].name, "tokio");
        assert_eq!(
            config.update.ignore[0].update_types,
            Some(vec![UpdateTypeToken::Major])
        );
        assert_eq!(config.update.ignore[1].name, "legacy-thing");
        assert_eq!(config.update.ignore[1].update_types, None);
    }

    #[test]
    fn test_load_update_ignore_unrecognized_update_types_token_is_a_hard_error() {
        let file = write_temp_toml(
            r#"
            [[update.ignore]]
            name = "tokio"
            update_types = ["unknown"]
            "#,
        );
        let result = load(Some(file.path()), Path::new("."));
        assert!(matches!(result, Err(ConfigError::Deserialize { .. })));
    }

    #[test]
    fn test_update_type_token_matches_only_its_own_kind() {
        assert!(UpdateTypeToken::Major.matches(deps_core::edit::UpdateKind::Major));
        assert!(!UpdateTypeToken::Major.matches(deps_core::edit::UpdateKind::Minor));
        assert!(!UpdateTypeToken::Major.matches(deps_core::edit::UpdateKind::Unknown));
        assert!(UpdateTypeToken::Minor.matches(deps_core::edit::UpdateKind::Minor));
        assert!(UpdateTypeToken::Patch.matches(deps_core::edit::UpdateKind::Patch));
    }
}
