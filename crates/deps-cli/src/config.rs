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
    #[error("failed to parse TOML in {path}: {source}")]
    Toml {
        /// The config file path.
        path: PathBuf,
        /// The underlying TOML parse error.
        #[source]
        source: toml_span::Error,
    },
    /// `path` parsed as TOML but does not match [`CliConfig`]'s schema (an unknown top-level
    /// key, or a field of the wrong type).
    #[error("invalid configuration in {path}: {source}")]
    Deserialize {
        /// The config file path.
        path: PathBuf,
        /// The underlying (de)serialization error.
        #[source]
        source: serde_json::Error,
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
/// [`safe_auto_discovered_policy`] applies to an auto-discovered file only; an explicitly-given
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

    let mut config = parse(&content, &path)?;
    if !required {
        for section in ignored_sections(&config.policy) {
            eprintln!(
                "deps-cli: warning: {path}'s [{section}] section was auto-discovered, not given via --config, and is ignored — see `deps_cli::config::safe_auto_discovered_policy`'s doc for why",
                path = path.display(),
            );
        }
        config.policy = safe_auto_discovered_policy(config.policy);
    }
    Ok(config)
}

/// Reduces a policy loaded from an *auto-discovered* `deps.toml` to only the fields that
/// cannot weaken what `--fail-on` observes (spec 062 review, F1 follow-up).
///
/// Built as an **allowlist** (what to *keep* from `parsed`) rather than a blocklist (what to
/// reset), deliberately: F1's first fix reset only `registries` and was proven, in the very
/// next review round, to have missed `diagnostics.*_enabled` and `network.offline` — an
/// enumerate-the-dangerous-fields approach already failed once on this exact code path. An
/// allowlist fails closed instead: a `PolicyConfig` field added later defaults to
/// `PolicyConfig::default()`'s (safe) value here automatically, rather than silently staying
/// attacker-controlled until someone notices and adds it to a reset list.
///
/// The only fields kept from `parsed`: `diagnostics`'s six `*_severity` values. These are
/// purely cosmetic (`table`/`json` severity display) — [`crate::report::FailOnPolicy::matches`]
/// checks a finding's `Category`, never its severity, so no severity value can suppress or
/// weaken a `--fail-on` match. Everything else reverts to [`PolicyConfig::default`]:
/// `diagnostics.{mutable_ref_pin,vulnerabilities}_enabled` (the two direct "disable the
/// check" levers), `cache.*` (a low `fetch_timeout_secs` can induce spurious fetch failures
/// that mask a real finding as an unresolved lookup instead), `freshness.*` and
/// `license_policy.{allow,deny}` (both change what counts as a violation),
/// `supply_chain.enabled` (moot for `deps-cli` today — `VersionData.trust` is hover-only and
/// never set here — reset anyway for uniformity), `network.offline` (F1-follow-up: silently
/// suppresses every registry/OSV-derived finding), and `registries.*` (F1).
#[must_use]
pub fn safe_auto_discovered_policy(parsed: PolicyConfig) -> PolicyConfig {
    PolicyConfig {
        diagnostics: DiagnosticsConfig::new()
            .with_outdated_severity(parsed.diagnostics.outdated_severity)
            .with_unknown_severity(parsed.diagnostics.unknown_severity)
            .with_yanked_severity(parsed.diagnostics.yanked_severity)
            .with_unsatisfiable_severity(parsed.diagnostics.unsatisfiable_severity)
            .with_deprecated_severity(parsed.diagnostics.deprecated_severity)
            .with_mutable_ref_pin_severity(parsed.diagnostics.mutable_ref_pin_severity),
        ..PolicyConfig::default()
    }
}

/// Names every section of `policy` that differs from [`PolicyConfig::default`] outside the
/// always-kept severity fields — used only to print a specific, per-section warning when
/// [`load`] ignores an auto-discovered file's non-cosmetic settings, so this is visible in CI
/// logs even if a future `PolicyConfig` field is missed by [`safe_auto_discovered_policy`]'s
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

    sections
}

/// Parses `content` as TOML and deserializes it into [`CliConfig`].
///
/// Goes through `toml_span::parse` (this project's TOML parser of record) and then bridges
/// the parsed [`toml_span::Value`] into [`CliConfig`] via its `serde::Deserialize` impl
/// (`toml_span::Value` implements `serde::Serialize` under its own `serde` feature) — so
/// `deps-cli` reuses `PolicyConfig`'s existing `Deserialize` impl instead of writing a
/// second, `toml_span::Deserialize`-based one.
fn parse(content: &str, path: &Path) -> Result<CliConfig, ConfigError> {
    let value = toml_span::parse(content).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    let json = serde_json::to_value(&value).map_err(|source| ConfigError::Deserialize {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_value(json).map_err(|source| ConfigError::Deserialize {
        path: path.to_path_buf(),
        source,
    })
}

/// Applies `--offline`/`--cooldown` CLI overrides onto a loaded [`CliConfig`] for this run
/// only (FR-015).
///
/// `--offline`'s presence forces `network.offline = true` (a bare on/off flag has no way to
/// express "explicitly false", so absence never overrides a `deps.toml`-configured `true`
/// back to `false`); `--cooldown`, when given, replaces `freshness.cooldown_secs` outright.
pub fn apply_overrides(mut config: CliConfig, offline: bool, cooldown: Option<u64>) -> CliConfig {
    if offline {
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

    #[test]
    fn test_load_unknown_top_level_key_is_rejected() {
        let file = write_temp_toml("totally_unknown_key = true\n");
        let result = load(Some(file.path()), Path::new("."));
        assert!(matches!(result, Err(ConfigError::Deserialize { .. })));
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
    /// fields `safe_auto_discovered_policy` now resets, see the F1-follow-up tests below;
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
            tower_lsp_server::ls_types::DiagnosticSeverity::ERROR
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
            tower_lsp_server::ls_types::DiagnosticSeverity::HINT
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
        let config = apply_overrides(CliConfig::default(), true, None);
        assert!(config.policy.network.offline);
    }

    #[test]
    fn test_apply_overrides_offline_absent_keeps_file_value() {
        let mut base = CliConfig::default();
        base.policy.network.offline = true;
        let config = apply_overrides(base, false, None);
        assert!(
            config.policy.network.offline,
            "absent flag must not clear a file-set true"
        );
    }

    #[test]
    fn test_apply_overrides_cooldown_replaces_file_value() {
        let mut base = CliConfig::default();
        base.policy.freshness.cooldown_secs = 999;
        let config = apply_overrides(base, false, Some(42));
        assert_eq!(config.policy.freshness.cooldown_secs, 42);
    }

    #[test]
    fn test_apply_overrides_no_cooldown_keeps_file_value() {
        let mut base = CliConfig::default();
        base.policy.freshness.cooldown_secs = 999;
        let config = apply_overrides(base, false, None);
        assert_eq!(config.policy.freshness.cooldown_secs, 999);
    }
}
