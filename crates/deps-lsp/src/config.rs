use serde::Deserialize;
use tower_lsp_server::ls_types::DiagnosticSeverity;

/// Root configuration for the deps-lsp server.
///
/// This configuration can be provided by the LSP client via initialization options
/// or workspace settings. All fields use sensible defaults if not specified.
///
/// # Examples
///
/// ```
/// use deps_lsp::config::DepsConfig;
///
/// let json = r#"{
///     "inlay_hints": {
///         "enabled": true,
///         "up_to_date_text": "✅",
///         "needs_update_text": "❌ {}"
///     }
/// }"#;
///
/// let config: DepsConfig = serde_json::from_str(json).unwrap();
/// assert!(config.inlay_hints.enabled);
/// ```
/// `deny_unknown_fields` on this top-level struct only (never on the section structs
/// below, to preserve forward-compat for keys added inside a known section): any key that
/// isn't one of `DepsConfig`'s own fields makes the whole payload fail to parse, so
/// `parse_config` (`server.rs`) can react by keeping the previous configuration rather
/// than silently substituting an all-defaults one. Without this, a single recognized key
/// in an otherwise-unrelated blob (e.g. a client that flattens its whole settings tree)
/// would deserialize successfully and reset every unrecognized section to its default —
/// issue #227 C2.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DepsConfig {
    #[serde(default)]
    pub inlay_hints: InlayHintsConfig,
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub cold_start: ColdStartConfig,
    #[serde(default)]
    pub loading_indicator: LoadingIndicatorConfig,
    #[serde(default)]
    pub code_lens: CodeLensConfig,
    #[serde(default)]
    pub freshness: FreshnessConfig,
    #[serde(default)]
    pub cargo: CargoConfig,
}

/// Configuration for inlay hints (inline version annotations).
///
/// Controls whether inlay hints are displayed and customizes their appearance.
/// Inlay hints show version information next to dependency declarations.
///
/// # Defaults
///
/// - `enabled`: `true`
/// - `up_to_date_text`: `"✅"`
/// - `needs_update_text`: `"❌ {}"` (where `{}` is replaced with the latest version)
///
/// # Examples
///
/// ```
/// use deps_lsp::config::InlayHintsConfig;
///
/// let config = InlayHintsConfig {
///     enabled: true,
///     up_to_date_text: "OK".into(),
///     needs_update_text: "UPDATE {}".into(),
/// };
///
/// assert_eq!(config.up_to_date_text, "OK");
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct InlayHintsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_up_to_date")]
    pub up_to_date_text: String,
    #[serde(default = "default_needs_update")]
    pub needs_update_text: String,
}

impl Default for InlayHintsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            up_to_date_text: default_up_to_date(),
            needs_update_text: default_needs_update(),
        }
    }
}

/// Configuration for diagnostic severity levels.
///
/// Controls the severity level reported for different types of dependency issues.
/// This allows users to customize whether issues appear as errors, warnings, hints, etc.
///
/// # Defaults
///
/// - `outdated_severity`: `HINT` - Dependencies with available updates
/// - `unknown_severity`: `WARNING` - Dependencies not found in registry
/// - `yanked_severity`: `WARNING` - Dependencies using yanked versions
/// - `unsatisfiable_severity`: `WARNING` - Dependencies whose requirement matches zero published versions
/// - `deprecated_severity`: `WARNING` - Dependencies on a package the registry reports as deprecated/abandoned
/// - `mutable_ref_pin_severity`: `HINT` - GitHub Actions `uses:` steps pinned to a mutable ref (tag) instead of a commit SHA
/// - `mutable_ref_pin_enabled`: `true` - Whether the mutable-ref-pin diagnostic runs at all
///
/// # Examples
///
/// ```
/// use deps_lsp::config::DiagnosticsConfig;
/// use tower_lsp_server::ls_types::DiagnosticSeverity;
///
/// let config = DiagnosticsConfig {
///     outdated_severity: DiagnosticSeverity::INFORMATION,
///     unknown_severity: DiagnosticSeverity::ERROR,
///     yanked_severity: DiagnosticSeverity::ERROR,
///     unsatisfiable_severity: DiagnosticSeverity::ERROR,
///     deprecated_severity: DiagnosticSeverity::ERROR,
///     mutable_ref_pin_severity: DiagnosticSeverity::ERROR,
///     mutable_ref_pin_enabled: true,
///     vulnerabilities_enabled: true,
/// };
///
/// assert_eq!(config.unknown_severity, DiagnosticSeverity::ERROR);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct DiagnosticsConfig {
    #[serde(default = "default_outdated_severity")]
    pub outdated_severity: DiagnosticSeverity,
    #[serde(default = "default_unknown_severity")]
    pub unknown_severity: DiagnosticSeverity,
    #[serde(default = "default_yanked_severity")]
    pub yanked_severity: DiagnosticSeverity,
    #[serde(default = "default_unsatisfiable_severity")]
    pub unsatisfiable_severity: DiagnosticSeverity,
    /// Severity for a dependency on a package the registry reports as
    /// deprecated/abandoned (issue #205). No corresponding `deprecated_enabled`
    /// toggle: unlike `vulnerabilities_enabled`, this signal is derived from
    /// already-fetched data (zero new registry requests — see #205's plan §1
    /// D2), so a boolean would gate only string formatting, not a network
    /// call. Matches the severity-only precedent set by the four fields above.
    #[serde(default = "default_deprecated_severity")]
    pub deprecated_severity: DiagnosticSeverity,
    /// Severity for a GitHub Actions `uses:` step pinned to a mutable ref (a tag)
    /// instead of a full commit SHA (issue #473). Tunes loudness only; see
    /// `mutable_ref_pin_enabled` for the on/off toggle.
    #[serde(default = "default_mutable_ref_pin_severity")]
    pub mutable_ref_pin_severity: DiagnosticSeverity,
    /// Whether the mutable-ref-pin diagnostic (issue #473) runs at all. Default
    /// `true`. **Corrected during implementation review (spec 031 FR-009)**: unlike
    /// `deprecated_severity`, this diagnostic *does* need a real `_enabled` toggle —
    /// `DiagnosticSeverity` has no suppression value, and severity is never treated
    /// as a suppression input anywhere in this codebase, so without this boolean the
    /// diagnostic would be permanent and unremovable on every tag-pinned `uses:` step
    /// (the dominant pinning style), even for teams that intentionally reject
    /// SHA-pinning. Mirrors `vulnerabilities_enabled`'s exact shape.
    #[serde(default = "default_true")]
    pub mutable_ref_pin_enabled: bool,
    /// Whether to run the OSV.dev vulnerability scan and render its
    /// diagnostics/hover content. Default `true` (opt-out): `cargo audit`/
    /// `npm audit` run by default, and an opt-in gate would undercut the
    /// feature (approved Q5).
    #[serde(default = "default_true")]
    pub vulnerabilities_enabled: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            outdated_severity: default_outdated_severity(),
            unknown_severity: default_unknown_severity(),
            yanked_severity: default_yanked_severity(),
            unsatisfiable_severity: default_unsatisfiable_severity(),
            deprecated_severity: default_deprecated_severity(),
            mutable_ref_pin_severity: default_mutable_ref_pin_severity(),
            mutable_ref_pin_enabled: true,
            vulnerabilities_enabled: true,
        }
    }
}

impl DiagnosticsConfig {
    /// Converts this LSP-facing config into the `deps-core` DTO threaded
    /// through `Ecosystem::generate_diagnostics`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::config::DiagnosticsConfig;
    ///
    /// let config = DiagnosticsConfig::default();
    /// let severities = config.to_severities();
    /// assert_eq!(severities.outdated, config.outdated_severity);
    /// assert_eq!(severities.unknown, config.unknown_severity);
    /// assert_eq!(severities.yanked, config.yanked_severity);
    /// assert_eq!(severities.unsatisfiable, config.unsatisfiable_severity);
    /// assert_eq!(severities.deprecated, config.deprecated_severity);
    /// assert_eq!(severities.mutable_ref_pin, config.mutable_ref_pin_severity);
    /// assert_eq!(severities.mutable_ref_pin_enabled, config.mutable_ref_pin_enabled);
    /// ```
    #[must_use]
    pub const fn to_severities(&self) -> deps_core::DiagnosticSeverities {
        deps_core::DiagnosticSeverities {
            outdated: self.outdated_severity,
            unknown: self.unknown_severity,
            yanked: self.yanked_severity,
            unsatisfiable: self.unsatisfiable_severity,
            deprecated: self.deprecated_severity,
            mutable_ref_pin: self.mutable_ref_pin_severity,
            mutable_ref_pin_enabled: self.mutable_ref_pin_enabled,
        }
    }
}

/// Configuration for HTTP caching behavior.
///
/// Controls cache settings for registry requests. The cache uses ETag and
/// Last-Modified headers for validation, minimizing network traffic.
///
/// # Defaults
///
/// - `enabled`: `true`
/// - `refresh_interval_secs`: `300` (5 minutes)
/// - `fetch_timeout_secs`: `10` (10 seconds per package)
/// - `max_concurrent_fetches`: `20` (20 concurrent requests)
///
/// # Examples
///
/// ```
/// use deps_lsp::config::CacheConfig;
///
/// let config = CacheConfig {
///     refresh_interval_secs: 600, // 10 minutes
///     enabled: true,
///     fetch_timeout_secs: 5,
///     max_concurrent_fetches: 20,
/// };
///
/// assert_eq!(config.refresh_interval_secs, 600);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Timeout for fetching a single package's versions (default: 10 seconds)
    #[serde(
        default = "default_fetch_timeout_secs",
        deserialize_with = "deserialize_fetch_timeout"
    )]
    pub fetch_timeout_secs: u64,
    /// Maximum concurrent package fetches (default: 20)
    #[serde(
        default = "default_max_concurrent_fetches",
        deserialize_with = "deserialize_max_concurrent"
    )]
    pub max_concurrent_fetches: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: default_refresh_interval(),
            enabled: true,
            fetch_timeout_secs: default_fetch_timeout_secs(),
            max_concurrent_fetches: default_max_concurrent_fetches(),
        }
    }
}

/// Configuration for loading indicator behavior.
///
/// Controls how the server shows loading feedback when fetching registry data.
///
/// # Defaults
///
/// - `enabled`: `true`
/// - `fallback_to_hints`: `true`
/// - `loading_text`: `"⏳"`
#[derive(Debug, Clone, Deserialize)]
pub struct LoadingIndicatorConfig {
    /// Enable loading indicators (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Show progress in inlay hints if LSP progress not supported (default: true)
    #[serde(default = "default_true")]
    pub fallback_to_hints: bool,

    /// Loading text to show in inlay hints (default: "⏳")
    /// Maximum length: 100 characters (truncated with warning if exceeded)
    #[serde(
        default = "default_loading_text",
        deserialize_with = "deserialize_loading_text"
    )]
    pub loading_text: String,
}

impl Default for LoadingIndicatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fallback_to_hints: true,
            loading_text: default_loading_text(),
        }
    }
}

// Default value functions
const fn default_true() -> bool {
    true
}

fn default_up_to_date() -> String {
    "✅".to_string()
}

fn default_needs_update() -> String {
    "❌ {}".to_string()
}

fn default_loading_text() -> String {
    "⏳".to_string()
}

/// Maximum length for loading_text (security limit)
const MAX_LOADING_TEXT_LENGTH: usize = 100;

/// Truncates and validates loading_text to prevent abuse
fn validate_loading_text(text: String) -> String {
    if text.len() > MAX_LOADING_TEXT_LENGTH {
        tracing::warn!(
            "loading_text exceeded max length of {} chars, truncating from {} to {}",
            MAX_LOADING_TEXT_LENGTH,
            text.len(),
            MAX_LOADING_TEXT_LENGTH
        );
        text.chars().take(MAX_LOADING_TEXT_LENGTH).collect()
    } else {
        text
    }
}

/// Custom deserializer for loading_text that validates length
fn deserialize_loading_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    Ok(validate_loading_text(text))
}

const fn default_outdated_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::HINT
}

const fn default_unknown_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::WARNING
}

const fn default_yanked_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::WARNING
}

const fn default_unsatisfiable_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::WARNING
}

const fn default_deprecated_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::WARNING
}

const fn default_mutable_ref_pin_severity() -> DiagnosticSeverity {
    DiagnosticSeverity::HINT
}

const fn default_refresh_interval() -> u64 {
    300 // 5 minutes
}

const fn default_fetch_timeout_secs() -> u64 {
    5
}

const fn default_max_concurrent_fetches() -> usize {
    20
}

/// Minimum timeout (seconds) to prevent zero-timeout edge case
const MIN_FETCH_TIMEOUT_SECS: u64 = 1;
/// Maximum timeout (seconds) - 5 minutes is generous
const MAX_FETCH_TIMEOUT_SECS: u64 = 300;

/// Minimum concurrent fetches (must be at least 1)
const MIN_CONCURRENT_FETCHES: usize = 1;
/// Maximum concurrent fetches
const MAX_CONCURRENT_FETCHES: usize = 100;

/// Custom deserializer for fetch_timeout_secs that validates bounds
fn deserialize_fetch_timeout<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    let clamped = secs.clamp(MIN_FETCH_TIMEOUT_SECS, MAX_FETCH_TIMEOUT_SECS);
    if clamped != secs {
        tracing::warn!(
            "fetch_timeout_secs {} clamped to {} (valid range: {}-{})",
            secs,
            clamped,
            MIN_FETCH_TIMEOUT_SECS,
            MAX_FETCH_TIMEOUT_SECS
        );
    }
    Ok(clamped)
}

/// Custom deserializer for max_concurrent_fetches that validates bounds
fn deserialize_max_concurrent<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let count = usize::deserialize(deserializer)?;
    let clamped = count.clamp(MIN_CONCURRENT_FETCHES, MAX_CONCURRENT_FETCHES);
    if clamped != count {
        tracing::warn!(
            "max_concurrent_fetches {} clamped to {} (valid range: {}-{})",
            count,
            clamped,
            MIN_CONCURRENT_FETCHES,
            MAX_CONCURRENT_FETCHES
        );
    }
    Ok(clamped)
}

/// Configuration for cold start behavior.
///
/// Controls how the server handles loading documents from disk when
/// they haven't been explicitly opened via didOpen notifications.
///
/// # Defaults
///
/// - `enabled`: `true`
/// - `rate_limit_ms`: `100` (10 req/sec per URI)
///
/// # Security
///
/// File size limit (10MB) is hardcoded and NOT configurable for security reasons.
/// See `loader::MAX_FILE_SIZE` constant.
///
/// # Examples
///
/// ```
/// use deps_lsp::config::ColdStartConfig;
///
/// let config = ColdStartConfig {
///     enabled: true,
///     rate_limit_ms: 200,
/// };
///
/// assert_eq!(config.rate_limit_ms, 200);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ColdStartConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rate_limit_ms")]
    pub rate_limit_ms: u64,
}

impl Default for ColdStartConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_ms: default_rate_limit_ms(),
        }
    }
}

const fn default_rate_limit_ms() -> u64 {
    100 // 10 req/sec per URI
}

/// Configuration for the "Update N outdated dependencies" code lens.
///
/// # Defaults
///
/// - `enabled`: `true`
///
/// # Examples
///
/// ```
/// use deps_lsp::config::CodeLensConfig;
///
/// let config = CodeLensConfig::default();
/// assert!(config.enabled);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct CodeLensConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// Deliberately hand-written rather than `#[derive(Default)]`: `DepsConfig` derives
// `Default` for its own `code_lens` field, so a derived `Default` here (`enabled: false`)
// would silently ship the feature disabled.
impl Default for CodeLensConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Configuration for the release-freshness signal (issue #145).
///
/// Controls whether a recently published "latest" version is flagged as
/// still within a cooldown window, mirroring GitHub Dependabot's default
/// 3-day package cooldown. Applied uniformly across all ecosystems — no
/// per-ecosystem override.
///
/// # Defaults
///
/// - `enabled`: `true`
/// - `cooldown_secs`: `259200` (3 days)
///
/// # Examples
///
/// ```
/// use deps_lsp::config::FreshnessConfig;
///
/// let config = FreshnessConfig {
///     enabled: true,
///     cooldown_secs: 3600,
/// };
///
/// assert_eq!(config.cooldown_secs, 3600);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct FreshnessConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cooldown window in seconds, clamped to 0..=30 days (default: 3 days)
    #[serde(
        default = "default_cooldown_secs",
        deserialize_with = "deserialize_cooldown_secs"
    )]
    pub cooldown_secs: u64,
}

impl Default for FreshnessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_secs: default_cooldown_secs(),
        }
    }
}

impl FreshnessConfig {
    /// Converts this LSP-facing config into the `deps-core` DTO threaded
    /// through `Ecosystem::generate_hover`/`generate_diagnostics`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::config::FreshnessConfig;
    ///
    /// let config = FreshnessConfig::default();
    /// let settings = config.to_settings();
    /// assert!(settings.enabled);
    /// ```
    #[must_use]
    pub const fn to_settings(&self) -> deps_core::FreshnessSettings {
        deps_core::FreshnessSettings {
            enabled: self.enabled,
            cooldown_secs: self.cooldown_secs,
        }
    }
}

const fn default_cooldown_secs() -> u64 {
    deps_core::DEFAULT_COOLDOWN_SECS
}

/// Minimum cooldown window (seconds) — 0 disables the cooldown callout
/// while keeping age display.
const MIN_COOLDOWN_SECS: u64 = 0;
/// Maximum cooldown window (seconds) — 30 days.
const MAX_COOLDOWN_SECS: u64 = 30 * 24 * 60 * 60;

/// Custom deserializer for `cooldown_secs` that validates bounds.
fn deserialize_cooldown_secs<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    let clamped = secs.clamp(MIN_COOLDOWN_SECS, MAX_COOLDOWN_SECS);
    if clamped != secs {
        tracing::warn!(
            "freshness.cooldown_secs {} clamped to {} (valid range: {}-{})",
            secs,
            clamped,
            MIN_COOLDOWN_SECS,
            MAX_COOLDOWN_SECS
        );
    }
    Ok(clamped)
}

/// Cargo ecosystem-specific settings (spec #443, plan-1b §1.7).
///
/// # Examples
///
/// ```
/// use deps_lsp::config::{CargoConfig, WorkspaceRegistriesSetting};
///
/// let config = CargoConfig::default();
/// assert_eq!(config.workspace_registries, WorkspaceRegistriesSetting::PublicOnly);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CargoConfig {
    #[serde(default)]
    pub workspace_registries: WorkspaceRegistriesSetting,
}

/// Controls which workspace-declared Cargo registry index hosts this LSP will ever fetch
/// (spec #443, plan-1b §1.1/§1.7).
///
/// Applies to both the `registry`/`registry-index` alias path (#440) and a
/// `[source.crates-io] replace-with` chain (1b). Never affects a `$CARGO_HOME/config.toml`-
/// configured registry, which is the user's own trusted configuration, not something a
/// cloned repository controls.
///
/// # Defaults
///
/// `"public_only"` — blocking the observed attack shape (an IP literal in a metadata/RFC1918
/// range) without breaking a legitimate corporate `https://index.mycorp.dev` registry (a DNS
/// name cannot be classified as internal without resolving it — see
/// [`deps_core::net_policy`]'s module docs for the residual risk this leaves and why `off`
/// is the only complete boundary).
///
/// # Examples
///
/// ```
/// use deps_lsp::config::WorkspaceRegistriesSetting;
///
/// let setting: WorkspaceRegistriesSetting = serde_json::from_str("\"off\"").unwrap();
/// assert_eq!(setting, WorkspaceRegistriesSetting::Off);
/// ```
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRegistriesSetting {
    /// Block every workspace-declared registry index — the only complete boundary. This
    /// blocks the `registry`/`registry-index` alias path as well as `[source]`; it does
    /// **not** affect `$CARGO_HOME`-configured registries, which keep working.
    Off,
    /// Allow only a host classified as public (spec `deps_core::net_policy::HostClass::Global`).
    #[default]
    PublicOnly,
    /// Allow every workspace-declared index, including loopback/RFC1918/metadata-range
    /// hosts — today's pre-#443 behavior, the escape hatch for a workspace that legitimately
    /// points at one.
    All,
}

impl WorkspaceRegistriesSetting {
    /// Converts this LSP-facing setting into the `deps-core` policy value threaded through
    /// `deps_cargo::config::RegistryIndex::new`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::WorkspaceRegistryAccess;
    /// use deps_lsp::config::WorkspaceRegistriesSetting;
    ///
    /// assert_eq!(
    ///     WorkspaceRegistriesSetting::Off.to_policy(),
    ///     WorkspaceRegistryAccess::Off
    /// );
    /// ```
    #[must_use]
    pub const fn to_policy(self) -> deps_core::net_policy::WorkspaceRegistryAccess {
        match self {
            Self::Off => deps_core::net_policy::WorkspaceRegistryAccess::Off,
            Self::PublicOnly => deps_core::net_policy::WorkspaceRegistryAccess::PublicOnly,
            Self::All => deps_core::net_policy::WorkspaceRegistryAccess::All,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DepsConfig::default();
        assert!(config.inlay_hints.enabled);
        assert_eq!(config.inlay_hints.up_to_date_text, "✅");
        assert_eq!(config.inlay_hints.needs_update_text, "❌ {}");
        assert_eq!(
            config.cargo.workspace_registries,
            WorkspaceRegistriesSetting::PublicOnly
        );
    }

    #[test]
    fn test_workspace_registries_setting_deserializes_all_variants() {
        assert_eq!(
            serde_json::from_str::<WorkspaceRegistriesSetting>("\"off\"").unwrap(),
            WorkspaceRegistriesSetting::Off
        );
        assert_eq!(
            serde_json::from_str::<WorkspaceRegistriesSetting>("\"public_only\"").unwrap(),
            WorkspaceRegistriesSetting::PublicOnly
        );
        assert_eq!(
            serde_json::from_str::<WorkspaceRegistriesSetting>("\"all\"").unwrap(),
            WorkspaceRegistriesSetting::All
        );
    }

    #[test]
    fn test_cargo_config_section_deserialization() {
        let json = r#"{"cargo": {"workspace_registries": "off"}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.cargo.workspace_registries,
            WorkspaceRegistriesSetting::Off
        );
    }

    #[test]
    fn test_workspace_registries_setting_to_policy() {
        use deps_core::net_policy::WorkspaceRegistryAccess;

        assert_eq!(
            WorkspaceRegistriesSetting::Off.to_policy(),
            WorkspaceRegistryAccess::Off
        );
        assert_eq!(
            WorkspaceRegistriesSetting::PublicOnly.to_policy(),
            WorkspaceRegistryAccess::PublicOnly
        );
        assert_eq!(
            WorkspaceRegistriesSetting::All.to_policy(),
            WorkspaceRegistryAccess::All
        );
    }

    #[test]
    fn test_inlay_hints_config_deserialization() {
        let json = r#"{
            "enabled": false,
            "up_to_date_text": "OK",
            "needs_update_text": "UPDATE {}"
        }"#;

        let config: InlayHintsConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.up_to_date_text, "OK");
        assert_eq!(config.needs_update_text, "UPDATE {}");
    }

    #[test]
    fn test_diagnostics_config_deserialization() {
        let json = r#"{
            "outdated_severity": 1,
            "unknown_severity": 2,
            "yanked_severity": 2,
            "unsatisfiable_severity": 1,
            "deprecated_severity": 1
        }"#;

        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.outdated_severity, DiagnosticSeverity::ERROR);
        assert_eq!(config.unknown_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.yanked_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.unsatisfiable_severity, DiagnosticSeverity::ERROR);
        assert_eq!(config.deprecated_severity, DiagnosticSeverity::ERROR);
    }

    #[test]
    fn test_diagnostics_config_unsatisfiable_severity_defaults_warning() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.unsatisfiable_severity, DiagnosticSeverity::WARNING);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.unsatisfiable_severity, DiagnosticSeverity::WARNING);
    }

    /// D8/O3: no `deprecated_enabled` toggle exists — severity is the only knob, matching
    /// the other four fields' precedent (deprecation adds no network call).
    #[test]
    fn test_diagnostics_config_deprecated_severity_defaults_warning() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.deprecated_severity, DiagnosticSeverity::WARNING);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.deprecated_severity, DiagnosticSeverity::WARNING);
    }

    /// Severity default (issue #473) — see `mutable_ref_pin_enabled` tests below for the
    /// separate on/off toggle, unlike `deprecated_severity`'s severity-only precedent.
    #[test]
    fn test_diagnostics_config_mutable_ref_pin_severity_defaults_hint() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.mutable_ref_pin_severity, DiagnosticSeverity::HINT);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mutable_ref_pin_severity, DiagnosticSeverity::HINT);
    }

    /// FR-009 (corrected during implementation review): mirrors
    /// `test_diagnostics_config_vulnerabilities_enabled_defaults_true` — this diagnostic
    /// does need a real `_enabled` toggle, since severity alone cannot suppress it.
    #[test]
    fn test_diagnostics_config_mutable_ref_pin_enabled_defaults_true() {
        let config = DiagnosticsConfig::default();
        assert!(config.mutable_ref_pin_enabled);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert!(config.mutable_ref_pin_enabled);
    }

    #[test]
    fn test_diagnostics_config_mutable_ref_pin_enabled_can_be_disabled() {
        let json = r#"{ "mutable_ref_pin_enabled": false }"#;
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert!(!config.mutable_ref_pin_enabled);
    }

    #[test]
    fn test_diagnostics_config_vulnerabilities_enabled_defaults_true() {
        let config = DiagnosticsConfig::default();
        assert!(config.vulnerabilities_enabled);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert!(config.vulnerabilities_enabled);
    }

    #[test]
    fn test_diagnostics_config_vulnerabilities_enabled_can_be_disabled() {
        let json = r#"{ "vulnerabilities_enabled": false }"#;
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert!(!config.vulnerabilities_enabled);
    }

    #[test]
    fn test_cache_config_deserialization() {
        let json = r#"{
            "refresh_interval_secs": 600,
            "enabled": false
        }"#;

        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.refresh_interval_secs, 600);
        assert!(!config.enabled);
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.refresh_interval_secs, 300);
        assert_eq!(config.fetch_timeout_secs, 5);
        assert_eq!(config.max_concurrent_fetches, 20);
    }

    #[test]
    fn test_cache_config_with_timeout_and_concurrency() {
        let json = r#"{
            "refresh_interval_secs": 600,
            "enabled": true,
            "fetch_timeout_secs": 10,
            "max_concurrent_fetches": 50
        }"#;

        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.refresh_interval_secs, 600);
        assert!(config.enabled);
        assert_eq!(config.fetch_timeout_secs, 10);
        assert_eq!(config.max_concurrent_fetches, 50);
    }

    #[test]
    fn test_full_config_deserialization() {
        let json = r#"{
            "inlay_hints": {
                "enabled": true,
                "up_to_date_text": "✅",
                "needs_update_text": "❌ {}"
            },
            "diagnostics": {
                "outdated_severity": 4,
                "unknown_severity": 2,
                "yanked_severity": 2
            },
            "cache": {
                "refresh_interval_secs": 300,
                "enabled": true
            }
        }"#;

        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(config.inlay_hints.enabled);
        assert_eq!(
            config.diagnostics.outdated_severity,
            DiagnosticSeverity::HINT
        );
        assert_eq!(config.cache.refresh_interval_secs, 300);
    }

    #[test]
    fn test_partial_config_deserialization() {
        let json = r#"{
            "inlay_hints": {
                "enabled": false
            }
        }"#;

        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(!config.inlay_hints.enabled);
        // Other fields should use defaults
        assert_eq!(config.inlay_hints.up_to_date_text, "✅");
        assert_eq!(
            config.diagnostics.outdated_severity,
            DiagnosticSeverity::HINT
        );
    }

    #[test]
    fn test_empty_config_deserialization() {
        let json = r"{}";
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        // All fields should use defaults
        assert!(config.inlay_hints.enabled);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_cold_start_config_defaults() {
        let config = ColdStartConfig::default();
        assert!(config.enabled);
        assert_eq!(config.rate_limit_ms, 100);
    }

    #[test]
    fn test_cold_start_config_deserialization() {
        let json = r#"{
            "enabled": false,
            "rate_limit_ms": 200
        }"#;

        let config: ColdStartConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.rate_limit_ms, 200);
    }

    #[test]
    fn test_full_config_with_cold_start() {
        let json = r#"{
            "cold_start": {
                "enabled": true,
                "rate_limit_ms": 150
            }
        }"#;

        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(config.cold_start.enabled);
        assert_eq!(config.cold_start.rate_limit_ms, 150);
    }

    #[test]
    fn test_loading_indicator_config_defaults() {
        let config = LoadingIndicatorConfig::default();
        assert!(config.enabled);
        assert!(config.fallback_to_hints);
        assert_eq!(config.loading_text, "⏳");
    }

    #[test]
    fn test_loading_indicator_config_deserialization() {
        let json = r#"{
            "enabled": false,
            "fallback_to_hints": false,
            "loading_text": "Loading..."
        }"#;

        let config: LoadingIndicatorConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert!(!config.fallback_to_hints);
        assert_eq!(config.loading_text, "Loading...");
    }

    #[test]
    fn test_loading_text_truncation() {
        let long_text = "a".repeat(150);
        let json = format!(
            r#"{{
            "enabled": true,
            "fallback_to_hints": true,
            "loading_text": "{}"
        }}"#,
            long_text
        );

        let config: LoadingIndicatorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.loading_text.len(), 100);
        assert_eq!(config.loading_text, "a".repeat(100));
    }

    #[test]
    fn test_loading_text_exactly_100_chars() {
        let text = "a".repeat(100);
        let json = format!(
            r#"{{
            "enabled": true,
            "fallback_to_hints": true,
            "loading_text": "{}"
        }}"#,
            text
        );

        let config: LoadingIndicatorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.loading_text.len(), 100);
        assert_eq!(config.loading_text, text);
    }

    #[test]
    fn test_loading_text_under_limit() {
        let json = r#"{
            "enabled": true,
            "fallback_to_hints": true,
            "loading_text": "⏳ Loading dependencies..."
        }"#;

        let config: LoadingIndicatorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.loading_text, "⏳ Loading dependencies...");
        assert!(config.loading_text.len() < 100);
    }

    #[test]
    fn test_loading_text_default() {
        let json = r#"{
            "enabled": true,
            "fallback_to_hints": true
        }"#;

        let config: LoadingIndicatorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.loading_text, "⏳");
    }

    #[test]
    fn test_cache_config_fetch_timeout_clamped_min() {
        let json = r#"{"fetch_timeout_secs": 0}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.fetch_timeout_secs, 1, "Should clamp 0 to MIN");
    }

    #[test]
    fn test_cache_config_fetch_timeout_clamped_max() {
        let json = r#"{"fetch_timeout_secs": 999999}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.fetch_timeout_secs, 300, "Should clamp to MAX");
    }

    #[test]
    fn test_cache_config_fetch_timeout_valid_range() {
        let json = r#"{"fetch_timeout_secs": 10}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.fetch_timeout_secs, 10,
            "Valid value should not be clamped"
        );
    }

    #[test]
    fn test_cache_config_max_concurrent_clamped_min() {
        let json = r#"{"max_concurrent_fetches": 0}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_concurrent_fetches, 1, "Should clamp 0 to MIN");
    }

    #[test]
    fn test_cache_config_max_concurrent_clamped_max() {
        let json = r#"{"max_concurrent_fetches": 100000}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_concurrent_fetches, 100, "Should clamp to MAX");
    }

    #[test]
    fn test_cache_config_max_concurrent_valid_range() {
        let json = r#"{"max_concurrent_fetches": 50}"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.max_concurrent_fetches, 50,
            "Valid value should not be clamped"
        );
    }

    #[test]
    fn test_code_lens_config_defaults() {
        let config = CodeLensConfig::default();
        assert!(config.enabled);
    }

    #[test]
    fn test_code_lens_config_deserialization() {
        let json = r#"{"enabled": false}"#;
        let config: CodeLensConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn test_code_lens_config_empty_object_defaults_to_enabled() {
        let config: CodeLensConfig = serde_json::from_str("{}").unwrap();
        assert!(config.enabled);
    }

    #[test]
    fn test_deps_config_default_has_code_lens_enabled() {
        // Regression guard: DepsConfig derives Default, which would silently produce
        // `enabled: false` if CodeLensConfig ever switched to a derived Default.
        let config = DepsConfig::default();
        assert!(config.code_lens.enabled);
    }

    #[test]
    fn test_freshness_config_defaults() {
        let config = FreshnessConfig::default();
        assert!(config.enabled);
        assert_eq!(config.cooldown_secs, 259_200);
    }

    #[test]
    fn test_freshness_config_partial_deserialization() {
        let json = r#"{"enabled": false}"#;
        let config: FreshnessConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.cooldown_secs, 259_200, "Should use default");
    }

    #[test]
    fn test_freshness_config_custom_cooldown() {
        let json = r#"{"cooldown_secs": 3600}"#;
        let config: FreshnessConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled, "Should use default");
        assert_eq!(config.cooldown_secs, 3600);
    }

    #[test]
    fn test_freshness_config_cooldown_clamped_min() {
        let json = r#"{"cooldown_secs": 0}"#;
        let config: FreshnessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cooldown_secs, 0, "0 disables the cooldown callout");
    }

    #[test]
    fn test_freshness_config_cooldown_clamped_max() {
        let json = r#"{"cooldown_secs": 99999999}"#;
        let config: FreshnessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.cooldown_secs,
            30 * 24 * 60 * 60,
            "Should clamp to 30 days"
        );
    }

    #[test]
    fn test_freshness_config_to_settings() {
        let config = FreshnessConfig {
            enabled: false,
            cooldown_secs: 1800,
        };
        let settings = config.to_settings();
        assert!(!settings.enabled);
        assert_eq!(settings.cooldown_secs, 1800);
    }

    #[test]
    fn test_deps_config_includes_freshness_default() {
        let config = DepsConfig::default();
        assert!(config.freshness.enabled);
        assert_eq!(config.freshness.cooldown_secs, 259_200);
    }

    #[test]
    fn test_deps_config_empty_json_includes_freshness_default() {
        let config: DepsConfig = serde_json::from_str("{}").unwrap();
        assert!(config.freshness.enabled);
        assert_eq!(config.freshness.cooldown_secs, 259_200);
    }
}
