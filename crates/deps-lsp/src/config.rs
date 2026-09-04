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
    pub supply_chain: SupplyChainConfig,
    #[serde(default)]
    pub registries: RegistriesConfig,
    #[serde(default)]
    pub network: NetworkConfig,
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
/// - `fetch_timeout_secs`: `10` (10 seconds per package)
/// - `max_concurrent_fetches`: `20` (20 concurrent requests)
///
/// # Examples
///
/// ```
/// use deps_lsp::config::CacheConfig;
///
/// let config = CacheConfig {
///     enabled: true,
///     fetch_timeout_secs: 5,
///     max_concurrent_fetches: 20,
/// };
///
/// assert_eq!(config.fetch_timeout_secs, 5);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Whether `deps_core::cache::HttpCache`'s entry map is used at all (issue #482):
    /// `false` bypasses it entirely (fetch fresh every time, never store).
    ///
    /// **Offline override**: while `network.offline` (see [`NetworkConfig::offline`]) is
    /// set, this flag's `false` value is overridden and treated as `true` — otherwise a
    /// warm entry fetched before going offline could never survive an online→offline
    /// transition, since nothing would have been stored while online in the first place.
    ///
    /// **Maven exception**: `deps-maven`'s `peek_cached`-based stale-data fallback
    /// (`crates/deps-maven/src/registry.rs`) behaves differently from every other
    /// ecosystem under `enabled: false`, which has no equivalent second-layer fallback to
    /// diverge on. This only "always misses" for a process that started cold with the
    /// flag already off — `peek_cached` reads the entry map directly and
    /// `set_cache_enabled` never clears it, so a *live* `true` -> `false` toggle leaves
    /// every already-stored entry servable through this fallback indefinitely.
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

/// Configuration for the supply-chain trust signal (spec 037, issue #543).
///
/// Controls whether hover attempts a deps.dev OpenSSF Scorecard / SLSA
/// provenance lookup for the hovered dependency. This is the first feature
/// to send package names to a third party that is not the package's own
/// registry, so it gets an off switch like every other opt-out-able signal
/// in this server (`diagnostics.vulnerabilities_enabled`), rather than
/// requiring a user on a locked-down network to go fully offline.
///
/// # Defaults
///
/// - `enabled`: `true`
///
/// # Examples
///
/// ```
/// use deps_lsp::config::SupplyChainConfig;
///
/// let config = SupplyChainConfig::default();
/// assert!(config.enabled);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct SupplyChainConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// Deliberately hand-written, mirroring `CodeLensConfig`'s rationale: a derived
// `Default` would silently ship the feature disabled.
impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
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

/// Cross-ecosystem workspace-declared registry settings (spec #443/plan-1b §1.7, renamed
/// from `cargo.workspace_registries` by `032-npm-npmrc-registry-support` FR-008/C2).
///
/// **Breaking, pre-1.0, no alias.** `HttpCache` holds exactly one global
/// `Arc<RegistryAccessPolicy>`, so this setting was never actually Cargo-scoped — it already
/// governed every ecosystem's workspace-declared registry fetches (the npm `.npmrc`
/// `registry=`/`@scope:registry=` path included, once that feature also reads it). A client
/// still sending the old `cargo` key fails `DepsConfig`'s top-level `deny_unknown_fields`
/// parse — since that attribute sits on `DepsConfig` itself, not on this section, the
/// rejection takes the **whole** settings payload with it, not just this one setting. Sent at
/// `initialize` (the common case) that means every setting reverts to its default — safely,
/// for the security-relevant one here, since `WorkspaceRegistriesSetting::default()` is
/// `PublicOnly` and `HttpCache::new` already starts there; sent later via
/// `workspace/didChangeConfiguration` the previously applied configuration is kept instead.
/// Either way the failure is logged (`tracing::warn!`), just not surfaced by most editors.
///
/// # Examples
///
/// ```
/// use deps_lsp::config::{RegistriesConfig, WorkspaceRegistriesSetting};
///
/// let config = RegistriesConfig::default();
/// assert_eq!(config.workspace_registries, WorkspaceRegistriesSetting::PublicOnly);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegistriesConfig {
    #[serde(default)]
    pub workspace_registries: WorkspaceRegistriesSetting,
    /// Issue #561, FR-006: whether a NuGet user-profile-tier `NuGet.Config` `<add>` with no
    /// repo-declared counterpart becomes a routing hop (`AlternateRegistry`-sourced, so
    /// OSV/deps.dev/hover-trust are suppressed for it — spec 035 §5a), not just a credential
    /// source for a repo-declared entry at the same URL. `#[serde(default)]`: additive-safe,
    /// since `RegistriesConfig` itself is not under `DepsConfig`'s top-level
    /// `deny_unknown_fields`. Default `false` — zero routing effect from any user-profile file
    /// unless explicitly opted in.
    #[serde(default)]
    pub nuget_user_profile_sources: bool,
}

/// Controls which workspace-declared registry index hosts this LSP will ever fetch.
///
/// Shared by every ecosystem with a workspace-declared-registry concept (spec #443,
/// plan-1b §1.1/§1.7; `032-npm-npmrc-registry-support` FR-008 widened this from Cargo-only
/// to cross-ecosystem).
///
/// Applies to Cargo's `registry`/`registry-index` alias path (#440), a
/// `[source.crates-io] replace-with` chain (1b), and npm's `.npmrc` `registry=`/
/// `@scope:registry=` resolution alike. Never affects a `$CARGO_HOME/config.toml`-configured
/// Cargo registry, which is the user's own trusted configuration, not something a cloned
/// repository controls — npm's `.npmrc` has no equivalent always-trusted tier (both its
/// project and user tiers are policy-symmetric, since phase 1 carries no credential
/// provenance to protect).
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

/// Configuration for outbound network access (issue #483).
///
/// # Defaults
///
/// - `offline`: `false`
///
/// # Examples
///
/// ```
/// use deps_lsp::config::NetworkConfig;
///
/// let config = NetworkConfig::default();
/// assert!(!config.offline);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// When `true`, blocks every *new* outbound registry/OSV/GitHub-tags request
    /// (`deps_core::cache::HttpCache`'s 4 send sites) instead of making it, serving
    /// already-cached data where available and returning `deps_core::DepsError::Offline`
    /// otherwise. Also forces `cache.enabled` semantics to `true` for the duration (see
    /// [`CacheConfig::enabled`]'s doc comment), so a warm entry keeps serving through an
    /// online→offline transition even if caching was explicitly disabled.
    ///
    /// `HttpCache::set_offline` is a bare atomic store: a request already past its
    /// `ensure_online` check and awaiting a response completes normally, and toggling
    /// this flag never cancels in-flight requests.
    #[serde(default)]
    pub offline: bool,
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
            config.registries.workspace_registries,
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
    fn test_registries_config_section_deserialization() {
        let json = r#"{"registries": {"workspace_registries": "off"}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.registries.workspace_registries,
            WorkspaceRegistriesSetting::Off
        );
    }

    /// The renamed key: a client still sending the old `cargo` section fails the whole
    /// settings payload's `deny_unknown_fields` parse (N-S2) — never silently accepted as a
    /// no-op, and never partially applied.
    #[test]
    fn test_old_cargo_config_key_is_rejected_not_silently_ignored() {
        let json = r#"{"cargo": {"workspace_registries": "off"}}"#;
        assert!(serde_json::from_str::<DepsConfig>(json).is_err());
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
            "enabled": false
        }"#;

        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.fetch_timeout_secs, 5);
        assert_eq!(config.max_concurrent_fetches, 20);
    }

    #[test]
    fn test_cache_config_with_timeout_and_concurrency() {
        let json = r#"{
            "enabled": true,
            "fetch_timeout_secs": 10,
            "max_concurrent_fetches": 50
        }"#;

        let config: CacheConfig = serde_json::from_str(json).unwrap();
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
                "enabled": true
            }
        }"#;

        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(config.inlay_hints.enabled);
        assert_eq!(
            config.diagnostics.outdated_severity,
            DiagnosticSeverity::HINT
        );
        assert!(config.cache.enabled);
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
    fn test_supply_chain_config_defaults() {
        let config = SupplyChainConfig::default();
        assert!(config.enabled);
    }

    #[test]
    fn test_supply_chain_config_deserialization() {
        let json = r#"{"enabled": false}"#;
        let config: SupplyChainConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn test_supply_chain_config_empty_object_defaults_to_enabled() {
        let config: SupplyChainConfig = serde_json::from_str("{}").unwrap();
        assert!(config.enabled);
    }

    #[test]
    fn test_deps_config_default_has_supply_chain_enabled() {
        // Regression guard: DepsConfig derives Default, which would silently produce
        // `enabled: false` if SupplyChainConfig ever switched to a derived Default.
        let config = DepsConfig::default();
        assert!(config.supply_chain.enabled);
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

    #[test]
    fn test_network_config_defaults_to_online() {
        let config = NetworkConfig::default();
        assert!(!config.offline);

        let config: DepsConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.network.offline);
    }

    #[test]
    fn test_network_config_accepts_offline_true() {
        let json = r#"{"network":{"offline":true}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(config.network.offline);
    }
}
