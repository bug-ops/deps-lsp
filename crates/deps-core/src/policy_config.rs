use crate::diagnostic::Severity;
use serde::Deserialize;

/// The policy-relevant subset of `deps-lsp`'s configuration.
///
/// Diagnostic severities, HTTP caching, release-freshness, supply-chain trust,
/// custom-registry access, network/offline mode, and license policy. Split out from
/// `deps-lsp::config::DepsConfig` (which keeps only its editor-only sections — inlay hints,
/// loading indicator, code lens, cold-start disk loading) so `deps-lsp` and `deps-cli` compose
/// the identical, single-sourced type instead of each parsing its own copy (constitution
/// principle 1).
///
/// Every section struct below (`DiagnosticsConfig`, `CacheConfig`, `FreshnessConfig`,
/// `SupplyChainConfig`, `RegistriesConfig`, `NetworkConfig`, `LicensePolicyConfig`,
/// `TyposquatConfig`) is
/// `#[non_exhaustive]`, matching `deps-core`'s general convention (issue #1064) — a field added
/// to any of them no longer breaks every downstream crate that names the struct's full literal
/// shape. `PolicyConfig` itself deliberately stays exhaustive: issue #1064/FR-006 scopes this to
/// the 8 leaf structs specifically, since `PolicyConfig`'s own fields only change when a whole
/// new policy *section* is added — a much rarer, more architecturally significant event than a
/// field added to an existing section.
///
/// This used to cost an exhaustive-destructure security guarantee (issue #592 security M1):
/// `deps-lsp::config::reparse_scope` used to destructure every field of every section here
/// directly, so the compiler rejected the build when a new field was added without an explicit
/// decision on whether it invalidates already-open documents. That guarantee now lives in
/// [`PolicyConfig::diff`] instead: it performs the same exhaustive, `..`-free destructuring, but
/// from inside `deps-core`, where `#[non_exhaustive]` does not restrict same-crate
/// destructuring. Its result, `PolicyConfigDiff`, is a plain (not `#[non_exhaustive]`) struct
/// that `deps-lsp::config::reparse_scope` destructures exhaustively in turn, carrying the same
/// compile-time guarantee across the crate boundary.
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::PolicyConfig;
///
/// let policy = PolicyConfig::default();
/// assert!(policy.diagnostics.vulnerabilities_enabled);
/// assert!(!policy.network.offline);
/// ```
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyConfig {
    /// Diagnostic severity and behavior settings.
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
    /// HTTP response cache settings.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Release-cooldown / freshness-window settings.
    #[serde(default)]
    pub freshness: FreshnessConfig,
    /// Supply-chain trust signal (Scorecard/SLSA) settings.
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,
    /// Custom/alternate registry settings.
    #[serde(default)]
    pub registries: RegistriesConfig,
    /// Network access and offline-mode settings.
    #[serde(default)]
    pub network: NetworkConfig,
    /// License policy (allow/deny list) settings.
    #[serde(default)]
    pub license_policy: LicensePolicyConfig,
    /// Typosquat-similarity diagnostic settings (issue #1437).
    #[serde(default)]
    pub typosquat: TyposquatConfig,
}

/// Which leaf fields differ between two [`PolicyConfig`] snapshots, at the exact granularity
/// `deps-lsp::config::reparse_scope` classifies them at.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike every section struct above:
/// `deps-lsp::config::reparse_scope` destructures this exhaustively (no `..`) to guarantee
/// every leaf field is mapped to a `ReparseScope` decision. Only `registries`'s three fields
/// are individually parse-affecting today (each scopes a different set of ecosystems), so this
/// carries one bool per leaf field of that section rather than one bool per section — see
/// [`PolicyConfig::diff`]'s doc for why the other six sections have no fields here at all.
///
/// # The E0027 mechanism this design relies on (issue #1064, NFR-004)
///
/// [`PolicyConfig::diff`] destructures every section of [`PolicyConfig`] exhaustively — no `..`
/// rest pattern at any level — so a field added to any of the 8 policy section structs without
/// also naming it in that destructuring fails to compile (rustc E0027), exactly as
/// `deps-lsp::config::reparse_scope` used to enforce directly before issue #592's guarantee
/// moved here. The doctest below only illustrates that underlying Rust language mechanism on a
/// synthetic, unrelated struct — an exhaustive struct-destructure pattern (no `..`) fails to
/// compile once the struct gains a field the pattern does not name. It does **not** itself
/// re-verify that `PolicyConfig::diff`'s or `reparse_scope`'s *real* destructuring stays
/// `..`-free (it would keep passing even if a `..` crept into either); a CI grep step
/// (`.github/workflows/ci.yml`'s `doc-and-hygiene` job, mirroring that job's existing
/// `test-util` leak guard) asserts that instead, on every PR.
///
/// ```compile_fail
/// struct Example {
///     a: bool,
///     b: bool,
///     // A hypothetical field added later without updating the destructure below — the same
///     // shape as adding a field to, say, `SupplyChainConfig` without updating
///     // `PolicyConfig::diff`'s destructure of it.
///     c: bool,
/// }
///
/// let e = Example { a: true, b: false, c: true };
/// // Missing `c` here fails with E0027.
/// let Example { a: _, b: _ } = e;
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyConfigDiff {
    /// Whether [`RegistriesConfig::workspace_registries`] changed.
    pub workspace_registries_changed: bool,
    /// Whether [`RegistriesConfig::nuget_user_profile_sources`] changed.
    pub nuget_user_profile_sources_changed: bool,
    /// Whether [`RegistriesConfig::gitlab_instance_host`] changed.
    pub gitlab_instance_host_changed: bool,
}

impl PolicyConfig {
    /// Reports which leaf fields differ between `old` and `new`.
    ///
    /// Exhaustively destructures both snapshots' sections — no `..` rest pattern at any
    /// level — so a field added to any of the 8 section structs forces an explicit decision
    /// here (see [`PolicyConfigDiff`]'s compile-time guarantee). `diagnostics`, `cache`,
    /// `freshness`, `supply_chain`, `network`, `license_policy`, and `typosquat` are destructured
    /// field-by-field purely to force that decision — as of today, none of their leaf fields
    /// are parse-affecting (a config change there is picked up the next time diagnostics/hover
    /// are requested, without invalidating already-parsed document state), so no field of
    /// theirs appears in [`PolicyConfigDiff`] itself. Only `registries`'s three fields are
    /// individually parse-affecting, since each scopes a different, narrower set of
    /// ecosystems (see `deps-lsp::config::{NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS,
    /// GITLAB_INSTANCE_HOST_ECOSYSTEMS}`).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::PolicyConfig;
    ///
    /// let old = PolicyConfig::default();
    /// let mut new = PolicyConfig::default();
    /// new.registries.nuget_user_profile_sources = true;
    ///
    /// let diff = PolicyConfig::diff(&old, &new);
    /// assert!(diff.nuget_user_profile_sources_changed);
    /// assert!(!diff.workspace_registries_changed);
    /// assert!(!diff.gitlab_instance_host_changed);
    /// ```
    #[must_use]
    pub fn diff(old: &Self, new: &Self) -> PolicyConfigDiff {
        let Self {
            diagnostics: new_diagnostics,
            cache: new_cache,
            freshness: new_freshness,
            supply_chain: new_supply_chain,
            registries: new_registries,
            network: new_network,
            license_policy: new_license_policy,
            typosquat: new_typosquat,
        } = new;

        // Not parse-affecting: exhaustive `_` bindings (never `..`) force a decision when a
        // field is added. `_` is rustc's E0027 fix-it default, but if a new field affects
        // already-parsed document state, add a diff bool instead (mirroring `registries` below).
        let DiagnosticsConfig {
            outdated_severity: _,
            unknown_severity: _,
            yanked_severity: _,
            unsatisfiable_severity: _,
            deprecated_severity: _,
            mutable_ref_pin_severity: _,
            mutable_ref_pin_enabled: _,
            vulnerabilities_enabled: _,
        } = new_diagnostics;
        let CacheConfig {
            enabled: _,
            fetch_timeout_secs: _,
            max_concurrent_fetches: _,
        } = new_cache;
        let FreshnessConfig {
            enabled: _,
            cooldown_secs: _,
        } = new_freshness;
        let SupplyChainConfig { enabled: _ } = new_supply_chain;
        let NetworkConfig { offline: _ } = new_network;
        let LicensePolicyConfig { allow: _, deny: _ } = new_license_policy;
        let TyposquatConfig { enabled: _ } = new_typosquat;

        // Parse-affecting: each leaf field of `registries` is individually diffed.
        let RegistriesConfig {
            workspace_registries: new_workspace_registries,
            nuget_user_profile_sources: new_nuget_user_profile_sources,
            gitlab_instance_host: new_gitlab_instance_host,
        } = new_registries;
        let RegistriesConfig {
            workspace_registries: old_workspace_registries,
            nuget_user_profile_sources: old_nuget_user_profile_sources,
            gitlab_instance_host: old_gitlab_instance_host,
        } = &old.registries;

        PolicyConfigDiff {
            workspace_registries_changed: old_workspace_registries != new_workspace_registries,
            nuget_user_profile_sources_changed: old_nuget_user_profile_sources
                != new_nuget_user_profile_sources,
            gitlab_instance_host_changed: old_gitlab_instance_host != new_gitlab_instance_host,
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
/// - `mutable_ref_pin_severity`: `HINT` - Dependencies pinned to a mutable ref (tag/branch) instead of a commit SHA (GitHub Actions `uses:` steps, GitLab CI `project:`/`component:` includes)
/// - `mutable_ref_pin_enabled`: `true` - Whether the mutable-ref-pin diagnostic runs at all
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::DiagnosticsConfig;
/// use deps_core::diagnostic::Severity;
///
/// let config = DiagnosticsConfig::new()
///     .with_outdated_severity(Severity::Information)
///     .with_unknown_severity(Severity::Error)
///     .with_yanked_severity(Severity::Error)
///     .with_unsatisfiable_severity(Severity::Error)
///     .with_deprecated_severity(Severity::Error)
///     .with_mutable_ref_pin_severity(Severity::Error)
///     .with_mutable_ref_pin_enabled(true)
///     .with_vulnerabilities_enabled(true);
///
/// assert_eq!(config.unknown_severity, Severity::Error);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct DiagnosticsConfig {
    /// Severity for a dependency with a newer version available.
    #[serde(default = "default_outdated_severity")]
    pub outdated_severity: Severity,
    /// Severity for a dependency not found in the registry.
    #[serde(default = "default_unknown_severity")]
    pub unknown_severity: Severity,
    /// Severity for a dependency pinned to a yanked/retracted version.
    #[serde(default = "default_yanked_severity")]
    pub yanked_severity: Severity,
    /// Severity for a dependency whose requirement matches zero published versions.
    #[serde(default = "default_unsatisfiable_severity")]
    pub unsatisfiable_severity: Severity,
    /// Severity for a dependency on a package the registry reports as
    /// deprecated/abandoned (issue #205). No corresponding `deprecated_enabled`
    /// toggle: unlike `vulnerabilities_enabled`, this signal is derived from
    /// already-fetched data (zero new registry requests — see #205's plan §1
    /// D2), so a boolean would gate only string formatting, not a network
    /// call. Matches the severity-only precedent set by the four fields above.
    #[serde(default = "default_deprecated_severity")]
    pub deprecated_severity: Severity,
    /// Severity for a dependency pinned to a mutable ref (a tag/branch) instead of a
    /// full commit SHA — a GitHub Actions `uses:` step (issue #473) or a GitLab CI
    /// `project:`/`component:` include (issue #634). Tunes loudness only; see
    /// `mutable_ref_pin_enabled` for the on/off toggle.
    #[serde(default = "default_mutable_ref_pin_severity")]
    pub mutable_ref_pin_severity: Severity,
    /// Whether the mutable-ref-pin diagnostic (issue #473, extended to GitLab CI by
    /// issue #634) runs at all. Default
    /// `true`. **Corrected during implementation review (spec 031 FR-009)**: unlike
    /// `deprecated_severity`, this diagnostic *does* need a real `_enabled` toggle —
    /// `Severity` has no suppression value, and severity is never treated
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
        Self::new()
    }
}

impl DiagnosticsConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::DiagnosticsConfig;
    /// use deps_core::diagnostic::Severity;
    ///
    /// let config = DiagnosticsConfig::new();
    /// assert_eq!(config.outdated_severity, Severity::Hint);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
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

    /// Overrides [`Self::outdated_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_outdated_severity(mut self, outdated_severity: Severity) -> Self {
        self.outdated_severity = outdated_severity;
        self
    }

    /// Overrides [`Self::unknown_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_unknown_severity(mut self, unknown_severity: Severity) -> Self {
        self.unknown_severity = unknown_severity;
        self
    }

    /// Overrides [`Self::yanked_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_yanked_severity(mut self, yanked_severity: Severity) -> Self {
        self.yanked_severity = yanked_severity;
        self
    }

    /// Overrides [`Self::unsatisfiable_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_unsatisfiable_severity(mut self, unsatisfiable_severity: Severity) -> Self {
        self.unsatisfiable_severity = unsatisfiable_severity;
        self
    }

    /// Overrides [`Self::deprecated_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_deprecated_severity(mut self, deprecated_severity: Severity) -> Self {
        self.deprecated_severity = deprecated_severity;
        self
    }

    /// Overrides [`Self::mutable_ref_pin_severity`]. See [`Self::new`].
    #[must_use]
    pub const fn with_mutable_ref_pin_severity(
        mut self,
        mutable_ref_pin_severity: Severity,
    ) -> Self {
        self.mutable_ref_pin_severity = mutable_ref_pin_severity;
        self
    }

    /// Overrides [`Self::mutable_ref_pin_enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_mutable_ref_pin_enabled(mut self, mutable_ref_pin_enabled: bool) -> Self {
        self.mutable_ref_pin_enabled = mutable_ref_pin_enabled;
        self
    }

    /// Overrides [`Self::vulnerabilities_enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_vulnerabilities_enabled(mut self, vulnerabilities_enabled: bool) -> Self {
        self.vulnerabilities_enabled = vulnerabilities_enabled;
        self
    }

    /// Converts this LSP-facing config into the `deps-core` DTO threaded
    /// through `Ecosystem::generate_diagnostics`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::DiagnosticsConfig;
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
    pub const fn to_severities(&self) -> crate::DiagnosticSeverities {
        crate::DiagnosticSeverities::new()
            .with_outdated(self.outdated_severity)
            .with_unknown(self.unknown_severity)
            .with_yanked(self.yanked_severity)
            .with_unsatisfiable(self.unsatisfiable_severity)
            .with_deprecated(self.deprecated_severity)
            .with_mutable_ref_pin(self.mutable_ref_pin_severity)
            .with_mutable_ref_pin_enabled(self.mutable_ref_pin_enabled)
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
/// use deps_core::policy_config::CacheConfig;
///
/// let config = CacheConfig::new()
///     .with_fetch_timeout_secs(5)
///     .with_max_concurrent_fetches(20);
///
/// assert_eq!(config.fetch_timeout_secs, 5);
/// ```
#[non_exhaustive]
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
        Self::new()
    }
}

impl CacheConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::CacheConfig;
    ///
    /// let config = CacheConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            enabled: true,
            fetch_timeout_secs: default_fetch_timeout_secs(),
            max_concurrent_fetches: default_max_concurrent_fetches(),
        }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Overrides [`Self::fetch_timeout_secs`]. See [`Self::new`]. Not clamped to the
    /// bounds `deserialize_fetch_timeout` enforces — that validation only guards
    /// untrusted LSP-client input, not construction from trusted Rust code.
    #[must_use]
    pub const fn with_fetch_timeout_secs(mut self, fetch_timeout_secs: u64) -> Self {
        self.fetch_timeout_secs = fetch_timeout_secs;
        self
    }

    /// Overrides [`Self::max_concurrent_fetches`]. See [`Self::new`]. Enforces the same
    /// `>= 1` floor (`MIN_CONCURRENT_FETCHES`) that `deserialize_max_concurrent` enforces
    /// on untrusted LSP-client input — but, unlike that deserializer, does not also cap the
    /// `MAX_CONCURRENT_FETCHES` ceiling, so a very large value passes through uncapped: this
    /// value is used directly as `futures::StreamExt::buffer_unordered`'s concurrency limit
    /// (`document::fetch`), and `buffer_unordered(0)` never polls its source stream, hanging
    /// the fetch forever instead of erroring (issue #833) — unlike
    /// [`Self::with_fetch_timeout_secs`], `0` here is not a merely degenerate value, so this
    /// setter enforces the floor itself rather than relying on a downstream re-guard
    /// (`handlers::diagnostics::loading_ceiling` also re-guards its own divisor, but that is
    /// a second, independent consumer, not a safety net for this one).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::CacheConfig;
    ///
    /// let config = CacheConfig::new().with_max_concurrent_fetches(0);
    /// assert_eq!(config.max_concurrent_fetches, 1);
    /// ```
    #[must_use]
    pub const fn with_max_concurrent_fetches(mut self, max_concurrent_fetches: usize) -> Self {
        self.max_concurrent_fetches = if max_concurrent_fetches == 0 {
            MIN_CONCURRENT_FETCHES
        } else {
            max_concurrent_fetches
        };
        self
    }
}

const fn default_true() -> bool {
    true
}

const fn default_outdated_severity() -> Severity {
    Severity::Hint
}

const fn default_unknown_severity() -> Severity {
    Severity::Warning
}

const fn default_yanked_severity() -> Severity {
    Severity::Warning
}

const fn default_unsatisfiable_severity() -> Severity {
    Severity::Warning
}

const fn default_deprecated_severity() -> Severity {
    Severity::Warning
}

const fn default_mutable_ref_pin_severity() -> Severity {
    Severity::Hint
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
/// use deps_core::policy_config::FreshnessConfig;
///
/// let config = FreshnessConfig::new().with_cooldown_secs(3600);
///
/// assert_eq!(config.cooldown_secs, 3600);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct FreshnessConfig {
    /// Whether the release-cooldown freshness signal is enabled at all.
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
        Self::new()
    }
}

impl FreshnessConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::FreshnessConfig;
    ///
    /// let config = FreshnessConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            enabled: true,
            cooldown_secs: default_cooldown_secs(),
        }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Overrides [`Self::cooldown_secs`]. See [`Self::new`]. Not clamped to the bounds
    /// `deserialize_cooldown_secs` enforces — that validation only guards untrusted
    /// LSP-client input, not construction from trusted Rust code.
    #[must_use]
    pub const fn with_cooldown_secs(mut self, cooldown_secs: u64) -> Self {
        self.cooldown_secs = cooldown_secs;
        self
    }

    /// Converts this LSP-facing config into the `deps-core` DTO threaded
    /// through `Ecosystem::generate_hover`/`generate_diagnostics`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::FreshnessConfig;
    ///
    /// let config = FreshnessConfig::default();
    /// let settings = config.to_settings();
    /// assert!(settings.enabled);
    /// ```
    #[must_use]
    pub const fn to_settings(&self) -> crate::FreshnessSettings {
        crate::FreshnessSettings {
            enabled: self.enabled,
            cooldown_secs: self.cooldown_secs,
        }
    }
}

const fn default_cooldown_secs() -> u64 {
    crate::DEFAULT_COOLDOWN_SECS
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
/// use deps_core::policy_config::SupplyChainConfig;
///
/// let config = SupplyChainConfig::default();
/// assert!(config.enabled);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct SupplyChainConfig {
    /// Whether supply-chain trust signals (OpenSSF Scorecard/SLSA provenance) are fetched.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// Hand-written, not derived: a derived `Default` would silently ship this disabled. Delegates
// to `Self::new` so the literal has one source of truth (mirrors `CodeLensConfig`).
impl Default for SupplyChainConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyChainConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// `deps-core`, so every other crate must chain the `with_*` setters onto this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::SupplyChainConfig;
    ///
    /// let config = SupplyChainConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self { enabled: true }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
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
/// use deps_core::policy_config::{RegistriesConfig, WorkspaceRegistriesSetting};
///
/// let config = RegistriesConfig::default();
/// assert_eq!(config.workspace_registries, WorkspaceRegistriesSetting::PublicOnly);
/// ```
///
/// `#[derive(RedactingDebug)]` (#936): `gitlab_instance_host` is a raw, unvalidated host
/// literal that can be credential-shaped (e.g. `user:hunter2@gitlab.corp`) since no
/// validation happens at deserialization time (see that field's own doc) — without redaction,
/// a derived `Debug` would print it verbatim into `server.rs`'s
/// `tracing::debug!("loaded configuration: {:?}", config)` at `RUST_LOG=debug`, before
/// `deps_gitlab_ci::host::GitlabInstanceHost::get` ever gets a chance to reject it.
#[non_exhaustive]
#[derive(Clone, Deserialize, crate::redact_debug::RedactingDebug)]
pub struct RegistriesConfig {
    /// Whether workspace-declared registry hosts (e.g. a manifest's own custom index
    /// URLs) may be reached at all, or only the default public registry.
    #[serde(default)]
    #[raw]
    pub workspace_registries: WorkspaceRegistriesSetting,
    /// Issue #561, FR-006: whether a NuGet user-profile-tier `NuGet.Config` `<add>` with no
    /// repo-declared counterpart becomes a routing hop (`AlternateRegistry`-sourced, so
    /// OSV/deps.dev/hover-trust are suppressed for it — spec 035 §5a), not just a credential
    /// source for a repo-declared entry at the same URL. `#[serde(default)]`: additive-safe,
    /// since `RegistriesConfig` itself is not under `DepsConfig`'s top-level
    /// `deny_unknown_fields`. Default `false` — zero routing effect from any user-profile file
    /// unless explicitly opted in.
    #[serde(default)]
    #[raw]
    pub nuget_user_profile_sources: bool,
    /// Issue #466, spec FR-005a/FR-011a: the GitLab instance host that `project:` includes
    /// and `$CI_SERVER_FQDN`-relative `component:` includes resolve against, and — replacing,
    /// not joined with, `gitlab.com` — the *only* host `GITLAB_TOKEN` may be sent to.
    /// `#[serde(default)]`: additive-safe, same rationale as `nuget_user_profile_sources`
    /// above. Default `""` (unset); an empty string is written through as `None` into the
    /// shared `Arc<RwLock<Option<String>>>` handle. **No validation happens at deserialization
    /// time** — `deps-lsp` must not depend on `deps-gitlab-ci` for host semantics, so this
    /// type accepts any string. Two validation points exist downstream instead: once per
    /// config update, via `deps_engine::setup::validate_gitlab_instance_host` (which surfaces
    /// a rejection to the user); and lazily on every read, via
    /// `deps_gitlab_ci::host::GitlabInstanceHost::get`, which also documents the
    /// already-open-document limitation of a live change to this setting.
    #[serde(default)]
    #[redact(url)]
    pub gitlab_instance_host: String,
}

// Hand-written, not derived, delegating to `Self::new` for a single source of truth
// (matches `SupplyChainConfig`'s/`NetworkConfig`'s rationale).
impl Default for RegistriesConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistriesConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// `deps-core`, so every other crate must chain the `with_*` setters onto this
    /// constructor instead. Not `const`, unlike `SupplyChainConfig::new`/`NetworkConfig::new` —
    /// `gitlab_instance_host` is a `String`, the same reason `InlayHintsConfig::new`
    /// (`deps-lsp/src/config.rs`) isn't `const` either.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::{RegistriesConfig, WorkspaceRegistriesSetting};
    ///
    /// let config = RegistriesConfig::new();
    /// assert_eq!(config.workspace_registries, WorkspaceRegistriesSetting::PublicOnly);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            workspace_registries: WorkspaceRegistriesSetting::PublicOnly,
            nuget_user_profile_sources: false,
            gitlab_instance_host: String::new(),
        }
    }

    /// Overrides [`Self::workspace_registries`]. See [`Self::new`].
    #[must_use]
    pub const fn with_workspace_registries(
        mut self,
        workspace_registries: WorkspaceRegistriesSetting,
    ) -> Self {
        self.workspace_registries = workspace_registries;
        self
    }

    /// Overrides [`Self::nuget_user_profile_sources`]. See [`Self::new`].
    #[must_use]
    pub const fn with_nuget_user_profile_sources(
        mut self,
        nuget_user_profile_sources: bool,
    ) -> Self {
        self.nuget_user_profile_sources = nuget_user_profile_sources;
        self
    }

    /// Overrides [`Self::gitlab_instance_host`]. See [`Self::new`].
    #[must_use]
    pub fn with_gitlab_instance_host(mut self, gitlab_instance_host: impl Into<String>) -> Self {
        self.gitlab_instance_host = gitlab_instance_host.into();
        self
    }
}

/// The three live-updatable settings [`RegistriesConfig::resolve`] derives from a config
/// snapshot.
///
/// Every consumer that needs to turn a [`RegistriesConfig`] into runtime-usable values
/// (`deps_engine::setup::EcosystemRuntime::from_policy`, and `deps-lsp`'s two config-reload
/// call sites in `initialize`/`did_change_configuration`) shares this one derivation instead
/// of each re-deriving `gitlab_instance_host`'s empty-string-to-`None` normalization
/// independently — three copies of that normalization is exactly the kind of drift-prone
/// duplication issue #1058 (T009) found and closed.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistryRuntimeSettings {
    /// Resolved workspace-registry access policy — see [`WorkspaceRegistriesSetting::to_policy`].
    pub workspace_registries: crate::net_policy::WorkspaceRegistryAccess,
    /// See [`RegistriesConfig::nuget_user_profile_sources`].
    pub nuget_user_profile_sources: bool,
    /// See [`RegistriesConfig::gitlab_instance_host`] — normalized from an empty string to
    /// `None`.
    pub gitlab_instance_host: Option<String>,
}

impl std::fmt::Debug for RegistryRuntimeSettings {
    /// Manual, not derived: `gitlab_instance_host` is a raw host string one hop away from
    /// [`RegistriesConfig`]'s own redacting `Debug` impl (#936), the same "sibling missed by a
    /// prior sweep" pattern as the rest of this leak class (CWE-532, #1222).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryRuntimeSettings")
            .field("workspace_registries", &self.workspace_registries)
            .field(
                "nuget_user_profile_sources",
                &self.nuget_user_profile_sources,
            )
            .field(
                "gitlab_instance_host",
                &self
                    .gitlab_instance_host
                    .as_deref()
                    .map(crate::redact::RedactedUrl::new),
            )
            .finish()
    }
}

impl RegistriesConfig {
    /// Derives the three live-updatable settings this section resolves into.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::WorkspaceRegistryAccess;
    /// use deps_core::policy_config::RegistriesConfig;
    ///
    /// let config = RegistriesConfig::new().with_gitlab_instance_host("gitlab.corp");
    /// let resolved = config.resolve();
    /// assert_eq!(resolved.workspace_registries, WorkspaceRegistryAccess::PublicOnly);
    /// assert_eq!(resolved.gitlab_instance_host.as_deref(), Some("gitlab.corp"));
    /// ```
    #[must_use]
    pub fn resolve(&self) -> RegistryRuntimeSettings {
        RegistryRuntimeSettings {
            workspace_registries: self.workspace_registries.to_policy(),
            nuget_user_profile_sources: self.nuget_user_profile_sources,
            gitlab_instance_host: (!self.gitlab_instance_host.is_empty())
                .then(|| self.gitlab_instance_host.clone()),
        }
    }
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
/// [`crate::net_policy`]'s module docs for the residual risk this leaves and why `off`
/// is the only complete boundary).
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::WorkspaceRegistriesSetting;
///
/// let setting: WorkspaceRegistriesSetting = serde_json::from_str("\"off\"").unwrap();
/// assert_eq!(setting, WorkspaceRegistriesSetting::Off);
/// ```
#[non_exhaustive]
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
    /// use deps_core::policy_config::WorkspaceRegistriesSetting;
    ///
    /// assert_eq!(
    ///     WorkspaceRegistriesSetting::Off.to_policy(),
    ///     WorkspaceRegistryAccess::Off
    /// );
    /// ```
    #[must_use]
    pub const fn to_policy(self) -> crate::net_policy::WorkspaceRegistryAccess {
        match self {
            Self::Off => crate::net_policy::WorkspaceRegistryAccess::Off,
            Self::PublicOnly => crate::net_policy::WorkspaceRegistryAccess::PublicOnly,
            Self::All => crate::net_policy::WorkspaceRegistryAccess::All,
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
/// use deps_core::policy_config::NetworkConfig;
///
/// let config = NetworkConfig::default();
/// assert!(!config.offline);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
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

// Hand-written, not derived, delegating to `Self::new` for a single source of truth
// (matches `SupplyChainConfig`'s rationale).
impl Default for NetworkConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// `deps-core`, so every other crate must chain the `with_*` setters onto this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::NetworkConfig;
    ///
    /// let config = NetworkConfig::new();
    /// assert!(!config.offline);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self { offline: false }
    }

    /// Overrides [`Self::offline`]. See [`Self::new`].
    #[must_use]
    pub const fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }
}

/// SPDX allow-list/deny-list policy for the license-policy diagnostic (issue #661, spec 010
/// Phase 2).
///
/// Both lists are independently optional; an empty/default policy produces no diagnostics.
/// Not parse-affecting (see `deps-lsp::config::reparse_scope`): a change here is picked up
/// the next time diagnostics are pulled, without forcing a document reparse, since policy
/// evaluation reads the current config fresh on every diagnostics request rather than being
/// baked into parse-time state.
///
/// # Defaults
///
/// - `allow`: `[]`
/// - `deny`: `[]`
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::LicensePolicyConfig;
///
/// let config = LicensePolicyConfig::default();
/// assert!(config.to_policy().is_empty());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LicensePolicyConfig {
    /// SPDX identifiers a dependency's license must include at least one of, when non-empty.
    #[serde(default, deserialize_with = "deserialize_spdx_list")]
    pub allow: Vec<String>,
    /// SPDX identifiers a dependency's license must not include any of.
    #[serde(default, deserialize_with = "deserialize_spdx_list")]
    pub deny: Vec<String>,
}

impl LicensePolicyConfig {
    /// Builds an empty allow/deny policy (mirrors [`Self::default`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::LicensePolicyConfig;
    ///
    /// let config = LicensePolicyConfig::new();
    /// assert!(config.allow.is_empty());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Overrides [`Self::allow`]. See [`Self::new`]. Takes `Vec<String>` rather than
    /// `impl Into<String>` — this field is a list, not a single string — mirroring
    /// `deps_core::ResolvedPackage::with_dependencies`'s existing precedent for a `Vec<String>`
    /// field, not this module's single-`String`-field setters (e.g.
    /// `deps-lsp::config::InlayHintsConfig::with_up_to_date_text`).
    #[must_use]
    pub fn with_allow(mut self, allow: Vec<String>) -> Self {
        self.allow = allow;
        self
    }

    /// Overrides [`Self::deny`]. See [`Self::new`] and [`Self::with_allow`]'s note on this
    /// setter's parameter type.
    #[must_use]
    pub fn with_deny(mut self, deny: Vec<String>) -> Self {
        self.deny = deny;
        self
    }

    /// Converts this LSP-facing config into the `deps-core` policy threaded through
    /// [`crate::licenses::evaluate`].
    ///
    /// Both fields already went through `deserialize_spdx_list` at config-load time, so
    /// this never drops entries or logs a warning of its own — [`crate::LicensePolicy::new`]
    /// simply re-validates already-clean data, which is a no-op.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::LicensePolicyConfig;
    ///
    /// let config = LicensePolicyConfig::new()
    ///     .with_allow(vec!["MIT".to_string()])
    ///     .with_deny(vec!["GPL-3.0".to_string()]);
    /// let policy = config.to_policy();
    /// assert_eq!(policy.allow, vec!["MIT".to_string()]);
    /// ```
    #[must_use]
    pub fn to_policy(&self) -> crate::LicensePolicy {
        crate::LicensePolicy::new(self.allow.clone(), self.deny.clone())
    }
}

/// Configuration for the typosquat-similarity diagnostic (issue #1437, spec 071).
///
/// Controls whether a declared dependency is checked against deps.dev's
/// `GetSimilarlyNamedPackages` endpoint for a much-more-popular, similarly-named package —
/// a possible sign of a typo or a typosquat. Ships **disabled by default**: unlike
/// `supply_chain`/`diagnostics.vulnerabilities_enabled` (both opt-out), this signal is built
/// on an undocumented, v3alpha (no stability guarantee) similarity algorithm, so spec 071
/// §9 resolves it as opt-in only at launch, with default-on deferred to a separate future
/// issue once the endpoint has shown stability across releases.
///
/// # Defaults
///
/// - `enabled`: `false`
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::TyposquatConfig;
///
/// let config = TyposquatConfig::default();
/// assert!(!config.enabled);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TyposquatConfig {
    /// Whether the typosquat-similarity diagnostic runs at all.
    #[serde(default)]
    pub enabled: bool,
}

impl TyposquatConfig {
    /// Builds the default (disabled) configuration (mirrors [`Self::default`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::TyposquatConfig;
    ///
    /// let config = TyposquatConfig::new();
    /// assert!(!config.enabled);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self { enabled: false }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Custom deserializer for `LicensePolicyConfig`'s `allow`/`deny` lists: drops (and warns
/// about, via [`crate::licenses::filter_valid_spdx_ids`]) any entry that isn't
/// syntactically a plausible single SPDX identifier, exactly once at config-load time —
/// same "warn, never crash" contract as every other custom deserializer in this module (spec
/// 010 plan.md's "Invalid SPDX identifier in policy" decision: `initializationOptions` has no
/// document URI to anchor an LSP diagnostic to, so a log warning is the only feedback
/// channel).
fn deserialize_spdx_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<String>::deserialize(deserializer)?;
    Ok(crate::licenses::filter_valid_spdx_ids(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_config_defaults() {
        let policy = PolicyConfig::default();
        assert!(policy.diagnostics.vulnerabilities_enabled);
        assert!(!policy.network.offline);
        assert_eq!(
            policy.registries.workspace_registries,
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

    /// #936: `RegistriesConfig`'s `#[derive(RedactingDebug)]`-generated `Debug` impl must
    /// redact a credential-shaped `gitlab_instance_host` while still identifying the host.
    #[test]
    fn test_registries_config_debug_redacts_gitlab_instance_host_credential() {
        let config = RegistriesConfig {
            gitlab_instance_host: "user:hunter2@gitlab.corp".to_string(),
            ..RegistriesConfig::default()
        };

        let section_debug = format!("{config:?}");
        assert!(!section_debug.contains("hunter2"), "{section_debug}");
        assert!(section_debug.contains("gitlab.corp"), "{section_debug}");
    }

    #[test]
    fn test_workspace_registries_setting_to_policy() {
        use crate::net_policy::WorkspaceRegistryAccess;

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

    /// #1058 M1: `WorkspaceRegistryAccess::default()` (`net_policy.rs`) and
    /// `WorkspaceRegistriesSetting::default()` (this module) are two independent `#[default]`
    /// derives that must resolve to the same policy — `ServerState::new`'s
    /// `EcosystemRuntime::from_policy(&PolicyConfig::default())` relies on this equivalence to
    /// reproduce the same defaults its old hand-built `RegistryAccessPolicy::default()` call
    /// had. Nothing else catches the two drifting apart; this test does.
    #[test]
    fn test_workspace_registry_access_default_matches_workspace_registries_setting_default() {
        assert_eq!(
            crate::net_policy::WorkspaceRegistryAccess::default(),
            WorkspaceRegistriesSetting::default().to_policy()
        );
    }

    #[test]
    fn test_registries_config_resolve_normalizes_empty_gitlab_instance_host_to_none() {
        let resolved = RegistriesConfig::default().resolve();
        assert_eq!(resolved.gitlab_instance_host, None);
        assert!(!resolved.nuget_user_profile_sources);
    }

    #[test]
    fn test_registries_config_resolve_carries_non_default_settings() {
        use crate::net_policy::WorkspaceRegistryAccess;

        let config = RegistriesConfig {
            workspace_registries: WorkspaceRegistriesSetting::All,
            nuget_user_profile_sources: true,
            gitlab_instance_host: "gitlab.corp".to_string(),
        };

        let resolved = config.resolve();
        assert_eq!(resolved.workspace_registries, WorkspaceRegistryAccess::All);
        assert!(resolved.nuget_user_profile_sources);
        assert_eq!(
            resolved.gitlab_instance_host.as_deref(),
            Some("gitlab.corp")
        );
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
        assert_eq!(config.outdated_severity, Severity::Error);
        assert_eq!(config.unknown_severity, Severity::Warning);
        assert_eq!(config.yanked_severity, Severity::Warning);
        assert_eq!(config.unsatisfiable_severity, Severity::Error);
        assert_eq!(config.deprecated_severity, Severity::Error);
    }

    #[test]
    fn test_diagnostics_config_mutable_ref_pin_enabled_can_be_disabled() {
        let json = r#"{ "mutable_ref_pin_enabled": false }"#;
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert!(!config.mutable_ref_pin_enabled);
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
    fn test_cache_config_with_enabled() {
        let config = CacheConfig::new().with_enabled(false);
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
    fn test_cache_config_fetch_timeout_clamped() {
        let json = r#"{ "fetch_timeout_secs": 10000 }"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.fetch_timeout_secs, MAX_FETCH_TIMEOUT_SECS);
    }

    #[test]
    fn test_cache_config_max_concurrent_fetches_clamped() {
        let json = r#"{ "max_concurrent_fetches": 0 }"#;
        let config: CacheConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_concurrent_fetches, MIN_CONCURRENT_FETCHES);
    }

    #[test]
    fn test_freshness_config_defaults() {
        let config = FreshnessConfig::default();
        assert!(config.enabled);
        assert_eq!(config.cooldown_secs, crate::DEFAULT_COOLDOWN_SECS);
    }

    #[test]
    fn test_freshness_config_cooldown_clamped() {
        let json = r#"{ "cooldown_secs": 99999999 }"#;
        let config: FreshnessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.cooldown_secs, MAX_COOLDOWN_SECS);
    }

    #[test]
    fn test_supply_chain_config_defaults() {
        assert!(SupplyChainConfig::default().enabled);
    }

    #[test]
    fn test_supply_chain_config_with_enabled() {
        assert!(!SupplyChainConfig::new().with_enabled(false).enabled);
    }

    #[test]
    fn test_network_config_defaults() {
        assert!(!NetworkConfig::default().offline);
    }

    #[test]
    fn test_network_config_with_offline() {
        assert!(NetworkConfig::new().with_offline(true).offline);
    }

    #[test]
    fn test_policy_config_diff_no_change_returns_all_false() {
        let old = PolicyConfig::default();
        let new = PolicyConfig::default();
        assert_eq!(PolicyConfig::diff(&old, &new), PolicyConfigDiff::default());
    }

    #[test]
    fn test_policy_config_diff_workspace_registries_change() {
        let old = PolicyConfig::default();
        let mut new = PolicyConfig::default();
        new.registries.workspace_registries = WorkspaceRegistriesSetting::Off;

        let diff = PolicyConfig::diff(&old, &new);
        assert!(diff.workspace_registries_changed);
        assert!(!diff.nuget_user_profile_sources_changed);
        assert!(!diff.gitlab_instance_host_changed);
    }

    #[test]
    fn test_policy_config_diff_nuget_user_profile_sources_change() {
        let old = PolicyConfig::default();
        let mut new = PolicyConfig::default();
        new.registries.nuget_user_profile_sources = true;

        let diff = PolicyConfig::diff(&old, &new);
        assert!(!diff.workspace_registries_changed);
        assert!(diff.nuget_user_profile_sources_changed);
        assert!(!diff.gitlab_instance_host_changed);
    }

    #[test]
    fn test_policy_config_diff_gitlab_instance_host_change() {
        let old = PolicyConfig::default();
        let mut new = PolicyConfig::default();
        new.registries.gitlab_instance_host = "gitlab.corp".to_string();

        let diff = PolicyConfig::diff(&old, &new);
        assert!(!diff.workspace_registries_changed);
        assert!(!diff.nuget_user_profile_sources_changed);
        assert!(diff.gitlab_instance_host_changed);
    }

    /// A non-registries change (issue #1064) must not surface in the diff at all — this is the
    /// same "not parse-affecting" set `reparse_scope` already ignored before this PR.
    #[test]
    fn test_policy_config_diff_non_registries_change_returns_all_false() {
        let old = PolicyConfig::default();
        let mut new = PolicyConfig::default();
        new.network.offline = true;
        new.freshness.cooldown_secs = 60;

        assert_eq!(PolicyConfig::diff(&old, &new), PolicyConfigDiff::default());
    }

    #[test]
    fn test_license_policy_config_invalid_spdx_dropped() {
        let json = r#"{ "allow": ["MIT", "not a valid spdx id!!"] }"#;
        let config: LicensePolicyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.allow, vec!["MIT".to_string()]);
    }

    crate::debug_redaction_conformance!(
        test_registry_runtime_settings_debug_redacts_credentials,
        1,
        RegistryRuntimeSettings {
            workspace_registries: crate::net_policy::WorkspaceRegistryAccess::PublicOnly,
            nuget_user_profile_sources: false,
            gitlab_instance_host: Some(crate::conformance::CREDENTIAL_PROBE_URL.to_string()),
        },
    );
}
