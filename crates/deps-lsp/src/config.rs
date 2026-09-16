/// Re-exported so `deps_lsp::config::{DiagnosticsConfig, CacheConfig, ...}` keeps resolving
/// for existing callers (in this crate and downstream) after these types moved to
/// `deps-core` — see [`deps_core::policy_config`] for the canonical, shared definitions.
pub use deps_core::policy_config::{
    CacheConfig, DiagnosticsConfig, FreshnessConfig, LicensePolicyConfig, NetworkConfig,
    PolicyConfig, RegistriesConfig, SupplyChainConfig, WorkspaceRegistriesSetting,
};
// Not part of the `pub use` above: `PolicyConfigDiff`'s only consumer in this crate is the
// `pub(crate)` `reparse_scope` below — no external caller needs it.
use deps_core::policy_config::PolicyConfigDiff;
use serde::Deserialize;

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
#[non_exhaustive]
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DepsConfig {
    /// Inline version-annotation settings.
    #[serde(default)]
    pub inlay_hints: InlayHintsConfig,
    /// Cold-start disk-load behavior settings.
    #[serde(default)]
    pub cold_start: ColdStartConfig,
    /// Loading-indicator (spinner/progress) settings.
    #[serde(default)]
    pub loading_indicator: LoadingIndicatorConfig,
    /// Code lens (update-all action) settings.
    #[serde(default)]
    pub code_lens: CodeLensConfig,
    /// The policy-relevant sections (diagnostics, cache, freshness, supply_chain, registries,
    /// network, license_policy) shared with `deps-cli` — see [`deps_core::policy_config`].
    /// `#[serde(flatten)]` keeps this crate's accepted JSON shape flat at the top level
    /// (`{"cache": {...}, "network": {...}}`), exactly as before this type moved to
    /// `deps-core` — verified empirically to still combine correctly with this struct's own
    /// `deny_unknown_fields` (see `tests::test_flatten_preserves_deny_unknown_fields_rejection`).
    #[serde(flatten)]
    pub policy: PolicyConfig,
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
/// let config = InlayHintsConfig::new()
///     .with_up_to_date_text("OK")
///     .with_needs_update_text("UPDATE {}");
///
/// assert_eq!(config.up_to_date_text, "OK");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct InlayHintsConfig {
    /// Whether inlay hints are shown at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Text shown when the dependency is already at the latest version.
    #[serde(default = "default_up_to_date")]
    pub up_to_date_text: String,
    /// Text shown when an update is available; `{}` is replaced with the latest version.
    #[serde(default = "default_needs_update")]
    pub needs_update_text: String,
}

impl Default for InlayHintsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl InlayHintsConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must chain the `with_*` setters onto this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::config::InlayHintsConfig;
    ///
    /// let config = InlayHintsConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            up_to_date_text: default_up_to_date(),
            needs_update_text: default_needs_update(),
        }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Overrides [`Self::up_to_date_text`]. See [`Self::new`].
    #[must_use]
    pub fn with_up_to_date_text(mut self, up_to_date_text: impl Into<String>) -> Self {
        self.up_to_date_text = up_to_date_text.into();
        self
    }

    /// Overrides [`Self::needs_update_text`]. See [`Self::new`].
    #[must_use]
    pub fn with_needs_update_text(mut self, needs_update_text: impl Into<String>) -> Self {
        self.needs_update_text = needs_update_text.into();
        self
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
#[non_exhaustive]
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
/// let config = ColdStartConfig::new().with_rate_limit_ms(200);
///
/// assert_eq!(config.rate_limit_ms, 200);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct ColdStartConfig {
    /// Whether cold-start disk loading is enabled at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum delay in milliseconds between cold-start registry fetches for the same URI.
    #[serde(default = "default_rate_limit_ms")]
    pub rate_limit_ms: u64,
}

impl Default for ColdStartConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ColdStartConfig {
    /// Builds the default configuration (mirrors [`Self::default`]).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must chain the `with_*` setters onto this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::config::ColdStartConfig;
    ///
    /// let config = ColdStartConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            enabled: true,
            rate_limit_ms: default_rate_limit_ms(),
        }
    }

    /// Overrides [`Self::enabled`]. See [`Self::new`].
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Overrides [`Self::rate_limit_ms`]. See [`Self::new`].
    #[must_use]
    pub const fn with_rate_limit_ms(mut self, rate_limit_ms: u64) -> Self {
        self.rate_limit_ms = rate_limit_ms;
        self
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
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct CodeLensConfig {
    /// Whether the "Update N outdated dependencies" code lens is shown at all.
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

/// Which open documents a config change invalidates and must reparse (issue #592).
///
/// `All` and a named `Ecosystems` set both exist so a change with a narrow, known blast
/// radius (e.g. `registries.nuget_user_profile_sources` only ever affects NuGet's parse
/// context) doesn't force a workspace-wide reparse.
///
/// **On `reparse_scope`'s actual safety property (security review correction)**: in
/// production, [`reparse_scope`] never returns `All` today — every currently-classified
/// field maps to a specific `Ecosystems` scope, not the fail-open `All` branch. The real
/// safety mechanism is that function's exhaustive destructuring: adding a field to
/// `DepsConfig` (or one of its sections) without updating `reparse_scope` is a compile error
/// (E0027), not a silent gap — verified empirically. That compile error does **not** itself
/// pick a safe branch, though: rustc's own suggested fix for it is `field: _`, which is
/// exactly the not-parse-affecting shape every existing field already uses. A developer
/// adding a genuinely security-relevant future field (e.g. a hypothetical
/// `network.proxy_url`) who follows that suggestion mechanically would make it silently
/// non-parse-affecting — the compile error forces *a* decision, it does not make the *safe*
/// decision for you. Whoever adds such a field must consciously map it to
/// [`ReparseScope::All`] (or a narrower scope) instead of reaching for `_`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReparseScope {
    /// Reparse every open document, regardless of ecosystem.
    All,
    /// Reparse only open documents whose `ecosystem_id()` is one of these.
    Ecosystems(Vec<&'static str>),
}

impl ReparseScope {
    /// Whether a document of this ecosystem falls within scope.
    pub(crate) fn matches(&self, ecosystem_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Ecosystems(ids) => ids.contains(&ecosystem_id),
        }
    }

    /// Unions two scopes together (issue #592: coalescing a burst of config changes must
    /// not lose an earlier change's scope to a later, narrower one). `All` absorbs
    /// anything; two `Ecosystems` sets are deduplicated-merged.
    pub(crate) fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::All, _) | (_, Self::All) => Self::All,
            (Self::Ecosystems(mut a), Self::Ecosystems(b)) => {
                for id in b {
                    if !a.contains(&id) {
                        a.push(id);
                    }
                }
                Self::Ecosystems(a)
            }
        }
    }
}

/// The only ecosystem `registries.nuget_user_profile_sources` affects.
const NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS: &[&str] = &["nuget"];

/// The only ecosystem `registries.gitlab_instance_host` affects.
///
/// Same single-ecosystem-scoped shape as [`NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS`], not a
/// member of `workspace_registry_ecosystems`: `deps_gitlab_ci::parser::parse_gitlab_ci_yaml`
/// resolves this setting into a `deps_gitlab_ci::types::HostRef` once, at parse time (see
/// `resolve_project_host`/`resolve_component_host`), so a changed instance host leaves
/// already-open documents' cached `HostRef`s stale until they are re-parsed. Listed
/// unconditionally here even though the `gitlab-ci` feature can be compiled out — `ReparseScope`
/// only ever narrows an *already-registered* ecosystem, so naming an absent one is a no-op, not
/// a hazard.
const GITLAB_INSTANCE_HOST_ECOSYSTEMS: &[&str] = &["gitlab-ci"];

/// Diffs `old` against `new` and returns the [`ReparseScope`] of open documents a
/// live-reloaded config change invalidates, or `None` if nothing parse-affecting changed
/// (issue #592).
///
/// `DepsConfig`'s own top-level sections (`inlay_hints`, `cold_start`, `loading_indicator`,
/// `code_lens` — untouched by spec 063 PR B) are destructured exhaustively here — **no `..`
/// rest pattern** — so a field added to `DepsConfig` itself is a compile error in this
/// function until it is explicitly classified as either not parse-affecting (bound to `_`,
/// its value never read) or mapped to a scope. `PolicyConfig`'s 7 sections are
/// `#[non_exhaustive]` (issue #1064), so this function no longer destructures them directly:
/// it delegates to [`deps_core::policy_config::PolicyConfig::diff`], which performs the same
/// exhaustive, `..`-free destructuring from inside `deps-core` (where `#[non_exhaustive]`
/// does not restrict same-crate destructuring), and consumes its `PolicyConfigDiff` result —
/// itself not `#[non_exhaustive]` — exhaustively in turn. This can't catch a field whose
/// *documented meaning* changes without changing its type (e.g. a hypothetical
/// `network.proxy_url`) — destructuring forces a human to look at every field, it cannot make
/// the classification decision by itself.
///
/// `workspace_registry_ecosystems` — the ecosystem ids to scope a `registries.workspace_registries`
/// change to — is a caller-supplied parameter rather than a hardcoded list in this module
/// (issue #592 security M1): the true set is whatever `register_ecosystems` (`lib.rs`)
/// actually threads the live `RegistryAccessPolicy` handle into, returned by that same
/// function and stored on `ServerState::workspace_registry_ecosystems`. Hardcoding a second,
/// independently-maintained copy here would let the two drift — a 6th policy-consuming
/// ecosystem added to `register_ecosystems` without updating a duplicate list would fail
/// *closed*: exactly the scenario #592 exists to close, since that ecosystem would keep
/// silently showing versions resolved under a revoked policy.
pub(crate) fn reparse_scope(
    old: &DepsConfig,
    new: &DepsConfig,
    workspace_registry_ecosystems: &[&'static str],
) -> Option<ReparseScope> {
    let DepsConfig {
        inlay_hints: new_inlay_hints,
        cold_start: new_cold_start,
        loading_indicator: new_loading_indicator,
        code_lens: new_code_lens,
        policy: new_policy,
    } = new;

    // Not parse-affecting: every field is named (never `..`), so its value is simply
    // unused here rather than compared, but a new field on any of these sections still
    // forces a decision at this line.
    let InlayHintsConfig {
        enabled: _,
        up_to_date_text: _,
        needs_update_text: _,
    } = new_inlay_hints;
    let ColdStartConfig {
        enabled: _,
        rate_limit_ms: _,
    } = new_cold_start;
    let LoadingIndicatorConfig {
        enabled: _,
        fallback_to_hints: _,
        loading_text: _,
    } = new_loading_indicator;
    let CodeLensConfig { enabled: _ } = new_code_lens;

    let PolicyConfigDiff {
        workspace_registries_changed,
        nuget_user_profile_sources_changed,
        gitlab_instance_host_changed,
    } = PolicyConfig::diff(&old.policy, new_policy);

    let mut scope: Option<ReparseScope> = None;
    let union_in = |scope: &mut Option<ReparseScope>, addition: ReparseScope| {
        *scope = Some(match scope.take() {
            Some(existing) => existing.union(addition),
            None => addition,
        });
    };

    if workspace_registries_changed {
        union_in(
            &mut scope,
            ReparseScope::Ecosystems(workspace_registry_ecosystems.to_vec()),
        );
    }
    if nuget_user_profile_sources_changed {
        union_in(
            &mut scope,
            ReparseScope::Ecosystems(NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS.to_vec()),
        );
    }
    if gitlab_instance_host_changed {
        union_in(
            &mut scope,
            ReparseScope::Ecosystems(GITLAB_INSTANCE_HOST_ECOSYSTEMS.to_vec()),
        );
    }

    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::diagnostic::Severity;

    #[test]
    fn test_default_config() {
        let config = DepsConfig::default();
        assert!(config.inlay_hints.enabled);
        assert_eq!(config.inlay_hints.up_to_date_text, "✅");
        assert_eq!(config.inlay_hints.needs_update_text, "❌ {}");
        assert_eq!(
            config.policy.registries.workspace_registries,
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
            config.policy.registries.workspace_registries,
            WorkspaceRegistriesSetting::Off
        );
    }

    /// Issue #466: `gitlab_instance_host` defaults to `""` (unset), and a payload omitting
    /// it still parses (additive-safety, mirroring the section above).
    #[test]
    fn test_gitlab_instance_host_defaults_to_empty_and_deserializes() {
        let default_config: DepsConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(default_config.policy.registries.gitlab_instance_host, "");

        let json = r#"{"registries": {"gitlab_instance_host": "gitlab.mycorp.dev"}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.policy.registries.gitlab_instance_host,
            "gitlab.mycorp.dev"
        );
    }

    /// #936: `RegistriesConfig`'s hand-written `Debug` impl must redact a credential-shaped
    /// `gitlab_instance_host` (no validation happens on this field before it reaches a log
    /// line — see the field's own doc) while still identifying the host, and the same
    /// guarantee must hold when the section is `Debug`-formatted as part of the whole
    /// `DepsConfig` (the shape `server.rs`'s `tracing::debug!("loaded configuration: {:?}",
    /// config)` actually formats).
    #[test]
    fn test_registries_config_debug_redacts_gitlab_instance_host_credential() {
        let json = r#"{"registries": {"gitlab_instance_host": "user:hunter2@gitlab.corp"}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();

        let section_debug = format!("{:?}", config.policy.registries);
        assert!(!section_debug.contains("hunter2"), "{section_debug}");
        assert!(section_debug.contains("gitlab.corp"), "{section_debug}");

        let whole_config_debug = format!("{config:?}");
        assert!(
            !whole_config_debug.contains("hunter2"),
            "{whole_config_debug}"
        );
        assert!(
            whole_config_debug.contains("gitlab.corp"),
            "{whole_config_debug}"
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

    /// T003 regression gate (spec 062 plan §3/§11): `#[serde(flatten)]` on `DepsConfig::policy`
    /// must still combine with `DepsConfig`'s own top-level `#[serde(deny_unknown_fields)]`
    /// exactly as the pre-refactor flat struct did — an unrecognized top-level key must reject
    /// the *whole* payload, never fall through and silently reset every unmentioned section to
    /// its default. `test_old_cargo_config_key_is_rejected_not_silently_ignored` above and
    /// `server::tests::parse_config_tests::test_parse_config_rejects_mixed_blob_with_one_recognized_key_and_unknown_siblings`
    /// already exercise this from a different call path; this test is the direct, minimal
    /// case naming the mechanism itself.
    #[test]
    fn test_flatten_preserves_deny_unknown_fields_rejection() {
        let json = r#"{"diagnostics": {"outdated_severity": 1}, "totally_unknown_key": true}"#;
        assert!(
            serde_json::from_str::<DepsConfig>(json).is_err(),
            "an unknown top-level key alongside a recognized flattened section must still \
             reject the whole payload"
        );
    }

    /// Companion to the test above: an unknown key *nested inside* a known section must stay
    /// tolerated (forward-compat for keys added inside a section later) — `deny_unknown_fields`
    /// applies only to `DepsConfig`'s own top-level shape, never to the section structs
    /// flattened into it, exactly as before this module's fields moved into
    /// `deps_core::policy_config`.
    #[test]
    fn test_flatten_still_tolerates_unknown_key_nested_inside_a_known_section() {
        let json = r#"{"diagnostics": {"outdated_severity": 1, "future_field": "ignored"}}"#;
        let config: DepsConfig =
            serde_json::from_str(json).expect("a nested unknown key must not reject the payload");
        assert_eq!(config.policy.diagnostics.outdated_severity, Severity::Error);
    }

    /// T003 regression gate: a realistic `initializationOptions` payload covering every
    /// section — the editor-only fields `DepsConfig` still owns directly, and every
    /// policy-relevant section now composed from `deps_core::policy_config::PolicyConfig` via
    /// `#[serde(flatten)]` — parses to the exact values sent, at the same flat top-level JSON
    /// shape LSP clients already use (`{"cache": {...}, "network": {...}}`, not a nested
    /// `{"policy": {"cache": {...}}}`).
    #[test]
    fn test_full_initialization_options_payload_parses_through_flatten() {
        let json = r#"{
            "inlay_hints": { "enabled": false, "up_to_date_text": "OK" },
            "cold_start": { "enabled": false, "rate_limit_ms": 250 },
            "loading_indicator": { "enabled": false },
            "code_lens": { "enabled": false },
            "diagnostics": { "outdated_severity": 1, "vulnerabilities_enabled": false },
            "cache": { "enabled": false, "max_concurrent_fetches": 5 },
            "freshness": { "enabled": false, "cooldown_secs": 60 },
            "supply_chain": { "enabled": false },
            "registries": { "workspace_registries": "off" },
            "network": { "offline": true },
            "license_policy": { "allow": ["MIT"], "deny": ["GPL-3.0"] }
        }"#;

        let config: DepsConfig = serde_json::from_str(json).unwrap();

        assert!(!config.inlay_hints.enabled);
        assert_eq!(config.inlay_hints.up_to_date_text, "OK");
        assert!(!config.cold_start.enabled);
        assert_eq!(config.cold_start.rate_limit_ms, 250);
        assert!(!config.loading_indicator.enabled);
        assert!(!config.code_lens.enabled);
        assert_eq!(config.policy.diagnostics.outdated_severity, Severity::Error);
        assert!(!config.policy.diagnostics.vulnerabilities_enabled);
        assert!(!config.policy.cache.enabled);
        assert_eq!(config.policy.cache.max_concurrent_fetches, 5);
        assert!(!config.policy.freshness.enabled);
        assert_eq!(config.policy.freshness.cooldown_secs, 60);
        assert!(!config.policy.supply_chain.enabled);
        assert_eq!(
            config.policy.registries.workspace_registries,
            WorkspaceRegistriesSetting::Off
        );
        assert!(config.policy.network.offline);
        assert_eq!(config.policy.license_policy.allow, vec!["MIT".to_string()]);
        assert_eq!(
            config.policy.license_policy.deny,
            vec!["GPL-3.0".to_string()]
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
    fn test_inlay_hints_config_with_enabled() {
        let config = InlayHintsConfig::new().with_enabled(false);
        assert!(!config.enabled);
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
        assert_eq!(config.outdated_severity, Severity::Error);
        assert_eq!(config.unknown_severity, Severity::Warning);
        assert_eq!(config.yanked_severity, Severity::Warning);
        assert_eq!(config.unsatisfiable_severity, Severity::Error);
        assert_eq!(config.deprecated_severity, Severity::Error);
    }

    #[test]
    fn test_diagnostics_config_unsatisfiable_severity_defaults_warning() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.unsatisfiable_severity, Severity::Warning);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.unsatisfiable_severity, Severity::Warning);
    }

    /// D8/O3: no `deprecated_enabled` toggle exists — severity is the only knob, matching
    /// the other four fields' precedent (deprecation adds no network call).
    #[test]
    fn test_diagnostics_config_deprecated_severity_defaults_warning() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.deprecated_severity, Severity::Warning);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.deprecated_severity, Severity::Warning);
    }

    /// Severity default (issue #473) — see `mutable_ref_pin_enabled` tests below for the
    /// separate on/off toggle, unlike `deprecated_severity`'s severity-only precedent.
    #[test]
    fn test_diagnostics_config_mutable_ref_pin_severity_defaults_hint() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.mutable_ref_pin_severity, Severity::Hint);

        let json = r"{}";
        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mutable_ref_pin_severity, Severity::Hint);
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
    fn test_cache_config_with_max_concurrent_fetches_clamps_zero_to_one() {
        // Regression test for issue #833: `buffer_unordered(0)` never completes, so
        // this setter must not let a `0` reach `document::fetch`.
        let config = CacheConfig::new().with_max_concurrent_fetches(0);
        assert_eq!(config.max_concurrent_fetches, 1);
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
        assert_eq!(config.policy.diagnostics.outdated_severity, Severity::Hint);
        assert!(config.policy.cache.enabled);
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
        assert_eq!(config.policy.diagnostics.outdated_severity, Severity::Hint);
    }

    #[test]
    fn test_empty_config_deserialization() {
        let json = r"{}";
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        // All fields should use defaults
        assert!(config.inlay_hints.enabled);
        assert!(config.policy.cache.enabled);
    }

    #[test]
    fn test_cold_start_config_with_enabled() {
        let config = ColdStartConfig::new().with_enabled(false);
        assert!(!config.enabled);
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
        assert!(config.policy.supply_chain.enabled);
    }

    #[test]
    fn test_freshness_config_with_enabled() {
        let config = FreshnessConfig::new().with_enabled(false);
        assert!(!config.enabled);
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
        let config = FreshnessConfig::new()
            .with_enabled(false)
            .with_cooldown_secs(1800);
        let settings = config.to_settings();
        assert!(!settings.enabled);
        assert_eq!(settings.cooldown_secs, 1800);
    }

    #[test]
    fn test_deps_config_includes_freshness_default() {
        let config = DepsConfig::default();
        assert!(config.policy.freshness.enabled);
        assert_eq!(config.policy.freshness.cooldown_secs, 259_200);
    }

    #[test]
    fn test_deps_config_empty_json_includes_freshness_default() {
        let config: DepsConfig = serde_json::from_str("{}").unwrap();
        assert!(config.policy.freshness.enabled);
        assert_eq!(config.policy.freshness.cooldown_secs, 259_200);
    }

    #[test]
    fn test_network_config_defaults_to_online() {
        let config = NetworkConfig::default();
        assert!(!config.offline);

        let config: DepsConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.policy.network.offline);
    }

    #[test]
    fn test_network_config_accepts_offline_true() {
        let json = r#"{"network":{"offline":true}}"#;
        let config: DepsConfig = serde_json::from_str(json).unwrap();
        assert!(config.policy.network.offline);
    }

    // =========================================================================
    // `reparse_scope` / `ReparseScope` tests (issue #592)
    // =========================================================================

    mod reparse_scope_tests {
        use super::*;

        /// A small, test-local stand-in for the real ecosystem list `reparse_scope` now
        /// takes as a parameter (issue #592 security M1) — these tests exercise
        /// `reparse_scope`'s diff/union *logic*, not the production ecosystem set, which is
        /// covered separately by `lib.rs`'s `register_ecosystems`-drift test.
        const TEST_WORKSPACE_REGISTRY_ECOSYSTEMS: &[&str] = &["cargo", "npm", "pypi", "go"];

        #[test]
        fn test_no_change_returns_none() {
            let config = DepsConfig::default();
            assert!(reparse_scope(&config, &config, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS).is_none());
        }

        #[test]
        fn test_inert_field_change_returns_none() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.freshness.cooldown_secs = 60;
            new.policy.network.offline = true;
            new.cold_start.rate_limit_ms = 0;
            assert!(
                reparse_scope(&old, &new, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS).is_none(),
                "freshness/network/cold_start changes must not trigger a reparse"
            );
        }

        #[test]
        fn test_workspace_registries_change_scopes_to_workspace_ecosystems() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.registries.workspace_registries = WorkspaceRegistriesSetting::Off;

            let scope = reparse_scope(&old, &new, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS)
                .expect("must trigger a reparse");
            assert_eq!(
                scope,
                ReparseScope::Ecosystems(TEST_WORKSPACE_REGISTRY_ECOSYSTEMS.to_vec())
            );
            for id in TEST_WORKSPACE_REGISTRY_ECOSYSTEMS {
                assert!(scope.matches(id));
            }
            assert!(!scope.matches("bundler"));
        }

        /// The scope must come from the caller-supplied list, not a value baked into
        /// `reparse_scope` itself (security M1) — passing a different list for the same
        /// config diff must change the result.
        #[test]
        fn test_workspace_registries_change_scope_reflects_caller_supplied_list() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.registries.workspace_registries = WorkspaceRegistriesSetting::Off;

            let scope =
                reparse_scope(&old, &new, &["only-this-one"]).expect("must trigger a reparse");
            assert_eq!(scope, ReparseScope::Ecosystems(vec!["only-this-one"]));
            assert!(!scope.matches("cargo"));
        }

        #[test]
        fn test_nuget_user_profile_sources_change_scopes_to_nuget_only() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.registries.nuget_user_profile_sources = true;

            let scope = reparse_scope(&old, &new, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS)
                .expect("must trigger a reparse");
            assert_eq!(
                scope,
                ReparseScope::Ecosystems(NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS.to_vec())
            );
            assert!(scope.matches("nuget"));
            assert!(!scope.matches("cargo"));
        }

        #[test]
        fn test_gitlab_instance_host_change_scopes_to_gitlab_ci_only() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.registries.gitlab_instance_host = "gitlab.mycorp.dev".to_string();

            let scope = reparse_scope(&old, &new, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS)
                .expect("must trigger a reparse");
            assert_eq!(
                scope,
                ReparseScope::Ecosystems(GITLAB_INSTANCE_HOST_ECOSYSTEMS.to_vec())
            );
            assert!(scope.matches("gitlab-ci"));
            assert!(!scope.matches("cargo"));
            assert!(!scope.matches("nuget"));
        }

        #[test]
        fn test_both_registry_fields_changed_unions_scopes() {
            let old = DepsConfig::default();
            let mut new = DepsConfig::default();
            new.policy.registries.workspace_registries = WorkspaceRegistriesSetting::Off;
            new.policy.registries.nuget_user_profile_sources = true;

            let scope = reparse_scope(&old, &new, TEST_WORKSPACE_REGISTRY_ECOSYSTEMS)
                .expect("must trigger a reparse");
            for id in TEST_WORKSPACE_REGISTRY_ECOSYSTEMS {
                assert!(scope.matches(id), "must still cover {id}");
            }
            assert!(scope.matches("nuget"));
        }

        #[test]
        fn test_scope_union_all_absorbs_ecosystems() {
            let all = ReparseScope::All;
            let ecosystems = ReparseScope::Ecosystems(vec!["cargo"]);
            assert_eq!(all.clone().union(ecosystems.clone()), ReparseScope::All);
            assert_eq!(ecosystems.union(all), ReparseScope::All);
        }

        #[test]
        fn test_scope_union_ecosystems_dedups() {
            let a = ReparseScope::Ecosystems(vec!["cargo", "npm"]);
            let b = ReparseScope::Ecosystems(vec!["npm", "pypi"]);
            let ReparseScope::Ecosystems(union) = a.union(b) else {
                panic!("expected Ecosystems variant");
            };
            assert_eq!(union.len(), 3, "npm must not be duplicated: {union:?}");
            for id in ["cargo", "npm", "pypi"] {
                assert!(union.contains(&id));
            }
        }

        #[test]
        fn test_scope_matches_all_matches_any_ecosystem() {
            assert!(ReparseScope::All.matches("anything"));
        }

        /// Every ecosystem id named in the `nuget_user_profile_sources` scope literal must
        /// actually resolve in the registered ecosystem set (critic Q1: a typo here fails
        /// silently closed — matching no document, no warning). The `workspace_registries`
        /// scope's ids are no longer a literal in this module (security M1) — their
        /// validity is covered by `lib.rs`'s `register_ecosystems`-drift test instead.
        #[test]
        fn test_nuget_user_profile_sources_ecosystem_ids_are_valid_ecosystem_ids() {
            for id in NUGET_USER_PROFILE_SOURCES_ECOSYSTEMS {
                id.parse::<deps_core::EcosystemId>()
                    .unwrap_or_else(|_| panic!("{id:?} is not a valid EcosystemId"));
            }
        }
    }
}
