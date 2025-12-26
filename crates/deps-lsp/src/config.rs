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
#[derive(Debug, Deserialize, Default)]
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
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            outdated_severity: default_outdated_severity(),
            unknown_severity: default_unknown_severity(),
            yanked_severity: default_yanked_severity(),
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
///
/// # Examples
///
/// ```
/// use deps_lsp::config::CacheConfig;
///
/// let config = CacheConfig {
///     refresh_interval_secs: 600, // 10 minutes
///     enabled: true,
/// };
///
/// assert_eq!(config.refresh_interval_secs, 600);
/// ```
#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: default_refresh_interval(),
            enabled: true,
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

const fn default_refresh_interval() -> u64 {
    300 // 5 minutes
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DepsConfig::default();
        assert!(config.inlay_hints.enabled);
        assert_eq!(config.inlay_hints.up_to_date_text, "✅");
        assert_eq!(config.inlay_hints.needs_update_text, "❌ {}");
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
            "yanked_severity": 2
        }"#;

        let config: DiagnosticsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.outdated_severity, DiagnosticSeverity::ERROR);
        assert_eq!(config.unknown_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.yanked_severity, DiagnosticSeverity::WARNING);
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
}
