//! Inlay hints handler implementation.
//!
//! Displays inline version annotations next to dependency version strings.
//! Shows "✓" for up-to-date dependencies and "↑ X.Y.Z" for outdated ones.

use crate::config::InlayHintsConfig;
use crate::document::{Ecosystem, ServerState, UnifiedDependency};
use deps_cargo::CratesIoRegistry;
use deps_npm::NpmRegistry;
use futures::future::join_all;
use semver::Version;
use std::sync::Arc;
use tower_lsp::lsp_types::{InlayHint, InlayHintKind, InlayHintLabel, InlayHintParams};

/// Handles inlay hint requests.
///
/// Returns version status hints for all registry dependencies in the document.
/// Gracefully degrades by returning empty vec on any errors.
///
/// # Examples
///
/// For this dependency:
/// ```toml
/// serde = "1.0.100"
/// ```
///
/// Shows: `serde = "1.0.100" ↑ 1.0.214` if outdated
/// Or: `serde = "1.0.214" ✓` if up-to-date
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    if !config.enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for inlay hints: {}", uri);
            return vec![];
        }
    };

    let ecosystem = doc.ecosystem;
    let deps_to_fetch: Vec<_> = doc
        .dependencies
        .iter()
        .filter(|dep| {
            dep.is_registry() && dep.version_range().is_some() && dep.version_req().is_some()
        })
        .cloned()
        .collect();

    drop(doc);

    match ecosystem {
        Ecosystem::Cargo => handle_cargo_inlay_hints(state, deps_to_fetch, config).await,
        Ecosystem::Npm => handle_npm_inlay_hints(state, deps_to_fetch, config).await,
    }
}

async fn handle_cargo_inlay_hints(
    state: Arc<ServerState>,
    dependencies: Vec<UnifiedDependency>,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let futures: Vec<_> = dependencies
        .iter()
        .filter_map(|dep| {
            if let UnifiedDependency::Cargo(cargo_dep) = dep {
                let name = cargo_dep.name.clone();
                let version_req = cargo_dep.version_req.as_ref()?.clone();
                let version_range = cargo_dep.version_range?;
                let registry = registry.clone();
                Some(async move {
                    let result = registry.get_latest_matching(&name, &version_req).await;
                    (name, version_req, version_range, result)
                })
            } else {
                None
            }
        })
        .collect();

    let results = join_all(futures).await;

    let mut hints = Vec::new();
    for (name, version_req, version_range, result) in results {
        let latest = match result {
            Ok(Some(v)) => v,
            Ok(None) => {
                tracing::debug!("No matching version found for {}: {}", name, version_req);
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to fetch versions for {}: {}", name, e);
                continue;
            }
        };

        let is_latest = is_version_latest(&version_req, &latest.num);

        let label = if is_latest {
            config.up_to_date_text.clone()
        } else {
            config.needs_update_text.replace("{}", &latest.num)
        };

        hints.push(InlayHint {
            position: version_range.end,
            label: InlayHintLabel::String(label),
            kind: Some(InlayHintKind::TYPE),
            text_edits: None,
            tooltip: None,
            padding_left: Some(true),
            padding_right: None,
            data: None,
        });
    }

    hints
}

async fn handle_npm_inlay_hints(
    state: Arc<ServerState>,
    dependencies: Vec<UnifiedDependency>,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    let registry = NpmRegistry::new(Arc::clone(&state.cache));

    let futures: Vec<_> = dependencies
        .iter()
        .filter_map(|dep| {
            if let UnifiedDependency::Npm(npm_dep) = dep {
                let name = npm_dep.name.clone();
                let version_req = npm_dep.version_req.as_ref()?.clone();
                let version_range = npm_dep.version_range?;
                let registry = registry.clone();
                Some(async move {
                    let result = registry.get_versions(&name).await;
                    (name, version_req, version_range, result)
                })
            } else {
                None
            }
        })
        .collect();

    let results = join_all(futures).await;

    let mut hints = Vec::new();
    for (name, version_req, version_range, result) in results {
        let versions = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to fetch versions for {}: {}", name, e);
                continue;
            }
        };

        let latest = match versions.first() {
            Some(v) => v,
            None => {
                tracing::debug!("No matching version found for {}: {}", name, version_req);
                continue;
            }
        };

        let is_latest = is_version_latest(&version_req, &latest.version);

        let label = if is_latest {
            config.up_to_date_text.clone()
        } else {
            config.needs_update_text.replace("{}", &latest.version)
        };

        hints.push(InlayHint {
            position: version_range.end,
            label: InlayHintLabel::String(label),
            kind: Some(InlayHintKind::TYPE),
            text_edits: None,
            tooltip: None,
            padding_left: Some(true),
            padding_right: None,
            data: None,
        });
    }

    hints
}

/// Checks if the current version requirement is satisfied by the latest version.
///
/// Compares the version requirement string (after stripping prefixes like ^, ~)
/// with the latest version. Returns true if they're semantically equivalent.
fn is_version_latest(version_req: &str, latest: &str) -> bool {
    let cleaned_req = version_req
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('=');

    if let (Ok(req_ver), Ok(latest_ver)) =
        (cleaned_req.parse::<Version>(), latest.parse::<Version>())
    {
        req_ver == latest_ver
    } else {
        cleaned_req == latest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_latest() {
        assert!(is_version_latest("1.0.0", "1.0.0"));
        assert!(is_version_latest("^1.0.0", "1.0.0"));
        assert!(is_version_latest("~1.0.0", "1.0.0"));
        assert!(is_version_latest("=1.0.0", "1.0.0"));

        assert!(!is_version_latest("1.0.0", "1.0.1"));
        assert!(!is_version_latest("^1.0.0", "1.0.1"));
    }

    #[test]
    fn test_is_version_latest_with_prerelease() {
        assert!(is_version_latest("1.0.0-alpha.1", "1.0.0-alpha.1"));
        assert!(!is_version_latest("1.0.0-alpha.1", "1.0.0-alpha.2"));
    }

    #[test]
    fn test_is_version_latest_invalid_versions() {
        assert!(!is_version_latest("invalid", "1.0.0"));
        assert!(!is_version_latest("1.0.0", "invalid"));
    }
}
