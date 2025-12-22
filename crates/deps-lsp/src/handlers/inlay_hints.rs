//! Inlay hints handler implementation.
//!
//! Displays inline version annotations next to dependency version strings.
//! Shows "✓" for up-to-date dependencies and "↑ X.Y.Z" for outdated ones.

use crate::cargo::registry::CratesIoRegistry;
use crate::cargo::types::DependencySource;
use crate::config::InlayHintsConfig;
use crate::document::ServerState;
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

    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    let deps_to_fetch: Vec<_> = doc
        .dependencies
        .iter()
        .filter(|dep| {
            matches!(dep.source, DependencySource::Registry)
                && dep.version_range.is_some()
                && dep.version_req.is_some()
        })
        .collect();

    let futures: Vec<_> = deps_to_fetch
        .iter()
        .map(|dep| {
            let name = dep.name.clone();
            let version_req = dep.version_req.as_ref().unwrap().clone();
            let version_range = dep.version_range.unwrap();
            let registry = registry.clone();
            async move {
                let result = registry.get_latest_matching(&name, &version_req).await;
                (name, version_req, version_range, result)
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
