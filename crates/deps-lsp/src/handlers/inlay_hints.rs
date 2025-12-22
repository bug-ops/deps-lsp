//! Inlay hints handler implementation.
//!
//! Displays inline version annotations next to dependency version strings.
//! Shows "✅" for up-to-date dependencies and "❌ X.Y.Z" for outdated ones.

use crate::config::InlayHintsConfig;
use crate::document::{Ecosystem, ServerState, UnifiedDependency, UnifiedVersion};
use deps_cargo::{CratesIoRegistry, crate_url};
use deps_npm::{NpmRegistry, package_url};
use deps_pypi::PypiRegistry;
use futures::future::join_all;
use semver::Version;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    InlayHint, InlayHintKind, InlayHintLabel, InlayHintLabelPart, InlayHintParams, MarkupContent,
    MarkupKind,
};

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
/// Shows: `serde = "1.0.100" ❌ 1.0.214` if outdated
/// Or: `serde = "1.0.214" ✅` if up-to-date
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    let uri = &params.text_document.uri;

    tracing::info!(
        "inlay_hint request: uri={}, range={}:{}-{}:{}",
        uri,
        params.range.start.line,
        params.range.start.character,
        params.range.end.line,
        params.range.end.character
    );

    if !config.enabled {
        tracing::debug!("inlay hints disabled in config");
        return vec![];
    }

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

    // Get cached versions before dropping doc
    let cached_versions = doc.versions.clone();

    tracing::info!(
        "inlay hints: found {} dependencies to fetch (total {} in doc, {} cached)",
        deps_to_fetch.len(),
        doc.dependencies.len(),
        cached_versions.len()
    );

    drop(doc);

    let hints = match ecosystem {
        Ecosystem::Cargo => {
            handle_cargo_inlay_hints(state, deps_to_fetch, config, &cached_versions).await
        }
        Ecosystem::Npm => {
            handle_npm_inlay_hints(state, deps_to_fetch, config, &cached_versions).await
        }
        Ecosystem::Pypi => {
            handle_pypi_inlay_hints(state, deps_to_fetch, config, &cached_versions).await
        }
    };

    tracing::info!("returning {} inlay hints", hints.len());
    hints
}

async fn handle_cargo_inlay_hints(
    state: Arc<ServerState>,
    dependencies: Vec<UnifiedDependency>,
    config: &InlayHintsConfig,
    cached_versions: &HashMap<String, UnifiedVersion>,
) -> Vec<InlayHint> {
    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

    // Separate deps into cached and needs-fetch
    let mut cached_deps = Vec::new();
    let mut fetch_deps = Vec::new();

    for dep in &dependencies {
        if let UnifiedDependency::Cargo(cargo_dep) = dep {
            let Some(version_req) = cargo_dep.version_req.as_ref() else {
                continue;
            };
            let Some(version_range) = cargo_dep.version_range else {
                continue;
            };

            if let Some(cached) = cached_versions.get(&cargo_dep.name) {
                // Use cached version
                cached_deps.push((
                    cargo_dep.name.clone(),
                    version_req.clone(),
                    version_range,
                    cached.version_string().to_string(),
                    cached.is_yanked(),
                ));
            } else {
                // Need to fetch
                fetch_deps.push((cargo_dep.name.clone(), version_req.clone(), version_range));
            }
        }
    }

    tracing::debug!(
        "inlay hints: {} cached, {} to fetch",
        cached_deps.len(),
        fetch_deps.len()
    );

    // Fetch missing versions in parallel
    let futures: Vec<_> = fetch_deps
        .into_iter()
        .map(|(name, version_req, version_range)| {
            let registry = registry.clone();
            async move {
                let result = registry.get_versions(&name).await;
                (name, version_req, version_range, result)
            }
        })
        .collect();

    let fetch_results = join_all(futures).await;

    let mut hints = Vec::new();

    // Process cached deps
    for (name, version_req, version_range, latest_version, is_yanked) in cached_deps {
        if is_yanked {
            continue;
        }
        let is_latest = is_version_latest(&version_req, &latest_version);
        hints.push(create_cargo_hint(
            &name,
            &version_req,
            version_range,
            &latest_version,
            is_latest,
            config,
        ));
    }

    // Process fetched deps
    for (name, version_req, version_range, result) in fetch_results {
        let versions = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to fetch versions for {}: {}", name, e);
                continue;
            }
        };

        let latest = match versions.iter().find(|v| !v.yanked) {
            Some(v) => v,
            None => continue,
        };

        let is_latest = is_version_latest(&version_req, &latest.num);
        hints.push(create_cargo_hint(
            &name,
            &version_req,
            version_range,
            &latest.num,
            is_latest,
            config,
        ));
    }

    hints
}

fn create_cargo_hint(
    name: &str,
    _version_req: &str,
    version_range: tower_lsp::lsp_types::Range,
    latest_version: &str,
    is_latest: bool,
    config: &InlayHintsConfig,
) -> InlayHint {
    let label_text = if is_latest {
        config.up_to_date_text.clone()
    } else {
        config.needs_update_text.replace("{}", latest_version)
    };

    let crates_io_url = crate_url(name);
    let tooltip_content = format!(
        "[{}]({}) - {}\n\nLatest: **{}**",
        name, crates_io_url, crates_io_url, latest_version
    );

    InlayHint {
        position: version_range.end,
        label: InlayHintLabel::LabelParts(vec![InlayHintLabelPart {
            value: label_text,
            tooltip: Some(
                tower_lsp::lsp_types::InlayHintLabelPartTooltip::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: tooltip_content,
                }),
            ),
            location: None,
            command: Some(tower_lsp::lsp_types::Command {
                title: "Open on crates.io".into(),
                command: "vscode.open".into(),
                arguments: Some(vec![serde_json::json!(crates_io_url)]),
            }),
        }]),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

async fn handle_npm_inlay_hints(
    state: Arc<ServerState>,
    dependencies: Vec<UnifiedDependency>,
    config: &InlayHintsConfig,
    cached_versions: &HashMap<String, UnifiedVersion>,
) -> Vec<InlayHint> {
    let registry = NpmRegistry::new(Arc::clone(&state.cache));

    // Separate deps into cached and needs-fetch
    let mut cached_deps = Vec::new();
    let mut fetch_deps = Vec::new();

    for dep in &dependencies {
        if let UnifiedDependency::Npm(npm_dep) = dep {
            let Some(version_req) = npm_dep.version_req.as_ref() else {
                continue;
            };
            let Some(version_range) = npm_dep.version_range else {
                continue;
            };

            if let Some(cached) = cached_versions.get(&npm_dep.name) {
                cached_deps.push((
                    npm_dep.name.clone(),
                    version_req.clone(),
                    version_range,
                    cached.version_string().to_string(),
                    cached.is_yanked(),
                ));
            } else {
                fetch_deps.push((npm_dep.name.clone(), version_req.clone(), version_range));
            }
        }
    }

    // Fetch missing versions in parallel
    let futures: Vec<_> = fetch_deps
        .into_iter()
        .map(|(name, version_req, version_range)| {
            let registry = registry.clone();
            async move {
                let result = registry.get_versions(&name).await;
                (name, version_req, version_range, result)
            }
        })
        .collect();

    let fetch_results = join_all(futures).await;

    let mut hints = Vec::new();

    // Process cached deps
    for (name, version_req, version_range, latest_version, is_deprecated) in cached_deps {
        if is_deprecated {
            continue;
        }
        let is_latest = is_version_latest(&version_req, &latest_version);
        hints.push(create_npm_hint(
            &name,
            &version_req,
            version_range,
            &latest_version,
            is_latest,
            config,
        ));
    }

    // Process fetched deps
    for (name, version_req, version_range, result) in fetch_results {
        let versions = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to fetch npm versions for {}: {}", name, e);
                continue;
            }
        };

        let latest = match versions.iter().find(|v| !v.deprecated) {
            Some(v) => v,
            None => continue,
        };

        let is_latest = is_version_latest(&version_req, &latest.version);
        hints.push(create_npm_hint(
            &name,
            &version_req,
            version_range,
            &latest.version,
            is_latest,
            config,
        ));
    }

    hints
}

fn create_npm_hint(
    name: &str,
    _version_req: &str,
    version_range: tower_lsp::lsp_types::Range,
    latest_version: &str,
    is_latest: bool,
    config: &InlayHintsConfig,
) -> InlayHint {
    let label_text = if is_latest {
        config.up_to_date_text.clone()
    } else {
        config.needs_update_text.replace("{}", latest_version)
    };

    let npm_url = package_url(name);
    let tooltip_content = format!(
        "[{}]({}) - {}\n\nLatest: **{}**",
        name, npm_url, npm_url, latest_version
    );

    InlayHint {
        position: version_range.end,
        label: InlayHintLabel::LabelParts(vec![InlayHintLabelPart {
            value: label_text,
            tooltip: Some(
                tower_lsp::lsp_types::InlayHintLabelPartTooltip::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: tooltip_content,
                }),
            ),
            location: None,
            command: Some(tower_lsp::lsp_types::Command {
                title: "Open on npmjs.com".into(),
                command: "vscode.open".into(),
                arguments: Some(vec![serde_json::json!(npm_url)]),
            }),
        }]),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

async fn handle_pypi_inlay_hints(
    state: Arc<ServerState>,
    dependencies: Vec<UnifiedDependency>,
    config: &InlayHintsConfig,
    cached_versions: &HashMap<String, UnifiedVersion>,
) -> Vec<InlayHint> {
    let registry = PypiRegistry::new(Arc::clone(&state.cache));

    // Separate deps into cached and needs-fetch
    let mut cached_deps = Vec::new();
    let mut fetch_deps = Vec::new();

    for dep in &dependencies {
        if let UnifiedDependency::Pypi(pypi_dep) = dep {
            let Some(version_req) = pypi_dep.version_req.as_ref() else {
                continue;
            };
            let Some(version_range) = pypi_dep.version_range else {
                continue;
            };

            if let Some(cached) = cached_versions.get(&pypi_dep.name) {
                cached_deps.push((
                    pypi_dep.name.clone(),
                    version_req.clone(),
                    version_range,
                    cached.version_string().to_string(),
                    cached.is_yanked(),
                ));
            } else {
                fetch_deps.push((pypi_dep.name.clone(), version_req.clone(), version_range));
            }
        }
    }

    // Fetch missing versions in parallel
    let futures: Vec<_> = fetch_deps
        .into_iter()
        .map(|(name, version_req, version_range)| {
            let registry = registry.clone();
            async move {
                let result = registry.get_versions(&name).await;
                (name, version_req, version_range, result)
            }
        })
        .collect();

    let fetch_results = join_all(futures).await;

    let mut hints = Vec::new();

    // Process cached deps
    for (name, version_req, version_range, latest_version, is_yanked) in cached_deps {
        if is_yanked {
            continue;
        }
        let is_latest = is_version_latest(&version_req, &latest_version);
        hints.push(create_pypi_hint(
            &name,
            &version_req,
            version_range,
            &latest_version,
            is_latest,
            config,
        ));
    }

    // Process fetched deps
    for (name, version_req, version_range, result) in fetch_results {
        let versions = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to fetch PyPI versions for {}: {}", name, e);
                continue;
            }
        };

        let latest = match versions.iter().find(|v| !v.yanked) {
            Some(v) => v,
            None => continue,
        };

        let is_latest = is_version_latest(&version_req, &latest.version);
        hints.push(create_pypi_hint(
            &name,
            &version_req,
            version_range,
            &latest.version,
            is_latest,
            config,
        ));
    }

    hints
}

fn create_pypi_hint(
    name: &str,
    _version_req: &str,
    version_range: tower_lsp::lsp_types::Range,
    latest_version: &str,
    is_latest: bool,
    config: &InlayHintsConfig,
) -> InlayHint {
    let label_text = if is_latest {
        config.up_to_date_text.clone()
    } else {
        config.needs_update_text.replace("{}", latest_version)
    };

    let pypi_url = format!("https://pypi.org/project/{}/", name);
    let tooltip_content = format!(
        "[{}]({}) - {}\n\nLatest: **{}**",
        name, pypi_url, pypi_url, latest_version
    );

    InlayHint {
        position: version_range.end,
        label: InlayHintLabel::LabelParts(vec![InlayHintLabelPart {
            value: label_text,
            tooltip: Some(
                tower_lsp::lsp_types::InlayHintLabelPartTooltip::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: tooltip_content,
                }),
            ),
            location: None,
            command: Some(tower_lsp::lsp_types::Command {
                title: "Open on PyPI".into(),
                command: "vscode.open".into(),
                arguments: Some(vec![serde_json::json!(pypi_url)]),
            }),
        }]),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

/// Checks if the latest version satisfies the version requirement.
///
/// Returns true if the latest available version matches the requirement,
/// meaning the dependency is effectively up-to-date within its constraint.
///
/// For example:
/// - `"0.1"` with latest `"0.1.83"` → true (0.1.83 satisfies ^0.1)
/// - `"1.0.0"` with latest `"1.0.5"` → true (1.0.5 satisfies ^1.0.0)
/// - `"1.0.0"` with latest `"2.0.0"` → false (2.0.0 doesn't satisfy ^1.0.0)
fn is_version_latest(version_req: &str, latest: &str) -> bool {
    use semver::VersionReq;

    // Parse the latest version
    let latest_ver = match latest.parse::<Version>() {
        Ok(v) => v,
        Err(_) => return version_req == latest,
    };

    // Try to parse as a semver requirement (handles ^, ~, =, etc.)
    if let Ok(req) = version_req.parse::<VersionReq>() {
        return req.matches(&latest_ver);
    }

    // If not a valid requirement, try treating it as a caret requirement
    // (Cargo's default: "1.0" means "^1.0")
    if let Ok(req) = format!("^{}", version_req).parse::<VersionReq>() {
        return req.matches(&latest_ver);
    }

    // Fallback: string comparison
    version_req == latest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_latest_exact_match() {
        // Exact version matches
        assert!(is_version_latest("1.0.0", "1.0.0"));
        assert!(is_version_latest("^1.0.0", "1.0.0"));
        assert!(is_version_latest("~1.0.0", "1.0.0"));
        assert!(is_version_latest("=1.0.0", "1.0.0"));
    }

    #[test]
    fn test_is_version_latest_compatible_versions() {
        // Latest version satisfies the requirement (up-to-date)
        assert!(is_version_latest("1.0.0", "1.0.5")); // ^1.0.0 allows 1.0.5
        assert!(is_version_latest("^1.0.0", "1.5.0")); // ^1.0.0 allows 1.5.0
        assert!(is_version_latest("0.1", "0.1.83")); // ^0.1 allows 0.1.83
        assert!(is_version_latest("1", "1.5.0")); // ^1 allows 1.5.0
    }

    #[test]
    fn test_is_version_latest_incompatible_versions() {
        // Latest version doesn't satisfy requirement (new major available)
        assert!(!is_version_latest("1.0.0", "2.0.0")); // 2.0.0 breaks ^1.0.0
        assert!(!is_version_latest("0.1", "0.2.0")); // 0.2.0 breaks ^0.1
        assert!(!is_version_latest("~1.0.0", "1.1.0")); // ~1.0.0 doesn't allow 1.1.0
    }

    #[test]
    fn test_is_version_latest_with_prerelease() {
        assert!(is_version_latest("1.0.0-alpha.1", "1.0.0-alpha.1"));
    }

    #[test]
    fn test_is_version_latest_invalid_versions() {
        assert!(!is_version_latest("invalid", "1.0.0"));
        assert!(!is_version_latest("1.0.0", "invalid")); // Invalid latest, fallback to string compare
    }
}
