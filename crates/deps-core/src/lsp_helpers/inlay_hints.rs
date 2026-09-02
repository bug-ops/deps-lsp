use tower_lsp_server::ls_types::{InlayHint, InlayHintKind, InlayHintLabel, InlayHintTooltip};

use crate::{ConcreteVersion, EcosystemConfig, ParseResult};

use super::{EcosystemFormatter, RequirementStatus, VersionData};

pub fn generate_inlay_hints(
    parse_result: &dyn ParseResult,
    versions: VersionData<'_>,
    loading_state: crate::LoadingState,
    config: &EcosystemConfig,
    formatter: &dyn EcosystemFormatter,
) -> Vec<InlayHint> {
    let deps = parse_result.dependencies();
    let mut hints = Vec::with_capacity(deps.len());

    for dep in deps {
        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let normalized_name = formatter.normalize_package_name(dep.name());
        let latest_version = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()))
            .map(|v| &v.latest);
        let resolved_version: Option<ConcreteVersion> =
            if formatter.manifest_requirement_is_resolved_version(dep) {
                dep.version_requirement()
                    .map(|r| ConcreteVersion::new(r.as_str()))
            } else {
                versions
                    .resolved
                    .get(normalized_name.as_str())
                    .or_else(|| versions.resolved.get(dep.name()))
                    .cloned()
            };

        // Show loading hint if loading and no cached version
        if loading_state == crate::LoadingState::Loading
            && config.show_loading_hints
            && latest_version.is_none()
        {
            hints.push(InlayHint {
                position: version_range.end,
                label: InlayHintLabel::String(config.loading_text.clone()),
                kind: Some(InlayHintKind::TYPE),
                tooltip: Some(InlayHintTooltip::String(
                    "Fetching latest version...".to_string(),
                )),
                padding_left: Some(true),
                padding_right: None,
                text_edits: None,
                data: None,
            });
            continue;
        }

        let Some(latest) = latest_version else {
            // Issue #483 I5/SEC-2: never discard a purely-local, lockfile-derived
            // `resolved_version` just because the registry side is unknown while
            // offline — show it alongside the marker rather than replacing it.
            if config.offline {
                let label = resolved_version
                    .as_ref()
                    .map_or_else(|| "📴".to_string(), |resolved| format!("📴 {resolved}"));
                hints.push(InlayHint {
                    position: version_range.end,
                    label: InlayHintLabel::String(label),
                    kind: Some(InlayHintKind::TYPE),
                    tooltip: Some(InlayHintTooltip::String(
                        "Offline: registry not checked".to_string(),
                    )),
                    padding_left: Some(true),
                    padding_right: None,
                    text_edits: None,
                    data: None,
                });
                continue;
            }

            if let Some(resolved) = &resolved_version
                && config.show_up_to_date_hints
            {
                hints.push(InlayHint {
                    position: version_range.end,
                    label: InlayHintLabel::String(format!(
                        "{} {}",
                        config.up_to_date_text, resolved
                    )),
                    kind: Some(InlayHintKind::TYPE),
                    padding_left: Some(true),
                    padding_right: None,
                    text_edits: None,
                    tooltip: None,
                    data: None,
                });
            }
            continue;
        };

        // Two-tier check for up-to-date status:
        // 1. If lock file has the dep, check if resolved == latest
        // 2. If NOT in lock file, check the version requirement against latest
        let status = if let Some(resolved) = &resolved_version {
            if resolved == latest {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            }
        } else {
            match dep.version_requirement() {
                Some(version_req) => formatter.requirement_status(version_req, latest),
                // No declared requirement at all (e.g. a dangling alias/reference the
                // parser couldn't resolve to any string) — nothing was verified.
                None => RequirementStatus::Unresolved,
            }
        };

        let label_text = match status {
            RequirementStatus::UpToDate => {
                if config.show_up_to_date_hints {
                    if let Some(resolved) = &resolved_version {
                        format!("{} {}", config.up_to_date_text, resolved)
                    } else {
                        config.up_to_date_text.clone()
                    }
                } else {
                    continue;
                }
            }
            RequirementStatus::Outdated => config.needs_update_text.replace("{}", latest.as_str()),
            // Resolution failed (e.g. dangling alias/unexpanded variable) — neither
            // "up to date" nor "outdated" was actually verified, so show nothing.
            RequirementStatus::Unresolved => continue,
        };

        // Issue #483 I5/SEC-2: `latest` here may be a warm-cache value fetched before an
        // online -> offline flip — without this, the badge is indistinguishable from live
        // data on this always-visible inline surface.
        let label_text = if config.offline {
            format!("{label_text} 📴")
        } else {
            label_text
        };

        hints.push(InlayHint {
            position: version_range.end,
            label: InlayHintLabel::String(label_text),
            kind: Some(InlayHintKind::TYPE),
            padding_left: Some(true),
            padding_right: None,
            text_edits: None,
            tooltip: None,
            data: None,
        });
    }

    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;

    #[test]
    fn test_inlay_hint_exact_version_shows_update_needed() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.1.1"));

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "❌ 2.1.1");
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_caret_version_up_to_date() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.1.1"));

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.1.1".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockGoFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "example.com/mod".into(),
            PackageVersions::latest_only("v0.9.1"),
        );

        // Stale go.sum entry left behind by a downgrade: go.sum is sorted ascending by
        // semver, so it sorts last and would win naive last-occurrence-wins parsing
        // even though go.mod's `require` line was downgraded back to v0.8.1 (#235).
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example.com/mod".into(), "v0.9.1".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                // Bug: using the stale go.sum "v0.9.1" as resolved would equal latest
                // ("v0.9.1") and wrongly report up-to-date. The fix takes go.mod's
                // pinned "v0.8.1", which is genuinely outdated relative to latest.
                assert!(
                    text.starts_with("❌"),
                    "expected outdated hint driven by go.mod pin, got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_non_go_formatter_uses_resolved_lockfile_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.2.0"));

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.2.0".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                // Non-Go formatters must keep using the lockfile-resolved version
                // ("1.2.0", matching latest) rather than the raw manifest requirement
                // ("1.0.0", which would wrongly report outdated) — confirms the Go
                // override does not leak into other ecosystems.
                assert!(
                    text.starts_with("✅"),
                    "expected up-to-date hint from resolved lockfile version, got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_loading_hint_shows_when_no_cached_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "⏳", "Expected loading hint");
            }
            _ => panic!("Expected string label"),
        }

        if let Some(InlayHintTooltip::String(tooltip)) = &hints[0].tooltip {
            assert_eq!(tooltip, "Fetching latest version...");
        } else {
            panic!("Expected tooltip");
        }
    }

    #[test]
    fn test_loading_hint_disabled_when_config_false() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: false,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(
            hints.len(),
            0,
            "Expected no hints when loading hints disabled"
        );
    }

    #[test]
    fn test_caret_version_0x_edge_cases() {
        let formatter = MockFormatter;

        // ^0.2 should only allow 0.2.x
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.2.0"), "^0.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.2.5"), "^0.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.2.99"), "^0.2"));

        // ^0.2 should NOT allow 0.3.x or 0.1.x
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("0.3.0"), "^0.2"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("0.1.0"), "^0.2"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "^0.2"));

        // ^0.0.3 should only allow 0.0.3 (left-most non-zero is patch)
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.0.3"), "^0.0.3"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.0.3"), "^0.0"));

        // ^0 should only allow 0.x.y (major is 0)
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.0.0"), "^0"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), "^0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "^0"));
    }

    #[test]
    fn test_caret_version_non_zero_major() {
        let formatter = MockFormatter;

        // ^1.2 allows any 1.x.x
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "^1.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "^1.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), "^1.2"));

        // ^1.2 should NOT allow 2.x.x
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.2"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "^1.2"));
    }

    #[test]
    fn test_loading_hint_not_shown_when_cached_version_exists() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.0.214".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(
                    text, "✅ 1.0.214",
                    "Expected up-to-date hint, not loading hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_but_satisfies_requirement() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".into(), PackageVersions::latest_only("0.5.1"));

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint for satisfied requirement, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_and_outdated() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.4".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("criterion".into(), PackageVersions::latest_only("0.5.1"));

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("❌"),
                    "Expected needs-update hint for unsatisfied requirement, got: {}",
                    text
                );
                assert!(text.contains("0.5.1"), "Expected latest version in hint");
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_unresolved_requirement_emits_no_hint() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "spring-boot-starter".into(),
                version_req: "$missing".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "spring-boot-starter".into(),
            PackageVersions::latest_only("3.2.0"),
        );

        // Not in lock file, so status is derived from `requirement_status` on the
        // formatter (which the caller sets to `Unresolved`) rather than a resolved-vs-latest
        // comparison.
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &MockUnresolvedFormatter,
        );

        assert!(
            hints.is_empty(),
            "Expected no inlay hint at all for an unresolved requirement (not even 'up to date'), got: {hints:?}"
        );
    }

    /// Issue #483 I5/SEC-2 (cold, no resolved version): with no cached `latest` and no
    /// lockfile-resolved version, offline mode shows the bare marker alone.
    #[test]
    fn test_inlay_hint_offline_cold_no_resolved_shows_bare_marker() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴"),
            _ => panic!("Expected string label"),
        }
    }

    /// Issue #483 I5/SEC-2 (cold, with a lockfile-resolved version): offline mode must not
    /// discard purely-local, lockfile-derived version information — show it alongside the
    /// marker rather than replacing it with a bare 📴.
    #[test]
    fn test_inlay_hint_offline_cold_with_resolved_shows_marker_and_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴 2.0.12"),
            _ => panic!("Expected string label"),
        }
    }

    /// Issue #483 I5/SEC-2 (warm cache): a normal up-to-date/outdated badge built from a
    /// warm-cache `latest` value (possibly fetched before an online -> offline flip) must
    /// carry the offline marker too, or it is indistinguishable from live data on this
    /// always-visible inline surface.
    #[test]
    fn test_inlay_hint_offline_warm_cache_appends_marker_to_outdated_badge() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: true,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.1.1"));

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "❌ 2.1.1 📴"),
            _ => panic!("Expected string label"),
        }
    }
}
