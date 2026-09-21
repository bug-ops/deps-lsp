use tower_lsp_server::ls_types::{InlayHint, InlayHintKind, InlayHintLabel, InlayHintTooltip};

use crate::{ConcreteVersion, EcosystemConfig, ParseResult};

use super::diagnostics::MAX_VERSION_DIAGNOSTIC_CHARS;
use super::{
    EcosystemFormatter, RequirementStatus, VersionData, in_use_version,
    sanitize_and_truncate_for_diagnostic,
};

/// Sanitizes and caps a version-shaped string (`latest` or `resolved_version`) for
/// interpolation into an inlay-hint label (#1268, code-review follow-up).
///
/// One small wrapper around `sanitize_and_truncate_for_diagnostic(_, MAX_VERSION_DIAGNOSTIC_CHARS)`
/// shared by all four sibling call sites in [`generate_inlay_hints`] (the offline
/// marker, the no-cached-latest up-to-date label, the `UpToDate` match arm, and the
/// `Outdated` match arm) rather than repeating the pair inline at each one — the exact
/// "fixed one sink, missed the sibling" pattern this PR's own S1 finding already
/// flagged once; a single call site here means a future change to the treatment only
/// needs updating in one place.
fn sanitize_hint_version(version: &str) -> String {
    sanitize_and_truncate_for_diagnostic(version, MAX_VERSION_DIAGNOSTIC_CHARS)
}

/// Builds inlay hints showing the latest/in-use version next to each dependency's declaration.
///
/// Shared by every ecosystem's default
/// [`crate::ecosystem::Ecosystem::generate_inlay_hints`] implementation: one hint is
/// emitted per dependency that has a version range, using `versions` and
/// `loading_state` to decide whether cached data is ready to render yet.
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
        let version_range: tower_lsp_server::ls_types::Range = version_range.into();

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
                in_use_version::resolve_occurrence_version(
                    dep,
                    normalized_name.as_str(),
                    versions.resolved,
                    versions.resolved_version_candidates,
                    formatter,
                )
                .cloned()
            };

        if super::version_range_is_synthetic_empty(dep) && resolved_version.is_none() {
            // Maven's `<version></version>` (#1161 M1 follow-up): `version_range()` is `Some`
            // purely so completion can locate the dependency at that position, but there is no
            // declared requirement to show a version hint against — skip, the same way a
            // manifest with no `<version>` tag at all (`version_range() == None`, caught by the
            // gate above) is already skipped. Without this, a dependency here would flash a
            // "Loading…" hint at the empty tag's position while `versions` is being fetched,
            // then vanish once `RequirementStatus::Unresolved` is reached.
            //
            // `version_range_is_synthetic_empty`, not a bare `version_requirement().is_none()`
            // (code-review follow-up, second round): Gradle's version-catalog `version.ref`
            // pointing at a dangling/rich-version alias legitimately has a REAL, non-empty
            // `version_range()` with `version_requirement()` still `None` — inlay hints
            // rendered for it before #1161, and a blanket check would have silently broken
            // that. Checked AFTER `resolved_version` is computed, not before (critic follow-up,
            // second round): a lockfile-derived `resolved_version` can be present even when
            // `version_requirement()` is `None` for a currently-unreached ecosystem/shape, and
            // the #483 I5/SEC-2 guarantee below never discards a purely-local, offline
            // `resolved_version` — skipping earlier would silently drop that hint instead.
            continue;
        }

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
                let label = resolved_version.as_ref().map_or_else(
                    || "📴".to_string(),
                    |resolved| format!("📴 {}", sanitize_hint_version(resolved.as_str())),
                );
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
                        config.up_to_date_text,
                        sanitize_hint_version(resolved.as_str())
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

        let status = if let Some(resolved) = &resolved_version {
            if resolved == latest {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            }
        } else {
            match dep.version_requirement() {
                // `requirement_status_for`, matching `diagnostics.rs`'s `apply_outdated_rule`
                // (#907): lets e.g. `GithubActionsFormatter` prefer a SHA pin's
                // registry-confirmed tag over trusting its own comment text.
                Some(version_req) => formatter.requirement_status_for(dep, version_req, latest),
                // No declared requirement at all (e.g. a dangling alias/reference the
                // parser couldn't resolve to any string) — nothing was verified.
                None => RequirementStatus::Unresolved,
            }
        };

        let label_text = match status {
            RequirementStatus::UpToDate => {
                if config.show_up_to_date_hints {
                    if let Some(resolved) = &resolved_version {
                        format!(
                            "{} {}",
                            config.up_to_date_text,
                            sanitize_hint_version(resolved.as_str())
                        )
                    } else {
                        config.up_to_date_text.clone()
                    }
                } else {
                    continue;
                }
            }
            RequirementStatus::Outdated => config
                .needs_update_text
                .replace("{}", &sanitize_hint_version(latest.as_str())),
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

    /// #1161 M1 (critic follow-up): a dependency whose `version_range()` is `Some` but which
    /// has no `version_requirement()` — Maven's `<version></version>`, whose zero-width
    /// `version_range()` exists purely so completion can locate the dependency — must emit no
    /// hint at all, including no transient "Loading…" hint while `versions` is still being
    /// fetched. Without the `version_requirement().is_none()` skip, this dependency would
    /// flash a loading hint at the empty tag's position and then vanish once steady state
    /// (`RequirementStatus::Unresolved`) is reached, unlike every other "no version" shape
    /// (a manifest with no `<version>` tag at all, `version_range() == None`), which the
    /// gate right above already skips outright.
    #[test]
    fn test_generate_inlay_hints_skips_dependency_with_no_requirement_even_while_loading() {
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

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:foo".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)).into(),
                version_range: Range::new(Position::new(5, 15), Position::new(5, 15)).into(),
            })],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };

        let hints_while_loading = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );
        assert!(
            hints_while_loading.is_empty(),
            "must not flash a Loading… hint for a dependency with no version_requirement"
        );

        let hints_loaded = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );
        assert!(hints_loaded.is_empty());
    }

    /// Critic follow-up (M1, second round) to #1161: the `version_requirement().is_none()`
    /// skip must be checked AFTER `resolved_version` is computed, and must not fire when a
    /// lockfile-derived `resolved_version` is present even without a `version_requirement` —
    /// this is the #483 I5/SEC-2 guarantee ("never discard a purely-local, lockfile-derived
    /// `resolved_version`") applied to a dependency shape #1161 introduced. Uses the offline,
    /// no-`latest`-cached path so a hint renders purely from `resolved_version`.
    #[test]
    fn test_generate_inlay_hints_shows_resolved_version_hint_despite_no_requirement() {
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

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:foo".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)).into(),
                version_range: Range::new(Position::new(5, 15), Position::new(5, 15)).into(),
            })],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("com.example:foo".into(), "1.2.3".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(
            hints.len(),
            1,
            "resolved_version alone must still produce a hint"
        );
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴 1.2.3"),
            _ => panic!("expected string label"),
        }
    }

    /// #1161 M1 code-review follow-up (second round): a REAL, non-empty `version_range()`
    /// with no `version_requirement()` — Gradle's version-catalog `version.ref` pointing at a
    /// dangling/rich-version alias — must still show the transient "Loading…" hint while
    /// `versions` is being fetched, exactly as it did before #1161 (this shape's
    /// `version_range()` alone gated inlay hints then, with no requirement check at all). A
    /// bare `version_requirement().is_none()` skip (the M1 fix's first attempt) would have
    /// suppressed this legitimate Gradle case identically to Maven's genuinely degenerate one.
    #[test]
    fn test_generate_inlay_hints_shows_loading_hint_for_non_empty_range_with_no_requirement() {
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

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:guava".into(),
                name_range: Range::new(Position::new(1, 0), Position::new(1, 5)).into(),
                version_range: Range::new(Position::new(4, 40), Position::new(4, 45)).into(),
            })],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(
            hints.len(),
            1,
            "must still show the Loading… hint for a real, non-empty version_range"
        );
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "⏳"),
            _ => panic!("expected string label"),
        }
    }

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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                // Non-Go formatters must keep using the lockfile-resolved "1.2.0" (matching
                // latest), not the raw "1.0.0" requirement — confirms the Go override doesn't leak.
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
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

    /// #1268 critic S1: a lockfile-resolved version is exactly as untrusted as a
    /// registry-reported one (both are attacker-controllable in a cloned repository),
    /// so a bidi override embedded in it must not survive into the offline-marker
    /// label's `resolved` interpolation either — the sibling sink to the `Outdated`
    /// arm's `latest`, on the same always-visible inline surface.
    #[test]
    fn test_inlay_hint_offline_marker_strips_bidi_override_from_resolved_version() {
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "2.0.12\u{202E}deifidom ton";
        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), malicious_resolved.into());

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
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the offline-marker label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268 critic S1: same sink concern as the offline-marker test above, for the
    /// online, no-cached-`latest`, `show_up_to_date_hints` arm's `resolved`
    /// interpolation.
    #[test]
    fn test_inlay_hint_no_cached_latest_up_to_date_strips_bidi_override_from_resolved_version() {
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "0.5.1\u{202E}deifidom ton";
        // Not in the registry cache (empty), only lockfile-resolved.
        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("criterion".into(), malicious_resolved.into());

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
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the up-to-date label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268 critic S1: same sink concern once more, for the `RequirementStatus::UpToDate`
    /// arm reached via the normal (non-offline, cached-`latest`-present) path, three
    /// lines above the fixed `Outdated` arm in the same `match`.
    #[test]
    fn test_inlay_hint_up_to_date_label_strips_bidi_override_from_resolved_version() {
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "2.1.1\u{202E}deifidom ton";
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions::latest_only(malicious_resolved),
        );
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), malicious_resolved.into());

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
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the up-to-date label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268: a bidi-override embedded in the registry-reported `latest` version must
    /// not survive into the "update available" inlay-hint label, which — unlike a
    /// diagnostic — is an always-visible inline editor surface.
    #[test]
    fn test_inlay_hint_outdated_label_strips_bidi_override_from_latest_version() {
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_latest = "2.1.1\u{202E}live.tsr";
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions::latest_only(malicious_latest),
        );

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
                assert!(
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the inlay hint label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268: an oversized `latest` version string must be capped, not interpolated
    /// unbounded into the always-visible inlay-hint label.
    #[test]
    fn test_inlay_hint_outdated_label_caps_oversized_latest_version() {
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
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let oversized_latest = format!("2.0.0-{}", "X".repeat(MAX_VERSION_DIAGNOSTIC_CHARS + 50));
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions::latest_only(oversized_latest),
        );

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
                // "❌ " (2 chars) + the truncated version (MAX_VERSION_DIAGNOSTIC_CHARS chars
                // + 1 ellipsis marker) — an exact bound, not just "< input length", so a cap
                // that truncates at the wrong point (e.g. loosely under the input length but
                // still oversized) cannot pass this assertion (critic M1).
                assert_eq!(
                    text.chars().count(),
                    2 + MAX_VERSION_DIAGNOSTIC_CHARS + 1,
                    "expected exact capped length; got: {text}"
                );
                assert!(
                    text.ends_with('…'),
                    "expected truncation marker; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }
}
