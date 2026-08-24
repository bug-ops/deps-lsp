use tower_lsp_server::ls_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position};

use crate::osv::{ADVISORY_DISPLAY_CAP, ScanOutcome};
use crate::{
    ParseResult, PublishTime, Registry, Version, VersionReq, format_relative_age,
    is_within_cooldown,
};

use super::{
    EcosystemFormatter, HOVER_RECENT_VERSIONS, VersionData, escape_markdown, markdown_code_span,
    position_in_range,
};

/// Formats the relative-age suffix for one "Recent versions" hover entry.
///
/// Returns an empty string when the registry doesn't expose a publish timestamp for
/// `version` (`published_at()` is `None`), so the entry renders exactly as it did
/// before this feature existed (graceful degradation, US-003).
///
/// `now` is taken as an explicit parameter rather than read internally so every entry
/// in the same "Recent versions" list is aged against one consistent instant.
fn version_age_suffix(version: &dyn Version, now: PublishTime) -> String {
    version
        .published_at()
        .map(|published| format!(" — {}", format_relative_age(published.age_secs_from(now))))
        .unwrap_or_default()
}

pub async fn generate_hover<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    versions: VersionData<'_>,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    freshness: crate::freshness::FreshnessSettings,
    now: PublishTime,
) -> Option<Hover> {
    use std::fmt::Write;

    let dep = parse_result.dependencies().into_iter().find(|d| {
        let on_name = position_in_range(position, d.name_range());
        let on_version = d
            .version_range()
            .is_some_and(|r| position_in_range(position, r));
        on_name || on_version
    })?;

    // A non-resolvable source (e.g. `CustomRegistry`, Git, Path) doesn't resolve
    // against `registry` at all — fetching by name here would silently check an
    // unrelated or coincidentally-named public-registry package (#248), so hover
    // must skip the registry lookup and every section built from it entirely.
    let resolvable = dep.source().is_version_resolvable();

    // `now` is a caller-supplied parameter (issue #227 M4) rather than computed
    // internally via `PublishTime::now()` — this is what lets tests pin an exact
    // cooldown-boundary instant deterministically, and guarantees every age rendered
    // in this single hover response (the `**Latest**` line and the "Recent versions"
    // list below) is aged against the same instant.
    let available_versions = if resolvable {
        Some(
            registry
                .get_versions_with(dep.name(), freshness)
                .await
                .ok()?,
        )
    } else {
        None
    };

    let url = formatter.package_url(dep.name());

    // Pre-allocate with estimated capacity to reduce allocations
    let mut markdown = String::with_capacity(512);
    write!(
        &mut markdown,
        "# [{}]({})\n\n",
        escape_markdown(dep.name().as_str()),
        url
    )
    .unwrap();

    let normalized_name = formatter.normalize_package_name(dep.name());

    let resolved: Option<&str> = if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement().map(VersionReq::as_str)
    } else {
        versions
            .resolved
            .get(normalized_name.as_str())
            .or_else(|| versions.resolved.get(dep.name()))
            .map(String::as_str)
    };
    if let Some(resolved_ver) = resolved {
        write!(
            &mut markdown,
            "**Current**: {}\n\n",
            markdown_code_span(resolved_ver)
        )
        .unwrap();
    } else if let Some(version_req) = dep.version_requirement() {
        write!(
            &mut markdown,
            "**Requirement**: {}\n\n",
            markdown_code_span(version_req.as_str())
        )
        .unwrap();
    }

    if let Some(marker_expr) = dep.markers() {
        write!(
            &mut markdown,
            "**Active when**: {}\n\n",
            markdown_code_span(marker_expr)
        )
        .unwrap();
    }

    // The `**Latest**` line prefers the just-fetched Ch2 list (`available_versions`) over
    // the Ch1 cache (`versions.cached`, populated by the lifecycle's background fetch)
    // whenever a live fetch is available. Ch1 alone would let this line render a version
    // older than the one the "Recent versions" list right below it shows as `*(latest)*` —
    // a self-contradictory response when a new version is published between the last
    // background fetch and this hover call, with the cooldown callout then decided off the
    // stale operand too (issue #227 F5). Falls back to Ch1 only when there is no live list
    // at all (non-resolvable source) — NOT merely when the live list has no stable entry:
    // a live list that's all pre-release still means a live fetch happened, and rendering
    // a stale Ch1 version that may not even appear in the live "Recent versions" list below
    // would be exactly the self-contradiction #227 F5 fixed, via a different path (#313).
    //
    // `live_latest_idx` (not raw index 0) picks the entry: `available_versions` is sorted
    // purely by version number, so a pre-release with the highest number can sort to index 0
    // even though it isn't the ecosystem's "latest stable" pick — mirroring this line to the
    // raw top entry would tag a pre-release as `(latest)` below, contradicting the
    // stable-only semantics of `versions.cached`'s `latest`. Recorded as an index (matching
    // `find_latest_stable`'s exact `is_stable` predicate) rather than a version string so the
    // "Recent versions" marker below can match by position instead of string equality, which
    // could spuriously tag more than one entry if two ever shared a version string.
    let live_latest_idx = available_versions
        .as_ref()
        .and_then(|v| v.iter().position(|ver| ver.is_stable()));
    let cached_latest = resolvable
        .then(|| {
            versions
                .cached
                .get(normalized_name.as_str())
                .or_else(|| versions.cached.get(dep.name()))
        })
        .flatten();
    // A non-empty live list with no stable entry is deliberately treated differently from
    // an empty (or absent) live list: the former still falls through to `None` below (no
    // header at all, matching the empty "Recent versions" list right beneath it) rather than
    // the Ch1 cache, since the cache's version wouldn't be part of what the live list just
    // showed. An empty live list carries no such contradiction risk — it has nothing to
    // contradict — so it keeps falling back to Ch1, same as when there's no live fetch.
    let latest_line: Option<(&str, Option<PublishTime>)> = match &available_versions {
        Some(v) if !v.is_empty() => live_latest_idx
            .map(|idx| &v[idx])
            .map(|live| (live.version_string(), live.published_at())),
        _ => cached_latest.map(|v| (v.latest.as_str(), v.published_at)),
    };
    if let Some((latest_ver, raw_published_at)) = latest_line {
        let published_at = freshness.enabled.then_some(raw_published_at).flatten();
        let age_secs = published_at.map(|p| p.age_secs_from(now));
        write!(
            &mut markdown,
            "**Latest**: {}",
            markdown_code_span(latest_ver)
        )
        .unwrap();
        if let Some(age_secs) = age_secs {
            write!(
                &mut markdown,
                " *(published {})*",
                format_relative_age(age_secs)
            )
            .unwrap();
        }
        markdown.push_str("\n\n");
        if age_secs.is_some_and(|age| is_within_cooldown(age, freshness.cooldown_secs)) {
            markdown.push_str(
                "> ⏳ **Recently published** — this release is still within the cooldown window.\n\
                 > It may still be yanked or superseded; consider verifying before upgrading.\n\n",
            );
        }
    }

    let vuln_outcome = versions.vulnerabilities.and_then(|m| {
        m.get(&normalized_name)
            .or_else(|| m.get(dep.name().as_str()))
    });
    push_vulnerability_hover_section(&mut markdown, vuln_outcome);

    if let Some(available_versions) = &available_versions {
        // Matched by position against `live_latest_idx` (the header's stable-latest pick)
        // rather than raw index 0 or string equality: `available_versions` is sorted purely
        // by version number, so index 0 can be a pre-release the header itself doesn't call
        // "latest" (issue #313), and matching by version string instead of index could tag
        // more than one entry if two ever shared a version string. No match in the rendered
        // top-N slice simply omits the marker.
        markdown.push_str("**Recent versions**:\n");
        for (i, version) in available_versions
            .iter()
            .take(HOVER_RECENT_VERSIONS)
            .enumerate()
        {
            let version_span = markdown_code_span(version.version_string());
            let age_suffix = if freshness.enabled {
                version_age_suffix(version.as_ref(), now)
            } else {
                String::new()
            };
            if Some(i) == live_latest_idx {
                writeln!(&mut markdown, "- {version_span} *(latest)*{age_suffix}").unwrap();
            } else if version.is_yanked() {
                writeln!(
                    &mut markdown,
                    "- {} {}{}",
                    version_span,
                    formatter.yanked_label(),
                    age_suffix
                )
                .unwrap();
            } else {
                writeln!(&mut markdown, "- {version_span}{age_suffix}").unwrap();
            }
        }
    }

    markdown.push_str("\n---\n⌨️ **Press `Cmd+.` to update version**");

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(dep.name_range()),
    })
}

/// Lowercase display label for a [`crate::osv::VulnSeverity`], used only in hover text.
const fn severity_label(severity: crate::osv::VulnSeverity) -> &'static str {
    match severity {
        crate::osv::VulnSeverity::Critical => "critical",
        crate::osv::VulnSeverity::High => "high",
        crate::osv::VulnSeverity::Medium => "medium",
        crate::osv::VulnSeverity::Low => "low",
        crate::osv::VulnSeverity::Unknown => "unknown severity",
    }
}

/// Appends the hover "Security advisories" section, gated strictly on the
/// scan outcome — never on map absence.
///
/// `Vulnerable` gets the advisories list, `Clean` may state the affirmative
/// "no known vulnerabilities", and `Skipped` (or no scan at all) says
/// **nothing**: saying "clean" about a dependency that was never queried is
/// worse than saying nothing at all (`architecture.md` §8 invariant 0).
fn push_vulnerability_hover_section(markdown: &mut String, outcome: Option<&ScanOutcome>) {
    use std::fmt::Write;

    match outcome {
        Some(ScanOutcome::Vulnerable(dv)) => {
            markdown.push_str("### Security advisories\n\n");

            let shown = dv.advisories.iter().take(ADVISORY_DISPLAY_CAP);
            for advisory in shown {
                writeln!(
                    markdown,
                    "- **[{}]({})** — {}",
                    escape_markdown(&advisory.id),
                    advisory.url,
                    severity_label(advisory.severity)
                )
                .unwrap();
                writeln!(
                    markdown,
                    "  {}",
                    escape_markdown(
                        advisory
                            .summary
                            .as_deref()
                            .unwrap_or("(no summary provided)")
                    )
                )
                .unwrap();

                let mut details = Vec::with_capacity(2);
                if let Some(fixed) = advisory.fixed_versions.last() {
                    details.push(format!("Fixed in: {}", markdown_code_span(fixed)));
                }
                if !advisory.aliases.is_empty() {
                    details.push(format!(
                        "Aliases: {}",
                        escape_markdown(&advisory.aliases.join(", "))
                    ));
                }
                if !details.is_empty() {
                    writeln!(markdown, "  {}", details.join(" \u{b7} ")).unwrap();
                }
            }

            let shown_count = dv.advisories.len().min(ADVISORY_DISPLAY_CAP);
            let remaining = dv.total_known.saturating_sub(shown_count);
            if remaining > 0 {
                writeln!(markdown, "- *(+{remaining} more advisories)*").unwrap();
            }

            if let crate::osv::UpgradeStatus::CandidateVulnerable { version, .. } =
                &dv.upgrade_status
            {
                writeln!(
                    markdown,
                    "\n\u{26a0}\u{fe0f} Latest version {} is also affected.",
                    markdown_code_span(version)
                )
                .unwrap();
            }

            markdown.push('\n');
        }
        Some(ScanOutcome::Clean) => {
            markdown.push_str("**No known vulnerabilities** (OSV.dev)\n\n");
        }
        Some(ScanOutcome::Skipped(_)) | None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_generate_hover_recent_versions_shows_age_when_known() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                // 2 days ago — safely mid-bucket, immune to sub-second test flakiness.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("- `1.2.3` *(latest)* — 2 days ago"),
            "got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_omits_age_when_unknown() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Exactly the pre-feature line: no trailing age suffix.
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_skips_prerelease_at_raw_top() {
        use std::collections::HashMap;

        // Raw registry order (newest by version number first): a pre-release sorts above
        // the actual stable latest, mirroring NuGet's Newtonsoft.Json 13.0.5-beta1 vs
        // 13.0.4 (#313).
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "13.0.5-beta1".to_string(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "13.0.4".to_string(),
                    yanked: false,
                    published_at: None,
                },
            ],
        };
        let parse_result = freshness_test_parse_result("Newtonsoft.Json");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `13.0.4`"),
            "got: {}",
            content.value
        );
        assert!(
            content.value.contains("- `13.0.4` *(latest)*"),
            "the stable version, not the raw-top pre-release, should carry the marker; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("13.0.5-beta1` *(latest)*"),
            "the pre-release must not be tagged latest; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_omitted_when_stable_outside_top_n() {
        use std::collections::HashMap;

        // Nine pre-releases followed by one stable version: the stable pick sits past
        // `HOVER_RECENT_VERSIONS`, so it never appears in the rendered list.
        let mut versions: Vec<MockVersionWithAge> = (0..=HOVER_RECENT_VERSIONS)
            .map(|i| MockVersionWithAge {
                version: format!("2.0.0-alpha{i}"),
                yanked: false,
                published_at: None,
            })
            .collect();
        versions.push(MockVersionWithAge {
            version: "1.9.0".to_string(),
            yanked: false,
            published_at: None,
        });
        let registry = MockRegistryWithVersions { versions };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Latest**: `1.9.0`"),
            "got: {}",
            content.value
        );
        assert!(
            !content.value.contains("*(latest)*"),
            "the stable latest isn't in the truncated top-N slice, so no entry should be marked; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_all_prerelease_degrades_gracefully() {
        use std::collections::HashMap;

        // No stable version exists anywhere in the list: `find_latest_stable` returns
        // `None`, and there is no Ch1 cache to fall back to either (#313 edge case).
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "2.0.0-beta2".to_string(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "2.0.0-beta1".to_string(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "1.9.0-alpha1".to_string(),
                    yanked: false,
                    published_at: None,
                },
            ],
        };
        let parse_result = freshness_test_parse_result("example");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Latest**:"),
            "no stable version exists, so the header should be omitted rather than picking a pre-release; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("*(latest)*"),
            "no stable version exists, so no entry in the list should be marked latest; got: {}",
            content.value
        );
        assert!(
            content.value.contains("2.0.0-beta2"),
            "the raw version list should still render even without a latest marker; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_latest_marker_all_prerelease_live_list_ignores_stale_cache() {
        use std::collections::HashMap;

        // A live fetch happened (so `available_versions` is `Some`), but every entry in it
        // is a pre-release: `live_latest_idx` is `None`. A stale Ch1 cache is also present,
        // recording a version that isn't part of the live list at all. Falling back to that
        // stale cached value here would render a `**Latest**` line that contradicts the live
        // "Recent versions" list right below it — exactly the self-contradiction #227 F5 was
        // fixed to prevent, just reached through this all-prerelease path instead (#313 S2).
        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "2.0.0-beta2".to_string(),
                yanked: false,
                published_at: None,
            }],
        };
        let parse_result = freshness_test_parse_result("example");
        let mut cached_versions = HashMap::new();
        cached_versions.insert("example".into(), PackageVersions::latest_only("1.5.0"));

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor, not panic");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Latest**:"),
            "a live fetch with no stable entry must not fall back to a stale cached version \
             that isn't in the live list; got: {}",
            content.value
        );
        assert!(
            !content.value.contains("1.5.0"),
            "the stale cached version must not leak into the response at all; got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 16)),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        // Stale go.sum entry left behind by a downgrade (#235): go.mod's `require`
        // line was downgraded back to v0.8.1, but the ledger-only go.sum still
        // records the higher v0.9.1 and sorts last, so it would win naive
        // last-occurrence-wins parsing if hover trusted `versions.resolved` here.
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("example.com/mod".into(), "v0.9.1".to_string());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockGoFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Current**: `v0.8.1`"),
            "expected hover to show go.mod's pinned version, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("v0.9.1"),
            "hover must not surface the stale go.sum version: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_non_go_formatter_uses_resolved_lockfile_version() {
        use std::collections::HashMap;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.2.0".to_string());
        let cached_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        // Non-Go formatters must keep showing the lockfile-resolved version
        // ("1.2.0"), not the raw manifest requirement ("1.0.0") — confirms the Go
        // override does not leak into other ecosystems.
        assert!(
            content.value.contains("**Current**: `1.2.0`"),
            "expected hover to show the resolved lockfile version, got: {}",
            content.value
        );
        assert!(!content.value.contains("**Current**: `1.0.0`"));
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_preserves_yanked_marker_with_age() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "1.2.3".to_string(),
                    yanked: false,
                    published_at: None,
                },
                MockVersionWithAge {
                    version: "1.2.1".to_string(),
                    yanked: true,
                    // ~5 months ago.
                    published_at: Some(PublishTime::from_unix_secs(
                        PublishTime::now().as_unix_secs() - 5 * 30 * 24 * 60 * 60,
                    )),
                },
            ],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("- `1.2.1` *(yanked)* — 5 months ago"),
            "got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_recent_versions_respects_freshness_disabled() {
        use std::collections::HashMap;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "1.2.3".to_string(),
                yanked: false,
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 2 * 24 * 60 * 60,
                )),
            }],
        };
        let parse_result = freshness_test_parse_result("serde");

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("- `1.2.3` *(latest)*\n"));
        assert!(!content.value.contains("ago"));
    }

    /// Issue #227 §4.2a: the `**Latest**` line gets a publish-age suffix and, within the
    /// cooldown window, the "Recently published" callout.
    #[tokio::test]
    async fn test_generate_hover_latest_line_shows_age_and_cooldown_callout_when_within_cooldown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".to_string(),
                available: Arc::from(vec!["2.0.0".to_string()]),
                yanked: Arc::from(Vec::new()),
                // 1 hour ago — well within the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `2.0.0` *(published 1 hour ago)*"),
            "got: {}",
            content.value
        );
        assert!(
            content.value.contains(
                "> ⏳ **Recently published** — this release is still within the cooldown window."
            ),
            "got: {}",
            content.value
        );
    }

    /// Same setup, but `latest` was published well outside the cooldown window — the age
    /// suffix still renders, but the callout must not.
    #[tokio::test]
    async fn test_generate_hover_latest_line_no_callout_when_outside_cooldown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".to_string(),
                available: Arc::from(vec!["2.0.0".to_string()]),
                yanked: Arc::from(Vec::new()),
                // 10 days ago — outside the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 10 * 24 * 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `2.0.0` *(published 1 week ago)*"),
            "got: {}",
            content.value
        );
        assert!(!content.value.contains("Recently published"));
    }

    /// A `latest` with no known publish time renders exactly the pre-feature line — no age
    /// suffix, no callout.
    #[tokio::test]
    async fn test_generate_hover_latest_line_omits_age_when_published_at_unknown() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.value.contains("published"));
        assert!(!content.value.contains("Recently published"));
    }

    /// `freshness.enabled: false` suppresses both the age suffix and the cooldown callout
    /// on the `**Latest**` line, even when the publish time would otherwise qualify.
    #[tokio::test]
    async fn test_generate_hover_latest_line_respects_freshness_disabled() {
        use std::collections::HashMap;

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".to_string(),
                available: Arc::from(vec!["2.0.0".to_string()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                cooldown_secs: crate::freshness::DEFAULT_COOLDOWN_SECS,
            },
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**: `2.0.0`\n\n"));
        assert!(!content.value.contains("published"));
        assert!(!content.value.contains("Recently published"));
    }

    /// Deterministic boundary test (issue #227 M4): `now` is threaded in as a parameter
    /// rather than read internally, so `published_at`/`now`/`cooldown_secs` can be pinned
    /// to fixed absolute values with no wall-clock dependency. `age == cooldown_secs`
    /// exactly must NOT be within cooldown — the bound is exclusive (`age < cooldown`).
    #[tokio::test]
    async fn test_generate_hover_latest_line_cooldown_boundary_is_exclusive() {
        use std::collections::HashMap;

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_at_boundary =
            PublishTime::from_unix_secs(10_000 - COOLDOWN_SECS.cast_signed());

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".to_string(),
                available: Arc::from(vec!["2.0.0".to_string()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_at_boundary),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Recently published"),
            "age exactly equal to cooldown_secs must not be within cooldown, got: {}",
            content.value
        );
    }

    /// Same fixture, one second younger — must flip to within cooldown.
    #[tokio::test]
    async fn test_generate_hover_latest_line_cooldown_boundary_one_second_inside_shows_callout() {
        use std::collections::HashMap;

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_just_inside =
            PublishTime::from_unix_secs(10_000 - (COOLDOWN_SECS.cast_signed() - 1));

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".to_string(),
                available: Arc::from(vec!["2.0.0".to_string()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_just_inside),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Recently published"),
            "age == cooldown_secs - 1 must be within cooldown, got: {}",
            content.value
        );
    }

    /// Issue #227 F5: the Ch1 cache (`versions.cached`, populated by the lifecycle's
    /// background fetch) can go stale relative to the live Ch2 fetch this same hover call
    /// just made (`registry.get_versions_with`) — e.g. a new version published between the
    /// last background fetch and now. Before this fix, the `**Latest**` line and cooldown
    /// callout read Ch1 alone, so hover could render a self-contradictory response: an
    /// older `**Latest**` line sitting above a "Recent versions" list whose own `*(latest)*`
    /// entry is a newer version. The line must prefer the live entry instead.
    #[tokio::test]
    async fn test_generate_hover_latest_line_prefers_live_fetch_over_stale_ch1_cache() {
        use std::collections::HashMap;

        let now = PublishTime::now();
        let live_latest_published = PublishTime::from_unix_secs(now.as_unix_secs() - 60 * 60);
        let registry = MockRegistryWithVersions {
            versions: vec![
                MockVersionWithAge {
                    version: "1.0.214".to_string(),
                    yanked: false,
                    published_at: Some(live_latest_published),
                },
                MockVersionWithAge {
                    version: "1.0.213".to_string(),
                    yanked: false,
                    published_at: Some(PublishTime::from_unix_secs(
                        now.as_unix_secs() - 30 * 24 * 60 * 60,
                    )),
                },
            ],
        };

        let parse_result = freshness_test_parse_result("serde");
        let mut cached_versions = HashMap::new();
        // Stale Ch1 entry: an older version, with an even older publish time, standing in
        // for a background fetch that ran before 1.0.214 was published.
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "1.0.213".to_string(),
                available: Arc::from(vec!["1.0.213".to_string()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(PublishTime::from_unix_secs(
                    now.as_unix_secs() - 90 * 24 * 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            now,
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Latest**: `1.0.214` *(published 1 hour ago)*"),
            "Latest line must reflect the live Ch2 fetch, not the stale Ch1 cache entry \
             `1.0.213`, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("**Latest**: `1.0.213`"),
            "must not render the stale Ch1 version, got: {}",
            content.value
        );
        assert!(
            content
                .value
                .contains("- `1.0.214` *(latest)* — 1 hour ago"),
            "the Recent versions list's own *(latest)* entry must agree with the Latest \
             line above it, got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_surfaces_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some("python_full_version >= '3.9'".to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains("**Active when**: `python_full_version >= '3.9'`")
        );
    }

    #[tokio::test]
    async fn test_generate_hover_omits_active_when_without_markers() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "requests".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                markers: None,
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Active when"));
    }

    #[tokio::test]
    async fn test_generate_hover_escapes_malicious_dependency_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let malicious_name = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label (between the H1's "# [" and the "](") must be the fully
        // escaped name, with no raw "](" sequence that could close the label early
        // and splice in an attacker-controlled markdown link.
        let header_line = content
            .value
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(
            label,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
    }

    #[tokio::test]
    async fn test_generate_hover_newline_in_name_cannot_forge_new_heading() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Combines S1 (newline breaks out of the ATX heading line) with an
        // autolink payload that needs no brackets/parens at all.
        let malicious_name = "react\n# [fake](https://evil.example) <https://evil.example>";

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: malicious_name.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(
                    Position::new(0, 0),
                    Position::new(0, malicious_name.len() as u32),
                ),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };

        // The link label must be the exact single-line escaped name: no raw
        // newline breaking the ATX heading, and the autolink's `<`/`>` escaped so
        // it cannot render as a live link independent of the `[]`/`()` escaping.
        let header_line = content
            .value
            .lines()
            .next()
            .expect("hover markdown has a header line");
        let label = header_line
            .strip_prefix("# [")
            .expect("header starts with link label")
            .split("](")
            .next()
            .expect("header contains label/url separator");
        assert_eq!(label, escape_markdown(malicious_name));
        assert!(!label.contains('\n'));
        assert!(label.contains(r"\<https"));
    }

    #[tokio::test]
    async fn test_generate_hover_marker_with_parens_renders_unescaped() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Regression guard (M4): a legitimate PEP 508 marker with parentheses must
        // render as-is inside its code span, not with visible `\(`/`\)` escapes —
        // backslash-escaping does not apply inside code spans.
        let marker = "python_version >= \"3.8\" and (sys_platform == \"linux\")";
        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "numpy".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                markers: Some(marker.to_string()),
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&HashMap::new(), &HashMap::new()),
            &MockRegistry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for a dependency at the cursor");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content
                .value
                .contains(&format!("**Active when**: `{marker}`"))
        );
    }

    #[tokio::test]
    async fn test_generate_hover_registry_sections_suppressed_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let registry = MockRegistryWithVersions {
            versions: vec![MockVersionWithAge {
                version: "9.9.9".to_string(),
                yanked: false,
                published_at: None,
            }],
        };
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should still be generated for a non-resolvable-source dependency");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("**Latest**"));
        assert!(!content.value.contains("**Recent versions**"));
        assert!(content.value.contains("**Requirement**"));

        // Control: the same fixture on a Registry-source dependency DOES show
        // both registry-derived sections, proving the fixture isn't vacuous.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let hover = generate_hover(
            &registry_parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions),
            &registry,
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");
        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("**Latest**"));
        assert!(content.value.contains("**Recent versions**"));
    }

    #[tokio::test]
    async fn test_generate_hover_clean_outcome_states_no_known_vulnerabilities() {
        use crate::osv::{ScanOutcome, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("clean-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert("clean-pkg".to_string(), ScanOutcome::Clean);

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_skipped_outcome_says_nothing_about_vulnerabilities() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let parse_result = MockParseResult {
            deps: vec![dep_at("path-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "path-pkg".to_string(),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(!content.value.contains("Security advisories"));
        assert!(!content.value.contains("No known vulnerabilities"));
    }

    #[tokio::test]
    async fn test_generate_hover_vulnerable_outcome_shows_advisories_and_more_count() {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let parse_result = MockParseResult {
            deps: vec![dep_at("bad-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "bad-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Critical)],
                total_known: 3,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "2.0.0".to_string(),
                    advisory_ids: vec!["RUSTSEC-2020-0071".to_string()],
                },
            }),
        );

        let hover = generate_hover(
            &parse_result,
            Position::new(0, 2),
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &MockRegistry,
            &MockFormatter,
            crate::FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("Security advisories"));
        assert!(content.value.contains("RUSTSEC-2020-0071"));
        assert!(content.value.contains("Fixed in"));
        assert!(
            content.value.contains("1.5.0"),
            "must show highest fixed version"
        );
        assert!(content.value.contains("+2 more advisories"));
        assert!(content.value.contains("also affected"));
    }
}
