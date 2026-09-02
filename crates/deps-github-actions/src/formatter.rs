//! GitHub Actions ecosystem formatter.

use dashmap::DashMap;
use deps_core::lsp_helpers::EcosystemFormatter;
use deps_core::parser::DependencySource;
use deps_core::{
    ConcreteVersion, Dependency, PackageName, VersionReq, lsp_helpers::warn_rejected_value,
};
use std::sync::Arc;

use crate::parser::{is_full_sha, is_tag_shaped};
use crate::registry::TagIndex;
use crate::types::{GithubActionsDependency, PinStyle};

/// Formatter for GitHub Actions ecosystem LSP responses.
pub struct GithubActionsFormatter {
    /// Shared handle to [`crate::registry::GithubActionsRegistry`]'s tag/SHA
    /// cross-reference — read-only from here (`format_version_replacing_for`'s
    /// `PinStyle::Sha` branch).
    pub(crate) tag_index: Arc<DashMap<PackageName, Arc<TagIndex>>>,
}

/// Rewrites `tag` to match `current`'s leading `v`/`V` prefix style (or lack of one).
///
/// A repository can change its tagging convention over time (`4.0.0` -> `v5.0.0`); the
/// formatted replacement should still read naturally against the user's existing pin
/// style rather than silently flipping it.
fn match_v_prefix_style(current: &str, tag: &str) -> String {
    let current_has_v = current.starts_with(['v', 'V']);
    let tag_has_v = tag.starts_with(['v', 'V']);
    match (current_has_v, tag_has_v) {
        (true, false) => format!("v{tag}"),
        (false, true) => tag[1..].to_string(),
        _ => tag.to_string(),
    }
}

impl EcosystemFormatter for GithubActionsFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.as_str().to_string()
    }

    /// Tag → the latest tag, preserving `current`'s `v`-prefix style. SHA → looks up the
    /// new SHA for `version`'s tag in the shared [`TagIndex`]; on a miss, returns
    /// `dep.version_literal().unwrap_or(current)` — byte-identical to the raw declared
    /// span, so every shared no-op guard (comparing against exactly that text)
    /// suppresses the action instead of emitting a destructive downgrade-to-tag edit
    /// (B1). Branch → `current` unchanged, for the same reason.
    fn format_version_replacing_for(
        &self,
        dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
            return self.format_version_for_text_edit(version);
        };
        match &gha_dep.pin {
            Some(PinStyle::Tag) => match_v_prefix_style(current, version.as_str()),
            Some(PinStyle::Sha { .. }) => self
                .tag_index
                .get(dep.name())
                .and_then(|index| index.tag_to_sha.get(version.as_str()).cloned())
                .map(|sha| format!("{sha} # {}", version.as_str()))
                .unwrap_or_else(|| dep.version_literal().unwrap_or(current).to_string()),
            Some(PinStyle::Branch) | None => current.to_string(),
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        if crate::is_valid_github_identity(name.as_str()) {
            format!("https://github.com/{name}")
        } else {
            warn_rejected_value(
                "is_valid_github_identity",
                "github actions package display formatting",
                name.as_str(),
            );
            String::new()
        }
    }

    /// Suppresses the hover heading link for a local composite action (`./x`,
    /// [`DependencySource::Path`]) and a Docker image ref (`docker://...`) — neither has a
    /// dependency name that [`Self::package_url`] can turn into a real URL, so without this
    /// override hover renders a dead `[name]()` link instead of a plain heading (#474).
    ///
    /// A reusable-workflow call (`owner/repo/.github/workflows/x.yml@ref`) is a
    /// [`DependencySource::Url`] too, but its `url` is always built from a valid
    /// `owner/repo` identity (see `crate::parser`'s `is_reusable_workflow` branch) and so is
    /// left unsuppressed; a Docker ref's `url` is the raw `docker://...` value and never
    /// matches that shape.
    fn suppress_package_url(&self, source: &DependencySource) -> bool {
        match source {
            DependencySource::Path { .. } => true,
            DependencySource::Url { url } => !url.starts_with("https://github.com/"),
            // `DependencySource` is `#[non_exhaustive]` (deps-core), so a catch-all arm is
            // required by the compiler regardless — this crate cannot match it exhaustively
            // by variant name. Every other source (`Registry`, `Git`, `Sdk`, `Workspace`,
            // `CustomRegistry`, `AlternateRegistry`, and any future variant) defaults to an
            // unsuppressed (linked) heading, same as before this override existed.
            _ => false,
        }
    }

    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Rewrites a native tag string into the spelling OSV.dev's SEMVER range matching
    /// expects: unprefixed (verified live against `GHSA-mrrh-fwg8-r2c3`, whose ranges
    /// carry no `v` prefix regardless of the affected repository's own tagging
    /// convention).
    ///
    /// `osv_version_to_native` is deliberately left at its default identity: adding a `v`
    /// prefix unconditionally, the way `deps-go` does for module versions, would be wrong
    /// for a GitHub Actions repository that tags without one — and
    /// `format_version_replacing_for`'s `match_v_prefix_style` already reconciles the
    /// prefix against the dependency's *own* declared pin style downstream, so no native
    /// version ever reaches the manifest with the wrong style regardless of what this
    /// method returns.
    fn osv_version(&self, version: &str) -> String {
        version
            .strip_prefix(['v', 'V'])
            .unwrap_or(version)
            .to_string()
    }

    /// A major-only or major.minor requirement (`v4`) is up to date while `latest`'s
    /// corresponding leading components match; a full version is compared component-for-
    /// component. `v`/`V` is normalized off both sides first. An unparseable requirement
    /// (a bare SHA or branch name — neither is dot-separated all-digit) returns `true`,
    /// never a false "outdated": [`Self::requirement_is_unresolved`] is what actually
    /// gates those out of the diagnostic/inlay-hint path; this is only the fallback for a
    /// caller (the "Update N outdated" code lens) that does not consult that hook first.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        let req = requirement
            .as_str()
            .strip_prefix(['v', 'V'])
            .unwrap_or(requirement.as_str());
        let lat = latest
            .as_str()
            .strip_prefix(['v', 'V'])
            .unwrap_or(latest.as_str());

        let req_parts: Vec<&str> = req.split('.').collect();
        let lat_parts: Vec<&str> = lat.split('.').collect();

        let is_all_digits = |parts: &[&str]| {
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        };
        if !is_all_digits(&req_parts) || req_parts.len() > lat_parts.len() {
            return true;
        }
        req_parts.iter().zip(lat_parts.iter()).all(|(r, l)| r == l)
    }

    /// A bare SHA or branch ref is recognizable from the requirement string alone: a
    /// 40-character hex string is a SHA, and anything not shaped like a tag (an optional
    /// `v`/`V` followed by a digit) is treated as a branch — the "honest unknown" side,
    /// since neither can be resolved to a concrete version without a `TagIndex` lookup
    /// this pure predicate has no access to.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        let req = requirement.as_str();
        is_full_sha(req) || !is_tag_shaped(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::parser::DependencySource;
    use tower_lsp_server::ls_types::{Position, Range};

    fn formatter() -> GithubActionsFormatter {
        GithubActionsFormatter {
            tag_index: Arc::new(DashMap::new()),
        }
    }

    // --- #474: hover suppress_package_url / footer regression coverage ---

    #[test]
    fn test_suppress_package_url_local_path_action() {
        let fmt = formatter();
        assert!(fmt.suppress_package_url(&DependencySource::Path {
            path: "./local-action".into(),
        }));
    }

    #[test]
    fn test_suppress_package_url_docker_ref() {
        let fmt = formatter();
        assert!(fmt.suppress_package_url(&DependencySource::Url {
            url: "docker://alpine:3.18".into(),
        }));
    }

    #[test]
    fn test_suppress_package_url_reusable_workflow_not_suppressed() {
        let fmt = formatter();
        assert!(!fmt.suppress_package_url(&DependencySource::Url {
            url: "https://github.com/octo-org/repo".into(),
        }));
    }

    #[test]
    fn test_suppress_package_url_registry_not_suppressed() {
        let fmt = formatter();
        assert!(!fmt.suppress_package_url(&DependencySource::Registry));
    }

    /// A registry mock whose `get_versions` always succeeds with an empty list — enough
    /// to drive `generate_hover`'s `resolvable && available_versions.is_some()` footer
    /// gate (#474) without needing a real `Box<dyn Version>` fixture.
    struct EmptyRegistry;

    impl deps_core::Registry for EmptyRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a PackageName,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = deps_core::Result<Vec<Box<dyn deps_core::Version>>>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a PackageName,
            _req: &'a VersionReq,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = deps_core::Result<Option<Box<dyn deps_core::Version>>>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Ok(None) })
        }

        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Runs `generate_hover` end-to-end against a real parsed workflow line and the real
    /// `GithubActionsFormatter`, mirroring the fixtures already used by `crate::parser`'s
    /// own unit tests (`./local-action`, `docker://alpine:3.18`,
    /// `octo-org/repo/.github/workflows/x.yml@v1`, `actions/checkout@v4`).
    async fn hover_markdown_for(content: &str) -> String {
        use deps_core::freshness::FreshnessSettings;
        use deps_core::lsp_helpers::generate_hover;
        use deps_core::{PublishTime, VersionData};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::HoverContents;

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let fmt = formatter();

        // Cursor placed at the start of the (single) parsed dependency's own name range,
        // rather than a hardcoded line/column, so this helper works for fixtures whose
        // `uses:` line varies in position (top-level `steps:` vs. nested `jobs:.call:`).
        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .name_range()
            .start;

        let hover = generate_hover(
            &parse_result,
            position,
            VersionData::new(&cached, &resolved),
            &EmptyRegistry,
            &fmt,
            FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        content.value
    }

    /// Hover escapes every name it renders (`# `/`# [...]` heading) via
    /// `deps_core::lsp_helpers::escape_markdown`, which backslash-escapes all ASCII
    /// punctuation — building the expected heading through the same function keeps these
    /// assertions from hardcoding that escaping rather than testing it.
    fn escaped(name: &str) -> String {
        deps_core::lsp_helpers::escape_markdown(name)
    }

    #[tokio::test]
    async fn test_hover_local_path_action_has_plain_header_and_no_footer() {
        let markdown = hover_markdown_for("steps:\n  - uses: ./local-action\n").await;
        assert!(
            markdown.starts_with(&format!("# {}\n", escaped("./local-action"))),
            "expected a plain heading, not a dead link; got: {markdown}"
        );
        assert!(!markdown.contains('['), "must not render a markdown link");
        assert!(
            !markdown.contains("Press `Cmd+.`"),
            "a local composite action offers no update code action; got: {markdown}"
        );
    }

    #[tokio::test]
    async fn test_hover_docker_ref_has_plain_header_and_no_footer() {
        let markdown = hover_markdown_for("steps:\n  - uses: docker://alpine:3.18\n").await;
        assert!(
            markdown.starts_with(&format!("# {}\n", escaped("docker://alpine:3.18"))),
            "expected a plain heading, not a dead link; got: {markdown}"
        );
        assert!(!markdown.contains('['), "must not render a markdown link");
        assert!(
            !markdown.contains("Press `Cmd+.`"),
            "a Docker ref offers no update code action; got: {markdown}"
        );
    }

    #[tokio::test]
    async fn test_hover_reusable_workflow_keeps_real_link_and_no_footer() {
        let markdown = hover_markdown_for(
            "jobs:\n  call:\n    uses: octo-org/repo/.github/workflows/x.yml@v1\n",
        )
        .await;
        assert!(
            markdown.starts_with(&format!(
                "# [{}](https://github.com/octo-org/repo)\n",
                escaped("octo-org/repo")
            )),
            "reusable-workflow calls resolve to a real owner/repo identity and keep their \
             link unchanged; got: {markdown}"
        );
        assert!(
            !markdown.contains("Press `Cmd+.`"),
            "a reusable-workflow call is non-resolvable, so no update code action exists; \
             got: {markdown}"
        );
    }

    #[tokio::test]
    async fn test_hover_registry_action_keeps_link_and_footer() {
        let markdown = hover_markdown_for("steps:\n  - uses: actions/checkout@v4\n").await;
        assert!(
            markdown.starts_with(&format!(
                "# [{}](https://github.com/actions/checkout)\n",
                escaped("actions/checkout")
            )),
            "non-regression: a normal Registry-sourced action keeps its link; got: {markdown}"
        );
        assert!(
            markdown.contains("Press `Cmd+.`"),
            "a resolvable Registry source with version data must still show the update \
             footer; got: {markdown}"
        );
    }

    fn dep(pin: Option<PinStyle>, name: &str, literal: Option<&str>) -> GithubActionsDependency {
        GithubActionsDependency {
            name: name.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some("v4".into()),
            version_range: Some(Range::new(Position::new(0, 0), Position::new(0, 1))),
            version_literal: literal.map(str::to_string),
            pin,
            source: DependencySource::Registry,
        }
    }

    #[test]
    fn test_package_url_valid_and_invalid() {
        let fmt = formatter();
        assert_eq!(
            fmt.package_url(&PackageName::new("actions/checkout")),
            "https://github.com/actions/checkout"
        );
        assert_eq!(fmt.package_url(&PackageName::new("no-slash")), "");
        assert_eq!(fmt.package_url(&PackageName::new("owner/..")), "");
    }

    #[test]
    fn test_normalize_package_name() {
        let fmt = formatter();
        assert_eq!(
            fmt.normalize_package_name(&PackageName::new("Actions/Checkout")),
            "actions/checkout"
        );
    }

    #[test]
    fn test_osv_version_strips_v_prefix() {
        let fmt = formatter();
        assert_eq!(fmt.osv_version("v4.2.0"), "4.2.0");
        assert_eq!(fmt.osv_version("4.2.0"), "4.2.0");
    }

    #[test]
    fn test_is_requirement_up_to_date_major_only() {
        let fmt = formatter();
        assert!(
            fmt.is_requirement_up_to_date(&VersionReq::new("v4"), &ConcreteVersion::new("4.3.1"))
        );
        assert!(
            !fmt.is_requirement_up_to_date(&VersionReq::new("v4"), &ConcreteVersion::new("5.0.0"))
        );
    }

    #[test]
    fn test_is_requirement_up_to_date_full_version() {
        let fmt = formatter();
        assert!(fmt.is_requirement_up_to_date(
            &VersionReq::new("v4.2.0"),
            &ConcreteVersion::new("v4.2.0")
        ));
        assert!(!fmt.is_requirement_up_to_date(
            &VersionReq::new("v4.2.0"),
            &ConcreteVersion::new("v4.3.0")
        ));
    }

    #[test]
    fn test_is_requirement_up_to_date_unparseable_never_false_positive() {
        let fmt = formatter();
        assert!(fmt.is_requirement_up_to_date(
            &VersionReq::new("a".repeat(40)),
            &ConcreteVersion::new("v4.3.1")
        ));
        assert!(
            fmt.is_requirement_up_to_date(
                &VersionReq::new("main"),
                &ConcreteVersion::new("v4.3.1")
            )
        );
    }

    #[test]
    fn test_requirement_is_unresolved_sha_and_branch() {
        let fmt = formatter();
        assert!(fmt.requirement_is_unresolved(&VersionReq::new("a".repeat(40))));
        assert!(fmt.requirement_is_unresolved(&VersionReq::new("main")));
    }

    #[test]
    fn test_requirement_is_unresolved_tag_is_resolved() {
        let fmt = formatter();
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new("v4")));
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new("v4.2.0")));
    }

    #[test]
    fn test_format_version_replacing_for_tag_preserves_v_style() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Tag), "actions/checkout", None);
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("5.0.0"), "v4"),
            "v5.0.0"
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "4"),
            "5.0.0"
        );
    }

    #[test]
    fn test_format_version_replacing_for_sha_resolves_via_tag_index() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index
            .tag_to_sha
            .insert("v5.0.0".to_string(), "deadbeef".repeat(5));
        fmt.tag_index.insert(name, Arc::new(index));

        let d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v4.2.0".to_string()),
            }),
            "actions/checkout",
            Some("oldsha # v4.2.0"),
        );
        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, format!("{} # v5.0.0", "deadbeef".repeat(5)));
    }

    #[test]
    fn test_format_version_replacing_for_sha_miss_returns_raw_literal_not_current() {
        // B1: on a TagIndex miss, the guard must compare byte-identical to the raw
        // literal span (`dep.version_literal()`), never to `current` (the synthesized
        // tag requirement) — else the shared no-op guard fails to fire and the edit
        // silently downgrades a SHA pin to a bare tag.
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v4.2.0".to_string()),
            }),
            "actions/checkout",
            Some("oldsha # v4.2.0"),
        );
        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, "oldsha # v4.2.0");
        assert_ne!(new_text, "v4.2.0");
    }

    #[test]
    fn test_format_version_replacing_for_branch_returns_current_unchanged() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Branch), "dev/tool", None);
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v1.0.0"), "main"),
            "main"
        );
    }

    #[test]
    fn test_format_version_replacing_for_non_gha_dependency_falls_back_to_identity() {
        struct OtherDep;
        impl Dependency for OtherDep {
            fn name(&self) -> &PackageName {
                static NAME: std::sync::LazyLock<PackageName> =
                    std::sync::LazyLock::new(|| PackageName::new("other"));
                &NAME
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                None
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> DependencySource {
                DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        let fmt = formatter();
        let d = OtherDep;
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("1.0.0"), "0.9.0"),
            "1.0.0"
        );
    }
}
