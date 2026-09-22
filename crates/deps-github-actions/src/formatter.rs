//! GitHub Actions ecosystem formatter.

use dashmap::DashMap;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementResolution, RequirementStatus, SourcePolicy, match_v_prefix_style,
};
use deps_core::parser::DependencySource;
use deps_core::{
    ConcreteVersion, Dependency, InvalidPackageName, PackageName, VersionReq,
    lsp_helpers::warn_rejected_value,
};
use std::sync::Arc;

use crate::parser::{is_full_sha, is_tag_shaped};
use crate::registry::TagIndex;
use crate::types::{GithubActionsDependency, PinStyle};

/// Formatter for GitHub Actions ecosystem LSP responses.
pub struct GithubActionsFormatter {
    /// Shared handle to [`crate::registry::GithubActionsRegistry`]'s tag/SHA
    /// cross-reference — read-only from here (`format_version_replacing_for`'s
    /// `PinStyle::Sha` branch and [`Self::sha_pin_replacement_for`]).
    pub(crate) tag_index: Arc<DashMap<PackageName, Arc<TagIndex>>>,
}

impl GithubActionsFormatter {
    /// Creates a new formatter over an already-populated (or empty) [`TagIndex`] map,
    /// the same shared handle [`crate::registry::GithubActionsRegistry::tag_index`]
    /// returns.
    ///
    /// `tag_index` stays `pub(crate)` (critic M1): this constructor is the intended
    /// external construction path — a seeded `TagIndex` for a doctest/integration test
    /// goes through [`crate::registry::TagIndex`]'s own already-`pub` fields, not
    /// through widening this struct's field visibility.
    ///
    /// # Examples
    ///
    /// ```
    /// use dashmap::DashMap;
    /// use deps_github_actions::GithubActionsFormatter;
    /// use deps_github_actions::registry::TagIndex;
    /// use deps_core::PackageName;
    /// use std::sync::Arc;
    ///
    /// let tag_index = Arc::new(DashMap::new());
    /// let mut index = TagIndex::default();
    /// index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
    /// tag_index.insert(PackageName::new("actions/checkout"), Arc::new(index));
    ///
    /// let formatter = GithubActionsFormatter::new(tag_index);
    /// assert_eq!(
    ///     formatter.sha_pin_replacement_for(&PackageName::new("actions/checkout"), "v4"),
    ///     Some(format!("{} # v4", "a".repeat(40)))
    /// );
    /// ```
    #[must_use]
    pub fn new(tag_index: Arc<DashMap<PackageName, Arc<TagIndex>>>) -> Self {
        Self { tag_index }
    }

    /// Looks up `tag`'s commit SHA for `name` in the shared [`TagIndex`], returning the
    /// `{sha} # {tag}` replacement text a "Pin to commit SHA" code action (issue #473)
    /// writes — `None` on a cache miss (no `TagIndex` entry for `name`, or no entry for
    /// this specific `tag`).
    ///
    /// Deliberately separate from [`Self::format_version_replacing_for`]'s
    /// `PinStyle::Tag` branch: that branch bumps to the *latest* tag (outdated-version
    /// semantics — "update `v3` to `v4`"), while this pins the *current* tag to its own
    /// SHA (mutability semantics — "harden `v4` to `<sha> # v4`"). The two operations
    /// are independent (a step can need either, both, or neither) and must never be
    /// conflated behind one method.
    ///
    /// # Examples
    ///
    /// ```
    /// use dashmap::DashMap;
    /// use deps_github_actions::GithubActionsFormatter;
    /// use deps_github_actions::registry::TagIndex;
    /// use deps_core::PackageName;
    /// use std::sync::Arc;
    ///
    /// let tag_index = Arc::new(DashMap::new());
    /// let mut index = TagIndex::default();
    /// index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
    /// tag_index.insert(PackageName::new("actions/checkout"), Arc::new(index));
    ///
    /// let formatter = GithubActionsFormatter::new(tag_index);
    /// // Miss: no entry for this tag.
    /// assert_eq!(
    ///     formatter.sha_pin_replacement_for(&PackageName::new("actions/checkout"), "v5"),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub fn sha_pin_replacement_for(&self, name: &PackageName, tag: &str) -> Option<String> {
        let sha = self
            .tag_index
            .get(name)
            .and_then(|index| index.tag_to_sha.get(tag).cloned())?;
        Some(format!("{sha} # {tag}"))
    }
}

/// Implements `deps-core`'s shared "pin to commit SHA" resolution (issue #1138) for a
/// `PinStyle::Tag` step: the same eligibility guards `build_sha_pin_action`/
/// `sha_pin_text_edit_for` used to re-derive locally (FR-010's quoted-scalar withholding,
/// #633's flow-style-line withholding), now the single source of truth both the
/// per-position quickfix and the bulk "pin all to SHA" code lens build on.
#[cfg(feature = "lsp-responses")]
impl deps_core::lsp_helpers::ShaPinning for GithubActionsFormatter {
    fn resolve_static_sha_pin(
        &self,
        dep: &dyn Dependency,
    ) -> Option<deps_core::lsp_helpers::ResolvedShaPin> {
        let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
        // Shared with `mutable_ref_pin_diagnostics`'s message-branch selection (#1188
        // critic S1/S2): the structural shape gate (`PinStyle::Tag`, `is_plain_scalar`/
        // FR-010, `is_last_on_line`/#633) lives in one ungated place so a diagnostic and
        // this quickfix can never independently drift on eligibility.
        if !crate::ecosystem::is_sha_pinnable_tag(gha_dep) {
            return None;
        }
        let version_range = gha_dep.version_range?;
        let tag = gha_dep.version_req.as_ref().map(VersionReq::as_str)?;
        let new_text = self.sha_pin_replacement_for(&gha_dep.name, tag)?;
        Some(deps_core::lsp_helpers::ResolvedShaPin {
            display_name: gha_dep.name.as_str().to_string(),
            version_range,
            replacement: new_text,
        })
    }
}

impl PackageNaming for GithubActionsFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Accepts `crate::is_valid_github_identity`'s `owner/repo` shape, or either of the
    /// two non-registry `uses:` forms `crate::parser::classify_uses_value` recognizes by
    /// the same leading literals: a local composite action path (`./x`, `.\x`,
    /// [`DependencySource::Path`]) or a Docker image reference (`docker://x`, carried as a
    /// [`DependencySource::Url`] — GitHub Actions has no dedicated Docker source variant).
    ///
    /// The non-registry forms matter here for the same reason a bare local-package name
    /// matters to `SwiftFormatter::validate_package_name` (#402 critique C1): a `Path`- or
    /// Docker-`uses:`-sourced [`GithubActionsDependency`] keeps its raw `uses:` value as
    /// `name()` verbatim rather than an `owner/repo` coordinate, and
    /// `deps_core::lsp_helpers::diagnostics`'s R5a "unknown package" rule runs
    /// `validate_package_name` unconditionally — even for a source this formatter's
    /// `can_resolve_source` (default, unoverridden) already treats as non-resolvable.
    /// Without accepting these two literal prefixes, every workflow step using a local
    /// action or a Docker image would be flagged "Invalid package name" instead of
    /// producing no diagnostic at all, as before this override existed.
    ///
    /// In the current codebase this method's `Err` arm is unreachable from any live call
    /// path: `classify_uses_value` already discards a malformed `owner/repo` `uses:` value
    /// as `Malformed` before a `Registry`- or reusable-workflow-sourced dependency is ever
    /// constructed, and `GithubActionsFormatter`'s `supports_package_rename` (default,
    /// unoverridden `false`) skips `deps_core::lsp_helpers::code_actions`'s
    /// `build_replacement_action` — the only other call site — before it reaches this
    /// method. The override exists for parity with every other GitHub-identifier-shaped
    /// or coordinate-shaped ecosystem formatter (`deps-swift`, and the #402/#375 sweep) and
    /// as a defensive gate for any future caller that constructs a name without going
    /// through `classify_uses_value`, not because a malformed name reaches it today.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] when `name` is none of the three accepted shapes.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if crate::is_valid_github_identity(name)
            || name.starts_with("./")
            || name.starts_with(".\\")
            || name.starts_with("docker://")
        {
            Ok(())
        } else {
            Err(InvalidPackageName::new(
                "name must be a GitHub 'owner/repo' identifier",
            ))
        }
    }
}

impl PackageRendering for GithubActionsFormatter {
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
            // is_plain_scalar: a quoted value has version_range inside quotes, so appending
            // `# {tag}` would break the string, not start a comment (#473). is_last_on_line:
            // a flow-style step has real YAML after the ref, which would get commented out
            // too (#633/#898). Both guards fall to the no-op fallback.
            Some(PinStyle::Sha { .. }) if gha_dep.is_plain_scalar && gha_dep.is_last_on_line => {
                self.tag_index
                    .get(dep.name())
                    .and_then(|index| index.tag_to_sha.get(version.as_str()).cloned())
                    .map(|sha| format!("{sha} # {}", version.as_str()))
                    .unwrap_or_else(|| dep.version_literal().unwrap_or(current).to_string())
            }
            Some(PinStyle::Sha { .. } | PinStyle::Branch) | None => {
                dep.version_literal().unwrap_or(current).to_string()
            }
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        if crate::is_valid_github_identity(name.as_str()) {
            format!("https://github.com/{}", name.as_str())
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
            // `DependencySource` is `#[non_exhaustive]`, so a catch-all arm is required;
            // every other source defaults to an unsuppressed (linked) heading.
            _ => false,
        }
    }
}

impl RequirementResolution for GithubActionsFormatter {
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

    /// Prefers a SHA pin's registry-confirmed tag (`TagIndex.sha_to_tag`, ground truth
    /// from the tags API) over trusting the comment text, when both are available (#907
    /// review S2): the trailing `# vX` comment names *a* tag the pin was written against,
    /// but the SHA itself is immutable — a stale comment can silently read as "up to
    /// date" against `latest` even though the pinned commit is actually behind newer
    /// releases still inside the same major/minor line. Falls back to
    /// [`Self::requirement_status`] (trusting the comment) on any `TagIndex` miss — a
    /// cold cache before the registry fetch populates it, or a commentless/tag/branch
    /// pin, for which the comment-trusting path is already correct or already
    /// `Unresolved`.
    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        self.sha_pin_status_from_tag_index(dep, latest)
            .unwrap_or_else(|| self.requirement_status(requirement, latest))
    }
}

impl GithubActionsFormatter {
    /// Ground-truth status for a comment-annotated SHA pin whose commit is indexed in
    /// `tag_index` — see [`RequirementResolution::requirement_status_for`]. `None` when
    /// `dep` isn't such a pin, or the SHA has no `TagIndex` entry yet.
    fn sha_pin_status_from_tag_index(
        &self,
        dep: &dyn Dependency,
        latest: &ConcreteVersion,
    ) -> Option<RequirementStatus> {
        let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
        // Restricted to comment-annotated SHA pins: a commentless pin has no human-written
        // text to distrust, so it stays on the ordinary path instead (#907 scope decision).
        if !matches!(
            gha_dep.pin,
            Some(PinStyle::Sha {
                comment_tag: Some(_)
            })
        ) {
            return None;
        }
        let sha = crate::types::sha_pin_raw_sha(gha_dep)?;
        if !is_full_sha(sha) {
            return None;
        }
        let real_tag = self.tag_index.get(dep.name())?.sha_to_tag.get(sha)?.clone();
        Some(
            if self.is_requirement_up_to_date(&VersionReq::new(real_tag), latest) {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            },
        )
    }
}

impl DiagnosticMessages for GithubActionsFormatter {}

impl DiagnosticPolicy for GithubActionsFormatter {}

impl SourcePolicy for GithubActionsFormatter {}

impl OsvNaming for GithubActionsFormatter {}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::parser::DependencySource;
    use deps_core::{Position, Range};

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

    /// A registry mock whose `get_versions` always succeeds with an empty list — a real
    /// GitHub repository whose only tags don't parse as full semver
    /// (`dtolnay/rust-toolchain`'s sole tag `v1`, issue #550), not a fetch failure.
    #[cfg(feature = "lsp-responses")]
    struct EmptyRegistry;

    #[cfg(feature = "lsp-responses")]
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

        fn search_raw<'a>(
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
    #[cfg(feature = "lsp-responses")]
    async fn hover_markdown_for(content: &str) -> String {
        use deps_core::freshness::FreshnessSettings;
        use deps_core::lsp_helpers::generate_hover;
        use deps_core::{PublishTime, VersionData};
        use std::collections::HashMap;

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let fmt = formatter();

        // The dependency's own name range, not a hardcoded line/column, so this works
        // regardless of where the `uses:` line falls.
        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .name_range()
            .start;

        let hover = generate_hover(
            &parse_result,
            position.into(),
            VersionData::new(&cached, &resolved),
            &EmptyRegistry,
            &fmt,
            FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for the dependency on this line");

        hover.markdown().to_string()
    }

    /// Hover escapes every name it renders (`# `/`# [...]` heading) via
    /// `deps_core::lsp_helpers::escape_markdown`, which backslash-escapes all ASCII
    /// punctuation — building the expected heading through the same function keeps these
    /// assertions from hardcoding that escaping rather than testing it.
    #[cfg(feature = "lsp-responses")]
    fn escaped(name: &str) -> String {
        deps_core::lsp_helpers::escape_markdown(name)
    }

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    /// #550: a resolvable Registry source whose live fetch genuinely succeeds with zero
    /// entries (e.g. `dtolnay/rust-toolchain`, whose only tag `v1` isn't full semver)
    /// must keep its link but must NOT show the update footer — there's nothing to
    /// update to, so advertising `Cmd+.` would be misleading. Supersedes this test's
    /// pre-#550 name and assertion, which locked in exactly that bug.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_hover_registry_action_keeps_link_no_footer_when_versions_empty() {
        let markdown = hover_markdown_for("steps:\n  - uses: actions/checkout@v4\n").await;
        assert!(
            markdown.starts_with(&format!(
                "# [{}](https://github.com/actions/checkout)\n",
                escaped("actions/checkout")
            )),
            "non-regression: a normal Registry-sourced action keeps its link; got: {markdown}"
        );
        assert!(
            !markdown.contains("**Recent versions**"),
            "an empty live version list must not render an empty section header; got: {markdown}"
        );
        assert!(
            !markdown.contains("Press `Cmd+.`"),
            "a resolvable Registry source with zero live versions and nothing cached has \
             no update code action to advertise; got: {markdown}"
        );
    }

    /// Non-regression companion to the above (#474's original contract): a resolvable
    /// Registry source whose live fetch returns real version data must still show the
    /// update footer.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_hover_registry_action_keeps_footer_when_versions_present() {
        use deps_core::freshness::FreshnessSettings;
        use deps_core::lsp_helpers::generate_hover;
        use deps_core::{PublishTime, VersionData};
        use std::collections::HashMap;

        struct OneVersionRegistry;

        impl deps_core::Registry for OneVersionRegistry {
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
                Box::pin(async move {
                    Ok(vec![Box::new(crate::types::GithubActionsVersion {
                        version: "v4.2.0".into(),
                        sha: "a".repeat(40),
                        prerelease: false,
                        published_at: None,
                    }) as Box<dyn deps_core::Version>])
                })
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

            fn search_raw<'a>(
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

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let fmt = formatter();
        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .name_range()
            .start;

        let hover = generate_hover(
            &parse_result,
            position.into(),
            VersionData::new(&cached, &resolved),
            &OneVersionRegistry,
            &fmt,
            FreshnessSettings::default(),
            PublishTime::now(),
        )
        .await
        .expect("hover should be generated for the dependency on this line");

        let content = hover.markdown();
        assert!(
            content.contains("**Recent versions**"),
            "a non-empty live version list must render the section; got: {}",
            content
        );
        assert!(
            content.contains("Press `Cmd+.`"),
            "a resolvable Registry source with real live version data must still show \
             the update footer; got: {}",
            content
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
            is_plain_scalar: true,
            is_last_on_line: true,
        }
    }

    /// End-to-end regression for issue #907: a SHA-pinned `uses:` ref annotated with the
    /// common `# vX` (major-only) comment convention must produce a real "outdated" inlay
    /// hint, not silently emit nothing. Before the fix, `extract_comment_tag` accepted only
    /// a full `major.minor.patch` comment, so this exact real-world shape degraded to an
    /// unresolvable bare-SHA requirement and `generate_inlay_hints` emitted no hint at all
    /// (`RequirementStatus::Unresolved`).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_inlay_hint_sha_pin_with_major_only_comment_tag_shows_outdated() {
        use deps_core::{EcosystemConfig, VersionData};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::InlayHintLabel;

        let sha = "d23441a48e516b6c34aea4fa41551a30e30af803";
        let content = format!("steps:\n  - uses: actions/checkout@{sha} # v6\n");
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let fmt = formatter();

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "actions/checkout".into(),
            deps_core::PackageVersions::latest_only("v7.0.1"),
        );
        let resolved_versions = HashMap::new();

        let config = EcosystemConfig::default();
        let hints = deps_core::lsp_helpers::generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
            &fmt,
        );

        assert_eq!(hints.len(), 1, "expected one inlay hint, got: {hints:?}");
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.contains("v7.0.1"),
                    "expected an outdated hint naming the latest version, got: {text}"
                );
            }
            other => panic!("expected string label, got: {other:?}"),
        }
    }

    /// Companion to the major-only case above at major.minor precision (`# v2.9`) — the
    /// other real-world precision `is_partial_semver_shaped` accepts, through the full
    /// `generate_inlay_hints` pipeline rather than only the parser level.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_inlay_hint_sha_pin_with_major_minor_comment_tag_shows_outdated() {
        use deps_core::{EcosystemConfig, VersionData};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::InlayHintLabel;

        let sha = "6b69fcf40e9b5fb17adeb57e4b6ecd020649a239";
        let content =
            format!("steps:\n  - uses: obi1kenobi/cargo-semver-checks-action@{sha} # v2.9\n");
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let fmt = formatter();

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "obi1kenobi/cargo-semver-checks-action".into(),
            deps_core::PackageVersions::latest_only("v3.1.0"),
        );
        let resolved_versions = HashMap::new();

        let config = EcosystemConfig::default();
        let hints = deps_core::lsp_helpers::generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
            &fmt,
        );

        assert_eq!(hints.len(), 1, "expected one inlay hint, got: {hints:?}");
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.contains("v3.1.0"),
                    "expected an outdated hint naming the latest version, got: {text}"
                );
            }
            other => panic!("expected string label, got: {other:?}"),
        }
    }

    /// #907 review S2: a comment-annotated SHA pin's status must prefer the
    /// registry-confirmed tag (`TagIndex.sha_to_tag`) over trusting the comment text,
    /// when the tag index actually has an entry for that SHA. Here the SHA is really
    /// `v4.0.0` (registry ground truth) even though its comment says `v4` — against a
    /// `latest` of `v4.3.1`, the naive comment-only comparison would say "up to date"
    /// (major matches), but the ground-truth-aware path must say "outdated".
    #[test]
    fn test_requirement_status_for_sha_pin_prefers_tag_index_ground_truth_over_comment() {
        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.sha_to_tag.insert(sha.clone(), "v4.0.0".to_string());
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v4".to_string()),
            }),
            "actions/checkout",
            Some(format!("{sha} # v4").as_str()),
        );

        // Confirms the naive comment-only path would say "up to date" here, so this test
        // exercises a genuine divergence, not a case where both paths happen to agree.
        assert_eq!(
            fmt.requirement_status(&VersionReq::new("v4"), &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::UpToDate
        );

        assert_eq!(
            fmt.requirement_status_for(&d, &VersionReq::new("v4"), &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::Outdated,
            "ground-truth tag v4.0.0 is behind latest v4.3.1; must not trust the stale v4 comment"
        );
    }

    /// #907 review C1: the parser's comment-tag rule only requires the `#` to be
    /// *preceded* by whitespace, so a two-space or tab gap before the `#` is a valid
    /// literal (`ecosystem.rs`'s `generate_hover` SHA-pin branch already documents and
    /// handles this). `sha_pin_status_from_tag_index` must extract the SHA the same
    /// whitespace-token way, or it silently misses the `TagIndex` lookup and falls back
    /// to trusting the (possibly stale) comment — reopening exactly the false-`UpToDate`
    /// gap S2 fixed.
    #[test]
    fn test_requirement_status_for_sha_pin_ground_truth_survives_non_single_space_gap() {
        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.sha_to_tag.insert(sha.clone(), "v4.0.0".to_string());
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        for literal in [format!("{sha}  # v4"), format!("{sha}\t# v4")] {
            let d = dep(
                Some(PinStyle::Sha {
                    comment_tag: Some("v4".to_string()),
                }),
                "actions/checkout",
                Some(literal.as_str()),
            );
            assert_eq!(
                fmt.requirement_status_for(
                    &d,
                    &VersionReq::new("v4"),
                    &ConcreteVersion::new("v4.3.1")
                ),
                RequirementStatus::Outdated,
                "must still reach the tag_index ground truth (v4.0.0, outdated) through a \
                 non-single-space gap: {literal:?}"
            );
        }
    }

    /// Companion to the above: on a `TagIndex` miss (SHA not indexed — e.g. cold cache
    /// before the registry fetch populates it), `requirement_status_for` must fall back
    /// to trusting the comment text exactly as `requirement_status` already does, not
    /// silently downgrade to `Unresolved`.
    #[test]
    fn test_requirement_status_for_sha_pin_falls_back_to_comment_on_tag_index_miss() {
        let sha = "a".repeat(40);
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v4".to_string()),
            }),
            "actions/checkout",
            Some(format!("{sha} # v4").as_str()),
        );

        assert_eq!(
            fmt.requirement_status_for(&d, &VersionReq::new("v4"), &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::UpToDate,
            "no TagIndex entry: falls back to the comment-trusting path"
        );
    }

    /// #907 review M3: the genuinely strongest argument for accepting a partial comment
    /// tag is a write/read round trip through this project's own "Pin to commit SHA"
    /// code action — `format_version_replacing_for`'s `PinStyle::Sha` branch writes the
    /// user's *current* tag (commonly `v4`) into the `# {tag}` comment, which the
    /// pre-#907 parser then rejected on the very next parse. Confirms the round trip is
    /// now stable: write with `format_version_replacing_for`, reparse, same tag back out.
    #[test]
    fn test_sha_pin_comment_tag_round_trips_through_format_version_replacing_for() {
        let sha = "b".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), sha.clone());
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let old_sha = "c".repeat(40);
        let d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v3".to_string()),
            }),
            "actions/checkout",
            Some(format!("{old_sha} # v3").as_str()),
        );
        let written = fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v4"), "v3");
        assert_eq!(written, format!("{sha} # v4"));

        let content = format!("steps:\n  - uses: actions/checkout@{written}\n");
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let result = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let reparsed = &deps_core::ParseResult::dependencies(&result)[0];
        assert_eq!(
            reparsed
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some("v4"),
            "the tag this code action just wrote must survive being reparsed"
        );
    }

    #[test]
    fn test_normalize_package_name() {
        let fmt = formatter();
        assert_eq!(
            fmt.normalize_package_name(&PackageName::new("Actions/Checkout")),
            "actions/checkout"
        );
    }

    // #758: exact-value `EcosystemFormatter` conformance, replacing several ad hoc tests. No
    // `version_roundtrip` — this formatter overrides the requirement-status methods instead,
    // hand-written below.
    deps_core::formatter_conformance! {
        mod github_actions_formatter_conformance;
        build: formatter();
        package_url: {
            "actions/checkout" => "https://github.com/actions/checkout",
            "no-slash" => "",
            "owner/.." => "",
        };
        accepts: [
            "actions/checkout", "./local-action", "./nested/local-action",
            "docker://alpine:3.18",
        ];
        rejects: [
            "", ".", "..", "no-slash", "owner/repo/extra", "../../etc/passwd", "owner/..",
        ];
        format_version: [ "v4.2.0" => "v4.2.0" ];
        hostile_package_url_expected: "";
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

    /// FR-010 sibling fix (security audit finding): a quoted-scalar SHA pin must fall
    /// back to the no-op literal even on a `TagIndex` hit — never append `# {tag}` inside
    /// the quotes.
    #[test]
    fn test_format_version_replacing_for_sha_quoted_scalar_falls_back_to_literal() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index
            .tag_to_sha
            .insert("v5.0.0".to_string(), "deadbeef".repeat(5));
        fmt.tag_index.insert(name, Arc::new(index));

        let mut d = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v4.2.0".to_string()),
            }),
            "actions/checkout",
            Some("oldsha # v4.2.0"),
        );
        d.is_plain_scalar = false;

        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, "oldsha # v4.2.0");
    }

    /// Issue #898 critic follow-up (S1): a flow-style SHA ref with sibling YAML content
    /// (`, with: {node-version: 20}}`) must withhold the `# {tag}`-appending edit even on
    /// a `TagIndex` hit, exactly like the quoted-scalar guard above — otherwise accepting
    /// the version-update code action comments out the sibling content, producing an
    /// unterminated flow mapping. Manifest shape from the issue's exact repro:
    /// `- {uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683, with: {node-version: 20}}`.
    #[test]
    fn test_format_version_replacing_for_sha_flow_style_not_last_on_line_falls_back_to_literal() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index
            .tag_to_sha
            .insert("v5.0.0".to_string(), "deadbeef".repeat(5));
        fmt.tag_index.insert(name, Arc::new(index));

        let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
        let mut d = dep(
            Some(PinStyle::Sha { comment_tag: None }),
            "actions/checkout",
            None,
        );
        d.is_last_on_line = false;

        // Commentless flow-style SHA ref: `current` is the raw SHA since `version_literal` is `None`.
        let new_text = fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), sha);
        assert_eq!(
            new_text, sha,
            "a flow-style SHA ref with sibling content must never gain a `# {{tag}}` suffix"
        );
        assert!(!new_text.contains('#'));
    }

    /// Positive-control companion to the withhold test above: an ordinary,
    /// genuinely-last-on-line SHA ref (the overwhelming common case) must keep resolving
    /// through `TagIndex` and appending `# {tag}` — the #898 fix must not become overly
    /// conservative and silently withhold a safe, correct edit.
    #[test]
    fn test_format_version_replacing_for_sha_last_on_line_still_appends_tag_comment() {
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
            Some("11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.0"),
        );
        assert!(d.is_last_on_line);

        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, format!("{} # v5.0.0", "deadbeef".repeat(5)));
    }

    #[test]
    fn test_format_version_replacing_for_sha_miss_returns_raw_literal_not_current() {
        // B1: on a TagIndex miss, the guard must compare against the raw literal span, never
        // `current` (the synthesized tag requirement), or a SHA pin silently downgrades to tag.
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
    fn test_sha_pin_replacement_for_hit() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        fmt.tag_index.insert(name.clone(), Arc::new(index));

        assert_eq!(
            fmt.sha_pin_replacement_for(&name, "v4"),
            Some(format!("{} # v4", "a".repeat(40)))
        );
    }

    /// M5 (tasks.md T003 gotcha): `TagIndex.tag_to_sha` keys are exact tag strings as
    /// published — a repository that tags without a `v` prefix must still hit.
    #[test]
    fn test_sha_pin_replacement_for_hit_without_v_prefix() {
        let fmt = formatter();
        let name = PackageName::new("owner/repo");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("2.1.0".to_string(), "b".repeat(40));
        fmt.tag_index.insert(name.clone(), Arc::new(index));

        assert_eq!(
            fmt.sha_pin_replacement_for(&name, "2.1.0"),
            Some(format!("{} # 2.1.0", "b".repeat(40)))
        );
    }

    #[test]
    fn test_sha_pin_replacement_for_miss_no_repo_entry() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        assert_eq!(fmt.sha_pin_replacement_for(&name, "v4"), None);
    }

    #[test]
    fn test_sha_pin_replacement_for_miss_tag_not_indexed() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        fmt.tag_index.insert(name.clone(), Arc::new(index));

        assert_eq!(fmt.sha_pin_replacement_for(&name, "v5"), None);
    }

    /// SC-005: the "Pin to commit SHA" code action's replacement text must be
    /// byte-identical to what `format_version_replacing_for`'s `PinStyle::Sha` branch
    /// already produces for the same `(name, tag)` pair.
    #[test]
    fn test_sha_pin_replacement_for_matches_format_version_replacing_for_sha_branch() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        fmt.tag_index.insert(name.clone(), Arc::new(index));

        let via_sha_pin_action = fmt.sha_pin_replacement_for(&name, "v4").unwrap();

        let sha_dep = dep(
            Some(PinStyle::Sha {
                comment_tag: Some("v3".to_string()),
            }),
            "actions/checkout",
            Some("oldsha # v3"),
        );
        let via_outdated_sha_update =
            fmt.format_version_replacing_for(&sha_dep, &ConcreteVersion::new("v4"), "v3");

        assert_eq!(via_sha_pin_action, via_outdated_sha_update);
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
