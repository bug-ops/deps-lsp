//! GitHub Actions dependency and version types.

use deps_core::parser::DependencySource;
use tower_lsp_server::ls_types::{Range, Uri};

/// How a `uses:` step's ref is pinned, driving requirement synthesis and edit shape.
///
/// `None` on [`GithubActionsDependency::pin`] (rather than a fourth variant here) covers
/// every non-resolvable form (`./local`, `docker://…`, a reusable-workflow call, or a bare
/// `uses: owner/repo` with no `@` at all) — those have no ref to classify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStyle {
    /// A tag ref, e.g. `@v4` or `@v4.2.0`.
    Tag,
    /// A 40-character commit SHA ref, optionally annotated with a trailing
    /// `# vX.Y.Z` comment naming the tag it corresponds to.
    Sha {
        /// The tag named by the `# vX.Y.Z` comment, if present and shaped like a full
        /// `major.minor.patch` version (see `parser`'s comment-tag rule).
        comment_tag: Option<String>,
    },
    /// A branch ref, e.g. `@main`.
    Branch,
}

/// Parsed `uses:` dependency from a GitHub Actions workflow file, with position tracking.
///
/// `name` is `owner/repo` — truncated at the second `/` for a subdirectory action
/// (`github/codeql-action/init@v3` -> `github/codeql-action`) or a reusable-workflow call
/// (`owner/repo/.github/workflows/x.yml@ref` -> `owner/repo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubActionsDependency {
    /// `owner/repo` identity.
    pub name: deps_core::PackageName,
    /// LSP range of the `owner/repo` text (truncated at the second `/`).
    pub name_range: Range,
    /// Normalized version requirement: the tag text for a [`PinStyle::Tag`] or a
    /// [`PinStyle::Sha`] with a `comment_tag`, the raw SHA for a commentless
    /// [`PinStyle::Sha`], the branch name for [`PinStyle::Branch`] — `None` for a
    /// non-resolvable source.
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the ref text — for a [`PinStyle::Sha`] with a `comment_tag`, this
    /// extends through the comment token (`<40hex> # v4.2.0`). `None` for a
    /// non-resolvable source or a bare `uses: owner/repo` with no `@` at all.
    pub version_range: Option<Range>,
    /// The raw literal text `version_range` spans, when it differs from `version_req` —
    /// populated only for the SHA-with-comment form, where `version_req` is the
    /// comment-derived tag but `version_range` spans the full `<sha> # <tag>` text.
    pub version_literal: Option<String>,
    /// How the ref is pinned; `None` for a non-resolvable source.
    pub pin: Option<PinStyle>,
    /// Dependency source: [`DependencySource::Registry`] for any `@ref` form (tag, SHA,
    /// or branch — all resolvable against the GitHub tags API by `name` alone),
    /// [`DependencySource::Path`] for `./local`, [`DependencySource::Url`] for
    /// `docker://image:tag` and a reusable-workflow call.
    pub source: DependencySource,
}

impl deps_core::ecosystem::Dependency for GithubActionsDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        self.source.clone()
    }

    fn version_literal(&self) -> Option<&str> {
        self.version_literal.as_deref()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Version information for a GitHub Actions dependency (a repository tag).
#[derive(Debug, Clone)]
pub struct GithubActionsVersion {
    /// The tag as published on GitHub, `v` prefix (or lack of one) kept as-is.
    pub version: deps_core::ConcreteVersion,
    /// The commit SHA this tag points at, as reported by the GitHub tags API.
    pub sha: String,
    /// Whether the tag's semver `pre` component is non-empty, computed once from the
    /// `semver::Version` already parsed while sorting tags.
    pub prerelease: bool,
}

// GitHub's tags API exposes no yank/deprecation signal for actions (mirroring
// `deps-swift`'s `SwiftVersion` — see `Registry::reports_yanked` on
// `GithubActionsRegistry`), so `status` is unconditionally `Available`.
deps_core::impl_version!(GithubActionsVersion {
    version: version,
    status: |_v: &GithubActionsVersion| deps_core::RemovalStatus::Available,
    prerelease: |v: &GithubActionsVersion| v.prerelease,
});

/// Result of parsing a `.github/workflows/*.yml`/`*.yaml` file.
#[derive(Debug)]
pub struct GithubActionsParseResult {
    /// Every `uses:` dependency found, including non-resolvable ones (their consumers
    /// filter on `version_range()`/`source()` as usual).
    pub dependencies: Vec<GithubActionsDependency>,
    /// URI of the parsed workflow file.
    pub uri: Uri,
}

impl deps_core::ParseResult for GithubActionsParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::registry::Version;
    use deps_core::{Dependency, ParseResult};
    use tower_lsp_server::ls_types::Position;

    fn range() -> Range {
        Range::new(Position::new(0, 0), Position::new(0, 10))
    }

    #[test]
    fn test_github_actions_dependency_tag_pin() {
        let dep = GithubActionsDependency {
            name: "actions/checkout".into(),
            name_range: range(),
            version_req: Some("v4".into()),
            version_range: Some(range()),
            version_literal: None,
            pin: Some(PinStyle::Tag),
            source: DependencySource::Registry,
        };
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4")
        );
        assert_eq!(dep.version_literal(), None);
    }

    #[test]
    fn test_github_actions_dependency_sha_with_comment_carries_literal() {
        let dep = GithubActionsDependency {
            name: "actions/checkout".into(),
            name_range: range(),
            version_req: Some("v4.2.0".into()),
            version_range: Some(range()),
            version_literal: Some("b4ffde65f46336ab88eb53be808477a3936bae11 # v4.2.0".to_string()),
            pin: Some(PinStyle::Sha {
                comment_tag: Some("v4.2.0".to_string()),
            }),
            source: DependencySource::Registry,
        };
        assert_eq!(dep.version_literal(), dep.version_literal.as_deref());
        assert_ne!(
            dep.version_literal(),
            dep.version_requirement().map(deps_core::VersionReq::as_str)
        );
    }

    #[test]
    fn test_github_actions_version_prerelease() {
        let stable = GithubActionsVersion {
            version: "v4.2.0".into(),
            sha: "a".repeat(40),
            prerelease: false,
        };
        let pre = GithubActionsVersion {
            version: "v4.2.0-beta.1".into(),
            sha: "b".repeat(40),
            prerelease: true,
        };
        assert!(!stable.is_prerelease());
        assert!(pre.is_prerelease());
        assert!(!stable.removal_status().blocks_resolution());
    }

    #[test]
    fn test_parse_result_dependencies_and_uri() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let result = GithubActionsParseResult {
            dependencies: vec![GithubActionsDependency {
                name: "actions/checkout".into(),
                name_range: range(),
                version_req: Some("v4".into()),
                version_range: Some(range()),
                version_literal: None,
                pin: Some(PinStyle::Tag),
                source: DependencySource::Registry,
            }],
            uri,
        };
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.uri().path().as_str().ends_with("ci.yml"));
    }
}
