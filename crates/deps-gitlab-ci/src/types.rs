//! GitLab CI dependency and version types.

use deps_core::parser::DependencySource;
use tower_lsp_server::ls_types::{Range, Uri};

use crate::host::GitlabHost;

/// Which `include:` form a dependency came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeKind {
    /// `include: - project: org/proj` + `ref:`.
    Project,
    /// `include: - component: host/org/proj/name@ref`.
    Component,
}

impl IncludeKind {
    /// The [`EndpointKind`] an include of this kind always resolves against — the fixed,
    /// 1:1 correspondence `crate::parser::build_project_dependency`/
    /// `crate::parser::build_component_dependency` bake in at parse time.
    ///
    /// Used to key [`crate::registry::TagIndex`] lookups by `(EndpointKind, PackageName)`
    /// rather than by `PackageName` alone (validation finding S2): a `component:`'s
    /// host-qualified name can textually collide with an unrelated `project:` include's own
    /// name (spec §3.1's documented residual collision is same-project only; this is the
    /// cross-project case it does not cover), and without the endpoint in the key the two
    /// would share one `TagIndex` entry, letting a quickfix resolve a SHA from the wrong
    /// repository.
    #[must_use]
    pub const fn endpoint(self) -> EndpointKind {
        match self {
            Self::Project => EndpointKind::Tags,
            Self::Component => EndpointKind::Releases,
        }
    }
}

/// Which GitLab REST endpoint a [`crate::registry::GitlabCiRegistry`] route resolves
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    /// `GET /projects/:id/repository/tags` — backs [`IncludeKind::Project`].
    Tags,
    /// `GET /projects/:id/releases` — backs [`IncludeKind::Component`] (spec FR-004/FR-007:
    /// a component version *is* a project Release; a tag with no release is not one).
    Releases,
}

impl EndpointKind {
    /// A stable string discriminator, used as one part of the route's hashed routing key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tags => "tags",
            Self::Releases => "releases",
        }
    }
}

/// A dependency's resolved (or not-yet-resolvable) host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRef {
    /// A validated, policy-gated host — from a `component:` prefix, or from
    /// `registries.gitlab_instance_host` (spec FR-011a).
    Literal(GitlabHost),
    /// `$CI_SERVER_FQDN` (or another unresolved CI-time variable), or a `project:` include
    /// with the instance-host setting unset — carries the raw, unresolved expression for
    /// display only (spec FR-012).
    Unresolved(String),
    /// A host that validated successfully but whose route/admission was refused purely by a
    /// capacity limit (spec §4.6's per-document host cap, or the registry's process-wide
    /// `MAX_GITLAB_ROUTES` cap) — carries the host's normalized origin. Deliberately distinct
    /// from [`Self::Unresolved`] (#466 review M-a): the host genuinely *is* determinable, so
    /// the diagnostic this produces must never suggest `registries.gitlab_instance_host` as
    /// the fix — a capacity refusal needs fewer distinct hosts/includes, not that setting.
    CapacityRefused(String),
}

/// The `(host, endpoint)` pair a dependency resolves against, registered at parse time
/// under an opaque routing key carried in `DependencySource::AlternateRegistry.index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabRoute {
    /// Normalized, ASCII-serialized origin (`https://{host}`).
    pub origin: String,
    /// Which endpoint this route resolves against.
    pub endpoint: EndpointKind,
}

/// How a pin (a `project:` ref, or a `component:` version) is classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStyle {
    /// A 40-character commit SHA.
    Sha,
    /// An exact published tag (`project:`) or release name (`component:`).
    Tag,
    /// Honest-unknown: not a SHA, not an exact tag/release, not `~latest`, not
    /// partial-semver-shaped. Also covers a git branch ref.
    Branch,
    /// Literal `~latest` (`component:` only) — highest published non-prerelease semver
    /// release.
    Latest,
    /// A partial semantic version, e.g. `1.2` or `1` (`component:` only).
    Partial,
}

/// Parsed `include:` dependency from a `.gitlab-ci.yml`-syntax file, with position
/// tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabCiDependency {
    /// Host-qualified when the host is known: `{host}/{project_path}` for [`IncludeKind::Project`],
    /// `{host}/{project_path}/{component_name}` for [`IncludeKind::Component`]. The bare
    /// path alone (no host prefix) when [`Self::host`] is [`HostRef::Unresolved`] (spec
    /// §3.1 — this also means every name-keyed structure is automatically per-instance).
    pub name: deps_core::PackageName,
    /// LSP range of the `project:`/`component:` value text.
    pub name_range: Range,
    /// Normalized version requirement: the ref/pin text, or `None` for a `project:`
    /// include with no `ref:` at all (GitLab defaults that to the project's default
    /// branch, which this crate cannot resolve to a concrete version).
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the ref/pin text.
    pub version_range: Option<Range>,
    /// The raw literal text, when it differs from `version_req` (unused today — no
    /// GitLab CI pin form carries a comment-derived requirement the way GitHub Actions'
    /// SHA-with-comment form does; kept for [`deps_core::ecosystem::Dependency`] parity).
    pub version_literal: Option<String>,
    /// Dependency source: [`DependencySource::AlternateRegistry`] when [`Self::host`] is
    /// known and its route was registered; [`DependencySource::CustomRegistry`] otherwise
    /// (unresolved host, or a route the process-wide cap refused) — see spec §3.2.
    pub source: DependencySource,
    /// Whether the whole include-entry value was written as a plain (unquoted) YAML
    /// scalar, mirroring `deps-github-actions`'s identical field.
    pub is_plain_scalar: bool,
    /// Which `include:` form this dependency came from.
    pub kind: IncludeKind,
    /// This dependency's resolved (or not-yet-resolvable) host.
    pub host: HostRef,
    /// How the ref/pin is classified; `None` only for a hostless-ref `project:` include
    /// (no `ref:` key at all).
    pub pin: Option<PinStyle>,
    /// The bare `org/sub/proj[/component]` path, without a host prefix — kept for URL
    /// construction and the registry's own fetch-path use.
    pub project_path: String,
}

impl deps_core::ecosystem::Dependency for GitlabCiDependency {
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

/// Version information for a GitLab CI dependency: a repository tag (`project:`) or a
/// project release (`component:`).
#[derive(Debug, Clone)]
pub struct GitlabCiVersion {
    /// The tag/release name as published, `v` prefix (or lack of one) kept as-is.
    pub version: deps_core::ConcreteVersion,
    /// The commit SHA this tag/release points at.
    pub sha: String,
    /// Whether the semver `pre` component is non-empty.
    pub prerelease: bool,
    /// `Some(released_at)` for the releases endpoint (free — same response); `None` for
    /// tags, since a tag's only date is its *commit* date, not a publish date, and using
    /// it would misreport freshness.
    pub published_at: Option<deps_core::PublishTime>,
}

// GitLab exposes no yank/deprecation signal for either endpoint, so `status` is
// unconditionally `Available` (mirrors `deps-github-actions`'s `GithubActionsVersion`).
deps_core::impl_version!(GitlabCiVersion {
    version: version,
    status: |_v: &GitlabCiVersion| deps_core::RemovalStatus::Available,
    published_at: published_at,
    prerelease: |v: &GitlabCiVersion| v.prerelease,
});

/// Result of parsing a `.gitlab-ci.yml`-syntax file.
#[derive(Debug)]
pub struct GitlabCiParseResult {
    /// Every `include:` dependency found, including ones with an unresolved host (their
    /// consumers filter on `source()`/hover-visible `HostRef` as usual).
    pub dependencies: Vec<GitlabCiDependency>,
    /// Distinct `(route_key, route)` pairs this parse produced, to be registered into the
    /// shared [`crate::registry::GitlabCiRegistry`] by `GitlabCiEcosystem::parse_manifest`
    /// before this result is returned (spec §3.2/§4.6's downgrade pass).
    pub routes: Vec<(String, GitlabRoute)>,
    /// URI of the parsed file.
    pub uri: Uri,
}

impl deps_core::ParseResult for GitlabCiParseResult {
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

    fn dep(host: HostRef, source: DependencySource) -> GitlabCiDependency {
        GitlabCiDependency {
            name: "gitlab.com/org/proj".into(),
            name_range: range(),
            version_req: Some("v1.0.0".into()),
            version_range: Some(range()),
            version_literal: None,
            source,
            is_plain_scalar: true,
            kind: IncludeKind::Project,
            host,
            pin: Some(PinStyle::Tag),
            project_path: "org/proj".to_string(),
        }
    }

    #[test]
    fn test_gitlab_ci_dependency_trait_impl() {
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let host = GitlabHost::parse("gitlab.com", &policy).unwrap();
        let d = dep(
            HostRef::Literal(host),
            DependencySource::AlternateRegistry {
                index: "gitlab:deadbeef".into(),
                mirrors_crates_io: false,
            },
        );
        assert_eq!(d.name(), "gitlab.com/org/proj");
        assert_eq!(
            d.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
        assert!(matches!(
            d.source(),
            DependencySource::AlternateRegistry { .. }
        ));
    }

    #[test]
    fn test_gitlab_ci_version_prerelease() {
        let stable = GitlabCiVersion {
            version: "v1.0.0".into(),
            sha: "a".repeat(40),
            prerelease: false,
            published_at: None,
        };
        let pre = GitlabCiVersion {
            version: "v1.0.0-beta.1".into(),
            sha: "b".repeat(40),
            prerelease: true,
            published_at: None,
        };
        assert!(!stable.is_prerelease());
        assert!(pre.is_prerelease());
        assert!(!stable.removal_status().blocks_resolution());
    }

    #[test]
    fn test_parse_result_dependencies_and_uri() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let result = GitlabCiParseResult {
            dependencies: vec![dep(
                HostRef::Unresolved("$CI_SERVER_FQDN".to_string()),
                DependencySource::CustomRegistry {
                    url: "$CI_SERVER_FQDN".to_string(),
                },
            )],
            routes: vec![],
            uri,
        };
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.uri().path().as_str().ends_with(".gitlab-ci.yml"));
    }

    #[test]
    fn test_endpoint_kind_as_str() {
        assert_eq!(EndpointKind::Tags.as_str(), "tags");
        assert_eq!(EndpointKind::Releases.as_str(), "releases");
    }

    #[test]
    fn test_include_kind_endpoint() {
        assert_eq!(IncludeKind::Project.endpoint(), EndpointKind::Tags);
        assert_eq!(IncludeKind::Component.endpoint(), EndpointKind::Releases);
    }
}
