//! GitLab CI dependency and version types.

use deps_core::parser::DependencySource;
use deps_core::position::Range;
use url::Url;

use crate::host::GitlabHost;

/// Which `include:` form a dependency came from.
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
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
    /// `deps_core::registry::MAX_ALTERNATE_REGISTRIES` cap) — carries the host's normalized
    /// origin. Deliberately distinct from [`Self::Unresolved`] (#466 review M-a): the host
    /// genuinely *is* determinable, so the diagnostic this produces must never suggest
    /// `registries.gitlab_instance_host` as the fix — a capacity refusal needs fewer
    /// distinct hosts/includes, not that setting.
    CapacityRefused(String),
    /// A host that would otherwise resolve, but whose class is blocked by the current
    /// `registries.workspace_registries` reachability policy. Deliberately distinct from
    /// [`Self::Unresolved`] (issue #967): the host itself is fully determinable, so telling
    /// the user to set `registries.gitlab_instance_host` would be wrong — the fix is to relax
    /// the policy. Surfaced via [`GitlabCiParseResult::blocked_registries`] instead of the
    /// `crate::ecosystem`'s unresolved-host diagnostic.
    ///
    /// A named struct variant, not a positional tuple (mirrors
    /// [`deps_core::BlockedRegistryOccurrence`]'s own #944 M9 rationale): `raw` and
    /// `declaration_key` are both `String`s, so a positional tuple would let them be silently
    /// swapped at any call site.
    PolicyBlocked {
        /// The blocked value itself: the configured `registries.gitlab_instance_host` string
        /// for the instance-setting-relative path (`project:` includes, and a
        /// `$`-prefixed `component:` host), or the literal `component:` host expression for
        /// the inline-literal path — never a placeholder like `$CI_SERVER_FQDN` (#967 S1: a
        /// placeholder would name a string that appears nowhere in the user's file or
        /// config).
        raw: String,
        /// The blocked host's classification.
        class: deps_core::net_policy::HostClass,
        /// Stable declaration id for [`deps_core::BlockedRegistryOccurrence::declaration_key`]
        /// grouping (#967 S3): `"gitlab_instance_host"` for the instance-setting-relative
        /// path — shared by every dependency resolving through that one setting, so they
        /// collapse into a single diagnostic — or `component-host:{host_expr}` for the
        /// inline-literal path, one per distinct literal host string.
        declaration_key: String,
    },
}

impl std::fmt::Debug for HostRef {
    /// Manual, not derived: `Unresolved`/`CapacityRefused`/`PolicyBlocked` carry raw,
    /// potentially credential-shaped host strings (CWE-532, #1222) — `PolicyBlocked::raw`
    /// mirrors the same `registries.gitlab_instance_host` value `RegistriesConfig`'s own
    /// `#[derive(RedactingDebug)]`-generated `Debug` already redacts (#936).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(host) => f.debug_tuple("Literal").field(host).finish(),
            Self::Unresolved(raw) => f
                .debug_tuple("Unresolved")
                .field(&deps_core::net_policy::redact_declaration_key(raw))
                .finish(),
            Self::CapacityRefused(raw) => f
                .debug_tuple("CapacityRefused")
                .field(&deps_core::net_policy::redact_declaration_key(raw))
                .finish(),
            Self::PolicyBlocked {
                raw,
                class,
                declaration_key,
            } => f
                .debug_struct("PolicyBlocked")
                .field("raw", &deps_core::net_policy::redact_declaration_key(raw))
                .field("class", class)
                .field(
                    "declaration_key",
                    &deps_core::net_policy::redact_declaration_key(declaration_key),
                )
                .finish(),
        }
    }
}

/// The `(host, endpoint)` pair a dependency resolves against, registered at parse time
/// under an opaque routing key carried in `DependencySource::AlternateRegistry.index`.
///
/// Output-only: constructed internally by this crate's own parser, never by external code —
/// no constructor is provided.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitlabRoute {
    /// Normalized, ASCII-serialized origin (`https://{host}`).
    pub origin: String,
    /// Which endpoint this route resolves against.
    pub endpoint: EndpointKind,
}

/// How a pin (a `project:` ref, or a `component:` version) is classified.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, deps_core::redact_debug::RedactingDebug)]
pub struct GitlabCiDependency {
    /// Host-qualified when the host is known: `{host}/{project_path}` for [`IncludeKind::Project`],
    /// `{host}/{project_path}/{component_name}` for [`IncludeKind::Component`]. The bare
    /// path alone (no host prefix) when [`Self::host`] is [`HostRef::Unresolved`] (spec
    /// §3.1 — this also means every name-keyed structure is automatically per-instance).
    #[raw]
    pub name: deps_core::PackageName,
    /// LSP range of the `project:`/`component:` value text.
    #[raw]
    pub name_range: Range,
    /// Normalized version requirement: the ref/pin text, or `None` for a `project:`
    /// include with no `ref:` at all (GitLab defaults that to the project's default
    /// branch, which this crate cannot resolve to a concrete version).
    #[raw]
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the ref/pin text.
    #[raw]
    pub version_range: Option<Range>,
    /// The raw literal text, when it differs from `version_req` (unused today — no
    /// GitLab CI pin form carries a comment-derived requirement the way GitHub Actions'
    /// SHA-with-comment form does; kept for [`deps_core::ecosystem::Dependency`] parity).
    #[raw]
    pub version_literal: Option<String>,
    /// Dependency source: [`DependencySource::AlternateRegistry`] when [`Self::host`] is
    /// known and its route was registered; [`DependencySource::CustomRegistry`] otherwise
    /// (unresolved host, or a route the process-wide cap refused) — see spec §3.2.
    #[raw]
    pub source: DependencySource,
    /// Whether the whole include-entry value was written as a plain (unquoted) YAML
    /// scalar, mirroring `deps-github-actions`'s identical field.
    #[raw]
    pub is_plain_scalar: bool,
    /// Whether the field this dependency's edit/completion write paths actually target —
    /// the `ref:` field when one is present, otherwise the `project:`/`component:` field
    /// itself — was captured from a same-file YAML alias to a scalar anchor recorded
    /// during parsing (spec FR-004/FR-009), rather than written as a literal in the
    /// document. Scoped to that one field, not "any field in this entry was ever an
    /// alias" (#912 critic S1): every SHA-pin/completion write path this flag gates
    /// (spec FR-010/FR-011) only ever rewrites `version_range`, so an unrelated aliased
    /// `project:` next to a literal `ref:` must not withhold that `ref:`'s fully
    /// auto-fixable quickfix or falsely claim "no automated fix available" for it. `true`
    /// withholds every SHA-pin code action, bulk-edit lens, and version-completion write
    /// path for this dependency: an alias token (`*pin`) is not an editable literal, so
    /// no automated fix may ever rewrite it.
    #[raw]
    pub is_alias_occurrence: bool,
    /// Which `include:` form this dependency came from.
    #[raw]
    pub kind: IncludeKind,
    /// This dependency's resolved (or not-yet-resolvable) host.
    #[raw]
    pub host: HostRef,
    /// How the ref/pin is classified; `None` only for a hostless-ref `project:` include
    /// (no `ref:` key at all).
    #[raw]
    pub pin: Option<PinStyle>,
    /// The bare `org/sub/proj[/component]` path, without a host prefix — kept for URL
    /// construction and the registry's own fetch-path use.
    #[redact(key)]
    pub project_path: String,
}

deps_core::impl_dependency!(GitlabCiDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
    source: source,
    version_literal: version_literal,
});

/// Version information for a GitLab CI dependency: a repository tag (`project:`) or a
/// project release (`component:`).
#[non_exhaustive]
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

impl GitlabCiVersion {
    /// Constructs a `GitlabCiVersion` from its required fields, with [`Self::published_at`]
    /// left `None` — chain [`Self::with_published_at`] to attach it.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Arguments
    ///
    /// * `version` - The tag/release name as published, `v` prefix (or lack of one) kept
    ///   as-is
    /// * `sha` - The commit SHA this tag/release points at
    /// * `prerelease` - Whether the semver `pre` component is non-empty
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_gitlab_ci::GitlabCiVersion;
    ///
    /// let version = GitlabCiVersion::new("1.2.0".into(), "a".repeat(40), false);
    /// assert_eq!(version.version.as_str(), "1.2.0");
    /// ```
    #[must_use]
    pub const fn new(version: deps_core::ConcreteVersion, sha: String, prerelease: bool) -> Self {
        Self {
            version,
            sha,
            prerelease,
            published_at: None,
        }
    }

    /// Attaches `Some(released_at)` for the releases endpoint. See [`Self::published_at`].
    #[must_use]
    pub const fn with_published_at(mut self, published_at: deps_core::PublishTime) -> Self {
        self.published_at = Some(published_at);
        self
    }
}

// No yank/deprecation signal from either endpoint — `status` is always `Available`
// (mirrors `deps-github-actions`'s `GithubActionsVersion`).
deps_core::impl_version!(GitlabCiVersion {
    version: version,
    status: |_v: &GitlabCiVersion| deps_core::RemovalStatus::Available,
    published_at: published_at,
    prerelease: |v: &GitlabCiVersion| v.prerelease,
});

/// Result of parsing a `.gitlab-ci.yml`-syntax file.
#[non_exhaustive]
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
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
    /// Dependencies whose host resolved to [`HostRef::PolicyBlocked`] (issue #967), one entry
    /// per affected dependency. Surfaced by
    /// [`deps_core::lsp_helpers::generate_diagnostics_from_cache`] via
    /// [`deps_core::ParseResult::blocked_registries`]'s trait override as an informational
    /// diagnostic, mirroring `deps_cargo`/`deps_npm`/`deps_pypi`/`deps_nuget`'s identical
    /// pattern (#925).
    pub blocked_registries: Vec<deps_core::BlockedRegistryOccurrence>,
}

deps_core::impl_parse_result!(
    GitlabCiParseResult,
    GitlabCiDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
        blocked_registries: blocked_registries,
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::position::Position;
    use deps_core::registry::Version;
    use deps_core::{Dependency, ParseResult};

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
            is_alias_occurrence: false,
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

    deps_core::debug_redaction_conformance!(
        test_gitlab_ci_dependency_debug_redacts_credentials,
        1,
        GitlabCiDependency {
            name: "gitlab.com/org/proj".into(),
            name_range: range(),
            version_req: Some("v1.0.0".into()),
            version_range: Some(range()),
            version_literal: None,
            source: DependencySource::Registry,
            is_plain_scalar: true,
            is_alias_occurrence: false,
            kind: IncludeKind::Project,
            host: HostRef::Unresolved("$CI_SERVER_FQDN".into()),
            pin: Some(PinStyle::Tag),
            project_path: deps_core::conformance::CREDENTIAL_PROBE_KEY.to_string(),
        },
    );

    deps_core::debug_redaction_conformance!(
        test_host_ref_policy_blocked_debug_redacts_credentials,
        2,
        HostRef::PolicyBlocked {
            raw: deps_core::conformance::CREDENTIAL_PROBE_KEY.to_string(),
            class: deps_core::net_policy::HostClass::Loopback,
            declaration_key: deps_core::conformance::CREDENTIAL_PROBE_KEY.to_string(),
        },
    );

    #[test]
    fn test_host_ref_unresolved_and_capacity_refused_redact_credentials() {
        for host in [
            HostRef::Unresolved(deps_core::conformance::CREDENTIAL_PROBE_KEY.into()),
            HostRef::CapacityRefused(deps_core::conformance::CREDENTIAL_PROBE_KEY.into()),
        ] {
            let rendered = format!("{host:?}");
            assert!(!rendered.contains(deps_core::conformance::CREDENTIAL_PROBE_SECRET));
            assert!(rendered.contains("***@git.internal.corp"));
        }
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
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        };
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.uri().path().ends_with(".gitlab-ci.yml"));
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
