//! GitLab CI ecosystem formatter.

use dashmap::DashMap;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementResolution, RequirementStatus, SourcePolicy, match_v_prefix_style,
    warn_rejected_value,
};
use deps_core::parser::DependencySource;
use deps_core::{ConcreteVersion, Dependency, InvalidPackageName, PackageName, VersionReq};
use std::sync::Arc;

use crate::host::is_valid_gitlab_coordinate;
use crate::types::{EndpointKind, GitlabCiDependency, GitlabRoute, PinStyle};

/// Formatter for GitLab CI ecosystem LSP responses.
pub struct GitlabCiFormatter {
    /// Shared handle to [`crate::registry::GitlabCiRegistry`]'s route table, so
    /// [`Self::suppress_package_url`] can distinguish a `project:` (Tags) route from a
    /// `component:` (Releases) route — the one NFR-004 carve-out this ecosystem has (spec
    /// §8.2): a `component:`'s heading link is suppressed, since its name ends in the
    /// component segment rather than the project path.
    pub(crate) routes: Arc<DashMap<String, GitlabRoute>>,
    /// Shared handle to [`crate::registry::GitlabCiRegistry`]'s tag/SHA cross-reference.
    pub(crate) tag_index: Arc<DashMap<PackageName, Arc<crate::registry::TagIndex>>>,
}

impl GitlabCiFormatter {
    /// Creates a new formatter over the given shared registry handles.
    #[must_use]
    pub fn new(
        routes: Arc<DashMap<String, GitlabRoute>>,
        tag_index: Arc<DashMap<PackageName, Arc<crate::registry::TagIndex>>>,
    ) -> Self {
        Self { routes, tag_index }
    }

    /// Looks up `pin`'s commit SHA for `name` in the shared tag index, mirroring
    /// `deps_github_actions::GithubActionsFormatter::sha_pin_replacement_for`'s lookup
    /// shape (used by hover's `**Resolved**` splice, `crate::ecosystem`).
    #[must_use]
    pub(crate) fn resolved_tag_for_sha(&self, name: &PackageName, sha: &str) -> Option<String> {
        self.tag_index
            .get(name)
            .and_then(|index| index.sha_to_tag.get(sha).cloned())
    }
}

impl PackageNaming for GitlabCiFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Accepts both the bare (`org/proj[/comp]`) and host-qualified
    /// (`host/org/proj[/comp]`) coordinate shapes — [`is_valid_gitlab_coordinate`] is a
    /// syntactic gate only, not a semantic classifier (see that function's doc).
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if is_valid_gitlab_coordinate(name) {
            Ok(())
        } else {
            Err(InvalidPackageName::new(
                "name must be a GitLab project/component coordinate",
            ))
        }
    }
}

impl PackageRendering for GitlabCiFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        version.as_str().to_string()
    }

    /// Preserves `current`'s `v`-prefix style for a normal (Sha/Tag/Branch/unpinned)
    /// update; `Partial`/`Latest` pins are returned unchanged — bumping `1.2` to `1.3.0`
    /// changes the pin's *kind*, not just its value, so the shared no-op guard correctly
    /// suppresses the code action instead of writing a value-changing-but-kind-wrong edit.
    fn format_version_replacing_for(
        &self,
        dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        let Some(gl_dep) = dep.as_any().downcast_ref::<GitlabCiDependency>() else {
            return self.format_version_for_text_edit(version);
        };
        match &gl_dep.pin {
            Some(PinStyle::Partial | PinStyle::Latest) => current.to_string(),
            _ => match_v_prefix_style(current, version.as_str()),
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        if is_valid_gitlab_coordinate(name.as_str()) {
            format!("https://{name}")
        } else {
            warn_rejected_value(
                "is_valid_gitlab_coordinate",
                "gitlab-ci package display formatting",
                name.as_str(),
            );
            String::new()
        }
    }

    /// `component:` includes only (spec §8.2/NFR-004 carve-out) — a component's name ends
    /// in the component segment, so `https://{name}` is not the project's URL; the real
    /// project link is spliced into the hover body instead (`crate::ecosystem`'s
    /// `generate_hover` override). A `project:` include's name is exactly
    /// `{host}/{project_path}`, so its standard heading link is correct and unsuppressed.
    fn suppress_package_url(&self, source: &DependencySource) -> bool {
        match source {
            DependencySource::AlternateRegistry { index, .. } => {
                match self.routes.get(index).map(|r| r.endpoint) {
                    Some(EndpointKind::Tags) => false,
                    // `Releases`, or an index absent from the route table (unreachable
                    // after `GitlabCiEcosystem::parse_manifest`'s downgrade pass — fail
                    // closed rather than guess a link).
                    Some(EndpointKind::Releases) | None => true,
                }
            }
            // `CustomRegistry` (unresolved host, FR-012) — the name carries no host at all.
            _ => true,
        }
    }
}

impl RequirementResolution for GitlabCiFormatter {
    /// Whether `requirement`'s pin — classified purely from its own text, mirroring
    /// [`crate::component::classify_component_pin_style`]'s shape-only rule — could not be
    /// resolved to a concrete version constraint: a SHA or branch-shaped ref.
    ///
    /// Text-only, so ambiguous for a shape shared between grammars (#466 review M-c) — a
    /// caller that already has the dependency in hand should call
    /// [`Self::requirement_status_for`] instead, which consults its authoritative
    /// [`crate::types::PinStyle`] rather than re-guessing from text.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        matches!(
            crate::component::classify_component_pin_style(requirement.as_str()),
            PinStyle::Sha | PinStyle::Branch
        )
    }

    /// `~latest` is always up to date (it dynamically tracks the newest release, like an
    /// existence wildcard). A `Partial` pin (`1.2`, `1`) is up to date while `latest` falls
    /// within its GitLab tilde-range semantics. A `Tag` pin is compared by normalized
    /// exact-string equality. A SHA/branch pin returns `true` unconditionally — never a
    /// false "outdated" (the diagnostic itself is separately gated by
    /// [`Self::requirement_is_unresolved`]; this is the boolean fallback for a caller that
    /// does not consult that first, e.g. the "Update N outdated" code lens).
    ///
    /// Text-only, so ambiguous for a shape shared between grammars — see
    /// [`Self::requirement_status_for`]'s doc for the dependency-aware alternative a caller
    /// holding the dependency should prefer.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        let pin = crate::component::classify_component_pin_style(requirement.as_str());
        !matches!(
            status_for_pin(&pin, requirement.as_str(), latest.as_str()),
            RequirementStatus::Outdated
        )
    }

    /// #466 review M-c: consults `dep`'s own parse-time [`PinStyle`] (authoritative — set
    /// once, at parse time, from the correct project-vs-component grammar) instead of
    /// re-classifying `requirement`'s raw text, which is ambiguous between the two:
    /// `"1.2"` is [`PinStyle::Partial`] under the `component:` pin grammar
    /// ([`crate::component::classify_component_pin_style`]) but [`PinStyle::Branch`] under
    /// the simpler `project:` ref grammar (`crate::parser`'s `classify_project_pin`) —
    /// indistinguishable from the text alone. This is the same source of truth
    /// [`PackageRendering::format_version_replacing_for`] already consults, so the two can
    /// no longer disagree about the same dependency (previously: the outdated diagnostic
    /// text-reclassified a `project:` `ref: "1.2"` as `Partial` and silently suppressed
    /// itself, while the code action offered by `format_version_replacing_for`'s correct
    /// `Branch` classification still treated it as a normal, bumpable pin).
    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        let Some(pin) = dep
            .as_any()
            .downcast_ref::<GitlabCiDependency>()
            .and_then(|gl_dep| gl_dep.pin.as_ref())
        else {
            return self.requirement_status(requirement, latest);
        };
        status_for_pin(pin, requirement.as_str(), latest.as_str())
    }
}

/// The shared classification -> status rule every [`RequirementResolution`] method on
/// [`GitlabCiFormatter`] reduces to, whether `pin` came from a fresh text-only guess
/// ([`crate::component::classify_component_pin_style`]) or the dependency's own
/// authoritative parse-time field (`GitlabCiDependency::pin`) — the single place this
/// mapping is defined, so the two call paths cannot drift apart (#466 review M-c).
fn status_for_pin(pin: &PinStyle, requirement: &str, latest: &str) -> RequirementStatus {
    match pin {
        PinStyle::Sha | PinStyle::Branch => RequirementStatus::Unresolved,
        PinStyle::Latest => RequirementStatus::UpToDate,
        PinStyle::Tag => {
            if deps_core::github::normalize_tag(requirement)
                == deps_core::github::normalize_tag(latest)
            {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            }
        }
        PinStyle::Partial => {
            if partial_leading_components_match(requirement, latest) {
                RequirementStatus::UpToDate
            } else {
                RequirementStatus::Outdated
            }
        }
    }
}

/// Whether `latest` falls within `req`'s (already partial-semver-shaped) GitLab tilde-range
/// semantics — the up-to-date rule for a `Partial` component pin. Delegates to
/// [`crate::component::gitlab_version_req`] (#466 review M-b), the same partial-pin parsing
/// `component::resolve_component_pin` and `registry::GitlabCiRegistry::select_latest_matching`
/// use, rather than a third, independently-maintained implementation.
fn partial_leading_components_match(req: &str, latest: &str) -> bool {
    crate::component::gitlab_version_req(req).is_some_and(|range| {
        semver::Version::parse(deps_core::github::normalize_tag(latest))
            .is_ok_and(|version| range.matches(&version))
    })
}

impl DiagnosticMessages for GitlabCiFormatter {}

impl DiagnosticPolicy for GitlabCiFormatter {}

impl SourcePolicy for GitlabCiFormatter {
    /// Only a source this crate's registry actually routes — mirrors every other
    /// per-source-routing ecosystem's override (`deps-npm`, `deps-pypi`, `deps-go`,
    /// `deps-nuget`). Pure function of `source`; must never read live configuration (spec
    /// §4.5 — a live-reading predicate here would replace the correct FR-012 informational
    /// diagnostic with a false "Unknown package" the moment a config change flips it, while
    /// the background fetch it would then imply has not actually run).
    fn can_resolve_source(&self, source: &DependencySource) -> bool {
        matches!(source, DependencySource::AlternateRegistry { .. })
    }
}

impl OsvNaming for GitlabCiFormatter {
    /// Unprefixed — mirrors `deps-github-actions`'s identical rationale, kept for
    /// cross-ecosystem consistency even though it is largely unreachable here (a git-tag
    /// pin has no OSV coordinate by name).
    fn osv_version(&self, version: &str) -> String {
        deps_core::github::normalize_tag(version).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::{Position, Range};

    fn formatter() -> GitlabCiFormatter {
        GitlabCiFormatter::new(Arc::new(DashMap::new()), Arc::new(DashMap::new()))
    }

    fn range() -> Range {
        Range::new(Position::new(0, 0), Position::new(0, 1))
    }

    fn dep(pin: Option<PinStyle>, name: &str, source: DependencySource) -> GitlabCiDependency {
        GitlabCiDependency {
            name: name.into(),
            name_range: range(),
            version_req: Some("1.0.0".into()),
            version_range: Some(range()),
            version_literal: None,
            source,
            is_plain_scalar: true,
            kind: crate::types::IncludeKind::Project,
            host: crate::types::HostRef::Unresolved("$CI_SERVER_FQDN".into()),
            pin,
            project_path: "org/proj".to_string(),
        }
    }

    #[test]
    fn test_validate_package_name_accepts_bare_and_host_qualified() {
        let fmt = formatter();
        assert!(fmt.validate_package_name("org/proj").is_ok());
        assert!(
            fmt.validate_package_name("gitlab.com/org/proj/comp")
                .is_ok()
        );
        assert!(fmt.validate_package_name("no-slash").is_err());
    }

    #[test]
    fn test_package_url() {
        let fmt = formatter();
        assert_eq!(
            fmt.package_url(&PackageName::new("gitlab.com/org/proj")),
            "https://gitlab.com/org/proj"
        );
        assert_eq!(fmt.package_url(&PackageName::new("no-slash")), "");
    }

    #[test]
    fn test_suppress_package_url_custom_registry_always_suppressed() {
        let fmt = formatter();
        assert!(fmt.suppress_package_url(&DependencySource::CustomRegistry {
            url: "$CI_SERVER_FQDN".into()
        }));
    }

    #[test]
    fn test_suppress_package_url_tags_route_not_suppressed() {
        let fmt = formatter();
        fmt.routes.insert(
            "gitlab:abc".to_string(),
            GitlabRoute {
                origin: "https://gitlab.com".into(),
                endpoint: EndpointKind::Tags,
            },
        );
        assert!(
            !fmt.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "gitlab:abc".into(),
                mirrors_crates_io: false,
            })
        );
    }

    #[test]
    fn test_suppress_package_url_releases_route_suppressed() {
        let fmt = formatter();
        fmt.routes.insert(
            "gitlab:abc".to_string(),
            GitlabRoute {
                origin: "https://gitlab.com".into(),
                endpoint: EndpointKind::Releases,
            },
        );
        assert!(
            fmt.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "gitlab:abc".into(),
                mirrors_crates_io: false,
            })
        );
    }

    #[test]
    fn test_suppress_package_url_unregistered_index_fails_closed() {
        let fmt = formatter();
        assert!(
            fmt.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "gitlab:missing".into(),
                mirrors_crates_io: false,
            })
        );
    }

    #[test]
    fn test_can_resolve_source() {
        let fmt = formatter();
        assert!(
            fmt.can_resolve_source(&DependencySource::AlternateRegistry {
                index: "x".into(),
                mirrors_crates_io: false,
            })
        );
        assert!(!fmt.can_resolve_source(&DependencySource::CustomRegistry { url: "x".into() }));
        assert!(!fmt.can_resolve_source(&DependencySource::Registry));
    }

    #[test]
    fn test_requirement_is_unresolved_sha_and_branch() {
        let fmt = formatter();
        assert!(fmt.requirement_is_unresolved(&VersionReq::new("a".repeat(40))));
        assert!(fmt.requirement_is_unresolved(&VersionReq::new("some-branch")));
    }

    #[test]
    fn test_requirement_is_unresolved_tag_latest_partial_are_resolved() {
        let fmt = formatter();
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new("1.0.0")));
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new("~latest")));
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new("1.2")));
    }

    #[test]
    fn test_is_requirement_up_to_date_latest_always_true() {
        let fmt = formatter();
        assert!(fmt.is_requirement_up_to_date(
            &VersionReq::new("~latest"),
            &ConcreteVersion::new("9.9.9")
        ));
    }

    #[test]
    fn test_is_requirement_up_to_date_partial_leading_components() {
        let fmt = formatter();
        assert!(
            fmt.is_requirement_up_to_date(&VersionReq::new("1.2"), &ConcreteVersion::new("1.2.5"))
        );
        assert!(
            !fmt.is_requirement_up_to_date(&VersionReq::new("1.2"), &ConcreteVersion::new("1.3.0"))
        );
        assert!(
            fmt.is_requirement_up_to_date(&VersionReq::new("1"), &ConcreteVersion::new("1.9.0"))
        );
    }

    #[test]
    fn test_is_requirement_up_to_date_tag_exact_match() {
        let fmt = formatter();
        assert!(
            fmt.is_requirement_up_to_date(
                &VersionReq::new("v1.0.0"),
                &ConcreteVersion::new("1.0.0")
            )
        );
        assert!(
            !fmt.is_requirement_up_to_date(
                &VersionReq::new("1.0.0"),
                &ConcreteVersion::new("1.1.0")
            )
        );
    }

    #[test]
    fn test_is_requirement_up_to_date_sha_never_false_positive() {
        let fmt = formatter();
        assert!(fmt.is_requirement_up_to_date(
            &VersionReq::new("a".repeat(40)),
            &ConcreteVersion::new("1.0.0")
        ));
    }

    /// M-c (#466 review) regression: `requirement_status_for` must side with the
    /// dependency's own `dep.pin` (here `Branch`, as a `project:` ref's simpler grammar
    /// would classify it — see `crate::parser::classify_project_pin`), not the blanket
    /// component-grammar text reclassification `is_requirement_up_to_date`/
    /// `requirement_is_unresolved` fall back to, which would misjudge `"1.2"` as `Partial`.
    #[test]
    fn test_requirement_status_for_consults_dep_pin_not_text_reclassification() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Branch),
            "org/proj",
            DependencySource::Registry,
        );
        let requirement = VersionReq::new("1.2");
        // Text-only reclassification (what the two boolean methods still fall back to
        // without a dependency) disagrees — it would call this `Partial`, not `Branch`,
        // and (falling within `~1.2`'s range) report it up to date.
        assert_eq!(
            fmt.requirement_status(&requirement, &ConcreteVersion::new("1.2.9")),
            RequirementStatus::UpToDate,
            "sanity: bare text reclassification treats this as an up-to-date Partial pin"
        );
        // The dep-aware path must instead honor the authoritative `Branch` classification:
        // honest-unknown, never a false "up to date" nor a false "outdated".
        assert_eq!(
            fmt.requirement_status_for(&d, &requirement, &ConcreteVersion::new("1.2.9")),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_for_partial_pin_matches_boolean_method() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Partial),
            "org/proj",
            DependencySource::Registry,
        );
        let requirement = VersionReq::new("1.2");
        assert_eq!(
            fmt.requirement_status_for(&d, &requirement, &ConcreteVersion::new("1.2.9")),
            RequirementStatus::UpToDate
        );
        assert_eq!(
            fmt.requirement_status_for(&d, &requirement, &ConcreteVersion::new("1.3.0")),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_requirement_status_for_non_gitlab_dependency_falls_back_to_text() {
        // A `dep` this formatter can't downcast (or whose `pin` is `None`) must fall back
        // to the ordinary text-based `requirement_status`, not panic or misbehave.
        struct OtherDep;
        impl Dependency for OtherDep {
            fn name(&self) -> &PackageName {
                unimplemented!()
            }
            fn name_range(&self) -> tower_lsp_server::ls_types::Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                None
            }
            fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
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
        let requirement = VersionReq::new("^1.0");
        assert_eq!(
            fmt.requirement_status_for(&OtherDep, &requirement, &ConcreteVersion::new("1.5.0")),
            fmt.requirement_status(&requirement, &ConcreteVersion::new("1.5.0"))
        );
    }

    #[test]
    fn test_format_version_replacing_for_partial_returns_current_unchanged() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Partial),
            "org/proj",
            DependencySource::Registry,
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("1.3.0"), "1.2"),
            "1.2"
        );
    }

    #[test]
    fn test_format_version_replacing_for_latest_returns_current_unchanged() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Latest),
            "org/proj",
            DependencySource::Registry,
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("2.0.0"), "~latest"),
            "~latest"
        );
    }

    #[test]
    fn test_format_version_replacing_for_tag_preserves_v_style() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Tag), "org/proj", DependencySource::Registry);
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("2.0.0"), "v1.0.0"),
            "v2.0.0"
        );
    }

    #[test]
    fn test_osv_version_strips_v_prefix() {
        let fmt = formatter();
        assert_eq!(fmt.osv_version("v1.2.3"), "1.2.3");
    }
}
