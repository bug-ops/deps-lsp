//! GitLab CI ecosystem formatter.

use dashmap::DashMap;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementResolution, RequirementStatus, SourcePolicy, match_v_prefix_style,
    requirement_contains_dollar_placeholder, warn_rejected_value,
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
    /// Shared handle to [`crate::registry::GitlabCiRegistry`]'s tag/SHA cross-reference,
    /// keyed by `(EndpointKind, PackageName)` — not `PackageName` alone (validation finding
    /// S2, see [`crate::types::IncludeKind::endpoint`]'s doc) — so an unrelated `project:`
    /// and `component:` include can never share one entry even when their host-qualified
    /// names collide textually.
    pub(crate) tag_index: Arc<DashMap<(EndpointKind, PackageName), Arc<crate::registry::TagIndex>>>,
}

impl GitlabCiFormatter {
    /// Creates a new formatter over the given shared registry handles.
    #[must_use]
    pub fn new(
        routes: Arc<DashMap<String, GitlabRoute>>,
        tag_index: Arc<DashMap<(EndpointKind, PackageName), Arc<crate::registry::TagIndex>>>,
    ) -> Self {
        Self { routes, tag_index }
    }

    /// Looks up `pin`'s commit SHA for `name` under `endpoint` in the shared tag index,
    /// mirroring `deps_github_actions::GithubActionsFormatter::sha_pin_replacement_for`'s
    /// lookup shape (used by hover's `**Resolved**` splice, `crate::ecosystem`).
    #[cfg(feature = "lsp-responses")]
    #[must_use]
    pub(crate) fn resolved_tag_for_sha(
        &self,
        endpoint: EndpointKind,
        name: &PackageName,
        sha: &str,
    ) -> Option<String> {
        self.tag_index
            .get(&(endpoint, name.clone()))
            .and_then(|index| index.sha_to_tag.get(sha).cloned())
    }

    /// Looks up `tag`'s commit SHA for `name` under `endpoint` in the shared tag index —
    /// the reverse direction of `Self::resolved_tag_for_sha`, both read from the very
    /// same [`crate::registry::TagIndex`] entry (issue #634: no second parallel cache).
    /// Backs the "Pin to commit SHA" quickfix (`crate::ecosystem::build_sha_pin_action`).
    ///
    /// `endpoint` disambiguates a `project:` (Tags) include from a `component:` (Releases)
    /// include whose host-qualified names happen to collide textually (validation finding
    /// S2) — always <code>[GitlabCiDependency::kind].endpoint()</code> at call sites, never
    /// guessed.
    ///
    /// Unlike `deps_github_actions`'s counterpart, the replacement is the bare SHA — no
    /// `# {tag}` trailing comment: GitLab CI's `PinStyle::Sha` has no comment-tag
    /// convention for a `ref:`/`component:` pin to preserve (`crate::types::PinStyle`),
    /// so appending one would be new, unparsed-back behavior rather than mirroring an
    /// existing one.
    ///
    /// # Examples
    ///
    /// ```
    /// use dashmap::DashMap;
    /// use deps_gitlab_ci::{EndpointKind, GitlabCiFormatter};
    /// use deps_gitlab_ci::registry::TagIndex;
    /// use deps_core::PackageName;
    /// use std::sync::Arc;
    ///
    /// let tag_index = Arc::new(DashMap::new());
    /// let mut index = TagIndex::default();
    /// index.tag_to_sha.insert("v1.0.0".to_string(), "a".repeat(40));
    /// tag_index.insert(
    ///     (EndpointKind::Tags, PackageName::new("gitlab.com/org/proj")),
    ///     Arc::new(index),
    /// );
    ///
    /// let formatter = GitlabCiFormatter::new(Arc::new(DashMap::new()), tag_index);
    /// // Miss: no entry for this tag.
    /// assert_eq!(
    ///     formatter.sha_pin_replacement_for(
    ///         EndpointKind::Tags,
    ///         &PackageName::new("gitlab.com/org/proj"),
    ///         "v2.0.0",
    ///     ),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub fn sha_pin_replacement_for(
        &self,
        endpoint: EndpointKind,
        name: &PackageName,
        tag: &str,
    ) -> Option<String> {
        self.tag_index
            .get(&(endpoint, name.clone()))
            .and_then(|index| index.tag_to_sha.get(tag).cloned())
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
    ///
    /// #1365 hardening: `current` containing an unresolved `$VAR`/`${VAR}`/`%VAR%` GitLab CI
    /// variable reference (see `contains_unresolved_gitlab_variable`) is also returned
    /// unchanged, checked ahead of the `PinStyle` match — a variable reference can be
    /// embedded inside an otherwise `Tag`-shaped ref (`is_tag_shaped` only inspects the
    /// leading characters, e.g. `v1.2-$BUILD` or `v1-%BUILD%`), not just the `Branch`
    /// catch-all a bare `$VAR` classifies as, so gating on `PinStyle` alone would miss that
    /// case.
    fn format_version_replacing_for(
        &self,
        dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        if contains_unresolved_gitlab_variable(current) {
            return current.to_string();
        }
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
            format!("https://{}", name.as_str())
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

    /// #1370: narrower than [`Self::requirement_is_unresolved`] — a SHA/branch pin is a
    /// concrete but undecidable ref (safe, sometimes intentional, to rewrite forward by a
    /// vulnerability fix), while an unresolved `$VAR`/`${VAR}`/`%VAR%` GitLab CI variable
    /// reference (see `contains_unresolved_gitlab_variable`) has no concrete version text at
    /// all — the same distinction [`PackageRendering::format_version_replacing_for`]'s guard
    /// already draws. Unlike `requirement_is_unresolved` (whose `PinStyle` classification can
    /// only ever be `Sha`/`Branch`), a variable reference can be embedded inside an otherwise
    /// `Tag`- or `Partial`-shaped ref (`v1.2-$BUILD`), so this checks the raw text directly
    /// rather than going through `PinStyle` at all.
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        contains_unresolved_gitlab_variable(requirement.as_str())
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

/// The length of the maximal `[a-zA-Z_][a-zA-Z0-9_]*`-shaped identifier starting at
/// `start` in `bytes` — GitLab's own variable-name grammar (`lib/expand_variables.rb`'s
/// `/\$([a-zA-Z_][a-zA-Z0-9_]*)|\${\g<1>}|%\g<1>%/`) — or `None` if `bytes[start]` does not
/// start one. Only the `%VAR%` scan in [`contains_unresolved_gitlab_variable`] still needs
/// this directly; the `$VAR`/`${VAR}` forms are delegated to
/// [`deps_core::lsp_helpers::requirement_contains_dollar_placeholder`] (#1374), which shares
/// this identifier grammar via its own private copy.
fn identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
    {
        end += 1;
    }
    Some(end)
}

/// Whether `text` contains an unresolved GitLab CI variable reference — `$VARIABLE_NAME`
/// (bare, POSIX-shell style), `${VARIABLE_NAME}` (braced), or `%VARIABLE_NAME%` (percent,
/// GitLab's Windows-`cmd`-style form) — per GitLab's own variable-expansion grammar
/// (`lib/expand_variables.rb`'s `/\$([a-zA-Z_][a-zA-Z0-9_]*)|\${\g<1>}|%\g<1>%/`, which
/// `ExpandVariables.expand` applies to `include:` ref/component values, not just shell
/// scripts — #1365 critic S1: this is not runner-OS-specific in this context), anywhere in
/// `text`, not just as the whole value: `ref: $DEPLOY_VERSION`, `ref: ${DEPLOY_VERSION}`,
/// `ref: %DEPLOY_VERSION%`, and an embedded form like `release-$VERSION` or `v1-%BUILD%` are
/// all detected. The percent form requires a closing `%` immediately after the identifier
/// (matching GitLab's own regex); the bare/braced forms do not require a closing `}` (#1365
/// critic M3: failing safe on an unclosed `${VAR` — still not rewriting it — is acceptable).
///
/// GitLab expands these at pipeline run time; this crate parses `.gitlab-ci.yml` statically
/// and can never resolve one, so a ref/pin containing this shape is not a value this crate
/// should ever treat as bumpable — distinct from `RequirementResolution::requirement_is_unresolved`
/// (issue #1365), which stays a broad "any SHA or branch ref, can't tell if outdated"
/// diagnostic predicate; this is a narrower predicate consulted only by
/// `PackageRendering::format_version_replacing_for`'s guard, to tell a genuinely unresolvable
/// variable reference apart from an ordinary, intentionally-bumpable branch name like `main`
/// (both currently classify as `PinStyle::Branch`). Mirrors `deps_bundler`'s
/// `requirement_contains_unresolved_interpolation` and `deps_swift`'s equivalent guard
/// (#1354/#1367).
///
/// #1374 (cross-ecosystem consistency, `CLAUDE.md`): the `$VAR`/`${VAR}` cases delegate to
/// [`deps_core::lsp_helpers::requirement_contains_dollar_placeholder`], the shared predicate
/// npm/Cargo/Dart/PyPI's equivalent guards also use — only the GitLab-specific `%VAR%` form
/// stays local to this crate.
fn contains_unresolved_gitlab_variable(text: &str) -> bool {
    if requirement_contains_dollar_placeholder(text) {
        return true;
    }
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        b == b'%' && identifier_end(bytes, i + 1).is_some_and(|end| bytes.get(end) == Some(&b'%'))
    })
}

/// The shared classification -> status rule every [`RequirementResolution`] method on
/// [`GitlabCiFormatter`] reduces to, whether `pin` came from a fresh text-only guess
/// ([`crate::component::classify_component_pin_style`]) or the dependency's own
/// authoritative parse-time field (`GitlabCiDependency::pin`) — the single place this
/// mapping is defined, so the two call paths cannot drift apart (#466 review M-c).
///
/// #1370: an unresolved `$VAR`/`${VAR}`/`%VAR%` reference is checked first, ahead of the
/// `pin`-based match — `PinStyle::Sha`/`Branch` already resolve to `Unresolved` below, but a
/// variable reference embedded in an otherwise `Tag`- or `Partial`-shaped ref
/// (`is_tag_shaped`/`gitlab_version_req` only inspect the requirement's own text) previously
/// fell through to the `Tag`/`Partial` arms' literal comparison, which can never match `latest`
/// and so reported a permanent, un-clearable `Outdated` instead of the honest "can't tell"
/// `Unresolved` this same reference already gets
/// [`PackageRendering::format_version_replacing_for`]'s write-path guard for.
fn status_for_pin(pin: &PinStyle, requirement: &str, latest: &str) -> RequirementStatus {
    if contains_unresolved_gitlab_variable(requirement) {
        return RequirementStatus::Unresolved;
    }
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

impl OsvNaming for GitlabCiFormatter {}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::position::{Position, Range};

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
            is_alias_occurrence: false,
            kind: crate::types::IncludeKind::Project,
            host: crate::types::HostRef::Unresolved("$CI_SERVER_FQDN".into()),
            pin,
            project_path: "org/proj".to_string(),
        }
    }

    // #758: replaces test_validate_package_name_accepts_bare_and_host_qualified/
    // test_package_url. No `version_roundtrip` — no `version_satisfies_requirement`
    // override here, only the hand-written methods below.
    deps_core::formatter_conformance! {
        mod gitlab_ci_formatter_conformance;
        build: formatter();
        package_url: {
            "gitlab.com/org/proj" => "https://gitlab.com/org/proj",
            "no-slash" => "",
        };
        accepts: [ "org/proj", "gitlab.com/org/proj/comp" ];
        rejects: [ "no-slash" ];
        format_version: [ "1.0.0" => "1.0.0" ];
        hostile_package_url_expected: "";
    }

    /// #1347 C1 empirical guard: proves the real `GitlabCiFormatter`'s tag-pin
    /// vulnerability-fix remediation is unaffected by NuGet's `$(...)` no-op fix
    /// (`deps_nuget::NuGetFormatter::format_version_replacing`) — a real cross-crate check,
    /// not `deps-core`'s `ShaPinFormatter` mock. `plan_vulnerability_fix` no longer gates on
    /// `requirement_is_unresolved` at all (reverted after the critic's C1 finding), so this
    /// also serves as a live regression test for that revert holding.
    #[test]
    fn test_plan_vulnerability_fix_still_offered_for_real_tag_pin() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let gl_dep = dep(
            Some(PinStyle::Tag),
            "gitlab.com/org/proj",
            DependencySource::AlternateRegistry {
                index: "gitlab:abc".into(),
                mirrors_crates_io: false,
            },
        );
        let version_range = gl_dep.version_range.expect("tag pin has a version range");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0004".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["2.0.0".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "2.0.0".to_string(),
            });

        let planned = plan_vulnerability_fix(&gl_dep, version_range, "1.0.0", &dv, &formatter());

        assert_eq!(
            planned
                .expect("tag-pin fix must still be planned")
                .edit
                .new_text,
            "2.0.0",
            "the real GitlabCiFormatter's tag-pin remediation must be unaffected by \
             NuGet's format_version_replacing no-op fix"
        );
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

    /// #1370: `requirement_is_placeholder` is narrower than `requirement_is_unresolved` — a
    /// SHA/branch pin is not a placeholder (it's safe to rewrite forward), while a variable
    /// reference embedded in an otherwise Tag-shaped ref, which `requirement_is_unresolved`
    /// never sees (its `PinStyle` classification can only be `Sha`/`Branch`), is.
    #[test]
    fn test_requirement_is_placeholder_variable_reference() {
        let fmt = formatter();
        assert!(fmt.requirement_is_placeholder(&VersionReq::new("$DEPLOY_VERSION")));
        assert!(fmt.requirement_is_placeholder(&VersionReq::new("${DEPLOY_VERSION}")));
        assert!(fmt.requirement_is_placeholder(&VersionReq::new("%DEPLOY_VERSION%")));
        assert!(fmt.requirement_is_placeholder(&VersionReq::new("v1.2-$BUILD")));
        assert!(!fmt.requirement_is_placeholder(&VersionReq::new("a".repeat(40))));
        assert!(!fmt.requirement_is_placeholder(&VersionReq::new("some-branch")));
        assert!(!fmt.requirement_is_placeholder(&VersionReq::new("1.2")));
    }

    /// #1370 regression: a variable embedded in an otherwise `Partial`-shaped ref must also
    /// classify `Unresolved`, not just the `Tag` case the live gap was reported for —
    /// `status_for_pin`'s variable check runs ahead of the whole `pin` match, not just the
    /// `Tag` arm.
    #[test]
    fn test_requirement_status_for_partial_pin_with_embedded_variable_is_unresolved() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Partial),
            "org/proj",
            DependencySource::Registry,
        );
        assert_eq!(
            fmt.requirement_status_for(
                &d,
                &VersionReq::new("1.$MINOR"),
                &ConcreteVersion::new("1.2.9")
            ),
            RequirementStatus::Unresolved
        );
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

    // --- #1365: unresolved GitLab CI $VAR/${VAR} ref placeholders must never be rewritten ---

    #[test]
    fn test_contains_unresolved_gitlab_variable_bare_and_braced() {
        assert!(contains_unresolved_gitlab_variable("$DEPLOY_VERSION"));
        assert!(contains_unresolved_gitlab_variable("${DEPLOY_VERSION}"));
        assert!(contains_unresolved_gitlab_variable("release-$VERSION"));
        assert!(contains_unresolved_gitlab_variable("v$MAJOR.$MINOR"));
    }

    /// #1365 critic S1 (live-reproduced against gitlab.com): GitLab's own
    /// `lib/expand_variables.rb` regex (`/\$([a-zA-Z_][a-zA-Z0-9_]*)|\${\g<1>}|%\g<1>%/`)
    /// expands the `%VAR%` form for `include:` ref/component values too, not only in shell
    /// scripts run on a Windows runner — a `ref: "v1-%BUILD%"` was rewritten to a literal
    /// version by `deps-cli update --dry-run` before this predicate covered it.
    #[test]
    fn test_contains_unresolved_gitlab_variable_percent_form() {
        assert!(contains_unresolved_gitlab_variable("%DEPLOY_VERSION%"));
        assert!(contains_unresolved_gitlab_variable("v1-%BUILD%"));
        assert!(contains_unresolved_gitlab_variable("v16.0-%BUILD%"));
        // No closing '%' — GitLab's own regex requires one, so this is not variable syntax.
        assert!(!contains_unresolved_gitlab_variable("50% done"));
        assert!(!contains_unresolved_gitlab_variable("trailing-%NOCLOSE"));
    }

    /// #1365 tester suggestion: variable names are case-sensitive in GitLab's grammar but
    /// the detector itself must not be case-sensitive about which letters count as an
    /// identifier — lowercase and mixed-case names must be detected in all three forms.
    #[test]
    fn test_contains_unresolved_gitlab_variable_lowercase_and_mixed_case_names() {
        assert!(contains_unresolved_gitlab_variable("$deploy_version"));
        assert!(contains_unresolved_gitlab_variable("${Deploy_Version}"));
        assert!(contains_unresolved_gitlab_variable("%buildNumber%"));
    }

    #[test]
    fn test_contains_unresolved_gitlab_variable_ordinary_refs_are_not_flagged() {
        assert!(!contains_unresolved_gitlab_variable("main"));
        assert!(!contains_unresolved_gitlab_variable("v1.0.0"));
        assert!(!contains_unresolved_gitlab_variable(&"a".repeat(40)));
        // A bare '$' not followed by an identifier-starting character is not variable syntax.
        assert!(!contains_unresolved_gitlab_variable("price-is-$5"));
        assert!(!contains_unresolved_gitlab_variable("trailing-$"));
        assert!(!contains_unresolved_gitlab_variable("empty-${}"));
        // #1365 tester suggestion: a leading digit never starts a GitLab variable name.
        assert!(!contains_unresolved_gitlab_variable("${123}"));
        assert!(!contains_unresolved_gitlab_variable("%123%"));
    }

    #[test]
    fn test_format_version_replacing_for_guards_bare_variable_reference() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Branch),
            "org/proj",
            DependencySource::Registry,
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("2.0.0"), "$DEPLOY_VERSION"),
            "$DEPLOY_VERSION"
        );
        assert_eq!(
            fmt.format_version_replacing_for(
                &d,
                &ConcreteVersion::new("2.0.0"),
                "${DEPLOY_VERSION}"
            ),
            "${DEPLOY_VERSION}"
        );
    }

    /// A variable reference can be embedded inside an otherwise `Tag`-shaped ref
    /// (`is_tag_shaped` only inspects the leading characters), so the guard must not rely on
    /// `PinStyle` alone — `v1.2-$BUILD` classifies as `PinStyle::Tag` yet still contains an
    /// unresolvable placeholder.
    #[test]
    fn test_format_version_replacing_for_guards_embedded_variable_in_tag_shaped_ref() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Tag), "org/proj", DependencySource::Registry);
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("2.0.0"), "v1.2-$BUILD"),
            "v1.2-$BUILD"
        );
    }

    /// #1365 critic S1: the `%VAR%` form, live-reproduced as a real destructive rewrite
    /// against gitlab.com before this guard covered it.
    #[test]
    fn test_format_version_replacing_for_guards_percent_variable_reference() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Tag), "org/proj", DependencySource::Registry);
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("19.4.1"), "v1-%BUILD%"),
            "v1-%BUILD%"
        );
    }

    /// Regression: an ordinary branch name with no variable syntax must still be treated as a
    /// normal, bumpable pin — the guard must not over-fire on every `Branch` pin.
    #[test]
    fn test_format_version_replacing_for_ordinary_branch_still_rewritten() {
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::Branch),
            "org/proj",
            DependencySource::Registry,
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("2.0.0"), "main"),
            "2.0.0"
        );
    }

    /// #1365 security audit / #1370: exercises `deps_core::edit::plan_vulnerability_fix` with
    /// the *real* `GitlabCiFormatter` and a `GitlabCiDependency` obtained from the real
    /// `crate::parser::parse_gitlab_ci_yaml` path, on a `ref:` whose declared value is an
    /// unresolved `$VAR` placeholder — mirrors `deps-bundler`'s
    /// `test_plan_vulnerability_fix_unresolved_interpolation_skips_via_no_op_rewrite` (#1367).
    ///
    /// GitLab CI's parser does not degrade `$VAR` to `version_requirement: None` (it is
    /// preserved verbatim, same as Bundler's `#{...}`). Since #1370, `plan_verified_fix`'s
    /// central placeholder gate (via `GitlabCiFormatter::requirement_is_placeholder`) fires
    /// before `format_version_replacing_for` is ever reached — the older
    /// `format_version_replacing_for` no-op guard this test used to key off still holds too, as
    /// defense-in-depth.
    #[test]
    fn test_plan_vulnerability_fix_var_placeholder_skips_via_no_op_rewrite() {
        use deps_core::ParseResult;
        use deps_core::edit::{VulnFixSkip, plan_vulnerability_fix};
        use deps_core::net_policy::RegistryAccessPolicy;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };
        use std::sync::{Arc, RwLock};

        let content = "include:\n  - project: org/proj\n    ref: $DEPLOY_VERSION\n";
        let uri = deps_core::test_util::test_uri("/test/.gitlab-ci.yml");
        let instance_host = crate::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(RegistryAccessPolicy::default()),
        );
        let policy = RegistryAccessPolicy::default();
        let result = crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
            .expect("valid gitlab-ci.yml");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        let current = dep
            .version_requirement()
            .expect("parser preserves the raw $VAR ref text")
            .as_str();
        assert_eq!(current, "$DEPLOY_VERSION");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-1365".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["2.0.0".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "2.0.0".to_string(),
            });

        let planned = plan_vulnerability_fix(
            *dep,
            dep.version_range().expect("ref has a version range"),
            current,
            &dv,
            &formatter(),
        );

        assert!(
            matches!(planned, Err(VulnFixSkip::UnresolvedPlaceholder)),
            "expected UnresolvedPlaceholder (the central #1370 gate firing), got {planned:?}"
        );
    }

    /// #1365 critic S2 / #1370 fix: the vulnerability-fix path above is not the reachable sink
    /// in production — `EcosystemId::GitlabCi::osv_ecosystem()` is `None`, so
    /// `plan_vulnerability_fix` is never called for a real GitLab CI dependency. The sink that
    /// *is* reachable is the bulk-update path (`deps-cli update`, the LSP "update all" code
    /// lens) via `deps_core::edit::collect_update_candidates`, gated on
    /// `requirement_status_for(..) == Outdated`.
    ///
    /// Before #1370, `v16.0-$BUILD` classified as `PinStyle::Tag` and `status_for_pin`'s `Tag`
    /// arm compared the raw (still variable-containing) text against `latest`, which could
    /// never match — reporting a permanent, un-clearable `Outdated` and reaching
    /// `format_version_replacing_for` through this exact path (caught only by that method's
    /// own no-op guard, `Unplannable { reason: NoOpRewrite, .. }`). #1370's `status_for_pin`
    /// fix checks [`contains_unresolved_gitlab_variable`] first, so this now classifies
    /// `Unresolved` instead — `collect_update_candidates` never even builds a candidate for it.
    /// Exercises the real formatter, a real parsed dependency, and the real
    /// `collect_update_candidates` entry point.
    #[test]
    fn test_collect_update_candidates_var_placeholder_in_tag_shaped_ref_produces_no_candidate() {
        use deps_core::edit::collect_update_candidates;
        use deps_core::net_policy::RegistryAccessPolicy;
        use deps_core::{PackageVersions, ParseResult, VersionData};
        use std::collections::HashMap;
        use std::sync::{Arc, RwLock};

        let content = "include:\n  - project: org/proj\n    ref: v16.0-$BUILD\n";
        let uri = deps_core::test_util::test_uri("/test/.gitlab-ci.yml");
        let instance_host = crate::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(RegistryAccessPolicy::default()),
        );
        let policy = RegistryAccessPolicy::default();
        let result = crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
            .expect("valid gitlab-ci.yml");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v16.0-$BUILD"),
            "parser preserves the raw $VAR-embedded tag-shaped ref text"
        );
        assert_eq!(
            formatter().requirement_status_for(
                *dep,
                dep.version_requirement().expect("checked above"),
                &ConcreteVersion::new("16.0.1")
            ),
            RequirementStatus::Unresolved,
            "a variable embedded in an otherwise Tag-shaped ref must classify Unresolved, not \
             a permanent Outdated"
        );

        let fmt = formatter();
        let mut cached = HashMap::new();
        cached.insert(dep.name().clone(), PackageVersions::latest_only("16.0.1"));
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);

        let candidates = collect_update_candidates(&result, content, versions, &fmt);

        assert!(
            candidates.is_empty(),
            "an Unresolved requirement must never reach collect_update_candidates' Outdated \
             gate, got {candidates:?}"
        );
    }
}
