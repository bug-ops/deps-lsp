//! GitHub Actions ecosystem formatter.

use dashmap::DashMap;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{
    BoundedVersionReq, CandidateTagSource, CommentCheck, CommitSha, DiagnosticMessages,
    DiagnosticPolicy, OsvNameAvailability, OsvNaming, PackageNaming, PackageRendering,
    PartialTagPolicy, PinResolution, RequirementResolution, RequirementStatus, ResolvedPin,
    ShaPinLookup, SourcePolicy, TagIndex, concrete_pin_version, extends_tag,
    is_partial_semver_shaped, match_v_prefix_style, requirement_contains_template_placeholder,
    sha_pin_rewrite, tag_has_precedence, tag_pin_is_up_to_date,
};
use deps_core::parser::DependencySource;
use deps_core::{
    ConcreteVersion, Dependency, EcosystemId, InvalidPackageName, PackageName,
    lsp_helpers::warn_rejected_value,
};
use std::sync::Arc;

use crate::parser::{is_full_sha, is_tag_shaped};
use crate::types::{GithubActionsDependency, PinStyle, ShaComment};

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
    /// goes through [`deps_core::lsp_helpers::TagIndex`]'s own already-`pub` fields, not
    /// through widening this struct's field visibility.
    ///
    /// # Examples
    ///
    /// ```
    /// use dashmap::DashMap;
    /// use deps_github_actions::GithubActionsFormatter;
    /// use deps_core::lsp_helpers::{CommitSha, TagIndex};
    /// use deps_core::PackageName;
    /// use std::sync::Arc;
    ///
    /// let tag_index = Arc::new(DashMap::new());
    /// let mut index = TagIndex::default();
    /// index.tag_to_sha.insert("v4".to_string(), CommitSha::parse(&"a".repeat(40)).unwrap());
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
    /// use deps_core::lsp_helpers::{CommitSha, TagIndex};
    /// use deps_core::PackageName;
    /// use std::sync::Arc;
    ///
    /// let tag_index = Arc::new(DashMap::new());
    /// let mut index = TagIndex::default();
    /// index.tag_to_sha.insert("v4".to_string(), CommitSha::parse(&"a".repeat(40)).unwrap());
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
        let sha = self.commit_for_tag(name, tag)?;
        Some(format!("{sha} # {tag}"))
    }

    /// The commit `tag` points at per the shared [`TagIndex`], `None` on a cache miss.
    // TODO(#1768): exact-key lookup misses `v4.1.3` for an OSV fix version `4.1.3`;
    // reuse `TagIndex::release_tag`.
    fn commit_for_tag(&self, name: &PackageName, tag: &str) -> Option<CommitSha> {
        self.tag_index
            .get(name)
            .and_then(|index| index.tag_to_sha.get(tag).cloned())
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
    /// new SHA for `version`'s tag in the shared [`TagIndex`] and rewrites the pin through
    /// [`sha_pin_rewrite`]: `{sha}{closers} # {tag}` for a comment-annotated pin (the closing
    /// quote/`}` are re-emitted, #1732) or a plain, last-on-line scalar, the bare SHA for a
    /// quoted/flow-style pin without a comment (`version_range` is then exactly the 40 hex,
    /// so no `#` may be injected, #1724). Otherwise (index miss) returns
    /// `dep.version_literal().unwrap_or(current)`, byte-identical to the raw declared span,
    /// so every shared no-op guard (comparing against exactly that text) suppresses the
    /// action instead of emitting a destructive downgrade-to-tag edit (B1). Branch →
    /// `current` unchanged, for the same reason.
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
            Some(PinStyle::Sha { .. }) => gha_dep
                .sha_pin_tail()
                .zip(self.commit_for_tag(dep.name(), version.as_str()))
                .map_or_else(
                    || dep.version_literal().unwrap_or(current).to_string(),
                    |(tail, sha)| sha_pin_rewrite(&tail, &sha, version),
                ),
            Some(PinStyle::Branch) | None => dep.version_literal().unwrap_or(current).to_string(),
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
    /// A major-only or major.minor requirement (`v4`) is up to date while `latest` extends it;
    /// any other tag is compared by semver precedence (see [`tag_pin_is_up_to_date`]), so a
    /// pre-release of an older line (`v2-beta` against `v7.0.0`) is outdated and a pin ahead of
    /// `latest` is not. `v`/`V` is normalized off both sides first. A requirement that is not
    /// tag-shaped (a bare SHA or branch name), or is tag-shaped but places on no version line
    /// (`v1.x`, a release-line branch), returns `true`, never a false "outdated". A bare SHA or
    /// branch name is additionally reported unresolved by
    /// [`Self::bounded_requirement_is_unresolved`]; a tag-shaped non-version like `v1.x` is not,
    /// so it reaches this method and reads as up to date, as it did before pre-release
    /// ordering existed.
    fn is_bounded_requirement_up_to_date(
        &self,
        requirement: BoundedVersionReq<'_>,
        latest: &ConcreteVersion,
    ) -> bool {
        let requirement = requirement.as_str();
        !is_tag_shaped(requirement)
            || !tag_has_precedence(requirement)
            || tag_pin_is_up_to_date(requirement, latest.as_str(), PartialTagPolicy::MovingLine)
    }

    /// A bare SHA or branch ref is recognizable from the requirement string alone: a
    /// 40-character hex string is a SHA, and anything not shaped like a tag (an optional
    /// `v`/`V` followed by a digit) is treated as a branch — the "honest unknown" side,
    /// since neither can be resolved to a concrete version without a `TagIndex` lookup
    /// this pure predicate has no access to.
    fn bounded_requirement_is_unresolved(&self, requirement: BoundedVersionReq<'_>) -> bool {
        let req = requirement.as_str();
        is_full_sha(req) || !is_tag_shaped(req)
    }

    /// #1370: an unresolved GitHub Actions expression (`${{ ... }}`) embedded in a `uses:`
    /// ref — e.g. `actions/checkout@v4-${{ env.CHECKOUT_REF }}`. Unlike a bare SHA or branch
    /// name, this can sit inside an otherwise [`is_tag_shaped`] ref (`is_tag_shaped` only
    /// inspects the leading characters: an optional `v`/`V` followed by a digit), so it is
    /// not always caught by [`Self::bounded_requirement_is_unresolved`]'s `PinStyle`-free shape check
    /// — the same embedded-placeholder gap `deps-gitlab-ci`'s
    /// `contains_unresolved_gitlab_variable` closes for its own `$VAR`/`${VAR}`/`%VAR%`
    /// syntax. `${{` alone is sufficient: it cannot appear in a SHA (hex-only) or a genuine
    /// branch/tag name (GitHub's own ref-name rules reject `{`/`$`), and GitHub itself never
    /// resolves an unexpanded expression inside a `uses:` value.
    ///
    /// #1391: `shared || native` — the shared [`requirement_contains_template_placeholder`]
    /// detector already matches `${{ env.X }}` via its generic `{{ ... }}` rule, so the native
    /// `${{`-prefix check here is kept only to also catch the empty `${{}}`/`${{ }}` form the
    /// shared detector's non-empty-content requirement misses.
    fn bounded_requirement_is_placeholder(&self, requirement: BoundedVersionReq<'_>) -> bool {
        let requirement = requirement.as_str();
        requirement_contains_template_placeholder(requirement) || requirement.contains("${{")
    }

    /// Prefers a SHA pin's registry-confirmed tag (`TagIndex.sha_to_tag`, ground truth
    /// from the tags API) over trusting the comment text, when both are available (#907
    /// review S2): the trailing `# vX` comment names *a* tag the pin was written against,
    /// but the SHA itself is immutable — a stale comment can silently read as "up to
    /// date" against `latest` even though the pinned commit is actually behind newer
    /// releases still inside the same major/minor line. Falls back to
    /// [`Self::classify_requirement_status`] (trusting the comment) on a cold cache, a
    /// comment-annotated pin absent from the populated index, or a tag/branch pin.
    fn classify_requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: BoundedVersionReq<'_>,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        self.sha_pin_status_from_tag_index(dep, latest)
            .unwrap_or_else(|| self.classify_requirement_status(requirement, latest))
    }

    /// #1556: a SHA pin's registry-confirmed tag (`TagIndex.sha_to_tag`) is a real,
    /// concrete version regardless of whether the pin's trailing `# comment` happens to
    /// have the full `major.minor.patch` shape [`deps_core::lsp_helpers::concrete_pin_version`]
    /// requires — a moving-major comment (`# v1`), a literal tool-name comment
    /// (`# cargo-deny`), or no comment at all all resolve here the same way a full
    /// `# v4.2.0` comment already did before this existed.
    ///
    /// Not gated on the SHA comment the way `Self::sha_pin_status_from_tag_index` is: that
    /// method only needs to *distrust* a human-written comment when one exists, but this
    /// method's job is finding a version at all, so a commentless SHA pin (whose raw SHA is
    /// its own `version_req`) is just as eligible. [`PinResolution::Unresolved`] on a cold cache
    /// or truncated index — the honest "unknown", not a fabricated version — and
    /// [`PinResolution::Untagged`] when a complete index proves no tag names the commit (#1735).
    ///
    /// #1684: a floating tag pin (`@v4`) resolves the same way through the commit its tag
    /// points at, see `Self::pinned_commit`, but only to a release that extends (or equals)
    /// the written tag (candidates are filtered before the most specific is picked): a commit
    /// that also carries an unrelated `v5.0.0` must not be scanned as that version.
    ///
    /// An exact full-semver tag pin (`@v4.8.0`) keeps itself as the primary and gains the other
    /// releases of its major line on the same commit as siblings (#1709).
    fn resolved_pin_version(&self, dep: &dyn Dependency) -> PinResolution {
        let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
            return PinResolution::Unresolved;
        };
        let resolved = |pin: Option<ResolvedPin>| {
            pin.map_or(PinResolution::Unresolved, PinResolution::Resolved)
        };
        if gha_dep.pin == Some(PinStyle::Tag)
            && let Some(written) = gha_dep.version_req.as_ref().map(VersionReq::as_str)
            && concrete_pin_version(written, EcosystemId::GithubActions).is_some()
        {
            return resolved(
                self.tag_index
                    .get(dep.name())
                    .and_then(|index| index.resolved_exact_tag(written)),
            );
        }
        let (Some(commit), Some(index)) =
            (self.pinned_commit(gha_dep), self.tag_index.get(dep.name()))
        else {
            return PinResolution::Unresolved;
        };
        if matches!(gha_dep.pin, Some(PinStyle::Sha { .. })) {
            return index.pin_resolution(&commit);
        }
        let Some(written) = gha_dep.version_req.as_ref().map(VersionReq::as_str) else {
            return PinResolution::Unresolved;
        };
        let candidates: Vec<(&str, &CommitSha)> = index
            .tag_to_sha
            .iter()
            .filter(|(tag, sha)| {
                **sha == commit && (tag.as_str() == written || extends_tag(tag, written))
            })
            .map(|(tag, sha)| (tag.as_str(), sha))
            .collect();
        resolved(TagIndex::from_tags(candidates).resolved_pin(&commit))
    }

    /// `tag_index` is populated as a side effect of [`GithubActionsRegistry`]'s own tags
    /// fetch, not before — see [`RequirementResolution::resolved_pin_version_depends_on_registry_fetch`].
    ///
    /// [`GithubActionsRegistry`]: crate::registry::GithubActionsRegistry
    fn resolved_pin_version_depends_on_registry_fetch(&self) -> bool {
        true
    }

    /// A SHA pin names its whole commit, so a candidate's siblings span every major; any other
    /// pin keeps the exact-tag same-major rule. Absent index entry: not yet fetched.
    fn candidate_tag_source(&self, dep: &dyn Dependency) -> CandidateTagSource {
        let Some(index) = self.tag_index.get(dep.name()) else {
            return CandidateTagSource::NotYetIndexed;
        };
        let is_sha_pin = dep
            .as_any()
            .downcast_ref::<GithubActionsDependency>()
            .is_some_and(|gha_dep| matches!(gha_dep.pin, Some(PinStyle::Sha { .. })));
        if is_sha_pin {
            CandidateTagSource::commit_pin(Arc::clone(&index))
        } else {
            CandidateTagSource::tag_pin(Arc::clone(&index))
        }
    }
}

impl GithubActionsFormatter {
    /// The commit `gha_dep` is pinned to: the raw SHA of a full-SHA pin, or the commit a
    /// *floating* tag pin (`@v4`, `@v4.1` — partial-semver-shaped but not a concrete
    /// version) currently points at per the `TagIndex` (#1684).
    ///
    /// Commit-based rather than "highest semver under `v4`": the commit is the release the
    /// runner actually executes, which differs when a major tag lags behind. Exact tags
    /// (`@v4.1.2`), branches and any `TagIndex` miss (cold cache, exact-text key absent)
    /// yield `None`, keeping exact tags on the text path.
    pub(crate) fn pinned_commit(&self, gha_dep: &GithubActionsDependency) -> Option<CommitSha> {
        match &gha_dep.pin {
            Some(PinStyle::Sha { sha, .. }) => Some(sha.clone()),
            Some(PinStyle::Tag) => {
                let tag = gha_dep.version_req.as_ref()?.as_str();
                let floating = is_partial_semver_shaped(tag)
                    && concrete_pin_version(tag, EcosystemId::GithubActions).is_none();
                if !floating {
                    return None;
                }
                self.commit_for_tag(&gha_dep.name, tag)
            }
            Some(PinStyle::Branch) | None => None,
        }
    }

    /// Ground-truth status for a full-SHA pin against the repository's `TagIndex` — see
    /// [`RequirementResolution::classify_requirement_status_for`]. `None` when `dep` isn't a
    /// full-SHA pin, or the index cannot vouch for the SHA's absence (cold cache, or a
    /// `Truncated` index); the comment, if any, is then trusted.
    ///
    /// #1648: no longer gates on `requirement_is_oversized` itself — this method is only ever
    /// reached through
    /// [`RequirementGate::requirement_status_for`](deps_core::lsp_helpers::RequirementGate::requirement_status_for),
    /// which already constructs a [`BoundedVersionReq`] before calling
    /// [`Self::classify_requirement_status_for`], so an oversized requirement never reaches
    /// here at all.
    ///
    /// #1720/#1722: a SHA absent from a `Complete` index is `Outdated`, comment or not
    /// (`latest` comes from the same tags fetch, so the pin is provably not `latest`'s commit,
    /// and a comment naming a tag must not override that). An indexed
    /// SHA is up to date when it is `latest`'s commit, or its tag is a version tag that is
    /// itself up to date; a non-version tag (`cargo-deny`) never counts as up to date by text.
    fn sha_pin_status_from_tag_index(
        &self,
        dep: &dyn Dependency,
        latest: &ConcreteVersion,
    ) -> Option<RequirementStatus> {
        let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
        let Some(PinStyle::Sha { sha, .. }) = &gha_dep.pin else {
            return None;
        };
        let index = self.tag_index.get(dep.name());
        ShaPinLookup::resolve(index.as_deref().map(AsRef::as_ref), sha, latest).status()
    }

    /// Whether a SHA pin's trailing `# tag` comment agrees with the repository's `TagIndex`
    /// (#1722). `None` when `gha_dep` is not a SHA pin.
    pub(crate) fn sha_comment_check(
        &self,
        gha_dep: &GithubActionsDependency,
    ) -> Option<CommentCheck> {
        let Some(PinStyle::Sha { sha, comment }) = &gha_dep.pin else {
            return None;
        };
        let index = self.tag_index.get(&gha_dep.name);
        Some(CommentCheck::evaluate(
            index.as_deref().map(AsRef::as_ref),
            sha,
            comment.as_ref().map(ShaComment::pin_comment),
        ))
    }
}

impl DiagnosticMessages for GithubActionsFormatter {
    fn sibling_match_label(&self) -> &'static str {
        "matched release tag"
    }
}

impl DiagnosticPolicy for GithubActionsFormatter {}

impl SourcePolicy for GithubActionsFormatter {}

impl OsvNaming for GithubActionsFormatter {
    /// Awaiting until the repository's tags response confirmed its canonical casing; the
    /// written name is offered meanwhile as a provisional query name (#1694).
    fn osv_name_availability(&self, dep: &dyn Dependency) -> OsvNameAvailability {
        if self.osv_package_name(dep).is_some() {
            OsvNameAvailability::Ready
        } else {
            OsvNameAvailability::AwaitingRegistryData {
                written_fallback: deps_core::osv::OsvPackageName::new_or_skip(dep.name().as_str()),
            }
        }
    }

    /// OSV's `GitHub Actions` names are exact-case, so only the canonical casing confirmed by
    /// the repository's tags response is queried; `None` (never a guessed casing, which would
    /// report a false clean) while it is unconfirmed.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<deps_core::osv::OsvPackageName> {
        let index = self.tag_index.get(dep.name())?;
        let canonical = index.canonical_repo_name()?.as_str();
        if !canonical.eq_ignore_ascii_case(dep.name().as_str()) {
            tracing::debug!(
                written = %deps_core::net_policy::redact_declaration_key(dep.name().as_str()),
                "canonical repository name differs from the written one beyond casing (renamed or transferred)"
            );
        }
        deps_core::osv::OsvPackageName::new_or_skip(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::{CommentMismatch, CommitSha, RequirementGate};
    use deps_core::pagination::ListCoverage;
    use deps_core::parser::DependencySource;
    use deps_core::{Position, Range};
    use std::assert_matches;

    fn formatter() -> GithubActionsFormatter {
        GithubActionsFormatter {
            tag_index: Arc::new(DashMap::new()),
        }
    }

    /// #1347 C1 empirical guard: proves the real `GithubActionsFormatter`'s
    /// tag-pin vulnerability-fix remediation is unaffected by NuGet's `$(...)` no-op fix
    /// (`deps_nuget::NuGetFormatter::format_version_replacing`) — a real cross-crate check,
    /// not `deps-core`'s `ShaPinFormatter` mock. `plan_vulnerability_fix` no longer gates on
    /// `requirement_is_unresolved` at all (reverted after the critic's C1 finding), so this
    /// also serves as a live regression test for that revert holding.
    #[test]
    fn test_plan_vulnerability_fix_still_offered_for_real_tag_pin() {
        use deps_core::ParseResult;
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        let yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n";
        let uri = deps_core::test_util::test_uri("/test/.github/workflows/ci.yml");
        let result = crate::parser::parse_workflow_yaml(yaml, &uri).expect("valid yaml");
        let deps = result.dependencies();
        let dep = deps
            .iter()
            .find(|d| d.name().as_str() == "actions/checkout")
            .expect("actions/checkout parsed");
        let version_range = dep.version_range().expect("tag pin has a version range");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0003".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("v4")]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("v4"),
            });

        let planned = plan_vulnerability_fix(*dep, version_range, "v3", &dv, None, &formatter());

        assert_eq!(
            planned
                .expect("tag-pin fix must still be planned")
                .edit
                .new_text,
            "v4",
            "the real GithubActionsFormatter's SHA/tag-pin remediation must be unaffected \
             by NuGet's format_version_replacing no-op fix"
        );
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
            _selection_context: &'a deps_core::SelectionContext,
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
                        sha: deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
                        prerelease: false,
                        published_at: None,
                    }) as Box<dyn deps_core::Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a deps_core::SelectionContext,
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

    fn dep(pin: Option<PinStyle>, name: &str) -> GithubActionsDependency {
        GithubActionsDependency {
            name: name.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some("v4".into()),
            version_range: Some(Range::new(Position::new(0, 0), Position::new(0, 1))),
            pin,
            source: DependencySource::Registry,
            is_plain_scalar: true,
            is_last_on_line: true,
        }
    }

    /// End-to-end regression for issue #907: a SHA-pinned `uses:` ref annotated with the
    /// common `# vX` (major-only) comment convention must produce a real "outdated" inlay
    /// hint, not silently emit nothing. Before the fix, `read_sha_pin_tail` accepted only
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
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "v4.0.0",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v4"))),
            "actions/checkout",
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

    /// #1644: an oversized `requirement` must short-circuit to `Unresolved` before ever
    /// consulting the `TagIndex`, even when the SHA has a real, resolvable ground-truth tag
    /// there — mirrors the divergence test above (same ground-truth tag `v4.0.0`, `latest`
    /// `v4.3.1`) but with a `requirement` past `MAX_REQUIREMENT_LEN`, proving the oversized
    /// gate wins over the ground-truth lookup rather than being silently bypassed by it.
    #[test]
    fn test_requirement_status_for_sha_pin_oversized_requirement_is_unresolved() {
        use deps_core::lsp_helpers::MAX_REQUIREMENT_LEN;

        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "v4.0.0",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v4"))),
            "actions/checkout",
        );

        let oversized = VersionReq::new("1".repeat(MAX_REQUIREMENT_LEN + 1));
        assert_eq!(
            fmt.requirement_status_for(&d, &oversized, &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::Unresolved,
            "oversized requirement must be reported Unresolved, not resolved via the \
             TagIndex ground truth"
        );
    }

    /// #1652: the gated boolean entry point treats an oversized requirement as up to date
    /// (unmodellable, consistent with `Unresolved` from `requirement_status`), not outdated.
    #[test]
    fn test_is_requirement_up_to_date_oversized_requirement_is_up_to_date() {
        use deps_core::lsp_helpers::MAX_REQUIREMENT_LEN;

        let oversized = VersionReq::new("1".repeat(MAX_REQUIREMENT_LEN + 1));

        assert!(formatter().is_requirement_up_to_date(&oversized, &ConcreteVersion::new("2.0.0")));

        // At-cap control: exactly `MAX_REQUIREMENT_LEN` still reaches the hook, which reports
        // an all-digit requirement with extra leading components outdated.
        let at_cap = VersionReq::new("1".repeat(MAX_REQUIREMENT_LEN));
        assert!(!formatter().is_requirement_up_to_date(&at_cap, &ConcreteVersion::new("2.0.0")));
    }

    /// #1652 critic M2: an oversized `TagIndex` ground-truth tag is unmodellable, so the status
    /// is `Unresolved` — it must not fall back to trusting the (possibly stale) comment (#907).
    #[test]
    fn test_requirement_status_for_sha_pin_oversized_ground_truth_tag_is_unresolved() {
        use deps_core::lsp_helpers::MAX_REQUIREMENT_LEN;

        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                format!("v{}", "1".repeat(MAX_REQUIREMENT_LEN)),
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v4"))),
            "actions/checkout",
        );

        assert_eq!(
            fmt.requirement_status_for(&d, &VersionReq::new("v4"), &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::Unresolved
        );
    }

    /// #907 review C1: the parser's comment-tag rule only requires the `#` to be
    /// *preceded* by whitespace, so a two-space or tab gap before the `#` is a valid
    /// comment. The parsed pin must still reach the `TagIndex` ground truth, or it falls
    /// back to trusting the (possibly stale) comment — reopening exactly the false-`UpToDate`
    /// gap S2 fixed.
    #[test]
    fn test_requirement_status_for_sha_pin_ground_truth_survives_non_single_space_gap() {
        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "v4.0.0",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        for gap in ["  ", "\t"] {
            let content = format!("steps:\n  - uses: actions/checkout@{sha}{gap}# v4\n");
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parsed = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
            let d = &parsed.dependencies[0];
            assert_eq!(
                fmt.requirement_status_for(
                    d,
                    &VersionReq::new("v4"),
                    &ConcreteVersion::new("v4.3.1")
                ),
                RequirementStatus::Outdated,
                "must still reach the tag_index ground truth (v4.0.0, outdated) through a \
                 non-single-space gap: {gap:?}"
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
            Some(PinStyle::sha_for_test(&sha, Some("v4"))),
            "actions/checkout",
        );

        assert_eq!(
            fmt.requirement_status_for(&d, &VersionReq::new("v4"), &ConcreteVersion::new("v4.3.1")),
            RequirementStatus::UpToDate,
            "no TagIndex entry: falls back to the comment-trusting path"
        );
    }

    // --- #1720: full-SHA pin absent from the release TagIndex ---

    const LATEST_SHA_1720: &str = "3333333333333333333333333333333333333333";
    const OLD_SHA_1720: &str = "4444444444444444444444444444444444444444";
    const MISSING_SHA_1720: &str = "5555555555555555555555555555555555555555";

    fn fmt_with_release_index_1720(extra: &[(&str, &str)]) -> GithubActionsFormatter {
        let fmt = formatter();
        let mut tags = vec![("v2.87.22", LATEST_SHA_1720), ("v2.87.21", OLD_SHA_1720)];
        tags.extend_from_slice(extra);
        let commits: Vec<(&str, CommitSha)> = tags
            .iter()
            .map(|(tag, sha)| (*tag, CommitSha::parse(sha).unwrap()))
            .collect();
        let index = TagIndex::from_tags(commits.iter().map(|(tag, sha)| (*tag, sha)));
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(index),
        );
        fmt
    }

    fn sha_pin_1720(sha: &str, comment_tag: Option<&str>) -> GithubActionsDependency {
        let mut d = dep(
            Some(PinStyle::sha_for_test(sha, comment_tag)),
            "EmbarkStudios/cargo-deny-action",
        );
        d.version_req = Some(comment_tag.map_or_else(|| sha.into(), Into::into));
        d
    }

    fn status_1720(fmt: &GithubActionsFormatter, d: &GithubActionsDependency) -> RequirementStatus {
        let req = d.version_req.clone().unwrap();
        fmt.requirement_status_for(d, &req, &ConcreteVersion::new("v2.87.22"))
    }

    #[test]
    fn test_sha_pin_missing_from_populated_index_commentless_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Outdated);
    }

    #[test]
    fn test_sha_pin_non_version_comment_missing_from_index_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[]);
        let content = format!(
            "steps:\n  - uses: EmbarkStudios/cargo-deny-action@{MISSING_SHA_1720} # cargo-deny\n"
        );
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let d = parsed.dependencies.first().expect("one dependency");
        let d = d
            .as_any()
            .downcast_ref::<GithubActionsDependency>()
            .unwrap();
        assert_matches!(d.pin, Some(PinStyle::Sha { comment: None, .. }));
        assert_eq!(status_1720(&fmt, d), RequirementStatus::Outdated);
    }

    #[test]
    fn test_sha_pin_version_comment_missing_from_index_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[]);
        assert_eq!(
            status_1720(&fmt, &sha_pin_1720(MISSING_SHA_1720, Some("v2.87.22"))),
            RequirementStatus::Outdated
        );
        assert_eq!(
            status_1720(&fmt, &sha_pin_1720(MISSING_SHA_1720, Some("v2.87.20"))),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_sha_pin_uppercase_hex_matches_lowercase_index() {
        let fmt =
            fmt_with_release_index_1720(&[("v2.87.0", "abcdefabcdefabcdefabcdefabcdefabcdefabcd")]);
        let upper_old = sha_pin_1720("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", None);
        assert_eq!(status_1720(&fmt, &upper_old), RequirementStatus::Outdated);

        let fmt = formatter();
        let latest = CommitSha::parse("abcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v2.87.22", &latest)])),
        );
        let upper_latest = sha_pin_1720("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", None);
        assert_eq!(
            status_1720(&fmt, &upper_latest),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_sha_pin_two_releases_on_latest_commit_is_up_to_date() {
        let fmt = fmt_with_release_index_1720(&[("v2.87.21", LATEST_SHA_1720)]);
        let d = sha_pin_1720(LATEST_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::UpToDate);
    }

    /// #1730: a commit tagged only by a floating alias that no longer tracks latest is outdated,
    /// however the alias text prefix-matches `latest`.
    #[test]
    fn test_sha_pin_tagged_only_by_outdated_floating_tag_is_outdated() {
        for floating in ["v2", "v2.87", "2", "v1"] {
            let fmt = fmt_with_release_index_1720(&[(floating, MISSING_SHA_1720)]);
            for comment in [None, Some("v2"), Some("v2.87.22")] {
                assert_eq!(
                    status_1720(&fmt, &sha_pin_1720(MISSING_SHA_1720, comment)),
                    RequirementStatus::Outdated,
                    "{floating} {comment:?}"
                );
            }
        }
    }

    #[test]
    fn test_sha_pin_floating_alias_beside_exact_old_release_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[("v2", OLD_SHA_1720)]);
        assert_eq!(
            status_1720(&fmt, &sha_pin_1720(OLD_SHA_1720, None)),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_sha_pin_tag_at_or_above_latest_is_up_to_date() {
        for ahead in ["v2.87.23", "v2.88", "v3", "v3.0.0-rc1", "v2.100.0"] {
            let fmt = fmt_with_release_index_1720(&[(ahead, MISSING_SHA_1720)]);
            assert_eq!(
                status_1720(&fmt, &sha_pin_1720(MISSING_SHA_1720, None)),
                RequirementStatus::UpToDate,
                "{ahead}"
            );
        }
    }

    #[test]
    fn test_sha_pin_floating_alias_on_latest_commit_is_up_to_date() {
        let fmt = fmt_with_release_index_1720(&[("v2", LATEST_SHA_1720)]);
        assert_eq!(
            status_1720(&fmt, &sha_pin_1720(LATEST_SHA_1720, Some("v2"))),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_sha_pin_populated_but_empty_index_stays_unresolved() {
        let fmt = formatter();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::default()),
        );
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Unresolved);
    }

    #[test]
    fn test_sha_pin_index_without_latest_tag_is_outdated() {
        let fmt = formatter();
        let old = CommitSha::parse(OLD_SHA_1720).unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v2.87.21", &old)])),
        );
        for sha in [MISSING_SHA_1720, OLD_SHA_1720] {
            assert_eq!(
                status_1720(&fmt, &sha_pin_1720(sha, None)),
                RequirementStatus::Outdated,
                "{sha}"
            );
        }
    }

    #[test]
    fn test_short_sha_pin_is_never_outdated() {
        let fmt = fmt_with_release_index_1720(&[]);
        let content = "steps:\n  - uses: EmbarkStudios/cargo-deny-action@abcdef1\n";
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        let d = parsed.dependencies.first().expect("one dependency");
        let d = d
            .as_any()
            .downcast_ref::<GithubActionsDependency>()
            .unwrap();
        assert_eq!(status_1720(&fmt, d), RequirementStatus::Unresolved);
    }

    #[test]
    fn test_sha_pin_commentless_on_latest_commit_is_up_to_date() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(LATEST_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::UpToDate);
    }

    #[test]
    fn test_sha_pin_commentless_on_older_release_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(OLD_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Outdated);
    }

    #[test]
    fn test_sha_pin_only_non_version_tag_on_old_commit_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[("cargo-deny", MISSING_SHA_1720)]);
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Outdated);
    }

    #[test]
    fn test_sha_pin_non_version_tag_on_latest_commit_is_up_to_date() {
        let fmt = fmt_with_release_index_1720(&[("cargo-deny", LATEST_SHA_1720)]);
        let d = sha_pin_1720(LATEST_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::UpToDate);
    }

    #[test]
    fn test_sha_pin_commentless_cold_cache_stays_unresolved() {
        let fmt = formatter();
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Unresolved);
    }

    // --- #1722: comment-vs-SHA verdict ---

    fn check_1722(fmt: &GithubActionsFormatter, d: &GithubActionsDependency) -> CommentCheck {
        fmt.sha_comment_check(d).expect("full-SHA pin")
    }

    fn mismatch_1722(check: CommentCheck) -> Option<CommentMismatch> {
        match check {
            CommentCheck::Mismatch(kind) => Some(kind),
            CommentCheck::NoComment | CommentCheck::Unverifiable | CommentCheck::Confirmed => None,
        }
    }

    fn fmt_with_coverage_1722(coverage: ListCoverage) -> GithubActionsFormatter {
        let fmt = formatter();
        let latest = CommitSha::parse(LATEST_SHA_1720).unwrap();
        let old = CommitSha::parse(OLD_SHA_1720).unwrap();
        let index = TagIndex::from_tags([("v2.87.22", &latest), ("v2.87.21", &old)])
            .with_coverage(coverage);
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(index),
        );
        fmt
    }

    #[test]
    fn test_comment_check_no_comment() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(check_1722(&fmt, &d), CommentCheck::NoComment);
    }

    #[test]
    fn test_comment_check_confirmed_exact_and_uppercase() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(OLD_SHA_1720, Some("v2.87.21"));
        assert_eq!(check_1722(&fmt, &d), CommentCheck::Confirmed);

        let fmt = formatter();
        let sha = CommitSha::parse("abcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v2.87.22", &sha)])),
        );
        let d = sha_pin_1720("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", Some("v2.87.22"));
        assert_eq!(check_1722(&fmt, &d), CommentCheck::Confirmed);
    }

    #[test]
    fn test_comment_check_partial_precision_comment_is_confirmed() {
        let fmt = fmt_with_release_index_1720(&[]);
        for comment in ["v2", "v2.87"] {
            let d = sha_pin_1720(LATEST_SHA_1720, Some(comment));
            assert_eq!(check_1722(&fmt, &d), CommentCheck::Confirmed, "{comment}");
        }
    }

    #[test]
    fn test_comment_check_other_tag_is_mismatch() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(LATEST_SHA_1720, Some("v2.87.20"));
        assert_eq!(
            mismatch_1722(check_1722(&fmt, &d)),
            Some(CommentMismatch::ShaIsOtherTag {
                actual: ConcreteVersion::new("v2.87.22")
            })
        );
    }

    #[test]
    fn test_comment_check_v_prefix_and_case_do_not_cause_mismatch() {
        let fmt = fmt_with_release_index_1720(&[]);
        for comment in ["2.87.22", "V2.87.22", "v2.87.22"] {
            let d = sha_pin_1720(LATEST_SHA_1720, Some(comment));
            assert_eq!(check_1722(&fmt, &d), CommentCheck::Confirmed, "{comment}");
        }

        let unprefixed = formatter();
        let sha = CommitSha::parse(OLD_SHA_1720).unwrap();
        unprefixed.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("4.1.0", &sha)])),
        );
        for comment in ["v4.1.0", "V4.1.0", "4.1.0"] {
            let d = sha_pin_1720(OLD_SHA_1720, Some(comment));
            assert_eq!(
                check_1722(&unprefixed, &d),
                CommentCheck::Confirmed,
                "{comment}"
            );
        }
    }

    #[test]
    fn test_comment_check_prerelease_tag_is_not_named_by_a_prefix_comment() {
        let fmt = formatter();
        let sha = CommitSha::parse(OLD_SHA_1720).unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v4.3.1-rc.1", &sha)])),
        );
        let prefix = sha_pin_1720(OLD_SHA_1720, Some("v4.3"));
        assert_eq!(
            mismatch_1722(check_1722(&fmt, &prefix)),
            Some(CommentMismatch::ShaIsOtherTag {
                actual: ConcreteVersion::new("v4.3.1-rc.1")
            })
        );
        let exact = sha_pin_1720(OLD_SHA_1720, Some("v4.3.1-rc.1"));
        assert_eq!(check_1722(&fmt, &exact), CommentCheck::Confirmed);
    }

    #[test]
    fn test_comment_check_moving_major_drift_is_confirmed() {
        let fmt = formatter();
        let latest = CommitSha::parse(LATEST_SHA_1720).unwrap();
        let other = CommitSha::parse(OLD_SHA_1720).unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v2", &other), ("v2.87.22", &latest)])),
        );
        let d = sha_pin_1720(LATEST_SHA_1720, Some("v2"));
        assert_eq!(check_1722(&fmt, &d), CommentCheck::Confirmed);
    }

    #[test]
    fn test_comment_check_partial_comment_of_other_line_is_mismatch() {
        let fmt = fmt_with_release_index_1720(&[]);
        for comment in ["v3", "v2.86"] {
            let d = sha_pin_1720(LATEST_SHA_1720, Some(comment));
            assert_eq!(
                mismatch_1722(check_1722(&fmt, &d)),
                Some(CommentMismatch::ShaIsOtherTag {
                    actual: ConcreteVersion::new("v2.87.22")
                }),
                "{comment}"
            );
        }
    }

    #[test]
    fn test_comment_check_sha_absent_from_complete_index_is_mismatch() {
        let fmt = fmt_with_release_index_1720(&[]);
        for comment in ["v2.87.22", "v2.87.20"] {
            let d = sha_pin_1720(MISSING_SHA_1720, Some(comment));
            assert_eq!(
                mismatch_1722(check_1722(&fmt, &d)),
                Some(CommentMismatch::ShaNotInIndex),
                "{comment}"
            );
        }
    }

    #[test]
    fn test_comment_check_cold_and_empty_index_are_unverifiable() {
        let fmt = formatter();
        let d = sha_pin_1720(MISSING_SHA_1720, Some("v2.87.22"));
        assert_eq!(check_1722(&fmt, &d), CommentCheck::Unverifiable);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::UpToDate);

        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::default()),
        );
        assert_eq!(check_1722(&fmt, &d), CommentCheck::Unverifiable);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::UpToDate);
    }

    #[test]
    fn test_truncated_index_absent_sha_is_unverifiable_not_outdated() {
        let fmt = fmt_with_coverage_1722(ListCoverage::Truncated);

        let commentless = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(
            status_1720(&fmt, &commentless),
            RequirementStatus::Unresolved
        );
        assert_eq!(check_1722(&fmt, &commentless), CommentCheck::NoComment);

        let commented = sha_pin_1720(MISSING_SHA_1720, Some("v2.87.22"));
        assert_eq!(status_1720(&fmt, &commented), RequirementStatus::UpToDate);
        assert_eq!(check_1722(&fmt, &commented), CommentCheck::Unverifiable);
    }

    #[test]
    fn test_truncated_index_present_sha_is_still_verified() {
        let fmt = fmt_with_coverage_1722(ListCoverage::Truncated);

        let ok = sha_pin_1720(OLD_SHA_1720, Some("v2.87.21"));
        assert_eq!(check_1722(&fmt, &ok), CommentCheck::Confirmed);
        assert_eq!(status_1720(&fmt, &ok), RequirementStatus::Outdated);

        let wrong = sha_pin_1720(OLD_SHA_1720, Some("v2.87.22"));
        assert_eq!(
            mismatch_1722(check_1722(&fmt, &wrong)),
            Some(CommentMismatch::ShaIsOtherTag {
                actual: ConcreteVersion::new("v2.87.21")
            })
        );
    }

    // --- #1740: pre-release pins against the newest release ---

    #[test]
    fn test_prerelease_tag_pin_is_outdated_against_newest_release() {
        let fmt = formatter();
        let latest = ConcreteVersion::new("v7.0.0");
        for pinned in ["v2-beta", "v3.0.0-rc.1", "v2.1-rc", "v6.9.9"] {
            assert_eq!(
                fmt.requirement_status(&VersionReq::new(pinned), &latest),
                RequirementStatus::Outdated,
                "{pinned}"
            );
        }
        for pinned in ["v7", "v7.0", "v7.0.0", "7.0.0", "v8-beta"] {
            assert_eq!(
                fmt.requirement_status(&VersionReq::new(pinned), &latest),
                RequirementStatus::UpToDate,
                "{pinned}"
            );
        }
    }

    /// impl-critic S1: a tag-shaped ref that is no version (a release-line branch like `v1.x`)
    /// or a variant tag (`v3-node20`) stays "not outdated", so no update is planned for it.
    #[test]
    fn test_non_version_tag_shaped_refs_are_not_outdated() {
        let fmt = formatter();
        let latest = ConcreteVersion::new("v1.10.1");
        for pinned in ["v1.x", "v1.*", "v1.2.x", "v1_2", "v3-node20", "v1.2-stable"] {
            assert_eq!(
                fmt.requirement_status(&VersionReq::new(pinned), &latest),
                RequirementStatus::UpToDate,
                "{pinned}"
            );
        }
        assert_eq!(
            fmt.requirement_status(&VersionReq::new("v2-beta"), &ConcreteVersion::new("v7.0.0")),
            RequirementStatus::Outdated
        );
    }

    /// A SHA whose indexed tag is an older pre-release of the latest line is outdated too.
    #[test]
    fn test_sha_pin_on_older_prerelease_tag_is_outdated() {
        let fmt = fmt_with_release_index_1720(&[("v2.87.21-rc.1", MISSING_SHA_1720)]);
        let d = sha_pin_1720(MISSING_SHA_1720, None);
        assert_eq!(status_1720(&fmt, &d), RequirementStatus::Outdated);
    }

    // --- #1735: a trailing comment must not stand in for an untagged commit ---

    fn in_use_version_1735(
        fmt: &GithubActionsFormatter,
        d: &GithubActionsDependency,
    ) -> Option<ConcreteVersion> {
        deps_core::lsp_helpers::resolve_in_use_version(
            d,
            "embarkstudios/cargo-deny-action",
            &std::collections::HashMap::new(),
            None,
            fmt,
            EcosystemId::GithubActions,
        )
    }

    #[test]
    fn test_in_use_version_commit_absent_from_complete_index_ignores_comment() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(MISSING_SHA_1720, Some("v2.87.22"));
        assert_eq!(in_use_version_1735(&fmt, &d), None);
    }

    #[test]
    fn test_in_use_version_commit_absent_from_truncated_index_keeps_comment() {
        let fmt = fmt_with_coverage_1722(ListCoverage::Truncated);
        let d = sha_pin_1720(MISSING_SHA_1720, Some("v2.87.22"));
        assert_eq!(
            in_use_version_1735(&fmt, &d),
            Some(ConcreteVersion::new("v2.87.22"))
        );
        assert_eq!(
            in_use_version_1735(&formatter(), &d),
            Some(ConcreteVersion::new("v2.87.22")),
            "a cold cache still lets the comment stand in provisionally"
        );
    }

    #[test]
    fn test_in_use_version_commit_resolving_to_alias_ignores_comment() {
        let fmt = formatter();
        let sha = CommitSha::parse(OLD_SHA_1720).unwrap();
        fmt.tag_index.insert(
            PackageName::new("EmbarkStudios/cargo-deny-action"),
            Arc::new(TagIndex::from_tags([("v1", &sha), ("v1.0.0.1", &sha)])),
        );
        let d = sha_pin_1720(OLD_SHA_1720, Some("v4.2.0"));
        assert_eq!(in_use_version_1735(&fmt, &d), None);
    }

    #[test]
    fn test_in_use_version_indexed_commit_uses_registry_tag_not_comment() {
        let fmt = fmt_with_release_index_1720(&[]);
        let d = sha_pin_1720(OLD_SHA_1720, Some("v2.87.22"));
        assert_eq!(
            in_use_version_1735(&fmt, &d),
            Some(ConcreteVersion::new("v2.87.21"))
        );
    }

    /// #1727: a SHA pin gets whole-commit candidate siblings, any other pin same-major, and a
    /// repository without an index entry is not yet indexed.
    #[test]
    fn test_candidate_tag_source_scope_follows_pin_style() {
        use deps_core::lsp_helpers::{CandidateTagSource, SiblingScope};

        let sha = "a".repeat(40);
        let fmt = formatter();
        let commit = CommitSha::parse(&sha).unwrap();
        let tag_dep = dep(Some(PinStyle::Tag), "actions/checkout");
        let sha_dep = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v4.8.0"))),
            "actions/checkout",
        );
        assert!(matches!(
            fmt.candidate_tag_source(&tag_dep),
            CandidateTagSource::NotYetIndexed
        ));

        fmt.tag_index.insert(
            PackageName::new("actions/checkout"),
            Arc::new(TagIndex::from_tags([("v4.8.0", &commit)])),
        );
        assert!(matches!(
            fmt.candidate_tag_source(&tag_dep),
            CandidateTagSource::Indexed {
                scope: SiblingScope::SameMajor,
                ..
            }
        ));
        assert!(matches!(
            fmt.candidate_tag_source(&sha_dep),
            CandidateTagSource::Indexed {
                scope: SiblingScope::WholeCommit,
                ..
            }
        ));
    }

    // --- #1556: resolved_pin_version ---

    /// A moving-major comment (`# v1`) fails `concrete_pin_version`'s full-semver shape
    /// check on its own, but a `TagIndex`-confirmed SHA must still resolve to the real tag.
    #[test]
    fn test_resolved_pin_version_sha_pin_moving_major_comment_resolves_via_tag_index() {
        let sha = "a".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "v1",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v1"))),
            "actions/checkout",
        );

        assert_eq!(
            fmt.resolved_pin_version(&d),
            PinResolution::Resolved(ResolvedPin::most_specific(ConcreteVersion::new("v1")))
        );
    }

    /// A literal tool-name comment (`# cargo-deny`) isn't tag-shaped at all, so it never
    /// even becomes a `comment` — must still resolve via the `TagIndex`, matching #551's identical literal-tag
    /// convention.
    #[test]
    fn test_resolved_pin_version_sha_pin_literal_comment_resolves_via_tag_index() {
        let sha = "b".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "cargo-deny",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("taiki-e/install-action"), Arc::new(index));

        let mut d = dep(
            Some(PinStyle::sha_for_test(&sha, None)),
            "taiki-e/install-action",
        );
        d.version_req = Some(sha.into());

        assert_eq!(
            fmt.resolved_pin_version(&d),
            PinResolution::Resolved(ResolvedPin::most_specific(ConcreteVersion::new(
                "cargo-deny"
            )))
        );
    }

    /// A commentless SHA pin (`version_req` is the bare SHA itself) must resolve exactly
    /// the same way — `resolved_pin_version` isn't gated on a comment existing at all.
    #[test]
    fn test_resolved_pin_version_commentless_sha_pin_resolves_via_tag_index() {
        let sha = "c".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            deps_core::lsp_helpers::ResolvedPin::most_specific(deps_core::ConcreteVersion::new(
                "v4.2.0",
            )),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let mut d = dep(Some(PinStyle::sha_for_test(&sha, None)), "actions/checkout");
        d.version_req = Some(sha.into());

        assert_eq!(
            fmt.resolved_pin_version(&d),
            PinResolution::Resolved(ResolvedPin::most_specific(ConcreteVersion::new("v4.2.0")))
        );
    }

    fn floating_tag_pin_for(tag: &str, indexed: &[(&str, &str)]) -> Option<ResolvedPin> {
        let fmt = formatter();
        let commits: Vec<(&str, CommitSha)> = indexed
            .iter()
            .map(|(name, sha)| (*name, CommitSha::parse(sha).unwrap()))
            .collect();
        let index = TagIndex::from_tags(commits.iter().map(|(name, sha)| (*name, sha)));
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));
        let mut d = dep(Some(PinStyle::Tag), "actions/checkout");
        d.version_req = Some(tag.into());
        resolved_pin_of(&fmt, &d)
    }

    fn resolved_pin_of(
        fmt: &GithubActionsFormatter,
        d: &GithubActionsDependency,
    ) -> Option<ResolvedPin> {
        match fmt.resolved_pin_version(d) {
            PinResolution::Resolved(pin) => Some(pin),
            PinResolution::Unresolved | PinResolution::Untagged => None,
        }
    }

    /// #1684: a floating tag pin resolves through the commit its tag points at.
    #[test]
    fn test_resolved_pin_version_floating_tag_resolves_via_commit() {
        let sha = "a".repeat(40);
        let warm = [("v4", sha.as_str()), ("v4.2.2", sha.as_str())];
        assert_eq!(
            floating_tag_pin_for("v4", &warm),
            Some(ResolvedPin::most_specific(ConcreteVersion::new("v4.2.2")))
        );
        assert_eq!(
            floating_tag_pin_for("v4", &[("v4", sha.as_str())]),
            Some(ResolvedPin::most_specific(ConcreteVersion::new("v4")))
        );
    }

    /// #1684: the commit, not the highest semver under `v4`, decides — a lagging major tag
    /// resolves to the release it really points at.
    #[test]
    fn test_resolved_pin_version_floating_tag_lagging_major_uses_commit() {
        let old = "a".repeat(40);
        let new = "b".repeat(40);
        let tags = [
            ("v4", old.as_str()),
            ("v4.1.0", old.as_str()),
            ("v4.2.0", new.as_str()),
        ];
        assert_eq!(
            floating_tag_pin_for("v4", &tags),
            Some(ResolvedPin::most_specific(ConcreteVersion::new("v4.1.0")))
        );
    }

    /// #1684 (security): a release on the commit that does not extend the written floating tag
    /// is never adopted as the pin's version.
    #[test]
    fn test_resolved_pin_version_floating_tag_ignores_unrelated_release() {
        let sha = "a".repeat(40);
        for other in ["v5.0.0", "v99.0.0"] {
            let tags = [("v4", sha.as_str()), (other, sha.as_str())];
            assert_eq!(
                floating_tag_pin_for("v4", &tags),
                Some(ResolvedPin::most_specific(ConcreteVersion::new("v4"))),
                "{other}: only the written tag itself remains, which is not a full version"
            );
        }
        let tags = [("v4", sha.as_str()), ("v4.2.2", sha.as_str())];
        assert_eq!(
            floating_tag_pin_for("v4", &tags),
            Some(ResolvedPin::most_specific(ConcreteVersion::new("v4.2.2")))
        );
        let tags = [
            ("v4", sha.as_str()),
            ("v4.2.2", sha.as_str()),
            ("v5.0.0", sha.as_str()),
        ];
        assert_eq!(
            floating_tag_pin_for("v4", &tags),
            Some(ResolvedPin::most_specific(ConcreteVersion::new("v4.2.2")))
        );
    }

    /// #1684 (critic N3): missing tags and a cold index stay on the text path.
    #[test]
    fn test_resolved_pin_version_unindexed_tag_is_unresolved() {
        let sha = "a".repeat(40);
        let warm = [("v4", sha.as_str()), ("v4.1.2", sha.as_str())];
        assert_eq!(floating_tag_pin_for("v5", &warm), None);
        assert_eq!(floating_tag_pin_for("V4", &warm), None);
        assert_eq!(floating_tag_pin_for("v4", &[]), None);
    }

    fn sibling_names(pin: &ResolvedPin) -> Vec<&str> {
        pin.siblings().iter().map(|t| t.as_str()).collect()
    }

    /// #1709/#1719: an exact tag pin stays primary and gains the same-major releases on its
    /// commit as siblings; other majors stay out.
    #[test]
    fn test_resolved_pin_version_exact_tag_keeps_written_primary_with_same_major_siblings() {
        let sha = "a".repeat(40);
        let warm = [
            ("v4.8.0", sha.as_str()),
            ("v4.9.0", sha.as_str()),
            ("v5.0.0", sha.as_str()),
        ];
        let pin = floating_tag_pin_for("v4.8.0", &warm).unwrap();
        assert_eq!(pin.version().as_str(), "v4.8.0");
        assert_eq!(sibling_names(&pin), ["v4.9.0"]);
        let pin = floating_tag_pin_for("v4.9.0", &warm).unwrap();
        assert_eq!(pin.version().as_str(), "v4.9.0");
        assert_eq!(sibling_names(&pin), ["v4.8.0"]);
    }

    /// #1709 (N3): a non-full-semver tag pin never takes the exact-tag path.
    #[test]
    fn test_resolved_pin_version_non_semver_tag_pin_is_not_resolved_as_exact() {
        let sha = "a".repeat(40);
        let warm = [("release-x", sha.as_str()), ("release-y", sha.as_str())];
        assert_eq!(floating_tag_pin_for("release-x", &warm), None);
    }

    /// #1709: a SHA pin carries every release on its commit, across majors (#1719).
    #[test]
    fn test_resolved_pin_version_sha_pin_carries_cross_major_siblings() {
        let pin = resolved_pin_for_tags(&["v5.0.0", "v4.8.0", "v4.9.0"]).unwrap();
        assert_eq!(pin.version().as_str(), "v4.8.0");
        assert_eq!(sibling_names(&pin), ["v4.9.0", "v5.0.0"]);
    }

    /// #1709 (M6): parsed GitHub Actions dependencies never carry a synthetic name range, so
    /// their scan key is per-occurrence.
    #[test]
    fn test_parsed_dependencies_have_real_name_ranges() {
        let content = format!(
            "steps:\n  - uses: actions/checkout@{}\n  - uses: actions/checkout@v4.8.0\n",
            "a".repeat(40)
        );
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        assert_eq!(parsed.dependencies.len(), 2);
        for dep in deps_core::ParseResult::dependencies(&parsed) {
            assert!(!dep.name_range_is_synthetic());
        }
    }

    /// #1684: the shared `pinned_commit` helper returns `None` for an exact tag even when
    /// the index carries it (hover and `resolved_pin_version` both rely on this).
    #[test]
    fn test_pinned_commit_exact_tag_is_none_floating_is_some() {
        let sha = "c".repeat(40);
        let fmt = formatter();
        let mut index = TagIndex::default();
        for tag in ["v4", "v4.1.2"] {
            index
                .tag_to_sha
                .insert(tag.to_string(), CommitSha::parse(&sha).unwrap());
        }
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));
        let mut d = dep(Some(PinStyle::Tag), "actions/checkout");
        assert_eq!(
            fmt.pinned_commit(&d).map(|c| c.as_str().to_string()),
            Some(sha)
        );
        d.version_req = Some("v4.1.2".into());
        assert_eq!(fmt.pinned_commit(&d), None);
    }

    fn resolved_pin_for_tags(tags: &[&str]) -> Option<ResolvedPin> {
        let sha = "a".repeat(40);
        let commit = CommitSha::parse(&sha).unwrap();
        let fmt = formatter();
        fmt.tag_index.insert(
            PackageName::new("actions/checkout"),
            Arc::new(TagIndex::from_tags(tags.iter().map(|t| (*t, &commit)))),
        );
        let mut d = dep(Some(PinStyle::sha_for_test(&sha, None)), "actions/checkout");
        d.version_req = Some(sha.into());
        resolved_pin_of(&fmt, &d)
    }

    /// #1668: the most specific tag on the commit wins and is classified by whether another
    /// tag extends it.
    #[test]
    fn test_resolved_pin_version_classifies_two_component_release_and_alias() {
        let most_specific = |tag: &str| Some(ResolvedPin::most_specific(ConcreteVersion::new(tag)));
        assert_eq!(
            resolved_pin_for_tags(&["v2", "v2.9"]),
            most_specific("v2.9")
        );
        assert_eq!(
            resolved_pin_for_tags(&["v2.9", "v2"]),
            most_specific("v2.9")
        );
        assert_eq!(resolved_pin_for_tags(&["v2"]), most_specific("v2"));
        assert_eq!(
            resolved_pin_for_tags(&["v2", "v2.9.1"]),
            most_specific("v2.9.1")
        );
        assert_eq!(
            resolved_pin_for_tags(&["v2.9", "v2.9.1.4"]),
            Some(ResolvedPin::alias(ConcreteVersion::new("v2.9")))
        );
    }

    /// Cold cache (no `TagIndex` entry for this SHA yet) must stay the honest `Unresolved`,
    /// never a fabricated version.
    #[test]
    fn test_resolved_pin_version_sha_pin_tag_index_miss_is_unresolved() {
        let sha = "d".repeat(40);
        let fmt = formatter();
        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v1"))),
            "actions/checkout",
        );

        assert_eq!(fmt.resolved_pin_version(&d), PinResolution::Unresolved);
    }

    /// #1735: a SHA absent from a populated, complete index is proven untagged, while a
    /// truncated index proves nothing.
    #[test]
    fn test_resolved_pin_version_sha_pin_absent_from_index_is_untagged_only_when_complete() {
        let tagged = CommitSha::parse(&"a".repeat(40)).unwrap();
        let d = dep(
            Some(PinStyle::sha_for_test(&"d".repeat(40), Some("v1.0.0"))),
            "actions/checkout",
        );
        for (coverage, expected) in [
            (
                deps_core::pagination::ListCoverage::Complete,
                PinResolution::Untagged,
            ),
            (
                deps_core::pagination::ListCoverage::Truncated,
                PinResolution::Unresolved,
            ),
        ] {
            let fmt = formatter();
            fmt.tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(TagIndex::from_tags([("v1.0.0", &tagged)]).with_coverage(coverage)),
            );
            assert_eq!(fmt.resolved_pin_version(&d), expected, "{coverage:?}");
        }
    }

    /// A `Tag`/`Branch` pin has no SHA to resolve at all — must stay `Unresolved`, leaving
    /// `concrete_pin_version`'s own text-shape ladder as the sole source for those pins.
    #[test]
    fn test_resolved_pin_version_non_sha_pin_is_unresolved() {
        let fmt = formatter();
        assert_eq!(
            fmt.resolved_pin_version(&dep(Some(PinStyle::Tag), "actions/checkout")),
            PinResolution::Unresolved
        );
        assert_eq!(
            fmt.resolved_pin_version(&dep(Some(PinStyle::Branch), "dev/tool")),
            PinResolution::Unresolved
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
        index
            .tag_to_sha
            .insert("v4".to_string(), CommitSha::parse(&sha).unwrap());
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let old_sha = "c".repeat(40);
        let d = dep(
            Some(PinStyle::sha_for_test(&old_sha, Some("v3"))),
            "actions/checkout",
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
        assert_eq!(fmt.osv_version(&ConcreteVersion::new("v4.2.0")), "4.2.0");
        assert_eq!(fmt.osv_version(&ConcreteVersion::new("4.2.0")), "4.2.0");
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
        let d = dep(Some(PinStyle::Tag), "actions/checkout");
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
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&"1".repeat(40), Some("v4.2.0"))),
            "actions/checkout",
        );
        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, format!("{} # v5.0.0", "deadbeef".repeat(5)));
    }

    /// Issue #1347 critic finding (C1), real-formatter regression: `requirement_is_unresolved`
    /// is `true` for every full-SHA pin (it means "not decidable from text alone", not
    /// "unexpanded placeholder, don't touch") — `deps_core::edit::plan_vulnerability_fix` must
    /// never gate on that predicate, or this ecosystem's working SHA-preserving vulnerability
    /// remediation would be silently suppressed. Proven here against the real
    /// `GithubActionsFormatter`, not a mock.
    #[test]
    fn test_plan_vulnerability_fix_still_remediates_sha_pin() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let old_sha = "a".repeat(40);
        let d = dep(
            Some(PinStyle::sha_for_test(&old_sha, Some("v4.2.0"))),
            "actions/checkout",
        );
        assert!(
            fmt.requirement_is_unresolved(&VersionReq::new(old_sha)),
            "sanity check: a bare SHA is 'unresolved' by this formatter's own definition"
        );

        let advisory = Arc::new(
            Advisory::new(
                "GHSA-test-0003".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("v5.0.0")]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("v5.0.0"),
            });

        let planned = plan_vulnerability_fix(
            &d,
            d.version_range.expect("test dep has a version range"),
            "v4.2.0",
            &dv,
            None,
            &fmt,
        );

        assert_eq!(
            planned
                .expect("fix must still be planned for a SHA pin")
                .edit
                .new_text,
            format!("{} # v5.0.0", "deadbeef".repeat(5))
        );
    }

    /// FR-010 sibling fix (security audit finding): a quoted-scalar SHA pin must never get
    /// `# {tag}` appended inside the quotes — the comment is written after the closing
    /// delimiters (#1732).
    #[test]
    fn test_format_version_replacing_for_sha_quoted_scalar_keeps_closing_quote() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let content = format!(
            "steps:\n  - uses: \"actions/checkout@{}\" # v4.2.0\n",
            "a".repeat(40)
        );
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let d = &parsed.dependencies[0];
        assert!(!d.is_plain_scalar);

        let new_text =
            fmt.format_version_replacing_for(d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, format!("{}\" # v5.0.0", "deadbeef".repeat(5)));
    }

    /// A release name that is not a comment-shaped tag must not be written as a comment the
    /// next parse cannot read back: the stale comment is dropped and the closer kept.
    #[test]
    fn test_format_version_replacing_for_sha_non_version_target_writes_no_comment() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "stable".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(&"1".repeat(40), Some("v4.2.0"))),
            "actions/checkout",
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("stable"), "v4.2.0"),
            "deadbeef".repeat(5)
        );
    }

    /// Parses `line` (one `uses:` step), rewrites its pin to the non-version release `stable`
    /// and returns the edited line.
    fn rewrite_to_non_version_release(line: &str) -> String {
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "stable".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let content = format!("steps:\n  - {line}\n");
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
        let d = parsed.dependencies[0]
            .as_any()
            .downcast_ref::<GithubActionsDependency>()
            .unwrap();
        let range = d.version_range.unwrap();
        let replacement =
            fmt.format_version_replacing_for(d, &ConcreteVersion::new("stable"), "v1.0.0");
        let edited_line = content.lines().nth(1).unwrap();
        let (start, end) = (range.start.character as usize, range.end.character as usize);
        format!(
            "{}{replacement}{}",
            edited_line.get(..start).unwrap(),
            edited_line.get(end..).unwrap()
        )
    }

    /// S2: words after the stale tag stay inside a comment when the tag is dropped.
    #[test]
    fn test_non_version_target_keeps_trailing_comment_words_inside_comment() {
        let sha = "a".repeat(40);
        let new = "deadbeef".repeat(5);
        assert_eq!(
            rewrite_to_non_version_release(&format!(
                "uses: actions/checkout@{sha} # v1.0.0 pinned for CVE"
            )),
            format!("  - uses: actions/checkout@{new} # pinned for CVE")
        );
    }

    #[test]
    fn test_non_version_target_keeps_trailing_comment_words_for_quoted_ref() {
        let sha = "a".repeat(40);
        let new = "deadbeef".repeat(5);
        assert_eq!(
            rewrite_to_non_version_release(&format!(
                "uses: \"actions/checkout@{sha}\" # v1.0.0 pinned for CVE"
            )),
            format!("  - uses: \"actions/checkout@{new}\" # pinned for CVE")
        );
    }

    #[test]
    fn test_non_version_target_drops_comment_without_trailing_words() {
        let sha = "a".repeat(40);
        let new = "deadbeef".repeat(5);
        assert_eq!(
            rewrite_to_non_version_release(&format!("uses: actions/checkout@{sha} # v1.0.0")),
            format!("  - uses: actions/checkout@{new}")
        );
    }

    /// Issue #898 critic follow-up (S1): a flow-style SHA ref with sibling YAML content
    /// (`, with: {node-version: 20}}`) must withhold the `# {tag}`-appending edit even on
    /// a `TagIndex` hit, exactly like the quoted-scalar guard above — otherwise accepting
    /// the version-update code action comments out the sibling content, producing an
    /// unterminated flow mapping. Manifest shape from the issue's exact repro:
    /// `- {uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683, with: {node-version: 20}}`.
    #[test]
    fn test_format_version_replacing_for_sha_flow_style_commentless_rewrites_only_the_sha() {
        let fmt = formatter();
        let name = PackageName::new("actions/checkout");
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
        let mut d = dep(Some(PinStyle::sha_for_test(sha, None)), "actions/checkout");
        d.is_last_on_line = false;

        // #1724: only the 40 hex is rewritten; `version_range` never covers the flow siblings.
        let new_text = fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), sha);
        assert_eq!(
            new_text,
            "deadbeef".repeat(5),
            "a flow-style SHA ref with sibling content must never gain a `# {{tag}}` suffix"
        );
        assert!(!new_text.contains('#'));
    }

    /// #1724: a quoted commentless SHA pin is rewritten to the bare new SHA.
    #[test]
    fn test_format_version_replacing_for_sha_quoted_commentless_rewrites_only_the_sha() {
        let fmt = formatter();
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
        let mut d = dep(Some(PinStyle::sha_for_test(sha, None)), "actions/checkout");
        d.is_plain_scalar = false;

        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), sha),
            "deadbeef".repeat(5)
        );
        assert_eq!(
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v9.9.9"), sha),
            sha,
            "an index miss keeps the no-op literal fallback"
        );
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
        index.tag_to_sha.insert(
            "v5.0.0".to_string(),
            CommitSha::parse(&"deadbeef".repeat(5)).unwrap(),
        );
        fmt.tag_index.insert(name, Arc::new(index));

        let d = dep(
            Some(PinStyle::sha_for_test(
                "11bd71901bbe5b1630ceea73d27597364c9af683",
                Some("v4.2.0"),
            )),
            "actions/checkout",
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
        let sha = "a".repeat(40);
        let d = dep(
            Some(PinStyle::sha_for_test(&sha, Some("v4.2.0"))),
            "actions/checkout",
        );
        let new_text =
            fmt.format_version_replacing_for(&d, &ConcreteVersion::new("v5.0.0"), "v4.2.0");
        assert_eq!(new_text, format!("{sha} # v4.2.0"));
        assert_ne!(new_text, "v4.2.0");
    }

    #[test]
    fn test_format_version_replacing_for_branch_returns_current_unchanged() {
        let fmt = formatter();
        let d = dep(Some(PinStyle::Branch), "dev/tool");
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
        index
            .tag_to_sha
            .insert("v4".to_string(), CommitSha::parse(&"a".repeat(40)).unwrap());
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
        index.tag_to_sha.insert(
            "2.1.0".to_string(),
            CommitSha::parse(&"b".repeat(40)).unwrap(),
        );
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
        index
            .tag_to_sha
            .insert("v4".to_string(), CommitSha::parse(&"a".repeat(40)).unwrap());
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
        index
            .tag_to_sha
            .insert("v4".to_string(), CommitSha::parse(&"a".repeat(40)).unwrap());
        fmt.tag_index.insert(name.clone(), Arc::new(index));

        let via_sha_pin_action = fmt.sha_pin_replacement_for(&name, "v4").unwrap();

        let sha_dep = dep(
            Some(PinStyle::sha_for_test(&"c".repeat(40), Some("v3"))),
            "actions/checkout",
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

    /// #1391 review S1: #1390's own repro text (`v4.<%= py %>`), parsed through the real
    /// `crate::parser::parse_workflow_yaml` path rather than a hand-built `GithubActionsDependency`
    /// — closes the coverage gap the existing `plan_vulnerability_fix` tests above leave (they
    /// only exercise ordinary tag/SHA pins, not the shared generic-template detector).
    #[test]
    fn test_plan_vulnerability_fix_generic_placeholder_through_real_parser_is_not_rewritten() {
        use deps_core::ParseResult;
        use deps_core::edit::{VulnFixSkip, plan_vulnerability_fix};
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        let yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.<%= py %>\n";
        let uri = deps_core::test_util::test_uri("/test/.github/workflows/ci.yml");
        let result = crate::parser::parse_workflow_yaml(yaml, &uri).expect("valid yaml");
        let deps = result.dependencies();
        let dep = deps
            .iter()
            .find(|d| d.name().as_str() == "actions/checkout")
            .expect("actions/checkout parsed");
        let current = dep
            .version_requirement()
            .expect("parser preserves the raw templated ref text")
            .as_str();
        assert_eq!(current, "v4.<%= py %>");
        let version_range = dep
            .version_range()
            .expect("templated ref has a version range");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0004".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("v5")]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("v5"),
            });

        let planned = plan_vulnerability_fix(*dep, version_range, current, &dv, None, &formatter());

        assert_eq!(
            planned,
            Err(VulnFixSkip::UnresolvedPlaceholder),
            "the real GithubActionsFormatter must suppress the fix for #1390's unexpanded ERB \
             template placeholder, got {planned:?}"
        );
    }

    /// #1683: OSV names are exact-case, so a lowercase `uses:` maps to the canonical casing
    /// GitHub reported, and to `None` (never the written casing) while it is unconfirmed.
    #[test]
    fn test_osv_package_name_uses_canonical_casing_from_tag_index() {
        use deps_core::ParseResult;
        use deps_core::lsp_helpers::OsvNaming;

        let yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: azure/setup-kubectl@v3\n";
        let uri = deps_core::test_util::test_uri("/test/.github/workflows/ci.yml");
        let result = crate::parser::parse_workflow_yaml(yaml, &uri).expect("valid yaml");
        let deps = result.dependencies();
        let dep = *deps.first().expect("one dependency");
        let name = PackageName::new("azure/setup-kubectl");
        let formatter = formatter();

        assert_eq!(formatter.osv_package_name(dep), None, "cold index");
        assert_eq!(
            formatter.osv_name_availability(dep),
            OsvNameAvailability::AwaitingRegistryData {
                written_fallback: deps_core::osv::OsvPackageName::new_or_skip(
                    "azure/setup-kubectl"
                ),
            }
        );

        formatter
            .tag_index
            .insert(name.clone(), Arc::new(TagIndex::default()));
        assert_eq!(formatter.osv_package_name(dep), None, "unconfirmed casing");

        let canonical = deps_core::github::CanonicalRepoName::from_commit_url(
            "https://api.github.com/repos/Azure/setup-kubectl/commits/abc",
        );
        formatter.tag_index.insert(
            name,
            Arc::new(TagIndex::default().with_canonical_repo_name(canonical)),
        );
        assert_eq!(
            formatter
                .osv_package_name(dep)
                .as_ref()
                .map(deps_core::osv::OsvPackageName::as_str),
            Some("Azure/setup-kubectl")
        );
        assert_eq!(
            formatter.osv_name_availability(dep),
            OsvNameAvailability::Ready
        );
    }

    /// #1683: the same action written in two casings is keyed separately in the tag index;
    /// each occurrence is `Ready` only once its own key holds a confirmed canonical name.
    #[test]
    fn test_osv_package_name_same_action_in_two_casings() {
        use deps_core::ParseResult;
        use deps_core::lsp_helpers::OsvNaming;

        let yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: Azure/setup-kubectl@v3\n      - uses: azure/setup-kubectl@v3\n";
        let uri = deps_core::test_util::test_uri("/test/.github/workflows/ci.yml");
        let result = crate::parser::parse_workflow_yaml(yaml, &uri).expect("valid yaml");
        let deps = result.dependencies();
        assert_eq!(deps.len(), 2);
        let canonical = || {
            Arc::new(TagIndex::default().with_canonical_repo_name(
                deps_core::github::CanonicalRepoName::from_commit_url(
                    "https://api.github.com/repos/Azure/setup-kubectl/commits/abc",
                ),
            ))
        };

        for populated in [
            &[][..],
            &["Azure/setup-kubectl"],
            &["Azure/setup-kubectl", "azure/setup-kubectl"],
        ] {
            let formatter = formatter();
            for key in populated {
                formatter
                    .tag_index
                    .insert(PackageName::new(*key), canonical());
            }
            for dep in &deps {
                let expected = if populated.contains(&dep.name().as_str()) {
                    Some("Azure/setup-kubectl")
                } else {
                    None
                };
                assert_eq!(
                    formatter
                        .osv_package_name(*dep)
                        .as_ref()
                        .map(deps_core::osv::OsvPackageName::as_str),
                    expected,
                    "populated={populated:?} dep={}",
                    dep.name().as_str()
                );
                assert_eq!(
                    formatter.osv_name_availability(*dep) == OsvNameAvailability::Ready,
                    expected.is_some()
                );
            }
        }
    }
}
