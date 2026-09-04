//! `component:` include pin classification and resolution.
//!
//! Two distinct steps, deliberately kept separate:
//!
//! - [`classify_component_pin_style`] — a pure, shape-only classification of the raw pin
//!   text, computed at parse time with no registry access (mirrors
//!   `deps-github-actions`'s `is_tag_shaped` — same documented trade-off: a textual release
//!   name that doesn't look like a version is classified [`crate::types::PinStyle::Branch`]
//!   even when it later turns out to exactly match a published release).
//! - [`resolve_component_pin`] — the FR-007 priority-ladder resolution against the
//!   project's **published releases** (never the raw tag list — an unreleased tag is not a
//!   usable component version), run once release data is actually fetched.

use crate::types::{GitlabCiVersion, PinStyle};
use deps_core::github::normalize_tag;
use deps_core::lsp_helpers::{is_full_sha, is_tag_shaped};

/// Literal `~latest` pin text (spec FR-007).
pub(crate) const LATEST: &str = "~latest";

/// Whether `raw` (after an optional `v`/`V` strip) is 1 or 2 dot-separated all-ASCII-digit
/// segments — GitLab's partial-semver component-pin shape (`1`, `1.2`, `v1.2`).
fn is_partial_semver_shaped(raw: &str) -> bool {
    let normalized = normalize_tag(raw);
    let parts: Vec<&str> = normalized.split('.').collect();
    (1..=2).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Classifies a `component:` pin's raw text by shape alone.
///
/// # Examples
///
/// ```
/// use deps_gitlab_ci::component::classify_component_pin_style;
/// use deps_gitlab_ci::PinStyle;
///
/// assert_eq!(classify_component_pin_style(&"a".repeat(40)), PinStyle::Sha);
/// assert_eq!(classify_component_pin_style("~latest"), PinStyle::Latest);
/// assert_eq!(classify_component_pin_style("1.2"), PinStyle::Partial);
/// assert_eq!(classify_component_pin_style("1.0.0"), PinStyle::Tag);
/// assert_eq!(classify_component_pin_style("some-branch"), PinStyle::Branch);
/// ```
#[must_use]
pub fn classify_component_pin_style(raw: &str) -> PinStyle {
    if is_full_sha(raw) {
        PinStyle::Sha
    } else if raw == LATEST {
        PinStyle::Latest
    } else if is_partial_semver_shaped(raw) {
        PinStyle::Partial
    } else if is_tag_shaped(raw) {
        PinStyle::Tag
    } else {
        PinStyle::Branch
    }
}

/// Builds the `semver::VersionReq` a partial-version pin (`1`, `1.2`) desugars to:
/// `~{normalized}` — `~1.2` matches `>=1.2.0, <1.3.0` (highest published `1.2.*`), `~1`
/// matches `>=1.0.0, <2.0.0` (highest published `1.*.*`), exactly GitLab's documented
/// semantics for this pin form.
fn partial_version_req(raw: &str) -> Option<semver::VersionReq> {
    semver::VersionReq::parse(&format!("~{}", normalize_tag(raw))).ok()
}

/// Parses `raw` as a `semver::VersionReq`, applying GitLab's own partial-pin semantics.
///
/// Spec plan §7, rather than the `semver` crate's implicit-caret default for a bare
/// version: a partial-semver-shaped `raw` (`1`, `1.2`) desugars via `partial_version_req`
/// (`~{raw}`), everything else parses through `semver::VersionReq::parse` unchanged.
///
/// Shared by [`resolve_component_pin`]'s `Partial` arm (via `partial_version_req`
/// directly, since it already knows the pin is partial-shaped) and
/// `GitlabCiRegistry::select_latest_matching`'s generic requirement
/// parsing, so the two paths cannot silently diverge on what a bare `"1.2"` means (#466
/// review M-b).
///
/// # Examples
///
/// ```
/// use deps_gitlab_ci::component::gitlab_version_req;
///
/// // GitLab's tilde semantics for a bare partial pin, not the semver crate's caret default.
/// let req = gitlab_version_req("1.2").unwrap();
/// assert!(req.matches(&semver::Version::parse("1.2.9").unwrap()));
/// assert!(!req.matches(&semver::Version::parse("1.3.0").unwrap()));
///
/// // A non-partial-shaped requirement (an explicit operator, or already a full version)
/// // parses through `semver::VersionReq` unchanged.
/// let range = gitlab_version_req(">=1.2.0, <1.3.0").unwrap();
/// assert!(range.matches(&semver::Version::parse("1.2.9").unwrap()));
/// assert!(!range.matches(&semver::Version::parse("1.3.0").unwrap()));
/// ```
#[must_use]
pub fn gitlab_version_req(raw: &str) -> Option<semver::VersionReq> {
    if is_partial_semver_shaped(raw) {
        partial_version_req(raw)
    } else {
        semver::VersionReq::parse(normalize_tag(raw)).ok()
    }
}

/// Resolves `raw` (a `component:` pin, already classified as `pin`) against `releases`.
///
/// `releases` must be the project's published CI/CD Catalog releases (spec FR-007's
/// priority order: SHA > exact release > branch > `~latest` > partial semver). A tag that
/// exists in the repository but was never published as a release is never a
/// candidate here — `releases` must already be the `/releases` response, never
/// `/repository/tags` (FR-004).
///
/// Returns `None` when nothing in `releases` matches — the honest "unresolvable" outcome for
/// a [`PinStyle::Branch`] pin, or for any pin naming a release/commit that doesn't exist.
///
/// # Examples
///
/// ```
/// use deps_gitlab_ci::PinStyle;
/// use deps_gitlab_ci::component::resolve_component_pin;
/// use deps_gitlab_ci::GitlabCiVersion;
///
/// let releases = vec![GitlabCiVersion {
///     version: "1.2.0".into(),
///     sha: "a".repeat(40),
///     prerelease: false,
///     published_at: None,
/// }];
/// let resolved = resolve_component_pin(&PinStyle::Tag, "1.2.0", &releases).unwrap();
/// assert_eq!(resolved.version.as_str(), "1.2.0");
/// ```
#[must_use]
pub fn resolve_component_pin(
    pin: &PinStyle,
    raw: &str,
    releases: &[GitlabCiVersion],
) -> Option<GitlabCiVersion> {
    match pin {
        PinStyle::Sha => releases.iter().find(|r| r.sha == raw).cloned(),
        // An exact release match always wins regardless of the parse-time shape guess —
        // FR-007's priority order puts it ahead of the "branch" honest-unknown, and the
        // registry is the only place this can actually be verified.
        PinStyle::Tag | PinStyle::Branch => {
            releases.iter().find(|r| r.version.as_str() == raw).cloned()
        }
        PinStyle::Latest => releases
            .iter()
            .filter(|r| !r.prerelease)
            .filter_map(|r| {
                semver::Version::parse(normalize_tag(r.version.as_str()))
                    .ok()
                    .map(|v| (v, r))
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, r)| r.clone()),
        PinStyle::Partial => {
            let req = partial_version_req(raw)?;
            releases
                .iter()
                .filter_map(|r| {
                    semver::Version::parse(normalize_tag(r.version.as_str()))
                        .ok()
                        .filter(|v| req.matches(v))
                        .map(|v| (v, r))
                })
                .max_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(_, r)| r.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, sha: &str) -> GitlabCiVersion {
        GitlabCiVersion {
            version: version.into(),
            sha: sha.to_string(),
            prerelease: version.contains('-'),
            published_at: None,
        }
    }

    // --- classify_component_pin_style ---

    #[test]
    fn test_classify_sha() {
        assert_eq!(classify_component_pin_style(&"a".repeat(40)), PinStyle::Sha);
    }

    #[test]
    fn test_classify_latest() {
        assert_eq!(classify_component_pin_style("~latest"), PinStyle::Latest);
    }

    #[test]
    fn test_classify_partial_one_component() {
        assert_eq!(classify_component_pin_style("1"), PinStyle::Partial);
    }

    #[test]
    fn test_classify_partial_two_components() {
        assert_eq!(classify_component_pin_style("1.2"), PinStyle::Partial);
        assert_eq!(classify_component_pin_style("v1.2"), PinStyle::Partial);
    }

    #[test]
    fn test_classify_full_version_is_tag() {
        assert_eq!(classify_component_pin_style("1.2.3"), PinStyle::Tag);
        assert_eq!(classify_component_pin_style("v1.2.3"), PinStyle::Tag);
    }

    #[test]
    fn test_classify_branch_shaped_ref() {
        assert_eq!(classify_component_pin_style("main"), PinStyle::Branch);
        assert_eq!(
            classify_component_pin_style("some-branch"),
            PinStyle::Branch
        );
    }

    // --- resolve_component_pin: FR-007 priority ladder ---

    #[test]
    fn test_resolve_sha() {
        let sha = "a".repeat(40);
        let releases = vec![release("1.0.0", &sha)];
        let resolved = resolve_component_pin(&PinStyle::Sha, &sha, &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "1.0.0");
    }

    #[test]
    fn test_resolve_exact_release() {
        let releases = vec![
            release("1.2.0", &"a".repeat(40)),
            release("1.3.0", &"b".repeat(40)),
        ];
        let resolved = resolve_component_pin(&PinStyle::Tag, "1.2.0", &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "1.2.0");
    }

    #[test]
    fn test_resolve_exact_release_v_prefix_is_literal_not_normalized() {
        let releases = vec![release("v1.2.0", &"a".repeat(40))];
        // Exact matching is literal, not normalized — "1.2.0" must NOT match "v1.2.0".
        assert!(resolve_component_pin(&PinStyle::Tag, "1.2.0", &releases).is_none());
        assert!(resolve_component_pin(&PinStyle::Tag, "v1.2.0", &releases).is_some());
    }

    #[test]
    fn test_resolve_latest_picks_highest_non_prerelease() {
        let releases = vec![
            release("1.0.0", &"a".repeat(40)),
            release("2.0.0", &"b".repeat(40)),
            release("3.0.0-beta.1", &"c".repeat(40)),
        ];
        let resolved = resolve_component_pin(&PinStyle::Latest, "~latest", &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "2.0.0");
    }

    #[test]
    fn test_resolve_partial_two_components() {
        let releases = vec![
            release("1.2.0", &"a".repeat(40)),
            release("1.2.5", &"b".repeat(40)),
            release("1.3.0", &"c".repeat(40)),
        ];
        let resolved = resolve_component_pin(&PinStyle::Partial, "1.2", &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "1.2.5");
    }

    #[test]
    fn test_resolve_partial_one_component() {
        let releases = vec![
            release("1.2.0", &"a".repeat(40)),
            release("1.9.0", &"b".repeat(40)),
            release("2.0.0", &"c".repeat(40)),
        ];
        let resolved = resolve_component_pin(&PinStyle::Partial, "1", &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "1.9.0");
    }

    #[test]
    fn test_resolve_partial_normalizes_v_prefixed_release_names() {
        // Revision-1 regression: matching must run against normalized release names, not
        // raw ones — a project tagging `v1.2.3` must still match a `1.2` partial pin.
        let releases = vec![release("v1.2.3", &"a".repeat(40))];
        let resolved = resolve_component_pin(&PinStyle::Partial, "1.2", &releases).unwrap();
        assert_eq!(resolved.version.as_str(), "v1.2.3");
    }

    #[test]
    fn test_resolve_partial_unmatched_returns_none() {
        let releases = vec![release("2.0.0", &"a".repeat(40))];
        assert!(resolve_component_pin(&PinStyle::Partial, "1.2", &releases).is_none());
    }

    #[test]
    fn test_resolve_branch_shaped_ref_with_no_matching_release_returns_none() {
        let releases = vec![release("1.0.0", &"a".repeat(40))];
        assert!(resolve_component_pin(&PinStyle::Branch, "main", &releases).is_none());
    }

    /// Spec S2 regression: a tag that exists in the repository but has no release must
    /// never be selected — this crate's registry layer must only ever pass `resolve_component_pin`
    /// the `/releases` list, never `/repository/tags`; this test fixes the *contract* (only
    /// releases are searched) rather than the fetch itself.
    ///
    /// The absence case alone can never fail by construction (#466 review impl-critic
    /// finding, `component.rs:274`): `resolve_component_pin` has no side channel to any
    /// tag/release outside the `releases` slice it's handed, so simply never passing
    /// `"2.0.0"` in proves nothing beyond "given one release, `Latest` picks it" — already
    /// covered by `test_resolve_latest_picks_highest_non_prerelease`. The contrast case
    /// below makes the assertion capable of failing: it proves the *same* pin genuinely
    /// picks the higher version once it's actually present, ruling out a regression where
    /// this function always returned the first/only entry regardless of version.
    #[test]
    fn test_resolve_latest_only_considers_passed_release_list() {
        let sha_a = "a".repeat(40);
        let sha_b = "b".repeat(40);

        let without_2_0_0 = vec![release("1.9.0", &sha_a)];
        let resolved = resolve_component_pin(&PinStyle::Latest, "~latest", &without_2_0_0).unwrap();
        assert_eq!(resolved.version.as_str(), "1.9.0");

        let with_2_0_0 = vec![release("1.9.0", &sha_a), release("2.0.0", &sha_b)];
        let resolved = resolve_component_pin(&PinStyle::Latest, "~latest", &with_2_0_0).unwrap();
        assert_eq!(resolved.version.as_str(), "2.0.0");
    }
}
