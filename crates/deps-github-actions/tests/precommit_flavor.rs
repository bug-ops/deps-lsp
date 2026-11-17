//! Acceptance tests for #575 / spec 044: the `GitTagsFlavor` dispatch of
//! `GithubActionsEcosystem` and the pre-commit parse / diagnostic behaviour behind it.
//!
//! Plan 2026-11-17T06-15-23-architect, T3: every flavor-sensitive `EcosystemBase` method is
//! asserted per flavor, `Actions` behaves exactly like `new`, and the shared pieces
//! (`refresh_events`, `lockfile_filenames`) stay identical.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use deps_core::ecosystem::BoxFuture;
use deps_core::lsp_helpers::{DiagnosticSeverities, VersionData};
use deps_core::position::Position;
use deps_core::{
    Ecosystem, EcosystemBase, EcosystemId, HttpCache, ParseResult, parse_manifest_blocking,
};
use deps_github_actions::{
    GitTagsFlavor, GithubActionsEcosystem, GithubActionsRegistry, parse_precommit_config,
};

fn ecosystem(flavor: GitTagsFlavor) -> GithubActionsEcosystem {
    let registry = Arc::new(GithubActionsRegistry::new(Arc::new(HttpCache::new())));
    GithubActionsEcosystem::with_registry(registry, flavor)
}

const PRECOMMIT_URI: &str = "/repo/.pre-commit-config.yaml";

fn precommit_uri() -> url::Url {
    deps_core::test_util::test_uri(PRECOMMIT_URI)
}

const BLACK: &str = "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n";

fn parse(content: &str) -> Vec<(String, Option<String>)> {
    let parsed = parse_precommit_config(content, &precommit_uri()).expect("valid yaml");
    ParseResult::dependencies(&parsed)
        .iter()
        .map(|d| {
            (
                d.name().as_str().to_owned(),
                d.version_requirement().map(ToString::to_string),
            )
        })
        .collect()
}

fn names(content: &str) -> Vec<String> {
    parse(content).into_iter().map(|(n, _)| n).collect()
}

// ---- per-flavor EcosystemBase behaviour ------------------------------------------------------

#[test]
fn ecosystem_id_follows_the_flavor() {
    assert_eq!(
        ecosystem(GitTagsFlavor::Actions).ecosystem_id(),
        EcosystemId::GithubActions
    );
    assert_eq!(
        ecosystem(GitTagsFlavor::PreCommit).ecosystem_id(),
        EcosystemId::PreCommit
    );
}

#[test]
fn display_name_follows_the_flavor() {
    assert_eq!(
        ecosystem(GitTagsFlavor::Actions).display_name(),
        "GitHub Actions"
    );
    assert!(
        ecosystem(GitTagsFlavor::PreCommit)
            .display_name()
            .to_lowercase()
            .contains("pre-commit")
    );
}

#[test]
fn manifest_filenames_follow_the_flavor() {
    assert_eq!(
        ecosystem(GitTagsFlavor::Actions).manifest_filenames(),
        ["action.yml", "action.yaml"]
    );
    assert_eq!(
        ecosystem(GitTagsFlavor::PreCommit).manifest_filenames(),
        [".pre-commit-config.yaml", ".pre-commit-config.yml"]
    );
}

#[test]
fn manifest_directory_patterns_follow_the_flavor() {
    assert_eq!(
        ecosystem(GitTagsFlavor::Actions).manifest_directory_patterns(),
        [
            (".github/workflows", ".yml"),
            (".github/workflows", ".yaml")
        ]
    );
    assert!(
        ecosystem(GitTagsFlavor::PreCommit)
            .manifest_directory_patterns()
            .is_empty()
    );
}

#[test]
fn refresh_events_are_available_for_both_flavors() {
    for flavor in [GitTagsFlavor::Actions, GitTagsFlavor::PreCommit] {
        assert!(ecosystem(flavor).refresh_events().is_some(), "{flavor:?}");
    }
}

#[test]
fn lockfile_filenames_are_empty_for_both_flavors() {
    for flavor in [GitTagsFlavor::Actions, GitTagsFlavor::PreCommit] {
        assert!(
            ecosystem(flavor).lockfile_filenames().is_empty(),
            "{flavor:?}"
        );
    }
}

#[test]
fn pin_all_to_sha_noun_follows_the_flavor() {
    let actions = ecosystem(GitTagsFlavor::Actions).pin_all_to_sha_noun();
    let precommit = ecosystem(GitTagsFlavor::PreCommit).pin_all_to_sha_noun();
    assert_ne!(actions.singular, precommit.singular);
    assert_eq!(precommit.singular, "hook");
}

#[test]
fn fallback_completion_prefix_follows_the_flavor_key() {
    let rev_line = "    rev: v1.2";
    let uses_line = "      - uses: actions/checkout@v4";
    let at_end = |line: &str| Position::new(0, u32::try_from(line.len()).expect("short line"));
    let actions = ecosystem(GitTagsFlavor::Actions);
    let precommit = ecosystem(GitTagsFlavor::PreCommit);

    assert!(
        precommit
            .fallback_completion_prefix(rev_line, at_end(rev_line))
            .is_some()
    );
    assert!(
        actions
            .fallback_completion_prefix(rev_line, at_end(rev_line))
            .is_none()
    );
    assert!(
        actions
            .fallback_completion_prefix(uses_line, at_end(uses_line))
            .is_some()
    );
    assert!(
        precommit
            .fallback_completion_prefix(uses_line, at_end(uses_line))
            .is_none()
    );
}

#[tokio::test]
async fn parse_dispatches_on_the_flavor() {
    let precommit: Arc<dyn Ecosystem> = Arc::new(ecosystem(GitTagsFlavor::PreCommit));
    let manifest = parse_manifest_blocking(&precommit, BLACK, &precommit_uri())
        .await
        .expect("pre-commit config parses");
    assert_eq!(manifest.ecosystem_id(), EcosystemId::PreCommit);
    assert_eq!(ParseResult::dependencies(&*manifest).len(), 1);

    let actions: Arc<dyn Ecosystem> = Arc::new(ecosystem(GitTagsFlavor::Actions));
    let workflow = "steps:\n  - uses: actions/checkout@v4\n";
    let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    let manifest = parse_manifest_blocking(&actions, workflow, &uri)
        .await
        .expect("workflow parses");
    assert_eq!(manifest.ecosystem_id(), EcosystemId::GithubActions);
    assert_eq!(ParseResult::dependencies(&*manifest).len(), 1);
}

// ---- parse_precommit_config ------------------------------------------------------------------

#[test]
fn parse_precommit_config_reads_block_mapping_entry() {
    let deps = parse(BLACK);
    assert_eq!(deps, [("psf/black".to_owned(), Some("24.1.0".to_owned()))]);
}

#[test]
fn parse_precommit_config_ranges_cover_repo_and_rev_scalars() {
    let parsed = parse_precommit_config(BLACK, &precommit_uri()).expect("valid yaml");
    let deps = ParseResult::dependencies(&parsed);
    let name = deps[0].name_range();
    let version = deps[0].version_range().expect("rev is resolvable");
    assert_eq!(name.start.line, 1);
    assert_eq!(version.start.line, 2);
    assert_eq!((version.start.character, version.end.character), (9, 15));
}

#[test]
fn parse_precommit_config_strips_git_suffix_and_trailing_slash() {
    for repo in [
        "https://github.com/psf/black.git",
        "https://github.com/psf/black/",
        "https://github.com/psf/black.git/",
    ] {
        let content = format!("repos:\n  - repo: {repo}\n    rev: 24.1.0\n");
        assert_eq!(names(&content), ["psf/black"], "{repo}");
    }
}

#[test]
fn parse_precommit_config_reads_quoted_and_flow_entries() {
    let content = "repos:\n  - {repo: \"https://github.com/a/b\", rev: 'v1.2.3'}\n  - repo: \"https://github.com/c/d\"\n    rev: \"v2.0.0\"\n";
    assert_eq!(
        parse(content),
        [
            ("a/b".to_owned(), Some("v1.2.3".to_owned())),
            ("c/d".to_owned(), Some("v2.0.0".to_owned())),
        ]
    );
}

#[test]
fn parse_precommit_config_skips_local_and_meta_repos_silently() {
    let content = "repos:\n  - repo: local\n    hooks:\n      - id: x\n        name: x\n        entry: x\n        language: system\n  - repo: meta\n    hooks:\n      - id: check-hooks-apply\n";
    assert!(names(content).is_empty());
}

#[test]
fn parse_precommit_config_skips_non_github_and_unusual_urls() {
    for repo in [
        "https://gitlab.com/a/b",
        "git@github.com:a/b",
        "ssh://git@github.com/a/b",
        "https://user@github.com/a/b",
        "https://github.com:8080/a/b",
        "https://github.com/a/b?ref=x",
        "https://github.com/a/b#frag",
        "https://github.com/a",
        "http://github.com/a/b/c/d",
    ] {
        let content = format!("repos:\n  - repo: {repo}\n    rev: v1.0.0\n");
        assert!(names(&content).is_empty(), "{repo} must be skipped");
    }
}

#[test]
fn parse_precommit_config_keeps_valid_entries_around_skipped_ones() {
    let content = "repos:\n  - repo: local\n  - repo: https://gitlab.com/x/y\n    rev: v1\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n";
    assert_eq!(names(content), ["psf/black"]);
}

#[test]
fn parse_precommit_config_skips_entries_with_missing_or_non_string_fields() {
    let content = "repos:\n  - repo: https://github.com/a/no-rev\n  - rev: v1.0.0\n  - repo: 12\n    rev: v1.0.0\n  - repo: https://github.com/a/int-rev\n    rev: 12\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n";
    assert_eq!(names(content), ["psf/black"]);
}

#[test]
fn parse_precommit_config_invalid_yaml_is_an_error() {
    assert!(parse_precommit_config("repos: [unclosed\n  - : :", &precommit_uri()).is_err());
}

#[test]
fn parse_precommit_config_without_repos_is_empty_not_an_error() {
    assert!(names("default_stages: [commit]\n").is_empty());
    assert!(names("").is_empty());
}

#[test]
fn parse_precommit_config_full_sha_with_frozen_comment_reads_the_commented_tag() {
    let sha = "a".repeat(40);
    let content = format!(
        "repos:\n  - repo: https://github.com/psf/black\n    rev: {sha}  # frozen: v24.1.0\n"
    );
    let parsed = parse_precommit_config(&content, &precommit_uri()).expect("valid yaml");
    let deps = ParseResult::dependencies(&parsed);
    assert_eq!(
        deps[0]
            .version_requirement()
            .map(ToString::to_string)
            .as_deref(),
        Some("v24.1.0")
    );
    let range = deps[0].version_range().expect("sha pin has a range");
    assert!(
        range.end.character > range.start.character + 40,
        "the range extends through the comment: {range:?}"
    );
}

#[test]
fn parse_precommit_config_full_sha_with_bare_comment_reads_the_commented_tag() {
    let sha = "b".repeat(40);
    let content =
        format!("repos:\n  - repo: https://github.com/psf/black\n    rev: {sha}  # v24.1.0\n");
    let parsed = parse_precommit_config(&content, &precommit_uri()).expect("valid yaml");
    let deps = ParseResult::dependencies(&parsed);
    assert_eq!(
        deps[0]
            .version_requirement()
            .map(ToString::to_string)
            .as_deref(),
        Some("v24.1.0")
    );
}

#[test]
fn parse_precommit_config_short_hex_rev_is_not_resolvable() {
    for len in [7, 12, 39] {
        let rev = "c".repeat(len);
        let content = format!("repos:\n  - repo: https://github.com/psf/black\n    rev: {rev}\n");
        let parsed = parse_precommit_config(&content, &precommit_uri()).expect("no error");
        let deps = ParseResult::dependencies(&parsed);
        assert!(
            deps.iter().all(|d| d.version_range().is_none()),
            "{len}-hex rev has no version range"
        );
    }
}

#[test]
fn parse_precommit_config_accepts_either_manifest_extension() {
    for path in [
        "/repo/.pre-commit-config.yaml",
        "/repo/.pre-commit-config.yml",
    ] {
        let uri = deps_core::test_util::test_uri(path);
        let parsed = parse_precommit_config(BLACK, &uri).expect("valid yaml");
        assert_eq!(ParseResult::dependencies(&parsed).len(), 1, "{path}");
    }
}

#[test]
fn actions_flavor_does_not_read_frozen_comments() {
    let sha = "d".repeat(40);
    let content = format!("steps:\n  - uses: actions/checkout@{sha} # frozen: v4.2.2\n");
    let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    let parsed = deps_github_actions::parse_workflow_yaml(&content, &uri).expect("valid yaml");
    let deps = ParseResult::dependencies(&parsed);
    assert_ne!(
        deps[0]
            .version_requirement()
            .map(ToString::to_string)
            .as_deref(),
        Some("v4.2.2"),
        "`# frozen:` is pre-commit's convention only (Actions unchanged, Bare only)"
    );
}

// ---- mutable-ref policy ----------------------------------------------------------------------

async fn diagnostic_codes(
    eco: GithubActionsEcosystem,
    content: &str,
    uri: url::Url,
) -> Vec<String> {
    let eco: Arc<dyn Ecosystem> = Arc::new(eco);
    let manifest = parse_manifest_blocking(&eco, content, &uri)
        .await
        .expect("parses");
    let cached = Default::default();
    let resolved = Default::default();
    let versions = VersionData::new(&cached, &resolved);
    let diagnostics: BoxFuture<'_, _> = manifest.generate_diagnostics(
        versions,
        &uri,
        Default::default(),
        DiagnosticSeverities::default(),
    );
    diagnostics
        .await
        .iter()
        .map(|d| format!("{:?}", d.code()))
        .collect()
}

fn precommit_rev(rev: &str) -> String {
    format!("repos:\n  - repo: https://github.com/psf/black\n    rev: {rev}\n")
}

#[tokio::test]
async fn precommit_mutable_ref_pin_flags_dotless_non_hex_revs() {
    for rev in ["v1", "main", "stable"] {
        let codes = diagnostic_codes(
            ecosystem(GitTagsFlavor::PreCommit),
            &precommit_rev(rev),
            precommit_uri(),
        )
        .await;
        assert!(
            codes
                .iter()
                .any(|c| c.contains("pre-commit-mutable-ref-pin")),
            "{rev}: {codes:?}"
        );
    }
}

#[tokio::test]
async fn precommit_mutable_ref_pin_accepts_dotted_and_hex_revs() {
    for rev in ["v1.2", "v1.2.3", "24.1.0", "abc1234"] {
        let codes = diagnostic_codes(
            ecosystem(GitTagsFlavor::PreCommit),
            &precommit_rev(rev),
            precommit_uri(),
        )
        .await;
        assert!(
            !codes.iter().any(|c| c.contains("mutable-ref-pin")),
            "{rev}: {codes:?}"
        );
    }
}

#[tokio::test]
async fn actions_mutable_ref_pin_still_flags_every_tag() {
    let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    for tag in ["v1", "v1.2", "v1.2.3"] {
        let content = format!("steps:\n  - uses: actions/checkout@{tag}\n");
        let codes =
            diagnostic_codes(ecosystem(GitTagsFlavor::Actions), &content, uri.clone()).await;
        assert!(
            codes
                .iter()
                .any(|c| c.contains(deps_github_actions::MUTABLE_REF_PIN_DIAGNOSTIC_CODE)),
            "{tag}: {codes:?}"
        );
    }
}
