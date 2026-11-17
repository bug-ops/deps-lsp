//! Regression test for #1684 / #1719: the release that stands in for a floating `@v4` in an OSV
//! scan is never reported as the pin's in-use version.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use deps_core::lsp_helpers::{CommitSha, TagIndex, resolve_in_use_version};
use deps_core::{EcosystemId, PackageName};
use deps_github_actions::types::GithubActionsDependency;
use deps_github_actions::{GithubActionsFormatter, RepositoryIndexes};

fn in_use_of_checkout_v4(tags: &[&str]) -> Option<String> {
    let sha = CommitSha::parse(&"a".repeat(40)).expect("40 hex");
    let indexes = Arc::new(RepositoryIndexes::default());
    indexes.insert(
        PackageName::new("actions/checkout"),
        Arc::new(TagIndex::from_tags(tags.iter().map(|t| (*t, &sha)))),
    );
    let formatter = GithubActionsFormatter::new(indexes);
    let uri = url::Url::parse("file:///w/.github/workflows/ci.yml").expect("uri");
    let parsed = deps_github_actions::parse_workflow_yaml(
        "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n",
        &uri,
    )
    .expect("parse");
    let dep: GithubActionsDependency = parsed.dependencies.into_iter().next().expect("one dep");

    resolve_in_use_version(
        &dep,
        &deps_core::test_util::package_key("actions/checkout"),
        &HashMap::new(),
        None,
        &formatter,
        EcosystemId::GithubActions,
    )
    .map(|v| v.as_str().to_owned())
}

#[test]
fn floating_pin_never_adopts_an_unrelated_major_as_in_use_version() {
    assert_eq!(in_use_of_checkout_v4(&["v4", "v5.0.0"]), None);
}

#[test]
fn floating_pin_with_its_own_full_release_reports_it() {
    assert_eq!(
        in_use_of_checkout_v4(&["v4", "v4.2.2", "v5.0.0"]).as_deref(),
        Some("v4.2.2")
    );
}
