//! #2072: every GitLab CI `include:` reference is a production dependency.

#![allow(clippy::expect_used)]

use std::sync::{Arc, RwLock};

use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{DependencyKind, ParseResult};
use deps_gitlab_ci::{GitlabInstanceHost, parse_gitlab_ci_yaml};

#[test]
fn kind_is_normal_for_every_include() {
    let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
    let host = GitlabInstanceHost::new(
        Arc::new(RwLock::new(None)),
        Arc::new(RegistryAccessPolicy::default()),
    );
    let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
    let result = parse_gitlab_ci_yaml(content, &uri, &RegistryAccessPolicy::default(), &host)
        .expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
