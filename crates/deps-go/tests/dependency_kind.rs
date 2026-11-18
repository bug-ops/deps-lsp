//! #2072: every Go requirement is a production dependency (`tool` lines are not parsed).

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

#[test]
fn kind_is_normal_for_every_requirement() {
    let uri = url::Url::parse("file:///project/go.mod").expect("uri");
    let result = deps_go::parse_go_mod(
        "module example.com/m\n\ngo 1.21\n\nrequire github.com/foo/bar v1.2.3\n",
        &uri,
    )
    .expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
