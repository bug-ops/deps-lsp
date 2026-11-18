//! #2072: every `deno.json` import is a production dependency.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

#[test]
fn kind_is_normal_for_every_import() {
    let uri = url::Url::from_file_path("/project/deno.json").expect("uri");
    let result = deps_deno::parse_deno_json(
        r#"{ "imports": { "@std/path": "jsr:@std/path@^1.0.0" } }"#,
        &uri,
    )
    .expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
