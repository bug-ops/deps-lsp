//! #2072 acceptance: `Dependency::kind()` for Cargo sections (architect v2 S5 mapping).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const MANIFEST: &str = r#"[package]
name = "fixture"
version = "0.1.0"

[dependencies]
normal-dep = "1.0"

[dev-dependencies]
dev-dep = "1.0"

[build-dependencies]
build-dep = "1.0"

[workspace.dependencies]
shared-dep = "1.0"
"#;

fn kind_of(result: &impl ParseResult, name: &str) -> Option<DependencyKind> {
    result
        .dependencies()
        .into_iter()
        .find(|dep| dep.name().as_str() == name)
        .unwrap_or_else(|| panic!("{name} not parsed"))
        .kind()
}

#[test]
fn kind_maps_cargo_sections() {
    let uri = url::Url::from_file_path("/project/Cargo.toml").expect("uri");
    let result = deps_cargo::parse_cargo_toml(MANIFEST, &uri).expect("parse");

    assert_eq!(kind_of(&result, "normal-dep"), Some(DependencyKind::Normal));
    assert_eq!(
        kind_of(&result, "dev-dep"),
        Some(DependencyKind::Development)
    );
    assert_eq!(kind_of(&result, "build-dep"), Some(DependencyKind::Build));
    assert_eq!(kind_of(&result, "shared-dep"), None);
}
