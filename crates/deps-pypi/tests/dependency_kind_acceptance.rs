//! #2072 acceptance: `Dependency::kind()` for `pyproject.toml` sections (architect v2 S5
//! mapping). Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not
//! exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};
use deps_pypi::PypiParser;

const PYPROJECT: &str = r#"[build-system]
requires = ["setuptools>=61"]

[project]
name = "fixture"
version = "0.1.0"
dependencies = ["requests>=2.0"]

[project.optional-dependencies]
docs = ["sphinx>=7"]

[dependency-groups]
dev = ["pytest>=8"]
"#;

#[test]
fn kind_maps_pyproject_sections() {
    let uri = url::Url::parse("file:///project/pyproject.toml").expect("uri");
    let result = PypiParser::new()
        .parse_content(PYPROJECT, &uri)
        .expect("parse");
    let kind_of = |name: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str() == name)
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("requests"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("setuptools"), Some(DependencyKind::Build));
    assert_eq!(kind_of("sphinx"), Some(DependencyKind::Optional));
    assert_eq!(kind_of("pytest"), Some(DependencyKind::Development));
}
