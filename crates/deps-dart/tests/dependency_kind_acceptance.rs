//! #2072 acceptance: `Dependency::kind()` for `pubspec.yaml` sections (architect v2 S5 mapping).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const PUBSPEC: &str = "name: fixture
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  http: ^1.0.0
dev_dependencies:
  test: ^1.24.0
dependency_overrides:
  path: ^1.8.0
";

#[test]
fn kind_maps_pubspec_sections_and_leaves_overrides_unknown() {
    let uri = url::Url::from_file_path("/project/pubspec.yaml").expect("uri");
    let result = deps_dart::parse_pubspec_yaml(PUBSPEC, &uri).expect("parse");
    let kind_of = |name: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str() == name)
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("http"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("test"), Some(DependencyKind::Development));
    assert_eq!(kind_of("path"), None);
}
