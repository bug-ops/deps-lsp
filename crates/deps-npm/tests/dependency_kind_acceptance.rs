//! #2072 acceptance: `Dependency::kind()` for `package.json` sections (architect v2 S5 mapping).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

use deps_core::{DependencyKind, ParseResult};

const MANIFEST: &str = r#"{
  "name": "fixture",
  "dependencies": { "normal-dep": "^1.0.0" },
  "devDependencies": { "dev-dep": "^1.0.0" },
  "peerDependencies": { "peer-dep": "^1.0.0" },
  "optionalDependencies": { "optional-dep": "^1.0.0" }
}"#;

#[test]
fn kind_maps_package_json_sections() {
    let uri = url::Url::parse("file:///project/package.json").expect("uri");
    let result = deps_npm::parse_package_json(MANIFEST, &uri).expect("parse");
    let kind_of = |name: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str() == name)
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("normal-dep"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("dev-dep"), Some(DependencyKind::Development));
    assert_eq!(kind_of("peer-dep"), Some(DependencyKind::Peer));
    assert_eq!(kind_of("optional-dep"), Some(DependencyKind::Optional));
}
