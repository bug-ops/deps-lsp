//! #2072 acceptance: `Dependency::kind()` for `composer.json` sections (architect v2 S5
//! mapping). Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not
//! exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const MANIFEST: &str = r#"{
  "name": "vendor/fixture",
  "require": { "monolog/monolog": "^3.0" },
  "require-dev": { "phpunit/phpunit": "^10.0" }
}"#;

#[test]
fn kind_maps_require_and_require_dev() {
    let uri = url::Url::parse("file:///project/composer.json").expect("uri");
    let result = deps_composer::parse_composer_json(MANIFEST, &uri).expect("parse");
    let kind_of = |name: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str() == name)
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("monolog/monolog"), Some(DependencyKind::Normal));
    assert_eq!(
        kind_of("phpunit/phpunit"),
        Some(DependencyKind::Development)
    );
}
