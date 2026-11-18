//! #2072 acceptance: `Dependency::kind()` for Gradle configurations (architect v2 S5 mapping:
//! contains `test` -> Development; `classpath`/`annotationProcessor`/`kapt`/`ksp` -> Build;
//! `*implementation|api|compileOnly|runtimeOnly|compile|runtime` -> Normal; else unknown).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const BUILD_GRADLE: &str = r"dependencies {
    implementation 'org.example:impl-lib:1.0.0'
    api 'org.example:api-lib:1.0.0'
    compileOnly 'org.example:compile-only-lib:1.0.0'
    testImplementation 'org.example:test-lib:1.0.0'
    annotationProcessor 'org.example:processor-lib:1.0.0'
}
";

#[test]
fn kind_maps_gradle_configuration_names() {
    let uri = url::Url::parse("file:///project/build.gradle").expect("uri");
    let result = deps_gradle::parse_gradle(BUILD_GRADLE, &uri).expect("parse");
    let kind_of = |needle: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str().contains(needle))
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("impl-lib"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("api-lib"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("compile-only-lib"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("test-lib"), Some(DependencyKind::Development));
    assert_eq!(kind_of("processor-lib"), Some(DependencyKind::Build));
}
