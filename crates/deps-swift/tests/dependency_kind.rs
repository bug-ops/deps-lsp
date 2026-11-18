//! #2072: every `Package.swift` package dependency is a production dependency.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

#[test]
fn kind_is_normal_for_every_package() {
    let uri = url::Url::parse("file:///project/Package.swift").expect("uri");
    let manifest = r#"// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
    ]
)
"#;
    let result = deps_swift::parse_package_swift(manifest, &uri).expect("parse");

    let dependencies = result.dependencies();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].kind(), Some(DependencyKind::Normal));
}
