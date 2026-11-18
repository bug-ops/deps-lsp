//! #2072 acceptance: `Dependency::kind()` for pom scopes (architect v2 S5 mapping).
//! Written tests-first; `Dependency::kind` and `deps_core::DependencyKind` do not exist yet.

#![allow(clippy::expect_used)]

use deps_core::{DependencyKind, ParseResult};

const POM: &str = r"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>fixture</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>compile-lib</artifactId>
      <version>2.0.9</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>test-lib</artifactId>
      <version>5.10.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>provided-lib</artifactId>
      <version>6.0.0</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>";

#[test]
fn kind_maps_maven_scopes() {
    let uri = url::Url::parse("file:///project/pom.xml").expect("uri");
    let result = deps_maven::parse_pom_xml(POM, &uri).expect("parse");
    let kind_of = |needle: &str| {
        result
            .dependencies()
            .into_iter()
            .find(|dep| dep.name().as_str().contains(needle))
            .expect("parsed")
            .kind()
    };

    assert_eq!(kind_of("compile-lib"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("provided-lib"), Some(DependencyKind::Normal));
    assert_eq!(kind_of("test-lib"), Some(DependencyKind::Development));
}
