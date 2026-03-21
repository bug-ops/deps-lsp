# deps-maven

[![Crates.io](https://img.shields.io/crates/v/deps-maven)](https://crates.io/crates/deps-maven)
[![docs.rs](https://img.shields.io/docsrs/deps-maven)](https://docs.rs/deps-maven)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-maven)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

pom.xml support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides Maven/JVM ecosystem support including pom.xml parsing, dependency extraction, and Maven Central registry integration, and implements `deps_core::Ecosystem`.

## Features

- **XML parsing** — Parse `pom.xml` with byte-accurate position tracking via the `quick-xml` SAX reader
- **Dependency sections** — Handle `<dependencies>`, `<dependencyManagement>`, and `<build><plugins>` blocks
- **Maven Central registry** — Solr API client for version lookups and artifact search
- **Version comparison** — Maven version qualifier support (`alpha`, `beta`, `RC`, `SNAPSHOT`, `GA`)
- **Property resolution** — Resolve `${property}` placeholders defined in `<properties>`
- **Scope handling** — Recognise `compile`, `test`, `provided`, `runtime`, and `import` scopes

## Installation

```toml
[dependencies]
deps-maven = "0.9.2"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_maven::{parse_pom_xml, MavenCentralRegistry};

let result = parse_pom_xml(content, &uri)?;
let registry = MavenCentralRegistry::new(cache);
let versions = registry.get_versions_typed("org.springframework:spring-core").await?;
```

## Supported pom.xml syntax

```xml
<project>
  <properties>
    <spring.version>6.1.0</spring.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>3.2.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.12.1</version>
      </plugin>
    </plugins>
  </build>
</project>
```

## License

[MIT](../../LICENSE)
