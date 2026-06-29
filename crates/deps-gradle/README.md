# deps-gradle

[![Crates.io](https://img.shields.io/crates/v/deps-gradle)](https://crates.io/crates/deps-gradle)
[![docs.rs](https://img.shields.io/docsrs/deps-gradle)](https://docs.rs/deps-gradle)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-gradle)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Gradle build system support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the Gradle ecosystem and implements `deps_core::Ecosystem`.

## Features

- **Version Catalog** — Parse `gradle/libs.versions.toml` with `[versions]`, `[libraries]`, and `[plugins]` sections
- **Kotlin DSL** — Parse `build.gradle.kts` dependency declarations
- **Groovy DSL** — Parse `build.gradle` dependency declarations
- **Multi-registry** — Resolves from Maven Central, Google Maven, and Gradle Plugin Portal
- **Maven version comparison** — Full qualifier-aware comparison (`alpha`, `beta`, `RC`, `SNAPSHOT`)
- **Configuration awareness** — Recognises `implementation`, `api`, `testImplementation`, and other Gradle configurations

> [!NOTE]
> Registry integration reuses `deps_maven::MavenCentralRegistry`. Gradle dependencies use the `groupId:artifactId` identifier format.

## Installation

```toml
[dependencies]
deps-gradle = "0.9.4"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_gradle::{parse_gradle, GradleEcosystem};

let result = parse_gradle(content, &uri)?;
```

## Supported manifest formats

### Version Catalog (`gradle/libs.versions.toml`)

```toml
[versions]
agp = "8.3.0"
kotlin = "1.9.22"

[libraries]
androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "agp" }
retrofit = { module = "com.squareup.retrofit2:retrofit", version = "2.9.0" }

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
```

### Kotlin DSL (`build.gradle.kts`)

```kotlin
dependencies {
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
}
```

### Groovy DSL (`build.gradle`)

```groovy
dependencies {
    implementation 'com.squareup.retrofit2:retrofit:2.9.0'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
}
```

## License

[MIT](../../LICENSE)
