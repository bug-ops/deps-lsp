# Reference Implementations

See existing implementations for reference:
- `crates/deps-cargo/` - Rust/Cargo.toml with crates.io sparse index
- `crates/deps-npm/` - JavaScript/package.json with npm registry
- `crates/deps-pypi/` - Python/pyproject.toml/poetry/requirements.txt with PyPI API and PEP 508 marker support
- `crates/deps-go/` - Go/go.mod with proxy.golang.org
- `crates/deps-bundler/` - Ruby/Gemfile with RubyGems API
- `crates/deps-dart/` - Dart/pubspec.yaml with pub.dev API
- `crates/deps-maven/` - Java/pom.xml with Maven Central (CDN metadata + Solr search)
- `crates/deps-gradle/` - Kotlin/Groovy with version catalogs and property resolution
- `crates/deps-composer/` - PHP/composer.json with Packagist V2 API
- `crates/deps-swift/` - Swift/Package.swift with GitHub API support
- `crates/deps-nuget/` - C#/.NET/.csproj/packages.config with NuGet V3 registry (SemVer2 prerelease, central package management)
- `crates/deps-deno/` - Deno/deno.json with the JSR API, delegating `npm:` specifiers to `deps-npm`'s registry client — the reference implementation for an ecosystem that dispatches across two registries from one manifest

