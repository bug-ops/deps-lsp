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
- `crates/deps-github-actions/` - GitHub Actions/`.github/workflows/*.yml`+`action.yml` with the
  GitHub tags API — the reference implementation for a **CI/CD pinning** ecosystem (no package
  registry, `manifest_directory_patterns()` instead of exact filenames, mutable-ref-vs-SHA
  pinning diagnostics) rather than a language package manager
- `crates/deps-gitlab-ci/` - GitLab CI/CD/`.gitlab-ci.yml` with the GitLab tags/releases API —
  the second CI/CD pinning reference implementation, plus YAML anchor/alias resolution and
  self-hosted-instance host configuration

