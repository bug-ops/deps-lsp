# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2025-12-25

### Fixed
- Inlay hints now compare against absolute latest stable version, not just matching major.minor
- Pre-release versions filtered from "newer version available" diagnostics
- Background tasks no longer exit early due to `parse_result` being lost on clone

### Changed
- Extracted `find_latest_stable()` utility for consistent version comparison across features

## [0.3.0] - 2025-12-24

### Added
- **Trait-based ecosystem architecture** — Unified handling for all package ecosystems
  - `Ecosystem` trait with parser, registry, and formatter
  - `EcosystemRegistry` for dynamic ecosystem lookup by URI
  - `LockfileProvider` trait for lock file parsing
  - Simplified document lifecycle with generic handlers

### Changed
- **Performance optimizations** — Significant latency improvements
  - Parallel registry fetching with `futures::join_all` (97% faster document open)
  - O(N log K) cache eviction algorithm with min-heap (90% faster eviction)
  - Parse-once pattern for version sorting (50% faster parsing)
  - String formatting optimization with `write!()` macro
  - Early lock release pattern with `get_document_clone()`

### Fixed
- npm: Remove extra quotes in code action version replacements (#29)

## [0.2.3] - 2025-12-23

### Changed
- CI: Use `katyo/publish-crates` for automatic workspace publishing with dependency ordering

### Fixed
- CI: Add missing `deps-pypi` to crates.io publish workflow

## [0.2.2] - 2025-12-23

### Added
- **Lock file support** — Resolved versions from lock files
  - Cargo.lock parsing with version extraction
  - package-lock.json v2/v3 parsing for npm
  - poetry.lock and uv.lock parsing for PyPI
  - Hover shows resolved version from lock file
  - Inlay hints compare resolved version vs latest
- **PyPI/pyproject.toml support** — Full ecosystem support for Python packages
  - PEP 621 format (`[project.dependencies]`)
  - PEP 735 dependency groups (`[dependency-groups]`)
  - Poetry format (`[tool.poetry.dependencies]`)
  - Package name autocomplete from PyPI registry
  - Version hints and diagnostics

### Fixed
- PyPI parser: Correct version range position for normalized specifiers (pep508 adds spaces)

## [0.2.1] - 2025-12-22

### Fixed
- CI: Skip strip for cross-compiled binaries (aarch64-linux-gnu)

### Changed
- CI: Use trusted publishing for crates.io releases (OIDC)
- Use workspace dependency for deps-core in deps-cargo and deps-npm

## [0.2.0] - 2025-12-22

### Added
- **npm/package.json support** — Full ecosystem support for npm packages
  - Package name autocomplete from npm registry
  - Version hints and diagnostics
  - Hover information with version list
- **Multi-crate architecture** — Extracted shared code into reusable crates
  - `deps-core`: Shared types, HTTP cache, error handling, traits
  - `deps-cargo`: Cargo.toml parser and crates.io registry client
  - `deps-npm`: package.json parser and npm registry client
- **UX improvements**
  - Emoji indicators for version status (✅ up-to-date, ❌ outdated)
  - Version list in hover popup with docs.rs links
  - Multiple version options in code actions (up to 5)
  - Clickable links to crates.io/npmjs.com in inlay hints
- **Performance improvements**
  - Version caching in document state
  - FULL document sync for immediate file change detection
  - Parallel version fetching

### Fixed
- npm parser: Correct position finding for dependencies sharing version string (e.g., vitest)

### Changed
- MSRV bumped to 1.89 for let-chains support
- Refactored handlers to use let-chains for cleaner code
- Extracted deps-zed to [separate repository](https://github.com/bug-ops/deps-zed) as git submodule

## [0.1.0] - 2024-12-22

### Added
- **Cargo.toml support** — Full LSP features for Rust dependencies
  - Package name autocomplete from crates.io sparse index
  - Version autocomplete with semver filtering
  - Feature flag autocomplete
  - Inlay hints showing latest available versions
  - Diagnostics for unknown, yanked, and outdated packages
  - Hover information with package metadata
  - Code actions to update dependency versions
  - Support for `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
  - Support for `[workspace.dependencies]` section
- **LSP server infrastructure**
  - tower-lsp based implementation
  - HTTP cache with ETag/Last-Modified validation
  - Document state management with DashMap
  - Configuration system with serde deserialization
  - Error types with thiserror
- **Zed extension** (deps-zed)
  - WASM-based extension for Zed editor
  - Auto-download of pre-built binaries
- **Development infrastructure**
  - Test suite with cargo-nextest
  - Code coverage with cargo-llvm-cov
  - Security scanning with cargo-deny
  - CI/CD pipeline with GitHub Actions
  - Cross-platform builds (Linux, macOS, Windows)

### Security
- Zero unsafe code blocks
- TLS enforced via rustls
- cargo-deny configured for vulnerability scanning

[Unreleased]: https://github.com/bug-ops/deps-lsp/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/bug-ops/deps-lsp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/bug-ops/deps-lsp/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/bug-ops/deps-lsp/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/bug-ops/deps-lsp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bug-ops/deps-lsp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bug-ops/deps-lsp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bug-ops/deps-lsp/releases/tag/v0.1.0
