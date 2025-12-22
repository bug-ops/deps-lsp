# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 1: Cargo.toml parser implementation (in progress)

## [0.1.0] - 2024-12-22

### Added
- Initial project infrastructure (Phase 0)
- LSP server scaffolding with tower-lsp
- HTTP cache with ETag/Last-Modified validation
- Document state management with DashMap
- Configuration system with serde deserialization
- Error types with thiserror
- Cargo.toml type definitions with position tracking
- Zed extension scaffolding (deps-zed)
- Test infrastructure with cargo-nextest
- Code coverage with cargo-llvm-cov (87% coverage)
- Security scanning with cargo-deny
- CI/CD pipeline with GitHub Actions

### Security
- Zero unsafe code blocks
- TLS enforced via rustls
- cargo-deny configured for vulnerability scanning

[Unreleased]: https://github.com/bug-ops/deps-lsp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bug-ops/deps-lsp/releases/tag/v0.1.0
