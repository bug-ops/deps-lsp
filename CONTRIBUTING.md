# Contributing to deps-lsp

Thank you for your interest in contributing to deps-lsp!

## Development Setup

### Prerequisites

- Rust 1.98+ (Edition 2024)
- Nightly toolchain for formatting (`cargo +nightly fmt`)
- cargo-nextest (`cargo install cargo-nextest`)
- cargo-llvm-cov (`cargo install cargo-llvm-cov`)
- cargo-deny (`cargo install cargo-deny`)

### Getting Started

```bash
git clone https://github.com/bug-ops/deps-lsp
cd deps-lsp
cargo build --workspace
cargo nextest run
```

## MSRV policy

The minimum supported Rust version is `rust-version` in the root `Cargo.toml`.

- The MSRV trails the latest stable release by at least two releases (N-2).
- An MSRV bump is a breaking change for consumers of the published crates and goes under `### Breaking` in `CHANGELOG.md`.
- Bump triggers (see #549): a resolved dependency's `rust-version` exceeds the MSRV; new code needs an API whose pre-MSRV form is a correctness or safety liability; or the number of cosmetic simplification sites justifies the churn.

Bump checklist, update every mirror in one PR:

- `Cargo.toml` `[workspace.package]` `rust-version` (the CI `msrv` job follows it)
- `README.md` badge and setup line
- `crates/*/README.md` "Requires Rust X or later" lines, including `deps-precommit`
- `CONTRIBUTING.md` prerequisites
- `CHANGELOG.md`

## Code Style

### Formatting

```bash
cargo +nightly fmt
```

### Linting

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

CI also runs a feature-matrix job (`cargo hack clippy --workspace --each-feature
--no-dev-deps`) that lints each ecosystem feature flag on its own, and reduced
feature sets in general — a warning that only appears with a single feature
enabled (e.g. an unused parameter that's only used when other ecosystems are
also compiled in) is invisible to the `--all-features` command above. Run the
same command locally before adding or changing a feature flag.

### API & Style Guidelines

Public APIs in this project must follow:

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) — naming
  conventions, trait implementations, interoperability, documentation, and
  predictability for public types and functions.
- [Microsoft's Rust Guidelines](https://microsoft.github.io/rust-guidelines/) —
  additional conventions for error handling, `unsafe` code, async APIs, and
  dependability that build on the guidelines above.

Conventions enforced specifically in this project:

- every `pub` type, trait, function, and method has a `///` doc comment;
  non-trivial public APIs include a runnable `# Examples` doctest
- errors are typed enums via `thiserror`, with a `# Errors` section on every
  fallible public function
- `unsafe_code = "forbid"` at the workspace level — no `unsafe` blocks
- async trait methods use native Edition 2024 syntax — do not add the
  `async-trait` crate unless it is already a workspace dependency
- logging goes through `tracing`, never `log`

## Testing

```bash
# Run all tests
cargo nextest run

# Run with coverage
cargo llvm-cov nextest

# Generate HTML report
cargo llvm-cov nextest --html
```

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Maintenance

Example: `feat(cargo): add version completion`

## Pull Request Process

1. Fork and create branch from `main`
2. Write code following style guidelines
3. Add tests for new functionality
4. Ensure all tests pass
5. Open PR with clear description

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
