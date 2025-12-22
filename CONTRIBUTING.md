# Contributing to deps-lsp

Thank you for your interest in contributing to deps-lsp!

## Development Setup

### Prerequisites

- Rust 1.85+ (Edition 2024)
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

## Code Style

### Formatting

```bash
cargo +nightly fmt
```

### Linting

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

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
