# Ecosystem Templates

This directory contains template files for creating new ecosystem support in deps-lsp.

## Quick Start

1. Copy the `deps-ecosystem/` directory to `crates/deps-{your-ecosystem}/`
2. Rename all `.template` files to `.rs` (or `.toml`)
3. Replace placeholders throughout all files:

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{ECOSYSTEM}` | Lowercase identifier | `maven`, `go`, `nuget` |
| `{ECOSYSTEM_SNAKE}` | Snake_case identifier | `maven`, `go_modules`, `nuget` |
| `{ECOSYSTEM_PASCAL}` | PascalCase identifier | `Maven`, `GoModules`, `Nuget` |
| `{ECOSYSTEM_DISPLAY}` | Human-readable name | `Maven`, `Go Modules`, `NuGet` |
| `{MANIFEST_FILE}` | Manifest filename | `pom.xml`, `go.mod`, `packages.config` |
| `{REGISTRY_NAME}` | Registry name | `Maven Central`, `proxy.golang.org`, `NuGet.org` |
| `{REGISTRY_URL}` | Registry API URL | `https://search.maven.org/...` |

4. Implement the TODO sections in each file
5. Add your crate to the workspace in `Cargo.toml`
6. Register your ecosystem in `deps-lsp/src/document.rs`

## File Structure

```
deps-ecosystem/
├── Cargo.toml.template    # Crate manifest
└── src/
    ├── lib.rs.template        # Module exports
    ├── error.rs.template      # Error types
    ├── types.rs.template      # Dependency/Version types
    ├── parser.rs.template     # Manifest parser (IMPORTANT!)
    ├── registry.rs.template   # Package registry client
    └── ecosystem.rs.template  # Main Ecosystem trait impl
```

## Key Implementation Notes

### Parser (parser.rs)

**Critical**: Position tracking must be accurate for LSP features to work.

- Use `LineOffsetTable` for byte offset → LSP Position conversion
- Track **both** name and version positions for every dependency
- Test position accuracy with multiline manifests

### Registry (registry.rs)

- Always use `urlencoding::encode()` for package names in URLs
- Return versions sorted newest-first
- Mark yanked/deprecated versions with `is_yanked()`

### Ecosystem (ecosystem.rs)

- Implement version comparison logic for `is_up_to_date` in inlay hints
- Format version strings according to ecosystem conventions in code actions

## Documentation

See [ECOSYSTEM_GUIDE.md](../docs/ECOSYSTEM_GUIDE.md) for detailed implementation instructions.

## Testing

Run the full test suite after implementing:

```bash
cargo test --package deps-{your-ecosystem}
cargo clippy --package deps-{your-ecosystem}
```
