# deps-nuget

[![Crates.io](https://img.shields.io/crates/v/deps-nuget)](https://crates.io/crates/deps-nuget)
[![docs.rs](https://img.shields.io/docsrs/deps-nuget)](https://docs.rs/deps-nuget)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-nuget)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

NuGet/.NET project file support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides NuGet/.NET ecosystem support including `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, and `packages.config` parsing, `packages.lock.json` lock file support, and NuGet V3 registry integration, and implements `deps_core::Ecosystem`.

## Features

- **XML parsing** — Parse `PackageReference` (attribute and child-element form), `PackageVersion`, and `packages.config` entries with byte-accurate position tracking via the `quick-xml` SAX reader
- **NuGet V3 registry** — Service index resolution, flat-container version listing, and `SearchQueryService` search (`semVerLevel=2.0.0`)
- **Version comparison** — 4-component NuGet versioning (`Major.Minor.Patch.Revision`), structural prerelease detection, interval range notation (`[1.0,2.0)`), and floating versions (`1.1.*`)
- **Central Package Management** — `Directory.Packages.props`-managed dependencies parse with no inline version, so hover/completion on the package name still work
- **Lock file support** — `packages.lock.json`, merged across target framework monikers

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Installation

```toml
[dependencies]
deps-nuget = "0.10"
```

## Usage

```rust
use deps_nuget::{parse_project_file, NuGetRegistry};

let result = parse_project_file(content, &uri)?;
let registry = NuGetRegistry::new(cache);
let versions = registry.get_versions_typed("Newtonsoft.Json").await?;
```

## Supported manifest syntax

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>
```

Central Package Management (`Directory.Packages.props`):

```xml
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
```

Legacy `packages.config`:

```xml
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
</packages>
```

> [!NOTE]
> A bare version in `PackageReference` (e.g. `Version="6.1"`) is a floor, not an exact pin. `packages.config` versions are normalized to an exact-pin range at parse time, since they carry no range syntax of their own.

## License

[MIT](../../LICENSE)
