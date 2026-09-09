//! NuGet/.NET project file parsing and registry integration.
//!
//! This crate provides NuGet ecosystem support for the deps-lsp server, including
//! `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, and `packages.config`
//! parsing, `packages.lock.json` lock file support, and NuGet V3 registry integration.

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
// #683: the three remaining #673 restriction lints, scoped to this crate only via a source
// attribute (which overrides this crate's `[lints] workspace = true` Cargo.toml table
// regardless of that table's level) rather than a duplicated `[lints.clippy]` table — avoids
// ~90 lines of drift-prone duplication of the workspace allow-list. Deliberately never added
// to `[workspace.lints.clippy]` itself (must stay opt-in per crate, not workspace-wide).
// Sites confirmed safe are individually `#[allow]`ed with a one-line justification.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]

pub mod config;
pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

pub use ecosystem::NuGetEcosystem;
pub use formatter::NuGetFormatter;
pub use lockfile::NuGetLockParser;
pub use parser::{parse_directory_packages_props, parse_packages_config, parse_project_file};
pub use registry::NuGetRegistry;
pub use types::{NuGetDependency, NuGetParseResult, NuGetVersion, PackageInfo};
