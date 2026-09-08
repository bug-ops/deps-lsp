//! npm ecosystem support for deps-lsp.
//!
//! This module provides package.json parsing and npm registry integration
//! for JavaScript/TypeScript projects.

// #673: restriction lints, scoped to this crate only via a source attribute (overrides
// this crate's `[lints] workspace = true` Cargo.toml table regardless of that table's
// level) rather than a duplicated `[lints.clippy]` table — avoids ~90 lines of
// drift-prone duplication of the workspace allow-list. Deliberately never added to
// `[workspace.lints.clippy]` itself (must stay opt-in per crate, not workspace-wide).
// Sites confirmed safe are individually `#[allow]`ed with a one-line justification.
// #680: `clippy::string_slice` appended to the same restriction-lint attribute for the
// same reason — string slicing on a byte index that isn't a verified char boundary
// panics; sites confirmed boundary-safe by construction are individually `#[allow]`ed.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]

pub mod catalog;
pub mod config;
pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use catalog::{CatalogOrigin, CatalogOutcome, PnpmWorkspaceCache};
pub use config::{NpmConfig, NpmConfigCache, NpmParseContext, NpmRegistryIndex};
pub use ecosystem::NpmEcosystem;
pub use formatter::NpmFormatter;
pub use lockfile::NpmLockParser;
pub use parser::{NpmParseResult, parse_package_json, parse_package_json_with_context};
pub use registry::{NpmRegistry, package_url};
pub use types::{NpmDependency, NpmDependencySection, NpmPackage, NpmVersion};

pub type NpmVersionReq = node_semver::Range;
