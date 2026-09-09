//! PHP/Composer ecosystem support for deps-lsp.
//!
//! This module provides composer.json parsing and Packagist registry integration
//! for PHP projects.

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

pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::ComposerEcosystem;
pub use formatter::ComposerFormatter;
pub use lockfile::ComposerLockParser;
pub use parser::{ComposerParseResult, parse_composer_json};
pub use registry::PackagistRegistry;
pub use types::{ComposerDependency, ComposerPackage, ComposerSection, ComposerVersion};
