//! pubspec.yaml parsing and pub.dev integration.
//!
//! This crate provides Dart/Pub ecosystem support for the deps-lsp server,
//! including pubspec.yaml parsing, dependency extraction, and pub.dev
//! registry integration.

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
pub mod version;

pub use ecosystem::DartEcosystem;
pub use formatter::DartFormatter;
pub use lockfile::PubspecLockParser;
pub use parser::{DartParseResult, parse_pubspec_yaml};
pub use registry::{PubDevRegistry, package_url};
pub use types::{DartDependency, DartVersion, DependencySection, DependencySource, PackageInfo};
