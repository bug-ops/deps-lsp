//! Swift Package Manager ecosystem support for deps-lsp.
//!
//! Provides LSP features for `Package.swift` files:
//! - Version autocomplete from GitHub tags
//! - Inlay hints showing latest versions
//! - Hover tooltips with package metadata
//! - Code actions to update versions
//! - Diagnostics for unknown packages
//!
//! Uses regex-based parsing (no Swift toolchain required) and GitHub API
//! for package discovery. Compatible with WASM (Zed extension) targets.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::SwiftEcosystem;
pub use error::SwiftError;
pub use formatter::SwiftFormatter;
pub use lockfile::SwiftLockParser;
pub use parser::parse_package_swift;
pub use registry::SwiftRegistry;
pub use types::{SwiftDependency, SwiftPackage, SwiftParseResult, SwiftVersion};
