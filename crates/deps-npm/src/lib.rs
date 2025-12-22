//! npm ecosystem support for deps-lsp.
//!
//! This module provides package.json parsing and npm registry integration
//! for JavaScript/TypeScript projects.

pub mod parser;
pub mod registry;
pub mod types;

pub use parser::{NpmParseResult, parse_package_json};
pub use registry::{NpmRegistry, package_url};
pub use types::{NpmDependency, NpmDependencySection, NpmPackage, NpmVersion};
