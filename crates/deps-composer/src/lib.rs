//! PHP/Composer ecosystem support for deps-lsp.
//!
//! This module provides composer.json parsing and Packagist registry integration
//! for PHP projects.

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
#![warn(clippy::string_slice)]

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
