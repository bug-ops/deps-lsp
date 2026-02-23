//! PHP/Composer ecosystem support for deps-lsp.
//!
//! This module provides composer.json parsing and Packagist registry integration
//! for PHP projects.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::ComposerEcosystem;
pub use error::{ComposerError, Result};
pub use formatter::ComposerFormatter;
pub use lockfile::ComposerLockParser;
pub use parser::{ComposerParseResult, parse_composer_json};
pub use registry::PackagistRegistry;
pub use types::{ComposerDependency, ComposerPackage, ComposerSection, ComposerVersion};
