// `PackagistRegistry::get_latest_matching`'s boxed-future coercion nests through several
// layers of `async`/`.await?` combinators; rustc's default recursion limit is occasionally
// insufficient to prove the resulting `Send` bound and downgrades a previously-silent
// trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz CI job's
// `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same class
// of fix as deps-nuget (#696), deps-swift (#673), and deps-cargo (#745).
#![recursion_limit = "256"]

//! PHP/Composer ecosystem support for deps-lsp.
//!
//! This module provides composer.json parsing and Packagist registry integration
//! for PHP projects.

pub mod ecosystem;
/// Version formatting and comparison for Composer (PHP semver-style ranges).
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
/// Domain types for Composer dependencies (parsed `composer.json` entries, Packagist versions).
pub mod types;

pub use ecosystem::ComposerEcosystem;
pub use formatter::ComposerFormatter;
pub use lockfile::ComposerLockParser;
pub use parser::{ComposerParseResult, parse_composer_json};
pub use registry::PackagistRegistry;
pub use types::{ComposerDependency, ComposerPackage, ComposerSection, ComposerVersion};
