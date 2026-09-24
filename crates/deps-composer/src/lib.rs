// Boxed-future `Send`-bound proof for `get_latest_matching`'s async chain occasionally
// exceeds rustc's default recursion limit, turning a silent trait-solver retry into a hard
// `-D warnings` error on the fuzz CI job (rust-lang/rust#159228). Same fix as deps-nuget
// (#696), deps-swift (#673), and deps-cargo (#745).
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
// Wrapper exposed only under non-default `fuzzing` feature (#1404) so `fuzz/`'s
// `json_lockfiles` target can reach the otherwise-private lock-file parser; mirrors
// `deps-gradle`'s `fuzz_parse_pom_licenses`.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_composer_lock;
pub use parser::{ComposerParseResult, parse_composer_json};
pub use registry::{PackagistRegistry, package_url};
pub use types::{ComposerDependency, ComposerPackage, ComposerSection, ComposerVersion};
