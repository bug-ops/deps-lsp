// `NuGetRegistry::unlisted_versions`'s boxed-future coercion in
// `NuGetEcosystem::generate_hover` nests through several layers of `tokio::join!`/
// `MaybeDone` combinators; rustc's default recursion limit is occasionally insufficient to
// prove the resulting `Send` bound and downgrades a previously-silent trait-solver retry
// into `recursion_depth_exceeding_limit`, which the fuzz CI job's `-D warnings` nightly
// build turns into a hard error (rust-lang/rust#159228). Same fix as deps-swift (#673).
#![recursion_limit = "256"]

//! NuGet/.NET project file parsing and registry integration.
//!
//! This crate provides NuGet ecosystem support for the deps-lsp server, including
//! `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, and `packages.config`
//! parsing, `packages.lock.json` lock file support, and NuGet V3 registry integration.

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
// Wrapper exposed only under non-default `fuzzing` feature (#1404) so `fuzz/`'s
// `json_lockfiles` target can reach the otherwise-private lock-file parser; mirrors
// `deps-gradle`'s `fuzz_parse_pom_licenses`.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_packages_lock_json;
pub use parser::{
    NuGetParseResult, parse_directory_packages_props, parse_packages_config, parse_project_file,
};
pub use registry::{NuGetRegistry, package_url};
pub use types::{NuGetDependency, NuGetVersion, PackageInfo};
