// `SwiftRegistry::get_versions`'s boxed-future coercion nests through several layers of
// `tokio::join!`/`MaybeDone` combinators; rustc's default recursion limit is occasionally
// insufficient to prove the resulting `Send` bound and downgrades a previously-silent
// trait-solver retry into `recursion_depth_exceeding_limit`, which the new #673 fuzz CI
// job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228).
#![recursion_limit = "256"]

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
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::SwiftEcosystem;
pub use formatter::SwiftFormatter;
pub use lockfile::SwiftLockParser;
pub use parser::{SwiftParseResult, parse_package_swift};
pub use registry::SwiftRegistry;
pub use types::{SwiftDependency, SwiftPackage, SwiftVersion};

/// Whether `name` matches the `owner/repo` GitHub identifier shape this crate accepts.
///
/// Shared by `registry::validate_owner_repo` (a credential-bearing fetch-URL gate) and
/// `formatter::is_valid_owner_repo` (a display-URL gate), so the two predicates cannot
/// drift out of sync on what counts as a valid identity. Delegates to
/// [`deps_core::github::is_valid_github_identity`], shared with `deps-github-actions`
/// (#472).
pub(crate) fn is_valid_github_identity(name: &str) -> bool {
    deps_core::github::is_valid_github_identity(name)
}
