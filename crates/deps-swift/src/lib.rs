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
pub use parser::parse_package_swift;
pub use registry::SwiftRegistry;
pub use types::{SwiftDependency, SwiftPackage, SwiftParseResult, SwiftVersion};

/// Whether `name` matches the `owner/repo` GitHub identifier shape this crate accepts:
/// `[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`, with neither segment being exactly `.`/`..` (see
/// [`deps_core::is_dot_segment`]).
///
/// Shared by `registry::validate_owner_repo` (a credential-bearing fetch-URL gate) and
/// `formatter::is_valid_owner_repo` (a display-URL gate), so the two predicates cannot
/// drift out of sync on what counts as a valid identity — `registry`'s dot-segment
/// rejection (#357) would otherwise have applied to the fetch path only, leaving
/// `formatter`'s hover link still able to render `https://github.com/apple/..`.
pub(crate) fn is_valid_github_identity(name: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$").expect("hardcoded regex is valid")
    });
    match name.split_once('/') {
        Some((owner, repo)) => {
            re.is_match(name)
                && !deps_core::is_dot_segment(owner)
                && !deps_core::is_dot_segment(repo)
        }
        None => false,
    }
}
