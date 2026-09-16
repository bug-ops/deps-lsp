// `get_versions`'s boxed-future coercion nests deep enough through `tokio::join!`/`MaybeDone`
// that rustc's default recursion limit can fail to prove the `Send` bound, which the #673 fuzz
// CI's `-D warnings` build turns into a hard error (rust-lang/rust#159228).
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

/// Whether `host` is GitHub's own hostname (case-insensitive).
///
/// Shared by `parser::url_to_identity` (a credential-bearing fetch-URL gate: only a
/// `github.com` URL may be turned into an `owner/repo` identity queried against the GitHub
/// API, #979) and `formatter::osv_package_name` (an advisory-attribution gate), so the two
/// predicates cannot drift out of sync on what counts as GitHub. A plain string match (e.g.
/// `host.ends_with("github.com")`) would accept attacker-owned hosts like
/// `github.com.evil.com` — callers must pass the fully-parsed host component (`Url::host_str`),
/// never a raw URL string.
pub(crate) fn is_github_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("www.github.com")
}
