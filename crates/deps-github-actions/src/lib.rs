//! GitHub Actions ecosystem support for deps-lsp.
//!
//! Provides LSP features for `.github/workflows/*.yml`/`*.yaml` files:
//! - Version autocomplete and hover for `uses: owner/repo@ref` steps
//! - Diagnostics and code actions for outdated tag pins and SHA-with-comment pins
//! - GitHub tags API for version discovery, with per-repository commit SHA resolution
//!
//! # Pin contract
//!
//! | `uses:` form | `version_range` spans | `version_requirement()` | `version_literal()` |
//! |---|---|---|---|
//! | `actions/checkout@v4` | `v4` | `v4` | `None` |
//! | `…@v4.2.0` / `…@4.2.0` | the tag | same | `None` |
//! | `…@<40hex> # v4.2.0` | `<40hex> # v4.2.0` | `v4.2.0` (from the comment) | the raw span |
//! | `…@<40hex>` (no comment) | `<40hex>` | `<40hex>` | `None` |
//! | `…@main` | `main` | `main` | `None` |
//! | `./local`, `docker://x:1`, a reusable-workflow call | `None` | `None` | `None` |
//!
//! Reusable-workflow calls (`owner/repo/.github/workflows/x.yml@ref`) are recognized and
//! their `owner/repo` truncated for display, but treated as non-resolvable — same shape as
//! `./local`/`docker://` — because the referenced workflow's version and the host repo's
//! release tags are not reliably the same thing (see `parser` module docs).

pub mod ecosystem;
pub mod formatter;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::GithubActionsEcosystem;
pub use formatter::GithubActionsFormatter;
pub use parser::parse_workflow_yaml;
pub use registry::GithubActionsRegistry;
pub use types::{
    GithubActionsDependency, GithubActionsParseResult, GithubActionsVersion, PinStyle,
};

/// Whether `name` matches the `owner/repo` GitHub identifier shape this crate accepts:
/// `[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`, with neither segment being exactly `.`/`..` (see
/// [`deps_core::is_dot_segment`]).
///
/// Shared by `registry::validate_owner_repo` (a credential-bearing fetch-URL gate) and
/// `formatter::GithubActionsFormatter::package_url` (a display-URL gate) — precedent:
/// `deps_swift::is_valid_github_identity` (`crates/deps-swift/src/lib.rs`), which this
/// mirrors so both GitHub-API-backed crates share one URL-injection gate shape.
///
/// # Examples
///
/// ```
/// use deps_github_actions::is_valid_github_identity;
///
/// assert!(is_valid_github_identity("actions/checkout"));
/// assert!(!is_valid_github_identity("not-a-valid-identifier"));
/// assert!(!is_valid_github_identity("owner/.."));
/// ```
#[must_use]
pub fn is_valid_github_identity(name: &str) -> bool {
    let Some((owner, repo)) = name.split_once('/') else {
        return false;
    };
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return false;
    }
    let charset_ok = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    charset_ok(owner)
        && charset_ok(repo)
        && !deps_core::is_dot_segment(owner)
        && !deps_core::is_dot_segment(repo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_github_identity_accepts_owner_repo() {
        assert!(is_valid_github_identity("actions/checkout"));
        assert!(is_valid_github_identity("org.name/repo_name-v2"));
    }

    #[test]
    fn test_is_valid_github_identity_rejects_malformed() {
        assert!(!is_valid_github_identity("no-slash"));
        assert!(!is_valid_github_identity(""));
        assert!(!is_valid_github_identity("owner/repo/extra"));
        assert!(!is_valid_github_identity("owner/ repo"));
        assert!(!is_valid_github_identity("../../etc/passwd"));
    }

    #[test]
    fn test_is_valid_github_identity_rejects_dot_segment() {
        assert!(!is_valid_github_identity("owner/.."));
        assert!(!is_valid_github_identity("owner/."));
        assert!(!is_valid_github_identity("../repo"));
        assert!(!is_valid_github_identity("./repo"));
    }
}
