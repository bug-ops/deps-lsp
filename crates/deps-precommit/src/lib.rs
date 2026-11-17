//! pre-commit hook dependency support for deps-lsp (#575, spec 044).
//!
//! Constructor-only: the pre-commit ecosystem is [`GithubActionsEcosystem`] built with
//! [`GitTagsFlavor::PreCommit`], because a hook `repo:` + `rev:` pair resolves against the same
//! GitHub tags registry as a workflow `uses:` step. The parser lives in `deps-github-actions`
//! (this crate depends on it, not the other way round).
//!
//! The shared registry's `github-actions` log and circuit-breaker attribution covers both
//! flavors, since they hit the same endpoint.

use std::sync::Arc;

use deps_core::HttpCache;
use deps_github_actions::{GitTagsFlavor, GithubActionsEcosystem, GithubActionsRegistry};

/// A pre-commit ecosystem over a registry shared with the GitHub Actions ecosystem, so the
/// two reuse one cache, rate gate, request coalescing and tag index.
#[must_use]
pub fn ecosystem(registry: Arc<GithubActionsRegistry>) -> GithubActionsEcosystem {
    GithubActionsEcosystem::with_registry(registry, GitTagsFlavor::PreCommit)
}

/// A pre-commit ecosystem with its own registry, for builds without the `github-actions`
/// feature.
#[must_use]
pub fn standalone(cache: Arc<HttpCache>) -> GithubActionsEcosystem {
    ecosystem(Arc::new(GithubActionsRegistry::new(cache)))
}
