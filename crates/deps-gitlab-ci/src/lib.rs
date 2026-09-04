//! GitLab CI/CD ecosystem support for deps-lsp.
//!
//! Provides LSP features for `.gitlab-ci.yml` and `.gitlab/ci/*.yml`/`*.yaml` files.
//!
//! `include: - project: org/proj` + `ref:` pins are resolved against the GitLab
//! repository-tags API. `include: - component: host/org/proj/name@ref` pins are resolved
//! against the GitLab CI/CD Catalog's project-releases API — a component version *is* a
//! Release, never a raw tag. Self-hosted GitLab instances are supported via
//! `registries.gitlab_instance_host`.
//!
//! # Pin contract
//!
//! | Include form | `pin` | Resolved against |
//! |---|---|---|
//! | `project: org/proj` + `ref: <40-hex sha>` | [`types::PinStyle::Sha`] | `/repository/tags` |
//! | `project: org/proj` + `ref: v1.2.3` (exact tag) | [`types::PinStyle::Tag`] | `/repository/tags` |
//! | `project: org/proj` + `ref: main` (branch) | [`types::PinStyle::Branch`] | not resolved |
//! | `project: org/proj` (no `ref:`) | `None` | not resolved |
//! | `component: host/org/proj/name@<40-hex sha>` | [`types::PinStyle::Sha`] | `/releases` |
//! | `component: host/org/proj/name@1.0` (exact release) | [`types::PinStyle::Tag`] | `/releases` |
//! | `component: host/org/proj/name@~latest` | [`types::PinStyle::Latest`] | `/releases` |
//! | `component: host/org/proj/name@1.2` (partial semver) | [`types::PinStyle::Partial`] | `/releases` |
//! | `component: host/org/proj/name@some-branch` | [`types::PinStyle::Branch`] | not resolved |
//!
//! `include: - template: ...` and `include: - remote: ...` are recognized and skipped
//! (spec FR-003) — not version-pinnable. `image:`/`services:` Docker tags are out of scope
//! entirely (spec FR-016) and never parsed.

pub mod client;
pub mod component;
pub mod ecosystem;
pub mod formatter;
pub mod host;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::GitlabCiEcosystem;
pub use formatter::GitlabCiFormatter;
pub use host::{GitlabHost, GitlabInstanceHost, is_valid_gitlab_coordinate};
pub use parser::parse_gitlab_ci_yaml;
pub use registry::GitlabCiRegistry;
pub use types::{
    EndpointKind, GitlabCiDependency, GitlabCiParseResult, GitlabCiVersion, HostRef, IncludeKind,
    PinStyle,
};

/// Stable [`tower_lsp_server::ls_types::Diagnostic::code`] for the FR-012 informational
/// unresolved-host diagnostic.
///
/// Local to this crate rather than a shared `deps-core` diagnostic kind — mirrors
/// `deps_github_actions::MUTABLE_REF_PIN_DIAGNOSTIC_CODE`'s precedent of a crate-local
/// stable code for a crate-specific diagnostic.
pub const UNRESOLVED_HOST_DIAGNOSTIC_CODE: &str = "unresolved-gitlab-host";
