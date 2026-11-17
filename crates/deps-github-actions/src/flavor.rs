//! The git-tag-pinning flavors this crate serves (#575).
//!
//! GitHub Actions workflows and pre-commit hook configurations both resolve `owner/repo` pins
//! against the same GitHub tags registry, so one ecosystem type carries a flavor instead of a
//! wrapper that could silently fall back to the other flavor's defaults.

use deps_core::EcosystemId;
use deps_core::lsp_helpers::{CommentStyle, MutablePinPolicy, PinSubject};

/// Which git-tag-pinning manifest family a [`crate::GithubActionsEcosystem`] serves.
///
/// Exhaustive on purpose: every flavor-sensitive method matches it without a wildcard arm, so a
/// new flavor fails to compile until each of them has decided its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitTagsFlavor {
    /// `.github/workflows/*.yml` and `action.yml` (`uses: owner/repo@ref`).
    Actions,
    /// `.pre-commit-config.yaml` (`repo:` + `rev:`).
    PreCommit,
}

impl GitTagsFlavor {
    /// The [`EcosystemId`] diagnostics, routing and OSV gating are keyed on.
    #[must_use]
    pub const fn ecosystem_id(self) -> EcosystemId {
        match self {
            Self::Actions => EcosystemId::GithubActions,
            Self::PreCommit => EcosystemId::PreCommit,
        }
    }

    /// Human-readable ecosystem name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Actions => "GitHub Actions",
            Self::PreCommit => "pre-commit",
        }
    }

    /// Exact-basename manifest routing.
    #[must_use]
    pub const fn manifest_filenames(self) -> &'static [&'static str] {
        match self {
            Self::Actions => &["action.yml", "action.yaml"],
            Self::PreCommit => &[".pre-commit-config.yaml", ".pre-commit-config.yml"],
        }
    }

    /// Directory-suffix manifest routing.
    #[must_use]
    pub const fn manifest_directory_patterns(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Actions => &[
                (".github/workflows", ".yml"),
                (".github/workflows", ".yaml"),
            ],
            Self::PreCommit => &[],
        }
    }

    /// What a mutable-ref-pin diagnostic calls the dependency.
    #[must_use]
    pub const fn pin_subject(self) -> PinSubject {
        match self {
            Self::Actions => PinSubject::GithubAction,
            Self::PreCommit => PinSubject::PreCommitHook,
        }
    }

    /// Singular and plural noun of the "pin all to SHA" actions.
    #[must_use]
    pub const fn pin_noun(self) -> (&'static str, &'static str) {
        match self {
            Self::Actions => ("action", "actions"),
            Self::PreCommit => ("hook", "hooks"),
        }
    }

    /// The comment spelling given to a pin that had none when it is rewritten to a SHA.
    #[must_use]
    pub const fn default_comment_style(self) -> CommentStyle {
        match self {
            Self::Actions => CommentStyle::Bare,
            Self::PreCommit => CommentStyle::Frozen,
        }
    }

    /// The SHA pin comment spellings this flavor reads.
    #[must_use]
    pub const fn accepted_comment_styles(self) -> &'static [CommentStyle] {
        match self {
            Self::Actions => CommentStyle::BARE_ONLY,
            Self::PreCommit => CommentStyle::ALL,
        }
    }

    /// Which refs count as mutable.
    #[must_use]
    pub const fn mutable_pin_policy(self) -> MutablePinPolicy {
        match self {
            Self::Actions => MutablePinPolicy::AllTags,
            Self::PreCommit => MutablePinPolicy::DotlessNonHex,
        }
    }

    /// The YAML key carrying the ref: `uses` or `rev`.
    #[must_use]
    pub const fn ref_key(self) -> &'static str {
        match self {
            Self::Actions => "uses",
            Self::PreCommit => "rev",
        }
    }
}
