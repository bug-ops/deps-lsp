//! Binding of `GITLAB_TOKEN` to the one host it may be sent to.
//!
//! LSP settings carry no provenance (editors merge user and repository settings), so the
//! credential's destination must come from the same trust tier as the credential itself: the
//! process environment. `registries.gitlab_instance_host` therefore never receives the token.

use deps_core::net_policy::{IndexUrlError, RedactedUrl};
use deps_core::secret::ApiToken;

use crate::host::GitlabHost;

/// Environment variable holding the `GITLAB_TOKEN` credential.
pub const GITLAB_TOKEN_ENV: &str = "GITLAB_TOKEN";

/// Environment variable naming the single self-hosted GitLab host `GITLAB_TOKEN` is sent to
/// (a bare hostname, like `registries.gitlab_instance_host`). Unset means `gitlab.com`.
pub const GITLAB_TOKEN_HOST_ENV: &str = "GITLAB_TOKEN_HOST";

/// A `GITLAB_TOKEN` together with the only host it may be attached to.
///
/// Built once from the environment by [`Self::from_env`]; nothing a workspace file or editor
/// setting supplies can alter it.
#[derive(Debug, Clone)]
pub(crate) enum TokenBinding {
    /// No `GITLAB_TOKEN` is configured.
    Absent,
    /// The token may be sent to `host` and nowhere else.
    Bound {
        /// The credential.
        token: ApiToken,
        /// The host the credential is bound to.
        host: GitlabHost,
    },
    /// A token is configured but `GITLAB_TOKEN_HOST` is invalid; the token is never sent, and
    /// never falls back to `gitlab.com`.
    Disabled,
}

impl TokenBinding {
    /// Reads `GITLAB_TOKEN` and `GITLAB_TOKEN_HOST` from the process environment.
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// [`Self::from_env`] over an injectable variable lookup, so the variable names and the
    /// empty-value rules are testable without mutating the process environment (`set_var` is
    /// `unsafe` and forbidden workspace-wide).
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let token = lookup(GITLAB_TOKEN_ENV)
            .filter(|t| !t.is_empty())
            .map(ApiToken::new);
        let host = lookup(GITLAB_TOKEN_HOST_ENV);
        Self::from_values(token, host.as_deref())
    }

    /// Pure core of [`Self::from_env`].
    ///
    /// An empty or whitespace-only `host` is treated as unset (CI templates export empty
    /// variables when the source is undefined), so the token binds to `gitlab.com`. A host
    /// with a trailing dot is rejected rather than normalized: the request side compares
    /// origins byte-for-byte, so a dotted spelling could never match and would only mislead.
    pub(crate) fn from_values(token: Option<ApiToken>, host: Option<&str>) -> Self {
        let Some(token) = token else {
            return Self::Absent;
        };
        let host = host.map(str::trim).filter(|h| !h.is_empty());
        let Some(raw) = host else {
            return Self::Bound {
                token,
                host: GitlabHost::gitlab_com(),
            };
        };
        let parsed = if raw.ends_with('.') {
            Err(IndexUrlError::InvalidUrl(RedactedUrl::new(raw)))
        } else {
            GitlabHost::parse_trusted(raw)
        };
        match parsed {
            Ok(host) => Self::Bound { token, host },
            Err(error) => {
                tracing::warn!(
                    %error,
                    value = %RedactedUrl::new(raw),
                    "{GITLAB_TOKEN_HOST_ENV} is invalid; GITLAB_TOKEN will not be sent to any host"
                );
                Self::Disabled
            }
        }
    }

    /// The token, only when `host` is the bound host.
    pub(crate) fn token_for(&self, host: &GitlabHost) -> Option<&ApiToken> {
        match self {
            Self::Absent | Self::Disabled => None,
            Self::Bound { token, host: bound } => (bound == host).then_some(token),
        }
    }

    /// The token, only when `origin` is the bound origin.
    pub(crate) fn token_for_origin(&self, origin: &str) -> Option<&ApiToken> {
        match self {
            Self::Absent | Self::Disabled => None,
            Self::Bound { token, host } => (host.origin() == origin).then_some(token),
        }
    }

    /// The origin the token is bound to, when one is usable.
    pub(crate) fn bound_origin(&self) -> Option<&str> {
        self.bound_host().map(GitlabHost::origin)
    }

    /// The host the token is bound to, when one is usable.
    pub(crate) const fn bound_host(&self) -> Option<&GitlabHost> {
        match self {
            Self::Bound { host, .. } => Some(host),
            Self::Absent | Self::Disabled => None,
        }
    }

    /// Test-only: binds `token` to `origin` directly, bypassing the environment.
    #[cfg(test)]
    pub(crate) fn for_test(token: &str, origin: &str) -> Self {
        Self::Bound {
            token: ApiToken::new(token.to_string()),
            host: GitlabHost::for_test(origin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
    use std::assert_matches;

    fn host(raw: &str) -> GitlabHost {
        GitlabHost::parse(
            raw,
            &RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly),
        )
        .unwrap()
    }

    fn token() -> Option<ApiToken> {
        Some(ApiToken::new("glpat-secret".to_string()))
    }

    #[test]
    fn unset_host_binds_to_gitlab_com_only() {
        let binding = TokenBinding::from_values(token(), None);
        assert!(binding.token_for(&host("gitlab.com")).is_some());
        assert!(binding.token_for(&host("gitlab.corp")).is_none());
    }

    #[test]
    fn empty_host_is_treated_as_unset() {
        let binding = TokenBinding::from_values(token(), Some("  "));
        assert!(binding.token_for(&host("gitlab.com")).is_some());
    }

    #[test]
    fn configured_host_replaces_gitlab_com() {
        let binding = TokenBinding::from_values(token(), Some("GitLab.Corp"));
        assert!(binding.token_for(&host("gitlab.corp")).is_some());
        assert!(binding.token_for(&host("gitlab.com")).is_none());
    }

    #[test]
    fn invalid_host_disables_token_and_never_falls_back_to_gitlab_com() {
        for bad in ["user:pw@x", "x/y", "https://x", "x:443"] {
            let binding = TokenBinding::from_values(token(), Some(bad));
            assert_matches!(binding, TokenBinding::Disabled, "{bad}");
            assert!(binding.token_for(&host("gitlab.com")).is_none(), "{bad}");
            assert!(binding.bound_origin().is_none());
        }
    }

    #[test]
    fn no_token_is_absent_regardless_of_host() {
        for h in [None, Some("gitlab.corp"), Some("x/y")] {
            assert_matches!(TokenBinding::from_values(None, h), TokenBinding::Absent);
        }
    }

    #[test]
    fn private_range_env_host_is_accepted_without_workspace_policy() {
        let binding = TokenBinding::from_values(token(), Some("10.0.0.5"));
        assert_eq!(binding.bound_origin(), Some("https://10.0.0.5"));
    }

    /// Regression for #1790: a host that arrives through LSP settings
    /// (`registries.gitlab_instance_host`) is not the env-bound origin, so it gets no token.
    #[test]
    fn settings_supplied_host_receives_no_token() {
        let binding = TokenBinding::from_values(token(), None);
        let attacker = GitlabHost::parse(
            "attacker.example",
            &RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly),
        )
        .unwrap();
        assert!(binding.token_for(&attacker).is_none());
    }

    #[test]
    fn trailing_dot_host_fails_closed() {
        let binding = TokenBinding::from_values(token(), Some("gitlab.corp."));
        assert_matches!(binding, TokenBinding::Disabled);
    }

    #[test]
    fn idn_host_requires_punycode() {
        let unicode = TokenBinding::from_values(token(), Some("b\u{fc}cher.example"));
        assert_matches!(unicode, TokenBinding::Disabled);
        let punycode = TokenBinding::from_values(token(), Some("xn--bcher-kva.example"));
        assert_eq!(
            punycode.bound_origin(),
            Some("https://xn--bcher-kva.example")
        );
    }

    #[test]
    fn origin_differing_only_by_port_gets_no_token() {
        let binding = TokenBinding::from_values(token(), Some("gitlab.corp"));
        assert!(
            binding
                .token_for_origin("https://gitlab.corp:8443")
                .is_none()
        );
        assert!(binding.token_for_origin("http://gitlab.corp").is_none());
        assert!(binding.token_for_origin("https://gitlab.corp").is_some());
    }

    #[test]
    fn lookup_reads_the_documented_variables() {
        let env = |name: &str| match name {
            "GITLAB_TOKEN" => Some("glpat-secret".to_string()),
            "GITLAB_TOKEN_HOST" => Some("gitlab.corp".to_string()),
            _ => None,
        };
        let binding = TokenBinding::from_lookup(env);
        assert_eq!(binding.bound_origin(), Some("https://gitlab.corp"));
    }

    #[test]
    fn lookup_treats_empty_variables_as_unset() {
        let empty_host = |name: &str| match name {
            "GITLAB_TOKEN" => Some("glpat-secret".to_string()),
            "GITLAB_TOKEN_HOST" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            TokenBinding::from_lookup(empty_host).bound_origin(),
            Some(crate::host::GITLAB_COM_ORIGIN)
        );
        let empty_token = |name: &str| (name == "GITLAB_TOKEN").then(String::new);
        assert_matches!(TokenBinding::from_lookup(empty_token), TokenBinding::Absent);
    }

    #[test]
    fn invalid_host_warning_redacts_credentials() {
        let log = deps_core::test_util::capture_tracing_output(|| {
            let _ = TokenBinding::from_values(token(), Some("user:hunter2@gitlab.corp"));
        });
        assert!(!log.contains("hunter2"), "log: {log}");
        assert!(log.contains("GITLAB_TOKEN_HOST"), "log: {log}");
    }
}
