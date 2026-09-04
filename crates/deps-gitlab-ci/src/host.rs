//! GitLab instance host validation and resolution.
//!
//! Two related concerns live here (spec FR-005a/FR-011a, plan §4.1/§4.5):
//!
//! - [`GitlabHost`] — a validated, policy-gated host newtype, produced once per unique host
//!   string encountered in a manifest (a `component:` prefix) or read from configuration.
//! - [`GitlabInstanceHost`] — the live-updatable `registries.gitlab_instance_host` setting,
//!   which is both the host `project:` includes resolve against when set, and the *only*
//!   host `GITLAB_TOKEN` may ever be attached to (replacing, not extending, `gitlab.com`).

use deps_core::net_policy::{
    IndexUrlError, PolicyGate, RegistryAccessPolicy, WorkspaceRegistryAccess, validate_index_url,
};
use std::sync::{Arc, RwLock};

/// The default GitLab.com host — the token host when `registries.gitlab_instance_host` is
/// unset (FR-005a).
pub const GITLAB_COM: &str = "gitlab.com";

/// `GITLAB_COM`'s normalized, ASCII-serialized origin — the value every token-host
/// comparison runs against for the default (unconfigured) case.
pub const GITLAB_COM_ORIGIN: &str = "https://gitlab.com";

/// A validated GitLab instance host.
///
/// `https`-only, no userinfo, not a loopback/link-local/private/cloud-metadata address (per
/// the live [`RegistryAccessPolicy`]), and round-tripped through URL parsing so a
/// structurally-injected value (`gitlab.com?x`, `gitlab.com/x`) cannot smuggle extra URL
/// components past validation.
///
/// Both the verified host and its ASCII-serialized origin are computed once at construction
/// — the origin is needed repeatedly (the token-host comparison, the pinned-transport
/// `trusted_origin` argument, and the `auth_id` digest), and re-deriving it per call is how
/// normalization bugs enter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitlabHost {
    host: String,
    origin: String,
}

impl GitlabHost {
    /// Validates `raw` as a GitLab instance host.
    ///
    /// `format!("https://{raw}")` will happily absorb a `raw` containing `:`, `?`, `#`, `@`
    /// or `/` — `gitlab.com?x` parses to a clean `https://gitlab.com` origin while the
    /// caller still believes the host is `gitlab.com?x`. This rejects any `raw` containing
    /// those characters *before* formatting, and asserts the parsed URL's host matches
    /// `raw` (lowercased) afterwards, closing that gap.
    ///
    /// # Errors
    ///
    /// Returns [`IndexUrlError`] when `raw` contains a URL-structural character, fails to
    /// parse, is not `https`-eligible, carries userinfo, round-trips to a different host, or
    /// resolves to a [`deps_core::net_policy::HostClass`] the current policy blocks.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
    /// use deps_gitlab_ci::host::GitlabHost;
    ///
    /// let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);
    /// let host = GitlabHost::parse("gitlab.com", &policy).unwrap();
    /// assert_eq!(host.host(), "gitlab.com");
    /// assert_eq!(host.origin(), "https://gitlab.com");
    ///
    /// assert!(GitlabHost::parse("gitlab.com/evil", &policy).is_err());
    /// assert!(GitlabHost::parse("169.254.169.254", &policy).is_err());
    /// ```
    pub fn parse(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, IndexUrlError> {
        if raw.contains([':', '?', '#', '@', '/']) {
            return Err(IndexUrlError::InvalidUrl(raw.to_string()));
        }
        let candidate = format!("https://{raw}");
        let url = validate_index_url(&candidate, raw, "gitlab-ci", PolicyGate::Enforce(policy))?;
        let raw_lowercased = raw.to_ascii_lowercase();
        if url.host_str() != Some(raw_lowercased.as_str()) {
            return Err(IndexUrlError::InvalidUrl(raw.to_string()));
        }
        Ok(Self {
            host: raw_lowercased,
            origin: url.origin().ascii_serialization(),
        })
    }

    /// The verified, lowercased host string (no scheme, no path).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Builds a [`GitlabHost`] pointed at `base_url` (e.g. a `mockito` server's
    /// `http://127.0.0.1:PORT` URL), bypassing [`Self::parse`]'s `https`-only gate and
    /// policy check entirely.
    ///
    /// Test-only: production code must always go through [`Self::parse`], which is the one
    /// place a manifest- or configuration-sourced host is validated.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(base_url: &str) -> Self {
        Self {
            host: base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .to_string(),
            origin: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// The normalized, ASCII-serialized origin (`https://{host}`), computed once at
    /// construction.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Reconstructs a [`GitlabHost`] from an already-validated origin string (spec §3.2 —
    /// `GitlabRoute::origin` is only ever populated from a [`Self::origin`] value this type
    /// itself produced), without re-running [`Self::parse`]'s policy/round-trip checks.
    ///
    /// `pub(crate)`, not `pub`: the trust boundary is this crate's own route table
    /// (`crate::registry::GitlabCiRegistry`), which never stores an origin from any other
    /// source.
    #[must_use]
    pub(crate) fn trusted(origin: &str) -> Self {
        let host = origin
            .strip_prefix("https://")
            .unwrap_or(origin)
            .to_string();
        Self {
            host,
            origin: origin.to_string(),
        }
    }
}

/// Whether `s` is safe to splice into a GitLab API request path and/or is a syntactically
/// well-formed project/component coordinate.
///
/// 2 or more `/`-separated segments, each non-empty and drawn from `[A-Za-z0-9._-]`, none of
/// them a `.`/`..` dot segment, and the final segment not ending in `.git`/`.atom`.
///
/// A **syntactic safety gate**, not a semantic classifier — it is deliberately not asked to
/// decide whether the first segment is a hostname or a group path, since a hostname's
/// character set is a subset of the segment charset and both the bare path (`org/proj`) and
/// the host-qualified name (`gitlab.com/org/proj`) must pass it. Shared by the fetch-URL
/// gate ([`crate::client`]) and the formatter's display-URL gate
/// ([`crate::formatter::GitlabCiFormatter`]), so the two cannot drift apart.
///
/// # Examples
///
/// ```
/// use deps_gitlab_ci::host::is_valid_gitlab_coordinate;
///
/// assert!(is_valid_gitlab_coordinate("org/project"));
/// assert!(is_valid_gitlab_coordinate("org/sub/group/project"));
/// assert!(!is_valid_gitlab_coordinate("org"));
/// assert!(!is_valid_gitlab_coordinate("org/.."));
/// assert!(!is_valid_gitlab_coordinate("org/project.git"));
/// ```
#[must_use]
pub fn is_valid_gitlab_coordinate(s: &str) -> bool {
    let segments: Vec<&str> = s.split('/').collect();
    if segments.len() < 2 || !segments.iter().all(|seg| is_valid_path_segment(seg)) {
        return false;
    }
    let last = segments[segments.len() - 1];
    !(last.ends_with(".git") || last.ends_with(".atom"))
}

/// Whether `seg` alone is safe to splice into a URL path segment: non-empty,
/// `[A-Za-z0-9._-]`-only, and not a `.`/`..` dot segment.
///
/// Shared by [`is_valid_gitlab_coordinate`] (each `/`-separated segment) and
/// `crate::parser`'s standalone component-name validation (a `component:` include's final
/// path segment, checked independently of the project-path segments before it).
#[must_use]
pub(crate) fn is_valid_path_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !deps_core::lsp_helpers::is_dot_segment(seg)
}

/// Tri-state outcome of resolving `registries.gitlab_instance_host` (spec FR-005a/FR-011a).
///
/// Distinct from a plain `Option<GitlabHost>` (security review, issue #466 H-security):
/// [`token_host_origin`] must tell "unset" — the correct, intentional `gitlab.com` default —
/// apart from "configured but rejected", which must **never** fall back to `gitlab.com`.
/// Collapsing the two meant an invalid/policy-rejected value silently redirected
/// `PRIVATE-TOKEN` to `gitlab.com`, leaking a self-hosted credential to the wrong host.
/// [`GitlabInstanceHost::get`] still collapses `Unset`/`Invalid` to `None` for every other
/// caller (host *resolution*, not token routing, where "can't resolve" is the same outcome
/// either way).
#[derive(Debug, Clone, PartialEq, Eq)]
enum InstanceHostOutcome {
    /// `registries.gitlab_instance_host` is not configured.
    Unset,
    /// Configured, but rejected by [`GitlabHost::parse`] (malformed, non-`https`-eligible,
    /// or a blocked [`deps_core::net_policy::HostClass`]).
    Invalid,
    /// Configured and validated successfully.
    Valid(GitlabHost),
}

/// Live-updatable, `Arc`-shareable handle to the `registries.gitlab_instance_host` setting
/// (spec FR-011a).
///
/// The shared raw string lives outside this crate (`deps-lsp`'s `EcosystemRuntime`, a plain
/// `Arc<RwLock<Option<String>>>` with no `#[cfg]` — see that struct's docs for why) and is
/// threaded in at construction; every host-semantics decision (validation, memoization)
/// lives here instead.
///
/// Validation runs on **read**, not on write: `Self::resolve` compares the current raw
/// string and live policy against a memo of the last outcome, re-validating only when either
/// changes (issue #588 critic M11 — the memo must be keyed on policy too, since
/// [`RegistryAccessPolicy`] mutates in place: a host accepted under a looser policy must not
/// keep resolving once the policy tightens). A rejected value is treated as unset for host
/// *resolution* purposes ([`Self::get`] returns `None`), but is tracked distinctly
/// (`InstanceHostOutcome::Invalid`) for token-host routing — see [`token_host_origin`].
pub struct GitlabInstanceHost {
    raw: Arc<RwLock<Option<String>>>,
    policy: Arc<RegistryAccessPolicy>,
    /// Last `(raw, policy)` this instance validated, and the outcome — both re-checked on
    /// every [`Self::resolve`] so a stale outcome from either axis can never be served.
    memo: RwLock<Option<(String, WorkspaceRegistryAccess, InstanceHostOutcome)>>,
    /// Test-only escape hatch: when set, [`Self::resolve`] returns this directly, bypassing
    /// [`GitlabHost::parse`]'s port-rejecting validation — needed only because a `mockito`
    /// server's `127.0.0.1:PORT` host could otherwise never stand in for a *configured*
    /// instance host in a test (production self-hosted GitLab hosts never need a port).
    #[cfg(test)]
    test_override: Option<GitlabHost>,
}

impl GitlabInstanceHost {
    /// Builds a handle sharing `raw` (the config-owned raw string cell) and `policy` (the
    /// same live [`RegistryAccessPolicy`] handle [`GitlabHost::parse`] gates against
    /// elsewhere).
    #[must_use]
    pub fn new(raw: Arc<RwLock<Option<String>>>, policy: Arc<RegistryAccessPolicy>) -> Self {
        Self {
            raw,
            policy,
            memo: RwLock::new(None),
            #[cfg(test)]
            test_override: None,
        }
    }

    /// Test-only: builds a handle whose [`Self::get`] always returns `host` directly. See
    /// [`Self::test_override`]'s doc for why this bypass exists.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(host: GitlabHost) -> Self {
        Self {
            raw: Arc::new(RwLock::new(None)),
            policy: Arc::new(RegistryAccessPolicy::default()),
            memo: RwLock::new(None),
            test_override: Some(host),
        }
    }

    /// The currently configured, validated instance host — `None` when unset or when the
    /// configured value fails validation (logged once per distinct `(raw, policy)` pair, not
    /// per read).
    ///
    /// Collapses `InstanceHostOutcome::Unset` and `InstanceHostOutcome::Invalid` to the
    /// same `None`: for host *resolution* (what a `project:`/`$...`-relative `component:`
    /// include resolves against), "not configured" and "configured but rejected" are the
    /// same outcome. They are **not** the same outcome for token routing — see
    /// [`token_host_origin`], which calls `Self::resolve` directly instead.
    #[must_use]
    pub fn get(&self) -> Option<GitlabHost> {
        match self.resolve() {
            InstanceHostOutcome::Valid(host) => Some(host),
            InstanceHostOutcome::Unset | InstanceHostOutcome::Invalid => None,
        }
    }

    /// The full tri-state outcome — see [`InstanceHostOutcome`]'s doc for why `Unset` and
    /// `Invalid` must stay distinguishable here even though [`Self::get`] collapses them.
    fn resolve(&self) -> InstanceHostOutcome {
        #[cfg(test)]
        if let Some(host) = &self.test_override {
            return InstanceHostOutcome::Valid(host.clone());
        }

        let Some(raw) = self
            .raw
            .read()
            .expect("gitlab_instance_host raw lock poisoned")
            .clone()
        else {
            return InstanceHostOutcome::Unset;
        };
        let policy_now = self.policy.get();

        if let Some((cached_raw, cached_policy, outcome)) = self
            .memo
            .read()
            .expect("gitlab_instance_host memo lock poisoned")
            .as_ref()
            && *cached_raw == raw
            && *cached_policy == policy_now
        {
            return outcome.clone();
        }

        let outcome = match GitlabHost::parse(&raw, &self.policy) {
            Ok(host) => InstanceHostOutcome::Valid(host),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "registries.gitlab_instance_host is invalid; treating it as unset for host \
                     resolution and disabling GITLAB_TOKEN entirely (it is not redirected to \
                     gitlab.com)"
                );
                InstanceHostOutcome::Invalid
            }
        };
        *self
            .memo
            .write()
            .expect("gitlab_instance_host memo lock poisoned") =
            Some((raw, policy_now, outcome.clone()));
        outcome
    }
}

/// The one host `PRIVATE-TOKEN` may be attached to (FR-005a): the configured
/// `registries.gitlab_instance_host`'s origin when set, **replacing** — not joined with —
/// [`GITLAB_COM_ORIGIN`] otherwise.
///
/// Returns `None` when the setting is configured but **invalid** (security review, issue
/// #466): the pre-fix version collapsed "unset" and "invalid" into the same fallback,
/// silently redirecting `PRIVATE-TOKEN` to `gitlab.com` for a rejected value instead of
/// disabling it — an invalid value must send the token nowhere, not to a default host the
/// user never configured. Callers compare with `.is_some_and(|o| o == host.origin())`
/// (never `.unwrap_or(...)`) so `None` can never equal any host's origin.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::RegistryAccessPolicy;
/// use deps_gitlab_ci::host::{GITLAB_COM_ORIGIN, GitlabInstanceHost, token_host_origin};
/// use std::sync::{Arc, RwLock};
///
/// let policy = Arc::new(RegistryAccessPolicy::default());
/// let unset = GitlabInstanceHost::new(Arc::new(RwLock::new(None)), Arc::clone(&policy));
/// assert_eq!(token_host_origin(&unset).as_deref(), Some(GITLAB_COM_ORIGIN));
///
/// let set = GitlabInstanceHost::new(
///     Arc::new(RwLock::new(Some("gitlab.mycorp.dev".to_string()))),
///     Arc::clone(&policy),
/// );
/// assert_eq!(token_host_origin(&set).as_deref(), Some("https://gitlab.mycorp.dev"));
///
/// // An invalid value is disabled outright, never redirected to `gitlab.com`.
/// let invalid = GitlabInstanceHost::new(
///     Arc::new(RwLock::new(Some("127.0.0.1".to_string()))),
///     policy,
/// );
/// assert_eq!(token_host_origin(&invalid), None);
/// ```
#[must_use]
pub fn token_host_origin(instance_host: &GitlabInstanceHost) -> Option<String> {
    match instance_host.resolve() {
        InstanceHostOutcome::Unset => Some(GITLAB_COM_ORIGIN.to_string()),
        InstanceHostOutcome::Valid(host) => Some(host.origin().to_string()),
        InstanceHostOutcome::Invalid => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(access: WorkspaceRegistryAccess) -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(access)
    }

    #[test]
    fn test_gitlab_host_parse_accepts_plain_host() {
        let p = policy(WorkspaceRegistryAccess::PublicOnly);
        let host = GitlabHost::parse("gitlab.com", &p).unwrap();
        assert_eq!(host.host(), "gitlab.com");
        assert_eq!(host.origin(), GITLAB_COM_ORIGIN);
    }

    #[test]
    fn test_gitlab_host_parse_lowercases() {
        let p = policy(WorkspaceRegistryAccess::PublicOnly);
        let host = GitlabHost::parse("GitLab.COM", &p).unwrap();
        assert_eq!(host.host(), "gitlab.com");
    }

    #[test]
    fn test_gitlab_host_parse_rejects_structural_characters() {
        let p = policy(WorkspaceRegistryAccess::All);
        for raw in [
            "gitlab.com?x",
            "gitlab.com/x",
            "gitlab.com#x",
            "gitlab.com:8080@evil.test",
            "user@gitlab.com",
        ] {
            assert!(
                GitlabHost::parse(raw, &p).is_err(),
                "expected {raw} to be rejected"
            );
        }
    }

    #[test]
    fn test_gitlab_host_parse_rejects_blocked_host_class() {
        let p = policy(WorkspaceRegistryAccess::PublicOnly);
        for raw in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "localhost"] {
            assert!(
                GitlabHost::parse(raw, &p).is_err(),
                "expected {raw} to be rejected"
            );
        }
    }

    #[test]
    fn test_gitlab_host_parse_allows_blocked_host_class_under_all_policy() {
        let p = policy(WorkspaceRegistryAccess::All);
        assert!(GitlabHost::parse("10.0.0.1", &p).is_ok());
    }

    #[test]
    fn test_is_valid_gitlab_coordinate_accepts_nested_subgroups() {
        assert!(is_valid_gitlab_coordinate("org/sub/group/project"));
        assert!(is_valid_gitlab_coordinate("org/project"));
        assert!(is_valid_gitlab_coordinate("gitlab.com/org/project"));
    }

    #[test]
    fn test_is_valid_gitlab_coordinate_rejects_single_segment() {
        assert!(!is_valid_gitlab_coordinate("org"));
        assert!(!is_valid_gitlab_coordinate(""));
    }

    #[test]
    fn test_is_valid_gitlab_coordinate_rejects_dot_segments() {
        assert!(!is_valid_gitlab_coordinate("org/.."));
        assert!(!is_valid_gitlab_coordinate("org/."));
        assert!(!is_valid_gitlab_coordinate("../repo"));
    }

    #[test]
    fn test_is_valid_gitlab_coordinate_rejects_git_atom_suffix() {
        assert!(!is_valid_gitlab_coordinate("org/project.git"));
        assert!(!is_valid_gitlab_coordinate("org/project.atom"));
    }

    #[test]
    fn test_is_valid_gitlab_coordinate_rejects_bad_charset() {
        assert!(!is_valid_gitlab_coordinate("org/pro ject"));
        assert!(!is_valid_gitlab_coordinate("org//project"));
    }

    #[test]
    fn test_gitlab_instance_host_unset_returns_none() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw = Arc::new(RwLock::new(None));
        let handle = GitlabInstanceHost::new(raw, policy);
        assert!(handle.get().is_none());
    }

    #[test]
    fn test_gitlab_instance_host_valid_value_resolves() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw = Arc::new(RwLock::new(Some("gitlab.mycorp.dev".to_string())));
        let handle = GitlabInstanceHost::new(raw, policy);
        let host = handle.get().unwrap();
        assert_eq!(host.host(), "gitlab.mycorp.dev");
    }

    #[test]
    fn test_gitlab_instance_host_invalid_value_reads_back_as_none() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        for bad in ["http://gitlab.mycorp.dev", "127.0.0.1", "169.254.169.254"] {
            let raw = Arc::new(RwLock::new(Some(bad.to_string())));
            let handle = GitlabInstanceHost::new(raw, Arc::clone(&policy));
            assert!(handle.get().is_none(), "expected {bad} to be rejected");
        }
    }

    #[test]
    fn test_gitlab_instance_host_memo_invalidates_on_raw_change() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw = Arc::new(RwLock::new(Some("gitlab.mycorp.dev".to_string())));
        let handle = GitlabInstanceHost::new(Arc::clone(&raw), policy);
        assert_eq!(handle.get().unwrap().host(), "gitlab.mycorp.dev");

        *raw.write().unwrap() = Some("gitlab.other.dev".to_string());
        assert_eq!(handle.get().unwrap().host(), "gitlab.other.dev");
    }

    /// Issue #588 critic M11 regression: a host validated while the policy allows it must
    /// stop resolving once the policy tightens to reject its class — the memo must be keyed
    /// on policy too, not just the raw string.
    #[test]
    fn test_gitlab_instance_host_memo_invalidates_on_policy_tightening() {
        let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
        let raw = Arc::new(RwLock::new(Some("10.0.0.1".to_string())));
        let handle = GitlabInstanceHost::new(raw, Arc::clone(&policy));
        assert!(
            handle.get().is_some(),
            "a private-range host is valid under the All policy"
        );

        policy.set(WorkspaceRegistryAccess::PublicOnly);
        assert!(
            handle.get().is_none(),
            "the same host must be rejected once the policy tightens, not served from a stale memo"
        );
    }

    #[test]
    fn test_token_host_origin_unset_is_gitlab_com() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let handle = GitlabInstanceHost::new(Arc::new(RwLock::new(None)), policy);
        assert_eq!(
            token_host_origin(&handle).as_deref(),
            Some(GITLAB_COM_ORIGIN)
        );
    }

    #[test]
    fn test_token_host_origin_set_replaces_gitlab_com() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw = Arc::new(RwLock::new(Some("gitlab.mycorp.dev".to_string())));
        let handle = GitlabInstanceHost::new(raw, policy);
        assert_eq!(
            token_host_origin(&handle).as_deref(),
            Some("https://gitlab.mycorp.dev")
        );
        assert_ne!(
            token_host_origin(&handle).as_deref(),
            Some(GITLAB_COM_ORIGIN)
        );
    }

    /// Security regression (#466 review): an invalid/policy-rejected instance host must
    /// disable the token outright, never fall back to `gitlab.com` — collapsing "unset" and
    /// "invalid" into one `None` (pre-fix) silently redirected `PRIVATE-TOKEN` to
    /// `gitlab.com`, leaking a self-hosted credential to the wrong host.
    #[test]
    fn test_token_host_origin_invalid_value_disables_token_not_gitlab_com() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw = Arc::new(RwLock::new(Some("127.0.0.1".to_string())));
        let handle = GitlabInstanceHost::new(raw, policy);
        assert_eq!(token_host_origin(&handle), None);
    }
}
