//! GitLab instance host validation and resolution.
//!
//! Two related concerns live here (spec FR-005a/FR-011a, plan §4.1/§4.5):
//!
//! - [`GitlabHost`] — a validated, policy-gated host newtype, produced once per unique host
//!   string encountered in a manifest (a `component:` prefix) or read from configuration.
//! - [`GitlabInstanceHost`] — the live-updatable `registries.gitlab_instance_host` setting,
//!   which is the host `project:` includes resolve against when set. It never carries
//!   `GITLAB_TOKEN`: the credential's destination comes from the process environment, see
//!   the `token` module.

use deps_core::EcosystemId;
use deps_core::net_policy::{
    BlockingPolicy, HostClass, IndexUrlError, PolicyGate, RedactedUrl, RegistryAccessPolicy,
    TrustedPrefix, WorkspaceRegistryAccess, validate_index_url,
};
use std::sync::{Arc, RwLock};

/// The default GitLab.com host — the token host when `GITLAB_TOKEN_HOST` is unset.
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
    prefix: TrustedPrefix,
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
        Self::parse_gated(raw, PolicyGate::Enforce(policy))
    }

    /// Structural validation only, with no host-class policy check — for a host whose
    /// provenance is the user's own process environment, not a workspace file.
    pub(crate) fn parse_trusted(raw: &str) -> Result<Self, IndexUrlError> {
        Self::parse_gated(raw, PolicyGate::Skip)
    }

    fn parse_gated(raw: &str, gate: PolicyGate<'_>) -> Result<Self, IndexUrlError> {
        if raw.contains([':', '?', '#', '@', '/']) {
            return Err(IndexUrlError::InvalidUrl(RedactedUrl::new(raw)));
        }
        let candidate = format!("https://{raw}");
        let url = validate_index_url(&candidate, raw, EcosystemId::GitlabCi, gate)?;
        let raw_lowercased = raw.to_ascii_lowercase();
        if url.host_str() != Some(raw_lowercased.as_str()) {
            return Err(IndexUrlError::InvalidUrl(RedactedUrl::new(raw)));
        }
        let origin = url.origin().ascii_serialization();
        let prefix = TrustedPrefix::parse(&format!("{origin}/"))
            .map_err(|_| IndexUrlError::InvalidUrl(RedactedUrl::new(raw)))?;
        Ok(Self {
            host: raw_lowercased,
            origin,
            prefix,
        })
    }

    /// The public `gitlab.com` instance.
    #[must_use]
    pub fn gitlab_com() -> Self {
        #[expect(
            clippy::expect_used,
            reason = "`gitlab.com` is a constant that always passes structural validation"
        )]
        Self::parse_trusted("gitlab.com").expect("gitlab.com is a valid GitLab host")
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
        let origin = base_url.trim_end_matches('/').to_string();
        Self {
            host: base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .to_string(),
            prefix: TrustedPrefix::parse(&format!("{origin}/"))
                .or_else(|_| TrustedPrefix::parse(&format!("https://{origin}/")))
                .unwrap(),
            origin,
        }
    }

    /// The `{origin}/` prefix confining requests to this host and every redirect hop they
    /// follow, computed once at construction.
    #[must_use]
    pub const fn trusted_prefix(&self) -> &TrustedPrefix {
        &self.prefix
    }

    /// The normalized, ASCII-serialized origin (`https://{host}`), computed once at
    /// construction.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
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
    segments
        .last()
        .is_some_and(|last| !(last.ends_with(".git") || last.ends_with(".atom")))
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

/// Outcome of resolving `registries.gitlab_instance_host` (spec FR-005a/FR-011a).
///
/// Distinct from a plain `Option<GitlabHost>` so diagnostics can tell "unset" apart from
/// "configured but rejected". [`Self::Blocked`] is kept distinct from [`Self::Invalid`] for the
/// same reason `crate::parser` needs them apart (issue #967): a policy block has a different fix
/// (relax the policy) than a malformed value (reconfigure the setting). [`GitlabInstanceHost::get`] still collapses
/// `Unset`/`Invalid`/`Blocked` to `None` for host *resolution*, where "can't resolve" is the
/// same outcome either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstanceHostOutcome {
    /// `registries.gitlab_instance_host` is not configured.
    Unset,
    /// Configured, but rejected by [`GitlabHost::parse`] for a reason other than a blocked
    /// host class (malformed, non-`https`-eligible, carries userinfo, ...).
    Invalid,
    /// Configured, but rejected specifically because its host class is blocked by the
    /// current `registries.workspace_registries` policy (issue #967) — kept distinct from
    /// [`Self::Invalid`] so callers can surface the correct diagnostic (the fix is to relax
    /// the policy, not to reconfigure `registries.gitlab_instance_host`).
    ///
    /// A named struct variant, not a positional tuple (code-review follow-up, consistency
    /// with [`crate::types::HostRef::PolicyBlocked`]'s own #944 M9-style rationale): `raw`
    /// and `class` differ in type today so a swap wouldn't compile, but naming them keeps the
    /// two `Blocked` shapes in this crate consistent as either evolves.
    Blocked {
        /// The configured raw value itself (#967 S1: a caller needs the real blocked
        /// string, not a placeholder, to name it accurately in a diagnostic).
        raw: String,
        /// The blocked host's classification.
        class: HostClass,
        /// The rule that refused the host.
        policy: BlockingPolicy,
    },
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
/// (`InstanceHostOutcome::Invalid`/`InstanceHostOutcome::Blocked`) for diagnostic messaging —
/// see `crate::parser`.
pub struct GitlabInstanceHost {
    raw: Arc<RwLock<Option<String>>>,
    policy: Arc<RegistryAccessPolicy>,
    /// Last `(raw, policy)` this instance validated, and the outcome — both re-checked on
    /// every [`Self::resolve`] so a stale outcome from either axis can never be served.
    memo: RwLock<Option<(String, WorkspaceRegistryAccess, InstanceHostOutcome)>>,
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
        }
    }

    /// The currently configured, validated instance host — `None` when unset or when the
    /// configured value fails validation (logged once per distinct `(raw, policy)` pair, not
    /// per read).
    ///
    /// Collapses `InstanceHostOutcome::Unset`, `InstanceHostOutcome::Invalid` and
    /// `InstanceHostOutcome::Blocked` to the same `None`: for host *resolution* (what a
    /// `project:`/`$...`-relative `component:` include resolves against), "not configured"
    /// and "configured but rejected" are the same outcome. They are **not** the same outcome
    /// for diagnostic messaging, where a caller needs to tell the two apart: see
    /// `Self::resolve` (`pub(crate)`, used by `crate::parser`).
    #[must_use]
    pub fn get(&self) -> Option<GitlabHost> {
        match self.resolve() {
            InstanceHostOutcome::Valid(host) => Some(host),
            InstanceHostOutcome::Unset
            | InstanceHostOutcome::Invalid
            | InstanceHostOutcome::Blocked { .. } => None,
        }
    }

    /// The full tri-state outcome — see [`InstanceHostOutcome`]'s doc for why `Unset` and
    /// `Invalid` must stay distinguishable here even though [`Self::get`] collapses them.
    ///
    /// `pub(crate)` rather than a `blocked_class`-style public wrapper (#967 M1 follow-up):
    /// a caller that needs both [`Self::get`]'s `Literal` case and the blocked case must
    /// match on one [`Self::resolve`] call, not call two separate accessors that could each
    /// observe a different outcome if the underlying config is written between them.
    pub(crate) fn resolve(&self) -> InstanceHostOutcome {
        let Some(raw) = self
            .raw
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return InstanceHostOutcome::Unset;
        };
        let policy_now = self.policy.get();

        if let Some((cached_raw, cached_policy, outcome)) = self
            .memo
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            && *cached_raw == raw
            && *cached_policy == policy_now
        {
            return outcome.clone();
        }

        let outcome = match GitlabHost::parse(&raw, &self.policy) {
            Ok(host) => InstanceHostOutcome::Valid(host),
            Err(IndexUrlError::BlockedHost { class, policy }) => {
                tracing::warn!(
                    %class,
                    "registries.gitlab_instance_host is blocked by the current \
                     registries.workspace_registries policy; treating it as unset for host \
                     resolution"
                );
                InstanceHostOutcome::Blocked {
                    raw: raw.clone(),
                    class,
                    policy,
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "registries.gitlab_instance_host is invalid; treating it as unset for host \
                     resolution"
                );
                InstanceHostOutcome::Invalid
            }
        };
        *self
            .memo
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((raw, policy_now, outcome.clone()));
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(access: WorkspaceRegistryAccess) -> RegistryAccessPolicy {
        RegistryAccessPolicy::with_allowlist(access, private_allowlist())
    }

    fn private_allowlist() -> Arc<deps_core::net_policy::PrivateRegistryAllowlist> {
        Arc::new(deps_core::net_policy::PrivateRegistryAllowlist::for_test(
            &["10.0.0.0/8"],
        ))
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

    /// Issue #808: `raw` fails the structural-character guard precisely on credential-shaped
    /// input, so the `InvalidUrl` error built from it must never carry the credential through
    /// its `Display` — mirroring the redaction fix applied to the other `RedactedUrl`-backed
    /// `IndexUrlError` construction sites in #807. Asserts both that the credential is absent
    /// and that the redacted form is present (critic M2 follow-up) — a positive assertion, not
    /// just an absence check that would pass vacuously if the error message were dropped
    /// entirely.
    #[test]
    fn test_gitlab_host_parse_structural_character_error_redacts_credential() {
        let p = policy(WorkspaceRegistryAccess::All);
        let raw = "user:hunter2@gitlab.corp";
        let err = GitlabHost::parse(raw, &p).unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "Display: {err}");
        assert!(
            err.to_string()
                .contains(&RedactedUrl::new(raw).into_inner()),
            "expected the redacted form to still be present: {err}"
        );
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

    /// Issue #967: `resolve()` must distinguish a policy-blocked value (`127.0.0.1`,
    /// `169.254.169.254`) from one rejected for an unrelated reason (`http://` scheme) — both
    /// collapse to `get() == None`, but only the former is `InstanceHostOutcome::Blocked`, and
    /// it must carry the real configured raw value (S1: never a placeholder).
    #[test]
    fn test_gitlab_instance_host_resolve_distinguishes_policy_block_from_other_invalid() {
        let policy = Arc::new(RegistryAccessPolicy::default());

        let blocked = GitlabInstanceHost::new(
            Arc::new(RwLock::new(Some("127.0.0.1".to_string()))),
            Arc::clone(&policy),
        );
        assert_eq!(
            blocked.resolve(),
            InstanceHostOutcome::Blocked {
                raw: "127.0.0.1".to_string(),
                class: HostClass::Loopback,
                policy: BlockingPolicy::Floor,
            }
        );

        let not_blocked = GitlabInstanceHost::new(
            Arc::new(RwLock::new(Some("http://gitlab.mycorp.dev".to_string()))),
            Arc::clone(&policy),
        );
        assert_eq!(not_blocked.resolve(), InstanceHostOutcome::Invalid);

        let unset = GitlabInstanceHost::new(Arc::new(RwLock::new(None)), policy);
        assert_eq!(unset.resolve(), InstanceHostOutcome::Unset);
    }

    /// Issue #808: a credential-shaped `registries.gitlab_instance_host` value must not leak
    /// through the `tracing::warn!` line `GitlabInstanceHost::resolve` emits for a rejected
    /// value — same threat model as the `.npmrc` case fixed in #767.
    #[test]
    fn test_gitlab_instance_host_invalid_value_log_redacts_credential() {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let raw_value = "user:hunter2@gitlab.corp";
        let raw = Arc::new(RwLock::new(Some(raw_value.to_string())));
        let handle = GitlabInstanceHost::new(raw, policy);

        let log = deps_core::test_util::capture_tracing_output(|| {
            assert!(handle.get().is_none());
        });
        assert!(!log.contains("hunter2"), "log: {log}");
        // Critic M2: a positive assertion, not just absence — would pass vacuously if the
        // warning were dropped entirely.
        assert!(
            log.contains(&RedactedUrl::new(raw_value).into_inner()),
            "expected the redacted form to still be present: {log}"
        );
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
        let policy = Arc::new(policy(WorkspaceRegistryAccess::All));
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
}
