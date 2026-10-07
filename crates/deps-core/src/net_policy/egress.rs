//! How guarded registry traffic leaves the process: directly, or through the system proxy.
//!
//! A workspace-declared registry host is attacker-influenced, so its connect-time address is
//! validated by a DNS resolver the client owns. A system proxy resolves the target name itself,
//! which would make that validation meaningless, so guarded traffic connects directly by
//! default ([`GuardedEgress::Direct`]) and uses the proxy only on an explicit opt-in
//! ([`GuardedEgress::Proxy`]).
//!
//! A proxy named by DNS (`proxy.corp`, `localhost`) is itself resolved through the guarded
//! resolver, so the proxy's own hosts are exempted from the address check ([`SystemProxy`]);
//! the exemption is detected at transport construction, at the moment the HTTP client reads the
//! same system configuration.

use std::ffi::{OsStr, OsString};
use std::sync::OnceLock;

use hyper_util::client::proxy::matcher::Matcher;

use super::{AllowlistOutcome, PRIVATE_REGISTRY_HOSTS_ENV, PrivateRegistryAllowlist};

/// Environment variable that opts guarded registry traffic into the system proxy.
pub const WORKSPACE_REGISTRY_PROXY_ENV: &str = "DEPS_LSP_WORKSPACE_REGISTRY_PROXY";

/// Destination names the proxy matcher is probed with; never resolved or connected to.
const HTTP_PROBE: &str = "http://deps-lsp-proxy-probe.invalid/";
const HTTPS_PROBE: &str = "https://deps-lsp-proxy-probe.invalid/";

/// How traffic to workspace-declared (guarded) registry hosts leaves the process.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::GuardedEgress;
///
/// assert_eq!(GuardedEgress::default(), GuardedEgress::Direct);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum GuardedEgress {
    /// Connect directly, bypassing any system proxy, so the resolver guard sees every address.
    #[default]
    Direct,
    /// Use the system proxy, and resolve each target name locally before every request.
    Proxy,
}

impl GuardedEgress {
    /// Reads [`WORKSPACE_REGISTRY_PROXY_ENV`]: `proxy` (case-insensitive) opts in; anything else,
    /// including a value that is not Unicode, stays [`Self::Direct`].
    #[must_use]
    pub fn from_os_value(value: Option<&OsStr>) -> Self {
        let Some(raw) = value else {
            return Self::Direct;
        };
        match raw.to_str().map(str::trim) {
            Some(text) if text.eq_ignore_ascii_case("proxy") => Self::Proxy,
            Some("" | "0") | None => Self::Direct,
            Some(_) => {
                tracing::warn!(
                    "{WORKSPACE_REGISTRY_PROXY_ENV} is not `proxy`; guarded registry traffic stays direct"
                );
                Self::Direct
            }
        }
    }
}

/// A proxy host in comparison form: lowercase, no trailing dot.
///
/// Credentials and the port are never retained.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyEndpoint(String);

impl ProxyEndpoint {
    fn from_uri(uri: &http::Uri) -> Option<Self> {
        uri.host().map(|host| Self(normalize_host(host)))
    }

    /// The normalized host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.0
    }
}

/// Lowercases `host` and drops one trailing dot, so `Proxy.Corp.` and `proxy.corp` compare equal.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The hosts of the proxies the process-wide configuration routes HTTP and HTTPS traffic through.
///
/// Built from the same matcher reqwest's system-proxy support uses, so environment variables, the
/// macOS SystemConfiguration proxy and the Windows registry proxy are all covered.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::SystemProxy;
///
/// assert!(!SystemProxy::default().is_configured());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemProxy {
    http: Option<ProxyEndpoint>,
    https: Option<ProxyEndpoint>,
}

impl SystemProxy {
    /// Reads the current system proxy configuration.
    ///
    /// Called when a transport is built, so the exemption set matches what the client read at
    /// `Client::build`.
    #[must_use]
    pub fn detect() -> Self {
        Self::from_matcher(&Matcher::from_system())
    }

    /// The configuration read once at first use, for diagnostics that need no freshness.
    #[must_use]
    pub fn current() -> &'static Self {
        static CURRENT: OnceLock<SystemProxy> = OnceLock::new();
        CURRENT.get_or_init(Self::detect)
    }

    // TODO(#1822): provenance-keyed egress for operator-owned sources ($GOENV GOPROXY, user
    // ~/.npmrc, user NuGet.Config). Re-run the DNS-named-proxy live test on every reqwest bump;
    // the probe assumes reqwest's system proxy resolves destinations exactly like this matcher.
    fn from_matcher(matcher: &Matcher) -> Self {
        let probe = |raw: &'static str| {
            matcher
                .intercept(&http::Uri::from_static(raw))
                .and_then(|intercept| ProxyEndpoint::from_uri(intercept.uri()))
        };
        Self {
            http: probe(HTTP_PROBE),
            https: probe(HTTPS_PROBE),
        }
    }

    /// Builds the same value from explicit proxy URLs and an optional `NO_PROXY` list.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(all_proxy: Option<&str>, no_proxy: Option<&str>) -> Self {
        let mut builder = Matcher::builder();
        if let Some(proxy) = all_proxy {
            builder = builder.all(proxy);
        }
        if let Some(no_proxy) = no_proxy {
            builder = builder.no(no_proxy);
        }
        Self::from_matcher(&builder.build())
    }

    /// Whether any proxy applies to HTTP or HTTPS traffic.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.http.is_some() || self.https.is_some()
    }

    /// The proxy hosts, for the resolver exemption.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.http
            .iter()
            .chain(self.https.iter())
            .map(ProxyEndpoint::host)
    }
}

/// Sealed source of the process-wide settings [`RegistryEnvironment`] reads.
///
/// Implemented by [`ProcessEnv`] in production; the test-only `MapEnv` stands in for it so no
/// settings or manifest data path can mint one.
pub trait EnvSource: private::Sealed {
    /// The raw value of environment variable `name`.
    fn var_os(&self, name: &str) -> Option<OsString>;

    /// The system proxy configuration.
    fn system_proxy(&self) -> SystemProxy;
}

mod private {
    pub trait Sealed {}
}

/// The real process environment and system proxy configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl private::Sealed for ProcessEnv {}

impl EnvSource for ProcessEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn system_proxy(&self) -> SystemProxy {
        SystemProxy::detect()
    }
}

/// An in-memory [`EnvSource`] for tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Default)]
pub struct MapEnv {
    vars: std::collections::HashMap<String, OsString>,
    proxy: SystemProxy,
}

#[cfg(any(test, feature = "test-util"))]
impl MapEnv {
    /// An empty environment with no system proxy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets variable `name`.
    #[must_use]
    pub fn with_var(mut self, name: &str, value: &str) -> Self {
        self.vars.insert(name.to_string(), OsString::from(value));
        self
    }

    /// Sets the system proxy.
    #[must_use]
    pub fn with_proxy(mut self, proxy: SystemProxy) -> Self {
        self.proxy = proxy;
        self
    }
}

#[cfg(any(test, feature = "test-util"))]
impl private::Sealed for MapEnv {}

#[cfg(any(test, feature = "test-util"))]
impl EnvSource for MapEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        self.vars.get(name).cloned()
    }

    fn system_proxy(&self) -> SystemProxy {
        self.proxy.clone()
    }
}

/// A one-line warning about a configuration that probably does not do what its operator expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressNotice {
    message: String,
}

impl EgressNotice {
    /// The user-facing text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for EgressNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Process-wide settings that bound how workspace-declared registries are reached.
///
/// Read once at startup from an [`EnvSource`] and handed to
/// [`RegistryAccessPolicy::with_environment`](super::RegistryAccessPolicy::with_environment).
#[derive(Debug, Clone)]
pub struct RegistryEnvironment {
    allowlist: AllowlistOutcome,
    egress: GuardedEgress,
    proxy: SystemProxy,
}

impl RegistryEnvironment {
    /// Reads the private-host allowlist, the egress opt-in and the system proxy from `source`.
    #[must_use]
    pub fn read(source: &impl EnvSource) -> Self {
        let allowlist = PrivateRegistryAllowlist::outcome_of(
            source.var_os(PRIVATE_REGISTRY_HOSTS_ENV).as_deref(),
        );
        let egress =
            GuardedEgress::from_os_value(source.var_os(WORKSPACE_REGISTRY_PROXY_ENV).as_deref());
        Self {
            allowlist,
            egress,
            proxy: source.system_proxy(),
        }
    }

    /// The parsed private-host allowlist outcome.
    #[must_use]
    pub const fn allowlist(&self) -> &AllowlistOutcome {
        &self.allowlist
    }

    /// How guarded traffic leaves the process.
    #[must_use]
    pub const fn egress(&self) -> GuardedEgress {
        self.egress
    }

    /// The system proxy configuration seen at read time.
    #[must_use]
    pub const fn proxy(&self) -> &SystemProxy {
        &self.proxy
    }

    /// A notice when egress is direct although a system proxy is configured: workspace-declared
    /// registries behind a mandatory proxy then fail until the operator opts in.
    #[must_use]
    pub fn egress_notice(&self) -> Option<EgressNotice> {
        match (self.egress, self.proxy.is_configured()) {
            (GuardedEgress::Direct, true) => Some(EgressNotice {
                message: format!(
                    "A system proxy is configured, but workspace-declared registries connect \
                     directly. Set {WORKSPACE_REGISTRY_PROXY_ENV}=proxy to route them through it."
                ),
            }),
            (GuardedEgress::Direct, false) | (GuardedEgress::Proxy, true | false) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_guarded_egress_defaults_to_direct() {
        assert_eq!(GuardedEgress::from_os_value(None), GuardedEgress::Direct);
        for raw in ["", "0", "direct", "yes"] {
            assert_eq!(
                GuardedEgress::from_os_value(Some(OsStr::new(raw))),
                GuardedEgress::Direct,
                "{raw}"
            );
        }
    }

    #[test]
    fn test_guarded_egress_proxy_opt_in_is_case_insensitive() {
        for raw in ["proxy", "PROXY", " Proxy "] {
            assert_eq!(
                GuardedEgress::from_os_value(Some(OsStr::new(raw))),
                GuardedEgress::Proxy,
                "{raw}"
            );
        }
    }

    #[test]
    fn test_system_proxy_probe_extracts_host_for_both_schemes() {
        let proxy = SystemProxy::for_test(Some("http://Proxy.Corp.:3128"), None);
        assert!(proxy.is_configured());
        assert_eq!(
            proxy.hosts().collect::<Vec<_>>(),
            ["proxy.corp", "proxy.corp"]
        );
    }

    #[test]
    fn test_system_proxy_http_only_and_https_only() {
        let http_only = SystemProxy::default();
        assert!(!http_only.is_configured());
        let mut builder = Matcher::builder();
        builder = builder.http("http://h.example:1");
        let proxy = SystemProxy::from_matcher(&builder.build());
        assert!(proxy.http.is_some() && proxy.https.is_none());
        let proxy =
            SystemProxy::from_matcher(&Matcher::builder().https("http://s.example:1").build());
        assert!(proxy.http.is_none() && proxy.https.is_some());
    }

    /// G3: `NO_PROXY` entries beyond `*` — an unrelated host, an unrelated suffix, a suffix that
    /// covers the probe destination — behave as the matcher defines, so a proxy is dropped only
    /// when the whole probe name is excluded.
    #[test]
    fn test_system_proxy_no_proxy_host_and_suffix_entries() {
        let proxy = "http://proxy.corp:3128";
        for no_proxy in ["registry.test", ".registry.test", "10.0.0.0/8"] {
            assert!(
                SystemProxy::for_test(Some(proxy), Some(no_proxy)).is_configured(),
                "{no_proxy}"
            );
        }
        for no_proxy in ["deps-lsp-proxy-probe.invalid", ".invalid", "invalid"] {
            assert!(
                !SystemProxy::for_test(Some(proxy), Some(no_proxy)).is_configured(),
                "{no_proxy}"
            );
        }
    }

    #[test]
    fn test_system_proxy_no_proxy_star_disables_all() {
        let proxy = SystemProxy::for_test(Some("http://proxy.corp:3128"), Some("*"));
        assert!(!proxy.is_configured());
    }

    #[test]
    fn test_system_proxy_retains_no_credentials() {
        let proxy = SystemProxy::for_test(Some("http://user:hunter2@proxy.corp:3128"), None);
        assert!(!format!("{proxy:?}").contains("hunter2"));
    }

    #[test]
    fn test_normalize_host_ignores_case_and_trailing_dot() {
        assert_eq!(normalize_host("Proxy.Corp."), "proxy.corp");
        assert_eq!(normalize_host("proxy.corp"), "proxy.corp");
    }

    #[test]
    fn test_egress_notice_truth_table() {
        let proxy = SystemProxy::for_test(Some("http://proxy.corp:3128"), None);
        let none = SystemProxy::default();
        let cases = [
            (None, &none, false),
            (None, &proxy, true),
            (Some("proxy"), &none, false),
            (Some("proxy"), &proxy, false),
        ];
        for (opt_in, system_proxy, expect_notice) in cases {
            let mut env = MapEnv::new().with_proxy(system_proxy.clone());
            if let Some(value) = opt_in {
                env = env.with_var(WORKSPACE_REGISTRY_PROXY_ENV, value);
            }
            let notice = RegistryEnvironment::read(&env).egress_notice();
            assert_eq!(
                notice.is_some(),
                expect_notice,
                "{opt_in:?} {system_proxy:?}"
            );
            if let Some(notice) = notice {
                assert!(notice.message().contains(WORKSPACE_REGISTRY_PROXY_ENV));
            }
        }
    }

    #[test]
    fn test_policy_with_environment_carries_egress_and_allowlist() {
        let env = MapEnv::new()
            .with_var(PRIVATE_REGISTRY_HOSTS_ENV, "10.0.0.0/8")
            .with_var(WORKSPACE_REGISTRY_PROXY_ENV, "proxy");
        let policy = super::super::RegistryAccessPolicy::with_environment(
            super::super::WorkspaceRegistryAccess::All,
            &RegistryEnvironment::read(&env),
        );
        assert_eq!(policy.egress(), GuardedEgress::Proxy);
        assert!(!policy.allowlist().is_empty());
        assert_eq!(
            super::super::RegistryAccessPolicy::default().egress(),
            GuardedEgress::Direct
        );
    }

    #[test]
    fn test_registry_environment_reads_allowlist_and_egress() {
        let env = MapEnv::new()
            .with_var(PRIVATE_REGISTRY_HOSTS_ENV, "10.0.0.0/8")
            .with_var(WORKSPACE_REGISTRY_PROXY_ENV, "proxy");
        let read = RegistryEnvironment::read(&env);
        assert_eq!(read.egress(), GuardedEgress::Proxy);
        assert_matches!(read.allowlist(), AllowlistOutcome::Parsed(_));
    }
}
