//! Registry credentials and `Authorization` header formatting for SE-0292 registries.
//!
//! A [`SwiftCredentialSource`] holds the one place SwiftPM's credentials come from (environment
//! variables, `SWIFTPM_NETRC_DATA`, or `~/.netrc`, in that precedence); [`bind_credential`] is
//! the only place that decides which registries receive them. Everything credential-shaped lives
//! in [`SwiftCredential`] (fields redacted) or [`SwiftRegistryAuth`] (pre-formatted header,
//! redacted), so neither can reach a log line, `Debug` output, hover text or a cache key.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use deps_core::mtime_cache::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache};
use deps_core::netrc::{DefaultEntry, Netrc, NetrcFlavor, NetrcLogin};
use deps_core::secret::{Redacted, basic_auth_header};
use zeroize::Zeroizing;

use crate::config::{SwiftAuthType, SwiftRegistryUrl, UserConfigPlatform, UserTier};

const TOKEN_VAR: &str = "SWIFTPM_REGISTRY_TOKEN";
const LOGIN_VAR: &str = "SWIFTPM_REGISTRY_LOGIN";
const PASSWORD_VAR: &str = "SWIFTPM_REGISTRY_PASSWORD";
const NETRC_DATA_VAR: &str = "SWIFTPM_NETRC_DATA";

/// The credential SwiftPM reads from the environment, before any registry-specific formatting.
///
/// `SWIFTPM_REGISTRY_TOKEN` wins over `SWIFTPM_REGISTRY_LOGIN`/`SWIFTPM_REGISTRY_PASSWORD`.
/// `Debug` never prints a value.
///
/// # Examples
///
/// ```
/// use deps_swift::SwiftCredential;
///
/// let credential = SwiftCredential::from_lookup(|name| {
///     (name == "SWIFTPM_REGISTRY_TOKEN").then(|| "t0ken".to_string().into())
/// });
/// assert!(format!("{credential:?}").contains("Token(Redacted(***))"));
/// ```
#[derive(Debug, Clone)]
pub enum SwiftCredential {
    /// A bearer token (`SWIFTPM_REGISTRY_TOKEN`).
    Token(Redacted),
    /// A login/password pair (`SWIFTPM_REGISTRY_LOGIN`/`SWIFTPM_REGISTRY_PASSWORD`).
    Login {
        /// The login name.
        username: Redacted,
        /// The password, or a token when the registry's authentication type is `token`.
        password: Redacted,
    },
}

impl SwiftCredential {
    /// Reads the credential from the process environment; `None` when none is configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_swift::SwiftCredential;
    ///
    /// // Whatever the environment holds, the value is never rendered.
    /// let credential = SwiftCredential::from_environment();
    /// assert!(!format!("{credential:?}").contains("hunter2"));
    /// ```
    #[must_use]
    pub fn from_environment() -> Option<Self> {
        Self::from_lookup(deps_core::secret::token_from_env)
    }

    /// Reads the credential through `lookup`, treating an empty value as absent.
    ///
    /// A login without a password, or the reverse, yields no credential and a warning naming
    /// only the variables, never a value.
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<Zeroizing<String>>) -> Option<Self> {
        let non_empty = |name: &str| lookup(name).filter(|value| !value.is_empty());
        if let Some(token) = non_empty(TOKEN_VAR) {
            return Some(Self::Token(Redacted::new(token.to_string())));
        }
        match (non_empty(LOGIN_VAR), non_empty(PASSWORD_VAR)) {
            (Some(username), Some(password)) => Some(Self::Login {
                username: Redacted::new(username.to_string()),
                password: Redacted::new(password.to_string()),
            }),
            (Some(_), None) => {
                tracing::warn!("{LOGIN_VAR} is set without {PASSWORD_VAR}; ignoring it");
                None
            }
            (None, Some(_)) => {
                tracing::warn!("{PASSWORD_VAR} is set without {LOGIN_VAR}; ignoring it");
                None
            }
            (None, None) => None,
        }
    }

    fn from_netrc(login: &NetrcLogin) -> Self {
        Self::Login {
            username: login.login().clone(),
            password: login.password().clone(),
        }
    }

    /// Formats this credential for a registry whose user-tier authentication type is
    /// `auth_type`, mirroring SwiftPM's `RegistryClient` (including its `user == "token"`
    /// heuristic).
    fn format(&self, auth_type: Option<SwiftAuthType>) -> SwiftRegistryAuth {
        match (self, auth_type) {
            (Self::Token(token), None | Some(SwiftAuthType::Token)) => bearer(token),
            (Self::Token(token), Some(SwiftAuthType::Basic)) => basic("token", token),
            (Self::Login { username, password }, None) => {
                if username.expose_secret() == "token" {
                    bearer(password)
                } else {
                    basic(username.expose_secret(), password)
                }
            }
            (Self::Login { password, .. }, Some(SwiftAuthType::Token)) => bearer(password),
            (Self::Login { username, password }, Some(SwiftAuthType::Basic)) => {
                basic(username.expose_secret(), password)
            }
        }
    }
}

fn bearer(secret: &Redacted) -> SwiftRegistryAuth {
    SwiftRegistryAuth(Redacted::new(format!("Bearer {}", secret.expose_secret())))
}

fn basic(username: &str, password: &Redacted) -> SwiftRegistryAuth {
    SwiftRegistryAuth(basic_auth_header(username, password.expose_secret()))
}

/// A pre-formatted `Authorization` header value for one registry.
///
/// Redacted in `Debug` and `Display`, and deliberately not `Hash`: a ready-to-send credential
/// must not be usable inside a hash key, nor comparable. Only `bind_credential` constructs one.
#[derive(Clone)]
pub struct SwiftRegistryAuth(Redacted);

impl SwiftRegistryAuth {
    /// The header value. Never log it; hand it to an `Authorization` header only.
    pub(crate) fn header_value(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SwiftRegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwiftRegistryAuth(***)")
    }
}

impl std::fmt::Display for SwiftRegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Where [`bind_credential`] finds a credential for a registry URL.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CredentialLookup<'a> {
    /// No credential is configured.
    None,
    /// One credential shared by every registry (the environment variables).
    Shared(&'a SwiftCredential),
    /// A netrc: the credential depends on the registry's host.
    PerHost(&'a Netrc),
}

#[cfg(test)]
impl<'a> CredentialLookup<'a> {
    /// Wraps an optional shared credential.
    pub(crate) fn shared(credential: Option<&'a SwiftCredential>) -> Self {
        credential.map_or(Self::None, Self::Shared)
    }
}

/// The single source SwiftPM reads registry credentials from, chosen once at construction.
///
/// SwiftPM's providers are exclusive, so the first one that exists wins: the
/// `SWIFTPM_REGISTRY_*` environment variables, then `SWIFTPM_NETRC_DATA`, then `~/.netrc`.
/// macOS Keychain is not supported. `~/.netrc` is read on macOS too, which SwiftPM does not do
/// by default; there its `default` entry is ignored.
///
/// # Examples
///
/// ```
/// use deps_swift::SwiftCredentialSource;
/// use deps_swift::config::UserConfigPlatform;
///
/// let source = SwiftCredentialSource::from_lookup(
///     |name| {
///         (name == "SWIFTPM_NETRC_DATA")
///             .then(|| "machine swift.acme.dev login deploy password hunter2".to_string().into())
///     },
///     None,
///     UserConfigPlatform::Other,
/// )
/// .unwrap();
/// assert!(!format!("{source:?}").contains("hunter2"));
/// ```
#[derive(Debug, Clone)]
pub enum SwiftCredentialSource {
    /// `SWIFTPM_REGISTRY_TOKEN` or `SWIFTPM_REGISTRY_LOGIN`/`SWIFTPM_REGISTRY_PASSWORD`.
    Environment(SwiftCredential),
    /// The content of `SWIFTPM_NETRC_DATA`, parsed once.
    NetrcData(Arc<Netrc>),
    /// `~/.netrc`, re-read whenever its modification time changes. An absent or invalid file
    /// yields no credential.
    NetrcFile {
        /// The file to read.
        path: PathBuf,
        /// Whether its `default` entry is used.
        default_entry: DefaultEntry,
        /// Parsed content keyed by modification time; `None` for an invalid file.
        cache: Arc<MtimeFileCache<Option<Netrc>>>,
        /// Set once an existing but unreadable file has been warned about.
        unreadable_warned: Arc<AtomicBool>,
    },
}

impl SwiftCredentialSource {
    /// Reads the source from the process environment and the home directory.
    #[must_use]
    pub fn from_environment(platform: UserConfigPlatform) -> Option<Self> {
        Self::from_lookup(
            deps_core::secret::token_from_env,
            dirs::home_dir().as_deref(),
            platform,
        )
    }

    /// Picks the source through `lookup` and `home`; `None` when no source is configured.
    ///
    /// An unparsable `SWIFTPM_NETRC_DATA` logs a warning naming only the variable and falls
    /// through to `~/.netrc`, which exists as a source whenever `home` is known.
    #[must_use]
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<Zeroizing<String>>,
        home: Option<&Path>,
        platform: UserConfigPlatform,
    ) -> Option<Self> {
        if let Some(credential) = SwiftCredential::from_lookup(&lookup) {
            return Some(Self::Environment(credential));
        }
        if let Some(data) = lookup(NETRC_DATA_VAR).filter(|data| !data.is_empty()) {
            match Netrc::parse(&data, NetrcFlavor::InMemory) {
                Ok(netrc) => return Some(Self::NetrcData(Arc::new(netrc))),
                Err(error) => {
                    tracing::warn!(%error, "{NETRC_DATA_VAR} is unusable; ignoring it");
                }
            }
        }
        let default_entry = match platform {
            UserConfigPlatform::MacOs => DefaultEntry::Ignore,
            UserConfigPlatform::Other => DefaultEntry::Honor,
        };
        home.map(|home| Self::NetrcFile {
            path: home.join(".netrc"),
            default_entry,
            cache: Arc::new(MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "swift netrc")),
            unreadable_warned: Arc::default(),
        })
    }

    /// Runs `f` with the credential lookup this source currently provides.
    pub(crate) fn with_lookup<R>(&self, f: impl FnOnce(CredentialLookup<'_>) -> R) -> R {
        match self {
            Self::Environment(credential) => f(CredentialLookup::Shared(credential)),
            Self::NetrcData(netrc) => f(CredentialLookup::PerHost(netrc)),
            Self::NetrcFile {
                path,
                default_entry,
                cache,
                unreadable_warned,
            } => {
                let flavor = NetrcFlavor::File {
                    default_entry: *default_entry,
                };
                let parsed = cache.get_or_parse(path, |content| {
                    Netrc::parse(content, flavor)
                        .inspect_err(|error| {
                            tracing::warn!(%error, "~/.netrc is unusable; ignoring it");
                        })
                        .ok()
                });
                if parsed.is_some() {
                    unreadable_warned.store(false, Ordering::Relaxed);
                } else if path.exists() && !unreadable_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!("~/.netrc exists but cannot be read; ignoring it");
                }
                match parsed.as_deref() {
                    Some(Some(netrc)) => f(CredentialLookup::PerHost(netrc)),
                    Some(None) | None => f(CredentialLookup::None),
                }
            }
        }
    }
}

/// Decides whether the looked-up credential is sent to `url`, and formats it.
///
/// The credential is attached iff `url` is `Trusted`, that is declared in or equal to a
/// user-level `registries.json` URL (full normalized URL, never host or origin). The header
/// format comes from the user tier's `authentication` map only; a project file cannot change it.
///
/// This is the only credential attach site.
// TODO(#1459): candidate for a shared credential-provenance predicate across ecosystems.
pub(crate) fn bind_credential(
    url: &SwiftRegistryUrl,
    user_tier: &UserTier,
    lookup: CredentialLookup<'_>,
) -> Option<SwiftRegistryAuth> {
    use crate::config::RegistryTrust;

    let format_for_registry =
        |credential: &SwiftCredential| credential.format(user_tier.auth_type_for(url.host_key()));
    match (url.trust(), lookup) {
        (RegistryTrust::Trusted, CredentialLookup::Shared(credential)) => {
            Some(format_for_registry(credential))
        }
        (RegistryTrust::Trusted, CredentialLookup::PerHost(netrc)) => {
            let login = netrc.login_for(url.url())?;
            Some(format_for_registry(&SwiftCredential::from_netrc(login)))
        }
        (RegistryTrust::Trusted, CredentialLookup::None)
        | (RegistryTrust::WorkspaceDeclared, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegistryTrust;
    use std::collections::HashMap;

    fn lookup<'a>(
        vars: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&str) -> Option<Zeroizing<String>> + 'a {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| Zeroizing::new((*value).to_string()))
        }
    }

    fn token(value: &str) -> SwiftCredential {
        SwiftCredential::Token(Redacted::new(value.to_string()))
    }

    fn login(user: &str, password: &str) -> SwiftCredential {
        SwiftCredential::Login {
            username: Redacted::new(user.to_string()),
            password: Redacted::new(password.to_string()),
        }
    }

    fn header(credential: &SwiftCredential, auth_type: Option<SwiftAuthType>) -> String {
        credential.format(auth_type).header_value().to_string()
    }

    #[test]
    fn test_formatting_table() {
        use SwiftAuthType::{Basic, Token};
        assert_eq!(header(&token("t"), None), "Bearer t");
        assert_eq!(header(&token("t"), Some(Token)), "Bearer t");
        assert_eq!(header(&token("t"), Some(Basic)), "Basic dG9rZW46dA==");
        assert_eq!(header(&login("token", "p"), None), "Bearer p");
        assert_eq!(header(&login("u", "p"), None), "Basic dTpw");
        assert_eq!(header(&login("u", "p"), Some(Basic)), "Basic dTpw");
        assert_eq!(header(&login("u", "p"), Some(Token)), "Bearer p");
        assert_eq!(
            header(&login("token", "p"), Some(Basic)),
            "Basic dG9rZW46cA=="
        );
    }

    #[test]
    fn test_token_wins_over_login() {
        let vars = [(TOKEN_VAR, "t"), (LOGIN_VAR, "u"), (PASSWORD_VAR, "p")];
        let credential = SwiftCredential::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(header(&credential, None), "Bearer t");
    }

    #[test]
    fn test_login_pair_is_used_without_token() {
        let vars = [(LOGIN_VAR, "u"), (PASSWORD_VAR, "p")];
        let credential = SwiftCredential::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(header(&credential, None), "Basic dTpw");
    }

    #[test]
    fn test_partial_and_empty_vars_yield_no_credential() {
        for vars in [
            vec![(LOGIN_VAR, "u")],
            vec![(PASSWORD_VAR, "p")],
            vec![(TOKEN_VAR, "")],
            vec![(LOGIN_VAR, ""), (PASSWORD_VAR, "p")],
            vec![],
        ] {
            assert!(
                SwiftCredential::from_lookup(lookup(&vars)).is_none(),
                "{vars:?}"
            );
        }
    }

    #[test]
    fn test_partial_login_warning_names_only_variables() {
        let logs = deps_core::test_util::capture_tracing_output(|| {
            let vars = [(LOGIN_VAR, "secret-user")];
            let _ = SwiftCredential::from_lookup(lookup(&vars));
        });
        assert!(logs.contains(LOGIN_VAR), "{logs}");
        assert!(!logs.contains("secret-user"), "{logs}");
    }

    #[test]
    fn test_debug_and_display_never_render_a_credential_value() {
        let probe = deps_core::conformance::CREDENTIAL_PROBE_SECRET;
        let credentials = [token(probe), login("deploy", probe), login("token", probe)];
        for credential in credentials {
            let auth = credential.format(None);
            for rendered in [
                format!("{credential:?}"),
                format!("{auth:?}"),
                auth.to_string(),
            ] {
                assert!(!rendered.contains(probe), "{rendered}");
                assert!(!rendered.contains("deploy"), "{rendered}");
                assert!(rendered.contains("***"), "{rendered}");
            }
        }
    }

    const NETRC: &str = "machine swift.acme.dev login deploy password hunter2\n\
                         default login fallback password fallback-pw";

    fn netrc(content: &str) -> Netrc {
        Netrc::parse(content, NetrcFlavor::InMemory).unwrap()
    }

    #[test]
    fn test_source_precedence_is_env_then_netrc_data_then_netrc_file() {
        let home = Path::new("home");
        let pick = |vars: &[(&str, &str)], home: Option<&Path>| {
            SwiftCredentialSource::from_lookup(lookup(vars), home, UserConfigPlatform::Other)
        };

        let all = [(TOKEN_VAR, "t"), (NETRC_DATA_VAR, NETRC)];
        assert!(matches!(
            pick(&all, Some(home)),
            Some(SwiftCredentialSource::Environment(_))
        ));
        let data = [(NETRC_DATA_VAR, NETRC)];
        assert!(matches!(
            pick(&data, Some(home)),
            Some(SwiftCredentialSource::NetrcData(_))
        ));
        match pick(&[], Some(home)) {
            Some(SwiftCredentialSource::NetrcFile { path, .. }) => {
                assert_eq!(path, home.join(".netrc"));
            }
            other => panic!("expected the netrc file, got {other:?}"),
        }
        assert!(pick(&[], None).is_none());
    }

    #[test]
    fn test_unusable_netrc_data_warns_without_its_content_and_falls_through() {
        let logs = deps_core::test_util::capture_tracing_output(|| {
            let vars = [(NETRC_DATA_VAR, "machine a.dev login secret-user")];
            let source = SwiftCredentialSource::from_lookup(
                lookup(&vars),
                Some(Path::new("home")),
                UserConfigPlatform::Other,
            );
            assert!(matches!(
                source,
                Some(SwiftCredentialSource::NetrcFile { .. })
            ));
        });
        assert!(logs.contains(NETRC_DATA_VAR), "{logs}");
        assert!(!logs.contains("secret-user"), "{logs}");
    }

    #[test]
    fn test_macos_ignores_the_netrc_file_default_entry() {
        let default_entry = |platform| match SwiftCredentialSource::from_lookup(
            lookup(&[]),
            Some(Path::new("home")),
            platform,
        ) {
            Some(SwiftCredentialSource::NetrcFile { default_entry, .. }) => default_entry,
            other => panic!("expected the netrc file, got {other:?}"),
        };
        assert_eq!(
            default_entry(UserConfigPlatform::MacOs),
            DefaultEntry::Ignore
        );
        assert_eq!(
            default_entry(UserConfigPlatform::Other),
            DefaultEntry::Honor
        );
    }

    #[test]
    fn test_netrc_credential_binds_by_host_to_trusted_urls_only() {
        let tier = user_tier_with_types(&[]);
        let netrc = netrc(NETRC);
        let bind = |url: &SwiftRegistryUrl| {
            bind_credential(url, &tier, CredentialLookup::PerHost(&netrc))
                .map(|auth| auth.header_value().to_string())
        };
        assert_eq!(
            bind(&url(RegistryTrust::Trusted)).as_deref(),
            Some("Basic ZGVwbG95Omh1bnRlcjI=")
        );
        assert_eq!(bind(&url(RegistryTrust::WorkspaceDeclared)), None);

        let other_host =
            SwiftRegistryUrl::for_test("https://other.example/api", RegistryTrust::Trusted);
        assert_eq!(
            bind(&other_host).as_deref(),
            Some("Basic ZmFsbGJhY2s6ZmFsbGJhY2stcHc="),
            "the default entry applies to a Trusted host without a machine entry"
        );
        let no_default = Netrc::parse(
            "machine swift.acme.dev login deploy password hunter2",
            NetrcFlavor::InMemory,
        )
        .unwrap();
        assert!(
            bind_credential(&other_host, &tier, CredentialLookup::PerHost(&no_default)).is_none()
        );
    }

    #[test]
    fn test_netrc_login_named_token_is_sent_as_a_bearer() {
        let tier = user_tier_with_types(&[]);
        let netrc = netrc("machine swift.acme.dev login token password t0k");
        let bound = bind_credential(
            &url(RegistryTrust::Trusted),
            &tier,
            CredentialLookup::PerHost(&netrc),
        );
        assert_eq!(bound.unwrap().header_value(), "Bearer t0k");
    }

    #[test]
    fn test_source_debug_never_renders_a_credential() {
        let probe = deps_core::conformance::CREDENTIAL_PROBE_SECRET;
        let content = format!("machine a.dev login deploy password {probe}");
        let data = [(NETRC_DATA_VAR, content.as_str())];
        let source =
            SwiftCredentialSource::from_lookup(lookup(&data), None, UserConfigPlatform::Other)
                .unwrap();
        let rendered = format!("{source:?}");
        assert!(!rendered.contains(probe), "{rendered}");
        assert!(!rendered.contains("deploy"), "{rendered}");
    }

    fn url(trust: RegistryTrust) -> SwiftRegistryUrl {
        SwiftRegistryUrl::for_test("https://swift.acme.dev/api", trust)
    }

    fn user_tier_with_types(types: &[(&str, SwiftAuthType)]) -> UserTier {
        UserTier::for_test(
            &["https://swift.acme.dev/api"],
            types
                .iter()
                .map(|(host, ty)| (crate::config::RegistryHostKey::parse(host).unwrap(), *ty))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn test_bind_attaches_only_to_trusted() {
        let tier = user_tier_with_types(&[]);
        let credential = token("t");
        let bound = bind_credential(
            &url(RegistryTrust::Trusted),
            &tier,
            CredentialLookup::Shared(&credential),
        );
        assert_eq!(bound.unwrap().header_value(), "Bearer t");
        assert!(
            bind_credential(
                &url(RegistryTrust::WorkspaceDeclared),
                &tier,
                CredentialLookup::Shared(&credential)
            )
            .is_none()
        );
        assert!(
            bind_credential(&url(RegistryTrust::Trusted), &tier, CredentialLookup::None).is_none()
        );
    }

    #[test]
    fn test_bind_uses_user_tier_auth_type_for_the_registry_host() {
        let tier = user_tier_with_types(&[("swift.acme.dev", SwiftAuthType::Basic)]);
        let credential = token("t");
        let bound = bind_credential(
            &url(RegistryTrust::Trusted),
            &tier,
            CredentialLookup::Shared(&credential),
        );
        assert_eq!(bound.unwrap().header_value(), "Basic dG9rZW46dA==");

        let other_host = user_tier_with_types(&[("other.example", SwiftAuthType::Basic)]);
        let bound = bind_credential(
            &url(RegistryTrust::Trusted),
            &other_host,
            CredentialLookup::Shared(&credential),
        );
        assert_eq!(bound.unwrap().header_value(), "Bearer t");
    }
}
