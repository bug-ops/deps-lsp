//! Environment credentials and `Authorization` header formatting for SE-0292 registries.
//!
//! The environment holds a single credential, not one per registry; [`bind_credential`] is the
//! only place that decides which registries receive it. Everything credential-shaped lives in
//! [`SwiftEnvCredential`] (fields redacted) or [`SwiftRegistryAuth`] (pre-formatted header,
//! redacted), so neither can reach a log line, `Debug` output, hover text or a cache key.

use deps_core::secret::{Redacted, basic_auth_header};
use zeroize::Zeroizing;

use crate::config::{SwiftAuthType, SwiftRegistryUrl, UserTier};

const TOKEN_VAR: &str = "SWIFTPM_REGISTRY_TOKEN";
const LOGIN_VAR: &str = "SWIFTPM_REGISTRY_LOGIN";
const PASSWORD_VAR: &str = "SWIFTPM_REGISTRY_PASSWORD";

/// The credential SwiftPM reads from the environment, before any registry-specific formatting.
///
/// `SWIFTPM_REGISTRY_TOKEN` wins over `SWIFTPM_REGISTRY_LOGIN`/`SWIFTPM_REGISTRY_PASSWORD`.
/// `Debug` never prints a value.
///
/// # Examples
///
/// ```
/// use deps_swift::SwiftEnvCredential;
///
/// let credential = SwiftEnvCredential::from_lookup(|name| {
///     (name == "SWIFTPM_REGISTRY_TOKEN").then(|| "t0ken".to_string().into())
/// });
/// assert!(format!("{credential:?}").contains("Token(Redacted(***))"));
/// ```
#[derive(Debug, Clone)]
pub enum SwiftEnvCredential {
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

impl SwiftEnvCredential {
    /// Reads the credential from the process environment; `None` when none is configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_swift::SwiftEnvCredential;
    ///
    /// // Whatever the environment holds, the value is never rendered.
    /// let credential = SwiftEnvCredential::from_environment();
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

/// Decides whether `credential` is sent to `url`, and formats it.
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
    credential: Option<&SwiftEnvCredential>,
) -> Option<SwiftRegistryAuth> {
    use crate::config::RegistryTrust;

    match url.trust() {
        RegistryTrust::Trusted => Some(credential?.format(user_tier.auth_type_for(url.host_key()))),
        RegistryTrust::WorkspaceDeclared => None,
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

    fn token(value: &str) -> SwiftEnvCredential {
        SwiftEnvCredential::Token(Redacted::new(value.to_string()))
    }

    fn login(user: &str, password: &str) -> SwiftEnvCredential {
        SwiftEnvCredential::Login {
            username: Redacted::new(user.to_string()),
            password: Redacted::new(password.to_string()),
        }
    }

    fn header(credential: &SwiftEnvCredential, auth_type: Option<SwiftAuthType>) -> String {
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
        let credential = SwiftEnvCredential::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(header(&credential, None), "Bearer t");
    }

    #[test]
    fn test_login_pair_is_used_without_token() {
        let vars = [(LOGIN_VAR, "u"), (PASSWORD_VAR, "p")];
        let credential = SwiftEnvCredential::from_lookup(lookup(&vars)).unwrap();
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
                SwiftEnvCredential::from_lookup(lookup(&vars)).is_none(),
                "{vars:?}"
            );
        }
    }

    #[test]
    fn test_partial_login_warning_names_only_variables() {
        let logs = deps_core::test_util::capture_tracing_output(|| {
            let vars = [(LOGIN_VAR, "secret-user")];
            let _ = SwiftEnvCredential::from_lookup(lookup(&vars));
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
        let bound = bind_credential(&url(RegistryTrust::Trusted), &tier, Some(&credential));
        assert_eq!(bound.unwrap().header_value(), "Bearer t");
        assert!(
            bind_credential(
                &url(RegistryTrust::WorkspaceDeclared),
                &tier,
                Some(&credential)
            )
            .is_none()
        );
        assert!(bind_credential(&url(RegistryTrust::Trusted), &tier, None).is_none());
    }

    #[test]
    fn test_bind_uses_user_tier_auth_type_for_the_registry_host() {
        let tier = user_tier_with_types(&[("swift.acme.dev", SwiftAuthType::Basic)]);
        let credential = token("t");
        let bound = bind_credential(&url(RegistryTrust::Trusted), &tier, Some(&credential));
        assert_eq!(bound.unwrap().header_value(), "Basic dG9rZW46dA==");

        let other_host = user_tier_with_types(&[("other.example", SwiftAuthType::Basic)]);
        let bound = bind_credential(&url(RegistryTrust::Trusted), &other_host, Some(&credential));
        assert_eq!(bound.unwrap().header_value(), "Bearer t");
    }
}
