//! Generic "never surfaced via `Debug`/`Display`" wrapper for in-memory secrets.
//!
//! `deps_cargo::config::AuthToken`, `deps_nuget::config::NuGetAuth`, and
//! `deps_nuget::config::RedactedSecret` each hand-rolled the same single-field tuple struct: a
//! private/crate-visible constructor, an `as_str()` accessor documented "never logged,
//! printed, or otherwise surfaced", and hand-written `Debug`/`Display` impls that print `***`
//! (#573). [`Redacted<T>`] is the one place that pattern is implemented, so the call sites
//! cannot silently diverge on it and a new ecosystem crate needing the same guarantee does
//! not reinvent it — [`ApiToken`] (#1480 item 8) is this module's own generic token wrapper
//! built directly on [`Redacted<T>`], replacing what were previously independent hand-rolled
//! `AuthToken` copies in `deps_core::github` and `deps_gitlab_ci::client`.
//!
//! Placed beside [`crate::redact::redact_userinfo`], which owns the adjacent "a
//! credential must not leak via a log line" concern for URLs specifically, while this module
//! owns it for an owned secret value held in memory.
//!
//! Beyond redacting `Debug`/`Display`, [`Redacted<T>`] zeroizes its backing memory on drop
//! (issue #574) — after the value goes out of scope, a core dump or a read of freed/swapped
//! memory cannot recover the plaintext credential.
//!
//! That guarantee only holds for the wrapper itself: a caller that copies
//! [`Redacted::expose_secret`]'s result into a plain `String` (e.g. via `format!`) must not
//! let that copy outlive an unzeroized scope. The preferred fix (issue #672) is to format the
//! derived value — e.g. a `Bearer`/`Basic` `Authorization` header — once at construction time
//! and rewrap it in a new [`Redacted<T>`] right away, the way [`ApiToken`],
//! `deps_cargo::config::AuthToken`, and `deps_nuget::config::NuGetAuth` all do; reach for a
//! bare [`zeroize::Zeroizing`] only when that per-request re-derivation is unavoidable.
//!
//! [`digest_salt`] and [`auth_digest`] cover the adjacent "identify a credential for a cache
//! key without exposing it in a log line" concern (issue #1003): `deps-gitlab-ci` and
//! `deps-nuget` each used to carry their own copy of this salted-hash pair.

use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use zeroize::{Zeroize, Zeroizing};

/// A secret value whose `Debug`/`Display` output is always `***`, and whose backing memory
/// is zeroized when it is dropped.
///
/// Wrap any credential that must never reach a log line, a panic message, or a future
/// `#[derive(Debug)]` added to a struct embedding it. `T` defaults to `String`, the shape
/// every current call site needs; a caller that needs a different backing type must supply
/// one that implements [`Zeroize`] (e.g. secret bytes as `Vec<u8>`).
///
/// # Examples
///
/// ```
/// use deps_core::secret::Redacted;
///
/// let token = Redacted::new("super-secret-value".to_string());
/// assert_eq!(token.expose_secret(), "super-secret-value");
/// assert_eq!(format!("{token:?}"), "Redacted(***)");
/// assert_eq!(format!("{token}"), "***");
/// ```
#[derive(Clone)]
pub struct Redacted<T: Zeroize = String>(Zeroizing<T>);

impl<T: Zeroize> Redacted<T> {
    /// Wraps `value`. The only way to recover it is [`Self::expose_secret`] (for `T: AsRef<str>`).
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl<T: Zeroize + AsRef<str>> Redacted<T> {
    /// The raw secret value. Never pass this to anything but the one call site that needs
    /// it (e.g. attaching a header value to a request) — never to a log, error message, or
    /// anything `Debug`/`Display`-formatted downstream.
    ///
    /// Named `expose_secret()` rather than `as_str()` deliberately, mirroring the `secrecy`
    /// crate's `ExposeSecret::expose_secret()` convention: a name shared with hundreds of
    /// ordinary string-conversion methods across the workspace cannot be grepped for in
    /// isolation, while a distinctive name lets a reviewer or a future automated lint find
    /// every place a secret's plaintext crosses its wrapper boundary with a single search.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T: Zeroize> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted(***)")
    }
}

impl<T: Zeroize> std::fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Redacted<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: Zeroize + Eq> Eq for Redacted<T> {}

/// Hashes the wrapped value, not the redaction wrapper — so `Redacted<T>` can be used as (or
/// inside) a hash-map/set key exactly when `T` itself could be. Opt-in via `T: Hash`, same
/// shape as the `PartialEq`/`Eq` impls above: a caller that needs this must ask for it by
/// bounding on `Hash`, so embedding a secret in a hash key stays a deliberate choice at each
/// call site rather than something a blanket impl would make automatic.
impl<T: Zeroize + std::hash::Hash> std::hash::Hash for Redacted<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (*self.0).hash(state);
    }
}

/// Marker confirming [`Redacted<T>`] zeroizes its backing memory on drop — the actual
/// zeroing is performed by the wrapped [`Zeroizing<T>`] field's own [`Drop`] impl.
impl<T: Zeroize> zeroize::ZeroizeOnDrop for Redacted<T> {}

/// A per-process random salt, mixed into [`auth_digest`] so the digest cannot be
/// reconstructed offline from a known origin/secret pair.
///
/// An unsalted, non-cryptographic 64-bit hash of a credential value is a brute-force target if
/// it ever reaches a log line: an attacker who can enumerate candidate secrets offline can hash
/// each one and compare against the leaked digest, needing no access to the origin service at
/// all (issue #561). The salt closes that path — the digest cannot be reproduced without also
/// knowing this process's random salt, which is never logged, persisted, or exposed.
///
/// # Examples
///
/// ```
/// use deps_core::secret::digest_salt;
///
/// // Stable within one process, whatever its actual value is.
/// assert_eq!(digest_salt(), digest_salt());
/// ```
pub fn digest_salt() -> u64 {
    static SALT: OnceLock<u64> = OnceLock::new();
    *SALT.get_or_init(|| {
        use std::collections::hash_map::RandomState;
        use std::hash::BuildHasher;
        let mut hasher = RandomState::new().build_hasher();
        std::process::id().hash(&mut hasher);
        std::time::SystemTime::now().hash(&mut hasher);
        hasher.finish()
    })
}

/// A per-request auth identity for a cache key.
///
/// `None` when `secret` is `None`, otherwise a salted hash of `origin` and `secret`. Lets a
/// caller distinguish an authenticated response from an unauthenticated one (or one fetched
/// with a different credential) in a cache key without ever storing or logging the
/// credential itself.
///
/// # Examples
///
/// ```
/// use deps_core::secret::auth_digest;
///
/// assert_eq!(auth_digest("https://example.com", None), None);
///
/// let a = auth_digest("https://example.com", Some("token-a")).unwrap();
/// let b = auth_digest("https://other.example.com", Some("token-a")).unwrap();
/// assert_ne!(a, b, "different origins must digest differently");
///
/// let c = auth_digest("https://example.com", Some("token-b")).unwrap();
/// assert_ne!(a, c, "different secrets must digest differently");
/// ```
pub fn auth_digest(origin: &str, secret: Option<&str>) -> Option<u64> {
    let secret = secret?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    digest_salt().hash(&mut hasher);
    origin.hash(&mut hasher);
    secret.hash(&mut hasher);
    Some(hasher.finish())
}

/// A registry API bearer/private token, redacted everywhere except the one call site that
/// hands it to a request as a header value.
///
/// A thin wrapper over [`Redacted`] rather than a bare type alias: `Debug` prints
/// `ApiToken(***)`, not `Redacted(***)`, so a panic message or log line still names which
/// credential leaked its type. Extracted from `deps_core::github::AuthToken` and
/// `deps_gitlab_ci::client::AuthToken`, which had independently hand-rolled the identical
/// wrapper (#1480 item 8) — `deps_cargo::config::AuthToken` deliberately keeps its own
/// separate type, since its `pub(crate)` constructor is a provenance security boundary, not
/// just a redaction wrapper.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(Redacted);

impl ApiToken {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Redacted::new(value))
    }

    /// The raw header value, for attaching to a request. Never logged, printed, or
    /// otherwise surfaced — callers must not pass this to anything but a header value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// The wrapped secret, for attaching to a request as a sensitive credential header.
    #[must_use]
    pub const fn as_redacted(&self) -> &Redacted {
        &self.0
    }
}

impl From<Redacted> for ApiToken {
    fn from(value: Redacted) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken(***)")
    }
}

impl std::fmt::Display for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Formats `username`/`password` into a pre-formatted `Basic base64(username:password)`
/// `Authorization` header value.
///
/// Every intermediate (the raw `user:pass` string and its reversible base64 encoding) is held
/// in [`Zeroizing`] from the point of construction, so no un-zeroized plaintext copy outlives
/// the call. Shared by every ecosystem that builds a `Basic` header (NuGet, Swift), so the
/// encoding cannot diverge between them.
///
/// # Examples
///
/// ```
/// use deps_core::secret::basic_auth_header;
///
/// let header = basic_auth_header("user", "pass");
/// assert_eq!(header.expose_secret(), "Basic dXNlcjpwYXNz");
/// assert_eq!(format!("{header:?}"), "Redacted(***)");
/// ```
#[must_use]
pub fn basic_auth_header(username: &str, password: &str) -> Redacted {
    use base64::Engine;

    let mut user_pass = Zeroizing::new(String::with_capacity(username.len() + 1 + password.len()));
    user_pass.push_str(username);
    user_pass.push(':');
    user_pass.push_str(password);
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*user_pass));
    Redacted::new(format!("Basic {}", *encoded))
}

/// Formats `token` into a pre-formatted `Bearer <token>` `Authorization` header value.
///
/// The `Bearer` counterpart of [`basic_auth_header`]: every ecosystem that builds a `Bearer`
/// header (GitHub, Cargo sparse registries, Swift) routes through it so the format cannot
/// diverge between them.
///
/// # Examples
///
/// ```
/// use deps_core::secret::bearer_auth_header;
///
/// let header = bearer_auth_header("tok");
/// assert_eq!(header.expose_secret(), "Bearer tok");
/// assert_eq!(format!("{header:?}"), "Redacted(***)");
/// ```
#[must_use]
pub fn bearer_auth_header(token: &str) -> Redacted {
    Redacted::new(format!("Bearer {token}"))
}

/// Reads `var` from the environment, treating an unset or empty value as absent.
///
/// Returns a [`zeroize::Zeroizing`] wrapper so the raw token text is wiped from memory once
/// the caller drops it, mirroring [`Redacted`]'s own zeroize-on-drop guarantee. Does not log
/// anything itself — callers keep their own `tracing::info!("... detected, using
/// authenticated ... requests")` line, since only the caller knows which token/ecosystem it
/// is naming.
///
/// # Examples
///
/// ```
/// use deps_core::secret::token_from_env;
///
/// assert!(token_from_env("DEPS_CORE_DOCTEST_UNSET_TOKEN_VAR").is_none());
/// ```
#[must_use]
pub fn token_from_env(var: &str) -> Option<zeroize::Zeroizing<String>> {
    non_empty_token(std::env::var(var).ok())
}

/// Pure predicate behind [`token_from_env`] over an already-read `Option<String>`, mirroring
/// `crate::test_util::is_configured_token`'s split: `std::env::set_var` is `unsafe` (forbidden
/// workspace-wide), so no test can mutate the real environment to exercise the
/// present/empty-string branches directly — this lets them be tested without touching it.
fn non_empty_token(raw: Option<String>) -> Option<zeroize::Zeroizing<String>> {
    raw.map(zeroize::Zeroizing::new).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn debug_redacts() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "Redacted(***)");
    }

    #[test]
    fn display_redacts() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{secret}"), "***");
    }

    #[test]
    fn expose_secret_recovers_the_value() {
        let secret = Redacted::new("hunter2".to_string());
        assert_eq!(secret.expose_secret(), "hunter2");
    }

    #[test]
    fn equality_compares_the_wrapped_value() {
        assert_eq!(
            Redacted::new("hunter2".to_string()),
            Redacted::new("hunter2".to_string())
        );
        assert_ne!(
            Redacted::new("hunter2".to_string()),
            Redacted::new("other".to_string())
        );
    }

    #[test]
    fn embedding_in_a_debug_derive_still_redacts() {
        #[derive(Debug)]
        struct Wrapper {
            token: Redacted,
        }
        let wrapper = Wrapper {
            token: Redacted::new("hunter2".to_string()),
        };
        assert_eq!(wrapper.token.expose_secret(), "hunter2");
        let debug_output = format!("{wrapper:?}");
        assert!(debug_output.contains("Redacted(***)"), "{debug_output}");
        assert!(!debug_output.contains("hunter2"), "{debug_output}");
    }

    /// Compile-time proof `Redacted<T>` zeroizes on drop — inspecting freed memory
    /// portably isn't practical in a test, so this asserts the trait bound instead (the
    /// idiomatic pattern for the `zeroize` ecosystem).
    #[test]
    fn implements_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Redacted<String>>();
    }

    #[test]
    fn api_token_debug_and_display_redact() {
        let token = super::ApiToken::new("hunter2".to_string());
        assert_eq!(format!("{token:?}"), "ApiToken(***)");
        assert_eq!(format!("{token}"), "***");
        assert_eq!(token.expose_secret(), "hunter2");
    }

    #[test]
    fn basic_auth_header_encodes_user_and_password() {
        assert_eq!(
            super::basic_auth_header("user", "pass").expose_secret(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn token_from_env_absent_var_is_none() {
        assert!(super::token_from_env("DEPS_CORE_TEST_UNSET_TOKEN_VAR_XYZ").is_none());
    }

    #[test]
    fn non_empty_token_empty_string_is_none() {
        assert!(super::non_empty_token(Some(String::new())).is_none());
    }

    #[test]
    fn non_empty_token_present_value_is_some() {
        let token = super::non_empty_token(Some("hunter2".to_string())).unwrap();
        assert_eq!(*token, "hunter2");
    }

    #[test]
    fn auth_digest_no_secret_is_none() {
        assert_eq!(super::auth_digest("https://example.com", None), None);
    }

    #[test]
    fn auth_digest_same_origin_and_secret_is_stable_within_process() {
        let a = super::auth_digest("https://example.com", Some("token"));
        let b = super::auth_digest("https://example.com", Some("token"));
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn auth_digest_different_origins_diverge() {
        let a = super::auth_digest("https://example.com", Some("token")).unwrap();
        let b = super::auth_digest("https://other.example.com", Some("token")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn auth_digest_different_secrets_diverge() {
        let a = super::auth_digest("https://example.com", Some("token-a")).unwrap();
        let b = super::auth_digest("https://example.com", Some("token-b")).unwrap();
        assert_ne!(a, b);
    }
}
