//! The one URL-alone registry trust rule (spec 084, #1822).
//!
//! A registry URL is [`RegistryTrust::Trusted`] if and only if its canonical form equals a URL
//! declared in an operator-owned file, whichever tier declared it in the current workspace;
//! otherwise it is [`RegistryTrust::WorkspaceDeclared`]. Trust is therefore a function of the
//! URL alone, so two workspaces sharing a URL never differ in transport or policy.
//!
//! The canonical form is the parsed URL after `${VAR}`/`%VAR%` expansion with the trailing `/`
//! trimmed; equality is per URL, never per host.
//!
//! This module decides **egress and workspace policy only**. A consumer may additionally bind a
//! credential to a Trusted URL (`deps-swift`, `deps-nuget`) or refuse a transport (`deps-cargo`);
//! those rules live with the consumer.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use super::{
    BlockedHost, CanonicalUrl, IndexUrlError, PolicyGate, RedactedUrl, RegistryAccessPolicy,
    RegistryUrlKind, TrustedConstantRegistryUrl, ValidatedRegistryUrl, WorkspaceRegistryAccess,
    classify_host, enforce_policy, validate_index_url,
};
use crate::EgressTier;
use crate::config_trust::OperatorPath;

/// Whether a registry URL is the operator's own or only workspace-declared.
///
/// **Exhaustive**: a wildcard arm at a consuming match would silently trust workspace input.
///
/// # Examples
///
/// ```
/// use deps_core::EgressTier;
/// use deps_core::net_policy::RegistryTrust;
///
/// assert_eq!(RegistryTrust::Trusted.egress(), EgressTier::Baseline);
/// assert_eq!(RegistryTrust::WorkspaceDeclared.egress(), EgressTier::Guarded);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryTrust {
    /// Equal to a URL declared in an operator-owned file: the workspace policy is skipped at URL
    /// time and at connect time, and requests use the system-proxy Baseline egress.
    Trusted,
    /// Declared only by the workspace: policy-gated and fetched over the Guarded egress.
    WorkspaceDeclared,
}

impl RegistryTrust {
    /// The egress tier requests to a URL of this trust use.
    #[must_use]
    pub const fn egress(self) -> EgressTier {
        match self {
            Self::Trusted => EgressTier::Baseline,
            Self::WorkspaceDeclared => EgressTier::Guarded,
        }
    }
}

/// The never-a-registry floor: the block for `url` when its host is of a class no setting
/// unblocks (loopback, link-local, cloud metadata, unspecified, reserved), else `None`.
///
/// Applies to Trusted registries too: operator ownership lifts the workspace policy, never this
/// floor. Test builds let `http` loopback through (the mock-server shape, which
/// `validate_index_url` admits only there); `https` loopback stays blocked everywhere.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{WorkspaceRegistryAccess, floor_block};
///
/// let metadata = url::Url::parse("https://169.254.169.254/").unwrap();
/// assert!(floor_block(&metadata, WorkspaceRegistryAccess::All).is_some());
/// let public = url::Url::parse("https://index.crates.io/").unwrap();
/// assert!(floor_block(&public, WorkspaceRegistryAccess::All).is_none());
/// ```
#[must_use]
pub fn floor_block(url: &url::Url, level: WorkspaceRegistryAccess) -> Option<BlockedHost> {
    let class = classify_host(url);
    let test_http_loopback = cfg!(any(test, feature = "test-util")) && url.scheme() == "http";
    (class.never_a_registry() && !test_http_loopback).then(|| BlockedHost::new(class, level))
}

/// The registry URLs one ecosystem's operator-owned file declares.
///
/// Built only from an [`OperatorPath`], so a repository cannot populate it. Misuse-resistant, not
/// unforgeable: the caller asserts that `candidates` are the file's entries.
///
/// # Examples
///
/// ```
/// use deps_core::config_trust::OperatorPath;
/// use deps_core::net_policy::OperatorRegistries;
///
/// let file = OperatorPath::for_test("/home/me/.npmrc");
/// let set = OperatorRegistries::declared_in(&file, ["https://npm.corp.example/"]);
/// assert!(set.contains_str("https://npm.corp.example"));
/// assert!(!set.contains_str("https://npm.corp.example/other"));
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OperatorRegistries {
    urls: HashSet<CanonicalUrl>,
}

/// Prints the size only: the set can hold query strings that carry tokens, so no URL is ever
/// rendered.
impl std::fmt::Debug for OperatorRegistries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorRegistries")
            .field("urls", &self.urls.len())
            .finish()
    }
}

impl OperatorRegistries {
    /// The URLs declared in `file`, given as the post-expansion strings the ecosystem resolved
    /// them to. An unparseable candidate, or one carrying userinfo, is skipped: neither could
    /// ever equal a validated URL, and a credential is never stored.
    #[must_use]
    pub fn declared_in<S: AsRef<str>>(
        _file: &OperatorPath,
        candidates: impl IntoIterator<Item = S>,
    ) -> Self {
        // `_file` is a provenance token only: holding one says `candidates` come from a file
        // located through the operator's own environment.
        let urls = candidates
            .into_iter()
            .filter_map(|candidate| url::Url::parse(candidate.as_ref()).ok())
            .filter(|url| url.username().is_empty() && url.password().is_none())
            .map(|url| CanonicalUrl::of(&url))
            .collect();
        Self { urls }
    }

    /// Whether the set declares no URL.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
    }

    /// Whether `candidate` (any spelling that parses to the same URL) is declared.
    #[must_use]
    pub fn contains_str(&self, candidate: &str) -> bool {
        url::Url::parse(candidate).is_ok_and(|url| self.contains(&url))
    }

    fn contains(&self, url: &url::Url) -> bool {
        self.urls.contains(&CanonicalUrl::of(url))
    }

    /// Validates `candidate` for kind `K` and classifies its trust.
    ///
    /// A URL in the set skips the workspace policy (the operator's own configuration) but never
    /// the never-a-registry floor; any other URL is validated under `policy`. `raw_for_log` is
    /// the pre-expansion text errors and logs name, always redacted.
    ///
    /// # Errors
    ///
    /// Returns `K::Error` when `candidate` is not a valid https registry URL for `K`, when a
    /// workspace-declared host is blocked by `policy`, or when a Trusted host is of a class that
    /// is never a registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::config_trust::OperatorPath;
    /// use deps_core::net_policy::{
    ///     OperatorRegistries, RegistryAccessPolicy, RegistryTrust, WorkspaceRegistryAccess,
    /// };
    /// # use deps_core::EcosystemId;
    /// # use deps_core::net_policy::{IndexUrlError, RegistryUrlKind};
    /// # pub enum Kind {}
    /// # impl deps_core::net_policy::private::Sealed for Kind {}
    /// # impl RegistryUrlKind for Kind {
    /// #     const ECOSYSTEM: EcosystemId = EcosystemId::Npm;
    /// #     const REJECT_QUERY_FRAGMENT: bool = false;
    /// #     type Error = IndexUrlError;
    /// # }
    ///
    /// let file = OperatorPath::for_test("/home/me/.npmrc");
    /// let operator = OperatorRegistries::declared_in(&file, ["https://npm.corp.example"]);
    /// let off = RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off);
    ///
    /// let trusted = operator
    ///     .classify::<Kind>("https://npm.corp.example/", "https://npm.corp.example/", &off)
    ///     .unwrap();
    /// assert_eq!(trusted.trust(), RegistryTrust::Trusted);
    ///
    /// // The policy still gates every other URL.
    /// assert!(operator
    ///     .classify::<Kind>("https://elsewhere.example", "https://elsewhere.example", &off)
    ///     .is_err());
    /// ```
    pub fn classify<K: RegistryUrlKind>(
        &self,
        candidate: &str,
        raw_for_log: &str,
        policy: &RegistryAccessPolicy,
    ) -> Result<DeclaredRegistry<K>, K::Error> {
        let parsed = validate_index_url(candidate, raw_for_log, K::ECOSYSTEM, PolicyGate::Skip)?;
        let shape = ValidatedRegistryUrl::<K>::from_validated(&parsed, raw_for_log)?;
        if self.contains(&parsed) {
            if let Some(block) = floor_block(&parsed, policy.get()) {
                tracing::warn!(
                    url = %RedactedUrl::new(raw_for_log),
                    class = ?block.class(),
                    ecosystem = %K::ECOSYSTEM,
                    "operator-declared registry host is never a registry; rejected"
                );
                return Err(IndexUrlError::BlockedHost { block }.into());
            }
            return Ok(DeclaredRegistry {
                url: shape,
                trust: RegistryTrust::Trusted,
            });
        }
        enforce_policy(&parsed, raw_for_log, K::ECOSYSTEM, policy)?;
        Ok(DeclaredRegistry {
            url: shape,
            trust: RegistryTrust::WorkspaceDeclared,
        })
    }
}

/// A validated registry URL together with the trust the URL-alone rule gave it.
///
/// Fields are private and the constructors are [`OperatorRegistries::classify`] and, for a
/// compile-time constant, [`Self::trusted_constant`], so trust is not assigned by a caller.
/// Misuse-resistant rather than sealed: the operator set a caller classifies against is the
/// caller's claim about which file it came from.
pub struct DeclaredRegistry<K> {
    url: ValidatedRegistryUrl<K>,
    trust: RegistryTrust,
}

impl<K> DeclaredRegistry<K> {
    /// The validated, normalized URL.
    #[must_use]
    pub const fn url(&self) -> &ValidatedRegistryUrl<K> {
        &self.url
    }

    /// The trust the rule assigned.
    #[must_use]
    pub const fn trust(&self) -> RegistryTrust {
        self.trust
    }

    /// The normalized URL text; never carries a trailing `/`.
    #[must_use]
    pub fn as_str(&self) -> &str
    where
        K: RegistryUrlKind,
    {
        self.url.as_str()
    }

    /// The egress tier requests to this URL use.
    #[must_use]
    pub const fn egress(&self) -> EgressTier {
        self.trust.egress()
    }
}

impl<K: TrustedConstantRegistryUrl> DeclaredRegistry<K> {
    /// A compile-time constant registry URL (the public registry), which is Trusted by
    /// construction: it is not workspace-declared input and needs no operator file to vouch for it.
    ///
    /// # Errors
    ///
    /// Returns `K::Error` when `raw` fails a non-policy check (https, userinfo, query/fragment).
    pub fn trusted_constant(raw: &'static str) -> Result<Self, K::Error> {
        Ok(Self {
            url: ValidatedRegistryUrl::<K>::new_trusted_constant(raw)?,
            trust: RegistryTrust::Trusted,
        })
    }
}

impl<K> Clone for DeclaredRegistry<K> {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            trust: self.trust,
        }
    }
}

impl<K: RegistryUrlKind> std::fmt::Debug for DeclaredRegistry<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclaredRegistry")
            .field("url", &self.url)
            .field("trust", &self.trust)
            .finish()
    }
}

impl<K> PartialEq for DeclaredRegistry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.trust == other.trust
    }
}

impl<K> Eq for DeclaredRegistry<K> {}

impl<K> Hash for DeclaredRegistry<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
        self.trust.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    use crate::EcosystemId;
    use crate::net_policy::{BlockingPolicy, HostClass, WorkspaceRegistryAccess};

    enum TestKind {}
    impl crate::net_policy::private::Sealed for TestKind {}
    impl RegistryUrlKind for TestKind {
        const ECOSYSTEM: EcosystemId = EcosystemId::Npm;
        const REJECT_QUERY_FRAGMENT: bool = false;
        type Error = IndexUrlError;
    }

    fn file() -> OperatorPath {
        OperatorPath::for_test("/home/me/.npmrc")
    }

    fn policy(level: WorkspaceRegistryAccess) -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(level)
    }

    fn classify(
        set: &OperatorRegistries,
        url: &str,
        level: WorkspaceRegistryAccess,
    ) -> Result<DeclaredRegistry<TestKind>, IndexUrlError> {
        set.classify::<TestKind>(url, url, &policy(level))
    }

    #[test]
    fn egress_follows_trust() {
        assert_eq!(RegistryTrust::Trusted.egress(), EgressTier::Baseline);
        assert_eq!(
            RegistryTrust::WorkspaceDeclared.egress(),
            EgressTier::Guarded
        );
    }

    #[test]
    fn operator_url_is_trusted_whatever_spelling_and_policy() {
        let set = OperatorRegistries::declared_in(&file(), ["https://Npm.Corp.example:443/"]);
        for spelling in [
            "https://npm.corp.example",
            "https://npm.corp.example/",
            "https://NPM.corp.example:443",
        ] {
            let declared = classify(&set, spelling, WorkspaceRegistryAccess::Off).unwrap();
            assert_eq!(declared.trust(), RegistryTrust::Trusted, "{spelling}");
            assert_eq!(declared.egress(), EgressTier::Baseline);
        }
    }

    #[test]
    fn workspace_only_url_is_workspace_declared_and_policy_gated() {
        let set = OperatorRegistries::declared_in(&file(), ["https://npm.corp.example"]);

        let declared = classify(
            &set,
            "https://repo.example",
            WorkspaceRegistryAccess::PublicOnly,
        )
        .unwrap();
        assert_eq!(declared.trust(), RegistryTrust::WorkspaceDeclared);

        let blocked = classify(&set, "https://repo.example", WorkspaceRegistryAccess::Off);
        assert_matches!(blocked, Err(IndexUrlError::BlockedHost { .. }));
    }

    #[test]
    fn same_host_different_path_is_not_trusted() {
        let set = OperatorRegistries::declared_in(&file(), ["https://npm.corp.example/team-a"]);

        let other = classify(
            &set,
            "https://npm.corp.example/team-b",
            WorkspaceRegistryAccess::PublicOnly,
        )
        .unwrap();
        assert_eq!(other.trust(), RegistryTrust::WorkspaceDeclared);

        let off = classify(
            &set,
            "https://npm.corp.example/team-b",
            WorkspaceRegistryAccess::Off,
        );
        assert_matches!(off, Err(IndexUrlError::BlockedHost { .. }));
    }

    #[test]
    fn trusted_never_a_registry_host_is_rejected_at_the_floor() {
        let set = OperatorRegistries::declared_in(&file(), ["https://169.254.169.254/"]);
        let error = classify(
            &set,
            "https://169.254.169.254",
            WorkspaceRegistryAccess::All,
        )
        .unwrap_err();
        let IndexUrlError::BlockedHost { block } = error else {
            panic!("expected a blocked host, got {error:?}");
        };
        assert_eq!(block.class(), HostClass::CloudMetadata);
        assert_eq!(block.policy(), BlockingPolicy::Floor);
    }

    #[test]
    fn userinfo_and_http_are_rejected_even_for_an_operator_url() {
        let set = OperatorRegistries::declared_in(
            &file(),
            [
                "https://user:pw@npm.corp.example",
                "http://npm.corp.example",
            ],
        );
        assert!(
            classify(
                &set,
                "https://user:pw@npm.corp.example",
                WorkspaceRegistryAccess::All
            )
            .is_err()
        );
        assert!(
            classify(
                &set,
                "http://npm.corp.example",
                WorkspaceRegistryAccess::All
            )
            .is_err()
        );
    }

    #[test]
    fn empty_set_trusts_nothing() {
        let set = OperatorRegistries::default();
        assert!(set.is_empty());
        let declared = classify(
            &set,
            "https://npm.corp.example",
            WorkspaceRegistryAccess::All,
        )
        .unwrap();
        assert_eq!(declared.trust(), RegistryTrust::WorkspaceDeclared);
    }

    #[test]
    fn debug_never_renders_a_url_or_credential() {
        let set = OperatorRegistries::declared_in(
            &file(),
            [
                "https://registry.corp.example/npm?_authToken=tok-secret",
                "https://user:s3cr3t@registry.corp.example/",
            ],
        );
        let rendered = format!("{set:?}");
        for leak in ["tok-secret", "s3cr3t", "registry.corp.example"] {
            assert!(!rendered.contains(leak), "{rendered}");
        }
        assert!(!set.contains_str("https://user:s3cr3t@registry.corp.example/"));
    }

    #[test]
    fn unparseable_candidates_are_skipped() {
        let set = OperatorRegistries::declared_in(&file(), ["not a url", "https://a.example"]);
        assert!(set.contains_str("https://a.example"));
        assert!(!set.is_empty());
    }
}
