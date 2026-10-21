//! SwiftPM SCM-to-registry swizzling (spec 088): the typed vocabulary and the one pure decision.
//!
//! With `registries.swift_scm_to_registry = "replace"`, an eligible `.package(url:)` dependency
//! whose repository the trusted user-tier default registry maps to exactly one identity is parsed
//! as an `id:` dependency. The parser and the PreFetch probe both decide through
//! [`swizzle_decision`], so a parse can never disagree with the probe that warms its inputs.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource};
use deps_core::parser::DependencySource;
use deps_core::policy_config::{FetchConcurrency, FetchTimeout, ScmToRegistry};

use crate::config::{SwiftRegistryUrl, TrustedLookupRegistry};
use crate::package_location::RegistryIdentityBuf;
use crate::scm_memo::ScmIdentityMemo;
use crate::types::SwiftDependency;

/// How a dependency's version requirement is written, as set by the parser.
///
/// Only [`Self::Version`] can be swizzled: a registry holds versions, never branches or
/// revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiftRequirementForm {
    /// `from:`, `.upToNextMajor`, `.upToNextMinor`, `.exact`, `exact:` or a range, on a `url:` or
    /// `id:` dependency.
    Version,
    /// `.branch("...")` or `branch:`.
    Branch,
    /// `.revision("...")` or `revision:`.
    Revision,
    /// `.package(path:)`, which has no requirement at all.
    Path,
}

/// Where a dependency's identity comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwiftOrigin {
    /// The dependency is what the manifest declares.
    Declared,
    /// A `url:` dependency swapped to a registry identity; `scm` is the repository it was
    /// declared with.
    Swizzled {
        /// The repository URL the dependency was written with, credential-stripped.
        scm: ScmLookupUrl,
    },
}

/// The memo key of a repository URL: the credential-free URL with a lowercase host, no trailing
/// `/` and no `.git` suffix. The repository path keeps its case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CanonicalScmUrl(String);

impl CanonicalScmUrl {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A repository URL that is safe to send to a registry's `identifiers` endpoint.
///
/// [`Self::parse`] is the only constructor: it accepts `http`/`https` only and drops userinfo,
/// query and fragment, so a value never carries a credential. It holds the credential-stripped
/// URL as written (what goes on the wire, because a registry indexes the exact URL it was given)
/// and its canonical form (the memo key).
///
/// # Examples
///
/// ```
/// use deps_swift::ScmLookupUrl;
///
/// let url = ScmLookupUrl::parse("https://oauth2:TOKEN@GitHub.com/Apple/Swift-NIO.git?x=1").unwrap();
/// assert_eq!(url.wire(), "https://github.com/Apple/Swift-NIO.git");
/// assert!(ScmLookupUrl::parse("git@github.com:apple/swift-nio.git").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmLookupUrl {
    canonical: CanonicalScmUrl,
    wire: String,
}

impl ScmLookupUrl {
    /// Parses `written` as a repository URL; `None` for anything a registry must not be asked
    /// about: a non-`http(s)` scheme (scp-like and `ssh` URLs included), a credential-shaped
    /// path segment, or a URL without a repository path.
    #[must_use]
    pub fn parse(written: &str) -> Option<Self> {
        let stripped = deps_core::redact::strip_url_credentials(written)?;
        if !matches!(stripped.scheme(), "https" | "http") || stripped.host_str().is_none() {
            return None;
        }
        let wire = stripped.as_str();
        let trimmed = wire.trim_end_matches('/');
        let canonical = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        let canonical = canonical.trim_end_matches('/');
        let has_repository_path = stripped.path_segments()?.any(|segment| !segment.is_empty());
        has_repository_path.then(|| Self {
            canonical: CanonicalScmUrl(canonical.to_string()),
            wire: wire.to_string(),
        })
    }

    /// The credential-stripped URL as written, the form first sent to the registry.
    #[must_use]
    pub fn wire(&self) -> &str {
        &self.wire
    }

    /// The memo key.
    pub(crate) const fn canonical(&self) -> &CanonicalScmUrl {
        &self.canonical
    }
}

/// What the trusted registry answered for a repository URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentityLookup {
    /// Exactly one identity, which passed the SE-0292 identity grammar.
    Unique(RegistryIdentityBuf),
    /// Several identities claim the repository.
    Ambiguous,
    /// The registry does not know the repository (404 or an empty list).
    NotRegistered,
    /// The registry returned a single string that is not a valid identity.
    Rejected,
    /// The request failed (transport, 5xx, rate limit, policy) or its body was unreadable.
    Failed,
}

/// The normalized URL of a registry, as stored in `DependencySource::AlternateRegistry`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RegistryIndexUrl(String);

impl RegistryIndexUrl {
    pub(crate) fn of(url: &SwiftRegistryUrl) -> Self {
        Self(url.as_str().to_string())
    }

    fn from_index(index: &str) -> Self {
        Self(index.to_string())
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the identity memo is keyed by: the registry that was asked and the repository it was
/// asked about.
///
/// An answer is only evidence about the registry that gave it, so changing the user-tier
/// `[default]` registry misses and asks the new one instead of reusing the old one's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MemoKey {
    registry: RegistryIndexUrl,
    repository: CanonicalScmUrl,
}

impl MemoKey {
    pub(crate) fn new(registry: &SwiftRegistryUrl, scm: &ScmLookupUrl) -> Self {
        Self {
            registry: RegistryIndexUrl::of(registry),
            repository: scm.canonical().clone(),
        }
    }

    /// The URL of the registry the answer is about.
    pub(crate) const fn registry(&self) -> &RegistryIndexUrl {
        &self.registry
    }

    pub(crate) const fn repository(&self) -> &CanonicalScmUrl {
        &self.repository
    }
}

/// The form a dependency takes after the swizzle decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SwiftForm {
    /// The dependency stays a source-control dependency.
    Scm,
    /// The dependency is the registry identity `identity`, served by the registry at `index`.
    RegistryIdentity {
        identity: RegistryIdentityBuf,
        index: RegistryIndexUrl,
    },
}

/// Every input of [`swizzle_decision`].
pub(crate) struct SwizzleInput<'a> {
    pub mode: ScmToRegistry,
    pub lookup: Option<&'a TrustedLookupRegistry<'a>>,
    pub form: SwiftRequirementForm,
    pub scm: Option<&'a ScmLookupUrl>,
    pub answer: Option<&'a IdentityLookup>,
}

/// Decides whether a dependency is swapped to a registry identity.
///
/// Pure, so the parser and the probe cannot disagree. The result is
/// [`SwiftForm::RegistryIdentity`] only when the mode is `Replace`, a trusted user-tier default
/// exists, the requirement is a version, the URL is eligible, and the memoized answer is a unique
/// identity whose scope the user tier routes. Every other combination is [`SwiftForm::Scm`].
pub(crate) fn swizzle_decision(input: SwizzleInput<'_>) -> SwiftForm {
    let SwizzleInput {
        mode,
        lookup,
        form,
        scm,
        answer,
    } = input;
    match mode {
        ScmToRegistry::Replace => {}
        ScmToRegistry::Disabled => return SwiftForm::Scm,
    }
    let Some(lookup) = lookup else {
        return SwiftForm::Scm;
    };
    match form {
        SwiftRequirementForm::Version => {}
        SwiftRequirementForm::Branch
        | SwiftRequirementForm::Revision
        | SwiftRequirementForm::Path => return SwiftForm::Scm,
    }
    if scm.is_none() {
        return SwiftForm::Scm;
    }
    match answer {
        Some(IdentityLookup::Unique(identity)) => lookup
            .route(&identity.as_identity().scope_key())
            .map_or(SwiftForm::Scm, |registry| SwiftForm::RegistryIdentity {
                identity: identity.clone(),
                index: RegistryIndexUrl::of(&registry.url),
            }),
        Some(
            IdentityLookup::Ambiguous
            | IdentityLookup::NotRegistered
            | IdentityLookup::Rejected
            | IdentityLookup::Failed,
        )
        | None => SwiftForm::Scm,
    }
}

/// [`swizzle_decision`] with the answer read from `memo` at `now`; the one call both the parser
/// and the probe make.
pub(crate) fn decide_from_memo(
    mode: ScmToRegistry,
    lookup: Option<&TrustedLookupRegistry<'_>>,
    form: SwiftRequirementForm,
    scm: Option<&ScmLookupUrl>,
    memo: Option<&ScmIdentityMemo>,
    now: Instant,
) -> SwiftForm {
    let answer = match mode {
        ScmToRegistry::Replace => lookup
            .zip(scm)
            .zip(memo)
            .and_then(|((lookup, scm), memo)| {
                memo.get(&MemoKey::new(&lookup.default_registry().url, scm), now)
            })
            .map(|read| read.answer),
        ScmToRegistry::Disabled => None,
    };
    swizzle_decision(SwizzleInput {
        mode,
        lookup,
        form,
        scm,
        answer: answer.as_ref(),
    })
}

/// The form `dependency` was parsed with, reconstructed from what the parser stored.
pub(crate) fn parsed_form(dependency: &SwiftDependency) -> SwiftForm {
    match (&dependency.origin, &dependency.source) {
        (SwiftOrigin::Swizzled { .. }, DependencySource::AlternateRegistry { index, .. }) => {
            RegistryIdentityBuf::parse(dependency.name.as_str()).map_or(
                SwiftForm::Scm,
                |identity| SwiftForm::RegistryIdentity {
                    identity,
                    index: RegistryIndexUrl::from_index(index),
                },
            )
        }
        (SwiftOrigin::Swizzled { .. } | SwiftOrigin::Declared, _) => SwiftForm::Scm,
    }
}

/// Most identifiers one answer may list before it is called ambiguous without being read.
const MAX_IDENTIFIERS: usize = 256;

/// Lock-file entries naming each source-control pin by the registry identity the memo maps its
/// repository to, so a dependency swapped to that identity finds the in-use version a
/// `remoteSourceControl` pin recorded (spec 088 FR-018).
///
/// The repository is matched through [`ScmLookupUrl::parse`], the canonicalization the lookup
/// itself uses (`.git` and trailing `/` ignored), compared case-insensitively because a lock
/// file spells a repository's case independently of the manifest.
pub(crate) fn identity_pins(
    parsed: &ResolvedPackages,
    memo: &ScmIdentityMemo,
    registry: &SwiftRegistryUrl,
) -> Vec<ResolvedPackage> {
    let identities = memo.unique_by_lowercase_repository(&RegistryIndexUrl::of(registry));
    if identities.is_empty() {
        return Vec::new();
    }
    parsed
        .iter()
        .filter_map(|(_, package)| {
            let ResolvedSource::Git { url, .. } = &package.source else {
                return None;
            };
            let repository = ScmLookupUrl::parse(url)?;
            let identity = identities.get(&repository.canonical().as_str().to_ascii_lowercase())?;
            Some(ResolvedPackage::new(
                identity.to_string(),
                package.version.clone(),
                package.source.clone(),
            ))
        })
        .collect()
}

/// Classifies the identifiers a registry returned for one URL.
///
/// Identities are case-insensitive in SwiftPM, so spellings differing only in case are one
/// identity. One pass, ending at the second distinct identity, so a hostile answer costs
/// linear work.
pub(crate) fn classify_identifiers(identifiers: &[String]) -> IdentityLookup {
    let Some(first) = identifiers.first() else {
        return IdentityLookup::NotRegistered;
    };
    if identifiers.len() > MAX_IDENTIFIERS
        || identifiers
            .iter()
            .any(|other| !other.eq_ignore_ascii_case(first))
    {
        return IdentityLookup::Ambiguous;
    }
    RegistryIdentityBuf::parse(first).map_or_else(
        || {
            tracing::debug!(len = first.len(), "registry returned an invalid identity");
            IdentityLookup::Rejected
        },
        IdentityLookup::Unique,
    )
}

/// The live `registries.swift_scm_to_registry` setting, shared between the server's
/// configuration handling and the Swift parse context.
///
/// A change takes effect on the next parse; the server must re-parse open Swift documents when
/// it calls [`Self::set`].
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::ScmToRegistry;
/// use deps_swift::ScmToRegistryHandle;
///
/// let handle = ScmToRegistryHandle::default();
/// assert_eq!(handle.get(), ScmToRegistry::Disabled);
/// handle.set(ScmToRegistry::Replace);
/// assert_eq!(handle.get(), ScmToRegistry::Replace);
/// ```
#[derive(Debug)]
pub struct ScmToRegistryHandle {
    replace: AtomicBool,
    warned_missing_default: AtomicBool,
    fetch_timeout_secs: AtomicU64,
    fetch_concurrency: AtomicUsize,
}

impl Default for ScmToRegistryHandle {
    fn default() -> Self {
        Self {
            replace: AtomicBool::new(false),
            warned_missing_default: AtomicBool::new(false),
            fetch_timeout_secs: AtomicU64::new(FetchTimeout::DEFAULT.as_secs()),
            fetch_concurrency: AtomicUsize::new(FetchConcurrency::DEFAULT.get()),
        }
    }
}

impl ScmToRegistryHandle {
    /// A handle holding `mode`.
    #[must_use]
    pub fn new(mode: ScmToRegistry) -> Self {
        let handle = Self::default();
        handle.set(mode);
        handle
    }

    /// The current setting.
    #[must_use]
    pub fn get(&self) -> ScmToRegistry {
        if self.replace.load(Ordering::Relaxed) {
            ScmToRegistry::Replace
        } else {
            ScmToRegistry::Disabled
        }
    }

    /// Stores `mode`; a change re-arms the one-time "no trusted default registry" warning.
    pub fn set(&self, mode: ScmToRegistry) {
        let replace = match mode {
            ScmToRegistry::Replace => true,
            ScmToRegistry::Disabled => false,
        };
        if self.replace.swap(replace, Ordering::Relaxed) != replace {
            self.warned_missing_default.store(false, Ordering::Relaxed);
        }
    }

    /// Bounds the identity lookups by the user's fetch settings: each lookup is cut off after
    /// `timeout` and at most `concurrency` run at once.
    pub fn set_fetch_limits(&self, timeout: FetchTimeout, concurrency: FetchConcurrency) {
        self.fetch_timeout_secs
            .store(timeout.as_secs(), Ordering::Relaxed);
        self.fetch_concurrency
            .store(concurrency.get(), Ordering::Relaxed);
    }

    /// The per-lookup timeout.
    #[must_use]
    pub fn fetch_timeout(&self) -> FetchTimeout {
        FetchTimeout::try_from_secs(self.fetch_timeout_secs.load(Ordering::Relaxed))
            .unwrap_or_default()
    }

    /// The most lookups that run at once.
    #[must_use]
    pub fn fetch_concurrency(&self) -> FetchConcurrency {
        FetchConcurrency::try_new(self.fetch_concurrency.load(Ordering::Relaxed))
            .unwrap_or_default()
    }

    /// Warns once per setting change that `Replace` has no trusted user-tier default registry.
    pub(crate) fn warn_missing_default_once(&self) {
        if !self.warned_missing_default.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "registries.swift_scm_to_registry = \"replace\" needs a [default] registry in the \
                 user-level registries.json; source-control dependencies are left unchanged"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    #[test]
    fn test_lookup_url_strips_credentials_query_and_fragment() {
        let url = ScmLookupUrl::parse(
            "https://oauth2:TOKEN@gitlab.example.com/group/repo.git?private_token=y#frag",
        )
        .unwrap();
        assert_eq!(url.wire(), "https://gitlab.example.com/group/repo.git");
        assert_eq!(
            url.canonical().as_str(),
            "https://gitlab.example.com/group/repo"
        );
        assert!(!format!("{url:?}").contains("TOKEN"));
    }

    #[test]
    fn test_lookup_url_lowercases_host_but_keeps_repository_case() {
        let url = ScmLookupUrl::parse("https://GitHub.com/Apple/Swift-NIO/").unwrap();
        assert_eq!(
            url.canonical().as_str(),
            "https://github.com/Apple/Swift-NIO"
        );
        assert_eq!(url.wire(), "https://github.com/Apple/Swift-NIO/");
    }

    #[test]
    fn test_lookup_url_canonical_form_is_shared_by_spellings_of_one_repository() {
        let canonical = |written| {
            ScmLookupUrl::parse(written)
                .unwrap()
                .canonical()
                .as_str()
                .to_string()
        };
        let bare = canonical("https://github.com/apple/swift-nio");
        assert_eq!(canonical("https://github.com/apple/swift-nio.git"), bare);
        assert_eq!(canonical("https://github.com/apple/swift-nio.git/"), bare);
        assert_eq!(canonical("https://GITHUB.com/apple/swift-nio/"), bare);
    }

    #[test]
    fn test_lookup_url_rejects_everything_a_registry_must_not_be_asked_about() {
        for written in [
            "git@github.com:apple/swift-nio.git",
            "ssh://git@github.com/apple/swift-nio.git",
            "file:///srv/repo",
            "ftp://host/repo",
            "https://host.example/user:glpat-SECRET@internal",
            "https://github.com",
            "https://github.com/",
            "not a url",
            "",
        ] {
            assert!(ScmLookupUrl::parse(written).is_none(), "{written}");
        }
    }

    #[test]
    fn test_lookup_url_accepts_http() {
        assert!(ScmLookupUrl::parse("http://git.example/team/repo").is_some());
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn test_classify_identifiers_covers_every_answer() {
        assert_eq!(classify_identifiers(&[]), IdentityLookup::NotRegistered);
        assert_eq!(
            classify_identifiers(&ids(&["apple.swift-nio"])),
            IdentityLookup::Unique(RegistryIdentityBuf::parse("apple.swift-nio").unwrap())
        );
        assert_eq!(
            classify_identifiers(&ids(&["apple.swift-nio", "other.swift-nio"])),
            IdentityLookup::Ambiguous
        );
        assert_eq!(
            classify_identifiers(&ids(&["not an identity"])),
            IdentityLookup::Rejected
        );
    }

    #[test]
    fn test_classify_identifiers_treats_case_variants_as_one_identity() {
        assert_matches!(
            classify_identifiers(&ids(&["Apple.Swift-NIO", "apple.swift-nio"])),
            IdentityLookup::Unique(_)
        );
    }

    #[test]
    fn test_classify_identifiers_is_linear_and_capped() {
        let flood: Vec<String> = (0..200_000).map(|i| format!("s.p{i}")).collect();
        assert_eq!(classify_identifiers(&flood), IdentityLookup::Ambiguous);

        let same: Vec<String> = vec!["apple.swift-nio".to_string(); MAX_IDENTIFIERS + 1];
        assert_eq!(classify_identifiers(&same), IdentityLookup::Ambiguous);
    }

    #[test]
    fn test_handle_carries_the_live_fetch_limits() {
        let handle = ScmToRegistryHandle::default();
        assert_eq!(handle.fetch_timeout(), FetchTimeout::DEFAULT);
        assert_eq!(handle.fetch_concurrency(), FetchConcurrency::DEFAULT);

        let timeout = FetchTimeout::try_from_secs(30).unwrap();
        let concurrency = FetchConcurrency::try_new(3).unwrap();
        handle.set_fetch_limits(timeout, concurrency);
        assert_eq!(handle.fetch_timeout(), timeout);
        assert_eq!(handle.fetch_concurrency(), concurrency);
    }

    #[test]
    fn test_handle_round_trips_and_rearms_the_warning_on_change() {
        let handle = ScmToRegistryHandle::new(ScmToRegistry::Replace);
        assert_eq!(handle.get(), ScmToRegistry::Replace);
        handle.warn_missing_default_once();
        assert!(handle.warned_missing_default.load(Ordering::Relaxed));
        handle.set(ScmToRegistry::Replace);
        assert!(handle.warned_missing_default.load(Ordering::Relaxed));
        handle.set(ScmToRegistry::Disabled);
        assert!(!handle.warned_missing_default.load(Ordering::Relaxed));
        assert_eq!(handle.get(), ScmToRegistry::Disabled);
    }
}
