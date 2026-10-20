//! Shares circuit breaker state between lookups that travel the same network path.
//!
//! An endpoint is derived from URL text alone (no DNS, no I/O) and stores no host, URL or
//! address: only a per-process keyed fingerprint, so it cannot leak a private registry URL
//! through logs or `Debug` output.

use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::LazyLock;

use url::Url;

static KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Hashes `value` with a key that is random per process and stable within it.
///
/// Every interactive-gate fingerprint goes through this one function, so a fingerprint can
/// neither be precomputed offline nor compared across processes.
pub(crate) fn keyed_hash64(value: &impl Hash) -> u64 {
    KEYS.hash_one(value)
}

/// The egress a request takes to reach a registry host, because two hops with the same URL but
/// different egress are different network paths.
///
/// # Examples
///
/// ```
/// use deps_core::EgressTier;
///
/// assert_ne!(EgressTier::Baseline, EgressTier::Guarded);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressTier {
    /// The system-proxy egress used for public and operator-trusted registries.
    Baseline,
    /// The workspace-guarded egress used for registries a workspace declared: direct unless a
    /// process-wide proxy setting says otherwise.
    Guarded,
}

/// Opaque, per-process fingerprint of a registry network path.
///
/// `Debug` prints no part of the value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointFingerprint(u64);

impl std::fmt::Debug for EndpointFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EndpointFingerprint(..)")
    }
}

/// A [`RegistryEndpoint`] computed on first use and then reused.
///
/// The fingerprint hashes URL text, which the gate would otherwise redo for every lookup. A
/// registry client holds one of these and computes it from its own immutable configuration.
///
/// # Examples
///
/// ```
/// use deps_core::{CachedEndpoint, EgressTier, RegistryEndpoint};
///
/// let cached = CachedEndpoint::default();
/// let endpoint = cached.get_or_compute(|| {
///     RegistryEndpoint::from_base_str("https://registry.example/", EgressTier::Baseline)
/// });
/// assert_eq!(cached.get_or_compute(|| RegistryEndpoint::Unresolved), endpoint);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CachedEndpoint(std::sync::OnceLock<RegistryEndpoint>);

impl CachedEndpoint {
    /// An empty cache, usable in `const` constructors.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::CachedEndpoint;
    ///
    /// const EMPTY: CachedEndpoint = CachedEndpoint::new();
    /// # let _ = EMPTY;
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    /// The cached endpoint, computing it with `compute` on the first call only.
    pub fn get_or_compute(&self, compute: impl FnOnce() -> RegistryEndpoint) -> RegistryEndpoint {
        *self.0.get_or_init(compute)
    }
}

/// The network path a registry lookup travels, as far as the registry can tell from URLs.
///
/// # Examples
///
/// ```
/// use deps_core::{EgressTier, RegistryEndpoint};
/// use url::Url;
///
/// let a = Url::parse("https://registry.example/npm/").unwrap();
/// let b = Url::parse("https://registry.example/npm").unwrap();
/// assert_eq!(
///     RegistryEndpoint::base(&a, EgressTier::Baseline),
///     RegistryEndpoint::base(&b, EgressTier::Baseline),
/// );
/// assert_ne!(
///     RegistryEndpoint::base(&a, EgressTier::Baseline),
///     RegistryEndpoint::base(&a, EgressTier::Guarded),
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryEndpoint {
    /// The registry cannot say where the lookup goes, so the breaker state stays scoped to the
    /// manifest and dependency source instead of being shared.
    Unresolved,
    /// The ordered hops of the lookup, fingerprinted.
    Resolved(EndpointFingerprint),
}

/// One hop as it enters the fingerprint: scheme, host, effective port, and the path without
/// one trailing slash. Userinfo, query and fragment never enter it.
#[derive(Hash)]
struct HopIdentity<'a> {
    scheme: &'a str,
    host: &'a str,
    port: Option<u16>,
    path: &'a str,
    egress: EgressTier,
}

impl RegistryEndpoint {
    /// A single-hop endpoint: `url`'s base reached through `egress`.
    ///
    /// Returns [`Self::Unresolved`] when `url` has no host.
    #[must_use]
    pub fn base(url: &Url, egress: EgressTier) -> Self {
        Self::chain([(url, egress)])
    }

    /// [`Self::base`] for a base URL held as text, such as a registry client's configured API
    /// base. Returns [`Self::Unresolved`] when `base` is not a URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{EgressTier, RegistryEndpoint};
    ///
    /// assert_ne!(
    ///     RegistryEndpoint::from_base_str("https://rubygems.org/api/v1", EgressTier::Baseline),
    ///     RegistryEndpoint::Unresolved,
    /// );
    /// assert_eq!(
    ///     RegistryEndpoint::from_base_str("not a url", EgressTier::Baseline),
    ///     RegistryEndpoint::Unresolved,
    /// );
    /// ```
    #[must_use]
    pub fn from_base_str(base: &str, egress: EgressTier) -> Self {
        Self::chain_from_strs([(base, egress)])
    }

    /// [`Self::chain`] for hops held as text, such as an index chain's configured bases.
    /// Returns [`Self::Unresolved`] when any hop is not a URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{EgressTier, RegistryEndpoint};
    ///
    /// let chain = RegistryEndpoint::chain_from_strs([
    ///     ("https://private.example/simple/", EgressTier::Guarded),
    ///     ("https://pypi.org/simple/", EgressTier::Baseline),
    /// ]);
    /// assert_ne!(chain, RegistryEndpoint::Unresolved);
    /// ```
    #[must_use]
    pub fn chain_from_strs<'a>(hops: impl IntoIterator<Item = (&'a str, EgressTier)>) -> Self {
        let parsed: Option<Vec<(Url, EgressTier)>> = hops
            .into_iter()
            .map(|(text, egress)| Url::parse(text).ok().map(|url| (url, egress)))
            .collect();
        parsed.map_or(Self::Unresolved, |hops| {
            Self::chain(hops.iter().map(|(url, egress)| (url, *egress)))
        })
    }

    /// An endpoint made of ordered hops, such as an index chain's head and fallbacks.
    ///
    /// Order and hop count are part of the identity. Returns [`Self::Unresolved`] when `hops`
    /// is empty or any hop has no host.
    #[must_use]
    pub fn chain<'a>(hops: impl IntoIterator<Item = (&'a Url, EgressTier)>) -> Self {
        let mut identities = Vec::new();
        for (url, egress) in hops {
            let Some(host) = url.host_str() else {
                return Self::Unresolved;
            };
            let path = url.path();
            identities.push(HopIdentity {
                scheme: url.scheme(),
                host,
                port: url.port_or_known_default(),
                path: path.strip_suffix('/').unwrap_or(path),
                egress,
            });
        }
        if identities.is_empty() {
            return Self::Unresolved;
        }
        Self::Resolved(EndpointFingerprint(keyed_hash64(&identities)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn base(text: &str, egress: EgressTier) -> RegistryEndpoint {
        RegistryEndpoint::base(&url(text), egress)
    }

    #[test]
    fn userinfo_query_and_trailing_slash_do_not_change_the_endpoint() {
        let plain = base("https://r.example/npm/", EgressTier::Baseline);
        let decorated = base(
            "https://user:pw@R.example:443/npm?token=1#frag",
            EgressTier::Baseline,
        );
        assert_eq!(plain, decorated);
    }

    #[test]
    fn path_port_scheme_and_egress_split_endpoints() {
        let reference = base("https://r.example/api/npm/local/", EgressTier::Baseline);
        for other in [
            base("https://r.example/api/npm/remote/", EgressTier::Baseline),
            base(
                "https://r.example:8443/api/npm/local/",
                EgressTier::Baseline,
            ),
            base("http://r.example/api/npm/local/", EgressTier::Baseline),
            base("https://r.example/api/npm/local/", EgressTier::Guarded),
        ] {
            assert_ne!(reference, other);
        }
    }

    #[test]
    fn chain_order_and_length_are_part_of_the_identity() {
        let (a, b) = (url("https://a.example/"), url("https://b.example/"));
        let ab = RegistryEndpoint::chain([(&a, EgressTier::Baseline), (&b, EgressTier::Baseline)]);
        let ba = RegistryEndpoint::chain([(&b, EgressTier::Baseline), (&a, EgressTier::Baseline)]);
        let only_a = RegistryEndpoint::chain([(&a, EgressTier::Baseline)]);
        assert_ne!(ab, ba);
        assert_ne!(ab, only_a);
    }

    #[test]
    fn hostless_or_empty_chains_are_unresolved() {
        assert_eq!(
            RegistryEndpoint::chain(std::iter::empty()),
            RegistryEndpoint::Unresolved
        );
        assert_eq!(
            base("file:///tmp/index", EgressTier::Baseline),
            RegistryEndpoint::Unresolved
        );
    }

    #[test]
    fn debug_hides_the_fingerprint_value() {
        let endpoint = base("https://r.example/", EgressTier::Baseline);
        assert_eq!(format!("{endpoint:?}"), "Resolved(EndpointFingerprint(..))");
    }

    #[test]
    fn keyed_hash_is_stable_within_a_process() {
        assert_eq!(keyed_hash64(&"x"), keyed_hash64(&"x"));
    }
}
