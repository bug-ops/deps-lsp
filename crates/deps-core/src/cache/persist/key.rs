//! Eligibility rule for entries that may be persisted to disk.
//!
//! [`PersistKey`] is the only way to name an entry on disk. It can be built
//! solely from a request that is anonymous, baseline-tier, `https`, addressed
//! to a [`PersistableHost`] and carrying only [`PersistableQueryKey`]
//! parameters with plain values, so a token-bearing URL is unrepresentable.

use crate::cache::CacheTier;
use crate::cache::auth::KeyAuth;
use crate::hash::fnv1a64;
use std::ffi::OsStr;
use std::num::NonZeroU32;
use url::{Host, Url};

const MAX_QUERY_VALUE_LEN: usize = 32;

crate::macros::closed_str_enum! {
    /// A registry host whose responses may be persisted.
    ///
    /// Closed on purpose: a new host needs an explicit variant, and
    /// self-hosted or IP hosts can never qualify.
    ///
    /// Only hosts whose cached requests are fully identified by the URL belong here. `api.osv.dev`
    /// and `api.deps.dev` are excluded because their queries are POSTs whose response depends on the
    /// request body, which a URL-only [`PersistKey`] cannot name (#2141).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(super) enum PersistableHost {
        /// `api.github.com`
        ApiGithubCom => "api.github.com",
        /// `gitlab.com`
        GitlabCom => "gitlab.com",
        /// `index.crates.io`
        IndexCratesIo => "index.crates.io",
        /// `crates.io`
        CratesIo => "crates.io",
        /// `registry.npmjs.org`
        RegistryNpmjsOrg => "registry.npmjs.org",
        /// `pypi.org`
        PypiOrg => "pypi.org",
        /// `proxy.golang.org`
        ProxyGolangOrg => "proxy.golang.org",
        /// `rubygems.org`
        RubygemsOrg => "rubygems.org",
        /// `pub.dev`
        PubDev => "pub.dev",
        /// `repo1.maven.org`
        Repo1MavenOrg => "repo1.maven.org",
        /// `dl.google.com`
        DlGoogleCom => "dl.google.com",
        /// `plugins.gradle.org`
        PluginsGradleOrg => "plugins.gradle.org",
        /// `repo.packagist.org`
        RepoPackagistOrg => "repo.packagist.org",
        /// `api.nuget.org`
        ApiNugetOrg => "api.nuget.org",
        /// `jsr.io`
        JsrIo => "jsr.io",
        /// `api.jsr.io`
        ApiJsrIo => "api.jsr.io",
    }
    /// Every host, in declaration order.
    all: pub(super);
    /// The canonical host name.
    #[must_use]
    to_str: pub(super) as_str;
    /// Parses an exact, lowercase host name; anything else is `None`.
    #[must_use]
    parse: pub(super) from_host;
}

/// Host names of every [`PersistableHost`], for tests that pin the allow-list against what the
/// ecosystem crates fetch by default.
#[doc(hidden)]
pub fn persistable_hosts() -> impl Iterator<Item = &'static str> {
    PersistableHost::ALL
        .iter()
        .copied()
        .map(PersistableHost::as_str)
}

const HASH_LEN: usize = 16;
const ENTRY_EXTENSION: &str = "entry";

fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The shape of a file in the store directory, as the writer names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreFileKind {
    /// A finished entry: `{16 hex}.entry`, matched ASCII case-insensitively.
    Entry,
    /// An in-flight temp file of the atomic writer, matched ASCII case-insensitively.
    Tmp,
}

impl StoreFileKind {
    /// Classifies a directory entry name; `None` for anything the store did not create.
    ///
    /// The whole name is matched ASCII case-insensitively on every platform, because case
    /// sensitivity is a property of the volume: on a case-insensitive one the writer's
    /// `{hex}.entry` may be listed as `{HEX}.ENTRY`, and such a file must still be pruned.
    /// Callers must act on the real directory-entry path, never on a rebuilt lowercase name.
    #[must_use]
    pub(super) fn classify(name: &OsStr) -> Option<Self> {
        let lowered = name.to_str()?.to_ascii_lowercase();
        let name = lowered.as_str();
        let (stem, rest) = name.split_once('.')?;
        if stem.len() != HASH_LEN || !stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let tail = rest.strip_prefix(ENTRY_EXTENSION)?;
        if tail.is_empty() {
            return Some(Self::Entry);
        }
        let mut numbers = tail
            .strip_prefix(".deps-cli-")?
            .strip_suffix(".tmp")?
            .split('-');
        let (pid, nanos) = (numbers.next()?, numbers.next()?);
        (numbers.next().is_none() && is_decimal(pid) && is_decimal(nanos)).then_some(Self::Tmp)
    }
}

crate::macros::closed_str_enum! {
    /// A query parameter that may appear in a persisted URL.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum PersistableQueryKey {
        Page => "page",
        PerPage => "per_page",
        OrderBy => "order_by",
        Sort => "sort",
    }
    #[expect(dead_code, reason = "only the exhaustive match of to_str and parse is used")]
    all: ;
    to_str: as_str;
    parse: from_name;
}

/// A query value restricted to `[A-Za-z0-9_.-]{1,32}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryValue(String);

impl QueryValue {
    fn new(raw: &str) -> Option<Self> {
        let plain = (1..=MAX_QUERY_VALUE_LEN).contains(&raw.len())
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        plain.then(|| Self(raw.to_owned()))
    }
}

/// A non-zero `page` query value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct PageNumber(NonZeroU32);

impl PageNumber {
    /// Returns `None` for zero.
    #[must_use]
    pub(super) const fn new(n: u32) -> Option<Self> {
        match NonZeroU32::new(n) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    const fn get(self) -> u32 {
        self.0.get()
    }

    /// Rejects leading zeros so `page=02` and `page=2` cannot become distinct keys.
    fn parse(raw: &str) -> Option<Self> {
        if !raw.bytes().all(|b| b.is_ascii_digit()) || (raw.len() > 1 && raw.starts_with('0')) {
            return None;
        }
        raw.parse().ok().and_then(Self::new)
    }
}

/// How a `page` query parameter relates to its siblings.
///
/// The caller declares this because only it knows whether `page` selects
/// one slice of a listing or is just a parameter of a standalone response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PageRole {
    /// One page of a paginated listing.
    ListingPage,
    /// A response that stands alone despite carrying `page`.
    Standalone,
}

/// A cache key proven eligible for disk persistence.
///
/// Holds the normalized URL, its validated query pairs in original order,
/// the request's `Accept` value and the declared [`PageRole`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PersistKey {
    url: String,
    pairs: Vec<(PersistableQueryKey, QueryValue)>,
    page: Option<PageNumber>,
    accept: String,
    page_role: Option<PageRole>,
}

impl PersistKey {
    /// Returns `Some` only for an eligible request.
    ///
    /// Eligible means: [`CacheTier::Baseline`], anonymous auth without a
    /// credential partition, `https` on the default port, no userinfo or
    /// fragment, a [`PersistableHost`] domain, and a query made only of
    /// distinct [`PersistableQueryKey`] pairs with plain values. A `page`
    /// pair additionally requires a declared `page_role`. Never panics.
    #[must_use]
    pub(super) fn new(
        url: &str,
        tier: CacheTier,
        auth: KeyAuth,
        accept: &str,
        page_role: Option<PageRole>,
    ) -> Option<Self> {
        match tier {
            CacheTier::Baseline => {}
            CacheTier::WorkspaceDeclared(_) | CacheTier::Pinned { .. } => return None,
        }
        match auth {
            KeyAuth::Anonymous(None) => {}
            KeyAuth::Anonymous(Some(_)) | KeyAuth::Credential(_) => return None,
        }

        let parsed = Url::parse(url).ok()?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.port().is_some()
        {
            return None;
        }
        match parsed.host()? {
            Host::Domain(domain) => {
                PersistableHost::from_host(domain)?;
            }
            Host::Ipv4(_) | Host::Ipv6(_) => return None,
        }

        let (pairs, page) = parse_query(parsed.query())?;
        if page.is_some() && page_role.is_none() {
            return None;
        }

        Some(Self {
            url: parsed.as_str().to_owned(),
            pairs,
            page,
            accept: accept.to_owned(),
            page_role,
        })
    }

    /// The normalized URL.
    #[must_use]
    pub(super) fn url(&self) -> &str {
        &self.url
    }

    /// The request's `Accept` value, verbatim.
    #[must_use]
    pub(super) fn accept(&self) -> &str {
        &self.accept
    }

    /// The file name this key is stored under: `{fnv1a64(url):016x}.entry`.
    #[must_use]
    pub(super) fn file_name(&self) -> String {
        format!("{:016x}.{ENTRY_EXTENSION}", fnv1a64(self.url.as_bytes()))
    }

    /// The `page` value, when present.
    #[must_use]
    pub(super) const fn page(&self) -> Option<PageNumber> {
        self.page
    }

    /// The declared role of the `page` pair, when the caller supplied one.
    #[must_use]
    pub(super) const fn page_role(&self) -> Option<PageRole> {
        self.page_role
    }

    /// The same key with only the `page` value replaced.
    ///
    /// Query order and every other pair stay byte-identical. A key without a
    /// `page` pair is its own page 1; any other `n` yields `None`.
    #[must_use]
    pub(super) fn sibling_page(&self, n: PageNumber) -> Option<Self> {
        if self.page.is_none() {
            return (n.get() == 1).then(|| self.clone());
        }
        let mut sibling = self.clone();
        for (key, value) in &mut sibling.pairs {
            if *key == PersistableQueryKey::Page {
                *value = QueryValue(n.get().to_string());
            }
        }
        sibling.page = Some(n);
        let query = sibling
            .pairs
            .iter()
            .map(|(key, value)| format!("{}={}", key.as_str(), value.0))
            .collect::<Vec<_>>()
            .join("&");
        let base = self
            .url
            .split_once('?')
            .map_or(self.url.as_str(), |(b, _)| b);
        sibling.url = format!("{base}?{query}");
        Some(sibling)
    }
}

type QueryPairs = Vec<(PersistableQueryKey, QueryValue)>;

fn parse_query(query: Option<&str>) -> Option<(QueryPairs, Option<PageNumber>)> {
    let mut pairs: QueryPairs = Vec::new();
    let mut page = None;
    for raw in query.into_iter().flat_map(|q| q.split('&')) {
        let (name, value) = raw.split_once('=')?;
        let key = PersistableQueryKey::from_name(name)?;
        if pairs.iter().any(|(seen, _)| *seen == key) {
            return None;
        }
        let value = QueryValue::new(value)?;
        if key == PersistableQueryKey::Page {
            page = Some(PageNumber::parse(&value.0)?);
        }
        pairs.push((key, value));
    }
    Some((pairs, page))
}
