//! Eligibility rule for entries that may be persisted to disk.
//!
//! [`PersistKey`] is the only way to name an entry on disk. It can be built
//! solely from a request that is anonymous, baseline-tier, `https`, addressed
//! to a [`PersistableHost`] and carrying only [`PersistableQueryKey`]
//! parameters with plain values, so a token-bearing URL is unrepresentable.

use crate::cache::CacheTier;
use crate::cache::auth::KeyAuth;
use std::num::NonZeroU32;
use url::{Host, Url};

const MAX_QUERY_VALUE_LEN: usize = 32;

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
    ApiGithubCom,
    /// `gitlab.com`
    GitlabCom,
    /// `index.crates.io`
    IndexCratesIo,
    /// `crates.io`
    CratesIo,
    /// `registry.npmjs.org`
    RegistryNpmjsOrg,
    /// `pypi.org`
    PypiOrg,
    /// `proxy.golang.org`
    ProxyGolangOrg,
    /// `rubygems.org`
    RubygemsOrg,
    /// `pub.dev`
    PubDev,
    /// `repo1.maven.org`
    Repo1MavenOrg,
    /// `dl.google.com`
    DlGoogleCom,
    /// `plugins.gradle.org`
    PluginsGradleOrg,
    /// `repo.packagist.org`
    RepoPackagistOrg,
    /// `api.nuget.org`
    ApiNugetOrg,
    /// `jsr.io`
    JsrIo,
    /// `api.jsr.io`
    ApiJsrIo,
}

impl PersistableHost {
    const ALL: [Self; 16] = [
        Self::ApiGithubCom,
        Self::GitlabCom,
        Self::IndexCratesIo,
        Self::CratesIo,
        Self::RegistryNpmjsOrg,
        Self::PypiOrg,
        Self::ProxyGolangOrg,
        Self::RubygemsOrg,
        Self::PubDev,
        Self::Repo1MavenOrg,
        Self::DlGoogleCom,
        Self::PluginsGradleOrg,
        Self::RepoPackagistOrg,
        Self::ApiNugetOrg,
        Self::JsrIo,
        Self::ApiJsrIo,
    ];

    /// Parses an exact, lowercase host name; anything else is `None`.
    #[must_use]
    pub(super) fn from_host(host: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|h| h.as_str() == host)
    }

    /// The canonical host name.
    #[must_use]
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ApiGithubCom => "api.github.com",
            Self::GitlabCom => "gitlab.com",
            Self::IndexCratesIo => "index.crates.io",
            Self::CratesIo => "crates.io",
            Self::RegistryNpmjsOrg => "registry.npmjs.org",
            Self::PypiOrg => "pypi.org",
            Self::ProxyGolangOrg => "proxy.golang.org",
            Self::RubygemsOrg => "rubygems.org",
            Self::PubDev => "pub.dev",
            Self::Repo1MavenOrg => "repo1.maven.org",
            Self::DlGoogleCom => "dl.google.com",
            Self::PluginsGradleOrg => "plugins.gradle.org",
            Self::RepoPackagistOrg => "repo.packagist.org",
            Self::ApiNugetOrg => "api.nuget.org",
            Self::JsrIo => "jsr.io",
            Self::ApiJsrIo => "api.jsr.io",
        }
    }
}

/// Host names of every [`PersistableHost`], for tests that pin the allow-list against what the
/// ecosystem crates fetch by default.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn persistable_hosts() -> impl Iterator<Item = &'static str> {
    PersistableHost::ALL
        .into_iter()
        .map(PersistableHost::as_str)
}

/// A query parameter that may appear in a persisted URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PersistableQueryKey {
    Page,
    PerPage,
    OrderBy,
    Sort,
}

impl PersistableQueryKey {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "page" => Some(Self::Page),
            "per_page" => Some(Self::PerPage),
            "order_by" => Some(Self::OrderBy),
            "sort" => Some(Self::Sort),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::PerPage => "per_page",
            Self::OrderBy => "order_by",
            Self::Sort => "sort",
        }
    }
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
