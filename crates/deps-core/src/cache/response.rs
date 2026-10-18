//! Cached response entries with their validators and credential partitions.

use bytes::Bytes;
use reqwest::header;
use std::hash::Hash;
use std::time::Instant;

/// What a cached read does when revalidating a stored entry fails.
///
/// A caller that merges several cached responses into one answer (a paginated list) cannot
/// accept a silently stale part: the merged result would mix generations.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RevalidationFailure;
///
/// assert_eq!(RevalidationFailure::default(), RevalidationFailure::ServeStale);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RevalidationFailure {
    /// Serve the stored entry and log the failure (stale-while-revalidate).
    #[default]
    ServeStale,
    /// Return the revalidation error and keep the stored entry.
    Fail,
}

/// Stands in for a `Link` header value that is not visible ASCII, so a caller detecting
/// pagination fails closed (treats the list as truncated) instead of silently ignoring it.
const UNREADABLE_LINK: &str = r#"<>; rel="next""#;

/// The response headers a [`CachedResponse`] keeps, captured before the body consumes the
/// response.
pub(super) struct ResponseValidators {
    etag: Option<String>,
    last_modified: Option<String>,
    link: Option<String>,
}

impl ResponseValidators {
    pub(super) fn from_headers(headers: &header::HeaderMap) -> Self {
        let single = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let links: Vec<&str> = headers
            .get_all(header::LINK)
            .iter()
            .map(|v| v.to_str().unwrap_or(UNREADABLE_LINK))
            .collect();
        Self {
            etag: single(header::ETAG),
            last_modified: single(header::LAST_MODIFIED),
            link: (!links.is_empty()).then(|| links.join(", ")),
        }
    }

    pub(super) fn into_response(self, body: Bytes) -> CachedResponse {
        CachedResponse {
            body,
            etag: self.etag,
            last_modified: self.last_modified,
            link: self.link,
            fetched_at: Instant::now(),
        }
    }
}

/// Identifies the credential state a trusted-origin response was fetched under, so the cache can
/// keep bodies of different states apart (see
/// [`HttpCache::get_cached_trusted_origin_response`](crate::cache::HttpCache::get_cached_trusted_origin_response)).
///
/// A distinct type from the credential-header digests used for pinned requests: the two are
/// both hashes, but only a partition is a statement about "which state", and mixing them up
/// would silently share or split cache entries.
///
/// # Examples
///
/// ```
/// use deps_core::cache::CredentialPartition;
///
/// assert_eq!(CredentialPartition::new(7), CredentialPartition::new(7));
/// assert_ne!(CredentialPartition::new(7), CredentialPartition::new(8));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialPartition(u64);

impl CredentialPartition {
    /// Wraps the caller's hash of its credential state.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

/// Cached HTTP response with validation headers.
///
/// Stores response body and cache validation headers (ETag, Last-Modified)
/// for efficient conditional requests. The body uses `Bytes` which is an
/// Arc-like type optimized for network data, enabling zero-cost cloning
/// across multiple consumers without copying.
///
/// # Examples
///
/// ```
/// use deps_core::cache::CachedResponse;
/// use bytes::Bytes;
/// use std::time::Instant;
///
/// let response = CachedResponse::new(Bytes::from("response data")).with_etag("\"abc123\"");
///
/// // Clone is cheap - only increments reference count
/// let cloned = response.clone();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// Raw response body, shareable across consumers without copying.
    pub body: Bytes,
    /// `ETag` header from the response, used for `If-None-Match` revalidation.
    pub etag: Option<String>,
    /// `Last-Modified` header from the response, used for `If-Modified-Since` revalidation.
    pub last_modified: Option<String>,
    /// Raw `Link` header (RFC 8288) from the response, kept so a caller can detect a paginated
    /// list (see `pagination::ListCoverage::from_link_header`). Several `Link` headers are
    /// joined with `, `. Carried over unchanged on a 304 revalidation.
    pub link: Option<String>,
    /// Local time the response was fetched, used for TTL expiry checks.
    pub fetched_at: Instant,
}

impl CachedResponse {
    /// Constructs a `CachedResponse` for `body`, fetched now, with [`Self::etag`] and
    /// [`Self::last_modified`] left `None` — chain [`Self::with_etag`] and/or
    /// [`Self::with_last_modified`] to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::cache::CachedResponse;
    /// use bytes::Bytes;
    ///
    /// let response = CachedResponse::new(Bytes::from("response data")).with_etag("\"abc123\"");
    /// assert_eq!(response.etag.as_deref(), Some("\"abc123\""));
    /// ```
    #[must_use]
    pub fn new(body: Bytes) -> Self {
        Self {
            body,
            etag: None,
            last_modified: None,
            link: None,
            fetched_at: Instant::now(),
        }
    }

    /// Attaches the response's `Link` header. See [`Self::link`].
    #[must_use]
    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
        self
    }

    /// Attaches the response's `ETag` header. See [`Self::etag`].
    #[must_use]
    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    /// Attaches the response's `Last-Modified` header. See [`Self::last_modified`].
    #[must_use]
    pub fn with_last_modified(mut self, last_modified: impl Into<String>) -> Self {
        self.last_modified = Some(last_modified.into());
        self
    }

    /// Overrides when the response was fetched — otherwise [`Self::new`] stamps
    /// [`Instant::now`]. Lets external code (tests, benches) construct a backdated entry to
    /// exercise TTL-expiry behavior, the one thing a direct struct literal used to allow.
    #[must_use]
    pub const fn with_fetched_at(mut self, fetched_at: Instant) -> Self {
        self.fetched_at = fetched_at;
        self
    }
}
