use crate::error::{DepsError, Result};
use dashmap::DashMap;
use reqwest::{Client, StatusCode, header};
use std::sync::Arc;
use std::time::Instant;

/// Maximum number of cached entries to prevent unbounded memory growth.
const MAX_CACHE_ENTRIES: usize = 1000;

/// Validates that a URL uses HTTPS protocol.
///
/// Returns an error if the URL doesn't start with "https://".
/// This ensures all network requests are encrypted.
///
/// In test mode, HTTP URLs are allowed for mockito compatibility.
#[inline]
fn ensure_https(url: &str) -> Result<()> {
    #[cfg(not(test))]
    if !url.starts_with("https://") {
        return Err(DepsError::CacheError(format!(
            "URL must use HTTPS: {}",
            url
        )));
    }
    #[cfg(test)]
    let _ = url; // Silence unused warning in tests
    Ok(())
}

/// Cached HTTP response with validation headers.
///
/// Stores response body and cache validation headers (ETag, Last-Modified)
/// for efficient conditional requests. The body is wrapped in `Arc` for
/// zero-cost cloning across multiple consumers.
///
/// # Examples
///
/// ```
/// use deps_core::cache::CachedResponse;
/// use std::sync::Arc;
/// use std::time::Instant;
///
/// let response = CachedResponse {
///     body: Arc::new(b"response data".to_vec()),
///     etag: Some("\"abc123\"".into()),
///     last_modified: None,
///     fetched_at: Instant::now(),
/// };
///
/// // Clone is cheap - only increments Arc reference count
/// let cloned = response.clone();
/// assert!(Arc::ptr_eq(&response.body, &cloned.body));
/// ```
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub body: Arc<Vec<u8>>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub fetched_at: Instant,
}

/// HTTP cache with ETag and Last-Modified validation.
///
/// Implements RFC 7232 conditional requests to minimize network traffic.
/// All responses are cached with their validation headers, and subsequent
/// requests use `If-None-Match` (ETag) or `If-Modified-Since` headers
/// to check for updates.
///
/// The cache uses `Arc<Vec<u8>>` for response bodies, enabling efficient
/// sharing of cached data across multiple consumers without copying.
///
/// # Examples
///
/// ```no_run
/// use deps_core::cache::HttpCache;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let cache = HttpCache::new();
///
/// // First request - fetches from network
/// let data1 = cache.get_cached("https://index.crates.io/se/rd/serde").await?;
///
/// // Second request - uses conditional GET (304 Not Modified if unchanged)
/// let data2 = cache.get_cached("https://index.crates.io/se/rd/serde").await?;
///
/// // Both share the same underlying buffer
/// assert!(std::sync::Arc::ptr_eq(&data1, &data2));
/// # Ok(())
/// # }
/// ```
pub struct HttpCache {
    entries: DashMap<String, CachedResponse>,
    client: Client,
}

impl HttpCache {
    /// Creates a new HTTP cache with default configuration.
    ///
    /// The cache uses a 30-second timeout for all requests and identifies
    /// itself with a `deps-lsp/0.1.0` user agent.
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("deps-lsp/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to create HTTP client");

        Self {
            entries: DashMap::new(),
            client,
        }
    }

    /// Retrieves data from URL with intelligent caching.
    ///
    /// On first request, fetches data from the network and caches it.
    /// On subsequent requests, performs a conditional GET request using
    /// cached ETag or Last-Modified headers. If the server responds with
    /// 304 Not Modified, returns the cached data. Otherwise, fetches and
    /// caches the new data.
    ///
    /// If the conditional request fails due to network errors, falls back
    /// to the cached data (stale-while-revalidate pattern).
    ///
    /// # Returns
    ///
    /// Returns `Arc<Vec<u8>>` containing the response body. Multiple calls
    /// for the same URL return Arc clones pointing to the same buffer,
    /// avoiding unnecessary memory allocations.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::RegistryError` if the initial fetch fails or
    /// if no cached data exists and the network is unavailable.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_core::cache::HttpCache;
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let data = cache.get_cached("https://example.com/api/data").await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached(&self, url: &str) -> Result<Arc<Vec<u8>>> {
        // Evict old entries if cache is at capacity
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            self.evict_entries();
        }

        if let Some(cached) = self.entries.get(url) {
            // Attempt conditional request with cached headers
            match self.conditional_request(url, &cached).await {
                Ok(Some(new_body)) => {
                    // 200 OK - content changed, cache updated internally
                    return Ok(new_body);
                }
                Ok(None) => {
                    // 304 Not Modified - use cached body (cheap Arc clone)
                    return Ok(Arc::clone(&cached.body));
                }
                Err(e) => {
                    // Network error - fall back to cached body if available
                    tracing::warn!("conditional request failed, using cache: {}", e);
                    return Ok(Arc::clone(&cached.body));
                }
            }
        }

        // No cache entry - fetch fresh
        self.fetch_and_store(url).await
    }

    /// Performs conditional HTTP request using cached validation headers.
    ///
    /// Sends `If-None-Match` (ETag) and/or `If-Modified-Since` headers
    /// to check if the cached content is still valid.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Arc<Vec<u8>>))` - Server returned 200 OK with new content
    /// - `Ok(None)` - Server returned 304 Not Modified (cache is valid)
    /// - `Err(_)` - Network or HTTP error occurred
    async fn conditional_request(
        &self,
        url: &str,
        cached: &CachedResponse,
    ) -> Result<Option<Arc<Vec<u8>>>> {
        ensure_https(url)?;
        let mut request = self.client.get(url);

        if let Some(etag) = &cached.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &cached.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
        }

        let response = request.send().await.map_err(|e| DepsError::RegistryError {
            package: url.to_string(),
            source: e,
        })?;

        if response.status() == StatusCode::NOT_MODIFIED {
            // 304 Not Modified - content unchanged
            return Ok(None);
        }

        // 200 OK - content changed
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response
            .bytes()
            .await
            .map_err(|e| DepsError::RegistryError {
                package: url.to_string(),
                source: e,
            })?;

        let body_arc = Arc::new(body.to_vec());

        // Update cache with new response
        self.entries.insert(
            url.to_string(),
            CachedResponse {
                body: Arc::clone(&body_arc),
                etag,
                last_modified,
                fetched_at: Instant::now(),
            },
        );

        Ok(Some(body_arc))
    }

    /// Fetches a fresh response from the network and stores it in the cache.
    ///
    /// This method bypasses the cache and always makes a network request.
    /// The response is stored with its ETag and Last-Modified headers for
    /// future conditional requests.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::CacheError` if the server returns a non-2xx status code,
    /// or `DepsError::RegistryError` if the network request fails.
    pub(crate) async fn fetch_and_store(&self, url: &str) -> Result<Arc<Vec<u8>>> {
        ensure_https(url)?;
        tracing::debug!("fetching fresh: {}", url);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DepsError::RegistryError {
                package: url.to_string(),
                source: e,
            })?;

        if !response.status().is_success() {
            return Err(DepsError::CacheError(format!(
                "HTTP {} for {}",
                response.status(),
                url
            )));
        }

        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response
            .bytes()
            .await
            .map_err(|e| DepsError::RegistryError {
                package: url.to_string(),
                source: e,
            })?;

        let body_arc = Arc::new(body.to_vec());

        self.entries.insert(
            url.to_string(),
            CachedResponse {
                body: Arc::clone(&body_arc),
                etag,
                last_modified,
                fetched_at: Instant::now(),
            },
        );

        Ok(body_arc)
    }

    /// Clears all cached entries.
    ///
    /// This removes all cached responses, forcing the next request for
    /// any URL to fetch fresh data from the network.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evicts approximately 10% of cache entries when capacity is reached.
    ///
    /// Uses a simple random eviction strategy. In a production system,
    /// this could be replaced with LRU or TTL-based eviction.
    fn evict_entries(&self) {
        let target_removals = MAX_CACHE_ENTRIES / 10;
        let mut removed = 0;

        // Simple eviction: remove oldest entries by fetched_at timestamp
        let mut entries_to_remove = Vec::new();

        for entry in self.entries.iter() {
            entries_to_remove.push((entry.key().clone(), entry.value().fetched_at));
            if entries_to_remove.len() >= MAX_CACHE_ENTRIES {
                break;
            }
        }

        // Sort by age (oldest first)
        entries_to_remove.sort_by_key(|(_, time)| *time);

        // Remove oldest entries
        for (url, _) in entries_to_remove.iter().take(target_removals) {
            self.entries.remove(url);
            removed += 1;
        }

        tracing::debug!("evicted {} cache entries", removed);
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = HttpCache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let cache = HttpCache::new();
        cache.entries.insert(
            "test".into(),
            CachedResponse {
                body: Arc::new(vec![1, 2, 3]),
                etag: None,
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cached_response_clone() {
        let response = CachedResponse {
            body: Arc::new(vec![1, 2, 3]),
            etag: Some("test".into()),
            last_modified: Some("date".into()),
            fetched_at: Instant::now(),
        };
        let cloned = response.clone();
        // Arc clone points to same data
        assert!(Arc::ptr_eq(&response.body, &cloned.body));
        assert_eq!(response.etag, cloned.etag);
    }

    #[test]
    fn test_cache_len() {
        let cache = HttpCache::new();
        assert_eq!(cache.len(), 0);

        cache.entries.insert(
            "url1".into(),
            CachedResponse {
                body: Arc::new(vec![]),
                etag: None,
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_get_cached_fresh_fetch() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("test data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/data", server.url());
        let result = cache.get_cached(&url).await.unwrap();

        assert_eq!(&**result, b"test data");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_get_cached_cache_hit() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("original data")
            .create_async()
            .await;

        let result1 = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result1, b"original data");
        assert_eq!(cache.len(), 1);

        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(304)
            .create_async()
            .await;

        let result2 = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result2, b"original data");
    }

    #[tokio::test]
    async fn test_get_cached_304_not_modified() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("original data")
            .create_async()
            .await;

        let result1 = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result1, b"original data");

        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(304)
            .create_async()
            .await;

        let result2 = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result2, b"original data");
    }

    #[tokio::test]
    async fn test_get_cached_etag_validation() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Arc::new(b"cached".to_vec()),
                etag: Some("\"tag123\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"tag123\"")
            .with_status(304)
            .create_async()
            .await;

        let result = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result, b"cached");
    }

    #[tokio::test]
    async fn test_get_cached_last_modified_validation() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Arc::new(b"cached".to_vec()),
                etag: None,
                last_modified: Some("Wed, 21 Oct 2024 07:28:00 GMT".into()),
                fetched_at: Instant::now(),
            },
        );

        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-modified-since", "Wed, 21 Oct 2024 07:28:00 GMT")
            .with_status(304)
            .create_async()
            .await;

        let result = cache.get_cached(&url).await.unwrap();
        assert_eq!(&**result, b"cached");
    }

    #[tokio::test]
    async fn test_get_cached_network_error_fallback() {
        let cache = HttpCache::new();
        let url = "http://invalid.localhost.test/data";

        cache.entries.insert(
            url.to_string(),
            CachedResponse {
                body: Arc::new(b"stale data".to_vec()),
                etag: Some("\"old\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        let result = cache.get_cached(url).await.unwrap();
        assert_eq!(&**result, b"stale data");
    }

    #[tokio::test]
    async fn test_fetch_and_store_http_error() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/missing")
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/missing", server.url());
        let result = cache.fetch_and_store(&url).await;

        assert!(result.is_err());
        match result {
            Err(DepsError::CacheError(msg)) => {
                assert!(msg.contains("404"));
            }
            _ => panic!("Expected CacheError"),
        }
    }

    #[tokio::test]
    async fn test_fetch_and_store_stores_headers() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_header("last-modified", "Wed, 21 Oct 2024 07:28:00 GMT")
            .with_body("test")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/data", server.url());
        cache.fetch_and_store(&url).await.unwrap();

        let cached = cache.entries.get(&url).unwrap();
        assert_eq!(cached.etag, Some("\"abc123\"".into()));
        assert_eq!(
            cached.last_modified,
            Some("Wed, 21 Oct 2024 07:28:00 GMT".into())
        );
    }
}
