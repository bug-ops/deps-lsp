//! Capped response-body reading and the per-request body-size limit.

use crate::error::{DepsError, Result};
use crate::redact::RedactedUrl;
use bytes::{Bytes, BytesMut};
use reqwest::Response;

/// Maximum decompressed response body size accepted from a single request.
///
/// `reqwest`'s `gzip` feature strips `Content-Length`/`Content-Encoding` after
/// decoding a response, so a header-based pre-check cannot bound body size
/// (`response.content_length()` is `None` for every decoded response). This
/// cap is instead enforced by counting bytes as the body streams in, aborting
/// as soon as the running total would exceed the limit.
pub(super) const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Ceiling every [`BodyLimit`] is clamped to at construction, so no caller can weaken
/// the size guard [`read_body_capped`] enforces past this value.
///
/// 128 MiB comfortably covers the largest known caller (`deps-pypi`'s PyPI
/// Simple API full index, ~43 MB decompressed today, capped at 96 MiB for organic
/// growth) while still bounding the pathological case.
pub(super) const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

/// Upper bound on a single response body, clamped at construction so no caller can
/// weaken the guard `read_body_capped` enforces past `ABSOLUTE_MAX_RESPONSE_BYTES`.
///
/// Every cache method that previously read `MAX_RESPONSE_BYTES` directly now takes
/// this newtype instead (defaulting to it via [`Self::DEFAULT`]), so a caller that
/// legitimately needs a larger cap — e.g. a full-index fetch that bypasses the entry
/// cache entirely, like [`HttpCache::get_transport_only_with_headers_limited`](crate::cache::HttpCache::get_transport_only_with_headers_limited) — can
/// request one without touching the shared constant every other registry client
/// relies on.
///
/// # Examples
///
/// ```
/// use deps_core::cache::BodyLimit;
///
/// let default_limit = BodyLimit::DEFAULT;
/// let clamped = BodyLimit::new(usize::MAX);
/// assert_ne!(clamped, default_limit);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimit(usize);

impl BodyLimit {
    /// The default limit (`MAX_RESPONSE_BYTES`), used by every cache method that
    /// does not take an explicit [`BodyLimit`].
    pub const DEFAULT: Self = Self(MAX_RESPONSE_BYTES);

    /// Creates a limit of `bytes`, clamped down to `ABSOLUTE_MAX_RESPONSE_BYTES` if
    /// `bytes` exceeds it.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        if bytes > ABSOLUTE_MAX_RESPONSE_BYTES {
            Self(ABSOLUTE_MAX_RESPONSE_BYTES)
        } else {
            Self(bytes)
        }
    }

    /// The clamped byte value this limit enforces.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

/// Reads a response body incrementally, aborting once it exceeds `limit`.
///
/// Chunked reading (via [`Response::chunk`]) is required because the
/// decompressed body size is not known upfront: `gzip` decoding strips
/// `Content-Length`, so the only reliable guard against an oversized or
/// maliciously amplified (decompression-bomb) response is counting bytes
/// as they arrive and bailing before the whole body is buffered.
pub(super) async fn read_body_capped(
    url: &str,
    mut response: Response,
    limit: BodyLimit,
) -> Result<Bytes> {
    let mut body = BytesMut::new();
    let limit = limit.bytes();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DepsError::RegistryError {
            package: RedactedUrl::new(url),
            source: e.into(),
        })?
    {
        if body.len() + chunk.len() > limit {
            return Err(DepsError::ResponseTooLarge {
                url: RedactedUrl::new(url),
                limit,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}
