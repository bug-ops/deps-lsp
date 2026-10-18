//! Mapping of HTTP statuses and transport failures to typed `DepsError` values.

use super::resolver::ResolveGuardError;
use crate::error::{DepsError, RateLimitEvidence};
use crate::redact::RedactedUrl;
use reqwest::{StatusCode, header};

/// Whether a non-2xx response carries explicit evidence of genuine rate-limit exhaustion —
/// a 403/429 with `X-RateLimit-Remaining: 0`, or a `Retry-After` header on either (#1295) —
/// as opposed to a 403 for some other reason (abuse-detection false positive, an
/// access-restricted resource).
///
/// `Retry-After` covers GitHub's *secondary* rate limit, which arrives as 403 or 429 with a
/// non-zero (or absent) `X-RateLimit-Remaining` — a `remaining == 0` check alone misses it
/// (critic S4). `429` is included alongside `403` since GitHub returns 429 for some rate-limit
/// responses too, not only 403.
///
/// **Residual false positive** (critic N4): `Retry-After` alone on a 403, with no
/// `X-RateLimit-Remaining` at all, is not *unambiguous* evidence — a WAF/Cloudflare
/// bot-challenge 403 can also carry `Retry-After`, and this predicate cannot distinguish that
/// from a genuine secondary rate limit. This is a narrower false-positive surface than the
/// bug #1295 fixes (which treated *every* untokened 403 as a rate limit with zero
/// corroborating evidence), and considered an acceptable trade-off rather than a bug to
/// eliminate here — see the issue for the full evidence-strength discussion.
///
/// Checked generically here (any header-carrying non-2xx response, not pinned to a GitHub
/// host) rather than in `crate::github`: the response's headers are only available at this
/// live-fetch chokepoint — by the time a caller like `GithubTagsClient` sees the error, it has
/// already collapsed to [`DepsError::HttpStatus`] with no header data left (the exact gap
/// `crate::test_util::unwrap_or_skip_github_rate_limit`'s doc used to describe). Not pinning
/// to a GitHub-shaped `url` also means a `mockito`-backed test can exercise this without a
/// real `api.github.com` request — including from non-GitHub ecosystem crates (`deps-gitlab-ci`)
/// whose registries can send the same evidence shape.
#[inline]
pub(super) fn confirmed_rate_limit_exhaustion(
    status: StatusCode,
    headers: &header::HeaderMap,
) -> bool {
    if !matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        return false;
    }
    let remaining_exhausted = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        == Some(0);
    remaining_exhausted || headers.contains_key("retry-after")
}

/// Fixed, registry-neutral message for a confirmed rate-limit-exhaustion classification
/// (#1295, critic S1). Deliberately generic — [`http_status_error`] runs at every
/// [`HttpCache`] live-fetch site, shared by all 14 ecosystems, not only GitHub, so it must not
/// assume a GitHub-specific remedy (`GITHUB_TOKEN`) applies to whichever registry actually
/// sent the confirming evidence. A GitHub-aware caller
/// (`crate::github::classify_tags_fetch_error`) swaps in the GitHub-specific hint on top of
/// this while keeping `verified: RateLimitEvidence::Confirmed`; `deps-gitlab-ci` does the
/// equivalent for its own gate.
const CONFIRMED_RATE_LIMIT_MESSAGE: &str =
    "registry rate limit exceeded (confirmed by the response)";

/// Builds the `Err` for a non-2xx `response`: a *verified* [`DepsError::RateLimited`] when
/// [`confirmed_rate_limit_exhaustion`] holds, else the usual [`DepsError::HttpStatus`]. Shared
/// by every live-fetch call site in this module so the check can't be forgotten at a new one
/// (#1295).
#[inline]
pub(super) fn http_status_error(
    url: &str,
    status: StatusCode,
    headers: &header::HeaderMap,
) -> DepsError {
    if confirmed_rate_limit_exhaustion(status, headers) {
        return DepsError::RateLimited {
            message: CONFIRMED_RATE_LIMIT_MESSAGE.to_string(),
            verified: RateLimitEvidence::Confirmed,
            source_status: Some(status.as_u16()),
        };
    }
    DepsError::HttpStatus {
        url: RedactedUrl::new(url),
        status: status.as_u16(),
    }
}

/// Maps a failed `send()` to a [`DepsError`], surfacing a connect-time resolver-guard block as
/// [`DepsError::HostBlockedByPolicy`] instead of a generic transport error.
///
/// Walks the source chain before the error is sanitized, since `SanitizedRegistryError` drops
/// the chain. A [`ResolveGuardError::NoAddresses`] stays a transport error.
pub(super) fn send_error(url: &str, error: reqwest::Error) -> DepsError {
    let blocked =
        std::iter::successors(std::error::Error::source(&error), |source| source.source())
            .find_map(|source| match source.downcast_ref::<ResolveGuardError>() {
                Some(ResolveGuardError::Blocked { block, .. }) => Some(*block),
                Some(ResolveGuardError::NoAddresses { .. }) | None => None,
            });
    match blocked {
        Some(block) => DepsError::HostBlockedByPolicy {
            url: RedactedUrl::new(url),
            block,
        },
        None => DepsError::RegistryError {
            package: RedactedUrl::new(url),
            source: error.into(),
        },
    }
}

/// Maps a failed preflight resolution to the error a failed send would have produced.
pub(super) fn preflight_error(
    url: &str,
    error: Box<dyn std::error::Error + Send + Sync>,
) -> DepsError {
    match error.downcast_ref::<ResolveGuardError>() {
        Some(ResolveGuardError::Blocked { block, .. }) => DepsError::HostBlockedByPolicy {
            url: RedactedUrl::new(url),
            block: *block,
        },
        Some(ResolveGuardError::NoAddresses { .. }) => {
            resolution_error(url, crate::error::ResolutionFailure::NoAddresses)
        }
        None => resolution_error(url, crate::error::ResolutionFailure::LookupFailed),
    }
}

fn resolution_error(url: &str, failure: crate::error::ResolutionFailure) -> DepsError {
    DepsError::RegistryError {
        package: RedactedUrl::new(url),
        source: failure.into(),
    }
}
