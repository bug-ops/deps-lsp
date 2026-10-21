//! Request credential headers, per-request auth, and the wire-header application path.

use super::response::CredentialPartition;
use crate::error::{DepsError, Result};
use crate::net_policy::TrustedPrefix;
use crate::rate_limit::QuotaMeter;
use crate::redact::RedactedUrl;
use crate::secret::{AuthorizationValue, Redacted, auth_digest};
use reqwest::{Url, header};
use std::sync::Arc;

/// A non-credential header an [`HttpCache`](crate::cache::HttpCache) request carries.
///
/// Every header this workspace sends beyond the conditional-request validators is either a
/// fixed content-negotiation `Accept` value or a credential. Credentials are not representable
/// here: they travel as a [`RequestAuth`], which only the origin-confined cached APIs accept.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RequestHeader;
///
/// let headers = [RequestHeader::Accept("application/json")];
/// assert_eq!(headers.len(), 1);
/// ```
#[derive(Debug, Clone, Copy)]
pub enum RequestHeader {
    /// A fixed `Accept` value.
    Accept(&'static str),
}

/// The header a credentialed request carries.
///
/// Both values are sent marked sensitive. An `Authorization` value is an
/// [`AuthorizationValue`], which only the shared `Basic`/`Bearer`/verbatim constructors build.
#[derive(Debug, Clone, Copy)]
pub enum CredentialHeader<'a> {
    /// `Authorization`.
    Authorization(&'a AuthorizationValue),
    /// GitLab's `PRIVATE-TOKEN`, carrying the raw token.
    GitlabPrivateToken(&'a Redacted),
}

impl CredentialHeader<'_> {
    fn expose_secret(&self) -> &str {
        match self {
            Self::Authorization(value) => value.expose_secret(),
            Self::GitlabPrivateToken(token) => token.expose_secret(),
        }
    }
}

/// Whether a confirmed rate limit (a `401`/`403` with exhausted `X-RateLimit-Remaining`) on a
/// credentialed revalidation means the credential may be revoked.
///
/// A per-source decision made by the caller that owns the credential, not a side effect of the
/// transport tier.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RateLimitRevocation;
///
/// assert_eq!(RateLimitRevocation::default(), RateLimitRevocation::Revokes);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RateLimitRevocation {
    /// Treat it like any other `401`/`403`: evict the entry instead of serving it stale (#1295).
    #[default]
    Revokes,
    /// Treat it as throttling only: the credential is fine, so the entry is served stale. For
    /// sources whose rate limiter answers `403` (GitHub).
    Throttles,
}

impl RateLimitRevocation {
    /// Whether `error`, from revalidating a credentialed entry, means the credential may be
    /// revoked, so the entry must be evicted instead of served stale (FR-015/NFR-004).
    ///
    /// A plain `401`/`403` always counts. Written without a catch-all so a new [`DepsError`]
    /// variant must be classified here.
    pub(super) fn revokes_credential(self, error: &DepsError) -> bool {
        match error {
            DepsError::HttpStatus {
                status: 401 | 403, ..
            } => true,
            DepsError::RateLimited {
                source_status: Some(401 | 403),
                ..
            } => match self {
                Self::Revokes => true,
                Self::Throttles => false,
            },
            DepsError::HttpStatus { .. }
            | DepsError::RateLimited { .. }
            | DepsError::ParseError { .. }
            | DepsError::RegistryError { .. }
            | DepsError::InsecureScheme { .. }
            | DepsError::BudgetExceeded(_)
            | DepsError::RecentlyFailed
            | DepsError::PackageNotFound { .. }
            | DepsError::ApiResponse { .. }
            | DepsError::ResponseTooLarge { .. }
            | DepsError::InvalidVersionReq(_)
            | DepsError::InvalidPackageName(_)
            | DepsError::Io(_)
            | DepsError::Json(_)
            | DepsError::UnsupportedEcosystem(_)
            | DepsError::AmbiguousEcosystem(_)
            | DepsError::InvalidUri(_)
            | DepsError::Offline { .. }
            | DepsError::ChainResolutionHalted
            | DepsError::PaginatedListIncomplete { .. }
            | DepsError::CredentialOutsideTrustedPrefix { .. }
            | DepsError::HostBlockedByPolicy { .. } => false,
        }
    }
}

/// The credential state of one origin-confined cached request.
///
/// A credentialed body is always stored under a partition derived from the credential, and an
/// anonymous request never reads it back, so removing or rotating a token cannot make a later
/// request see a body fetched under the old one. The cache key carries the variant too, so the
/// same [`CredentialPartition`] used with a credential and anonymously yields two entries.
///
/// # Examples
///
/// ```
/// use deps_core::cache::{CredentialHeader, CredentialPartition, RequestAuth};
/// use deps_core::net_policy::TrustedPrefix;
/// use deps_core::secret::{Redacted, bearer_auth_header};
///
/// let prefix = TrustedPrefix::parse("https://index.mycorp.dev/").unwrap();
/// let token = bearer_auth_header(&Redacted::new("secret-token".to_string()));
/// let auth = RequestAuth::credential(CredentialHeader::Authorization(&token), &prefix);
/// assert!(!format!("{auth:?}").contains("secret-token"));
/// let _anonymous = RequestAuth::anonymous(Some(CredentialPartition::new(1)));
/// ```
#[derive(Debug, Clone, Copy)]
pub enum RequestAuth<'a> {
    /// No credential; `partition` separates cache entries by the caller's credential state.
    Anonymous {
        /// The caller's credential-state partition, `None` for the plain per-URL entry.
        partition: Option<CredentialPartition>,
        /// The meter fed from the live responses of this request, if any.
        quota: Option<&'a Arc<QuotaMeter>>,
    },
    /// A credential, always cached under its own partition.
    Credential {
        /// The header to send.
        header: CredentialHeader<'a>,
        /// The partition the response is stored under.
        partition: CredentialPartition,
        /// What a confirmed rate limit on revalidation means for this credential.
        on_rate_limit: RateLimitRevocation,
        /// The meter fed from the live responses of this request, if any.
        quota: Option<&'a Arc<QuotaMeter>>,
    },
}

impl<'a> RequestAuth<'a> {
    /// A request with no credential and no partition.
    pub const ANONYMOUS: Self = Self::anonymous(None);

    /// An anonymous request stored under `partition`.
    #[must_use]
    pub const fn anonymous(partition: Option<CredentialPartition>) -> Self {
        Self::Anonymous {
            partition,
            quota: None,
        }
    }

    /// A credentialed request whose partition is a salted digest of `prefix` and the secret.
    #[must_use]
    pub fn credential(header: CredentialHeader<'a>, prefix: &TrustedPrefix) -> Self {
        Self::credential_in(
            header,
            CredentialPartition::new(auth_digest_of(prefix.as_str(), header.expose_secret())),
        )
    }

    /// A credentialed request stored under a caller-chosen `partition`.
    #[must_use]
    pub const fn credential_in(
        header: CredentialHeader<'a>,
        partition: CredentialPartition,
    ) -> Self {
        Self::Credential {
            header,
            partition,
            on_rate_limit: RateLimitRevocation::Revokes,
            quota: None,
        }
    }

    /// Sets what a confirmed rate limit means for this request's credential. No effect on an
    /// anonymous request.
    #[must_use]
    pub const fn with_rate_limit(self, on_rate_limit: RateLimitRevocation) -> Self {
        match self {
            Self::Credential {
                header,
                partition,
                quota,
                ..
            } => Self::Credential {
                header,
                partition,
                on_rate_limit,
                quota,
            },
            Self::Anonymous { .. } => self,
        }
    }

    /// Feeds `meter` from the rate-limit headers of every response this request receives over
    /// the network, whichever variant it is.
    ///
    /// Recording happens inside the fetch layer when a response arrives, never from a stored
    /// cache entry, so a stale reading cannot be replayed into the meter.
    #[must_use]
    pub const fn with_quota_meter(self, meter: &'a Arc<QuotaMeter>) -> Self {
        match self {
            Self::Anonymous { partition, .. } => Self::Anonymous {
                partition,
                quota: Some(meter),
            },
            Self::Credential {
                header,
                partition,
                on_rate_limit,
                ..
            } => Self::Credential {
                header,
                partition,
                on_rate_limit,
                quota: Some(meter),
            },
        }
    }

    pub(super) const fn quota(&self) -> Option<&'a Arc<QuotaMeter>> {
        match *self {
            Self::Anonymous { quota, .. } | Self::Credential { quota, .. } => quota,
        }
    }

    pub(super) fn key_auth(&self) -> KeyAuth {
        match *self {
            Self::Anonymous { partition, .. } => KeyAuth::Anonymous(partition),
            Self::Credential { partition, .. } => KeyAuth::Credential(partition),
        }
    }

    /// Fails closed unless a credentialed request's `url` lies under `prefix`.
    ///
    /// The redirect policy confines every hop to `prefix`'s origin, which includes its scheme,
    /// so a request that starts under an `https` prefix can never be redirected onto plain
    /// `http` with the credential attached. That only holds when the initial URL is itself
    /// under the prefix, so the credential is withheld otherwise.
    pub(super) fn ensure_within(&self, url: &str, prefix: &TrustedPrefix) -> Result<()> {
        match self {
            Self::Anonymous { .. } => Ok(()),
            Self::Credential { .. } => {
                if Url::parse(url).is_ok_and(|parsed| prefix.permits(&parsed)) {
                    Ok(())
                } else {
                    Err(DepsError::CredentialOutsideTrustedPrefix {
                        url: RedactedUrl::new(url),
                    })
                }
            }
        }
    }

    pub(super) fn rate_limit(&self) -> RateLimitRevocation {
        match *self {
            Self::Anonymous { .. } => RateLimitRevocation::default(),
            Self::Credential { on_rate_limit, .. } => on_rate_limit,
        }
    }
}

/// The credential state a cache key is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyAuth {
    Anonymous(Option<CredentialPartition>),
    Credential(CredentialPartition),
}

impl KeyAuth {
    pub(super) const ANONYMOUS: Self = Self::Anonymous(None);

    pub(super) const fn is_credentialed(self) -> bool {
        matches!(self, Self::Credential(_))
    }
}

/// A header as sent on the wire: a fixed `Accept`, or a credential.
#[derive(Debug, Clone, Copy)]
pub(super) enum WireHeader<'a> {
    Accept(&'static str),
    Credential(CredentialHeader<'a>),
}

impl From<RequestHeader> for WireHeader<'_> {
    fn from(header: RequestHeader) -> Self {
        match header {
            RequestHeader::Accept(value) => Self::Accept(value),
        }
    }
}

pub(super) fn wire_headers<'a>(
    accept: &[RequestHeader],
    auth: &RequestAuth<'a>,
) -> Vec<WireHeader<'a>> {
    let mut headers: Vec<WireHeader<'a>> = wire_accept_headers(accept);
    match auth {
        RequestAuth::Credential { header, .. } => headers.push(WireHeader::Credential(*header)),
        RequestAuth::Anonymous { .. } => {}
    }
    headers
}

pub(super) fn wire_accept_headers(accept: &[RequestHeader]) -> Vec<WireHeader<'static>> {
    accept.iter().copied().map(WireHeader::from).collect()
}

pub(super) fn accept_headers(accept: Option<&'static str>) -> Vec<RequestHeader> {
    accept.map(RequestHeader::Accept).into_iter().collect()
}

fn auth_digest_of(origin: &str, secret: &str) -> u64 {
    // A `Some` secret always digests; the variant tag in the cache key keeps `0` unambiguous anyway.
    auth_digest(origin, Some(secret)).unwrap_or_default()
}

/// Adds `name: secret` to `request`, marked sensitive.
///
/// A value that is not a valid header value is passed through raw so
/// `RequestBuilder::send` fails exactly as it would for any malformed header, with no value
/// in the error.
fn sensitive_header(
    request: reqwest::RequestBuilder,
    name: header::HeaderName,
    secret: &str,
) -> reqwest::RequestBuilder {
    match header::HeaderValue::from_str(secret) {
        Ok(mut value) => {
            value.set_sensitive(true);
            request.header(name, value)
        }
        Err(_) => request.header(name, secret),
    }
}

/// Attaches `headers` to `request`, marking every credential value sensitive.
///
/// A credential value that is not a valid header value is passed through raw so
/// `RequestBuilder::send` fails exactly as it would for any malformed header, with no value
/// in the error.
pub(super) fn apply_request_headers(
    mut request: reqwest::RequestBuilder,
    headers: &[WireHeader<'_>],
) -> reqwest::RequestBuilder {
    for header in headers {
        request = match header {
            WireHeader::Accept(value) => request.header(header::ACCEPT, *value),
            WireHeader::Credential(CredentialHeader::Authorization(value)) => {
                sensitive_header(request, header::AUTHORIZATION, value.expose_secret())
            }
            WireHeader::Credential(CredentialHeader::GitlabPrivateToken(token)) => {
                sensitive_header(
                    request,
                    header::HeaderName::from_static("private-token"),
                    token.expose_secret(),
                )
            }
        };
    }
    request
}
