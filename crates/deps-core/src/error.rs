use thiserror::Error;

use crate::net_policy::RedactedUrl;

/// Reconstructs the "{status} {reason}" text `reqwest::StatusCode`'s `Display`
/// produces, since `HttpStatus` stores a bare `u16` for structural matching
/// and loses the canonical reason phrase otherwise.
///
/// `url` is already a [`RedactedUrl`] (#789: `HttpStatus::url`'s field type itself makes the
/// raw value unreachable, so there is nothing left to redact here) — this is the only place
/// `HttpStatus`'s `Display` text is built.
fn http_status_message(status: u16, url: &RedactedUrl) -> String {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason());
    reason.map_or_else(
        || format!("HTTP {status} for {url}"),
        |reason| format!("HTTP {status} {reason} for {url}"),
    )
}

/// Builds [`DepsError::RegistryError`]'s `Display` text from its already-[`RedactedUrl`]
/// `package` field (#767, #789).
///
/// [`DepsError::RegistryError`]'s `package` field is documented as a package name, but
/// several `deps-core::cache` call sites populate it with a URL instead, so it is stored as
/// [`RedactedUrl`] rather than a plain `String` — a no-op for an actual package name
/// (including an npm-scoped one like `@types/node`, which an earlier revision of this
/// function mangled into `***@types/node` before
/// [`crate::net_policy::redact_userinfo`]'s empty-userinfo false positive was fixed at the
/// root — #767 M1/code-review follow-up). `source`'s own `Display` can no longer re-embed the
/// raw URL either: [`SanitizedRegistryError`]'s only constructor strips it unconditionally.
fn registry_error_message(package: &RedactedUrl, source: &SanitizedRegistryError) -> String {
    format!("registry request failed for {package}: {source}")
}

/// Builds [`DepsError::ResponseTooLarge`]'s `Display` text from its already-[`RedactedUrl`]
/// `url` field (#767, #789).
fn response_too_large_message(url: &RedactedUrl, limit: usize) -> String {
    format!("response body for {url} exceeds {limit} byte limit")
}

/// Builds [`DepsError::Offline`]'s `Display` text from its already-[`RedactedUrl`] `url`
/// field (#767, #789).
fn offline_message(url: &RedactedUrl) -> String {
    format!("offline: request to {url} was blocked by network.offline")
}

/// Wraps a `reqwest::Error` with its embedded request URL stripped, for storage in
/// [`DepsError::RegistryError`]'s `source` field.
///
/// `reqwest::Error`'s own `Display` appends `" for url (...)"` when the underlying error
/// carries a URL — `reqwest::Error::without_url()` strips this, but relying on every
/// `RegistryError`-construction site to remember to call it is exactly the discipline gap
/// this type closes (issue #789, see [`RedactedUrl`]'s own docs for the same problem on the
/// URL-string side). The only constructor (`From<reqwest::Error>`) applies `.without_url()`
/// unconditionally, so a raw URL can never reach `DepsError`'s `Display`/`Debug` through
/// `{source}` forwarding, even when a future call site forgets.
///
/// **`self.0`'s own `source` chain is never exposed**, through either `Debug` or
/// [`std::error::Error::source`] — this is deliberate, not an oversight. `.without_url()`
/// only clears the *outer* error's own `url` field; `reqwest`'s `source` field is
/// independent of it, and that source is not always a URL-free `hyper`/`io` error: reqwest
/// 0.13.4's redirect policy (`src/redirect.rs`, the `https_only` check in
/// `TowerPolicy::redirect`) rejects an `http://` redirect target by building
/// `crate::error::redirect(crate::error::url_bad_scheme(next_url.clone()), next_url)` — the
/// *inner* `url_bad_scheme(...)` error is itself a full `reqwest::Error` with `next_url`
/// populated via `.with_url(...)`, nested as the *outer* error's `source`. That inner `url`
/// is a field `.without_url()` on the outer error never touches, and `reqwest::Error`'s own
/// derived-style `Debug` impl recursively prints `source`'s `Debug` (including that inner
/// `url`) — so both a manual `.source()` walk and `{:?}` on the raw `reqwest::Error` can leak
/// it. Since `reqwest` exposes no `source_mut()`-style API to reach in and strip that nested
/// URL, this type treats itself as a leaf node instead: its [`std::error::Error::source`]
/// impl always returns `None`, and `Debug` is hand-written to forward to the (already-safe)
/// `Display` text rather than to `self.0`'s own `Debug`.
///
/// **Precision note on what is actually verified today**: this project's own client
/// configuration never calls `reqwest::ClientBuilder::https_only` (`grep -rn '\.https_only('
/// crates/` finds no hits), so the nested-URL shape above cannot currently occur through this
/// crate's own request paths — the regression test below instead exercises a genuinely
/// populated source chain via a real connection-refused (io-level) failure, which is what
/// this project's client config can actually produce, and confirms it is discarded. The
/// `https_only`/redirect mechanism itself is read directly from `reqwest` 0.13.4's pinned
/// source (`redirect.rs`), not reproduced live here (doing so would need a TLS test harness
/// this project does not otherwise have). `source()` returning `None` unconditionally — not
/// only when a URL-bearing nested error is possible — is what makes this correct regardless:
/// if a future change enables `https_only` on a shared client, this type's contract does not
/// need re-auditing.
///
/// # Examples
///
/// ```
/// use deps_core::error::SanitizedRegistryError;
///
/// // A builder-only `reqwest::Error` never carries a URL in the first place, so this
/// // demonstrates the wrapper's `Display`/`Debug` forwarding without needing a real request.
/// let raw = reqwest::Client::new().get("not a url").build().unwrap_err();
/// let sanitized: SanitizedRegistryError = raw.into();
/// assert!(!sanitized.to_string().is_empty());
/// ```
pub struct SanitizedRegistryError(reqwest::Error);

impl From<reqwest::Error> for SanitizedRegistryError {
    fn from(error: reqwest::Error) -> Self {
        Self(error.without_url())
    }
}

impl std::fmt::Display for SanitizedRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::fmt::Debug for SanitizedRegistryError {
    /// Hand-written, not derived: forwards to `Display` (safe — `reqwest::Error`'s own
    /// `Display` never recurses into its `source`'s text) instead of `self.0`'s own `Debug`,
    /// which does recurse into `source` and would reopen the nested-URL leak this type's own
    /// docs describe.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SanitizedRegistryError({})", self.0)
    }
}

impl std::error::Error for SanitizedRegistryError {
    /// Always `None` — see this type's own docs for why the wrapped error's source chain is
    /// never safe to expose, even via this trait's usual chain-walking contract.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Core error types for deps-lsp.
///
/// Extended from Phase 1 to support multiple ecosystems (Cargo, npm, PyPI).
/// All errors provide structured error handling with source error tracking.
///
/// # Examples
///
/// ```
/// use deps_core::error::{DepsError, Result};
///
/// fn parse_file(content: &str, file_type: &str) -> Result<()> {
///     // Parsing errors are automatically wrapped
///     if content.is_empty() {
///         return Err(DepsError::ParseError {
///             file_type: file_type.into(),
///             source: Box::new(std::io::Error::new(
///                 std::io::ErrorKind::InvalidData,
///                 "empty content"
///             )),
///         });
///     }
///     Ok(())
/// }
/// ```
#[non_exhaustive]
#[derive(Error)]
pub enum DepsError {
    /// A manifest or lockfile failed to parse.
    #[error("failed to parse {file_type}: {source}")]
    ParseError {
        /// Ecosystem/file kind being parsed (e.g. `"Cargo.toml"`), for the error message.
        file_type: String,
        /// The underlying parser error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A registry HTTP request failed at the transport layer.
    #[error("{}", registry_error_message(package, source))]
    RegistryError {
        /// Name of the package the request was for — or, at several `deps-core::cache` call
        /// sites, the request URL instead (see [`RedactedUrl`]'s own docs: it is a no-op for
        /// a genuine package name, so this field is safe to redact unconditionally).
        package: RedactedUrl,
        /// The underlying `reqwest` error, with its embedded request URL stripped.
        #[source]
        source: SanitizedRegistryError,
    },

    /// The cache layer itself failed (e.g. a poisoned lock), independent of any registry request.
    #[error("cache error: {0}")]
    CacheError(String),

    /// A registry request was rejected for exceeding a rate limit. Unlike other variants,
    /// `message` is a pre-vetted, IP-free, actionable hint safe to surface verbatim in a
    /// per-dependency diagnostic (see [`Self::fetch_failure`]) — never build one from a raw
    /// registry error body, which can embed the caller's public IP (`github.rs:332-346`).
    #[error("{message}")]
    RateLimited {
        /// Pre-vetted, IP-free message safe to surface verbatim in a diagnostic.
        message: String,
    },

    /// A package name was not found on the given registry.
    #[error("{package} not found on {registry}")]
    PackageNotFound {
        /// Name of the package that was looked up.
        package: String,
        /// Name of the registry that reported the package as missing.
        registry: &'static str,
    },

    /// A registry HTTP request returned a non-success status code.
    #[error("{}", http_status_message(*status, url))]
    HttpStatus {
        /// URL that was requested — stored redacted (#789): the raw value is unreachable
        /// from this field's type.
        url: RedactedUrl,
        /// HTTP status code returned.
        status: u16,
    },

    /// A registry's response body failed to deserialize as JSON.
    #[error("failed to parse {registry} response for {package}: {source}")]
    ApiResponse {
        /// Name of the package whose response failed to parse.
        package: String,
        /// Name of the registry the response came from.
        registry: &'static str,
        /// The underlying JSON deserialization error.
        #[source]
        source: serde_json::Error,
    },

    /// A response body exceeded the configured size cap and was rejected before full download.
    #[error("{}", response_too_large_message(url, *limit))]
    ResponseTooLarge {
        /// URL the oversized response came from — stored redacted (#789): the raw value is
        /// unreachable from this field's type.
        url: RedactedUrl,
        /// The size cap, in bytes, that was exceeded.
        limit: usize,
    },

    /// Deliberately shared between two distinct rejection kinds: malformed version-requirement
    /// strings (all ecosystems) and malformed Go module paths (`deps-go`, which has no separate
    /// variant for the latter — see its `validate_module_path`). Nothing in the workspace
    /// discriminates on this variant beyond rendering its message, so a consumer-specific split
    /// was deferred (#399).
    #[error("invalid version requirement: {0}")]
    InvalidVersionReq(String),

    /// A filesystem I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON parsing operation failed outside of a registry response context.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The manifest file's ecosystem could not be determined from any registered router.
    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(String),

    /// More than one ecosystem's routing rules matched the same manifest path.
    #[error("ambiguous ecosystem detection for file: {0}")]
    AmbiguousEcosystem(String),

    /// A URI supplied by the client or a manifest could not be parsed.
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Returned by `deps_core::cache::HttpCache`'s 4 send sites (issue #483) when
    /// `network.offline` is set, instead of attempting the request. `url` is the request
    /// that was blocked, for diagnostic/logging purposes.
    #[error("{}", offline_message(url))]
    Offline {
        /// The request URL that was blocked — stored redacted (#789): the raw value is
        /// unreachable from this field's type.
        url: RedactedUrl,
    },

    /// A multi-hop alternate/private-index chain's resolution was halted because a hop
    /// returned a genuine transport error (5xx, timeout, connection failure) rather than a
    /// clean "not found" — the chain deliberately does not fall through to a further, less
    /// trusted hop in this case (`deps_pypi`'s FR-005(c)/NFR-003(3), #513). Carries no
    /// arbitrary error text — mirrors [`Self::RateLimited`]'s pre-vetted-message precedent
    /// (see [`Self::fetch_failure`]'s security-load-bearing invariant) — so its
    /// classification there can safely be [`FetchFailure::Actionable`] with a fixed, safe
    /// message, surfacing this case in hover/diagnostics instead of only a `tracing::warn!`.
    #[error(
        "index chain resolution halted by a transport error on one hop — not falling back \
         to a less-trusted index"
    )]
    ChainResolutionHalted,
}

/// Hand-written, not derived: originally because a derived `Debug` would have printed
/// `HttpStatus.url`, `Offline.url`, `ResponseTooLarge.url`, and `RegistryError.package` raw
/// and unredacted (#767 code-review follow-up) — any `tracing::warn!(?err, ...)`/`{err:?}`
/// call site, a common and arguably more idiomatic alternative to `%err`, would have bypassed
/// the hand-written `Display` text entirely and reintroduced the raw URL/query string. Since
/// #789, those four fields are typed [`RedactedUrl`] directly, so a derived `Debug` would
/// actually be safe too (each field's own `Debug` already forwards to redacted text) — this
/// impl is kept hand-written anyway as defense-in-depth against a future field-type
/// regression, not because it is still load-bearing on its own. Every field is still shown
/// (this is not a summary).
impl std::fmt::Debug for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError { file_type, source } => f
                .debug_struct("ParseError")
                .field("file_type", file_type)
                .field("source", source)
                .finish(),
            Self::RegistryError { package, source } => f
                .debug_struct("RegistryError")
                .field("package", package)
                .field("source", source)
                .finish(),
            Self::CacheError(message) => f.debug_tuple("CacheError").field(message).finish(),
            Self::RateLimited { message } => f
                .debug_struct("RateLimited")
                .field("message", message)
                .finish(),
            Self::PackageNotFound { package, registry } => f
                .debug_struct("PackageNotFound")
                .field("package", package)
                .field("registry", registry)
                .finish(),
            Self::HttpStatus { url, status } => f
                .debug_struct("HttpStatus")
                .field("url", url)
                .field("status", status)
                .finish(),
            Self::ApiResponse {
                package,
                registry,
                source,
            } => f
                .debug_struct("ApiResponse")
                .field("package", package)
                .field("registry", registry)
                .field("source", source)
                .finish(),
            Self::ResponseTooLarge { url, limit } => f
                .debug_struct("ResponseTooLarge")
                .field("url", url)
                .field("limit", limit)
                .finish(),
            Self::InvalidVersionReq(req) => f.debug_tuple("InvalidVersionReq").field(req).finish(),
            Self::Io(source) => f.debug_tuple("Io").field(source).finish(),
            Self::Json(source) => f.debug_tuple("Json").field(source).finish(),
            Self::UnsupportedEcosystem(ecosystem) => f
                .debug_tuple("UnsupportedEcosystem")
                .field(ecosystem)
                .finish(),
            Self::AmbiguousEcosystem(path) => {
                f.debug_tuple("AmbiguousEcosystem").field(path).finish()
            }
            Self::InvalidUri(uri) => f.debug_tuple("InvalidUri").field(uri).finish(),
            Self::Offline { url } => f.debug_struct("Offline").field("url", url).finish(),
            Self::ChainResolutionHalted => f.write_str("ChainResolutionHalted"),
        }
    }
}

impl DepsError {
    /// Returns `true` when this error means the registry was successfully asked and
    /// answered "this package doesn't exist", as opposed to the registry not having
    /// been answerable at all (network failure, timeout, malformed response, 5xx).
    ///
    /// Distinguishing the two matters for diagnostics (#267): a genuine not-found is
    /// evidence the package name is wrong, while any other error is evidence only that
    /// this particular request failed — reporting the latter as "Unknown package" would
    /// mislabel a transient registry outage as a nonexistent dependency. Covers
    /// [`DepsError::PackageNotFound`] (the ecosystems that map a 404 to it explicitly:
    /// npm, PyPI, Go, Swift) and a bare [`DepsError::HttpStatus`] with `status == 404`
    /// (the ecosystems that propagate the raw HTTP status instead: Cargo, Maven, Gradle,
    /// Bundler, Dart, Composer, NuGet).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::DepsError;
    ///
    /// let not_found = DepsError::PackageNotFound {
    ///     package: "left-pad".into(),
    ///     registry: "npm",
    /// };
    /// assert!(not_found.is_not_found());
    ///
    /// let http_404 = DepsError::HttpStatus {
    ///     url: "https://crates.io/api/v1/crates/left-pad".into(),
    ///     status: 404,
    /// };
    /// assert!(http_404.is_not_found());
    ///
    /// let outage = DepsError::HttpStatus {
    ///     url: "https://crates.io/api/v1/crates/serde".into(),
    ///     status: 503,
    /// };
    /// assert!(!outage.is_not_found());
    ///
    /// let cache_err = DepsError::CacheError("connection reset".into());
    /// assert!(!cache_err.is_not_found());
    /// ```
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::PackageNotFound { .. } | Self::HttpStatus { status: 404, .. }
        )
    }

    /// Classifies this error for the per-dependency "registry lookup failed" diagnostic
    /// (#478), distinguishing a failure with a safe, actionable hint to show the user from
    /// one whose raw text must never reach a diagnostic.
    ///
    /// **Security-load-bearing invariant**: [`FetchFailure::Actionable`] is produced *only*
    /// from [`Self::RateLimited`]'s pre-vetted, IP-free canned message. Every other variant
    /// must classify as [`FetchFailure::Transient`] — never call `.to_string()`/`Display` on
    /// an arbitrary `DepsError` to build an `Actionable` value, since a raw `HttpStatus` or
    /// `RegistryError` body can embed the caller's public IP (`github.rs:332-346`, exercised
    /// by the `github` crate's `test_parse_tags_page_github_rate_limit_returns_error`).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::error::{DepsError, FetchFailure};
    ///
    /// let rate_limited = DepsError::RateLimited { message: "set GITHUB_TOKEN".into() };
    /// assert_eq!(
    ///     rate_limited.fetch_failure(),
    ///     FetchFailure::Actionable("set GITHUB_TOKEN".into())
    /// );
    ///
    /// let other = DepsError::CacheError("connection reset".into());
    /// assert_eq!(other.fetch_failure(), FetchFailure::Transient);
    /// ```
    #[must_use]
    pub fn fetch_failure(&self) -> FetchFailure {
        match self {
            Self::RateLimited { message } => FetchFailure::Actionable(message.clone()),
            // Fixed, pre-vetted message — see `Self::ChainResolutionHalted`'s own doc for why
            // this is safe to build as `Actionable` the same way `RateLimited` is.
            Self::ChainResolutionHalted => FetchFailure::Actionable(
                "index unreachable — resolution halted, not falling back to a less-trusted \
                 index"
                    .to_string(),
            ),
            _ => FetchFailure::Transient,
        }
    }

    /// Returns `true` when this error means a request was blocked by `network.offline`
    /// (issue #483), as opposed to any other network or registry failure.
    ///
    /// Used by `deps_maven::registry` to skip poisoning its negative-search-failure
    /// cache with an offline block, so toggling `network.offline` back to `false` takes
    /// effect immediately instead of being masked by `RECENT_FAILURE_TTL`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::DepsError;
    ///
    /// let offline = DepsError::Offline { url: "https://crates.io/".into() };
    /// assert!(offline.is_offline());
    ///
    /// let other = DepsError::CacheError("connection reset".into());
    /// assert!(!other.is_offline());
    /// ```
    #[must_use]
    pub const fn is_offline(&self) -> bool {
        matches!(self, Self::Offline { .. })
    }

    /// A URL-free summary of this error, safe to attach to a `tracing` field or log line at
    /// an outbound-request chokepoint. [`Self::HttpStatus`], [`Self::Offline`],
    /// [`Self::ResponseTooLarge`], and [`Self::RegistryError`]'s own `Display` now redact
    /// their URL via [`RedactedUrl`] (#767, #789), but this summary deliberately still never
    /// derives from `self`'s `Display`/`Debug`: a future variant added here should not be
    /// able to reintroduce a leak just by being included in a `{self}` interpolation.
    /// [`Self::RegistryError`]'s wrapped [`SanitizedRegistryError`] can no longer re-embed
    /// the raw URL through its own `Display` either way, since its only constructor strips
    /// it unconditionally.
    ///
    /// Returns the HTTP status code when this is [`Self::HttpStatus`], plus a coarse,
    /// URL-free cause discriminant for every variant — so a routine transport
    /// failure/timeout still carries some triage signal instead of collapsing to `status =
    /// None` with nothing else.
    #[must_use]
    pub(crate) const fn safe_tracing_summary(&self) -> (Option<u16>, &'static str) {
        match self {
            Self::HttpStatus { status, .. } => (Some(*status), "http-status"),
            Self::RegistryError { .. } => (None, "transport"),
            Self::CacheError(_) => (None, "cache"),
            Self::Offline { .. } => (None, "offline"),
            Self::ResponseTooLarge { .. } => (None, "response-too-large"),
            Self::RateLimited { .. } => (None, "rate-limited"),
            Self::ApiResponse { .. } => (None, "api-response"),
            Self::PackageNotFound { .. } => (None, "not-found"),
            _ => (None, "other"),
        }
    }
}

/// Outcome of a registry fetch attempt for one dependency, as recorded in
/// `DocumentState::outcomes` (`deps-lsp`) and rendered by
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] (#478).
///
/// Replaces a bare `HashSet<PackageName>` membership check so the per-dependency diagnostic
/// can distinguish a failure with a safe, user-actionable hint from an opaque one, without
/// ever threading raw, potentially IP-bearing error text into the diagnostic (see
/// [`DepsError::fetch_failure`]).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchFailure {
    /// The fetch failed with a pre-vetted, safe-to-display hint (currently only produced
    /// from [`DepsError::RateLimited`]).
    Actionable(String),
    /// The fetch failed for a reason with no safe user-facing detail to show — the
    /// diagnostic falls back to a generic "lookup failed" message.
    Transient,
    /// The dependency was never actually queried (e.g. a name/source collision detected
    /// before the fetch, see `deps-lsp`'s `dedup_dependencies_by_source`) — renders the
    /// same generic "lookup failed" message as [`Self::Transient`], since the absence of
    /// an attempt is not evidence the package doesn't exist.
    NotAttempted,
}

/// Convenience type alias for `Result<T, DepsError>`.
///
/// This is the standard `Result` type used throughout the deps-lsp codebase.
/// It simplifies function signatures by defaulting the error type to `DepsError`.
///
/// # Examples
///
/// ```
/// use deps_core::error::Result;
///
/// fn get_version(name: &str) -> Result<String> {
///     if name.is_empty() {
///         return Err(deps_core::error::DepsError::CacheError("empty name".into()));
///     }
///     Ok("1.0.0".into())
/// }
/// ```
pub type Result<T> = std::result::Result<T, DepsError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn test_error_display() {
        let error = DepsError::CacheError("test error".into());
        assert_eq!(error.to_string(), "cache error: test error");
    }

    /// #789: `SanitizedRegistryError`'s own `Display` must never re-embed the request URL,
    /// even when the wrapped `reqwest::Error` genuinely carries one — a builder-only error
    /// like `Client::get("not a url").build().unwrap_err()` never populates `.url()`, so this
    /// needs a real transport-level failure (connection refused on a closed loopback port) to
    /// actually exercise the strip, mirroring `deps_core::cache`'s own
    /// `test_registry_error_source_redacts_url_on_real_transport_error`.
    #[tokio::test]
    async fn test_sanitized_registry_error_strips_url_on_real_transport_error() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/pkg?token=super-secret-value");

        let reqwest_err = reqwest::Client::new().get(&url).send().await.unwrap_err();
        assert!(
            reqwest_err.url().is_some(),
            "test setup invariant: the underlying reqwest::Error must carry a URL"
        );

        let sanitized: SanitizedRegistryError = reqwest_err.into();
        assert!(
            !sanitized.to_string().contains("super-secret-value"),
            "sanitized: {sanitized}"
        );
        assert!(
            !format!("{sanitized:?}").contains("super-secret-value"),
            "sanitized debug: {sanitized:?}"
        );
    }

    /// #789 S2: `SanitizedRegistryError` must treat itself as a leaf node for source-chaining
    /// purposes — `reqwest`'s redirect policy can nest a *second* `reqwest::Error` (with its
    /// own populated `url` field) as the outer error's `source` (see the type's own docs for
    /// the exact `https_only`/redirect code path), which `.without_url()` on the outer error
    /// alone does not touch. This proves the wrapper discards a real, populated source chain
    /// (not merely that one never existed): the *raw* wrapped `reqwest::Error` behind
    /// `sanitized.0` (accessible here since `mod tests` is a child of `error`) genuinely has
    /// `.source().is_some()` for a real connection-refused failure, yet `SanitizedRegistryError`'s
    /// own `source()` is unconditionally `None`.
    #[tokio::test]
    async fn test_sanitized_registry_error_source_is_always_none() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/pkg?token=super-secret-value");

        let reqwest_err = reqwest::Client::new().get(&url).send().await.unwrap_err();
        let sanitized: SanitizedRegistryError = reqwest_err.into();
        assert!(
            sanitized.0.source().is_some(),
            "test setup invariant: a connection-refused error must have a populated source chain"
        );
        assert!(
            StdError::source(&sanitized).is_none(),
            "SanitizedRegistryError::source() must always be None"
        );
    }

    /// #756 code-review finding: `safe_tracing_summary` must never derive its output from
    /// `self`'s own `Display`/`Debug` (both embed the raw, unredacted request URL for several
    /// variants) — pinning the exact `(status, cause)` pairs for every variant a `HttpCache`/
    /// `OsvClient` call site can actually produce, so a routine transport failure still
    /// carries triage signal (`cause`) instead of collapsing to `(None, "other")`.
    #[test]
    fn test_safe_tracing_summary_covers_every_reachable_variant() {
        assert_eq!(
            DepsError::HttpStatus {
                url: "https://example.com/pkg?token=secret".into(),
                status: 503,
            }
            .safe_tracing_summary(),
            (Some(503), "http-status")
        );
        assert_eq!(
            DepsError::RegistryError {
                package: "https://example.com/pkg?token=secret".into(),
                source: reqwest::Client::new()
                    .get("not a url")
                    .build()
                    .unwrap_err()
                    .into(),
            }
            .safe_tracing_summary(),
            (None, "transport")
        );
        assert_eq!(
            DepsError::CacheError("poisoned lock".into()).safe_tracing_summary(),
            (None, "cache")
        );
        assert_eq!(
            DepsError::Offline {
                url: "https://example.com/pkg?token=secret".into(),
            }
            .safe_tracing_summary(),
            (None, "offline")
        );
        assert_eq!(
            DepsError::ResponseTooLarge {
                url: "https://example.com/pkg?token=secret".into(),
                limit: 1024,
            }
            .safe_tracing_summary(),
            (None, "response-too-large")
        );
    }

    /// A `(status, cause)` pair must never itself carry the URL — the whole point of this
    /// method — even when the source error's own `Display` would have.
    #[test]
    fn test_safe_tracing_summary_output_never_contains_the_url() {
        let error = DepsError::HttpStatus {
            url: "https://npm.internal/pkg?token=super-secret-value".into(),
            status: 503,
        };
        let (status, cause) = error.safe_tracing_summary();
        assert_eq!(status, Some(503));
        assert!(!cause.contains("super-secret-value"));
        assert!(!cause.contains("npm.internal"));
    }

    #[test]
    fn test_response_too_large() {
        let error = DepsError::ResponseTooLarge {
            url: "https://example.com/data".into(),
            limit: 32 * 1024 * 1024,
        };
        assert_eq!(
            error.to_string(),
            "response body for https://example.com/data exceeds 33554432 byte limit"
        );
    }

    /// #767: `HttpStatus`'s `Display` is surfaced verbatim through `window/showMessage`
    /// (`deps-lsp`'s fetch-failure toast), so a query-string credential (e.g. an `.npmrc`
    /// `?_authToken=...` value after `${VAR}` expansion) must never reach it.
    #[test]
    fn test_http_status_display_redacts_query_string() {
        let error = DepsError::HttpStatus {
            url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
            status: 503,
        };
        let message = error.to_string();
        assert!(
            !message.contains("super-secret-value"),
            "message: {message}"
        );
        assert_eq!(
            message,
            "HTTP 503 Service Unavailable for https://npm.internal/pkg"
        );
    }

    /// #767 companion for [`DepsError::RegistryError`], whose `package` field is frequently
    /// populated with a raw URL rather than a package name (`deps-core::cache`'s
    /// `read_body_capped`/`get_cached_with_headers_via`/`post_json`/`get_cached_bytes`).
    #[test]
    fn test_registry_error_display_redacts_query_string() {
        let error = DepsError::RegistryError {
            package: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
            source: reqwest::Client::new()
                .get("not a url")
                .build()
                .unwrap_err()
                .into(),
        };
        let message = error.to_string();
        assert!(
            !message.contains("super-secret-value"),
            "message: {message}"
        );
        assert!(message.starts_with("registry request failed for https://npm.internal/pkg:"));
    }

    /// #767 M1: `RegistryError::package` is documented as a package name, and an npm-scoped
    /// name (leading `@`, no scheme) must never be mangled by the URL redaction meant for
    /// call sites that populate this field with a URL instead — reproduced false positive:
    /// `url_for_tracing`'s unparseable-URL fallback previously misread `@types/node` as
    /// `user@host`-shaped userinfo and rendered `***@types/node`.
    #[test]
    fn test_registry_error_display_does_not_mangle_scoped_package_name() {
        let error = DepsError::RegistryError {
            package: "@types/node".into(),
            source: reqwest::Client::new()
                .get("not a url")
                .build()
                .unwrap_err()
                .into(),
        };
        let message = error.to_string();
        assert!(
            message.starts_with("registry request failed for @types/node:"),
            "message: {message}"
        );
    }

    /// #767: `Offline`'s `Display` also embeds the blocked request URL — same redaction
    /// applies.
    #[test]
    fn test_offline_display_redacts_query_string() {
        let error = DepsError::Offline {
            url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
        };
        let message = error.to_string();
        assert!(
            !message.contains("super-secret-value"),
            "message: {message}"
        );
    }

    /// #767: `ResponseTooLarge`'s `Display` also embeds the source URL — same redaction
    /// applies.
    #[test]
    fn test_response_too_large_display_redacts_query_string() {
        let error = DepsError::ResponseTooLarge {
            url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
            limit: 1024,
        };
        let message = error.to_string();
        assert!(
            !message.contains("super-secret-value"),
            "message: {message}"
        );
    }

    /// Code-review follow-up on #767: `DepsError` derives `Debug` no longer — a derived
    /// impl would print `HttpStatus.url`/`Offline.url`/`ResponseTooLarge.url`/
    /// `RegistryError.package` raw, so any `tracing::warn!(?err, ...)`/`{err:?}` call site
    /// (a common, arguably more idiomatic alternative to `%err`) would bypass every
    /// hand-written `Display` redaction above and reintroduce the leak. Covers all four
    /// URL-shaped variants via `{:?}`.
    #[test]
    fn test_debug_redacts_query_string_for_every_url_bearing_variant() {
        let credential_bearing = [
            DepsError::HttpStatus {
                url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
                status: 503,
            },
            DepsError::Offline {
                url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
            },
            DepsError::ResponseTooLarge {
                url: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
                limit: 1024,
            },
            DepsError::RegistryError {
                package: "https://npm.internal/pkg?_authToken=super-secret-value".into(),
                source: reqwest::Client::new()
                    .get("not a url")
                    .build()
                    .unwrap_err()
                    .into(),
            },
        ];
        for error in credential_bearing {
            let debug = format!("{error:?}");
            assert!(
                !debug.contains("super-secret-value"),
                "Debug leaked the credential for {error}: {debug}"
            );
        }
    }

    /// #789 S1 regression: destructuring `HttpStatus.url` directly (bypassing `Display`/
    /// `Debug` entirely) must still yield only redacted text — the field's type itself
    /// (`RedactedUrl`, not `String`) is what makes this true, not any redaction step at the
    /// access site. There is no way to get the raw string back out even via direct field
    /// access, because nothing raw was ever stored in the field to begin with.
    #[test]
    fn test_http_status_url_field_is_redacted_even_via_direct_destructure() {
        let error = DepsError::HttpStatus {
            url: RedactedUrl::new("https://npm.internal/pkg?_authToken=super-secret-value"),
            status: 401,
        };
        let DepsError::HttpStatus { url, .. } = error else {
            unreachable!()
        };
        assert_eq!(url.to_string(), "https://npm.internal/pkg");
        assert!(!url.to_string().contains("super-secret-value"));
    }

    /// `Debug` must still show every field for the ordinary, non-URL-bearing variants —
    /// this is a redaction fix, not a summary, so field values unrelated to a URL must
    /// come through unchanged.
    #[test]
    fn test_debug_still_shows_non_url_fields() {
        let error = DepsError::PackageNotFound {
            package: "left-pad".into(),
            registry: "npm",
        };
        let debug = format!("{error:?}");
        assert!(debug.contains("left-pad"), "debug: {debug}");
        assert!(debug.contains("npm"), "debug: {debug}");
    }

    #[test]
    fn test_invalid_version_req() {
        let error = DepsError::InvalidVersionReq("invalid".into());
        assert_eq!(error.to_string(), "invalid version requirement: invalid");
    }

    #[test]
    fn test_parse_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        let error = DepsError::ParseError {
            file_type: "Cargo.toml".into(),
            source: Box::new(io_err),
        };
        assert!(error.to_string().contains("failed to parse Cargo.toml"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let error: DepsError = io_err.into();
        assert!(error.to_string().contains("I/O error"));
    }

    #[test]
    fn test_unsupported_ecosystem() {
        let error = DepsError::UnsupportedEcosystem("unknown".into());
        assert_eq!(error.to_string(), "unsupported ecosystem: unknown");
    }

    #[test]
    fn test_ambiguous_ecosystem() {
        let error = DepsError::AmbiguousEcosystem("file.txt".into());
        assert_eq!(
            error.to_string(),
            "ambiguous ecosystem detection for file: file.txt"
        );
    }

    #[test]
    fn test_invalid_uri() {
        let error = DepsError::InvalidUri("http://example.com".into());
        assert_eq!(error.to_string(), "invalid URI: http://example.com");
    }

    #[test]
    fn test_offline_error_display_and_predicate() {
        let error = DepsError::Offline {
            url: "https://crates.io/api/v1/crates/serde".into(),
        };
        assert!(error.to_string().contains("offline"));
        assert!(error.is_offline());
        assert!(!error.is_not_found());

        let other = DepsError::CacheError("boom".into());
        assert!(!other.is_offline());
    }

    #[test]
    fn test_package_not_found() {
        let error = DepsError::PackageNotFound {
            package: "flask".into(),
            registry: "PyPI",
        };
        assert_eq!(error.to_string(), "flask not found on PyPI");
    }

    #[test]
    fn test_http_status_with_known_reason() {
        let error = DepsError::HttpStatus {
            url: "https://example.com/data".into(),
            status: 404,
        };
        assert_eq!(
            error.to_string(),
            "HTTP 404 Not Found for https://example.com/data"
        );
    }

    #[test]
    fn test_http_status_with_unknown_code() {
        let error = DepsError::HttpStatus {
            url: "https://example.com/data".into(),
            status: 599,
        };
        assert_eq!(error.to_string(), "HTTP 599 for https://example.com/data");
    }

    #[test]
    fn test_api_response_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let error = DepsError::ApiResponse {
            package: "flask".into(),
            registry: "PyPI",
            source: json_err,
        };
        assert!(
            error
                .to_string()
                .starts_with("failed to parse PyPI response for flask:")
        );
    }

    /// Exhaustive companion to the doc-test on [`DepsError::fetch_failure`]: every variant
    /// other than [`DepsError::RateLimited`] and [`DepsError::ChainResolutionHalted`] must
    /// classify as [`FetchFailure::Transient`]. This is the invariant the doc comment calls
    /// security-load-bearing (a future variant wired to `Actionable` by mistake could leak
    /// raw, potentially IP-bearing error text into a diagnostic), so it must be a real test
    /// enumerating every variant, not just a handful of spot checks. `ChainResolutionHalted`
    /// is exempted from the "everything else is Transient" list — like `RateLimited`, it
    /// carries no arbitrary payload, only a fixed, pre-vetted message, so it is safe to be
    /// the second `Actionable`-producing variant (see its own doc and #513's M2 fix).
    #[test]
    fn test_fetch_failure_classifies_every_non_rate_limited_variant_as_transient() {
        // A `reqwest::Error` built from an invalid URL — `RequestBuilder::build`
        // is synchronous and fails on URL parsing alone, so this needs no network
        // access or async runtime.
        let reqwest_err = reqwest::Client::new()
            .get("not a valid url")
            .build()
            .unwrap_err();
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");

        let non_rate_limited = [
            DepsError::ParseError {
                file_type: "Cargo.toml".into(),
                source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad")),
            },
            DepsError::RegistryError {
                package: "flask".into(),
                source: reqwest_err.into(),
            },
            DepsError::CacheError("connection reset".into()),
            DepsError::PackageNotFound {
                package: "flask".into(),
                registry: "PyPI",
            },
            DepsError::HttpStatus {
                url: "https://example.com".into(),
                status: 500,
            },
            DepsError::ApiResponse {
                package: "flask".into(),
                registry: "PyPI",
                source: json_err,
            },
            DepsError::ResponseTooLarge {
                url: "https://example.com".into(),
                limit: 1024,
            },
            DepsError::InvalidVersionReq("bad range".into()),
            DepsError::Io(io_err),
            DepsError::Json(serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err()),
            DepsError::UnsupportedEcosystem("unknown".into()),
            DepsError::AmbiguousEcosystem("file.txt".into()),
            DepsError::InvalidUri("not a uri".into()),
            DepsError::Offline {
                url: "https://example.com".into(),
            },
        ];

        for error in non_rate_limited {
            assert_eq!(
                error.fetch_failure(),
                FetchFailure::Transient,
                "expected Transient for {error:?}"
            );
        }

        let rate_limited = DepsError::RateLimited {
            message: "set GITHUB_TOKEN to increase the rate limit".into(),
        };
        assert_eq!(
            rate_limited.fetch_failure(),
            FetchFailure::Actionable("set GITHUB_TOKEN to increase the rate limit".into())
        );

        assert_eq!(
            DepsError::ChainResolutionHalted.fetch_failure(),
            FetchFailure::Actionable(
                "index unreachable — resolution halted, not falling back to a less-trusted \
                 index"
                    .to_string()
            )
        );
    }
}
