use thiserror::Error;

/// Reconstructs the "{status} {reason}" text `reqwest::StatusCode`'s `Display`
/// produces, since `HttpStatus` stores a bare `u16` for structural matching
/// and loses the canonical reason phrase otherwise.
fn http_status_message(status: u16, url: &str) -> String {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason());
    reason.map_or_else(
        || format!("HTTP {status} for {url}"),
        |reason| format!("HTTP {status} {reason} for {url}"),
    )
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
#[derive(Error, Debug)]
pub enum DepsError {
    #[error("failed to parse {file_type}: {source}")]
    ParseError {
        file_type: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("registry request failed for {package}: {source}")]
    RegistryError {
        package: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("cache error: {0}")]
    CacheError(String),

    /// A registry request was rejected for exceeding a rate limit. Unlike other variants,
    /// `message` is a pre-vetted, IP-free, actionable hint safe to surface verbatim in a
    /// per-dependency diagnostic (see [`Self::fetch_failure`]) — never build one from a raw
    /// registry error body, which can embed the caller's public IP (`github.rs:332-346`).
    #[error("{message}")]
    RateLimited { message: String },

    #[error("{package} not found on {registry}")]
    PackageNotFound {
        package: String,
        registry: &'static str,
    },

    #[error("{}", http_status_message(*status, url))]
    HttpStatus { url: String, status: u16 },

    #[error("failed to parse {registry} response for {package}: {source}")]
    ApiResponse {
        package: String,
        registry: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("response body for {url} exceeds {limit} byte limit")]
    ResponseTooLarge { url: String, limit: usize },

    /// Deliberately shared between two distinct rejection kinds: malformed version-requirement
    /// strings (all ecosystems) and malformed Go module paths (`deps-go`, which has no separate
    /// variant for the latter — see its `validate_module_path`). Nothing in the workspace
    /// discriminates on this variant beyond rendering its message, so a consumer-specific split
    /// was deferred (#399).
    #[error("invalid version requirement: {0}")]
    InvalidVersionReq(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(String),

    #[error("ambiguous ecosystem detection for file: {0}")]
    AmbiguousEcosystem(String),

    #[error("invalid URI: {0}")]
    InvalidUri(String),
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
            _ => FetchFailure::Transient,
        }
    }
}

/// Outcome of a registry fetch attempt for one dependency, as recorded in
/// `DocumentState::fetch_failed` and rendered by
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] (#478).
///
/// Replaces a bare `HashSet<PackageName>` membership check so the per-dependency diagnostic
/// can distinguish a failure with a safe, user-actionable hint from an opaque one, without
/// ever threading raw, potentially IP-bearing error text into the diagnostic (see
/// [`DepsError::fetch_failure`]).
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

    #[test]
    fn test_error_display() {
        let error = DepsError::CacheError("test error".into());
        assert_eq!(error.to_string(), "cache error: test error");
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

    /// Exhaustive companion to the doc-test on [`DepsError::fetch_failure`]: every
    /// variant other than [`DepsError::RateLimited`] must classify as
    /// [`FetchFailure::Transient`]. This is the invariant the doc comment calls
    /// security-load-bearing (a future variant wired to `Actionable` by mistake
    /// could leak raw, potentially IP-bearing error text into a diagnostic), so it
    /// must be a real test enumerating every variant, not just the 2-variant
    /// doc-test spot check.
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
                source: reqwest_err,
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
    }
}
