use thiserror::Error;

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
}
