//! Errors specific to Swift/SPM dependency handling.

use thiserror::Error;

/// Errors specific to Swift/SPM dependency handling.
#[derive(Error, Debug)]
pub enum SwiftError {
    /// Failed to parse Package.swift
    #[error("Failed to parse Package.swift: {message}")]
    ParseError { message: String },

    /// Invalid SPM version specifier
    #[error("Invalid SPM version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },

    /// GitHub API request failed
    #[error("GitHub API request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// GitHub API returned an error status
    #[error("GitHub API error: {status} {message}")]
    GitHubApiError { status: u16, message: String },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for Swift operations.
pub type Result<T> = std::result::Result<T, SwiftError>;

impl SwiftError {
    pub fn registry_error(
        package: impl Into<String>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::RegistryError {
            package: package.into(),
            source: Box::new(error),
        }
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::ParseError {
            message: message.into(),
        }
    }

    pub fn github_api_error(message: impl Into<String>) -> Self {
        Self::GitHubApiError {
            status: 0,
            message: message.into(),
        }
    }
}

impl From<deps_core::DepsError> for SwiftError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::CacheError(msg) => Self::ParseError { message: msg },
            deps_core::DepsError::InvalidVersionReq(msg) => Self::InvalidVersionSpecifier {
                specifier: String::new(),
                message: msg,
            },
            deps_core::DepsError::Io(e) => Self::Io(e),
            other => Self::ParseError {
                message: other.to_string(),
            },
        }
    }
}

impl From<SwiftError> for deps_core::DepsError {
    fn from(err: SwiftError) -> Self {
        match err {
            SwiftError::ParseError { message } => Self::CacheError(message),
            SwiftError::InvalidVersionSpecifier { message, .. } => Self::InvalidVersionReq(message),
            SwiftError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("GitHub API for {package}"),
                source,
            },
            SwiftError::GitHubApiError { status, message } => {
                Self::CacheError(format!("GitHub API {status}: {message}"))
            }
            SwiftError::Io(e) => Self::Io(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SwiftError::ParseError {
            message: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse Package.swift: unexpected token"
        );

        let err = SwiftError::GitHubApiError {
            status: 403,
            message: "rate limited".into(),
        };
        assert_eq!(err.to_string(), "GitHub API error: 403 rate limited");
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = SwiftError::ParseError {
            message: "test".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(deps_err.to_string().contains("test"));
    }
}
