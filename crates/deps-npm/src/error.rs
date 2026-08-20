//! Errors specific to npm/JavaScript dependency handling.
//!
//! These errors cover parsing package.json files. Registry communication
//! errors are reported as `deps_core::DepsError` directly (see
//! `crate::registry`).

use thiserror::Error;

/// Errors specific to npm/JavaScript dependency handling.
#[derive(Error, Debug)]
pub enum NpmError {
    /// Failed to parse package.json
    #[error("Failed to parse package.json: {source}")]
    JsonParseError {
        #[source]
        source: serde_json::Error,
    },
}

/// Result type alias for npm operations.
pub type Result<T> = std::result::Result<T, NpmError>;

/// Convert to deps_core::DepsError for interoperability
impl From<NpmError> for deps_core::DepsError {
    fn from(err: NpmError) -> Self {
        match err {
            NpmError::JsonParseError { source } => Self::Json(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = NpmError::JsonParseError { source: json_err };
        assert!(err.to_string().contains("Failed to parse package.json"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let npm_err = NpmError::JsonParseError { source: json_err };
        let deps_err: deps_core::DepsError = npm_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Json(_)));
    }
}
