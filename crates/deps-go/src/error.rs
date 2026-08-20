//! Errors specific to Go module dependency handling.

use thiserror::Error;

/// Errors that can occur during Go module operations.
///
/// These errors cover module path and version-string validation. Registry
/// communication errors are reported as `deps_core::DepsError` directly (see
/// `crate::registry`).
#[derive(Error, Debug)]
pub enum GoError {
    /// Invalid module path
    #[error("Invalid module path: {0}")]
    InvalidModulePath(String),

    /// Invalid version specifier
    #[error("Invalid version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },
}

/// Result type alias for Go operations.
pub type Result<T> = std::result::Result<T, GoError>;

impl From<GoError> for deps_core::DepsError {
    fn from(err: GoError) -> Self {
        match err {
            GoError::InvalidModulePath(msg) => Self::InvalidVersionReq(msg),
            GoError::InvalidVersionSpecifier { message, .. } => Self::InvalidVersionReq(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_module_path_display() {
        let err = GoError::InvalidModulePath("module path is empty".into());
        assert_eq!(err.to_string(), "Invalid module path: module path is empty");
    }

    #[test]
    fn test_invalid_version_specifier_display() {
        let err = GoError::InvalidVersionSpecifier {
            specifier: "bad".into(),
            message: "not a valid version".into(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid version specifier 'bad': not a valid version"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let go_err = GoError::InvalidModulePath("invalid".to_string());
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(
            deps_err,
            deps_core::DepsError::InvalidVersionReq(_)
        ));

        let go_err = GoError::InvalidVersionSpecifier {
            specifier: "v".into(),
            message: "bad".into(),
        };
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(
            deps_err,
            deps_core::DepsError::InvalidVersionReq(_)
        ));
    }
}
