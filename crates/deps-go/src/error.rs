//! Errors specific to Go module dependency handling.

use thiserror::Error;

/// Errors that can occur during Go module operations.
#[derive(Error, Debug)]
pub enum GoError {
    /// Failed to parse go.mod file
    #[error("Failed to parse go.mod: {source}")]
    ParseError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Invalid version specifier
    #[error("Invalid version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },

    /// Module not found in registry
    #[error("Module '{module}' not found")]
    ModuleNotFound { module: String },

    /// Registry request failed
    #[error("Registry request failed for '{module}': {source}")]
    RegistryError {
        module: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Invalid module path
    #[error("Invalid module path: {0}")]
    InvalidModulePath(String),

    /// Invalid pseudo-version format
    #[error("Invalid pseudo-version '{version}': {reason}")]
    InvalidPseudoVersion { version: String, reason: String },

    /// Failed to deserialize proxy.golang.org API response
    #[error("Failed to parse proxy.golang.org API response for '{module}': {source}")]
    ApiResponseError {
        module: String,
        #[source]
        source: serde_json::Error,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error wrapper
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Result type alias for Go operations.
pub type Result<T> = std::result::Result<T, GoError>;

impl GoError {
    /// Helper for creating registry errors
    pub fn registry_error(
        module: impl Into<String>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::RegistryError {
            module: module.into(),
            source: Box::new(error),
        }
    }

    /// Helper for creating invalid version specifier errors
    pub fn invalid_version_specifier(
        specifier: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidVersionSpecifier {
            specifier: specifier.into(),
            message: message.into(),
        }
    }

    /// Helper for creating module not found errors
    pub fn module_not_found(module: impl Into<String>) -> Self {
        Self::ModuleNotFound {
            module: module.into(),
        }
    }

    /// Helper for creating invalid pseudo-version errors
    pub fn invalid_pseudo_version(version: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidPseudoVersion {
            version: version.into(),
            reason: reason.into(),
        }
    }
}

impl From<GoError> for deps_core::DepsError {
    fn from(err: GoError) -> Self {
        match err {
            GoError::ParseError { source } => Self::ParseError {
                file_type: "go.mod".into(),
                source,
            },
            GoError::InvalidVersionSpecifier { message, .. } => Self::InvalidVersionReq(message),
            GoError::ModuleNotFound { module } => {
                Self::CacheError(format!("Module '{module}' not found"))
            }
            GoError::RegistryError { module, source } => Self::ParseError {
                file_type: format!("registry for {module}"),
                source,
            },
            GoError::CacheError(msg) => Self::CacheError(msg),
            GoError::InvalidModulePath(msg) => Self::InvalidVersionReq(msg),
            GoError::InvalidPseudoVersion { version, reason } => {
                Self::InvalidVersionReq(format!("{version}: {reason}"))
            }
            GoError::ApiResponseError { module: _, source } => Self::Json(source),
            GoError::Io(e) => Self::Io(e),
            GoError::Other(e) => Self::ParseError {
                file_type: "go".into(),
                source: e,
            },
        }
    }
}

impl From<deps_core::DepsError> for GoError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => Self::ParseError { source },
            deps_core::DepsError::CacheError(msg) => Self::CacheError(msg),
            deps_core::DepsError::InvalidVersionReq(msg) => Self::InvalidVersionSpecifier {
                specifier: String::new(),
                message: msg,
            },
            deps_core::DepsError::Io(e) => Self::Io(e),
            deps_core::DepsError::Json(e) => Self::ApiResponseError {
                module: String::new(),
                source: e,
            },
            other => Self::CacheError(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_construction() {
        let err = GoError::ModuleNotFound {
            module: "test/module".to_string(),
        };
        assert_eq!(err.to_string(), "Module 'test/module' not found");
    }

    #[test]
    fn test_error_conversion() {
        let go_err = GoError::InvalidModulePath("invalid".to_string());
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(
            deps_err,
            deps_core::DepsError::InvalidVersionReq(_)
        ));
    }

    #[test]
    fn test_parse_error_conversion() {
        let go_err = GoError::ParseError {
            source: Box::new(std::io::Error::other("parse failed")),
        };
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_registry_error_conversion() {
        let go_err = GoError::RegistryError {
            module: "test/module".to_string(),
            source: Box::new(std::io::Error::other("network failed")),
        };
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_io_error_conversion() {
        let go_err = GoError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Io(_)));
    }

    #[test]
    fn test_cache_error_conversion() {
        let go_err = GoError::CacheError("cache miss".to_string());
        let deps_err: deps_core::DepsError = go_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }

    #[test]
    fn test_bidirectional_conversion() {
        let deps_err = deps_core::DepsError::CacheError("test error".to_string());
        let go_err: GoError = deps_err.into();
        assert!(matches!(go_err, GoError::CacheError(_)));
    }

    #[test]
    fn test_helper_methods() {
        let err = GoError::registry_error("test/module", std::io::Error::other("fail"));
        assert!(matches!(err, GoError::RegistryError { .. }));

        let err = GoError::invalid_version_specifier("v1.0", "invalid");
        assert!(matches!(err, GoError::InvalidVersionSpecifier { .. }));

        let err = GoError::module_not_found("test/module");
        assert!(matches!(err, GoError::ModuleNotFound { .. }));

        let err = GoError::invalid_pseudo_version("v0.0.0", "bad format");
        assert!(matches!(err, GoError::InvalidPseudoVersion { .. }));
    }
}
