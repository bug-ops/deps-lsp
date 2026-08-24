//! Errors specific to Deno/JSR dependency handling.
//!
//! These errors cover parsing `deno.json`/`deno.jsonc`. Registry communication errors are
//! reported as `deps_core::DepsError` directly (see `crate::registry`).

use thiserror::Error;

/// Errors specific to Deno/JSR dependency handling.
#[derive(Error, Debug)]
pub enum DenoError {
    /// Failed to parse `deno.json`/`deno.jsonc` as JSON/JSONC.
    #[error("Failed to parse deno.json: {message}")]
    JsonParseError {
        /// The underlying `jsonc-parser` error, stringified — `jsonc_parser::ParseError`
        /// does not implement `std::error::Error`, so this stores its `Display` output
        /// rather than boxing it as a source.
        message: String,
    },
}

/// Result type alias for Deno operations.
pub type Result<T> = std::result::Result<T, DenoError>;

/// Convert to `deps_core::DepsError` for interoperability.
impl From<DenoError> for deps_core::DepsError {
    fn from(err: DenoError) -> Self {
        match err {
            DenoError::JsonParseError { message } => Self::ParseError {
                file_type: "deno.json".to_string(),
                source: message.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DenoError::JsonParseError {
            message: "unexpected token".to_string(),
        };
        assert!(err.to_string().contains("Failed to parse deno.json"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = DenoError::JsonParseError {
            message: "unexpected token".to_string(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }
}
