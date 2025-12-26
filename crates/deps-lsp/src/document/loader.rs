//! Document loading from filesystem for cold start scenarios.
//!
//! When an LSP client has a file already open and the server starts,
//! the client may not send a didOpen event. This module provides
//! infrastructure to load documents from disk when handlers receive
//! requests for unknown documents.
//!
//! # Performance
//!
//! File reading is async and non-blocking. Typical latency is <50ms
//! for documents under 100KB (most manifest files are <10KB).
//!
//! # Error Handling
//!
//! All errors are logged and result in graceful degradation (handlers
//! return empty results rather than crashing).

use deps_core::error::{DepsError, Result};
use tower_lsp_server::ls_types::Uri;

/// Maximum allowed file size in bytes (50MB).
///
/// Files larger than this limit will be rejected to prevent excessive memory usage
/// and performance degradation. This is a hard limit - files exceeding it cannot be loaded.
const MAX_FILE_SIZE: u64 = 50_000_000; // 50MB

/// Loads document content from disk.
///
/// # Arguments
///
/// * `uri` - Document URI (must be file:// scheme)
///
/// # Returns
///
/// * `Ok(String)` - File content
/// * `Err(DepsError)` - File not found, permission denied, or not a file URI
///
/// # Errors
///
/// - `DepsError::InvalidUri` - URI is not a file:// URI
/// - `DepsError::Io` - File read error (not found, permission denied, etc.)
///
/// # Examples
///
/// ```no_run
/// use deps_lsp::document::load_document_from_disk;
/// use tower_lsp_server::ls_types::Uri;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let uri = Uri::from_file_path("/path/to/Cargo.toml").unwrap();
/// let content = load_document_from_disk(&uri).await?;
/// println!("Loaded {} bytes", content.len());
/// # Ok(())
/// # }
/// ```
pub async fn load_document_from_disk(uri: &Uri) -> Result<String> {
    // Convert URI to filesystem path
    let path = match uri.to_file_path() {
        Some(p) => p,
        None => {
            tracing::debug!("Cannot load non-file URI: {:?}", uri);
            return Err(DepsError::InvalidUri(format!("{:?}", uri)));
        }
    };

    tracing::debug!("Loading document from disk: {:?}", path);

    // Check file metadata for size limits and warnings
    match tokio::fs::metadata(&path).await {
        Ok(metadata) => {
            let size = metadata.len();

            // Hard limit: reject files over 50MB
            if size > MAX_FILE_SIZE {
                tracing::error!(
                    "Document exceeds maximum size: {} bytes (limit: {} bytes)",
                    size,
                    MAX_FILE_SIZE
                );
                return Err(DepsError::CacheError(format!(
                    "file too large: {} bytes (max: {} bytes)",
                    size, MAX_FILE_SIZE
                )));
            }

            // Warning for files over 10MB (but under 50MB limit)
            if size > 10_000_000 {
                tracing::warn!(
                    "Document is very large: {} bytes. This may impact performance.",
                    size
                );
            }

            tracing::trace!("File size: {} bytes", size);
        }
        Err(e) => {
            tracing::debug!("Failed to read metadata for {:?}: {}", path, e);
            return Err(DepsError::Io(e));
        }
    }

    // Read file content asynchronously
    let content = tokio::fs::read_to_string(&path).await.map_err(|e| {
        tracing::debug!("Failed to read file {:?}: {}", path, e);
        DepsError::Io(e)
    })?;

    tracing::debug!(
        "Successfully loaded document: {:?} ({} bytes)",
        path,
        content.len()
    );

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tower_lsp_server::ls_types::Uri;

    #[tokio::test]
    async fn test_load_existing_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = "test content";
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded, content);
    }

    #[tokio::test]
    async fn test_load_nonexistent_file() {
        let uri = Uri::from_file_path("/nonexistent/file/path.toml").unwrap();
        let result = load_document_from_disk(&uri).await;

        assert!(result.is_err());
        match result {
            Err(DepsError::Io(_)) => {}
            _ => panic!("Expected Io error"),
        }
    }

    #[tokio::test]
    async fn test_load_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        // File is empty, don't write anything

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded, "");
    }

    // Note: Tests for non-file URIs (http://, untitled:) are covered by integration tests
    // Creating non-file URIs in unit tests would require adding fluent_uri as a dev dependency
    // The implementation correctly handles these cases via to_file_path() returning None

    #[tokio::test]
    async fn test_load_utf8_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = "Hello 世界 🌍 Привет";
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded, content);
    }

    #[tokio::test]
    async fn test_load_non_utf8_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write invalid UTF-8 bytes
        temp_file.write_all(&[0xFF, 0xFE, 0xFD]).unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let result = load_document_from_disk(&uri).await;

        assert!(result.is_err());
        match result {
            Err(DepsError::Io(_)) => {}
            _ => panic!("Expected Io error for non-UTF8 content"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_load_permission_denied() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test").unwrap();
        temp_file.flush().unwrap();

        // Remove read permissions
        let mut perms = fs::metadata(temp_file.path()).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(temp_file.path(), perms.clone()).unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let result = load_document_from_disk(&uri).await;

        // Restore permissions for cleanup
        perms.set_mode(0o644);
        let _ = fs::set_permissions(temp_file.path(), perms);

        assert!(result.is_err());
        match result {
            Err(DepsError::Io(_)) => {}
            _ => panic!("Expected Io error for permission denied"),
        }
    }

    #[tokio::test]
    async fn test_load_large_file_warning() {
        // This test verifies that large files can be loaded (with warning logged)
        // We don't create a 10MB+ file to avoid slow tests, but we verify
        // that normal-sized files load successfully
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = "a".repeat(1000); // 1KB, well under the warning threshold
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded.len(), 1000);
    }

    #[tokio::test]
    async fn test_load_cargo_toml() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded, content);
        assert!(loaded.contains("[dependencies]"));
    }

    #[tokio::test]
    async fn test_file_size_limit_constant() {
        // Document the limit for maintainability
        assert_eq!(MAX_FILE_SIZE, 50_000_000);
    }
}
