//! Document loading from filesystem for cold start scenarios.
//!
//! When an LSP client has a file already open and the server starts,
//! the client may not send a didOpen event. This module provides
//! infrastructure to load documents from disk when handlers receive
//! requests for unknown documents.
//!
//! # Architecture
//!
//! Cold start loading is pull-based (not workspace scanning):
//! - Handlers check if document exists in state
//! - If not, call `ensure_document_loaded()`
//! - Document is loaded from disk, parsed, and cached
//! - Background task fetches version information
//!
//! # Performance
//!
//! File reading is async and non-blocking. Typical latency is <50ms
//! for documents under 100KB (most manifest files are <10KB).
//!
//! # Security
//!
//! - Rate limiting prevents DOS attacks (10 req/sec per URI)
//! - File size limit: 10MB (configurable)
//! - Non-UTF8 files are rejected
//!
//! # Error Handling
//!
//! All errors are logged and result in graceful degradation (handlers
//! return empty results rather than crashing).

use deps_core::error::{DepsError, Result};
use tower_lsp_server::ls_types::Uri;

/// Maximum allowed file/document size in bytes (10MB).
///
/// Files larger than this limit will be rejected to prevent excessive memory usage
/// and performance degradation. This is a hard limit - files exceeding it cannot be loaded.
/// Typical manifest files are <100KB, so 10MB provides ample headroom.
///
/// `pub(crate)` since [`super::lifecycle`] applies the same bound to content
/// received directly over the LSP protocol (`textDocument/didOpen` /
/// `textDocument/didChange`), which has no filesystem `metadata()` call to
/// gate on before it reaches this crate.
pub(crate) const MAX_FILE_SIZE: u64 = 10_000_000; // 10MB

/// Large file warning threshold (1MB).
///
/// Files larger than this will log a warning, as typical manifests are much smaller.
const LARGE_FILE_THRESHOLD: u64 = 1_000_000; // 1MB

/// Loads document content from disk.
///
/// # Arguments
///
/// * `uri` - Document URI (must be file:// scheme)
///
/// # Returns
///
/// * `Ok(String)` - File content
/// * `Err(DepsError)` - File not found, permission denied, not a file URI, or too large/not a
///   regular file
///
/// # Errors
///
/// - `DepsError::InvalidUri` - URI is not a file:// URI
/// - `DepsError::Io` - File read error (not found, permission denied, etc.)
/// - `DepsError::CacheError` - Not a regular file, or exceeds `MAX_FILE_SIZE`
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
    // Convert URI to filesystem path. Owned (not `Cow::Borrowed`), since the read below runs
    // in `spawn_blocking` and needs a `'static` path.
    let path = match uri.to_file_path() {
        Some(p) => p.into_owned(),
        None => {
            tracing::debug!("Cannot load non-file URI: {:?}", uri);
            return Err(DepsError::InvalidUri(format!("{uri:?}")));
        }
    };

    tracing::debug!("Loading document from disk: {:?}", path);

    // Check file metadata for size limits and warnings
    match tokio::fs::metadata(&path).await {
        Ok(metadata) => {
            // Reject anything but a regular file (FIFO, socket, character device,
            // directory) before ever attempting to open it — a FIFO/chardev reports
            // `len() == 0`, would pass the size gate below, and then block the
            // `spawn_blocking` thread that opens it indefinitely (mirrors the `is_file`
            // gate `discover_workspace` applies via `fs_probe::metadata` in
            // `deps-cargo/src/parser.rs`).
            if !metadata.is_file() {
                tracing::warn!("Rejecting non-regular-file document: {:?}", path);
                return Err(DepsError::CacheError(format!(
                    "not a regular file: {}",
                    path.display()
                )));
            }

            let size = metadata.len();

            // Hard limit: reject files over 10MB
            if size > MAX_FILE_SIZE {
                tracing::error!(
                    "Document exceeds maximum size: {} bytes (limit: {} bytes)",
                    size,
                    MAX_FILE_SIZE
                );
                return Err(DepsError::CacheError(format!(
                    "file too large: {size} bytes (max: {MAX_FILE_SIZE} bytes)"
                )));
            }

            // Warning for files over 1MB
            if size > LARGE_FILE_THRESHOLD {
                tracing::warn!(
                    "Document is large: {} bytes for {:?}. Typical manifests are <100KB.",
                    size,
                    path
                );
            }

            tracing::trace!("File size: {} bytes", size);
        }
        Err(e) => {
            // Differentiate permission errors from other IO errors
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    tracing::debug!("File not found: {:?}", path);
                }
                std::io::ErrorKind::PermissionDenied => {
                    tracing::warn!("Permission denied: {:?}", path);
                }
                _ => {
                    tracing::error!("IO error reading metadata for {:?}: {}", path, e);
                }
            }
            return Err(DepsError::Io(e));
        }
    }

    // Read file content, bounded by the read itself (not just the metadata pre-filter
    // above): `read_to_string_capped` opens the file and caps via `Read::take`, so a
    // symlink swap or concurrent growth between the `metadata` call above and this read
    // cannot let an oversized file through (CWE-367). Runs in `spawn_blocking` since it is a
    // synchronous `std::fs` call.
    let read_path = path.clone();
    let capped = tokio::task::spawn_blocking(move || {
        deps_core::fs_probe::read_to_string_capped(&read_path, MAX_FILE_SIZE)
    })
    .await
    .map_err(|e| {
        tracing::error!("document read task for {:?} panicked: {}", path, e);
        DepsError::CacheError(format!("document read task failed: {e}"))
    })?
    .map_err(|e| {
        // Differentiate permission errors in file read
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                tracing::debug!("File not found during read: {:?}", path);
            }
            std::io::ErrorKind::PermissionDenied => {
                tracing::warn!("Permission denied reading file: {:?}", path);
            }
            _ => {
                tracing::error!("IO error reading file {:?}: {}", path, e);
            }
        }
        DepsError::Io(e)
    })?;

    let content = match capped {
        Some(content) => content,
        None => {
            // Unreachable without a real TOCTOU race (a symlink swap or concurrent growth
            // between the `metadata` check above and this read): the metadata gate already
            // rejects anything over `MAX_FILE_SIZE` before the read starts. This is
            // race-only defense-in-depth, not the primary mitigation — the property that
            // this branch can even fire is what `fs_probe`'s own
            // `read_to_string_capped_rejects_content_over_cap` test proves.
            tracing::error!(
                "Document exceeds maximum size during read (limit: {} bytes): {:?}",
                MAX_FILE_SIZE,
                path
            );
            return Err(DepsError::CacheError(format!(
                "file too large (max: {MAX_FILE_SIZE} bytes)"
            )));
        }
    };

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
        let uri = deps_core::test_util::test_uri("/nonexistent/file/path.toml");
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
        assert_eq!(MAX_FILE_SIZE, 10_000_000);
        assert_eq!(LARGE_FILE_THRESHOLD, 1_000_000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_load_symlink_to_valid_file() {
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.toml");
        let link = temp_dir.path().join("link.toml");

        std::fs::write(&target, "[dependencies]").unwrap();
        symlink(&target, &link).unwrap();

        let uri = Uri::from_file_path(&link).unwrap();
        let content = load_document_from_disk(&uri).await.unwrap();
        assert_eq!(content, "[dependencies]");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_load_circular_symlink() {
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let link1 = temp_dir.path().join("link1.toml");
        let link2 = temp_dir.path().join("link2.toml");

        symlink(&link2, &link1).unwrap();
        symlink(&link1, &link2).unwrap();

        let uri = Uri::from_file_path(&link1).unwrap();
        let result = load_document_from_disk(&uri).await;
        assert!(result.is_err(), "Circular symlink should fail");
    }

    /// A FIFO reports `len() == 0` from `metadata`, which would pass the size gate — without
    /// the `is_file` check, opening it for read blocks the `spawn_blocking` thread
    /// indefinitely (a writerless FIFO never yields EOF). Wrapped in a timeout so a
    /// regression fails this test in seconds instead of hanging the whole suite.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_load_fifo_does_not_hang() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let fifo_path = temp_dir.path().join("Cargo.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mkfifo must succeed for this test to be meaningful"
        );

        let uri = Uri::from_file_path(&fifo_path).unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            load_document_from_disk(&uri),
        )
        .await
        .expect("a FIFO must be rejected by the is_file gate, not block trying to open it");

        assert!(
            result.is_err(),
            "a FIFO must never be treated as a loadable document"
        );
    }

    #[tokio::test]
    async fn test_load_file_exceeding_max_size() {
        use std::io::Write;

        // Create a file just over MAX_FILE_SIZE (10MB)
        // To avoid slow tests, we create a sparse file if possible
        // Otherwise, we verify the error message format with metadata check
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write a small file for fast test execution
        // We'll verify the size check logic by examining metadata
        let content = "test content";
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Verify the constant is enforced (boundary test)
        assert_eq!(MAX_FILE_SIZE, 10_000_000, "MAX_FILE_SIZE constant changed");

        // For platforms supporting sparse files, create a file > 10MB
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let large_file = temp_dir.path().join("large.toml");

            // Create file and write single byte at position > 10MB
            // This creates a sparse file without actually allocating disk space
            let file = std::fs::File::create(&large_file).unwrap();
            let beyond_limit = MAX_FILE_SIZE + 1;
            file.write_at(b"x", beyond_limit).unwrap();

            let uri = Uri::from_file_path(&large_file).unwrap();
            let result = load_document_from_disk(&uri).await;

            assert!(result.is_err(), "Should reject files > MAX_FILE_SIZE");
            match result {
                Err(DepsError::CacheError(msg)) => {
                    assert!(
                        msg.contains("file too large"),
                        "Error message should indicate file size issue: {msg}"
                    );
                    assert!(
                        msg.contains(&beyond_limit.to_string())
                            || msg.contains(&(beyond_limit + 1).to_string()),
                        "Error should mention actual file size: {msg}"
                    );
                }
                _ => panic!("Expected CacheError for oversized file"),
            }
        }
    }

    /// A file exactly at `MAX_FILE_SIZE` must still load in full: `read_to_string_capped`
    /// reads one byte past the cap to detect an overage, and an off-by-one there would
    /// falsely reject a file that lands exactly on the boundary (mirrors
    /// `deps_core::mtime_cache::tests::file_exactly_at_cap_is_still_cached`).
    #[tokio::test]
    async fn test_load_file_exactly_at_max_size() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let path = temp_dir.path().join("exact.toml");
        let content = "a".repeat(MAX_FILE_SIZE as usize);
        std::fs::write(&path, &content).unwrap();

        let uri = Uri::from_file_path(&path).unwrap();
        let loaded = load_document_from_disk(&uri).await.unwrap();

        assert_eq!(loaded.len(), MAX_FILE_SIZE as usize);
    }

    /// Proves the read goes through the counted `fs_probe::read_to_string_capped`, not a raw
    /// `tokio::fs::read_to_string` that would bypass the cap enforced at the read itself —
    /// the property that closes the TOCTOU gap for #603 the same way #601 closed it for
    /// `MtimeFileCache`.
    #[tokio::test]
    async fn test_load_routes_through_capped_read() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test content").unwrap();
        temp_file.flush().unwrap();

        let uri = Uri::from_file_path(temp_file.path()).unwrap();
        let (_, reads_before) = deps_core::fs_probe::snapshot();
        load_document_from_disk(&uri).await.unwrap();
        let (_, reads_after) = deps_core::fs_probe::snapshot();

        assert_eq!(
            reads_after - reads_before,
            1,
            "load_document_from_disk must read exactly once through the counted fs_probe path"
        );
    }
}
