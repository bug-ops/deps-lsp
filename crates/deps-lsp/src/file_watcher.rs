//! Lock file watching infrastructure.
//!
//! Provides file system watcher registration for lock files.
//! Lock file patterns are provided by individual ecosystem implementations.

use std::path::Path;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    DidChangeWatchedFilesRegistrationOptions, FileSystemWatcher, GlobPattern, Registration,
    WatchKind,
};

/// Registers file system watchers for lock files from all registered ecosystems.
///
/// Uses dynamic registration to request the client to watch lock file patterns.
/// Patterns are collected from all registered ecosystems via `EcosystemRegistry::all_lockfile_patterns()`.
///
/// # Arguments
///
/// * `client` - LSP client for registration requests
/// * `patterns` - Lock file glob patterns (e.g., "**/Cargo.lock")
///
/// # Errors
///
/// Returns an error if the client doesn't support dynamic registration
/// or if the registration request fails.
pub async fn register_lock_file_watchers(
    client: &Client,
    patterns: &[String],
) -> Result<(), String> {
    if patterns.is_empty() {
        tracing::debug!("No lock file patterns to watch");
        return Ok(());
    }

    let watchers: Vec<FileSystemWatcher> = patterns
        .iter()
        .map(|pattern| FileSystemWatcher {
            glob_pattern: GlobPattern::String(pattern.clone()),
            kind: Some(WatchKind::Create | WatchKind::Change | WatchKind::Delete),
        })
        .collect();

    let options = DidChangeWatchedFilesRegistrationOptions { watchers };

    let registration = Registration {
        id: "deps-lsp-lockfile-watcher".to_string(),
        method: "workspace/didChangeWatchedFiles".to_string(),
        register_options: Some(serde_json::to_value(options).map_err(|e| e.to_string())?),
    };

    client
        .register_capability(vec![registration])
        .await
        .map_err(|e| format!("Failed to register file watchers: {}", e))?;

    tracing::info!("Registered {} lock file watchers", patterns.len());
    Ok(())
}

/// Determines the ecosystem type from a lock file path.
///
/// This is a convenience function that extracts the filename and can be used
/// in conjunction with `EcosystemRegistry::get_for_lockfile()`.
///
/// # Arguments
///
/// * `lockfile_path` - Path to the lock file
///
/// # Returns
///
/// * `Some(&str)` - Lock file name
/// * `None` - Path has no filename component
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use deps_lsp::file_watcher::extract_lockfile_name;
///
/// let path = Path::new("/project/Cargo.lock");
/// assert_eq!(extract_lockfile_name(path), Some("Cargo.lock"));
/// ```
pub fn extract_lockfile_name(lockfile_path: &Path) -> Option<&str> {
    lockfile_path.file_name()?.to_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_lockfile_name_cargo() {
        let path = PathBuf::from("/project/Cargo.lock");
        assert_eq!(extract_lockfile_name(&path), Some("Cargo.lock"));
    }

    #[test]
    fn test_extract_lockfile_name_npm() {
        let path = PathBuf::from("/project/package-lock.json");
        assert_eq!(extract_lockfile_name(&path), Some("package-lock.json"));
    }

    #[test]
    fn test_extract_lockfile_name_poetry() {
        let path = PathBuf::from("/project/poetry.lock");
        assert_eq!(extract_lockfile_name(&path), Some("poetry.lock"));
    }

    #[test]
    fn test_extract_lockfile_name_uv() {
        let path = PathBuf::from("/project/uv.lock");
        assert_eq!(extract_lockfile_name(&path), Some("uv.lock"));
    }

    #[test]
    fn test_extract_lockfile_name_nested() {
        let path = PathBuf::from("/workspace/member/Cargo.lock");
        assert_eq!(extract_lockfile_name(&path), Some("Cargo.lock"));
    }

    #[test]
    fn test_extract_lockfile_name_no_filename() {
        let path = PathBuf::from("/");
        assert_eq!(extract_lockfile_name(&path), None);
    }
}
