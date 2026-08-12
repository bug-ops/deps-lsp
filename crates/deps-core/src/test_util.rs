//! Cross-platform test URI helper shared across ecosystem crates.
//!
//! Test fixtures throughout the workspace write absolute paths in Unix
//! style (e.g. `/project/Cargo.toml`) for readability. `Uri::from_file_path`
//! requires a platform-absolute path, and a Unix-style path is not
//! recognized as absolute on Windows (no drive letter), so calling it
//! directly with such a literal panics on Windows only. [`test_uri`]
//! normalizes the path per host platform before constructing the [`Uri`].

use tower_lsp_server::ls_types::Uri;

/// Builds a [`Uri`] from a Unix-style absolute test path.
///
/// On Windows, a synthetic `C:` drive is prefixed so the path is
/// recognized as absolute; on other platforms the path is used as-is.
///
/// # Panics
///
/// Panics if the resulting path is not a valid file URI. This is a test
/// helper: fixture paths are expected to always be well-formed.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::test_uri;
///
/// let uri = test_uri("/project/Cargo.toml");
/// assert!(uri.path().as_str().ends_with("Cargo.toml"));
/// ```
#[must_use]
pub fn test_uri(unix_path: &str) -> Uri {
    #[cfg(windows)]
    let owned;
    #[cfg(windows)]
    let path: &str = {
        owned = format!("C:{unix_path}");
        &owned
    };
    #[cfg(not(windows))]
    let path: &str = unix_path;

    Uri::from_file_path(path).expect("test_uri: fixture path must be a valid file URI")
}
