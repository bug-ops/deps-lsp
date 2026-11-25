//! Gradle layout facts shared by `deps-gradle` and `deps-cli` (#2174): settings file names and
//! what counts as a version catalog, defined once so the two crates cannot drift apart.

use std::path::Path;

/// A Gradle settings file flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradleSettingsFile {
    /// `settings.gradle.kts`.
    Kotlin,
    /// `settings.gradle`.
    Groovy,
}

impl GradleSettingsFile {
    /// Every settings file flavour in lookup order (Kotlin first).
    pub const ALL: [Self; 2] = [Self::Kotlin, Self::Groovy];

    /// The settings file's name on disk.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Kotlin => "settings.gradle.kts",
            Self::Groovy => "settings.gradle",
        }
    }
}

/// Whether `path` names a Gradle version catalog file (a `.toml` file, ASCII case-insensitive).
///
/// Gradle imports only TOML catalogs, so for a file already routed to the Gradle ecosystem the
/// extension is the whole rule, whether routing came from the `*.versions.toml` glob or from a
/// `settings.gradle(.kts)` declaration.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use deps_core::gradle_layout::is_version_catalog_file;
///
/// assert!(is_version_catalog_file(Path::new("gradle/libs.versions.toml")));
/// assert!(is_version_catalog_file(Path::new("gradle/Deps.TOML")));
/// assert!(!is_version_catalog_file(Path::new("build.gradle.kts")));
/// ```
#[must_use]
pub fn is_version_catalog_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
}
