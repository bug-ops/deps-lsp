//! Manifest recognition that needs no registry, no policy and no ecosystem instance.
//!
//! A driving adapter must decide whether a file is a manifest before it has loaded the
//! configuration the ecosystems are built from, which this module answers (#2182).

use deps_core::ecosystem::ClaimBound;
use std::path::Path;

/// Whether an ecosystem claims `path` as a manifest that static routing cannot recognize by
/// name, such as a Gradle version catalog declared by a settings file.
///
/// Only content-independent claims are answered: `false` without the `gradle` feature, since no
/// other ecosystem has one. A relative `path` is resolved against the current directory;
/// `bound` caps how far the lookup may reach. Reads the filesystem, so call it only from a
/// blocking context.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// assert!(!deps_engine::manifest_probe::manifest_claimed_without_policy(
///     Path::new("deps.toml"),
///     None
/// ));
/// ```
#[must_use]
pub fn manifest_claimed_without_policy(path: &Path, bound: Option<&ClaimBound>) -> bool {
    #[cfg(feature = "gradle")]
    {
        std::path::absolute(path)
            .is_ok_and(|absolute| deps_gradle::settings_declare_catalog(&absolute, bound))
    }
    #[cfg(not(feature = "gradle"))]
    {
        let _ = (path, bound);
        false
    }
}
