//! Canonical PyPI package name normalization (PEP 503).
//!
//! This is the single normalization used across deps-pypi — registry lookups,
//! `PypiFormatter`'s [`normalize_package_name`](deps_core::lsp_helpers::EcosystemFormatter::normalize_package_name)
//! override, and lock file parsing — so a name declared any of several ways
//! (`Zope.Interface`, `zope_interface`, `zope-interface`) resolves to the
//! same lookup key everywhere. See [`crate::types::PypiDependency::name`] for
//! why the *declared* name is not itself always normalized.

/// Normalizes `name` per [PEP 503](https://peps.python.org/pep-0503/#normalized-names):
/// lowercases, then collapses any run of `-`, `_`, or `.` into a single `-`.
///
/// This matches the actual PyPI Simple API URL contract
/// (`https://pypi.org/simple/<name>/`) and what both `poetry.lock` and
/// `uv.lock` store, unlike the historical `_`-based key space this replaces.
///
/// **Deliberate deviation from PEP 503's own regex** (`re.sub(r"[-_.]+",
/// "-", name).lower()`): that regex collapses a *leading or trailing*
/// separator run into a single leading/trailing `-` (`"_package_"` ->
/// `"-package-"`), which this function strips entirely instead
/// (`"_package_"` -> `"package"`). PyPI's own package-name validation
/// regex forbids a name from starting or ending with a separator, so no
/// real published package name can exercise this difference — stripping
/// matches what a human clearly meant by a manifest name like `_package_`
/// better than preserving a leading/trailing hyphen would.
///
/// # Examples
///
/// ```
/// use deps_pypi::name::normalize;
///
/// assert_eq!(normalize("Flask"), "flask");
/// assert_eq!(normalize("django_rest_framework"), "django-rest-framework");
/// assert_eq!(normalize("Pillow.Image"), "pillow-image");
/// assert_eq!(normalize("my__package"), "my-package");
/// assert_eq!(normalize("---"), "");
/// ```
pub fn normalize(name: &str) -> String {
    name.to_lowercase()
        .replace(['_', '.'], "-")
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_lowercase() {
        assert_eq!(normalize("Flask"), "flask");
        assert_eq!(normalize("DJANGO"), "django");
        assert_eq!(normalize("Requests"), "requests");
    }

    #[test]
    fn test_normalize_underscores() {
        assert_eq!(normalize("django_rest_framework"), "django-rest-framework");
        assert_eq!(normalize("my_package"), "my-package");
    }

    #[test]
    fn test_normalize_dots() {
        assert_eq!(normalize("Pillow.Image"), "pillow-image");
        assert_eq!(normalize("zope.interface"), "zope-interface");
    }

    #[test]
    fn test_normalize_consecutive_separators() {
        assert_eq!(normalize("my__package"), "my-package");
        assert_eq!(normalize("my..package"), "my-package");
        assert_eq!(normalize("my_.package"), "my-package");
    }

    #[test]
    fn test_normalize_mixed() {
        assert_eq!(normalize("My_Package.Name"), "my-package-name");
        assert_eq!(normalize("SOME__Weird.._Package"), "some-weird-package");
    }

    #[test]
    fn test_normalize_already_normalized() {
        assert_eq!(normalize("my-package"), "my-package");
        assert_eq!(normalize("django-rest-framework"), "django-rest-framework");
    }

    #[test]
    fn test_normalize_edge_cases() {
        assert_eq!(normalize("a"), "a");
        assert_eq!(normalize("A_B_C"), "a-b-c");
        assert_eq!(normalize("---"), "");
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn test_normalize_leading_trailing_separators() {
        assert_eq!(normalize("_package_"), "package");
        assert_eq!(normalize(".package."), "package");
        assert_eq!(normalize("__package__"), "package");
    }
}
