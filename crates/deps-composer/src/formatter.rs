use deps_core::lsp_helpers::EcosystemFormatter;

/// Composer-specific LSP formatting.
///
/// Overrides version_satisfies_requirement to implement Composer's tilde (~)
/// operator semantics, which differ from npm:
/// - `~1.2.3` means `>=1.2.3 <1.3.0` (same as npm)
/// - `~1.2` means `>=1.2.0 <2.0.0` (DIFFERENT from npm where ~1.2 = >=1.2.0 <1.3.0)
pub struct ComposerFormatter;

impl EcosystemFormatter for ComposerFormatter {
    fn normalize_package_name(&self, name: &str) -> String {
        name.to_lowercase()
    }

    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://packagist.org/packages/{name}")
    }

    fn yanked_message(&self) -> &'static str {
        "This package is abandoned"
    }

    fn yanked_label(&self) -> &'static str {
        "*(abandoned)*"
    }

    /// Checks if a version satisfies a Composer version requirement.
    ///
    /// Handles Composer-specific operators:
    /// - `^` — caret (same semantics as default)
    /// - `~X.Y.Z` — tilde with patch: `>=X.Y.Z <X.(Y+1).0`
    /// - `~X.Y` — tilde without patch: `>=X.Y.0 <(X+1).0.0` (Composer-specific!)
    /// - `X.Y.*` — wildcard patch
    /// - `>=X <Y` — range (space = AND)
    /// - `X || Y` — OR combinator
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        let requirement = requirement.trim();

        if requirement.is_empty() || requirement == "*" {
            return true;
        }

        // OR combinator: "1.0 || 2.0"
        if requirement.contains("||") {
            return requirement
                .split("||")
                .any(|part| self.version_satisfies_requirement(version, part.trim()));
        }

        // Range with AND (space-separated constraints like ">=1.0 <2.0")
        // Only treat as AND if there are multiple space-separated tokens that look like constraints
        let parts: Vec<&str> = requirement.split_whitespace().collect();
        if parts.len() > 1
            && parts
                .iter()
                .any(|p| p.starts_with('>') || p.starts_with('<'))
        {
            return parts
                .iter()
                .all(|part| self.version_satisfies_requirement(version, part));
        }

        // Caret operator
        if let Some(req) = requirement.strip_prefix('^') {
            return satisfies_caret(version, req);
        }

        // Tilde operator — Composer-specific semantics
        if let Some(req) = requirement.strip_prefix('~') {
            return satisfies_tilde_composer(version, req);
        }

        // Comparison operators
        if let Some(req) = requirement.strip_prefix(">=") {
            return compare_versions(version, req.trim()) >= 0;
        }
        if let Some(req) = requirement.strip_prefix("<=") {
            return compare_versions(version, req.trim()) <= 0;
        }
        if let Some(req) = requirement.strip_prefix('>') {
            return compare_versions(version, req.trim()) > 0;
        }
        if let Some(req) = requirement.strip_prefix('<') {
            return compare_versions(version, req.trim()) < 0;
        }
        if let Some(req) = requirement.strip_prefix('=') {
            return compare_versions(version, req.trim()) == 0;
        }
        if let Some(req) = requirement.strip_prefix("!=") {
            return compare_versions(version, req.trim()) != 0;
        }

        // Wildcard: "1.0.*" means >=1.0.0 <1.1.0
        if requirement.ends_with(".*") {
            let prefix = requirement.trim_end_matches(".*");
            return version.starts_with(prefix) && version[prefix.len()..].starts_with('.');
        }

        // Exact or partial version match
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let ver_parts: Vec<&str> = version.split('.').collect();

        if req_parts.len() == ver_parts.len() {
            return version == requirement;
        }

        // Partial version: "1" matches "1.x.x", "1.2" matches "1.2.x"
        if req_parts.len() < ver_parts.len() {
            return ver_parts.starts_with(&req_parts);
        }

        false
    }
}

/// Composer tilde semantics.
///
/// - `~X.Y.Z` — `>=X.Y.Z <X.(Y+1).0` (bumps minor)
/// - `~X.Y` — `>=X.Y.0 <(X+1).0.0` (bumps MAJOR — Composer-specific!)
/// - `~X` — `>=X.0.0 <(X+1).0.0`
fn satisfies_tilde_composer(version: &str, req: &str) -> bool {
    let req_parts: Vec<&str> = req.split('.').collect();
    let ver_parts: Vec<&str> = version.split('.').collect();

    if req_parts.len() >= 3 {
        // ~X.Y.Z: same as default — >=X.Y.Z <X.(Y+1).0
        // Must have same major and minor
        if req_parts.first() != ver_parts.first() {
            return false;
        }
        if req_parts.get(1) != ver_parts.get(1) {
            return false;
        }
        // Patch must be >= req patch
        let req_patch: u64 = req_parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_patch: u64 = ver_parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        ver_patch >= req_patch
    } else if req_parts.len() == 2 {
        // ~X.Y: >=X.Y.0 <(X+1).0.0 — bumps MAJOR (Composer-specific!)
        let req_major: u64 = req_parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let req_minor: u64 = req_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_major: u64 = ver_parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_minor: u64 = ver_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);

        if ver_major != req_major {
            return false;
        }
        // Same major: minor must be >= req_minor
        ver_minor >= req_minor
    } else {
        // ~X: >=X.0.0 <(X+1).0.0 — same as caret for single segment
        req_parts.first() == ver_parts.first()
    }
}

/// Caret operator — same as default EcosystemFormatter but inlined for clarity.
fn satisfies_caret(version: &str, req: &str) -> bool {
    let req_parts: Vec<&str> = req.split('.').collect();
    let ver_parts: Vec<&str> = version.split('.').collect();

    if req_parts.first() != ver_parts.first() {
        return false;
    }

    if req_parts.first().is_some_and(|m| *m != "0") {
        return true;
    }

    if req_parts.len() >= 2 && ver_parts.len() >= 2 {
        return req_parts[1] == ver_parts[1];
    }

    true
}

/// Simple semantic version comparison returning -1, 0, or 1.
///
/// Compares version strings by splitting on '.' and comparing each numeric segment.
fn compare_versions(a: &str, b: &str) -> i32 {
    fn parse_segment(s: &str) -> u64 {
        let digits: String = s
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().unwrap_or(0)
    }
    let a_trimmed = a.trim_start_matches(|c: char| !c.is_ascii_digit());
    let b_trimmed = b.trim_start_matches(|c: char| !c.is_ascii_digit());
    let a_parts: Vec<u64> = a_trimmed.split('.').map(parse_segment).collect();
    let b_parts: Vec<u64> = b_trimmed.split('.').map(parse_segment).collect();

    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_package_name() {
        let f = ComposerFormatter;
        assert_eq!(f.normalize_package_name("Vendor/Package"), "vendor/package");
        assert_eq!(
            f.normalize_package_name("symfony/console"),
            "symfony/console"
        );
    }

    #[test]
    fn test_package_url() {
        let f = ComposerFormatter;
        assert_eq!(
            f.package_url("symfony/console"),
            "https://packagist.org/packages/symfony/console"
        );
    }

    #[test]
    fn test_wildcard() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.2.3", "*"));
        assert!(f.version_satisfies_requirement("99.0.0", "*"));
    }

    #[test]
    fn test_caret_operator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(f.version_satisfies_requirement("1.5.0", "^1.0"));
        assert!(!f.version_satisfies_requirement("2.0.0", "^1.2"));
        assert!(!f.version_satisfies_requirement("0.3.0", "^1.0"));
    }

    #[test]
    fn test_tilde_with_three_segments() {
        let f = ComposerFormatter;
        // ~1.2.3 means >=1.2.3 <1.3.0 (same as npm)
        assert!(f.version_satisfies_requirement("1.2.3", "~1.2.3"));
        assert!(f.version_satisfies_requirement("1.2.9", "~1.2.3"));
        assert!(!f.version_satisfies_requirement("1.3.0", "~1.2.3"));
        assert!(!f.version_satisfies_requirement("1.2.2", "~1.2.3"));
    }

    #[test]
    fn test_tilde_with_two_segments_composer_specific() {
        let f = ComposerFormatter;
        // ~1.2 means >=1.2.0 <2.0.0 (DIFFERENT from npm ~1.2 = >=1.2.0 <1.3.0)
        assert!(f.version_satisfies_requirement("1.2.0", "~1.2"));
        assert!(f.version_satisfies_requirement("1.9.9", "~1.2"));
        assert!(!f.version_satisfies_requirement("2.0.0", "~1.2")); // upper bound is <2.0.0
        assert!(!f.version_satisfies_requirement("1.1.9", "~1.2")); // minor too low
        assert!(!f.version_satisfies_requirement("0.9.0", "~1.2")); // major too low
    }

    #[test]
    fn test_wildcard_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.0.5", "1.0.*"));
        assert!(!f.version_satisfies_requirement("1.1.0", "1.0.*"));
    }

    #[test]
    fn test_or_combinator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.0.0", "1.0.0 || 2.0.0"));
        assert!(f.version_satisfies_requirement("2.0.0", "1.0.0 || 2.0.0"));
        assert!(!f.version_satisfies_requirement("3.0.0", "1.0.0 || 2.0.0"));
    }

    #[test]
    fn test_range_constraint() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", ">=1.0 <2.0"));
        assert!(!f.version_satisfies_requirement("2.0.0", ">=1.0 <2.0"));
        assert!(!f.version_satisfies_requirement("0.9.0", ">=1.0 <2.0"));
    }

    #[test]
    fn test_comparison_operators() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("2.0.0", ">=2.0.0"));
        assert!(f.version_satisfies_requirement("2.0.1", ">=2.0.0"));
        assert!(!f.version_satisfies_requirement("1.9.9", ">=2.0.0"));

        assert!(f.version_satisfies_requirement("1.9.9", "<2.0.0"));
        assert!(!f.version_satisfies_requirement("2.0.0", "<2.0.0"));

        assert!(f.version_satisfies_requirement("1.0.0", "=1.0.0"));
        assert!(!f.version_satisfies_requirement("1.0.1", "=1.0.0"));
    }

    #[test]
    fn test_exact_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.2.3", "1.2.3"));
        assert!(!f.version_satisfies_requirement("1.2.4", "1.2.3"));
    }

    #[test]
    fn test_partial_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement("1.2.3", "1"));
        assert!(f.version_satisfies_requirement("1.2.3", "1.2"));
        assert!(!f.version_satisfies_requirement("2.0.0", "1.2"));
    }
}
