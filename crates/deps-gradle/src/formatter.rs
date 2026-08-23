//! Version formatting for Gradle ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;

pub struct GradleFormatter;

impl EcosystemFormatter for GradleFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        deps_maven::registry::package_url(name)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // Unresolved Gradle variable reference (`$var` or `${var}`) — skip comparison
        if requirement.contains('$') {
            return true;
        }
        if requirement == "latest" || requirement.starts_with("latest.") {
            return true;
        }
        if let Some(prefix) = requirement.strip_suffix('+') {
            return version == prefix.trim_end_matches('.') || version.starts_with(prefix);
        }
        // `]` is included alongside `[`/`(` because Gradle's reversed-bracket exclusive
        // notation (`]1.2,1.5]`) is a leading delimiter in its own right, not just a
        // trailing one.
        if requirement.starts_with(['[', '(', ']']) {
            return crate::range::satisfies(version, requirement);
        }
        version == requirement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = GradleFormatter;
        assert_eq!(f.format_version_for_text_edit("3.2.0"), "3.2.0");
        assert_eq!(
            f.format_version_for_text_edit("1.0.0-SNAPSHOT"),
            "1.0.0-SNAPSHOT"
        );
    }

    #[test]
    fn test_package_url() {
        let f = GradleFormatter;
        assert_eq!(
            f.package_url("org.springframework.boot:spring-boot-starter"),
            "https://central.sonatype.com/artifact/org.springframework.boot/spring-boot-starter"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.2.0", "3.2.0"));
        assert!(!f.version_satisfies_requirement("3.2.0", "3.1.0"));
        assert!(!f.version_satisfies_requirement("3.2.0", "3.2.1"));
    }

    #[test]
    fn test_version_satisfies_dynamic_prefix() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("1.0.5", "1.0.+"));
        assert!(f.version_satisfies_requirement("1.0", "1.0.+"));
        assert!(!f.version_satisfies_requirement("1.1.0", "1.0.+"));
        // Prefix boundary: "2.10.+" must not false-match "2.1.5" via a naive
        // non-dot-anchored prefix check.
        assert!(!f.version_satisfies_requirement("2.1.5", "2.10.+"));
        assert!(f.version_satisfies_requirement("2.10.5", "2.10.+"));
    }

    #[test]
    fn test_version_satisfies_latest_selector() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.2.0", "latest.release"));
        assert!(f.version_satisfies_requirement("3.2.0-SNAPSHOT", "latest.integration"));
    }

    #[test]
    fn test_version_satisfies_range() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", "[1.0,2.0)"));
        assert!(!f.version_satisfies_requirement("2.0.0", "[1.0,2.0)"));
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_reversed_bracket_range() {
        let f = GradleFormatter;
        // `implementation 'com.google.guava:guava:[30.0,31.0['` — Gradle's documented
        // exclusive-upper-bound notation, leading with `[` but trailing with `[` instead of
        // `)`/`]`.
        assert!(f.version_satisfies_requirement("30.5", "[30.0,31.0["));
        assert!(!f.version_satisfies_requirement("31.0", "[30.0,31.0["));
        // Exclusive-lower-bound notation, which leads with `]` rather than `[`/`(`.
        assert!(!f.version_satisfies_requirement("1.2", "]1.2,1.5]"));
        assert!(f.version_satisfies_requirement("1.3", "]1.2,1.5]"));
    }

    #[test]
    fn test_version_satisfies_unresolved_bare_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "$someVersion"));
    }

    #[test]
    fn test_version_satisfies_unresolved_braced_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "${someVersion}"));
    }

    #[test]
    fn test_version_satisfies_unresolved_compound_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "1.0.0-$suffix"));
    }

    #[test]
    fn test_normalize_is_identity() {
        let f = GradleFormatter;
        assert_eq!(
            f.normalize_package_name("com.google.guava:guava"),
            "com.google.guava:guava"
        );
    }
}
