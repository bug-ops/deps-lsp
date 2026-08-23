use deps_core::InvalidPackageName;
use deps_core::lsp_helpers::EcosystemFormatter;

/// Maximum name length npm's registry accepts.
///
/// npm counts UTF-16 code units; this counts Unicode scalar values
/// (`str::chars().count()`) instead, which undercounts names containing
/// characters outside the Basic Multilingual Plane. Still strictly more
/// accurate than a byte-length check for the common case of non-ASCII names
/// within the BMP.
const MAX_NAME_LENGTH: usize = 214;

/// Names npm's own validator hard-rejects regardless of character content.
const BLOCKED_NAMES: [&str; 2] = ["node_modules", "favicon.ico"];

/// Reports whether every character of `segment` is in npm's unreserved set —
/// the set `encodeURIComponent` leaves untouched (`A-Za-z0-9` plus
/// `! ' ( ) * - . _ ~`). This mirrors npm's actual
/// `encodeURIComponent(segment) === segment` check: any other ASCII
/// punctuation or any non-ASCII character fails it.
fn is_url_friendly_segment(segment: &str) -> bool {
    segment.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '!' | '\'' | '(' | ')' | '*' | '-' | '.' | '_' | '~')
    })
}

pub struct NpmFormatter;

impl EcosystemFormatter for NpmFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        crate::registry::package_url(name)
    }

    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }

    /// Lints `name` against npm's own `validate-npm-package-name` rules.
    ///
    /// Deliberately permissive beyond what npm hard-rejects: uppercase letters are
    /// allowed (npm only warns for legacy packages, never rejects), and any
    /// character in npm's unreserved set (`! ' ( ) * - . _ ~` plus alphanumerics)
    /// is accepted, matching npm's `encodeURIComponent(name) === name` check
    /// exactly rather than an approximation of it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, exceeds 214 characters,
    /// starts with `.` or `_`, is a reserved name (`node_modules`, `favicon.ico`),
    /// has a malformed `@scope/name` structure, or contains a character outside
    /// npm's unreserved set.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(InvalidPackageName::new(format!(
                "name cannot exceed {MAX_NAME_LENGTH} characters"
            )));
        }
        if name.starts_with('.') {
            return Err(InvalidPackageName::new("name cannot start with a period"));
        }
        if name.starts_with('_') {
            return Err(InvalidPackageName::new(
                "name cannot start with an underscore",
            ));
        }
        if BLOCKED_NAMES
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
        {
            return Err(InvalidPackageName::new(format!(
                "'{name}' is a reserved name"
            )));
        }

        // Scoped names are `@scope/name`; anything else with a '/' is invalid.
        let (scope, pkg_name) = match name.split_once('/') {
            Some((scope, pkg_name)) => {
                let Some(scope) = scope.strip_prefix('@') else {
                    return Err(InvalidPackageName::new("unscoped name cannot contain '/'"));
                };
                (Some(scope), pkg_name)
            }
            None => (None, name),
        };

        if let Some(scope) = scope {
            if scope.is_empty() {
                return Err(InvalidPackageName::new("scope cannot be empty"));
            }
            if !is_url_friendly_segment(scope) {
                return Err(InvalidPackageName::new(
                    "scope contains characters that are not URL-friendly",
                ));
            }
        }

        if pkg_name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if pkg_name.contains('/') {
            return Err(InvalidPackageName::new(
                "name cannot contain more than one '/'",
            ));
        }
        if !is_url_friendly_segment(pkg_name) {
            return Err(InvalidPackageName::new(
                "name contains characters that are not URL-friendly",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_package_name_accepts_hostile_but_legitimate_names() {
        let formatter = NpmFormatter;
        let long_but_valid = "a".repeat(214);

        for name in [
            "@types/node",
            "@scope/_private",
            "@scope/.config",
            "lodash.debounce",
            "c8",
            "-",
            "a",
            long_but_valid.as_str(),
            "MyLegacyPackage",
        ] {
            assert!(
                formatter.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let formatter = NpmFormatter;
        let too_long = "a".repeat(215);

        for name in [
            "",
            "node_modules",
            "NODE_MODULES",
            "favicon.ico",
            "foo/bar",
            "a\\b",
            ".hidden",
            "_private",
            too_long.as_str(),
            "@scope",
            "@/pkg",
            "@scope/",
            "@scope/pkg/extra",
        ] {
            assert!(
                formatter.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_package_name_does_not_reject_star() {
        // npm's encodeURIComponent leaves `!'()*-._~` untouched, so `*` is a
        // legitimate (if unusual) character in a package name.
        let formatter = NpmFormatter;
        assert!(formatter.validate_package_name("weird*name").is_ok());
    }

    #[test]
    fn test_validate_package_name_rejects_disallowed_char_inside_scope() {
        // Structurally well-formed `@scope/name` (single '/', both segments
        // non-empty), but the scope segment itself contains a space, which is
        // outside npm's unreserved character set.
        let formatter = NpmFormatter;
        assert!(
            formatter
                .validate_package_name("@sco pe/valid-pkg")
                .is_err()
        );
    }

    #[test]
    fn test_validate_package_name_rejects_disallowed_char_inside_name_with_valid_scope() {
        // Same, but the disallowed character is in the name segment while the
        // scope is well-formed — the asymmetric case in the other direction.
        let formatter = NpmFormatter;
        assert!(
            formatter
                .validate_package_name("@valid-scope/pkg name")
                .is_err()
        );
    }

    #[test]
    fn test_format_version() {
        let formatter = NpmFormatter;
        // Version should not include quotes - parser's version_range excludes them
        assert_eq!(formatter.format_version_for_text_edit("1.0.214"), "1.0.214");
        assert_eq!(formatter.format_version_for_text_edit("18.3.1"), "18.3.1");
    }

    #[test]
    fn test_package_url() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.package_url("react"),
            "https://www.npmjs.com/package/react"
        );
        assert_eq!(
            formatter.package_url("@types/node"),
            "https://www.npmjs.com/package/@types/node"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.normalize_package_name("react"), "react");
        assert_eq!(
            formatter.normalize_package_name("@types/node"),
            "@types/node"
        );
    }

    #[test]
    fn test_deprecated_messages() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.yanked_message(), "This version is deprecated");
        assert_eq!(formatter.yanked_label(), "*(deprecated)*");
    }

    #[test]
    fn test_version_satisfies_requirement() {
        let formatter = NpmFormatter;

        // Exact match
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));

        // Partial versions
        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        // Caret - allows any version with same major (for major > 0)
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.0"));
        assert!(formatter.version_satisfies_requirement("1.5.0", "^1.2.3"));
        assert!(formatter.version_satisfies_requirement("10.1.3", "^10.1.3")); // Same version
        assert!(formatter.version_satisfies_requirement("10.2.0", "^10.1.3")); // Higher minor

        // Tilde - allows patch changes
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.5", "~1.2"));

        // Should not match
        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
        assert!(!formatter.version_satisfies_requirement("2.0.0", "^1.2.3")); // Different major
    }
}
