use deps_core::Dependency;
use deps_core::lsp_helpers::EcosystemFormatter;
use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;
use tower_lsp::lsp_types::Position;

pub struct PypiFormatter;

impl EcosystemFormatter for PypiFormatter {
    fn normalize_package_name(&self, name: &str) -> String {
        if !name.chars().any(|c| c.is_uppercase() || c == '-') {
            return name.to_string();
        }
        name.to_lowercase().replace('-', "_")
    }

    fn format_version_for_code_action(&self, version: &str) -> String {
        let next_major = version
            .split('.')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .and_then(|v| v.checked_add(1))
            .unwrap_or(1);

        format!(">={},<{}", version, next_major)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        let Ok(ver) = Version::from_str(version) else {
            return false;
        };

        let Ok(specs) = VersionSpecifiers::from_str(requirement) else {
            return false;
        };

        specs.contains(&ver)
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://pypi.org/project/{}", name)
    }

    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        let name_range = dep.name_range();

        if position.line != name_range.start.line {
            return false;
        }

        let end_char = dep
            .version_range()
            .map(|r| r.end.character)
            .unwrap_or(name_range.end.character);

        let start_char = name_range.start.character.saturating_sub(2);
        let end_char = end_char.saturating_add(2);

        position.character >= start_char && position.character <= end_char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_package_name() {
        let formatter = PypiFormatter;
        assert_eq!(formatter.normalize_package_name("requests"), "requests");
        assert_eq!(
            formatter.normalize_package_name("Django-REST-Framework"),
            "django_rest_framework"
        );
        assert_eq!(formatter.normalize_package_name("My-Package"), "my_package");
    }

    #[test]
    fn test_format_version() {
        let formatter = PypiFormatter;
        assert_eq!(
            formatter.format_version_for_code_action("1.2.3"),
            ">=1.2.3,<2"
        );
        assert_eq!(
            formatter.format_version_for_code_action("2.28.0"),
            ">=2.28.0,<3"
        );
        assert_eq!(
            formatter.format_version_for_code_action("0.1.0"),
            ">=0.1.0,<1"
        );
    }

    #[test]
    fn test_format_version_overflow_protection() {
        let formatter = PypiFormatter;
        // u32::MAX should not overflow, checked_add returns None
        assert_eq!(
            formatter.format_version_for_code_action("4294967295.0.0"),
            ">=4294967295.0.0,<1"
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = PypiFormatter;
        assert_eq!(
            formatter.package_url("requests"),
            "https://pypi.org/project/requests"
        );
        assert_eq!(
            formatter.package_url("django"),
            "https://pypi.org/project/django"
        );
    }

    #[test]
    fn test_version_satisfies_pep440() {
        let formatter = PypiFormatter;

        assert!(formatter.version_satisfies_requirement("1.2.3", ">=1.0,<2"));
        assert!(formatter.version_satisfies_requirement("2.28.0", ">=2.0"));
        assert!(formatter.version_satisfies_requirement("1.0.0", "==1.0.0"));
        assert!(formatter.version_satisfies_requirement("1.2.0", "~=1.2.0"));

        assert!(!formatter.version_satisfies_requirement("2.0.0", ">=1.0,<2"));
        assert!(!formatter.version_satisfies_requirement("0.9.0", ">=1.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_version() {
        let formatter = PypiFormatter;
        assert!(!formatter.version_satisfies_requirement("not-a-version", ">=1.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_specifier() {
        let formatter = PypiFormatter;
        assert!(!formatter.version_satisfies_requirement("1.0.0", "not-a-specifier"));
    }

    #[test]
    fn test_default_yanked_message() {
        let formatter = PypiFormatter;
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_normalize_fast_path() {
        let formatter = PypiFormatter;
        // Already lowercase, no hyphens - should hit fast path
        assert_eq!(formatter.normalize_package_name("requests"), "requests");
        assert_eq!(formatter.normalize_package_name("flask"), "flask");
        assert_eq!(formatter.normalize_package_name("numpy"), "numpy");
    }

    mod is_position_on_dependency_tests {
        use super::*;
        use deps_core::parser::DependencySource;
        use std::any::Any;
        use tower_lsp::lsp_types::Range;

        struct MockDep {
            name_range: Range,
            version_range: Option<Range>,
        }

        impl deps_core::Dependency for MockDep {
            fn name(&self) -> &str {
                "test-package"
            }
            fn name_range(&self) -> Range {
                self.name_range
            }
            fn version_requirement(&self) -> Option<&str> {
                Some(">=1.0")
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> DependencySource {
                DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        #[test]
        fn test_position_on_name() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position on package name
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 15)));
        }

        #[test]
        fn test_position_in_padding_before() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position in padding before name (character - 2)
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 8)));
        }

        #[test]
        fn test_position_after_version_padding() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position after version range (character + 2)
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 37)));
        }

        #[test]
        fn test_position_too_far_before() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position too far before (outside padding)
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 5)));
        }

        #[test]
        fn test_position_too_far_after() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Position too far after (outside padding)
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 40)));
        }

        #[test]
        fn test_position_different_line() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: Some(Range::new(Position::new(5, 25), Position::new(5, 35))),
            };
            // Different line
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(4, 15)));
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(6, 15)));
        }

        #[test]
        fn test_position_without_version_range() {
            let formatter = PypiFormatter;
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 10), Position::new(5, 20)),
                version_range: None,
            };
            // Should use name_range.end for calculation
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 22)));
            assert!(!formatter.is_position_on_dependency(&dep, Position::new(5, 25)));
        }

        #[test]
        fn test_saturating_sub_at_column_zero() {
            let formatter = PypiFormatter;
            // Edge case: character 0 with saturating_sub(2)
            let dep = MockDep {
                name_range: Range::new(Position::new(5, 0), Position::new(5, 10)),
                version_range: None,
            };
            // saturating_sub(2) should give 0, not underflow
            assert!(formatter.is_position_on_dependency(&dep, Position::new(5, 0)));
        }
    }
}
