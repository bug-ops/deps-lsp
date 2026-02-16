//! Version formatting for Dart ecosystem.

use crate::version::version_matches_constraint;
use deps_core::lsp_helpers::EcosystemFormatter;

pub struct DartFormatter;

impl EcosystemFormatter for DartFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        format!("^{version}")
    }

    fn package_url(&self, name: &str) -> String {
        crate::registry::package_url(name)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version_matches_constraint(version, requirement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = DartFormatter;
        assert_eq!(f.format_version_for_code_action("1.0.0"), "^1.0.0");
        assert_eq!(f.format_version_for_code_action("6.1.2"), "^6.1.2");
    }

    #[test]
    fn test_package_url() {
        let f = DartFormatter;
        assert_eq!(
            f.package_url("provider"),
            "https://pub.dev/packages/provider"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let f = DartFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", "^1.0.0"));
        assert!(!f.version_satisfies_requirement("2.0.0", "^1.0.0"));
    }

    #[test]
    fn test_normalize_is_identity() {
        let f = DartFormatter;
        assert_eq!(f.normalize_package_name("flutter_bloc"), "flutter_bloc");
    }
}
