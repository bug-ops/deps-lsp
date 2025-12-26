use deps_core::lsp_helpers::EcosystemFormatter;

pub struct CargoFormatter;

impl EcosystemFormatter for CargoFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        format!("\"{version}\"")
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://crates.io/crates/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.format_version_for_code_action("1.0.214"),
            "\"1.0.214\""
        );
        assert_eq!(
            formatter.format_version_for_code_action("0.1.0"),
            "\"0.1.0\""
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.package_url("serde"),
            "https://crates.io/crates/serde"
        );
        assert_eq!(
            formatter.package_url("tokio-util"),
            "https://crates.io/crates/tokio-util"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = CargoFormatter;
        assert_eq!(formatter.normalize_package_name("serde"), "serde");
        assert_eq!(formatter.normalize_package_name("tokio-util"), "tokio-util");
    }

    #[test]
    fn test_default_yanked_message() {
        let formatter = CargoFormatter;
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_version_satisfies_requirement() {
        let formatter = CargoFormatter;

        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
    }
}
