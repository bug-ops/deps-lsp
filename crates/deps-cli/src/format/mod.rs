//! Output formatters for a [`crate::report::CheckReport`] (FR-006, FR-007).

pub mod json;
pub mod sarif;
pub mod table;

/// Renders `severity` as the lowercase token used by both output formats.
#[must_use]
pub fn severity_str(severity: deps_core::diagnostic::Severity) -> &'static str {
    use deps_core::diagnostic::Severity;
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Information => "information",
        Severity::Hint => "hint",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::diagnostic::Severity;

    #[test]
    fn test_severity_str_covers_every_lsp_severity() {
        assert_eq!(severity_str(Severity::Error), "error");
        assert_eq!(severity_str(Severity::Warning), "warning");
        assert_eq!(severity_str(Severity::Information), "information");
        assert_eq!(severity_str(Severity::Hint), "hint");
    }
}
