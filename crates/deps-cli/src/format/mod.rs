//! Output formatters for a [`crate::report::CheckReport`] (FR-006, FR-007).

pub mod json;
pub mod table;

/// Renders `severity` as the lowercase token used by both output formats.
#[must_use]
pub fn severity_str(severity: tower_lsp_server::ls_types::DiagnosticSeverity) -> &'static str {
    use tower_lsp_server::ls_types::DiagnosticSeverity;
    match severity {
        DiagnosticSeverity::ERROR => "error",
        DiagnosticSeverity::WARNING => "warning",
        DiagnosticSeverity::INFORMATION => "information",
        DiagnosticSeverity::HINT => "hint",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::DiagnosticSeverity;

    #[test]
    fn test_severity_str_covers_every_lsp_severity() {
        assert_eq!(severity_str(DiagnosticSeverity::ERROR), "error");
        assert_eq!(severity_str(DiagnosticSeverity::WARNING), "warning");
        assert_eq!(severity_str(DiagnosticSeverity::INFORMATION), "information");
        assert_eq!(severity_str(DiagnosticSeverity::HINT), "hint");
    }
}
