//! Output formatters for a [`crate::report::CheckReport`] (FR-006, FR-007).

pub mod json;
pub mod sarif;
pub mod table;

/// Whether an `update` run only previewed its plan without writing any change to disk.
///
/// Shared by [`json::render_update`]/[`json::update_to_document`] and [`table::render_update`]
/// so `--dry-run` cannot be transposed with another positional flag at either call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DryRun {
    /// `--dry-run` was passed: the plan was computed but never written to disk.
    Yes,
    /// A real run: applied edits were written to disk.
    No,
}

impl DryRun {
    /// Builds a `DryRun` from the `--dry-run` CLI flag (`true` means [`Self::Yes`]).
    ///
    /// The single, explicitly named conversion point from that boundary's `bool`
    /// representation (issue #1436 S1) — deliberately not a `From<bool>` impl; see
    /// `deps_core::cache::NetworkMode::from_offline_flag`'s doc for why an ambient blanket
    /// impl defeats the point of typing this API.
    #[must_use]
    pub fn from_flag(dry_run: bool) -> Self {
        if dry_run { Self::Yes } else { Self::No }
    }
}

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
