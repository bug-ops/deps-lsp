//! Human-readable table output (FR-006): findings grouped by file, then severity.

use super::severity_str;
use crate::report::CheckReport;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use tower_lsp_server::ls_types::DiagnosticSeverity;

/// Renders `report` as a table grouped by manifest path, then by severity
/// (error > warning > information > hint) within each file.
///
/// # Examples
///
/// ```
/// use deps_cli::format::table::render;
/// use deps_cli::report::CheckReport;
///
/// assert_eq!(render(&CheckReport::default()), "No findings.\n");
/// ```
#[must_use]
pub fn render(report: &CheckReport) -> String {
    if report.findings.is_empty() {
        return "No findings.\n".to_string();
    }

    let mut by_file: BTreeMap<&std::path::Path, Vec<&crate::report::CheckFinding>> =
        BTreeMap::new();
    for finding in &report.findings {
        by_file
            .entry(finding.manifest_path.as_path())
            .or_default()
            .push(finding);
    }

    let mut out = String::new();
    for (path, mut findings) in by_file {
        findings.sort_by_key(|f| {
            (
                severity_rank(f.severity),
                f.range.start.line,
                f.range.start.character,
            )
        });
        let _ = writeln!(out, "{}", path.display());
        for finding in findings {
            let dependency = finding.dependency_name.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "  [{}] {}:{} {} ({}) — {}",
                severity_str(finding.severity),
                finding.range.start.line + 1,
                finding.range.start.character + 1,
                dependency,
                finding.category,
                finding.message,
            );
        }
    }

    let summary = report.summary();
    let _ = writeln!(out);
    let _ = write!(out, "Summary:");
    for (category, count) in &summary {
        let _ = write!(out, " {category}={count}");
    }
    let _ = writeln!(out);

    out
}

/// Sort key for severity within one file's findings — error first, hint last.
fn severity_rank(severity: DiagnosticSeverity) -> u8 {
    match severity {
        DiagnosticSeverity::ERROR => 0,
        DiagnosticSeverity::WARNING => 1,
        DiagnosticSeverity::INFORMATION => 2,
        DiagnosticSeverity::HINT => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use std::path::PathBuf;
    use tower_lsp_server::ls_types::{Position, Range};

    fn finding(path: &str, category: Category, severity: DiagnosticSeverity) -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from(path),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            category,
            severity,
            range: Range::new(Position::new(4, 0), Position::new(4, 10)),
            message: "Newer version available: 1.1.0".to_string(),
        }
    }

    #[test]
    fn test_render_empty_report() {
        assert_eq!(render(&CheckReport::default()), "No findings.\n");
    }

    #[test]
    fn test_render_single_finding_includes_path_and_message() {
        let report = CheckReport {
            findings: vec![finding(
                "Cargo.toml",
                Category::Outdated,
                DiagnosticSeverity::HINT,
            )],
        };
        let table = render(&report);
        assert!(table.contains("Cargo.toml"));
        assert!(table.contains("serde"));
        assert!(table.contains("outdated"));
        assert!(table.contains("Newer version available"));
        assert!(table.contains("Summary:"));
        assert!(table.contains("outdated=1"));
    }

    #[test]
    fn test_render_groups_findings_by_file() {
        let report = CheckReport {
            findings: vec![
                finding("Cargo.toml", Category::Outdated, DiagnosticSeverity::HINT),
                finding(
                    "package.json",
                    Category::Vulnerable,
                    DiagnosticSeverity::ERROR,
                ),
            ],
        };
        let table = render(&report);
        let cargo_pos = table.find("Cargo.toml").expect("Cargo.toml present");
        let npm_pos = table.find("package.json").expect("package.json present");
        assert!(
            cargo_pos < npm_pos,
            "files must be grouped, Cargo.toml sorts first"
        );
    }

    #[test]
    fn test_render_sorts_by_severity_within_a_file() {
        let report = CheckReport {
            findings: vec![
                finding("Cargo.toml", Category::Outdated, DiagnosticSeverity::HINT),
                finding(
                    "Cargo.toml",
                    Category::Vulnerable,
                    DiagnosticSeverity::ERROR,
                ),
            ],
        };
        let table = render(&report);
        let error_pos = table.find("[error]").expect("error entry present");
        let hint_pos = table.find("[hint]").expect("hint entry present");
        assert!(error_pos < hint_pos, "error severity must sort before hint");
    }

    /// Snapshot test (S5, spec 062 review) covering multiple files, categories, and
    /// severities in one report — pins the exact rendered layout so a formatting
    /// regression (stray whitespace, column reordering, ordering change) shows up as a
    /// snapshot diff instead of silently passing a `.contains()`-only assertion.
    #[test]
    fn test_render_multi_category_snapshot() {
        let mut vulnerable = finding(
            "Cargo.toml",
            Category::Vulnerable,
            DiagnosticSeverity::ERROR,
        );
        vulnerable.message = "GHSA-xxxx-yyyy-zzzz: example advisory".to_string();
        let mut license = finding(
            "package.json",
            Category::License,
            DiagnosticSeverity::WARNING,
        );
        license.dependency_name = Some("left-pad".to_string());
        license.message = "left-pad: GPL-3.0 denied".to_string();

        let report = CheckReport {
            findings: vec![
                finding("Cargo.toml", Category::Outdated, DiagnosticSeverity::HINT),
                vulnerable,
                license,
            ],
        };
        insta::assert_snapshot!(render(&report));
    }
}
