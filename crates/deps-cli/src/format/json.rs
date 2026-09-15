//! Versioned JSON output (FR-007).
//!
//! Schema mirrors `specs/062-cli-check-mode/plan.md` §4 exactly. `schema_version` lets
//! downstream tooling detect a future breaking change to this shape (constitution
//! principle 8) — bump it, and document the bump in `CHANGELOG.md` as `Breaking`, whenever
//! a field is renamed or removed (adding a new optional field is not itself a bump).

use super::severity_str;
use crate::report::CheckReport;
use serde::Serialize;
use std::collections::BTreeMap;

/// The current `schema_version` this module emits and [`ReportDocument`] can deserialize.
pub const SCHEMA_VERSION: u32 = 1;

/// Top-level JSON document shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct ReportDocument {
    /// The schema version this document was produced under.
    pub schema_version: u32,
    /// Every finding, in the order [`CheckReport::findings`] held them.
    pub findings: Vec<FindingDocument>,
    /// Per-category finding counts (FR-009's category tokens as keys).
    pub summary: BTreeMap<String, usize>,
}

/// One finding's JSON shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct FindingDocument {
    /// The ecosystem id (e.g. `"cargo"`).
    pub ecosystem: String,
    /// The manifest path, as reported by [`crate::walk`].
    pub manifest_path: String,
    /// The dependency name, when the finding could be traced to one manifest occurrence.
    pub dependency_name: Option<String>,
    /// The declared version requirement, when known.
    pub requirement: Option<String>,
    /// The FR-009 category token.
    pub category: String,
    /// The lowercase severity token (`error`/`warning`/`information`/`hint`).
    pub severity: String,
    /// The LSP range within the manifest.
    pub range: RangeDocument,
    /// The human-readable finding message.
    pub message: String,
}

/// LSP `Range`'s JSON shape (`{"start": {...}, "end": {...}}`).
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct RangeDocument {
    /// The range's start position.
    pub start: PositionDocument,
    /// The range's end position.
    pub end: PositionDocument,
}

/// LSP `Position`'s JSON shape (`{"line": ..., "character": ...}`), both zero-based.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct PositionDocument {
    /// Zero-based line number.
    pub line: u32,
    /// Zero-based UTF-16 code-unit offset within the line.
    pub character: u32,
}

/// Builds the versioned [`ReportDocument`] for `report`.
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::{SCHEMA_VERSION, to_document};
/// use deps_cli::report::CheckReport;
///
/// let document = to_document(&CheckReport::default());
/// assert_eq!(document.schema_version, SCHEMA_VERSION);
/// assert!(document.findings.is_empty());
/// ```
#[must_use]
pub fn to_document(report: &CheckReport) -> ReportDocument {
    let findings = report
        .findings
        .iter()
        .map(|finding| FindingDocument {
            ecosystem: finding.ecosystem.id().to_string(),
            manifest_path: finding.manifest_path.display().to_string(),
            dependency_name: finding.dependency_name.clone(),
            requirement: finding.requirement.clone(),
            category: finding.category.as_str().to_string(),
            severity: severity_str(finding.severity).to_string(),
            range: RangeDocument {
                start: PositionDocument {
                    line: finding.range.start.line,
                    character: finding.range.start.character,
                },
                end: PositionDocument {
                    line: finding.range.end.line,
                    character: finding.range.end.character,
                },
            },
            message: finding.message.clone(),
        })
        .collect();

    let summary = report
        .summary()
        .into_iter()
        .map(|(category, count)| (category.as_str().to_string(), count))
        .collect();

    ReportDocument {
        schema_version: SCHEMA_VERSION,
        findings,
        summary,
    }
}

/// Renders `report` as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns an error only if [`ReportDocument`]'s `Serialize` impl fails, which does not
/// happen for the plain-data shape this module builds.
pub fn render(report: &CheckReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_document(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use std::path::PathBuf;
    use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};

    fn finding() -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from("Cargo.toml"),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            category: Category::Outdated,
            code: None,
            advisory_url: None,
            advisory_severity: None,
            severity: DiagnosticSeverity::HINT,
            range: Range::new(Position::new(4, 0), Position::new(4, 10)),
            message: "Newer version available: 1.1.0".to_string(),
        }
    }

    #[test]
    fn test_to_document_empty_report() {
        let document = to_document(&CheckReport::default());
        assert_eq!(document.schema_version, SCHEMA_VERSION);
        assert!(document.findings.is_empty());
        assert!(document.summary.is_empty());
    }

    #[test]
    fn test_to_document_maps_finding_fields() {
        let document = to_document(&CheckReport {
            findings: vec![finding()],
        });
        let f = &document.findings[0];
        assert_eq!(f.ecosystem, "cargo");
        assert_eq!(f.manifest_path, "Cargo.toml");
        assert_eq!(f.dependency_name.as_deref(), Some("serde"));
        assert_eq!(f.requirement.as_deref(), Some("1.0"));
        assert_eq!(f.category, "outdated");
        assert_eq!(f.severity, "hint");
        assert_eq!(f.range.start.line, 4);
        assert_eq!(document.summary.get("outdated"), Some(&1));
    }

    #[test]
    fn test_render_round_trips_through_serde_json() {
        let report = CheckReport {
            findings: vec![finding()],
        };
        let rendered = render(&report).expect("render must succeed");
        let parsed: ReportDocument = serde_json::from_str(&rendered).expect("must round-trip");
        assert_eq!(parsed, to_document(&report));
    }

    #[test]
    fn test_render_includes_schema_version_field() {
        let rendered = render(&CheckReport::default()).expect("render must succeed");
        assert!(rendered.contains("\"schema_version\": 1"));
    }

    /// Snapshot test (S5, spec 062 review): pins the exact JSON document shape so a field
    /// rename, key reordering, or nesting change shows up as a snapshot diff — this
    /// document is a stable, versioned public schema (`SCHEMA_VERSION`), not an
    /// implementation detail.
    #[test]
    fn test_to_document_snapshot() {
        let mut other = finding();
        other.category = Category::Vulnerable;
        other.severity = DiagnosticSeverity::ERROR;
        other.manifest_path = PathBuf::from("package.json");
        other.dependency_name = None;
        other.requirement = None;
        other.message = "GHSA-xxxx-yyyy-zzzz: example advisory".to_string();

        let document = to_document(&CheckReport {
            findings: vec![finding(), other],
        });
        insta::assert_json_snapshot!(document);
    }
}
