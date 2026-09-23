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

/// The current `schema_version` [`update_to_document`] emits.
pub const UPDATE_SCHEMA_VERSION: u32 = 1;

/// Top-level JSON document shape for an `update` run (FR-021).
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct UpdateReportDocument {
    /// The schema version this document was produced under.
    pub schema_version: u32,
    /// Whether `--dry-run` was passed — when `true`, every `"applied"` item's edit was
    /// planned but **not** written to disk (critic finding M1/US-005: without this marker,
    /// a `--dry-run` document is indistinguishable from a real run that wrote its edits).
    pub dry_run: bool,
    /// One entry per candidate dependency the planner considered.
    pub items: Vec<UpdateItemDocument>,
}

/// One `update` plan item's JSON shape.
#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct UpdateItemDocument {
    /// The dependency's declared (raw) name.
    pub name: String,
    /// The current (resolved in-use, or declared) version.
    pub current: String,
    /// The version this item's edit would move the dependency to, when applicable.
    pub target: String,
    /// One of `applied` / `skipped` / `requires-lockfile-update` / `unfixable`.
    pub outcome: String,
    /// A one-line human-readable reason for `outcome`.
    pub reason: String,
    /// OSV advisory ids this item resolves — non-empty only in `--security-only` mode.
    pub advisory_ids: Vec<String>,
}

/// Builds the versioned [`UpdateReportDocument`] for `plan`.
///
/// # Examples
///
/// ```
/// use deps_cli::format::json::{UPDATE_SCHEMA_VERSION, update_to_document};
/// use deps_cli::update::UpdatePlan;
///
/// let document = update_to_document(&UpdatePlan::default(), false);
/// assert_eq!(document.schema_version, UPDATE_SCHEMA_VERSION);
/// assert!(!document.dry_run);
/// assert!(document.items.is_empty());
/// ```
#[must_use]
pub fn update_to_document(plan: &crate::update::UpdatePlan, dry_run: bool) -> UpdateReportDocument {
    // Security-S3: same sanitizer `format::table::render_update` routes `name`/`current`
    // through — a JSON consumer that prints these fields verbatim gets the same protection.
    let items = plan
        .items
        .iter()
        .map(|item| UpdateItemDocument {
            name: crate::sanitize::sanitize_message_for_display(&item.name),
            current: crate::sanitize::sanitize_message_for_display(&item.current),
            target: item.target.clone(),
            outcome: item.outcome.wire_token().to_string(),
            reason: item.reason(),
            advisory_ids: item.advisory_ids.clone(),
        })
        .collect();

    UpdateReportDocument {
        schema_version: UPDATE_SCHEMA_VERSION,
        dry_run,
        items,
    }
}

/// Renders `plan` as a pretty-printed JSON string.
///
/// # Errors
///
/// Returns an error only if [`UpdateReportDocument`]'s `Serialize` impl fails, which does not
/// happen for the plain-data shape this module builds.
pub fn render_update(
    plan: &crate::update::UpdatePlan,
    dry_run: bool,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&update_to_document(plan, dry_run))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use deps_core::diagnostic::Severity;
    use deps_core::position::{Position, Range};
    use std::path::PathBuf;

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
            severity: Severity::Hint,
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
        other.severity = Severity::Error;
        other.manifest_path = PathBuf::from("package.json");
        other.dependency_name = None;
        other.requirement = None;
        other.message = "GHSA-xxxx-yyyy-zzzz: example advisory".to_string();

        let document = to_document(&CheckReport {
            findings: vec![finding(), other],
        });
        insta::assert_json_snapshot!(document);
    }

    fn update_item(outcome: crate::update::Outcome) -> crate::update::PlannedUpdateItem {
        crate::update::PlannedUpdateItem {
            name: "serde".to_string(),
            current: "1.0.0".to_string(),
            target: "1.2.0".to_string(),
            outcome,
            advisory_ids: vec!["RUSTSEC-2024-0001".to_string()],
            ignore_rule_overridden: false,
        }
    }

    fn applied_edit() -> deps_core::edit::ManifestEdit {
        deps_core::edit::ManifestEdit {
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            new_text: "1.2.0".to_string(),
        }
    }

    /// S5: `update_to_document` on a non-empty plan — every field (including the `dry_run`
    /// marker and advisory ids) must survive into the document, not just the empty-plan
    /// doctest's shape.
    #[test]
    fn test_update_to_document_non_empty_plan_maps_every_field() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(crate::update::Outcome::Applied(applied_edit()))],
        };
        let document = update_to_document(&plan, true);
        assert_eq!(document.schema_version, UPDATE_SCHEMA_VERSION);
        assert!(document.dry_run);
        assert_eq!(document.items.len(), 1);
        let item = &document.items[0];
        assert_eq!(item.name, "serde");
        assert_eq!(item.current, "1.0.0");
        assert_eq!(item.target, "1.2.0");
        assert_eq!(item.outcome, "applied");
        assert_eq!(item.advisory_ids, vec!["RUSTSEC-2024-0001".to_string()]);
    }

    #[test]
    fn test_render_update_non_empty_plan_round_trips_through_serde_json() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(crate::update::Outcome::Applied(applied_edit()))],
        };
        let rendered = render_update(&plan, false).expect("render must succeed");
        let parsed: UpdateReportDocument =
            serde_json::from_str(&rendered).expect("must round-trip");
        assert_eq!(parsed, update_to_document(&plan, false));
    }
}
