//! Human-readable table output (FR-006): findings grouped by file, then severity.

use super::{DryRun, severity_str};
use crate::report::CheckReport;
use std::collections::BTreeMap;
use std::fmt::Write as _;

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
        // `Severity`'s own `Ord` (declaration order: `Error` most severe, `Hint` least)
        // sorts error-first for free — issue #1532 code-review finding 1: this used to be a
        // hand-rolled rank function that had drifted out of sync with an oppositely-signed
        // one in `deps-core`.
        findings.sort_by_key(|f| (f.severity, f.range.start.line, f.range.start.character));
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

/// Renders an `update` run's plan: one line per item (name, current, target, outcome,
/// reason), following `render`'s table style.
///
/// `dry_run` prints a leading note so an `applied` line is never confused with an edit that
/// was actually written (critic finding M1/US-005 — mirrors
/// `format::json::render_update`'s `dry_run` field, which is likewise emitted unconditionally
/// regardless of item count — code review finding 3: this note used to be skipped for an
/// empty plan, so `--dry-run --format table` on an empty plan was indistinguishable from a
/// real run, unlike the json format's always-present `dry_run` field).
///
/// # Examples
///
/// ```
/// use deps_cli::format::DryRun;
/// use deps_cli::format::table::render_update;
/// use deps_cli::update::UpdatePlan;
///
/// assert_eq!(
///     render_update(&UpdatePlan::default(), DryRun::No),
///     "No eligible updates.\n"
/// );
/// assert_eq!(
///     render_update(&UpdatePlan::default(), DryRun::Yes),
///     "(dry run — no changes written)\nNo eligible updates.\n"
/// );
/// ```
#[must_use]
pub fn render_update(plan: &crate::update::UpdatePlan, dry_run: DryRun) -> String {
    let mut out = String::new();
    if dry_run == DryRun::Yes {
        let _ = writeln!(out, "(dry run — no changes written)");
    }
    if plan.items.is_empty() {
        out.push_str("No eligible updates.\n");
        return out;
    }

    for item in &plan.items {
        // Security-S3: `target`/`reason()` carry unvalidated `ConcreteVersion` text, sanitized
        // like `name`/`current` below; only `None` means "no target".
        let target = item.target().map_or_else(
            || "-".to_string(),
            |v| crate::sanitize::sanitize_message_for_display(v.as_str()),
        );
        let _ = writeln!(
            out,
            "[{}] {} {} -> {} — {}",
            item.outcome.wire_token(),
            crate::sanitize::sanitize_message_for_display(&item.name),
            crate::sanitize::sanitize_message_for_display(&item.current.render_text()),
            target,
            crate::sanitize::sanitize_message_for_display(&item.reason()),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use deps_core::diagnostic::Severity;
    use deps_core::position::{Position, Range};
    use std::path::PathBuf;

    fn finding(path: &str, category: Category, severity: Severity) -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from(path),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            category,
            code: None,
            advisory_url: None,
            advisory: None,
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
            findings: vec![finding("Cargo.toml", Category::Outdated, Severity::Hint)],
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
                finding("Cargo.toml", Category::Outdated, Severity::Hint),
                finding("package.json", Category::Vulnerable, Severity::Error),
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
                finding("Cargo.toml", Category::Outdated, Severity::Hint),
                finding("Cargo.toml", Category::Vulnerable, Severity::Error),
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
        let mut vulnerable = finding("Cargo.toml", Category::Vulnerable, Severity::Error);
        vulnerable.message = "GHSA-xxxx-yyyy-zzzz: example advisory".to_string();
        let mut license = finding("package.json", Category::License, Severity::Warning);
        license.dependency_name = Some("left-pad".to_string());
        license.message = "left-pad: GPL-3.0 denied".to_string();

        let report = CheckReport {
            findings: vec![
                finding("Cargo.toml", Category::Outdated, Severity::Hint),
                vulnerable,
                license,
            ],
        };
        insta::assert_snapshot!(render(&report));
    }

    fn update_item(outcome: crate::update::Outcome) -> crate::update::PlannedUpdateItem {
        crate::update::PlannedUpdateItem {
            name: "serde".to_string(),
            current: crate::update::CurrentVersion::Resolved(deps_core::ConcreteVersion::from(
                "1.0.0",
            )),
            outcome,
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
            gossip_excluded_version: None,
            cooldown_fallback: None,
        }
    }

    fn applied_edit() -> deps_core::edit::ManifestEdit {
        deps_core::edit::ManifestEdit {
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            new_text: "1.2.0".to_string(),
        }
    }

    fn applied_outcome() -> crate::update::Outcome {
        crate::update::Outcome::Applied {
            edit: applied_edit(),
            target: deps_core::ConcreteVersion::from("1.2.0"),
        }
    }

    /// S5: `render_update` on a non-empty plan — the empty-plan doctest alone never exercised
    /// the per-item line format or the `dry_run` leading note.
    #[test]
    fn test_render_update_non_empty_plan_includes_item_line() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(applied_outcome())],
        };
        let table = render_update(&plan, DryRun::No);
        assert!(table.contains("serde"));
        assert!(table.contains("1.0.0"));
        assert!(table.contains("1.2.0"));
        assert!(table.contains("applied"));
        assert!(!table.contains("dry run"));
    }

    #[test]
    fn test_render_update_dry_run_includes_leading_note() {
        let plan = crate::update::UpdatePlan {
            items: vec![update_item(applied_outcome())],
        };
        let table = render_update(&plan, DryRun::Yes);
        assert!(table.starts_with("(dry run"));
    }

    /// Code review finding 3: an empty plan must still carry the `dry_run` leading note —
    /// otherwise `--dry-run --format table` on an empty plan was indistinguishable from a
    /// real run (`format::json::render_update`'s `dry_run` field never had this gap, since it
    /// is emitted unconditionally regardless of item count).
    #[test]
    fn test_render_update_empty_plan_still_includes_dry_run_note() {
        let table = render_update(&crate::update::UpdatePlan::default(), DryRun::Yes);
        assert!(table.starts_with("(dry run"));
        assert!(table.contains("No eligible updates."));
    }

    /// #1605: `None` is the sole "no target" sentinel now — it still renders as `-`.
    #[test]
    fn test_render_update_none_target_renders_dash() {
        let item = update_item(crate::update::Outcome::Skipped {
            reason: crate::update::SkipReason::NotRequested,
            target: None,
        });
        let plan = crate::update::UpdatePlan { items: vec![item] };
        let table = render_update(&plan, DryRun::No);
        assert!(table.contains(" -> - "), "got: {table}");
    }

    /// #1605 critic S1: `target` and `reason()`'s cooldown-fallback attribution both carry
    /// unvalidated registry text (`ConcreteVersion` is deliberately unchecked) and must both be
    /// sanitized at this render sink.
    #[test]
    fn test_render_update_strips_ansi_from_target_and_reason() {
        let mut item = update_item(crate::update::Outcome::Skipped {
            reason: crate::update::SkipReason::NotSafelyEditable(
                deps_core::edit::UnplannableReason::LatestFlaggedByOsv,
            ),
            target: Some(deps_core::ConcreteVersion::from("1.2.0\x1B[31m")),
        });
        item.cooldown_fallback = Some(crate::update::CooldownFallbackNote::Blocked {
            version: deps_core::ConcreteVersion::from("1.1.0\x1B[31m"),
        });
        let mut applied_instead_of_item = update_item(applied_outcome());
        applied_instead_of_item.cooldown_fallback =
            Some(crate::update::CooldownFallbackNote::AppliedInsteadOf(
                deps_core::ConcreteVersion::from("1.3.0\x1B[31m"),
            ));
        let plan = crate::update::UpdatePlan {
            items: vec![item, applied_instead_of_item],
        };
        let table = render_update(&plan, DryRun::No);
        assert!(!table.contains('\x1B'), "got: {table}");
        assert!(table.contains("1.2.0"), "got: {table}");
        assert!(table.contains("1.1.0"), "got: {table}");
        assert!(table.contains("1.3.0"), "got: {table}");
    }
}
