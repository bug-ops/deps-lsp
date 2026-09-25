//! Exit-code mapping (FR-011, FR-012): 0 clean, 1 policy violation, 2 execution error.

use crate::report::{CheckReport, FailOnPolicy};
use crate::update::{Outcome, SkipReason, UpdatePlan};

/// The process exited cleanly: no finding matched the `--fail-on` policy.
pub const EXIT_CLEAN: i32 = 0;
/// At least one finding matched the `--fail-on` policy.
pub const EXIT_POLICY_VIOLATION: i32 = 1;
/// A registry required by a non-offline run was unreachable, or another execution error
/// occurred (a malformed `deps.toml`, an unreadable explicitly-given manifest path, ...).
pub const EXIT_EXECUTION_ERROR: i32 = 2;

/// Whether a `check` run's execution hit a registry/parse failure independent of any
/// `--fail-on` policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// No execution-level registry/parse failure occurred.
    Clean,
    /// A registry required by a non-offline run was unreachable, or another execution error
    /// occurred (a malformed `deps.toml`, an unreadable explicitly-given manifest path, ...).
    Failed,
}

impl ExecutionOutcome {
    /// Builds an `ExecutionOutcome` from the accumulated execution-error flag (`true` means
    /// [`Self::Failed`]).
    ///
    /// The single, explicitly named conversion point from that boundary's `bool`
    /// representation (issue #1436 S1) — deliberately not a `From<bool>` impl; see
    /// `deps_core::cache::NetworkMode::from_offline_flag`'s doc for why an ambient blanket
    /// impl defeats the point of typing this API.
    #[must_use]
    pub fn from_had_execution_error(had_execution_error: bool) -> Self {
        if had_execution_error {
            Self::Failed
        } else {
            Self::Clean
        }
    }
}

/// Computes the process exit code for a completed `check` run.
///
/// A real policy violation (T021) always reports as `1`, even when `had_execution_error` is
/// also set: a genuine `--fail-on` hit is the more actionable signal, and an unrelated
/// registry/parse error elsewhere in the run must not hide it behind a less specific `2`
/// (spec 062 review S3 — the original precedence order lost this signal, e.g. one malformed
/// manifest anywhere in a monorepo turning a real `--fail-on vulnerable` hit from `1` into
/// `2`). `had_execution_error` only takes precedence over an otherwise-*clean* policy result:
/// a run that could not reach a registry it needed, or failed to parse a manifest, produced
/// an incomplete report, so its exit code must never claim a clean `0`, even when nothing
/// already-resolved happened to violate `policy`.
///
/// # Examples
///
/// ```
/// use deps_cli::exit::{EXIT_CLEAN, EXIT_EXECUTION_ERROR, EXIT_POLICY_VIOLATION, ExecutionOutcome, exit_code};
/// use deps_cli::report::{CheckReport, FailOnPolicy};
///
/// let clean = CheckReport::default();
/// let policy = FailOnPolicy::default_categories();
/// assert_eq!(exit_code(&clean, &policy, ExecutionOutcome::Clean), EXIT_CLEAN);
/// assert_eq!(exit_code(&clean, &policy, ExecutionOutcome::Failed), EXIT_EXECUTION_ERROR);
/// ```
#[must_use]
pub fn exit_code(
    report: &CheckReport,
    policy: &FailOnPolicy,
    had_execution_error: ExecutionOutcome,
) -> i32 {
    if policy.matches(&report.findings) {
        return EXIT_POLICY_VIOLATION;
    }
    if had_execution_error == ExecutionOutcome::Failed {
        return EXIT_EXECUTION_ERROR;
    }
    EXIT_CLEAN
}

/// Computes the process exit code for a completed `update` run (spec §5's exit-code table,
/// as amended by S3 — see below).
///
/// `0` if every item is [`Outcome::Applied`], the plan was empty (nothing eligible), or every
/// non-`Applied` item is a deliberate operator exclusion
/// (<code>[Outcome::Skipped]([SkipReason::NotRequested])</code> — a `--package` narrowing —
/// or <code>[Outcome::Skipped]([SkipReason::IgnoreRule])</code> — a `[update].ignore` match).
/// `1` if at least one item is
/// <code>[Outcome::Skipped]([SkipReason::NotSafelyEditable])</code>,
/// [`Outcome::RequiresLockfileUpdate`], or [`Outcome::Unfixable`] — these represent something
/// the run *wanted* to fix but could not, unlike an operator-requested exclusion. `2`
/// (execution error — parse/write/TOCTOU/symlink/offline-gate failures) is set by the caller
/// before this function is ever reached, never by this function itself (FR-022 — a non-zero
/// exit here never implies the working tree is unmodified: a mixed run can exit `1` with real
/// edits already on disk).
///
/// **S3 amendment**: spec.md's own exit-code table (§5) originally listed *any* skip,
/// including `NotRequested`/`IgnoreRule`, under exit `1` — directly contradicting US-004's
/// stated acceptance criterion ("`tokio` is skipped, reported `skipped (ignore-rule)`, and
/// the run still exits `0` if every other selected dependency was applied"). This function
/// implements US-004's reading: an operator explicitly asking to skip something is not a
/// failure. spec.md §5 and `book/src/cli.md` are updated to match.
///
/// # Examples
///
/// ```
/// use deps_cli::exit::{EXIT_CLEAN, EXIT_POLICY_VIOLATION, update_exit_code};
/// use deps_cli::update::UpdatePlan;
///
/// assert_eq!(update_exit_code(&UpdatePlan::default()), EXIT_CLEAN);
/// ```
#[must_use]
pub fn update_exit_code(plan: &UpdatePlan) -> i32 {
    let has_unresolved_item = plan.items.iter().any(|item| {
        !matches!(
            item.outcome,
            Outcome::Applied(_)
                | Outcome::Skipped(SkipReason::NotRequested | SkipReason::IgnoreRule)
        )
    });
    if has_unresolved_item {
        EXIT_POLICY_VIOLATION
    } else {
        EXIT_CLEAN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, CheckFinding};
    use deps_core::EcosystemId;
    use deps_core::diagnostic::Severity;
    use deps_core::position::Range;
    use std::path::PathBuf;

    fn finding(category: Category) -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from("Cargo.toml"),
            dependency_name: Some("serde".to_string()),
            requirement: None,
            category,
            code: None,
            advisory_url: None,
            advisory_severity: None,
            severity: Severity::Warning,
            range: Range::default(),
            message: "test".to_string(),
        }
    }

    #[test]
    fn test_exit_code_clean_report_is_zero() {
        let report = CheckReport::default();
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Clean),
            EXIT_CLEAN
        );
    }

    #[test]
    fn test_exit_code_policy_violation_is_one() {
        let report = CheckReport {
            findings: vec![finding(Category::Vulnerable)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Clean),
            EXIT_POLICY_VIOLATION
        );
    }

    #[test]
    fn test_exit_code_non_failing_category_is_zero() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Clean),
            EXIT_CLEAN
        );
    }

    #[test]
    fn test_exit_code_execution_error_is_two() {
        let report = CheckReport::default();
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Failed),
            EXIT_EXECUTION_ERROR
        );
    }

    #[test]
    fn test_exit_code_execution_error_takes_precedence_over_clean_policy() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Failed),
            EXIT_EXECUTION_ERROR
        );
    }

    /// Regression test for S3 (spec 062 review): a real policy violation must win over an
    /// unrelated execution error, not be masked by it.
    #[test]
    fn test_exit_code_policy_violation_takes_precedence_over_execution_error() {
        let report = CheckReport {
            findings: vec![finding(Category::Vulnerable)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(
            exit_code(&report, &policy, ExecutionOutcome::Failed),
            EXIT_POLICY_VIOLATION
        );
    }

    // --- update_exit_code (spec 068, S3) ---

    use crate::update::{PlannedUpdateItem, UnfixableReason};
    use deps_core::edit::{ManifestEdit, UnplannableReason};

    fn update_item(outcome: Outcome) -> PlannedUpdateItem {
        PlannedUpdateItem {
            name: "serde".to_string(),
            current: "1.0.0".to_string(),
            target: "1.2.0".to_string(),
            outcome,
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
        }
    }

    fn applied() -> Outcome {
        Outcome::Applied(ManifestEdit {
            range: Range::default(),
            new_text: "1.2.0".to_string(),
        })
    }

    #[test]
    fn test_update_exit_code_empty_plan_is_clean() {
        assert_eq!(update_exit_code(&UpdatePlan::default()), EXIT_CLEAN);
    }

    #[test]
    fn test_update_exit_code_all_applied_is_clean() {
        let plan = UpdatePlan {
            items: vec![update_item(applied()), update_item(applied())],
        };
        assert_eq!(update_exit_code(&plan), EXIT_CLEAN);
    }

    /// US-004: an ignore-rule skip alone must not fail the run.
    #[test]
    fn test_update_exit_code_ignore_rule_skip_alone_is_clean() {
        let plan = UpdatePlan {
            items: vec![
                update_item(applied()),
                update_item(Outcome::Skipped(SkipReason::IgnoreRule)),
            ],
        };
        assert_eq!(update_exit_code(&plan), EXIT_CLEAN);
    }

    /// US-002: a `--package` exclusion alone must not fail the run.
    #[test]
    fn test_update_exit_code_not_requested_skip_alone_is_clean() {
        let plan = UpdatePlan {
            items: vec![
                update_item(applied()),
                update_item(Outcome::Skipped(SkipReason::NotRequested)),
            ],
        };
        assert_eq!(update_exit_code(&plan), EXIT_CLEAN);
    }

    #[test]
    fn test_update_exit_code_not_safely_editable_skip_is_policy_violation() {
        let plan = UpdatePlan {
            items: vec![update_item(Outcome::Skipped(
                SkipReason::NotSafelyEditable(UnplannableReason::NonLiteralSpan),
            ))],
        };
        assert_eq!(update_exit_code(&plan), EXIT_POLICY_VIOLATION);
    }

    #[test]
    fn test_update_exit_code_requires_lockfile_update_is_policy_violation() {
        let plan = UpdatePlan {
            items: vec![update_item(Outcome::RequiresLockfileUpdate)],
        };
        assert_eq!(update_exit_code(&plan), EXIT_POLICY_VIOLATION);
    }

    #[test]
    fn test_update_exit_code_unfixable_is_policy_violation() {
        let plan = UpdatePlan {
            items: vec![update_item(Outcome::Unfixable(
                UnfixableReason::FetchFailedOrAbsent,
            ))],
        };
        assert_eq!(update_exit_code(&plan), EXIT_POLICY_VIOLATION);
    }

    #[test]
    fn test_update_exit_code_mixed_applied_and_operator_skips_is_clean() {
        let plan = UpdatePlan {
            items: vec![
                update_item(applied()),
                update_item(Outcome::Skipped(SkipReason::NotRequested)),
                update_item(Outcome::Skipped(SkipReason::IgnoreRule)),
            ],
        };
        assert_eq!(update_exit_code(&plan), EXIT_CLEAN);
    }
}
