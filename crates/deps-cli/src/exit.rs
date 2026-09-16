//! Exit-code mapping (FR-011, FR-012): 0 clean, 1 policy violation, 2 execution error.

use crate::report::{CheckReport, FailOnPolicy};

/// The process exited cleanly: no finding matched the `--fail-on` policy.
pub const EXIT_CLEAN: i32 = 0;
/// At least one finding matched the `--fail-on` policy.
pub const EXIT_POLICY_VIOLATION: i32 = 1;
/// A registry required by a non-offline run was unreachable, or another execution error
/// occurred (a malformed `deps.toml`, an unreadable explicitly-given manifest path, ...).
pub const EXIT_EXECUTION_ERROR: i32 = 2;

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
/// use deps_cli::exit::{EXIT_CLEAN, EXIT_EXECUTION_ERROR, EXIT_POLICY_VIOLATION, exit_code};
/// use deps_cli::report::{CheckReport, FailOnPolicy};
///
/// let clean = CheckReport::default();
/// let policy = FailOnPolicy::default_categories();
/// assert_eq!(exit_code(&clean, &policy, false), EXIT_CLEAN);
/// assert_eq!(exit_code(&clean, &policy, true), EXIT_EXECUTION_ERROR);
/// ```
#[must_use]
pub fn exit_code(report: &CheckReport, policy: &FailOnPolicy, had_execution_error: bool) -> i32 {
    if policy.matches(&report.findings) {
        return EXIT_POLICY_VIOLATION;
    }
    if had_execution_error {
        return EXIT_EXECUTION_ERROR;
    }
    EXIT_CLEAN
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
        assert_eq!(exit_code(&report, &policy, false), EXIT_CLEAN);
    }

    #[test]
    fn test_exit_code_policy_violation_is_one() {
        let report = CheckReport {
            findings: vec![finding(Category::Vulnerable)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(exit_code(&report, &policy, false), EXIT_POLICY_VIOLATION);
    }

    #[test]
    fn test_exit_code_non_failing_category_is_zero() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(exit_code(&report, &policy, false), EXIT_CLEAN);
    }

    #[test]
    fn test_exit_code_execution_error_is_two() {
        let report = CheckReport::default();
        let policy = FailOnPolicy::default_categories();
        assert_eq!(exit_code(&report, &policy, true), EXIT_EXECUTION_ERROR);
    }

    #[test]
    fn test_exit_code_execution_error_takes_precedence_over_clean_policy() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(exit_code(&report, &policy, true), EXIT_EXECUTION_ERROR);
    }

    /// Regression test for S3 (spec 062 review): a real policy violation must win over an
    /// unrelated execution error, not be masked by it.
    #[test]
    fn test_exit_code_policy_violation_takes_precedence_over_execution_error() {
        let report = CheckReport {
            findings: vec![finding(Category::Vulnerable)],
        };
        let policy = FailOnPolicy::default_categories();
        assert_eq!(exit_code(&report, &policy, true), EXIT_POLICY_VIOLATION);
    }
}
