//! Derives [`VulnSeverity`] from a raw OSV record, and maps it to
//! [`DiagnosticSeverity`].
//!
//! See `architecture.md` §6 for the precedence rules and the rationale for
//! capping at `WARNING` rather than `ERROR`.

use tower_lsp_server::ls_types::DiagnosticSeverity;

use super::types::{OsvAffected, VulnSeverity};

/// Parses an OSV severity label (`database_specific.severity` or
/// `ecosystem_specific.severity`) case-insensitively.
fn parse_severity_label(s: &str) -> Option<VulnSeverity> {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(VulnSeverity::Critical),
        "HIGH" => Some(VulnSeverity::High),
        "MODERATE" | "MEDIUM" => Some(VulnSeverity::Medium),
        "LOW" => Some(VulnSeverity::Low),
        _ => None,
    }
}

fn severity_from_json(value: &serde_json::Value) -> Option<VulnSeverity> {
    value
        .get("severity")?
        .as_str()
        .and_then(parse_severity_label)
}

/// Classifies a record's severity, first hit wins:
///
/// 1. `database_specific.severity` (GHSA-sourced records carry this).
/// 2. `relevant_affected[].ecosystem_specific.severity` (some RUSTSEC records).
/// 3. [`VulnSeverity::Unknown`].
///
/// `relevant_affected` must already be filtered to the entries describing
/// the package actually queried (`OsvVulnRecord::into_advisory`) — an
/// unfiltered record can cover several unrelated packages sharing one
/// advisory id, and this must never pick up a stranger's `ecosystem_specific`
/// severity.
pub(super) fn classify(
    database_specific: Option<&serde_json::Value>,
    relevant_affected: &[&OsvAffected],
) -> VulnSeverity {
    if let Some(v) = database_specific.and_then(severity_from_json) {
        return v;
    }

    for affected in relevant_affected {
        if let Some(v) = affected
            .ecosystem_specific
            .as_ref()
            .and_then(severity_from_json)
        {
            return v;
        }
    }

    VulnSeverity::Unknown
}

/// Maps a [`VulnSeverity`] to the [`DiagnosticSeverity`] used to render it.
///
/// `Critical`/`High` and `Unknown` cap at `WARNING` rather than `ERROR`:
/// `ERROR` conventionally means "this file is broken", and a valid manifest
/// declaring a real-but-vulnerable dependency is not a parse error.
/// `Unknown -> WARNING` (not `HINT`) reflects that a record this could not
/// grade is not evidence of low risk.
///
/// # Examples
///
/// ```
/// // `severity` is a private module; this function is re-exported publicly
/// // as `deps_core::osv::diagnostic_severity_for`.
/// use deps_core::osv::VulnSeverity;
/// use deps_core::osv::diagnostic_severity_for as to_diagnostic_severity;
/// use tower_lsp_server::ls_types::DiagnosticSeverity;
///
/// assert_eq!(to_diagnostic_severity(VulnSeverity::Critical), DiagnosticSeverity::WARNING);
/// assert_eq!(to_diagnostic_severity(VulnSeverity::Low), DiagnosticSeverity::INFORMATION);
/// assert_eq!(to_diagnostic_severity(VulnSeverity::Unknown), DiagnosticSeverity::WARNING);
/// ```
#[must_use]
pub const fn to_diagnostic_severity(severity: VulnSeverity) -> DiagnosticSeverity {
    match severity {
        VulnSeverity::Critical | VulnSeverity::High | VulnSeverity::Unknown => {
            DiagnosticSeverity::WARNING
        }
        VulnSeverity::Medium | VulnSeverity::Low => DiagnosticSeverity::INFORMATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::types::OsvAffected;

    #[test]
    fn database_specific_severity_wins() {
        let json = serde_json::json!({ "severity": "CRITICAL" });
        assert_eq!(classify(Some(&json), &[]), VulnSeverity::Critical);
    }

    #[test]
    fn database_specific_moderate_maps_to_medium() {
        let json = serde_json::json!({ "severity": "MODERATE" });
        assert_eq!(classify(Some(&json), &[]), VulnSeverity::Medium);
    }

    #[test]
    fn falls_back_to_ecosystem_specific_severity() {
        let affected = OsvAffected {
            package: None,
            ecosystem_specific: Some(serde_json::json!({ "severity": "LOW" })),
            ranges: vec![],
        };
        assert_eq!(classify(None, &[&affected]), VulnSeverity::Low);
    }

    #[test]
    fn cvss_vector_only_record_is_unknown() {
        assert_eq!(classify(None, &[]), VulnSeverity::Unknown);
    }

    #[test]
    fn no_severity_at_all_is_unknown() {
        assert_eq!(classify(None, &[]), VulnSeverity::Unknown);
    }

    #[test]
    fn to_diagnostic_severity_mapping() {
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Critical),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::High),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Medium),
            DiagnosticSeverity::INFORMATION
        );
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Low),
            DiagnosticSeverity::INFORMATION
        );
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Unknown),
            DiagnosticSeverity::WARNING
        );
    }
}
