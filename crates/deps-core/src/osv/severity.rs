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
/// 0. `id`, or any entry in `aliases`, carries OSV's `MAL-` prefix ->
///    [`VulnSeverity::Malicious`], taking precedence over every graded signal
///    below. OSV can file one confirmed-malicious-package event under a
///    non-`MAL-` primary id while cross-referencing the canonical `MAL-*` id
///    only via `aliases` — live-verified via `crates.io/rustdecimal`, served
///    as three separate records (`GHSA-7pwq-f4pq-78gm`, `MAL-2022-1`,
///    `RUSTSEC-2022-0042`) that all alias each other, where the `GHSA-`
///    record additionally carries a graded `database_specific.severity` of
///    its own. Checking `id` alone would misclassify the two non-`MAL-`-id
///    records as `Critical`/`Unknown` despite describing the exact same
///    malware. A confirmed-malicious-package record must never be masked by
///    a graded severity value it also happens to carry (FR-004) — this check
///    runs first and returns immediately, so a `MAL-*` id or alias always
///    wins regardless of what `database_specific` or `ecosystem_specific`
///    report.
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
    id: &str,
    aliases: &[String],
    database_specific: Option<&serde_json::Value>,
    relevant_affected: &[&OsvAffected],
) -> VulnSeverity {
    if id.starts_with("MAL-") || aliases.iter().any(|alias| alias.starts_with("MAL-")) {
        return VulnSeverity::Malicious;
    }

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
/// `Critical`/`High`/`Unknown`/`Malicious` all cap at `WARNING` rather than
/// `ERROR`: `ERROR` conventionally means "this file is broken", and a valid
/// manifest declaring a real-but-vulnerable (or even confirmed-malicious)
/// dependency is not a parse error. `Unknown -> WARNING` (not `HINT`)
/// reflects that a record this could not grade is not evidence of low risk.
/// `Malicious` stays at `WARNING` too rather than escalating to `ERROR` — a
/// confirmed-malicious-package finding is distinguished from an ordinary
/// unscored advisory via its message and label instead (see
/// [`crate::lsp_helpers`]'s vulnerability diagnostic and hover rendering),
/// keeping the "ERROR means broken manifest" convention intact.
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
/// assert_eq!(to_diagnostic_severity(VulnSeverity::Malicious), DiagnosticSeverity::WARNING);
/// ```
#[must_use]
pub const fn to_diagnostic_severity(severity: VulnSeverity) -> DiagnosticSeverity {
    match severity {
        VulnSeverity::Critical
        | VulnSeverity::High
        | VulnSeverity::Unknown
        | VulnSeverity::Malicious => DiagnosticSeverity::WARNING,
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
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], Some(&json), &[]),
            VulnSeverity::Critical
        );
    }

    #[test]
    fn database_specific_moderate_maps_to_medium() {
        let json = serde_json::json!({ "severity": "MODERATE" });
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], Some(&json), &[]),
            VulnSeverity::Medium
        );
    }

    #[test]
    fn falls_back_to_ecosystem_specific_severity() {
        let affected = OsvAffected {
            package: None,
            ecosystem_specific: Some(serde_json::json!({ "severity": "LOW" })),
            ranges: vec![],
        };
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], None, &[&affected]),
            VulnSeverity::Low
        );
    }

    #[test]
    fn cvss_vector_only_record_is_unknown() {
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], None, &[]),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn no_severity_at_all_is_unknown() {
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], None, &[]),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn mal_prefix_with_no_severity_fields_is_malicious() {
        // Live-verified shape: OSV's MAL-2025-47141 record for npm
        // `@ctrl/tinycolor` has no severity field anywhere.
        assert_eq!(
            classify("MAL-2025-47141", &[], None, &[]),
            VulnSeverity::Malicious
        );
    }

    #[test]
    fn mal_prefix_wins_over_a_graded_severity_present_on_the_same_record() {
        // FR-004: a record carrying both a MAL- id and a graded severity must
        // still classify as Malicious — the malicious classification is never
        // masked by an unrelated graded value.
        let json = serde_json::json!({ "severity": "CRITICAL" });
        assert_eq!(
            classify("MAL-2025-47141", &[], Some(&json), &[]),
            VulnSeverity::Malicious
        );
    }

    #[test]
    fn mal_alias_without_mal_prefixed_id_is_still_malicious() {
        // S1 (impl-critic): live-verified via crates.io/rustdecimal, OSV
        // serves the same malware event as three separate records that all
        // alias each other. GHSA-7pwq-f4pq-78gm's own id has no MAL- prefix
        // and carries a graded database_specific.severity of HIGH, but one
        // of its aliases is MAL-2022-1 — the alias check must still win over
        // the graded value (FR-004 extends to alias-based detection too).
        let json = serde_json::json!({ "severity": "HIGH" });
        let aliases = ["MAL-2022-1".to_string(), "RUSTSEC-2022-0042".to_string()];
        assert_eq!(
            classify("GHSA-7pwq-f4pq-78gm", &aliases, Some(&json), &[]),
            VulnSeverity::Malicious
        );
    }

    #[test]
    fn rustdecimal_three_alias_group_all_classify_as_malicious() {
        // S1 regression: the full live-verified crates.io/rustdecimal shape —
        // every record in the alias group must classify as Malicious,
        // regardless of which one carries the MAL- id itself.
        let ghsa_aliases = ["MAL-2022-1".to_string(), "RUSTSEC-2022-0042".to_string()];
        let mal_aliases = [
            "GHSA-7pwq-f4pq-78gm".to_string(),
            "RUSTSEC-2022-0042".to_string(),
        ];
        let rustsec_aliases = ["GHSA-7pwq-f4pq-78gm".to_string(), "MAL-2022-1".to_string()];
        let ghsa_severity = serde_json::json!({ "severity": "HIGH" });

        assert_eq!(
            classify(
                "GHSA-7pwq-f4pq-78gm",
                &ghsa_aliases,
                Some(&ghsa_severity),
                &[]
            ),
            VulnSeverity::Malicious
        );
        assert_eq!(
            classify("MAL-2022-1", &mal_aliases, None, &[]),
            VulnSeverity::Malicious
        );
        assert_eq!(
            classify("RUSTSEC-2022-0042", &rustsec_aliases, None, &[]),
            VulnSeverity::Malicious
        );
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
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Malicious),
            DiagnosticSeverity::WARNING
        );
    }
}
