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

/// Whether a `database_specific.informational` JSON value should trigger
/// [`VulnSeverity::Informational`] classification, per FR-007 (further
/// narrowed by security finding L1) — an **allowlist** of exactly one value,
/// `"unmaintained"`. Everything else — including RUSTSEC's `"unsound"` (a
/// real memory-safety/UB finding, e.g. live-verified `RUSTSEC-2021-0145`/
/// `atty`, `RUSTSEC-2019-0036`/`failure` — security finding H1) AND
/// RUSTSEC's `"notice"` (live-verified `RUSTSEC-2026-0174`/`http-types`
/// carries `informational: "notice"` while describing a real defect — an
/// incorrect `unsafe` justification for an ASCII-invariant guarantee — the
/// same failure class as H1, just narrower in the live corpus; security
/// finding L1), OSV's `"unknown"` enum value, any unrecognized future
/// value, a missing field, `null`, or an empty/whitespace-only string — is
/// treated as absent, so the record falls through to the existing
/// precedence chain (graded severity, else [`VulnSeverity::Unknown`]/
/// `WARNING`). Defaulting unrecognized values to the safer, more-visible
/// `Unknown` treatment (rather than the less-visible `Informational`) is
/// deliberate: silently downgrading a real finding to a "not a
/// vulnerability" label would be worse than leaving it at today's
/// `Unknown`/`WARNING` bucket.
fn is_informational_value(value: &serde_json::Value) -> bool {
    value
        .get("informational")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s.trim() == "unmaintained")
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
/// 3. `relevant_affected[].database_specific.informational`, if it is one of
///    the allowlisted values (see [`is_informational_value`]) and the entry
///    genuinely describes `osv_name`/`osv_eco` (see below) ->
///    [`VulnSeverity::Informational`].
/// 4. [`VulnSeverity::Unknown`].
///
/// `relevant_affected` must already be filtered to the entries describing
/// the package actually queried (`OsvVulnRecord::into_advisory`) — an
/// unfiltered record can cover several unrelated packages sharing one
/// advisory id, and this must never pick up a stranger's `ecosystem_specific`
/// severity.
///
/// Steps 1-2 run as one pass over `relevant_affected` (first entry with a
/// graded severity wins, unchanged from before this function gained step 3)
/// before step 3 is even considered — never interleaved with it — so an
/// earlier entry's `informational` value can never win over a later entry's
/// graded severity (FR-002a/FR-005).
///
/// Step 3's genuine-match guard is stricter than steps 1-2's: it requires
/// `affected.package` to be `Some` and to equal `osv_name`/`osv_eco`
/// exactly — a `package`-less entry (which steps 1-2, and the caller's own
/// `relevant_affected` filter, treat leniently as "matches any queried
/// package") does NOT count as genuine here, and neither does
/// `OsvVulnRecord::into_advisory`'s "no entry matched the queried package;
/// using all entries" fallback set, whose entries by construction never
/// equal `osv_name`/`osv_eco` (impl-critic finding M2, FR-002b). This
/// prevents a stranger or ambiguous entry's `informational` value from ever
/// downgrading this record's classification for a package it does not
/// actually, confirmedly describe.
pub(super) fn classify(
    id: &str,
    aliases: &[String],
    database_specific: Option<&serde_json::Value>,
    relevant_affected: &[&OsvAffected],
    osv_name: &str,
    osv_eco: &str,
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

    for affected in relevant_affected {
        let genuinely_this_package = affected
            .package
            .as_ref()
            .is_some_and(|p| p.name == osv_name && p.ecosystem == osv_eco);
        if genuinely_this_package
            && affected
                .database_specific
                .as_ref()
                .is_some_and(is_informational_value)
        {
            return VulnSeverity::Informational;
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
/// `Informational` maps to `INFORMATION`, not `HINT`: VS Code's Problems
/// panel excludes `Hint`-severity diagnostics entirely and Zed de-emphasizes
/// them, which would make an informational/unmaintained notice *less*
/// visible than today's `WARNING`-bucket `Unknown` treatment — the opposite
/// of this classification's purpose (issue #1007, spec §9(a) REVISED).
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
/// assert_eq!(to_diagnostic_severity(VulnSeverity::Informational), DiagnosticSeverity::INFORMATION);
/// ```
#[must_use]
pub const fn to_diagnostic_severity(severity: VulnSeverity) -> DiagnosticSeverity {
    match severity {
        VulnSeverity::Critical
        | VulnSeverity::High
        | VulnSeverity::Unknown
        | VulnSeverity::Malicious => DiagnosticSeverity::WARNING,
        VulnSeverity::Medium | VulnSeverity::Low | VulnSeverity::Informational => {
            DiagnosticSeverity::INFORMATION
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::types::{OsvAffected, OsvPackage};

    const PKG_NAME: &str = "yaml-rust";
    const PKG_ECO: &str = "crates.io";

    #[test]
    fn database_specific_severity_wins() {
        let json = serde_json::json!({ "severity": "CRITICAL" });
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                Some(&json),
                &[],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Critical
        );
    }

    #[test]
    fn database_specific_moderate_maps_to_medium() {
        let json = serde_json::json!({ "severity": "MODERATE" });
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                Some(&json),
                &[],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Medium
        );
    }

    #[test]
    fn falls_back_to_ecosystem_specific_severity() {
        let affected = OsvAffected {
            package: None,
            ecosystem_specific: Some(serde_json::json!({ "severity": "LOW" })),
            database_specific: None,
            ranges: vec![],
        };
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Low
        );
    }

    #[test]
    fn cvss_vector_only_record_is_unknown() {
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], None, &[], PKG_NAME, PKG_ECO),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn no_severity_at_all_is_unknown() {
        assert_eq!(
            classify("RUSTSEC-2020-0071", &[], None, &[], PKG_NAME, PKG_ECO),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn non_mal_aliases_do_not_trigger_malicious_classification() {
        // N5 (impl-critic): pins the discriminating half of the MAL- alias
        // predicate — a record with a non-empty, non-MAL-prefixed aliases
        // list must not be misclassified as Malicious (NFR-001).
        let aliases = ["GHSA-xxxx-xxxx-xxxx".to_string(), "CVE-2020-1".to_string()];
        assert_eq!(
            classify("RUSTSEC-2020-0071", &aliases, None, &[], PKG_NAME, PKG_ECO),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn mal_prefix_with_no_severity_fields_is_malicious() {
        // Live-verified shape: OSV's MAL-2025-47141 record for npm
        // `@ctrl/tinycolor` has no severity field anywhere.
        assert_eq!(
            classify("MAL-2025-47141", &[], None, &[], PKG_NAME, PKG_ECO),
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
            classify("MAL-2025-47141", &[], Some(&json), &[], PKG_NAME, PKG_ECO),
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
            classify(
                "GHSA-7pwq-f4pq-78gm",
                &aliases,
                Some(&json),
                &[],
                PKG_NAME,
                PKG_ECO
            ),
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
                &[],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Malicious
        );
        assert_eq!(
            classify("MAL-2022-1", &mal_aliases, None, &[], PKG_NAME, PKG_ECO),
            VulnSeverity::Malicious
        );
        assert_eq!(
            classify(
                "RUSTSEC-2022-0042",
                &rustsec_aliases,
                None,
                &[],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Malicious
        );
    }

    /// An `affected[]` entry whose `package` genuinely, exactly matches
    /// `PKG_NAME`/`PKG_ECO` — the only shape `classify()`'s informational
    /// pass treats as a genuine match (FR-002b/M2).
    fn informational_affected(value: &str) -> OsvAffected {
        OsvAffected {
            package: Some(OsvPackage {
                name: PKG_NAME.to_string(),
                ecosystem: PKG_ECO.to_string(),
            }),
            ecosystem_specific: None,
            database_specific: Some(serde_json::json!({ "informational": value })),
            ranges: vec![],
        }
    }

    #[test]
    fn plain_unmaintained_is_classified_informational() {
        // Live-verified shape: RUSTSEC-2024-0320 (yaml-rust) carries
        // `informational: "unmaintained"` and no severity field anywhere.
        let affected = informational_affected("unmaintained");
        assert_eq!(
            classify(
                "RUSTSEC-2024-0320",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Informational
        );
    }

    #[test]
    fn notice_value_is_not_classified_informational() {
        // L1 (security, revised from an earlier allowlist that included
        // "notice"): live-verified RUSTSEC-2026-0174/http-types carries
        // `informational: "notice"` while describing a real defect (an
        // incorrect `unsafe` justification for an ASCII-invariant
        // guarantee) — the same failure class as H1's "unsound" finding.
        // "notice" must fall through to Unknown/WARNING, never be
        // downgraded to Informational.
        let affected = informational_affected("notice");
        assert_eq!(
            classify(
                "RUSTSEC-2026-0174",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn unsound_value_is_not_classified_informational() {
        // H1 (security): RUSTSEC's "unsound" category is a real
        // memory-safety/UB finding (live-verified: RUSTSEC-2021-0145/atty,
        // RUSTSEC-2019-0036/failure), NOT a maintenance-status notice — it
        // must fall through to Unknown/WARNING, never be downgraded to
        // Informational.
        let affected = informational_affected("unsound");
        assert_eq!(
            classify(
                "RUSTSEC-2021-0145",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn osv_unknown_informational_value_is_not_classified_informational() {
        // FR-007 (revised): OSV's own `informational: "unknown"` enum value
        // is NOT in the allowlist ("unmaintained"/"notice" only) — it falls
        // through to VulnSeverity::Unknown exactly like a record with no
        // `informational` field at all, sidestepping any naming-collision
        // concern with this crate's own Unknown variant.
        let affected = informational_affected("unknown");
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn unrecognized_future_value_is_not_classified_informational() {
        let affected = informational_affected("something-new-osv-invented");
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn graded_severity_on_another_entry_wins_over_informational_regardless_of_order() {
        // FR-005/FR-002a: two relevant entries, one graded and one
        // informational — graded must win no matter which entry comes
        // first, since classify() runs a full graded-severity pass before
        // ever considering the informational pass.
        let graded = OsvAffected {
            package: None,
            ecosystem_specific: Some(serde_json::json!({ "severity": "HIGH" })),
            database_specific: None,
            ranges: vec![],
        };
        let informational = informational_affected("unmaintained");

        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&informational, &graded],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::High,
            "informational entry listed first must not win over a later graded entry"
        );
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&graded, &informational],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::High
        );
    }

    #[test]
    fn mal_prefix_wins_over_informational() {
        let affected = informational_affected("unmaintained");
        assert_eq!(
            classify("MAL-2025-47141", &[], None, &[&affected], PKG_NAME, PKG_ECO),
            VulnSeverity::Malicious
        );
    }

    #[test]
    fn informational_on_fallback_all_entries_is_not_classified_informational() {
        // FR-002b: when `relevant_affected` is the "no entry matched the
        // queried package; using all entries" fallback set, its entries'
        // `package` never equals the queried osv_name/osv_eco by
        // construction — an `informational` value on one of those stranger
        // entries must not downgrade this record's classification.
        let stranger = OsvAffected {
            package: Some(OsvPackage {
                name: "some-other-crate".to_string(),
                ecosystem: PKG_ECO.to_string(),
            }),
            ecosystem_specific: None,
            database_specific: Some(serde_json::json!({ "informational": "unmaintained" })),
            ranges: vec![],
        };
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&stranger],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn informational_on_package_less_entry_is_not_classified_informational() {
        // M2 (impl-critic): a `package`-less entry is lenient-matched into
        // `relevant_affected` for graded-severity purposes, but must NOT
        // count as a genuine match for the informational check specifically
        // — it is not confirmed to actually describe the queried package.
        let affected = OsvAffected {
            package: None,
            ecosystem_specific: None,
            database_specific: Some(serde_json::json!({ "informational": "unmaintained" })),
            ranges: vec![],
        };
        assert_eq!(
            classify(
                "RUSTSEC-2020-0071",
                &[],
                None,
                &[&affected],
                PKG_NAME,
                PKG_ECO
            ),
            VulnSeverity::Unknown
        );
    }

    #[test]
    fn empty_whitespace_and_null_informational_values_are_not_classified_informational() {
        for value in [
            serde_json::json!({ "informational": "" }),
            serde_json::json!({ "informational": "   " }),
            serde_json::json!({ "informational": null }),
            serde_json::json!({}),
        ] {
            let affected = OsvAffected {
                package: Some(OsvPackage {
                    name: PKG_NAME.to_string(),
                    ecosystem: PKG_ECO.to_string(),
                }),
                ecosystem_specific: None,
                database_specific: Some(value.clone()),
                ranges: vec![],
            };
            assert_eq!(
                classify(
                    "RUSTSEC-2020-0071",
                    &[],
                    None,
                    &[&affected],
                    PKG_NAME,
                    PKG_ECO
                ),
                VulnSeverity::Unknown,
                "expected {value:?} to not trigger Informational classification"
            );
        }
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
        assert_eq!(
            to_diagnostic_severity(VulnSeverity::Informational),
            DiagnosticSeverity::INFORMATION
        );
    }
}
