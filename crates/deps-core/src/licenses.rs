//! SPDX license-policy matching (issue #661, spec 010 Phase 2).
//!
//! Deliberately minimal: exact, case-insensitive, top-level SPDX identifier
//! set-membership matching only — no `AND`/`OR`/`WITH` expression-operator
//! parsing and no new SPDX-parsing dependency (spec 010 `plan.md`'s explicit
//! scope decision). A dependency's license is already a flat set of discrete
//! identifiers by the time it reaches this module — [`crate::Version::license`]
//! returns `Vec<String>`, one entry per declared identifier (a dual-licensed
//! package's `"MIT OR Apache-2.0"` SPDX expression is reported by every source
//! this feature uses as two separate strings, not one raw expression) — so
//! plain set membership needs no parser.

use std::fmt;

/// Maximum length of a single SPDX identifier accepted into a
/// [`LicensePolicy`] — mirrors `deps-core::lsp_helpers::hover`'s
/// `MAX_LICENSE_ID_CHARS` cap on the untrusted-length side of this same data
/// (registry-declared license strings), applied here to user-supplied policy
/// config instead.
const MAX_SPDX_ID_CHARS: usize = 128;

/// Cap on how many declared license entries [`evaluate`] joins into a
/// [`LicenseViolation::license`] message for [`ViolationReason::NotAllowed`] — defense in
/// depth against a compromised/malicious registry response declaring an excessive number of
/// license entries for one dependency (issue #660/#661 critic security P2), mirroring
/// `deps-core::lsp_helpers::hover`'s own `MAX_LICENSE_ENTRIES_RENDERED` cap for the same
/// untrusted data.
const MAX_LICENSE_ENTRIES_JOINED: usize = 8;

/// Whether `id` is syntactically plausible as a single SPDX license
/// identifier (e.g. `MIT`, `Apache-2.0`, `GPL-3.0-or-later`,
/// `LicenseRef-Acme-Custom`) — a lightweight charset/length sanity check, not
/// validation against the canonical SPDX License List (which would need a
/// new dependency or an embedded list this feature's scope deliberately
/// avoids, see the module docs).
///
/// Rejects anything containing whitespace or characters outside
/// `[A-Za-z0-9.+-]`, which also rejects a raw multi-token SPDX *expression*
/// (`"MIT OR Apache-2.0"`) — this module only ever matches single
/// identifiers, so an expression could never match anyway and is better
/// dropped with a warning than kept as a policy entry that silently never
/// matches.
fn is_syntactically_valid_spdx_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SPDX_ID_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// Filters `ids` down to entries `is_syntactically_valid_spdx_id` accepts,
/// logging one `tracing::warn!` per dropped entry.
///
/// Shared by [`LicensePolicy::new`] and `deps-lsp`'s
/// `initializationOptions.license_policy` config deserializer, so an invalid
/// identifier is only ever validated (and warned about) once, at config-load
/// time, regardless of how many times a [`LicensePolicy`] is subsequently
/// constructed from the already-cleaned lists.
///
/// # Examples
///
/// ```
/// use deps_core::licenses::filter_valid_spdx_ids;
///
/// let cleaned = filter_valid_spdx_ids(vec![
///     "MIT".to_string(),
///     "not a license".to_string(),
/// ]);
/// assert_eq!(cleaned, vec!["MIT".to_string()]);
/// ```
#[must_use]
pub fn filter_valid_spdx_ids(ids: Vec<String>) -> Vec<String> {
    ids.into_iter()
        .filter(|id| {
            let valid = is_syntactically_valid_spdx_id(id);
            if !valid {
                tracing::warn!(
                    identifier = %id,
                    "license policy: dropping invalid SPDX identifier"
                );
            }
            valid
        })
        .collect()
}

/// An allow-list/deny-list SPDX license policy (issue #661), configured via
/// `initializationOptions.license_policy: { allow?: string[], deny?: string[] }`.
///
/// Both lists are independently optional; an empty policy (`is_empty()`)
/// matches nothing and [`evaluate`] always returns `None` for it. See
/// [`evaluate`] for matching and precedence rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LicensePolicy {
    /// SPDX identifiers a dependency's license must include at least one of,
    /// when non-empty.
    pub allow: Vec<String>,
    /// SPDX identifiers a dependency's license must not include any of.
    pub deny: Vec<String>,
}

impl LicensePolicy {
    /// Builds a policy from raw, user-supplied SPDX identifier lists,
    /// dropping any entry [`filter_valid_spdx_ids`] rejects.
    ///
    /// Never fails and never panics (NFR-003): an
    /// `initializationOptions.license_policy` payload has no document URI to
    /// anchor an LSP diagnostic to, so the `tracing::warn!` logged by
    /// [`filter_valid_spdx_ids`] for a dropped entry is the only feedback
    /// channel available for a typo'd identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::licenses::LicensePolicy;
    ///
    /// let policy = LicensePolicy::new(
    ///     vec!["MIT".to_string(), "not a license".to_string()],
    ///     vec!["GPL-3.0".to_string()],
    /// );
    /// assert_eq!(policy.allow, vec!["MIT".to_string()]);
    /// assert_eq!(policy.deny, vec!["GPL-3.0".to_string()]);
    /// ```
    #[must_use]
    pub fn new(allow: Vec<String>, deny: Vec<String>) -> Self {
        Self {
            allow: filter_valid_spdx_ids(allow),
            deny: filter_valid_spdx_ids(deny),
        }
    }

    /// Whether this policy has neither an allow-list nor a deny-list entry —
    /// [`evaluate`] never produces a violation against an empty policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::licenses::LicensePolicy;
    ///
    /// assert!(LicensePolicy::default().is_empty());
    /// assert!(!LicensePolicy::new(vec!["MIT".to_string()], vec![]).is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// Why a dependency's license violates a [`LicensePolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationReason {
    /// The license matches an entry on the policy's deny-list. Deny always
    /// wins over allow when a license matches both (spec 010 `plan.md`'s
    /// "Allow vs deny precedence" decision — matches `cargo deny licenses`'
    /// own precedence convention).
    Denied,
    /// The policy has a non-empty allow-list and none of the dependency's
    /// declared licenses matches an entry on it.
    NotAllowed,
}

impl fmt::Display for ViolationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "denied by policy",
            Self::NotAllowed => "not on the allowed license list",
        })
    }
}

/// A policy violation for one dependency, ready to render as an LSP
/// diagnostic (issue #661 FR-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseViolation {
    /// The specific declared license that triggered the violation, for
    /// [`ViolationReason::Denied`]; every declared license joined with
    /// `", "`, for [`ViolationReason::NotAllowed`] — no single entry alone
    /// caused that violation.
    pub license: String,
    /// Why this dependency's license violates the policy.
    pub reason: ViolationReason,
}

/// Checks `license` — a dependency's declared SPDX identifiers, e.g. from
/// [`crate::Version::license`] — against `policy`, returning the violation
/// if any.
///
/// Matching is exact, case-insensitive, top-level SPDX identifier
/// set-membership (module docs) — no expression-operator parsing.
///
/// A dependency with no known license (`license.is_empty()`) never violates
/// the policy: there is nothing to check, and treating "unknown" as "denied"
/// would turn every dependency this feature hasn't fetched license data for
/// into a false positive (NFR-003 graceful degradation).
///
/// A multi-licensed dependency (more than one entry in `license`, e.g. a
/// dual-licensed `"MIT OR Apache-2.0"` reported as two identifiers) is
/// denied if **any** entry matches the deny-list — the `Vec` license shape
/// carries no `AND`/`OR` structure to know whether picking a different
/// declared license would avoid the denied one, so a compliance gate errs
/// toward flagging for manual review. It is allowed if **any** entry matches
/// a non-empty allow-list — the permissive reading, since a multi-licensed
/// dependency lets the consumer pick whichever license they comply with.
///
/// # Examples
///
/// ```
/// use deps_core::licenses::{LicensePolicy, ViolationReason, evaluate};
///
/// let policy = LicensePolicy::new(
///     vec!["MIT".to_string(), "Apache-2.0".to_string()],
///     vec!["GPL-3.0".to_string()],
/// );
///
/// // Denied wins even if also on the allow-list.
/// let denied = evaluate(&["GPL-3.0".to_string()], &policy).unwrap();
/// assert_eq!(denied.reason, ViolationReason::Denied);
///
/// // Not on the allow-list.
/// let not_allowed = evaluate(&["ISC".to_string()], &policy).unwrap();
/// assert_eq!(not_allowed.reason, ViolationReason::NotAllowed);
///
/// // Compliant.
/// assert!(evaluate(&["MIT".to_string()], &policy).is_none());
///
/// // Unknown license never violates.
/// assert!(evaluate(&[], &policy).is_none());
/// ```
#[must_use]
pub fn evaluate(license: &[String], policy: &LicensePolicy) -> Option<LicenseViolation> {
    if license.is_empty() {
        return None;
    }

    if let Some(denied) = license.iter().find(|l| contains_ci(&policy.deny, l)) {
        return Some(LicenseViolation {
            license: denied.clone(),
            reason: ViolationReason::Denied,
        });
    }

    if !policy.allow.is_empty() && !license.iter().any(|l| contains_ci(&policy.allow, l)) {
        return Some(LicenseViolation {
            license: join_capped(license, MAX_LICENSE_ENTRIES_JOINED),
            reason: ViolationReason::NotAllowed,
        });
    }

    None
}

/// Case-insensitive `haystack.contains(needle)` for SPDX identifiers —
/// registry-declared and user-configured license strings are free text, not
/// a normalized enum, mirroring `deps-core::lsp_helpers::hover`'s
/// `license_sets_differ` precedent for the same data.
fn contains_ci(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|h| h.eq_ignore_ascii_case(needle))
}

/// Joins `licenses` with `", "`, capping the number of entries rendered at `max_entries`
/// and collapsing the remainder into a `"(+N more)"` suffix (issue #660/#661 critic
/// security P2) — mirrors `lsp_helpers::hover::format_license_list`'s shape for the same
/// registry-controlled, unbounded-length data.
fn join_capped(licenses: &[String], max_entries: usize) -> String {
    let shown = licenses.len().min(max_entries);
    // `shown <= licenses.len()` by construction (the `.min` above), so `.get(..shown)`
    // never actually falls back — `unwrap_or(licenses)` just satisfies
    // `clippy::indexing_slicing` (issue #678 hardening) without panicking if that
    // invariant is ever violated.
    let mut joined = licenses.get(..shown).unwrap_or(licenses).join(", ");
    let remaining = licenses.len() - shown;
    if remaining > 0 {
        joined.push_str(&format!(" (+{remaining} more)"));
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_syntactically_valid_spdx_id / filter_valid_spdx_ids ---

    #[test]
    fn valid_identifiers_are_kept() {
        let cleaned = filter_valid_spdx_ids(vec![
            "MIT".to_string(),
            "Apache-2.0".to_string(),
            "GPL-3.0-or-later".to_string(),
            "LicenseRef-Acme-Custom".to_string(),
        ]);
        assert_eq!(cleaned.len(), 4);
    }

    #[test]
    fn empty_identifier_is_dropped() {
        assert!(filter_valid_spdx_ids(vec![String::new()]).is_empty());
    }

    #[test]
    fn whitespace_identifier_is_dropped() {
        // Also rejects a raw SPDX *expression* like "MIT OR Apache-2.0" — see the
        // module docs' rationale.
        assert!(filter_valid_spdx_ids(vec!["MIT OR Apache-2.0".to_string()]).is_empty());
    }

    #[test]
    fn overlong_identifier_is_dropped() {
        let overlong = "A".repeat(MAX_SPDX_ID_CHARS + 1);
        assert!(filter_valid_spdx_ids(vec![overlong]).is_empty());
    }

    #[test]
    fn max_length_identifier_is_kept() {
        let exact = "A".repeat(MAX_SPDX_ID_CHARS);
        assert_eq!(filter_valid_spdx_ids(vec![exact.clone()]), vec![exact]);
    }

    #[test]
    fn valid_and_invalid_entries_are_partitioned() {
        let cleaned = filter_valid_spdx_ids(vec!["MIT".to_string(), "???".to_string()]);
        assert_eq!(cleaned, vec!["MIT".to_string()]);
    }

    // --- LicensePolicy ---

    #[test]
    fn new_drops_invalid_entries_from_both_lists() {
        let policy = LicensePolicy::new(
            vec!["MIT".to_string(), "bad id!".to_string()],
            vec!["GPL-3.0".to_string(), String::new()],
        );
        assert_eq!(policy.allow, vec!["MIT".to_string()]);
        assert_eq!(policy.deny, vec!["GPL-3.0".to_string()]);
    }

    #[test]
    fn default_policy_is_empty() {
        assert!(LicensePolicy::default().is_empty());
    }

    #[test]
    fn policy_with_only_allow_is_not_empty() {
        assert!(!LicensePolicy::new(vec!["MIT".to_string()], vec![]).is_empty());
    }

    #[test]
    fn policy_with_only_deny_is_not_empty() {
        assert!(!LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]).is_empty());
    }

    // --- evaluate: the decision-table branches from plan.md §7 ---

    #[test]
    fn evaluate_against_empty_policy_never_violates() {
        let policy = LicensePolicy::default();
        assert!(evaluate(&["GPL-3.0".to_string()], &policy).is_none());
    }

    #[test]
    fn evaluate_unknown_license_never_violates() {
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec!["GPL-3.0".to_string()]);
        assert!(evaluate(&[], &policy).is_none());
    }

    #[test]
    fn evaluate_denied_license_violates() {
        let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);
        let violation = evaluate(&["GPL-3.0".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::Denied);
        assert_eq!(violation.license, "GPL-3.0");
    }

    #[test]
    fn evaluate_denied_match_is_case_insensitive() {
        let policy = LicensePolicy::new(vec![], vec!["gpl-3.0".to_string()]);
        let violation = evaluate(&["GPL-3.0".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::Denied);
    }

    #[test]
    fn evaluate_not_allowed_license_violates() {
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
        let violation = evaluate(&["ISC".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::NotAllowed);
        assert_eq!(violation.license, "ISC");
    }

    #[test]
    fn evaluate_allowed_license_is_compliant() {
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
        assert!(evaluate(&["MIT".to_string()], &policy).is_none());
    }

    #[test]
    fn evaluate_allowed_match_is_case_insensitive() {
        let policy = LicensePolicy::new(vec!["mit".to_string()], vec![]);
        assert!(evaluate(&["MIT".to_string()], &policy).is_none());
    }

    #[test]
    fn evaluate_no_allow_list_means_no_restriction_beyond_deny() {
        let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);
        assert!(evaluate(&["Anything-Not-Denied".to_string()], &policy).is_none());
    }

    #[test]
    fn evaluate_deny_wins_when_license_matches_both_lists() {
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec!["MIT".to_string()]);
        let violation = evaluate(&["MIT".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::Denied);
    }

    #[test]
    fn evaluate_multi_license_denied_if_any_entry_matches_deny() {
        let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);
        let violation = evaluate(&["MIT".to_string(), "GPL-3.0".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::Denied);
        assert_eq!(violation.license, "GPL-3.0");
    }

    #[test]
    fn evaluate_multi_license_allowed_if_any_entry_matches_allow() {
        // Dual-licensed "MIT OR GPL-3.0": the consumer can pick MIT, so this is
        // compliant even though GPL-3.0 alone would not be on the allow-list.
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
        assert!(evaluate(&["MIT".to_string(), "GPL-3.0".to_string()], &policy).is_none());
    }

    #[test]
    fn evaluate_multi_license_not_allowed_if_no_entry_matches_allow() {
        let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
        let violation =
            evaluate(&["GPL-3.0".to_string(), "AGPL-3.0".to_string()], &policy).unwrap();
        assert_eq!(violation.reason, ViolationReason::NotAllowed);
        assert_eq!(violation.license, "GPL-3.0, AGPL-3.0");
    }

    // --- ViolationReason::Display ---

    #[test]
    fn violation_reason_display_text() {
        assert_eq!(ViolationReason::Denied.to_string(), "denied by policy");
        assert_eq!(
            ViolationReason::NotAllowed.to_string(),
            "not on the allowed license list"
        );
    }
}
