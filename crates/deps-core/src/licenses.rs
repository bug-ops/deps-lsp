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
//!
//! [`normalize_pom_license_name`]/[`normalize_pom_license_names`] (issue #679) bring a
//! Gradle dependency's Maven Central POM free-text `<license><name>` into this same
//! flat-identifier shape before evaluation. Free text like `"GNU General Public License
//! v3"` never disambiguates the deprecated bare SPDX id (`GPL-3.0`) from the current
//! `-only`/`-or-later` split, so the GPL/LGPL/AGPL families normalize to *all three*
//! forms for one POM entry — the same "any entry matches" set-membership semantics
//! `evaluate` already applies to a genuinely multi-licensed dependency (module docs
//! above), so a `license_policy.deny`/`.allow` list written in either convention still
//! matches. Dropping an entry the table doesn't recognize is fail-closed against a
//! *false* violation (an unmatched entry can never manufacture a `Denied` or
//! `NotAllowed` result it doesn't deserve), but it is **not** fail-closed with respect
//! to policy *enforcement* — an unrecognized copyleft license on a `deny` list silently
//! escapes rather than being flagged. Extending `KNOWN_POM_LICENSE_NAMES`'s coverage
//! is the mitigation; there is no way to make an unrecognized string safe to guess at.

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

/// Maximum length of a raw free-text `<license><name>` value considered for
/// normalization — mirrors `deps-core::lsp_helpers::hover`'s `MAX_LICENSE_ID_CHARS`
/// (issue #660/#661 critic security P2 precedent). The longest [`KNOWN_POM_LICENSE_NAMES`]
/// key is under 60 characters, so this rejects no real match; it exists purely to stop
/// [`collapse_whitespace`]'s `split_whitespace().collect::<Vec<_>>().join(...)` from
/// re-allocating a large token vector for an oversized, whitespace-dense value on every
/// diagnostics pass (issue #679 security P2: an unbounded `<name>` gave ~10x memory
/// amplification per dependency).
const MAX_POM_LICENSE_NAME_RAW_CHARS: usize = 128;

/// Known Maven Central POM `<license><name>` free-text variants mapped to their
/// canonical SPDX identifier(s) (issue #679).
///
/// An explicit lookup table, not a heuristic — [`normalize_pom_license_name`] compares
/// case-insensitively after whitespace collapsing, never by substring, so e.g. "GNU
/// Lesser General Public License v3" can never be mistaken for a plain "GPL-3.0" entry.
/// Covers the common Apache/MIT/BSD/GPL/LGPL/AGPL/EPL/MPL/CDDL/ISC variants Maven Central
/// POMs declare; an unlisted variant is deliberately left unmatched rather than guessed
/// at (see [`normalize_pom_license_name`]'s fail-closed contract).
///
/// Each entry maps to a **slice** of SPDX ids, not one: free text like "GNU General
/// Public License v3" never disambiguates the deprecated bare id (`GPL-3.0`) from the
/// current `-only`/`-or-later` split, so the GPL/LGPL/AGPL families list all three forms
/// (module docs). A genuinely disjunctive POM name — `"CDDL + GPLv2 with classpath
/// exception"` is Sun/Oracle's convention for "either license applies, consumer's
/// choice", not "both simultaneously" — maps the same way, to `&["CDDL-1.1",
/// "GPL-2.0-with-classpath-exception"]`; [`evaluate`]'s existing multi-entry "any entry
/// matches" semantics is exactly the right reading for that "OR", the same as if a
/// registry had reported the two identifiers as separate `license` entries.
///
/// A `*-with-classpath-exception` license (e.g. `"GPL2 w/ CPE"`) is intentionally kept
/// distinct from its plain `GPL-2.0` family — folding it into bare `GPL-2.0` would
/// misclassify a permissively-usable (classpath-exception) artifact as plain copyleft.
const KNOWN_POM_LICENSE_NAMES: &[(&str, &[&str])] = &[
    // Apache-2.0
    ("The Apache Software License, Version 2.0", &["Apache-2.0"]),
    ("The Apache License, Version 2.0", &["Apache-2.0"]),
    ("Apache License, Version 2.0", &["Apache-2.0"]),
    ("Apache License Version 2.0", &["Apache-2.0"]),
    ("Apache License 2.0", &["Apache-2.0"]),
    ("Apache Software License - Version 2.0", &["Apache-2.0"]),
    ("Apache 2.0", &["Apache-2.0"]),
    ("Apache 2", &["Apache-2.0"]),
    ("Apache-2.0 License", &["Apache-2.0"]),
    ("Apache-2.0", &["Apache-2.0"]),
    // MIT
    ("MIT License", &["MIT"]),
    ("The MIT License", &["MIT"]),
    ("MIT License (MIT)", &["MIT"]),
    ("The MIT License (MIT)", &["MIT"]),
    ("MIT", &["MIT"]),
    // BSD-3-Clause (Eclipse Distribution License is BSD-3-Clause under another name)
    ("BSD 3-Clause License", &["BSD-3-Clause"]),
    ("The BSD 3-Clause License", &["BSD-3-Clause"]),
    ("3-Clause BSD License", &["BSD-3-Clause"]),
    ("BSD 3-Clause", &["BSD-3-Clause"]),
    ("BSD 3-clause New License", &["BSD-3-Clause"]),
    ("New BSD License", &["BSD-3-Clause"]),
    ("The New BSD License", &["BSD-3-Clause"]),
    ("Eclipse Distribution License - v 1.0", &["BSD-3-Clause"]),
    (
        "Eclipse Distribution License (New BSD License)",
        &["BSD-3-Clause"],
    ),
    ("BSD-3-Clause", &["BSD-3-Clause"]),
    // BSD-2-Clause
    ("BSD 2-Clause License", &["BSD-2-Clause"]),
    ("2-Clause BSD License", &["BSD-2-Clause"]),
    ("Simplified BSD License", &["BSD-2-Clause"]),
    ("BSD-2-Clause", &["BSD-2-Clause"]),
    // GPL-2.0 (free text never disambiguates only/or-later — list both plus the
    // deprecated bare id so either policy-config convention matches)
    (
        "GNU General Public License v2",
        &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
    ),
    (
        "GNU General Public License v2.0",
        &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
    ),
    (
        "GNU General Public License, Version 2",
        &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
    ),
    (
        "GNU General Public License Version 2",
        &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
    ),
    ("GPLv2", &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"]),
    ("GPL v2", &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"]),
    ("GPL-2.0", &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"]),
    // GPL-2.0-with-classpath-exception — kept out of the plain GPL-2.0 family above
    // (see the table doc comment); the bare SPDX id itself is handled by
    // `normalize_pom_license_name`'s already-valid-id passthrough, not listed here.
    ("GPL2 w/ CPE", &["GPL-2.0-with-classpath-exception"]),
    (
        "GNU General Public License, version 2 (GPL2), with the classpath exception",
        &["GPL-2.0-with-classpath-exception"],
    ),
    // GPL-3.0
    (
        "GNU General Public License v3",
        &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"],
    ),
    (
        "GNU General Public License v3.0",
        &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"],
    ),
    (
        "GNU General Public License, Version 3",
        &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"],
    ),
    ("GPLv3", &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"]),
    ("GPL v3", &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"]),
    ("GPL-3.0", &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"]),
    // AGPL-3.0
    (
        "GNU Affero General Public License v3.0",
        &["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"],
    ),
    (
        "GNU Affero General Public License v3",
        &["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"],
    ),
    (
        "AGPLv3",
        &["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"],
    ),
    (
        "AGPL-3.0",
        &["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"],
    ),
    // LGPL-2.1
    (
        "GNU Lesser General Public License v2.1",
        &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
    ),
    (
        "GNU Lesser General Public License, Version 2.1",
        &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
    ),
    (
        "LGPLv2.1",
        &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
    ),
    (
        "LGPL 2.1",
        &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
    ),
    (
        "LGPL-2.1",
        &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
    ),
    // LGPL-3.0
    (
        "GNU Lesser General Public License v3",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    (
        "GNU Lesser General Public License v3.0",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    (
        "GNU Lesser General Public License, Version 3",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    (
        "LGPLv3",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    (
        "LGPL 3.0",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    (
        "LGPL-3.0",
        &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
    ),
    // EPL-1.0
    ("Eclipse Public License - v 1.0", &["EPL-1.0"]),
    ("Eclipse Public License - Version 1.0", &["EPL-1.0"]),
    ("Eclipse Public License, Version 1.0", &["EPL-1.0"]),
    ("Eclipse Public License 1.0", &["EPL-1.0"]),
    ("Eclipse Public License v1.0", &["EPL-1.0"]),
    ("EPL-1.0", &["EPL-1.0"]),
    // EPL-2.0
    ("Eclipse Public License - v 2.0", &["EPL-2.0"]),
    ("Eclipse Public License v. 2.0", &["EPL-2.0"]),
    ("Eclipse Public License v2.0", &["EPL-2.0"]),
    ("Eclipse Public License 2.0", &["EPL-2.0"]),
    ("EPL-2.0", &["EPL-2.0"]),
    // MPL-2.0
    ("Mozilla Public License 2.0", &["MPL-2.0"]),
    ("Mozilla Public License Version 2.0", &["MPL-2.0"]),
    ("Mozilla Public License, Version 2.0", &["MPL-2.0"]),
    ("MPL 2.0", &["MPL-2.0"]),
    ("MPL-2.0", &["MPL-2.0"]),
    // MPL-1.1
    ("Mozilla Public License 1.1", &["MPL-1.1"]),
    ("MPL 1.1", &["MPL-1.1"]),
    ("MPL-1.1", &["MPL-1.1"]),
    // CDDL-1.0
    (
        "Common Development and Distribution License (CDDL) v1.0",
        &["CDDL-1.0"],
    ),
    (
        "COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.0",
        &["CDDL-1.0"],
    ),
    ("CDDL 1.0", &["CDDL-1.0"]),
    // CDDL-1.1
    ("CDDL 1.1", &["CDDL-1.1"]),
    // CDDL + GPL-2.0-with-classpath-exception dual license (see the table doc comment
    // for why this maps to two ids, not one)
    (
        "CDDL + GPLv2 with classpath exception",
        &["CDDL-1.1", "GPL-2.0-with-classpath-exception"],
    ),
    // ISC
    ("ISC License", &["ISC"]),
    ("ISC", &["ISC"]),
];

/// Collapses runs of ASCII/Unicode whitespace in `s` down to a single space, so e.g.
/// `"Apache  License,\nVersion 2.0"` (a POM's raw, occasionally multi-line free text)
/// still matches the single-space-normalized [`KNOWN_POM_LICENSE_NAMES`] entries.
fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Maps a Maven Central POM's free-text `<license><name>` to its canonical SPDX
/// identifier(s) (issue #679).
///
/// Looks `raw` up (case-insensitive, whitespace-collapsed, never fuzzy/substring)
/// against the explicit variant list in `KNOWN_POM_LICENSE_NAMES`, e.g. mapping
/// `"The Apache Software License, Version 2.0"` to `["Apache-2.0"]` — see that
/// constant's doc comment for why some families expand to more than one id. A `raw`
/// value longer than `MAX_POM_LICENSE_NAME_RAW_CHARS` or that matches nothing in the
/// table falls through to one more check: if it is already syntactically shaped like an
/// SPDX id (`is_syntactically_valid_spdx_id`) *and* contains at least one ASCII digit,
/// it is accepted as-is — a POM sometimes uses the SPDX id itself as the free-text name
/// (e.g. `"AGPL-3.0"`, `"GPL-2.0-with-classpath-exception"`). The digit requirement is
/// deliberate: it excludes genuinely ambiguous bare terms real POMs also use verbatim
/// (`"GPL"`, `"BSD"`, `"Apache License"` with no version), which would otherwise pass
/// the same charset check and produce a false match. Anything else returns an empty
/// `Vec` rather than a guessed identifier, so a caller feeding the result into
/// [`evaluate`] never risks a false allow/deny match on text this function doesn't
/// explicitly recognize.
///
/// # Examples
///
/// ```
/// use deps_core::licenses::normalize_pom_license_name;
///
/// assert_eq!(
///     normalize_pom_license_name("The Apache Software License, Version 2.0"),
///     vec!["Apache-2.0".to_string()]
/// );
/// assert_eq!(
///     normalize_pom_license_name("GNU General Public License v3"),
///     vec!["GPL-3.0".to_string(), "GPL-3.0-only".to_string(), "GPL-3.0-or-later".to_string()]
/// );
/// // Already SPDX-shaped free text passes through as-is.
/// assert_eq!(normalize_pom_license_name("SSPL-1.0"), vec!["SSPL-1.0".to_string()]);
/// // Genuinely ambiguous (no version) — never guessed at.
/// assert!(normalize_pom_license_name("GPL").is_empty());
/// assert!(normalize_pom_license_name("Some Bespoke Corporate License").is_empty());
/// ```
#[must_use]
pub fn normalize_pom_license_name(raw: &str) -> Vec<String> {
    if raw.len() > MAX_POM_LICENSE_NAME_RAW_CHARS {
        return Vec::new();
    }
    let canonical = collapse_whitespace(raw.trim());
    if canonical.is_empty() {
        return Vec::new();
    }
    if let Some((_, ids)) = KNOWN_POM_LICENSE_NAMES
        .iter()
        .find(|(variant, _)| variant.eq_ignore_ascii_case(&canonical))
    {
        return ids.iter().map(|id| (*id).to_string()).collect();
    }
    if is_syntactically_valid_spdx_id(&canonical) && canonical.bytes().any(|b| b.is_ascii_digit()) {
        return vec![canonical];
    }
    Vec::new()
}

/// Applies `normalize_pom_license_name` to every entry in `raw`, merging the results.
///
/// A thin wrapper around [`normalize_pom_license_names_checked`] that drops the
/// "did every entry normalize" flag — use the checked variant directly instead of
/// calling both in the same place, to avoid normalizing each entry twice (issue #679
/// review nitpick).
///
/// # Examples
///
/// ```
/// use deps_core::licenses::normalize_pom_license_names;
///
/// let normalized = normalize_pom_license_names(&[
///     "The Apache Software License, Version 2.0".to_string(),
///     "Some Bespoke Corporate License".to_string(),
/// ]);
/// assert_eq!(normalized, vec!["Apache-2.0".to_string()]);
/// ```
#[must_use]
pub fn normalize_pom_license_names(raw: &[String]) -> Vec<String> {
    normalize_pom_license_names_checked(raw).0
}

/// Applies `normalize_pom_license_name` to every entry in `raw`, merging the results
/// and reporting whether every entry normalized successfully.
///
/// Deduplicates the combined ids and logs (`tracing::debug!`) each entry that doesn't
/// match a known variant (issue #679 fail-closed contract) rather than keeping the free
/// text or guessing — `debug!`, not `warn!`, since this runs on every diagnostics pass
/// for ordinary registry data, not a one-time user config load like
/// [`filter_valid_spdx_ids`]'s equivalent per-dropped-entry logging.
///
/// Used to bring a Gradle dependency's Maven Central POM license names into
/// [`evaluate`]'s expected SPDX-identifier shape before license-policy evaluation. A
/// dual-licensed POM with one recognized and one unrecognized entry still evaluates the
/// recognized one — only the unmatched entry is excluded from the returned `Vec`, since
/// `evaluate` requires no `AND`/`OR` structure between entries (module docs). The `bool`
/// is `false` when at least one entry was dropped — a caller needs this to decide
/// whether to trust a resulting `NotAllowed` evaluation, since the surviving ids are
/// then incomplete evidence (issue #679 critic S1): "no entry matches allow" can't be
/// trusted when an entry was silently excluded, but a `Denied` match is still valid
/// regardless, since a recognized entry matching `deny` is real evidence either way.
///
/// # Examples
///
/// ```
/// use deps_core::licenses::normalize_pom_license_names_checked;
///
/// let (ids, all_matched) = normalize_pom_license_names_checked(&["MIT License".to_string()]);
/// assert_eq!(ids, vec!["MIT".to_string()]);
/// assert!(all_matched);
///
/// let (ids, all_matched) = normalize_pom_license_names_checked(&[
///     "MIT License".to_string(),
///     "Some Bespoke Corporate License".to_string(),
/// ]);
/// assert_eq!(ids, vec!["MIT".to_string()]);
/// assert!(!all_matched);
/// ```
#[must_use]
pub fn normalize_pom_license_names_checked(raw: &[String]) -> (Vec<String>, bool) {
    let mut normalized = Vec::new();
    let mut all_matched = true;
    for name in raw {
        let ids = normalize_pom_license_name(name);
        if ids.is_empty() {
            all_matched = false;
            tracing::debug!(
                license = %name,
                "license policy: gradle POM license name did not normalize to a known SPDX identifier"
            );
        }
        for id in ids {
            if !normalized.contains(&id) {
                normalized.push(id);
            }
        }
    }
    (normalized, all_matched)
}

/// Resolves `raw` tier-3 pre-fetched license text into policy-evaluation-ready SPDX
/// identifiers for `source` (issue #687/#688).
///
/// See [`resolve_license_entries_for_display`] for the sibling used to *render* the same
/// data in hover. Applies [`normalize_pom_license_names_checked`] for [`crate::LicenseSource::PomFreeText`]
/// and passes every other source through unchanged. The single normalization call site
/// `generate_diagnostics_from_cache`'s license-policy rule reads through — before this,
/// it re-derived its own Gradle-only `==` branch inline.
///
/// Deliberately fail-closed, unlike [`resolve_license_entries_for_display`]: an entry the
/// normalization table doesn't recognize is dropped rather than guessed at (never
/// fabricate a policy violation), and a POM entry that is genuinely one declared license
/// but ambiguous between SPDX conventions (e.g. `"GNU General Public License v3"`)
/// expands to every synonym (`GPL-3.0`/`-only`/`-or-later`) so a `deny`/`allow` list
/// written in any of them still matches — both are correct for policy evaluation and
/// wrong for a human-facing hover line, which is exactly why display uses a different
/// function.
///
/// The second element mirrors [`normalize_pom_license_names_checked`]'s "did every entry
/// normalize" flag — always `true` for a source with nothing to normalize, so a caller
/// that uses it to gate a policy conclusion (see that function's doc) behaves identically
/// for both a genuinely non-`PomFreeText` source and a `PomFreeText` source whose entries
/// all recognized.
///
/// # Examples
///
/// ```
/// use deps_core::LicenseSource;
/// use deps_core::licenses::resolve_license_entries;
///
/// let (ids, all_matched) = resolve_license_entries(
///     LicenseSource::PomFreeText,
///     &["The Apache Software License, Version 2.0".to_string()],
/// );
/// assert_eq!(ids, vec!["Apache-2.0".to_string()]);
/// assert!(all_matched);
///
/// let (ids, all_matched) =
///     resolve_license_entries(LicenseSource::RegistryDeclaredSpdx, &["MIT".to_string()]);
/// assert_eq!(ids, vec!["MIT".to_string()]);
/// assert!(all_matched);
/// ```
#[must_use]
pub fn resolve_license_entries(
    source: crate::LicenseSource,
    raw: &[String],
) -> (Vec<String>, bool) {
    match source {
        crate::LicenseSource::PomFreeText => normalize_pom_license_names_checked(raw),
        crate::LicenseSource::RegistryDeclaredSpdx | crate::LicenseSource::DetectedSpdx => {
            (raw.to_vec(), true)
        }
    }
}

/// Resolves `raw` tier-3 pre-fetched license text for *display* (hover), for `source`
/// (issue #687 critic S1/S2).
///
/// See [`resolve_license_entries`] for the sibling used to *evaluate* the same data
/// against a [`LicensePolicy`]. Differs from it in exactly the two ways display needs:
/// - **Never drops an entry.** [`resolve_license_entries`] fails closed and drops an
///   entry [`normalize_pom_license_name`] doesn't recognize (correct for policy
///   evaluation: never fabricate a violation from guessed data) — but the
///   `KNOWN_POM_LICENSE_NAMES` table is deliberately non-exhaustive (see the module
///   docs above), so dropping is the *designed-for* path, not a rare edge case, and
///   applying it to hover made the license line silently vanish for any unrecognized
///   POM name. Falls back to the raw text instead, since showing the author's declared
///   string is strictly more useful to a reader than showing nothing.
/// - **One id per entry when the ids are synonyms, not a policy-matching slice.** A POM
///   name ambiguous between SPDX conventions (e.g. the GPL family) normalizes to three
///   synonymous ids for [`resolve_license_entries`] so a `deny`/`allow` list written in
///   any of them still matches — correct for policy, but printing `` `GPL-3.0`,
///   `GPL-3.0-only`, `GPL-3.0-or-later` `` in hover for what is genuinely one declared
///   license reads as three licenses. Keeps only the first (canonical) id in that case —
///   but a genuinely disjunctive entry (`"CDDL + GPLv2 with classpath exception"` names
///   two unrelated licenses, not synonyms of one) still shows every id, or a
///   dual-licensed dependency would misleadingly read as single-licensed. See this
///   module's private `ids_are_synonyms` helper for how the two shapes are told apart.
///
/// Entries are deduplicated (preserving first-seen order), same as
/// [`normalize_pom_license_names_checked`].
///
/// # Examples
///
/// ```
/// use deps_core::LicenseSource;
/// use deps_core::licenses::resolve_license_entries_for_display;
///
/// // Recognized: normalizes to its canonical id, like `resolve_license_entries`.
/// let ids = resolve_license_entries_for_display(
///     LicenseSource::PomFreeText,
///     &["The Apache Software License, Version 2.0".to_string()],
/// );
/// assert_eq!(ids, vec!["Apache-2.0".to_string()]);
///
/// // Unrecognized: falls back to the raw text instead of vanishing (issue #687 S1).
/// let ids = resolve_license_entries_for_display(
///     LicenseSource::PomFreeText,
///     &["Some Bespoke Corporate License".to_string()],
/// );
/// assert_eq!(ids, vec!["Some Bespoke Corporate License".to_string()]);
///
/// // Ambiguous SPDX convention: one canonical id, not the full policy-matching slice
/// // (issue #687 S2).
/// let ids = resolve_license_entries_for_display(
///     LicenseSource::PomFreeText,
///     &["GNU General Public License v3".to_string()],
/// );
/// assert_eq!(ids, vec!["GPL-3.0".to_string()]);
///
/// // Genuinely disjunctive (two unrelated licenses, not synonyms of one): both ids
/// // are kept, unlike the GPL-family case above (code-review must-fix).
/// let ids = resolve_license_entries_for_display(
///     LicenseSource::PomFreeText,
///     &["CDDL + GPLv2 with classpath exception".to_string()],
/// );
/// assert_eq!(
///     ids,
///     vec!["CDDL-1.1".to_string(), "GPL-2.0-with-classpath-exception".to_string()]
/// );
/// ```
#[must_use]
pub fn resolve_license_entries_for_display(
    source: crate::LicenseSource,
    raw: &[String],
) -> Vec<String> {
    match source {
        crate::LicenseSource::PomFreeText => {
            let mut resolved = Vec::new();
            for name in raw {
                let ids = normalize_pom_license_name(name);
                let display_ids: Vec<String> = if ids.is_empty() {
                    vec![name.clone()]
                } else if ids_are_synonyms(&ids) {
                    // Safe to collapse: every id names the same declared license,
                    // just a different SPDX-convention spelling of it.
                    ids.into_iter().take(1).collect()
                } else {
                    // A genuine multi-license OR (e.g. `"CDDL + GPLv2 with classpath
                    // exception"`) — every id names a different license, so all must
                    // be shown or a dual-licensed dependency reads as single-licensed.
                    ids
                };
                for id in display_ids {
                    if !resolved.contains(&id) {
                        resolved.push(id);
                    }
                }
            }
            resolved
        }
        crate::LicenseSource::RegistryDeclaredSpdx | crate::LicenseSource::DetectedSpdx => {
            raw.to_vec()
        }
    }
}

/// Whether `ids` — one [`KNOWN_POM_LICENSE_NAMES`] entry's normalized SPDX id list —
/// represents interchangeable synonyms of a single declared license (safe for
/// [`resolve_license_entries_for_display`] to collapse to one representative id)
/// rather than a genuine multi-license OR (every id must be shown, code-review
/// must-fix: collapsing `"CDDL + GPLv2 with classpath exception"` to one id
/// misrepresented a dual-licensed dependency as solely CDDL-licensed).
///
/// Every synonym-set entry in the table is formed by SPDX's own `-only`/`-or-later`
/// suffix convention over one shared base id (e.g. `GPL-3.0`, `GPL-3.0-only`,
/// `GPL-3.0-or-later` — see the table's own doc comment on why free text can't
/// disambiguate the convention), so every id after the first is that first id with a
/// suffix appended. The table's one genuinely disjunctive entry names two unrelated
/// license families with no such shared prefix, so a plain prefix check tells the two
/// shapes apart without a separate marker on every one of the table's ~90 rows. A
/// single-id (or empty) list is trivially "synonyms" — there is nothing to collapse.
fn ids_are_synonyms(ids: &[String]) -> bool {
    match ids.split_first() {
        Some((first, rest)) => rest.iter().all(|id| id.starts_with(first.as_str())),
        None => true,
    }
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

    // --- normalize_pom_license_name / normalize_pom_license_names (issue #679) ---

    /// Asserts that every variant in `variants` normalizes to exactly `expected` (order
    /// matches the table's declared id order for that family).
    fn assert_all_normalize_to(variants: &[&str], expected: &[&str]) {
        let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
        for variant in variants {
            assert_eq!(
                normalize_pom_license_name(variant),
                expected,
                "variant: {variant}"
            );
        }
    }

    #[test]
    fn normalizes_apache_2_0_variants() {
        assert_all_normalize_to(
            &[
                "The Apache Software License, Version 2.0",
                "Apache License, Version 2.0",
                "Apache License 2.0",
                "Apache 2.0",
                "Apache-2.0",
            ],
            &["Apache-2.0"],
        );
    }

    #[test]
    fn normalizes_mit_variants() {
        assert_all_normalize_to(
            &[
                "MIT License",
                "The MIT License",
                "The MIT License (MIT)",
                "MIT",
            ],
            &["MIT"],
        );
    }

    #[test]
    fn normalizes_bsd_3_clause_variants() {
        assert_all_normalize_to(
            &[
                "BSD 3-Clause License",
                "3-Clause BSD License",
                "BSD-3-Clause",
                "Eclipse Distribution License - v 1.0",
            ],
            &["BSD-3-Clause"],
        );
    }

    #[test]
    fn normalizes_bsd_2_clause_variants() {
        assert_all_normalize_to(
            &[
                "BSD 2-Clause License",
                "Simplified BSD License",
                "BSD-2-Clause",
            ],
            &["BSD-2-Clause"],
        );
    }

    /// GPL/LGPL/AGPL free text never disambiguates `-only` from `-or-later`, so every
    /// variant normalizes to all three forms (module docs) — this also proves LGPL/AGPL
    /// are never matched by the plain GPL entries.
    #[test]
    fn normalizes_gpl_2_0_variants_without_confusing_lgpl() {
        assert_all_normalize_to(
            &[
                "GNU General Public License v2",
                "GNU General Public License v2.0",
                "GPL-2.0",
                "GPLv2",
            ],
            &["GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"],
        );
        assert_all_normalize_to(
            &["GNU Lesser General Public License v2.1", "LGPL-2.1"],
            &["LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"],
        );
    }

    #[test]
    fn normalizes_gpl_3_0_variants_without_confusing_lgpl_or_agpl() {
        assert_all_normalize_to(
            &[
                "GNU General Public License v3",
                "GNU General Public License v3.0",
                "GPL-3.0",
                "GPLv3",
            ],
            &["GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"],
        );
        assert_all_normalize_to(
            &["GNU Lesser General Public License v3", "LGPL-3.0"],
            &["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"],
        );
        assert_all_normalize_to(
            &["GNU Affero General Public License v3", "AGPL-3.0"],
            &["AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"],
        );
    }

    /// The classpath-exception form must never collapse into the plain GPL-2.0 family
    /// (issue #679 critic S3 caution) — it is a distinct, more permissive SPDX id.
    #[test]
    fn normalizes_gpl_2_0_classpath_exception_as_a_distinct_id() {
        assert_all_normalize_to(
            &["GPL2 w/ CPE", "GPL-2.0-with-classpath-exception"],
            &["GPL-2.0-with-classpath-exception"],
        );
        assert_ne!(
            normalize_pom_license_name("GPL2 w/ CPE"),
            normalize_pom_license_name("GPLv2")
        );
    }

    #[test]
    fn normalizes_epl_variants() {
        assert_all_normalize_to(
            &[
                "Eclipse Public License - v 1.0",
                "Eclipse Public License 1.0",
                "EPL-1.0",
            ],
            &["EPL-1.0"],
        );
        assert_all_normalize_to(
            &[
                "Eclipse Public License - v 2.0",
                "Eclipse Public License v2.0",
                "Eclipse Public License 2.0",
                "EPL-2.0",
            ],
            &["EPL-2.0"],
        );
    }

    #[test]
    fn normalizes_mpl_variants() {
        assert_all_normalize_to(
            &[
                "Mozilla Public License 2.0",
                "Mozilla Public License Version 2.0",
                "MPL-2.0",
            ],
            &["MPL-2.0"],
        );
        assert_all_normalize_to(&["Mozilla Public License 1.1", "MPL-1.1"], &["MPL-1.1"]);
    }

    #[test]
    fn normalizes_isc_variants() {
        assert_all_normalize_to(&["ISC License", "ISC"], &["ISC"]);
    }

    #[test]
    fn normalizes_cddl_and_dual_classpath_license() {
        assert_all_normalize_to(
            &[
                "Common Development and Distribution License (CDDL) v1.0",
                "CDDL 1.0",
            ],
            &["CDDL-1.0"],
        );
        assert_all_normalize_to(&["CDDL 1.1"], &["CDDL-1.1"]);
        assert_all_normalize_to(
            &["CDDL + GPLv2 with classpath exception"],
            &["CDDL-1.1", "GPL-2.0-with-classpath-exception"],
        );
    }

    #[test]
    fn normalize_is_case_insensitive_and_whitespace_collapsing() {
        assert_eq!(
            normalize_pom_license_name("mit license"),
            vec!["MIT".to_string()]
        );
        assert_eq!(
            normalize_pom_license_name("  Apache   License,  Version 2.0  "),
            vec!["Apache-2.0".to_string()]
        );
    }

    /// A POM sometimes uses the bare SPDX id itself as the free-text name — not in the
    /// table, but syntactically SPDX-shaped and version-bearing, so it passes through.
    #[test]
    fn already_spdx_shaped_free_text_passes_through() {
        for id in [
            "SSPL-1.0",
            "BUSL-1.1",
            "EUPL-1.2",
            "GPL-3.0-or-later",
            "GPL-2.0-only",
        ] {
            assert_eq!(
                normalize_pom_license_name(id),
                vec![id.to_string()],
                "id: {id}"
            );
        }
    }

    /// Issue #679 security S1: a bare, version-less term is genuinely ambiguous (which
    /// GPL/BSD/Apache version?) and must never pass through even though it satisfies the
    /// SPDX charset check.
    #[test]
    fn bare_versionless_terms_never_pass_through() {
        for term in ["GPL", "BSD", "Apache", "MPL"] {
            assert!(normalize_pom_license_name(term).is_empty(), "term: {term}");
        }
    }

    #[test]
    fn unrecognized_free_text_fails_closed() {
        assert!(normalize_pom_license_name("Some Bespoke Corporate License").is_empty());
        assert!(normalize_pom_license_name("").is_empty());
    }

    /// Issue #679 security S3: an oversized raw value is rejected before
    /// `collapse_whitespace` ever allocates, regardless of content.
    #[test]
    fn oversized_raw_value_is_rejected_before_collapsing() {
        let oversized = format!("{}Apache-2.0", " ".repeat(MAX_POM_LICENSE_NAME_RAW_CHARS));
        assert!(oversized.len() > MAX_POM_LICENSE_NAME_RAW_CHARS);
        assert!(normalize_pom_license_name(&oversized).is_empty());
    }

    #[test]
    fn normalize_names_drops_only_unmatched_entries() {
        let normalized = normalize_pom_license_names(&[
            "The Apache Software License, Version 2.0".to_string(),
            "Some Bespoke Corporate License".to_string(),
            "MIT License".to_string(),
        ]);
        assert_eq!(
            normalized,
            vec!["Apache-2.0".to_string(), "MIT".to_string()]
        );
    }

    #[test]
    fn normalize_names_all_unmatched_yields_empty() {
        assert!(normalize_pom_license_names(&["Unknown License Text".to_string()]).is_empty());
    }

    #[test]
    fn normalize_names_deduplicates_overlapping_ids() {
        // Both entries normalize to the same GPL-3.0 family — the merged result must
        // not repeat any id.
        let normalized = normalize_pom_license_names(&["GPL-3.0".to_string(), "GPLv3".to_string()]);
        assert_eq!(
            normalized,
            vec![
                "GPL-3.0".to_string(),
                "GPL-3.0-only".to_string(),
                "GPL-3.0-or-later".to_string()
            ]
        );
    }

    #[test]
    fn normalize_names_checked_reports_full_coverage() {
        let (ids, all_matched) = normalize_pom_license_names_checked(&["MIT License".to_string()]);
        assert_eq!(ids, vec!["MIT".to_string()]);
        assert!(all_matched);
    }

    #[test]
    fn normalize_names_checked_reports_partial_coverage() {
        let (ids, all_matched) = normalize_pom_license_names_checked(&[
            "MIT License".to_string(),
            "Some Bespoke Corporate License".to_string(),
        ]);
        assert_eq!(ids, vec!["MIT".to_string()]);
        assert!(!all_matched);
    }

    #[test]
    fn normalize_names_checked_reports_zero_coverage() {
        let (ids, all_matched) =
            normalize_pom_license_names_checked(&["Some Bespoke Corporate License".to_string()]);
        assert!(ids.is_empty());
        assert!(!all_matched);
    }

    /// Review nitpick: `normalize_pom_license_names` must stay a thin wrapper over the
    /// checked variant, not a second independent implementation that could drift.
    #[test]
    fn normalize_names_agrees_with_checked_variant() {
        let raw = vec!["MIT License".to_string(), "GPLv3".to_string()];
        assert_eq!(
            normalize_pom_license_names(&raw),
            normalize_pom_license_names_checked(&raw).0
        );
    }

    /// Issue #679 critic M3: guards against a future case-insensitive duplicate table
    /// key silently shadowing an earlier (correct) mapping — `find` takes the first
    /// match, so a duplicate key would make the second entry dead code.
    #[test]
    fn known_pom_license_names_has_no_duplicate_keys() {
        for (i, (key_a, _)) in KNOWN_POM_LICENSE_NAMES.iter().enumerate() {
            for (key_b, _) in &KNOWN_POM_LICENSE_NAMES[i + 1..] {
                assert!(
                    !key_a.eq_ignore_ascii_case(key_b),
                    "duplicate (case-insensitive) table key: {key_a:?}"
                );
            }
        }
    }

    /// Code-review follow-up: `ids_are_synonyms` assumes every synonym-set entry in
    /// `KNOWN_POM_LICENSE_NAMES` lists its base SPDX id first, with every later id
    /// formed by appending an `-only`/`-or-later` suffix to it —
    /// `resolve_license_entries_for_display` relies on that ordering to collapse a
    /// synonym set to one id for hover (issue #687 S2) without also collapsing the
    /// table's genuinely disjunctive entry. This walks the whole table and locks the
    /// classification in, so a future entry added base-id-last (or a new disjunctive
    /// entry not added to `DISJUNCTIVE_KEYS` below) fails loudly here instead of
    /// silently breaking hover's collapse/no-collapse decision.
    #[test]
    fn known_pom_license_names_synonym_entries_list_base_id_first() {
        // The table's only entry naming two genuinely unrelated licenses (not
        // convention-ambiguous synonyms of one) — see that entry's own comment.
        const DISJUNCTIVE_KEYS: &[&str] = &["CDDL + GPLv2 with classpath exception"];

        for &(key, ids) in KNOWN_POM_LICENSE_NAMES {
            let ids_owned: Vec<String> = ids.iter().map(|id| (*id).to_string()).collect();
            let expected_disjunctive = DISJUNCTIVE_KEYS.contains(&key);
            assert_eq!(
                ids_are_synonyms(&ids_owned),
                !expected_disjunctive,
                "{key:?} -> {ids:?}: expected {}, ids_are_synonyms said {}",
                if expected_disjunctive {
                    "disjunctive (base id not first, or a new genuine OR)"
                } else {
                    "synonyms (base id first)"
                },
                ids_are_synonyms(&ids_owned)
            );
        }
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
