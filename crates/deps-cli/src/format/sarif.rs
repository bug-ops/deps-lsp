//! SARIF 2.1.0 output (FR-008, US-002) for GitHub code scanning and other SARIF consumers.
//!
//! Each distinct SARIF rule id becomes one `tool.driver.rules` entry, and each
//! [`CheckFinding`] becomes one `run.results` entry with its LSP [`Range`] translated to a
//! SARIF physical location region. A rule id is [`CheckFinding::code`] when the finding is
//! [`Category::Vulnerable`] *and* `code` passes [`deps_core::osv::is_valid_osv_id`]
//! (`is_advisory_finding`), falling back to its [`Category`] wire token otherwise (issue
//! #1075, spec 062 review S3: FR-008 says "each existing diagnostic code becomes a SARIF rule
//! id"; issue #1077 review #2: `code` is never trusted as a rule id/name verbatim without that
//! validity check). A vulnerability finding's `code` is its OSV advisory id
//! (`RUSTSEC-...`/`GHSA-...`), so distinct advisories now produce distinct rules instead of
//! collapsing into one shared `vulnerable` rule. `code` is deliberately *not* used for the
//! other coded categories (`Unsatisfiable`/`License`/`Deprecated`/`MutableRefPin`): their
//! diagnostic-code constants are already 1:1 with a `Category` (no finer granularity to gain),
//! and `MutableRefPin` alone has two internal code constants (GitHub Actions' and GitLab CI's)
//! that would otherwise fragment one category into two rules for zero benefit (issue #1077
//! S1 review). `Outdated`/`Yanked`/`Other` findings, and the "+N more advisories" overflow
//! line, carry no code at all and always use the category token.
//!
//! Rule metadata (issue #1077): every rule gets a `shortDescription` from
//! [`Category::description`]. An advisory rule additionally gets:
//! - `helpUri`, preferring [`CheckFinding::advisory_url`] — the authoritative
//!   `https://osv.dev/vulnerability/{id}` page OSV itself gave the diagnostic — and falling
//!   back to [`deps_core::osv::validated_osv_url`] (the same validated-construction path
//!   `deps-core`'s own OSV client uses for [`deps_core::osv::Advisory::url`]) only when that is
//!   unavailable;
//! - `fullDescription`, built from the finding's own message, which already embeds the
//!   advisory's OSV-provided summary (`push_vulnerability_diagnostics`);
//! - `properties["security-severity"]`, from `security_severity_score`, when
//!   [`CheckFinding::advisory_severity`] names a graded bucket.
//!
//! A category-only rule gets none of the three: it has no natural per-rule URL, no
//! single-advisory description, and no per-advisory severity to report.
//!
//! Each result also carries a `partialFingerprints` entry (`collect_result_contexts`, issue
//! #1077) derived from (manifest path, percent-encoded dependency identity, percent-encoded
//! rule id, an occurrence ordinal) — deliberately excluding the finding's range, so an
//! unrelated line shift elsewhere in the manifest does not change it and make GitHub treat an
//! existing alert as new. See that function's doc for why percent-encoding and the ordinal are
//! both necessary (issue #1077 S2 review: a raw `|` join can collide across components, and
//! same-manifest/same-dependency/same-rule findings — e.g. one package declared in both
//! `[dependencies]` and `[dev-dependencies]` — would otherwise collapse onto one fingerprint).
//!
//! `run.automationDetails.id` (`automation_id`, issue #1077) disambiguates repeated SARIF
//! uploads for the same commit — see that function's doc for the category/run-id split GitHub
//! expects it to follow.

use crate::report::{Category, CheckFinding, CheckReport};
use deps_core::osv::{VulnSeverity, is_valid_osv_id, validated_osv_url};
use serde_sarif::sarif::{
    ArtifactLocation, Location, MultiformatMessageString, PhysicalLocation, PropertyBag, Region,
    ReportingDescriptor, Result as SarifResult, ResultLevel, Run, RunAutomationDetails, SCHEMA_URL,
    Sarif, Tool, ToolComponent, Version,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Range};

/// Builds the [`Sarif`] document for `report`.
///
/// # Examples
///
/// ```
/// use deps_cli::format::sarif::to_sarif;
/// use deps_cli::report::CheckReport;
///
/// let sarif = to_sarif(&CheckReport::default());
/// assert_eq!(sarif.runs.len(), 1);
/// assert!(sarif.runs[0].results.as_ref().unwrap().is_empty());
/// ```
#[must_use]
pub fn to_sarif(report: &CheckReport) -> Sarif {
    let contexts = collect_result_contexts(&report.findings);
    let rule_meta = collect_rule_meta(&report.findings, &contexts);
    let rule_indices: HashMap<&str, usize> = rule_meta
        .keys()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();

    let rules: Vec<ReportingDescriptor> = rule_meta
        .iter()
        .map(|(id, meta)| build_rule_descriptor(id, meta))
        .collect();

    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .zip(&contexts)
        .map(|(finding, context)| {
            let rule_index = rule_indices
                .get(context.rule_id.as_str())
                .copied()
                .unwrap_or_default();
            to_sarif_result(finding, rule_index, context)
        })
        .collect();

    let driver = ToolComponent::builder()
        .name("deps-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .information_uri(env!("CARGO_PKG_REPOSITORY"))
        .rules(rules)
        .build();

    let automation_details = RunAutomationDetails::builder().id(automation_id()).build();

    let run = Run::builder()
        .tool(Tool::from(driver))
        .results(results)
        .automation_details(automation_details)
        .build();

    Sarif::builder()
        .version(Version::V2_1_0.to_string())
        .schema(SCHEMA_URL)
        .runs(vec![run])
        .build()
}

/// Whether `finding` is eligible for an advisory-keyed rule: [`Category::Vulnerable`] with a
/// `code` that also passes [`is_valid_osv_id`] (issue #1077 review #2) — a `code` that fails
/// the allowlist falls back to the plain category-token rule instead of being trusted as a
/// rule id/name verbatim. `classify` (`crate::report`) documents that its "any unrecognized
/// diagnostic code -> `Vulnerable`" fallback is only sound as long as the known-code list it
/// maintains stays exhaustive; this is the independent, defense-in-depth check on the `code`
/// value itself for exactly the case where that fallback let something unexpected through.
///
/// This is the single source of truth both [`sarif_rule_id`] and [`collect_rule_meta`] use —
/// carried into [`RuleMeta::is_advisory`] rather than re-derived later by comparing the rule id
/// string against the category token (issue #1077 review #3): a *valid* advisory id that
/// happens to equal a category token verbatim (e.g. an OSV id literally spelled `"license"` —
/// contrived, but within the allowlist) would otherwise silently misclassify as category-only,
/// dropping `helpUri`/`fullDescription`/`security-severity` for a finding that legitimately
/// earned them.
fn is_advisory_finding(finding: &CheckFinding) -> bool {
    finding.category == Category::Vulnerable && finding.code.as_deref().is_some_and(is_valid_osv_id)
}

/// The SARIF rule id `finding` belongs to — see the module doc for the code-first,
/// category-fallback rule, and [`is_advisory_finding`] for exactly when `code` is trusted.
fn sarif_rule_id(finding: &CheckFinding) -> &str {
    if is_advisory_finding(finding) {
        // `is_advisory_finding` already confirmed `finding.code` is `Some`.
        finding
            .code
            .as_deref()
            .unwrap_or_else(|| finding.category.as_str())
    } else {
        finding.category.as_str()
    }
}

/// The data [`build_rule_descriptor`] needs for one distinct rule id, collected from whichever
/// [`CheckFinding`] first produced that id — see [`collect_rule_meta`] for why "first wins" is
/// deliberate here.
struct RuleMeta<'a> {
    category: Category,
    /// See [`is_advisory_finding`] — carried from the finding that first produced this rule id,
    /// not re-derived from the id string in [`build_rule_descriptor`].
    is_advisory: bool,
    message: &'a str,
    advisory_url: Option<String>,
    advisory_severity: Option<VulnSeverity>,
}

/// Collects one [`RuleMeta`] per distinct rule id across `findings` (reusing each finding's
/// already-computed [`ResultContext::rule_id`] rather than recomputing [`sarif_rule_id`] a
/// second time), keyed — and thus sorted, for a deterministic `tool.driver.rules` order — by
/// the rule id itself.
///
/// "First finding for a given rule id wins" (`or_insert_with`, issue #1077 S4 review) is a
/// deliberate, not incidental, choice: every finding sharing one rule id is expected to
/// describe the same advisory (an advisory-keyed rule) or the same kind of issue (a
/// category-only rule), so the first one's message/url/severity is as representative as any
/// other — this is rule-*level* metadata, not a per-result field, and `run.results[].message`
/// (set in [`to_sarif_result`], one per finding) still carries each finding's own text
/// regardless of which one seeded the rule description.
fn collect_rule_meta<'a>(
    findings: &'a [CheckFinding],
    contexts: &[ResultContext],
) -> BTreeMap<String, RuleMeta<'a>> {
    let mut rules = BTreeMap::new();
    for (finding, context) in findings.iter().zip(contexts) {
        rules
            .entry(context.rule_id.clone())
            .or_insert_with(|| RuleMeta {
                category: finding.category,
                is_advisory: is_advisory_finding(finding),
                message: finding.message.as_str(),
                advisory_url: finding.advisory_url.clone(),
                advisory_severity: finding.advisory_severity,
            });
    }
    rules
}

/// Builds `id`'s `tool.driver.rules` entry from `meta` — see the module doc for which fields a
/// category-only rule gets versus an advisory rule. Constructed as a plain struct literal
/// (every field is `pub`, and the type is not `#[non_exhaustive]`) rather than through
/// [`ReportingDescriptor::builder`]: the builder's per-field type-state generics make it
/// impossible to assign the same builder variable conditionally across an `if`/`else`, and
/// this rule has three independent optional pieces (`help_uri`, `full_description`,
/// `properties`) to fill in.
fn build_rule_descriptor(id: &str, meta: &RuleMeta<'_>) -> ReportingDescriptor {
    let is_advisory = meta.is_advisory;

    let short_description = MultiformatMessageString::builder()
        .text(meta.category.description())
        .build();

    let (help_uri, full_description) = if is_advisory {
        let help_uri = meta.advisory_url.clone().or_else(|| validated_osv_url(id));
        let full_description = MultiformatMessageString::builder()
            .text(meta.message.to_string())
            .build();
        (help_uri, Some(full_description))
    } else {
        (None, None)
    };

    let properties = if is_advisory {
        meta.advisory_severity
            .and_then(security_severity_score)
            .map(|score| {
                let mut additional_properties = BTreeMap::new();
                additional_properties.insert(
                    "security-severity".to_string(),
                    serde_json::Value::String(score.to_string()),
                );
                PropertyBag::builder()
                    .additional_properties(additional_properties)
                    .build()
            })
    } else {
        None
    };

    // An advisory rule's `name` is the advisory id itself (e.g. `RUSTSEC-2020-0071`) rather
    // than the shared `Category::as_str()` token every advisory rule would otherwise carry
    // identically, which would make `name` useless for telling two advisory rules apart.
    let name = if is_advisory {
        id.to_string()
    } else {
        meta.category.as_str().to_string()
    };

    ReportingDescriptor {
        default_configuration: None,
        deprecated_guids: None,
        deprecated_ids: None,
        deprecated_names: None,
        full_description,
        guid: None,
        help: None,
        help_uri,
        id: id.to_string(),
        message_strings: None,
        name: Some(name),
        properties,
        relationships: None,
        short_description: Some(short_description),
    }
}

/// Maps a `deps-core` [`VulnSeverity`] bucket to a representative `security-severity` string
/// (issue #1077 C2 review), using the midpoint of GitHub's own documented CVSS bands for code
/// scanning (critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9).
///
/// `VulnSeverity` is itself a bucket `deps-core` already derived from real advisory data, not
/// a per-advisory CVSS score (`deps_core::osv::Advisory::cvss_vector` is a raw vector string
/// this crate has no parser for) — this is the closest honest representative value, never a
/// fabricated precise score. [`VulnSeverity::Unknown`] ("no severity field was present or
/// recognized") and [`VulnSeverity::Informational`] ("this is a maintenance notice, not a
/// vulnerability") return `None`: neither should be dressed up as a numeric severity that
/// GitHub's alert sort would then treat as graded fact.
fn security_severity_score(severity: VulnSeverity) -> Option<&'static str> {
    match severity {
        VulnSeverity::Malicious => Some("10.0"),
        VulnSeverity::Critical => Some("9.5"),
        VulnSeverity::High => Some("8.0"),
        VulnSeverity::Medium => Some("5.5"),
        VulnSeverity::Low => Some("2.0"),
        VulnSeverity::Unknown | VulnSeverity::Informational => None,
        // `VulnSeverity` is `#[non_exhaustive]`: a bucket this crate does not yet recognize
        // must never guess a numeric score for it either.
        _ => None,
    }
}

/// `run.automationDetails.id` — disambiguates repeated SARIF uploads for the same commit
/// (issue #1077). GitHub's own code-scanning ingestion splits this id at the *last* `/`:
/// everything before it is the "category" (identifies *which* analysis line a run belongs to
/// — must stay stable across repeated runs of the same workflow+job), everything after is the
/// "run id" (must vary, so a later upload supersedes an earlier one instead of accumulating a
/// forever-open duplicate alert). Reading `GITHUB_WORKFLOW`/`GITHUB_JOB` (stable per
/// workflow+job, ambient in every Actions job environment) for the category and
/// `GITHUB_RUN_ID`-`GITHUB_RUN_ATTEMPT` (varies every run/retry) for the run id keeps that
/// split correct — issue #1077 C1 review: an earlier version of this function put the run id
/// in the *middle* (`deps-cli/{run_id}/{attempt}`), which made the category itself vary every
/// run and meant no upload ever superseded a previous one. A direct CLI invocation outside
/// Actions has no such context and falls back to the fixed `"deps-cli/local"` — category
/// `"deps-cli"`, run `"local"` — so repeated local runs intentionally share one category too
/// (do not add a timestamp/PID here: the whole point is for a later local run to supersede an
/// earlier one, the same as in Actions).
fn automation_id() -> String {
    automation_id_with_env(|name| std::env::var(name).ok())
}

/// [`automation_id`], but reading environment variables through `env` instead of
/// [`std::env::var`] directly — lets tests inject a fake environment instead of mutating the
/// real process environment (this workspace forbids `unsafe`, and Rust 2024 made
/// `std::env::set_var`/`remove_var` `unsafe fn`s, so a test cannot do that mutation at all).
fn automation_id_with_env(env: impl Fn(&str) -> Option<String>) -> String {
    let Some(run_id) = env("GITHUB_RUN_ID") else {
        return "deps-cli/local".to_string();
    };
    let workflow = env("GITHUB_WORKFLOW").unwrap_or_default();
    let job = env("GITHUB_JOB").unwrap_or_default();
    let run = match env("GITHUB_RUN_ATTEMPT") {
        Some(attempt) => format!("{run_id}-{attempt}"),
        None => run_id,
    };
    format!("deps-cli/{workflow}/{job}/{run}")
}

/// Per-finding data derived once up front rather than recomputed per field or per call site:
/// [`manifest_uri`] is otherwise built twice per finding (once for `artifactLocation.uri`,
/// once inside the fingerprint), and [`sarif_rule_id`] is otherwise recomputed independently
/// in [`collect_rule_meta`], here, and in [`to_sarif`]'s results-mapping step.
struct ResultContext {
    manifest_uri: String,
    rule_id: String,
    fingerprint: String,
}

/// Builds one [`ResultContext`] per finding, in `findings` order.
///
/// The fingerprint is (manifest path, percent-encoded dependency identity, percent-encoded
/// rule id, an occurrence ordinal) — deliberately excluding the finding's own range, so an
/// unrelated line shift elsewhere in the manifest does not change it and make GitHub treat an
/// existing alert as new (the whole point of `partialFingerprints`).
///
/// Percent-encoding the dependency and rule-id components (`manifest_uri` already encodes the
/// manifest path) closes a raw-`|`-delimiter collision: without it, a dependency literally
/// named e.g. `serde|outdated` could produce the same joined string as a different
/// (dependency, rule) pair (issue #1077 security review).
///
/// The ordinal — this occurrence's 0-based rank among every finding sharing the same
/// (manifest, dependency, rule id) triple, in `findings` order — disambiguates
/// same-manifest/same-dependency/same-rule findings that would otherwise collapse onto one
/// fingerprint (issue #1077 S2 review, corroborated independently by the critic and security
/// reviews): two document-level [`Category::Other`] notices with no dependency (e.g. an
/// offline notice and a truncation notice), or the same package declared in both
/// `[dependencies]` and `[dev-dependencies]` (`deps-core`'s #394 S2 deliberately keeps such
/// occurrences distinct; collapsing them here would silently undo that). It is intentionally
/// not the finding's range: an ordinal only shifts when an occurrence of the *same*
/// (manifest, dependency, rule) triple is added, removed, or reordered — a far narrower and
/// rarer edit than "any line shifted anywhere in the file."
fn collect_result_contexts(findings: &[CheckFinding]) -> Vec<ResultContext> {
    // Keyed by (`manifest_uri` — a fresh local `String` each iteration, so this map must own
    // its own copy; `dependency`/`rule_id` — both borrowed straight from `finding`, which
    // outlives this whole function, so no clone is needed just to build the ordinal-counting
    // key (issue #1077 review #8)).
    let mut seen: HashMap<(String, &str, &str), usize> = HashMap::new();
    findings
        .iter()
        .map(|finding| {
            let manifest = manifest_uri(&finding.manifest_path);
            let dependency = finding.dependency_name.as_deref().unwrap_or("");
            let rule_id = sarif_rule_id(finding);

            let counter = seen
                .entry((manifest.clone(), dependency, rule_id))
                .or_insert(0);
            let ordinal = *counter;
            *counter += 1;

            let fingerprint = format!(
                "{manifest}|{}|{}|{ordinal}",
                urlencoding::encode(dependency),
                urlencoding::encode(rule_id),
            );

            ResultContext {
                manifest_uri: manifest,
                rule_id: rule_id.to_string(),
                fingerprint,
            }
        })
        .collect()
}

/// Builds one `run.results` entry for `finding`, whose rule is at `rule_index` within
/// [`to_sarif`]'s `tool.driver.rules`, using `context` for the fields
/// [`collect_result_contexts`] already computed once (including `context.rule_id` itself).
fn to_sarif_result(
    finding: &CheckFinding,
    rule_index: usize,
    context: &ResultContext,
) -> SarifResult {
    let region = to_sarif_region(finding.range);
    let artifact_location = ArtifactLocation::builder()
        .uri(context.manifest_uri.as_str())
        .build();
    let physical_location = PhysicalLocation::builder()
        .artifact_location(artifact_location)
        .region(region)
        .build();
    let location = Location::builder()
        .physical_location(physical_location)
        .build();

    let mut partial_fingerprints = BTreeMap::new();
    partial_fingerprints.insert("depsCli/v1".to_string(), context.fingerprint.clone());

    SarifResult::builder()
        .rule_id(context.rule_id.as_str())
        .rule_index(i64::try_from(rule_index).unwrap_or(i64::MAX))
        .message(finding.message.as_str())
        .locations(vec![location])
        .level(to_result_level(finding.severity))
        .partial_fingerprints(partial_fingerprints)
        .build()
}

/// Renders `path` as a percent-encoded, `/`-separated, always-relative SARIF
/// `artifactLocation.uri` (RFC 3986 URI-reference).
///
/// `manifest_path.display().to_string()` is not safe to use directly here (spec 062 review
/// S2/B3): it can emit a literal `#`, which a SARIF/URI consumer reads as a fragment
/// separator rather than part of the path (a directory named `a b#c` would silently point a
/// consumer at a different, wrong location); a literal space, which is not valid in a bare
/// URI-reference; and, on Windows, `\`-separated components, which are not URI path
/// separators at all. Building the URI from [`Path::components`] instead of the platform's
/// own `Display` avoids all three: each component is percent-encoded independently and
/// joined with `/`, regardless of the host platform's native separator.
///
/// `Component::RootDir`/`Component::Prefix` (a leading `/` on Unix, or a `C:`-style drive
/// prefix on Windows) are dropped rather than encoded (spec 062 review R1): `CheckFinding`
/// carries an absolute `manifest_path` whenever a manifest was named as an explicit file
/// argument rather than discovered under a walked directory root (`walk::walk`'s
/// `root.is_file()` branch passes the path through unchanged) — this formatter has no walked
/// root to relativize against, so it drops the absolute-path marker rather than either
/// leaking local machine path structure into a document meant for GitHub's Security tab, or
/// emitting a URI that `Path::is_absolute()` still reports as absolute.
fn manifest_uri(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => {
                Some(urlencoding::encode(&part.to_string_lossy()).into_owned())
            }
            Component::CurDir => Some(".".to_string()),
            Component::ParentDir => Some("..".to_string()),
            Component::RootDir | Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Translates an LSP [`Range`] (zero-based line/character) into a SARIF [`Region`]
/// (one-based line/column, per the SARIF 2.1.0 spec).
fn to_sarif_region(range: Range) -> Region {
    Region::builder()
        .start_line(i64::from(range.start.line) + 1)
        .start_column(i64::from(range.start.character) + 1)
        .end_line(i64::from(range.end.line) + 1)
        .end_column(i64::from(range.end.character) + 1)
        .build()
}

/// Maps an LSP [`DiagnosticSeverity`] to the closest SARIF [`ResultLevel`].
fn to_result_level(severity: DiagnosticSeverity) -> ResultLevel {
    match severity {
        DiagnosticSeverity::ERROR => ResultLevel::Error,
        DiagnosticSeverity::WARNING => ResultLevel::Warning,
        DiagnosticSeverity::INFORMATION | DiagnosticSeverity::HINT => ResultLevel::Note,
        _ => ResultLevel::None,
    }
}

/// Renders `report` as a pretty-printed SARIF 2.1.0 JSON string.
///
/// # Errors
///
/// Returns an error only if [`Sarif`]'s `Serialize` impl fails, which does not happen for the
/// plain-data document [`to_sarif`] builds.
pub fn render(report: &CheckReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&to_sarif(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::EcosystemId;
    use std::path::PathBuf;
    use tower_lsp_server::ls_types::Position;

    fn finding(category: Category, severity: DiagnosticSeverity) -> CheckFinding {
        CheckFinding {
            ecosystem: EcosystemId::Cargo,
            manifest_path: PathBuf::from("Cargo.toml"),
            dependency_name: Some("serde".to_string()),
            requirement: Some("1.0".to_string()),
            category,
            code: None,
            advisory_url: None,
            advisory_severity: None,
            severity,
            range: Range::new(Position::new(4, 0), Position::new(4, 10)),
            message: "Newer version available: 1.1.0".to_string(),
        }
    }

    fn finding_with_code(category: Category, code: &str, message: &str) -> CheckFinding {
        CheckFinding {
            code: Some(code.to_string()),
            message: message.to_string(),
            ..finding(category, DiagnosticSeverity::WARNING)
        }
    }

    #[test]
    fn test_to_sarif_empty_report_has_one_empty_run() {
        let sarif = to_sarif(&CheckReport::default());
        assert_eq!(sarif.runs.len(), 1);
        assert!(sarif.runs[0].results.as_ref().unwrap().is_empty());
        assert!(sarif.runs[0].tool.driver.rules.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_to_sarif_sets_tool_driver_name() {
        let sarif = to_sarif(&CheckReport::default());
        assert_eq!(sarif.runs[0].tool.driver.name, "deps-cli");
    }

    #[test]
    fn test_to_sarif_rule_id_matches_category_token() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "outdated");

        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].rule_id.as_deref(), Some("outdated"));
        assert_eq!(results[0].rule_index, Some(0));
    }

    #[test]
    fn test_to_sarif_deduplicates_rules_across_findings() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Outdated, DiagnosticSeverity::HINT),
                finding(Category::Outdated, DiagnosticSeverity::HINT),
                finding(Category::Vulnerable, DiagnosticSeverity::ERROR),
            ],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_to_sarif_translates_range_to_one_based_region() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let sarif = to_sarif(&report);
        let locations = sarif.runs[0].results.as_ref().unwrap()[0]
            .locations
            .as_ref()
            .unwrap();
        let region = locations[0]
            .physical_location
            .as_ref()
            .unwrap()
            .region
            .as_ref()
            .unwrap();
        assert_eq!(region.start_line, Some(5));
        assert_eq!(region.start_column, Some(1));
        assert_eq!(region.end_line, Some(5));
        assert_eq!(region.end_column, Some(11));
    }

    #[test]
    fn test_to_sarif_artifact_uri_matches_manifest_path() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let sarif = to_sarif(&report);
        let locations = sarif.runs[0].results.as_ref().unwrap()[0]
            .locations
            .as_ref()
            .unwrap();
        let artifact_location = locations[0]
            .physical_location
            .as_ref()
            .unwrap()
            .artifact_location
            .as_ref()
            .unwrap();
        assert_eq!(artifact_location.uri.as_deref(), Some("Cargo.toml"));
    }

    #[test]
    fn test_manifest_uri_percent_encodes_hash_and_space() {
        let path = Path::new("a b#c%20d").join("Cargo.toml");
        let uri = manifest_uri(&path);
        assert_eq!(uri, "a%20b%23c%2520d/Cargo.toml");
        assert!(
            !uri.contains('#'),
            "a literal '#' would be read as a URI fragment separator"
        );
        assert!(
            !uri.contains(' '),
            "a literal space is not valid in a bare URI-reference"
        );
    }

    #[test]
    fn test_manifest_uri_joins_nested_components_with_forward_slash() {
        let path = Path::new("crates").join("deps-cli").join("Cargo.toml");
        assert_eq!(manifest_uri(&path), "crates/deps-cli/Cargo.toml");
    }

    // `/tmp/...` has a `RootDir` component but no `Prefix`, so `Path::is_absolute()` on
    // Windows reports it as *not* absolute (Windows requires a drive prefix) — hence the
    // separate `cfg(windows)` fixture below using a drive-rooted path instead of gating this
    // whole test to `cfg(unix)` and losing Windows coverage of the fix (spec 062 review R1).
    #[cfg(unix)]
    #[test]
    fn test_manifest_uri_drops_leading_root_dir_for_an_absolute_unix_path() {
        let path = Path::new("/tmp/deps-cli-manual-test/Cargo.toml");
        assert!(
            path.is_absolute(),
            "test setup bug: fixture path must be absolute"
        );
        let uri = manifest_uri(path);
        assert_eq!(uri, "tmp/deps-cli-manual-test/Cargo.toml");
        assert!(
            !Path::new(&uri).is_absolute(),
            "an absolute manifest_path must not leak into an absolute artifactLocation.uri \
             (spec 062 review R1)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_manifest_uri_drops_leading_prefix_and_root_dir_for_an_absolute_windows_path() {
        let path = Path::new(r"C:\tmp\deps-cli-manual-test\Cargo.toml");
        assert!(
            path.is_absolute(),
            "test setup bug: fixture path must be absolute"
        );
        let uri = manifest_uri(path);
        assert_eq!(uri, "tmp/deps-cli-manual-test/Cargo.toml");
        assert!(
            !Path::new(&uri).is_absolute(),
            "an absolute manifest_path must not leak into an absolute artifactLocation.uri \
             (spec 062 review R1)"
        );
    }

    #[test]
    fn test_to_sarif_artifact_uri_of_nested_path_has_no_fragment_character() {
        let mut finding = finding(Category::Outdated, DiagnosticSeverity::HINT);
        finding.manifest_path = Path::new("a b#c").join("Cargo.toml");
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let locations = sarif.runs[0].results.as_ref().unwrap()[0]
            .locations
            .as_ref()
            .unwrap();
        let uri = locations[0]
            .physical_location
            .as_ref()
            .unwrap()
            .artifact_location
            .as_ref()
            .unwrap()
            .uri
            .as_ref()
            .unwrap();
        assert!(!uri.contains('#'));
        assert!(!uri.contains(' '));
    }

    #[test]
    fn test_to_sarif_severity_level_mapping() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Vulnerable, DiagnosticSeverity::ERROR),
                finding(Category::License, DiagnosticSeverity::WARNING),
                finding(Category::Deprecated, DiagnosticSeverity::HINT),
            ],
        };
        let sarif = to_sarif(&report);
        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].level, Some(ResultLevel::Error));
        assert_eq!(results[1].level, Some(ResultLevel::Warning));
        assert_eq!(results[2].level, Some(ResultLevel::Note));
    }

    #[test]
    fn test_render_round_trips_through_serde_json() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let rendered = render(&report).expect("render must succeed");
        let parsed: Sarif = serde_json::from_str(&rendered).expect("must round-trip");
        assert_eq!(parsed.version, to_sarif(&report).version);
    }

    /// Snapshot test (mirrors T022/T023's own coverage) pinning the exact SARIF document
    /// shape so a field rename or nesting change shows up as a snapshot diff.
    ///
    /// `automationDetails.id` is redacted: [`automation_id`] reads the real `GITHUB_RUN_ID`
    /// environment variable, which is set (to a different value every time) whenever this
    /// test itself runs inside GitHub Actions CI — an unredacted snapshot would then never
    /// match the value accepted locally.
    #[test]
    fn test_to_sarif_multi_category_snapshot() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Outdated, DiagnosticSeverity::HINT),
                finding(Category::Vulnerable, DiagnosticSeverity::ERROR),
            ],
        };
        insta::assert_json_snapshot!(to_sarif(&report), {
            ".runs[0].automationDetails.id" => "[automation_id]",
        });
    }

    #[test]
    fn test_to_sarif_rule_id_uses_code_when_present() {
        let report = CheckReport {
            findings: vec![finding_with_code(
                Category::Vulnerable,
                "RUSTSEC-2020-0071",
                "RUSTSEC-2020-0071: Potential segfault in the time crate",
            )],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "RUSTSEC-2020-0071");

        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].rule_id.as_deref(), Some("RUSTSEC-2020-0071"));
    }

    #[test]
    fn test_to_sarif_distinct_advisory_codes_produce_distinct_rules() {
        let report = CheckReport {
            findings: vec![
                finding_with_code(Category::Vulnerable, "RUSTSEC-2020-0071", "advisory A"),
                finding_with_code(Category::Vulnerable, "GHSA-xxxx-yyyy-zzzz", "advisory B"),
            ],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(
            rules.len(),
            2,
            "two distinct advisories must not collapse into one rule"
        );
    }

    #[test]
    fn test_to_sarif_advisory_overflow_line_falls_back_to_category_rule() {
        // The "+N more advisories" summary line is `Category::Vulnerable` but carries no
        // diagnostic code (`push_vulnerability_diagnostics` in `deps-core`), so it must still
        // fall back to the category-token rule rather than panicking or producing an empty id.
        let report = CheckReport {
            findings: vec![finding(
                Category::Vulnerable,
                DiagnosticSeverity::INFORMATION,
            )],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules[0].id, "vulnerable");
    }

    /// Regression test for issue #1077 S1 review: a coded finding in one of the four
    /// non-`Vulnerable` coded categories must still use the plain category-token rule id, not
    /// its (redundant, 1:1-with-category) diagnostic code — `code` is only meaningful rule-id
    /// material for `Vulnerable`.
    #[test]
    fn test_to_sarif_coded_non_vulnerable_finding_still_uses_category_rule_id() {
        let report = CheckReport {
            findings: vec![finding_with_code(
                Category::Unsatisfiable,
                "unsatisfiable-requirement",
                "no matching version",
            )],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "unsatisfiable");
        assert!(rules[0].help_uri.is_none());
        assert!(rules[0].full_description.is_none());

        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].rule_id.as_deref(), Some("unsatisfiable"));
    }

    /// Regression test for issue #1077 S1 review: `MutableRefPin` findings carry one of two
    /// distinct internal code constants (GitHub Actions' vs GitLab CI's) depending on their
    /// source ecosystem — both must still collapse into the one `mutable-ref` rule.
    #[test]
    fn test_to_sarif_mutable_ref_pin_does_not_split_on_differing_codes() {
        let report = CheckReport {
            findings: vec![
                finding_with_code(
                    Category::MutableRefPin,
                    "mutable-ref-pin",
                    "pinned to a tag",
                ),
                finding_with_code(
                    Category::MutableRefPin,
                    "gitlab-ci-mutable-ref-pin",
                    "pinned to a tag",
                ),
            ],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(
            rules.len(),
            1,
            "MutableRefPin's two internal code constants must not fragment one category into two rules"
        );
        assert_eq!(rules[0].id, "mutable-ref");
    }

    #[test]
    fn test_build_rule_descriptor_advisory_rule_has_help_uri_and_full_description() {
        let report = CheckReport {
            findings: vec![finding_with_code(
                Category::Vulnerable,
                "RUSTSEC-2020-0071",
                "RUSTSEC-2020-0071: Potential segfault in the time crate",
            )],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        assert_eq!(
            rule.help_uri.as_deref(),
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071")
        );
        assert_eq!(
            rule.full_description.as_ref().unwrap().text,
            "RUSTSEC-2020-0071: Potential segfault in the time crate"
        );
        assert_eq!(
            rule.short_description.as_ref().unwrap().text,
            Category::Vulnerable.description()
        );
        assert_eq!(rule.name.as_deref(), Some("RUSTSEC-2020-0071"));
    }

    #[test]
    fn test_build_rule_descriptor_category_only_rule_has_no_help_uri_or_full_description() {
        let report = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        assert!(
            rule.help_uri.is_none(),
            "a category-only rule has no natural URL to fabricate one for"
        );
        assert!(rule.full_description.is_none());
        assert!(rule.properties.is_none());
        assert_eq!(
            rule.short_description.as_ref().unwrap().text,
            Category::Outdated.description()
        );
    }

    #[test]
    fn test_build_rule_descriptor_prefers_advisory_url_over_derived_formula() {
        let mut finding = finding_with_code(Category::Vulnerable, "RUSTSEC-2020-0071", "msg");
        finding.advisory_url =
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071?utm=x".to_string());
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        assert_eq!(
            rule.help_uri.as_deref(),
            Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071?utm=x"),
            "the authoritative OSV-provided href must win over the derived formula"
        );
    }

    /// Regression test for issue #1077 MEDIUM security review: an advisory id that would
    /// produce an invalid URI (a literal space here) must never reach `helpUri` unvalidated.
    #[test]
    fn test_build_rule_descriptor_omits_help_uri_for_a_malformed_advisory_id() {
        let report = CheckReport {
            findings: vec![finding_with_code(
                Category::Vulnerable,
                "RUSTSEC with a space",
                "msg",
            )],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(
            rules.len(),
            1,
            "a code failing the allowlist must fall back to the category-token rule, not \
             become its own rule id (issue #1077 review #2)"
        );
        assert_eq!(rules[0].id, "vulnerable");
        assert!(
            rules[0].help_uri.is_none(),
            "a malformed advisory id must not become an unvalidated helpUri"
        );

        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results[0].rule_id.as_deref(), Some("vulnerable"));
    }

    /// Regression test for issue #1077 MEDIUM/S3 security review: a `.`/`..` advisory id is a
    /// syntactically valid URI path segment but would retarget the link away from
    /// `/vulnerability/`. Also fails [`is_valid_osv_id`] (issue #1077 review #1/#2), so it
    /// falls back to the category-token rule entirely, not just to a bare `helpUri` omission.
    #[test]
    fn test_build_rule_descriptor_omits_help_uri_for_a_traversal_id() {
        let report = CheckReport {
            findings: vec![finding_with_code(Category::Vulnerable, "..", "msg")],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules[0].id, "vulnerable");
        assert!(rules[0].help_uri.is_none());
    }

    /// Regression test for issue #1077 review #1: a multi-segment traversal embedded in the
    /// code (a `/` is not in the allowlist) must be rejected the same way a bare `..` is.
    #[test]
    fn test_build_rule_descriptor_omits_help_uri_for_an_embedded_slash_traversal() {
        let report = CheckReport {
            findings: vec![finding_with_code(Category::Vulnerable, "../evil", "msg")],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules[0].id, "vulnerable");
        assert!(rules[0].help_uri.is_none());
    }

    /// Regression test for issue #1077 review #3: a *valid* advisory id that happens to equal
    /// a category token verbatim must still be treated as a genuine advisory rule (getting
    /// `helpUri`/`fullDescription`), not misclassified as category-only by a string comparison
    /// against its own id.
    #[test]
    fn test_build_rule_descriptor_advisory_id_equal_to_a_category_token_is_still_advisory() {
        let report = CheckReport {
            findings: vec![finding_with_code(Category::Vulnerable, "vulnerable", "msg")],
        };
        let sarif = to_sarif(&report);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "vulnerable");
        assert_eq!(rules[0].name.as_deref(), Some("vulnerable"));
        assert_eq!(
            rules[0].help_uri.as_deref(),
            Some("https://osv.dev/vulnerability/vulnerable"),
            "a valid code equal to the category token must still be trusted as an advisory id"
        );
        assert_eq!(rules[0].full_description.as_ref().unwrap().text, "msg");
    }

    #[test]
    fn test_build_rule_descriptor_sets_security_severity_from_advisory_bucket() {
        let mut finding = finding_with_code(Category::Vulnerable, "RUSTSEC-2020-0071", "msg");
        finding.advisory_severity = Some(VulnSeverity::Critical);
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        let properties = rule.properties.as_ref().expect("properties must be set");
        assert_eq!(
            properties.additional_properties.get("security-severity"),
            Some(&serde_json::Value::String("9.5".to_string()))
        );
    }

    #[test]
    fn test_build_rule_descriptor_omits_security_severity_for_an_ungraded_bucket() {
        let mut finding = finding_with_code(Category::Vulnerable, "RUSTSEC-2020-0071", "msg");
        finding.advisory_severity = Some(VulnSeverity::Unknown);
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        assert!(rule.properties.is_none());
    }

    #[test]
    fn test_build_rule_descriptor_omits_security_severity_without_advisory_severity_data() {
        let report = CheckReport {
            findings: vec![finding_with_code(
                Category::Vulnerable,
                "RUSTSEC-2020-0071",
                "msg",
            )],
        };
        let sarif = to_sarif(&report);
        let rule = &sarif.runs[0].tool.driver.rules.as_ref().unwrap()[0];
        assert!(rule.properties.is_none());
    }

    #[test]
    fn test_to_sarif_partial_fingerprint_is_stable_across_a_line_shift() {
        let mut moved = finding(Category::Outdated, DiagnosticSeverity::HINT);
        moved.range = Range::new(Position::new(40, 0), Position::new(40, 10));
        let report_before = CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        };
        let report_after = CheckReport {
            findings: vec![moved],
        };

        let fingerprint_before = sarif_fingerprint(&report_before);
        let fingerprint_after = sarif_fingerprint(&report_after);
        assert_eq!(
            fingerprint_before, fingerprint_after,
            "an unrelated line shift must not change the fingerprint"
        );
    }

    #[test]
    fn test_to_sarif_partial_fingerprint_differs_across_dependency_and_category() {
        let base = sarif_fingerprint(&CheckReport {
            findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
        });

        let mut other_dependency = finding(Category::Outdated, DiagnosticSeverity::HINT);
        other_dependency.dependency_name = Some("tokio".to_string());
        let other_dependency_fp = sarif_fingerprint(&CheckReport {
            findings: vec![other_dependency],
        });
        assert_ne!(base, other_dependency_fp);

        let other_category_fp = sarif_fingerprint(&CheckReport {
            findings: vec![finding(Category::Vulnerable, DiagnosticSeverity::ERROR)],
        });
        assert_ne!(base, other_category_fp);
    }

    /// Regression test for issue #1077 S2 review (independently corroborated by both the
    /// critic and security reviews): the same dependency declared under two sections (e.g.
    /// `[dependencies]` and `[dev-dependencies]`) produces two distinct findings that must not
    /// collapse onto one fingerprint (`deps-core`'s #394 S2 keeps them distinct upstream).
    #[test]
    fn test_to_sarif_partial_fingerprint_disambiguates_duplicate_occurrences_by_ordinal() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Outdated, DiagnosticSeverity::HINT),
                finding(Category::Outdated, DiagnosticSeverity::HINT),
            ],
        };
        let sarif = to_sarif(&report);
        let results = sarif.runs[0].results.as_ref().unwrap();
        let fp0 = result_fingerprint(&results[0]);
        let fp1 = result_fingerprint(&results[1]);
        assert_ne!(
            fp0, fp1,
            "two occurrences of the same (manifest, dependency, rule) must not collapse"
        );
    }

    /// Regression test for issue #1077 S2 review: two document-level notices with no
    /// `dependency_name` (e.g. an offline notice and a truncation notice) must not collapse
    /// onto one fingerprint either.
    #[test]
    fn test_to_sarif_partial_fingerprint_disambiguates_two_document_level_other_notices() {
        let mut first = finding(Category::Other, DiagnosticSeverity::INFORMATION);
        first.dependency_name = None;
        let mut second = finding(Category::Other, DiagnosticSeverity::INFORMATION);
        second.dependency_name = None;
        let report = CheckReport {
            findings: vec![first, second],
        };
        let sarif = to_sarif(&report);
        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_ne!(
            result_fingerprint(&results[0]),
            result_fingerprint(&results[1])
        );
    }

    /// Regression test for issue #1077 security review: a raw `|` join is not delimiter-safe
    /// — a dependency literally named `serde|outdated` must not be able to collide with a
    /// different (dependency, rule) pair.
    #[test]
    fn test_to_sarif_partial_fingerprint_percent_encodes_a_pipe_in_the_dependency_name() {
        let mut finding = finding(Category::Outdated, DiagnosticSeverity::HINT);
        finding.dependency_name = Some("serde|outdated".to_string());
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let fp = result_fingerprint(&sarif.runs[0].results.as_ref().unwrap()[0]);
        assert!(
            !fp.contains("serde|outdated"),
            "a literal delimiter inside a component must be percent-encoded, not passed through raw"
        );
        assert!(fp.contains("serde%7Coutdated"));
    }

    #[test]
    fn test_to_sarif_partial_fingerprint_handles_missing_dependency_name() {
        let mut finding = finding(Category::Other, DiagnosticSeverity::INFORMATION);
        finding.dependency_name = None;
        let report = CheckReport {
            findings: vec![finding],
        };
        let sarif = to_sarif(&report);
        let fp = result_fingerprint(&sarif.runs[0].results.as_ref().unwrap()[0]);
        assert!(!fp.is_empty());
    }

    fn sarif_fingerprint(report: &CheckReport) -> String {
        result_fingerprint(&to_sarif(report).runs[0].results.as_ref().unwrap()[0])
    }

    fn result_fingerprint(result: &SarifResult) -> String {
        result
            .partial_fingerprints
            .as_ref()
            .unwrap()
            .get("depsCli/v1")
            .unwrap()
            .clone()
    }

    #[test]
    fn test_automation_id_category_is_stable_and_run_id_is_last_segment() {
        let id = automation_id_with_env(|name| match name {
            "GITHUB_RUN_ID" => Some("12345".to_string()),
            "GITHUB_RUN_ATTEMPT" => Some("2".to_string()),
            "GITHUB_WORKFLOW" => Some("CI".to_string()),
            "GITHUB_JOB" => Some("test".to_string()),
            _ => None,
        });
        assert_eq!(id, "deps-cli/CI/test/12345-2");
        let (category, run) = id.rsplit_once('/').expect("id must contain a separator");
        assert_eq!(category, "deps-cli/CI/test");
        assert_eq!(run, "12345-2");
    }

    /// Regression test for issue #1077 C1 review: the category (everything before the last
    /// `/`) must stay identical across two different runs of the same workflow+job, so a
    /// later upload supersedes an earlier one instead of GitHub treating each run as a new,
    /// never-closed analysis line.
    #[test]
    fn test_automation_id_category_is_stable_across_two_runs_of_the_same_workflow_and_job() {
        let env_for = |run_id: &'static str| {
            move |name: &str| match name {
                "GITHUB_RUN_ID" => Some(run_id.to_string()),
                "GITHUB_WORKFLOW" => Some("CI".to_string()),
                "GITHUB_JOB" => Some("test".to_string()),
                _ => None,
            }
        };
        let first = automation_id_with_env(env_for("111"));
        let second = automation_id_with_env(env_for("222"));
        let (first_category, _) = first.rsplit_once('/').unwrap();
        let (second_category, _) = second.rsplit_once('/').unwrap();
        assert_eq!(
            first_category, second_category,
            "category must stay stable across runs so a later upload supersedes an earlier one"
        );
        assert_ne!(first, second, "the run id itself must still vary");
    }

    #[test]
    fn test_automation_id_run_attempt_unset_still_uses_run_id_alone() {
        let id = automation_id_with_env(|name| match name {
            "GITHUB_RUN_ID" => Some("12345".to_string()),
            "GITHUB_WORKFLOW" => Some("CI".to_string()),
            "GITHUB_JOB" => Some("test".to_string()),
            _ => None,
        });
        assert_eq!(id, "deps-cli/CI/test/12345");
    }

    #[test]
    fn test_automation_id_falls_back_without_github_run_id() {
        let id = automation_id_with_env(|_| None);
        assert_eq!(id, "deps-cli/local");
    }

    #[test]
    fn test_to_sarif_sets_automation_details_id() {
        let sarif = to_sarif(&CheckReport::default());
        assert!(
            sarif.runs[0]
                .automation_details
                .as_ref()
                .and_then(|details| details.id.as_deref())
                .is_some_and(|id| !id.is_empty())
        );
    }
}
