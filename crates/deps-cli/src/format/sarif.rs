//! SARIF 2.1.0 output (FR-008, US-002) for GitHub code scanning and other SARIF consumers.
//!
//! Each distinct [`crate::report::Category`] present in the report becomes one
//! `tool.driver.rules` entry (the SARIF rule id), and each [`crate::report::CheckFinding`]
//! becomes one `run.results` entry with its LSP [`Range`] translated to a SARIF physical
//! location region.
//!
//! Deviation from FR-008's literal wording (spec 062 review S3): FR-008 says "each existing
//! diagnostic code becomes a SARIF rule id", but `CheckFinding` (the PR 2 surface this module
//! builds on) carries only [`crate::report::Category`], not the finer-grained
//! `generate_diagnostics` code string — so a rule here is one per `Category` (e.g. every OSV
//! advisory collapses into the single `vulnerable` rule, not one rule per CVE). This is a
//! deliberate scope decision for this PR, not an oversight; diagnostic-code-level rule
//! granularity is tracked as a follow-up rather than changing `CheckFinding`'s shape here.

use crate::report::{CheckFinding, CheckReport};
use serde_sarif::sarif::{
    ArtifactLocation, Location, PhysicalLocation, Region, ReportingDescriptor,
    Result as SarifResult, ResultLevel, Run, SCHEMA_URL, Sarif, Tool, ToolComponent, Version,
};
use std::collections::BTreeSet;
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
    let categories: Vec<_> = report
        .findings
        .iter()
        .map(|finding| finding.category)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let rules: Vec<ReportingDescriptor> = categories
        .iter()
        .map(|category| ReportingDescriptor::builder().id(category.as_str()).build())
        .collect();

    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|finding| {
            let rule_index = categories
                .iter()
                .position(|category| *category == finding.category)
                .unwrap_or_default();
            to_sarif_result(finding, rule_index)
        })
        .collect();

    let driver = ToolComponent::builder()
        .name("deps-cli")
        .version(env!("CARGO_PKG_VERSION"))
        .information_uri(env!("CARGO_PKG_REPOSITORY"))
        .rules(rules)
        .build();

    let run = Run::builder()
        .tool(Tool::from(driver))
        .results(results)
        .build();

    Sarif::builder()
        .version(Version::V2_1_0.to_string())
        .schema(SCHEMA_URL)
        .runs(vec![run])
        .build()
}

/// Builds one `run.results` entry for `finding`, whose rule is at `rule_index` within
/// [`to_sarif`]'s `tool.driver.rules`.
fn to_sarif_result(finding: &CheckFinding, rule_index: usize) -> SarifResult {
    let region = to_sarif_region(finding.range);
    let artifact_location = ArtifactLocation::builder()
        .uri(manifest_uri(&finding.manifest_path))
        .build();
    let physical_location = PhysicalLocation::builder()
        .artifact_location(artifact_location)
        .region(region)
        .build();
    let location = Location::builder()
        .physical_location(physical_location)
        .build();

    SarifResult::builder()
        .rule_id(finding.category.as_str())
        .rule_index(i64::try_from(rule_index).unwrap_or(i64::MAX))
        .message(finding.message.as_str())
        .locations(vec![location])
        .level(to_result_level(finding.severity))
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
    use crate::report::Category;
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
            severity,
            range: Range::new(Position::new(4, 0), Position::new(4, 10)),
            message: "Newer version available: 1.1.0".to_string(),
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
    #[test]
    fn test_to_sarif_multi_category_snapshot() {
        let report = CheckReport {
            findings: vec![
                finding(Category::Outdated, DiagnosticSeverity::HINT),
                finding(Category::Vulnerable, DiagnosticSeverity::ERROR),
            ],
        };
        insta::assert_json_snapshot!(to_sarif(&report));
    }
}
