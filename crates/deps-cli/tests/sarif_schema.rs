//! Validates every SARIF fixture `format::sarif` can produce against the vendored SARIF
//! 2.1.0 JSON schema (spec 062 tasks.md T028, SC-002).
//!
//! `tests/fixtures/sarif-2.1.0.schema.json` is vendored from `serde-sarif` 0.8.0's own
//! `src/schema.json` (the official OASIS SARIF 2.1.0 schema, MIT-licensed alongside the
//! crate) — `serde-sarif` only uses this schema at its own build time to generate Rust
//! types, it does not expose runtime schema validation itself.

#![allow(clippy::expect_used)]

use deps_cli::format::sarif::to_sarif;
use deps_cli::report::{Category, CheckFinding, CheckReport};
use deps_core::EcosystemId;
use deps_core::osv::VulnSeverity;
use std::path::PathBuf;
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};

const SCHEMA_JSON: &str = include_str!("fixtures/sarif-2.1.0.schema.json");

/// The upstream OASIS SARIF 2.1.0 schema's `language` property (on `run` and on
/// `toolComponent`) ships a malformed `pattern` regex — an unbalanced bracket, unrelated to
/// anything this crate's `format::sarif` module ever sets — which fails draft-07 meta-schema
/// validation when compiling a [`jsonschema::Validator`] from it.
const BROKEN_LANGUAGE_PATTERN: &str = "^[a-zA-Z]{2}|^[a-zA-Z]{2}-[a-zA-Z]{2}]?$";

/// Recursively drops every `"pattern": "<BROKEN_LANGUAGE_PATTERN>"` keyword from `value`.
///
/// Mutates only the in-memory copy, not the vendored fixture file, so re-vendoring a future
/// schema update stays a plain file replace rather than requiring this patch to be re-applied
/// by hand.
fn strip_broken_language_pattern(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("pattern").and_then(serde_json::Value::as_str)
                == Some(BROKEN_LANGUAGE_PATTERN)
            {
                map.remove("pattern");
            }
            for nested in map.values_mut() {
                strip_broken_language_pattern(nested);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_broken_language_pattern(item);
            }
        }
        _ => {}
    }
}

fn schema_validator() -> jsonschema::Validator {
    let mut schema: serde_json::Value =
        serde_json::from_str(SCHEMA_JSON).expect("vendored SARIF schema must be valid JSON");
    strip_broken_language_pattern(&mut schema);
    jsonschema::validator_for(&schema).expect("vendored SARIF schema must itself be valid")
}

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

fn assert_valid_sarif(report: &CheckReport) {
    let validator = schema_validator();
    let document = serde_json::to_value(to_sarif(report)).expect("Sarif must serialize to JSON");
    if let Err(error) = validator.validate(&document) {
        panic!(
            "produced SARIF document does not conform to the SARIF 2.1.0 schema: {error}\n\
             document: {document:#}"
        );
    }
}

#[test]
fn test_empty_report_produces_schema_valid_sarif() {
    assert_valid_sarif(&CheckReport::default());
}

#[test]
fn test_single_finding_produces_schema_valid_sarif() {
    assert_valid_sarif(&CheckReport {
        findings: vec![finding(Category::Outdated, DiagnosticSeverity::HINT)],
    });
}

#[test]
fn test_multi_category_report_produces_schema_valid_sarif() {
    assert_valid_sarif(&CheckReport {
        findings: vec![
            finding(Category::Outdated, DiagnosticSeverity::HINT),
            finding(Category::Vulnerable, DiagnosticSeverity::ERROR),
            finding(Category::License, DiagnosticSeverity::WARNING),
            finding(Category::Other, DiagnosticSeverity::INFORMATION),
        ],
    });
}

#[test]
fn test_advisory_coded_finding_produces_schema_valid_sarif() {
    let mut vulnerable = finding(Category::Vulnerable, DiagnosticSeverity::ERROR);
    vulnerable.code = Some("RUSTSEC-2020-0071".to_string());
    vulnerable.message = "RUSTSEC-2020-0071: Potential segfault in the time crate".to_string();
    vulnerable.advisory_url = Some("https://osv.dev/vulnerability/RUSTSEC-2020-0071".to_string());
    vulnerable.advisory_severity = Some(VulnSeverity::High);
    assert_valid_sarif(&CheckReport {
        findings: vec![vulnerable],
    });
}

/// Regression test for issue #1077 MEDIUM security review: a malformed advisory `code` (one
/// that would produce an invalid `helpUri`) must not break the *whole* SARIF document's
/// schema validation — the offending `helpUri` must be omitted, not emitted unvalidated.
#[test]
fn test_malformed_advisory_id_does_not_break_schema_validation() {
    let mut vulnerable = finding(Category::Vulnerable, DiagnosticSeverity::ERROR);
    vulnerable.code = Some("evil id\nwith\"quotes and spaces".to_string());
    assert_valid_sarif(&CheckReport {
        findings: vec![vulnerable],
    });
}
