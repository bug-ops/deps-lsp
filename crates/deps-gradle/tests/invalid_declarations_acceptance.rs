//! #2170: a `[libraries]` entry of a version catalog that cannot be read as a library declaration
//! is reported (parse result, shared diagnostic) instead of being dropped silently.

#![expect(clippy::unwrap_used, reason = "test code")]

use deps_core::position::{Position, Range};
use deps_core::{InvalidDeclarationOccurrence, InvalidDeclarationReason, ParseResult};
use deps_gradle::parser::parse_gradle;

const CATALOG: &str = r#"[libraries]
good = { module = "com.google.guava:guava", version = "33.0.0-jre" }
bad-short = "not-a-coordinate"
bad-table = { version = "1" }
bad-int = 1
"#;

fn alias_range(line: u32, alias: &str) -> Range {
    Range::new(
        Position::new(line, 0),
        Position::new(line, u32::try_from(alias.len()).unwrap()),
    )
}

fn occurrence(
    line: u32,
    key: &str,
    reason: InvalidDeclarationReason,
) -> (Range, String, InvalidDeclarationReason) {
    (alias_range(line, key), key.to_owned(), reason)
}

fn summarize(
    occurrences: Vec<InvalidDeclarationOccurrence>,
) -> Vec<(Range, String, InvalidDeclarationReason)> {
    occurrences
        .into_iter()
        .map(|o| (o.range, o.key, o.reason))
        .collect()
}

fn expected() -> Vec<(Range, String, InvalidDeclarationReason)> {
    vec![
        occurrence(
            2,
            "bad-short",
            InvalidDeclarationReason::MalformedCoordinate,
        ),
        occurrence(3, "bad-table", InvalidDeclarationReason::MissingCoordinate),
        occurrence(4, "bad-int", InvalidDeclarationReason::UnsupportedValue),
    ]
}

#[test]
fn catalog_parse_reports_each_unreadable_library_entry_once_at_its_alias() {
    let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");

    let result = parse_gradle(CATALOG, &uri).unwrap();

    assert_eq!(result.dependencies.len(), 1, "valid entries are unaffected");
    assert_eq!(summarize(result.invalid_declarations.clone()), expected());
    assert_eq!(
        summarize(ParseResult::invalid_declarations(&result)),
        expected(),
        "the trait method forwards the field"
    );
}

#[test]
fn catalog_without_unreadable_entries_and_build_scripts_report_nothing() {
    let catalog = parse_gradle(
        "[libraries]\ngood = \"com.google.guava:guava:33.0.0-jre\"\n",
        &deps_core::test_util::test_uri("/project/gradle/libs.versions.toml"),
    )
    .unwrap();
    let script = parse_gradle(
        "dependencies { implementation(\"com.google.guava:guava:33.0.0-jre\") }\n",
        &deps_core::test_util::test_uri("/project/build.gradle.kts"),
    )
    .unwrap();

    assert!(catalog.invalid_declarations.is_empty());
    assert!(script.invalid_declarations.is_empty());
}

#[cfg(feature = "lsp-responses")]
#[test]
fn shared_diagnostics_emit_one_warning_per_unreadable_entry_at_its_alias() {
    use deps_core::VersionData;
    use deps_core::diagnostic::Severity;
    use deps_core::lsp_helpers::generate_diagnostics_from_cache;
    use std::collections::HashMap;

    let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");
    let result = parse_gradle(CATALOG, &uri).unwrap();
    let cached = HashMap::new();
    let resolved = HashMap::new();

    let diagnostics = generate_diagnostics_from_cache(
        &result,
        VersionData::new(&cached, &resolved),
        &deps_gradle::GradleFormatter,
        result.uri(),
        deps_core::FreshnessSettings::default(),
        deps_core::DiagnosticSeverities::default(),
        deps_core::PublishTime::now(),
    );

    for (range, key, _) in expected() {
        let at_alias: Vec<_> = diagnostics.iter().filter(|d| d.range == range).collect();
        assert_eq!(at_alias.len(), 1, "{key}: {diagnostics:?}");
        assert_eq!(at_alias[0].severity, Some(Severity::Warning));
        assert!(at_alias[0].message().contains(&key), "{key}");
    }
}
