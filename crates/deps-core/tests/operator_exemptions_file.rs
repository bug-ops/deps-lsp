//! Acceptance tests for #1964 / spec 101: the `advisory-exemptions.toml` file format and the
//! `OperatorExemptions::load` contract (plan 2026-11-17T06-15-23-architect, Contracts).
//!
//! Error variants are matched through their `Debug` name so the tests do not depend on the
//! payload shape of `ExemptionFileError`.

#![cfg(feature = "test-util")]
#![allow(clippy::expect_used)]

use deps_core::lsp_helpers::exemption::{ExemptionFile, ExemptionFileError, OperatorExemptions};

fn load_body(body: &str) -> Result<Option<OperatorExemptions>, ExemptionFileError> {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("advisory-exemptions.toml");
    std::fs::write(&path, body).expect("write file");
    OperatorExemptions::load(&ExemptionFile::for_test(path))
}

fn entry(id: &str, reason: &str) -> String {
    format!("[[advisory]]\nid = \"{id}\"\nreason = \"{reason}\"\n")
}

fn assert_variant(result: Result<Option<OperatorExemptions>, ExemptionFileError>, name: &str) {
    let err = result.expect_err("file must be rejected");
    let debug = format!("{err:?}");
    assert!(debug.starts_with(name), "expected {name}, got {debug}");
}

#[test]
fn load_absent_file_is_none() {
    let dir = tempfile::tempdir().expect("temp dir");
    let file = ExemptionFile::for_test(dir.path().join("advisory-exemptions.toml"));
    assert!(matches!(OperatorExemptions::load(&file), Ok(None)));
}

#[test]
fn load_valid_entry_with_and_without_expiry_is_some() {
    let body = format!(
        "{}\n{}expires = \"2099-12-31\"\n",
        entry("GHSA-aaaa-bbbb-cccc", "accepted"),
        entry("CVE-2099-0001", "tracked in JIRA-1")
    );
    // The second entry's `expires` lands in the second table because it follows its fields.
    assert!(matches!(load_body(&body), Ok(Some(_))));
}

#[test]
fn load_reason_is_trimmed_before_validation() {
    assert!(matches!(
        load_body(&entry("GHSA-aaaa-bbbb-cccc", "   padded   ")),
        Ok(Some(_))
    ));
}

#[test]
fn load_reason_of_exactly_500_chars_is_accepted() {
    let reason = "r".repeat(500);
    assert!(matches!(
        load_body(&entry("GHSA-aaaa-bbbb-cccc", &reason)),
        Ok(Some(_))
    ));
}

#[test]
fn load_reason_of_501_chars_is_a_schema_error() {
    let reason = "r".repeat(501);
    assert_variant(load_body(&entry("GHSA-aaaa-bbbb-cccc", &reason)), "Schema");
}

#[test]
fn load_blank_reason_is_a_schema_error() {
    assert_variant(load_body(&entry("GHSA-aaaa-bbbb-cccc", "   ")), "Schema");
}

#[test]
fn load_reason_with_control_character_is_a_schema_error() {
    assert_variant(
        load_body(&entry("GHSA-aaaa-bbbb-cccc", "bad\\u001b[31mred")),
        "Schema",
    );
}

#[test]
fn load_missing_reason_is_a_schema_error() {
    assert_variant(
        load_body("[[advisory]]\nid = \"GHSA-aaaa-bbbb-cccc\"\n"),
        "Schema",
    );
}

#[test]
fn load_missing_id_is_a_schema_error() {
    assert_variant(load_body("[[advisory]]\nreason = \"r\"\n"), "Schema");
}

#[test]
fn load_unknown_field_is_a_schema_error() {
    let body = format!("{}package = \"serde\"\n", entry("GHSA-aaaa-bbbb-cccc", "r"));
    assert_variant(load_body(&body), "Schema");
}

#[test]
fn load_unknown_top_level_table_is_a_schema_error() {
    let body = format!("[settings]\nx = 1\n{}", entry("GHSA-aaaa-bbbb-cccc", "r"));
    assert_variant(load_body(&body), "Schema");
}

#[test]
fn load_malformed_expiry_date_is_a_schema_error() {
    for bad in ["2026-13-45", "tomorrow", "2026/01/01"] {
        let body = format!("{}expires = \"{bad}\"\n", entry("GHSA-aaaa-bbbb-cccc", "r"));
        assert_variant(load_body(&body), "Schema");
    }
}

#[test]
fn load_duplicate_id_is_a_duplicate_id_error() {
    let body = format!(
        "{}{}",
        entry("GHSA-aaaa-bbbb-cccc", "one"),
        entry("GHSA-aaaa-bbbb-cccc", "two")
    );
    assert_variant(load_body(&body), "DuplicateId");
}

#[test]
fn load_invalid_toml_is_a_toml_error_that_does_not_echo_the_input() {
    let result = load_body("[[advisory]]\nreason = \"TOPSECRETVALUE\nid = ");
    let err = result.expect_err("syntax error must be rejected");
    assert!(format!("{err:?}").starts_with("Toml"), "{err:?}");
    assert!(!err.to_string().contains("TOPSECRETVALUE"), "{err}");
}

fn many_entries(count: usize) -> String {
    (0..count)
        .map(|i| entry(&format!("GHSA-{i:04x}-aaaa-aaaa"), "r"))
        .collect()
}

#[test]
fn load_1024_entries_is_accepted() {
    assert!(matches!(load_body(&many_entries(1024)), Ok(Some(_))));
}

#[test]
fn load_1025_entries_is_a_too_many_entries_error() {
    assert_variant(load_body(&many_entries(1025)), "TooManyEntries");
}

#[test]
fn load_file_over_64_kib_is_a_too_large_error() {
    let body = format!(
        "# {}\n{}",
        "x".repeat(70 * 1024),
        entry("GHSA-aaaa-bbbb-cccc", "r")
    );
    assert_variant(load_body(&body), "TooLarge");
}

#[test]
fn load_unreadable_path_is_an_io_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A directory where a file is expected is readable as neither absent nor valid.
    let path = dir.path().join("advisory-exemptions.toml");
    std::fs::create_dir(&path).expect("create directory in place of file");
    assert_variant(
        OperatorExemptions::load(&ExemptionFile::for_test(path)),
        "Io",
    );
}

#[test]
fn none_is_constructible_without_a_file() {
    let _ = OperatorExemptions::none();
}
