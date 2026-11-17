//! Acceptance tests for the `deps_core::parser::deserialize_toml_checked` helper extracted from
//! deps-cli's `config::parse` (plan N2): same acceptance, two error variants, redacted and
//! bounded messages built at construction.

#![allow(clippy::expect_used)]

use deps_core::parser::{TomlDeserializeError, deserialize_toml_checked};
use serde::Deserialize;
use std::assert_matches;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Sample {
    name: String,
    #[serde(default)]
    count: u32,
}

#[test]
fn deserialize_toml_checked_accepts_valid_document() {
    let parsed: Sample = deserialize_toml_checked("name = \"x\"\ncount = 3\n").expect("valid");
    assert_eq!(
        parsed,
        Sample {
            name: "x".into(),
            count: 3
        }
    );
}

#[test]
fn deserialize_toml_checked_syntax_error_is_the_toml_variant() {
    let err = deserialize_toml_checked::<Sample>("name = ").expect_err("syntax error");
    assert_matches!(err, TomlDeserializeError::Toml(_), "{err:?}");
}

#[test]
fn deserialize_toml_checked_unknown_field_is_the_deserialize_variant() {
    let err = deserialize_toml_checked::<Sample>("name = \"x\"\nextra = 1\n").expect_err("unknown");
    assert_matches!(err, TomlDeserializeError::Deserialize(_), "{err:?}");
}

#[test]
fn deserialize_toml_checked_wrong_type_is_the_deserialize_variant() {
    let err = deserialize_toml_checked::<Sample>("name = 5\n").expect_err("type error");
    assert_matches!(err, TomlDeserializeError::Deserialize(_), "{err:?}");
}

#[test]
fn deserialize_toml_checked_messages_do_not_echo_input_values() {
    let toml = "name = \"x\"\ncount = \"TOPSECRETVALUE\"\n";
    let err = deserialize_toml_checked::<Sample>(toml).expect_err("type error");
    let text = match &err {
        TomlDeserializeError::Toml(m) | TomlDeserializeError::Deserialize(m) => m.clone(),
    };
    assert!(!text.contains("TOPSECRETVALUE"), "{text}");
}

#[test]
fn deserialize_toml_checked_messages_are_bounded() {
    let toml = format!("name = \"x\"\n{} = 1\n", "k".repeat(100_000));
    let err = deserialize_toml_checked::<Sample>(&toml).expect_err("unknown field");
    let text = match &err {
        TomlDeserializeError::Toml(m) | TomlDeserializeError::Deserialize(m) => m.clone(),
    };
    assert!(text.len() < 4096, "message length {}", text.len());
}

#[test]
fn deserialize_toml_checked_excessive_nesting_is_rejected_not_a_panic() {
    let depth = 5_000;
    let toml = format!("name = {}1{}\n", "[".repeat(depth), "]".repeat(depth));
    let err = deserialize_toml_checked::<Sample>(&toml).expect_err("too deep");
    let text = match &err {
        TomlDeserializeError::Toml(m) | TomlDeserializeError::Deserialize(m) => m.clone(),
    };
    assert!(text.len() < 4096, "message length {}", text.len());
}
