//! #2113 acceptance: `json_ast::string_literal_span(content, path)` returns the byte range of the
//! quoted string literal at an object path, so a lock file value can be replaced byte for byte.
//!
//! Contract: `Some(r)` exactly when every key resolves (last duplicate key wins) to an object and
//! the final value is a string literal; `content[r]` is the quoted literal; never panics.
//! The `path: &[&str]` parameter type is the test's assumption of the plan's "non-empty path".

use deps_core::json_ast::string_literal_span;

fn literal<'a>(content: &'a str, path: &[&str]) -> Option<&'a str> {
    string_literal_span(content, path).and_then(|range| content.get(range))
}

#[test]
fn string_literal_span_returns_the_quoted_literal_of_a_nested_string() {
    let content = "{\n  \"a\": { \"b\": \"[2.*, )\", \"c\": 1 }\n}\n";

    assert_eq!(literal(content, &["a", "b"]), Some("\"[2.*, )\""));
}

#[test]
fn string_literal_span_keeps_escapes_byte_for_byte() {
    let content = r#"{"a":{"b":"x\"yA\\z"}}"#;

    assert_eq!(literal(content, &["a", "b"]), Some(r#""x\"yA\\z""#));
}

#[test]
fn string_literal_span_last_duplicate_key_wins() {
    let content = r#"{"a":{"b":"first"},"a":{"b":"second"}}"#;

    assert_eq!(literal(content, &["a", "b"]), Some("\"second\""));
}

#[test]
fn string_literal_span_is_none_for_a_non_string_final_value() {
    for content in [
        r#"{"a":{"b":1}}"#,
        r#"{"a":{"b":null}}"#,
        r#"{"a":{"b":["x"]}}"#,
        r#"{"a":{"b":{"c":"x"}}}"#,
    ] {
        assert_eq!(literal(content, &["a", "b"]), None, "{content}");
    }
}

#[test]
fn string_literal_span_is_none_when_an_intermediate_key_is_not_an_object_or_is_missing() {
    for content in [
        r#"{"a":"text"}"#,
        r#"{"a":["b"]}"#,
        r#"{"x":{"b":"y"}}"#,
        r#"{"a":{"x":"y"}}"#,
    ] {
        assert_eq!(literal(content, &["a", "b"]), None, "{content}");
    }
}

#[test]
fn string_literal_span_is_none_for_unparsable_or_non_object_documents() {
    for content in ["", "not json", "[1,2]", "\"top\"", "{\"a\":"] {
        assert_eq!(literal(content, &["a", "b"]), None, "{content:?}");
    }
}

#[test]
fn string_literal_span_resolves_a_single_key_path() {
    let content = r#"{"requested":"[1.0, )"}"#;

    assert_eq!(literal(content, &["requested"]), Some("\"[1.0, )\""));
}
