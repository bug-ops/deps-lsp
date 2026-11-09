//! Shared JSONC-AST helpers for recovering exact dependency source positions (#613).
//!
//! `deps-npm` and `deps-composer` each parse a JSON manifest's *semantic* content
//! (dependency names, version requirement strings, `minimum-stability`, ...) via
//! `serde_json`/[`crate::parse_json_checked`], as before — this module is never a
//! replacement for that.
//!
//! What it replaces is how each crate previously recovered a dependency's *position*:
//! substring-scanning the raw manifest text for a section's byte range, then for each
//! name/version pattern within it (removed by #613, since it broke down for duplicate keys and
//! same-named nested values — see `find_json_section_byte_range`'s removal in this same
//! change). Reading positions directly off a position-preserving parse tree is correct by
//! construction regardless of `serde_json::Map` iteration order, duplicate keys, or nested
//! value shapes, mirroring `crates/deps-deno/src/parser.rs`'s original D6 design — generalized
//! here for the "several named top-level sections" shape (`dependencies`/`devDependencies`,
//! `require`/`require-dev`) that `deno.json`'s single flat `imports` map doesn't have.
//!
//! [`JsonSection`] keeps `jsonc-parser`'s own AST types out of every downstream crate's public
//! (and Cargo.toml direct-dependency) surface — only `deps-core` names `jsonc_parser::ast`
//! types directly. The one exception is [`parse_jsonc_ast_checked`], whose only caller
//! (`deps-deno`, which already depends on `jsonc-parser` directly) walks the AST for positions;
//! every other caller goes through [`parse_jsonc_typed`].

mod de;

use jsonc_parser::ast::{Object, ObjectProp, ObjectPropName, Value};
use jsonc_parser::errors::ParseErrorKind;
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use std::collections::HashMap;

use crate::error::{DepsError, ParseFailureKind, Result};
use crate::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use crate::parser::{MAX_JSON_NESTING_DEPTH, json_depth_error_message};
use crate::position::Range;

/// Computes `value`'s real nesting depth (`value` itself counts as depth 1, each further
/// `Object`/`Array` descent adds one), rejecting once it exceeds `max_depth`.
///
/// Walking the already-parsed AST is immune to JSONC comment characters (`//`, `/* */`)
/// miscounting as structural nesting, unlike a raw byte scan
/// ([`crate::check_json_nesting_depth`]): a comment's bracket characters never become AST
/// nodes. `jsonc-parser`'s own hardcoded 512-deep recursion cap already bounds `parse_to_ast`;
/// this walk aligns JSONC parsing with the tighter [`MAX_JSON_NESTING_DEPTH`] every other JSON
/// call site enforces. An explicit stack keeps the walk non-recursive.
///
/// Returns `Err(depth)` with the depth reached the instant nesting exceeds `max_depth`.
fn check_ast_nesting_depth(root: &Value<'_>, max_depth: usize) -> std::result::Result<(), usize> {
    let mut stack = vec![(root, 1_usize)];
    while let Some((value, depth)) = stack.pop() {
        match value {
            Value::Object(obj) => {
                if depth > max_depth {
                    return Err(depth);
                }
                stack.extend(obj.properties.iter().map(|prop| (&prop.value, depth + 1)));
            }
            Value::Array(arr) => {
                if depth > max_depth {
                    return Err(depth);
                }
                stack.extend(arr.elements.iter().map(|elem| (elem, depth + 1)));
            }
            Value::StringLit(_)
            | Value::NumberLit(_)
            | Value::BooleanLit(_)
            | Value::NullKeyword(_) => {}
        }
    }
    Ok(())
}

/// Rejects the first number literal that is not valid JSON (e.g. hex), anywhere in `root`.
///
/// [`de::AstDeserializer`] never visits subtrees the target ignores, so this keeps their
/// numbers validated exactly as when the whole tree was converted. Allocation-free apart from
/// the explicit stack.
fn check_ast_numbers(root: &Value<'_>) -> std::result::Result<(), String> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(obj) => stack.extend(obj.properties.iter().map(|prop| &prop.value)),
            Value::Array(arr) => stack.extend(arr.elements.iter()),
            Value::NumberLit(lit) => {
                if lit.value.parse::<serde_json::Number>().is_err() {
                    return Err(format!("invalid JSON number `{}`", lit.value));
                }
            }
            Value::StringLit(_) | Value::BooleanLit(_) | Value::NullKeyword(_) => {}
        }
    }
    Ok(())
}

/// Parses JSONC `content` (comments and trailing commas allowed) into an AST bounded by
/// [`MAX_JSON_NESTING_DEPTH`]. `Ok(None)` means the document holds no value (empty,
/// whitespace-only or comment-only).
///
/// `file_type` names the file in the resulting [`DepsError::ParseError`].
///
/// # Errors
///
/// [`ParseFailureKind::Malformed`] for a syntax error, [`ParseFailureKind::NestingTooDeep`]
/// when the document nests deeper than [`MAX_JSON_NESTING_DEPTH`].
///
/// # Examples
///
/// ```
/// use deps_core::json_ast::parse_jsonc_ast_checked;
///
/// assert!(parse_jsonc_ast_checked(r#"{"a": [1,],}"#, "deno.json").unwrap().is_some());
/// assert!(parse_jsonc_ast_checked("  // nothing\n", "deno.json").unwrap().is_none());
/// assert!(parse_jsonc_ast_checked("{", "deno.json").is_err());
/// ```
pub fn parse_jsonc_ast_checked<'a>(
    content: &'a str,
    file_type: &'static str,
) -> Result<Option<Value<'a>>> {
    let ast = parse_to_ast(
        content,
        &CollectOptions::default(),
        &ParseOptions::default(),
    )
    .map_err(|e| {
        let kind = if matches!(e.kind(), ParseErrorKind::NestingDepthExceeded) {
            ParseFailureKind::NestingTooDeep
        } else {
            ParseFailureKind::Malformed
        };
        DepsError::parse_error_of_kind(file_type, kind, &e)
    })?;

    if let Some(value) = &ast.value
        && let Err(depth) = check_ast_nesting_depth(value, MAX_JSON_NESTING_DEPTH)
    {
        return Err(DepsError::parse_error_of_kind(
            file_type,
            ParseFailureKind::NestingTooDeep,
            &json_depth_error_message(depth),
        ));
    }
    Ok(ast.value)
}

/// Test oracle for [`parse_jsonc_typed`]: converts a depth-bounded AST into a
/// `serde_json::Value`. Duplicate object keys resolve to the last occurrence, like
/// [`find_last_prop`].
#[cfg(test)]
fn ast_to_json(value: &Value<'_>, file_type: &'static str) -> Result<serde_json::Value> {
    Ok(match value {
        Value::Object(obj) => {
            let mut map = serde_json::Map::with_capacity(obj.properties.len());
            for prop in &obj.properties {
                map.insert(
                    prop.name.as_str().to_string(),
                    ast_to_json(&prop.value, file_type)?,
                );
            }
            serde_json::Value::Object(map)
        }
        Value::Array(arr) => serde_json::Value::Array(
            arr.elements
                .iter()
                .map(|element| ast_to_json(element, file_type))
                .collect::<Result<_>>()?,
        ),
        Value::StringLit(lit) => serde_json::Value::String(lit.value.to_string()),
        Value::NumberLit(lit) => {
            serde_json::Value::Number(lit.value.parse::<serde_json::Number>().map_err(|_| {
                DepsError::parse_error(file_type, &format!("invalid JSON number `{}`", lit.value))
            })?)
        }
        Value::BooleanLit(lit) => serde_json::Value::Bool(lit.value),
        Value::NullKeyword(_) => serde_json::Value::Null,
    })
}

/// Deserializes JSONC `content` (comments and trailing commas allowed) into `T`, after the
/// same [`MAX_JSON_NESTING_DEPTH`] gate as [`parse_jsonc_ast_checked`].
///
/// `T` is deserialized straight from the AST, so subtrees it ignores are never materialized.
/// Semantics match `serde_json::from_value`: the last duplicate key wins and numbers must be
/// valid JSON, including inside subtrees `T` ignores. Integer map keys are parsed from their
/// string form, and enums must be unit variants spelled as strings.
///
/// `Ok(None)` means the document holds no value (empty, whitespace-only or comment-only), so a
/// caller can treat it as an empty file.
///
/// # Errors
///
/// [`DepsError::ParseError`] for a syntax error, excessive nesting, a number that is not valid
/// JSON (e.g. hex), or a value that does not fit `T`.
///
/// # Examples
///
/// ```
/// use deps_core::json_ast::parse_jsonc_typed;
/// use std::collections::HashMap;
///
/// let map: Option<HashMap<String, u32>> =
///     parse_jsonc_typed("{ \"a\": 1, // note\n \"b\": 2, }", "bun.lock").unwrap();
/// assert_eq!(map.unwrap().len(), 2);
///
/// let empty: Option<HashMap<String, u32>> = parse_jsonc_typed("  ", "bun.lock").unwrap();
/// assert!(empty.is_none());
/// ```
pub fn parse_jsonc_typed<T: serde::de::DeserializeOwned>(
    content: &str,
    file_type: &'static str,
) -> Result<Option<T>> {
    let Some(root) = parse_jsonc_ast_checked(content, file_type)? else {
        return Ok(None);
    };
    check_ast_numbers(&root).map_err(|message| DepsError::parse_error(file_type, &message))?;
    T::deserialize(de::AstDeserializer(&root))
        .map(Some)
        .map_err(|e| DepsError::parse_error(file_type, &e))
}

/// Finds the property named `key` among `object`'s own direct children, taking the *last* one
/// if `key` occurs more than once.
///
/// This is JSON's last-key-wins semantics, which `jsonc-parser`'s `Vec<ObjectProp>` does not
/// enforce on its own (unlike `serde_json::Map`, which dedupes during deserialization).
///
/// # Examples
///
/// ```
/// use deps_core::json_ast::find_last_prop;
/// use jsonc_parser::ast::Value;
/// use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
///
/// let content = r#"{"a": 1, "a": 2}"#;
/// let parsed = parse_to_ast(content, &CollectOptions::default(), &ParseOptions::default()).unwrap();
/// let Some(Value::Object(root)) = parsed.value else { panic!("expected an object") };
///
/// let prop = find_last_prop(&root, "a").unwrap();
/// assert!(matches!(&prop.value, Value::NumberLit(lit) if lit.value == "2"));
/// ```
#[must_use]
pub fn find_last_prop<'a, 'b>(object: &'a Object<'b>, key: &str) -> Option<&'a ObjectProp<'b>> {
    object
        .properties
        .iter()
        .rev()
        .find(|prop| prop.name.as_str() == key)
}

/// A parsed JSON/JSONC document, used only to recover a named top-level section's exact
/// source positions — never a substitute for a caller's own `serde_json` parse of the
/// document's semantic content.
///
/// # Examples
///
/// ```
/// use deps_core::json_ast::JsonAst;
///
/// let content = r#"{"dependencies": {"express": "^4.18.2"}}"#;
/// let ast = JsonAst::parse(content).unwrap();
/// assert!(ast.section("dependencies").is_some());
/// assert!(ast.section("devDependencies").is_none());
/// ```
pub struct JsonAst<'a> {
    root: Object<'a>,
}

impl<'a> JsonAst<'a> {
    /// Parses `content`. Returns `None` if it isn't valid JSONC, or its root value isn't an
    /// object — a caller that reached this via [`crate::parse_json_checked`] should not
    /// normally see `None` here (jsonc-parser's grammar is a strict superset of JSON), but must
    /// still degrade gracefully (every dependency's position falling back to the default,
    /// zero `Range`) rather than assume it.
    ///
    /// Relies on the caller having already bounded `content`'s nesting depth (e.g. via
    /// [`crate::parse_json_checked`]/[`crate::check_json_nesting_depth`]) — jsonc-parser's own
    /// internal recursion cap (512, hardcoded, not configurable) is a last resort, not this
    /// workspace's first line of defense against a stack-overflowing payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::json_ast::JsonAst;
    ///
    /// assert!(JsonAst::parse(r#"{"a": 1}"#).is_some());
    /// assert!(JsonAst::parse("not json").is_none());
    /// assert!(JsonAst::parse("[1, 2, 3]").is_none(), "root value must be an object");
    /// ```
    #[must_use]
    pub fn parse(content: &'a str) -> Option<Self> {
        let parsed = parse_to_ast(
            content,
            &CollectOptions::default(),
            &ParseOptions::default(),
        )
        .ok()?;
        match parsed.value {
            Some(Value::Object(root)) => Some(Self { root }),
            _ => None,
        }
    }

    /// Indexes `key`'s top-level section by its direct properties' own names, for O(1)
    /// per-dependency position lookup instead of an O(section length) rescan per dependency.
    /// `None` if `key` is absent at the top level or its value isn't an object. A duplicate key
    /// *within* the section resolves to its last occurrence too, matching `key`'s own
    /// last-key-wins resolution (see [`find_last_prop`]) — the same rule applied one level
    /// deeper.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::json_ast::JsonAst;
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let content = r#"{"require": {"vendor/pkg": "^1.0"}}"#;
    /// let table = LineOffsetTable::new(content);
    /// let ast = JsonAst::parse(content).unwrap();
    /// let section = ast.section("require").unwrap();
    ///
    /// let (name_range, version_range) = section.position("vendor/pkg", content, &table).unwrap();
    /// let name_start = content.find("vendor/pkg").unwrap() as u32;
    /// assert_eq!(name_range.start.character, name_start);
    /// assert!(version_range.is_some());
    /// ```
    #[must_use]
    pub fn section(&self, key: &str) -> Option<JsonSection<'_>> {
        let Value::Object(section) = &find_last_prop(&self.root, key)?.value else {
            return None;
        };
        let mut by_name = HashMap::with_capacity(section.properties.len());
        for prop in &section.properties {
            by_name.insert(prop.name.as_str(), prop);
        }
        Some(JsonSection { by_name })
    }

    /// Looks up a **root-level** (not nested inside a section) property's own
    /// `(name_range, value_range)` LSP position pair — the same shape
    /// [`JsonSection::position`] returns, but for a top-level scalar field like Composer's
    /// `minimum-stability` rather than a `dependencies`-style map of entries.
    ///
    /// Last-key-wins, matching `serde_json`'s own duplicate-key resolution (see
    /// [`find_last_prop`]). `value_range` is `Some` only when the property's value is itself a
    /// plain string literal, `None` for any other JSON value shape (number, bool, null,
    /// object, array).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::json_ast::JsonAst;
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let content = r#"{"minimum-stability": "beta"}"#;
    /// let table = LineOffsetTable::new(content);
    /// let ast = JsonAst::parse(content).unwrap();
    ///
    /// let (name_range, value_range) = ast
    ///     .root_property_position("minimum-stability", content, &table)
    ///     .unwrap();
    /// let name_start = content.find("minimum-stability").unwrap() as u32;
    /// assert_eq!(name_range.start.character, name_start);
    /// assert!(value_range.is_some());
    ///
    /// assert!(ast.root_property_position("missing", content, &table).is_none());
    /// ```
    #[must_use]
    pub fn root_property_position(
        &self,
        key: &str,
        content: &str,
        table: &LineOffsetTable,
    ) -> Option<(Range, Option<Range>)> {
        let prop = find_last_prop(&self.root, key)?;
        Some(dependency_position(content, table, prop))
    }
}

/// One top-level section's direct properties, indexed by name.
///
/// Opaque handle returned by [`JsonAst::section`], keeping `jsonc-parser`'s own AST types out
/// of every downstream crate's public API and direct dependency graph.
pub struct JsonSection<'a> {
    by_name: HashMap<&'a str, &'a ObjectProp<'a>>,
}

impl JsonSection<'_> {
    /// Looks up `name`'s `(name_range, version_range)` LSP position pair within this section.
    ///
    /// `version_range` is `Some` only when the property's value is itself a plain string
    /// literal (an object/array/number/bool/null value has no meaningful "version span",
    /// matching each caller's own `value.as_str()` gate on whether the entry is a
    /// dependency declaration at all). `None` if `name` isn't a direct property of this
    /// section.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::json_ast::JsonAst;
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let content = r#"{"require": {"vendor/pkg": {"nested": true}}}"#;
    /// let table = LineOffsetTable::new(content);
    /// let ast = JsonAst::parse(content).unwrap();
    /// let section = ast.section("require").unwrap();
    ///
    /// let (_, version_range) = section.position("vendor/pkg", content, &table).unwrap();
    /// assert!(version_range.is_none(), "a non-string value has no version span");
    /// assert!(section.position("missing", content, &table).is_none());
    /// ```
    #[must_use]
    pub fn position(
        &self,
        name: &str,
        content: &str,
        table: &LineOffsetTable,
    ) -> Option<(Range, Option<Range>)> {
        let prop = *self.by_name.get(name)?;
        Some(dependency_position(content, table, prop))
    }
}

/// Converts one dependency's AST property into its `(name_range, version_range)` LSP position
/// pair.
///
/// Trimming a literal's surrounding quotes is always a safe, single-byte, ASCII offset
/// adjustment regardless of whether the literal's *value* required unescaping — unlike
/// recovering a sub-span *inside* an escaped value (see `deps-deno`'s parser for that harder
/// case), which this never needs to do since a caller only ever wants the whole version
/// literal's span, not a piece of it.
fn dependency_position(
    content: &str,
    table: &LineOffsetTable,
    prop: &ObjectProp<'_>,
) -> (Range, Option<Range>) {
    let name_range = match &prop.name {
        ObjectPropName::String(lit) => quoted_lsp_range(content, table, lit.range),
        // Defensive only: an unquoted property name can't occur in content already accepted by
        // `parse_json_checked`'s strict-JSON parse, but this must not mis-trim quotes that
        // aren't there if it somehow does.
        ObjectPropName::Word(lit) => {
            byte_span_to_range(content, table, lit.range.start, lit.range.end)
        }
    };
    let version_range = match &prop.value {
        Value::StringLit(lit) => Some(quoted_lsp_range(content, table, lit.range)),
        _ => None,
    };
    (name_range, version_range)
}

/// Converts a jsonc-parser `Range` spanning a quoted literal (including its surrounding quotes)
/// into the LSP `Range` covering just the inner, unquoted text.
fn quoted_lsp_range(
    content: &str,
    table: &LineOffsetTable,
    range: jsonc_parser::common::Range,
) -> Range {
    byte_span_to_range(content, table, range.start + 1, range.end.saturating_sub(1))
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 for Position/Range assertions never \
              approach truncation range"
)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jsonc_typed_last_duplicate_key_wins() {
        let parsed: Option<HashMap<String, u32>> =
            parse_jsonc_typed(r#"{"a": 1, "a": 2}"#, "t").unwrap();
        assert_eq!(parsed.unwrap()["a"], 2);
    }

    #[test]
    fn test_parse_jsonc_typed_rejects_non_json_number_and_wrong_shape() {
        assert!(parse_jsonc_typed::<serde_json::Value>("[0x10]", "t").is_err());
        assert!(parse_jsonc_typed::<HashMap<String, u32>>(r#"{"a": "x"}"#, "t").is_err());
    }

    #[test]
    fn test_parse_jsonc_typed_nesting_depth_boundary() {
        let nest = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_jsonc_typed::<serde_json::Value>(&nest(MAX_JSON_NESTING_DEPTH), "t").is_ok());
        let err = parse_jsonc_typed::<serde_json::Value>(&nest(MAX_JSON_NESTING_DEPTH + 1), "t")
            .unwrap_err();
        assert_eq!(
            err.parse_failure_kind(),
            Some(ParseFailureKind::NestingTooDeep)
        );
    }

    fn oracle(content: &str) -> Result<Option<serde_json::Value>> {
        let Some(root) = parse_jsonc_ast_checked(content, "t")? else {
            return Ok(None);
        };
        ast_to_json(&root, "t").map(Some)
    }

    #[test]
    fn test_parse_jsonc_typed_matches_value_tree_oracle() {
        let corpus = [
            r#"{"a": 1, "a": 2, "b": {"c": [1, 2.5, -3, 1e3, true, null, "xé\n"]}}"#,
            "{\"k\": 1, // c\n \"k\": {\"k\": [ {\"z\": 1, \"z\": 2}, ], }, /* d */ }",
            "[18446744073709551615, -9223372036854775808, 0.1, 1E-2]",
            r#""scalar""#,
            "null",
            r#"{"": "", "a": 1, "a": 2}"#,
            r#"{"vendor\/pkg": ["a@1.0.0", "", {}, "sha512-x"]}"#,
        ];
        for content in corpus {
            let expected = oracle(content).unwrap();
            let actual = parse_jsonc_typed::<serde_json::Value>(content, "t").unwrap();
            assert_eq!(actual, expected, "{content}");
        }
        for bad in ["[0x10]", "[1,, 2]", "{", "[.5]"] {
            assert_eq!(
                parse_jsonc_typed::<serde_json::Value>(bad, "t").is_err(),
                oracle(bad).is_err(),
                "{bad}"
            );
        }
    }

    /// Asserts `parse_jsonc_typed::<T>` and `from_value::<T>` over the oracle tree agree on
    /// success vs failure and, on success, on the value.
    fn assert_typed_matches_oracle<T>(content: &str)
    where
        T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let expected = oracle(content).map(|tree| tree.map(serde_json::from_value::<T>));
        let actual = parse_jsonc_typed::<T>(content, "t");
        match (expected, actual) {
            (Ok(Some(Ok(expected))), Ok(Some(actual))) => assert_eq!(actual, expected, "{content}"),
            (Ok(Some(Err(_))) | Err(_), Err(_)) | (Ok(None), Ok(None)) => {}
            (expected, actual) => panic!(
                "{} {content}: oracle {expected:?}, actual {actual:?}",
                std::any::type_name::<T>()
            ),
        }
    }

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Newtype(u32);

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Pair(u8, String);

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Partial {
        keep: Vec<u32>,
        #[serde(default)]
        opt: Option<String>,
    }

    #[test]
    fn test_parse_jsonc_typed_typed_targets_match_value_tree_oracle() {
        use std::collections::BTreeMap;

        let inputs = [
            "{}",
            r#"{"a": 1, "b": 4294967295, "c": 4294967296, "d": -1, "e": 1.5, "f": 2.0}"#,
            r#"{"1": "x", "2": "y", "-3": "z", "k": "w", "1": "dup"}"#,
            r#"{"1": "x", "2": "y", "1": "dup"}"#,
            r#"{"-3": "z", "127": "m", "128": "n"}"#,
            r#"{"1": 2, "-3": 4, "300": 1}"#,
            r#"{"1": 2, "-3": 4}"#,
            r#"{"true": 1, "1.5": 2, "": 3}"#,
            "[0, 255, 256, -1, 1.0, 18446744073709551615, -9223372036854775808]",
            r#"[1, "a"]"#,
            r#"[1, "a", 3]"#,
            "[1]",
            "[]",
            "true",
            "false",
            "null",
            "1",
            "-1",
            "1.5",
            "4294967296",
            "18446744073709551615",
            "-9223372036854775808",
            "9223372036854775808",
            r#""text""#,
            r#"{"keep": [1, 2], "opt": null, "skip": {"deep": [[[{"x": 1}]]], "n": 0.5}}"#,
            r#"{"keep": [1], "opt": "o", "keep": [2, 3], "skip": [1, {"a": null}]}"#,
            r#"{"keep": "no"}"#,
            r#"{"opt": "missing keep"}"#,
            "[0x10]",
            "[1,, 2]",
            "{",
            "",
            "// only a comment",
        ];
        for input in inputs {
            assert_typed_matches_oracle::<HashMap<String, u32>>(input);
            assert_typed_matches_oracle::<BTreeMap<u32, String>>(input);
            assert_typed_matches_oracle::<BTreeMap<i8, u8>>(input);
            assert_typed_matches_oracle::<Vec<u8>>(input);
            assert_typed_matches_oracle::<Vec<i64>>(input);
            assert_typed_matches_oracle::<Vec<u64>>(input);
            assert_typed_matches_oracle::<Vec<f64>>(input);
            assert_typed_matches_oracle::<(u8, String)>(input);
            assert_typed_matches_oracle::<Pair>(input);
            assert_typed_matches_oracle::<Newtype>(input);
            assert_typed_matches_oracle::<bool>(input);
            assert_typed_matches_oracle::<u32>(input);
            assert_typed_matches_oracle::<i64>(input);
            assert_typed_matches_oracle::<u64>(input);
            assert_typed_matches_oracle::<f64>(input);
            assert_typed_matches_oracle::<String>(input);
            assert_typed_matches_oracle::<Option<u32>>(input);
            assert_typed_matches_oracle::<Option<Vec<u8>>>(input);
            assert_typed_matches_oracle::<Partial>(input);
            assert_typed_matches_oracle::<()>(input);
            assert_typed_matches_oracle::<serde::de::IgnoredAny>(input);
        }
    }

    #[test]
    fn test_parse_jsonc_typed_float_to_integer_is_an_error() {
        assert!(parse_jsonc_typed::<u32>("1.5", "t").is_err());
        assert!(parse_jsonc_typed::<u32>("2.0", "t").is_err());
        assert!(parse_jsonc_typed::<u8>("256", "t").is_err());
    }

    #[test]
    fn test_parse_jsonc_typed_duplicate_key_in_derived_struct() {
        #[derive(serde::Deserialize)]
        struct Doc {
            a: u32,
        }
        let doc: Doc = parse_jsonc_typed(r#"{"a": 1, "a": 2}"#, "t")
            .unwrap()
            .unwrap();
        assert_eq!(doc.a, 2);
    }

    #[test]
    fn test_parse_jsonc_typed_option_and_unit_enum() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        enum Kind {
            Alpha,
        }
        #[derive(serde::Deserialize)]
        struct Doc {
            kind: Kind,
            maybe: Option<u32>,
            absent: Option<u32>,
        }
        let doc: Doc = parse_jsonc_typed(r#"{"kind": "Alpha", "maybe": null}"#, "t")
            .unwrap()
            .unwrap();
        assert_eq!(doc.kind, Kind::Alpha);
        assert_eq!((doc.maybe, doc.absent), (None, None));
        assert!(parse_jsonc_typed::<Doc>(r#"{"kind": 1}"#, "t").is_err());
    }

    #[test]
    fn test_parse_jsonc_typed_comment_only_is_none() {
        assert!(
            parse_jsonc_typed::<serde_json::Value>("// c\n/* d */", "t")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_section_indexes_direct_properties_only() {
        let content = r#"{"require": {"a/b": {"c/d": "0.0.1"}, "c/d": "^2.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        let (_, version_range) = section.position("c/d", content, &table).unwrap();
        let version_range = version_range.unwrap();
        // The real top-level "c/d" value ("^2.0") is what must be found, not the nested one
        // ("0.0.1") inside "a/b"'s value.
        let expected_start = content.rfind("^2.0").unwrap();
        assert_eq!(version_range.start.character, expected_start as u32);
    }

    #[test]
    fn test_duplicate_top_level_key_resolves_to_last_occurrence() {
        let content = r#"{"require": {"a": "1.0"}, "require": {"b": "2.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        assert!(section.position("b", content, &table).is_some());
        assert!(section.position("a", content, &table).is_none());
    }

    /// M6(a): a duplicate key *within* a section (as opposed to a duplicate top-level section
    /// key) must resolve to its last occurrence too — `HashMap::insert` overwrites in source
    /// order, so the last-seen `ObjectProp` for a repeated name is the one that survives.
    #[test]
    fn test_duplicate_key_within_section_resolves_to_last_occurrence() {
        let content = r#"{"dependencies": {"pkg": "1.0", "pkg": "2.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("dependencies").unwrap();

        let (_, version_range) = section.position("pkg", content, &table).unwrap();
        let version_range = version_range.unwrap();
        let expected_start = content.rfind("2.0").unwrap();
        assert_eq!(version_range.start.character, expected_start as u32);
    }

    /// M6(b): the whole double-parse design rests on `ObjectPropName::as_str()` returning the
    /// *unescaped* key, matching `serde_json`'s own unescaped `Map` key — so a lookup by the
    /// unescaped name must find a property declared with an escaped key in the source.
    #[test]
    fn test_escaped_key_resolves_through_the_section_index() {
        let content = r#"{"require": {"vendor\/pkg": "^1.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        // Looked up by the unescaped name — the same string `serde_json::Map`'s key holds.
        let (name_range, version_range) = section.position("vendor/pkg", content, &table).unwrap();
        // The raw (still-escaped) source span is 15 bytes: "vendor\/pkg" == v-e-n-d-o-r-\-/-p-k-g.
        assert_eq!(name_range.end.character - name_range.start.character, 11);
        assert!(version_range.is_some());
    }

    #[test]
    fn test_section_missing_key_is_none() {
        let content = r#"{"require": {}}"#;
        let ast = JsonAst::parse(content).unwrap();
        assert!(ast.section("require-dev").is_none());
    }

    #[test]
    fn test_section_non_object_value_is_none() {
        let content = r#"{"require": "not-an-object"}"#;
        let ast = JsonAst::parse(content).unwrap();
        assert!(ast.section("require").is_none());
    }

    #[test]
    fn test_parse_invalid_json_is_none() {
        assert!(JsonAst::parse("{ not valid").is_none());
    }

    #[test]
    fn test_parse_non_object_root_is_none() {
        assert!(JsonAst::parse("[1, 2, 3]").is_none());
    }

    #[test]
    fn test_position_trims_quotes_and_finds_version() {
        let content = r#"{"require": {"vendor/pkg": "^1.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        let (name_range, version_range) = section.position("vendor/pkg", content, &table).unwrap();
        let name_start = content.find("vendor/pkg").unwrap();
        assert_eq!(name_range.start.character, name_start as u32);
        assert_eq!(
            name_range.end.character,
            (name_start + "vendor/pkg".len()) as u32
        );

        let version_range = version_range.expect("string value must produce a version_range");
        let version_start = content.find("^1.0").unwrap();
        assert_eq!(version_range.start.character, version_start as u32);
    }

    #[test]
    fn test_position_non_string_value_has_no_version_range() {
        let content = r#"{"require": {"vendor/pkg": {"nested": true}}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        let (_, version_range) = section.position("vendor/pkg", content, &table).unwrap();
        assert!(version_range.is_none());
    }

    #[test]
    fn test_position_missing_name_is_none() {
        let content = r#"{"require": {"vendor/pkg": "^1.0"}}"#;
        let table = LineOffsetTable::new(content);
        let ast = JsonAst::parse(content).unwrap();
        let section = ast.section("require").unwrap();

        assert!(
            section
                .position("does-not-exist", content, &table)
                .is_none()
        );
    }

    // #673: property tests for JSONC parsing/position recovery, shared by every
    // JSON-manifest ecosystem (npm, Composer, NuGet, Deno). Complements the `fuzz/`
    // corpus with a fast, CI-covered "never panics, never returns an out-of-bounds
    // offset" gate over arbitrary input.
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            // #673 S3: random bytes almost never parse as valid JSON, so the original version
            // of this property barely reached `section.position`. Generates a manifest-shaped
            // grammar instead so parsing succeeds and position recovery runs every time.
            #[test]
            fn parse_and_position_never_panic(
                pairs in proptest::collection::vec(
                    ("[a-zA-Z0-9_.-]{1,20}", "[a-zA-Z0-9_.-]{1,20}"),
                    0..8,
                )
            ) {
                let mut deps = serde_json::Map::new();
                for (name, version) in &pairs {
                    deps.insert(name.clone(), serde_json::Value::String(version.clone()));
                }
                let mut root = serde_json::Map::new();
                root.insert("dependencies".to_string(), serde_json::Value::Object(deps));
                let content = serde_json::to_string_pretty(&serde_json::Value::Object(root))
                    .expect("serde_json::Value serialization is infallible");

                let Some(ast) = JsonAst::parse(&content) else {
                    return Ok(());
                };
                let table = LineOffsetTable::new(&content);
                let Some(section) = ast.section("dependencies") else {
                    return Ok(());
                };

                for (name, _) in &pairs {
                    // Property: any returned range's start line must be a real line in
                    // `table` — position recovery must never invent an out-of-bounds
                    // line/offset for content it was itself derived from.
                    if let Some((name_range, version_range)) =
                        section.position(name, &content, &table)
                    {
                        prop_assert!(table.line_start(name_range.start.line as usize).is_some());
                        if let Some(version_range) = version_range {
                            prop_assert!(
                                table.line_start(version_range.start.line as usize).is_some()
                            );
                        }
                    }
                }
            }
        }
    }
}
