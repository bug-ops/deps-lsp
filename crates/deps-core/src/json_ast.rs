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
//! types directly.

use jsonc_parser::ast::{Object, ObjectProp, ObjectPropName, Value};
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use std::collections::HashMap;
use tower_lsp_server::ls_types::Range;

use crate::lsp_helpers::LineOffsetTable;

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
    /// matching each caller's own `value.as_str()` gate on `version_req`). `None` if `name`
    /// isn't a direct property of this section.
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
        ObjectPropName::Word(lit) => Range::new(
            table.byte_offset_to_position(content, lit.range.start),
            table.byte_offset_to_position(content, lit.range.end),
        ),
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
    Range::new(
        table.byte_offset_to_position(content, range.start + 1),
        table.byte_offset_to_position(content, range.end.saturating_sub(1)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
