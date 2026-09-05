//! `deno.json` / `deno.jsonc` parser using `jsonc-parser`'s AST (D6).
//!
//! Plain JSON is a strict subset of JSONC, so both `deno.json` and `deno.jsonc` share this
//! single code path. Reading positions straight off the AST (rather than a text search) is
//! required here specifically because Deno import maps routinely point several aliases at the
//! identical specifier value — a find-first-occurrence text search would hand every such alias
//! the same source position, corrupting hover/inlay-hint/code-action targeting. `deps-npm` and
//! `deps-composer` since #613 also read positions off this same `jsonc-parser` AST (via
//! `deps_core::json_ast`), for the equally AST-shaped duplicate-key and nested-value bugs their
//! own manifests can hit — this module's `find_last_prop` reuse of that shared helper is the
//! overlap between the two designs; the value-oriented parsing below (specifier scheme
//! detection, escape guards) is Deno-specific and has no equivalent there.

use crate::specifier::parse_specifier;
use crate::types::{DenoDependency, DenoDependencySection};
use deps_core::json_ast::find_last_prop;
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::{
    DepsError, MAX_JSON_NESTING_DEPTH, PackageName, Result, VersionReq, json_depth_error_message,
};
use jsonc_parser::ast::{Object, StringLit, Value};
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use std::borrow::Cow;
use std::collections::HashSet;
use tower_lsp_server::ls_types::{Range, Uri};

/// Result of parsing a `deno.json`/`deno.jsonc` file.
#[derive(Debug)]
pub struct DenoParseResult {
    /// All dependencies found in the `imports` map.
    pub dependencies: Vec<DenoDependency>,
    /// Document URI.
    pub uri: Uri,
}

deps_core::impl_parse_result!(
    DenoParseResult,
    DenoDependency {
        dependencies: dependencies,
        uri: uri,
    }
);

/// Parses a `deno.json`/`deno.jsonc` file and extracts all `imports` entries with
/// positions.
///
/// # Errors
///
/// Returns an error if the content is not valid JSON/JSONC (malformed syntax, unclosed
/// block comment, stray brace), or if the parsed AST nests deeper than
/// [`deps_core::MAX_JSON_NESTING_DEPTH`] — the file is then not recognized as a Deno
/// manifest and degrades gracefully (spec §6), matching every other ecosystem's
/// parse-failure behavior.
///
/// # Examples
///
/// ```no_run
/// use deps_deno::parser::parse_deno_json;
/// use tower_lsp_server::ls_types::Uri;
///
/// let json = r#"{
///   "imports": {
///     "@std/fs": "jsr:@std/fs@^1.0"
///   }
/// }"#;
/// let uri = Uri::from_file_path("/project/deno.json").unwrap();
///
/// let result = parse_deno_json(json, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "jsr:@std/fs");
/// ```
pub fn parse_deno_json(content: &str, uri: &Uri) -> Result<DenoParseResult> {
    let ast = parse_to_ast(
        content,
        &CollectOptions::default(),
        &ParseOptions::default(),
    )
    .map_err(|e| DepsError::ParseError {
        file_type: "deno.json".into(),
        source: e.to_string().into(),
    })?;

    if let Some(value) = &ast.value
        && let Err(depth) = check_ast_nesting_depth(value, MAX_JSON_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "deno.json".into(),
            source: json_depth_error_message(depth).into(),
        });
    }

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    if let Some(Value::Object(root)) = ast.value
        && let Some(imports_prop) = find_last_prop(&root, "imports")
        && let Value::Object(imports) = &imports_prop.value
    {
        collect_imports(imports, content, &line_table, &mut dependencies);
    }

    Ok(DenoParseResult {
        dependencies,
        uri: uri.clone(),
    })
}

/// Computes `value`'s real nesting depth (`value` itself counts as depth 1, each further
/// `Object`/`Array` descent adds one), rejecting once it exceeds `max_depth`.
///
/// Unlike a raw byte scan over the source text (`deps_core::check_json_nesting_depth`, the
/// pattern `deps-npm`/`deps-composer` use ahead of their own strict-JSON `serde_json` parse),
/// walking the already-parsed AST is immune to JSONC comment characters (`//`, `/* */`)
/// miscounting as structural nesting — a comment's bracket characters never become AST nodes
/// at all, so they cannot be mistaken for real nesting the way a text scanner would (impl-critic
/// #618 S1). `jsonc-parser`'s own hardcoded 512-deep recursion cap already bounded
/// `parse_to_ast` itself before this ever runs, so this walk exists to align `deno.json`
/// parsing with `deps_core::MAX_JSON_NESTING_DEPTH` — the same, tighter bound every other
/// workspace JSON call site enforces — not because `parse_to_ast`'s result is unsafe to walk.
/// An explicit stack (rather than recursive descent) keeps the walk itself non-recursive
/// regardless.
///
/// # Errors
///
/// Returns `Err(depth)` with the depth reached the instant nesting exceeds `max_depth`.
fn check_ast_nesting_depth(root: &Value<'_>, max_depth: usize) -> std::result::Result<(), usize> {
    let mut stack = vec![(root, 1_usize)];
    while let Some((value, depth)) = stack.pop() {
        // Only `Object`/`Array` nodes open a nesting level; a leaf (string/number/bool/null)
        // is never itself checked or descended into, so it can never inflate the depth of the
        // container that holds it.
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

/// Builds a [`DenoDependency`] for every entry in the `imports` object, applying
/// last-alias-wins deduplication (S6) so a manifest with two entries for the same import
/// alias produces exactly one dependency — positioned at the *last* occurrence, matching
/// where its value actually lives once JSON parsing collapses the duplicate.
fn collect_imports(
    imports: &Object,
    content: &str,
    line_table: &LineOffsetTable,
    out: &mut Vec<DenoDependency>,
) {
    let mut seen_aliases = HashSet::new();
    let mut collected = Vec::new();

    // Walk in reverse (last occurrence first) so the first alias we see for a given key
    // is the one that wins; earlier (source-order) duplicates are then skipped.
    for prop in imports.properties.iter().rev() {
        let alias = prop.name.as_str();
        if !seen_aliases.insert(alias.to_string()) {
            continue;
        }
        let Value::StringLit(value_lit) = &prop.value else {
            continue;
        };
        if let Some(dep) = build_dependency(value_lit, content, line_table) {
            collected.push(dep);
        }
    }

    // Restore source order for the surviving (deduplicated) entries.
    collected.reverse();
    out.extend(collected);
}

/// Builds a [`DenoDependency`] from one `imports` value's string literal, or `None` if the
/// value is neither a recognized `jsr:`/`npm:` specifier nor a syntactically incomplete,
/// still-being-typed one (D7 — e.g. `http://`, `file:`, a bare alias — silently skipped,
/// same as an unparseable entry in any other ecosystem).
fn build_dependency(
    value_lit: &StringLit,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<DenoDependency> {
    let raw_value = value_lit.value.as_ref();

    // S5 escape guard: `value_lit.range` covers the whole literal *including* its
    // surrounding quotes. Byte-arithmetic from that range into offsets relative to the
    // *unescaped* value is only sound when no unescaping happened — exactly when
    // `value_lit.value` is `Cow::Borrowed` (a direct slice of the source). Deno specifiers
    // never legitimately need escapes, so this is a correctness fail-safe: an escaped
    // value only degrades to the inner-span fallback (no `version_range`) when it fully
    // parses; a partial/in-progress escaped value (#310) is skipped entirely rather than
    // guessing at an unsound byte range for it.
    if let Cow::Owned(_) = &value_lit.value {
        let parsed = parse_specifier(raw_value)?;
        tracing::debug!(
            "deno.json: import value contains escape sequences, skipping precise position tracking"
        );
        let inner_start = value_lit.range.start + 1;
        let inner_end = value_lit.range.end.saturating_sub(1);
        return Some(DenoDependency {
            name: PackageName::new(parsed.name),
            name_range: byte_range_to_lsp(content, line_table, inner_start, inner_end),
            version_req: parsed.version_req.map(VersionReq::new),
            version_range: None,
            section: DenoDependencySection::Imports,
        });
    }

    // The literal's inner (unquoted) text starts right after its opening quote.
    let value_start = value_lit.range.start + 1;

    if let Some(parsed) = parse_specifier(raw_value) {
        let name_range = byte_range_to_lsp(
            content,
            line_table,
            value_start + parsed.name_range.start,
            value_start + parsed.name_range.end,
        );
        let version_range = parsed.version_range.map(|r| {
            byte_range_to_lsp(
                content,
                line_table,
                value_start + r.start,
                value_start + r.end,
            )
        });

        return Some(DenoDependency {
            name: PackageName::new(parsed.name),
            name_range,
            version_req: parsed.version_req.map(VersionReq::new),
            version_range,
            section: DenoDependencySection::Imports,
        });
    }

    // #310: a syntactically incomplete but still in-progress jsr:/npm: specifier ("jsr:",
    // "jsr:@", "jsr:@std", "jsr:@std/", ...) — `parse_specifier` correctly rejects these
    // (not yet a valid, routable name), but a `Dependency` must still exist here for
    // `detect_completion_context` to have a range to fire `PackageName` completion
    // against. This mirrors `deps-npm`'s parser, which always builds a `Dependency` from a
    // `dependencies` object key regardless of scope completeness (`deps-npm/src/parser.rs`)
    // — validity is deferred to `DenoFormatter::validate_package_name`'s diagnostic, not
    // gated at parse time.
    let partial_range = crate::specifier::partial_name_range(raw_value)?;
    let name_range = byte_range_to_lsp(
        content,
        line_table,
        value_start + partial_range.start,
        value_start + partial_range.end,
    );

    Some(DenoDependency {
        name: PackageName::new(&raw_value[partial_range]),
        name_range,
        version_req: None,
        version_range: None,
        section: DenoDependencySection::Imports,
    })
}

/// Converts a `[start, end)` byte range in `content` to an LSP `Range`.
fn byte_range_to_lsp(content: &str, table: &LineOffsetTable, start: usize, end: usize) -> Range {
    Range::new(
        table.byte_offset_to_position(content, start),
        table.byte_offset_to_position(content, end),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/deno.json")
    }

    #[test]
    fn test_parse_simple_jsr_import() {
        let json = r#"{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "jsr:@std/fs");
        assert_eq!(dep.version_req, Some("^1.0".into()));
        assert_matches!(dep.section, DenoDependencySection::Imports);
    }

    #[test]
    fn test_parse_npm_import() {
        let json = r#"{
  "imports": {
    "react": "npm:react@^18"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "npm:react");
        assert_eq!(result.dependencies[0].version_req, Some("^18".into()));
    }

    #[test]
    fn test_parse_mixed_jsr_and_npm() {
        let json = r#"{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0",
    "react": "npm:react@^18",
    "preact": "npm:preact@^10"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert!(result.dependencies.iter().any(|d| d.name == "jsr:@std/fs"));
        assert!(result.dependencies.iter().any(|d| d.name == "npm:react"));
        assert!(result.dependencies.iter().any(|d| d.name == "npm:preact"));
    }

    #[test]
    fn test_parse_empty_imports() {
        let json = r#"{"imports": {}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_parse_no_imports_key() {
        let json = r#"{"name": "my-app"}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_parse_unsupported_specifier_silently_skipped() {
        let json = r#"{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0",
    "legacy": "https://deno.land/x/legacy/mod.ts",
    "local": "./local.ts"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@std/fs");
    }

    #[test]
    fn test_parse_invalid_json_errors() {
        let json = "{ imports: not valid json !!!";
        let result = parse_deno_json(json, &test_uri());
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "deno.json"
        );
    }

    #[test]
    fn test_parse_jsonc_comments_tolerated() {
        let jsonc = r#"{
  // line comment
  "imports": {
    /* block comment */
    "@std/fs": "jsr:@std/fs@^1.0"
  }
}"#;

        let result = parse_deno_json(jsonc, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@std/fs");
    }

    #[test]
    fn test_duplicate_alias_keys_last_wins() {
        // S6: jsonc-parser's `Vec<ObjectProp>` does not dedupe like serde_json::Map does.
        let json = r#"{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0",
    "@std/fs": "jsr:@std/fs@^2.0"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("^2.0".into()));
        // The surviving dependency's position must be the *last* occurrence's line.
        assert_eq!(result.dependencies[0].name_range.start.line, 3);
    }

    #[test]
    fn test_two_aliases_same_specifier_get_distinct_positions() {
        // The core reason D6 uses the AST rather than deps-npm's text-search pattern:
        // two different aliases mapping to the identical specifier value must not collapse
        // onto the same source position.
        let json = r#"{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0",
    "@std/fs/": "jsr:@std/fs@^1.0"
  }
}"#;

        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        let lines: Vec<u32> = result
            .dependencies
            .iter()
            .map(|d| d.name_range.start.line)
            .collect();
        assert_ne!(lines[0], lines[1]);
    }

    #[test]
    fn test_empty_version_after_at_produces_a_version_range() {
        // S7, exercised through the full parser: the completion path relies on
        // `version_range` being `Some` (an empty span) right after the user types '@'.
        let json = r#"{"imports": {"@std/fs": "jsr:@std/fs@"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.version_req, Some(String::new().into()));
        let range = dep.version_range.expect("version_range must be Some");
        assert_eq!(range.start, range.end);
    }

    #[test]
    fn test_scoped_npm_import() {
        let json = r#"{"imports": {"node-types": "npm:@types/node@^20"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "npm:@types/node");
        assert_eq!(result.dependencies[0].version_req, Some("^20".into()));
    }

    #[test]
    fn test_escaped_specifier_falls_back_to_inner_span_with_no_version_range() {
        // S5 escape-guard fail-safe: a JSON `\uXXXX` escape inside the value (unescaping
        // to the character '1' here) means `value_lit.value` is `Cow::Owned`, so
        // byte-offset arithmetic into the raw *source* text is unsound for anything
        // narrower than the whole literal. `name`/`version_req` still come from the
        // already-unescaped value (jsonc-parser did that work); only position tracking
        // degrades to the inner-span fallback with no `version_range`.
        let json_escape = "\\u0031"; // a JSON \uXXXX escape unescaping to the character '1'
        let raw_value = format!("jsr:@std/fs@{json_escape}.0"); // raw source text, escape included
        let json = format!(r#"{{"imports": {{"@std/fs": "{raw_value}"}}}}"#);
        let result = parse_deno_json(&json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "jsr:@std/fs");
        assert_eq!(dep.version_req, Some("1.0".into()));
        assert!(dep.version_range.is_none());

        // name_range widens to the raw literal's inner span (excluding quotes) — the
        // whole escaped value text, not just the name portion, and never the whole
        // literal *including* quotes (which would let a later edit delete them).
        let value_start_byte = json.find(&format!("\"{raw_value}\"")).unwrap() + 1;
        let value_end_byte = value_start_byte + raw_value.len();

        assert_eq!(dep.name_range.start.line, 0);
        assert_eq!(dep.name_range.start.character, value_start_byte as u32);
        assert_eq!(dep.name_range.end.character, value_end_byte as u32);
    }

    // --- #310: partial jsr:/npm: specifiers still produce a completion-eligible Dependency ---

    #[test]
    fn test_partial_jsr_bare_scheme_produces_dependency_with_no_version() {
        let json = r#"{"imports": {"@std/fs": "jsr:"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "jsr:");
        assert_eq!(dep.version_req, None);
        assert_eq!(dep.version_range, None);
    }

    #[test]
    fn test_partial_jsr_scope_started_produces_dependency() {
        let json = r#"{"imports": {"@std/fs": "jsr:@"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@");
    }

    #[test]
    fn test_partial_jsr_scope_in_progress_produces_dependency() {
        let json = r#"{"imports": {"@std/fs": "jsr:@std"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@std");
    }

    #[test]
    fn test_partial_jsr_trailing_slash_produces_dependency() {
        let json = r#"{"imports": {"@std/fs": "jsr:@std/"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@std/");
    }

    #[test]
    fn test_partial_specifier_name_range_covers_the_typed_text() {
        // The completion path relies on `name_range` spanning exactly the typed text (no
        // quotes) so `detect_completion_context` can extract the right prefix.
        let json = r#"{"imports": {"@std/fs": "jsr:@std/"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        let value_start = json.find(r#""jsr:@std/""#).unwrap() + 1;
        assert_eq!(dep.name_range.start.character, value_start as u32);
        assert_eq!(
            dep.name_range.end.character,
            (value_start + "jsr:@std/".len()) as u32
        );
    }

    #[test]
    fn test_permanently_malformed_empty_scope_still_skipped() {
        // "jsr:@/pkg" is not a partial state (no scope prefix to complete against) --
        // must remain silently skipped, same as before #310.
        let json = r#"{"imports": {"@std/fs": "jsr:@/pkg"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_unsupported_scheme_still_skipped_not_treated_as_partial() {
        let json = r#"{"imports": {"legacy": "https://deno.land/x/legacy/mod.ts"}}"#;
        let result = parse_deno_json(json, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_partial_specifier_end_to_end_completion_context_fires() {
        use deps_core::completion::{CompletionContext, detect_completion_context};

        for value in ["jsr:", "jsr:@", "jsr:@std", "jsr:@std/"] {
            let content = format!(r#"{{"imports": {{"@std/fs": "{value}"}}}}"#);
            let result = parse_deno_json(&content, &test_uri()).unwrap();
            assert_eq!(result.dependencies.len(), 1, "value: {value}");

            let name_range = result.dependencies[0].name_range;
            let cursor = name_range.end; // cursor right after the last typed character
            let context = detect_completion_context(&result, cursor, &content);

            match context {
                CompletionContext::PackageName { prefix, .. } => {
                    assert_eq!(prefix, value, "value: {value}");
                }
                other => panic!("value {value}: expected PackageName context, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_parse_deeply_nested_json_rejected_after_ast_parse() {
        // #618: a deeply nested deno.json must be rejected by the explicit AST nesting-depth
        // guard (deps_core::MAX_JSON_NESTING_DEPTH, tighter than jsonc-parser's own
        // internal 512-deep recursion cap) once it's been safely parsed, matching
        // deps-npm/deps-composer's own JSON depth bound (#617/#430) even though those two
        // apply it to raw text ahead of a strict-JSON `serde_json` parse, not JSONC.
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_deno_json(&json, &test_uri());
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "deno.json"
        );
    }

    #[test]
    fn test_parse_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"imports": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let result = parse_deno_json(&json, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_comment_brackets_not_miscounted_as_nesting() {
        // impl-critic #618 S1: a byte-level scanner over raw source text would miscount
        // comment bracket characters as structural nesting; the AST-based check must ignore
        // them entirely, since a comment never produces an AST node.
        let over_max_bracket_count = deps_core::MAX_JSON_NESTING_DEPTH + 5;
        let comment_brackets = "[".repeat(over_max_bracket_count);
        let json = format!(
            r#"{{
  // {comment_brackets}
  "imports": {{
    "@std/fs": "jsr:@std/fs@^1.0"
  }}
}}"#
        );
        let result = parse_deno_json(&json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "jsr:@std/fs");
    }

    #[test]
    fn test_unclosed_block_comment_is_a_parse_error() {
        // deps-lsp testing gap: the only prior invalid-JSONC test used generic garbage
        // text, not the JSONC-specific failure mode the parser's own docs name.
        let jsonc = r#"{
  /* unclosed comment
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0"
  }
}"#;
        let result = parse_deno_json(jsonc, &test_uri());
        assert!(result.is_err());
    }
}
