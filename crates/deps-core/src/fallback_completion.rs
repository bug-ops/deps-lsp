//! Shared raw-text scanners for fallback (parse-failure) completion.
//!
//! When a manifest fails to parse (typically because the user is mid-edit), ecosystems
//! fall back to a raw-text heuristic instead of [`crate::ecosystem::Ecosystem::generate_completions`]'s
//! parsed-AST path: is the cursor inside a dependencies-like section, and if so, what
//! prefix has the user typed? This module holds the syntax-shape scanners shared by two
//! or more ecosystems (issue #722) — a manifest-format-specific ecosystem (e.g. Maven's
//! XML coordinate segments) keeps its own composition in its own crate, calling into
//! these primitives rather than reimplementing them.
//!
//! Each ecosystem composes these into its own
//! [`Ecosystem::fallback_completion_prefix`](crate::ecosystem::Ecosystem::fallback_completion_prefix)
//! override: a section-boundary check (this module, or an ecosystem-local equivalent)
//! followed by [`raw_prefix`] and, where the manifest syntax wraps the completable value
//! (a JSON string, an XML tag/attribute), a syntax-specific strip.

use tower_lsp_server::ls_types::Position;

/// Returns the line of `content` at `position.line`, or `None` if the document has
/// fewer lines than that (e.g. the cursor is on a not-yet-existing trailing line).
#[must_use]
pub fn line_at(content: &str, position: Position) -> Option<&str> {
    content.lines().nth(position.line as usize)
}

/// Extracts what the user has typed on `line` up to the cursor (`character`, a UTF-16
/// code unit count), trimmed of whitespace.
///
/// `character` is converted via [`crate::completion::utf16_to_byte_offset`]; when the
/// cursor sits beyond the line's UTF-16 length (`None`), this clamps to the full line
/// rather than panicking on an out-of-bounds slice.
#[must_use]
pub fn raw_prefix(line: &str, character: u32) -> &str {
    let prefix_end = crate::completion::utf16_to_byte_offset(line, character).unwrap_or(line.len());
    debug_assert!(
        line.is_char_boundary(prefix_end),
        "prefix_end must be a char boundary"
    );
    line.get(..prefix_end).unwrap_or(line).trim()
}

/// Checks if a line is inside a TOML dependencies section.
///
/// Looks for `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` sections
/// in Cargo.toml or `[project.dependencies]` in pyproject.toml. Shared by Cargo and
/// PyPI — PyPI's PEP 621 primary dependency list needs its own array-based scan on top
/// of this (see `deps_pypi`'s `is_in_pypi_project_dependencies_array`), since it is not
/// a section header at all.
#[must_use]
pub fn is_in_toml_dependencies(content: &str, line_number: usize) -> bool {
    // Walk backwards from current line to find the most recent section header
    // Collect lines up to target, then iterate backwards
    let lines: Vec<_> = content.lines().enumerate().take(line_number + 1).collect();

    for (_, line) in lines.iter().rev() {
        let line = line.trim();

        // Check if this is a section header
        if line.starts_with('[') && line.ends_with(']') {
            // Check if it's a dependencies section
            return line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line == "[workspace.dependencies]"
                || line == "[project.dependencies]"
                || line == "[project.optional-dependencies]"
                || line.starts_with("[target.")
                    && (line.contains(".dependencies]")
                        || line.contains(".dev-dependencies]")
                        || line.contains(".build-dependencies]"));
        }
    }

    false
}

/// Checks if a line is inside a JSON dependencies-like section.
///
/// Looks for `"{key}": {` for any of the given `keys`, e.g. `dependencies` /
/// `devDependencies` in package.json, or `require` / `require-dev` in composer.json.
#[must_use]
pub fn is_in_json_dependencies(content: &str, line_number: usize, keys: &[&str]) -> bool {
    let mut in_dependencies = false;
    let mut brace_depth = 0;
    // Build each `"{key}":` needle once per call rather than once per line.
    let needles: Vec<String> = keys.iter().map(|key| format!("\"{key}\":")).collect();

    for (i, line) in content.lines().enumerate() {
        // Early exit: stop if we've passed the target line
        if i > line_number {
            break;
        }

        let trimmed = line.trim();

        // Check if we're entering a dependencies-like section
        if trimmed.starts_with('"')
            && needles
                .iter()
                .any(|needle| trimmed.contains(needle.as_str()))
        {
            in_dependencies = true;
            brace_depth = 0;
        }

        // Track brace depth when in dependencies section
        if in_dependencies {
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        // If we've closed the dependencies section
                        if brace_depth <= 0 {
                            in_dependencies = false;
                        }
                    }
                    _ => {}
                }
            }

            // If we're at the target line and inside dependencies section with depth > 0
            if i == line_number && in_dependencies && brace_depth > 0 {
                return true;
            }
        }
    }

    false
}

/// Checks if a line is inside an XML `<tag>...</tag>` element.
///
/// Tracks nested open/close tag counts (ignoring attributes and self-closing tags) to
/// find whether the target line falls within any occurrence of the element, e.g.
/// `<dependencies>` in pom.xml (including nested inside `<dependencyManagement>`), or
/// `<ItemGroup>`/`<packages>` in NuGet's three manifest schemas.
#[must_use]
pub fn is_in_xml_tag_section(content: &str, line_number: usize, tag: &str) -> bool {
    let open_prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut depth: usize = 0;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let opens_here = count_open_tags(line, &open_prefix);
        depth += opens_here;
        // A line with an opening tag counts as "inside" even if the same line also
        // closes it (`<dependencies></dependencies>`), consistent with the target
        // line being the header itself in `is_in_toml_dependencies`.
        if i == line_number && opens_here > 0 {
            return true;
        }

        depth = depth.saturating_sub(line.matches(close.as_str()).count());
        if i == line_number && depth > 0 {
            return true;
        }
    }

    false
}

/// Counts real `<{open_prefix}...>` tag occurrences on `line`, i.e. `open_prefix`
/// followed by `>` or whitespace (an attribute) rather than more tag-name characters
/// (so `<dependencies` doesn't also match a longer, unrelated tag name).
// `search_from` starts at 0 and is only ever advanced to `idx + open_prefix.len()`,
// where `idx` is a `str::find` match start (always a char boundary) and the offset
// lands exactly at the end of that matched substring (also always a char boundary).
#[allow(clippy::string_slice)]
fn count_open_tags(line: &str, open_prefix: &str) -> usize {
    let mut count = 0;
    let mut search_from = 0;

    while let Some(rel_idx) = line[search_from..].find(open_prefix) {
        let idx = search_from + rel_idx;
        let after = &line[idx + open_prefix.len()..];
        if after.starts_with('>') || after.starts_with(char::is_whitespace) {
            count += 1;
        }
        search_from = idx + open_prefix.len();
    }

    count
}

/// Strips everything up to and including the *last* `>` in `prefix`, also returning the
/// name of the tag whose content the cursor now sits inside, when there is one.
///
/// `<artifactId>gua` -> `("gua", Some("artifactId"))`; returns `(prefix, None)` unchanged
/// if it contains no `>` at all (e.g. the tag is not yet closed, as when the user is
/// still typing the tag name itself).
///
/// Scans for the last `>`, not the first, to mirror the closest opening tag *before
/// the cursor*, which is the last one on the line, not the first — a first-`>` version
/// diverges whenever more than one tag precedes the cursor on a line
/// (`<groupId>com.google.guava</groupId><artifactId>gua` — the first `>` sits inside
/// `<groupId>`, well short of the real value).
///
/// The returned tag name is `None` in three cases: no `>` at all (see above); the
/// `<...>` ending at that `>` is a *closing* tag (`</artifactId>` — its name slice
/// starts with `/`), e.g. cursor right after `<artifactId>guava</artifactId>` — the
/// last `>` is the line's very last character, correctly yielding an empty stripped
/// string and no open tag; or loose text after a closed tag (`<artifactId>guava</artifactId>
/// comm` — same closing-tag case, `Some(" comm")` would otherwise wrongly read as
/// "inside `artifactId`"). Otherwise the name is the element name immediately after
/// that tag's `<` (attributes and a trailing `/` stripped, mirroring
/// [`strip_open_xml_attribute_value`]'s own element extraction).
#[must_use]
pub fn strip_leading_xml_tag(prefix: &str) -> (&str, Option<&str>) {
    // `>`/`<` are single-byte ASCII chars, so `gt + 1`/`lt + 1` are always valid char
    // boundaries, and slicing at `gt`/`lt` (found via `rfind` on the byte string) is too.
    #[allow(clippy::string_slice)]
    {
        let Some(gt) = prefix.rfind('>') else {
            return (prefix, None);
        };
        let stripped = &prefix[gt + 1..];
        let Some(lt) = prefix[..gt].rfind('<') else {
            return (stripped, None);
        };
        // A closing tag's name segment (`/artifactId` for `</artifactId>`) splits to an
        // empty first token, since `/` is itself a delimiter — that's what makes
        // `name.is_empty()` double as the "not a closing tag" check.
        let name = prefix[lt + 1..gt]
            .split(|c: char| c == '/' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if name.is_empty() {
            (stripped, None)
        } else {
            (stripped, Some(name))
        }
    }
}

/// Extracts the value being typed inside an open attribute (named in `attrs`) at the
/// end of `prefix`, on one of the elements named in `elements`
/// (`<PackageReference Include="Newt` -> `Newt`).
///
/// Returns an *empty* string whenever the cursor is not inside one of `attrs`'
/// *unclosed* values on one of `elements` — still inside the element/attribute name
/// itself (no candidate package-name text yet), inside a different attribute's value,
/// past an already-closed value, inside a target attribute name on an unrelated
/// element, or plain non-markup text (comments, a bare word). Deliberately empty
/// rather than the raw `prefix`, unlike [`strip_leading_xml_tag`]'s "return unchanged"
/// fallback: an unmodified prefix here would usually contain no `=` either, so a
/// caller's `contains('=')` guard alone cannot reject it, and a search on that raw
/// text would query the registry for markup or arbitrary noise.
///
/// Scans the whole `prefix` tracking the currently open quote, rather than `rfind` as
/// [`strip_leading_xml_tag`] does for tag content: an attribute value's opening quote
/// is the same character as a closed value's closing quote, so telling them apart
/// requires tracking quote parity from the start of the element instead of searching
/// backwards from the end. Only sees the element opening tag when it is on the same
/// line as the cursor.
#[must_use]
pub fn strip_open_xml_attribute_value<'a>(
    prefix: &'a str,
    elements: &[&str],
    attrs: &[&str],
) -> &'a str {
    let mut quote: Option<char> = None;
    let mut value_start = 0usize;
    let mut in_target_attr = false;
    let mut segment_start = 0usize;
    let mut element = "";

    for (idx, ch) in prefix.char_indices() {
        if let Some(open) = quote {
            if ch == open {
                quote = None;
                segment_start = idx + ch.len_utf8();
            }
            continue;
        }
        if ch == '<' {
            // `idx + 1` is a char boundary: `<` is a single-byte ASCII char. Reset
            // here too (not just on a closing quote) so `before_quote` below never
            // spans back across a *previous* element's tail.
            segment_start = idx + ch.len_utf8();
            #[allow(clippy::string_slice)]
            let rest = &prefix[segment_start..];
            element = rest
                .split(|c: char| c == '>' || c == '/' || c.is_whitespace())
                .next()
                .unwrap_or("");
            continue;
        }
        if ch == '"' || ch == '\'' {
            // `idx` is a char boundary (from `char_indices`), so this slice is valid.
            #[allow(clippy::string_slice)]
            let before_quote = prefix[segment_start..idx].trim_end();
            let name = before_quote
                .strip_suffix('=')
                .unwrap_or(before_quote)
                .split_whitespace()
                .next_back()
                .unwrap_or("");
            in_target_attr = elements.contains(&element) && attrs.contains(&name);
            quote = Some(ch);
            value_start = idx + ch.len_utf8();
        }
    }

    if quote.is_some() && in_target_attr {
        // `value_start` is `idx + ch.len_utf8()` for the opening quote char, always a
        // char boundary.
        #[allow(clippy::string_slice)]
        let value = &prefix[value_start..];
        // A package id never contains a quote character. The scan above only closes
        // `quote` on the *matching* delimiter, so an opposite-type quote character
        // would otherwise survive into the extracted value; stop at the first quote
        // of either kind instead.
        return value.split(['"', '\'']).next().unwrap_or(value);
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_raw_prefix_cursor_beyond_line() {
        let line = "serde";
        assert_eq!(raw_prefix(line, 100), "serde");
    }

    /// Sums a line's UTF-16 code unit length. `len_utf16()` is always 1 or 2, so a
    /// short test line can never overflow `u32`.
    #[allow(clippy::cast_possible_truncation)]
    fn utf16_len(line: &str) -> u32 {
        line.chars().map(char::len_utf16).sum::<usize>() as u32
    }

    /// `character` beyond the line's UTF-16 length hits `utf16_to_byte_offset`'s
    /// `None` branch; `unwrap_or(line.len())` must clamp to the full line rather
    /// than panic, even when the line contains multi-byte characters.
    #[test]
    fn test_raw_prefix_fallback_when_character_exceeds_line() {
        let line = "café";
        let character = utf16_len(line) + 10;
        assert_eq!(raw_prefix(line, character), "café");
    }

    /// `character` is a UTF-16 code unit count; using it as a raw byte index (a past
    /// bug) split "é" mid-encoding here and panicked on the slice.
    #[test]
    fn test_raw_prefix_does_not_panic_on_multibyte_char_boundary() {
        let line = "    \"é";
        assert_eq!(raw_prefix(line, utf16_len(line)), "\"é");
    }

    #[test]
    fn test_raw_prefix_multibyte_word_not_truncated() {
        let line = "café";
        assert_eq!(raw_prefix(line, utf16_len(line)), "café");
    }

    #[test]
    fn test_raw_prefix_cjk_word_not_truncated() {
        let line = "日本";
        assert_eq!(raw_prefix(line, utf16_len(line)), "日本");
    }

    #[test]
    fn test_line_at_returns_requested_line() {
        let content = "one\ntwo\nthree\n";
        assert_eq!(line_at(content, Position::new(1, 0)), Some("two"));
    }

    #[test]
    fn test_line_at_out_of_range_is_none() {
        let content = "one\ntwo\n";
        assert_eq!(line_at(content, Position::new(5, 0)), None);
    }

    #[test]
    fn test_is_in_toml_dependencies_basic() {
        let content = r#"
[package]
name = "test"

[dependencies]
serde
"#;
        assert!(is_in_toml_dependencies(content, 5));
        assert!(!is_in_toml_dependencies(content, 1));
    }

    #[test]
    fn test_is_in_toml_dependencies_dev_deps() {
        let content = r"
[dev-dependencies]
tokio
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_build_deps() {
        let content = r"
[build-dependencies]
cc
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_project_deps() {
        let content = r"
[project.dependencies]
requests
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_workspace_deps() {
        let content = r#"
[workspace.dependencies]
serde = "1.0"
"#;
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_target_specific() {
        let content = r"
[target.'cfg(windows)'.dependencies]
winapi
";
        assert!(is_in_toml_dependencies(content, 2));
    }

    #[test]
    fn test_is_in_toml_dependencies_wrong_section() {
        let content = r#"
[package]
name = "test"

[profile.release]
opt-level = 3
"#;
        assert!(!is_in_toml_dependencies(content, 2));
        assert!(!is_in_toml_dependencies(content, 5));
    }

    #[test]
    fn test_is_in_toml_dependencies_multiple_sections() {
        let content = r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tokio
"#;
        assert!(is_in_toml_dependencies(content, 2));
        assert!(is_in_toml_dependencies(content, 5));
    }

    const NPM_KEYS: &[&str] = &[
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    #[test]
    fn test_is_in_json_dependencies_basic() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 1, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_dev_deps() {
        let content = r#"{
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_peer_deps() {
        let content = r#"{
  "peerDependencies": {
    "react"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_optional_deps() {
        let content = r#"{
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_outside_section() {
        let content = r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.0.0"
  },
  "scripts": {
    "start": "node index.js"
  }
}"#;
        assert!(is_in_json_dependencies(content, 3, NPM_KEYS));
        assert!(!is_in_json_dependencies(content, 6, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_nested_braces() {
        let content = r#"{
  "dependencies": {
    "package": "1.0.0"
  }
}"#;
        assert!(is_in_json_dependencies(content, 2, NPM_KEYS));
    }

    #[test]
    fn test_is_in_json_dependencies_custom_keys() {
        let content = r#"{
  "require": {
    "monolog/monolog": "^2.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^9.0"
  }
}"#;
        assert!(is_in_json_dependencies(
            content,
            2,
            &["require", "require-dev"]
        ));
        assert!(is_in_json_dependencies(
            content,
            5,
            &["require", "require-dev"]
        ));
    }

    #[test]
    fn test_is_in_xml_tag_section_basic() {
        let content = r"
<project>
  <dependencies>
    <dependency></dependency>
  </dependencies>
</project>
";
        assert!(is_in_xml_tag_section(content, 3, "dependencies"));
        assert!(!is_in_xml_tag_section(content, 1, "dependencies"));
    }

    #[test]
    fn test_is_in_xml_tag_section_single_line() {
        let content = "<project><dependencies></dependencies></project>\n";
        assert!(is_in_xml_tag_section(content, 0, "dependencies"));
    }

    #[test]
    fn test_is_in_xml_tag_section_attributed_tag() {
        let content = r#"
<project>
  <dependencies xmlns="http://maven.apache.org/POM/4.0.0">
    <dependency></dependency>
  </dependencies>
</project>
"#;
        assert!(is_in_xml_tag_section(content, 3, "dependencies"));
    }

    #[test]
    fn test_is_in_xml_tag_section_no_false_positive_on_longer_tag_name() {
        let content = r"
<project>
  <dependencyManagement>
    <dependencies>
      <dependency></dependency>
    </dependencies>
  </dependencyManagement>
</project>
";
        // Line 2 opens `<dependencyManagement>`, not `<dependencies>` — must not match.
        assert!(!is_in_xml_tag_section(content, 2, "dependencies"));
        // Line 4 is genuinely inside the nested `<dependencies>` block.
        assert!(is_in_xml_tag_section(content, 4, "dependencies"));
    }

    #[test]
    fn test_strip_leading_xml_tag_for_maven() {
        // Cursor right after "gua" in `<artifactId>gua`.
        assert_eq!(
            strip_leading_xml_tag("<artifactId>gua"),
            ("gua", Some("artifactId"))
        );
    }

    #[test]
    fn test_strip_leading_xml_tag_unclosed_tag_is_unchanged() {
        // Nothing to strip: no `>` exists yet.
        assert_eq!(strip_leading_xml_tag("<artifactId"), ("<artifactId", None));
    }

    /// A first-`>`-based strip diverges whenever more than one tag precedes the
    /// cursor on a line — the first `>` here sits inside `<groupId>`, well short of
    /// the real value.
    #[test]
    fn test_strip_leading_xml_tag_strips_last_tag_not_first() {
        let prefix = "<dependency><groupId>com.google.guava</groupId><artifactId>gua";
        assert_eq!(strip_leading_xml_tag(prefix), ("gua", Some("artifactId")));
    }

    /// Cursor right after a fully closed tag must yield an empty prefix and no open tag.
    #[test]
    fn test_strip_leading_xml_tag_after_closed_tag_is_empty() {
        assert_eq!(
            strip_leading_xml_tag("<artifactId>guava</artifactId>"),
            ("", None)
        );
    }

    /// Loose inter-element text right after a closed tag
    /// (`<artifactId>guava</artifactId> comm`) must not be read as "inside the
    /// `artifactId` tag" — the closing `</artifactId>` is the last `>` on the line, so
    /// a naive "found a `>`" check would wrongly signal an open `artifactId` tag here.
    #[test]
    fn test_strip_leading_xml_tag_loose_text_after_closed_tag_has_no_open_tag() {
        assert_eq!(
            strip_leading_xml_tag("<artifactId>guava</artifactId> comm"),
            (" comm", None)
        );
    }

    #[test]
    fn test_strip_leading_xml_tag_reports_other_tag_name() {
        assert_eq!(
            strip_leading_xml_tag("<groupId>org.apa"),
            ("org.apa", Some("groupId"))
        );
    }

    const NUGET_ELEMENTS: &[&str] = &["PackageReference", "PackageVersion", "package"];
    const NUGET_ATTRS: &[&str] = &["Include", "id"];

    #[test]
    fn test_strip_open_xml_attribute_value_include() {
        assert_eq!(
            strip_open_xml_attribute_value(
                "<PackageReference Include=\"Newt",
                NUGET_ELEMENTS,
                NUGET_ATTRS
            ),
            "Newt"
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_id() {
        assert_eq!(
            strip_open_xml_attribute_value("<package id=\"Newt", NUGET_ELEMENTS, NUGET_ATTRS),
            "Newt"
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_spaced_equals() {
        assert_eq!(
            strip_open_xml_attribute_value(
                "<PackageReference Include = \"Newt",
                NUGET_ELEMENTS,
                NUGET_ATTRS
            ),
            "Newt"
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_single_quote() {
        assert_eq!(
            strip_open_xml_attribute_value(
                "<PackageReference Include='Newt",
                NUGET_ELEMENTS,
                NUGET_ATTRS
            ),
            "Newt"
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_non_target_attribute_is_empty() {
        assert_eq!(
            strip_open_xml_attribute_value(
                "<PackageReference Include=\"Foo\" Version=\"1.0",
                NUGET_ELEMENTS,
                NUGET_ATTRS
            ),
            ""
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_non_target_element_is_empty() {
        assert_eq!(
            strip_open_xml_attribute_value("<Compile Include=\"Mode", NUGET_ELEMENTS, NUGET_ATTRS),
            ""
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_element_name_only_is_empty() {
        assert_eq!(
            strip_open_xml_attribute_value("<PackageReference ", NUGET_ELEMENTS, NUGET_ATTRS),
            ""
        );
    }

    #[test]
    fn test_strip_open_xml_attribute_value_mismatched_quote_does_not_leak() {
        assert_eq!(
            strip_open_xml_attribute_value(
                "<PackageReference Include=\"Foo'",
                NUGET_ELEMENTS,
                NUGET_ATTRS
            ),
            "Foo"
        );
    }
}
