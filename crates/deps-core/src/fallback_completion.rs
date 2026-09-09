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

/// Counts the `"` characters in `segment` that actually open or close a string —
/// skipping any `\"` escape sequence — along with the byte index of the last such
/// real quote, if any.
///
/// A `"` is escaped, and does not toggle string state, when it is preceded by an *odd*
/// number of consecutive `\` characters immediately before it (an even count, zero
/// included, means those backslashes are themselves pairwise-escaped, so the quote is
/// real) — e.g. in `"a\"b"` the middle `"` is escaped (one preceding `\`), so the
/// string is `a"b`, not two separate strings. A naive per-`"` count desyncs from real
/// open/close string state on any segment containing `\"` (#729 code-review, #733: raw
/// counting both over-counts, flipping a closed key+value pair to look "open", and
/// under-counts the inverse, flipping a still-open key to look "closed").
///
/// # Examples
///
/// ```
/// use deps_core::fallback_completion::count_real_quotes;
///
/// // Two plain quotes, both real: last one is at byte index 7.
/// assert_eq!(count_real_quotes("\"pytest\""), (2, Some(7)));
/// // The middle quote is escaped (one preceding `\`), so it isn't counted: only the
/// // opening quote (index 0) is real.
/// assert_eq!(count_real_quotes("\"a\\\"b"), (1, Some(0)));
/// ```
#[must_use]
pub fn count_real_quotes(segment: &str) -> (usize, Option<usize>) {
    let mut backslash_run = 0usize;
    let mut count = 0usize;
    let mut last_real_quote = None;
    for (idx, ch) in segment.char_indices() {
        match ch {
            '\\' => backslash_run += 1,
            '"' => {
                if backslash_run.is_multiple_of(2) {
                    count += 1;
                    last_real_quote = Some(idx);
                }
                backslash_run = 0;
            }
            _ => backslash_run = 0,
        }
    }
    (count, last_real_quote)
}

/// Classifies whether `prefix` (the trimmed line text up to the cursor) sits inside an
/// open JSON string that is a dependency object's *key*.
///
/// Covers `package.json`'s `"expr` while the key is still being typed, and
/// `composer.json`'s `require`/`require-dev` entries — distinguishing that from a
/// closed key, an open value string, or plain unquoted text.
///
/// Uses quote parity — an odd count of real (see [`count_real_quotes`]) `"`
/// characters means the cursor sits inside an open string literal — adapted for a JSON
/// object key instead of an XML tag/attribute: the text immediately before the open
/// string's opening quote decides key-vs-value: a `:` right before it
/// (`"express": "^4`) means the open string is the *value*, not the key.
///
/// Returns `(text_after_the_open_quote, true)` only when the cursor is genuinely
/// inside an open key string — the one case where a fallback-completion insert should
/// be the bare candidate name rather than a full `"{name}": "^{latest}"` snippet, the
/// same "already open" bare-insert shape as
/// [`strip_leading_xml_tag`]'s `Some("artifactId")` case and
/// [`strip_open_xml_attribute_value`]'s non-empty result. Every other shape returns
/// `("", false)`:
/// - Even quote count with at least one real `"` present means the cursor sits right
///   after a fully-closed string (`"express"` with the cursor past both quotes) —
///   quote parity alone cannot tell whether that position wants a new key, is
///   mid-value, or something else, so this suppresses rather than guesses (#729 critic
///   S1, matching Maven's "no safe bare text to offer here" discipline for a
///   non-`artifactId` open tag).
/// - Odd quote count whose open string's text is preceded by `:` means the cursor is
///   inside an open *value* string, not the key — a bare package-name insert there
///   would corrupt the version instead of completing the key (#729 critic S2).
///
/// Even quote count with *zero* real `"` present (plain unquoted text, or nothing
/// typed yet) is the one exception: it returns `(prefix, false)` unchanged, since no
/// quote has been opened at all and the normal full-pair insert is still correct
/// there.
#[must_use]
pub fn strip_open_json_key(prefix: &str) -> (&str, bool) {
    let (quote_count, last_quote) = count_real_quotes(prefix);
    if quote_count == 0 {
        return (prefix, false);
    }
    if quote_count.is_multiple_of(2) {
        return ("", false);
    }
    // `quote_count` odd (so >= 1) guarantees `count_real_quotes` found one; `"`
    // is a single-byte ASCII char, so `last_quote + 1` is always a char boundary.
    #[allow(clippy::string_slice)]
    let Some(last_quote) = last_quote else {
        return ("", false);
    };
    #[allow(clippy::string_slice)]
    let (before_quote, after_quote) = (&prefix[..last_quote], &prefix[last_quote + 1..]);
    if before_quote.trim_end().ends_with(':') {
        ("", false)
    } else {
        (after_quote, true)
    }
}

/// Returns the tail of a genuinely still-open quoted string ending at the cursor, or
/// `None` when there isn't one.
///
/// The tail is the text after the last real, escape-aware (see [`count_real_quotes`])
/// opening `"` in `segment`, returned only when the cursor sits inside a genuinely
/// still-open quoted string — an odd count of real `"` characters. Returns `None` when
/// the string is already closed (an even, non-zero count) or no quote has been typed
/// at all (zero count): in both cases there is no open string to extract a value from.
///
/// Shared by ecosystems whose raw-text fallback-completion prefix survives inside a
/// quoted value (a JSON object key/value, a TOML string-array element) — used instead
/// of an unconditional `trim_matches('"')`, which cannot distinguish a genuinely open
/// string from an already-closed one and so cannot tell a caller when a bare insert at
/// the cursor would corrupt the manifest rather than complete an open value (#734).
///
/// # Examples
///
/// ```
/// use deps_core::fallback_completion::open_quoted_tail;
///
/// // Still-open string: only the opening quote exists.
/// assert_eq!(open_quoted_tail("\"flas"), Some("flas"));
/// // Already-closed string: both quotes exist, nothing left to complete.
/// assert_eq!(open_quoted_tail("\"pytest\""), None);
/// // No quote typed yet.
/// assert_eq!(open_quoted_tail("dependencies = ["), None);
/// ```
#[must_use]
pub fn open_quoted_tail(segment: &str) -> Option<&str> {
    let (count, last_quote) = count_real_quotes(segment);
    if count.is_multiple_of(2) {
        return None;
    }
    // `last_quote` is the byte index of a `"` char (from `char_indices`), and `"` is a
    // single-byte ASCII char, so `last_quote + 1` is always a char boundary.
    #[allow(clippy::string_slice)]
    last_quote.map(|pos| &segment[pos + 1..])
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

    #[test]
    fn test_strip_open_json_key_open_key_leading_quote() {
        // package.json / composer.json: cursor sits before the closing quote while the
        // key is still being typed, e.g. `    "expr` with the cursor right after "expr".
        let prefix = "\"expr";
        assert_eq!(strip_open_json_key(prefix), ("expr", true));
    }

    #[test]
    fn test_strip_open_json_key_closed_key_is_suppressed_not_reopened() {
        // #729 critic S1: cursor right after an already fully-closed key
        // (`"express"`, quote parity even) is NOT an open string — a naive
        // `ends_with('"')` check would misclassify this as open and bare-insert into
        // it (`"express"express`, still invalid JSON). Quote parity correctly reports
        // this as ambiguous instead, suppressing the item rather than guessing.
        let prefix = "\"express\"";
        assert_eq!(strip_open_json_key(prefix), ("", false));
    }

    #[test]
    fn test_strip_open_json_key_open_value_string_is_suppressed_not_key() {
        // #729 critic S2: cursor inside an open *value* string (`"express": "^4`, odd
        // quote parity) must not be reported as an open key — a bare package-name
        // insert there would corrupt the version string, not complete the key.
        let prefix = "\"express\": \"^4";
        assert_eq!(strip_open_json_key(prefix), ("", false));
    }

    #[test]
    fn test_strip_open_json_key_open_key_after_prior_closed_entry_on_same_line() {
        // A second key on the same line as an already-closed entry (`"express":
        // "4.19.2", "look`) must still be recognized as an open key: the text right
        // before its opening quote is `, `, not `:`, so quote parity correctly
        // distinguishes it from the value-position case above.
        let prefix = "\"express\": \"4.19.2\", \"look";
        assert_eq!(strip_open_json_key(prefix), ("look", true));
    }

    #[test]
    fn test_strip_open_json_key_no_quote_survives_reports_unchanged() {
        // No `"` typed yet at all (e.g. the user deleted the key and is retyping bare
        // text): nothing proves a string is already open, so the normal full-pair
        // insert is still correct here (#729).
        let prefix = "expr";
        assert_eq!(strip_open_json_key(prefix), ("expr", false));
    }

    #[test]
    fn test_strip_open_json_key_escaped_quote_in_closed_pair_is_not_open() {
        // #729 code-review: a closed key containing one escaped quote, plus a closed
        // value, plus trailing bare text with no opening quote yet. A naive raw `"`
        // count sees 5 quote characters (odd) and wrongly reports this as an open key
        // with a garbage prefix; the escape-aware count sees the real state (nothing
        // open) and suppresses.
        let prefix = "\"a\\\"b\": \"1\", lodash";
        assert_eq!(strip_open_json_key(prefix), ("", false));
    }

    #[test]
    fn test_strip_open_json_key_escaped_quote_inside_still_open_key() {
        // Inverse of the above: an escaped quote inside a key that is genuinely still
        // open. A naive raw count would see 2 quote characters (even) and wrongly
        // suppress a valid completion; the escape-aware count correctly reports this
        // as still open.
        let prefix = "\"a\\\"b";
        assert_eq!(strip_open_json_key(prefix), ("a\\\"b", true));
    }

    #[test]
    fn test_open_quoted_tail_open_string_returns_tail() {
        assert_eq!(open_quoted_tail("\"flas"), Some("flas"));
    }

    #[test]
    fn test_open_quoted_tail_closed_string_is_none() {
        assert_eq!(open_quoted_tail("\"pytest\""), None);
    }

    #[test]
    fn test_open_quoted_tail_no_quote_is_none() {
        assert_eq!(open_quoted_tail("dependencies = ["), None);
    }

    /// The escaped `\"` inside the value must not be counted as a real delimiter,
    /// otherwise this would misclassify as closed (even count) instead of open.
    #[test]
    fn test_open_quoted_tail_skips_escaped_quote() {
        assert_eq!(open_quoted_tail("\"a\\\"b"), Some("a\\\"b"));
    }

    /// A run of two backslashes before the quote is itself an escaped backslash, so
    /// the quote after it is real and closes the string.
    #[test]
    fn test_open_quoted_tail_even_backslash_run_quote_is_real() {
        assert_eq!(open_quoted_tail("\"a\\\\\""), None);
    }

    #[test]
    fn test_count_real_quotes_skips_escaped_quote() {
        let (count, last) = count_real_quotes("\"a\\\"b\"");
        assert_eq!(count, 2);
        assert_eq!(last, Some(5));
    }
}
