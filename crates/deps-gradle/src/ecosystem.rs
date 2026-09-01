//! Gradle ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter, position_in_range,
};
use deps_maven::MavenCentralRegistry;

use crate::formatter::GradleFormatter;

pub struct GradleEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: GradleFormatter,
}

impl GradleEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(cache)),
            formatter: GradleFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    async fn complete_versions(
        &self,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
            freshness,
        )
        .await
    }

    /// Detects completion context for Gradle files at the given position.
    ///
    /// Returns `(context_type, value, range)` where `context_type` is
    /// "version" | "package" | ""; `value` is the already-typed prefix up to the
    /// cursor; `range` spans the *entire* existing package coordinate (module/`group:artifact`)
    /// being completed, not just up to the cursor, and is meaningless when
    /// `context_type` is not "package" (mirrors `MavenEcosystem::detect_xml_context`).
    ///
    /// `position.character` is a UTF-16 code unit offset (LSP spec) and is converted to a
    /// byte offset once via [`deps_core::completion::utf16_to_byte_offset`] before any
    /// slicing, avoiding panics on multi-byte content preceding the cursor (e.g. an accented
    /// character in a `groupId`); the returned `range`'s `character` fields are converted
    /// back to UTF-16 units via [`deps_core::completion::byte_to_utf16_offset`].
    fn detect_completion_context<'a>(
        content: &'a str,
        position: Position,
        uri: &Uri,
    ) -> (&'static str, &'a str, Range) {
        let path = uri.path().to_string();
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        if line_idx >= lines.len() {
            return ("", "", Range::default());
        }

        let line = lines[line_idx];
        let col_idx = deps_core::completion::utf16_to_byte_offset(line, position.character)
            .unwrap_or(line.len());
        let before_cursor = &line[..col_idx];

        if path.ends_with("libs.versions.toml") {
            detect_catalog_context(before_cursor, line, col_idx, position.line)
        } else if path.ends_with(".gradle.kts") || path.ends_with(".gradle") {
            detect_dsl_context(before_cursor, line, col_idx, position.line)
        } else {
            ("", "", Range::default())
        }
    }
}

/// Builds an LSP [`Range`] on `line_idx` from a pair of byte offsets into `line`,
/// converting each to a UTF-16 code unit offset via
/// [`deps_core::completion::byte_to_utf16_offset`].
fn byte_range(line: &str, line_idx: u32, start_byte: usize, end_byte: usize) -> Range {
    Range::new(
        Position::new(
            line_idx,
            deps_core::completion::byte_to_utf16_offset(line, start_byte),
        ),
        Position::new(
            line_idx,
            deps_core::completion::byte_to_utf16_offset(line, end_byte),
        ),
    )
}

/// Finds the byte offset (relative to `before_cursor`) where the current inline-table
/// field starts — right after the last comma that is *not* inside a quoted string.
///
/// An inline-table catalog entry like `lib = { module = "...", version = "..." }` puts
/// multiple `key = "value"` fields on one line; without this, an unscoped `rfind` for
/// "version"/"module" (and the quote-parity check alongside it) can walk back past a
/// comma into an *earlier* field and misidentify which field the cursor is actually in
/// (e.g. treating a cursor inside `module`'s still-open value as "version" context,
/// because "version" appears earlier on the line and the combined quote count happens
/// to be odd).
fn current_field_start(before_cursor: &str) -> usize {
    let mut in_string = false;
    let mut field_start = 0;
    for (i, c) in before_cursor.char_indices() {
        match c {
            '"' => in_string = !in_string,
            ',' if !in_string => field_start = i + 1,
            _ => {}
        }
    }
    field_start
}

/// Detects completion context in version catalog files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
fn detect_catalog_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (&'static str, &'a str, Range) {
    let cursor = col_idx.min(line.len());
    // Scope keyword/quote-parity detection to the current inline-table field (see
    // `current_field_start`'s doc comment) so an earlier field on the same line can't be
    // mistaken for the one the cursor is actually in.
    let field_start = current_field_start(before_cursor);
    let field = &before_cursor[field_start..];

    // version = "..." or version.ref = "..."
    if let Some(rel_eq_pos) = field.rfind("version")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        // An odd quote count means the cursor sits inside an unclosed string opened by
        // the LAST quote in `after` — i.e. `rfind` below is genuinely the opening quote.
        // With an even count (string already closed, or no quote at all before cursor)
        // the cursor is past this `version = "..."` entirely (e.g. a trailing comment on
        // the same line), and this is not the right completion context.
        && after.chars().filter(|&c| c == '"').count() % 2 == 1
        && let Some(quote_start) = after.rfind('"')
    {
        let value_start = field_start + rel_eq_pos + quote_start + 1;
        if value_start <= cursor {
            return ("version", &line[value_start..cursor], Range::default());
        }
    }

    // module = "..."
    if let Some(rel_eq_pos) = field.rfind("module")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        && after.chars().filter(|&c| c == '"').count() % 2 == 1
        && let Some(quote_start) = after.rfind('"')
    {
        let value_start = field_start + rel_eq_pos + quote_start + 1;
        if value_start <= cursor {
            // Fall back to the cursor position (not end-of-line) when unterminated, so an
            // unclosed string doesn't swallow unrelated trailing line content into the
            // replace range (mirrors `MavenEcosystem::detect_xml_context`'s equivalent
            // no-closing-tag fallback).
            let value_end = line[value_start..]
                .find('"')
                .map_or(cursor, |rel| value_start + rel)
                .max(cursor);
            let range = byte_range(line, line_idx, value_start, value_end);
            return ("package", &line[value_start..cursor], range);
        }
    }

    ("", "", Range::default())
}

/// Detects completion context in Kotlin/Groovy DSL files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
fn detect_dsl_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (&'static str, &'a str, Range) {
    let cursor = col_idx.min(line.len());
    let in_string = before_cursor
        .chars()
        .filter(|&c| c == '"' || c == '\'')
        .count()
        % 2
        == 1;
    if !in_string {
        return ("", "", Range::default());
    }

    let colon_count = before_cursor.chars().filter(|&c| c == ':').count();
    let quote_char = if before_cursor.contains('"') {
        '"'
    } else {
        '\''
    };

    let Some(open_pos) = before_cursor.rfind(quote_char) else {
        return ("", "", Range::default());
    };

    match colon_count {
        0 | 1 => {
            // The package range covers "group" or "group:artifact" — up to a second
            // colon (start of an already-typed version) if one exists, else the closing
            // quote. If the string is unterminated on this line, the scan is bounded by
            // the cursor instead of end-of-line, so it doesn't swallow unrelated trailing
            // content (mirrors `MavenEcosystem::detect_xml_context`'s no-closing-tag
            // fallback).
            let rest = &line[open_pos + 1..];
            let closing_quote_rel = rest.find(quote_char);
            let scan_limit_rel = closing_quote_rel.unwrap_or(cursor - (open_pos + 1));
            let end_rel = rest[..scan_limit_rel]
                .char_indices()
                .filter(|&(_, c)| c == ':')
                .nth(1)
                .map_or(scan_limit_rel, |(i, _)| i);
            let value_end = (open_pos + 1 + end_rel).max(cursor);
            let range = byte_range(line, line_idx, open_pos + 1, value_end);
            ("package", &line[open_pos + 1..cursor], range)
        }
        _ => {
            let version_start = before_cursor
                .char_indices()
                .filter(|(_, c)| *c == ':')
                .nth(1)
                .map(|(i, _)| i + 1)
                .unwrap_or(before_cursor.len());
            ("version", &line[version_start..cursor], Range::default())
        }
    }
}

impl deps_core::ecosystem::private::Sealed for GradleEcosystem {}

impl Ecosystem for GradleEcosystem {
    fn id(&self) -> &'static str {
        "gradle"
    }

    fn display_name(&self) -> &'static str {
        "Gradle (JVM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &[
            "libs.versions.toml",
            "build.gradle.kts",
            "build.gradle",
            "settings.gradle.kts",
            "settings.gradle",
        ]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_gradle(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            let uri = parse_result.uri();
            let (ctx_type, value, range) = Self::detect_completion_context(content, position, uri);

            match ctx_type {
                "version" => {
                    let dep = parse_result.dependencies().into_iter().find(|d| {
                        d.version_range()
                            .is_some_and(|r| position_in_range(position, r))
                            || d.name_range().start.line == position.line
                    });
                    if let Some(dep) = dep {
                        self.complete_versions(dep.name(), value, freshness).await
                    } else {
                        vec![]
                    }
                }
                "package" => self.complete_package_names(value, range).await,
                _ => vec![],
            }
            .into()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> Arc<deps_core::HttpCache> {
        Arc::new(deps_core::HttpCache::new())
    }

    #[test]
    fn test_ecosystem_id() {
        let eco = GradleEcosystem::new(make_cache());
        assert_eq!(eco.id(), "gradle");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let eco = GradleEcosystem::new(make_cache());
        assert_eq!(eco.display_name(), "Gradle (JVM)");
    }

    #[test]
    fn test_manifest_filenames() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.manifest_filenames().contains(&"libs.versions.toml"));
        assert!(eco.manifest_filenames().contains(&"build.gradle.kts"));
        assert!(eco.manifest_filenames().contains(&"build.gradle"));
        assert!(eco.manifest_filenames().contains(&"settings.gradle.kts"));
        assert!(eco.manifest_filenames().contains(&"settings.gradle"));
    }

    #[test]
    fn test_lockfile_filenames_empty() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.lockfile_filenames().is_empty());
    }

    #[test]
    fn test_lockfile_provider_none() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.lockfile_provider().is_none());
    }

    #[test]
    fn test_as_any() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.as_any().is::<GradleEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_short_prefix() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(
            eco.complete_package_names("a", Range::default())
                .await
                .is_empty()
        );
        assert!(
            eco.complete_package_names("", Range::default())
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_kts() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"junit:junit:4.13.2\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[test]
    fn test_detect_catalog_context_version_cursor_at_start() {
        // version = "|1.0.0"
        let line = r#"version = "1.0.0""#;
        // before_cursor = `version = "`, cursor at 11 (right after '"')
        let col = 11;
        let before = &line[..col];
        let (t, v, _) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "");
    }

    #[test]
    fn test_detect_catalog_context_version_cursor_mid() {
        // version = "1.0|.0"
        let line = r#"version = "1.0.0""#;
        // value_start = 11, "1.0" = 3 chars, cursor at 14
        let col = 14;
        let before = &line[..col];
        let (t, v, _) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn test_detect_catalog_context_version_cursor_at_end() {
        // version = "1.0.0|"
        let line = r#"version = "1.0.0""#;
        // value_start = 11, "1.0.0" = 5 chars, cursor at 16
        let col = 16;
        let before = &line[..col];
        let (t, v, _) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_detect_catalog_context_module_prefix() {
        // module = "com.ex|ample:lib"
        let line = r#"module = "com.example:lib""#;
        // value_start = 9 + 1 = 10 (after `module = "`), "com.ex" = 6 chars, cursor at 16
        let col = 16;
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "com.ex");
        // range replaces the whole quoted value ("com.example:lib"), not just "com.ex"
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, 25))
        );
        assert_eq!(&line[10..25], "com.example:lib");
    }

    #[test]
    fn test_detect_dsl_context_package_cursor_mid() {
        // implementation("junit|:junit:4.13.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // open_pos=15 ('"'), "junit" = 5 chars, cursor at 21 (after 5 chars)
        // before_cursor = `implementation("junit`
        let col = 21;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "junit");
        // range replaces the whole "group:artifact" coordinate ("junit:junit"),
        // stopping before the version separator, not just the already-typed "junit"
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 27))
        );
        assert_eq!(&line[16..27], "junit:junit");
    }

    #[test]
    fn test_detect_dsl_context_package_no_version_yet() {
        // implementation("junit|") — no colon typed yet, string not closed by a version
        let line = r#"implementation("junit")"#;
        let col = 21; // right after "junit"
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "junit");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 21))
        );
        assert_eq!(&line[16..21], "junit");
    }

    #[test]
    fn test_detect_completion_context_catalog_multibyte_module_value() {
        // module = "café:lib" — 'é' is 2 bytes in UTF-8 but 1 UTF-16 code unit, so byte
        // and UTF-16 offsets diverge from this point on in the line. Exercises the
        // top-level UTF-16-to-byte conversion and the byte-to-UTF-16 conversion on the
        // returned range (regression test for the #232 follow-up: byte offsets were
        // previously emitted directly as UTF-16 character positions).
        let content = "module = \"café:lib\"\n";
        let uri = deps_core::test_util::test_uri("/test/libs.versions.toml");
        let position = Position::new(0, 14); // cursor right after "café" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, "package");
        assert_eq!(v, "café");
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, 18))
        );
    }

    #[test]
    fn test_detect_completion_context_catalog_inline_table_multibyte_does_not_consume_closing_quote()
     {
        // Live repro from code review: `lib = { module = "com.exämple:lib", version = "1.0" }`
        // with the cursor right after the fully-typed module value (byte offset 34, right
        // before the closing quote). Before the UTF-16 fix, the byte offset (34) was
        // returned directly as the range's end *character* — but "com.exämple:lib" is only
        // 15 UTF-16 units (ä is 2 bytes / 1 UTF-16 unit), so the correct end is 33, not 34.
        // A range ending at 34 would extend one UTF-16 unit past the value, consuming the
        // closing quote itself when the client applies the edit — corrupting the TOML.
        let content = r#"lib = { module = "com.exämple:lib", version = "1.0" }"#;
        assert_eq!(&content[18..34], "com.exämple:lib");
        assert_eq!(content.as_bytes()[34], b'"');
        let uri = deps_core::test_util::test_uri("/test/libs.versions.toml");
        let position = Position::new(0, 33); // cursor right after "lib" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, "package");
        assert_eq!(v, "com.exämple:lib");
        // Range must end at UTF-16 33 (right before the closing quote), not 34 (which
        // would swallow it).
        assert_eq!(
            range,
            Range::new(Position::new(0, 18), Position::new(0, 33))
        );
    }

    #[test]
    fn test_detect_completion_context_dsl_multibyte_package_value() {
        // implementation("café:junit") — same multi-byte concern as above, in the
        // Kotlin/Groovy DSL path.
        let content = "implementation(\"café:junit\")\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let position = Position::new(0, 20); // cursor right after "café" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, "package");
        assert_eq!(v, "café");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 26))
        );
    }

    #[test]
    fn test_detect_catalog_context_cursor_past_closing_quote_not_matched() {
        // module = "com.example:lib"|  — cursor placed after the closing quote (e.g. in
        // trailing content on the same line) must not be treated as still inside the
        // quoted value.
        let line = r#"module = "com.example:lib" # trailing"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "");
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[test]
    fn test_detect_catalog_context_module_unterminated_falls_back_to_cursor() {
        // module = "com.example:lib   (no closing quote on the line) — the range must
        // stop at the cursor, not swallow the rest of the line.
        let line = r#"module = "com.example:li"#;
        let col = line.len(); // cursor at end of line, right after "li"
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "com.example:li");
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, col as u32))
        );
    }

    #[test]
    fn test_detect_catalog_context_inline_table_does_not_leak_across_fields() {
        // lib = { version = "1.0", module = "com.exa|  — cursor is inside the *module*
        // field's still-open value. An earlier field ("version") appearing before it on
        // the same line must not be mistaken for the current context: without scoping to
        // the current inline-table field, `rfind("version")` would walk back past the
        // comma, and the combined quote count across both fields happens to be odd,
        // producing a bogus "version" context instead of "package".
        let line = r#"lib = { version = "1.0", module = "com.exa"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "com.exa");
        assert_eq!(
            range,
            Range::new(Position::new(0, 35), Position::new(0, col as u32))
        );
    }

    #[test]
    fn test_detect_catalog_context_inline_table_version_field_after_module() {
        // lib = { module = "com.example:lib", version = "1.0|  — the reverse ordering:
        // cursor inside the *version* field, with a completed "module" field earlier on
        // the same line. Confirms the field-scoping fix doesn't over-correct and still
        // matches "version" correctly here.
        let line = r#"lib = { module = "com.example:lib", version = "1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn test_detect_dsl_context_unterminated_falls_back_to_cursor() {
        // implementation("junit:junit   (no closing quote/paren on the line) — the range
        // must stop at the cursor, not swallow the rest of the line.
        let line = r#"implementation("junit:junit"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "junit:junit");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, col as u32))
        );
    }

    #[test]
    fn test_detect_dsl_context_version_cursor_mid() {
        // implementation("junit:junit:4.1|3.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // second ':' at index 27; version_start=28, "4.1"=3 chars, cursor at 31
        let col = 31;
        let before = &line[..col];
        let (t, v, _) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "4.1");
    }

    #[test]
    fn test_detect_dsl_context_version_cursor_at_start() {
        // implementation("junit:junit:|4.13.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // second ':' at index 27, cursor at 28 (right after it)
        let col = 28;
        let before = &line[..col];
        let (t, v, _) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "version");
        assert_eq!(v, "");
    }

    #[tokio::test]
    async fn test_parse_manifest_groovy() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }
}
