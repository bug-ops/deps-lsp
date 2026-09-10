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

/// [`Ecosystem`] implementation for Gradle (`build.gradle`/`build.gradle.kts`), reusing
/// Maven Central resolution via [`MavenCentralRegistry`].
pub struct GradleEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: GradleFormatter,
    /// Kept alongside `registry` (which owns its own clone, internal to
    /// `MavenCentralRegistry`) for [`Self::fetch_license`]'s independent POM fetch
    /// (issue #660) — that fetch targets a different Maven Central endpoint
    /// (`{coord}/{version}/{artifact}-{version}.pom`) than any `MavenCentralRegistry`
    /// method exposes, so it goes through `crate::license` directly rather than
    /// growing `MavenCentralRegistry`'s own (differently-scoped, `deps-maven`-owned)
    /// public API.
    http_cache: Arc<deps_core::HttpCache>,
}

impl GradleEcosystem {
    /// Creates a Gradle ecosystem instance backed by the given shared HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(Arc::clone(&cache))),
            formatter: GradleFormatter,
            http_cache: cache,
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
    // `col_idx` comes from `utf16_to_byte_offset` (char_indices-based), so it is always a
    // char boundary.
    #[allow(clippy::string_slice)]
    fn detect_completion_context<'a>(
        content: &'a str,
        position: Position,
        uri: &Uri,
    ) -> (&'static str, &'a str, Range) {
        let path = uri.path().to_string();
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        let Some(&line) = lines.get(line_idx) else {
            return ("", "", Range::default());
        };
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
// Kept as its own escape-aware loop rather than calling
// `deps_core::fallback_completion::count_real_quotes`/`find_closing_quote`: this needs
// an `in_string` toggle interleaved with comma-boundary tracking in a *single* forward
// pass (a comma's own `!in_string` guard depends on the running parity at that exact
// position), which the shared helpers — built to answer "count/find real quotes over
// the whole segment" — don't expose mid-scan. Keeps the same backslash-run escape rule
// as those helpers (see `count_real_quotes`'s doc comment) so the two can't disagree on
// a line containing `\"` (#738 follow-up); a future change to that rule must be mirrored
// here too.
fn current_field_start(before_cursor: &str) -> usize {
    let mut in_string = false;
    let mut backslash_run = 0usize;
    let mut field_start = 0;
    for (i, c) in before_cursor.char_indices() {
        match c {
            '\\' => backslash_run += 1,
            '"' => {
                if backslash_run.is_multiple_of(2) {
                    in_string = !in_string;
                }
                backslash_run = 0;
            }
            ',' if !in_string => {
                field_start = i + 1;
                backslash_run = 0;
            }
            _ => backslash_run = 0,
        }
    }
    field_start
}

/// Detects completion context in version catalog files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
// Every offset below (`field_start`, `rel_eq_pos`, `quote_start`, `value_start`/`value_end`)
// derives from `char_indices()` or `find`/`rfind` of an ASCII token (`"`, `=`, `version`,
// `module`), so every slice bound is always a char boundary.
#[allow(clippy::string_slice)]
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
        // An odd, escape-aware (see `count_real_quotes`) quote count means the cursor
        // sits inside an unclosed string opened by the last *real* quote in `after`.
        // With an even count (string already closed, or no quote at all before cursor)
        // the cursor is past this `version = "..."` entirely (e.g. a trailing comment on
        // the same line), and this is not the right completion context.
        && let (quote_count, Some(quote_start)) =
            deps_core::fallback_completion::count_real_quotes(after)
        && !quote_count.is_multiple_of(2)
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
        && let (quote_count, Some(quote_start)) =
            deps_core::fallback_completion::count_real_quotes(after)
        && !quote_count.is_multiple_of(2)
    {
        let value_start = field_start + rel_eq_pos + quote_start + 1;
        if value_start <= cursor {
            // Fall back to the cursor position (not end-of-line) when unterminated, so an
            // unclosed string doesn't swallow unrelated trailing line content into the
            // replace range (mirrors `MavenEcosystem::detect_xml_context`'s equivalent
            // no-closing-tag fallback).
            let value_end =
                deps_core::fallback_completion::find_closing_quote(&line[value_start..], '"')
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
// Every offset below (`open_pos`, `end_rel`, `version_start`) derives from `rfind`/`find` of
// an ASCII `'"'`/`'\''`/`':'` token or `char_indices()`, so every slice bound is always a
// char boundary.
#[allow(clippy::string_slice)]
fn detect_dsl_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (&'static str, &'a str, Range) {
    let cursor = col_idx.min(line.len());
    let quote_char = if before_cursor.contains('"') {
        '"'
    } else {
        '\''
    };
    // Escape-aware (see `count_real_quotes_with`) odd-parity check on the chosen quote
    // character: an even count means the cursor sits past a closed string, or none was
    // opened at all on this line (#738).
    let (quote_count, last_real_quote) =
        deps_core::fallback_completion::count_real_quotes_with(before_cursor, quote_char);
    if quote_count.is_multiple_of(2) {
        return ("", "", Range::default());
    }
    let Some(open_pos) = last_real_quote else {
        return ("", "", Range::default());
    };

    let colon_count = before_cursor.chars().filter(|&c| c == ':').count();

    match colon_count {
        0 | 1 => {
            // The package range covers "group" or "group:artifact" — up to a second
            // colon (start of an already-typed version) if one exists, else the closing
            // quote. If the string is unterminated on this line, the scan is bounded by
            // the cursor instead of end-of-line, so it doesn't swallow unrelated trailing
            // content (mirrors `MavenEcosystem::detect_xml_context`'s no-closing-tag
            // fallback).
            let rest = &line[open_pos + 1..];
            let closing_quote_rel =
                deps_core::fallback_completion::find_closing_quote(rest, quote_char);
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

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("implementation(\"{name}:{latest}\")"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s (`"group:artifact"`) license at `version` from Maven Central,
    /// following one or more `<parent>` POM hops when the leaf POM declares no
    /// `<licenses>` block of its own (issue #660/#688/#692). See
    /// `crate::license::fetch_license`.
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        Box::pin(crate::license::fetch_license(
            &self.http_cache,
            name,
            version,
        ))
    }

    /// Gradle's Maven Central POM `<licenses><license><name>` is free text, not an SPDX
    /// identifier — see [`deps_core::LicenseSource::PomFreeText`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::PomFreeText
    }
}

#[cfg(test)]
// Fixtures are single-line ASCII (or explicitly UTF-16-tested) literals with
// hand-computed byte offsets.
#[allow(clippy::string_slice)]
mod tests {
    use super::*;

    fn make_cache() -> Arc<deps_core::HttpCache> {
        Arc::new(deps_core::HttpCache::new())
    }

    // #758: exact-value `Ecosystem` conformance, replacing test_ecosystem_id,
    // test_ecosystem_display_name, test_manifest_filenames, and test_as_any. Gradle has no
    // lock file format, so `lockfile_filenames` is omitted here; `no_lockfile_support: true;`
    // (#782 gap 2) replaces the hand-copied test_lockfile_filenames_empty/
    // test_lockfile_provider_none pair below.
    deps_core::ecosystem_conformance! {
        mod gradle_ecosystem_conformance;
        build: GradleEcosystem::new(make_cache());
        ty: GradleEcosystem;
        id: "gradle";
        display_name: "Gradle (JVM)";
        manifest_filenames: &[
            "libs.versions.toml",
            "build.gradle.kts",
            "build.gradle",
            "settings.gradle.kts",
            "settings.gradle",
        ];
        no_lockfile_support: true;
    }

    // #784: `build_arc:` (not `build:`) against the real `Ecosystem::registry()` wiring —
    // `GradleEcosystem` reuses `deps_maven::MavenCentralRegistry` unchanged (#233), so a
    // `build:` fixture constructing that type directly would only duplicate
    // `deps-maven/src/registry.rs`'s own `test_select_latest_matching_not_default_none`
    // and prove nothing gradle-specific; this proves the type Gradle's `registry()` hands
    // back actually overrides the method. `req: "*"` (rather than an exact-string pin) also
    // exercises the wildcard/existence-ladder branch both LSP fetch call sites
    // (`deps-lsp/src/document/fetch.rs`, `deps-core/src/lsp_helpers/hover.rs`) actually take,
    // instead of a branch production code never reaches.
    deps_core::registry_conformance! {
        mod gradle_registry_conformance;
        build_arc: GradleEcosystem::new(make_cache()).registry();
        select_latest_matching: {
            versions: vec![
                Box::new(deps_maven::MavenVersion::new("3.2.0".into())),
                Box::new(deps_maven::MavenVersion::new("3.1.0".into())),
            ];
            req: "*";
            expected_index: 0;
        };
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_short_prefix — also closes the missing max-length case
    // (issue #758 named deps-gradle as missing this).
    deps_core::completion_guard_conformance! {
        mod gradle_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + '_>,
        > {
            Box::pin(async move {
                deps_core::completion::complete_package_names_generic(
                    registry,
                    &prefix,
                    20,
                    Range::default(),
                )
                .await
            })
        };
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
    fn test_detect_catalog_context_version_closed_value_with_escaped_quote_stays_closed() {
        // version = "a\"b" | — cursor past a properly closed value that contains an
        // escaped quote. A naive raw `"` count sees 3 quote characters (odd, "still
        // open") and wrongly reports a "version" context whose value is the trailing
        // space; the escape-aware count correctly sees 2 real quotes (even, closed) and
        // reports no completion context at all (#738 follow-up).
        let line = "version = \"a\\\"b\" ";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "");
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[test]
    fn test_detect_catalog_context_module_escaped_quote_does_not_close_string() {
        // module = "com.example\"extra:lib — an escaped quote inside the still-open
        // value must not be miscounted as closing the string (#738): a naive raw `"`
        // count sees 2 quote characters (even, "closed") while the escape-aware count
        // correctly sees 1 real quote (odd, still open).
        let line = "module = \"com.example\\\"extra:lib";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, "package");
        let value_start = line.find('"').unwrap() + 1;
        assert_eq!(v, &line[value_start..col]);
        assert_eq!(
            range,
            Range::new(
                Position::new(0, value_start as u32),
                Position::new(0, col as u32)
            )
        );
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
    fn test_detect_dsl_context_escaped_quote_in_earlier_group_does_not_block_completion() {
        // implementation "a\"b", "com.foo:ba — the escaped quote inside the first,
        // already-closed string argument must not desync the quote-parity check and
        // suppress completion on the second, still-open string (#738). A naive raw `"`
        // count sees 4 quote characters total (even, "no open string") and reports no
        // completion context at all.
        let line = "implementation \"a\\\"b\", \"com.foo:ba";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "com.foo:ba");
    }

    #[test]
    fn test_detect_dsl_context_apostrophe_inside_double_quoted_package_name() {
        // implementation "com.o'reilly:li — an apostrophe inside a double-quoted
        // string must not be mistaken for a single-quote delimiter (#738).
        let line = r#"implementation "com.o'reilly:li"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "package");
        assert_eq!(v, "com.o'reilly:li");
    }

    #[test]
    fn test_detect_dsl_context_mixed_quote_types_on_one_line_no_completion() {
        // exclude module: "x"; implementation 'com.baz:qu — a completed double-quoted
        // string earlier on the line, followed by a still-open single-quoted string.
        // `quote_char` picks '"' (the line contains one), whose own parity is even
        // (closed), so this deliberately reports "no completion context" instead of
        // guessing at the unrelated single-quoted string — accepted limitation, not a
        // regression from this fix: a line mixing both quote styles picks one quote
        // character for the whole line, not per-field.
        let line = r#"exclude module: "x"; implementation 'com.baz:qu"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, "");
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
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

    /// Gradle spans five manifest formats (TOML version catalog, Groovy DSL, Kotlin
    /// DSL) with no raw-text section marker shared across all of them — no override,
    /// unreachable in practice.
    #[test]
    fn test_fallback_completion_prefix_default_none() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(
            eco.fallback_completion_prefix("anything at all\n", Position::new(0, 0))
                .is_none()
        );
    }

    #[test]
    fn test_completion_insert_text() {
        let eco = GradleEcosystem::new(make_cache());
        struct MockMetadata {
            name: deps_core::PackageName,
            latest_version: deps_core::ConcreteVersion,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                &self.latest_version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("implementation(\"org.apache.commons:commons-lang3:3.14.0\")".to_string())
        );
    }
}
