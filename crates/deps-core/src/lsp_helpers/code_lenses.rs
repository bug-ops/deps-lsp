use tower_lsp_server::ls_types::{CodeLens, Command, Position, Range, TextEdit, Uri};

use crate::ParseResult;
#[cfg(test)]
use crate::PublishTime;

use super::{
    EcosystemFormatter, LineOffsetTable, VersionData, is_safe_version_string, literal_span_matches,
    slice_for_range, strip_whitespace, warn_rejected_value,
};

/// Manifest edits bringing every safely-editable outdated dependency to `latest`.
///
/// A dependency is included when all of the following hold:
/// - it declares a `version_range` (a span to rewrite exists);
/// - a `latest` version is known in `versions.cached` (normalized name first, then raw —
///   mirroring [`crate::lsp_helpers::generate_diagnostics_from_cache`]);
/// - `formatter.is_requirement_up_to_date` reports the declared requirement as *not*
///   satisfying `latest` — the same predicate diagnostics use, so on a fixture where the
///   guard below is a no-op, `collect_update_all_edits(..).len()` equals the number of
///   `generate_diagnostics_from_cache` "Newer version available" diagnostics;
/// - the **literal-span guard** (`literal_span_matches`): `content` sliced over
///   `version_range` must still be (up to whitespace and NuGet's bracket wrap) the
///   literal text — [`Dependency::version_literal`](crate::Dependency::version_literal)
///   when the ecosystem provides one (e.g. `deps-swift`, whose synthesized comparator
///   requirement string diverges from the bare literal `version_range` spans), falling
///   back to the declared requirement text otherwise. Some ecosystems point
///   `version_range` at something that is not a version literal at all — a Maven
///   `${property}` reference or a Gradle DSL variable/version-catalog alias — and
///   rewriting those spans would corrupt the manifest instead of fixing it. A dependency
///   that fails the guard is skipped entirely: neither counted nor edited.
///
/// Accepted edits are sorted by start position; a later edit whose start falls before the
/// previous edit's end (an overlap — a `WorkspaceEdit` protocol violation) is dropped with
/// a `tracing::warn!`. No current parser produces overlapping `version_range`s, so this is
/// a guard against future parser changes, not an expected code path.
///
/// `content` is the manifest source, needed for the literal-span guard above — the same
/// parameter [`Ecosystem::generate_completions`](crate::Ecosystem::generate_completions)
/// already threads through for a similar reason.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     collect_update_all_edits, EcosystemFormatter, PackageVersions, VersionData,
/// };
/// use deps_core::{ConcreteVersion, Dependency, ParseResult, PackageName, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use tower_lsp_server::ls_types::{Position, Range, Uri};
///
/// struct MockFormatter;
/// impl EcosystemFormatter for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{name}")
///     }
/// }
///
/// struct MockDep {
///     name: PackageName,
///     version_req: VersionReq,
///     version_range: Range,
///     name_range: Range,
/// }
/// impl Dependency for MockDep {
///     fn name(&self) -> &PackageName { &self.name }
///     fn name_range(&self) -> Range { self.name_range }
///     fn version_requirement(&self) -> Option<&VersionReq> { Some(&self.version_req) }
///     fn version_range(&self) -> Option<Range> { Some(self.version_range) }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// struct MockParseResult { deps: Vec<MockDep>, uri: Uri }
/// impl ParseResult for MockParseResult {
///     fn dependencies(&self) -> Vec<&dyn Dependency> {
///         self.deps.iter().map(|d| d as &dyn Dependency).collect()
///     }
///     fn workspace_root(&self) -> Option<&std::path::Path> { None }
///     fn uri(&self) -> &Uri { &self.uri }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// let content = r#"serde = "1.0.0""#;
/// let parse_result = MockParseResult {
///     deps: vec![MockDep {
///         name: PackageName::new("serde"),
///         version_req: VersionReq::new("1.0.0"),
///         version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
///         name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
///     }],
///     uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
/// };
///
/// let mut cached = HashMap::new();
/// cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
/// let resolved = HashMap::new();
///
/// let edits = collect_update_all_edits(
///     &parse_result,
///     content,
///     VersionData::new(&cached, &resolved),
///     &MockFormatter,
/// );
///
/// assert_eq!(edits.len(), 1);
/// assert_eq!(edits[0].new_text, "1.2.0");
/// ```
pub fn collect_update_all_edits(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<TextEdit> {
    let deps = parse_result.dependencies();
    let mut edits: Vec<TextEdit> = Vec::with_capacity(deps.len());
    // Built once and reused for every dependency below — content is fixed for the
    // whole call, so re-scanning it per dependency would be O(n²) in dependency count.
    let line_offsets = LineOffsetTable::new(content);

    for dep in deps {
        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let normalized_name = formatter.normalize_package_name(dep.name());
        let Some(latest) = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()))
            .map(|v| &v.latest)
        else {
            continue;
        };
        if !is_safe_version_string(latest.as_str()) {
            warn_rejected_value(
                "is_safe_version_string",
                "update-all code lens edit",
                latest.as_str(),
            );
            continue;
        }

        let Some(version_req) = dep.version_requirement() else {
            continue;
        };
        if version_req.as_str().is_empty() {
            // Defense-in-depth: an empty requirement would trivially satisfy the guard
            // below (both sides normalize to ""), so without this, a future formatter
            // whose `is_requirement_up_to_date` doesn't treat "" as up to date could
            // emit an edit anchored on a span that was never a version literal.
            continue;
        }
        if formatter.is_requirement_up_to_date(version_req, latest) {
            continue;
        }

        let slice = slice_for_range(content, &line_offsets, version_range);
        let literal_target = dep
            .version_literal()
            .unwrap_or_else(|| version_req.as_str());
        if !literal_span_matches(slice, literal_target) {
            continue;
        }

        let new_text = formatter.format_version_replacing(latest, version_req.as_str());
        // No-op guard, mirroring the REFACTOR-loop dedup and vulnerability-fix N1
        // guard in `code_actions`: a formatter can decide a declared
        // requirement has no single unambiguous rewrite (e.g. `deps-gradle`'s
        // `{strictly}!!{preferred}` shorthand, left unchanged rather than risking a
        // destructive or misleading edit) and return it unchanged. Without this
        // check, such a dependency would still count toward — and appear fixed
        // by — the "Update N outdated dependencies" lens while its click applies
        // nothing. Compares against `literal_target` (not `version_req`) for the same
        // reason the literal-span guard above does: for `deps-swift`, `version_req` is a
        // synthesized comparator that never equals the bare-literal formatted text even
        // when the edit genuinely is a no-op.
        if strip_whitespace(&new_text) == strip_whitespace(literal_target) {
            continue;
        }

        edits.push(TextEdit {
            range: version_range,
            new_text,
        });
    }

    edits.sort_by_key(|edit| (edit.range.start.line, edit.range.start.character));

    let mut non_overlapping: Vec<TextEdit> = Vec::with_capacity(edits.len());
    for edit in edits {
        let overlaps_prev = non_overlapping.last().is_some_and(|prev: &TextEdit| {
            (edit.range.start.line, edit.range.start.character)
                < (prev.range.end.line, prev.range.end.character)
        });
        if overlaps_prev {
            tracing::warn!(
                range = ?edit.range,
                "collect_update_all_edits: dropping overlapping TextEdit"
            );
            continue;
        }
        non_overlapping.push(edit);
    }

    non_overlapping
}

/// Zero or one lens for the document, bound to `command_id`.
///
/// Delegates to [`collect_update_all_edits`] for the count in the lens title — the same
/// call the command handler makes to produce the edits it applies, so `title N == edits
/// applied` holds by construction rather than by two implementations agreeing. Returns no
/// lens when there is nothing to update: a permanent line-0 annotation on every
/// up-to-date manifest would be noise.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{generate_code_lenses, EcosystemFormatter, VersionData};
/// use deps_core::{ConcreteVersion, PackageName, ParseResult};
/// use std::collections::HashMap;
///
/// struct MockFormatter;
/// impl EcosystemFormatter for MockFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{name}")
///     }
/// }
///
/// // An empty parse result yields no outdated dependencies, so no lens is generated.
/// # struct EmptyParseResult { uri: tower_lsp_server::ls_types::Uri }
/// # impl deps_core::ParseResult for EmptyParseResult {
/// #     fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> { vec![] }
/// #     fn workspace_root(&self) -> Option<&std::path::Path> { None }
/// #     fn uri(&self) -> &tower_lsp_server::ls_types::Uri { &self.uri }
/// #     fn as_any(&self) -> &dyn std::any::Any { self }
/// # }
/// let parse_result = EmptyParseResult { uri: deps_core::test_util::test_uri("/test/Cargo.toml") };
/// let cached = HashMap::new();
/// let resolved = HashMap::new();
///
/// let lenses = generate_code_lenses(
///     &parse_result,
///     "",
///     VersionData::new(&cached, &resolved),
///     &MockFormatter,
///     parse_result.uri(),
///     "deps-lsp.updateAllOutdated",
/// );
///
/// assert!(lenses.is_empty());
/// ```
pub fn generate_code_lenses(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
    uri: &Uri,
    command_id: &str,
) -> Vec<CodeLens> {
    let edits = collect_update_all_edits(parse_result, content, versions, formatter);
    if edits.is_empty() {
        return Vec::new();
    }

    let count = edits.len();
    let title = if count == 1 {
        "Update 1 outdated dependency".to_string()
    } else {
        format!("Update {count} outdated dependencies")
    };

    vec![CodeLens {
        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        command: Some(Command {
            title,
            command: command_id.to_string(),
            arguments: Some(vec![serde_json::json!({ "uri": uri })]),
        }),
        data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;
    use crate::{ConcreteVersion, PackageName, VersionReq};
    use std::any::Any;
    use std::collections::HashMap;

    mod update_all_edits_tests {
        use super::*;
        use tower_lsp_server::ls_types::{Position, Range};

        struct UaeDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            version_range: Option<Range>,
        }

        impl Dependency for UaeDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct UaeParseResult {
            deps: Vec<UaeDep>,
            uri: Uri,
        }

        impl ParseResult for UaeParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Range {
            Range::new(Position::new(sl, sc), Position::new(el, ec))
        }

        fn dep(name: &str, req: Option<&str>, vr: Option<Range>) -> UaeDep {
            UaeDep {
                name: PackageName::new(name),
                version_req: req.map(VersionReq::new),
                version_range: vr,
            }
        }

        fn parse_result(deps: Vec<UaeDep>) -> UaeParseResult {
            UaeParseResult {
                deps,
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            }
        }

        /// A formatter whose `is_requirement_up_to_date` ignores range semantics and
        /// always reports "not up to date" — mirrors NuGet's bare-requirement-is-a-floor
        /// override (`crates/deps-nuget/src/formatter.rs`), used to prove the override
        /// point is actually consulted rather than the trait default. Appends `-forced`
        /// in `format_version_for_text_edit` so the resulting edit is never a no-op: the
        /// override-is-honored test below intentionally declares a requirement already
        /// textually identical to `latest` (to isolate "was the hook consulted" from "is
        /// this genuinely outdated"), which would otherwise be indistinguishable from a
        /// real no-op and get filtered by `collect_update_all_edits`'s no-op guard.
        struct FloorFormatter;

        impl EcosystemFormatter for FloorFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                format!("{version}-forced")
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn is_requirement_up_to_date(
                &self,
                _requirement: &VersionReq,
                _latest: &ConcreteVersion,
            ) -> bool {
                false
            }
        }

        #[test]
        fn test_zero_outdated_returns_empty_edits_and_no_lens() {
            let content = r#"serde = "1.0.0""#;
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.0.0"));
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            assert!(edits.is_empty());

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert!(lenses.is_empty());
        }

        #[test]
        fn test_n_outdated_produces_n_edits_with_expected_range_and_text() {
            let content = "serde = \"1.0.0\"\ntokio = \"1.0.0\"\n";
            let pr = parse_result(vec![
                dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14))),
                dep("tokio", Some("1.0.0"), Some(range(1, 9, 1, 14))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            cached.insert("tokio".into(), PackageVersions::latest_only("1.3.0"));
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            assert_eq!(edits.len(), 2);
            assert_eq!(edits[0].range, range(0, 9, 0, 14));
            assert_eq!(
                edits[0].new_text,
                MockFormatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.0"))
            );
            assert_eq!(edits[1].range, range(1, 9, 1, 14));
            assert_eq!(
                edits[1].new_text,
                MockFormatter.format_version_for_text_edit(&ConcreteVersion::new("1.3.0"))
            );

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert_eq!(lenses.len(), 1);
            let command = lenses[0].command.as_ref().expect("lens has a command");
            assert_eq!(command.title, "Update 2 outdated dependencies");
            assert_eq!(command.command, "deps-lsp.updateAllOutdated");
        }

        #[test]
        fn test_singular_title_for_one_outdated_dependency() {
            let content = r#"serde = "1.0.0""#;
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let lenses = generate_code_lenses(
                &pr,
                content,
                versions,
                &MockFormatter,
                pr.uri(),
                "deps-lsp.updateAllOutdated",
            );
            assert_eq!(lenses.len(), 1);
            assert_eq!(
                lenses[0].command.as_ref().unwrap().title,
                "Update 1 outdated dependency"
            );
        }

        #[test]
        fn test_missing_version_range_is_skipped() {
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), None)]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_empty_version_requirement_is_skipped() {
            // Defense-in-depth (H2): an empty requirement would trivially satisfy
            // `literal_span_matches` if the guard were reached (both sides normalize to
            // "") and the span text would then be discarded and overwritten outright —
            // this must never reach the guard in the first place.
            let content = "pkg = \"\"\n";
            let pr = parse_result(vec![dep("pkg", Some(""), Some(range(0, 6, 0, 6)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("1.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "an empty version requirement must never produce an edit"
            );
        }

        #[test]
        fn test_dependency_absent_from_cache_is_skipped() {
            let content = "git-dep = \"1.0.0\"\n";
            let pr = parse_result(vec![dep(
                "git-dep",
                Some("1.0.0"),
                Some(range(0, 11, 0, 16)),
            )]);
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_empty_cached_latest_is_skipped() {
            // Regression for #303: an empty cached `latest` must never produce an
            // edit — the old no-op guard (comparing formatted text to the declared
            // requirement) doesn't catch this because `"" != "1.0.0"`, so without an
            // explicit guard the requirement gets erased instead of updated.
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only(""));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "an empty cached latest must never produce a requirement-erasing edit"
            );
        }

        #[test]
        fn test_whitespace_only_cached_latest_is_skipped() {
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("   "));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_cached_latest_with_unsafe_characters_is_skipped() {
            // Regression for #302: a registry-cached `latest` containing manifest-
            // structural characters must never be written verbatim into a `TextEdit`.
            let content = "serde = \"1.0.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14)))]);
            let mut cached = HashMap::new();
            cached.insert(
                "serde".into(),
                PackageVersions::latest_only("1.2.0\", \"evil\": \"true"),
            );
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_requirement_already_accepts_latest_is_not_counted() {
            // "^1.0" already accepts "1.2.0" per the default `is_requirement_up_to_date`,
            // so no edit is produced even though `latest` differs from the source text.
            let content = "serde = \"^1.0\"\n";
            let pr = parse_result(vec![dep("serde", Some("^1.0"), Some(range(0, 9, 0, 13)))]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.2.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_formatter_is_requirement_up_to_date_override_is_honored() {
            // With the trait default, "1.0.0" satisfying "1.0.0" would be up to date.
            // `FloorFormatter` overrides the hook to always report outdated, proving
            // `collect_update_all_edits` calls through the formatter, not the default.
            let content = r#"pkg = "1.0.0""#;
            let pr = parse_result(vec![dep("pkg", Some("1.0.0"), Some(range(0, 7, 0, 12)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("1.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &FloorFormatter,
            );
            assert_eq!(edits.len(), 1);
            assert_eq!(edits[0].new_text, "1.0.0-forced");
        }

        #[test]
        fn test_no_op_edit_is_excluded() {
            // M2: a formatter can decide a declared requirement has no single
            // unambiguous rewrite and return it unchanged (e.g. `deps-gradle`'s
            // `{strictly}!!{preferred}` infix shorthand). Without a no-op guard, this
            // dependency would still count toward, and be "fixed" by, the "Update N
            // outdated dependencies" lens while applying nothing.
            struct NoOpFormatter;
            impl EcosystemFormatter for NoOpFormatter {
                fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                    version.to_string()
                }
                fn package_url(&self, name: &PackageName) -> String {
                    format!("https://example.com/{name}")
                }
                fn format_version_replacing(
                    &self,
                    _version: &ConcreteVersion,
                    current: &str,
                ) -> String {
                    current.to_string()
                }
                fn is_requirement_up_to_date(
                    &self,
                    _requirement: &VersionReq,
                    _latest: &ConcreteVersion,
                ) -> bool {
                    false
                }
            }

            let content = r#"pkg = "1.0.0""#;
            let pr = parse_result(vec![dep("pkg", Some("1.0.0"), Some(range(0, 7, 0, 12)))]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("1.2.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &NoOpFormatter,
            );
            assert!(edits.is_empty());
        }

        #[test]
        fn test_guard_rejects_span_that_is_not_the_requirement() {
            // Simulates the Maven `${property}` class: version_range spans a reference,
            // version_requirement is the already-resolved value.
            let content = "<version>${slf4j.version}</version>";
            let pr = parse_result(vec![dep(
                "slf4j-api",
                Some("2.0.16"),
                Some(range(0, 9, 0, 25)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("slf4j-api".into(), PackageVersions::latest_only("2.1.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "a version_range spanning a property reference must not be edited"
            );
        }

        #[test]
        fn test_guard_accepts_whitespace_only_difference() {
            // PyPI's pep508 round-trip: `version_requirement()` is normalized to
            // ">=1.7, <2.0" while `version_range` still spans the un-normalized source.
            let content = "pkg>=1.7,<2.0";
            let pr = parse_result(vec![dep(
                "pkg",
                Some(">=1.7, <2.0"),
                Some(range(0, 3, 0, 13)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("pkg".into(), PackageVersions::latest_only("3.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(edits.len(), 1, "whitespace-only divergence must not skip");
        }

        #[test]
        fn test_guard_accepts_nuget_bracket_wrap() {
            // NuGet wraps a bare source version as the requirement: source "1.0.0" ->
            // requirement "[1.0.0]". The guard's bracket branch is the exact inverse.
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="1.0.0" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[1.0.0]"),
                Some(range(0, 53, 0, 58)),
            )]);
            let mut cached = HashMap::new();
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "NuGet's bracket-wrapped requirement must be kept"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_already_bracketed_source() {
            // The real reason the guard wraps only the slice, not both operands: NuGet's
            // parser wraps *unconditionally* — a source that is already bracketed,
            // `Version="[1.0.0]"`, still yields a double-wrapped requirement `[[1.0.0]]`
            // (`crates/deps-nuget/src/parser.rs`). A symmetric strip would compare
            // `[1.0.0]` against `1.0.0` here and falsely reject an editable dependency;
            // the asymmetric wrap-the-slice rule handles it correctly.
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0.0]" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0.0]]"),
                Some(range(0, 53, 0, 60)),
            )]);
            let mut cached = HashMap::new();
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "an already-bracketed NuGet source must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_open_ended_lower_bound_spelling() {
            // Another double-bracket NuGet spelling from §4.4's table: source
            // "[1.0.0,]" (open-ended lower bound) wraps to requirement "[[1.0.0,]]".
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0.0,]" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0.0,]]"),
                Some(range(0, 53, 0, 61)),
            )]);
            let mut cached = HashMap::new();
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "the open-ended-lower-bound NuGet spelling must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_accepts_nuget_exclusive_upper_bound_spelling() {
            // Third double-bracket NuGet spelling from §4.4's table: source
            // "[1.0,2.0)" (exclusive upper bound) wraps to requirement "[[1.0,2.0)]".
            let content = r#"<PackageReference Include="Newtonsoft.Json" Version="[1.0,2.0)" />"#;
            let pr = parse_result(vec![dep(
                "Newtonsoft.Json",
                Some("[[1.0,2.0)]"),
                Some(range(0, 53, 0, 62)),
            )]);
            let mut cached = HashMap::new();
            cached.insert(
                "Newtonsoft.Json".into(),
                PackageVersions::latest_only("13.0.3"),
            );
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(
                edits.len(),
                1,
                "the exclusive-upper-bound NuGet spelling must not be falsely rejected"
            );
        }

        #[test]
        fn test_guard_rejects_bracketed_interval_against_unbracketed_requirement() {
            // Regression guard for the OLD (broken) symmetric-strip rule: stripping
            // brackets from *both* operands would wrongly match a Maven-style bracketed
            // interval span `[1.0,2.0]` against an unbracketed requirement `1.0,2.0`.
            // The corrected asymmetric rule only wraps the *slice*, so
            // `format!("[{slice}]")` produces `[[1.0,2.0]]`, which does not equal
            // `1.0,2.0` either — the dependency must be skipped.
            let content = "<version>[1.0,2.0]</version>";
            let pr = parse_result(vec![dep(
                "interval-dep",
                Some("1.0,2.0"),
                Some(range(0, 9, 0, 18)),
            )]);
            let mut cached = HashMap::new();
            cached.insert("interval-dep".into(), PackageVersions::latest_only("3.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert!(
                edits.is_empty(),
                "a bracketed interval span must not match an unbracketed requirement"
            );
        }

        #[test]
        fn test_invariant_edit_count_matches_diagnostic_count_when_guard_is_noop() {
            // On a fixture where every span already equals its requirement (the guard is
            // a no-op), the edit count must equal the diagnostic count — same predicate.
            let content = "serde = \"1.0.0\"\ntokio = \"^1.5\"\nunknown = \"1.0.0\"\n";
            let pr = parse_result(vec![
                dep("serde", Some("1.0.0"), Some(range(0, 9, 0, 14))),
                dep("tokio", Some("^1.5"), Some(range(1, 9, 1, 13))),
                dep("unknown", Some("1.0.0"), Some(range(2, 11, 2, 16))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
            cached.insert("tokio".into(), PackageVersions::latest_only("1.9.0"));
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let edits = collect_update_all_edits(&pr, content, versions, &MockFormatter);
            let diagnostics = generate_diagnostics_from_cache(
                &pr,
                versions,
                &MockFormatter,
                crate::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );
            let newer_version_diagnostics = diagnostics
                .iter()
                .filter(|d| d.message.contains("Newer version available"))
                .count();

            assert_eq!(edits.len(), newer_version_diagnostics);
            assert_eq!(edits.len(), 1);
        }

        #[test]
        fn test_overlapping_edits_are_dropped_keeping_the_first() {
            let content = "aaaa = \"1.0.0\"\n";
            // Two dependencies whose declared version_range identically overlaps —
            // synthesizes the protocol-violation case the sort+assert guard exists for.
            let pr = parse_result(vec![
                dep("aaaa", Some("1.0.0"), Some(range(0, 8, 0, 13))),
                dep("aaaa-dup", Some("1.0.0"), Some(range(0, 8, 0, 13))),
            ]);
            let mut cached = HashMap::new();
            cached.insert("aaaa".into(), PackageVersions::latest_only("2.0.0"));
            cached.insert("aaaa-dup".into(), PackageVersions::latest_only("3.0.0"));
            let resolved = HashMap::new();

            let edits = collect_update_all_edits(
                &pr,
                content,
                VersionData::new(&cached, &resolved),
                &MockFormatter,
            );
            assert_eq!(edits.len(), 1, "the overlapping later edit must be dropped");
        }
    }
}
