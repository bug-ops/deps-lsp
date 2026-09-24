//! Manifest parsers for `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, and
//! `packages.config`, with byte-accurate LSP position tracking.
//!
//! No element-count/scan-position bound is applied here (#698): the input is a local
//! manifest already capped by `deps-lsp`'s `MAX_FILE_SIZE` (10 MB) read path, unlike a
//! remote registry response.
//!
//! # Attribute byte spans
//!
//! NuGet carries its values in XML *attributes* (`Include="..."`, `Version="..."`), and
//! `quick-xml`'s `Attribute` exposes no span API. This module uses the borrowed-slice
//! offset instead of a text scan: `Reader::from_str(content)` + `reader.read_event()`
//! (mirroring `deps-maven`'s reader setup exactly, `crates/deps-maven/src/parser.rs:51,62`)
//! yields `Event<'a>` borrowed from `content` itself, so an attribute's raw `Cow<'a, str>`
//! value is `Cow::Borrowed` pointing directly into `content`'s bytes. The byte offset is then
//! simple pointer arithmetic:
//!
//! ```ignore
//! let offset = value.as_ptr() as usize - content.as_ptr() as usize;
//! ```
//!
//! This is O(1) and immune to the false-match a text scan would hit on an MSBuild
//! `Condition` attribute whose *value* happens to contain the literal text `Version="`
//! (see `test_condition_attribute_with_literal_version_text` below). Switching the reader
//! to `Reader::from_reader` + `read_event_into(&mut buf)` would make attributes borrow from
//! the scratch buffer instead of `content`, silently breaking this arithmetic — it would
//! compile and produce garbage ranges. `test_attribute_byte_range_matches_source_bytes`
//! guards against that regression.

use crate::types::NuGetDependency;
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::position::Range;
use deps_core::{DepsError, Result};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, BytesText, Event};
use url::Url;

/// Parsed result of a single manifest file (`.csproj`, `Directory.Packages.props`,
/// `packages.config`).
#[non_exhaustive]
#[derive(Debug)]
pub struct NuGetParseResult {
    /// Dependencies found in the manifest.
    pub dependencies: Vec<NuGetDependency>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// Every routing chain this manifest's resolved `NuGet.Config` implies (issue #523) — one
    /// per distinct `<packageSourceMapping>` hop-set, or the single plain accumulated chain
    /// when no mapping is declared. Registered against the shared `NuGetRegistry` by
    /// `NuGetEcosystem::parse_manifest`; empty when nothing is registrable (no config, or
    /// every dependency resolves to plain `Registry`/a fail-closed `CustomRegistry`).
    pub resolved_chains: Vec<crate::config::NuGetSourceChain>,
    /// Dependency lines whose `NuGet.Config` `<packageSources>`/`<packageSourceMapping>`
    /// resolution was blocked by the current `registries.workspace_registries` policy (#925,
    /// mirrors `deps_cargo::parser::CargoParseResult::blocked_registries`), where the
    /// declaration key (from [`crate::config::NuGetConfig::blocked_class_for`]) is the
    /// source's own declared `<add key>` name, distinguishing two independently declared
    /// sources even when they share a raw value. Surfaced by
    /// [`deps_core::lsp_helpers::generate_diagnostics_from_cache`] via
    /// [`Self::blocked_registries`]'s trait override as an informational diagnostic, so the
    /// block never degrades silently.
    pub blocked_registries: Vec<deps_core::BlockedRegistryOccurrence>,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796).
    pub dependency_truncation: Option<(usize, usize)>,
}

deps_core::impl_parse_result!(
    NuGetParseResult,
    NuGetDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
        blocked_registries: blocked_registries,
    }
);

/// Parses a `.csproj`/`.fsproj`/`.vbproj` MSBuild project file, extracting `PackageReference` entries.
///
/// Supports both the attribute form (`Version="1.0"`) and the child-element metadata form
/// (`<Version>1.0</Version>`). Central package management entries (no `Version` attribute
/// or child) are emitted with `version_requirement: None` so hover/completion on the name
/// still works.
///
/// # Errors
///
/// Returns a [`DepsError::ParseError`] if `content` is not well-formed XML.
pub fn parse_project_file(content: &str, doc_uri: &Url) -> Result<NuGetParseResult> {
    parse_reference_elements(content, doc_uri, "PackageReference")
}

/// Parses a `Directory.Packages.props` central package management file, extracting
/// `PackageVersion` entries.
///
/// # Errors
///
/// Same as [`parse_project_file`].
pub fn parse_directory_packages_props(content: &str, doc_uri: &Url) -> Result<NuGetParseResult> {
    parse_reference_elements(content, doc_uri, "PackageVersion")
}

/// Parses a legacy `packages.config` file, extracting `package` entries.
///
/// `packages.config` `version="..."` semantics are an **exact pin**, unlike the floor
/// semantics of a bare `PackageReference` `Version="..."`. That difference is normalized at
/// parse time into a bracketed exact range (`"1.0.0"` → `"[1.0.0]"`) so the existing interval
/// parser (`crate::version::satisfies`) handles it with no new formatter state.
///
/// # Errors
///
/// Same as [`parse_project_file`].
pub fn parse_packages_config(content: &str, doc_uri: &Url) -> Result<NuGetParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut dependencies = Vec::new();
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    loop {
        let event = reader
            .read_event()
            .map_err(|e| DepsError::parse_error("NuGet project file", &e))?;

        match event {
            Event::Empty(ref e) | Event::Start(ref e) if e.local_name().as_ref() == "package" => {
                if let Some(dep) = parse_package_element(content, &line_table, e)
                    && budget.allow()
                {
                    dependencies.push(dep);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(NuGetParseResult {
        dependencies,
        uri: doc_uri.clone(),
        resolved_chains: Vec::new(),
        blocked_registries: Vec::new(),
        dependency_truncation: budget.truncation(),
    })
}

/// True when `s` contains an unexpanded MSBuild reference: a property (`$(Name)`), an
/// item-metadata (`%(Name)`), or an item-list (`@(Name)`) reference. None of these are a
/// concrete value until MSBuild expands them, so wherever this is true a `version`/`Version`
/// string must degrade to "no requirement" rather than be treated as a real, checkable one —
/// used by both this module's parse-time degrade guards and
/// [`crate::formatter::NuGetFormatter::requirement_is_placeholder`] (whose default
/// `requirement_is_unresolved` delegates to it, #1380), so the same reference is never
/// partially recognized at one layer and not the other (#1355).
///
/// A false positive is not realistically possible: a literal `%` in an MSBuild string must be
/// escaped as `%25`, and none of `$`, `%`, `@` followed by `(` can appear in a real NuGet
/// version string.
pub(crate) fn is_msbuild_reference(s: &str) -> bool {
    s.contains("$(") || s.contains("%(") || s.contains("@(")
}

fn parse_package_element(
    content: &str,
    line_table: &LineOffsetTable,
    e: &BytesStart<'_>,
) -> Option<NuGetDependency> {
    let mut name = None;
    let mut name_span = (0usize, 0usize);
    let mut version = None;
    let mut version_span = (0usize, 0usize);

    for attr in e.attributes().flatten() {
        match attr.key.local_name().as_ref() {
            "id" => {
                name_span = attribute_byte_range(content, &attr.value);
                name = Some(decode_attr_value(&attr.value));
            }
            "version" => {
                version_span = attribute_byte_range(content, &attr.value);
                version = Some(decode_attr_value(&attr.value));
            }
            _ => {}
        }
    }

    let name = name?;
    let name_range = span_to_range(content, line_table, name_span);
    // An empty `version=""` attribute must degrade to "no requirement" like an unresolved
    // MSBuild reference does — left unguarded, it gets wrapped into `"[]"`, which
    // `crate::version::parse_range` now rejects as malformed (#821) rather than treating it
    // as an exact pin — but wrapping it at all would still turn "no version" into a
    // requirement string instead of being skipped by the empty-`VersionReq` guards downstream.
    let (version_requirement, version_range) = match version {
        Some(v) if !v.trim().is_empty() && !is_msbuild_reference(&v) => (
            Some(format!("[{}]", v.trim())),
            Some(span_to_range(content, line_table, version_span)),
        ),
        _ => (None, None),
    };

    Some(NuGetDependency {
        name: name.into(),
        name_range,
        version_requirement: version_requirement.map(Into::into),
        version_range,
        source: deps_core::parser::DependencySource::Registry,
    })
}

/// Accumulator for a single `PackageReference`/`PackageVersion` entry being parsed.
#[derive(Default)]
struct DepAccum {
    name: Option<String>,
    name_span: (usize, usize),
    version: Option<String>,
    version_span: (usize, usize),
}

fn parse_reference_elements(
    content: &str,
    doc_uri: &Url,
    tag_name: &str,
) -> Result<NuGetParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut dependencies = Vec::new();
    let mut current: Option<DepAccum> = None;
    let mut in_version_child = false;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    loop {
        let text_pos = reader.buffer_position();
        let event = reader
            .read_event()
            .map_err(|e| DepsError::parse_error("NuGet project file", &e))?;

        match event {
            Event::Empty(ref e) => {
                if e.local_name().as_ref() == tag_name
                    && let Some(dep) =
                        finalize_dep(content, &line_table, accum_from_attrs(content, e))
                    && budget.allow()
                {
                    dependencies.push(dep);
                }
            }
            Event::Start(ref e) => {
                if e.local_name().as_ref() == tag_name {
                    current = Some(accum_from_attrs(content, e));
                } else if current.is_some() && e.local_name().as_ref() == "Version" {
                    in_version_child = true;
                }
            }
            Event::Text(ref e) if in_version_child => {
                if let Some(accum) = current.as_mut() {
                    let text_end = reader.buffer_position();
                    accum.version = Some(decode_text(e));
                    accum.version_span = (text_pos as usize, text_end as usize);
                }
            }
            Event::End(ref e) => {
                let local = e.local_name();
                if local.as_ref() == "Version" && in_version_child {
                    in_version_child = false;
                } else if local.as_ref() == tag_name
                    && let Some(accum) = current.take()
                    && let Some(dep) = finalize_dep(content, &line_table, accum)
                    && budget.allow()
                {
                    dependencies.push(dep);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(NuGetParseResult {
        dependencies,
        uri: doc_uri.clone(),
        resolved_chains: Vec::new(),
        blocked_registries: Vec::new(),
        dependency_truncation: budget.truncation(),
    })
}

fn accum_from_attrs(content: &str, e: &BytesStart<'_>) -> DepAccum {
    let mut accum = DepAccum::default();
    for attr in e.attributes().flatten() {
        match attr.key.local_name().as_ref() {
            "Include" => {
                accum.name_span = attribute_byte_range(content, &attr.value);
                accum.name = Some(decode_attr_value(&attr.value));
            }
            "Version" => {
                accum.version_span = attribute_byte_range(content, &attr.value);
                accum.version = Some(decode_attr_value(&attr.value));
            }
            _ => {}
        }
    }
    accum
}

fn finalize_dep(
    content: &str,
    line_table: &LineOffsetTable,
    accum: DepAccum,
) -> Option<NuGetDependency> {
    let name = accum.name?;
    let name_range = span_to_range(content, line_table, accum.name_span);
    let (version_requirement, version_range) =
        resolve_version_field(content, line_table, accum.version, accum.version_span);

    Some(NuGetDependency {
        name: name.into(),
        name_range,
        version_requirement: version_requirement.map(Into::into),
        version_range,
        source: deps_core::parser::DependencySource::Registry,
    })
}

/// Unresolvable MSBuild reference expressions (`Version="$(SerilogVersion)"`,
/// `Version="%(Version)"`, `Version="@(PollyVer)"`), central package management entries (no
/// `Version` at all), and an empty/whitespace-only `Version=""` attribute all degrade to
/// `version_requirement: None` rather than a bogus or unresolved-looking requirement (spec
/// §3, deferred scope) — matching the `packages.config` path's `version=""` guard in
/// `parse_package_element` above.
fn resolve_version_field(
    content: &str,
    line_table: &LineOffsetTable,
    version: Option<String>,
    span: (usize, usize),
) -> (Option<String>, Option<Range>) {
    match version {
        Some(ref v) if !v.trim().is_empty() && !is_msbuild_reference(v) => (
            Some(v.trim().to_string()),
            Some(span_to_range(content, line_table, span)),
        ),
        _ => (None, None),
    }
}

/// Computes the byte offset range of an attribute's raw value slice within `content`.
///
/// Sound only when `raw` borrows directly from `content` (`Cow::Borrowed`), which holds for
/// `Reader::from_str` + `read_event()` per the module docs above. `checked_sub` guards
/// against that invariant being violated by a future reader-setup regression: release
/// builds have no overflow checks, so an unchecked subtraction would wrap silently into a
/// garbage offset instead of failing loudly — falling back to an empty `(0, 0)` range is
/// safe (worst case, a wrong/empty LSP range) where a wrapped `usize` is not.
fn attribute_byte_range(content: &str, raw: &str) -> (usize, usize) {
    let Some(offset) = (raw.as_ptr() as usize).checked_sub(content.as_ptr() as usize) else {
        return (0, 0);
    };
    (offset, offset + raw.len())
}

/// Adapts a `(start, end)` byte-offset pair to [`deps_core::lsp_helpers::byte_span_to_range`].
fn span_to_range(content: &str, line_table: &LineOffsetTable, span: (usize, usize)) -> Range {
    deps_core::lsp_helpers::byte_span_to_range(content, line_table, span.0, span.1)
}

fn decode_attr_value(raw: &str) -> String {
    quick_xml::escape::unescape(raw)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

fn decode_text(e: &BytesText<'_>) -> String {
    let s = e.trim().to_string();
    quick_xml::escape::unescape(&s)
        .map(|c| c.into_owned())
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/test/App.csproj")
    }

    #[test]
    fn test_is_msbuild_reference_recognizes_all_three_forms() {
        assert!(is_msbuild_reference("$(SerilogVersion)"));
        assert!(is_msbuild_reference("%(Version)"));
        assert!(is_msbuild_reference("@(PollyVer)"));
        assert!(is_msbuild_reference("[$(MinVersion),$(MaxVersion))"));
        assert!(!is_msbuild_reference("13.0.3"));
        assert!(!is_msbuild_reference("[1.0,2.0)"));
        assert!(!is_msbuild_reference(""));
    }

    #[test]
    fn test_parse_attribute_form() {
        let xml = r#"<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "Newtonsoft.Json");
        assert_eq!(dep.version_requirement, Some("13.0.3".into()));
        assert!(dep.version_range.is_some());
    }

    #[test]
    fn test_parse_child_element_form() {
        let xml = r#"<Project>
  <ItemGroup>
    <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
  </ItemGroup>
</Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "Serilog");
        assert_eq!(dep.version_requirement, Some("3.1.1".into()));
    }

    #[test]
    fn test_parse_child_element_form_multiline_whitespace() {
        // Whitespace-padded child-element form: `<Version>\n  3.1.1\n</Version>`.
        // decode_text() trims the extracted value regardless of surrounding whitespace
        // (matches deps-maven's identical text-node handling).
        let xml = "<Project><ItemGroup><PackageReference Include=\"Serilog\"><Version>\n      3.1.1\n    </Version></PackageReference></ItemGroup></Project>";
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("3.1.1".into())
        );
    }

    /// #1243: `quick_xml`'s `IllFormed::MismatchedEndTag` embeds the raw tag-name text
    /// verbatim in its `Display` output, so a credential-shaped tag name must be redacted
    /// the same way `toml_span`/`yaml_rust2` parse errors already are (#1240/#1241).
    /// `parse_project_file` (`parse_reference_elements`) and `parse_packages_config` are
    /// independent call sites with their own `reader.read_event()` `map_err`, so each gets
    /// its own regression test below — see `test_parse_packages_config_mismatched_end_tag_error_redacts_credential`
    /// for the `parse_packages_config` coverage (#1243 M2).
    #[test]
    fn test_parse_mismatched_end_tag_error_redacts_credential() {
        let xml = "<root><https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x ></root>";

        let message = parse_project_file(xml, &test_uri())
            .unwrap_err()
            .to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    #[test]
    fn test_parse_mismatched_end_tag_error_benign_name_unchanged() {
        let xml = "<root><foo></bar></root>";

        // Derived from the raw quick-xml error, not hardcoded, so assert_eq! gates a
        // redaction regression (mirrors #1240 M5's convention).
        let mut reader = quick_xml::Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let raw_err = loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Eof) => panic!("expected a parse error"),
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        let expected = format!("failed to parse NuGet project file: {raw_err}");

        let message = parse_project_file(xml, &test_uri())
            .unwrap_err()
            .to_string();
        assert_eq!(message, expected);
    }

    #[test]
    fn test_parse_central_package_management_no_version() {
        let xml = r#"<Project>
  <ItemGroup>
    <PackageReference Include="Serilog" />
  </ItemGroup>
</Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Serilog");
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    #[test]
    fn test_parse_multiple_references() {
        let xml = r#"<Project>
  <ItemGroup>
    <PackageReference Include="A" Version="1.0.0" />
    <PackageReference Include="B" Version="2.0.0" />
  </ItemGroup>
</Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "A");
        assert_eq!(result.dependencies[1].name, "B");
    }

    #[test]
    fn test_attribute_order_version_before_include() {
        let xml = r#"<Project><ItemGroup><PackageReference Version="1.2.3" Include="Foo" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("1.2.3".into())
        );
    }

    #[test]
    fn test_single_and_double_quotes() {
        let xml = r"<Project><ItemGroup><PackageReference Include='Foo' Version='1.0.0' /></ItemGroup></Project>";
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("1.0.0".into())
        );
    }

    #[test]
    fn test_whitespace_around_equals() {
        let xml = r#"<Project><ItemGroup><PackageReference Include = "Foo" Version = "1.0.0" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("1.0.0".into())
        );
    }

    #[test]
    fn test_self_closing_vs_paired_tags() {
        let self_closing = r#"<Project><ItemGroup><PackageReference Include="Foo" Version="1.0.0" /></ItemGroup></Project>"#;
        let paired = r#"<Project><ItemGroup><PackageReference Include="Foo" Version="1.0.0"></PackageReference></ItemGroup></Project>"#;

        let r1 = parse_project_file(self_closing, &test_uri()).unwrap();
        let r2 = parse_project_file(paired, &test_uri()).unwrap();

        assert_eq!(r1.dependencies.len(), 1);
        assert_eq!(r2.dependencies.len(), 1);
        assert_eq!(r1.dependencies[0].name, r2.dependencies[0].name);
        assert_eq!(
            r1.dependencies[0].version_requirement,
            r2.dependencies[0].version_requirement
        );
    }

    #[test]
    fn test_condition_attribute_with_literal_version_text() {
        // A `Condition` attribute value containing the literal text `Version="` would
        // false-match a naive text scan. The attribute-key-based parser must not be fooled.
        let xml = r#"<Project><ItemGroup><PackageReference Include="Foo" Condition="'$(Version)' == 'Version="9.9.9"'" Version="1.0.0" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("1.0.0".into())
        );
    }

    #[test]
    #[allow(clippy::string_slice)] // ASCII fixture literal
    fn test_attribute_byte_range_matches_source_bytes() {
        // Guards the reader-setup constraint: attribute values must borrow directly from
        // `content` (Reader::from_str + read_event()), not a scratch buffer, or this
        // pointer-arithmetic offset silently produces garbage ranges.
        let xml = r#"<PackageReference Include="Foo" Version="1.2.3" />"#;
        let mut reader = Reader::from_str(xml);
        let event = reader.read_event().unwrap();
        let Event::Empty(e) = event else {
            panic!("expected Empty event");
        };
        let mut checked = false;
        for attr in e.attributes().flatten() {
            if attr.key.local_name().as_ref() == "Version" {
                let (start, end) = attribute_byte_range(xml, &attr.value);
                assert_eq!(&xml[start..end], attr.value.as_ref());
                assert_eq!(&xml[start..end], "1.2.3");
                checked = true;
            }
        }
        assert!(
            checked,
            "Version attribute was never found — guarded assertions did not run"
        );
    }

    #[test]
    #[allow(clippy::string_slice)] // ASCII fixture literal
    fn test_attribute_byte_range_checked_sub_fallback_on_invariant_violation() {
        // Deterministically construct `raw` at a lower memory address than `content` by
        // slicing the same backing buffer in reverse order — this violates the "raw
        // borrows from content" invariant and must return the safe (0, 0) fallback instead
        // of wrapping.
        let buffer = "0123456789";
        let content = &buffer[5..];
        let raw = &buffer[0..3];
        assert_eq!(attribute_byte_range(content, raw), (0, 0));
    }

    #[test]
    fn test_directory_packages_props() {
        let xml = r#"<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>"#;
        let uri = deps_core::test_util::test_uri("/test/Directory.Packages.props");
        let result = parse_directory_packages_props(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Newtonsoft.Json");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("13.0.3".into())
        );
    }

    #[test]
    fn test_packages_config_normalizes_exact_pin() {
        let xml = r#"<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Newtonsoft.Json");
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("[13.0.3]".into())
        );
    }

    #[test]
    fn test_packages_config_empty_version_degrades_to_none() {
        let xml = r#"<packages>
  <package id="Foo" version="" targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert_eq!(result.dependencies[0].version_requirement, None);
        assert_eq!(result.dependencies[0].version_range, None);
    }

    /// M1: a whitespace-only `version` attribute must degrade to `None` the same as a
    /// truly empty one — otherwise it produces the bogus `"[   ]"` exact pin.
    #[test]
    fn test_packages_config_whitespace_only_version_degrades_to_none() {
        let xml = r#"<packages>
  <package id="Foo" version="   " targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_requirement, None);
        assert_eq!(result.dependencies[0].version_range, None);
    }

    /// M11: a non-empty `version` attribute with leading/trailing whitespace must have
    /// that whitespace trimmed before being wrapped into the exact-pin syntax, or the
    /// stray spaces end up baked into `"[ 1.0.0 ]"` instead of `"[1.0.0]"`.
    #[test]
    fn test_packages_config_version_with_surrounding_whitespace_is_trimmed() {
        let xml = r#"<packages>
  <package id="Foo" version=" 1.0.0 " targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("[1.0.0]".into())
        );
    }

    #[test]
    fn test_packages_config_multiple_packages() {
        let xml = r#"<packages>
  <package id="A" version="1.0.0" targetFramework="net48" />
  <package id="B" version="2.0.0" targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 2);
    }

    #[test]
    fn test_unresolved_msbuild_property_degrades_to_none() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Serilog" Version="$(SerilogVersion)" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Serilog");
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// #1355: `%(Version)` (MSBuild item-metadata syntax) must degrade to `None` the same as
    /// `$(PropertyName)` — before this fix it survived parsing as a real requirement string
    /// and could plan an incorrect version-rewrite edit, offer completions, and render a
    /// diagnostic (live-verified by impl-critic).
    #[test]
    fn test_unresolved_msbuild_item_metadata_degrades_to_none() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Polly" Version="%(Version)" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Polly");
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// #1355: `@(ItemList)` (MSBuild item-list reference) must degrade to `None` too — it has
    /// no bracket for `crate::version::parse_range`'s nested-bracket guard to trip on, so
    /// unguarded it parsed as a bogus bare-floor version (live-verified by impl-critic).
    #[test]
    fn test_unresolved_msbuild_item_list_degrades_to_none() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Polly" Version="@(PollyVer)" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Polly");
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// #1355: same degrade behavior via the `packages.config` parse path
    /// (`parse_package_element`'s inline guard, not `resolve_version_field`).
    #[test]
    fn test_packages_config_msbuild_item_metadata_degrades_to_none() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Polly" version="%(Version)" targetFramework="net48" />
</packages>"#;
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let result = parse_packages_config(xml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// M2: `Version=""` on a `PackageReference` must degrade to `None`, aligning with the
    /// `packages.config` `version=""` guard instead of yielding `Some("")`.
    #[test]
    fn test_package_reference_empty_version_degrades_to_none() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Foo" Version="" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "Foo");
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// M1/M2 sibling: whitespace-only `Version` must also degrade to `None`.
    #[test]
    fn test_package_reference_whitespace_only_version_degrades_to_none() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Foo" Version="   " /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_requirement.is_none());
        assert!(result.dependencies[0].version_range.is_none());
    }

    /// M11 sibling: same whitespace trimming for the `PackageReference`/central-package
    /// resolution path (`resolve_version_field`).
    #[test]
    fn test_package_reference_version_with_surrounding_whitespace_is_trimmed() {
        let xml = r#"<Project><ItemGroup><PackageReference Include="Foo" Version=" 1.0.0 " /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].version_requirement,
            Some("1.0.0".into())
        );
    }

    #[test]
    fn test_empty_project() {
        let xml = "<Project></Project>";
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_invalid_xml_errors() {
        let xml = r#"<Project attr="unclosed></Project>"#;
        let result = parse_project_file(xml, &test_uri());
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "NuGet project file"
        );
    }

    #[test]
    fn test_packages_config_invalid_xml_errors() {
        let xml = r#"<packages attr="unclosed></packages>"#;
        let result = parse_packages_config(xml, &test_uri());
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "NuGet project file"
        );
    }

    /// #1243 M2: `parse_packages_config` has its own `reader.read_event()` `map_err` site,
    /// independent of `parse_reference_elements`'s (covered by
    /// `test_parse_mismatched_end_tag_error_redacts_credential` above) — regressing this site
    /// alone would leave the rest of the suite green.
    #[test]
    fn test_parse_packages_config_mismatched_end_tag_error_redacts_credential() {
        let xml = "<root><https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x ></root>";

        let message = parse_packages_config(xml, &test_uri())
            .unwrap_err()
            .to_string();
        assert!(!message.contains("ghp_SUPERSECRETTOKEN123"));
        assert!(!message.contains("svcacct"));
        assert!(message.contains("pkg.internal.corp"));
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let xml = r#"<Project><ItemGroup><PackageReference Include="Foo" Version="1.0.0" /></ItemGroup></Project>"#;
        let result = parse_project_file(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<NuGetParseResult>());
    }

    #[test]
    fn test_position_tracking() {
        let xml = "<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Foo\" Version=\"1.0.0\" />\n  </ItemGroup>\n</Project>";
        let result = parse_project_file(xml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name_range.start.line, 2);
    }
}
