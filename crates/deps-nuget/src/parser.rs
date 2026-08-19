//! Manifest parsers for `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, and
//! `packages.config`, with byte-accurate LSP position tracking.
//!
//! # Attribute byte spans
//!
//! NuGet carries its values in XML *attributes* (`Include="..."`, `Version="..."`), and
//! `quick-xml`'s `Attribute` exposes no span API. This module uses the borrowed-slice
//! offset instead of a text scan: `Reader::from_str(content)` + `reader.read_event()`
//! (mirroring `deps-maven`'s reader setup exactly, `crates/deps-maven/src/parser.rs:51,62`)
//! yields `Event<'a>` borrowed from `content` itself, so an attribute's raw `Cow<'a, [u8]>`
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

use crate::error::{NuGetError, Result};
use crate::types::NuGetDependency;
use deps_core::lsp_helpers::LineOffsetTable;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, BytesText, Event};
use tower_lsp_server::ls_types::{Range, Uri};

use crate::types::NuGetParseResult;

/// Parses a `.csproj`/`.fsproj`/`.vbproj` MSBuild project file, extracting `PackageReference` entries.
///
/// Supports both the attribute form (`Version="1.0"`) and the child-element metadata form
/// (`<Version>1.0</Version>`). Central package management entries (no `Version` attribute
/// or child) are emitted with `version_requirement: None` so hover/completion on the name
/// still works.
pub fn parse_project_file(content: &str, doc_uri: &Uri) -> Result<NuGetParseResult> {
    parse_reference_elements(content, doc_uri, "PackageReference")
}

/// Parses a `Directory.Packages.props` central package management file, extracting
/// `PackageVersion` entries.
pub fn parse_directory_packages_props(content: &str, doc_uri: &Uri) -> Result<NuGetParseResult> {
    parse_reference_elements(content, doc_uri, "PackageVersion")
}

/// Parses a legacy `packages.config` file, extracting `package` entries.
///
/// `packages.config` `version="..."` semantics are an **exact pin**, unlike the floor
/// semantics of a bare `PackageReference` `Version="..."`. That difference is normalized at
/// parse time into a bracketed exact range (`"1.0.0"` → `"[1.0.0]"`) so the existing interval
/// parser (`crate::version::satisfies`) handles it with no new formatter state.
pub fn parse_packages_config(content: &str, doc_uri: &Uri) -> Result<NuGetParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut dependencies = Vec::new();

    loop {
        let event = reader.read_event().map_err(|e| NuGetError::ParseError {
            message: e.to_string(),
        })?;

        match event {
            Event::Empty(ref e) | Event::Start(ref e) if e.local_name().as_ref() == b"package" => {
                if let Some(dep) = parse_package_element(content, &line_table, e) {
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
    })
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
            b"id" => {
                name_span = attribute_byte_range(content, &attr.value);
                name = Some(decode_attr_value(&attr.value));
            }
            b"version" => {
                version_span = attribute_byte_range(content, &attr.value);
                version = Some(decode_attr_value(&attr.value));
            }
            _ => {}
        }
    }

    let name = name?;
    let name_range = span_to_range(content, line_table, name_span);
    let (version_requirement, version_range) = match version {
        Some(v) if !v.contains("$(") => (
            Some(format!("[{v}]")),
            Some(span_to_range(content, line_table, version_span)),
        ),
        _ => (None, None),
    };

    Some(NuGetDependency {
        name,
        name_range,
        version_requirement,
        version_range,
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
    doc_uri: &Uri,
    tag_name: &str,
) -> Result<NuGetParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut dependencies = Vec::new();
    let mut current: Option<DepAccum> = None;
    let mut in_version_child = false;

    loop {
        let text_pos = reader.buffer_position();
        let event = reader.read_event().map_err(|e| NuGetError::ParseError {
            message: e.to_string(),
        })?;

        match event {
            Event::Empty(ref e) => {
                if e.local_name().as_ref() == tag_name.as_bytes()
                    && let Some(dep) =
                        finalize_dep(content, &line_table, accum_from_attrs(content, e))
                {
                    dependencies.push(dep);
                }
            }
            Event::Start(ref e) => {
                if e.local_name().as_ref() == tag_name.as_bytes() {
                    current = Some(accum_from_attrs(content, e));
                } else if current.is_some() && e.local_name().as_ref() == b"Version" {
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
                if local.as_ref() == b"Version" && in_version_child {
                    in_version_child = false;
                } else if local.as_ref() == tag_name.as_bytes()
                    && let Some(accum) = current.take()
                    && let Some(dep) = finalize_dep(content, &line_table, accum)
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
    })
}

fn accum_from_attrs(content: &str, e: &BytesStart<'_>) -> DepAccum {
    let mut accum = DepAccum::default();
    for attr in e.attributes().flatten() {
        match attr.key.local_name().as_ref() {
            b"Include" => {
                accum.name_span = attribute_byte_range(content, &attr.value);
                accum.name = Some(decode_attr_value(&attr.value));
            }
            b"Version" => {
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
        name,
        name_range,
        version_requirement,
        version_range,
    })
}

/// Unresolvable MSBuild property expressions (`Version="$(SerilogVersion)"`) and central
/// package management entries (no `Version` at all) both degrade to `version_requirement:
/// None` rather than a bogus or unresolved-looking requirement (spec §3, deferred scope).
fn resolve_version_field(
    content: &str,
    line_table: &LineOffsetTable,
    version: Option<String>,
    span: (usize, usize),
) -> (Option<String>, Option<Range>) {
    match version {
        Some(v) if !v.contains("$(") => (Some(v), Some(span_to_range(content, line_table, span))),
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
fn attribute_byte_range(content: &str, raw: &[u8]) -> (usize, usize) {
    let Some(offset) = (raw.as_ptr() as usize).checked_sub(content.as_ptr() as usize) else {
        return (0, 0);
    };
    (offset, offset + raw.len())
}

fn span_to_range(content: &str, line_table: &LineOffsetTable, span: (usize, usize)) -> Range {
    Range::new(
        line_table.byte_offset_to_position(content, span.0),
        line_table.byte_offset_to_position(content, span.1),
    )
}

fn decode_attr_value(raw: &[u8]) -> String {
    std::str::from_utf8(raw)
        .ok()
        .and_then(|s| quick_xml::escape::unescape(s).ok())
        .map(|c| c.into_owned())
        .unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned())
}

fn decode_text(e: &BytesText<'_>) -> String {
    match e.decode() {
        Ok(cow) => {
            let s = cow.trim().to_string();
            quick_xml::escape::unescape(&s)
                .map(|c| c.into_owned())
                .unwrap_or(s)
        }
        Err(_) => String::from_utf8_lossy(e.as_ref()).trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/App.csproj")
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
            if attr.key.local_name().as_ref() == b"Version" {
                let (start, end) = attribute_byte_range(xml, &attr.value);
                assert_eq!(&xml.as_bytes()[start..end], attr.value.as_ref());
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
    fn test_attribute_byte_range_checked_sub_fallback_on_invariant_violation() {
        // Deterministically construct `raw` at a lower memory address than `content` by
        // slicing the same backing buffer in reverse order — this violates the "raw
        // borrows from content" invariant and must return the safe (0, 0) fallback instead
        // of wrapping.
        let buffer = "0123456789";
        let content = &buffer[5..];
        let raw = &buffer.as_bytes()[0..3];
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
        assert!(result.is_err());
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
