//! pom.xml parser with byte-accurate position tracking.
//!
//! Uses quick-xml SAX reader to parse Maven POM files.
//! Tracks byte positions for LSP range computation.
//!
//! No element-count/scan-position bound is applied here (#698): the input is a local
//! manifest already capped by `deps-lsp`'s `MAX_FILE_SIZE` (10 MB) read path, unlike
//! `deps-maven::registry::parse_metadata_xml`'s remote, unbounded-by-default input.

use crate::types::{MavenDependency, MavenScope};
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use deps_core::position::Range;
use deps_core::{DepsError, Result};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;
use url::Url;

/// Result of parsing a `pom.xml` file.
#[non_exhaustive]
#[derive(Debug)]
pub struct MavenParseResult {
    /// Dependencies found across `<dependencies>` and `<dependencyManagement>`.
    pub dependencies: Vec<MavenDependency>,
    /// The `<properties>` section, for resolving `${...}` version placeholders.
    pub properties: HashMap<String, String>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// Context stack element for SAX parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseContext {
    Root,
    Dependencies,
    DependencyManagement,
    Plugins,
    Dependency,
    Plugin,
    Properties,
}

/// Accumulator for a single dependency being parsed.
#[derive(Default)]
struct DepAccum {
    group_id: Option<String>,
    artifact_id: Option<String>,
    artifact_id_start: u64,
    artifact_id_end: u64,
    version: Option<String>,
    version_start: u64,
    version_end: u64,
    /// Byte offset right after `<version>`'s opening tag, captured unconditionally on
    /// `Start` (independent of whether a `Text` event ever follows) — quick-xml's reader
    /// (`trim_text(true)`) emits no `Text` event at all for an empty or whitespace-only
    /// `<version></version>`, so this is the only position captured for that shape (#1161).
    version_open_pos: Option<u64>,
    /// Buffer position captured before reading the `End` event for `</version>`, set only
    /// when no `Text` event set `version` — see `version_open_pos`.
    version_close_pos: Option<u64>,
    scope: Option<String>,
    /// `<systemPath>` text, present only for a `scope: system` dependency (#1202, Maven fix)
    /// — the explicit, already-per-dependency local-jar binding `MavenScope::System` names.
    system_path: Option<String>,
}

/// Parses a `pom.xml` document into a [`MavenParseResult`].
///
/// # Errors
///
/// Returns an error if the content is not well-formed XML.
pub fn parse_pom_xml(content: &str, doc_uri: &Url) -> Result<MavenParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut properties = HashMap::new();

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut context_stack: Vec<ParseContext> = vec![ParseContext::Root];
    let mut current_dep: Option<DepAccum> = None;
    let mut current_tag: Option<String> = None;
    let mut current_prop_key: Option<String> = None;
    let mut root_tag: Option<String> = None;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    loop {
        let pos = reader.buffer_position();
        let event = reader.read_event().map_err(|e| DepsError::ParseError {
            file_type: "pom.xml".into(),
            source: deps_core::net_policy::parse_error_source(&e),
        })?;

        match event {
            Event::Start(ref e) => {
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                match (ctx, tag.as_str()) {
                    (ParseContext::Root, "dependencies") => {
                        context_stack.push(ParseContext::Dependencies);
                    }
                    (ParseContext::Root, "dependencyManagement") => {
                        context_stack.push(ParseContext::DependencyManagement);
                    }
                    (ParseContext::DependencyManagement, "dependencies") => {
                        context_stack.push(ParseContext::Dependencies);
                    }
                    (ParseContext::Root, "plugins") => {
                        // Matches both top-level <plugins> and <build><plugins>:
                        // <build> is silently ignored (falls through `_ => {}`), so
                        // when <plugins> is encountered inside <build> the stack is
                        // still at Root — this is intentional for MVP simplicity.
                        context_stack.push(ParseContext::Plugins);
                    }
                    (ParseContext::Dependencies, "dependency") => {
                        context_stack.push(ParseContext::Dependency);
                        current_dep = Some(DepAccum::default());
                        current_tag = None;
                    }
                    (ParseContext::Plugins, "plugin") => {
                        context_stack.push(ParseContext::Plugin);
                        current_dep = Some(DepAccum::default());
                        current_tag = None;
                    }
                    (ParseContext::Root, "properties") => {
                        context_stack.push(ParseContext::Properties);
                    }
                    (ParseContext::Properties, key) => {
                        current_prop_key = Some(key.to_string());
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, field) => {
                        current_tag = Some(field.to_string());
                        if field == "version"
                            && let Some(dep) = current_dep.as_mut()
                        {
                            dep.version_open_pos = Some(reader.buffer_position());
                        }
                    }
                    (ParseContext::Root, tag @ ("version" | "groupId" | "artifactId")) => {
                        root_tag = Some(tag.to_string());
                    }
                    _ => {}
                }
                let _ = pos;
            }
            Event::Text(ref e) => {
                let text_start = pos;
                let text = {
                    let s = e.trim().to_string();
                    quick_xml::escape::unescape(&s)
                        .map(|c| c.into_owned())
                        .unwrap_or(s)
                };
                let text_end = reader.buffer_position();

                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                if matches!(ctx, ParseContext::Dependency | ParseContext::Plugin) {
                    if let (Some(ref tag), Some(ref mut dep)) =
                        (current_tag.clone(), current_dep.as_mut())
                    {
                        match tag.as_str() {
                            "groupId" => {
                                dep.group_id = Some(text.clone());
                            }
                            "artifactId" => {
                                dep.artifact_id = Some(text.clone());
                                dep.artifact_id_start = text_start;
                                dep.artifact_id_end = text_end;
                            }
                            "version" => {
                                dep.version = Some(text.clone());
                                dep.version_start = text_start;
                                dep.version_end = text_end;
                            }
                            "scope" => {
                                dep.scope = Some(text.clone());
                            }
                            "systemPath" => {
                                dep.system_path = Some(text.clone());
                            }
                            _ => {}
                        }
                    }
                } else if ctx == ParseContext::Properties
                    && let Some(key) = current_prop_key.take()
                {
                    properties.insert(key, text);
                } else if ctx == ParseContext::Root
                    && let Some(tag) = root_tag.take()
                {
                    let prop_key = format!("project.{tag}");
                    properties.insert(prop_key, text);
                }
            }
            Event::Empty(ref e) => {
                // A self-closing `<version/>` never fires `Start`+`End` — quick-xml emits a
                // single `Empty` event for it instead — so without this arm it fell through
                // the wildcard `_ => {}` below and `version_open_pos`/`version_close_pos`
                // were never captured, reproducing #1161's original symptom verbatim for
                // this manifest shape (S1 critic/tester follow-up). There is no separate
                // open/close position for a self-closing tag, so both are set to the same
                // "right after this tag" offset, matching `<version></version>`'s and
                // `<version>   </version>`'s treatment as "an empty, present version" rather
                // than "no version tag at all".
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);
                if tag == "version"
                    && matches!(ctx, ParseContext::Dependency | ParseContext::Plugin)
                    && let Some(dep) = current_dep.as_mut()
                {
                    let p = reader.buffer_position();
                    dep.version_open_pos = Some(p);
                    dep.version_close_pos = Some(p);
                }
            }
            Event::End(ref e) => {
                let tag = e.local_name().as_ref().to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                match (ctx, tag.as_str()) {
                    (ParseContext::Dependency, "dependency") | (ParseContext::Plugin, "plugin") => {
                        context_stack.pop();
                        if let Some(dep) = current_dep.take()
                            && let Some(maven_dep) =
                                finalize_dep(dep, content, &line_table, &properties)
                            && budget.allow()
                        {
                            dependencies.push(maven_dep);
                        }
                        current_tag = None;
                    }
                    (ParseContext::Dependencies, "dependencies")
                    | (ParseContext::DependencyManagement, "dependencyManagement")
                    | (ParseContext::Plugins, "plugins")
                    | (ParseContext::Properties, "properties") => {
                        context_stack.pop();
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, "version") => {
                        if let Some(dep) = current_dep.as_mut()
                            && dep.version.is_none()
                        {
                            dep.version_close_pos = Some(pos);
                        }
                        current_tag = None;
                    }
                    (ParseContext::Dependency | ParseContext::Plugin, _) => {
                        current_tag = None;
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(MavenParseResult {
        dependencies,
        properties,
        uri: doc_uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

fn finalize_dep(
    dep: DepAccum,
    content: &str,
    line_table: &LineOffsetTable,
    properties: &HashMap<String, String>,
) -> Option<MavenDependency> {
    let group_id = dep.group_id?;
    let artifact_id = dep.artifact_id?;
    let name = format!("{group_id}:{artifact_id}");

    // name_range covers the artifactId text (primary hover/action target)
    let name_range = text_range(
        content,
        line_table,
        dep.artifact_id_start as usize,
        dep.artifact_id_end as usize,
        &artifact_id,
    );

    let version_range = if let Some(v) = dep.version.as_ref() {
        Some(text_range(
            content,
            line_table,
            dep.version_start as usize,
            dep.version_end as usize,
            v,
        ))
    } else if let (Some(open), Some(close)) = (dep.version_open_pos, dep.version_close_pos) {
        // `<version></version>` (or whitespace-only content quick-xml elides entirely under
        // `trim_text(true)`) — `text_range` bails out on empty text since it has nothing to
        // search for, so build the (possibly zero-width) span directly from the tag's own
        // boundaries instead (#1161). `version_req` below deliberately stays `None`: there is
        // still no literal text to report as a requirement, only a trackable position.
        let start = content.floor_char_boundary(open as usize);
        let end = content.floor_char_boundary((close as usize).max(open as usize));
        Some(byte_span_to_range(content, line_table, start, end))
    } else {
        None
    };

    let scope = dep
        .scope
        .as_deref()
        .unwrap_or("compile")
        .parse::<MavenScope>()
        .unwrap_or_default();

    // #1202 (critic Maven fix): `scope: system` is an explicit, per-dependency local-jar
    // binding via `<systemPath>` — unlike the unbound `<repositories>` gap (see the
    // `types.rs` TODO), this one is already a real per-dependency field this parser reads,
    // so classifying it needs no heuristic at all. Falls back to `Registry` only if a
    // malformed manifest declares `scope: system` with no `systemPath` at all (never crashes
    // on it, but there is nothing to classify against either).
    let source = if scope == MavenScope::System {
        dep.system_path
            .as_deref()
            .map(|path| deps_core::parser::DependencySource::Path {
                path: resolve_properties(path, properties),
            })
            .unwrap_or(deps_core::parser::DependencySource::Registry)
    } else {
        deps_core::parser::DependencySource::Registry
    };

    let version_req = dep.version.map(|v| resolve_properties(&v, properties));

    Some(MavenDependency {
        group_id,
        artifact_id,
        name: name.into(),
        name_range,
        version_req: version_req.map(Into::into),
        version_range,
        scope,
        source,
    })
}

/// Resolves `${property}` references in a string using the properties map.
///
/// Handles `${project.version}` and similar Maven property expressions.
/// Unresolved properties are left as-is.
// All indices come from `find("${")`/`find('}')`, both ASCII tokens, so every slice bound
// is always a char boundary.
#[allow(clippy::string_slice)]
fn resolve_properties(input: &str, properties: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    // Capped at 5 to bound rare nested property references.
    for _ in 0..5 {
        let Some(start) = result.find("${") else {
            break;
        };
        let Some(end) = result[start..].find('}') else {
            break;
        };
        let key = &result[start + 2..start + end];
        if let Some(value) = properties.get(key) {
            result = format!(
                "{}{}{}",
                &result[..start],
                value,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Finds the LSP range of `text` within content, searching near `hint_start`.
///
/// Limitation: uses `str::find` which returns the first occurrence at or after
/// `hint_start`. For pom.xml files with duplicate artifactId values across
/// different groupIds, the range may point to an earlier occurrence if the
/// byte hint is imprecise. This is acceptable for MVP single-version-tag use.
// `search_from` is floor_char_boundary-clamped just below before slicing `content`.
#[allow(clippy::string_slice)]
fn text_range(
    content: &str,
    line_table: &LineOffsetTable,
    hint_start: usize,
    _hint_end: usize,
    text: &str,
) -> Range {
    if text.is_empty() {
        return Range::default();
    }
    // `hint_start` is a quick-xml buffer offset; `floor_char_boundary` clamps it to both
    // `content.len()` (if past the end) and the nearest char boundary, since it is not
    // guaranteed to land on either (#680).
    let search_from = content.floor_char_boundary(hint_start);
    if let Some(rel) = content[search_from..].find(text) {
        let abs_start = search_from + rel;
        let abs_end = abs_start + text.len();
        byte_span_to_range(content, line_table, abs_start, abs_end)
    } else {
        Range::default()
    }
}

deps_core::impl_parse_result!(
    MavenParseResult,
    MavenDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/test/pom.xml")
    }

    #[test]
    fn test_parse_simple_pom() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
  </dependencies>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.group_id, "org.apache.commons");
        assert_eq!(dep.artifact_id, "commons-lang3");
        assert_eq!(dep.name, "org.apache.commons:commons-lang3");
        assert_eq!(dep.version_req, Some("3.14.0".into()));
        assert_matches!(dep.scope, MavenScope::Compile);
    }

    #[test]
    fn test_parse_multiple_deps() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "com.google.guava:guava");
        assert_eq!(result.dependencies[1].name, "junit:junit");
        assert_matches!(result.dependencies[1].scope, MavenScope::Test);
    }

    /// #1202 (critic Maven fix): a `scope: system` dependency's `<systemPath>` classifies as
    /// `Path` — never sent to repo1.maven.org/OSV, and its hover link is suppressed.
    #[test]
    fn test_system_scope_dependency_classifies_as_path() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(result.dependencies[0].scope, MavenScope::System);
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "/opt/lib/internal-jar-1.0.0.jar".into(),
            }
        );
    }

    /// A regular (non-`system`) dependency keeps resolving through the registry, even when
    /// other dependencies in the same manifest are `system`-scoped.
    #[test]
    fn test_non_system_scope_stays_registry_alongside_system_scope() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.acme</groupId>
      <artifactId>internal-jar</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
      <systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        let system = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "internal-jar")
            .unwrap();
        let guava = result
            .dependencies
            .iter()
            .find(|d| d.artifact_id == "guava")
            .unwrap();
        assert_eq!(
            system.source,
            deps_core::parser::DependencySource::Path {
                path: "/opt/lib/internal-jar-1.0.0.jar".into(),
            }
        );
        assert_eq!(guava.source, deps_core::parser::DependencySource::Registry);
    }

    #[test]
    fn test_parse_dependency_management() {
        let xml = r"<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>3.2.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_matches!(result.dependencies[0].scope, MavenScope::Import);
    }

    #[test]
    fn test_parse_plugin_deps() {
        let xml = r"<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.apache.maven.plugins:maven-compiler-plugin"
        );
    }

    #[test]
    fn test_parse_scopes() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>c</groupId>
      <artifactId>d</artifactId>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].scope, MavenScope::Runtime);
        assert_matches!(result.dependencies[1].scope, MavenScope::Provided);
    }

    #[test]
    fn test_parse_no_version() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    // #1161: an empty `<version></version>` tag must still resolve a trackable, zero-width
    // `version_range` for completion to anchor on, while `version_req` stays `None` — same as
    // `test_parse_no_version` above. code_actions/code_lenses/most diagnostics rules already
    // gate on `version_req` being `Some`, unaffected either way; hover/inlay-hints/the
    // remaining diagnostics rules (deprecation, vulnerability, in-use-yanked) matched or
    // anchored on `version_range` alone and needed their own `version_req`-aware guard —
    // see `deps_core::lsp_helpers::{hover, inlay_hints, diagnostics::version_anchor_range}`
    // (#1161 M1 critic follow-up).
    #[test]
    fn test_parse_empty_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>foo</artifactId>
      <version></version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("empty tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "empty tag content must be zero-width"
        );
        let line = xml.lines().nth(range.start.line as usize).unwrap();
        let expected_character = u32::try_from("      <version>".chars().count()).unwrap();
        assert_eq!(
            range.start.character, expected_character,
            "range must sit right after the opening tag on {line:?}, not at (0, 0)"
        );
    }

    // #1161 follow-up: whitespace-only content between the tags must behave identically to
    // fully empty, since quick-xml elides an all-whitespace text node under `trim_text(true)`
    // the same way it elides a genuinely empty one.
    #[test]
    fn test_parse_whitespace_only_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      <version>   </version>\n    </dependency>\n  </dependencies>\n</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("whitespace-only tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "whitespace-only tag content must be zero-width"
        );
        // Empirically verified (quick-xml 0.42.0): a whitespace-only text node between tags
        // is elided entirely under `trim_text(true)` — no `Event::Text` fires at all, so this
        // takes the exact same `version_open_pos`/`version_close_pos` fallback path as a fully
        // empty tag, landing right after `<version>` rather than at a bogus `(0, 0)` (the
        // position `text_range` would produce if an empty-string `Event::Text` ever did fire
        // here and got routed through the `Some(v)` branch instead).
        let expected_character = u32::try_from("      <version>".chars().count()).unwrap();
        assert_eq!(range.start.character, expected_character);
        assert_eq!(range.start.line, 5);
    }

    // S1 (critic/tester follow-up to #1161): a self-closing `<version/>` fires a single
    // quick-xml `Event::Empty`, never `Start`+`End` — without a dedicated arm for it, this
    // reproduces the original #1161 symptom (`version_range = None`) verbatim, since neither
    // `version_open_pos` nor `version_close_pos` would ever be set.
    #[test]
    fn test_parse_self_closing_version_tag_sets_zero_width_range_but_no_requirement() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      <version/>\n    </dependency>\n  </dependencies>\n</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        let range = dep
            .version_range
            .expect("self-closing tag must still yield a trackable range");
        assert_eq!(
            range.start, range.end,
            "self-closing tag content must be zero-width"
        );
        assert_eq!(range.start.line, 5);
    }

    #[test]
    fn test_parse_property_version_resolved() {
        let xml = r"<project>
  <properties>
    <slf4j.version>2.0.16</slf4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("2.0.16".into()));
    }

    #[test]
    fn test_parse_property_version_unresolved() {
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        // Unresolved property kept as-is
        assert_eq!(
            result.dependencies[0].version_req,
            Some("${slf4j.version}".into())
        );
    }

    #[test]
    fn test_parse_project_version_property() {
        let xml = r"<project>
  <groupId>org.example</groupId>
  <artifactId>my-app</artifactId>
  <version>2.5.0</version>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>my-lib</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("2.5.0".into()));
        assert_eq!(
            result.properties.get("project.version"),
            Some(&"2.5.0".to_string())
        );
        assert_eq!(
            result.properties.get("project.groupId"),
            Some(&"org.example".to_string())
        );
        assert_eq!(
            result.properties.get("project.artifactId"),
            Some(&"my-app".to_string())
        );
    }

    #[test]
    fn test_parse_empty_pom() {
        let xml = r#"<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_parse_invalid_xml() {
        // Stray < inside text is a well-formed XML error
        let xml = "<project><dependencies><dependency><groupId>a</groupId><artifactId>b < c</artifactId></dependency></dependencies></project>";
        let result = parse_pom_xml(xml, &test_uri());
        // quick-xml may or may not error on this; either empty deps or error is acceptable
        if let Ok(ref r) = result {
            // If parsed, groupId should not contain invalid XML content
            let _ = r.dependencies.len();
        }
        // Malformed attribute triggers a hard error
        let xml2 = r#"<project attr="unclosed></project>"#;
        let result2 = parse_pom_xml(xml2, &test_uri());
        assert_matches!(
            result2,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "pom.xml"
        );
    }

    /// #1243: `quick_xml`'s `IllFormed::MismatchedEndTag` embeds the raw tag-name text
    /// verbatim in its `Display` output, so a credential-shaped tag name must be redacted
    /// the same way `toml_span`/`yaml_rust2` parse errors already are (#1240/#1241).
    #[test]
    fn test_parse_mismatched_end_tag_error_redacts_credential() {
        let xml = "<root><https://svcacct:ghp_SUPERSECRETTOKEN123@pkg.internal.corp/x ></root>";

        let message = parse_pom_xml(xml, &test_uri()).unwrap_err().to_string();
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
        let expected = format!("failed to parse pom.xml: {raw_err}");

        let message = parse_pom_xml(xml, &test_uri()).unwrap_err().to_string();
        assert_eq!(message, expected);
    }

    #[test]
    fn test_parse_with_namespaces() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>"#;

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
    }

    #[test]
    fn test_position_tracking() {
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>my-lib</artifactId>\n      <version>1.0.0</version>\n    </dependency>\n  </dependencies>\n</project>";
        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // artifactId "my-lib" is on line 4 (0-indexed)
        assert_eq!(dep.name_range.start.line, 4);
    }

    #[test]
    fn test_text_range_hint_start_inside_multibyte_char_does_not_panic() {
        // #680: `hint_start` (a quick-xml buffer offset) is not guaranteed to land on a char
        // boundary. "café" is 5 bytes ('é' occupies bytes 3-4); hint_start = 4 lands inside it.
        let content = "café<version>1.0</version>";
        let line_table = LineOffsetTable::new(content);

        // hint_start = 0 is a safe boundary, used as the known-good baseline.
        let expected = text_range(content, &line_table, 0, 0, "1.0");
        // hint_start = 4 lands mid-character in 'é' and must clamp down rather than panic,
        // while still locating the same text.
        let actual = text_range(content, &line_table, 4, 4, "1.0");

        assert_eq!(actual.start.line, expected.start.line);
        assert_eq!(actual.start.character, expected.start.character);
        assert_eq!(actual.end.line, expected.end.line);
        assert_eq!(actual.end.character, expected.end.character);
        assert_ne!(
            actual.start.character, actual.end.character,
            "must locate real text"
        );
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
    </dependency>
  </dependencies>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<MavenParseResult>());
    }

    #[test]
    fn test_resolve_properties() {
        let mut props = HashMap::new();
        props.insert("ver".to_string(), "1.0".to_string());
        props.insert("suffix".to_string(), "RELEASE".to_string());

        assert_eq!(resolve_properties("${ver}", &props), "1.0");
        assert_eq!(resolve_properties("plain", &props), "plain");
        assert_eq!(resolve_properties("${missing}", &props), "${missing}");
        assert_eq!(
            resolve_properties("${ver}-${suffix}", &props),
            "1.0-RELEASE"
        );
    }

    #[test]
    fn test_parse_properties() {
        let xml = r"<project>
  <properties>
    <java.version>17</java.version>
    <spring.version>3.2.0</spring.version>
  </properties>
</project>";

        let result = parse_pom_xml(xml, &test_uri()).unwrap();
        assert_eq!(
            result.properties.get("java.version"),
            Some(&"17".to_string())
        );
        assert_eq!(
            result.properties.get("spring.version"),
            Some(&"3.2.0".to_string())
        );
    }
}
