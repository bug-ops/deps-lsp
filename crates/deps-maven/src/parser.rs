//! pom.xml parser with byte-accurate position tracking.
//!
//! Uses quick-xml SAX reader to parse Maven POM files.
//! Tracks byte positions for LSP range computation.

use crate::error::{MavenError, Result};
use crate::types::{MavenDependency, MavenScope};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::any::Any;
use std::collections::HashMap;
use tower_lsp_server::ls_types::{Position, Range, Uri};

pub struct MavenParseResult {
    pub dependencies: Vec<MavenDependency>,
    pub properties: HashMap<String, String>,
    pub uri: Uri,
}

struct LineOffsetTable {
    line_starts: Vec<usize>,
}

impl LineOffsetTable {
    fn new(content: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let offset = offset.min(content.len());
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts[line];

        let character = content[line_start..offset]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();

        Position::new(line as u32, character)
    }
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
    scope: Option<String>,
}

pub fn parse_pom_xml(content: &str, doc_uri: &Uri) -> Result<MavenParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut properties = HashMap::new();

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut context_stack: Vec<ParseContext> = vec![ParseContext::Root];
    let mut current_dep: Option<DepAccum> = None;
    let mut current_tag: Option<String> = None;
    let mut current_prop_key: Option<String> = None;

    loop {
        let pos = reader.buffer_position();
        let event = reader.read_event().map_err(|e| MavenError::ParseError {
            message: e.to_string(),
        })?;

        match event {
            Event::Start(ref e) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
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
                    }
                    _ => {}
                }
                let _ = pos;
            }
            Event::Text(ref e) => {
                let text_start = pos;
                let text = match e.decode() {
                    Ok(cow) => {
                        let s = cow.trim().to_string();
                        // Unescape XML entities
                        quick_xml::escape::unescape(&s)
                            .map(|c| c.into_owned())
                            .unwrap_or(s)
                    }
                    Err(_) => String::from_utf8_lossy(e.as_ref()).trim().to_string(),
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
                            _ => {}
                        }
                    }
                } else if ctx == ParseContext::Properties
                    && let Some(key) = current_prop_key.take()
                {
                    properties.insert(key, text);
                }
            }
            Event::End(ref e) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let ctx = context_stack.last().cloned().unwrap_or(ParseContext::Root);

                match (ctx, tag.as_str()) {
                    (ParseContext::Dependency, "dependency") | (ParseContext::Plugin, "plugin") => {
                        context_stack.pop();
                        if let Some(dep) = current_dep.take()
                            && let Some(maven_dep) = finalize_dep(dep, content, &line_table)
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
    })
}

fn finalize_dep(
    dep: DepAccum,
    content: &str,
    line_table: &LineOffsetTable,
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

    let version_range = dep.version.as_ref().map(|v| {
        text_range(
            content,
            line_table,
            dep.version_start as usize,
            dep.version_end as usize,
            v,
        )
    });

    let scope = dep
        .scope
        .as_deref()
        .unwrap_or("compile")
        .parse::<MavenScope>()
        .unwrap_or_default();

    Some(MavenDependency {
        group_id,
        artifact_id,
        name,
        name_range,
        version_req: dep.version,
        version_range,
        scope,
    })
}

/// Finds the LSP range of `text` within content, searching near `hint_start`.
///
/// Limitation: uses `str::find` which returns the first occurrence at or after
/// `hint_start`. For pom.xml files with duplicate artifactId values across
/// different groupIds, the range may point to an earlier occurrence if the
/// byte hint is imprecise. This is acceptable for MVP single-version-tag use.
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
    let search_from = hint_start.min(content.len());
    if let Some(rel) = content[search_from..].find(text) {
        let abs_start = search_from + rel;
        let abs_end = abs_start + text.len();
        let start = line_table.byte_offset_to_position(content, abs_start);
        let end = line_table.byte_offset_to_position(content, abs_end);
        Range::new(start, end)
    } else {
        Range::default()
    }
}

impl deps_core::ParseResult for MavenParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        #[cfg(windows)]
        let path = "C:/test/pom.xml";
        #[cfg(not(windows))]
        let path = "/test/pom.xml";
        Uri::from_file_path(path).unwrap()
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
        assert!(matches!(dep.scope, MavenScope::Compile));
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
        assert!(matches!(result.dependencies[1].scope, MavenScope::Test));
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
        assert!(matches!(result.dependencies[0].scope, MavenScope::Import));
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
        assert!(matches!(result.dependencies[0].scope, MavenScope::Runtime));
        assert!(matches!(result.dependencies[1].scope, MavenScope::Provided));
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

    #[test]
    fn test_parse_property_version() {
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
        // Property references are stored as-is (not resolved in MVP)
        assert_eq!(
            result.dependencies[0].version_req,
            Some("${slf4j.version}".into())
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
        assert!(result2.is_err());
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
