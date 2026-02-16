//! pubspec.yaml parser with position tracking.

use crate::error::Result;
use crate::types::{DartDependency, DependencySection, DependencySource};
use std::any::Any;
use tower_lsp_server::ls_types::{Position, Range, Uri};
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Debug, Clone)]
pub struct DartParseResult {
    pub dependencies: Vec<DartDependency>,
    pub sdk_constraint: Option<String>,
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

pub fn parse_pubspec_yaml(content: &str, doc_uri: &Uri) -> Result<DartParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut sdk_constraint = None;

    let docs =
        YamlLoader::load_from_str(content).map_err(|e| crate::error::DartError::ParseError {
            message: e.to_string(),
        })?;

    let doc = match docs.first() {
        Some(d) => d,
        None => {
            return Ok(DartParseResult {
                dependencies,
                sdk_constraint,
                uri: doc_uri.clone(),
            });
        }
    };

    // Extract SDK constraint
    if let Some(env) = doc["environment"]["sdk"].as_str() {
        sdk_constraint = Some(env.to_string());
    }

    // Parse each dependency section
    let sections = [
        ("dependencies", DependencySection::Dependencies),
        ("dev_dependencies", DependencySection::DevDependencies),
        (
            "dependency_overrides",
            DependencySection::DependencyOverrides,
        ),
    ];

    for (key, section) in &sections {
        if let Yaml::Hash(map) = &doc[*key] {
            for (name_yaml, value) in map {
                if let Some(name) = name_yaml.as_str() {
                    let (name_range, version_req, version_range, source) =
                        parse_dependency_entry(name, value, content, &line_table);

                    dependencies.push(DartDependency {
                        name: name.to_string(),
                        name_range,
                        version_req,
                        version_range,
                        section: section.clone(),
                        source,
                    });
                }
            }
        }
    }

    Ok(DartParseResult {
        dependencies,
        sdk_constraint,
        uri: doc_uri.clone(),
    })
}

fn parse_dependency_entry(
    name: &str,
    value: &Yaml,
    content: &str,
    line_table: &LineOffsetTable,
) -> (Range, Option<String>, Option<Range>, DependencySource) {
    let name_range = find_key_range(name, content, line_table);

    match value {
        // Simple version string: "package: ^1.0.0"
        Yaml::String(ver) => {
            let version_range = find_value_range_after_key(name, ver, content, line_table);
            (
                name_range,
                Some(ver.clone()),
                version_range,
                DependencySource::Hosted,
            )
        }
        // Map form
        Yaml::Hash(map) => {
            let mut version_req = None;
            let mut version_range = None;
            let mut source = DependencySource::Hosted;

            if let Some(Yaml::String(ver)) = map.get(&Yaml::String("version".into())) {
                version_req = Some(ver.clone());
                version_range = find_value_range_after_key("version", ver, content, line_table);
            }

            if let Some(git_val) = map.get(&Yaml::String("git".into())) {
                source = parse_git_source(git_val);
            } else if let Some(Yaml::String(path)) = map.get(&Yaml::String("path".into())) {
                source = DependencySource::Path { path: path.clone() };
            } else if let Some(Yaml::String(sdk)) = map.get(&Yaml::String("sdk".into())) {
                source = DependencySource::Sdk { sdk: sdk.clone() };
            }

            (name_range, version_req, version_range, source)
        }
        _ => (name_range, None, None, DependencySource::Hosted),
    }
}

fn parse_git_source(git_val: &Yaml) -> DependencySource {
    match git_val {
        Yaml::String(url) => DependencySource::Git {
            url: url.clone(),
            ref_: None,
            path: None,
        },
        Yaml::Hash(map) => {
            let url = map
                .get(&Yaml::String("url".into()))
                .and_then(Yaml::as_str)
                .unwrap_or("")
                .to_string();
            let ref_ = map
                .get(&Yaml::String("ref".into()))
                .and_then(Yaml::as_str)
                .map(String::from);
            let path = map
                .get(&Yaml::String("path".into()))
                .and_then(Yaml::as_str)
                .map(String::from);
            DependencySource::Git { url, ref_, path }
        }
        _ => DependencySource::Hosted,
    }
}

fn find_key_range(key: &str, content: &str, line_table: &LineOffsetTable) -> Range {
    // Search for "key:" pattern in YAML content
    for (i, _) in content.match_indices(key) {
        let after = i + key.len();
        if after < content.len() {
            let next_char = content.as_bytes()[after];
            if next_char == b':' {
                // Verify this is at the start of a line (after optional whitespace)
                let line_start = content[..i].rfind('\n').map_or(0, |p| p + 1);
                let prefix = &content[line_start..i];
                if prefix.chars().all(|c| c == ' ') {
                    let start = line_table.byte_offset_to_position(content, i);
                    let end = line_table.byte_offset_to_position(content, after);
                    return Range::new(start, end);
                }
            }
        }
    }
    Range::default()
}

fn find_value_range_after_key(
    key: &str,
    value: &str,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<Range> {
    // Find "key: value" or "key: 'value'" patterns
    let pattern = format!("{key}:");
    for (i, _) in content.match_indices(&pattern) {
        let after_colon = i + pattern.len();
        let rest = &content[after_colon..];
        if let Some(val_offset) = rest.find(value) {
            let abs_start = after_colon + val_offset;
            let abs_end = abs_start + value.len();
            let start = line_table.byte_offset_to_position(content, abs_start);
            let end = line_table.byte_offset_to_position(content, abs_end);
            return Some(Range::new(start, end));
        }
    }
    None
}

impl deps_core::ParseResult for DartParseResult {
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
        let path = "C:/test/pubspec.yaml";
        #[cfg(not(windows))]
        let path = "/test/pubspec.yaml";
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_simple_deps() {
        let yaml = r"
name: my_app
dependencies:
  provider: ^6.0.0
  http: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "provider");
        assert_eq!(result.dependencies[0].version_req, Some("^6.0.0".into()));
        assert_eq!(result.dependencies[1].name, "http");
    }

    #[test]
    fn test_parse_dev_dependencies() {
        let yaml = r"
name: my_app
dev_dependencies:
  flutter_test:
    sdk: flutter
  build_runner: ^2.4.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert!(matches!(
            result.dependencies[0].section,
            DependencySection::DevDependencies
        ));
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Sdk { .. }
        ));
    }

    #[test]
    fn test_parse_git_dependency() {
        let yaml = r"
name: my_app
dependencies:
  my_pkg:
    git:
      url: https://github.com/user/repo.git
      ref: main
      path: packages/my_pkg
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { url, ref_, path } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(ref_, &Some("main".into()));
                assert_eq!(path, &Some("packages/my_pkg".into()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_path_dependency() {
        let yaml = r"
name: my_app
dependencies:
  local_pkg:
    path: ../local_pkg
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Path { .. }
        ));
    }

    #[test]
    fn test_parse_sdk_constraint() {
        let yaml = r"
name: my_app
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  http: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.sdk_constraint, Some(">=3.0.0 <4.0.0".into()));
    }

    #[test]
    fn test_parse_empty_pubspec() {
        let yaml = "name: empty_app\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
        assert!(result.sdk_constraint.is_none());
    }

    #[test]
    fn test_parse_dependency_overrides() {
        let yaml = r"
name: my_app
dependency_overrides:
  http: ^2.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].section,
            DependencySection::DependencyOverrides
        ));
    }

    #[test]
    fn test_parse_hosted_with_version() {
        let yaml = r"
name: my_app
dependencies:
  custom_pkg:
    hosted: https://custom-registry.example.com
    version: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("^1.0.0".into()));
    }

    #[test]
    fn test_parse_git_shorthand() {
        let yaml = r"
name: my_app
dependencies:
  my_pkg:
    git: https://github.com/user/repo.git
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Git { url, ref_, path } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert!(ref_.is_none());
                assert!(path.is_none());
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_position_tracking() {
        let yaml = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // Name should be on line 2 (0-indexed)
        assert_eq!(dep.name_range.start.line, 2);
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;
        let yaml = "name: app\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<DartParseResult>());
    }

    #[test]
    fn test_line_offset_table() {
        let content = "abc\ndef";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }

    #[test]
    fn test_invalid_yaml() {
        let yaml = "{{invalid yaml";
        let result = parse_pubspec_yaml(yaml, &test_uri());
        assert!(result.is_err());
    }
}
