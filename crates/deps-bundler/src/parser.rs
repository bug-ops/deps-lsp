//! Gemfile DSL parser with position tracking.
//!
//! Parses Gemfile files using regex-based line parsing to extract dependencies
//! with precise LSP positions.

use crate::error::Result;
use crate::types::{BundlerDependency, DependencyGroup, DependencySource};
use regex::Regex;
use std::any::Any;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::{Position, Range, Uri};

/// Result of parsing a Gemfile.
#[derive(Debug, Clone)]
pub struct BundlerParseResult {
    pub dependencies: Vec<BundlerDependency>,
    pub ruby_version: Option<String>,
    pub source_url: Option<String>,
    pub uri: Uri,
}

/// Pre-computed line start byte offsets for O(1) position lookups.
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

// Regex patterns for Gemfile parsing
static GEM_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*gem\s+['"]([^'"]+)['"]"#).expect("Invalid regex"));

static VERSION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]([~>=<!\d][^'"]*)['"]\s*(?:,|$)"#).expect("Invalid regex"));

static SOURCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*source\s+['"]([^'"]+)['"]\s*$"#).expect("Invalid regex"));

static RUBY_VERSION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*ruby\s+['"]([^'"]+)['"]\s*$"#).expect("Invalid regex"));

static GROUP_BLOCK_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*group\s+(.+?)\s+do\s*$").expect("Invalid regex"));

static GROUP_BLOCK_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*end\s*$").expect("Invalid regex"));

static GROUP_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"group:\s*(\[.+?\]|:\w+)").expect("Invalid regex"));

static GIT_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"git:\s*['"]([^'"]+)['"]\s*"#).expect("Invalid regex"));

static PATH_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"path:\s*['"]([^'"]+)['"]\s*"#).expect("Invalid regex"));

static GITHUB_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"github:\s*['"]([^'"]+)['"]\s*"#).expect("Invalid regex"));

static REQUIRE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"require:\s*(false|['"][^'"]*['"]\s*)"#).expect("Invalid regex"));

static PLATFORMS_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"platforms:\s*(\[.+?\]|:\w+)").expect("Invalid regex"));

/// Parses a Gemfile and extracts all dependencies with positions.
pub fn parse_gemfile(content: &str, doc_uri: &Uri) -> Result<BundlerParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut ruby_version = None;
    let mut source_url = None;
    let mut current_group: Option<DependencyGroup> = None;

    for (line_idx, line) in content.lines().enumerate() {
        let line_start = line_table.line_starts[line_idx];

        // Check for source declaration
        if let Some(caps) = SOURCE_PATTERN.captures(line) {
            if source_url.is_none() {
                source_url = Some(caps[1].to_string());
            }
            continue;
        }

        // Check for ruby version
        if let Some(caps) = RUBY_VERSION_PATTERN.captures(line) {
            ruby_version = Some(caps[1].to_string());
            continue;
        }

        // Check for group block start
        if let Some(caps) = GROUP_BLOCK_START.captures(line) {
            current_group = Some(parse_group_symbols(&caps[1]));
            continue;
        }

        // Check for group block end
        if GROUP_BLOCK_END.is_match(line) {
            current_group = None;
            continue;
        }

        // Check for gem declaration
        if let Some(caps) = GEM_PATTERN.captures(line) {
            let name = caps[1].to_string();

            // Find name position in line
            let name_match = caps.get(1).unwrap();
            let name_start = line_start + name_match.start();
            let name_end = line_start + name_match.end();

            let name_range = Range::new(
                line_table.byte_offset_to_position(content, name_start),
                line_table.byte_offset_to_position(content, name_end),
            );

            // Extract version if present
            let rest_of_line = &line[caps.get(0).unwrap().end()..];
            let (version_req, version_range) = extract_version(
                rest_of_line,
                content,
                &line_table,
                line_start + caps.get(0).unwrap().end(),
            );

            // Extract group from inline option or current block
            let group = extract_group(rest_of_line)
                .unwrap_or_else(|| current_group.clone().unwrap_or(DependencyGroup::Default));

            // Extract source
            let source = extract_source(rest_of_line);

            // Extract platforms
            let platforms = extract_platforms(rest_of_line);

            // Extract require option
            let require = extract_require(rest_of_line);

            dependencies.push(BundlerDependency {
                name,
                name_range,
                version_req,
                version_range,
                group,
                source,
                platforms,
                require,
            });
        }
    }

    Ok(BundlerParseResult {
        dependencies,
        ruby_version,
        source_url,
        uri: doc_uri.clone(),
    })
}

fn extract_version(
    line: &str,
    content: &str,
    line_table: &LineOffsetTable,
    base_offset: usize,
) -> (Option<String>, Option<Range>) {
    if let Some(caps) = VERSION_PATTERN.captures(line) {
        let version = caps[1].to_string();
        let version_match = caps.get(1).unwrap();
        let version_start = base_offset + version_match.start();
        let version_end = base_offset + version_match.end();

        let version_range = Range::new(
            line_table.byte_offset_to_position(content, version_start),
            line_table.byte_offset_to_position(content, version_end),
        );

        (Some(version), Some(version_range))
    } else {
        (None, None)
    }
}

fn extract_group(line: &str) -> Option<DependencyGroup> {
    GROUP_OPTION
        .captures(line)
        .map(|caps| parse_group_symbols(&caps[1]))
}

fn parse_group_symbols(text: &str) -> DependencyGroup {
    let text = text.trim();

    if text.contains(":development") {
        DependencyGroup::Development
    } else if text.contains(":test") {
        DependencyGroup::Test
    } else if text.contains(":production") {
        DependencyGroup::Production
    } else if text.starts_with(':') {
        DependencyGroup::Custom(text.trim_start_matches(':').to_string())
    } else {
        DependencyGroup::Default
    }
}

fn extract_source(line: &str) -> DependencySource {
    if let Some(caps) = GIT_OPTION.captures(line) {
        return DependencySource::Git {
            url: caps[1].to_string(),
            branch: None,
            tag: None,
            ref_: None,
        };
    }

    if let Some(caps) = GITHUB_OPTION.captures(line) {
        return DependencySource::Github {
            repo: caps[1].to_string(),
            branch: None,
        };
    }

    if let Some(caps) = PATH_OPTION.captures(line) {
        return DependencySource::Path {
            path: caps[1].to_string(),
        };
    }

    DependencySource::Registry
}

fn extract_platforms(line: &str) -> Vec<String> {
    if let Some(caps) = PLATFORMS_OPTION.captures(line) {
        let platforms_str = &caps[1];
        if platforms_str.starts_with('[') {
            // Parse array: [:mingw, :mswin]
            platforms_str
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|s| s.trim().trim_start_matches(':').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            // Single symbol: :ruby
            vec![platforms_str.trim_start_matches(':').to_string()]
        }
    } else {
        vec![]
    }
}

fn extract_require(line: &str) -> Option<String> {
    if let Some(caps) = REQUIRE_OPTION.captures(line) {
        let value = &caps[1];
        if value == "false" {
            Some("false".to_string())
        } else {
            Some(value.trim_matches(|c| c == '\'' || c == '"').to_string())
        }
    } else {
        None
    }
}

/// Parser for Gemfile manifests.
pub struct BundlerParser;

impl deps_core::ManifestParser for BundlerParser {
    type Dependency = BundlerDependency;
    type ParseResult = BundlerParseResult;

    fn parse(&self, content: &str, doc_uri: &Uri) -> deps_core::Result<Self::ParseResult> {
        parse_gemfile(content, doc_uri).map_err(Into::into)
    }
}

impl deps_core::ParseResultInfo for BundlerParseResult {
    type Dependency = BundlerDependency;

    fn dependencies(&self) -> &[Self::Dependency] {
        &self.dependencies
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
}

impl deps_core::ParseResult for BundlerParseResult {
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
        let path = "C:/test/Gemfile";
        #[cfg(not(windows))]
        let path = "/test/Gemfile";
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_simple_gem() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, None);
    }

    #[test]
    fn test_parse_gem_with_version() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    #[test]
    fn test_parse_gem_with_group() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rspec', group: :test";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].group,
            DependencyGroup::Test
        ));
    }

    #[test]
    fn test_parse_group_block() {
        let gemfile = r"source 'https://rubygems.org'

group :development, :test do
  gem 'rspec'
  gem 'pry'
end

gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        // rspec and pry should be in development group
        assert!(matches!(
            result.dependencies[0].group,
            DependencyGroup::Development
        ));
        assert!(matches!(
            result.dependencies[1].group,
            DependencyGroup::Development
        ));

        // rails should be default group
        assert!(matches!(
            result.dependencies[2].group,
            DependencyGroup::Default
        ));
    }

    #[test]
    fn test_parse_git_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', git: 'https://github.com/rails/rails.git'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Git { .. }
        ));
    }

    #[test]
    fn test_parse_github_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', github: 'rails/rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Github { .. }
        ));
    }

    #[test]
    fn test_parse_path_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'local_gem', path: '../local_gem'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Path { .. }
        ));
    }

    #[test]
    fn test_parse_ruby_version() {
        let gemfile = r"source 'https://rubygems.org'
ruby '3.2.2'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.ruby_version, Some("3.2.2".into()));
    }

    #[test]
    fn test_parse_source_url() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.source_url, Some("https://rubygems.org".into()));
    }

    #[test]
    fn test_position_tracking() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Name should be on line 1 (0-indexed)
        assert_eq!(dep.name_range.start.line, 1);
        // Version should also be on line 1
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 1);
    }

    #[test]
    fn test_parse_platforms() {
        let gemfile = r"source 'https://rubygems.org'
gem 'tzinfo-data', platforms: [:mingw, :mswin]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].platforms, vec!["mingw", "mswin"]);
    }

    #[test]
    fn test_parse_require_false() {
        let gemfile = r"source 'https://rubygems.org'
gem 'puma', require: false";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some("false".into()));
    }

    #[test]
    fn test_empty_gemfile() {
        let gemfile = "";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_gemfile_with_comments() {
        let gemfile = r"source 'https://rubygems.org'
# This is a comment
gem 'rails'
# gem 'disabled'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
    }

    #[test]
    fn test_line_offset_table() {
        let content = "abc\ndef";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }
}
