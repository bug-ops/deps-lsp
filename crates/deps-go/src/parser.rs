//! go.mod parser with position tracking.
//!
//! Parses go.mod files using regex patterns and line-by-line parsing.
//! Critical for LSP features like hover, completion, and inlay hints.
//!
//! # Key Features
//!
//! - Position-preserving parsing with byte-to-LSP conversion
//! - Handles go.mod directives: module, go, require, replace, exclude
//! - Supports multi-line blocks and inline/block comments
//! - Extracts indirect dependency markers (// indirect)
//! - Note: retract directive is defined in types but not yet parsed

use crate::error::Result;
use crate::types::{GoDependency, GoDirective};
use once_cell::sync::Lazy;
use regex::Regex;
use tower_lsp_server::ls_types::{Position, Range, Uri};

/// Result of parsing a go.mod file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GoParseResult {
    /// All dependencies found in the file
    pub dependencies: Vec<GoDependency>,
    /// Module path declared in `module` directive
    pub module_path: Option<String>,
    /// Minimum Go version from `go` directive
    pub go_version: Option<String>,
    /// Document URI
    pub uri: Uri,
}

/// Pre-computed line start byte offsets for O(log n) position lookups.
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

    /// Converts byte offset to LSP Position (line, UTF-16 character).
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

/// Parses a go.mod file and extracts all dependencies with positions.
pub fn parse_go_mod(content: &str, doc_uri: &Uri) -> Result<GoParseResult> {
    tracing::debug!(uri = ?doc_uri, "Parsing go.mod file");

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut module_path = None;
    let mut go_version = None;

    static MODULE_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*module\s+(\S+)").unwrap());
    static GO_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*go\s+(\S+)").unwrap());
    static REQUIRE_SINGLE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*require\s+(\S+)\s+(\S+)").unwrap());
    static REQUIRE_BLOCK_START: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*require\s*\(").unwrap());
    static REPLACE_PATTERN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*replace\s+(\S+)\s+(?:(\S+)\s+)?=>\s+(\S+)\s+(\S+)").unwrap());
    static EXCLUDE_PATTERN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*exclude\s+(\S+)\s+(\S+)").unwrap());

    let mut in_require_block = false;
    let mut line_offset = 0;

    for line in content.lines() {
        let line_without_comment = strip_line_comment(line);
        let line_trimmed = line_without_comment.trim();

        if let Some(caps) = MODULE_PATTERN.captures(line_trimmed) {
            module_path = Some(caps[1].to_string());
        }

        if let Some(caps) = GO_PATTERN.captures(line_trimmed) {
            go_version = Some(caps[1].to_string());
        }

        if REQUIRE_BLOCK_START.is_match(line_trimmed) {
            in_require_block = true;
            line_offset += line.len() + 1;
            continue;
        }

        if in_require_block && line_trimmed.contains(')') {
            in_require_block = false;
            line_offset += line.len() + 1;
            continue;
        }

        if (in_require_block || REQUIRE_SINGLE.is_match(line_trimmed))
            && let Some(dep) = parse_require_line(line, line_offset, content, &line_table)
        {
            dependencies.push(dep);
        }

        if let Some(caps) = REPLACE_PATTERN.captures(line_trimmed) {
            let module = &caps[1];
            let version = caps.get(2).map(|m| m.as_str());
            if let Some(dep) =
                parse_replace_line(line, line_offset, module, version, content, &line_table)
            {
                dependencies.push(dep);
            }
        }

        if let Some(caps) = EXCLUDE_PATTERN.captures(line_trimmed) {
            let module = &caps[1];
            let version = &caps[2];
            if let Some(dep) =
                parse_exclude_line(line, line_offset, module, version, content, &line_table)
            {
                dependencies.push(dep);
            }
        }

        let line_end = line_offset + line.len();
        let next_line_start = if line_end < content.len() && content.as_bytes()[line_end] == b'\n' {
            line_end + 1
        } else {
            line_end
        };
        line_offset = next_line_start;
    }

    tracing::debug!(
        dependencies = %dependencies.len(),
        module = ?module_path,
        go_version = ?go_version,
        "Parsed go.mod successfully"
    );

    Ok(GoParseResult {
        dependencies,
        module_path,
        go_version,
        uri: doc_uri.clone(),
    })
}

/// Strips line comments from a line (everything after //).
///
/// Handles URL schemes (e.g., https://) to avoid stripping URL paths.
fn strip_line_comment(line: &str) -> &str {
    let mut in_url = false;
    for (i, c) in line.char_indices() {
        if c == ':' && line[i..].starts_with("://") {
            in_url = true;
            continue;
        }
        if in_url && c.is_whitespace() {
            in_url = false;
        }
        if !in_url && line[i..].starts_with("//") {
            return &line[..i];
        }
    }
    line
}

/// Parses a single require line.
fn parse_require_line(
    line: &str,
    line_start_offset: usize,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<GoDependency> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let (module_path, version) = if parts[0] == "require" {
        if parts.len() < 3 {
            return None;
        }
        (parts[1], parts[2])
    } else {
        if parts.len() < 2 {
            return None;
        }
        (parts[0], parts[1])
    };

    let indirect = line.contains("// indirect");

    let module_start = line.find(module_path)?;
    let module_offset = line_start_offset + module_start;
    let module_path_range = Range::new(
        line_table.byte_offset_to_position(content, module_offset),
        line_table.byte_offset_to_position(content, module_offset + module_path.len()),
    );

    let version_start = line.find(version)?;
    let version_offset = line_start_offset + version_start;
    let version_range = Range::new(
        line_table.byte_offset_to_position(content, version_offset),
        line_table.byte_offset_to_position(content, version_offset + version.len()),
    );

    Some(GoDependency {
        module_path: module_path.to_string(),
        module_path_range,
        version: Some(version.to_string()),
        version_range: Some(version_range),
        directive: GoDirective::Require,
        indirect,
    })
}

/// Parses a replace directive line.
fn parse_replace_line(
    line: &str,
    line_start_offset: usize,
    module: &str,
    version: Option<&str>,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<GoDependency> {
    let module_start = line.find(module)?;
    let module_offset = line_start_offset + module_start;
    let module_path_range = Range::new(
        line_table.byte_offset_to_position(content, module_offset),
        line_table.byte_offset_to_position(content, module_offset + module.len()),
    );

    let (version_str, version_range) = if let Some(ver) = version {
        let version_start = line.find(ver)?;
        let version_offset = line_start_offset + version_start;
        let range = Range::new(
            line_table.byte_offset_to_position(content, version_offset),
            line_table.byte_offset_to_position(content, version_offset + ver.len()),
        );
        (Some(ver.to_string()), Some(range))
    } else {
        (None, None)
    };

    Some(GoDependency {
        module_path: module.to_string(),
        module_path_range,
        version: version_str,
        version_range,
        directive: GoDirective::Replace,
        indirect: false,
    })
}

/// Parses an exclude directive line.
fn parse_exclude_line(
    line: &str,
    line_start_offset: usize,
    module: &str,
    version: &str,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<GoDependency> {
    let module_start = line.find(module)?;
    let module_offset = line_start_offset + module_start;
    let module_path_range = Range::new(
        line_table.byte_offset_to_position(content, module_offset),
        line_table.byte_offset_to_position(content, module_offset + module.len()),
    );

    let version_start = line.find(version)?;
    let version_offset = line_start_offset + version_start;
    let version_range = Range::new(
        line_table.byte_offset_to_position(content, version_offset),
        line_table.byte_offset_to_position(content, version_offset + version.len()),
    );

    Some(GoDependency {
        module_path: module.to_string(),
        module_path_range,
        version: Some(version.to_string()),
        version_range: Some(version_range),
        directive: GoDirective::Exclude,
        indirect: false,
    })
}

impl deps_core::parser::ParseResultInfo for GoParseResult {
    type Dependency = GoDependency;

    fn dependencies(&self) -> &[Self::Dependency] {
        &self.dependencies
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }
}

deps_core::impl_parse_result!(
    GoParseResult,
    GoDependency {
        dependencies: dependencies,
        uri: uri,
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    fn test_uri() -> Uri {
        use std::str::FromStr;
        Uri::from_str("file:///test/go.mod").unwrap()
    }

    #[test]
    fn test_parse_single_require() {
        let content = r#"module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"#;
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].module_path,
            "github.com/gin-gonic/gin"
        );
        assert_eq!(result.dependencies[0].version, Some("v1.9.1".to_string()));
        assert!(!result.dependencies[0].indirect);
    }

    #[test]
    fn test_parse_module_directive() {
        let content = "module example.com/myapp\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.module_path, Some("example.com/myapp".to_string()));
    }

    #[test]
    fn test_parse_go_version() {
        let content = "go 1.21\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.go_version, Some("1.21".to_string()));
    }

    #[test]
    fn test_parse_require_block() {
        let content = r#"require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)
"#;
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert!(!result.dependencies[0].indirect);
        assert!(result.dependencies[1].indirect);
    }

    #[test]
    fn test_parse_replace_directive() {
        let content = "replace github.com/old/module => github.com/new/module v1.2.3\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].directive, GoDirective::Replace);
        assert_eq!(result.dependencies[0].module_path, "github.com/old/module");
    }

    #[test]
    fn test_parse_exclude_directive() {
        let content = "exclude github.com/bad/module v0.1.0\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].directive, GoDirective::Exclude);
        assert_eq!(result.dependencies[0].module_path, "github.com/bad/module");
        assert_eq!(result.dependencies[0].version, Some("v0.1.0".to_string()));
    }

    #[test]
    fn test_parse_pseudo_version() {
        let content = "require golang.org/x/crypto v0.0.0-20191109021931-daa7c04131f5\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].version,
            Some("v0.0.0-20191109021931-daa7c04131f5".to_string())
        );
    }

    #[test]
    fn test_position_tracking() {
        let content = "require github.com/gin-gonic/gin v1.9.1";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.module_path_range.start.line, 0);
        assert!(dep.version_range.is_some());
    }

    #[test]
    fn test_empty_file() {
        let content = "";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
        assert_eq!(result.module_path, None);
        assert_eq!(result.go_version, None);
    }

    #[test]
    fn test_comments_stripped() {
        let content =
            "// This is a comment\nrequire github.com/pkg/errors v0.9.1 // inline comment\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].module_path, "github.com/pkg/errors");
    }

    #[test]
    fn test_complex_go_mod() {
        let content = r#"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)

replace github.com/old/module => github.com/new/module v1.2.3

exclude github.com/bad/module v0.1.0
"#;
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);
        assert_eq!(result.module_path, Some("example.com/myapp".to_string()));
        assert_eq!(result.go_version, Some("1.21".to_string()));

        let require_deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.directive == GoDirective::Require)
            .collect();
        assert_eq!(require_deps.len(), 2);

        let replace_deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.directive == GoDirective::Replace)
            .collect();
        assert_eq!(replace_deps.len(), 1);

        let exclude_deps: Vec<_> = result
            .dependencies
            .iter()
            .filter(|d| d.directive == GoDirective::Exclude)
            .collect();
        assert_eq!(exclude_deps.len(), 1);
    }

    #[test]
    fn test_position_tracking_no_trailing_newline() {
        let content = "require github.com/gin-gonic/gin v1.9.1";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.module_path_range.start.character, 8);
        assert_eq!(dep.module_path_range.end.character, 32);
        assert_eq!(dep.version_range.as_ref().unwrap().start.character, 33);
        assert_eq!(dep.version_range.as_ref().unwrap().end.character, 39);
    }

    #[test]
    fn test_parse_complex_go_mod_snapshot() {
        let content = r#"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)

replace github.com/old/module => github.com/new/module v1.2.3

exclude github.com/bad/module v0.1.0
"#;
        let result = parse_go_mod(content, &test_uri()).unwrap();
        insta::assert_debug_snapshot!(result);
    }

    #[test]
    fn test_strip_line_comment_with_url() {
        let line = "replace github.com/old => https://github.com/new // comment";
        let stripped = strip_line_comment(line);
        assert_eq!(
            stripped,
            "replace github.com/old => https://github.com/new "
        );
    }
}
