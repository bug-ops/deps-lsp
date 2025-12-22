//! package.json parser with position tracking.
//!
//! Parses package.json files and extracts dependency information with precise
//! source positions for LSP operations.

use crate::types::{NpmDependency, NpmDependencySection};
use deps_core::{DepsError, Result};
use serde_json::Value;
use tower_lsp::lsp_types::{Position, Range};

/// Line offset table for O(log n) position lookups.
///
/// Stores byte offsets of each line start, enabling fast binary search
/// for line-to-offset conversion. This avoids O(n) scans for each position lookup.
struct LineOffsetTable {
    offsets: Vec<usize>,
}

impl LineOffsetTable {
    /// Builds a line offset table from content in O(n) time.
    fn new(content: &str) -> Self {
        let mut offsets = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                offsets.push(i + 1);
            }
        }
        Self { offsets }
    }

    /// Converts byte offset to line/character position in O(log n) time.
    fn position_from_offset(&self, offset: usize) -> Position {
        let line = match self.offsets.binary_search(&offset) {
            Ok(line) => line,
            Err(line) => line.saturating_sub(1),
        };
        let character = (offset - self.offsets[line]) as u32;
        Position::new(line as u32, character)
    }
}

/// Result of parsing a package.json file.
///
/// Contains all dependencies found in the file with their positions.
#[derive(Debug)]
pub struct NpmParseResult {
    pub dependencies: Vec<NpmDependency>,
}

/// Parses a package.json file and extracts all dependencies with positions.
///
/// Handles all dependency sections:
/// - `dependencies`
/// - `devDependencies`
/// - `peerDependencies`
/// - `optionalDependencies`
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - File is not a valid package.json structure
///
/// # Examples
///
/// ```
/// use deps_npm::parser::parse_package_json;
///
/// let json = r#"{
///   "dependencies": {
///     "express": "^4.18.2"
///   }
/// }"#;
///
/// let result = parse_package_json(json).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "express");
/// ```
pub fn parse_package_json(content: &str) -> Result<NpmParseResult> {
    let root: Value = serde_json::from_str(content).map_err(|e| DepsError::ParseError {
        file_type: "package.json".into(),
        source: Box::new(e),
    })?;

    // Build line offset table once for O(log n) position lookups
    let line_table = LineOffsetTable::new(content);

    let mut dependencies = Vec::new();

    // Parse each dependency section
    if let Some(deps) = root.get("dependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::Dependencies,
            &line_table,
        )?);
    }

    if let Some(deps) = root.get("devDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::DevDependencies,
            &line_table,
        )?);
    }

    if let Some(deps) = root.get("peerDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::PeerDependencies,
            &line_table,
        )?);
    }

    if let Some(deps) = root.get("optionalDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::OptionalDependencies,
            &line_table,
        )?);
    }

    Ok(NpmParseResult { dependencies })
}

/// Parses a single dependency section and extracts positions.
fn parse_dependency_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: NpmDependencySection,
    line_table: &LineOffsetTable,
) -> Result<Vec<NpmDependency>> {
    let mut result = Vec::new();

    for (name, value) in deps {
        let version_req = value.as_str().map(String::from);

        // Calculate positions for name and version
        let (name_range, version_range) =
            find_dependency_positions(content, name, &version_req, line_table);

        result.push(NpmDependency {
            name: name.clone(),
            name_range,
            version_req,
            version_range,
            section,
        });
    }

    Ok(result)
}

/// Finds the position of a dependency name and version in the source text.
///
/// Searches for the dependency as a JSON key-value pair to avoid false matches
/// when the name appears elsewhere in the file (e.g., in scripts).
fn find_dependency_positions(
    content: &str,
    name: &str,
    version_req: &Option<String>,
    line_table: &LineOffsetTable,
) -> (Range, Option<Range>) {
    let mut name_range = Range::default();
    let mut version_range = None;

    let name_pattern = format!("\"{}\"", name);

    // Find all occurrences of the name pattern and check which one is a dependency key
    let mut search_start = 0;
    while let Some(rel_idx) = content[search_start..].find(&name_pattern) {
        let name_start_idx = search_start + rel_idx;
        let after_name = &content[name_start_idx + name_pattern.len()..];

        // Check if this is a JSON key (followed by optional whitespace and colon)
        let trimmed = after_name.trim_start();
        if !trimmed.starts_with(':') {
            // Not a key, continue searching
            search_start = name_start_idx + name_pattern.len();
            continue;
        }

        // Found a valid key, calculate position
        let name_start = line_table.position_from_offset(name_start_idx + 1);
        let name_end = line_table.position_from_offset(name_start_idx + 1 + name.len());
        name_range = Range::new(name_start, name_end);

        // Find version position (after the colon)
        if let Some(version) = version_req {
            let version_search = format!("\"{}\"", version);
            // Search for version only in the portion after the colon
            let colon_offset =
                name_start_idx + name_pattern.len() + (after_name.len() - trimmed.len());
            let after_colon = &content[colon_offset..];

            // Limit search to the next 100 chars to stay within this key-value pair
            let search_limit = after_colon.len().min(100 + version.len());
            let search_area = &after_colon[..search_limit];

            if let Some(ver_rel_idx) = search_area.find(&version_search) {
                let version_start_idx = colon_offset + ver_rel_idx + 1;
                let version_start = line_table.position_from_offset(version_start_idx);
                let version_end =
                    line_table.position_from_offset(version_start_idx + version.len());
                version_range = Some(Range::new(version_start, version_end));
            }
        }

        // Found valid dependency, stop searching
        break;
    }

    (name_range, version_range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_dependencies() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert!(matches!(
            express.section,
            NpmDependencySection::Dependencies
        ));

        let lodash = &result.dependencies[1];
        assert_eq!(lodash.name, "lodash");
        assert_eq!(lodash.version_req, Some("^4.17.21".into()));
    }

    #[test]
    fn test_parse_dev_dependencies() {
        let json = r#"{
  "devDependencies": {
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        assert!(
            result
                .dependencies
                .iter()
                .all(|d| matches!(d.section, NpmDependencySection::DevDependencies))
        );
    }

    #[test]
    fn test_parse_peer_dependencies() {
        let json = r#"{
  "peerDependencies": {
    "react": "^18.0.0"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].section,
            NpmDependencySection::PeerDependencies
        ));
    }

    #[test]
    fn test_parse_optional_dependencies() {
        let json = r#"{
  "optionalDependencies": {
    "fsevents": "^2.3.2"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].section,
            NpmDependencySection::OptionalDependencies
        ));
    }

    #[test]
    fn test_parse_multiple_sections() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let deps_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, NpmDependencySection::Dependencies))
            .count();
        let dev_deps_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, NpmDependencySection::DevDependencies))
            .count();

        assert_eq!(deps_count, 1);
        assert_eq!(dev_deps_count, 1);
    }

    #[test]
    fn test_parse_empty_dependencies() {
        let json = r#"{
  "dependencies": {}
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_no_dependencies() {
        let json = r#"{
  "name": "my-package",
  "version": "1.0.0"
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = "{ invalid json }";
        let result = parse_package_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_position_calculation() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        let express = &result.dependencies[0];

        // Name should be on line 2 (0-indexed: line 2)
        assert_eq!(express.name_range.start.line, 2);

        // Version should also be on line 2
        if let Some(version_range) = express.version_range {
            assert_eq!(version_range.start.line, 2);
        }
    }

    #[test]
    fn test_line_offset_table() {
        let content = "line0\nline1\nline2";
        let table = LineOffsetTable::new(content);

        let pos0 = table.position_from_offset(0);
        assert_eq!(pos0.line, 0);
        assert_eq!(pos0.character, 0);

        let pos6 = table.position_from_offset(6);
        assert_eq!(pos6.line, 1);
        assert_eq!(pos6.character, 0);

        let pos12 = table.position_from_offset(12);
        assert_eq!(pos12.line, 2);
        assert_eq!(pos12.character, 0);
    }

    #[test]
    fn test_dependency_with_git_url() {
        let json = r#"{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "my-lib");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("git+https://github.com/user/repo.git".into())
        );
    }

    #[test]
    fn test_dependency_with_file_path() {
        let json = r#"{
  "dependencies": {
    "local-pkg": "file:../local-package"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "local-pkg");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("file:../local-package".into())
        );
    }

    #[test]
    fn test_scoped_package() {
        let json = r#"{
  "devDependencies": {
    "@vitest/coverage-v8": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "@vitest/coverage-v8");
        assert_eq!(result.dependencies[0].version_req, Some("^3.1.4".into()));
        assert!(result.dependencies[0].version_range.is_some());
    }

    #[test]
    fn test_package_name_in_scripts_not_confused() {
        // Regression test: "vitest" appears in scripts as a value,
        // but should only be found as a dependency key
        let json = r#"{
  "scripts": {
    "test": "vitest",
    "coverage": "vitest run --coverage"
  },
  "devDependencies": {
    "vitest": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let vitest = &result.dependencies[0];
        assert_eq!(vitest.name, "vitest");
        assert_eq!(vitest.version_req, Some("^3.1.4".into()));
        // Verify version_range is found (this was the bug)
        assert!(
            vitest.version_range.is_some(),
            "vitest should have a version_range"
        );
        // Verify position is in devDependencies, not scripts
        // devDependencies starts at line 6
        assert!(
            vitest.name_range.start.line >= 5,
            "vitest should be found in devDependencies, not scripts"
        );
    }

    #[test]
    fn test_multiple_packages_same_version() {
        // Both packages have the same version - each should have distinct positions
        let json = r#"{
  "devDependencies": {
    "@vitest/coverage-v8": "^3.1.4",
    "vitest": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        // Find both dependencies
        let coverage = result
            .dependencies
            .iter()
            .find(|d| d.name == "@vitest/coverage-v8")
            .expect("@vitest/coverage-v8 should be parsed");
        let vitest = result
            .dependencies
            .iter()
            .find(|d| d.name == "vitest")
            .expect("vitest should be parsed");

        // Both should have version ranges
        assert!(
            coverage.version_range.is_some(),
            "@vitest/coverage-v8 should have version_range"
        );
        assert!(
            vitest.version_range.is_some(),
            "vitest should have version_range"
        );

        // Positions should be different
        let coverage_pos = coverage.version_range.unwrap();
        let vitest_pos = vitest.version_range.unwrap();
        assert_ne!(
            coverage_pos.start.line, vitest_pos.start.line,
            "version positions should be on different lines"
        );
    }
}
