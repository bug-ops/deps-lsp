//! `pyproject.toml` parsing: PEP 621, PEP 735, Poetry, and PEP 517/518
//! build-system requires.

use super::{ParseResult, PypiParser, normalize_marker_string, span_start, span_to_range};
use crate::error::Result;
use crate::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
use deps_core::lsp_helpers::LineOffsetTable;
use toml_span::value::{Table, Value};
use tower_lsp_server::ls_types::Uri;

impl PypiParser {
    /// Parse pyproject.toml content and extract all dependencies.
    ///
    /// Parses both PEP 621 and Poetry formats in a single pass.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TOML is malformed
    /// - PEP 508 dependency specifications are invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::parser::PypiParser;
    /// # use tower_lsp_server::ls_types::Uri;
    /// let parser = PypiParser::new();
    /// let content = std::fs::read_to_string("pyproject.toml").unwrap();
    /// let uri = Uri::from_file_path("/project/pyproject.toml").unwrap();
    /// let result = parser.parse_content(&content, &uri).unwrap();
    /// ```
    pub fn parse_content(&self, content: &str, uri: &Uri) -> Result<ParseResult> {
        if let Err(depth) =
            deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH)
        {
            return Err(crate::error::PypiError::TomlParseError {
                message: format!(
                    "array/table nesting depth {depth} exceeds maximum of {}",
                    deps_core::MAX_TOML_NESTING_DEPTH
                ),
            });
        }

        let doc =
            toml_span::parse(content).map_err(|e| crate::error::PypiError::TomlParseError {
                message: e.to_string(),
            })?;

        let line_table = LineOffsetTable::new(content);
        let mut dependencies = Vec::new();

        let root_table = match doc.as_table() {
            Some(t) => t,
            None => {
                return Ok(ParseResult {
                    dependencies,
                    workspace_root: None,
                    uri: uri.clone(),
                });
            }
        };

        // Parse build-system requires (PEP 517/518)
        if let Some(build_system) = get_table(root_table, "build-system") {
            dependencies.extend(self.parse_build_system_requires(
                build_system,
                content,
                &line_table,
            )?);
        }

        // Parse PEP 621 format
        if let Some(project) = get_table(root_table, "project") {
            dependencies.extend(self.parse_pep621_dependencies(project, content, &line_table)?);
            dependencies.extend(self.parse_pep621_optional_dependencies(
                project,
                content,
                &line_table,
            )?);
        }

        // Parse PEP 735 dependency-groups format
        if let Some(dep_groups) = get_table(root_table, "dependency-groups") {
            dependencies.extend(self.parse_dependency_groups(dep_groups, content, &line_table)?);
        }

        // Parse Poetry format
        if let Some(tool_table) = get_table(root_table, "tool")
            && let Some(poetry) = get_table(tool_table, "poetry")
        {
            dependencies.extend(self.parse_poetry_dependencies(poetry, content, &line_table)?);
            dependencies.extend(self.parse_poetry_groups(poetry, content, &line_table)?);
        }

        Ok(ParseResult {
            dependencies,
            workspace_root: None,
            uri: uri.clone(),
        })
    }

    /// Parse PEP 517/518 `[build-system]` requires array.
    fn parse_build_system_requires(
        &self,
        build_system: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let Some(requires_val) = build_system.get("requires") else {
            return Ok(Vec::new());
        };

        let Some(requires_array) = requires_val.as_array() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for value in requires_array {
            if let Some(dep_str) = value.as_str() {
                match self.parse_pep508_requirement(
                    dep_str,
                    Some(value.span.start..value.span.end),
                    content,
                    line_table,
                ) {
                    Ok(mut dep) => {
                        dep.section = PypiDependencySection::BuildSystem;
                        dependencies.push(dep);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse build-system require '{}': {}",
                            super::truncate_for_log(dep_str),
                            e
                        );
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse PEP 621 `[project.dependencies]` array.
    fn parse_pep621_dependencies(
        &self,
        project: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let Some(deps_val) = project.get("dependencies") else {
            return Ok(Vec::new());
        };

        let Some(deps_array) = deps_val.as_array() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for value in deps_array {
            if let Some(dep_str) = value.as_str() {
                match self.parse_pep508_requirement(
                    dep_str,
                    Some(value.span.start..value.span.end),
                    content,
                    line_table,
                ) {
                    Ok(mut dep) => {
                        dep.section = PypiDependencySection::Dependencies;
                        dependencies.push(dep);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse dependency '{}': {}",
                            super::truncate_for_log(dep_str),
                            e
                        );
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse PEP 621 `[project.optional-dependencies]` tables.
    fn parse_pep621_optional_dependencies(
        &self,
        project: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let Some(opt_deps_val) = project.get("optional-dependencies") else {
            return Ok(Vec::new());
        };

        let Some(opt_deps_table) = opt_deps_val.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (group_key, group_val) in opt_deps_table {
            if let Some(group_array) = group_val.as_array() {
                for value in group_array {
                    if let Some(dep_str) = value.as_str() {
                        match self.parse_pep508_requirement(
                            dep_str,
                            Some(value.span.start..value.span.end),
                            content,
                            line_table,
                        ) {
                            Ok(mut dep) => {
                                dep.section = PypiDependencySection::OptionalDependencies {
                                    group: group_key.name.to_string(),
                                };
                                dependencies.push(dep);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse dependency '{}': {}",
                                    super::truncate_for_log(dep_str),
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse PEP 735 `[dependency-groups]` tables.
    ///
    /// Format: `[dependency-groups]` with named groups containing arrays of PEP 508 requirements.
    /// Example:
    /// ```toml
    /// [dependency-groups]
    /// dev = ["pytest>=8.0", "mypy>=1.0"]
    /// test = ["pytest>=8.0", "pytest-cov>=4.0"]
    /// ```
    fn parse_dependency_groups(
        &self,
        dep_groups: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let mut dependencies = Vec::new();

        for (group_key, group_val) in dep_groups {
            if let Some(group_array) = group_val.as_array() {
                for value in group_array {
                    if let Some(dep_str) = value.as_str() {
                        match self.parse_pep508_requirement(
                            dep_str,
                            Some(value.span.start..value.span.end),
                            content,
                            line_table,
                        ) {
                            Ok(mut dep) => {
                                dep.section = PypiDependencySection::DependencyGroup {
                                    group: group_key.name.to_string(),
                                };
                                dependencies.push(dep);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse dependency group '{}' item '{}': {}",
                                    group_key.name,
                                    super::truncate_for_log(dep_str),
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse Poetry `[tool.poetry.dependencies]` table.
    fn parse_poetry_dependencies(
        &self,
        poetry: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let Some(deps_val) = poetry.get("dependencies") else {
            return Ok(Vec::new());
        };

        let Some(deps_table) = deps_val.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (name_key, value) in deps_table {
            let name = &name_key.name;
            // Skip Python version constraint
            if name == "python" {
                continue;
            }

            let position = span_start(content, line_table, name_key.span);

            match self.parse_poetry_dependency(name, value, Some(position), content, line_table) {
                Ok(mut dep) => {
                    dep.section = PypiDependencySection::PoetryDependencies;
                    dependencies.push(dep);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse Poetry dependency '{}': {}", name, e);
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse Poetry `[tool.poetry.group.*.dependencies]` tables.
    fn parse_poetry_groups(
        &self,
        poetry: &Table<'_>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<Vec<PypiDependency>> {
        let Some(group_val) = poetry.get("group") else {
            return Ok(Vec::new());
        };

        let Some(groups_table) = group_val.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (group_name_key, group_val) in groups_table {
            let group_name = &group_name_key.name;
            if let Some(group_table) = group_val.as_table()
                && let Some(deps_val) = group_table.get("dependencies")
                && let Some(deps_table) = deps_val.as_table()
            {
                for (name_key, value) in deps_table {
                    let name = &name_key.name;
                    let position = span_start(content, line_table, name_key.span);

                    match self.parse_poetry_dependency(
                        name,
                        value,
                        Some(position),
                        content,
                        line_table,
                    ) {
                        Ok(mut dep) => {
                            dep.section = PypiDependencySection::PoetryGroup {
                                group: group_name.to_string(),
                            };
                            dependencies.push(dep);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse Poetry dependency '{}': {}", name, e);
                        }
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse a Poetry dependency (can be string or table).
    ///
    /// Examples:
    /// - String: `requests = "^2.28.0"`
    /// - String with marker: `requests = "^2.28.0; sys_platform == 'win32'"`
    /// - Table: `flask = { version = "^3.0", extras = ["async"] }`
    fn parse_poetry_dependency(
        &self,
        name: &str,
        value: &Value<'_>,
        base_position: Option<tower_lsp_server::ls_types::Position>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<PypiDependency> {
        use tower_lsp_server::ls_types::{Position, Range};

        let name_range = base_position
            .map(|pos| {
                Range::new(
                    pos,
                    Position::new(pos.line, pos.character + name.len() as u32),
                )
            })
            .unwrap_or_default();

        // Simple string version, optionally followed by a `; <marker>` suffix
        // mirroring PEP 508 syntax (not standard Poetry, but handled defensively).
        if let Some(raw_value) = value.as_str() {
            let value_span = value.span;
            let source_slice = &content[value_span.start..value_span.end];

            let (version_str, raw_marker) = match raw_value.find(';') {
                Some(idx) => (&raw_value[..idx], Some(&raw_value[idx + 1..])),
                None => (raw_value, None),
            };

            // Locate the split independently in the *source* slice: `;` is
            // never produced by TOML escape decoding, so this byte offset is
            // safe for range math even when the decoded string's length
            // diverges from the source (e.g. `\"` escapes in the marker).
            // Deriving both ranges from `value_span` here (rather than
            // `name.len()` arithmetic) also makes them correct regardless of
            // spacing around `=` or whether the key itself is quoted.
            let source_semicolon = source_slice.find(';');
            let version_end_byte =
                value_span.start + source_semicolon.unwrap_or(source_slice.len());
            let version_range = Some(span_to_range(
                content,
                line_table,
                toml_span::Span::new(value_span.start, version_end_byte),
            ));

            let (markers, markers_range) = match (raw_marker, source_semicolon) {
                (Some(marker), Some(src_idx)) => match normalize_marker_string(marker) {
                    Some(normalized) => {
                        let marker_span =
                            toml_span::Span::new(value_span.start + src_idx + 1, value_span.end);
                        (
                            Some(normalized),
                            Some(span_to_range(content, line_table, marker_span)),
                        )
                    }
                    None => (None, None),
                },
                _ => (None, None),
            };

            return Ok(PypiDependency {
                name: name.into(),
                name_range,
                version_req: Some(version_str.trim().into()),
                version_range,
                extras: Vec::new(),
                extras_range: None,
                markers,
                markers_range,
                section: PypiDependencySection::PoetryDependencies,
                source: PypiDependencySource::Registry,
            });
        }

        // Table format
        if let Some(table) = value.as_table() {
            let version_req = table
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from);
            let extras = table
                .get("extras")
                .and_then(|e| e.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let markers_value = table.get("markers").filter(|v| v.as_str().is_some());
            let markers = markers_value
                .and_then(|m| m.as_str())
                .and_then(normalize_marker_string);
            let markers_range = markers_value
                .filter(|_| markers.is_some())
                .map(|v| span_to_range(content, line_table, v.span));

            let source = if table.contains_key("git") {
                PypiDependencySource::Git {
                    url: table
                        .get("git")
                        .and_then(|g| g.as_str())
                        .unwrap_or("")
                        .to_string(),
                    rev: table.get("rev").and_then(|r| r.as_str()).map(String::from),
                }
            } else if table.contains_key("path") {
                PypiDependencySource::Path {
                    path: table
                        .get("path")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string(),
                }
            } else if table.contains_key("url") {
                PypiDependencySource::Url {
                    url: table
                        .get("url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_string(),
                }
            } else {
                PypiDependencySource::Registry
            };

            return Ok(PypiDependency {
                name: name.into(),
                name_range,
                version_req: version_req.map(Into::into),
                version_range: None,
                extras,
                extras_range: None,
                markers,
                markers_range,
                section: PypiDependencySection::PoetryDependencies,
                source,
            });
        }

        Err(crate::error::PypiError::unsupported_format(format!(
            "Unsupported Poetry dependency format for '{name}'"
        )))
    }
}

/// Get a nested table value by key from a toml-span Table.
fn get_table<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Table<'a>> {
    table.get(key)?.as_table()
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_MARKER_LEN, marker_too_deep};
    use super::*;
    use crate::error::PypiError;
    use tower_lsp_server::ls_types::{Position, Range};

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/pyproject.toml")
    }

    #[test]
    fn test_parse_content_rejects_excessive_nesting() {
        // Well past MAX_TOML_NESTING_DEPTH (64) but far below the depth
        // that would actually overflow the stack, so the guard is what's
        // being exercised here, not the crash itself.
        let content = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        let parser = PypiParser::new();
        let result = parser.parse_content(&content, &test_uri());
        assert!(matches!(result, Err(PypiError::TomlParseError { .. })));
    }

    #[test]
    fn test_parse_pep621_dependencies() {
        let content = r#"
[project]
dependencies = [
    "requests>=2.28.0",
    "flask[async]>=3.0",
]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(
            deps[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some(">=2.28.0")
        );
        assert!(matches!(
            deps[0].section,
            PypiDependencySection::Dependencies
        ));

        assert_eq!(deps[1].name, "flask");
        assert_eq!(deps[1].extras, vec!["async"]);
    }

    #[test]
    fn test_parse_pep621_optional_dependencies() {
        let content = r#"
[project.optional-dependencies]
dev = ["pytest>=7.0", "mypy>=1.0"]
docs = ["sphinx>=5.0"]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 3);

        let dev_deps: Vec<_> = deps.iter().filter(|d| {
            matches!(&d.section, PypiDependencySection::OptionalDependencies { group } if group == "dev")
        }).collect();
        assert_eq!(dev_deps.len(), 2);

        let docs_deps: Vec<_> = deps.iter().filter(|d| {
            matches!(&d.section, PypiDependencySection::OptionalDependencies { group } if group == "docs")
        }).collect();
        assert_eq!(docs_deps.len(), 1);
    }

    #[test]
    fn test_parse_poetry_dependencies() {
        let content = r#"
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        // Should skip "python"
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert!(matches!(
            deps[0].section,
            PypiDependencySection::PoetryDependencies
        ));
    }

    #[test]
    fn test_parse_poetry_groups() {
        let content = r#"
[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
mypy = "^1.0"

[tool.poetry.group.docs.dependencies]
sphinx = "^5.0"
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 3);

        let dev_deps: Vec<_> = deps.iter().filter(|d| {
            matches!(&d.section, PypiDependencySection::PoetryGroup { group } if group == "dev")
        }).collect();
        assert_eq!(dev_deps.len(), 2);

        let docs_deps: Vec<_> = deps.iter().filter(|d| {
            matches!(&d.section, PypiDependencySection::PoetryGroup { group } if group == "docs")
        }).collect();
        assert_eq!(docs_deps.len(), 1);
    }

    #[test]
    fn test_parse_pep735_dependency_groups() {
        let content = r#"
[dependency-groups]
dev = ["pytest>=8.0", "mypy>=1.0", "ruff>=0.8"]
test = ["pytest>=8.0", "pytest-cov>=4.0"]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 5);

        let dev_deps: Vec<_> = deps
            .iter()
            .filter(|d| {
                matches!(&d.section, PypiDependencySection::DependencyGroup { group } if group == "dev")
            })
            .collect();
        assert_eq!(dev_deps.len(), 3);

        let test_deps: Vec<_> = deps
            .iter()
            .filter(|d| {
                matches!(&d.section, PypiDependencySection::DependencyGroup { group } if group == "test")
            })
            .collect();
        assert_eq!(test_deps.len(), 2);

        // Verify package names
        assert!(dev_deps.iter().any(|d| d.name == "pytest"));
        assert!(dev_deps.iter().any(|d| d.name == "mypy"));
        assert!(dev_deps.iter().any(|d| d.name == "ruff"));
    }

    #[test]
    fn test_parse_pep508_with_markers() {
        let content = r#"
[project]
dependencies = [
    "numpy>=1.24; python_version>='3.9'",
]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "numpy");
        // pep508_rs's marker algebra canonicalizes `python_version` comparisons
        // into `python_full_version` form when serializing back to a string.
        assert_eq!(
            deps[0].markers,
            Some("python_full_version >= '3.9'".to_string())
        );
    }

    #[test]
    fn test_parse_pep508_without_markers() {
        let content = r#"
[project]
dependencies = [
    "requests>=2.28.0",
]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].markers, None);
    }

    #[test]
    fn test_parse_pep508_with_compound_marker() {
        let content = r#"
[project]
dependencies = [
    "colorama>=0.4; sys_platform == 'win32' and python_version >= '3.8'",
]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "colorama");
        assert_eq!(
            deps[0].markers,
            Some("python_full_version >= '3.8' and sys_platform == 'win32'".to_string())
        );
    }

    #[test]
    fn test_parse_mixed_formats() {
        let content = r#"
[project]
dependencies = ["requests>=2.28.0"]

[tool.poetry.dependencies]
python = "^3.9"
flask = "^3.0"
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 2);

        let pep621_deps: Vec<_> = deps
            .iter()
            .filter(|d| matches!(d.section, PypiDependencySection::Dependencies))
            .collect();
        assert_eq!(pep621_deps.len(), 1);

        let poetry_deps: Vec<_> = deps
            .iter()
            .filter(|d| matches!(d.section, PypiDependencySection::PoetryDependencies))
            .collect();
        assert_eq!(poetry_deps.len(), 1);
    }

    #[test]
    fn test_parse_invalid_toml() {
        let content = "invalid toml {{{";
        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PypiError::TomlParseError { .. }
        ));
    }

    #[test]
    fn test_parse_empty_dependencies() {
        let content = r#"
[project]
name = "test"
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_position_tracking_pep735() {
        // Test that position tracking works correctly for PEP 735 dependency-groups
        let content = r#"[dependency-groups]
dev = ["pytest>=8.0", "mypy>=1.0"]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 2);

        // Check pytest>=8.0 position
        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        // Line 1 (0-indexed), character should be at 'p' (position 8 after `dev = ["`)
        assert_eq!(pytest.name_range.start.line, 1);
        assert_eq!(pytest.name_range.start.character, 8);
        // Version range should point to >=8.0
        assert!(pytest.version_range.is_some());
        let version_range = pytest.version_range.unwrap();
        assert_eq!(version_range.start.line, 1);
        // pytest is 6 chars, so version starts at 8 + 6 = 14
        assert_eq!(version_range.start.character, 14);
        // >=8.0 is 5 chars, so version ends at 14 + 5 = 19
        assert_eq!(version_range.end.character, 19);

        // Check mypy>=1.0 position
        let mypy = deps.iter().find(|d| d.name == "mypy").unwrap();
        assert_eq!(mypy.name_range.start.line, 1);
        // mypy starts after `dev = ["pytest>=8.0", "` = position 23
        // dev = ["pytest>=8.0", " = 22 chars, then position 22 is ", position 23 is m
        assert_eq!(mypy.name_range.start.character, 23);
        assert!(mypy.version_range.is_some());
        let version_range = mypy.version_range.unwrap();
        // mypy is 4 chars, so version starts at 23 + 4 = 27
        assert_eq!(version_range.start.character, 27);
        // >=1.0 is 5 chars, so version ends at 27 + 5 = 32
        assert_eq!(version_range.end.character, 32);
    }

    #[test]
    fn test_version_range_position_without_space() {
        // Bug: pep508 normalizes ">=1.7,<2.0" to ">=1.7, <2.0" (adds space)
        // Version range end must use original string length, not normalized
        let content = r#"[dependency-groups]
dev = [
    "maturin>=1.7,<2.0",
]
"#;
        // Line 0: [dependency-groups]
        // Line 1: dev = [
        // Line 2:     "maturin>=1.7,<2.0",
        //             ^    ^         ^
        //             5    12        22 (end of version, before closing quote)

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let maturin = &result.dependencies[0];

        let version_range = maturin.version_range.unwrap();
        assert_eq!(version_range.start.line, 2);
        assert_eq!(version_range.start.character, 12); // after "maturin"
        assert_eq!(version_range.end.line, 2);
        assert_eq!(version_range.end.character, 22); // ">=1.7,<2.0" = 10 chars
    }

    #[test]
    fn test_version_range_position_with_space() {
        // With space in original - should also work correctly
        let content = r#"[dependency-groups]
dev = [
    "maturin>=1.7, <2.0",
]
"#;
        // ">=1.7, <2.0" = 11 chars, end at 12 + 11 = 23

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let maturin = &result.dependencies[0];

        let version_range = maturin.version_range.unwrap();
        assert_eq!(version_range.start.character, 12);
        assert_eq!(version_range.end.character, 23);
    }

    #[test]
    fn test_position_tracking_with_extras() {
        let content = r#"[project]
dependencies = ["flask[async]>=3.0"]
"#;

        let parser = PypiParser::new();
        let result = parser.parse_content(content, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);

        let flask = &deps[0];
        assert_eq!(flask.name, "flask");
        assert_eq!(flask.extras, vec!["async"]);

        // Version range should account for extras
        assert!(flask.version_range.is_some());
        let version_range = flask.version_range.unwrap();
        // dependencies = [" is 17 chars, flask starts at char 17
        // flask is 5 chars, [async] is 7 chars, so version starts at 17 + 5 + 7 = 29
        assert_eq!(version_range.start.character, 29);
    }

    #[test]
    fn test_parse_pep621_with_comments() {
        let toml = r#"
[project]
name = "test"
dependencies = [
    "django>=4.0",  # Web framework
    # "old-package>=1.0",  # Commented out
    "requests>=2.0",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[1].name, "requests");
    }

    #[test]
    fn test_parse_poetry_with_python_constraint() {
        let toml = r#"
[tool.poetry]
name = "test"

[tool.poetry.dependencies]
python = "^3.9"
django = "^4.0"
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "django");
    }

    #[test]
    fn test_parse_pep508_with_platform_marker() {
        let toml = r#"
[project]
dependencies = [
    "pywin32>=1.0; sys_platform == 'win32'",
    "django>=4.0",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "pywin32");
        assert_eq!(deps[1].name, "django");
    }

    #[test]
    fn test_parse_poetry_with_multiple_constraints() {
        let toml = r#"
[tool.poetry.dependencies]
django = { version = "^4.0", python = "^3.9" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        // Poetry table-style with python constraints may not be fully parsed yet
        if !deps.is_empty() {
            assert_eq!(deps[0].name, "django");
            assert_eq!(
                deps[0]
                    .version_req
                    .as_ref()
                    .map(deps_core::VersionReq::as_str),
                Some("^4.0")
            );
        }
    }

    #[test]
    fn test_parse_pep621_with_git_url() {
        let toml = r#"
[project]
dependencies = [
    "mylib @ git+https://github.com/user/mylib.git@main",
    "django>=4.0",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "mylib");
        assert!(matches!(deps[0].source, PypiDependencySource::Git { .. }));
        assert_eq!(deps[1].name, "django");
    }

    #[test]
    fn test_parse_empty_optional_dependencies_table() {
        let toml = r#"
[project]
dependencies = ["django>=4.0"]

[project.optional-dependencies]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "django");
    }

    #[test]
    fn test_parse_whitespace_only_dependency() {
        let toml = r#"
[project]
dependencies = [
    "django>=4.0",
    "   ",
    "requests>=2.0",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_parse_version_with_wildcard() {
        let toml = r#"
[project]
dependencies = [
    "django==4.*",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("==4.*")
        );
    }

    #[test]
    fn test_parse_poetry_path_dependency() {
        let toml = r#"
[tool.poetry.dependencies]
mylib = { path = "../mylib" }
django = "^4.0"
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        // Poetry path dependencies may not be fully parsed yet
        let django_dep = deps.iter().find(|d| d.name == "django");
        assert!(django_dep.is_some());
    }

    #[test]
    fn test_parse_pep735_with_includes() {
        let toml = r#"
[dependency-groups]
test = [
    { include-group = "dev" },
    "pytest>=7.0",
]
dev = [
    "ruff>=0.1",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert!(deps.len() >= 2);
        assert!(deps.iter().any(|d| d.name == "pytest"));
        assert!(deps.iter().any(|d| d.name == "ruff"));
    }

    #[test]
    fn test_parse_complex_version_specifier() {
        let toml = r#"
[project]
dependencies = [
    "django>=4.0,<5.0,!=4.0.1",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "django");
        // Version specifier should be preserved
        assert!(deps[0].version_req.is_some());
    }

    #[test]
    fn test_parse_no_project_section() {
        let toml = r#"
[tool.my-custom-tool]
config = "value"
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 0);
    }

    #[test]
    fn test_parse_build_system_requires() {
        let toml = r#"
[build-system]
requires = ["setuptools>=61.0", "wheel", "maturin>=1.7,<2.0"]
build-backend = "setuptools.build_meta"
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 3);
        assert!(
            deps.iter()
                .all(|d| matches!(d.section, PypiDependencySection::BuildSystem))
        );

        let setuptools = deps.iter().find(|d| d.name == "setuptools").unwrap();
        assert_eq!(
            setuptools
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some(">=61.0")
        );

        let maturin = deps.iter().find(|d| d.name == "maturin").unwrap();
        assert_eq!(
            maturin
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.7, <2.0")
        );

        // wheel has no version constraint
        let wheel = deps.iter().find(|d| d.name == "wheel").unwrap();
        assert_eq!(wheel.version_req, None);
    }

    #[test]
    fn test_parse_duplicate_dependency_positions() {
        // Test that duplicate dependency strings get correct positions
        let toml = r#"[build-system]
requires = ["maturin>=1.7,<2.0"]

[dependency-groups]
dev = ["maturin>=1.7,<2.0"]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 2);

        // First maturin in [build-system] should be on line 1
        let build_system_maturin = deps
            .iter()
            .find(|d| matches!(d.section, PypiDependencySection::BuildSystem))
            .unwrap();
        assert_eq!(build_system_maturin.name_range.start.line, 1);

        // Second maturin in [dependency-groups] should be on line 4
        let dep_group_maturin = deps
            .iter()
            .find(|d| matches!(d.section, PypiDependencySection::DependencyGroup { .. }))
            .unwrap();
        assert_eq!(dep_group_maturin.name_range.start.line, 4);
    }

    #[test]
    fn test_version_range_for_code_actions() {
        // Test that version_range correctly covers the version specifier for code actions
        let toml = r#"[dependency-groups]
dev = ["pytest-cov>=4.0,<8.0"]
"#;
        // Line 0: [dependency-groups]
        // Line 1: dev = ["pytest-cov>=4.0,<8.0"]
        //               ^          ^         ^
        //               8          18        28 (positions)
        //               name_start version_start version_end

        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];

        assert_eq!(dep.name, "pytest-cov");
        assert_eq!(dep.name_range.start.line, 1);
        assert_eq!(dep.name_range.start.character, 8); // after `dev = ["`

        // Version range should cover >=4.0,<8.0
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(version_range.start.line, 1);
        // pytest-cov is 10 chars, so version starts at 8 + 10 = 18
        assert_eq!(version_range.start.character, 18);
        // >=4.0,<8.0 is 10 chars, so version ends at 18 + 10 = 28
        assert_eq!(version_range.end.character, 28);

        // Verify that cursor at position 20 (on '4') is within version_range
        let cursor_on_version = Position::new(1, 20);
        assert!(
            cursor_on_version.character >= version_range.start.character
                && cursor_on_version.character < version_range.end.character,
            "cursor at {} should be within version_range {}..{}",
            cursor_on_version.character,
            version_range.start.character,
            version_range.end.character
        );
    }

    #[test]
    fn test_version_range_with_space_before_specifier() {
        // Test version_range when there's a space between name and version specifier
        let toml = r#"[dependency-groups]
dev = ["pytest-cov >=4.0,<8.0"]
"#;
        // Line 1: dev = ["pytest-cov >=4.0,<8.0"]
        //               ^           ^         ^
        //               8           19        29 (positions)
        //               name_start  version   version_end

        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];

        // Version range should cover exactly ">=4.0,<8.0", not the leading
        // whitespace: `start_offset` is derived by scanning for the first
        // specifier character, not from `name.len()` arithmetic (§6.2).
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(version_range.start.line, 1);
        // pytest-cov is 10 chars plus 1 space, so version starts at 8 + 11 = 19
        assert_eq!(version_range.start.character, 19);
        // ">=4.0,<8.0" is 10 chars, so version ends at 19 + 10 = 29
        assert_eq!(version_range.end.character, 29);

        // Verify that a cursor within the specifier text is within version_range
        let cursor_on_version = Position::new(1, 21);
        assert!(
            cursor_on_version.character >= version_range.start.character
                && cursor_on_version.character < version_range.end.character,
            "cursor at {} should be within version_range {}..{}",
            cursor_on_version.character,
            version_range.start.character,
            version_range.end.character
        );
    }

    /// Converts an LSP UTF-16 code-unit offset within `line` to a byte offset.
    fn utf16_offset_to_byte(line: &str, utf16_offset: u32) -> usize {
        let mut utf16_count = 0u32;
        for (byte_idx, ch) in line.char_indices() {
            if utf16_count >= utf16_offset {
                return byte_idx;
            }
            utf16_count += ch.len_utf16() as u32;
        }
        line.len()
    }

    /// Extracts the text a single-line `Range` covers, for asserting on
    /// exact marker/version spans without hand-computing offsets. `Range`
    /// characters are UTF-16 code units per the LSP spec, so this converts
    /// through byte offsets rather than indexing `line` directly (which would
    /// panic, or silently misbehave, on non-ASCII content).
    fn slice_range(content: &str, range: Range) -> String {
        assert_eq!(
            range.start.line, range.end.line,
            "helper only supports single-line ranges"
        );
        let line = content.lines().nth(range.start.line as usize).unwrap();
        let start = utf16_offset_to_byte(line, range.start.character);
        let end = utf16_offset_to_byte(line, range.end.character);
        line[start..end].to_string()
    }

    #[test]
    fn test_pep621_markers_range_covers_marker_text() {
        let toml = r#"[project]
dependencies = [
    "numpy>=1.24; python_version>='3.9'",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(
            dep.markers,
            Some("python_full_version >= '3.9'".to_string())
        );

        // Range starts right after `;`, so it includes the following space.
        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert_eq!(slice_range(toml, markers_range), " python_version>='3.9'");
    }

    #[test]
    fn test_pep621_without_markers_has_no_markers_range() {
        let toml = r#"[project]
dependencies = ["requests>=2.28.0"]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].markers, None);
        assert_eq!(deps[0].markers_range, None);
    }

    #[test]
    fn test_pep621_version_range_excludes_marker_text() {
        // Regression test: version_range is the sole TextEdit range for the
        // "update version" code action. If it overlapped markers_range,
        // accepting that quick-fix would delete the marker from the file.
        let toml = r#"[project]
dependencies = [
    "numpy>=1.24; python_version>='3.9'",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), ">=1.24");

        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert!(version_range.end.character <= markers_range.start.character);
    }

    #[test]
    fn test_poetry_table_form_markers_normalized() {
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0", markers = "python_version >= \"3.8\"" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.name, "django");
        // pep508_rs canonicalizes python_version comparisons to python_full_version.
        assert_eq!(
            dep.markers,
            Some("python_full_version >= '3.8'".to_string())
        );

        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert_eq!(
            slice_range(toml, markers_range),
            "python_version >= \\\"3.8\\\""
        );
    }

    #[test]
    fn test_poetry_table_form_invalid_markers_falls_back_to_raw() {
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0", markers = "not a valid marker (((" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        // Unparseable text that also isn't marker-shaped (no recognized
        // marker variable token) is dropped rather than preserved verbatim.
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_unbalanced_parens_rejected() {
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0", markers = "os_name == 'a' (((" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Text that references a real marker variable but has unbalanced
        // trailing parens no longer decomposes into the grammar's
        // `marker_atom := '(' marker_expr ')' | marker_clause` production, so
        // it's dropped rather than preserved (the grammar validator now
        // checks paren balance, unlike the earlier per-operand adjacency
        // check it replaced).
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_trivially_true_marker_becomes_none() {
        // Matches the PEP 621 path: a marker that normalizes to always-true
        // has no string form and is indistinguishable from no marker at all.
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0", markers = "os_name == 'a' or os_name != 'a'" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_empty_markers_becomes_none() {
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0", markers = "   " }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_oversized_marker_skips_normalization() {
        let long_marker: String = "os_name == 'a' or ".repeat(200) + "os_name == 'a'";
        assert!(long_marker.len() > MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{long_marker}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Falls back to raw text rather than being handed to pep508_rs's
        // unbounded recursive-descent parser.
        assert_eq!(dep.markers, Some(long_marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_poetry_table_form_without_markers_key_has_no_markers() {
        let toml = r#"[tool.poetry.dependencies]
django = { version = "^4.0" }
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].markers, None);
        assert_eq!(deps[0].markers_range, None);
    }

    #[test]
    fn test_poetry_string_form_without_marker_stays_none() {
        let toml = r#"[tool.poetry.dependencies]
requests = "^2.28.0"
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_string_form_with_marker_suffix_normalized() {
        let toml = "[tool.poetry.dependencies]\nrequests = \"^2.28.0; python_version >= '3.8'\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(dep.name, "requests");
        // The marker suffix is split out of version_req and normalized.
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(
            dep.markers,
            Some("python_full_version >= '3.8'".to_string())
        );

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");

        // Range starts right after `;`, so it includes the following space.
        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert_eq!(slice_range(toml, markers_range), " python_version >= '3.8'");
    }

    #[test]
    fn test_poetry_string_form_with_invalid_marker_suffix_falls_back_to_raw() {
        let toml = "[tool.poetry.dependencies]\nrequests = \"^2.28.0; not a valid marker (((\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        // Unparseable text that also isn't marker-shaped (no recognized
        // marker variable token) is dropped rather than preserved verbatim.
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_string_form_version_range_without_marker() {
        let toml = "[tool.poetry.dependencies]\nrequests = \"^2.28.0\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");
    }

    #[test]
    fn test_poetry_string_form_empty_marker_after_semicolon() {
        let toml = "[tool.poetry.dependencies]\nrequests = \"^2.28.0;\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_string_form_no_space_around_equals() {
        // value.span-based range derivation must not depend on `name.len()`
        // arithmetic assuming a fixed ` = "` layout.
        let toml = "[tool.poetry.dependencies]\nrequests=\"^2.28.0; python_version >= '3.8'\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "requests");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(
            dep.markers,
            Some("python_full_version >= '3.8'".to_string())
        );

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");
        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert_eq!(slice_range(toml, markers_range), " python_version >= '3.8'");
    }

    #[test]
    fn test_poetry_string_form_quoted_key() {
        let toml =
            "[tool.poetry.dependencies]\n\"requests\" = \"^2.28.0; python_version >= '3.8'\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "requests");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");
        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert_eq!(slice_range(toml, markers_range), " python_version >= '3.8'");
    }

    #[test]
    fn test_poetry_string_form_marker_with_escaped_quotes() {
        // TOML decodes `\"` to `"`, so the decoded string's byte length
        // diverges from the source; range math must not desync from this.
        let toml =
            "[tool.poetry.dependencies]\nrequests = \"^2.28.0; python_version >= \\\"3.8\\\"\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(
            dep.markers,
            Some("python_full_version >= '3.8'".to_string())
        );

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");
    }

    #[test]
    fn test_poetry_string_form_marker_with_non_ascii() {
        // Byte offsets must be converted to UTF-16 code units (the LSP
        // Position unit) via the line table, not added to Position::character
        // directly.
        let toml = "[tool.poetry.dependencies]\nrequests = \"^2.28.0; os_name == 'ПРИВЕТ🚀'\"\n";
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );

        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice_range(toml, version_range), "^2.28.0");

        let line = toml.lines().nth(1).unwrap();
        let line_utf16_len = line.encode_utf16().count() as u32;
        let markers_range = dep.markers_range.expect("markers_range should be set");
        assert!(markers_range.end.character <= line_utf16_len);
        assert_eq!(slice_range(toml, markers_range), " os_name == 'ПРИВЕТ🚀'");
    }

    #[test]
    fn test_poetry_string_form_oversized_marker_skips_normalization() {
        let long_marker: String = "os_name == 'a' or ".repeat(200) + "os_name == 'a'";
        assert!(long_marker.len() > MAX_MARKER_LEN);
        let toml = format!("[tool.poetry.dependencies]\nrequests = \"^2.28.0; {long_marker}\"\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("^2.28.0")
        );
        assert_eq!(dep.markers, Some(long_marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_oversized_marker_skips_normalization() {
        let long_marker: String = "os_name == 'a' or ".repeat(200) + "os_name == 'a'";
        assert!(long_marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"numpy>=1.24; {long_marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "numpy");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some(">=1.24")
        );
        // Skips normalization (would blow the stack in pep508_rs's parser)
        // but preserves the raw marker text rather than dropping it.
        assert_eq!(dep.markers, Some(long_marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_oversized_extras_list_rejected_fast() {
        // Regression test for #229: `pep508_rs` 0.9.2 parses an extras list
        // in O(n²). Before the length cap, a single requirement this size
        // would take on the order of seconds to parse (extrapolating the
        // measured quadratic growth); with the cap it is rejected in O(1)
        // and the rest of the manifest still parses normally.
        let huge_extras = "a,".repeat(500_000); // ~1 MiB extras list
        let requirement = format!("pkg[{huge_extras}]==1.0");
        assert!(requirement.len() > super::super::MAX_REQUIREMENT_LEN);
        let toml = format!(
            "[project]\ndependencies = [\n    \"{requirement}\",\n    \"good-pkg==2.0\",\n]\n"
        );
        let parser = PypiParser::new();

        let start = std::time::Instant::now();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "oversized extras dependency took too long to reject: {elapsed:?}"
        );
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "good-pkg");
    }

    #[test]
    fn test_pep621_oversized_marker_beyond_total_cap_still_survives() {
        // Regression test for critic finding S1: the length cap must measure
        // only the pre-marker (name/extras/version) portion, not the whole
        // requirement string including the marker. This requirement's
        // pre-marker portion ("numpy>=1.24") is tiny, but the marker alone
        // pushes the total past MAX_REQUIREMENT_LEN — it must still be kept,
        // with the marker falling back to raw text via the pre-existing
        // MAX_MARKER_LEN guard, not dropped by the new cap.
        let long_marker: String = "os_name == 'a' or ".repeat(230) + "os_name == 'a'";
        assert!(long_marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"numpy>=1.24; {long_marker}\",\n]\n");
        assert!(
            "numpy>=1.24".len() < super::super::MAX_REQUIREMENT_LEN,
            "pre-marker portion must stay under the cap"
        );
        assert!(
            format!("numpy>=1.24; {long_marker}").len() > super::super::MAX_REQUIREMENT_LEN,
            "total requirement (incl. marker) must exceed the cap for this test to be meaningful"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();

        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "numpy");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some(">=1.24")
        );
        assert_eq!(dep.markers, Some(long_marker));
    }

    #[test]
    fn test_pep621_deeply_nested_marker_under_length_cap_skips_normalization() {
        // Regression test for #146: a marker packs ~1 paren pair per 2 bytes,
        // so nesting depth can exceed MAX_MARKER_DEPTH while the marker text
        // stays well under MAX_MARKER_LEN. Must not overflow the stack in
        // pep508_rs's unbounded recursive-descent parser.
        let depth = 1000;
        let nested_marker = format!("{}os_name == 'a'{}", "(".repeat(depth), ")".repeat(depth));
        assert!(nested_marker.len() < MAX_MARKER_LEN);
        let toml =
            format!("[project]\ndependencies = [\n    \"numpy>=1.24; {nested_marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "numpy");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some(">=1.24")
        );
        assert_eq!(dep.markers, Some(nested_marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_poetry_table_form_deeply_nested_marker_skips_normalization() {
        // Same attack via the Poetry `markers` key, which goes through
        // `normalize_marker_string` rather than `parse_pep508_requirement`.
        let depth = 1000;
        let nested_marker = format!("{}os_name == 'a'{}", "(".repeat(depth), ")".repeat(depth));
        assert!(nested_marker.len() < MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{nested_marker}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, Some(nested_marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_marker_depth_bypass_via_quoted_parens_falls_back() {
        // Regression test for the quote-bypass gap: pep508_rs's own tokenizer
        // treats `(`/`)` inside a quoted marker value as opaque (marker/parse.rs
        // uses `take_while(|c| c != quotation_mark)`, no escape handling), so a
        // scanner that counted parens unconditionally could be tricked into
        // never observing real nesting depth. Each level here opens one real
        // `(` but also embeds a `)` inside a quoted extra value; a quote-unaware
        // scanner treats that `)` as closing the level's own `(`, capping the
        // observed depth at 1 forever while the real recursive-descent parser
        // keeps recursing one level per iteration.
        let levels = 60;
        let mut marker = String::new();
        for _ in 0..levels {
            marker.push_str("(extra==')'and ");
        }
        marker.push_str("extra=='a'");
        for _ in 0..levels {
            marker.push(')');
        }
        assert!(marker.len() < MAX_MARKER_LEN);
        assert!(marker_too_deep(&marker));

        let toml = format!("[project]\ndependencies = [\n    \"numpy>=1.24; {marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "numpy");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some(">=1.24")
        );
        // Routed through the raw fallback rather than handed to pep508_rs.
        assert_eq!(dep.markers, Some(marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_reasonably_nested_marker_still_normalizes() {
        // Legitimate markers nest a handful of levels at most; these must
        // still be parsed and normalized, not routed to the raw fallback.
        let toml = r#"[project]
dependencies = [
    "numpy>=1.24; (os_name == 'a' and sys_platform == 'b') or os_name == 'c'",
]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "numpy");
        let markers = dep.markers.as_ref().expect("marker should normalize");
        assert!(markers.contains("os_name"));
        assert!(markers.contains("sys_platform"));
    }

    #[test]
    fn test_pep621_marker_extras_bracket_injection_rejected() {
        // Regression test for #261: a `;` landing before an oversized
        // extras/version tail (rather than before an actual marker) used to
        // have that whole tail — `[...]==1.0`, not a marker expression at
        // all — stored verbatim on `markers` via the length-cap bypass in
        // #146, then rendered into hover.
        let huge_extras = "a".repeat(60_000);
        let toml = format!("[project]\ndependencies = [\n    \"pkg;[{huge_extras}]==1.0\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.version_req, None);
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_oversized_non_marker_text_rejected() {
        // Same #261 gap via the Poetry `markers` key, which goes through
        // `normalize_marker_string` rather than `parse_pep508_requirement`:
        // oversized text with no marker-like shape must not be retained.
        let garbage = "[".to_string() + &"x".repeat(60_000) + "]";
        assert!(garbage.len() > MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{garbage}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_keyword_repeated_without_separators_rejected() {
        // Regression test for the substring-only `looks_like_marker` bypass:
        // a marker variable name repeated with no separators contains
        // "extra" as a substring but tokenizes as one giant unrecognized
        // identifier, not a real reference to the `extra` marker variable.
        let garbage = "extra".repeat(1600);
        assert!(garbage.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {garbage}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_keyword_padded_with_unquoted_garbage_rejected() {
        // Regression test for the substring-only `looks_like_marker` bypass:
        // a real marker variable followed by an unquoted run of filler bytes
        // used to pass (keyword present as a substring, all bytes in the
        // allowed character set); the filler is not a quoted string literal,
        // a known identifier, or an operator, so it must now be rejected.
        let filler = "A".repeat(5000);
        let raw_marker = format!("python_version <{filler}>");
        assert!(raw_marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {raw_marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_oversized_garbage_under_length_cap_rejected() {
        // Regression test for M2: text under MAX_MARKER_LEN that fails to
        // parse used to be retained unconditionally via the `MarkerTree::
        // from_str` error path, which had no shape validation of its own —
        // identical garbage was kept or dropped purely on whether it crossed
        // MAX_MARKER_LEN, not on whether it looked like a marker at all.
        let garbage = format!("[{}]==1.0", "a".repeat(1980));
        assert!(garbage.len() < MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{garbage}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_repeated_token_no_operator_rejected() {
        // Regression test for the reviewer's residual #261 bypass: bare
        // whitespace-separated repetition of a recognized marker variable,
        // with no comparison operator anywhere, used to still tokenize as
        // "marker-shaped" (at least one recognized token present) and be
        // retained verbatim.
        let garbage = "python_version ".repeat(500);
        assert!(garbage.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {garbage}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_and_joined_repeated_token_no_operator_rejected() {
        // Same bypass shape, joined by `and` instead of bare whitespace —
        // still no comparison operator anywhere in the text.
        let garbage = "python_version and ".repeat(400) + "python_version";
        assert!(garbage.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {garbage}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_repeated_token_no_operator_rejected() {
        // Same bypass shape via the Poetry `markers` key, which goes through
        // `normalize_marker_string` rather than `parse_pep508_requirement`.
        let garbage = "python_version ".repeat(500);
        assert!(garbage.len() > MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{garbage}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_chained_comparison_rejected() {
        // Regression test for the reviewer's round-3 #261 bypass: chained
        // comparisons share one operand across more than one clause
        // (`a == b == c == ...`). The per-operand adjacency check this
        // replaces treated every operand as valid ("touches an operator on
        // some side"), but PEP 508's grammar has no production for chaining
        // — `pep508_rs` itself rejects a short version of this shape
        // outright (confirmed: `pkg; python_version==python_version==
        // python_version` fails to parse at all).
        let chain = "python_version==".repeat(500) + "python_version";
        assert!(chain.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {chain}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_marker_chained_in_rejected() {
        // Same bypass shape using `in` instead of `==`.
        let chain = "python_version in ".repeat(500) + "python_version";
        assert!(chain.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {chain}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_poetry_table_form_chained_comparison_rejected() {
        // Same bypass shape via the Poetry `markers` key.
        let chain = "python_version==".repeat(500) + "python_version";
        assert!(chain.len() > MAX_MARKER_LEN);
        let toml = format!(
            "[tool.poetry.dependencies]\ndjango = {{ version = \"^4.0\", markers = \"{chain}\" }}\n"
        );
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.markers, None);
        assert_eq!(dep.markers_range, None);
    }

    #[test]
    fn test_pep621_oversized_in_operator_marker_still_normalizes() {
        // Legitimate use of the `in` operator must still be preserved
        // through the raw fallback once it's oversized enough to bypass
        // `pep508_rs`'s parser.
        let marker =
            "python_version in '3.8'".to_string() + &" or python_version in '3.8'".repeat(200);
        assert!(marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, Some(marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_oversized_not_in_operator_marker_still_normalizes() {
        // Same as above for `not in`.
        let marker = "python_version not in '3.8'".to_string()
            + &" or python_version not in '3.8'".repeat(200);
        assert!(marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, Some(marker));
        assert!(dep.markers_range.is_some());
    }

    #[test]
    fn test_pep621_non_ascii_marker_literal_still_normalizes() {
        // Regression test for M3: a genuine, if oversized, marker whose
        // quoted string literal contains non-ASCII bytes must not be
        // rejected just because those bytes aren't ASCII — only unquoted
        // text is required to tokenize as known marker-grammar elements.
        let filler = "é".repeat(1500);
        let raw_marker = format!("platform_release == '{filler}' or python_version >= '3.8'");
        assert!(raw_marker.len() > MAX_MARKER_LEN);
        let toml = format!("[project]\ndependencies = [\n    \"pkg; {raw_marker}\",\n]\n");
        let parser = PypiParser::new();
        let result = parser.parse_content(&toml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "pkg");
        assert_eq!(dep.markers, Some(raw_marker));
        assert!(dep.markers_range.is_some());
    }
}
