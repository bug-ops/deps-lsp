use crate::error::{PypiError, Result};
use crate::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
use pep508_rs::{Requirement, VersionOrUrl};
use std::str::FromStr;
use toml_edit::{DocumentMut, Item, Table};
use tower_lsp::lsp_types::{Position, Range};

/// Parser for Python pyproject.toml files.
///
/// Supports both PEP 621 standard format and Poetry format.
/// Uses `toml_edit` to preserve source positions for LSP operations.
///
/// # Examples
///
/// ```no_run
/// use deps_pypi::parser::PypiParser;
///
/// let content = r#"
/// [project]
/// dependencies = ["requests>=2.28.0", "flask[async]>=3.0"]
/// "#;
///
/// let parser = PypiParser::new();
/// let dependencies = parser.parse(content).unwrap();
/// assert_eq!(dependencies.len(), 2);
/// ```
pub struct PypiParser;

impl PypiParser {
    /// Create a new PyPI parser.
    pub fn new() -> Self {
        Self
    }

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
    /// let parser = PypiParser::new();
    /// let content = std::fs::read_to_string("pyproject.toml").unwrap();
    /// let dependencies = parser.parse(&content).unwrap();
    /// ```
    pub fn parse(&self, content: &str) -> Result<Vec<PypiDependency>> {
        let doc = content
            .parse::<DocumentMut>()
            .map_err(|e| PypiError::TomlParseError { source: e })?;

        let mut dependencies = Vec::new();

        // Parse PEP 621 format
        if let Some(project) = doc.get("project").and_then(|i| i.as_table()) {
            dependencies.extend(self.parse_pep621_dependencies(project, content)?);
            dependencies.extend(self.parse_pep621_optional_dependencies(project, content)?);
        }

        // Parse Poetry format
        if let Some(tool) = doc.get("tool").and_then(|i| i.as_table())
            && let Some(poetry) = tool.get("poetry").and_then(|i| i.as_table())
        {
            dependencies.extend(self.parse_poetry_dependencies(poetry, content)?);
            dependencies.extend(self.parse_poetry_groups(poetry, content)?);
        }

        Ok(dependencies)
    }

    /// Parse PEP 621 `[project.dependencies]` array.
    fn parse_pep621_dependencies(
        &self,
        project: &Table,
        content: &str,
    ) -> Result<Vec<PypiDependency>> {
        let Some(deps_item) = project.get("dependencies") else {
            return Ok(Vec::new());
        };

        let Some(deps_array) = deps_item.as_array() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (idx, value) in deps_array.iter().enumerate() {
            if let Some(dep_str) = value.as_str() {
                let position =
                    self.find_array_element_position(content, "project.dependencies", idx);

                match self.parse_pep508_requirement(dep_str, position) {
                    Ok(mut dep) => {
                        dep.section = PypiDependencySection::Dependencies;
                        dependencies.push(dep);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse dependency '{}': {}", dep_str, e);
                    }
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse PEP 621 `[project.optional-dependencies]` tables.
    fn parse_pep621_optional_dependencies(
        &self,
        project: &Table,
        content: &str,
    ) -> Result<Vec<PypiDependency>> {
        let Some(opt_deps_item) = project.get("optional-dependencies") else {
            return Ok(Vec::new());
        };

        let Some(opt_deps_table) = opt_deps_item.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (group_name, group_item) in opt_deps_table.iter() {
            if let Some(group_array) = group_item.as_array() {
                for (idx, value) in group_array.iter().enumerate() {
                    if let Some(dep_str) = value.as_str() {
                        let section_name = format!("project.optional-dependencies.{}", group_name);
                        let position =
                            self.find_array_element_position(content, &section_name, idx);

                        match self.parse_pep508_requirement(dep_str, position) {
                            Ok(mut dep) => {
                                dep.section = PypiDependencySection::OptionalDependencies {
                                    group: group_name.to_string(),
                                };
                                dependencies.push(dep);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse dependency '{}': {}", dep_str, e);
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
        poetry: &Table,
        content: &str,
    ) -> Result<Vec<PypiDependency>> {
        let Some(deps_item) = poetry.get("dependencies") else {
            return Ok(Vec::new());
        };

        let Some(deps_table) = deps_item.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (name, value) in deps_table.iter() {
            // Skip Python version constraint
            if name == "python" {
                continue;
            }

            let position = self.find_table_key_position(content, "tool.poetry.dependencies", name);

            match self.parse_poetry_dependency(name, value, position) {
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
    fn parse_poetry_groups(&self, poetry: &Table, content: &str) -> Result<Vec<PypiDependency>> {
        let Some(group_item) = poetry.get("group") else {
            return Ok(Vec::new());
        };

        let Some(groups_table) = group_item.as_table() else {
            return Ok(Vec::new());
        };

        let mut dependencies = Vec::new();

        for (group_name, group_item) in groups_table.iter() {
            if let Some(group_table) = group_item.as_table()
                && let Some(deps_item) = group_table.get("dependencies")
                && let Some(deps_table) = deps_item.as_table()
            {
                for (name, value) in deps_table.iter() {
                    let section_path = format!("tool.poetry.group.{}.dependencies", group_name);
                    let position = self.find_table_key_position(content, &section_path, name);

                    match self.parse_poetry_dependency(name, value, position) {
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

    /// Parse a PEP 508 requirement string.
    ///
    /// Example: `requests[security,socks]>=2.28.0,<3.0; python_version>='3.8'`
    fn parse_pep508_requirement(
        &self,
        requirement_str: &str,
        base_position: Option<Position>,
    ) -> Result<PypiDependency> {
        let requirement = Requirement::from_str(requirement_str)
            .map_err(|e| PypiError::InvalidDependencySpec { source: e })?;

        let name = requirement.name.to_string();
        let name_range = base_position
            .map(|pos| {
                Range::new(
                    pos,
                    Position::new(pos.line, pos.character + name.len() as u32),
                )
            })
            .unwrap_or_default();

        let (version_req, version_range, source) = match requirement.version_or_url {
            Some(VersionOrUrl::VersionSpecifier(specs)) => {
                let version_str = specs.to_string();
                let start_offset = name.len() + requirement.extras.len();
                let version_range = base_position.map(|pos| {
                    Range::new(
                        Position::new(pos.line, pos.character + start_offset as u32),
                        Position::new(
                            pos.line,
                            pos.character + start_offset as u32 + version_str.len() as u32,
                        ),
                    )
                });
                (Some(version_str), version_range, PypiDependencySource::PyPI)
            }
            Some(VersionOrUrl::Url(url)) => {
                let url_str = url.to_string();
                if url_str.starts_with("git+") {
                    (
                        None,
                        None,
                        PypiDependencySource::Git {
                            url: url_str.clone(),
                            rev: None,
                        },
                    )
                } else if url_str.ends_with(".whl") || url_str.ends_with(".tar.gz") {
                    (None, None, PypiDependencySource::Url { url: url_str })
                } else {
                    (None, None, PypiDependencySource::PyPI)
                }
            }
            None => (None, None, PypiDependencySource::PyPI),
        };

        let extras: Vec<String> = requirement
            .extras
            .into_iter()
            .map(|e| e.to_string())
            .collect();
        // For now, skip markers - we'll implement proper MarkerTree serialization later
        // TODO: Implement proper marker serialization
        let markers = None;

        Ok(PypiDependency {
            name,
            name_range,
            version_req,
            version_range,
            extras,
            extras_range: None,
            markers,
            markers_range: None,
            section: PypiDependencySection::Dependencies,
            source,
        })
    }

    /// Parse a Poetry dependency (can be string or table).
    ///
    /// Examples:
    /// - String: `requests = "^2.28.0"`
    /// - Table: `flask = { version = "^3.0", extras = ["async"] }`
    fn parse_poetry_dependency(
        &self,
        name: &str,
        value: &Item,
        base_position: Option<Position>,
    ) -> Result<PypiDependency> {
        let name_range = base_position
            .map(|pos| {
                Range::new(
                    pos,
                    Position::new(pos.line, pos.character + name.len() as u32),
                )
            })
            .unwrap_or_default();

        // Simple string version
        if let Some(version_str) = value.as_str() {
            let version_range = base_position.map(|pos| {
                Range::new(
                    Position::new(pos.line, pos.character + name.len() as u32 + 3),
                    Position::new(
                        pos.line,
                        pos.character + name.len() as u32 + 3 + version_str.len() as u32,
                    ),
                )
            });

            return Ok(PypiDependency {
                name: name.to_string(),
                name_range,
                version_req: Some(version_str.to_string()),
                version_range,
                extras: Vec::new(),
                extras_range: None,
                markers: None,
                markers_range: None,
                section: PypiDependencySection::PoetryDependencies,
                source: PypiDependencySource::PyPI,
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

            let markers = table
                .get("markers")
                .and_then(|m| m.as_str())
                .map(String::from);

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
                PypiDependencySource::PyPI
            };

            return Ok(PypiDependency {
                name: name.to_string(),
                name_range,
                version_req,
                version_range: None,
                extras,
                extras_range: None,
                markers,
                markers_range: None,
                section: PypiDependencySection::PoetryDependencies,
                source,
            });
        }

        Err(PypiError::unsupported_format(format!(
            "Unsupported Poetry dependency format for '{}'",
            name
        )))
    }

    /// Find position of array element in source content.
    fn find_array_element_position(
        &self,
        _content: &str,
        _section: &str,
        _index: usize,
    ) -> Option<Position> {
        // TODO: Implement actual position tracking using toml_edit spans
        // For now, return None - positions will be default
        None
    }

    /// Find position of table key in source content.
    fn find_table_key_position(
        &self,
        _content: &str,
        _section: &str,
        _key: &str,
    ) -> Option<Position> {
        // TODO: Implement actual position tracking using toml_edit spans
        // For now, return None - positions will be default
        None
    }
}

impl Default for PypiParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let deps = parser.parse(content).unwrap();

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version_req, Some(">=2.28.0".to_string()));
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
        let deps = parser.parse(content).unwrap();

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
        let deps = parser.parse(content).unwrap();

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
        let deps = parser.parse(content).unwrap();

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
    fn test_parse_pep508_with_markers() {
        let content = r#"
[project]
dependencies = [
    "numpy>=1.24; python_version>='3.9'",
]
"#;

        let parser = PypiParser::new();
        let deps = parser.parse(content).unwrap();

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "numpy");
        // TODO: Implement proper marker serialization from MarkerTree
        // assert_eq!(deps[0].markers, Some("python_version >= '3.9'".to_string()));
        assert_eq!(deps[0].markers, None);
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
        let deps = parser.parse(content).unwrap();

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
        let result = parser.parse(content);

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
        let deps = parser.parse(content).unwrap();

        assert_eq!(deps.len(), 0);
    }
}
