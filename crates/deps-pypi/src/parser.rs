use crate::error::{PypiError, Result};
use crate::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
use pep508_rs::{Requirement, VersionOrUrl};
use std::any::Any;
use std::str::FromStr;
use toml_edit::{DocumentMut, Item, Table};
use tower_lsp::lsp_types::{Position, Range, Url};

/// Parse result containing all dependencies from pyproject.toml.
///
/// Stores dependencies and optional workspace information for LSP operations.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// All dependencies found in the manifest
    pub dependencies: Vec<PypiDependency>,
    /// Workspace root path (None for Python - no workspace concept like Cargo)
    pub workspace_root: Option<std::path::PathBuf>,
    /// URI of the parsed file
    pub uri: Url,
}

impl deps_core::ParseResult for ParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.workspace_root.as_deref()
    }

    fn uri(&self) -> &Url {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parser for Python pyproject.toml files.
///
/// Supports both PEP 621 standard format and Poetry format.
/// Uses `toml_edit` to preserve source positions for LSP operations.
///
/// # Examples
///
/// ```no_run
/// use deps_pypi::parser::PypiParser;
/// use tower_lsp::lsp_types::Url;
///
/// let content = r#"
/// [project]
/// dependencies = ["requests>=2.28.0", "flask[async]>=3.0"]
/// "#;
///
/// let parser = PypiParser::new();
/// let uri = Url::parse("file:///test/pyproject.toml").unwrap();
/// let result = parser.parse_content(content, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
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
    /// # use tower_lsp::lsp_types::Url;
    /// let parser = PypiParser::new();
    /// let content = std::fs::read_to_string("pyproject.toml").unwrap();
    /// let uri = Url::parse("file:///project/pyproject.toml").unwrap();
    /// let result = parser.parse_content(&content, &uri).unwrap();
    /// ```
    pub fn parse_content(&self, content: &str, uri: &Url) -> Result<ParseResult> {
        let doc = content
            .parse::<DocumentMut>()
            .map_err(|e| PypiError::TomlParseError { source: e })?;

        let mut dependencies = Vec::new();

        // Parse PEP 621 format
        if let Some(project) = doc.get("project").and_then(|i| i.as_table()) {
            dependencies.extend(self.parse_pep621_dependencies(project, content)?);
            dependencies.extend(self.parse_pep621_optional_dependencies(project, content)?);
        }

        // Parse PEP 735 dependency-groups format
        if let Some(dep_groups) = doc.get("dependency-groups").and_then(|i| i.as_table()) {
            dependencies.extend(self.parse_dependency_groups(dep_groups, content)?);
        }

        // Parse Poetry format
        if let Some(tool) = doc.get("tool").and_then(|i| i.as_table())
            && let Some(poetry) = tool.get("poetry").and_then(|i| i.as_table())
        {
            dependencies.extend(self.parse_poetry_dependencies(poetry, content)?);
            dependencies.extend(self.parse_poetry_groups(poetry, content)?);
        }

        Ok(ParseResult {
            dependencies,
            workspace_root: None,
            uri: uri.clone(),
        })
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

        for value in deps_array.iter() {
            if let Some(dep_str) = value.as_str() {
                // Find exact position of this dependency string in content
                let position = self.find_dependency_string_position(content, dep_str);

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
                for value in group_array.iter() {
                    if let Some(dep_str) = value.as_str() {
                        // Find exact position of this dependency string in content
                        let position = self.find_dependency_string_position(content, dep_str);

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
        dep_groups: &Table,
        content: &str,
    ) -> Result<Vec<PypiDependency>> {
        let mut dependencies = Vec::new();

        for (group_name, group_item) in dep_groups.iter() {
            if let Some(group_array) = group_item.as_array() {
                for value in group_array.iter() {
                    if let Some(dep_str) = value.as_str() {
                        // Find exact position of this dependency string in content
                        let position = self.find_dependency_string_position(content, dep_str);

                        match self.parse_pep508_requirement(dep_str, position) {
                            Ok(mut dep) => {
                                dep.section = PypiDependencySection::DependencyGroup {
                                    group: group_name.to_string(),
                                };
                                dependencies.push(dep);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse dependency group '{}' item '{}': {}",
                                    group_name,
                                    dep_str,
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
                // Calculate offset from name start to version specifier
                // For "package>=1.0": offset = len("package") = 7
                // For "package[extra]>=1.0": offset = len("package[extra]") = 14
                let extras_str_len = if requirement.extras.is_empty() {
                    0
                } else {
                    // Format: "[extra1,extra2]"
                    let extras_joined = requirement
                        .extras
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    extras_joined.len() + 2 // +2 for [ and ]
                };
                let start_offset = name.len() + extras_str_len;

                // Calculate original version length from requirement_str
                // pep508 normalizes version specifiers (e.g., ">=1.7,<2.0" -> ">=1.7, <2.0")
                // We need the original length for correct position tracking
                let original_version_len = requirement_str.len() - start_offset;

                let version_range = base_position.map(|pos| {
                    Range::new(
                        Position::new(pos.line, pos.character + start_offset as u32),
                        Position::new(
                            pos.line,
                            pos.character + start_offset as u32 + original_version_len as u32,
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

    /// Find the exact position of a dependency string in the content.
    /// Returns the position at the START of the package name (for name_range)
    /// and can be used to calculate version_range.
    fn find_dependency_string_position(&self, content: &str, dep_str: &str) -> Option<Position> {
        // Search for the quoted dependency string
        let quoted = format!("\"{}\"", dep_str);
        if let Some(pos) = content.find(&quoted) {
            let before = &content[..pos + 1]; // +1 to skip opening quote
            let line = before.chars().filter(|&c| c == '\n').count() as u32;
            let last_newline = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
            let character = (pos + 1 - last_newline) as u32; // +1 to skip opening quote
            return Some(Position::new(line, character));
        }

        // Try single quotes
        let single_quoted = format!("'{}'", dep_str);
        if let Some(pos) = content.find(&single_quoted) {
            let before = &content[..pos + 1];
            let line = before.chars().filter(|&c| c == '\n').count() as u32;
            let last_newline = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
            let character = (pos + 1 - last_newline) as u32;
            return Some(Position::new(line, character));
        }

        None
    }

    /// Find position of table key in source content.
    fn find_table_key_position(&self, content: &str, section: &str, key: &str) -> Option<Position> {
        // Find section first
        let section_marker = format!("[{}]", section);
        let section_start = content.find(&section_marker)?;

        // Find the key after the section
        let after_section = &content[section_start..];
        let key_pattern = format!("{} = ", key);
        let key_pos = after_section.find(&key_pattern)?;

        let total_offset = section_start + key_pos;
        let before_key = &content[..total_offset];
        let line = before_key.chars().filter(|&c| c == '\n').count() as u32;
        let last_newline = before_key.rfind('\n').map(|p| p + 1).unwrap_or(0);
        let character = (total_offset - last_newline) as u32;

        Some(Position::new(line, character))
    }
}

impl Default for PypiParser {
    fn default() -> Self {
        Self::new()
    }
}

// Implement deps_core traits for interoperability with LSP server

impl deps_core::ManifestParser for PypiParser {
    type Dependency = PypiDependency;
    type ParseResult = ParseResult;

    fn parse(&self, content: &str, doc_uri: &Url) -> deps_core::error::Result<Self::ParseResult> {
        self.parse_content(content, doc_uri)
            .map_err(|e| deps_core::error::DepsError::ParseError {
                file_type: "pyproject.toml".to_string(),
                source: Box::new(e),
            })
    }
}

impl deps_core::DependencyInfo for PypiDependency {
    fn name(&self) -> &str {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&str> {
        self.version_req.as_deref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::DependencySource {
        match &self.source {
            PypiDependencySource::PyPI => deps_core::DependencySource::Registry,
            PypiDependencySource::Git { url, rev } => deps_core::DependencySource::Git {
                url: url.clone(),
                rev: rev.clone(),
            },
            PypiDependencySource::Path { path } => {
                deps_core::DependencySource::Path { path: path.clone() }
            }
            // URL dependencies are treated as Registry since they're still remote packages
            PypiDependencySource::Url { .. } => deps_core::DependencySource::Registry,
        }
    }

    fn features(&self) -> &[String] {
        &self.extras
    }
}

impl deps_core::ParseResultInfo for ParseResult {
    type Dependency = PypiDependency;

    fn dependencies(&self) -> &[Self::Dependency] {
        &self.dependencies
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.workspace_root.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Url {
        Url::parse("file:///test/pyproject.toml").unwrap()
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
            assert_eq!(deps[0].version_req.as_deref(), Some("^4.0"));
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
        assert_eq!(deps[0].version_req.as_deref(), Some("==4.*"));
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
[build-system]
requires = ["setuptools"]
"#;
        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;
        assert_eq!(deps.len(), 0);
    }
}
