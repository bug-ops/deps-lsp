use crate::error::{PypiError, Result};
use crate::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
use deps_core::lsp_helpers::LineOffsetTable;
use pep508_rs::{MarkerTree, Requirement, VersionOrUrl};
use std::any::Any;
use std::str::FromStr;
use toml_span::value::{Table, Value};
use tower_lsp_server::ls_types::{Position, Range, Uri};

/// Marker expressions longer than this are not handed to `pep508_rs`'s
/// recursive-descent parser, which has no depth limit and can overflow the
/// stack on deeply nested expressions (verified: ~5000 nested parens, ~10 KiB,
/// aborts the process; ~4000 survives). Text over the cap falls back to its
/// raw, unnormalized form rather than being parsed.
const MAX_MARKER_LEN: usize = 2048;

/// Generous bound on PEP 508 marker parenthesis nesting depth.
///
/// `pep508_rs`'s recursive-descent marker parser recurses once per nesting
/// level with no depth limit, so a marker can overflow the stack from
/// nesting alone while staying well under [`MAX_MARKER_LEN`] — a marker can
/// pack roughly one `(`/`)` pair per 2 bytes (verified: 1016 levels in 2047
/// bytes aborts the process on a 256 KiB stack). Real-world markers rarely
/// nest more than 2-3 levels, so this cap leaves ample headroom.
const MAX_MARKER_DEPTH: u32 = 32;

/// Returns `true` if `marker` nests parentheses deeper than [`MAX_MARKER_DEPTH`].
///
/// Tracks quoted-string state the same way `pep508_rs`'s tokenizer does
/// (`marker/parse.rs`: a quote opens on an unquoted `'`/`"` and closes on the
/// next occurrence of that same character, with no escape handling) so that
/// `(`/`)` bytes inside a quoted marker value — e.g. `extra == ')'` — are not
/// mistaken for real nesting. A scanner that counted paren bytes unconditionally
/// could be tricked into undercounting depth by parentheses hidden in quoted
/// values while the real recursive-descent parser, which treats quoted content
/// as opaque, keeps recursing.
fn marker_too_deep(marker: &str) -> bool {
    let mut depth: u32 = 0;
    let mut quote: Option<u8> = None;
    for b in marker.bytes() {
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' => {
                depth += 1;
                if depth > MAX_MARKER_DEPTH {
                    return true;
                }
            }
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

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
    pub uri: Uri,
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

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parser for Python pyproject.toml files.
///
/// Supports both PEP 621 standard format and Poetry format.
/// Uses `toml-span` to preserve source positions for LSP operations.
///
/// # Examples
///
/// ```no_run
/// use deps_pypi::parser::PypiParser;
/// use tower_lsp_server::ls_types::Uri;
///
/// let content = r#"
/// [project]
/// dependencies = ["requests>=2.28.0", "flask[async]>=3.0"]
/// "#;
///
/// let parser = PypiParser::new();
/// let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();
/// let result = parser.parse_content(content, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
/// ```
pub struct PypiParser;

impl PypiParser {
    /// Create a new PyPI parser.
    pub const fn new() -> Self {
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
            return Err(PypiError::TomlParseError {
                message: format!(
                    "array/table nesting depth {depth} exceeds maximum of {}",
                    deps_core::MAX_TOML_NESTING_DEPTH
                ),
            });
        }

        let doc = toml_span::parse(content).map_err(|e| PypiError::TomlParseError {
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
                match self.parse_pep508_requirement(dep_str, Some(value.span), content, line_table)
                {
                    Ok(mut dep) => {
                        dep.section = PypiDependencySection::BuildSystem;
                        dependencies.push(dep);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse build-system require '{}': {}", dep_str, e);
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
                match self.parse_pep508_requirement(dep_str, Some(value.span), content, line_table)
                {
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
                            Some(value.span),
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
                            Some(value.span),
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

    /// Parse a PEP 508 requirement string.
    ///
    /// Example: `requests[security,socks]>=2.28.0,<3.0; python_version>='3.8'`
    ///
    /// `value_span` is the requirement string's source span (used for both
    /// `Position` tracking and, via [`span_to_range`], UTF-16-correct
    /// `markers_range` computation).
    fn parse_pep508_requirement(
        &self,
        requirement_str: &str,
        value_span: Option<toml_span::Span>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<PypiDependency> {
        let base_position = value_span.map(|span| span_start(content, line_table, span));

        // `;` never appears inside a version/extras clause, so the first
        // occurrence unambiguously anchors the marker section (direct-reference
        // URLs containing `;` are a known, documented edge case - see #<follow-up>).
        let semicolon_idx = requirement_str.find(';');

        // Pathologically long or deeply nested marker expressions can overflow
        // the stack in `pep508_rs`'s unbounded recursive-descent parser. Parse
        // only the name/version/extras portion and skip marker normalization
        // instead of handing the oversized/deeply-nested marker text to the
        // parser.
        let marker_too_complex = semicolon_idx.is_some_and(|idx| {
            let marker_text = &requirement_str[idx..];
            marker_text.len() > MAX_MARKER_LEN || marker_too_deep(marker_text)
        });
        let parse_str = if marker_too_complex {
            &requirement_str[..semicolon_idx.unwrap()]
        } else {
            requirement_str
        };

        let requirement = Requirement::from_str(parse_str)
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

        // Version/extras text never extends past the marker section.
        let version_end = semicolon_idx.unwrap_or(requirement_str.len());

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
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    extras_joined.len() + 2 // +2 for [ and ]
                };
                let start_offset = name.len() + extras_str_len;

                // Calculate original version length from requirement_str, bounded
                // at the marker section so the range never overlaps markers_range
                // (it is the sole TextEdit target for the "update version" code
                // action, so overlap would delete the marker on accept).
                // pep508 normalizes version specifiers (e.g., ">=1.7,<2.0" -> ">=1.7, <2.0")
                // We need the original length for correct position tracking
                let original_version_len = version_end.saturating_sub(start_offset);

                let version_range = base_position.map(|pos| {
                    Range::new(
                        Position::new(pos.line, pos.character + start_offset as u32),
                        Position::new(
                            pos.line,
                            pos.character + start_offset as u32 + original_version_len as u32,
                        ),
                    )
                });
                (
                    Some(version_str),
                    version_range,
                    PypiDependencySource::Registry,
                )
            }
            Some(VersionOrUrl::Url(url)) => {
                let url_str = url.to_string();
                if url_str.starts_with("git+") {
                    (
                        None,
                        None,
                        PypiDependencySource::Git {
                            url: url_str,
                            rev: None,
                        },
                    )
                } else if url_str.ends_with(".whl") || url_str.ends_with(".tar.gz") {
                    (None, None, PypiDependencySource::Url { url: url_str })
                } else {
                    (None, None, PypiDependencySource::Registry)
                }
            }
            None => (None, None, PypiDependencySource::Registry),
        };

        let extras: Vec<String> = requirement
            .extras
            .into_iter()
            .map(|e| e.to_string())
            .collect();

        let markers = if marker_too_complex {
            let raw_marker = requirement_str[semicolon_idx.unwrap() + 1..].trim();
            if raw_marker.is_empty() {
                None
            } else {
                tracing::warn!(
                    "Marker expression for '{}' is too complex ({} bytes, over the {}-byte length cap or {}-level nesting cap), skipping normalization",
                    name,
                    raw_marker.len(),
                    MAX_MARKER_LEN,
                    MAX_MARKER_DEPTH
                );
                Some(raw_marker.to_string())
            }
        } else {
            requirement.marker.try_to_string()
        };

        // The marker text starts right after the first `;` in the original
        // requirement string; `pep508_rs` doesn't expose a source span for it.
        let markers_range = markers.as_ref().and_then(|_| {
            let idx = semicolon_idx?;
            value_span.map(|span| {
                span_to_range(
                    content,
                    line_table,
                    toml_span::Span::new(span.start + idx + 1, span.end),
                )
            })
        });

        Ok(PypiDependency {
            name,
            name_range,
            version_req,
            version_range,
            extras,
            extras_range: None,
            markers,
            markers_range,
            section: PypiDependencySection::Dependencies,
            source,
        })
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
        base_position: Option<Position>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<PypiDependency> {
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
                name: name.to_string(),
                name_range,
                version_req: Some(version_str.trim().to_string()),
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
                name: name.to_string(),
                name_range,
                version_req,
                version_range: None,
                extras,
                extras_range: None,
                markers,
                markers_range,
                section: PypiDependencySection::PoetryDependencies,
                source,
            });
        }

        Err(PypiError::unsupported_format(format!(
            "Unsupported Poetry dependency format for '{name}'"
        )))
    }
}

/// Get a nested table value by key from a toml-span Table.
fn get_table<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Table<'a>> {
    table.get(key)?.as_table()
}

/// Convert the start of a toml-span Span to an LSP Position.
///
/// toml-span string spans exclude surrounding quotes, so the span start
/// points directly to the first character of the string content.
fn span_start(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Position {
    line_table.byte_offset_to_position(content, span.start)
}

/// Converts a toml-span byte span to an LSP `Range` using the pre-computed line table.
fn span_to_range(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Range {
    let start = line_table.byte_offset_to_position(content, span.start);
    let end = line_table.byte_offset_to_position(content, span.end);
    Range::new(start, end)
}

/// Parses a raw PEP 508 marker expression and serializes it back through
/// `MarkerTree` for consistency with the PEP 621 requirement-string path,
/// which canonicalizes markers on serialization (e.g. `python_version`
/// comparisons become `python_full_version`).
///
/// Returns `None` for an empty/whitespace-only expression, or one that
/// normalizes to the trivially-true marker (which has no string form, e.g.
/// `os_name == 'a' or os_name != 'a'`) — matching the PEP 621 path, which
/// likewise yields `None` for an absent or always-true marker. Falls back to
/// the raw string, unmodified, if the expression fails to parse or exceeds
/// [`MAX_MARKER_LEN`] or [`MAX_MARKER_DEPTH`].
fn normalize_marker_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > MAX_MARKER_LEN || marker_too_deep(trimmed) {
        tracing::warn!(
            "Marker expression is too complex ({} bytes, over the {}-byte length cap or {}-level nesting cap), skipping normalization: '{}'",
            trimmed.len(),
            MAX_MARKER_LEN,
            MAX_MARKER_DEPTH,
            trimmed
        );
        return Some(trimmed.to_string());
    }
    match MarkerTree::from_str(trimmed) {
        Ok(tree) => tree.try_to_string(),
        Err(e) => {
            tracing::warn!("Failed to parse marker expression '{}': {}", trimmed, e);
            Some(trimmed.to_string())
        }
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

    fn parse(&self, content: &str, doc_uri: &Uri) -> deps_core::error::Result<Self::ParseResult> {
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
        self.source.clone()
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
        assert_eq!(setuptools.version_req, Some(">=61.0".to_string()));

        let maturin = deps.iter().find(|d| d.name == "maturin").unwrap();
        assert_eq!(maturin.version_req, Some(">=1.7, <2.0".to_string()));

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
        //               ^          ^          ^
        //               8          18         29 (positions)
        //               name_start space+ver  version_end

        let parser = PypiParser::new();
        let result = parser.parse_content(toml, &test_uri()).unwrap();
        let deps = &result.dependencies;

        assert_eq!(deps.len(), 1);
        let dep = &deps[0];

        // Version range should cover " >=4.0,<8.0" (with leading space)
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(version_range.start.line, 1);
        // pytest-cov is 10 chars, so version_range starts at 8 + 10 = 18 (the space)
        assert_eq!(version_range.start.character, 18);
        // " >=4.0,<8.0" is 11 chars, so version ends at 18 + 11 = 29
        assert_eq!(version_range.end.character, 29);

        // Verify that cursor at position 21 (on '>') is within version_range
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
        // Unparseable marker text is preserved verbatim rather than dropped.
        assert_eq!(dep.markers, Some("not a valid marker (((".to_string()));
        assert!(dep.markers_range.is_some());
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
        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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
        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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
        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
        assert_eq!(dep.markers, Some("not a valid marker (((".to_string()));
        assert!(dep.markers_range.is_some());
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

        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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
        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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
        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));

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

        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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

        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));

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

        assert_eq!(dep.version_req, Some("^2.28.0".to_string()));
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
        assert_eq!(dep.version_req, Some(">=1.24".to_string()));
        // Skips normalization (would blow the stack in pep508_rs's parser)
        // but preserves the raw marker text rather than dropping it.
        assert_eq!(dep.markers, Some(long_marker));
        assert!(dep.markers_range.is_some());
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
        assert_eq!(dep.version_req, Some(">=1.24".to_string()));
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
        assert_eq!(dep.version_req, Some(">=1.24".to_string()));
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
}
