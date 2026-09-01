//! Cargo.toml parser with position tracking.
//!
//! Parses Cargo.toml files using toml-span to preserve formatting and extract
//! precise LSP positions for every dependency field. Critical for features like
//! hover, completion, and inlay hints.
//!
//! # Key Features
//!
//! - Position-preserving parsing via toml-span spans
//! - Handles all dependency formats: inline, table, workspace inheritance
//! - Extracts dependencies from all sections: dependencies, dev-dependencies, build-dependencies,
//!   including their `[target.<cfg-expr-or-triple>]` variants
//! - Converts byte offsets to LSP Position (line, UTF-16 character)
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::parse_cargo_toml;
//! use tower_lsp_server::ls_types::Uri;
//!
//! let toml = r#"
//! [dependencies]
//! serde = "1.0"
//! "#;
//!
//! let url = Uri::from_file_path("/test/Cargo.toml").unwrap();
//! let result = parse_cargo_toml(toml, &url).unwrap();
//! assert_eq!(result.dependencies.len(), 1);
//! assert_eq!(result.dependencies[0].name, "serde");
//! ```

use crate::config::{AuthToken, RegistryIndex};
use crate::types::{DependencySection, DependencySource, ParsedDependency};
use deps_core::{DepsError, Result};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use toml_span::value::{Table, Value};
use tower_lsp_server::ls_types::{Range, Uri};

pub use deps_core::lsp_helpers::LineOffsetTable;

/// Result of parsing a Cargo.toml file.
///
/// Contains all extracted dependencies with their positions, plus optional
/// workspace root information for resolving inherited dependencies.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// All dependencies found in the file
    pub dependencies: Vec<ParsedDependency>,
    /// Workspace root path if this is a workspace member
    pub workspace_root: Option<PathBuf>,
    /// Document URI
    pub uri: Uri,
    /// Every alternate-registry index this parse resolved (spec FR-002), paired with the
    /// credential (if any) to attach to requests against it.
    ///
    /// `crate::ecosystem::CargoEcosystem::parse_manifest` registers each of these into the
    /// shared `CargoRegistry` router immediately after parsing, so a later
    /// `Registry::get_versions_from` call for the matching
    /// `DependencySource::AlternateRegistry` source can find its (possibly authenticated)
    /// client. Always empty when [`Self::dependencies`] contains no `CustomRegistry`
    /// source (spec NFR-004's zero-extra-work lazy trigger).
    pub resolved_registries: Vec<(RegistryIndex, Option<AuthToken>)>,
}

/// Parses a Cargo.toml file and extracts all dependencies with positions.
///
/// # Errors
///
/// Returns an error if:
/// - TOML syntax is invalid
/// - File path cannot be converted from URL
///
/// # Examples
///
/// ```no_run
/// use deps_cargo::parse_cargo_toml;
/// use tower_lsp_server::ls_types::Uri;
///
/// let toml = r#"
/// [dependencies]
/// serde = "1.0"
/// tokio = { version = "1.0", features = ["full"] }
/// "#;
///
/// let url = Uri::from_file_path("/test/Cargo.toml").unwrap();
/// let result = parse_cargo_toml(toml, &url).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
/// ```
pub fn parse_cargo_toml(content: &str, doc_uri: &Uri) -> Result<ParseResult> {
    if let Err(depth) =
        deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "Cargo.toml".into(),
            source: Box::new(std::io::Error::other(format!(
                "array/table nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_TOML_NESTING_DEPTH
            ))),
        });
    }

    let doc = toml_span::parse(content).map_err(|e| DepsError::ParseError {
        file_type: "Cargo.toml".into(),
        source: Box::new(std::io::Error::other(e.to_string())),
    })?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    let root_table = doc.as_table().ok_or_else(|| DepsError::ParseError {
        file_type: "Cargo.toml".into(),
        source: Box::new(std::io::Error::other("root is not a table")),
    })?;

    parse_dependency_kind_tables(root_table, content, &line_table, &mut dependencies);

    // Parse target-specific dependency tables: [target.<cfg-expr-or-triple>.dependencies],
    // .dev-dependencies, .build-dependencies (#392). Each entry under [target] is keyed by a
    // cfg expression (e.g. `cfg(unix)`) or a target triple; every such table can carry the
    // same three dependency kinds as the top level.
    if let Some(target_val) = get_val(root_table, "target")
        && let Some(target_table) = target_val.as_table()
    {
        for target_entry in target_table.values() {
            if let Some(target_spec_table) = target_entry.as_table() {
                parse_dependency_kind_tables(
                    target_spec_table,
                    content,
                    &line_table,
                    &mut dependencies,
                );
            }
        }
    }

    // Parse workspace dependencies (for workspace root Cargo.toml)
    if let Some(workspace_val) = get_val(root_table, "workspace")
        && let Some(workspace_table) = workspace_val.as_table()
        && let Some(workspace_deps_val) = get_val(workspace_table, "dependencies")
        && let Some(workspace_deps) = workspace_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            workspace_deps,
            content,
            &line_table,
            DependencySection::WorkspaceDependencies,
        ));
    }

    let workspace_root = find_workspace_root(doc_uri)?;

    let resolved_registries = resolve_alternate_registries(&mut dependencies, doc_uri);

    Ok(ParseResult {
        dependencies,
        workspace_root,
        uri: doc_uri.clone(),
        resolved_registries,
    })
}

fn get_val<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Value<'a>> {
    table.get(key)
}

/// Rewrites every `DependencySource::CustomRegistry` entry in `dependencies` into a
/// resolved `DependencySource::AlternateRegistry` when possible (spec FR-002), returning
/// the newly-resolved `(index, auth)` pairs for `crate::ecosystem::CargoEcosystem::parse_manifest`
/// to register into the shared `CargoRegistry` router.
///
/// Two distinct forms reach this function, both stored as `CustomRegistry { url }` by the
/// caller above:
/// - `registry-index = "sparse+https://..."` — `url` is already a concrete index URL, so it
///   resolves directly via [`RegistryIndex::new`], with no `.cargo/config.toml` lookup and
///   no possible credential (a literal URL in `Cargo.toml` is workspace-declared by
///   definition — `auth` is always `None` for this form).
/// - `registry = "<alias>"` — `url` is an alias name, which does not parse as a URL, so it
///   falls through to alias resolution via `crate::config::resolve` against the
///   `.cargo/config.toml` hierarchy plus `$CARGO_HOME/config.toml` (spec FR-003: an alias
///   with no matching entry stays `CustomRegistry`, unchanged, with a `tracing::warn!`).
///
/// A no-op — zero additional filesystem reads (spec NFR-004) — when `dependencies` contains
/// no `CustomRegistry` source at all.
fn resolve_alternate_registries(
    dependencies: &mut [ParsedDependency],
    doc_uri: &Uri,
) -> Vec<(RegistryIndex, Option<AuthToken>)> {
    let raw_values: HashSet<String> = dependencies
        .iter()
        .filter_map(|dep| match &dep.source {
            DependencySource::CustomRegistry { url } => Some(url.clone()),
            _ => None,
        })
        .collect();

    if raw_values.is_empty() {
        return Vec::new();
    }

    let mut aliases: HashSet<String> = HashSet::new();
    // Maps each raw `CustomRegistry.url` value that resolved to its concrete index, so the
    // rewrite pass below can look a dependency's exact declared value back up.
    let mut resolved_by_raw_value: HashMap<String, RegistryIndex> = HashMap::new();
    let mut newly_resolved: Vec<(RegistryIndex, Option<AuthToken>)> = Vec::new();

    for value in &raw_values {
        match RegistryIndex::new(value) {
            Ok(index) => {
                resolved_by_raw_value.insert(value.clone(), index.clone());
                newly_resolved.push((index, None));
            }
            Err(_) => {
                aliases.insert(value.clone());
            }
        }
    }

    if !aliases.is_empty() {
        match doc_uri.to_file_path() {
            Some(manifest_path) => {
                let start_dir = manifest_path
                    .parent()
                    .map_or_else(|| manifest_path.to_path_buf(), std::path::Path::to_path_buf);
                let workspace_paths = crate::config::discover_workspace_config_paths(&start_dir);
                let cargo_home_path = crate::config::cargo_home_config_path();
                let config =
                    crate::config::resolve(&aliases, &workspace_paths, cargo_home_path.as_deref());

                for alias in &aliases {
                    if let Some(entry) = config.get(alias) {
                        resolved_by_raw_value.insert(alias.clone(), entry.index.clone());
                        newly_resolved.push((entry.index.clone(), entry.auth.clone()));
                    } else {
                        tracing::warn!(
                            alias,
                            "registry alias did not resolve via the .cargo/config.toml \
                             hierarchy or $CARGO_HOME/config.toml; dependency stays unresolved"
                        );
                    }
                }
            }
            None => {
                for alias in &aliases {
                    tracing::warn!(
                        alias,
                        "could not determine a directory to search for .cargo/config.toml; \
                         alias stays unresolved"
                    );
                }
            }
        }
    }

    for dep in dependencies.iter_mut() {
        if let DependencySource::CustomRegistry { url } = &dep.source
            && let Some(index) = resolved_by_raw_value.get(url)
        {
            dep.source = DependencySource::AlternateRegistry {
                index: index.as_str().to_string(),
            };
        }
    }

    newly_resolved
}

/// Parses the `dependencies`, `dev-dependencies`, and `build-dependencies` tables
/// nested under `table`, extending `dependencies` with what is found.
///
/// Shared by the manifest root and by each `[target.<spec>]` table, since both
/// carry the same three dependency kinds.
fn parse_dependency_kind_tables(
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    dependencies: &mut Vec<ParsedDependency>,
) {
    if let Some(deps_val) = get_val(table, "dependencies")
        && let Some(deps) = deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            deps,
            content,
            line_table,
            DependencySection::Dependencies,
        ));
    }

    if let Some(dev_deps_val) = get_val(table, "dev-dependencies")
        && let Some(dev_deps) = dev_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            dev_deps,
            content,
            line_table,
            DependencySection::DevDependencies,
        ));
    }

    if let Some(build_deps_val) = get_val(table, "build-dependencies")
        && let Some(build_deps) = build_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            build_deps,
            content,
            line_table,
            DependencySection::BuildDependencies,
        ));
    }
}

/// Parses a single dependency section (dependencies, dev-dependencies, or build-dependencies).
fn parse_dependencies_section(
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    section: DependencySection,
) -> Vec<ParsedDependency> {
    let mut deps = Vec::new();

    for (key, value) in table {
        let name = key.name.to_string();
        let name_range = span_to_range(content, line_table, key.span);

        let mut dep = ParsedDependency {
            name: name.into(),
            name_range,
            version_req: None,
            version_range: None,
            features: Vec::new(),
            features_range: None,
            source: DependencySource::Registry,
            section,
        };

        if let Some(s) = value.as_str() {
            // Simple string version: serde = "1.0"
            dep.version_req = Some(s.into());
            dep.version_range = Some(span_to_range(content, line_table, value.span));
        } else if let Some(t) = value.as_table() {
            // Inline table or full table: serde = { version = "1.0" }
            parse_table_dependency(&mut dep, t, content, line_table);
        } else {
            continue;
        }

        deps.push(dep);
    }

    deps
}

/// Parses a table (inline or full) dependency entry.
fn parse_table_dependency(
    dep: &mut ParsedDependency,
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
) {
    // `toml_span::value::Table` is a `BTreeMap` keyed by field name, so it iterates
    // in alphabetical order (`branch`, `git`, `rev`, `tag`), not TOML source order —
    // `git` cannot be relied on to run before or after `tag`/`branch`/`rev`. The rev
    // value is collected here and applied to `dep.source` once the whole table has
    // been walked, so the result doesn't depend on that ordering (#393).
    let mut git_rev: Option<String> = None;

    for (key, value) in table {
        match key.name.as_ref() {
            "version" => {
                if let Some(s) = value.as_str() {
                    dep.version_req = Some(s.into());
                    dep.version_range = Some(span_to_range(content, line_table, value.span));
                }
            }
            "features" => {
                if let Some(arr) = value.as_array() {
                    dep.features = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    dep.features_range = Some(span_to_range(content, line_table, value.span));
                }
            }
            "workspace" if value.as_bool() == Some(true) => {
                dep.source = DependencySource::Workspace;
            }
            "workspace" => {}
            "git" => {
                if let Some(url) = value.as_str() {
                    dep.source = DependencySource::Git {
                        url: url.to_string(),
                        rev: None,
                    };
                }
            }
            // Cargo allows at most one of these per git dependency; take
            // whichever is present rather than duplicating Cargo's own
            // validation of that constraint.
            "tag" | "branch" | "rev" => {
                if let Some(rev) = value.as_str() {
                    git_rev = Some(rev.to_string());
                }
            }
            "path" => {
                if let Some(path) = value.as_str() {
                    dep.source = DependencySource::Path {
                        path: path.to_string(),
                    };
                }
            }
            // `registry = "my-corp"` names an alternative registry defined in
            // `.cargo/config.toml`, not crates.io. deps-cargo has no client
            // for it, so it must not stay classified as the plain `Registry`
            // source: `CustomRegistry` opts it out of version-resolution
            // diagnostics that would otherwise silently check it against
            // crates.io's unrelated package of the same name (#248, known
            // limitation until private-registry client support exists).
            // `"crates-io"` is Cargo's reserved alias for the *public*
            // registry (not a custom one) and must stay classified as
            // `Registry`.
            "registry" => {
                if let Some(name) = value.as_str()
                    && name != "crates-io"
                {
                    dep.source = DependencySource::CustomRegistry {
                        url: name.to_string(),
                    };
                }
            }
            // `registry-index = "<url>"` is the direct-URL spelling of the
            // same concept as `registry` above. Cargo's built-in public
            // index URLs must stay classified as `Registry`; any other URL
            // names a private index this LSP has no client for.
            "registry-index" => {
                if let Some(url) = value.as_str()
                    && !is_public_crates_io_index(url)
                {
                    dep.source = DependencySource::CustomRegistry {
                        url: url.to_string(),
                    };
                }
            }
            _ => {}
        }
    }

    if let DependencySource::Git { rev, .. } = &mut dep.source {
        *rev = git_rev;
    }
}

/// Returns true if `url` is one of Cargo's built-in public crates.io index URLs
/// (the git index or the sparse index), as opposed to a private registry index.
fn is_public_crates_io_index(url: &str) -> bool {
    matches!(
        url,
        "https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
    )
}

/// Converts toml-span byte offsets to LSP Range using pre-computed line table.
fn span_to_range(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Range {
    let start = line_table.byte_offset_to_position(content, span.start);
    let end = line_table.byte_offset_to_position(content, span.end);
    Range::new(start, end)
}

/// Finds the workspace root by walking up the directory tree.
///
/// Looks for a Cargo.toml file with a [workspace] section.
fn find_workspace_root(doc_uri: &Uri) -> Result<Option<PathBuf>> {
    let path = doc_uri
        .to_file_path()
        .ok_or_else(|| DepsError::InvalidUri(format!("{doc_uri:?}")))?;

    let mut current = path.parent();

    while let Some(dir) = current {
        let workspace_toml = dir.join("Cargo.toml");

        if workspace_toml.exists()
            && let Ok(content) = std::fs::read_to_string(&workspace_toml)
        {
            if deps_core::check_toml_nesting_depth(&content, deps_core::MAX_TOML_NESTING_DEPTH)
                .is_err()
            {
                tracing::warn!(
                    path = %workspace_toml.display(),
                    "skipping ancestor Cargo.toml during workspace root discovery: nesting depth exceeds maximum"
                );
            } else if let Ok(doc) = toml_span::parse(&content)
                && doc
                    .as_table()
                    .and_then(|t| get_val(t, "workspace"))
                    .is_some()
            {
                return Ok(Some(dir.to_path_buf()));
            }
        }

        current = dir.parent();
    }

    Ok(None)
}

/// Parser for Cargo.toml manifests implementing the deps-core traits.
pub struct CargoParser;

// Implement new ParseResult trait for trait object support
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_url() -> Uri {
        #[cfg(windows)]
        let path = "C:/test/Cargo.toml";
        #[cfg(not(windows))]
        let path = "/test/Cargo.toml";
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_cargo_toml_rejects_excessive_nesting() {
        // Well past MAX_TOML_NESTING_DEPTH (64) but far below the depth
        // that would actually overflow the stack, so the guard is what's
        // being exercised here, not the crash itself.
        let content = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        let result = parse_cargo_toml(&content, &test_url());
        assert!(matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "Cargo.toml"
        ));
    }

    #[test]
    fn test_find_workspace_root_rejects_non_file_uri() {
        // Empty path (`Uri::to_file_path` returns `None` only when the path is
        // empty, not merely for a non-file scheme) is what actually drives the
        // `InvalidUri` branch — this pins that call site to `DepsError::InvalidUri`
        // rather than the pre-fix `DepsError::CacheError`.
        let uri: Uri = "https://example.com".parse().unwrap();
        let result = parse_cargo_toml("[dependencies]\nserde = \"1.0\"", &uri);
        assert!(
            matches!(result, Err(DepsError::InvalidUri(_))),
            "expected InvalidUri, got {result:?}"
        );
    }

    #[test]
    fn test_parse_inline_dependency() {
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "serde");
        assert_eq!(result.dependencies[0].version_req, Some("1.0".into()));
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Registry
        ));
    }

    #[test]
    fn test_parse_table_dependency() {
        let toml = r#"[dependencies]
serde = { version = "1.0", features = ["derive"] }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("1.0".into()));
        assert_eq!(result.dependencies[0].features, vec!["derive"]);
    }

    #[test]
    fn test_parse_workspace_inheritance() {
        let toml = r"[dependencies]
serde = { workspace = true }";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Workspace
        ));
    }

    #[test]
    fn test_parse_git_dependency() {
        let toml = r#"[dependencies]
tower-lsp = { git = "https://github.com/ebkalderon/tower-lsp", branch = "main" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { rev, .. } => assert_eq!(rev.as_deref(), Some("main")),
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_git_dependency_with_tag() {
        let toml = r#"[dependencies]
helix-core = { git = "https://github.com/helix-editor/helix", tag = "25.07.1" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { rev, .. } => assert_eq!(rev.as_deref(), Some("25.07.1")),
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_git_dependency_with_rev() {
        let toml = r#"[dependencies]
example = { git = "https://github.com/example/example", rev = "abc123" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { rev, .. } => assert_eq!(rev.as_deref(), Some("abc123")),
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_git_dependency_without_rev_stays_none() {
        let toml = r#"[dependencies]
example = { git = "https://github.com/example/example" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { rev, .. } => assert!(rev.is_none()),
            other => panic!("expected Git, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_path_dependency() {
        let toml = r#"[dependencies]
local = { path = "../local" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Path { .. }
        ));
    }

    #[test]
    fn test_parse_custom_registry_dependency() {
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry = "my-corp" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "my-corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(!result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_parse_registry_crates_io_alias_stays_registry() {
        let toml = r#"[dependencies]
serde = { version = "1.0", registry = "crates-io" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert!(result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_parse_registry_index_custom_url() {
        // A literal `registry-index` URL is already a concrete, fetchable index — it
        // resolves to `AlternateRegistry` directly, with no `.cargo/config.toml` lookup
        // needed (spec FR-002).
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry-index = "https://gitlab.mycorp.com/registry-index" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::AlternateRegistry { index } => {
                assert_eq!(index, "https://gitlab.mycorp.com/registry-index");
            }
            other => panic!("expected AlternateRegistry, got {other:?}"),
        }
        assert_eq!(result.resolved_registries.len(), 1);
        assert!(result.resolved_registries[0].1.is_none());
    }

    #[test]
    fn test_parse_registry_index_invalid_url_stays_custom_registry() {
        // An http:// registry-index URL fails `RegistryIndex` validation, so it must stay
        // unresolved rather than silently downgrading to an insecure fetch.
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry-index = "http://insecure.mycorp.com/index" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "http://insecure.mycorp.com/index");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(result.resolved_registries.is_empty());
    }

    #[test]
    fn test_parse_custom_registry_alias_unresolved_without_config() {
        // No `.cargo/config.toml` exists anywhere above the test fixture path, so the
        // alias stays unresolved (spec FR-003) — this is the pre-existing
        // `test_parse_custom_registry_dependency` scenario, additionally asserting the
        // resolution attempt itself doesn't panic or resolve anything.
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry = "my-corp" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "my-corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(result.resolved_registries.is_empty());
    }

    #[test]
    fn test_parse_custom_registry_alias_resolves_via_workspace_config() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\n",
        )
        .unwrap();

        let manifest_path = root.path().join("Cargo.toml");
        std::fs::write(&manifest_path, "").unwrap();
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry = "my-corp" }"#;
        let result = parse_cargo_toml(toml, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::AlternateRegistry { index } => {
                assert_eq!(index, "https://index.mycorp.dev/");
            }
            other => panic!("expected AlternateRegistry, got {other:?}"),
        }
        assert_eq!(result.resolved_registries.len(), 1);
        assert!(
            result.resolved_registries[0].1.is_none(),
            "workspace-sourced entry must never carry a token"
        );
    }

    #[test]
    fn test_parse_no_custom_registry_dependency_resolves_nothing() {
        // NFR-004: a manifest with no CustomRegistry source resolves nothing at all — the
        // lazy trigger, asserted at the parser's own boundary rather than only inferred
        // from behavior.
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert!(result.resolved_registries.is_empty());
    }

    #[test]
    fn test_parse_registry_index_public_crates_io_stays_registry() {
        let toml = r#"[dependencies]
serde = { version = "1.0", registry-index = "https://github.com/rust-lang/crates.io-index" }
serde_json = { version = "1.0", registry-index = "sparse+https://index.crates.io/" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            assert_eq!(dep.source, DependencySource::Registry);
        }
    }

    #[test]
    fn test_parse_multiple_sections() {
        let toml = r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
insta = "1.0"

[build-dependencies]
cc = "1.0"
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        assert!(matches!(
            result.dependencies[0].section,
            DependencySection::Dependencies
        ));
        assert!(matches!(
            result.dependencies[1].section,
            DependencySection::DevDependencies
        ));
        assert!(matches!(
            result.dependencies[2].section,
            DependencySection::BuildDependencies
        ));
    }

    #[test]
    fn test_parse_target_cfg_dependencies() {
        let toml = "[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "libc");
        assert_eq!(dep.version_req, Some("0.2".into()));
        assert_eq!(dep.source, DependencySource::Registry);
        assert!(matches!(dep.section, DependencySection::Dependencies));

        // Position must point into the target table, not the (nonexistent) top-level one.
        assert_eq!(dep.name_range.start.line, 1);
        assert_eq!(dep.name_range.start.character, 0);
        assert_eq!(dep.name_range.end.character, 4);
    }

    #[test]
    fn test_parse_target_cfg_dev_dependencies() {
        let toml = "[target.'cfg(windows)'.dev-dependencies]\nwinapi = \"0.3\"";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "winapi");
        assert_eq!(dep.version_req, Some("0.3".into()));
        assert!(matches!(dep.section, DependencySection::DevDependencies));
    }

    #[test]
    fn test_parse_target_triple_build_dependencies() {
        let toml = "[target.x86_64-unknown-linux-gnu.build-dependencies]\ncc = \"1.0\"";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "cc");
        assert_eq!(dep.version_req, Some("1.0".into()));
        assert!(matches!(dep.section, DependencySection::BuildDependencies));
    }

    #[test]
    fn test_parse_target_dependencies_alongside_top_level() {
        let toml = r#"
[dependencies]
serde = "1.0"

[target.'cfg(unix)'.dependencies]
libc = { version = "0.2", features = ["extra_traits"] }

[target.'cfg(windows)'.dev-dependencies]
winapi = "0.3"

[target.x86_64-unknown-linux-gnu.build-dependencies]
cc = "1.0"
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 4);

        let serde = result
            .dependencies
            .iter()
            .find(|d| d.name == "serde")
            .unwrap();
        assert!(matches!(serde.section, DependencySection::Dependencies));

        let libc = result
            .dependencies
            .iter()
            .find(|d| d.name == "libc")
            .unwrap();
        assert_eq!(libc.version_req, Some("0.2".into()));
        assert_eq!(libc.features, vec!["extra_traits"]);
        assert!(matches!(libc.section, DependencySection::Dependencies));

        let winapi = result
            .dependencies
            .iter()
            .find(|d| d.name == "winapi")
            .unwrap();
        assert!(matches!(winapi.section, DependencySection::DevDependencies));

        let cc = result.dependencies.iter().find(|d| d.name == "cc").unwrap();
        assert!(matches!(cc.section, DependencySection::BuildDependencies));
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
    fn test_line_offset_table_unicode() {
        let content = "hello 世界\nworld";
        let table = LineOffsetTable::new(content);
        let world_offset = content.find("world").unwrap();
        let pos = table.byte_offset_to_position(content, world_offset);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }

    #[test]
    fn test_malformed_toml() {
        let toml = r#"[dependencies
serde = "1.0"#;
        let result = parse_cargo_toml(toml, &test_url());
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_dependencies() {
        let toml = r"[dependencies]";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_position_tracking() {
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "serde");
        assert_eq!(dep.version_req, Some("1.0".into()));

        // Verify name_range is on line 1 (after [dependencies])
        assert_eq!(dep.name_range.start.line, 1);
        // serde starts at column 0 on that line
        assert_eq!(dep.name_range.start.character, 0);
        // Verify end position is after "serde" (5 characters)
        assert_eq!(dep.name_range.end.character, 5);
    }

    #[test]
    fn test_name_range_tracking() {
        let toml = r#"[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();

        for dep in &result.dependencies {
            // All dependencies should have non-default name ranges
            let is_default = dep.name_range.start.line == 0
                && dep.name_range.start.character == 0
                && dep.name_range.end.line == 0
                && dep.name_range.end.character == 0;
            assert!(
                !is_default,
                "name_range should not be default for {}",
                dep.name
            );
        }
    }

    #[test]
    fn test_parse_workspace_dependencies() {
        let toml = r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        for dep in &result.dependencies {
            assert!(matches!(
                dep.section,
                DependencySection::WorkspaceDependencies
            ));
        }

        let serde = result.dependencies.iter().find(|d| d.name == "serde");
        assert!(serde.is_some());
        let serde = serde.unwrap();
        assert_eq!(serde.version_req, Some("1.0".into()));
        // version_range should be set for inlay hints
        assert!(
            serde.version_range.is_some(),
            "version_range should be set for serde"
        );

        let tokio = result.dependencies.iter().find(|d| d.name == "tokio");
        assert!(tokio.is_some());
        let tokio = tokio.unwrap();
        assert_eq!(tokio.version_req, Some("1.0".into()));
        assert_eq!(tokio.features, vec!["full"]);
        // version_range should be set for inlay hints
        assert!(
            tokio.version_range.is_some(),
            "version_range should be set for tokio"
        );
    }

    #[test]
    fn test_parse_workspace_and_regular_dependencies() {
        let toml = r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
serde = "1.0"

[dependencies]
tokio = "1.0"
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let serde = result.dependencies.iter().find(|d| d.name == "serde");
        assert!(serde.is_some());
        assert!(matches!(
            serde.unwrap().section,
            DependencySection::WorkspaceDependencies
        ));

        let tokio = result.dependencies.iter().find(|d| d.name == "tokio");
        assert!(tokio.is_some());
        assert!(matches!(
            tokio.unwrap().section,
            DependencySection::Dependencies
        ));
    }

    #[test]
    fn test_find_workspace_root_skips_over_depth_ancestor() {
        // Directory layout:
        //   <root>/workspace/Cargo.toml        - valid, has [workspace]
        //   <root>/workspace/mid/Cargo.toml     - malicious: over MAX_TOML_NESTING_DEPTH
        //   <root>/workspace/mid/pkg/Cargo.toml - the file actually opened
        // find_workspace_root must skip the malicious ancestor (log + continue)
        // rather than failing the whole parse, and still find the valid
        // workspace root further up.
        let root = tempfile::tempdir().unwrap();
        let workspace_dir = root.path().join("workspace");
        let mid_dir = workspace_dir.join("mid");
        let pkg_dir = mid_dir.join("pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        std::fs::write(
            workspace_dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"mid/pkg\"]\n",
        )
        .unwrap();

        let malicious = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        std::fs::write(mid_dir.join("Cargo.toml"), malicious).unwrap();

        let opened_content = "[dependencies]\nserde = \"1.0\"\n";
        let opened_path = pkg_dir.join("Cargo.toml");
        std::fs::write(&opened_path, opened_content).unwrap();

        let doc_uri = Uri::from_file_path(&opened_path).unwrap();
        let result = parse_cargo_toml(opened_content, &doc_uri).unwrap();

        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.workspace_root, Some(workspace_dir));
    }
}
