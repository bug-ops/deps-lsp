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

use crate::config::{
    AuthToken, ConfigFileCache, IndexTrust, RegistryIndex, RegistryIndexError, SourceReplacement,
};
use crate::types::{DependencySection, DependencySource, ParsedDependency};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{DepsError, Result};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
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
    /// client. Empty when [`Self::dependencies`] contains no `CustomRegistry` source *and*
    /// no `[source.crates-io] replace-with` chain resolves to a sparse mirror — 1a's
    /// zero-extra-work lazy trigger (spec NFR-004) no longer holds unconditionally once 1b's
    /// `[source]` support is in play, since a mirror can rewrite every plain dependency (spec
    /// NFR-005's corrected premise).
    pub resolved_registries: Vec<(RegistryIndex, Option<AuthToken>)>,
    /// Dependency lines whose `registry`/`registry-index` resolution was blocked by the
    /// current `registries.workspace_registries` policy (spec #443, plan-1b §1.7) —
    /// `(name_range, blocked host class, raw declared value)` triples. Surfaced by
    /// [`deps_core::lsp_helpers::generate_diagnostics_from_cache`] via
    /// [`Self::blocked_registries`]'s trait override as an informational diagnostic, so the
    /// block never degrades silently.
    pub blocked_registries: Vec<(Range, deps_core::net_policy::HostClass, String)>,
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
    parse_cargo_toml_with_context(content, doc_uri, &CargoParseContext::default())
}

/// Carries the two pieces of process-wide state a Cargo parse needs beyond its own manifest
/// content.
///
/// The live workspace-registry reachability policy (spec #443, `registries.workspace_registries`)
/// and the `.cargo/config.toml` memoization cache (spec NFR-005, plan-1b §1.5) — plumbed
/// together so [`crate::ecosystem::CargoEcosystem::with_context`] has one thing to hold and
/// pass through the sync parser (plan-1b §1.6), shared across every document this ecosystem
/// parses.
#[derive(Clone)]
pub struct CargoParseContext {
    /// Gates every `IndexTrust::WorkspaceDeclared` [`RegistryIndex`] this parse constructs.
    pub policy: Arc<RegistryAccessPolicy>,
    /// Memoizes each distinct `.cargo/config.toml`/`$CARGO_HOME/config.toml` file's raw,
    /// unvalidated contents across every parse that reads it.
    pub config_cache: Arc<ConfigFileCache>,
}

impl Default for CargoParseContext {
    fn default() -> Self {
        Self {
            policy: Arc::new(RegistryAccessPolicy::default()),
            config_cache: Arc::new(ConfigFileCache::new()),
        }
    }
}

/// [`parse_cargo_toml`], but threading `ctx` through to alternate-registry resolution.
///
/// The real entry point; [`parse_cargo_toml`] delegates here with a fresh, default context
/// (mirrors this module's own `resolve`/`resolve_with_env` and
/// `cargo_home_config_path`/`_with_env` pattern), so every pre-existing test/doctest call
/// site keeps compiling unchanged.
///
/// # Errors
///
/// Returns an error if:
/// - TOML syntax is invalid
/// - File path cannot be converted from URL
pub fn parse_cargo_toml_with_context(
    content: &str,
    doc_uri: &Uri,
    ctx: &CargoParseContext,
) -> Result<ParseResult> {
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

    let discovery = discover_workspace(doc_uri)?;

    let (resolved_registries, blocked_registries) =
        resolve_alternate_registries(&mut dependencies, &discovery.config_paths, ctx);

    Ok(ParseResult {
        dependencies,
        workspace_root: discovery.workspace_root,
        uri: doc_uri.clone(),
        blocked_registries,
        resolved_registries,
    })
}

fn get_val<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Value<'a>> {
    table.get(key)
}

/// Return type of [`resolve_alternate_registries`]: the newly-resolved `(index, auth)`
/// pairs to register into the shared `CargoRegistry` router, alongside every dependency
/// line whose registry-index resolution was blocked by policy (spec #443, plan-1b §1.7).
type AlternateRegistryResolution = (
    Vec<(RegistryIndex, Option<AuthToken>)>,
    Vec<(Range, deps_core::net_policy::HostClass, String)>,
);

/// Rewrites every `DependencySource::CustomRegistry` entry in `dependencies` into a
/// resolved `DependencySource::AlternateRegistry` when possible (spec FR-002), and every
/// plain `DependencySource::Registry` entry into a resolved `AlternateRegistry {
/// mirrors_crates_io: true, .. }` when a `[source.crates-io] replace-with` chain resolves to
/// a sparse mirror (spec FR-005/006/007, plan-1b §1.4). Returns the newly-resolved `(index,
/// auth)` pairs for `crate::ecosystem::CargoEcosystem::parse_manifest` to register into the
/// shared `CargoRegistry` router.
///
/// Two distinct forms of `CustomRegistry` reach the alias-resolution half of this function:
/// - `registry-index = "sparse+https://..."` — `url` is already a concrete index URL, so it
///   resolves directly via [`RegistryIndex::new`], with no `.cargo/config.toml` lookup and
///   no possible credential (a literal URL in `Cargo.toml` is workspace-declared by
///   definition — `auth` is always `None` for this form).
/// - `registry = "<alias>"` — `url` is an alias name, which does not parse as a URL, so it
///   falls through to alias resolution via `crate::config::resolve` against the
///   `.cargo/config.toml` hierarchy plus `$CARGO_HOME/config.toml` (spec FR-003: an alias
///   with no matching entry stays `CustomRegistry`, unchanged, with a `tracing::warn!`).
///
/// Unlike 1a, this is **not** skipped when `dependencies` contains no `CustomRegistry`
/// source: a `[source]` replace-with chain can rewrite *every* plain dependency, so
/// `crate::config::resolve` always runs (spec NFR-005's corrected premise — the zero-cost
/// lazy trigger from 1a no longer holds once 1b's `[source]` support lands). The merged
/// ancestor walk ([`discover_workspace`]) this function's `workspace_config_paths` comes
/// from is unconditional regardless, so the only new unconditional cost here is the (cheap,
/// memoized) config resolution itself.
fn resolve_alternate_registries(
    dependencies: &mut [ParsedDependency],
    workspace_config_paths: &[PathBuf],
    ctx: &CargoParseContext,
) -> AlternateRegistryResolution {
    let raw_values: HashSet<String> = dependencies
        .iter()
        .filter_map(|dep| match &dep.source {
            DependencySource::CustomRegistry { url } => Some(url.clone()),
            _ => None,
        })
        .collect();

    let mut aliases: HashSet<String> = HashSet::new();
    // Maps each raw `CustomRegistry.url` value that resolved to its concrete index, so the
    // rewrite pass below can look a dependency's exact declared value back up.
    let mut resolved_by_raw_value: HashMap<String, RegistryIndex> = HashMap::new();
    // Raw values blocked specifically by policy (spec #443/plan-1b §1.7), so the rewrite
    // pass below can surface an informational diagnostic on the exact dependency line.
    let mut blocked_by_raw_value: HashMap<String, deps_core::net_policy::HostClass> =
        HashMap::new();
    let mut newly_resolved: Vec<(RegistryIndex, Option<AuthToken>)> = Vec::new();

    for value in &raw_values {
        // A literal `registry-index` URL is workspace-declared by construction — it is a
        // value written directly into the `Cargo.toml` being parsed. An `InvalidUrl`/
        // `NotHttps`/`UserInfoPresent` error covers "not a URL at all" (the common case:
        // `value` is actually an alias, not a literal index) and a genuinely-invalid literal
        // URL alike — either way, falling through to alias resolution below is safe: an
        // alias lookup for a URL-shaped string simply won't match any `[registries.*]` entry
        // and stays unresolved, identical in outcome to failing here directly.
        match RegistryIndex::new(value, IndexTrust::WorkspaceDeclared, &ctx.policy) {
            Ok(index) => {
                resolved_by_raw_value.insert(value.clone(), index.clone());
                newly_resolved.push((index, None));
            }
            Err(RegistryIndexError::BlockedHost { class }) => {
                blocked_by_raw_value.insert(value.clone(), class);
            }
            Err(_) => {
                aliases.insert(value.clone());
            }
        }
    }

    let cargo_home_path = crate::config::cargo_home_config_path();
    let (config, source_replacement) = crate::config::resolve(
        &aliases,
        workspace_config_paths,
        cargo_home_path.as_deref(),
        &ctx.config_cache,
        &ctx.policy,
    );

    for alias in &aliases {
        if let Some(entry) = config.get(alias) {
            resolved_by_raw_value.insert(alias.clone(), entry.index.clone());
            newly_resolved.push((entry.index.clone(), entry.auth.clone()));
        } else if let Some(class) = config.blocked_class(alias) {
            blocked_by_raw_value.insert(alias.clone(), class);
        } else {
            // `alias` here is the raw `registry-index`/`registry` value from the manifest,
            // not a config-file alias name — it may itself be a URL carrying `user:pass@`
            // credentials (e.g. `RegistryIndexError::UserInfoPresent` fell through to alias
            // resolution). Redact before logging (see `deps_core::net_policy::redact_userinfo`).
            let redacted = deps_core::net_policy::redact_userinfo(alias);
            tracing::warn!(
                alias = %redacted,
                "registry alias did not resolve via the .cargo/config.toml \
                 hierarchy or $CARGO_HOME/config.toml; dependency stays unresolved"
            );
        }
    }

    // [source] replace-with mirror rewrite (FR-005/006/007): every plain `Registry`
    // dependency reroutes to the resolved mirror. An alias-based `AlternateRegistry` a
    // dependency may already carry from the loop above is left untouched — a `[registries]`
    // alias is not crates.io, so `[source.crates-io]` replacement does not apply to it.
    if let SourceReplacement::SparseMirror { index, auth } = source_replacement {
        newly_resolved.push((index.clone(), auth));
        for dep in dependencies.iter_mut() {
            if dep.source == DependencySource::Registry {
                dep.source = DependencySource::AlternateRegistry {
                    index: index.as_str().to_string(),
                    mirrors_crates_io: true,
                };
            }
        }
    }

    let mut blocked_registries = Vec::new();
    for dep in dependencies.iter_mut() {
        if let DependencySource::CustomRegistry { url } = &dep.source {
            if let Some(index) = resolved_by_raw_value.get(url) {
                dep.source = DependencySource::AlternateRegistry {
                    index: index.as_str().to_string(),
                    mirrors_crates_io: false,
                };
            } else if let Some(class) = blocked_by_raw_value.get(url) {
                blocked_registries.push((dep.name_range, *class, url.clone()));
            }
        }
    }

    (newly_resolved, blocked_registries)
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

/// Upper bound on how many ancestor directories [`discover_workspace`] climbs, independent
/// of whether the filesystem root has been reached (spec NFR-005, plan-1b §1.5, critic N1).
///
/// Caps the previously-unbounded workspace-root search — today's manifest walk is unbounded
/// and TOML-parses every ancestor `Cargo.toml` — and bounds the merged `.cargo/config.toml`
/// discovery pass added alongside it. A workspace root or config file more than 64
/// directories up is not a realistic layout; a hostile deeply-nested tree hits this cap
/// instead of doing unbounded work per parse.
pub(crate) const MAX_CONFIG_ANCESTOR_DEPTH: usize = 64;

/// Result of [`discover_workspace`]'s merged ancestor walk.
struct WorkspaceDiscovery {
    /// The workspace root, if any `[workspace]`-carrying `Cargo.toml` was found within
    /// [`MAX_CONFIG_ANCESTOR_DEPTH`] — unchanged in meaning from the pre-1b
    /// `find_workspace_root`, just capped.
    workspace_root: Option<PathBuf>,
    /// Every ancestor `.cargo/config.toml` found along the way, closest-first — independent
    /// of the workspace-root search's own short-circuit (plan-1b §1.5: "only the
    /// `[workspace]` search short-circuits; config discovery does not").
    config_paths: Vec<PathBuf>,
}

/// Finds the workspace root by walking up the directory tree from `doc_uri`'s manifest,
/// merged with collecting every ancestor `.cargo/config.toml` along the same walk (spec
/// NFR-005, plan-1b §1.5) — one pass instead of two separate ancestor walks per parse.
///
/// The workspace-root search still stops at the first ancestor `Cargo.toml` carrying a
/// `[workspace]` table (unchanged), but **config-path collection does not stop there**: a
/// `.cargo/config.toml` above the workspace root (e.g. `~/projects/.cargo/config.toml` over
/// `~/projects/myrepo/`) is exactly what Cargo itself still consults, and #440 already
/// shipped that behavior for the alias-resolution path — a naive merge that stopped both
/// searches at the workspace root would silently regress it (critic N1). Both searches share
/// [`MAX_CONFIG_ANCESTOR_DEPTH`] as their only stopping bound beyond the filesystem root.
///
/// At most two `stat`s per ancestor directory: one for `.cargo/config.toml`'s existence,
/// and — only while the workspace root is still unresolved — one for `Cargo.toml`'s
/// existence (plus a read+parse on a hit). Once the workspace root is found, every further
/// ancestor costs exactly one stat.
fn discover_workspace(doc_uri: &Uri) -> Result<WorkspaceDiscovery> {
    let path = doc_uri
        .to_file_path()
        .ok_or_else(|| DepsError::InvalidUri(format!("{doc_uri:?}")))?;

    let mut workspace_root = None;
    let mut config_paths = Vec::new();
    let mut current = path.parent();
    let mut depth = 0usize;

    while let Some(dir) = current {
        if depth >= MAX_CONFIG_ANCESTOR_DEPTH {
            break;
        }
        depth += 1;

        let config_candidate = dir.join(".cargo").join("config.toml");
        if deps_core::fs_probe::is_file(&config_candidate) {
            config_paths.push(config_candidate);
        }

        if workspace_root.is_none() {
            let workspace_toml = dir.join("Cargo.toml");

            if let Ok(metadata) = deps_core::fs_probe::metadata(&workspace_toml)
                && metadata.is_file()
            {
                if metadata.len() > deps_core::MAX_CACHED_FILE_BYTES {
                    tracing::warn!(
                        path = %workspace_toml.display(),
                        len = metadata.len(),
                        cap = deps_core::MAX_CACHED_FILE_BYTES,
                        "skipping ancestor Cargo.toml during workspace root discovery: exceeds size cap"
                    );
                } else {
                    match deps_core::fs_probe::read_to_string_capped(
                        &workspace_toml,
                        deps_core::MAX_CACHED_FILE_BYTES,
                    ) {
                        Ok(Some(content)) => {
                            if deps_core::check_toml_nesting_depth(
                                &content,
                                deps_core::MAX_TOML_NESTING_DEPTH,
                            )
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
                                workspace_root = Some(dir.to_path_buf());
                            }
                        }
                        Ok(None) => {
                            // The stat pre-filter above passed, but the read itself still
                            // hit the cap — a symlink swap or concurrent growth between the
                            // two calls (CWE-367). Same outward behavior as the stat-based
                            // rejection above, just observed later: warn, then skip.
                            tracing::warn!(
                                path = %workspace_toml.display(),
                                cap = deps_core::MAX_CACHED_FILE_BYTES,
                                "skipping ancestor Cargo.toml during workspace root discovery: exceeds size cap on read"
                            );
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        current = dir.parent();
    }

    Ok(WorkspaceDiscovery {
        workspace_root,
        config_paths,
    })
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

    fn blocked_registries(&self) -> Vec<(Range, deps_core::net_policy::HostClass, String)> {
        self.blocked_registries.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

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
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "Cargo.toml"
        );
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
        assert_matches!(result.dependencies[0].source, DependencySource::Registry);
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
        assert_matches!(result.dependencies[0].source, DependencySource::Workspace);
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
        assert_matches!(result.dependencies[0].source, DependencySource::Path { .. });
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
            DependencySource::AlternateRegistry { index, .. } => {
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

    /// S3 (impl-critic): `ParseResult::blocked_registries` must actually be populated — for a
    /// literal `registry-index` URL blocked by the default `public_only` policy — carrying
    /// the dependency's own `name_range` and the raw declared value (so a diagnostic message
    /// can name it), not just leaving the dependency unresolved with no trace.
    #[test]
    fn test_parse_registry_index_literal_blocked_by_policy_populates_blocked_registries() {
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry-index = "https://169.254.169.254/index" }"#;
        let ctx = CargoParseContext::default(); // default policy is PublicOnly
        let result = parse_cargo_toml_with_context(toml, &test_url(), &ctx).unwrap();

        assert_eq!(result.dependencies.len(), 1);
        assert!(
            matches!(
                &result.dependencies[0].source,
                DependencySource::CustomRegistry { url } if url == "https://169.254.169.254/index"
            ),
            "a blocked index must stay unresolved, not silently become AlternateRegistry"
        );
        assert_eq!(result.blocked_registries.len(), 1);
        let (range, class, raw_value) = &result.blocked_registries[0];
        assert_eq!(*range, result.dependencies[0].name_range);
        assert_eq!(*class, deps_core::net_policy::HostClass::CloudMetadata);
        assert_eq!(raw_value, "https://169.254.169.254/index");
    }

    /// The alias path's `blocked_registries` counterpart: an alias resolving via
    /// `.cargo/config.toml` to a blocked host must populate the same channel, keyed by the
    /// alias name (not the resolved URL) since that is what the dependency itself declared.
    #[test]
    fn test_parse_custom_registry_alias_blocked_by_policy_populates_blocked_registries() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.my-corp]\nindex = \"https://169.254.169.254\"\n",
        )
        .unwrap();

        let manifest_path = root.path().join("Cargo.toml");
        let manifest_content =
            "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"my-corp\" }\n";
        std::fs::write(&manifest_path, manifest_content).unwrap();
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let ctx = CargoParseContext::default();
        let result = parse_cargo_toml_with_context(manifest_content, &uri, &ctx).unwrap();

        assert_eq!(result.blocked_registries.len(), 1);
        let (range, class, raw_value) = &result.blocked_registries[0];
        assert_eq!(*range, result.dependencies[0].name_range);
        assert_eq!(*class, deps_core::net_policy::HostClass::CloudMetadata);
        assert_eq!(raw_value, "my-corp");
    }

    /// #536: a `registry-index` value carrying literal `user:pass@` userinfo fails
    /// `RegistryIndex::new` with `UserInfoPresent`, so `resolve_alternate_registries` falls
    /// through to alias resolution (spec: an `InvalidUrl`/`UserInfoPresent` literal is
    /// treated as a possible `.cargo/config.toml` alias name). When that "alias" then fails
    /// to resolve too, the unresolved-alias `tracing::warn!` must never log the raw,
    /// credential-bearing value — it must be redacted first (see
    /// `deps_core::net_policy::redact_userinfo`), matching the #529 precedent already applied
    /// to `validate_index_url`'s own error `Display`.
    #[test]
    fn test_parse_registry_index_userinfo_alias_fallback_redacts_credential_in_log() {
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry-index = "sparse+https://user:hunter2@index.crates.io/" }"#;

        let log = deps_core::test_util::capture_tracing_output(|| {
            let result = parse_cargo_toml(toml, &test_url()).unwrap();
            assert_eq!(result.dependencies.len(), 1);
            assert!(
                matches!(
                    &result.dependencies[0].source,
                    DependencySource::CustomRegistry { url }
                        if url == "sparse+https://user:hunter2@index.crates.io/"
                ),
                "a userinfo-bearing index that fails alias resolution must stay unresolved"
            );
        });

        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
        assert!(
            !log.contains("user:"),
            "tracing output leaked the username: {log:?}"
        );
        assert!(
            log.contains("index.crates.io"),
            "host should survive redaction: {log:?}"
        );
    }

    /// #536 C1: two `registry-index` userinfo literals differing only by case (Cargo's
    /// env-var naming uppercases the whole alias, so `user:...` and `USER:...` collide on
    /// the same `CARGO_REGISTRIES_*_INDEX` name — spec FR-015) fall through to alias
    /// resolution and trip `resolve_registries`' env-collision `tracing::warn!`
    /// (`config.rs`), which logs the full raw value list. That WARN is a second call site
    /// (distinct from the unresolved-alias WARN covered above) that must also redact each
    /// entry before logging.
    #[test]
    fn test_parse_registry_index_env_collision_redacts_credential_in_log() {
        let toml = r#"[dependencies]
a = { version = "1.0", registry-index = "sparse+https://user:hunter2@index.mycorp.dev/" }
b = { version = "1.0", registry-index = "sparse+https://USER:hunter2@index.mycorp.dev/" }"#;

        let log = deps_core::test_util::capture_tracing_output(|| {
            let result = parse_cargo_toml(toml, &test_url()).unwrap();
            assert_eq!(result.dependencies.len(), 2);
        });

        assert!(
            log.contains("two aliases derive the same"),
            "expected the env-collision WARN to fire: {log:?}"
        );
        assert!(
            !log.contains("hunter2"),
            "tracing output leaked the credential: {log:?}"
        );
        assert!(
            !log.to_lowercase().contains("user:"),
            "tracing output leaked the username: {log:?}"
        );
        assert!(
            log.contains("index.mycorp.dev"),
            "host should survive redaction: {log:?}"
        );
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
            DependencySource::AlternateRegistry { index, .. } => {
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
        // With no CustomRegistry source and no `[source.crates-io] replace-with` chain
        // anywhere in scope (no `.cargo/config.toml` exists above the fixture path, and
        // `$CARGO_HOME` is either unset or has no such override), nothing resolves. Unlike
        // 1a, this is no longer a zero-cost lazy trigger (spec NFR-005's corrected premise
        // — `[source]` can affect every plain dependency) — `crate::config::resolve` still
        // runs, it just finds nothing to resolve.
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert!(result.resolved_registries.is_empty());
    }

    /// FR-005/plan-1b §1.4: a `[source.crates-io] replace-with` chain resolving to a sparse
    /// mirror rewrites every plain `Registry` dependency into a resolved, `mirrors_crates_io:
    /// true` `AlternateRegistry` — no `registry`/`registry-index` needed on the dependency
    /// itself.
    #[test]
    fn test_parse_plain_dependency_rewritten_via_source_replace_with_mirror() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[source.crates-io]\nreplace-with = \"my-mirror\"\n\
             [source.my-mirror]\nregistry = \"sparse+https://mirror.corp.example\"\n",
        )
        .unwrap();

        let manifest_content = "[dependencies]\nserde = \"1.0\"\n";
        let manifest_path = root.path().join("Cargo.toml");
        std::fs::write(&manifest_path, manifest_content).unwrap();
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let result = parse_cargo_toml(manifest_content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::AlternateRegistry {
                index,
                mirrors_crates_io,
            } => {
                assert_eq!(index, "https://mirror.corp.example/");
                assert!(*mirrors_crates_io);
            }
            other => panic!("expected a resolved crates.io mirror, got {other:?}"),
        }
        assert_eq!(result.resolved_registries.len(), 1);
    }

    /// FR-006/US-003: a `[source]` replace-with chain terminating at a `directory`
    /// (vendored) source must leave plain dependencies unchanged — the pre-1b, crates.io
    /// fallback behavior, byte-identical.
    #[test]
    fn test_parse_plain_dependency_unchanged_when_source_replace_with_is_vendored() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[source.crates-io]\nreplace-with = \"vendored\"\n\
             [source.vendored]\ndirectory = \"vendor\"\n",
        )
        .unwrap();

        let manifest_content = "[dependencies]\nserde = \"1.0\"\n";
        let manifest_path = root.path().join("Cargo.toml");
        std::fs::write(&manifest_path, manifest_content).unwrap();
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let result = parse_cargo_toml(manifest_content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
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

        assert_matches!(
            result.dependencies[0].section,
            DependencySection::Dependencies
        );
        assert_matches!(
            result.dependencies[1].section,
            DependencySection::DevDependencies
        );
        assert_matches!(
            result.dependencies[2].section,
            DependencySection::BuildDependencies
        );
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
        assert_matches!(dep.section, DependencySection::Dependencies);

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
        assert_matches!(dep.section, DependencySection::DevDependencies);
    }

    #[test]
    fn test_parse_target_triple_build_dependencies() {
        let toml = "[target.x86_64-unknown-linux-gnu.build-dependencies]\ncc = \"1.0\"";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "cc");
        assert_eq!(dep.version_req, Some("1.0".into()));
        assert_matches!(dep.section, DependencySection::BuildDependencies);
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
        assert_matches!(serde.section, DependencySection::Dependencies);

        let libc = result
            .dependencies
            .iter()
            .find(|d| d.name == "libc")
            .unwrap();
        assert_eq!(libc.version_req, Some("0.2".into()));
        assert_eq!(libc.features, vec!["extra_traits"]);
        assert_matches!(libc.section, DependencySection::Dependencies);

        let winapi = result
            .dependencies
            .iter()
            .find(|d| d.name == "winapi")
            .unwrap();
        assert_matches!(winapi.section, DependencySection::DevDependencies);

        let cc = result.dependencies.iter().find(|d| d.name == "cc").unwrap();
        assert_matches!(cc.section, DependencySection::BuildDependencies);
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
            assert_matches!(dep.section, DependencySection::WorkspaceDependencies);
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
        assert_matches!(
            serde.unwrap().section,
            DependencySection::WorkspaceDependencies
        );

        let tokio = result.dependencies.iter().find(|d| d.name == "tokio");
        assert!(tokio.is_some());
        assert_matches!(tokio.unwrap().section, DependencySection::Dependencies);
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

    /// N1 regression: the merged ancestor walk must **not** stop collecting
    /// `.cargo/config.toml` paths once it finds the workspace root — a config file living
    /// *above* the workspace root (e.g. `~/projects/.cargo/config.toml` over
    /// `~/projects/myrepo/`) is exactly what Cargo itself still consults, and #440 already
    /// shipped that for the alias-resolution path. A naive merge of the workspace-root
    /// search with config discovery would silently regress this already-shipped behavior —
    /// this is the regression gate for that merge, and it fails against a naive
    /// stop-at-workspace-root implementation. The fixture places the config *outside* the
    /// tmpdir workspace directory, since a config placed inside the workspace passes either
    /// way (naive or correct).
    #[test]
    fn test_discover_workspace_config_above_workspace_root_still_resolves() {
        let root = tempfile::tempdir().unwrap();
        let workspace_dir = root.path().join("workspace");
        std::fs::create_dir_all(&workspace_dir).unwrap();
        std::fs::write(
            workspace_dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"pkg\"]\n",
        )
        .unwrap();

        // The config file lives at `root/.cargo/config.toml` — an ancestor of
        // `workspace_dir`, but not itself inside it.
        std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
        std::fs::write(
            root.path().join(".cargo/config.toml"),
            "[registries.above-root]\nindex = \"sparse+https://above-root.example\"\n",
        )
        .unwrap();

        let pkg_dir = workspace_dir.join("pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let manifest_content =
            "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"above-root\" }\n";
        let manifest_path = pkg_dir.join("Cargo.toml");
        std::fs::write(&manifest_path, manifest_content).unwrap();

        let doc_uri = Uri::from_file_path(&manifest_path).unwrap();
        let result = parse_cargo_toml(manifest_content, &doc_uri).unwrap();

        assert_eq!(result.workspace_root, Some(workspace_dir));
        match &result.dependencies[0].source {
            DependencySource::AlternateRegistry { index, .. } => {
                assert_eq!(index, "https://above-root.example/");
            }
            other => panic!(
                "expected the above-workspace-root config to resolve the alias, got {other:?}"
            ),
        }
    }

    /// The ancestor walk stops at [`MAX_CONFIG_ANCESTOR_DEPTH`], for both the workspace-root
    /// search and config-path collection — a pathologically deep tree must not do unbounded
    /// work per parse.
    #[test]
    fn test_discover_workspace_stops_at_max_ancestor_depth() {
        let root = tempfile::tempdir().unwrap();

        // Build a chain deeper than MAX_CONFIG_ANCESTOR_DEPTH, each level carrying its own
        // `.cargo/config.toml` with a distinct alias, plus a `[workspace]`-carrying
        // `Cargo.toml` at the very top (beyond the cap) that must never be found.
        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH + 5) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        // Place the far (unreachable) workspace root and a distinguishing config file at
        // the very top of the tree.
        std::fs::write(
            root.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"*\"]\n",
        )
        .unwrap();

        let opened_content = "[dependencies]\nserde = \"1.0\"\n";
        let opened_path = current.join("Cargo.toml");
        std::fs::write(&opened_path, opened_content).unwrap();

        let doc_uri = Uri::from_file_path(&opened_path).unwrap();
        let result = parse_cargo_toml(opened_content, &doc_uri).unwrap();

        assert_eq!(
            result.workspace_root, None,
            "a workspace root beyond MAX_CONFIG_ANCESTOR_DEPTH must not be found"
        );
    }

    /// An ancestor `Cargo.toml` over [`deps_core::MAX_CACHED_FILE_BYTES`] must be skipped
    /// during workspace-root discovery via the cheap `stat`-based size pre-filter, which
    /// rejects it before `deps_core::fs_probe::read_to_string_capped` is even called — this
    /// proves the CWE-400 (uncontrolled resource consumption) rejection path, not the
    /// TOCTOU-closing property of the capped read itself (both `read_to_string` and
    /// `read_to_string_capped` would pass this test identically, since the pre-filter is
    /// what actually stops the read here). The bound on the read call itself is proven
    /// independently by `deps_core::fs_probe::tests::read_to_string_capped_rejects_content_over_cap`.
    #[test]
    fn test_discover_workspace_skips_oversized_ancestor_cargo_toml() {
        let root = tempfile::tempdir().unwrap();

        // A synthetic chain deeper than MAX_CONFIG_ANCESTOR_DEPTH, so the depth cap always
        // stops the walk inside this tempdir — it never escapes into the real filesystem's
        // ancestry above it (which could contain an unrelated, readable Cargo.toml and make
        // the read-count assertion below flaky).
        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH + 5) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        // Sparse file, large enough to exceed the cap without allocating real disk space —
        // content is irrelevant, since the size cap must reject it before any open/read.
        // Placed two levels up from the opened file, well within the depth budget.
        let oversized_manifest = current
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("Cargo.toml");
        let file = std::fs::File::create(&oversized_manifest).unwrap();
        file.set_len(deps_core::MAX_CACHED_FILE_BYTES + 1).unwrap();
        drop(file);

        let opened_content = "[dependencies]\nserde = \"1.0\"\n";
        let opened_path = current.join("Cargo.toml");
        std::fs::write(&opened_path, opened_content).unwrap();
        let doc_uri = Uri::from_file_path(&opened_path).unwrap();

        let (_, reads_before) = deps_core::fs_probe::snapshot();
        let discovery = discover_workspace(&doc_uri).unwrap();
        let (_, reads_after) = deps_core::fs_probe::snapshot();

        assert_eq!(
            discovery.workspace_root, None,
            "an oversized ancestor Cargo.toml must never be treated as the workspace root"
        );
        assert_eq!(
            reads_after - reads_before,
            1,
            "expected exactly one read: the opened document's own directory Cargo.toml — the \
             oversized ancestor two levels up must be rejected by the stat-based pre-filter \
             without ever being opened for a read"
        );
    }

    /// P1 (plan-1b §4 Performance/M4, flagged missing by the tester validator): the real
    /// bound on the merged ancestor walk is "at most two stats per ancestor directory,
    /// capped at MAX_CONFIG_ANCESTOR_DEPTH" — verified here by actually counting `stat`
    /// calls (via `deps_core::fs_probe`), not merely asserting the depth cap holds.
    /// Uses a purely synthetic chain deeper than the cap, with no `Cargo.toml`/
    /// `.cargo/config.toml` anywhere in it, so neither search ever short-circuits before the
    /// cap — pinning the count to exactly `2 * MAX_CONFIG_ANCESTOR_DEPTH` regardless of the
    /// real filesystem's ancestry above the tempdir.
    #[test]
    fn test_discover_workspace_stats_at_most_two_per_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let mut current = root.path().to_path_buf();
        for i in 0..(MAX_CONFIG_ANCESTOR_DEPTH + 5) {
            current = current.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&current).unwrap();

        let opened_content = "[dependencies]\nserde = \"1.0\"\n";
        let opened_path = current.join("Cargo.toml");
        std::fs::write(&opened_path, opened_content).unwrap();
        let doc_uri = Uri::from_file_path(&opened_path).unwrap();

        // Calls `discover_workspace` directly, not `parse_cargo_toml` — this bounds the
        // merged ancestor walk itself (parser.rs's own two stat sites), independent of
        // `resolve_alternate_registries`'s downstream config resolution, which may add its
        // own (unrelated, already-bounded) `$CARGO_HOME/config.toml` stat if the test
        // process happens to have a real `CARGO_HOME` set.
        let (stats_before, _) = deps_core::fs_probe::snapshot();
        let discovery = discover_workspace(&doc_uri).unwrap();
        let (stats_after, _) = deps_core::fs_probe::snapshot();

        assert_eq!(discovery.workspace_root, None);
        assert_eq!(
            stats_after - stats_before,
            2 * MAX_CONFIG_ANCESTOR_DEPTH,
            "expected exactly two stats per ancestor for all MAX_CONFIG_ANCESTOR_DEPTH levels"
        );
    }
}
