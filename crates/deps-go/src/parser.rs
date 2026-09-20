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

use crate::config::{GoParseContext, GoProxyChain};
use crate::types::{GoDependency, GoDirective};
use deps_core::Result;
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use regex::Regex;
use url::Url;

/// Fixed declaration key for every [`GoParseResult::blocked_registries`] entry (#958) — see
/// that field's doc for why a single `GOPROXY` declaration must always dedupe to one
/// diagnostic, unlike Cargo/npm's per-alias declaration keys.
const GOPROXY_BLOCKED_DECLARATION_KEY: &str = "goproxy";

/// Result of parsing a go.mod file.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GoParseResult {
    /// All dependencies found in the file
    pub dependencies: Vec<GoDependency>,
    /// Module path declared in `module` directive
    pub module_path: Option<String>,
    /// Minimum Go version from `go` directive
    pub go_version: Option<String>,
    /// Document URI
    pub uri: Url,
    /// Every `$GOENV`-resolved `GOPROXY`/`GOPRIVATE`-bypass chain this parse implies (spec
    /// 034), ready for `GoRegistry::register_alternate`. Empty when `$GOENV` declares no
    /// override (US-005).
    pub resolved_chains: Vec<GoProxyChain>,
    /// One [`deps_core::BlockedRegistryOccurrence`] per `require`/`replace`/`exclude` module
    /// line whose resolution fell back to [`deps_core::parser::DependencySource::CustomRegistry`]
    /// because every `GOPROXY` hop was rejected by the current `registries.workspace_registries`
    /// policy (#958, mirrors `deps_cargo::parser::CargoParseResult::blocked_registries`).
    ///
    /// Unlike Cargo/npm's per-alias declarations, `GOPROXY` is a single config-global
    /// declaration (one `$GOENV` value shared by every module in the document), so every entry
    /// here shares the same fixed `GOPROXY_BLOCKED_DECLARATION_KEY` — `deps_core`'s
    /// `blocked_registry_diagnostics` groups by that key and collapses the group into one
    /// diagnostic with the other affected modules named as `related_information`. Surfaced via
    /// [`Self::blocked_registries`]'s trait override as an informational diagnostic, so the
    /// block never degrades silently.
    pub blocked_registries: Vec<deps_core::BlockedRegistryOccurrence>,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// Parses a go.mod file and extracts all dependencies with positions, using a fresh, default
/// [`GoParseContext`].
///
/// No live `$GOENV` policy handle — every dependency resolves to plain
/// [`deps_core::parser::DependencySource::Registry`], byte-identical to pre-#519 behavior.
/// Production parsing goes through [`parse_go_mod_with_context`] instead.
///
/// # Errors
///
/// Infallible by construction: unrecognized lines are skipped rather than erroring.
/// Returns [`Result`] only to match the shared parser signature every ecosystem implements.
pub fn parse_go_mod(content: &str, doc_uri: &Url) -> Result<GoParseResult> {
    parse_go_mod_with_context(content, doc_uri, &GoParseContext::default())
}

/// Parses a go.mod file and extracts all dependencies with positions.
///
/// Resolves each dependency's [`deps_core::parser::DependencySource`] against `ctx`'s
/// `$GOENV`-derived `GOPROXY`/`GOPRIVATE` configuration (spec 034 FR-002/FR-007/FR-008/FR-009).
///
/// # Errors
///
/// Same as [`parse_go_mod`].
pub fn parse_go_mod_with_context(
    content: &str,
    doc_uri: &Url,
    ctx: &GoParseContext,
) -> Result<GoParseResult> {
    tracing::debug!(uri = ?doc_uri, "Parsing go.mod file");

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::with_capacity(50);
    let mut module_path = None;
    let mut go_version = None;

    // Compile-time-constant patterns; a malformed literal is a build-visible programmer
    // error, not attacker-influenceable input.
    #[allow(clippy::unwrap_used)]
    static MODULE_PATTERN: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\s*module\s+(\S+)").unwrap());
    // Same guarantee as MODULE_PATTERN above.
    #[allow(clippy::unwrap_used)]
    static GO_PATTERN: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\s*go\s+(\S+)").unwrap());
    // Same guarantee as MODULE_PATTERN above.
    #[allow(clippy::unwrap_used)]
    static REQUIRE_SINGLE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\s*require\s+(\S+)\s+(\S+)").unwrap());
    // Same guarantee as MODULE_PATTERN above.
    #[allow(clippy::unwrap_used)]
    static REQUIRE_BLOCK_START: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\s*require\s*\(").unwrap());
    // Same guarantee as MODULE_PATTERN above.
    #[allow(clippy::unwrap_used)]
    static REPLACE_PATTERN: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^\s*replace\s+(\S+)\s+(?:(\S+)\s+)?=>\s+(\S+)\s+(\S+)").unwrap()
    });
    // Same guarantee as MODULE_PATTERN above.
    #[allow(clippy::unwrap_used)]
    static EXCLUDE_PATTERN: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"^\s*exclude\s+(\S+)\s+(\S+)").unwrap());

    let mut in_require_block = false;
    let mut line_offset = 0;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

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
            && let Some(dep) = parse_require_line(
                line_without_comment,
                line.contains("// indirect"),
                line_offset,
                content,
                &line_table,
            )
            && budget.allow()
        {
            dependencies.push(dep);
        }

        if let Some(caps) = REPLACE_PATTERN.captures(line_trimmed) {
            let module = &caps[1];
            let version = caps.get(2).map(|m| m.as_str());
            if let Some(dep) = parse_replace_line(
                line_without_comment,
                line_offset,
                module,
                version,
                content,
                &line_table,
            ) && budget.allow()
            {
                dependencies.push(dep);
            }
        }

        if let Some(caps) = EXCLUDE_PATTERN.captures(line_trimmed) {
            let module = &caps[1];
            let version = &caps[2];
            if let Some(dep) = parse_exclude_line(
                line_without_comment,
                line_offset,
                module,
                version,
                content,
                &line_table,
            ) && budget.allow()
            {
                dependencies.push(dep);
            }
        }

        let line_end = line_offset + line.len();
        let next_line_start = if content.as_bytes().get(line_end) == Some(&b'\n') {
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

    let go_config = crate::config::resolve_with_context(ctx);
    // Loop-invariant: `GOPROXY` is one config-global declaration, so `blocked_class()` cannot
    // vary across dependencies — computed once rather than once per dependency (up to
    // `MAX_DEPENDENCIES_PER_DOCUMENT`).
    let blocked_class = go_config.blocked_class();
    let mut blocked_registries = Vec::new();
    for dep in &mut dependencies {
        dep.source = go_config.resolve_source_for(dep.module_path.as_str());
        // Only a dependency that actually fell back to `CustomRegistry` was affected by the
        // blocked chain — a `GOPRIVATE`-matched module bypasses `GOPROXY` entirely and keeps
        // resolving via `AlternateRegistry`, so it must not also get a blocked-registry notice.
        if let (Some((class, raw)), true) = (
            &blocked_class,
            matches!(
                dep.source,
                deps_core::parser::DependencySource::CustomRegistry { .. }
            ),
        ) {
            blocked_registries.push(deps_core::BlockedRegistryOccurrence {
                range: dep.module_path_range,
                class: *class,
                raw_value: raw.clone(),
                declaration_key: GOPROXY_BLOCKED_DECLARATION_KEY.to_string(),
            });
        }
    }

    Ok(GoParseResult {
        dependencies,
        module_path,
        go_version,
        uri: doc_uri.clone(),
        resolved_chains: go_config.resolved_chains(),
        blocked_registries,
        dependency_truncation: budget.truncation(),
    })
}

/// Strips line comments from a line (everything after //).
///
/// Handles URL schemes (e.g., https://) to avoid stripping URL paths.
// `i` comes from `char_indices()`, always a char boundary.
#[allow(clippy::string_slice)]
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
///
/// `line` must already have any trailing `//` comment stripped (see
/// [`strip_line_comment`]) — otherwise a comment-only directive on a line whose version was
/// deleted (e.g. `github.com/foo/bar // indirect`) can be misparsed as `[module, "//", ..]`,
/// setting `version` to the comment token itself (#1179). `indirect` is derived from the raw
/// (unstripped) line by the caller, since the `// indirect` marker lives in the comment this
/// function no longer sees.
fn parse_require_line(
    line: &str,
    indirect: bool,
    line_start_offset: usize,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<GoDependency> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (module_path, version) = match parts.as_slice() {
        ["require", module, version, ..] => (*module, *version),
        ["require", ..] => return None,
        [module, version, ..] => (*module, *version),
        _ => return None,
    };

    let module_start = line.find(module_path)?;
    let module_offset = line_start_offset + module_start;
    let module_path_range = byte_span_to_range(
        content,
        line_table,
        module_offset,
        module_offset + module_path.len(),
    );

    let version_start = line.find(version)?;
    let version_offset = line_start_offset + version_start;
    let version_range = byte_span_to_range(
        content,
        line_table,
        version_offset,
        version_offset + version.len(),
    );

    Some(GoDependency {
        module_path: module_path.into(),
        module_path_range,
        version: Some(version.into()),
        version_range: Some(version_range),
        directive: GoDirective::Require,
        indirect,
        source: deps_core::parser::DependencySource::Registry,
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
    let module_path_range = byte_span_to_range(
        content,
        line_table,
        module_offset,
        module_offset + module.len(),
    );

    let (version_str, version_range) = if let Some(ver) = version {
        let version_start = line.find(ver)?;
        let version_offset = line_start_offset + version_start;
        let range = byte_span_to_range(
            content,
            line_table,
            version_offset,
            version_offset + ver.len(),
        );
        (Some(ver.to_string()), Some(range))
    } else {
        (None, None)
    };

    Some(GoDependency {
        module_path: module.into(),
        module_path_range,
        version: version_str.map(Into::into),
        version_range,
        directive: GoDirective::Replace,
        indirect: false,
        source: deps_core::parser::DependencySource::Registry,
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
    let module_path_range = byte_span_to_range(
        content,
        line_table,
        module_offset,
        module_offset + module.len(),
    );

    let version_start = line.find(version)?;
    let version_offset = line_start_offset + version_start;
    let version_range = byte_span_to_range(
        content,
        line_table,
        version_offset,
        version_offset + version.len(),
    );

    Some(GoDependency {
        module_path: module.into(),
        module_path_range,
        version: Some(version.into()),
        version_range: Some(version_range),
        directive: GoDirective::Exclude,
        indirect: false,
        source: deps_core::parser::DependencySource::Registry,
    })
}

deps_core::impl_parse_result!(
    GoParseResult,
    GoDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
        blocked_registries: blocked_registries,
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    fn test_uri() -> Url {
        Url::parse("file:///test/go.mod").unwrap()
    }

    #[test]
    fn test_parse_single_require() {
        let content = r"module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].module_path,
            "github.com/gin-gonic/gin"
        );
        assert_eq!(
            result.dependencies[0]
                .version
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v1.9.1")
        );
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
        let content = r"require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)
";
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
        assert_eq!(
            result.dependencies[0]
                .version
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v0.1.0")
        );
    }

    #[test]
    fn test_parse_pseudo_version() {
        let content = "require golang.org/x/crypto v0.0.0-20191109021931-daa7c04131f5\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].version,
            Some(deps_core::VersionReq::new(
                "v0.0.0-20191109021931-daa7c04131f5"
            ))
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
        let content = r"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)

replace github.com/old/module => github.com/new/module v1.2.3

exclude github.com/bad/module v0.1.0
";
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
    fn test_parse_complex_go_mod() {
        let content = r"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)

replace github.com/old/module => github.com/new/module v1.2.3

exclude github.com/bad/module v0.1.0
";
        let result = parse_go_mod(content, &test_uri()).unwrap();

        assert_eq!(result.module_path, Some("example.com/myapp".to_string()));
        assert_eq!(result.go_version, Some("1.21".to_string()));

        assert_eq!(result.dependencies.len(), 4);

        let gin = &result.dependencies[0];
        assert_eq!(gin.module_path, "github.com/gin-gonic/gin");
        assert_eq!(
            gin.version.as_ref().map(deps_core::VersionReq::as_str),
            Some("v1.9.1")
        );
        assert_eq!(gin.directive, GoDirective::Require);
        assert!(!gin.indirect);

        let crypto = &result.dependencies[1];
        assert_eq!(crypto.module_path, "golang.org/x/crypto");
        assert_eq!(
            crypto.version.as_ref().map(deps_core::VersionReq::as_str),
            Some("v0.17.0")
        );
        assert_eq!(crypto.directive, GoDirective::Require);
        assert!(crypto.indirect);

        let replace = &result.dependencies[2];
        assert_eq!(replace.module_path, "github.com/old/module");
        assert_eq!(replace.version, None);
        assert_eq!(replace.directive, GoDirective::Replace);

        let exclude = &result.dependencies[3];
        assert_eq!(exclude.module_path, "github.com/bad/module");
        assert_eq!(
            exclude.version.as_ref().map(deps_core::VersionReq::as_str),
            Some("v0.1.0")
        );
        assert_eq!(exclude.directive, GoDirective::Exclude);
    }

    /// #1179: a require-block line whose version was deleted but a directive comment remains
    /// must not have the comment's `//` token misparsed as the version. Also covers the more
    /// common real-world case (impl-critic M1) of a fully commented-out require entry, where the
    /// old behavior misparsed `module_path = "//"` / `version` from the comment body itself.
    #[test]
    fn test_require_block_line_missing_version_with_comment_yields_no_dependency() {
        let content = "require (\n\tgithub.com/foo/bar // indirect\n\t// github.com/foo/bar v1.0.0\n\t// TODO check this\n)\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    /// #1179 follow-up: a `replace` directive followed by a trailing comment must still parse
    /// the correct module/version, exercising the same `line_without_comment` call site as the
    /// require-block fix.
    #[test]
    fn test_parse_replace_directive_with_trailing_comment() {
        let content = "replace github.com/old/module => github.com/new/module v1.2.3 // pinned\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].directive, GoDirective::Replace);
        assert_eq!(result.dependencies[0].module_path, "github.com/old/module");
    }

    /// #1179 follow-up: an `exclude` directive followed by a trailing comment must still parse
    /// the correct module/version, exercising the same `line_without_comment` call site as the
    /// require-block fix.
    #[test]
    fn test_parse_exclude_directive_with_trailing_comment() {
        let content = "exclude github.com/bad/module v0.1.0 // known vulnerability\n";
        let result = parse_go_mod(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].directive, GoDirective::Exclude);
        assert_eq!(result.dependencies[0].module_path, "github.com/bad/module");
        assert_eq!(
            result.dependencies[0]
                .version
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v0.1.0")
        );
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

    /// Integration test (issue #559 follow-up): the full parse -> resolve -> `register_alternate`
    /// -> `get_versions_from` path, exercised end-to-end against a real fixture `$GOENV` file
    /// via [`GoParseContext::goenv_path`] rather than the real host environment.
    #[tokio::test]
    async fn test_integration_parse_resolve_register_alternate_get_versions() {
        use crate::registry::GoRegistry;
        use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
        use deps_core::{FreshnessSettings, HttpCache, Registry};
        use std::sync::Arc;

        let mut alt_server = mockito::Server::new_async().await;
        alt_server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.1\n")
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let goenv_path = dir.path().join("env");
        std::fs::write(
            &goenv_path,
            format!("GOPROXY={},direct\n", alt_server.url()),
        )
        .unwrap();

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let ctx = GoParseContext {
            policy: Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)),
            goenv_path: Some(goenv_path),
            ..Default::default()
        };

        let content = "module example.com/myapp\n\nrequire github.com/gin-gonic/gin v1.9.0\n";
        let result = parse_go_mod_with_context(content, &test_uri(), &ctx).unwrap();
        assert_eq!(result.resolved_chains.len(), 1);

        let registry = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        for chain in &result.resolved_chains {
            GoRegistry::register_alternate(&registry, chain);
        }

        let source = result.dependencies[0].source.clone();
        let versions = registry
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    /// #958: a `GOPROXY` chain that fails closed to `CustomRegistry` because its sole hop is
    /// policy-blocked must surface via `ParseResult::blocked_registries`, not just a
    /// `tracing::warn!`.
    #[test]
    fn test_parse_go_mod_blocked_goproxy_populates_blocked_registries() {
        use crate::config::GoEnvCache;
        use deps_core::ParseResult as _;
        use deps_core::net_policy::{HostClass, RegistryAccessPolicy, WorkspaceRegistryAccess};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let goenv_path = dir.path().join("env");
        std::fs::write(&goenv_path, "GOPROXY=https://goproxy.mycorp.example\n").unwrap();

        let ctx = GoParseContext::new(
            Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)),
            Arc::new(GoEnvCache::new()),
            Some(goenv_path),
        );

        let content = "module example.com/myapp\n\nrequire github.com/gin-gonic/gin v1.9.0\n";
        let result = parse_go_mod_with_context(content, &test_uri(), &ctx).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "https://goproxy.mycorp.example".to_string(),
            }
        );

        let blocked = result.blocked_registries();
        assert_eq!(blocked.len(), 1);
        let occurrence = &blocked[0];
        assert_eq!(occurrence.range, result.dependencies[0].module_path_range);
        assert_eq!(occurrence.class, HostClass::Global);
        assert_eq!(occurrence.raw_value, "https://goproxy.mycorp.example");
        assert_eq!(occurrence.declaration_key, GOPROXY_BLOCKED_DECLARATION_KEY);
    }

    /// `GOPROXY` is one config-global declaration — every affected `require` line gets its own
    /// [`deps_core::BlockedRegistryOccurrence`], but all of them share the same declaration key
    /// so `deps_core::lsp_helpers::diagnostics::blocked_registry_diagnostics` groups and collapses
    /// them into one diagnostic with the other affected modules as `related_information`.
    #[test]
    fn test_parse_go_mod_blocked_goproxy_shares_declaration_key_across_dependencies() {
        use crate::config::GoEnvCache;
        use deps_core::ParseResult as _;
        use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let goenv_path = dir.path().join("env");
        std::fs::write(&goenv_path, "GOPROXY=https://goproxy.mycorp.example\n").unwrap();

        let ctx = GoParseContext::new(
            Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)),
            Arc::new(GoEnvCache::new()),
            Some(goenv_path),
        );

        let content = r"module example.com/myapp

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0
)
";
        let result = parse_go_mod_with_context(content, &test_uri(), &ctx).unwrap();
        let blocked = result.blocked_registries();
        assert_eq!(blocked.len(), 2);
        assert_eq!(blocked[0].range, result.dependencies[0].module_path_range);
        assert_eq!(blocked[1].range, result.dependencies[1].module_path_range);
        assert!(
            blocked
                .iter()
                .all(|occurrence| occurrence.declaration_key == GOPROXY_BLOCKED_DECLARATION_KEY)
        );
    }

    /// #958: a `GOPRIVATE`-matched module bypasses `GOPROXY` entirely (routes to the `direct`
    /// chain), so it must never get a blocked-registry notice even while `GOPROXY` itself is
    /// failing closed for every other module.
    #[test]
    fn test_parse_go_mod_blocked_goproxy_excludes_goprivate_bypassed_dependency() {
        use crate::config::GoEnvCache;
        use deps_core::ParseResult as _;
        use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let goenv_path = dir.path().join("env");
        std::fs::write(
            &goenv_path,
            "GOPROXY=https://goproxy.mycorp.example\nGOPRIVATE=git.mycorp.example/*\n",
        )
        .unwrap();

        let ctx = GoParseContext::new(
            Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::Off)),
            Arc::new(GoEnvCache::new()),
            Some(goenv_path),
        );

        let content =
            "module example.com/myapp\n\nrequire git.mycorp.example/internal/lib v1.0.0\n";
        let result = parse_go_mod_with_context(content, &test_uri(), &ctx).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: crate::config::GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            }
        );
        assert!(result.blocked_registries().is_empty());
    }
}
