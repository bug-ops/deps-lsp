//! package.json parser with position tracking.
//!
//! Parses package.json files and extracts dependency information with precise
//! source positions for LSP operations.

use crate::config::{NpmConfig, NpmParseContext, NpmRegistryIndex};
use crate::types::{NpmDependency, NpmDependencySection};
use deps_core::Result;
use deps_core::json_ast::{JsonAst, JsonSection};
use deps_core::json_helpers::string_valued_entries;
use deps_core::lsp_helpers::LineOffsetTable;
use serde_json::Value;
use url::Url;

/// Result of parsing a package.json file.
///
/// Contains all dependencies found in the file with their positions.
#[non_exhaustive]
#[derive(Debug)]
pub struct NpmParseResult {
    /// Dependencies found across all `package.json` sections.
    pub dependencies: Vec<NpmDependency>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// Every `.npmrc`-resolved alternate registry this parse's dependencies reference,
    /// deduplicated (spec FR-002–004) — fed to `NpmRegistry::register_alternate` by
    /// `NpmEcosystem::parse_manifest`, the one place a per-document `.npmrc` resolution and
    /// the long-lived shared router meet. Empty for a workspace declaring no `.npmrc`
    /// (NFR-005: zero regression).
    pub resolved_registries: Vec<NpmRegistryIndex>,
    /// Dependency lines whose `.npmrc` `registry`/`@scope:registry` resolution was blocked by
    /// the current `registries.workspace_registries` policy (#925, mirrors
    /// `deps_cargo::parser::CargoParseResult::blocked_registries`), where the declaration key
    /// (from [`NpmConfig::blocked_class_for`]) distinguishes a top-level `registry=` block
    /// from a `@scope:registry=` block even when both happen to share the same raw value.
    /// Surfaced by [`deps_core::lsp_helpers::generate_diagnostics_from_cache`] via
    /// [`Self::blocked_registries`]'s trait override as an informational diagnostic, so the
    /// block never degrades silently.
    pub blocked_registries: Vec<deps_core::BlockedRegistryOccurrence>,
    /// Dependency lines whose `.npmrc` `registry`/`@scope:registry` resolution was rejected
    /// for a reason other than a policy-blocked host (#1438) — an invalid URL, non-https,
    /// embedded userinfo, an undefined `${VAR}`, or a disallowed `${VAR}` expansion, where
    /// the declaration key (from [`NpmConfig::rejected_reason_for`]) distinguishes a
    /// top-level `registry=` rejection from a `@scope:registry=` rejection the same way
    /// [`Self::blocked_registries`] does. Surfaced by
    /// [`deps_core::lsp_helpers::generate_diagnostics_from_cache`] via
    /// [`Self::rejected_registries`]'s trait override as an informational diagnostic.
    pub rejected_registries: Vec<deps_core::RejectedRegistryOccurrence>,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

deps_core::impl_parse_result!(
    NpmParseResult,
    NpmDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
        blocked_registries: blocked_registries,
        rejected_registries: rejected_registries,
    }
);

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
/// ```no_run
/// use deps_npm::parser::parse_package_json;
/// use url::Url;
///
/// let json = r#"{
///   "dependencies": {
///     "express": "^4.18.2"
///   }
/// }"#;
/// let uri = Url::from_file_path("/project/package.json").unwrap();
///
/// let result = parse_package_json(json, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "express");
/// ```
pub fn parse_package_json(content: &str, uri: &Url) -> Result<NpmParseResult> {
    parse_package_json_with_context(content, uri, &NpmParseContext::default())
}

/// [`parse_package_json`], but threading `ctx` through to `.npmrc` registry resolution.
///
/// Spec FR-002–FR-008 — the real entry point; [`parse_package_json`] delegates here with a
/// fresh, default context, mirroring
/// `deps_cargo::parser::parse_cargo_toml_with_context`'s pattern.
///
/// # Errors
///
/// Same as [`parse_package_json`].
pub fn parse_package_json_with_context(
    content: &str,
    uri: &Url,
    ctx: &NpmParseContext,
) -> Result<NpmParseResult> {
    let root: Value = deps_core::parse_json_checked(content.as_bytes())?;

    // Build line offset table once for O(log n) position lookups
    let line_table = LineOffsetTable::new(content);
    let ast = JsonAst::parse(content);
    if ast.is_none() {
        tracing::warn!(
            "jsonc-parser failed to parse package.json content serde_json already accepted; \
             dependency positions will default to (0,0)"
        );
    }

    let mut dependencies = Vec::new();
    // Shared across every section below (#796) — the ceiling is per-document, not
    // per-section.
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    // Reads each entry's position directly from the AST (#613) — `Object::properties` only
    // lists a given object's *direct* children, so a name repeated across sections or nested
    // inside an unrelated value never gets confused with the real top-level occurrence.
    const SECTIONS: [(&str, NpmDependencySection); 4] = [
        ("dependencies", NpmDependencySection::Dependencies),
        ("devDependencies", NpmDependencySection::DevDependencies),
        ("peerDependencies", NpmDependencySection::PeerDependencies),
        (
            "optionalDependencies",
            NpmDependencySection::OptionalDependencies,
        ),
    ];

    for (key, section) in SECTIONS {
        if let Some(deps) = root.get(key).and_then(|v| v.as_object()) {
            let positions = ast.as_ref().and_then(|ast| ast.section(key));
            dependencies.extend(parse_dependency_section(
                content,
                deps,
                section,
                positions.as_ref(),
                &line_table,
                &mut budget,
            ));
        }
    }

    // FR-002: a non-`file:` URI (or one `to_file_path` can't resolve) has no directory to walk
    // `.npmrc`/pnpm-workspace discovery from — falls back to the empty `NpmConfig` (every
    // dependency resolves to `Registry`, NFR-005) rather than failing the whole parse; this is
    // also what makes catalog resolution land on `CatalogOutcome::NoWorkspaceFile` (S3).
    //
    // #1071/#1090: resolving through `deps_core::lockfile::resolve_manifest_file_path` makes
    // the scheme check explicit rather than relying solely on `Url::to_file_path`'s internal
    // validation — left unguarded, `untitled:package.json` would resolve `manifest_dir` to a
    // *relative* path, and discovery would probe the server process's own CWD instead of the
    // document's workspace. Both `.npmrc` resolution and the catalog gate share this guard.
    let manifest_dir = deps_core::lockfile::resolve_manifest_file_path(uri)
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf));

    let npm_config: NpmConfig = manifest_dir
        .as_deref()
        .map(|dir| crate::config::resolve(dir, &ctx.config_cache, &ctx.policy))
        .unwrap_or_default();

    let mut blocked_registries = Vec::new();
    let mut rejected_registries = Vec::new();
    for dep in &mut dependencies {
        // #1202: a `git+`/`file:`/`link:`/`portal:`/`github:`/`workspace:` specifier is not a
        // registry reference at all — `.npmrc` scope/registry resolution has no meaning for
        // it, and applying it anyway would silently reclassify a non-registry dependency back
        // to `Registry`/`AlternateRegistry`, sending its name to a registry over the network.
        let version_req = dep
            .version_req
            .as_ref()
            .map(deps_core::VersionReq::as_str)
            .unwrap_or_default();
        if let Some(source) = classify_non_registry_specifier(version_req) {
            dep.source = source;
            continue;
        }

        // Route by the real registry name, not the manifest alias (#654 S2): a `.npmrc`
        // scope entry matches the package actually installed, not the local alias.
        let name = deps_core::Dependency::name(dep).clone();
        dep.source = npm_config.resolve_source_for(&name);
        if let Some(classification) = npm_config.blocked_class_for(&name) {
            blocked_registries.push(classification.into_occurrence(dep.name_range));
        } else if let Some(classification) = npm_config.rejected_reason_for(&name) {
            rejected_registries.push(classification.into_occurrence(dep.name_range));
        }
    }

    // FR-001/NFR-002: cheap fast-path — a non-pnpm manifest pays one string check per
    // dependency and zero filesystem calls. `apply` always runs once this fires, never
    // short-circuited by `load` returning `None`.
    if dependencies.iter().any(|dep| {
        dep.version_req
            .as_ref()
            .is_some_and(|req| req.as_str().starts_with("catalog:"))
    }) {
        let workspace_config = crate::catalog::load(manifest_dir.as_deref(), &ctx.workspace_cache);
        crate::catalog::apply(&mut dependencies, workspace_config.as_deref());
    }

    Ok(NpmParseResult {
        dependencies,
        uri: uri.clone(),
        resolved_registries: npm_config.resolved_registries(),
        blocked_registries,
        rejected_registries,
        dependency_truncation: budget.truncation(),
    })
}

/// Parses a single dependency section and extracts positions.
///
/// `positions` is this section's own direct properties, pre-indexed by name (see
/// [`JsonAst::section`]) — `None` when the AST parse degraded (see
/// [`parse_package_json_with_context`]), in which case every dependency falls back to a
/// default, zero position rather than being dropped.
fn parse_dependency_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: NpmDependencySection,
    positions: Option<&JsonSection<'_>>,
    line_table: &LineOffsetTable,
    budget: &mut deps_core::DependencyBudget,
) -> Vec<NpmDependency> {
    let mut result = Vec::new();

    // A non-string manifest value isn't a valid dependency declaration — `string_valued_entries`
    // skips it rather than fabricating an entry with no `version_req` (#619).
    for (name, version_req) in string_valued_entries(deps) {
        if !budget.allow() {
            continue;
        }

        let (name_range, version_range) = positions
            .and_then(|s| s.position(name, content, line_table))
            .unwrap_or_default();

        let (package, version_req) = match parse_npm_alias(version_req) {
            Some(alias) => (Some(alias.package.into()), alias.version_req),
            None => (None, version_req.to_string()),
        };

        result.push(NpmDependency {
            name: name.into(),
            name_range,
            version_req: Some(version_req.into()),
            version_range,
            section,
            // Overwritten once `.npmrc` resolution runs; `Registry` is correct for a
            // manifest with none (NFR-005) and for this function's own unit tests.
            source: deps_core::parser::DependencySource::Registry,
            // Overwritten by the catalog post-pass when the `catalog:` gate fires.
            catalog: None,
            package,
        });
    }

    result
}

/// Classifies an npm dependency specifier that names a non-registry source directly (#1202) —
/// `git+`/`git://`, `github:`/`gitlab:`/`bitbucket:`/`gist:`, bare GitHub shorthand
/// (`owner/repo`), `file:`/`link:`/`portal:`, a bare relative/absolute local path, a direct
/// tarball URL, and `workspace:` all bypass the registry entirely, so `.npmrc` scope/registry
/// resolution must never run for them (see the call site in
/// [`parse_package_json_with_context`]).
///
/// Returns `None` for anything else (a plain semver range, an `npm:` alias, a dist-tag, ...),
/// meaning the caller falls through to ordinary `.npmrc` resolution.
fn classify_non_registry_specifier(value: &str) -> Option<deps_core::parser::DependencySource> {
    let value = value.trim();

    if let Some(rest) = value.strip_prefix("git+") {
        let (url, rev) = split_committish(rest);
        return Some(deps_core::parser::DependencySource::Git {
            url: url.to_string(),
            rev,
        });
    }
    if value.starts_with("git://") {
        let (url, rev) = split_committish(value);
        return Some(deps_core::parser::DependencySource::Git {
            url: url.to_string(),
            rev,
        });
    }
    // Code review #1202: an empty remainder (a bare "github:"/"gitlab:"/"bitbucket:"/"gist:"
    // with nothing after the colon) is not a valid reference at all — `.filter` falls
    // through to the checks below instead of building a malformed `.../.git` URL.
    if let Some(rest) = value.strip_prefix("github:").filter(|r| !r.is_empty()) {
        return Some(git_shorthand("github.com", rest));
    }
    if let Some(rest) = value.strip_prefix("gitlab:").filter(|r| !r.is_empty()) {
        return Some(git_shorthand("gitlab.com", rest));
    }
    if let Some(rest) = value.strip_prefix("bitbucket:").filter(|r| !r.is_empty()) {
        return Some(git_shorthand("bitbucket.org", rest));
    }
    if let Some(rest) = value.strip_prefix("gist:").filter(|r| !r.is_empty()) {
        let (id, rev) = split_committish(rest);
        return Some(deps_core::parser::DependencySource::Git {
            url: format!("https://gist.github.com/{id}.git"),
            rev,
        });
    }
    if let Some(rest) = value
        .strip_prefix("file:")
        .or_else(|| value.strip_prefix("link:"))
        .or_else(|| value.strip_prefix("portal:"))
    {
        return Some(deps_core::parser::DependencySource::Path {
            path: rest.to_string(),
        });
    }
    if value.starts_with("workspace:") {
        return Some(deps_core::parser::DependencySource::Workspace);
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        // Code review #1202: a bare (no `git+` prefix) URL to a known git-hosting service
        // ending in `.git` is still a git reference, consistent with this crate's own
        // lockfile-side detection (`lockfile::parse_npm_source`) — checked before the
        // generic tarball-URL fallback below, splitting off any `#<committish>` into `rev`
        // instead of baking it into the stored URL.
        if is_bare_git_host_url(value) {
            let (url, rev) = split_committish(value);
            return Some(deps_core::parser::DependencySource::Git {
                url: url.to_string(),
                rev,
            });
        }
        // A direct tarball reference (S1, critic): npm accepts a bare `http(s)://` URL as a
        // dependency specifier with no other scheme prefix — never a semver range/tag/alias,
        // which never contain `://`.
        return Some(deps_core::parser::DependencySource::Url {
            url: value.to_string(),
        });
    }
    // A bare local path (S1, critic): npm accepts `./`/`../`/an absolute path (`/`, `~/`, or
    // a Windows drive letter) with no `file:` prefix at all — distinct from the
    // explicit-prefix case above.
    if deps_core::parser::looks_like_filesystem_path(value) {
        return Some(deps_core::parser::DependencySource::Path {
            path: value.to_string(),
        });
    }
    // Bare GitHub shorthand (S1, critic): `"owner/repo"`/`"owner/repo#ref"` with no scheme
    // prefix at all — checked last since every scheme above also structurally contains `/`
    // and must be ruled out first.
    if is_github_shorthand(value) {
        return Some(git_shorthand("github.com", value));
    }

    None
}

/// Whether `value` (already known to start with `http://`/`https://`) is a bare URL to a
/// known git-hosting service ending in `.git` — e.g. `https://github.com/acme/pkg.git`.
/// Consistent with this crate's own lockfile-side git-URL detection
/// (`lockfile::parse_npm_source`), which recognizes this exact shape.
fn is_bare_git_host_url(value: &str) -> bool {
    let (base, _) = split_committish(value);
    base.ends_with(".git")
        && ["github.com/", "gitlab.com/", "bitbucket.org/"]
            .iter()
            .any(|host| base.contains(host))
}

/// Builds a [`DependencySource::Git`](deps_core::parser::DependencySource::Git) for an
/// `owner/repo`-shaped `rest` (optionally `#<committish>`-suffixed) against `host`.
fn git_shorthand(host: &str, rest: &str) -> deps_core::parser::DependencySource {
    let (repo, rev) = split_committish(rest);
    deps_core::parser::DependencySource::Git {
        url: format!("https://{host}/{repo}.git"),
        rev,
    }
}

/// Whether `value` is npm's bare GitHub-shorthand specifier form: exactly one `/`-separated
/// `owner/repo` pair (each an npm-package-arg-shaped token: alphanumeric plus `-`/`_`/`.`),
/// optionally followed by `#<committish>`. Deliberately excludes anything already recognized
/// by an explicit prefix above (a scoped package alias value never reaches this function in
/// specifier position, and a tarball URL/absolute path has already returned by this point).
fn is_github_shorthand(value: &str) -> bool {
    let (candidate, _) = split_committish(value);
    let Some((owner, repo)) = candidate.split_once('/') else {
        return false;
    };
    let is_token = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    is_token(owner) && !repo.contains('/') && is_token(repo)
}

/// Splits off an npm git specifier's optional trailing `#<committish>` — returns
/// `(base, Some(committish))` when present and non-empty, else `(value, None)`.
fn split_committish(value: &str) -> (&str, Option<String>) {
    match value.rsplit_once('#') {
        Some((base, rev)) if !rev.is_empty() => (base, Some(rev.to_string())),
        _ => (value, None),
    }
}

/// The real registry package name and version requirement parsed out of an `npm:` alias value.
struct NpmAlias {
    package: String,
    version_req: String,
}

/// Parses an `npm:` alias specifier (issue #654): npm/pnpm/yarn let a manifest install a
/// dependency under a different registry name than its JSON key
/// (`"my-react": "npm:react@^18.0.0"`) — the key becomes a local import alias, and the value
/// names the real package to resolve against the registry, with everything after the package
/// name's own trailing `@` as its version requirement.
///
/// Returns `None` when `value` (after trimming surrounding whitespace — `npm`'s own
/// `npm-package-arg` parser tolerates it, so a manifest author accidentally adding it should
/// not silently disable the alias) doesn't start with `npm:`, when the parsed package name
/// is empty (e.g. `"npm:"`, `"npm:@"`, `"npm:@/pkg"`, `"npm:@scope/"`), or for the
/// pnpm-catalog combination form (`npm:<pkg>@catalog:<name>`, deliberately unhandled — see
/// below) — the caller then falls back to the original literal value, matching
/// pre-alias-support behavior.
///
/// The name/version boundary is [`deps_core::package::npm_style_name_boundary`] — shared
/// with `deps-deno`'s `npm:`/`jsr:` specifier grammar so a scoped real package name
/// (`@scope/pkg`) is bounded identically in both crates (issue #654 S3) rather than
/// reimplemented here more loosely. A trailing `/` right after the name (that helper's
/// subpath-boundary behavior, meaningful for Deno's own `npm:` import specifiers) has no
/// equivalent in a `package.json` dependency value, so it is treated as malformed here, not
/// silently truncated.
///
/// A dist-tag alias (`"npm:react@beta"`, `"npm:foo@latest"`) is legal npm syntax but not a
/// semver range `NpmFormatter::compile_requirement`'s `node_semver::Range` can parse, which
/// would otherwise silently match no version at all — treated the same as the
/// missing-version case below.
///
/// The pnpm-catalog combination form is left to the caller's literal-value fallback rather
/// than resolved here: `catalog.rs`'s `apply` looks up the catalog map by
/// [`crate::types::NpmDependency::name`] (the JSON key/alias), not the real package this
/// function would extract, so resolving the alias here would feed the catalog lookup the
/// wrong key — see `catalog.rs`'s "Known limitations" doc, which this leaves unchanged.
// `name_len` comes from `npm_style_name_boundary` (ASCII-find derived), so it is always a
// char boundary.
#[allow(clippy::string_slice)]
fn parse_npm_alias(value: &str) -> Option<NpmAlias> {
    let rest = value.trim().strip_prefix("npm:")?;

    let Some(name_len) = deps_core::package::npm_style_name_boundary(rest) else {
        tracing::debug!(
            value,
            "npm: alias has a malformed package name, using literal value"
        );
        return None;
    };
    let package = rest[..name_len].trim();
    if package.is_empty() {
        tracing::debug!(
            value,
            "npm: alias has an empty package name, using literal value"
        );
        return None;
    }

    let after_name = &rest[name_len..];
    let version_req = match after_name.strip_prefix('@') {
        Some(v) => v.trim(),
        // Empty: no version at all. Anything else starts with `/` — Deno's subpath syntax,
        // not valid here — reject rather than truncate.
        None if after_name.is_empty() => "",
        None => {
            tracing::debug!(
                value,
                "npm: alias has a subpath after the package name, using literal value"
            );
            return None;
        }
    };

    if version_req.starts_with("catalog:") {
        tracing::debug!(
            value,
            "npm: alias is the pnpm-catalog combination form, deferring to catalog.rs"
        );
        return None;
    }

    // No requirement, an empty one, or a dist-tag (`"beta"`/`"latest"`) `node_semver::Range`
    // can't parse is still a valid alias: treat it as an existence wildcard rather than
    // fabricating an invalid range or dropping the dependency (mirrors `is_existence_wildcard`).
    //
    // An oversized requirement (see `requirement_len_exceeds_cap`'s docs) skips `Range::parse`
    // entirely and is kept verbatim: mapping it to `"*"` would fabricate an existence wildcard
    // and falsely report the real aliased package as up to date.
    let version_req = if version_req.is_empty() {
        "*"
    } else if deps_core::lsp_helpers::requirement_len_exceeds_cap(version_req) {
        tracing::debug!(
            len = version_req.len(),
            "npm: alias version requirement exceeds max length, keeping literal value"
        );
        version_req
    } else if node_semver::Range::parse(version_req).is_err() {
        "*"
    } else {
        version_req
    };

    Some(NpmAlias {
        package: package.to_string(),
        version_req: version_req.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use deps_core::Range;
    use std::assert_matches;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/test/package.json")
    }

    #[test]
    fn test_parse_simple_dependencies() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert_matches!(express.section, NpmDependencySection::Dependencies);

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

        let result = parse_package_json(json, &test_uri()).unwrap();
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

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].section,
            NpmDependencySection::PeerDependencies
        );
    }

    #[test]
    fn test_parse_optional_dependencies() {
        let json = r#"{
  "optionalDependencies": {
    "fsevents": "^2.3.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].section,
            NpmDependencySection::OptionalDependencies
        );
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

        let result = parse_package_json(json, &test_uri()).unwrap();
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
    fn test_non_string_dependency_value_is_skipped() {
        // #619: an object-valued entry is not a valid dependency declaration. Full coverage
        // of every non-string kind lives in `string_valued_entries`'s own tests (#624).
        let json = r#"{
  "dependencies": {
    "nested-shadow": { "express": "0.0.1" },
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "express");
        assert_eq!(result.dependencies[0].version_req, Some("^4.18.2".into()));
    }

    #[test]
    fn test_non_string_dependency_value_of_another_kind_is_skipped_end_to_end() {
        // #619: confirms a non-object non-string kind (number) is skipped too, guarding only
        // the parser/helper wiring — full value-kind coverage lives in #624's own tests.
        let json = r#"{
  "dependencies": {
    "bad-number": 1,
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "express");
    }

    #[test]
    fn test_parse_empty_dependencies() {
        let json = r#"{
  "dependencies": {}
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_no_dependencies() {
        let json = r#"{
  "name": "my-package",
  "version": "1.0.0"
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = "{ invalid json }";
        let result = parse_package_json(json, &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `package.json` must be rejected by the depth guard, reported
        // as the same `DepsError::Json` variant a genuinely malformed manifest produces.
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_package_json(&json, &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"dependencies": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let result = parse_package_json(&json, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_position_calculation() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let express = &result.dependencies[0];

        assert_eq!(express.name_range.start.line, 2);

        if let Some(version_range) = express.version_range {
            assert_eq!(version_range.start.line, 2);
        }
    }

    #[test]
    fn test_line_offset_table() {
        let content = "line0\nline1\nline2";
        let table = LineOffsetTable::new(content);

        let pos0 = table.byte_offset_to_position(content, 0);
        assert_eq!(pos0.line, 0);
        assert_eq!(pos0.character, 0);

        let pos6 = table.byte_offset_to_position(content, 6);
        assert_eq!(pos6.line, 1);
        assert_eq!(pos6.character, 0);

        let pos12 = table.byte_offset_to_position(content, 12);
        assert_eq!(pos12.line, 2);
        assert_eq!(pos12.character, 0);
    }

    #[test]
    fn test_line_offset_table_utf16() {
        // UTF-16 character counting (LSP requirement), with multi-byte "世界".
        let content = "hello 世界\nworld";
        let table = LineOffsetTable::new(content);

        let world_offset = content.find("world").unwrap();
        let pos = table.byte_offset_to_position(content, world_offset);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);

        let world_char_offset = content.find('世').unwrap();
        let pos = table.byte_offset_to_position(content, world_char_offset);
        assert_eq!(pos.line, 0);
        assert_eq!(pos.character, 6); // "hello " = 6 UTF-16 code units
    }

    #[test]
    fn test_line_offset_table_emoji() {
        // Emoji: 4-byte UTF-8, 2 UTF-16 code units.
        let content = "test 🚀 rocket\nline2";
        let table = LineOffsetTable::new(content);

        let rocket_offset = content.find("rocket").unwrap();
        let pos = table.byte_offset_to_position(content, rocket_offset);
        assert_eq!(pos.line, 0);
        // "test " = 5, "🚀" = 2 UTF-16 code units, " " = 1 => total 8
        assert_eq!(pos.character, 8);
    }

    #[test]
    fn test_dependency_with_git_url() {
        let json = r#"{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "my-lib");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("git+https://github.com/user/repo.git".into())
        );
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/user/repo.git".into(),
                rev: None,
            },
            "#1202: a git+ specifier must classify as Git, never fall through to Registry"
        );
    }

    #[test]
    fn test_dependency_with_git_url_committish() {
        let json = r#"{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git#v1.2.3"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/user/repo.git".into(),
                rev: Some("v1.2.3".into()),
            }
        );
    }

    #[test]
    fn test_dependency_with_github_shorthand() {
        let json = r#"{
  "dependencies": {
    "acme-internal-secret": "github:acme/internal-secret#main"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/acme/internal-secret.git".into(),
                rev: Some("main".into()),
            },
            "#1202: a private acme-internal-secret repo must never be sent to a public registry"
        );
    }

    #[test]
    fn test_dependency_with_file_path() {
        let json = r#"{
  "dependencies": {
    "local-pkg": "file:../local-package"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "local-pkg");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("file:../local-package".into())
        );
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Path {
                path: "../local-package".into(),
            }
        );
    }

    #[test]
    fn test_dependency_with_link_and_portal_protocols() {
        let json = r#"{
  "dependencies": {
    "linked-pkg": "link:../linked-package",
    "portal-pkg": "portal:../portal-package"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let linked = result
            .dependencies
            .iter()
            .find(|d| d.name == "linked-pkg")
            .unwrap();
        let portal = result
            .dependencies
            .iter()
            .find(|d| d.name == "portal-pkg")
            .unwrap();
        assert_eq!(
            linked.source,
            deps_core::parser::DependencySource::Path {
                path: "../linked-package".into(),
            }
        );
        assert_eq!(
            portal.source,
            deps_core::parser::DependencySource::Path {
                path: "../portal-package".into(),
            }
        );
    }

    #[test]
    fn test_dependency_with_workspace_protocol() {
        let json = r#"{
  "dependencies": {
    "sibling-pkg": "workspace:*"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Workspace
        );
    }

    /// S1 (critic, #1202): bare GitHub shorthand, with and without a committish.
    #[test]
    fn test_dependency_with_bare_github_shorthand() {
        let json = r#"{
  "dependencies": {
    "acme-internal-secret": "acme/internal-secret",
    "acme-pinned": "acme/internal-secret#main"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let bare = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme-internal-secret")
            .unwrap();
        let pinned = result
            .dependencies
            .iter()
            .find(|d| d.name == "acme-pinned")
            .unwrap();
        assert_eq!(
            bare.source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/acme/internal-secret.git".into(),
                rev: None,
            }
        );
        assert_eq!(
            pinned.source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/acme/internal-secret.git".into(),
                rev: Some("main".into()),
            }
        );
    }

    /// S1 (critic, #1202): `gitlab:`/`bitbucket:`/`gist:` protocols.
    #[test]
    fn test_dependency_with_gitlab_bitbucket_and_gist_protocols() {
        let json = r#"{
  "dependencies": {
    "gl-pkg": "gitlab:acme/secret",
    "bb-pkg": "bitbucket:acme/secret",
    "gist-pkg": "gist:abcdef1234567890"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let gl = result
            .dependencies
            .iter()
            .find(|d| d.name == "gl-pkg")
            .unwrap();
        let bb = result
            .dependencies
            .iter()
            .find(|d| d.name == "bb-pkg")
            .unwrap();
        let gist = result
            .dependencies
            .iter()
            .find(|d| d.name == "gist-pkg")
            .unwrap();
        assert_eq!(
            gl.source,
            deps_core::parser::DependencySource::Git {
                url: "https://gitlab.com/acme/secret.git".into(),
                rev: None,
            }
        );
        assert_eq!(
            bb.source,
            deps_core::parser::DependencySource::Git {
                url: "https://bitbucket.org/acme/secret.git".into(),
                rev: None,
            }
        );
        assert_eq!(
            gist.source,
            deps_core::parser::DependencySource::Git {
                url: "https://gist.github.com/abcdef1234567890.git".into(),
                rev: None,
            }
        );
    }

    /// Code review #1202: a bare (no `git+` prefix) specifier of exactly `"github:"` (or
    /// `"gitlab:"`/`"bitbucket:"`/`"gist:"`) has no owner/repo after the colon at all — must
    /// not build a malformed `.../.git` URL, and must fall back to ordinary registry
    /// resolution.
    #[test]
    fn test_empty_remainder_after_git_shorthand_prefix_falls_back_to_registry() {
        let json = r#"{
  "dependencies": {
    "gh-empty": "github:",
    "gl-empty": "gitlab:",
    "bb-empty": "bitbucket:",
    "gist-empty": "gist:"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        for dep in &result.dependencies {
            assert_eq!(
                dep.source,
                deps_core::parser::DependencySource::Registry,
                "{} must fall back to Registry, not build a malformed .git URL",
                dep.name.as_str()
            );
        }
    }

    /// Code review #1202: a bare `https://` URL to a known git-hosting service ending in
    /// `.git` is still a git reference (consistent with this crate's own lockfile-side
    /// detection), and any trailing `#<committish>` must split into `rev`, not stay baked
    /// into the stored URL.
    #[test]
    fn test_bare_https_git_host_url_classifies_as_git_with_split_committish() {
        let json = r#"{
  "dependencies": {
    "secretpkg": "https://github.com/acme/secretpkg.git#v1.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Git {
                url: "https://github.com/acme/secretpkg.git".into(),
                rev: Some("v1.0.0".into()),
            }
        );
    }

    /// A bare `https://` URL that is NOT a known git host (or has no `.git` suffix) still
    /// classifies as a plain tarball `Url` reference, unaffected by the new git-host check.
    #[test]
    fn test_bare_https_non_git_host_url_still_classifies_as_url() {
        let json = r#"{
  "dependencies": {
    "not-git-host": "https://example.com/acme-secretpkg-1.0.0.tgz",
    "github_no_dot_git": "https://github.com/acme/secretpkg"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        for name in ["not-git-host", "github_no_dot_git"] {
            let dep = result.dependencies.iter().find(|d| d.name == name).unwrap();
            assert_matches!(dep.source, deps_core::parser::DependencySource::Url { .. });
        }
    }

    /// S1 (critic, #1202): a direct tarball URL and a bare local relative path with no
    /// `file:` prefix at all.
    #[test]
    fn test_dependency_with_tarball_url_and_bare_local_path() {
        let json = r#"{
  "dependencies": {
    "tarball-pkg": "https://example.com/acme-secretpkg-1.0.0.tgz",
    "bare-local": "../local-sibling"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let tarball = result
            .dependencies
            .iter()
            .find(|d| d.name == "tarball-pkg")
            .unwrap();
        let bare_local = result
            .dependencies
            .iter()
            .find(|d| d.name == "bare-local")
            .unwrap();
        assert_eq!(
            tarball.source,
            deps_core::parser::DependencySource::Url {
                url: "https://example.com/acme-secretpkg-1.0.0.tgz".into(),
            }
        );
        assert_eq!(
            bare_local.source,
            deps_core::parser::DependencySource::Path {
                path: "../local-sibling".into(),
            }
        );
    }

    /// M8 (critic, #1202): npm also accepts `~/`-relative and Windows drive-letter paths
    /// with no `file:` prefix.
    #[test]
    fn test_dependency_with_home_relative_and_windows_drive_paths() {
        let json = r#"{
  "dependencies": {
    "home-relative": "~/local/sibling",
    "windows-drive": "C:/local/sibling"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let home_relative = result
            .dependencies
            .iter()
            .find(|d| d.name == "home-relative")
            .unwrap();
        let windows_drive = result
            .dependencies
            .iter()
            .find(|d| d.name == "windows-drive")
            .unwrap();
        assert_eq!(
            home_relative.source,
            deps_core::parser::DependencySource::Path {
                path: "~/local/sibling".into(),
            }
        );
        assert_eq!(
            windows_drive.source,
            deps_core::parser::DependencySource::Path {
                path: "C:/local/sibling".into(),
            }
        );
    }

    /// A plain semver range/tag never contains a `/`, so the bare-GitHub-shorthand detector
    /// must never misfire on it.
    #[test]
    fn test_ordinary_semver_specifiers_are_not_misclassified() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17",
    "tagged": "latest"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        for dep in &result.dependencies {
            assert_eq!(dep.source, deps_core::parser::DependencySource::Registry);
        }
    }

    #[test]
    fn test_scoped_package() {
        let json = r#"{
  "devDependencies": {
    "@vitest/coverage-v8": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "@vitest/coverage-v8");
        assert_eq!(result.dependencies[0].version_req, Some("^3.1.4".into()));
        assert!(result.dependencies[0].version_range.is_some());
    }

    /// Issue #654: `"npm:<pkg>@<range>"` resolves the real registry package name while the
    /// JSON key stays the position anchor.
    #[test]
    fn test_parse_npm_alias_resolves_real_package_name() {
        let json = r#"{
  "dependencies": {
    "my-react": "npm:react@^18.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "my-react");
        assert_eq!(dep.package, Some("react".into()));
        assert_eq!(
            deps_core::Dependency::name(dep).as_str(),
            "react",
            "registry lookups must use the real package name"
        );
        assert_eq!(dep.version_req, Some("^18.0.0".into()));
    }

    /// Issue #654: a scoped real package name (`@scope/pkg`) must not be split on its own
    /// leading `@` when locating the name/version boundary.
    #[test]
    fn test_parse_npm_alias_resolves_scoped_real_package_name() {
        let json = r#"{
  "dependencies": {
    "my-pkg": "npm:@scope/pkg@^1.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "my-pkg");
        assert_eq!(dep.package, Some("@scope/pkg".into()));
        assert_eq!(dep.version_req, Some("^1.0.0".into()));
    }

    /// Issue #654: no version at all after the real package name falls back to the
    /// existence-wildcard `"*"` rather than an invalid semver range.
    #[test]
    fn test_parse_npm_alias_without_version_falls_back_to_wildcard() {
        let json = r#"{
  "dependencies": {
    "my-react": "npm:react"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, Some("react".into()));
        assert_eq!(dep.version_req, Some("*".into()));
    }

    /// Issue #654: the pnpm-catalog combination form (`npm:<pkg>@catalog:<name>`) is left as
    /// the original literal value — resolving the alias here would feed `catalog::apply`'s
    /// name-keyed lookup the wrong key (see `catalog.rs`'s `apply` doc).
    #[test]
    fn test_parse_npm_alias_catalog_combination_form_left_unresolved() {
        let json = r#"{
  "dependencies": {
    "my-pkg": "npm:lodash@catalog:utils"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, None);
        assert_eq!(dep.version_req, Some("npm:lodash@catalog:utils".into()));
    }

    /// Critique M1: a lone `"npm:@"` (empty scope, no `/pkg`) must be rejected like `"npm:"`
    /// is, not parsed as a real package literally named `"@"`.
    #[test]
    fn test_parse_npm_alias_lone_at_sign_is_rejected() {
        let json = r#"{"dependencies": {"my-pkg": "npm:@"}}"#;
        let result = parse_package_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, None);
        assert_eq!(dep.version_req, Some("npm:@".into()));
    }

    /// Critique S3: an empty scope (`"npm:@/pkg@^1"`) or empty package segment
    /// (`"npm:@scope/@1.0"`) must be rejected, matching `deps-deno`'s stricter grammar for
    /// the same `@scope/pkg` shape.
    #[test]
    fn test_parse_npm_alias_malformed_scope_is_rejected() {
        for value in ["npm:@/pkg@^1", "npm:@scope/@1.0"] {
            let json = format!(r#"{{"dependencies": {{"my-pkg": "{value}"}}}}"#);
            let result = parse_package_json(&json, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(dep.package, None, "{value} should not resolve a package");
            assert_eq!(dep.version_req, Some(value.into()));
        }
    }

    /// Critique M1b/M6: whitespace around the `npm:` prefix, the real package name, or the
    /// version must not silently produce a garbage package/version.
    #[test]
    fn test_parse_npm_alias_trims_whitespace() {
        let json = r#"{
  "dependencies": {
    "leading-space-before-prefix": " npm:react@^18.0.0",
    "space-after-colon": "npm: react@^18.0.0",
    "space-before-version-at": "npm:react @^18.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        for dep in &result.dependencies {
            assert_eq!(dep.package, Some("react".into()), "{}", dep.name.as_str());
            assert_eq!(
                dep.version_req,
                Some("^18.0.0".into()),
                "{}",
                dep.name.as_str()
            );
        }
    }

    /// Critique M2: a dist-tag alias (`"npm:react@beta"`) is legal npm syntax but not a
    /// `node_semver::Range` — it must fall back to the existence wildcard rather than
    /// silently matching no version.
    #[test]
    fn test_parse_npm_alias_dist_tag_falls_back_to_wildcard() {
        let json = r#"{
  "dependencies": {
    "my-react": "npm:react@beta"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, Some("react".into()));
        assert_eq!(dep.version_req, Some("*".into()));
    }

    /// #1490 (CWE-400): an alias version requirement longer than `MAX_REQUIREMENT_LEN` must
    /// skip `node_semver::Range::parse` entirely (that parser allocates roughly 1.6 KB per
    /// `||` alternative, so an unbounded string is a resource-exhaustion vector) and be kept
    /// verbatim — mapping it to `"*"` would fabricate an existence wildcard and falsely report
    /// the real aliased package as up to date.
    #[test]
    fn test_parse_npm_alias_oversized_version_kept_verbatim() {
        let oversized = "1".repeat(deps_core::lsp_helpers::MAX_REQUIREMENT_LEN + 1);
        let json = format!(r#"{{"dependencies": {{"my-react": "npm:react@{oversized}"}}}}"#);

        let result = parse_package_json(&json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, Some("react".into()));
        assert_eq!(dep.version_req, Some(oversized.into()));
    }

    /// The cap is exclusive: an alias version requirement of exactly `MAX_REQUIREMENT_LEN`
    /// bytes must still reach `node_semver::Range::parse`, matching
    /// `requirement_is_unsatisfiable`'s own `> MAX_REQUIREMENT_LEN` boundary. The payload is
    /// deliberately unparseable (a 256-digit number overflows `node_semver`'s internal `u64`
    /// component parse) rather than a valid range: a valid range at the cap would fall
    /// through to the verbatim-value `else` branch either way, so it can't distinguish this
    /// gate's correct exclusive `>` from a buggy `>=` — only an unparseable at-cap payload
    /// that reaches the parser and is rejected there (falling back to `"*"`) proves the gate
    /// itself didn't fire early (impl-critic S1).
    #[test]
    fn test_parse_npm_alias_version_at_length_cap_reaches_parser() {
        let at_cap = "1".repeat(deps_core::lsp_helpers::MAX_REQUIREMENT_LEN);
        assert_eq!(at_cap.len(), deps_core::lsp_helpers::MAX_REQUIREMENT_LEN);
        assert!(
            node_semver::Range::parse(&at_cap).is_err(),
            "test fixture must be unparseable to distinguish the exclusive `>` gate from a buggy `>=`"
        );
        let json = format!(r#"{{"dependencies": {{"my-react": "npm:react@{at_cap}"}}}}"#);

        let result = parse_package_json(&json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.package, Some("react".into()));
        assert_eq!(dep.version_req, Some("*".into()));
    }

    #[test]
    fn test_package_name_in_scripts_not_confused() {
        // "vitest" appears in scripts as a value, but must only be found as a dependency key.
        let json = r#"{
  "scripts": {
    "test": "vitest",
    "coverage": "vitest run --coverage"
  },
  "devDependencies": {
    "vitest": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let vitest = &result.dependencies[0];
        assert_eq!(vitest.name, "vitest");
        assert_eq!(vitest.version_req, Some("^3.1.4".into()));
        assert!(
            vitest.version_range.is_some(),
            "vitest should have a version_range"
        );
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

        let result = parse_package_json(json, &test_uri()).unwrap();
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

        assert!(
            coverage.version_range.is_some(),
            "@vitest/coverage-v8 should have version_range"
        );
        assert!(
            vitest.version_range.is_some(),
            "vitest should have version_range"
        );

        let coverage_pos = coverage.version_range.unwrap();
        let vitest_pos = vitest.version_range.unwrap();
        assert_ne!(
            coverage_pos.start.line, vitest_pos.start.line,
            "version positions should be on different lines"
        );
    }

    // --- `.npmrc` registry resolution (spec FR-002–FR-008, FR-010) ---

    fn all_policy() -> crate::config::NpmParseContext {
        crate::config::NpmParseContext {
            policy: std::sync::Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
                deps_core::net_policy::WorkspaceRegistryAccess::All,
            )),
            config_cache: std::sync::Arc::new(crate::config::NpmConfigCache::new()),
            workspace_cache: std::sync::Arc::new(crate::catalog::PnpmWorkspaceCache::new()),
        }
    }

    /// FR-003 end-to-end (M7): a top-level `registry=` override rewrites every unscoped
    /// dependency, and leaves a scoped dependency with its own `@scope:registry` entry alone.
    #[test]
    fn test_parse_with_context_top_level_override_and_scope_override_coexist() {
        // `parse_package_json_with_context` transitively touches fs_probe (via
        // `config::resolve`); shares a binary with config.rs's diffing test (snapshot_guard).
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://npm.mycorp.example\n@myorg:registry=https://npm.pkg.github.com\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2", "@myorg/internal-lib": "^2.0.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let express = result
            .dependencies
            .iter()
            .find(|d| d.name == "express")
            .unwrap();
        assert_eq!(
            express.source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: "https://npm.mycorp.example".to_string(),
                mirrors_crates_io: false,
            }
        );

        let scoped = result
            .dependencies
            .iter()
            .find(|d| d.name == "@myorg/internal-lib")
            .unwrap();
        assert_eq!(
            scoped.source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            }
        );

        assert_eq!(result.resolved_registries.len(), 2);
    }

    /// Critique S2: `.npmrc` scoped-registry routing must key off the real registry package
    /// name, not the manifest alias — otherwise a private scoped package aliased to an
    /// unscoped local key gets routed to (and queried against) the *public* registry,
    /// disclosing the private name.
    #[test]
    fn test_parse_with_context_npm_alias_routes_by_real_package_name() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "@myorg:registry=https://npm.pkg.github.com\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"my-lib": "npm:@myorg/internal@^1.0.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "my-lib");
        assert_eq!(dep.package, Some("@myorg/internal".into()));
        assert_eq!(
            dep.source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            },
            "routing must follow the real package's scope, not the unscoped alias key"
        );
    }

    /// FR-006/US-004/SC-004: the npm form of issue #248 — a misconfigured `@scope:registry=`
    /// fails closed to `CustomRegistry`, never falling back to `Registry` (the public
    /// registry).
    #[test]
    fn test_parse_with_context_invalid_scope_registry_fails_closed() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "@myorg:registry=not-a-valid-url\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"@myorg/internal-lib": "^2.0.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
        assert!(!result.dependencies[0].source.is_version_resolvable());
        assert!(result.resolved_registries.is_empty());
    }

    /// NFR-005: no `.npmrc` at any tier is byte-identical to pre-feature behavior — every
    /// dependency resolves to the plain public registry.
    #[test]
    fn test_parse_with_context_no_npmrc_resolves_to_public_registry() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
        assert!(result.resolved_registries.is_empty());
    }

    /// FR-008: a workspace-declared index blocked by the default `public_only` policy fails
    /// closed to `CustomRegistry`, same shape as an invalid URL.
    ///
    /// #925 (impl-critic S3, mirrors `deps-cargo`'s
    /// `test_parse_registry_index_literal_blocked_by_policy_populates_blocked_registries`):
    /// `NpmParseResult::blocked_registries` must also be populated — the block must never
    /// degrade to only a `tracing::warn!` in the server log.
    #[test]
    fn test_parse_with_context_policy_blocked_registry_fails_closed() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://169.254.169.254\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let ctx = NpmParseContext::default(); // default policy is `public_only`
        let result = parse_package_json_with_context(json, &uri, &ctx).unwrap();

        assert_matches!(
            &result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry { .. }
        );
        assert_eq!(result.blocked_registries.len(), 1);
        let occurrence = &result.blocked_registries[0];
        assert_eq!(occurrence.range, result.dependencies[0].name_range);
        assert_eq!(
            occurrence.class,
            deps_core::net_policy::HostClass::CloudMetadata
        );
        assert_eq!(occurrence.raw_value, "https://169.254.169.254");
        assert_eq!(occurrence.declaration_key, "top-level");

        // #969 (impl-critic S2): assert through the trait method, not just the struct field —
        // `deps_core::impl_parse_result!` generates this override; a regression that silently
        // dropped the `blocked_registries:` arm would fall back to the trait's empty-`Vec`
        // default while leaving the struct field (asserted above) untouched, so a field-only
        // assertion would not catch it.
        let via_trait = deps_core::ParseResult::blocked_registries(&result);
        assert_eq!(via_trait.len(), 1);
        assert_eq!(via_trait[0].raw_value, "https://169.254.169.254");
    }

    /// #1438: a rejected `.npmrc` entry that is *not* a blocked host (an
    /// `ExpansionNotAllowedInProjectTier` rejection here, the exact shape reported live
    /// against issue #1428/#1420's project-tier env-var guard) must populate
    /// `NpmParseResult::rejected_registries`, not silently drop the dependency with only a
    /// `tracing::warn!` — the regression this issue reports. Mirrors
    /// `test_parse_with_context_policy_blocked_registry_fails_closed` above, but for the
    /// non-`BlockedHost` path.
    #[test]
    fn test_parse_with_context_rejected_registry_entry_fails_closed() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://evil.example.com/${GITHUB_TOKEN}\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"left-pad": "^1.3.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_matches!(
            &result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry { .. }
        );
        assert!(
            result.blocked_registries.is_empty(),
            "this is not a BlockedHost rejection, so blocked_registries must stay empty"
        );
        assert_eq!(result.rejected_registries.len(), 1);
        let occurrence = &result.rejected_registries[0];
        assert_eq!(occurrence.range, result.dependencies[0].name_range);
        assert_eq!(
            occurrence.reason,
            deps_core::net_policy::RegistryRejectionReason::EnvVarExpansionNotPermitted
        );
        assert_eq!(
            occurrence.raw_value,
            "https://evil.example.com/${GITHUB_TOKEN}"
        );
        assert_eq!(occurrence.declaration_key, "top-level");

        // #969-style regression guard (mirrors the trait-method assertion above): assert
        // through `deps_core::ParseResult::rejected_registries`, not just the struct field, so
        // a regression that silently dropped the `rejected_registries:` arm from
        // `impl_parse_result!` would still be caught.
        let via_trait = deps_core::ParseResult::rejected_registries(&result);
        assert_eq!(via_trait.len(), 1);
        assert_eq!(
            via_trait[0].raw_value,
            "https://evil.example.com/${GITHUB_TOKEN}"
        );
    }

    /// #1438: `UserInfoPresent` is the other reason reported live against the issue — a
    /// distinct manifest shape from the `${VAR}`-expansion case above, exercised separately
    /// since `resolve_entry` checks userinfo before ever reaching `${VAR}` handling.
    #[test]
    fn test_parse_with_context_rejected_registry_entry_userinfo_present() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://user:pass@registry.npmjs.org/\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"left-pad": "^1.3.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(result.rejected_registries.len(), 1);
        assert_eq!(
            result.rejected_registries[0].reason,
            deps_core::net_policy::RegistryRejectionReason::UserInfoPresent
        );
    }

    // --- pnpm catalogs (spec 046) ---

    /// S3 regression: a manifest URI with no filesystem path at all (e.g. a bare virtual-host
    /// URI with nothing after the authority) has no directory to search for
    /// `pnpm-workspace.yaml` from — `Url::to_file_path` returns `Err(())` for it (verified by
    /// the `assert!` below, so this test fails loudly rather than silently degrading into an
    /// ordinary no-workspace-file case if a future `url` version starts resolving it). The
    /// catalog post-pass must still land this on `CatalogOutcome::NoWorkspaceFile` — never
    /// leave the raw `catalog:` specifier in `version_req`, which would re-arm the destructive
    /// "Update all outdated dependencies" rewrite (spec §6's totality invariant).
    #[test]
    fn test_parse_with_context_uri_with_no_file_path_catalog_dep_has_no_requirement() {
        let uri: Url = "vscode-vfs://host"
            .parse()
            .expect("a non-file scheme must still parse as a valid Url");
        assert!(
            uri.to_file_path().is_err(),
            "test premise: this Url must not resolve to any filesystem path"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert_matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        );
    }

    /// A companion regression for a virtual-filesystem URI that carries a path component.
    /// Implementation-critique S2: without the `scheme() == "file"` guard added to
    /// `manifest_dir`'s computation, a `Uri` type that resolves `to_file_path` without
    /// checking the scheme would walk up to 64 real ancestors of `/nonexistent-mount/repo` on
    /// *this* machine's filesystem — a `vscode-vfs://`/`vscode-remote://` path that happens to
    /// mirror a real local path could then silently resolve against an unrelated local
    /// `pnpm-workspace.yaml`/`.npmrc`. With the guard, the non-`file` scheme collapses
    /// `manifest_dir` to `None` directly, with no filesystem probe at all — deterministic, not
    /// merely "happens not to exist on this machine". (`url::Url::to_file_path` additionally
    /// refuses this specific URI on its own, since its host `"host"` is neither absent nor
    /// `localhost` — belt-and-suspenders with the explicit scheme guard, not a substitute for
    /// it.)
    #[test]
    fn test_parse_with_context_virtual_fs_uri_scheme_guard_skips_filesystem_probe_entirely() {
        let uri: Url = "vscode-vfs://host/nonexistent-mount/repo/package.json"
            .parse()
            .expect("a non-file scheme must still parse as a valid Url");

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert_matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        );
    }

    /// S2 regression, originally written against `ls_types::Uri` (whose `to_file_path` does not
    /// check scheme and resolves `untitled:package.json` — VS Code's unsaved-buffer form — to
    /// the *relative* path `"package.json"`, making the explicit `scheme() == "file"` guard
    /// load-bearing to keep `.parent()`/`find_workspace_file`/`.npmrc` discovery from probing
    /// the **LSP server process's own current working directory**).
    ///
    /// FLAG (issue #1071 migration, url::Url substitution): `url::Url::to_file_path` treats
    /// `untitled:package.json` as an opaque (non-hierarchical) URL and returns `Err(())`
    /// unconditionally, regardless of scheme — so this premise no longer holds verbatim under
    /// `url::Url`. The outcome this test guards (never resolving `manifest_dir` from a
    /// non-`file` scheme) still holds, and by construction even more strongly (`Url` never
    /// yields a *relative* `PathBuf` from `to_file_path` for any scheme), but this is a
    /// behavioral divergence between the two URI types, not a pure mechanical substitution —
    /// flagged to team-lead per T016 handoff instructions rather than silently reinterpreted.
    #[test]
    fn test_parse_with_context_untitled_scheme_relative_path_does_not_probe_process_cwd() {
        let uri: Url = "untitled:package.json"
            .parse()
            .expect("untitled: must still parse as a valid Url");
        assert!(
            uri.to_file_path().is_err(),
            "test premise (url::Url): to_file_path resolves this to Err, not a relative path"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert_matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        );
        // The same guard protects `.npmrc` registry resolution, sharing `manifest_dir`.
        assert_eq!(react.source, deps_core::parser::DependencySource::Registry);
    }

    /// Deterministic pin (security review, `.local/handoff/2026-09-15T16-50-50-security.md`):
    /// unlike bare `untitled:package.json` above (where `to_file_path` itself already fails,
    /// so this test alone can't distinguish "blocked by the scheme guard" from "blocked
    /// because `to_file_path` had nothing to resolve"), a hierarchical `untitled:` URI with an
    /// absolute-looking path *does* resolve via `to_file_path` under `url::Url` — so this
    /// dependency landing on `NoWorkspaceFile` here proves the explicit `scheme() == "file"`
    /// check in `manifest_dir`'s computation is what blocks it, not an incidental parse failure.
    #[test]
    fn test_parse_with_context_untitled_scheme_hierarchical_path_blocked_by_scheme_guard() {
        // `to_file_path` needs a drive-letter-shaped first segment to resolve on Windows, so
        // the raw URI and expected path are platform-conditional to keep the test's premise
        // (to_file_path succeeds, so the scheme guard is what blocks manifest_dir) true on both.
        #[cfg(windows)]
        let (raw, expected): (&str, &std::path::Path) = (
            "untitled:/C:/nonexistent/repo/package.json",
            std::path::Path::new(r"C:\nonexistent\repo\package.json"),
        );
        #[cfg(not(windows))]
        let (raw, expected): (&str, &std::path::Path) = (
            "untitled:/nonexistent/repo/package.json",
            std::path::Path::new("/nonexistent/repo/package.json"),
        );
        let uri: Url = raw
            .parse()
            .expect("untitled: must still parse as a valid Url");
        assert_eq!(
            uri.to_file_path().as_deref(),
            Ok(expected),
            "test premise: to_file_path resolves this to a real absolute path, not Err — so \
             the scheme guard, not to_file_path failing, must be what blocks manifest_dir"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert_matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        );
    }

    /// #1090 regression: the pre-fix hand-rolled `manifest_dir` guard only checked
    /// `scheme() == "file"` and `is_absolute()`, missing a `file://` URI carrying a remote
    /// host. Uses a real on-disk `pnpm-workspace.yaml` that a bypass would have found, to
    /// prove the guard — not just an absent-directory coincidence — is what blocks it.
    ///
    /// `#[cfg(unix)]` (guard-gap follow-up): when the manifest's real absolute path is
    /// Windows-drive-letter-shaped (`C:\...`, as `tempfile::tempdir()` produces on a real
    /// Windows machine), a `file:` URI with a non-empty host and that path cannot be
    /// represented by a parsed `url::Url` at all — the WHATWG URL Standard's file-host
    /// parsing rule (`SyntaxViolation::FileWithHostAndWindowsDrive`) strips the host before
    /// `manifest_dir`'s scheme/host check (or any code holding only a `&Url`) can see it, so
    /// this exact fixture asserted an unreachable invariant and failed on `windows-latest`
    /// CI. On Unix the path is never drive-letter-shaped, so the host survives parsing and
    /// this test still protects the guard from silently regressing (wiring-drift coverage).
    /// The drive-letter bypass itself is guarded and tested platform-independently at the
    /// point where untrusted URIs are first parsed:
    /// `deps_lsp::lsp_types_interop::from_lsp_uri`, see its test
    /// `test_from_lsp_uri_rejects_windows_drive_host_bypass`.
    #[cfg(unix)]
    #[test]
    fn test_parse_with_context_file_scheme_remote_host_is_rejected() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let file_uri = Url::from_file_path(&manifest_path).unwrap();
        let path_part = file_uri.as_str().strip_prefix("file://").unwrap();
        let uri: Url = format!("file://attacker.example{path_part}")
            .parse()
            .unwrap();

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(
            react.version_req, None,
            "a remote-host file: URI must never resolve a real workspace file"
        );
        assert_matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        );
        assert_eq!(react.source, deps_core::parser::DependencySource::Registry);
    }

    /// S2 regression, originally written against `ls_types::Uri`: a `file:` URI whose path is
    /// written relative (not RFC 3986-conformant for `file:`, but not rejected by a generic URI
    /// parser either) must not resolve `manifest_dir` to a relative directory either — the
    /// `is_absolute()` filter applies regardless of scheme.
    ///
    /// Reworked for the issue #1071 `url::Url` migration (security review, `.local/handoff/
    /// 2026-09-15T16-50-50-security.md`): under `ls_types::Uri` (fluent_uri, RFC 3986-literal),
    /// `"file:relative/path/package.json"` resolved to the *relative* `PathBuf`
    /// `"relative/path/package.json"`. Under `url::Url` (WHATWG URL Standard), the same string
    /// is normalized at parse time to `file:///relative/path/package.json` and root-anchored to
    /// the *absolute* path `/relative/path/package.json` on Unix — verified not exploitable
    /// (`url::Url::to_file_path` never yields a CWD-relative path or a `..`-traversal escape;
    /// the old guard never restricted *which* absolute directory anyway). On Windows,
    /// `url`'s file-path decoding additionally requires a drive-letter first segment, so this
    /// same input instead yields `Err(())` there — the premise below is deliberately
    /// platform-conditional rather than a bare `assert!` to avoid breaking Windows CI.
    #[test]
    fn test_parse_with_context_authority_less_file_uri_never_resolves_against_process_cwd() {
        let uri: Url = "file:relative/path/package.json"
            .parse()
            .expect("a relative-looking file: URI must still parse as a valid Url");
        if let Ok(path) = uri.to_file_path() {
            assert_eq!(
                path,
                std::path::Path::new("/relative/path/package.json"),
                "authority-less file: URIs must root-anchor, never resolve against the process CWD"
            );
        }
    }

    #[test]
    fn test_parse_with_context_default_catalog_resolves_end_to_end() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(result.dependencies[0].version_req, Some("^18.3.0".into()));
    }

    /// Pinning regression for the `Resolved` catalog path's protection documented in
    /// `catalog.rs`'s module doc: with `version_requirement()` now `Some("^18.3.0")` (not
    /// `None` — the totality invariant doesn't cover this path) and a newer registry version
    /// cached, `collect_update_all_edits` must still produce **no edit** for this dependency,
    /// because `literal_span_matches` rejects the manifest's still-`"catalog:"` `version_range`
    /// slice against the resolved requirement. This holds only because `NpmDependency` does
    /// not override `version_literal()` — if that ever changes, this test must fail.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_resolved_catalog_dependency_blocks_update_all_rewrite() {
        // See the comment in `test_parse_with_context_top_level_override_and_scope_override_coexist`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Url::from_file_path(&manifest_path).unwrap();

        let content = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(content, &uri, &all_policy()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("^18.3.0".into()));

        let mut cached = std::collections::HashMap::new();
        cached.insert(
            deps_core::PackageName::new("react"),
            deps_core::lsp_helpers::PackageVersions::latest_only("19.0.0"),
        );
        let resolved = std::collections::HashMap::new();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = deps_core::lsp_helpers::collect_update_all_edits(
            &result,
            content,
            versions,
            &crate::formatter::NpmFormatter,
        );

        assert!(
            edits.is_empty(),
            "a catalog-resolved dependency must never be rewritten by \"Update all outdated \
             dependencies\": {edits:?}"
        );
    }

    #[test]
    fn test_parse_with_context_no_catalog_dependency_skips_workspace_lookup() {
        // `config::resolve` still runs unconditionally for this absolute `file:` URI even
        // though the catalog gate is skipped (see the earlier snapshot_guard comment).
        let _guard = deps_core::fs_probe::snapshot_guard();
        // FR-008/NFR-002: no `catalog:` value anywhere, so the gate never fires — a bogus
        // workspace path must not affect the result.
        let uri = deps_core::test_util::test_uri("/nonexistent/path/package.json");
        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(result.dependencies[0].version_req, Some("^4.18.2".into()));
        assert!(result.dependencies[0].catalog.is_none());
    }

    // --- #605: duplicate dependency names across sections ---

    #[test]
    fn test_duplicate_name_across_two_sections_with_intervening_entries() {
        // #605: "lodash" in both sections, separated by intervening entries — each occurrence
        // must resolve to its own position, not collapse onto the first match in the file.
        let json = r#"{
  "dependencies": {
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "aaa": "^1.0.0",
    "bbb": "^1.0.0",
    "ccc": "^1.0.0",
    "lodash": "^4.17.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 5);

        let deps_lodash = result
            .dependencies
            .iter()
            .find(|d| d.name == "lodash" && matches!(d.section, NpmDependencySection::Dependencies))
            .expect("lodash in dependencies");
        let dev_lodash = result
            .dependencies
            .iter()
            .find(|d| {
                d.name == "lodash" && matches!(d.section, NpmDependencySection::DevDependencies)
            })
            .expect("lodash in devDependencies");

        assert_eq!(deps_lodash.version_req, Some("^4.17.21".into()));
        assert_eq!(dev_lodash.version_req, Some("^4.17.0".into()));

        assert_eq!(deps_lodash.name_range.start.line, 2);
        assert_eq!(dev_lodash.name_range.start.line, 8);

        let deps_version = deps_lodash
            .version_range
            .expect("dependencies lodash version_range");
        let dev_version = dev_lodash
            .version_range
            .expect("devDependencies lodash version_range");
        assert_eq!(deps_version.start.line, 2);
        assert_eq!(dev_version.start.line, 8);
    }

    #[test]
    fn test_duplicate_name_across_three_sections() {
        let json = r#"{
  "dependencies": {
    "shared-lib": "^1.0.0"
  },
  "devDependencies": {
    "shared-lib": "^2.0.0"
  },
  "optionalDependencies": {
    "shared-lib": "^3.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        let dep = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, NpmDependencySection::Dependencies))
            .expect("shared-lib in dependencies");
        let dev = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, NpmDependencySection::DevDependencies))
            .expect("shared-lib in devDependencies");
        let opt = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, NpmDependencySection::OptionalDependencies))
            .expect("shared-lib in optionalDependencies");

        assert_eq!(dep.version_req, Some("^1.0.0".into()));
        assert_eq!(dev.version_req, Some("^2.0.0".into()));
        assert_eq!(opt.version_req, Some("^3.0.0".into()));

        assert_eq!(dep.name_range.start.line, 2);
        assert_eq!(dev.name_range.start.line, 5);
        assert_eq!(opt.name_range.start.line, 8);
    }

    #[test]
    fn test_section_range_unaffected_by_unbalanced_brace_inside_version_string() {
        // The AST (#613) parses strings as atomic tokens, so an unbalanced `{` inside one
        // can never be miscounted as real object structure.
        let json = r#"{
  "dependencies": {
    "weird": "pkg@file:../{unbalanced",
    "after-weird": "^1.0.0"
  },
  "devDependencies": {
    "weird": "^2.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        let deps_weird = result
            .dependencies
            .iter()
            .find(|d| d.name == "weird" && matches!(d.section, NpmDependencySection::Dependencies))
            .expect("weird in dependencies");
        let dev_weird = result
            .dependencies
            .iter()
            .find(|d| {
                d.name == "weird" && matches!(d.section, NpmDependencySection::DevDependencies)
            })
            .expect("weird in devDependencies");
        let after_weird = result
            .dependencies
            .iter()
            .find(|d| d.name == "after-weird")
            .expect("after-weird");

        assert_eq!(
            deps_weird.version_req,
            Some("pkg@file:../{unbalanced".into())
        );
        assert_eq!(dev_weird.version_req, Some("^2.0.0".into()));
        assert!(matches!(
            after_weird.section,
            NpmDependencySection::Dependencies
        ));
        assert_eq!(after_weird.version_req, Some("^1.0.0".into()));
        assert!(after_weird.version_range.is_some());

        assert_eq!(deps_weird.name_range.start.line, 2);
        assert_eq!(dev_weird.name_range.start.line, 6);
    }

    #[test]
    fn test_section_key_nested_under_package_extensions_not_mistaken_for_top_level() {
        // impl-critic C1: pnpm's `packageExtensions` can nest a `dependencies` object before
        // the real top-level one — the AST (#613) only indexes the root's direct properties.
        let json = r#"{
  "packageExtensions": {
    "some-pkg": {
      "dependencies": {
        "nested-only": "^9.9.9"
      }
    }
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert!(matches!(
            express.section,
            NpmDependencySection::Dependencies
        ));
        assert_ne!(express.name_range, Range::default());
        assert!(express.version_range.is_some());
    }

    #[test]
    fn test_section_key_nested_under_overrides_not_mistaken_for_top_level() {
        // impl-critic C1: npm's `overrides` can likewise nest a `dependencies` key (e.g.
        // for a package-specific override) before the real top-level `dependencies`.
        let json = r#"{
  "overrides": {
    "some-pkg": {
      "dependencies": {
        "nested-only": "^9.9.9"
      }
    }
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert!(matches!(
            express.section,
            NpmDependencySection::Dependencies
        ));
        assert_ne!(express.name_range, Range::default());
        assert!(express.version_range.is_some());
    }

    #[test]
    fn test_dependencies_section_not_matched_by_run_dependencies_script_key() {
        // The AST's `find_last_prop` matches by exact property-name equality; a script
        // literally named "run-dependencies" must not be mistaken for the real section key.
        let json = r#"{
  "scripts": {
    "run-dependencies": "some-cli-tool"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert!(matches!(
            express.section,
            NpmDependencySection::Dependencies
        ));
        assert_eq!(express.name_range.start.line, 5);
        assert!(express.version_range.is_some());
    }

    // --- #613: AST-based position recovery edge cases ---

    /// A dependency's value can itself be a nested object containing a key with the same
    /// name as a real top-level dependency in this section. A text-based scanner finds the
    /// nested occurrence first; the AST only ever indexes a section's own *direct*
    /// properties, so the real top-level occurrence's position is never stolen by one nested
    /// inside a sibling's value. `a-lib` itself has an object value, so it is skipped
    /// entirely (#619) — only `b-lib` survives.
    #[test]
    fn test_nested_object_value_with_colliding_key_resolves_to_top_level_position() {
        let json = r#"{
  "dependencies": {
    "a-lib": {
      "b-lib": "0.0.1"
    },
    "b-lib": "^2.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let b_lib = result
            .dependencies
            .iter()
            .find(|d| d.name == "b-lib")
            .expect("b-lib");
        assert_eq!(b_lib.version_req, Some("^2.0.0".into()));
        // The real top-level "b-lib" is on line 5, not line 3 (nested inside "a-lib"'s value).
        assert_eq!(b_lib.name_range.start.line, 5);
        let version_range = b_lib.version_range.expect("b-lib version_range");
        assert_eq!(version_range.start.line, 5);
    }

    /// JSON permits (if unusual) a duplicate top-level key; `serde_json::Map` keeps only the
    /// *last* occurrence's value (last-key-wins during deserialization). The AST lookup must
    /// resolve the identically-named "dependencies" key the same way — the last one — not the
    /// first, or the surviving dependency's position silently defaults to `Range::default()`
    /// whenever the two sections don't share every name.
    #[test]
    fn test_duplicate_top_level_section_key_resolves_to_last_occurrence() {
        let json = r#"{
  "dependencies": {
    "only-in-first": "^1.0.0"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert_ne!(express.name_range, Range::default());
        assert_eq!(express.name_range.start.line, 5);
        assert!(express.version_range.is_some());
    }

    /// M6(c): when the AST parse degrades (e.g. a future `jsonc-parser` disagreement with
    /// `serde_json` on content this crate's own `parse_package_json` never actually produces
    /// — see [`JsonAst::parse`]'s doc), `positions: None` must still yield a dependency entry
    /// with a default, zero position rather than dropping it or panicking.
    #[test]
    fn test_parse_dependency_section_with_no_ast_positions_falls_back_to_default_range() {
        let mut deps = serde_json::Map::new();
        deps.insert("express".to_string(), Value::String("^4.18.2".into()));
        let content = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let line_table = LineOffsetTable::new(content);

        let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
        let result = parse_dependency_section(
            content,
            &deps,
            NpmDependencySection::Dependencies,
            None,
            &line_table,
            &mut budget,
        );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "express");
        assert_eq!(result[0].name_range, Range::default());
        assert!(result[0].version_range.is_none());
    }
}
