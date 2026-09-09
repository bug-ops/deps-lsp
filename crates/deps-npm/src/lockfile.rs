//! package-lock.json file parsing.
//!
//! Parses package-lock.json files (versions 2 and 3) to extract resolved dependency
//! versions. Supports npm workspaces and proper path resolution.
//!
//! # package-lock.json Format
//!
//! package-lock.json uses JSON format with a "packages" object:
//!
//! ```json
//! {
//!   "name": "my-project",
//!   "lockfileVersion": 3,
//!   "packages": {
//!     "": {
//!       "name": "my-project",
//!       "dependencies": { "express": "^4.18.0" }
//!     },
//!     "node_modules/express": {
//!       "version": "4.18.2",
//!       "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
//!       "integrity": "sha512-..."
//!     }
//!   }
//! }
//! ```

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_and_parse_lockfile,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;
use yaml_rust2::{Yaml, YamlLoader};

/// package-lock.json file parser.
///
/// Implements lock file parsing for npm package manager.
/// Supports both project-level and workspace-level lock files.
///
/// # Lock File Location
///
/// The parser searches for package-lock.json in the following order:
/// 1. Same directory as package.json
/// 2. Parent directories (up to 5 levels) for workspace root
///
/// # Examples
///
/// ```no_run
/// use deps_npm::lockfile::NpmLockParser;
/// use deps_core::lockfile::LockFileProvider;
/// use tower_lsp_server::ls_types::Uri;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let parser = NpmLockParser;
/// let manifest_uri = Uri::from_file_path("/path/to/package.json").unwrap();
///
/// if let Some(lockfile_path) = parser.locate_lockfile(&manifest_uri) {
///     let resolved = parser.parse_lockfile(&lockfile_path).await?;
///     println!("Found {} resolved packages", resolved.len());
/// }
/// # Ok(())
/// # }
/// ```
pub struct NpmLockParser;

impl NpmLockParser {
    /// Lock file names for npm ecosystem, in resolution-precedence order: `package-lock.json`
    /// wins over `pnpm-lock.yaml` when both exist in the same directory (spec 052 FR-001/FR-002).
    const LOCKFILE_NAMES: &'static [&'static str] = &["package-lock.json", "pnpm-lock.yaml"];
}

/// package-lock.json structure (partial, only fields we need).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageLockJson {
    /// Packages object with resolved dependencies
    #[serde(default)]
    packages: HashMap<String, PackageEntry>,
}

/// Individual package entry in the "packages" object.
#[derive(Debug, Deserialize)]
struct PackageEntry {
    /// The package's own name, present when it differs from the lockfile key's physical
    /// install-path basename — npm writes this whenever a dependency is installed under an
    /// `npm:` alias (issue #654), so `node_modules/my-react` carries `"name": "react"`. `None`
    /// for the common case where the two already agree; [`extract_package_name`] is the
    /// fallback then.
    name: Option<String>,

    /// Package version
    version: Option<String>,

    /// Registry URL where package was downloaded from
    resolved: Option<String>,

    /// Integrity hash (sha512-... format)
    integrity: Option<String>,

    /// True for local packages
    link: Option<bool>,

    /// Dependencies of this package (optional, for dependency tree)
    #[serde(default)]
    dependencies: HashMap<String, String>,
}

impl LockFileProvider for NpmLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            if lockfile_path.file_name().and_then(|n| n.to_str()) == Some("pnpm-lock.yaml") {
                parse_pnpm_lock(lockfile_path).await
            } else {
                parse_package_lock_json(lockfile_path).await
            }
        })
    }
}

/// Parses a `package-lock.json` at `lockfile_path` into resolved packages.
async fn parse_package_lock_json(lockfile_path: &Path) -> Result<ResolvedPackages> {
    tracing::debug!("Parsing package-lock.json: {}", lockfile_path.display());

    let packages = read_and_parse_lockfile(
        lockfile_path,
        "package-lock.json",
        parse_package_lock_json_content,
    )
    .await?;

    tracing::info!(
        "Parsed package-lock.json: {} packages from {}",
        packages.len(),
        lockfile_path.display()
    );

    Ok(packages)
}

/// Parses `package-lock.json` content (already read and size-capped) into resolved packages.
///
/// The CPU-bound half of [`parse_package_lock_json`], run inside
/// [`deps_core::lockfile::read_and_parse_lockfile`]'s `spawn_blocking`.
fn parse_package_lock_json_content(content: String) -> Result<ResolvedPackages> {
    let lock_data: PackageLockJson =
        deps_core::parse_json_checked(content.as_bytes()).map_err(|e| DepsError::ParseError {
            file_type: "package-lock.json".into(),
            source: Box::new(e),
        })?;

    let mut packages = ResolvedPackages::new();

    for (key, entry) in lock_data.packages {
        // Skip root package (empty key)
        if key.is_empty() {
            continue;
        }

        // Prefer the entry's own `name` (npm writes this when it differs from the
        // physical install path — always the case for an `npm:` alias, issue #654)
        // over the key-derived basename, so an aliased dependency's lock-file entry
        // groups under its real registry name, matching `Dependency::name()`.
        let name = entry
            .name
            .clone()
            .unwrap_or_else(|| extract_package_name(&key).to_string());

        // Version is required for actual dependencies
        let Some(ref version) = entry.version else {
            tracing::debug!("Skipping package '{}' with no version", name);
            continue;
        };

        // Parse source based on link, resolved, and integrity fields
        let source = parse_npm_source(&entry);

        // Extract dependency names
        let dependencies: Vec<String> = entry.dependencies.keys().cloned().collect();

        packages.insert(ResolvedPackage {
            name,
            version: version.clone(),
            source,
            dependencies,
        });
    }

    Ok(packages)
}

/// Lowest supported `pnpm-lock.yaml` `lockfileVersion` major component (spec 052 FR-006, Out
/// of Scope): pre-pnpm-8 lock files use an incompatible `packages` shape and peer-suffix
/// syntax, so they are rejected rather than silently misparsed.
const MIN_PNPM_LOCKFILE_MAJOR_VERSION: u32 = 6;

/// Parses a `pnpm-lock.yaml` at `lockfile_path` into resolved packages, aggregating every
/// workspace importer (spec 052 FR-004/FR-007).
///
/// **Known limitation**: importers are aggregated flatly into one shared version pool per
/// package name, with no correlation back to the specific `package.json` being queried (spec
/// 052's deliberate scoping — Out of Scope forbids importer-to-manifest correlation). When two
/// importers have *overlapping* semver ranges that pnpm resolved to *different* concrete
/// versions, a caller resolving one importer's dependency can be handed the version resolved
/// for a different importer instead of its own — a false-negative risk for OSV vulnerability
/// matching, not merely an imprecision. The same applies to any `package.json` under the
/// workspace root that isn't itself a registered importer, since it inherits whichever
/// importer's version the ancestor lock-file search happens to attach to. See
/// `docs/ECOSYSTEM_GUIDE.md`'s pnpm section for the user-facing note.
async fn parse_pnpm_lock(lockfile_path: &Path) -> Result<ResolvedPackages> {
    tracing::debug!("Parsing pnpm-lock.yaml: {}", lockfile_path.display());

    // NFR-001: the nesting/expansion guards and the YAML parse itself are CPU-bound work on
    // already-read, untrusted content — `read_and_parse_lockfile` runs `parse_pnpm_lock_yaml`
    // on the blocking-thread pool (mirrors `read_lockfile_content`'s own `spawn_blocking` for
    // the file read) rather than on the calling tokio worker, so a large `pnpm-lock.yaml` near
    // the 32 MiB cap can't stall the async executor.
    let packages = read_and_parse_lockfile(lockfile_path, "pnpm-lock.yaml", |content| {
        parse_pnpm_lock_yaml(&content)
    })
    .await?;

    tracing::info!(
        "Parsed pnpm-lock.yaml: {} packages from {}",
        packages.len(),
        lockfile_path.display()
    );

    Ok(packages)
}

/// The CPU-bound half of [`parse_pnpm_lock`], run inside
/// [`deps_core::lockfile::read_and_parse_lockfile`]'s `spawn_blocking`.
fn parse_pnpm_lock_yaml(content: &str) -> Result<ResolvedPackages> {
    let to_parse_error = |message: String| DepsError::ParseError {
        file_type: "pnpm-lock.yaml".into(),
        source: Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message,
        )),
    };

    if deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH).is_err()
        || deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES).is_err()
    {
        return Err(to_parse_error(
            "exceeds YAML nesting depth or expansion bounds".into(),
        ));
    }

    let docs = YamlLoader::load_from_str(content)
        .map_err(|e| to_parse_error(format!("invalid YAML: {e}")))?;
    let Some(doc) = docs.first() else {
        return Ok(ResolvedPackages::new());
    };

    // FR-006/L4: an absent or explicit-null `lockfileVersion` is permitted (matches
    // `catalog.rs`'s `Yaml::BadValue | Yaml::Null` "absent" convention) — but once the key is
    // present with any other shape, it must resolve to a supported version or the file is
    // rejected outright, rather than silently treating a non-scalar value (e.g. a nested
    // mapping) the same as "absent".
    match &doc["lockfileVersion"] {
        Yaml::BadValue | Yaml::Null => {}
        node => {
            let Some(version) = yaml_scalar_string(node) else {
                return Err(to_parse_error(
                    "lockfileVersion is present but not a scalar value".into(),
                ));
            };
            let major = version.split('.').next().unwrap_or(&version);
            let major: u32 = major
                .parse()
                .map_err(|_| to_parse_error(format!("unparseable lockfileVersion '{version}'")))?;
            if major < MIN_PNPM_LOCKFILE_MAJOR_VERSION {
                return Err(to_parse_error(format!(
                    "unsupported lockfileVersion '{version}' (requires {MIN_PNPM_LOCKFILE_MAJOR_VERSION}.0 or newer)"
                )));
            }
        }
    }

    let mut packages = ResolvedPackages::new();

    let Yaml::Hash(importers) = &doc["importers"] else {
        tracing::debug!("pnpm-lock.yaml has no importers");
        return Ok(packages);
    };

    for (_importer_path, importer) in importers {
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Yaml::Hash(deps) = &importer[section] else {
                continue;
            };
            for (name, entry) in deps {
                let Some(importer_key) = name.as_str() else {
                    continue;
                };
                // `yaml_scalar_string` coerces an unquoted, numeric-looking `version` (e.g.
                // `version: 1.0`, parsed as `Yaml::Real`) the same way the `lockfileVersion`
                // gate above does — `as_str()` alone would silently drop such an entry.
                let Some(raw_version) = yaml_scalar_string(&entry["version"]) else {
                    tracing::debug!(
                        "Skipping pnpm entry '{importer_key}' with missing or non-scalar version field"
                    );
                    continue;
                };
                // FR-005: a workspace-local sibling package, not a registry resolution.
                if raw_version.starts_with("link:") {
                    continue;
                }

                let (name, version) =
                    resolve_pnpm_entry_name_and_version(importer_key, &raw_version);

                // S2: anything that isn't a semver-shaped resolution (`file:...`, `git+...`, a
                // bare tarball URL, `workspace:...`, a malformed value) must not be stored as a
                // fake "resolved version" — it would otherwise flow verbatim into hover text and
                // OSV vulnerability-lookup queries.
                if node_semver::Version::parse(version).is_err() {
                    tracing::debug!(
                        "Skipping pnpm entry '{name}' with non-semver version '{version}'"
                    );
                    continue;
                }

                packages.insert(ResolvedPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    source: ResolvedSource::Registry {
                        url: String::new(),
                        checksum: String::new(),
                    },
                    dependencies: Vec::new(),
                });
            }
        }
    }

    Ok(packages)
}

/// Resolves one importer dependency entry's real package name and plain version, handling
/// pnpm's `name@version` alias-resolution form.
///
/// pnpm keys an aliased dependency (e.g. `"my-lodash": "npm:lodash@^4.17.0"` in `package.json`)
/// by the manifest alias in `importers.<path>.dependencies`, but resolves its `version` field to
/// `<real-name>@<real-version>` rather than a plain semver string — so the importer key must
/// never be used as the resolved package name for an aliased entry (mirrors
/// [`parse_package_lock_json`]'s `entry.name`-based handling of npm's own `npm:` alias form,
/// issue #654). A regular, non-aliased entry's `version` field never contains `@` (semver
/// strings don't use it), so splitting on the *last* `@` — which also correctly separates a
/// scoped real name like `@myorg/pkg@1.2.3` — is an unambiguous signal: no split point falls
/// back to treating `raw_version` as a plain version under `importer_key`'s name.
fn resolve_pnpm_entry_name_and_version<'a>(
    importer_key: &'a str,
    raw_version: &'a str,
) -> (&'a str, &'a str) {
    let base = strip_peer_suffix(raw_version);
    match base.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() => (name, version),
        _ => (importer_key, base),
    }
}

/// Strips a parenthesized peer-dependency suffix from a pnpm-resolved version string, e.g.
/// `"1.2.3(react@18.2.0)"` -> `"1.2.3"` (spec 052 FR-004).
fn strip_peer_suffix(version: &str) -> &str {
    version.split_once('(').map_or(version, |(base, _)| base)
}

/// Renders a scalar YAML node as a string regardless of whether pnpm wrote it quoted
/// (`Yaml::String`) or bare (`Yaml::Real`/`Yaml::Integer`) — `yaml-rust2`'s `as_str` only
/// matches `Yaml::String`, so an unquoted numeric-looking scalar (a bare `6.0` `lockfileVersion`,
/// or a two-component `version: 1.0`) would otherwise be silently treated as absent. Shared by
/// the `lockfileVersion` gate and the per-entry `version` field read, both of which face the
/// same yaml-rust2 String/Real/Integer gotcha.
fn yaml_scalar_string(node: &Yaml) -> Option<String> {
    match node {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

/// Extracts package name from lockfile key.
///
/// # Examples
///
/// - `"node_modules/express"` → `"express"`
/// - `"node_modules/@babel/core"` → `"@babel/core"`
/// - `"node_modules/express/node_modules/debug"` → `"debug"`
fn extract_package_name(key: &str) -> &str {
    // Find the last occurrence of "node_modules/"
    key.rsplit("node_modules/").next().unwrap_or(key)
}

/// Parses npm source information into ResolvedSource.
///
/// # Source Detection
///
/// - `link: true` → Path (local package)
/// - `resolved` URL with `integrity` → Registry
/// - `resolved` git URL → Git
/// - No `resolved` → Path (workspace dependency)
fn parse_npm_source(entry: &PackageEntry) -> ResolvedSource {
    // Local packages (link: true)
    if entry.link == Some(true) {
        return ResolvedSource::Path {
            path: String::new(),
        };
    }

    // Parse resolved URL
    if let Some(resolved_url) = &entry.resolved {
        // Git sources (various formats)
        if resolved_url.starts_with("git+")
            || resolved_url.starts_with("git://")
            || resolved_url.contains("github.com")
                && (resolved_url.contains(".git") || resolved_url.contains("/tarball/"))
        {
            return parse_git_source(resolved_url);
        }

        // Registry source with integrity
        if let Some(integrity) = &entry.integrity {
            return ResolvedSource::Registry {
                url: resolved_url.clone(),
                checksum: integrity.clone(),
            };
        }

        // Registry without integrity (shouldn't happen in v2+, but handle it)
        return ResolvedSource::Registry {
            url: resolved_url.clone(),
            checksum: String::new(),
        };
    }

    // No resolved URL means local/workspace dependency
    ResolvedSource::Path {
        path: String::new(),
    }
}

/// Parses Git source URL and extracts commit hash.
///
/// # Git URL Formats
///
/// - `git+https://github.com/user/repo.git#abc123` → rev: abc123
/// - `https://github.com/user/repo/tarball/abc123` → rev: abc123
/// - `git://github.com/user/repo.git#v1.0.0` → rev: v1.0.0
// `idx` comes from `rfind("/tarball/")`, an ASCII token, so `idx` and `idx + 9` are always
// char boundaries.
#[allow(clippy::string_slice)]
fn parse_git_source(url: &str) -> ResolvedSource {
    // Try to extract commit hash from URL
    let (clean_url, rev) = if let Some((base, hash)) = url.split_once('#') {
        (base.to_string(), hash.to_string())
    } else if url.contains("/tarball/") {
        // GitHub tarball URL: .../tarball/commitish
        if let Some(idx) = url.rfind("/tarball/") {
            let base = &url[..idx];
            let hash = &url[idx + 9..]; // len("/tarball/") = 9
            (base.to_string(), hash.to_string())
        } else {
            (url.to_string(), String::new())
        }
    } else {
        (url.to_string(), String::new())
    };

    // Remove git+ prefix if present
    let clean_url = clean_url
        .strip_prefix("git+")
        .unwrap_or(&clean_url)
        .to_string();

    ResolvedSource::Git {
        url: clean_url,
        rev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_package_name_simple() {
        assert_eq!(extract_package_name("node_modules/express"), "express");
    }

    #[test]
    fn test_extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("node_modules/@babel/core"),
            "@babel/core"
        );
    }

    #[test]
    fn test_extract_package_name_nested() {
        assert_eq!(
            extract_package_name("node_modules/express/node_modules/debug"),
            "debug"
        );
    }

    #[test]
    fn test_parse_npm_source_registry() {
        let entry = PackageEntry {
            name: None,
            version: Some("4.18.2".into()),
            resolved: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".into()),
            integrity: Some("sha512-abc123".into()),
            link: None,
            dependencies: HashMap::new(),
        };

        let source = parse_npm_source(&entry);

        match source {
            ResolvedSource::Registry { url, checksum } => {
                assert_eq!(
                    url,
                    "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
                );
                assert_eq!(checksum, "sha512-abc123");
            }
            _ => panic!("Expected Registry source"),
        }
    }

    #[test]
    fn test_parse_npm_source_link() {
        let entry = PackageEntry {
            name: None,
            version: Some("1.0.0".into()),
            resolved: None,
            integrity: None,
            link: Some(true),
            dependencies: HashMap::new(),
        };

        let source = parse_npm_source(&entry);

        match source {
            ResolvedSource::Path { .. } => {}
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_parse_git_source_with_hash() {
        let source = parse_git_source("git+https://github.com/user/repo.git#abc123");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_git_source_tarball() {
        let source = parse_git_source("https://github.com/user/repo/tarball/abc123");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_git_source_no_hash() {
        let source = parse_git_source("git+https://github.com/user/repo.git");

        match source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert!(rev.is_empty());
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_parse_simple_package_lock() {
        let lockfile_content = r#"{
  "name": "my-project",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-project",
      "dependencies": {
        "express": "^4.18.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-abc123",
      "dependencies": {
        "body-parser": "1.20.1"
      }
    },
    "node_modules/body-parser": {
      "version": "1.20.1",
      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz",
      "integrity": "sha512-def456"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved.get_version("express"), Some("4.18.2"));
        assert_eq!(resolved.get_version("body-parser"), Some("1.20.1"));

        let express_pkg = resolved.get("express").unwrap();
        assert_eq!(express_pkg.dependencies.len(), 1);
        assert_eq!(express_pkg.dependencies[0], "body-parser");
    }

    /// Issue #654 S1: an `npm:` alias installs under `node_modules/<alias>`, but npm records
    /// the real package name in the entry's own `"name"` field — that must win over the
    /// key-derived alias basename, so `Dependency::name()` (the real name) finds this entry.
    #[tokio::test]
    async fn test_parse_package_lock_with_npm_alias_resolves_real_name() {
        let lockfile_content = r#"{
  "name": "my-project",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-project",
      "dependencies": {
        "my-react": "npm:react@^18.0.0"
      }
    },
    "node_modules/my-react": {
      "name": "react",
      "version": "18.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
      "integrity": "sha512-abc123"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
        assert_eq!(
            resolved.get_version("my-react"),
            None,
            "the alias key must not shadow the real package name"
        );
    }

    #[tokio::test]
    async fn test_parse_package_lock_with_git() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "my-git-dep": "github:user/repo#abc123"
      }
    },
    "node_modules/my-git-dep": {
      "version": "0.1.0",
      "resolved": "git+https://github.com/user/repo.git#abc123"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        let pkg = resolved.get("my-git-dep").unwrap();
        assert_eq!(pkg.version, "0.1.0");

        match &pkg.source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[tokio::test]
    async fn test_parse_package_lock_with_local() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "my-local": "file:../my-local"
      }
    },
    "node_modules/my-local": {
      "version": "1.0.0",
      "link": true
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        let pkg = resolved.get("my-local").unwrap();

        match &pkg.source {
            ResolvedSource::Path { .. } => {}
            _ => panic!("Expected Path source for local package"),
        }
    }

    #[tokio::test]
    async fn test_parse_empty_package_lock() {
        let lockfile_content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "empty-project"
    }
  }
}"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 0);
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_parse_malformed_package_lock() {
        let lockfile_content = "not valid json {{{";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let content = format!(
            r#"{{"packages": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, &content).await.unwrap();

        let parser = NpmLockParser;
        assert!(parser.parse_lockfile(&lockfile_path).await.is_ok());
    }

    #[tokio::test]
    async fn test_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let content = format!(
            r#"{{"packages": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        tokio::fs::write(&lockfile_path, &content).await.unwrap();

        let parser = NpmLockParser;
        assert!(parser.parse_lockfile(&lockfile_path).await.is_err());
    }

    #[test]
    fn test_locate_lockfile_same_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        let lock_path = temp_dir.path().join("package-lock.json");

        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();
        std::fs::write(&lock_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_workspace_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_lock = temp_dir.path().join("package-lock.json");
        let member_dir = temp_dir.path().join("packages").join("member");
        std::fs::create_dir_all(&member_dir).unwrap();
        let member_manifest = member_dir.join("package.json");

        std::fs::write(&workspace_lock, r#"{"lockfileVersion": 3}"#).unwrap();
        std::fs::write(&member_manifest, r#"{"name": "member"}"#).unwrap();

        let manifest_uri = Uri::from_file_path(&member_manifest).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), workspace_lock);
    }

    #[test]
    fn test_locate_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_none());
    }

    #[test]
    fn test_is_lockfile_stale_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let mtime = std::fs::metadata(&lockfile_path)
            .unwrap()
            .modified()
            .unwrap();
        let parser = NpmLockParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, mtime),
            "Lock file should not be stale when mtime matches"
        );
    }

    #[test]
    fn test_is_lockfile_stale_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        let old_time = std::time::UNIX_EPOCH;
        let parser = NpmLockParser;

        assert!(
            parser.is_lockfile_stale(&lockfile_path, old_time),
            "Lock file should be stale when last_modified is old"
        );
    }

    #[test]
    fn test_is_lockfile_stale_deleted() {
        let parser = NpmLockParser;
        let non_existent = std::path::Path::new("/nonexistent/package-lock.json");

        assert!(
            parser.is_lockfile_stale(non_existent, std::time::SystemTime::now()),
            "Non-existent lock file should be considered stale"
        );
    }

    #[test]
    fn test_is_lockfile_stale_future_time() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("package-lock.json");
        std::fs::write(&lockfile_path, r#"{"lockfileVersion": 3}"#).unwrap();

        // Use a time far in the future
        let future_time = std::time::SystemTime::now() + std::time::Duration::from_hours(24);
        let parser = NpmLockParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, future_time),
            "Lock file should not be stale when last_modified is in the future"
        );
    }

    // --- pnpm-lock.yaml (spec 052) ---

    #[tokio::test]
    async fn test_parse_pnpm_lock_single_importer() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0
    devDependencies:
      typescript:
        specifier: ^5.3.0
        version: 5.3.3
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
        assert_eq!(resolved.get_version("typescript"), Some("5.3.3"));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_monorepo_multi_importer_aggregation() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.0.0
        version: 4.17.21
  packages/foo:
    dependencies:
      lodash:
        specifier: ^3.0.0
        version: 3.10.1
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved.get_all("lodash").unwrap().len(), 2);
        assert_eq!(resolved.get_version("lodash"), Some("4.17.21"));
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_strips_peer_suffix() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      use-sync-external-store:
        specifier: ^1.2.0
        version: 1.2.0(react@18.2.0)
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(
            resolved.get_version("use-sync-external-store"),
            Some("1.2.0")
        );
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_skips_link_entries() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      shared-lib:
        specifier: workspace:*
        version: link:../shared-lib
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get_version("shared-lib"), None);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_malformed_yaml_is_parse_error() {
        let lockfile_content = "importers: [unterminated";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        let Err(DepsError::ParseError { file_type, .. }) = result else {
            panic!("expected DepsError::ParseError, got {result:?}");
        };
        assert!(file_type.contains("pnpm-lock.yaml"));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_empty_importers_is_empty_not_error() {
        let lockfile_content = "lockfileVersion: '9.0'\n";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_explicit_empty_importers_map_is_empty_not_error() {
        let lockfile_content = "lockfileVersion: '9.0'\nimporters: {}\n";

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_unsupported_lockfile_version_is_parse_error() {
        let lockfile_content = r"
lockfileVersion: '5.4'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        let Err(DepsError::ParseError { file_type, source }) = result else {
            panic!("expected DepsError::ParseError, got {result:?}");
        };
        assert!(file_type.contains("pnpm-lock.yaml"));
        assert!(source.to_string().contains("5.4"));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_non_scalar_lockfile_version_is_parse_error() {
        let lockfile_content = r"
lockfileVersion:
  - 9
  - 0
importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let result = parser.parse_lockfile(&lockfile_path).await;

        assert!(matches!(result, Err(DepsError::ParseError { .. })));
    }

    #[tokio::test]
    async fn test_parse_pnpm_lock_optional_dependencies() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    optionalDependencies:
      fsevents:
        specifier: ^2.3.0
        version: 2.3.3
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.get_version("fsevents"), Some("2.3.3"));
    }

    /// One importer with `dependencies`, `devDependencies`, and `optionalDependencies` all
    /// present — every section must contribute its entries to the same aggregated result.
    #[tokio::test]
    async fn test_parse_pnpm_lock_all_three_sections_in_one_importer() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0
    devDependencies:
      typescript:
        specifier: ^5.3.0
        version: 5.3.3
    optionalDependencies:
      fsevents:
        specifier: ^2.3.0
        version: 2.3.3
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
        assert_eq!(resolved.get_version("typescript"), Some("5.3.3"));
        assert_eq!(resolved.get_version("fsevents"), Some("2.3.3"));
    }

    /// S3 regression: pnpm resolves an `npm:`-aliased importer dependency's `version` field to
    /// `<real-name>@<real-version>`, keyed in `importers.<path>.dependencies` by the manifest
    /// alias — the alias key must never leak in as the resolved package name (mirrors issue
    /// #654's `package-lock.json` handling).
    #[tokio::test]
    async fn test_parse_pnpm_lock_npm_alias_resolves_real_name() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      my-lodash:
        specifier: npm:lodash@^4.17.0
        version: lodash@4.17.21
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get_version("lodash"), Some("4.17.21"));
        assert_eq!(
            resolved.get_version("my-lodash"),
            None,
            "the alias key must not shadow the real package name"
        );
    }

    /// S3: a scoped real package name behind an alias (`@myorg/pkg@1.2.3`) must still split on
    /// the *last* `@`, not the first (which would land inside the scope segment).
    #[tokio::test]
    async fn test_parse_pnpm_lock_npm_alias_resolves_scoped_real_name() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      my-pkg:
        specifier: npm:@myorg/pkg@^1.0.0
        version: '@myorg/pkg@1.2.3'
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.get_version("@myorg/pkg"), Some("1.2.3"));
        assert_eq!(resolved.get_version("my-pkg"), None);
    }

    /// S2 regression: a non-semver-shaped resolution (`file:`, a bare tarball URL,
    /// `workspace:*`) must not be stored as a fake resolved version — it would otherwise flow
    /// verbatim into hover text and OSV vulnerability-lookup queries.
    #[tokio::test]
    async fn test_parse_pnpm_lock_skips_non_semver_versions() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      local-tarball:
        specifier: file:../local-tarball.tgz
        version: file:../local-tarball.tgz
      from-git:
        specifier: git+https://github.com/user/repo.git
        version: https://codeload.github.com/user/repo/tar.gz/abc123
      workspace-star:
        specifier: workspace:*
        version: workspace:*
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
        assert_eq!(resolved.get_version("local-tarball"), None);
        assert_eq!(resolved.get_version("from-git"), None);
        assert_eq!(resolved.get_version("workspace-star"), None);
    }

    /// Code-review regression: an unquoted, numeric-looking `version` (e.g. `version: 1.0`)
    /// parses as `Yaml::Real`, not `Yaml::String` — `as_str()` alone would silently drop the
    /// entry via `continue` with no explanation. `yaml_scalar_string` coerces it the same way
    /// it already does for `lockfileVersion`, so the entry reaches the (still-applicable)
    /// semver-shape gate — a two-component value is not a valid registry-resolved version
    /// either way, but it is now evaluated and skipped for that reason, not silently dropped
    /// for looking like the wrong YAML type.
    #[tokio::test]
    async fn test_parse_pnpm_lock_coerces_unquoted_numeric_version_then_semver_gate_skips_it() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      widget:
        specifier: ^1.0.0
        version: 1.0
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.get_version("widget"), None);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
    }

    /// A `version` field that isn't even a scalar (e.g. a nested mapping) must be logged and
    /// skipped without panicking, and must not affect resolution of sibling entries.
    #[tokio::test]
    async fn test_parse_pnpm_lock_non_scalar_version_field_is_skipped_without_panic() {
        let lockfile_content = r"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      broken:
        specifier: ^1.0.0
        version:
          nested: mapping
      react:
        specifier: ^18.0.0
        version: 18.2.0
";
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("pnpm-lock.yaml");
        tokio::fs::write(&lockfile_path, lockfile_content)
            .await
            .unwrap();

        let parser = NpmLockParser;
        let resolved = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(resolved.get_version("broken"), None);
        assert_eq!(resolved.get_version("react"), Some("18.2.0"));
    }

    #[test]
    fn test_locate_lockfile_prefers_package_lock_json_over_pnpm() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        let npm_lock = temp_dir.path().join("package-lock.json");
        let pnpm_lock = temp_dir.path().join("pnpm-lock.yaml");

        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();
        std::fs::write(&npm_lock, r#"{"lockfileVersion": 3}"#).unwrap();
        std::fs::write(&pnpm_lock, "lockfileVersion: '9.0'\n").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        assert_eq!(parser.locate_lockfile(&manifest_uri).unwrap(), npm_lock);
    }

    #[test]
    fn test_locate_lockfile_falls_back_to_pnpm_when_no_package_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("package.json");
        let pnpm_lock = temp_dir.path().join("pnpm-lock.yaml");

        std::fs::write(&manifest_path, r#"{"name": "test"}"#).unwrap();
        std::fs::write(&pnpm_lock, "lockfileVersion: '9.0'\n").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NpmLockParser;

        assert_eq!(parser.locate_lockfile(&manifest_uri).unwrap(), pnpm_lock);
    }
}
