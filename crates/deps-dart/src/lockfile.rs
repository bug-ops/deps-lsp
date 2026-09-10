//! pubspec.lock file parsing.

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_and_parse_lockfile,
};
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;
use yaml_rust2::{Yaml, YamlLoader};

/// [`LockFileProvider`] implementation for `pubspec.lock`.
pub struct PubspecLockParser;

impl PubspecLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["pubspec.lock"];
}

impl LockFileProvider for PubspecLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing pubspec.lock: {}", lockfile_path.display());

            read_and_parse_lockfile(lockfile_path, "pubspec.lock", |content| {
                parse_pubspec_lock(&content)
            })
            .await
        })
    }
}

/// Parses a `pubspec.lock` file's resolved package versions.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] if the YAML nesting depth exceeds the
/// configured limit or the content is not valid YAML.
pub fn parse_pubspec_lock(content: &str) -> Result<ResolvedPackages> {
    if let Err(depth) =
        deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "pubspec.lock".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_YAML_NESTING_DEPTH
            ))),
        });
    }

    if let Err(bytes) = deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES)
    {
        return Err(DepsError::ParseError {
            file_type: "pubspec.lock".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML expansion {bytes} bytes exceeds maximum of {} bytes",
                deps_core::MAX_YAML_EXPANDED_BYTES
            ))),
        });
    }

    let mut packages = ResolvedPackages::new();

    let docs = YamlLoader::load_from_str(content).map_err(|e| DepsError::ParseError {
        file_type: "pubspec.lock".into(),
        source: Box::new(std::io::Error::other(e.to_string())),
    })?;

    let doc = match docs.first() {
        Some(d) => d,
        None => return Ok(packages),
    };

    if let Yaml::Hash(pkgs) = &doc["packages"] {
        for (name_yaml, entry) in pkgs {
            let Some(name) = name_yaml.as_str() else {
                continue;
            };
            // #721: goes through `yaml_scalar_string` rather than `as_str` directly —
            // an unquoted, numeric-looking version (`version: 1.0`, parsed as
            // `Yaml::Real`) is valid pubspec.lock syntax, and `as_str` alone would
            // silently skip the entry via this `continue`.
            let Some(version) = deps_core::yaml_scalar_string(&entry["version"]) else {
                continue;
            };

            let source_type = entry["source"].as_str().unwrap_or("hosted");
            let source = match source_type {
                "hosted" => {
                    let url = entry["description"]["url"]
                        .as_str()
                        .unwrap_or("https://pub.dev")
                        .to_string();
                    ResolvedSource::Registry {
                        url,
                        checksum: String::new(),
                    }
                }
                "git" => {
                    let url = entry["description"]["url"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let rev = entry["description"]["resolved-ref"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    ResolvedSource::Git { url, rev }
                }
                "path" => {
                    let path = entry["description"]["path"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    ResolvedSource::Path { path }
                }
                _ => ResolvedSource::Registry {
                    url: "https://pub.dev".to_string(),
                    checksum: String::new(),
                },
            };

            // Remove surrounding quotes from version if present
            let version = version.trim_matches('"').to_string();

            packages.insert(ResolvedPackage::new(name.to_string(), version, source));
        }
    }

    tracing::info!("Parsed pubspec.lock: {} packages", packages.len());

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_lock() {
        let lock = r#"
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  provider:
    dependency: "direct main"
    description:
      name: provider
      url: "https://pub.dev"
    source: hosted
    version: "6.1.2"
"#;
        let packages = parse_pubspec_lock(lock).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages.get_version("http"), Some("1.2.0"));
        assert_eq!(packages.get_version("provider"), Some("6.1.2"));
    }

    /// #721: an unquoted, numeric-looking version (`version: 1.0`, parsed by
    /// `yaml-rust2` as `Yaml::Real`, not `Yaml::String`) is valid YAML — the entry
    /// must still be read, not silently skipped via the `continue` guard a plain
    /// `Yaml::as_str()` read would hit.
    #[test]
    fn test_parse_unquoted_numeric_version() {
        let lock = r#"
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: 1.0
"#;
        let packages = parse_pubspec_lock(lock).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages.get_version("http"), Some("1.0"));
    }

    #[test]
    fn test_parse_git_source() {
        let lock = r#"
packages:
  my_pkg:
    dependency: "direct main"
    description:
      url: "https://github.com/user/repo.git"
      resolved-ref: abc123
    source: git
    version: "0.1.0"
"#;
        let packages = parse_pubspec_lock(lock).unwrap();
        let pkg = packages.get("my_pkg").unwrap();
        match &pkg.source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_path_source() {
        let lock = r#"
packages:
  local_pkg:
    dependency: "direct main"
    description:
      path: "../local_pkg"
    source: path
    version: "0.1.0"
"#;
        let packages = parse_pubspec_lock(lock).unwrap();
        let pkg = packages.get("local_pkg").unwrap();
        match &pkg.source {
            ResolvedSource::Path { path } => {
                assert_eq!(path, "../local_pkg");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_parse_empty_lock() {
        let lock = "";
        let packages = parse_pubspec_lock(lock).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn test_deeply_nested_lock_rejected_not_crashed() {
        // 6000 comfortably exceeds the empirically bisected real
        // `yaml-rust2` 0.12 crash threshold for this exact payload shape
        // (compact dash chain: aborts at depth 4536 on a 2 MiB debug
        // stack), so this is a genuine regression test for the pre-fix
        // SIGABRT, not just proof the 64 limit fires.
        let lock = format!("{}1", "- ".repeat(6000));
        let result = parse_pubspec_lock(&lock);
        assert!(result.is_err());
    }

    #[test]
    fn test_deeply_nested_lock_with_apostrophe_rejected_not_crashed() {
        // impl-critic C1: a `'`/`"` inside a plain scalar earlier in the
        // file must not blind the guard to real nesting later in the file.
        let lock = format!(
            "packages:\n  http:\n    description: it doesn't matter\n{}1",
            "- ".repeat(6000)
        );
        let result = parse_pubspec_lock(&lock);
        assert!(result.is_err());
    }

    #[test]
    fn test_anchor_alias_expansion_bomb_rejected_not_oomed() {
        // #175: a shallow (depth-2) doubling chain of anchor/alias
        // references, which `check_yaml_nesting_depth` cannot catch since
        // nesting depth stays constant — must be rejected by the expansion
        // budget instead of handed to `YamlLoader::load_from_str`, which
        // would OOM/SIGKILL the process on this shape.
        let mut lock = String::from("packages:\n  a0: &a0 [x, x]\n");
        for i in 1..=30 {
            lock.push_str(&format!(
                "  a{i}: &a{i} [*a{prev}, *a{prev}]\n",
                prev = i - 1
            ));
        }
        let result = parse_pubspec_lock(&lock);
        // Asserting on the message (not just `is_err()`) pins that this is
        // rejected by the expansion guard specifically, so a future reorder
        // that lets a different guard fire first would be caught.
        let err = result.expect_err("expected the expansion budget to reject this");
        assert!(
            err.to_string().contains("YAML expansion"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_asterisk_in_description_not_misread_as_alias() {
        let lock = r#"
packages:
  http:
    dependency: "direct main"
    description: A package for *multiplier* http requests
    source: hosted
    version: "1.2.0"
"#;
        let result = parse_pubspec_lock(lock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_realistic_pubspec_lock_still_parses() {
        let lock = r#"
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
"#;
        let packages = parse_pubspec_lock(lock).unwrap();
        assert_eq!(packages.get_version("http"), Some("1.2.0"));
    }

    // #758: shared `LockFileProvider` conformance, replacing test_locate_lockfile and
    // test_locate_lockfile_not_found — deps-dart had no prior `is_lockfile_stale` coverage at
    // all, so this also adds that.
    deps_core::lockfile_conformance! {
        mod dart_lockfile_conformance;
        build: PubspecLockParser;
        manifest: "pubspec.yaml" => "name: test";
        lockfiles: [
            "pubspec.lock" => "packages:\n",
        ];
        malformed: "not valid yaml: [[[";
    }

    #[tokio::test]
    async fn test_parse_lockfile_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("pubspec.lock");

        let content = r#"
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
"#;
        std::fs::write(&lock_path, content).unwrap();

        let parser = PubspecLockParser;
        let packages = parser.parse_lockfile(&lock_path).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages.get_version("http"), Some("1.2.0"));
    }
}
