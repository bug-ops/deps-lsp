//! pubspec.lock file parsing.

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_lockfile_content,
};
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;
use yaml_rust2::{Yaml, YamlLoader};

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

            let content = read_lockfile_content(lockfile_path, "pubspec.lock").await?;

            parse_pubspec_lock(&content)
        })
    }
}

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
            let Some(version) = entry["version"].as_str() else {
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

            packages.insert(ResolvedPackage {
                name: name.to_string(),
                version,
                source,
                dependencies: vec![],
            });
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

    #[test]
    fn test_locate_lockfile() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("pubspec.yaml");
        let lock_path = temp_dir.path().join("pubspec.lock");

        std::fs::write(&manifest_path, "name: test").unwrap();
        std::fs::write(&lock_path, "packages:\n").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = PubspecLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("pubspec.yaml");
        std::fs::write(&manifest_path, "name: test").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = PubspecLockParser;

        assert!(parser.locate_lockfile(&manifest_uri).is_none());
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
