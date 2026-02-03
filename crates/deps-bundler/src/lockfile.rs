//! Gemfile.lock file parsing.
//!
//! Parses Gemfile.lock files to extract resolved dependency versions.

use async_trait::async_trait;
use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

/// Gemfile.lock parser.
pub struct GemfileLockParser;

impl GemfileLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["Gemfile.lock"];
}

// Regex for parsing gem specs: "    gemname (version)"
static GEM_SPEC_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)").expect("Invalid regex"));

#[derive(Debug, Clone, Copy, PartialEq)]
enum Section {
    None,
    Gem,
    Git,
    Path,
    Platforms,
    Dependencies,
    BundledWith,
    RubyVersion,
}

#[async_trait]
impl LockFileProvider for GemfileLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    async fn parse_lockfile(&self, lockfile_path: &Path) -> Result<ResolvedPackages> {
        tracing::debug!("Parsing Gemfile.lock: {}", lockfile_path.display());

        let content = tokio::fs::read_to_string(lockfile_path)
            .await
            .map_err(|e| DepsError::ParseError {
                file_type: format!("Gemfile.lock at {}", lockfile_path.display()),
                source: Box::new(e),
            })?;

        parse_gemfile_lock(&content)
    }
}

/// Parses Gemfile.lock content and extracts resolved packages.
pub fn parse_gemfile_lock(content: &str) -> Result<ResolvedPackages> {
    let mut packages = ResolvedPackages::new();
    let mut current_section = Section::None;
    let mut current_source = ResolvedSource::Registry {
        url: "https://rubygems.org".to_string(),
        checksum: String::new(),
    };
    let mut in_specs = false;

    for line in content.lines() {
        // Check for section headers
        if let Some(section) = detect_section(line) {
            current_section = section;
            in_specs = false;

            // Reset source based on section
            current_source = match section {
                Section::Gem => ResolvedSource::Registry {
                    url: "https://rubygems.org".to_string(),
                    checksum: String::new(),
                },
                Section::Git => ResolvedSource::Git {
                    url: String::new(),
                    rev: String::new(),
                },
                Section::Path => ResolvedSource::Path {
                    path: String::new(),
                },
                _ => current_source.clone(),
            };
            continue;
        }

        // Check for "specs:" marker
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }

        // Update source URL for GIT/PATH sections
        if line.starts_with("  remote:") {
            let url = line.trim_start_matches("  remote:").trim().to_string();
            current_source = match current_section {
                Section::Gem => ResolvedSource::Registry {
                    url,
                    checksum: String::new(),
                },
                Section::Git => ResolvedSource::Git {
                    url,
                    rev: String::new(),
                },
                Section::Path => ResolvedSource::Path { path: url },
                _ => current_source.clone(),
            };
            continue;
        }

        // Update revision for GIT section
        if line.starts_with("  revision:") {
            if let ResolvedSource::Git { url, .. } = &current_source {
                let rev = line.trim_start_matches("  revision:").trim().to_string();
                current_source = ResolvedSource::Git {
                    url: url.clone(),
                    rev,
                };
            }
            continue;
        }

        // Parse gem specs
        if in_specs
            && matches!(current_section, Section::Gem | Section::Git | Section::Path)
            && let Some(caps) = GEM_SPEC_PATTERN.captures(line)
        {
            let name = caps[1].to_string();
            let version = caps[2].to_string();

            packages.insert(ResolvedPackage {
                name,
                version,
                source: current_source.clone(),
                dependencies: vec![],
            });
        }
    }

    tracing::info!("Parsed Gemfile.lock: {} packages", packages.len());

    Ok(packages)
}

fn detect_section(line: &str) -> Option<Section> {
    match line.trim() {
        "GEM" => Some(Section::Gem),
        "GIT" => Some(Section::Git),
        "PATH" => Some(Section::Path),
        "PLATFORMS" => Some(Section::Platforms),
        "DEPENDENCIES" => Some(Section::Dependencies),
        "BUNDLED WITH" => Some(Section::BundledWith),
        "RUBY VERSION" => Some(Section::RubyVersion),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_gemfile_lock() {
        let lockfile = r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)
    pg (1.5.4)
    puma (6.4.0)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  pg (>= 1.1)
  puma (~> 6.0)
  rails (~> 7.0)

BUNDLED WITH
   2.5.3
"#;

        let packages = parse_gemfile_lock(lockfile).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages.get_version("rails"), Some("7.0.8"));
        assert_eq!(packages.get_version("pg"), Some("1.5.4"));
        assert_eq!(packages.get_version("puma"), Some("6.4.0"));
    }

    #[test]
    fn test_parse_git_source() {
        let lockfile = r#"GIT
  remote: https://github.com/rails/rails.git
  revision: abc123
  specs:
    rails (7.1.0.alpha)

GEM
  remote: https://rubygems.org/
  specs:
    pg (1.5.4)

DEPENDENCIES
  rails!
  pg

BUNDLED WITH
   2.5.3
"#;

        let packages = parse_gemfile_lock(lockfile).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages.get_version("rails"), Some("7.1.0.alpha"));

        let rails = packages.get("rails").unwrap();
        match &rails.source {
            ResolvedSource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/rails/rails.git");
                assert_eq!(rev, "abc123");
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_path_source() {
        let lockfile = r#"PATH
  remote: ../my_gem
  specs:
    my_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    pg (1.5.4)

DEPENDENCIES
  my_gem!
  pg

BUNDLED WITH
   2.5.3
"#;

        let packages = parse_gemfile_lock(lockfile).unwrap();
        assert_eq!(packages.len(), 2);

        let my_gem = packages.get("my_gem").unwrap();
        match &my_gem.source {
            ResolvedSource::Path { path } => {
                assert_eq!(path, "../my_gem");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_parse_empty_lockfile() {
        let lockfile = "";
        let packages = parse_gemfile_lock(lockfile).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn test_locate_lockfile_same_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Gemfile");
        let lock_path = temp_dir.path().join("Gemfile.lock");

        std::fs::write(&manifest_path, "source 'https://rubygems.org'").unwrap();
        std::fs::write(&lock_path, "GEM\n  specs:\n").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = GemfileLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_some());
        assert_eq!(located.unwrap(), lock_path);
    }

    #[test]
    fn test_locate_lockfile_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Gemfile");
        std::fs::write(&manifest_path, "source 'https://rubygems.org'").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = GemfileLockParser;

        let located = parser.locate_lockfile(&manifest_uri);
        assert!(located.is_none());
    }

    #[tokio::test]
    async fn test_parse_lockfile_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("Gemfile.lock");

        let content = r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.8)

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.3
"#;
        std::fs::write(&lockfile_path, content).unwrap();

        let parser = GemfileLockParser;
        let packages = parser.parse_lockfile(&lockfile_path).await.unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages.get_version("rails"), Some("7.0.8"));
    }

    #[test]
    fn test_is_lockfile_stale_not_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("Gemfile.lock");
        std::fs::write(&lockfile_path, "GEM\n  specs:\n").unwrap();

        let mtime = std::fs::metadata(&lockfile_path)
            .unwrap()
            .modified()
            .unwrap();
        let parser = GemfileLockParser;

        assert!(
            !parser.is_lockfile_stale(&lockfile_path, mtime),
            "Lock file should not be stale when mtime matches"
        );
    }

    #[test]
    fn test_is_lockfile_stale_modified() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("Gemfile.lock");
        std::fs::write(&lockfile_path, "GEM\n  specs:\n").unwrap();

        let old_time = std::time::UNIX_EPOCH;
        let parser = GemfileLockParser;

        assert!(
            parser.is_lockfile_stale(&lockfile_path, old_time),
            "Lock file should be stale when last_modified is old"
        );
    }
}
