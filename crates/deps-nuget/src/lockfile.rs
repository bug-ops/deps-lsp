//! `packages.lock.json` parser.
//!
//! Every field except the package name is optional (S2): `"type": "Project"` and
//! `"type": "CentralTransitive"` entries carry `requested` but no `resolved` at all — a
//! required `resolved` field would abort deserialization of the *entire* file, which would
//! only surface on multi-project solutions and not on the single-project fixture a test is
//! most likely to use. Entries without `resolved` are simply skipped.
//!
//! `packages.<project_name>.lock.json` cannot be expressed here — `lockfile_filenames()` is
//! an exact-name list with no glob support (D3, follow-up).
// TODO(critic): multi-project lock file names (packages.<project>.lock.json) cannot be
// expressed as exact names.

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;

const NUGET_ORG_URL: &str = "https://api.nuget.org/v3/index.json";

pub struct NuGetLockParser;

impl NuGetLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["packages.lock.json"];
}

#[derive(Deserialize)]
struct PackagesLock {
    // The top-level "version" field (1 or 2) is intentionally not modeled: both schema
    // versions are accepted without gating on its value, and serde ignores unknown fields
    // by default, so there is nothing to read it for.
    #[serde(default)]
    dependencies: HashMap<String, HashMap<String, LockEntry>>,
}

#[derive(Deserialize)]
struct LockEntry {
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default, rename = "contentHash")]
    content_hash: Option<String>,
}

impl LockFileProvider for NuGetLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, Self::LOCKFILE_NAMES)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing packages.lock.json: {}", lockfile_path.display());

            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(|e| DepsError::ParseError {
                    file_type: format!("packages.lock.json at {}", lockfile_path.display()),
                    source: Box::new(e),
                })?;

            let lock_data: PackagesLock =
                serde_json::from_str(&content).map_err(|e| DepsError::ParseError {
                    file_type: "packages.lock.json".into(),
                    source: Box::new(e),
                })?;

            // Collect every TFM's resolved version per package name, then resolve the
            // cross-TFM tie-break with the crate's own `compare_versions` (S6) instead of
            // `deps_core::lockfile::best_package`, whose `semver::Version::parse` fallback
            // always fails on NuGet's 4-component versions and degrades to string
            // comparison (e.g. "1.10.0" < "1.9.0"). Only the single winner is ever handed
            // to `ResolvedPackages`, so that broken comparator is never reached.
            let mut candidates: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
            for packages in lock_data.dependencies.into_values() {
                for (name, entry) in packages {
                    // "type": "Project" / "CentralTransitive" entries carry no `resolved`
                    // at all — skip rather than aborting the whole file (S2).
                    if let Some(resolved) = entry.resolved {
                        candidates
                            .entry(name)
                            .or_default()
                            .push((resolved, entry.content_hash));
                    }
                }
            }

            let mut packages = ResolvedPackages::new();
            for (name, versions) in candidates {
                let best = versions
                    .into_iter()
                    .max_by(|a, b| crate::version::compare_versions(&a.0, &b.0));
                if let Some((version, content_hash)) = best {
                    packages.insert(ResolvedPackage {
                        name,
                        version,
                        source: ResolvedSource::Registry {
                            url: NUGET_ORG_URL.into(),
                            checksum: content_hash.unwrap_or_default(),
                        },
                        dependencies: vec![],
                    });
                }
            }

            tracing::info!(
                "Parsed packages.lock.json: {} packages from {}",
                packages.len(),
                lockfile_path.display()
            );

            Ok(packages)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_single_tfm() {
        let content = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "abc123"
      }
    }
  }
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get_version("Newtonsoft.Json"), Some("13.0.3"));
    }

    #[tokio::test]
    async fn test_project_reference_entry_skipped() {
        let content = r#"{
  "version": 2,
  "dependencies": {
    "net8.0": {
      "MyCompany.Shared": { "type": "Project" },
      "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" }
    }
  }
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(resolved.get("MyCompany.Shared").is_none());
        assert_eq!(resolved.get_version("Newtonsoft.Json"), Some("13.0.3"));
    }

    #[tokio::test]
    async fn test_multi_tfm_tie_break_uses_nuget_comparator() {
        // 4-component versions where "1.10.0.0" > "1.9.0.0" numerically but would sort the
        // other way under a broken semver-then-string fallback.
        let content = r#"{
  "version": 1,
  "dependencies": {
    "net472": {
      "Foo": { "type": "Direct", "resolved": "1.9.0.0" }
    },
    "net8.0": {
      "Foo": { "type": "Direct", "resolved": "1.10.0.0" }
    }
  }
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.get_version("Foo"), Some("1.10.0.0"));
    }

    #[tokio::test]
    async fn test_missing_optional_fields() {
        let content = r#"{
  "dependencies": {
    "net8.0": {
      "Bare": { "resolved": "1.0.0" }
    }
  }
}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.get_version("Bare"), Some("1.0.0"));
    }

    #[tokio::test]
    async fn test_invalid_json_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, b"not valid json").await.unwrap();

        let parser = NuGetLockParser;
        let result = parser.parse_lockfile(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_dependencies_returns_empty() {
        let content = r#"{"version": 1, "dependencies": {}}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 0);
    }

    #[test]
    fn test_locate_lockfile() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("App.csproj");
        let lock_path = temp_dir.path().join("packages.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        let located = parser.locate_lockfile(&manifest_uri);
        assert_eq!(located, Some(lock_path));
    }
}
