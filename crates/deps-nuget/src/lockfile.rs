//! `packages.lock.json` parser.
//!
//! Every field except the package name is optional (S2): `"type": "Project"` and
//! `"type": "CentralTransitive"` entries carry `requested` but no `resolved` at all — a
//! required `resolved` field would abort deserialization of the *entire* file, which would
//! only surface on multi-project solutions and not on the single-project fixture a test is
//! most likely to use. Entries without `resolved` are simply skipped.
//!
//! `packages.<project_name>.lock.json` (per-project lock files, used when multiple projects
//! share a directory) cannot be expressed as an exact name —
//! [`NuGetLockParser::locate_lockfile`] falls back to that computed name (`<project_name>`
//! being the manifest's own file stem, NuGet's convention) once the exact
//! `packages.lock.json` name misses (D3, #451). This must be an exact match against *this*
//! manifest's project name, not the first `packages.*.lock.json` found in the directory —
//! a directory shared by multiple projects can hold several such files, and taking the
//! first one silently attaches an unrelated project's resolved versions (#451 follow-up,
//! tester-found regression).

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_lockfile_content,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tower_lsp_server::ls_types::Uri;

/// Mirrors `deps_core::lockfile::locate_lockfile_for_manifest`'s workspace-root search
/// depth, so the multi-project fallback below walks exactly the same directories the
/// exact-name search already tried.
const MAX_WORKSPACE_DEPTH: usize = 5;

pub struct NuGetLockParser;

impl NuGetLockParser {
    const LOCKFILE_NAMES: &'static [&'static str] = &["packages.lock.json"];
}

/// Falls back to *this manifest's own* multi-project lock file name —
/// `packages.<project_name>.lock.json`, where `<project_name>` is the manifest's file stem
/// (NuGet's convention: the project name defaults to the project file's name without its
/// extension) — once the exact `packages.lock.json` search (same directory, then up to
/// [`MAX_WORKSPACE_DEPTH`] parent directories) has already missed. Mirrors
/// `locate_lockfile_for_manifest`'s own directory-walk order, but against this one computed
/// filename rather than a fixed list — an exact match, deliberately, not "the first
/// `packages.*.lock.json` in the directory": a directory shared by multiple projects can
/// hold several per-project lock files, and picking the wrong one would silently attach an
/// unrelated project's resolved versions (#451 follow-up regression).
fn locate_multi_project_lockfile(manifest_uri: &Uri) -> Option<PathBuf> {
    let manifest_path = manifest_uri.to_file_path()?;
    let project_name = manifest_path.file_stem()?.to_str()?;
    if project_name.is_empty() {
        return None;
    }
    let lock_filename = format!("packages.{project_name}.lock.json");
    let manifest_dir = manifest_path.parent()?;

    let mut lock_path = manifest_dir.to_path_buf();
    lock_path.push(&lock_filename);
    if lock_path.is_file() {
        return Some(lock_path);
    }

    let mut current_dir = manifest_dir.parent()?;
    for _ in 0..MAX_WORKSPACE_DEPTH {
        lock_path = current_dir.join(&lock_filename);
        if lock_path.is_file() {
            return Some(lock_path);
        }
        current_dir = current_dir.parent()?;
    }
    None
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
            .or_else(|| locate_multi_project_lockfile(manifest_uri))
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing packages.lock.json: {}", lockfile_path.display());

            let content = read_lockfile_content(lockfile_path, "packages.lock.json").await?;

            let lock_data: PackagesLock = deps_core::parse_json_checked(content.as_bytes())
                .map_err(|e| DepsError::ParseError {
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
                            // Informational only — nothing in `deps-lsp`/`deps-core::lsp_helpers`
                            // reads `ResolvedSource`, and this path makes no network request, so
                            // it never routes a lockfile-resolved version against a private feed
                            // (issue #523's config resolution intentionally stops at
                            // `NuGetDependency::source`, not `ResolvedPackage::source`).
                            url: crate::registry::NUGET_ORG_INDEX_URL.into(),
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
    async fn test_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let content = format!(
            r#"{{"dependencies": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, &content).await.unwrap();

        let parser = NuGetLockParser;
        assert!(parser.parse_lockfile(&path).await.is_ok());
    }

    #[tokio::test]
    async fn test_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let content = format!(
            r#"{{"dependencies": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, &content).await.unwrap();

        let parser = NuGetLockParser;
        assert!(parser.parse_lockfile(&path).await.is_err());
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

    // --- locate_lockfile: multi-project fallback (D3, #451) ---

    /// Regression test (tester-found, #451 follow-up): with two per-project lock files in
    /// the same directory, each manifest must resolve to *its own* lock file by matching
    /// the `<project>` segment against the manifest's file stem — not just the first
    /// `packages.*.lock.json` a directory scan happens to find.
    #[test]
    fn test_locate_lockfile_multi_project_matches_own_project_not_first_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let app1_manifest = temp_dir.path().join("App1.csproj");
        let app2_manifest = temp_dir.path().join("App2.csproj");
        let app1_lock = temp_dir.path().join("packages.App1.lock.json");
        let app2_lock = temp_dir.path().join("packages.App2.lock.json");
        std::fs::write(&app1_manifest, "<Project></Project>").unwrap();
        std::fs::write(&app2_manifest, "<Project></Project>").unwrap();
        std::fs::write(&app1_lock, "{}").unwrap();
        std::fs::write(&app2_lock, "{}").unwrap();

        let parser = NuGetLockParser;
        assert_eq!(
            parser.locate_lockfile(&Uri::from_file_path(&app1_manifest).unwrap()),
            Some(app1_lock)
        );
        assert_eq!(
            parser.locate_lockfile(&Uri::from_file_path(&app2_manifest).unwrap()),
            Some(app2_lock)
        );
    }

    /// Same scenario as above but with only the *other* project's lock file present: must
    /// return `None` rather than wrongly attaching an unrelated project's resolved versions.
    #[test]
    fn test_locate_lockfile_multi_project_does_not_match_other_projects_lock_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let app1_manifest = temp_dir.path().join("App1.csproj");
        let app2_lock = temp_dir.path().join("packages.App2.lock.json");
        std::fs::write(&app1_manifest, "<Project></Project>").unwrap();
        std::fs::write(&app2_lock, "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&app1_manifest).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), None);
    }

    #[test]
    fn test_locate_lockfile_finds_multi_project_name_in_manifest_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        let lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(lock_path));
    }

    #[test]
    fn test_locate_lockfile_prefers_exact_name_over_multi_project() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        let exact_lock_path = temp_dir.path().join("packages.lock.json");
        let multi_lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&exact_lock_path, "{}").unwrap();
        std::fs::write(&multi_lock_path, "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(exact_lock_path));
    }

    #[test]
    fn test_locate_lockfile_finds_multi_project_name_in_workspace_parent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let project_dir = temp_dir.path().join("src").join("MyApp");
        std::fs::create_dir_all(&project_dir).unwrap();
        let manifest_path = project_dir.join("MyApp.csproj");
        let lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(lock_path));
    }

    #[test]
    fn test_locate_lockfile_no_match_returns_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), None);
    }

    #[test]
    fn test_locate_lockfile_ignores_unrelated_files_in_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(temp_dir.path().join("packages.json"), "{}").unwrap();
        std::fs::write(temp_dir.path().join("packages..lock.json"), "{}").unwrap();

        let manifest_uri = Uri::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), None);
    }
}
