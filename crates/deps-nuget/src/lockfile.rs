//! `packages.lock.json` parser.
//!
//! Every field except the package name is optional (S2): `"type": "Project"` and
//! `"type": "CentralTransitive"` entries carry `requested` but no `resolved` at all — a
//! required `resolved` field would abort deserialization of the *entire* file, which would
//! only surface on multi-project solutions and not on the single-project fixture a test is
//! most likely to use. Entries without `resolved` are simply skipped.
//!
//! `packages.<project_name>.lock.json` (per-project lock files, used when multiple projects
//! share a directory) cannot be expressed as an exact name, so
//! [`NuGetLockParser::locate_lockfile`] adds that computed name (`<project_name>` being the
//! manifest's own file stem, NuGet's convention) as a second candidate alongside the exact
//! `packages.lock.json` name, both passed to the shared
//! [`deps_core::lockfile::locate_lockfile_for_manifest`] walker in one call (#1351). That
//! walker already checks every candidate name in a directory before moving up to its parent,
//! so the *nearest* directory wins regardless of which of the two names matches there — an
//! ancestor's `packages.lock.json` (belonging to a different project) no longer shadows this
//! manifest's own `packages.<project_name>.lock.json` one level closer. Candidate order
//! within a directory is preserved from before the fix: the exact name is checked first, so
//! it still wins over the per-project name when both sit in the same directory (D3, #451).
//! This must be an exact match against *this* manifest's project name, not the first
//! `packages.*.lock.json` found in the directory — a directory shared by multiple projects
//! can hold several such files, and taking the first one silently attaches an unrelated
//! project's resolved versions (#451 follow-up, tester-found regression).

use deps_core::error::{DepsError, Result};
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest, read_and_parse_lockfile, resolve_manifest_file_path,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use url::Url;

/// [`LockFileProvider`] implementation for `packages.lock.json`.
pub struct NuGetLockParser;

impl NuGetLockParser {
    const EXACT_LOCKFILE_NAME: &'static str = "packages.lock.json";
}

/// Builds this manifest's per-project lock file name —
/// `packages.<project_name>.lock.json`, where `<project_name>` is the manifest's file stem
/// (NuGet's convention: the project name defaults to the project file's name without its
/// extension). Returns `None` for a non-`file:`/remote-host URI (see
/// `resolve_manifest_file_path`'s doc, #1084/#1085) or an empty file stem — in both cases
/// [`NuGetLockParser::locate_lockfile`] falls back to searching for the exact name alone.
fn multi_project_lockfile_name(manifest_uri: &Url) -> Option<String> {
    let manifest_path = resolve_manifest_file_path(manifest_uri)?;
    let project_name = manifest_path.file_stem()?.to_str()?;
    if project_name.is_empty() {
        return None;
    }
    Some(format!("packages.{project_name}.lock.json"))
}

#[derive(Deserialize)]
struct PackagesLock {
    // Top-level "version" field (1 or 2) isn't modeled: both schemas are accepted
    // regardless of its value, and serde ignores unknown fields, so nothing reads it.
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
    fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
        let multi_project_name = multi_project_lockfile_name(manifest_uri);
        let candidates: Vec<&str> = std::iter::once(Self::EXACT_LOCKFILE_NAME)
            .chain(multi_project_name.as_deref())
            .collect();
        locate_lockfile_for_manifest(manifest_uri, &candidates)
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            tracing::debug!("Parsing packages.lock.json: {}", lockfile_path.display());

            let packages = read_and_parse_lockfile(
                lockfile_path,
                "packages.lock.json",
                parse_packages_lock_json,
            )
            .await?;

            tracing::info!(
                "Parsed packages.lock.json: {} packages from {}",
                packages.len(),
                lockfile_path.display()
            );

            Ok(packages)
        })
    }
}

/// Parses `packages.lock.json` content (already read and size-capped) into resolved packages.
///
/// The CPU-bound half of [`NuGetLockParser::parse_lockfile`], run inside
/// [`deps_core::lockfile::read_and_parse_lockfile`]'s `spawn_blocking`.
fn parse_packages_lock_json(content: String) -> Result<ResolvedPackages> {
    let lock_data: PackagesLock = deps_core::parse_json_checked(content.as_bytes())
        .map_err(|e| DepsError::parse_error("packages.lock.json", &e))?;

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
            packages.insert(ResolvedPackage::new(
                name,
                version,
                ResolvedSource::Registry {
                    // Informational only — nothing in `deps-lsp`/`deps-core::lsp_helpers`
                    // reads `ResolvedSource`, and this path makes no network request, so
                    // it never routes a lockfile-resolved version against a private feed
                    // (issue #523's config resolution intentionally stops at
                    // `NuGetDependency::source`, not `ResolvedPackage::source`).
                    url: crate::registry::NUGET_ORG_INDEX_URL.into(),
                    checksum: content_hash.unwrap_or_default(),
                },
            ));
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_single_tfm() {
        // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `parse_lockfile` transitively
        // touches fs_probe, and this test runs in the same binary as `deps-nuget/src/config.rs`'s
        // diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        assert_eq!(resolved.version("Newtonsoft.Json"), Some("13.0.3"));
    }

    #[tokio::test]
    async fn test_project_reference_entry_skipped() {
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        assert_eq!(resolved.version("Newtonsoft.Json"), Some("13.0.3"));
    }

    #[tokio::test]
    async fn test_multi_tfm_tie_break_uses_nuget_comparator() {
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        assert_eq!(resolved.version("Foo"), Some("1.10.0.0"));
    }

    #[tokio::test]
    async fn test_missing_optional_fields() {
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        assert_eq!(resolved.version("Bare"), Some("1.0.0"));
    }

    #[tokio::test]
    async fn test_invalid_json_returns_error() {
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, b"not valid json").await.unwrap();

        let parser = NuGetLockParser;
        let result = parser.parse_lockfile(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nesting_at_max_depth_accepted() {
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
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
        // See the comment in `test_parse_single_tfm` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let content = r#"{"version": 1, "dependencies": {}}"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("packages.lock.json");
        tokio::fs::write(&path, content).await.unwrap();

        let parser = NuGetLockParser;
        let resolved = parser.parse_lockfile(&path).await.unwrap();
        assert_eq!(resolved.len(), 0);
    }

    // #758: `LockFileProvider` conformance — exact-name location/malformed-parse behavior,
    // replacing test_locate_lockfile. Does not cover the multi-project
    // (`packages.<project>.lock.json`) fallback below, which is unique to this crate.
    deps_core::lockfile_conformance! {
        mod nuget_lockfile_conformance;
        build: NuGetLockParser;
        manifest: "App.csproj" => "<Project></Project>";
        lockfiles: [ "packages.lock.json" => "{}" ];
        malformed: "not valid json";
    }

    // --- locate_lockfile: multi-project fallback (D3, #451) ---

    /// Regression test (tester-found, #451 follow-up): with two per-project lock files in
    /// the same directory, each manifest must resolve to *its own* lock file by matching
    /// the `<project>` segment against the manifest's file stem — not just the first
    /// `packages.*.lock.json` a directory scan happens to find.
    #[test]
    fn test_locate_lockfile_multi_project_matches_own_project_not_first_found() {
        // Held per `deps_core::fs_probe::snapshot_guard`'s doc: `locate_lockfile` transitively
        // touches fs_probe (via `fs_probe::is_file`), and this test runs in the same binary as
        // `deps-nuget/src/config.rs`'s diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard();
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
            parser.locate_lockfile(&Url::from_file_path(&app1_manifest).unwrap()),
            Some(app1_lock)
        );
        assert_eq!(
            parser.locate_lockfile(&Url::from_file_path(&app2_manifest).unwrap()),
            Some(app2_lock)
        );
    }

    /// Same scenario as above but with only the *other* project's lock file present: must
    /// return `None` rather than wrongly attaching an unrelated project's resolved versions.
    #[test]
    fn test_locate_lockfile_multi_project_does_not_match_other_projects_lock_file() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let app1_manifest = temp_dir.path().join("App1.csproj");
        let app2_lock = temp_dir.path().join("packages.App2.lock.json");
        std::fs::write(&app1_manifest, "<Project></Project>").unwrap();
        std::fs::write(&app2_lock, "{}").unwrap();

        let manifest_uri = Url::from_file_path(&app1_manifest).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), None);
    }

    #[test]
    fn test_locate_lockfile_finds_multi_project_name_in_manifest_dir() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        let lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(lock_path));
    }

    #[test]
    fn test_locate_lockfile_prefers_exact_name_over_multi_project() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        let exact_lock_path = temp_dir.path().join("packages.lock.json");
        let multi_lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&exact_lock_path, "{}").unwrap();
        std::fs::write(&multi_lock_path, "{}").unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(exact_lock_path));
    }

    #[test]
    fn test_locate_lockfile_finds_multi_project_name_in_workspace_parent() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let project_dir = temp_dir.path().join("src").join("MyApp");
        std::fs::create_dir_all(&project_dir).unwrap();
        let manifest_path = project_dir.join("MyApp.csproj");
        let lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), Some(lock_path));
    }

    /// #1085 regression: `multi_project_lockfile_name`'s own manifest-path resolution
    /// previously had no scheme guard either. Empirically confirmed before the fix: a
    /// `untitled:` URI whose path component names a real manifest resolved
    /// `parser.locate_lockfile` to that manifest's real `packages.<project>.lock.json`
    /// despite the non-`file:` scheme — this pins the fixed, safe behavior.
    #[test]
    fn test_locate_lockfile_multi_project_fallback_rejects_non_file_uri() {
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        let lock_path = temp_dir.path().join("packages.MyApp.lock.json");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(&lock_path, "{}").unwrap();

        // Built from `Url::from_file_path` rather than `format!("untitled:{}", path.display())`
        // to stay valid on Windows: `Path::display()` there uses `\` separators and an
        // unescaped drive letter, neither of which is a legal URI path character.
        let file_uri = Url::from_file_path(&manifest_path).unwrap();
        let path_part = file_uri.as_str().strip_prefix("file://").unwrap();
        let manifest_uri: Url = format!("untitled:{path_part}").parse().unwrap();
        let parser = NuGetLockParser;

        assert_eq!(
            parser.locate_lockfile(&manifest_uri),
            None,
            "a non-file-scheme URI must never resolve to a filesystem path, even via the \
             multi-project fallback"
        );
    }

    /// #1351 regression: an ancestor's own `packages.lock.json` must not shadow a nested
    /// project's own `packages.<Project>.lock.json` one directory closer. Reproduces the
    /// exact tree from the issue:
    /// ```text
    /// root/Root.csproj
    /// root/packages.lock.json          <- Root.csproj's lock file
    /// root/src/A/A.csproj
    /// root/src/A/packages.A.lock.json  <- A.csproj's own lock file
    /// ```
    #[test]
    fn test_locate_lockfile_own_multi_project_file_wins_over_ancestor_exact_name() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let root_dir = tempfile::tempdir().unwrap();
        let a_dir = root_dir.path().join("src").join("A");
        std::fs::create_dir_all(&a_dir).unwrap();

        let root_manifest = root_dir.path().join("Root.csproj");
        let root_lock = root_dir.path().join("packages.lock.json");
        let a_manifest = a_dir.join("A.csproj");
        let a_lock = a_dir.join("packages.A.lock.json");
        std::fs::write(&root_manifest, "<Project></Project>").unwrap();
        std::fs::write(&root_lock, "{}").unwrap();
        std::fs::write(&a_manifest, "<Project></Project>").unwrap();
        std::fs::write(&a_lock, "{}").unwrap();

        let parser = NuGetLockParser;
        let a_manifest_uri = Url::from_file_path(&a_manifest).unwrap();
        assert_eq!(
            parser.locate_lockfile(&a_manifest_uri),
            Some(a_lock),
            "A.csproj must resolve to its own nested lock file, not Root.csproj's ancestor one"
        );

        let root_manifest_uri = Url::from_file_path(&root_manifest).unwrap();
        assert_eq!(
            parser.locate_lockfile(&root_manifest_uri),
            Some(root_lock),
            "Root.csproj must still resolve to its own lock file"
        );
    }

    #[test]
    fn test_locate_lockfile_ignores_unrelated_files_in_dir() {
        // See the comment in `test_locate_lockfile_multi_project_matches_own_project_not_first_found`
        // on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard();
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("MyApp.csproj");
        std::fs::write(&manifest_path, "<Project></Project>").unwrap();
        std::fs::write(temp_dir.path().join("packages.json"), "{}").unwrap();
        std::fs::write(temp_dir.path().join("packages..lock.json"), "{}").unwrap();

        let manifest_uri = Url::from_file_path(&manifest_path).unwrap();
        let parser = NuGetLockParser;
        assert_eq!(parser.locate_lockfile(&manifest_uri), None);
    }
}
