//! In-use version selection across npm-family lock formats (#1981).
//!
//! Each case feeds a real lock file through [`NpmLockParser`] and resolves the manifest's
//! direct dependencies with the shared `resolve_in_use_version`, the path hover, inlay hints
//! and OSV targeting all use.

// Test code: workspace-level `clippy::unwrap_used` is meant for library code (#689).
#![allow(clippy::unwrap_used)]

use deps_core::lockfile::LockFileProvider;
use deps_core::{EcosystemId, PackageKey};
use deps_npm::{NpmFormatter, NpmLockParser, parse_package_json};
use url::Url;

async fn resolve(
    package_json: &str,
    lock_name: &str,
    lock_content: &str,
) -> Vec<(String, Option<String>)> {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join(lock_name);
    tokio::fs::write(&lock_path, lock_content).await.unwrap();

    let packages = NpmLockParser.parse_lockfile(&lock_path).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&NpmFormatter);

    let uri = Url::from_file_path(dir.path().join("package.json")).unwrap();
    let parsed = parse_package_json(package_json, &uri).unwrap();
    parsed
        .dependencies
        .iter()
        .map(|dep| {
            let key = PackageKey::new(&dep.name, &NpmFormatter);
            let version = deps_core::lsp_helpers::resolve_in_use_version(
                dep,
                &key,
                &versions,
                Some(&candidates),
                &NpmFormatter,
                EcosystemId::Npm,
            );
            (
                dep.name.as_str().to_string(),
                version.map(|v| v.as_str().to_string()),
            )
        })
        .collect()
}

fn minimist_manifest() -> &'static str {
    r#"{"name":"t","version":"1.0.0","dependencies":{"minimist":"^1.2.0"}}"#
}

async fn assert_minimist(lock_name: &str, lock: &str, expected: &str) {
    let resolved = resolve(minimist_manifest(), lock_name, lock).await;
    assert_eq!(
        resolved,
        [("minimist".to_string(), Some(expected.to_string()))],
        "{lock_name}"
    );
}

#[tokio::test]
async fn package_lock_nested_newer_copy_does_not_hide_root_version() {
    let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "t", "dependencies": {"minimist": "^1.2.0"}},
    "node_modules/minimist": {"version": "1.2.5"},
    "node_modules/foo": {"version": "1.0.0"},
    "node_modules/foo/node_modules/minimist": {"version": "1.2.8"}
  }
}"#;
    assert_minimist("package-lock.json", lock, "1.2.5").await;
}

#[tokio::test]
async fn package_lock_hoisted_newer_beats_nested_exact_pin() {
    let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "t", "dependencies": {"minimist": "^1.2.0"}},
    "node_modules/minimist": {"version": "1.2.8"},
    "node_modules/foo": {"version": "1.0.0"},
    "node_modules/foo/node_modules/minimist": {"version": "1.2.5"}
  }
}"#;
    assert_minimist("package-lock.json", lock, "1.2.8").await;
}

#[tokio::test]
async fn package_lock_workspace_member_entry_stays_a_candidate() {
    let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "t"},
    "node_modules/chalk": {"version": "1.0.0"},
    "packages/bar/node_modules/chalk": {"version": "2.0.0"}
  }
}"#;
    for (req, expected) in [("^1", "1.0.0"), ("^2", "2.0.0")] {
        let manifest = format!(r#"{{"name":"t","dependencies":{{"chalk":"{req}"}}}}"#);
        let resolved = resolve(&manifest, "package-lock.json", lock).await;
        assert_eq!(
            resolved,
            [("chalk".to_string(), Some(expected.to_string()))]
        );
    }
}

#[tokio::test]
async fn yarn_v1_lowest_satisfying_entry_wins() {
    let lock = "# yarn lockfile v1\n\n\
minimist@^1.2.0:\n  version \"1.2.5\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz\"\n\n\
minimist@^1.2.8:\n  version \"1.2.8\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.8.tgz\"\n";
    assert_minimist("yarn.lock", lock, "1.2.5").await;
}

#[tokio::test]
async fn yarn_berry_lowest_satisfying_entry_wins() {
    let lock = "__metadata:\n  version: 8\n\n\
\"minimist@npm:^1.2.0\":\n  version: 1.2.5\n  resolution: \"minimist@npm:1.2.5\"\n\n\
\"minimist@npm:^1.2.8\":\n  version: 1.2.8\n  resolution: \"minimist@npm:1.2.8\"\n";
    assert_minimist("yarn.lock", lock, "1.2.5").await;
}

#[tokio::test]
async fn bun_lowest_satisfying_entry_wins() {
    let lock = r#"{
  "lockfileVersion": 1,
  "workspaces": {"": {"dependencies": {"minimist": "^1.2.0"}}},
  "packages": {
    "minimist": ["minimist@1.2.5", "", {}, "sha512-a"],
    "foo": ["foo@1.0.0", "", {}, "sha512-b"],
    "foo/minimist": ["minimist@1.2.8", "", {}, "sha512-c"]
  }
}"#;
    assert_minimist("bun.lock", lock, "1.2.5").await;
}

#[tokio::test]
async fn bun_workspace_entries_resolve_by_requirement() {
    let lock = r#"{
  "lockfileVersion": 1,
  "workspaces": {"": {}},
  "packages": {
    "chalk": ["chalk@1.0.0", "", {}, "sha512-a"],
    "bar/chalk": ["chalk@2.0.0", "", {}, "sha512-b"]
  }
}"#;
    for (req, expected) in [("^1", "1.0.0"), ("^2", "2.0.0")] {
        let manifest = format!(r#"{{"name":"t","dependencies":{{"chalk":"{req}"}}}}"#);
        let resolved = resolve(&manifest, "bun.lock", lock).await;
        assert_eq!(
            resolved,
            [("chalk".to_string(), Some(expected.to_string()))]
        );
    }
}

#[tokio::test]
async fn pnpm_importer_specifier_still_selects_its_own_version() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      minimist:\n        specifier: ^1.2.0\n        version: 1.2.5\npackages:\n  minimist@1.2.8: {}\n";
    assert_minimist("pnpm-lock.yaml", lock, "1.2.5").await;
}
