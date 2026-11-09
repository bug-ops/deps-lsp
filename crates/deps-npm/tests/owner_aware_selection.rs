//! Owner-aware lock entry selection across npm-family lock formats (#1993).
//!
//! Two workspace members declare overlapping ranges of one package that the lock file resolved
//! differently. Each case feeds a real lock file through [`NpmLockParser`] and resolves each
//! member's own manifest with the scope the server derives from its path, so the member is
//! handed its own entry even where the other member's entry is higher.

// Test code: workspace-level `clippy::unwrap_used` is meant for library code (#689).
#![allow(clippy::unwrap_used)]

use deps_core::lockfile::{ImporterPath, LockFileProvider};
use deps_core::{EcosystemId, PackageKey};
use deps_npm::{NpmFormatter, NpmLockParser, parse_package_json};
use url::Url;

const MEMBER_A_RANGE: &str = "^1.0.0";
const MEMBER_B_RANGE: &str = "^1.2.0";

struct Resolved {
    primary: String,
    alternatives: Vec<String>,
}

/// Resolves `left-pad` for the member at `member_dir` (relative to the lock file), or with the
/// owner-blind split when `scoped` is `false`.
async fn resolve(
    lock_name: &str,
    lock_content: &str,
    member_dir: &str,
    range: &str,
    scoped: bool,
) -> Resolved {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join(lock_name);
    tokio::fs::write(&lock_path, lock_content).await.unwrap();
    let manifest_path = dir.path().join(member_dir).join("package.json");

    let packages = NpmLockParser.parse_lockfile(&lock_path).await.unwrap();
    let (versions, candidates) = if scoped {
        let scope = ImporterPath::of_manifest(&lock_path, &manifest_path).unwrap();
        packages.split_normalized_for(&NpmFormatter, &scope)
    } else {
        packages.split_normalized(&NpmFormatter)
    };

    let manifest =
        format!(r#"{{"name":"m","version":"1.0.0","dependencies":{{"left-pad":"{range}"}}}}"#);
    let uri = Url::from_file_path(&manifest_path).unwrap();
    let parsed = parse_package_json(&manifest, &uri).unwrap();
    let dep = parsed.dependencies.first().unwrap();
    let in_use = deps_core::lsp_helpers::resolve_in_use_versions(
        dep,
        &PackageKey::new(&dep.name, &NpmFormatter),
        &versions,
        Some(&candidates),
        &NpmFormatter,
        EcosystemId::Npm,
    )
    .unwrap();
    Resolved {
        primary: in_use.primary().as_str().to_string(),
        alternatives: in_use
            .lock_alternatives()
            .iter()
            .map(|v| v.as_str().to_string())
            .collect(),
    }
}

/// Each member gets its own entry; the other stays a lock alternative.
async fn assert_each_member_gets_its_own_entry(lock_name: &str, lock: &str) {
    let a = resolve(lock_name, lock, "packages/a", MEMBER_A_RANGE, true).await;
    assert_eq!(a.primary, "1.0.5", "{lock_name}: member a");
    assert_eq!(a.alternatives, ["1.2.0"], "{lock_name}: member a");

    let b = resolve(lock_name, lock, "packages/b", MEMBER_B_RANGE, true).await;
    assert_eq!(b.primary, "1.2.0", "{lock_name}: member b");
    assert_eq!(
        b.alternatives,
        Vec::<String>::new(),
        "{lock_name}: member b"
    );
}

#[tokio::test]
async fn package_lock_members_resolve_their_own_node_modules_entries() {
    let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "root"},
    "packages/a": {"name": "a", "version": "1.0.0"},
    "packages/b": {"name": "b", "version": "1.0.0"},
    "packages/a/node_modules/left-pad": {"version": "1.0.5"},
    "packages/b/node_modules/left-pad": {"version": "1.2.0"}
  }
}"#;
    assert_each_member_gets_its_own_entry("package-lock.json", lock).await;

    let blind = resolve(
        "package-lock.json",
        lock,
        "packages/a",
        MEMBER_A_RANGE,
        false,
    )
    .await;
    assert_eq!(
        blind.primary, "1.2.0",
        "the unscoped split keeps the highest"
    );
    assert_eq!(blind.alternatives, ["1.0.5"]);
}

#[tokio::test]
async fn pnpm_importers_resolve_their_own_entries() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  packages/a:\n    dependencies:\n      left-pad:\n        specifier: ^1.0.0\n        version: 1.0.5\n  packages/b:\n    dependencies:\n      left-pad:\n        specifier: ^1.2.0\n        version: 1.2.0\n";
    assert_each_member_gets_its_own_entry("pnpm-lock.yaml", lock).await;
}

#[tokio::test]
async fn bun_workspace_members_resolve_their_own_entries() {
    let lock = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root"},
    "packages/a": {"name": "a", "dependencies": {"left-pad": "^1.0.0"}},
    "packages/b": {"name": "b", "dependencies": {"left-pad": "^1.2.0"}},
  },
  "packages": {
    "a/left-pad": ["left-pad@1.0.5", "", {}, "sha512-a"],
    "b/left-pad": ["left-pad@1.2.0", "", {}, "sha512-b"],
  }
}"#;
    assert_each_member_gets_its_own_entry("bun.lock", lock).await;
}

#[tokio::test]
async fn yarn_v1_members_resolve_the_entry_recording_their_requirement() {
    let lock = "# yarn lockfile v1\n\nleft-pad@^1.0.0:\n  version \"1.0.5\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.0.5.tgz\"\n\nleft-pad@^1.2.0:\n  version \"1.2.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.0.tgz\"\n";
    assert_each_member_gets_its_own_entry("yarn.lock", lock).await;
}

#[tokio::test]
async fn yarn_berry_members_resolve_the_entry_recording_their_requirement() {
    let lock = "__metadata:\n  version: 8\n\n\"left-pad@npm:^1.0.0\":\n  version: 1.0.5\n  resolution: \"left-pad@npm:1.0.5\"\n\n\"left-pad@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"left-pad@npm:1.2.0\"\n";
    assert_each_member_gets_its_own_entry("yarn.lock", lock).await;
}

#[tokio::test]
async fn yarn_entry_serving_several_descriptors_is_found_by_any_of_them() {
    let lock = "# yarn lockfile v1\n\n\"left-pad@^1.0.0\", left-pad@~1.0.4:\n  version \"1.0.5\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.0.5.tgz\"\n\nleft-pad@^1.2.0:\n  version \"1.2.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.0.tgz\"\n";
    let tilde = resolve("yarn.lock", lock, "packages/a", "~1.0.4", true).await;
    assert_eq!(tilde.primary, "1.0.5");
}

/// A copy nested under another package is demoted before the owner preference applies, so a
/// higher nested copy is neither the primary nor a lock alternative.
#[tokio::test]
async fn package_lock_nested_copy_is_demoted_before_owner_preference() {
    let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "root"},
    "packages/a/node_modules/left-pad": {"version": "1.0.5"},
    "packages/b/node_modules/left-pad": {"version": "1.2.0"},
    "packages/a/node_modules/x": {"version": "1.0.0"},
    "packages/a/node_modules/x/node_modules/left-pad": {"version": "9.0.0"}
  }
}"#;
    assert_each_member_gets_its_own_entry("package-lock.json", lock).await;
}

#[tokio::test]
async fn bun_nested_copy_is_demoted_before_owner_preference() {
    let lock = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "root"},
    "packages/a": {"name": "a"},
    "packages/b": {"name": "b"},
  },
  "packages": {
    "a/left-pad": ["left-pad@1.0.5", "", {}, "sha512-a"],
    "b/left-pad": ["left-pad@1.2.0", "", {}, "sha512-b"],
    "x": ["x@1.0.0", "", {}, "sha512-x"],
    "x/left-pad": ["left-pad@9.0.0", "", {}, "sha512-n"],
  }
}"#;
    assert_each_member_gets_its_own_entry("bun.lock", lock).await;
}
