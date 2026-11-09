//! In-use version selection across npm-family lock formats (#1981).
//!
//! Each case feeds a real lock file through [`NpmLockParser`] and resolves the manifest's
//! direct dependencies with the shared `resolve_in_use_versions`, the path hover, inlay hints
//! and OSV targeting all use. The primary is the highest satisfying lock entry; every other
//! satisfying entry is a lock alternative that the OSV scan covers too.
//!
//! yarn, bun and pnpm cannot attribute a lock entry to the manifest that requested it, so a
//! transitive consumer's copy of the same package is a lock alternative there. package-lock.json
//! can, and filters nested copies out.

// Test code: workspace-level `clippy::unwrap_used` is meant for library code (#689).
#![allow(clippy::unwrap_used)]

use deps_core::lockfile::LockFileProvider;
use deps_core::{EcosystemId, PackageKey};
use deps_npm::{NpmFormatter, NpmLockParser, parse_package_json};
use url::Url;

#[derive(Debug, PartialEq, Eq)]
struct Selection {
    name: String,
    primary: String,
    alternatives: Vec<String>,
}

fn selection(name: &str, primary: &str, alternatives: &[&str]) -> Selection {
    Selection {
        name: name.to_string(),
        primary: primary.to_string(),
        alternatives: alternatives.iter().map(ToString::to_string).collect(),
    }
}

async fn resolve(package_json: &str, lock_name: &str, lock_content: &str) -> Vec<Selection> {
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
        .filter_map(|dep| {
            let key = PackageKey::new(&dep.name, &NpmFormatter);
            let in_use = deps_core::lsp_helpers::resolve_in_use_versions(
                dep,
                &key,
                &versions,
                Some(&candidates),
                &NpmFormatter,
                EcosystemId::Npm,
            )?;
            Some(Selection {
                name: dep.name.as_str().to_string(),
                primary: in_use.primary().as_str().to_string(),
                alternatives: in_use
                    .lock_alternatives()
                    .iter()
                    .map(|v| v.as_str().to_string())
                    .collect(),
            })
        })
        .collect()
}

fn minimist_manifest() -> &'static str {
    r#"{"name":"t","version":"1.0.0","dependencies":{"minimist":"^1.2.0"}}"#
}

fn ua_parser_manifest() -> &'static str {
    r#"{"name":"t","version":"1.0.0","dependencies":{"ua-parser-js":"^0.7.28"}}"#
}

async fn assert_minimist(lock_name: &str, lock: &str, primary: &str, alternatives: &[&str]) {
    let resolved = resolve(minimist_manifest(), lock_name, lock).await;
    assert_eq!(
        resolved,
        [selection("minimist", primary, alternatives)],
        "{lock_name}"
    );
}

async fn assert_ua_parser(lock_name: &str, lock: &str) {
    let resolved = resolve(ua_parser_manifest(), lock_name, lock).await;
    assert_eq!(
        resolved,
        [selection("ua-parser-js", "0.7.29", &["0.7.28"])],
        "{lock_name}"
    );
}

const YARN_V1_MINIMIST: [&str; 2] = [
    "minimist@^1.2.0:\n  version \"1.2.5\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz\"\n",
    "minimist@^1.2.8:\n  version \"1.2.8\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.8.tgz\"\n",
];

fn yarn_v1(blocks: &[&str]) -> String {
    format!("# yarn lockfile v1\n\n{}", blocks.join("\n"))
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
    assert_minimist("package-lock.json", lock, "1.2.5", &[]).await;
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
    assert_minimist("package-lock.json", lock, "1.2.8", &[]).await;
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
        assert_eq!(resolved, [selection("chalk", expected, &[])]);
    }
}

/// The root entry and a workspace member's own `node_modules` entry are both Hoisted, so both
/// satisfy: the root's is the primary and the member's a lock alternative, which is how the
/// malware advisory against 0.7.29 and the older copy are both scanned.
#[tokio::test]
async fn package_lock_two_hoisted_candidates_both_satisfy() {
    let lock = r#"{"name":"root","lockfileVersion":3,"requires":true,"packages":{
 "":{"name":"root","workspaces":["packages/*"],"dependencies":{"ua-parser-js":"^0.7.28"}},
 "node_modules/ua-parser-js":{"version":"0.7.29","resolved":"https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz","integrity":"sha512-x"},
 "node_modules/ui":{"resolved":"packages/ui","link":true},
 "packages/ui":{"name":"ui","version":"1.0.0","dependencies":{"ua-parser-js":"0.7.28"}},
 "packages/ui/node_modules/ua-parser-js":{"version":"0.7.28","resolved":"https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.28.tgz","integrity":"sha512-y"}
}}"#;
    assert_ua_parser("package-lock.json", lock).await;
}

#[tokio::test]
async fn yarn_v1_highest_satisfying_entry_is_primary_and_the_rest_are_alternatives() {
    assert_minimist(
        "yarn.lock",
        &yarn_v1(&YARN_V1_MINIMIST),
        "1.2.8",
        &["1.2.5"],
    )
    .await;
}

#[tokio::test]
async fn yarn_berry_highest_satisfying_entry_is_primary_and_the_rest_are_alternatives() {
    let lock = "__metadata:\n  version: 8\n\n\
\"minimist@npm:^1.2.0\":\n  version: 1.2.5\n  resolution: \"minimist@npm:1.2.5\"\n\n\
\"minimist@npm:^1.2.8\":\n  version: 1.2.8\n  resolution: \"minimist@npm:1.2.8\"\n";
    assert_minimist("yarn.lock", lock, "1.2.8", &["1.2.5"]).await;
}

#[tokio::test]
async fn yarn_v1_malware_version_stays_primary_beside_an_older_exact_pin() {
    let lock = "# yarn lockfile v1\n\n\
ua-parser-js@0.7.28:\n  version \"0.7.28\"\n  resolved \"https://registry.yarnpkg.com/ua-parser-js/-/ua-parser-js-0.7.28.tgz\"\n\n\
ua-parser-js@^0.7.28:\n  version \"0.7.29\"\n  resolved \"https://registry.yarnpkg.com/ua-parser-js/-/ua-parser-js-0.7.29.tgz\"\n";
    assert_ua_parser("yarn.lock", lock).await;
}

#[tokio::test]
async fn yarn_v1_selection_is_independent_of_block_order() {
    let [low, high] = YARN_V1_MINIMIST;
    let forward = resolve(minimist_manifest(), "yarn.lock", &yarn_v1(&[low, high])).await;
    let reversed = resolve(minimist_manifest(), "yarn.lock", &yarn_v1(&[high, low])).await;

    assert_eq!(forward, reversed);
    assert_eq!(forward, [selection("minimist", "1.2.8", &["1.2.5"])]);
}

fn bun_lock(package_entries: &[&str]) -> String {
    format!(
        r#"{{
  "lockfileVersion": 1,
  "workspaces": {{"": {{"dependencies": {{"minimist": "^1.2.0"}}}}}},
  "packages": {{
    {}
  }}
}}"#,
        package_entries.join(",\n    ")
    )
}

const BUN_MINIMIST_ENTRIES: [&str; 3] = [
    r#""minimist": ["minimist@1.2.5", "", {}, "sha512-a"]"#,
    r#""foo": ["foo@1.0.0", "", {}, "sha512-b"]"#,
    r#""foo/minimist": ["minimist@1.2.8", "", {}, "sha512-c"]"#,
];

#[tokio::test]
async fn bun_highest_satisfying_entry_is_primary_and_the_rest_are_alternatives() {
    assert_minimist(
        "bun.lock",
        &bun_lock(&BUN_MINIMIST_ENTRIES),
        "1.2.8",
        &["1.2.5"],
    )
    .await;
}

#[tokio::test]
async fn bun_selection_is_independent_of_entry_order() {
    let [root, foo, nested] = BUN_MINIMIST_ENTRIES;
    let orders = [
        [root, foo, nested],
        [nested, foo, root],
        [foo, nested, root],
        [nested, root, foo],
    ];
    for order in orders {
        let resolved = resolve(minimist_manifest(), "bun.lock", &bun_lock(&order)).await;
        assert_eq!(
            resolved,
            [selection("minimist", "1.2.8", &["1.2.5"])],
            "{order:?}"
        );
    }
}

#[tokio::test]
async fn bun_malware_version_stays_primary_beside_a_nested_older_copy() {
    let lock = r#"{
  "lockfileVersion": 1,
  "workspaces": {"": {"dependencies": {"ua-parser-js": "^0.7.28"}}},
  "packages": {
    "ua-parser-js": ["ua-parser-js@0.7.29", "", {}, "sha512-a"],
    "foo": ["foo@1.0.0", "", {"dependencies": {"ua-parser-js": "0.7.28"}}, "sha512-b"],
    "foo/ua-parser-js": ["ua-parser-js@0.7.28", "", {}, "sha512-c"]
  }
}"#;
    assert_ua_parser("bun.lock", lock).await;
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
        assert_eq!(resolved, [selection("chalk", expected, &[])]);
    }
}

#[tokio::test]
async fn pnpm_importer_specifier_still_selects_its_own_version() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      minimist:\n        specifier: ^1.2.0\n        version: 1.2.5\npackages:\n  minimist@1.2.8: {}\n";
    assert_minimist("pnpm-lock.yaml", lock, "1.2.5", &[]).await;
}

#[tokio::test]
async fn pnpm_importers_flatten_into_primary_and_alternatives() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ua-parser-js:\n        specifier: ^0.7.28\n        version: 0.7.29\n  packages/ui:\n    dependencies:\n      ua-parser-js:\n        specifier: 0.7.28\n        version: 0.7.28\npackages:\n  ua-parser-js@0.7.28: {}\n  ua-parser-js@0.7.29: {}\n";
    assert_ua_parser("pnpm-lock.yaml", lock).await;
}
