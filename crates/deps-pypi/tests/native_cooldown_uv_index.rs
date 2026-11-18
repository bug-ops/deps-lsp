//! #2052 / spec 099 acceptance (track B): uv's index-level `exclude-newer`
//! (`[[tool.uv.index]]` in `pyproject.toml`, `[[index]]` in `uv.toml`) and its precedence:
//! package (`exclude-newer-package`) > index > global `exclude-newer`.
//!
//! The index of a dependency is the one `[tool.uv.sources]` pins it to; an unpinned dependency
//! uses the layer's only non-explicit index when that index is `default = true`. Index-level
//! `exclude-newer-package` is a documented limitation and is not read.
//!
//! Written tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use deps_core::policy_config::{AtomicToggle, NativeCooldownMode};
use deps_core::{Dependency, HttpCache, TypedEcosystem};
use deps_pypi::PypiEcosystem;

const HEAD: &str =
    "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n";

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn root() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

/// The window of `requests` in the pyproject at `dir` whose text is `content`.
async fn window(dir: &Path, content: &str) -> Option<String> {
    let path = dir.join("pyproject.toml");
    write(&path, content);
    let eco = PypiEcosystem::new(Arc::new(HttpCache::new()))
        .with_native_cooldown_toggle(Arc::new(AtomicToggle::new(NativeCooldownMode::Honor)));
    let uri = url::Url::from_file_path(&path).unwrap();
    let parsed = eco.parse(content, &uri).await.unwrap();
    let dep = parsed
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == "requests")
        .unwrap();
    Dependency::native_cooldown(dep).map(ToString::to_string)
}

/// A pyproject whose `requests` is pinned to `internal` and whose uv table is `uv_table`
/// (`[[tool.uv.index]]` entries and keys).
fn pinned(uv_table: &str) -> String {
    format!("{HEAD}\n[tool.uv.sources]\nrequests = {{ index = \"internal\" }}\n\n{uv_table}")
}

fn index(extra: &str) -> String {
    format!(
        "[[tool.uv.index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\n{extra}\n"
    )
}

const GLOBAL: &str = "[tool.uv]\nexclude-newer = \"7 days\"\n\n";

#[tokio::test]
async fn named_index_window_applies_to_a_dependency_pinned_to_it() {
    let (_g, root) = root();
    let content = pinned(&index("exclude-newer = \"3 days\""));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn named_index_window_beats_the_global_window() {
    let (_g, root) = root();
    let content = pinned(&format!("{GLOBAL}{}", index("exclude-newer = \"3 days\"")));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn named_index_false_beats_the_global_window() {
    let (_g, root) = root();
    let content = pinned(&format!("{GLOBAL}{}", index("exclude-newer = false")));
    assert_eq!(window(&root, &content).await, None);
}

#[tokio::test]
async fn package_window_beats_the_index_window() {
    let (_g, root) = root();
    let content = pinned(&format!(
        "[tool.uv]\nexclude-newer-package = {{ requests = \"2 days\" }}\n\n{}",
        index("exclude-newer = \"3 days\"")
    ));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer-package.requests = 2 days")
    );
}

#[tokio::test]
async fn package_false_beats_the_index_window() {
    let (_g, root) = root();
    let content = pinned(&format!(
        "[tool.uv]\nexclude-newer-package = {{ requests = false }}\n\n{}",
        index("exclude-newer = \"3 days\"")
    ));
    assert_eq!(window(&root, &content).await, None);
}

#[tokio::test]
async fn index_without_the_key_falls_back_to_the_global_window() {
    let (_g, root) = root();
    let content = pinned(&format!("{GLOBAL}{}", index("")));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn unknown_index_name_falls_back_to_the_global_window() {
    let (_g, root) = root();
    let content = format!(
        "{HEAD}\n[tool.uv.sources]\nrequests = {{ index = \"nope\" }}\n\n{GLOBAL}{}",
        index("exclude-newer = \"3 days\"")
    );
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn malformed_index_value_is_ignored_and_the_global_window_applies() {
    let (_g, root) = root();
    let content = pinned(&format!("{GLOBAL}{}", index("exclude-newer = \"soon\"")));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn other_index_keys_do_not_disturb_the_window() {
    let (_g, root) = root();
    let content = pinned(&index(
        "authenticate = \"always\"\nignore-error-codes = [401]\nformat = \"flat\"\nexclude-newer = \"3 days\"",
    ));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn sole_default_index_window_applies_to_an_unpinned_dependency() {
    let (_g, root) = root();
    let content = format!(
        "{HEAD}\n[[tool.uv.index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\ndefault = true\nexclude-newer = \"3 days\"\n"
    );
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn non_default_sole_index_does_not_apply_to_an_unpinned_dependency() {
    let (_g, root) = root();
    let content = format!("{HEAD}\n{GLOBAL}{}", index("exclude-newer = \"3 days\""));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn ambiguous_non_explicit_indexes_fall_back_to_the_global_window() {
    let (_g, root) = root();
    let content = format!(
        "{HEAD}\n{GLOBAL}[[tool.uv.index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\ndefault = true\nexclude-newer = \"3 days\"\n\n[[tool.uv.index]]\nname = \"mirror\"\nurl = \"https://mirror.example.com/simple\"\nexclude-newer = \"1 day\"\n"
    );
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn explicit_index_is_ignored_for_an_unpinned_dependency() {
    let (_g, root) = root();
    let content = format!(
        "{HEAD}\n{GLOBAL}[[tool.uv.index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\nexplicit = true\nexclude-newer = \"3 days\"\n"
    );
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn explicit_index_still_applies_to_a_dependency_pinned_to_it() {
    let (_g, root) = root();
    let content = pinned(&index("explicit = true\nexclude-newer = \"3 days\""));
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn uv_toml_index_array_applies_to_a_pinned_dependency() {
    let (_g, root) = root();
    write(
        &root.join("uv.toml"),
        "[[index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\nexclude-newer = \"3 days\"\n",
    );
    let content = format!("{HEAD}\n[tool.uv.sources]\nrequests = {{ index = \"internal\" }}\n");
    assert_eq!(
        window(&root, &content).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}

#[tokio::test]
async fn uv_toml_default_index_applies_to_an_unpinned_dependency() {
    let (_g, root) = root();
    write(
        &root.join("uv.toml"),
        "[[index]]\nname = \"internal\"\nurl = \"https://example.com/simple\"\ndefault = true\nexclude-newer = \"3 days\"\n",
    );
    assert_eq!(
        window(&root, HEAD).await.as_deref(),
        Some("uv index.internal.exclude-newer = 3 days")
    );
}
