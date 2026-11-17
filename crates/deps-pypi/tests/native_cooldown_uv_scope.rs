//! #2042 regression: uv reads only the nearest `uv.toml` / `pyproject.toml [tool.uv]`
//! (docs.astral.sh/uv/concepts/configuration-files), never a per-key merge with a farther
//! directory, and a workspace member reads its root's file alone.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use deps_core::policy_config::{AtomicToggle, NativeCooldownMode};
use deps_core::{Dependency, HttpCache, TypedEcosystem};
use deps_pypi::PypiEcosystem;

const PROJECT: &str =
    "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n";

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
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

fn root() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

#[tokio::test]
async fn farther_uv_toml_does_not_apply_when_the_nearest_tool_uv_lacks_the_key() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let content = format!("{PROJECT}\n[tool.uv]\nindex-strategy = \"first-index\"\n");
    assert_eq!(window(&root.join("app"), &content).await, None);
}

#[tokio::test]
async fn uv_toml_without_the_key_hides_the_pyproject_value_in_the_same_directory() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "index-strategy = \"first-index\"\n");
    let content = format!("{PROJECT}\n[tool.uv]\nexclude-newer = \"7 days\"\n");
    assert_eq!(window(&root, &content).await, None);
}

#[tokio::test]
async fn pyproject_without_tool_uv_defers_to_the_parent_directory() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    assert_eq!(
        window(&root.join("app"), PROJECT).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn workspace_member_reads_only_the_root_file_even_when_a_parent_has_one() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let ws = root.join("ws");
    write(
        &ws.join("pyproject.toml"),
        "[project]\nname = \"ws\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n",
    );
    let member = format!("{PROJECT}\n[tool.uv]\nexclude-newer = \"2026-01-01T00:00:00Z\"\n");
    assert_eq!(
        window(&ws.join("packages/app"), &member).await,
        None,
        "the root has no window and the farther uv.toml must not leak in"
    );
}

#[tokio::test]
async fn pyproject_without_any_uv_config_resolves_no_window() {
    let (_g, root) = root();
    assert_eq!(window(&root, PROJECT).await, None);
}

#[tokio::test]
async fn outer_package_entry_never_lifts_the_nearest_files_global_window() {
    let (_g, root) = root();
    write(
        &root.join("uv.toml"),
        "exclude-newer-package = { requests = false }\n",
    );
    let content = format!("{PROJECT}\n[tool.uv]\nexclude-newer = \"7 days\"\n");
    assert_eq!(
        window(&root.join("app"), &content).await.as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

fn workspace_root(root: &Path, workspace_table: &str) {
    write(
        &root.join("pyproject.toml"),
        &format!(
            "[project]\nname = \"ws\"\nversion = \"0.1.0\"\n\n[tool.uv]\nexclude-newer = \"2026-01-01T00:00:00Z\"\n\n[tool.uv.workspace]\n{workspace_table}\n"
        ),
    );
}

const OWN_WINDOW: &str = "\n[tool.uv]\nexclude-newer = \"7 days\"\n";

#[tokio::test]
async fn project_outside_the_workspace_members_keeps_its_own_window() {
    let (_g, root) = root();
    workspace_root(&root, "members = [\"packages/*\"]");
    let outsider = root.join("tools/app");
    assert_eq!(
        window(&outsider, &format!("{PROJECT}{OWN_WINDOW}"))
            .await
            .as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn excluded_project_keeps_its_own_window() {
    let (_g, root) = root();
    workspace_root(
        &root,
        "members = [\"packages/*\"]\nexclude = [\"packages/legacy\"]",
    );
    assert_eq!(
        window(
            &root.join("packages/legacy"),
            &format!("{PROJECT}{OWN_WINDOW}")
        )
        .await
        .as_deref(),
        Some("uv exclude-newer = 7 days")
    );
}

#[tokio::test]
async fn listed_member_reads_the_root_cutoff() {
    let (_g, root) = root();
    workspace_root(&root, "members = [\"packages/*\", \"libs/**\"]");
    for member in ["packages/app", "libs/a/b"] {
        let window = window(&root.join(member), &format!("{PROJECT}{OWN_WINDOW}")).await;
        assert!(
            window.is_some_and(|w| w.contains("2026-01-01")),
            "{member} must read the workspace root"
        );
    }
}
