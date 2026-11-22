//! #2042 / spec 099 acceptance: uv's `exclude-newer` / `exclude-newer-package` read from
//! `[tool.uv]` in `pyproject.toml` and from `uv.toml` (FR-001, FR-004, FR-007, FR-014, FR-017).
//!
//! Written tests-first against plans `2026-11-17T18-35-26-architect` (Q6, Track 1),
//! `20-24-32-architect` and `20-32-28-architect` (M2, M10). Assumed seam:
//! `PypiEcosystem::with_native_cooldown_toggle(Arc<AtomicToggle<NativeCooldownMode>>)`.

#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
use std::assert_matches;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use deps_core::native_cooldown::{NativeCooldown, NativeHold, NativeLimit};
use deps_core::policy_config::{AtomicToggle, NativeCooldownMode};
use deps_core::{ConcreteVersion, Dependency, HttpCache, PublishTime, TypedEcosystem};
use deps_pypi::PypiEcosystem;
use url::Url;

const CUTOFF: i64 = 1_767_225_600;
const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn ecosystem(mode: NativeCooldownMode) -> PypiEcosystem {
    PypiEcosystem::new(Arc::new(HttpCache::new()))
        .with_native_cooldown_toggle(Arc::new(AtomicToggle::new(mode)))
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

fn pyproject(tool_uv: &str) -> String {
    format!(
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\", \"urllib3>=1\"]\n\n[tool.uv]\n{tool_uv}\n"
    )
}

/// Parses `buffer` as the pyproject at `dir` (not necessarily what is on disk) and returns the
/// window of the dependency `name`.
async fn cooldown_in(
    eco: &PypiEcosystem,
    dir: &Path,
    file: &str,
    buffer: &str,
    name: &str,
) -> Option<NativeCooldown> {
    let uri = Url::from_file_path(dir.join(file)).unwrap();
    let result = eco.parse(buffer, &uri).await.unwrap();
    let dep = result
        .dependencies
        .iter()
        .find(|d| d.name.as_str() == name)
        .unwrap_or_else(|| panic!("dependency {name} not parsed"));
    Dependency::native_cooldown(dep).cloned()
}

/// Writes `tool_uv` as the pyproject of `dir` and returns the window of `requests`.
async fn requests_window(dir: &Path, tool_uv: &str) -> Option<NativeCooldown> {
    let content = pyproject(tool_uv);
    write(&dir.join("pyproject.toml"), &content);
    cooldown_in(
        &ecosystem(NativeCooldownMode::Honor),
        dir,
        "pyproject.toml",
        &content,
        "requests",
    )
    .await
}

async fn assert_control_applies() {
    let (_g, root) = root();
    let cooldown = requests_window(&root, "exclude-newer = \"7 days\"")
        .await
        .expect("control: a valid window must resolve");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
}

#[tokio::test]
async fn timestamp_pins_a_fixed_cutoff_and_holds_newer_files_indefinitely() {
    let (_g, root) = root();
    let cooldown = requests_window(&root, "exclude-newer = \"2026-01-01T00:00:00Z\"")
        .await
        .expect("cutoff applies");
    assert_matches!(cooldown.limit(), NativeLimit::PublishedAfter(_));
    assert!(cooldown.to_string().contains("exclude-newer"));
    let v = ConcreteVersion::new("2.32.0");
    let now = PublishTime::from_unix_secs(NOW);
    assert_eq!(
        cooldown.hold(Some(PublishTime::from_unix_secs(CUTOFF + 1)), &v, now),
        Some(NativeHold::Indefinite)
    );
    assert_eq!(
        cooldown.hold(Some(PublishTime::from_unix_secs(CUTOFF)), &v, now),
        None
    );
}

#[tokio::test]
async fn friendly_and_iso_durations_are_relative_to_now() {
    for (raw, secs) in [
        ("7 days", 7 * DAY),
        ("1 week", 7 * DAY),
        ("P2D", 2 * DAY),
        ("PT48H", 2 * DAY),
    ] {
        let (_g, root) = root();
        let cooldown = requests_window(&root, &format!("exclude-newer = \"{raw}\""))
            .await
            .unwrap_or_else(|| panic!("{raw:?} must apply"));
        let v = ConcreteVersion::new("2.32.0");
        let now = PublishTime::from_unix_secs(NOW);
        assert_eq!(
            cooldown.hold(Some(PublishTime::from_unix_secs(NOW - 3600)), &v, now),
            Some(NativeHold::For(u64::try_from(secs - 3600).unwrap())),
            "{raw:?}"
        );
    }
}

#[tokio::test]
async fn date_only_calendar_units_and_garbage_are_ignored() {
    assert_control_applies().await;
    for raw in [
        "2026-01-01",
        "1 month",
        "1 year",
        "P1M",
        "yesterday",
        "-1 days",
        "0 days",
    ] {
        let (_g, root) = root();
        assert!(
            requests_window(&root, &format!("exclude-newer = \"{raw}\""))
                .await
                .is_none(),
            "{raw:?} must not produce a window"
        );
    }
}

#[tokio::test]
async fn non_string_exclude_newer_is_ignored() {
    assert_control_applies().await;
    let (_g, root) = root();
    assert!(requests_window(&root, "exclude-newer = 7").await.is_none());
}

#[tokio::test]
async fn exclude_newer_package_overrides_the_global_value_for_that_package_only() {
    let (_g, root) = root();
    let tool_uv = "exclude-newer = \"7 days\"\nexclude-newer-package = { requests = \"2026-01-01T00:00:00Z\" }";
    let content = pyproject(tool_uv);
    write(&root.join("pyproject.toml"), &content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    let requests = cooldown_in(&eco, &root, "pyproject.toml", &content, "requests")
        .await
        .unwrap();
    assert_matches!(requests.limit(), NativeLimit::PublishedAfter(_));
    assert!(requests.to_string().contains("exclude-newer-package"));
    assert!(requests.to_string().contains("requests"));
    let urllib3 = cooldown_in(&eco, &root, "pyproject.toml", &content, "urllib3")
        .await
        .unwrap();
    assert_matches!(
        urllib3.limit(),
        NativeLimit::MinAge(_),
        "global still applies to others"
    );
}

#[tokio::test]
async fn exclude_newer_package_false_exempts_that_package() {
    let (_g, root) = root();
    let tool_uv = "exclude-newer = \"7 days\"\nexclude-newer-package = { requests = false }";
    let content = pyproject(tool_uv);
    write(&root.join("pyproject.toml"), &content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &content, "requests")
            .await
            .is_none()
    );
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &content, "urllib3")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn exclude_newer_package_names_are_matched_pep_503_normalized() {
    let (_g, root) = root();
    let content = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"my-pkg>=1\"]\n\n[tool.uv]\nexclude-newer = \"7 days\"\nexclude-newer-package = { \"My_Pkg\" = false }\n";
    write(&root.join("pyproject.toml"), content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", content, "my-pkg")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn invalid_per_package_value_falls_back_to_the_global_window() {
    let (_g, root) = root();
    let tool_uv = "exclude-newer = \"7 days\"\nexclude-newer-package = { requests = \"soon\" }";
    let cooldown = requests_window(&root, tool_uv)
        .await
        .expect("global applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
}

#[tokio::test]
async fn uv_toml_beats_pyproject_tool_uv_in_the_same_directory() {
    let (_g, root) = root();
    write(
        &root.join("uv.toml"),
        "exclude-newer = \"2026-01-01T00:00:00Z\"\n",
    );
    let cooldown = requests_window(&root, "exclude-newer = \"7 days\"")
        .await
        .expect("window");
    assert_matches!(
        cooldown.limit(),
        NativeLimit::PublishedAfter(_),
        "uv.toml wins: got {cooldown}"
    );
}

#[tokio::test]
async fn uv_toml_alone_supplies_the_window() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let content =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n";
    write(&root.join("pyproject.toml"), content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", content, "requests")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn uv_toml_without_the_key_still_hides_the_pyproject_value() {
    assert_control_applies().await;
    let (_g, root) = root();
    write(&root.join("uv.toml"), "index-strategy = \"first-index\"\n");
    assert!(
        requests_window(&root, "exclude-newer = \"7 days\"")
            .await
            .is_none(),
        "uv ignores [tool.uv] when uv.toml exists in the same directory (no per-key merge)"
    );
}

#[tokio::test]
async fn nearest_config_file_without_the_key_hides_a_farther_window() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let project = root.join("tools/app");
    let content = pyproject("index-strategy = \"first-index\"");
    write(&project.join("pyproject.toml"), &content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &project, "pyproject.toml", &content, "requests")
            .await
            .is_none(),
        "only the nearest directory holding uv config is read"
    );
}

#[tokio::test]
async fn open_buffer_wins_over_the_saved_file() {
    let (_g, root) = root();
    write(
        &root.join("pyproject.toml"),
        &pyproject("# nothing configured"),
    );
    let buffer = pyproject("exclude-newer = \"7 days\"");
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &buffer, "requests")
            .await
            .is_some()
    );
    let removed = pyproject("# nothing configured");
    write(&root.join("pyproject.toml"), &buffer);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &removed, "requests")
            .await
            .is_none(),
        "an unsaved edit removing the window must take effect"
    );
}

#[tokio::test]
async fn workspace_member_reads_the_workspace_root_config_only() {
    let (_g, root) = root();
    write(
        &root.join("pyproject.toml"),
        "[project]\nname = \"ws\"\nversion = \"0.1.0\"\n\n[tool.uv]\nexclude-newer = \"2026-01-01T00:00:00Z\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n",
    );
    write(&root.join("uv.lock"), "version = 1\n");
    let member = root.join("packages/app");
    let member_content = pyproject("exclude-newer = \"7 days\"");
    write(&member.join("pyproject.toml"), &member_content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    let cooldown = cooldown_in(&eco, &member, "pyproject.toml", &member_content, "requests")
        .await
        .expect("root window applies to the member");
    assert_matches!(
        cooldown.limit(),
        NativeLimit::PublishedAfter(_),
        "member's own [tool.uv] is ignored in a workspace, got {cooldown}"
    );
}

#[tokio::test]
async fn workspace_root_uv_toml_beats_root_pyproject_for_members() {
    let (_g, root) = root();
    write(
        &root.join("pyproject.toml"),
        "[project]\nname = \"ws\"\nversion = \"0.1.0\"\n\n[tool.uv]\nexclude-newer = \"7 days\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n",
    );
    write(
        &root.join("uv.toml"),
        "exclude-newer = \"2026-01-01T00:00:00Z\"\n",
    );
    let member = root.join("packages/app");
    let member_content = pyproject("");
    write(&member.join("pyproject.toml"), &member_content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    let cooldown = cooldown_in(&eco, &member, "pyproject.toml", &member_content, "requests")
        .await
        .expect("root config applies");
    assert_matches!(cooldown.limit(), NativeLimit::PublishedAfter(_));
}

#[tokio::test]
async fn closest_ancestor_uv_toml_applies_to_a_standalone_project() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let project = root.join("tools/app");
    let content =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n";
    write(&project.join("pyproject.toml"), content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &project, "pyproject.toml", content, "requests")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn closer_directory_config_wins_over_a_farther_one() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    let project = root.join("tools/app");
    write(
        &project.join("uv.toml"),
        "exclude-newer = \"2026-01-01T00:00:00Z\"\n",
    );
    let content =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n";
    write(&project.join("pyproject.toml"), content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    let cooldown = cooldown_in(&eco, &project, "pyproject.toml", content, "requests")
        .await
        .unwrap();
    assert_matches!(cooldown.limit(), NativeLimit::PublishedAfter(_));
}

#[tokio::test]
async fn requirements_txt_and_pipfile_get_no_window() {
    let (_g, root) = root();
    write(&root.join("uv.toml"), "exclude-newer = \"7 days\"\n");
    write(
        &root.join("pyproject.toml"),
        &pyproject("exclude-newer = \"7 days\""),
    );
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "requirements.txt", "requests>=2\n", "requests")
            .await
            .is_none()
    );
    let pipfile = "[packages]\nrequests = \">=2\"\n";
    assert!(
        cooldown_in(&eco, &root, "Pipfile", pipfile, "requests")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn direct_url_dependencies_get_no_window() {
    let (_g, root) = root();
    let content = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ git+https://example.com/r.git\", \"urllib3>=1\"]\n\n[tool.uv]\nexclude-newer = \"7 days\"\n";
    write(&root.join("pyproject.toml"), content);
    let eco = ecosystem(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", content, "requests")
            .await
            .is_none()
    );
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", content, "urllib3")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn ignore_mode_resolves_no_window() {
    assert_control_applies().await;
    let (_g, root) = root();
    let content = pyproject("exclude-newer = \"7 days\"");
    write(&root.join("pyproject.toml"), &content);
    let eco = ecosystem(NativeCooldownMode::Ignore);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &content, "requests")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn flipping_the_shared_toggle_applies_to_the_next_parse() {
    let (_g, root) = root();
    let content = pyproject("exclude-newer = \"7 days\"");
    write(&root.join("pyproject.toml"), &content);
    let toggle = Arc::new(AtomicToggle::new(NativeCooldownMode::Ignore));
    let eco = PypiEcosystem::new(Arc::new(HttpCache::new()))
        .with_native_cooldown_toggle(Arc::clone(&toggle));
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &content, "requests")
            .await
            .is_none()
    );
    toggle.set(NativeCooldownMode::Honor);
    assert!(
        cooldown_in(&eco, &root, "pyproject.toml", &content, "requests")
            .await
            .is_some()
    );
}
