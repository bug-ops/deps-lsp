//! #2104 / #2105 acceptance: plain I/O failures during regeneration are reported as
//! `RegenerationError::Io { operation, .. }` instead of `ManifestChanged` or `Spawn { Go }`, and
//! the manifest re-read keeps failing as `ManifestReparseFailed` at every call site.
//!
//! Driven through fake tools in a re-executed test binary (see `common/regen_harness.rs`). The
//! failing writes are provoked by making the project directory read-only (atomic writes rename
//! into it); a test returns early when the process can write there anyway (running as root).
//! The `*_reparse_*` tests are characterization guards of the #2105 refactor: they pass before it
//! and must keep passing.

#![cfg(all(unix, feature = "npm", feature = "go"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use harness::{Case, Project, outcome_of, prepare, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const MINIMIST_LOCK_ONLY: &str = "minimist|minimist|^1.2.0|^1.2.0|1.2.0|1.2.8";
const PACKAGE: &str = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const LOCK_OLD: &str = "{\"name\":\"p\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}},\"node_modules/minimist\":{\"version\":\"1.2.0\"}}}\n";
const LOCK_NEW: &str = "{\"name\":\"p\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"p\",\"version\":\"1.0.0\",\"dependencies\":{\"minimist\":\"^1.2.0\"}},\"node_modules/minimist\":{\"version\":\"1.2.8\"}}}\n";

const GO_MOD: &str = "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.30.0\n";
const GO_SUM: &str =
    "golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.30.0/go.mod h1:oldmod=\n";
const GO_BUMP: &str = "golang.org/x/text|golang.org/x/text|v0.30.0|v0.31.0|v0.30.0|v0.31.0";
const MODULES_OLD: &str = "# golang.org/x/text v0.30.0\n## explicit; go 1.21\n";

fn npm_case<'a>(tools: Vec<(&'a str, &'a str)>, cooldown_fallback: bool) -> Case<'a> {
    Case {
        ecosystem: "npm",
        manifest: "package.json",
        files: vec![
            ("package.json", PACKAGE.as_bytes().to_vec()),
            ("package-lock.json", LOCK_OLD.as_bytes().to_vec()),
        ],
        tools,
        mode: "lockonly",
        bumps: MINIMIST_LOCK_ONLY,
        cooldown_fallback,
        unlistened: false,
    }
}

fn go_case(go_body: &str) -> Case<'_> {
    Case {
        ecosystem: "go",
        manifest: "go.mod",
        files: vec![
            ("go.mod", GO_MOD.as_bytes().to_vec()),
            ("go.sum", GO_SUM.as_bytes().to_vec()),
            ("vendor/modules.txt", MODULES_OLD.as_bytes().to_vec()),
        ],
        tools: vec![("go", go_body)],
        mode: "edit",
        bumps: GO_BUMP,
        cooldown_fallback: false,
        unlistened: false,
    }
}

/// Makes the project directory writable again so the temp dir can be removed.
struct Unlock(PathBuf);

impl Drop for Unlock {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

fn read_only_dir_is_enforced(project: &Project) -> bool {
    let probe = std::fs::set_permissions(&project.root, std::fs::Permissions::from_mode(0o555))
        .is_ok()
        && std::fs::write(project.root.join(".probe"), b"").is_err();
    let _ = std::fs::set_permissions(&project.root, std::fs::Permissions::from_mode(0o755));
    probe
}

/// Runs the case; `lock_first` makes the project directory read-only before the child starts.
fn run_with_lock(case: &Case<'_>, lock_first: bool) -> Option<(Project, String)> {
    let project = prepare(case);
    if !read_only_dir_is_enforced(&project) {
        const WHY: &str =
            "a read-only directory does not stop this process from writing (running as root?)";
        assert!(
            std::env::var_os("CI").is_none(),
            "{WHY}: this test would silently test nothing in CI"
        );
        eprintln!("SKIPPED: {WHY}; nothing was tested");
        return None;
    }
    let _unlock = Unlock(project.root.clone());
    if lock_first {
        std::fs::set_permissions(&project.root, std::fs::Permissions::from_mode(0o555))
            .expect("lock the project directory");
    }
    let output = project.child(case).output().expect("run the child test");
    let _ = std::fs::set_permissions(&project.root, std::fs::Permissions::from_mode(0o755));
    assert!(
        output.status.success(),
        "child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome = outcome_of(&String::from_utf8_lossy(&output.stdout));
    Some((project, outcome))
}

#[test]
fn fallback_exact_pin_write_failure_is_an_io_error_not_manifest_changed() {
    let case = npm_case(vec![("npm", "exit 0")], true);
    let Some((project, outcome)) = run_with_lock(&case, true) else {
        return;
    };

    assert!(outcome.contains("Io"), "{outcome}");
    assert!(outcome.contains("WriteExactPinManifest"), "{outcome}");
    assert!(!outcome.contains("ManifestChanged"), "{outcome}");
    assert!(project.calls().is_empty(), "{:?}", project.calls());
    assert_eq!(
        std::fs::read(project.root.join("package.json")).expect("manifest"),
        PACKAGE.as_bytes()
    );
}

#[test]
fn fallback_write_back_failure_is_an_io_error_not_a_restore_of_manifest_changed() {
    let body = format!("cat > ROOT/package-lock.json <<'EOF'\n{LOCK_NEW}EOF\nchmod 555 ROOT\n");
    let case = npm_case(vec![("npm", &body)], true);
    let Some((project, outcome)) = run_with_lock(&case, false) else {
        return;
    };

    assert!(outcome.contains("Io"), "{outcome}");
    assert!(outcome.contains("WriteBackManifest"), "{outcome}");
    assert!(!outcome.contains("ManifestChanged"), "{outcome}");
    assert_eq!(project.calls().len(), 1, "{:?}", project.calls());
}

#[test]
fn go_vendor_scratch_directory_failure_is_an_io_error_not_a_go_spawn_failure() {
    let body =
        "case \"$1\" in\n  env) echo; exit 0;;\n  get) chmod 555 ROOT; exit 0;;\nesac\nexit 0\n";
    let case = go_case(body);
    let Some((_project, outcome)) = run_with_lock(&case, false) else {
        return;
    };

    assert!(outcome.contains("Io"), "{outcome}");
    assert!(outcome.contains("CreateScratchDirectory"), "{outcome}");
    assert!(!outcome.contains("Spawn"), "{outcome}");
}

#[test]
fn go_vendor_swap_failure_is_an_io_error_naming_the_move() {
    let body = "case \"$1\" in\n  env) echo; exit 0;;\n  get) printf 'golang.org/x/text v0.31.0 h1:n=\\ngolang.org/x/text v0.31.0/go.mod h1:m=\\n' > ROOT/go.sum; exit 0;;\n  mod) mkdir -p \"$4\"; printf '# golang.org/x/text v0.31.0\\n## explicit; go 1.21\\ngolang.org/x/text/unicode\\n' > \"$4/modules.txt\"; chmod 555 ROOT; exit 0;;\nesac\nexit 0\n";
    let case = go_case(body);
    let Some((_project, outcome)) = run_with_lock(&case, false) else {
        return;
    };

    assert!(outcome.contains("Io"), "{outcome}");
    assert!(outcome.contains("MoveVendorAside"), "{outcome}");
    assert!(!outcome.contains("Spawn"), "{outcome}");
}

#[test]
fn verify_pins_reparse_of_a_manifest_the_tool_broke_is_manifest_reparse_failed() {
    let body = "printf '{ not json' > ROOT/package.json\n";
    let mut case = npm_case(vec![("npm", body)], false);
    case.mode = "edit";
    case.bumps = "minimist|minimist|^1.2.0|^1.2.8|1.2.0|1.2.8";

    let ran = run(&case);

    assert!(
        ran.outcome.contains("ManifestReparseFailed"),
        "{}",
        ran.outcome
    );
}

#[test]
fn fallback_reparse_of_an_unparsable_manifest_is_manifest_reparse_failed_without_a_spawn() {
    let mut case = npm_case(vec![("npm", "exit 0")], true);
    case.files[0] = ("package.json", b"{ not json".to_vec());

    let ran = run(&case);

    assert!(
        ran.outcome.contains("ManifestReparseFailed"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}
