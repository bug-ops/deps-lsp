//! #2046 / #2047 acceptance: new lock-file regeneration strategies (uv, Bundler, Deno, Yarn
//! berry, npm workspace members, Go workspace) driven through fake tools in a re-executed test
//! binary (see `common/regen_harness.rs`).
//!
//! Written tests-first against architect v1 + v2 and critic notes N1 (Bundler argv order), M7
//! (uv: one `--upgrade-package` per pin) and the user decisions (npm/pnpm env unchanged: no
//! `COREPACK_ENABLE_AUTO_PIN`). Fake tools record `tool argv|cwd|env`; argv is matched through the
//! `starts_with("<tool> <argv>|")` form so a trailing difference fails.
//!
//! Not covered here (needs a live tool, left to the live-tester): pnpm members/`--filter`, real
//! argv acceptance by the installed tools.

#![cfg(all(
    unix,
    feature = "npm",
    feature = "pypi",
    feature = "bundler",
    feature = "deno",
    feature = "go"
))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

fn case<'a>(
    ecosystem: &'a str,
    manifest: &'a str,
    files: Vec<(&'a str, &'a str)>,
    tools: Vec<(&'a str, &'a str)>,
    mode: &'a str,
    bumps: &'a str,
) -> Case<'a> {
    Case {
        ecosystem,
        manifest,
        files: files
            .into_iter()
            .map(|(path, body)| (path, body.as_bytes().to_vec()))
            .collect(),
        tools,
        mode,
        bumps,
        cooldown_fallback: false,
        unlistened: false,
    }
}

fn calls_starting<'a>(ran: &'a Ran, prefix: &str) -> Vec<&'a String> {
    ran.calls
        .iter()
        .filter(|call| call.starts_with(prefix))
        .collect()
}

fn writing_calls<'a>(ran: &'a Ran, tool: &str, probes: &[&str]) -> Vec<&'a String> {
    ran.calls_of(tool)
        .into_iter()
        .filter(|call| {
            !probes
                .iter()
                .any(|probe| call.starts_with(&format!("{tool} {probe}|")))
        })
        .collect()
}

fn cwd_of(call: &str) -> &str {
    call.split('|').nth(1).expect("cwd field")
}

fn env_of(call: &str) -> &str {
    call.split('|').nth(2).expect("env field")
}

// --- Bundler ---

const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'rake', '~> 13.0'\n";
const LOCK_OLD: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (~> 13.0)\n\nBUNDLED WITH\n   2.5.0\n";
const LOCK_NEW: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (~> 13.0)\n\nBUNDLED WITH\n   2.5.0\n";
const RAKE_EDIT: &str = "rake|gem 'rake'|~> 13.0|~> 13.1|13.0.6|13.1.0";
const RAKE_LOCK_ONLY: &str = "rake|gem 'rake'|~> 13.0|~> 13.0|13.0.6|13.1.0";

fn bundle_writing_lock() -> String {
    format!("cat > ROOT/Gemfile.lock <<'EOF'\n{LOCK_NEW}EOF\n")
}

#[test]
fn bundler_manifest_edit_runs_bundle_lock_in_the_manifest_dir_and_verifies() {
    let body = bundle_writing_lock();
    let ran = run(&case(
        "bundler",
        "Gemfile",
        vec![("Gemfile", GEMFILE), ("Gemfile.lock", LOCK_OLD)],
        vec![("bundle", &body)],
        "edit",
        RAKE_EDIT,
    ));

    let locks = calls_starting(&ran, "bundle lock|");
    assert_eq!(locks.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(locks[0]), ran.root.display().to_string());
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn bundler_lock_only_pin_passes_conservative_before_update_and_names_last() {
    let body = bundle_writing_lock();
    let ran = run(&case(
        "bundler",
        "Gemfile",
        vec![("Gemfile", GEMFILE), ("Gemfile.lock", LOCK_OLD)],
        vec![("bundle", &body)],
        "lockonly",
        RAKE_LOCK_ONLY,
    ));

    assert_eq!(
        calls_starting(&ran, "bundle lock --conservative --update rake|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn bundler_lock_in_an_ancestor_directory_is_a_workspace_member_refusal() {
    let ran = run(&case(
        "bundler",
        "app/Gemfile",
        vec![("app/Gemfile", GEMFILE), ("Gemfile.lock", LOCK_OLD)],
        vec![("bundle", "exit 0")],
        "edit",
        RAKE_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- uv ---

const PYPROJECT: &str = "[project]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n  \"requests>=2.0\",\n  \"rich>=13.0\",\n]\n";
const UV_OLD: &str = "version = 1\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"rich\"\nversion = \"13.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
const UV_NEW: &str = "version = 1\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"rich\"\nversion = \"13.7.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
const UV_BUMPS: &str =
    "requests|requests|>=2.0|>=2.31.0|2.0.0|2.31.0\nrich|rich|>=13.0|>=13.7.0|13.0.0|13.7.0";

#[test]
fn uv_uses_one_upgrade_package_flag_per_pin_and_verifies_exact_versions() {
    let body = format!("cat > ROOT/uv.lock <<'EOF'\n{UV_NEW}EOF\n");
    let ran = run(&case(
        "pypi",
        "pyproject.toml",
        vec![("pyproject.toml", PYPROJECT), ("uv.lock", UV_OLD)],
        vec![("uv", &body)],
        "edit",
        UV_BUMPS,
    ));

    assert_eq!(
        calls_starting(
            &ran,
            "uv lock --no-build --no-python-downloads --upgrade-package requests==2.31.0 --upgrade-package rich==13.7.0|"
        )
        .len(),
        1,
        "{:?}",
        ran.calls
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn pipenv_lock_beside_a_pyproject_is_an_ownership_mismatch_without_a_spawn() {
    let ran = run(&case(
        "pypi",
        "pyproject.toml",
        vec![("pyproject.toml", PYPROJECT), ("Pipfile.lock", "{}")],
        vec![("uv", "exit 0"), ("pipenv", "exit 0")],
        "edit",
        UV_BUMPS,
    ));

    assert!(
        ran.outcome.contains("LockfileOwnershipMismatch"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn uv_lock_beside_a_requirements_file_is_an_ownership_mismatch() {
    let ran = run(&case(
        "pypi",
        "requirements.txt",
        vec![("requirements.txt", "requests>=2.0\n"), ("uv.lock", UV_OLD)],
        vec![("uv", "exit 0")],
        "edit",
        "requests|requests|>=2.0|>=2.31.0|2.0.0|2.31.0",
    ));

    assert!(
        ran.outcome.contains("LockfileOwnershipMismatch"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn uv_workspace_member_manifest_is_refused() {
    let ran = run(&case(
        "pypi",
        "member/pyproject.toml",
        vec![
            (
                "pyproject.toml",
                "[project]\nname = \"root\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"member\"]\n",
            ),
            ("member/pyproject.toml", PYPROJECT),
            ("uv.lock", UV_OLD),
        ],
        vec![("uv", "exit 0")],
        "edit",
        UV_BUMPS,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- Deno ---

const DENO_JSON: &str = "{\n  \"imports\": {\n    \"chalk\": \"npm:chalk@^4.0.0\"\n  }\n}\n";
const DENO_LOCK: &str = "{\n  \"version\": \"4\"\n}\n";
const CHALK_EDIT: &str = "chalk|chalk|^4.0.0|^4.1.2|4.0.0|4.1.2";

// Deno argv (`--lock=./deno.lock`) is pinned in tests/update_deno_lockers.rs.

#[test]
fn deno_workspace_member_is_refused() {
    let ran = run(&case(
        "deno",
        "a/deno.json",
        vec![
            ("deno.json", "{\n  \"workspace\": [\"./a\"]\n}\n"),
            ("a/deno.json", DENO_JSON),
            ("deno.lock", DENO_LOCK),
        ],
        vec![("deno", "exit 0")],
        "edit",
        CHALK_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- Yarn berry ---

const PACKAGE_JSON: &str = "{\n  \"name\": \"fx\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const YARN_LOCK: &str = "__metadata:\n  version: 8\n";
const MINIMIST_EDIT: &str = "minimist|minimist|^1.2.0|^1.2.8|1.2.0|1.2.8";
const MINIMIST_LOCK_ONLY: &str = "minimist|minimist|^1.2.0|^1.2.0|1.2.0|1.2.8";

fn yarn_body(version: &str) -> String {
    format!("if [ \"$1\" = --version ]; then echo '{version}'; exit 0; fi\nexit 0\n")
}

fn yarn_case<'a>(body: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "npm",
        "package.json",
        vec![("package.json", PACKAGE_JSON), ("yarn.lock", YARN_LOCK)],
        vec![("yarn", body)],
        mode,
        bumps,
    )
}

#[test]
fn yarn_berry_manifest_edit_updates_the_lockfile_only_with_scripts_disabled() {
    let body = yarn_body("4.5.0");

    let ran = run(&yarn_case(&body, "edit", MINIMIST_EDIT));

    let calls = writing_calls(&ran, "yarn", &["--version"]);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("yarn install --mode=update-lockfile|"),
        "{}",
        calls[0]
    );
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    for entry in [
        "COREPACK_ENABLE_DOWNLOAD_PROMPT=0",
        "YARN_ENABLE_IMMUTABLE_INSTALLS=false",
        "YARN_ENABLE_SCRIPTS=false",
    ] {
        assert!(env_of(calls[0]).contains(entry), "{entry} in {}", calls[0]);
    }
}

#[test]
fn yarn_berry_lock_only_pin_runs_recursive_up_by_name() {
    let body = yarn_body("4.5.0");

    let ran = run(&yarn_case(&body, "lockonly", MINIMIST_LOCK_ONLY));

    let calls = writing_calls(&ran, "yarn", &["--version"]);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("yarn up --recursive --mode=update-lockfile minimist|"),
        "{}",
        calls[0]
    );
}

#[test]
fn yarn_classic_is_unsupported_and_runs_only_the_version_probe() {
    let body = yarn_body("1.22.22");

    let ran = run(&yarn_case(&body, "edit", MINIMIST_EDIT));

    assert!(ran.outcome.contains("YarnClassic"), "{}", ran.outcome);
    assert!(
        writing_calls(&ran, "yarn", &["--version"]).is_empty(),
        "{:?}",
        ran.calls
    );
}

// --- npm workspace members ---

const ROOT_PACKAGE: &str =
    "{\n  \"name\": \"root\",\n  \"private\": true,\n  \"workspaces\": [\"packages/*\"]\n}\n";
const MEMBER_PACKAGE: &str = "{\n  \"name\": \"a\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const ROOT_LOCK: &str = "{\n  \"name\": \"root\",\n  \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {\n    \"\": { \"name\": \"root\", \"workspaces\": [\"packages/*\"] },\n    \"packages/a\": { \"name\": \"a\", \"version\": \"1.0.0\", \"dependencies\": { \"minimist\": \"^1.2.0\" } }\n  }\n}\n";

fn member_case<'a>(npm_body: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "npm",
        "packages/a/package.json",
        vec![
            ("package.json", ROOT_PACKAGE),
            ("packages/a/package.json", MEMBER_PACKAGE),
            ("package-lock.json", ROOT_LOCK),
        ],
        vec![("npm", npm_body)],
        mode,
        bumps,
    )
}

const NPM_NOOP: &str = "exit 0\n";

#[test]
fn npm_member_manifest_edit_installs_at_the_workspace_root_without_auto_pin() {
    let ran = run(&member_case(NPM_NOOP, "edit", MINIMIST_EDIT));

    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with("npm install "), "{}", calls[0]);
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    assert!(
        !env_of(calls[0]).contains("COREPACK_ENABLE_AUTO_PIN"),
        "{}",
        calls[0]
    );
}

#[test]
fn npm_member_lock_only_pin_updates_with_the_workspace_flag_at_the_root() {
    let ran = run(&member_case(NPM_NOOP, "lockonly", MINIMIST_LOCK_ONLY));

    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with("npm update "), "{}", calls[0]);
    assert!(
        calls[0].contains("--workspace=./packages/a"),
        "{}",
        calls[0]
    );
    assert!(calls[0].contains("minimist"), "{}", calls[0]);
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
}

#[test]
fn npm_member_under_the_unlistened_entry_point_is_regenerated_at_the_workspace_root() {
    let mut case = member_case(NPM_NOOP, "edit", MINIMIST_EDIT);
    case.unlistened = true;

    let ran = run(&case);

    let calls = ran.calls_of("npm");
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with("npm install "), "{}", calls[0]);
    assert_eq!(cwd_of(calls[0]), ran.root.display().to_string());
    assert!(
        !ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
}

// --- Go workspace ---

const GO_MOD: &str = "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.30.0\n";
const GO_SUM: &str =
    "golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.30.0/go.mod h1:oldmod=\n";

#[test]
fn go_workspace_runs_go_get_with_gowork_off_instead_of_refusing() {
    let body = "if [ \"$1\" = env ]; then echo 'ROOT/go.work'; exit 0; fi\nexit 0\n";

    let ran = run(&case(
        "go",
        "go.mod",
        vec![
            ("go.mod", GO_MOD),
            ("go.sum", GO_SUM),
            ("go.work", "go 1.21\n\nuse .\n"),
        ],
        vec![("go", body)],
        "edit",
        "golang.org/x/text|golang.org/x/text|v0.30.0|v0.31.0|v0.30.0|v0.31.0",
    ));

    let gets = calls_starting(&ran, "go get ");
    assert_eq!(gets.len(), 1, "{:?} / {}", ran.calls, ran.outcome);
    assert!(env_of(gets[0]).contains("GOWORK=off"), "{}", gets[0]);
    assert!(!ran.outcome.contains("GoWorkspace"), "{}", ran.outcome);
}
