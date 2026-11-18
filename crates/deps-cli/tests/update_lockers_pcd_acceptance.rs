//! #2081 / #2082 / #2083 acceptance: Poetry, PDM, Composer and Dart/Flutter lock-file
//! regeneration driven through fake tools in a re-executed test binary (see
//! `common/regen_harness.rs`). Fake tools record `tool argv|cwd|env`.
//!
//! Not covered here (needs the real tools, see the handoff): that the installed Poetry, PDM,
//! Composer, Dart and Flutter accept the argv and rewrite their lock files as assumed.

#![cfg(all(unix, feature = "pypi", feature = "composer", feature = "dart"))]
#![allow(clippy::expect_used)]

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

fn cwd_of(call: &str) -> &str {
    call.split('|').nth(1).expect("cwd field")
}

fn regenerated(ran: &Ran) {
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

// --- Poetry and PDM ---

const PYPROJECT: &str = "[project]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n  \"requests>=2.0\",\n  \"rich>=13.0\",\n]\n";
const LOCK_OLD: &str = "[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\n\n[[package]]\nname = \"rich\"\nversion = \"13.0.0\"\n";
const LOCK_NEW: &str = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"rich\"\nversion = \"13.7.0\"\n";
const EDIT_BUMPS: &str =
    "requests|requests|>=2.0|>=2.31.0|2.0.0|2.31.0\nrich|rich|>=13.0|>=13.7.0|13.0.0|13.7.0";

fn poetry_tool(version: &str) -> String {
    format!(
        "if [ \"$1 $2\" = \"--no-plugins --version\" ]; then echo 'Poetry (version {version})'; exit 0; fi\ncat > ROOT/poetry.lock <<'EOF'\n{LOCK_NEW}EOF\n"
    )
}

fn poetry_case<'a>(tool: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "pypi",
        "pyproject.toml",
        vec![("pyproject.toml", PYPROJECT), ("poetry.lock", LOCK_OLD)],
        vec![("poetry", tool)],
        mode,
        bumps,
    )
}

#[test]
fn poetry_one_x_locks_with_no_update_after_probing_the_version() {
    let tool = poetry_tool("1.8.3");
    let ran = run(&poetry_case(&tool, "edit", EDIT_BUMPS));

    assert_eq!(
        calls_starting(&ran, "poetry --no-plugins --version|").len(),
        1,
        "{:?}",
        ran.calls
    );
    let locks = calls_starting(
        &ran,
        "poetry lock --no-interaction --no-plugins --no-update|",
    );
    assert_eq!(locks.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(locks[0]), ran.root.display().to_string());
    assert_eq!(ran.calls.len(), 2, "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn poetry_two_x_locks_without_the_no_update_flag() {
    let tool = poetry_tool("2.1.3");
    let ran = run(&poetry_case(&tool, "edit", EDIT_BUMPS));

    assert_eq!(
        calls_starting(&ran, "poetry lock --no-interaction --no-plugins|").len(),
        1,
        "{:?}",
        ran.calls
    );
    regenerated(&ran);
}

#[test]
fn poetry_older_than_one_two_is_too_old_and_never_writes() {
    let tool = poetry_tool("1.1.15");
    let ran = run(&poetry_case(&tool, "edit", EDIT_BUMPS));

    assert!(
        ran.outcome.contains("ToolTooOld(Poetry)"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    assert!(ran.calls[0].starts_with("poetry --no-plugins --version|"));
    assert_eq!(ran.read("poetry.lock"), LOCK_OLD.as_bytes());
}

#[test]
fn poetry_rejecting_no_plugins_is_too_old_and_never_retried_with_plugins() {
    let ran = run(&poetry_case(
        "if [ \"$1\" = \"--no-plugins\" ]; then echo 'The \"--no-plugins\" option does not exist' >&2; exit 1; fi\nexit 0",
        "edit",
        EDIT_BUMPS,
    ));

    assert!(
        ran.outcome.contains("ToolTooOld(Poetry)"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    assert!(ran.calls[0].starts_with("poetry --no-plugins --version|"));
    assert_eq!(ran.read("poetry.lock"), LOCK_OLD.as_bytes());
}

#[test]
fn poetry_unreadable_version_output_fails_without_a_writing_spawn() {
    let ran = run(&poetry_case(
        "if [ \"$2\" = \"--version\" ]; then echo 'poetry'; exit 0; fi\nexit 0",
        "edit",
        EDIT_BUMPS,
    ));

    assert!(
        ran.outcome.contains("UnexpectedProbeOutput"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
}

#[test]
fn poetry_lock_only_pins_run_update_lock_with_the_names_and_no_lock() {
    let tool = poetry_tool("2.1.3");
    let ran = run(&poetry_case(
        &tool,
        "lockonly",
        "requests|requests|>=2.0|>=2.0|2.0.0|2.31.0\nrich|rich|>=13.0|>=13.0|13.0.0|13.7.0",
    ));

    assert_eq!(
        calls_starting(
            &ran,
            "poetry update --lock --no-interaction --no-plugins requests rich|"
        )
        .len(),
        1,
        "{:?}",
        ran.calls
    );
    assert!(
        calls_starting(&ran, "poetry lock").is_empty(),
        "{:?}",
        ran.calls
    );
    regenerated(&ran);
}

#[test]
fn poetry_cooldown_fallback_target_is_refused_before_any_spawn() {
    let tool = poetry_tool("2.1.3");
    let mut case = poetry_case(&tool, "edit", EDIT_BUMPS);
    case.cooldown_fallback = true;
    let ran = run(&case);

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn poetry_lock_beside_a_requirements_file_is_an_ownership_mismatch() {
    let tool = poetry_tool("2.1.3");
    let ran = run(&case(
        "pypi",
        "requirements.txt",
        vec![
            ("requirements.txt", "requests>=2.0\n"),
            ("poetry.lock", LOCK_OLD),
        ],
        vec![("poetry", &tool)],
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

const PDM_METADATA: &str = "[metadata]\nlock_version = \"4.5.0\"\n\n";
const PDM_LOCK_OLD: &str = "[metadata]\nlock_version = \"4.5.0\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\n\n[[package]]\nname = \"rich\"\nversion = \"13.0.0\"\n";

fn pdm_tool() -> String {
    format!("cat > ROOT/pdm.lock <<'EOF'\n{PDM_METADATA}{LOCK_NEW}EOF\n")
}

fn pdm_case<'a>(tool: &'a str, mode: &'a str, bumps: &'a str) -> Case<'a> {
    case(
        "pypi",
        "pyproject.toml",
        vec![("pyproject.toml", PYPROJECT), ("pdm.lock", PDM_LOCK_OLD)],
        vec![("pdm", tool)],
        mode,
        bumps,
    )
}

#[test]
fn pdm_manifest_edit_locks_reusing_pins() {
    let tool = pdm_tool();
    let ran = run(&pdm_case(&tool, "edit", EDIT_BUMPS));

    assert_eq!(
        calls_starting(&ran, "pdm lock --update-reuse --skip=:all|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn pdm_lock_only_pins_run_update_no_sync_with_the_names() {
    let tool = pdm_tool();
    let ran = run(&pdm_case(
        &tool,
        "lockonly",
        "requests|requests|>=2.0|>=2.0|2.0.0|2.31.0",
    ));

    assert_eq!(
        calls_starting(&ran, "pdm update --no-sync --skip=:all requests|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn pdm_cooldown_fallback_target_is_refused_before_any_spawn() {
    let tool = pdm_tool();
    let mut case = pdm_case(&tool, "edit", EDIT_BUMPS);
    case.cooldown_fallback = true;
    let ran = run(&case);

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn pipenv_stays_a_deferred_locker_without_a_spawn() {
    let ran = run(&case(
        "pypi",
        "Pipfile",
        vec![
            ("Pipfile", "[packages]\nrequests = \">=2.0\"\n"),
            ("Pipfile.lock", "{}"),
        ],
        vec![("pipenv", "exit 0")],
        "edit",
        "requests|requests|>=2.0|>=2.31.0|2.0.0|2.31.0",
    ));

    assert!(
        ran.outcome.contains("PythonLockerDeferred"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- Composer ---

const COMPOSER_JSON: &str = "{\n  \"require\": {\n    \"monolog/monolog\": \"^3.0\"\n  }\n}\n";
const COMPOSER_LOCK_OLD: &str =
    "{\"packages\":[{\"name\":\"monolog/monolog\",\"version\":\"3.0.0\"}],\"packages-dev\":[]}\n";
const COMPOSER_LOCK_NEW: &str =
    "{\"packages\":[{\"name\":\"monolog/monolog\",\"version\":\"3.5.0\"}],\"packages-dev\":[]}\n";
const MONOLOG_EDIT: &str = "monolog/monolog|monolog/monolog|^3.0|^3.5|3.0.0|3.5.0";

fn composer_tool() -> String {
    format!(
        "printf '%s' \"$COMPOSER\" > ROOT/composer-env.txt\ncat > ROOT/composer.lock <<'EOF'\n{COMPOSER_LOCK_NEW}EOF\n"
    )
}

#[test]
fn composer_update_names_the_package_with_code_execution_disabled() {
    let tool = composer_tool();
    let ran = run(&case(
        "composer",
        "composer.json",
        vec![
            ("composer.json", COMPOSER_JSON),
            ("composer.lock", COMPOSER_LOCK_OLD),
        ],
        vec![("composer", &tool)],
        "edit",
        MONOLOG_EDIT,
    ));

    let updates = calls_starting(
        &ran,
        "composer update monolog/monolog --no-install --no-scripts --no-plugins --no-interaction|",
    );
    assert_eq!(updates.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(updates[0]), ran.root.display().to_string());
    assert_eq!(ran.read("composer-env.txt"), b"composer.json");
    regenerated(&ran);
}

#[test]
fn composer_lock_only_pin_uses_the_same_update_form() {
    let tool = composer_tool();
    let ran = run(&case(
        "composer",
        "composer.json",
        vec![
            ("composer.json", COMPOSER_JSON),
            ("composer.lock", COMPOSER_LOCK_OLD),
        ],
        vec![("composer", &tool)],
        "lockonly",
        "monolog/monolog|monolog/monolog|^3.0|^3.0|3.0.0|3.5.0",
    ));

    assert_eq!(
        calls_starting(&ran, "composer update monolog/monolog --no-install").len(),
        1,
        "{:?}",
        ran.calls
    );
    regenerated(&ran);
}

#[test]
fn composer_cooldown_fallback_target_is_refused_before_any_spawn() {
    let mut case = case(
        "composer",
        "composer.json",
        vec![
            ("composer.json", COMPOSER_JSON),
            ("composer.lock", COMPOSER_LOCK_OLD),
        ],
        vec![("composer", "exit 0")],
        "edit",
        MONOLOG_EDIT,
    );
    case.cooldown_fallback = true;
    let ran = run(&case);

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn composer_lock_in_an_ancestor_is_a_workspace_member() {
    let ran = run(&case(
        "composer",
        "member/composer.json",
        vec![
            ("member/composer.json", COMPOSER_JSON),
            ("composer.lock", COMPOSER_LOCK_OLD),
        ],
        vec![("composer", "exit 0")],
        "edit",
        MONOLOG_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn composer_failure_leaves_the_lock_file_restored() {
    let ran = run(&case(
        "composer",
        "composer.json",
        vec![
            ("composer.json", COMPOSER_JSON),
            ("composer.lock", COMPOSER_LOCK_OLD),
        ],
        vec![("composer", "printf 'broken' > ROOT/composer.lock\nexit 2")],
        "edit",
        MONOLOG_EDIT,
    ));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
}

// --- Dart and Flutter ---

const PUBSPEC: &str =
    "name: app\nenvironment:\n  sdk: \">=3.0.0 <4.0.0\"\ndependencies:\n  http: ^1.0.0\n";
const PUBSPEC_FLUTTER: &str = "name: app\nenvironment:\n  sdk: \">=3.0.0 <4.0.0\"\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.0.0\n";
const PUBSPEC_MEMBER: &str = "name: app\nresolution: workspace\nenvironment:\n  sdk: \">=3.0.0 <4.0.0\"\ndependencies:\n  http: ^1.0.0\n";
const PUB_LOCK_OLD: &str = "packages:\n  http:\n    dependency: \"direct main\"\n    description:\n      name: http\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.0.0\"\nsdks:\n  dart: \">=3.0.0 <4.0.0\"\n";
const PUB_LOCK_NEW: &str = "packages:\n  http:\n    dependency: \"direct main\"\n    description:\n      name: http\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.2.0\"\nsdks:\n  dart: \">=3.0.0 <4.0.0\"\n";
const HTTP_EDIT: &str = "http|http:|^1.0.0|^1.2.0|1.0.0|1.2.0";

fn pub_tool() -> String {
    format!("cat > ROOT/pubspec.lock <<'EOF'\n{PUB_LOCK_NEW}EOF\n")
}

fn pub_case<'a>(pubspec: &'a str, tools: Vec<(&'a str, &'a str)>, mode: &'a str) -> Case<'a> {
    let bumps = if mode == "edit" {
        HTTP_EDIT
    } else {
        "http|http:|^1.0.0|^1.0.0|1.0.0|1.2.0"
    };
    case(
        "dart",
        "pubspec.yaml",
        vec![("pubspec.yaml", pubspec), ("pubspec.lock", PUB_LOCK_OLD)],
        tools,
        mode,
        bumps,
    )
}

#[test]
fn dart_manifest_edit_runs_pub_get_through_dart() {
    let tool = pub_tool();
    let ran = run(&pub_case(PUBSPEC, vec![("dart", &tool)], "edit"));

    assert_eq!(
        calls_starting(&ran, "dart pub get --no-example|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn dart_lock_only_pin_runs_pub_upgrade_with_the_names() {
    let tool = pub_tool();
    let ran = run(&pub_case(PUBSPEC, vec![("dart", &tool)], "lockonly"));

    assert_eq!(
        calls_starting(&ran, "dart pub upgrade --no-example http|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert_eq!(ran.calls.len(), 1, "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn flutter_sdk_dependency_selects_flutter_pub() {
    let tool = pub_tool();
    let ran = run(&pub_case(
        PUBSPEC_FLUTTER,
        vec![("flutter", &tool), ("dart", "exit 9")],
        "edit",
    ));

    assert_eq!(
        calls_starting(&ran, "flutter pub get --no-example|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert!(calls_starting(&ran, "dart ").is_empty(), "{:?}", ran.calls);
    regenerated(&ran);
}

#[test]
fn dart_workspace_member_with_its_own_stray_lock_is_refused() {
    let ran = run(&pub_case(PUBSPEC_MEMBER, vec![("dart", "exit 0")], "edit"));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn dart_lock_in_an_ancestor_is_a_workspace_member() {
    let ran = run(&case(
        "dart",
        "member/pubspec.yaml",
        vec![
            ("member/pubspec.yaml", PUBSPEC_MEMBER),
            ("pubspec.lock", PUB_LOCK_OLD),
        ],
        vec![("dart", "exit 0")],
        "edit",
        HTTP_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn dart_cooldown_fallback_target_is_refused_before_any_spawn() {
    let mut case = pub_case(PUBSPEC, vec![("dart", "exit 0")], "edit");
    case.cooldown_fallback = true;
    let ran = run(&case);

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}
