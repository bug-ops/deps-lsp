//! #2102 acceptance: a Gradle project with the legacy `gradle/dependency-locks/*.lockfile` layout
//! is migrated to the unified `gradle.lockfile` by a first `--update-locks` spawn, proven equal to
//! the legacy state (D3), and only then updated for the pins; stale legacy files are removed and
//! reported; a legacy directory beside a unified lock and settings locks are typed refusals.
//!
//! Written tests-first against the final plan (`LegacyLayoutConflict`, `Companion::{Created,
//! Removed}`, `RegenerationError::LockStateDrift`, the `migration` JSON field). Fake `gradle` shell
//! scripts run through a re-executed test binary (see `common/regen_harness.rs`); real Gradle
//! behaviour is covered by the live-tester contract.

#![cfg(all(unix, feature = "gradle"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use deps_cli::update::regen::{LegacyLayoutConflict, UnsupportedReason};
use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const BUILD_GRADLE: &str = "plugins { id 'java' }\ndependencies {\n    implementation 'com.google.guava:guava:32.1.2-jre'\n}\n";
const GUAVA_EDIT: &str =
    "com.google.guava:guava|com.google.guava:guava|32.1.2-jre|33.0.0-jre|32.1.2-jre|33.0.0-jre";
const MIGRATION_MARKER: &str = "invalid.deps-cli:lock-layout-migration";
const SPAWN_ONE: &str = "gradle --no-daemon --console=plain :dependencies --update-locks invalid.deps-cli:lock-layout-migration|";
const SPAWN_TWO: &str =
    "gradle --no-daemon --console=plain :dependencies --update-locks com.google.guava:guava|";

const LEGACY_DIR: &str = "gradle/dependency-locks";
const COMPILE: &str = "gradle/dependency-locks/compileClasspath.lockfile";
const RUNTIME: &str = "gradle/dependency-locks/runtimeClasspath.lockfile";
const STALE: &str = "gradle/dependency-locks/testRuntimeClasspath.lockfile";
const KAPT: &str = "gradle/dependency-locks/kapt.lockfile";
const BUILDSCRIPT_LEGACY: &str = "gradle/dependency-locks/buildscript-classpath.lockfile";

const HEADER: &str = "# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\n# This file is expected to be part of source control.\n";

fn legacy(coordinates: &[&str]) -> String {
    let lines: String = coordinates.iter().flat_map(|c| [*c, "\n"]).collect();
    format!("{HEADER}{lines}")
}

fn unified(lines: &[&str]) -> String {
    let lines: String = lines.iter().flat_map(|l| [*l, "\n"]).collect();
    format!("{HEADER}{lines}")
}

const GUAVA_OLD: &str = "com.google.guava:guava:32.1.2-jre";
const GUAVA_OLD_BOTH: &str = "com.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath";
const GUAVA_NEW_BOTH: &str = "com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath";

fn legacy_files() -> Vec<(&'static str, String)> {
    vec![
        ("build.gradle", BUILD_GRADLE.to_owned()),
        (COMPILE, legacy(&[GUAVA_OLD])),
        (RUNTIME, legacy(&[GUAVA_OLD])),
    ]
}

fn write_to(path: &str, text: &str) -> String {
    format!("cat > ROOT/{path} <<'EOF'\n{text}EOF\n")
}

/// A fake that answers the migration spawn with `migrated` (plus `extra`, a shell snippet) and
/// every other spawn with `finished`.
fn gradle_body(migrated: &str, extra: &str, finished: &str) -> String {
    format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{}{extra}\n;;\n*)\n{finished}\n;;\nesac\n",
        write_to("gradle.lockfile", migrated)
    )
}

fn happy_body() -> String {
    gradle_body(
        &unified(&[
            GUAVA_OLD_BOTH,
            "empty=annotationProcessor,testCompileClasspath",
        ]),
        "",
        &write_to(
            "gradle.lockfile",
            &unified(&[
                GUAVA_NEW_BOTH,
                "empty=annotationProcessor,testCompileClasspath",
            ]),
        ),
    )
}

fn case<'a>(files: &'a [(&'a str, String)], body: &'a str, mode: &'a str) -> Case<'a> {
    Case {
        ecosystem: "gradle",
        manifest: "build.gradle",
        files: files
            .iter()
            .map(|(path, text)| (*path, text.as_bytes().to_vec()))
            .collect(),
        tools: vec![("gradle", body)],
        mode,
        bumps: GUAVA_EDIT,
        cooldown_fallback: false,
        unlistened: false,
    }
}

fn gradle_calls(ran: &Ran) -> Vec<&String> {
    ran.calls_of("gradle")
}

fn exists(ran: &Ran, rel: &str) -> bool {
    ran.root.join(rel).exists()
}

fn assert_refused_without_a_spawn(ran: &Ran, needle: &str) {
    assert!(ran.outcome.contains(needle), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

fn assert_legacy_untouched(ran: &Ran, files: &[(&str, String)]) {
    for (path, text) in files
        .iter()
        .filter(|(path, _)| path.starts_with(LEGACY_DIR))
    {
        assert_eq!(ran.read(path), text.as_bytes(), "{path}");
    }
    assert!(!exists(ran, "gradle.lockfile"), "created lock must be gone");
    assert!(!exists(ran, "buildscript-gradle.lockfile"));
}

fn json_paths(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get("migration")
        .and_then(|migration| migration.get(key))
        .and_then(serde_json::Value::as_array)
        .expect("migration section with the key")
        .iter()
        .map(|path| path.as_str().expect("path string").to_owned())
        .collect()
}

fn json_removed(value: &serde_json::Value) -> Vec<(String, String)> {
    value
        .get("migration")
        .and_then(|migration| migration.get("removed"))
        .and_then(serde_json::Value::as_array)
        .expect("migration section with removed")
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().expect("path").to_owned(),
                entry["removal"].as_str().expect("removal").to_owned(),
            )
        })
        .collect()
}

fn removal_of(removed: &[(String, String)], file: &str) -> String {
    removed
        .iter()
        .find(|(path, _)| path.ends_with(file))
        .map(|(_, removal)| removal.clone())
        .unwrap_or_else(|| panic!("{file} not in {removed:?}"))
}

// --- migration ---

#[test]
fn gradle_legacy_layout_migrates_then_updates_and_reports_created_and_removed_files() {
    let files = legacy_files();
    let ran = run(&case(&files, &happy_body(), "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let calls = gradle_calls(&ran);
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(calls[0].starts_with(SPAWN_ONE), "{}", calls[0]);
    assert!(calls[1].starts_with(SPAWN_TWO), "{}", calls[1]);
    assert!(
        ran.calls.iter().all(|call| !call.contains("--write-locks")),
        "{:?}",
        ran.calls
    );
    assert!(!exists(&ran, COMPILE) && !exists(&ran, RUNTIME));
    assert!(
        String::from_utf8(ran.read("gradle.lockfile"))
            .expect("utf-8")
            .contains(GUAVA_NEW_BOTH)
    );
    assert!(
        ran.outcome.contains("Created(") && ran.outcome.contains("/project/gradle.lockfile"),
        "{}",
        ran.outcome
    );
    assert!(
        ran.outcome.contains("Removed {") && ran.outcome.contains("runtimeClasspath.lockfile"),
        "{}",
        ran.outcome
    );
}

#[test]
fn gradle_legacy_migration_is_reported_in_the_json_lockfile_section() {
    let files = legacy_files();
    let ran = run(&case(&files, &happy_body(), "edit"));

    let json = ran.lockfile_json.as_ref().expect("child printed the JSON");
    let created = json_paths(json, "created");
    let removed = json_removed(json);
    assert!(
        created.iter().any(|path| path.ends_with("gradle.lockfile")),
        "{created:?}"
    );
    assert_eq!(
        removal_of(&removed, "runtimeClasspath.lockfile"),
        "migrated"
    );
    assert_eq!(
        removal_of(&removed, "compileClasspath.lockfile"),
        "migrated"
    );
}

#[test]
fn gradle_unified_layout_run_has_no_migration_section() {
    let old = unified(&[
        "com.google.guava:guava:32.1.2-jre=compileClasspath",
        "empty=",
    ]);
    let new = unified(&[
        "com.google.guava:guava:33.0.0-jre=compileClasspath",
        "empty=",
    ]);
    let files = vec![
        ("build.gradle", BUILD_GRADLE.to_owned()),
        ("gradle.lockfile", old),
    ];
    let body = write_to("gradle.lockfile", &new);

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let json = ran.lockfile_json.as_ref().expect("child printed the JSON");
    assert!(json.get("migration").is_none(), "{json}");
    assert!(!ran.outcome.contains("Created("), "{}", ran.outcome);
}

#[test]
fn gradle_legacy_lock_only_pin_migrates_first_too() {
    let files = legacy_files();
    let ran = run(&case(&files, &happy_body(), "lockonly"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(gradle_calls(&ran)[0].starts_with(SPAWN_ONE));
}

#[test]
fn gradle_stale_legacy_files_are_removed_and_classified_by_what_was_dropped() {
    let mut files = legacy_files();
    files.push((STALE, legacy(&["junit:junit:4.13.2"])));
    files.push((KAPT, legacy(&[])));

    let ran = run(&case(&files, &happy_body(), "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(!exists(&ran, STALE) && !exists(&ran, KAPT));
    assert!(
        ran.outcome.contains("StaleDropped") && ran.outcome.contains("StaleEmpty"),
        "{}",
        ran.outcome
    );
    assert!(
        ran.outcome.contains("Migrated"),
        "a resolved configuration is Migrated: {}",
        ran.outcome
    );
    let json = ran.lockfile_json.as_ref().expect("JSON");
    let removed = json_removed(json);
    assert_eq!(
        removal_of(&removed, "testRuntimeClasspath.lockfile"),
        "stale-dropped"
    );
    assert_eq!(removal_of(&removed, "kapt.lockfile"), "stale-empty");
    assert_eq!(
        removal_of(&removed, "runtimeClasspath.lockfile"),
        "migrated"
    );
}

#[test]
fn gradle_empty_value_in_a_buildscript_lock_is_no_configurations_and_not_drift() {
    for empty_line in ["empty=", "empty=classpath"] {
        let mut files = legacy_files();
        files.push((BUILDSCRIPT_LEGACY, legacy(&[])));
        let extra = write_to("buildscript-gradle.lockfile", &unified(&[empty_line]));
        let body = gradle_body(
            &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"]),
            &extra,
            &write_to(
                "gradle.lockfile",
                &unified(&[GUAVA_NEW_BOTH, "empty=annotationProcessor"]),
            ),
        );

        let ran = run(&case(&files, &body, "edit"));

        assert!(
            ran.outcome.starts_with("Regenerated"),
            "{empty_line}: {}",
            ran.outcome
        );
        assert!(!exists(&ran, BUILDSCRIPT_LEGACY), "{empty_line}");
    }
}

// --- drift and rollback ---

const FAILUREACCESS_OLD: &str = "com.google.guava:failureaccess:1.0.1";

#[test]
fn gradle_migration_that_gains_or_loses_a_coordinate_of_a_migrated_configuration_is_drift() {
    for (name, migrated, expected_change, message) in [
        (
            "gained",
            unified(&[GUAVA_OLD_BOTH, "org.extra:lib:1.0=compileClasspath"]),
            "Gained",
            "gained org.extra:lib:1.0",
        ),
        (
            "lost",
            unified(&[
                "com.google.guava:guava:32.1.2-jre=runtimeClasspath",
                "com.google.guava:failureaccess:1.0.1=compileClasspath",
            ]),
            "Lost",
            "lost com.google.guava:guava:32.1.2-jre",
        ),
    ] {
        let mut files = legacy_files();
        files[1] = (COMPILE, legacy(&[FAILUREACCESS_OLD, GUAVA_OLD]));
        let body = gradle_body(&migrated, "", "exit 0");

        let ran = run(&case(&files, &body, "edit"));

        assert!(
            ran.outcome.contains("LockStateDrift") && ran.outcome.contains(expected_change),
            "{name}: {}",
            ran.outcome
        );
        assert_eq!(gradle_calls(&ran).len(), 1, "{name}: {:?}", ran.calls);
        assert_legacy_untouched(&ran, &files);
        let json = ran.lockfile_json.as_ref().expect("JSON");
        assert_eq!(json["kind"], "lock-state-drift", "{name}");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|text| text.contains(message)),
            "{name}: the drift text names the coordinate: {json}"
        );
    }
}

#[test]
fn gradle_configuration_missing_from_the_migrated_lock_is_stale_dropped_not_drift() {
    let files = legacy_files();
    let body = gradle_body(
        &unified(&["com.google.guava:guava:32.1.2-jre=runtimeClasspath"]),
        "",
        &write_to("gradle.lockfile", &unified(&[GUAVA_NEW_BOTH])),
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(!exists(&ran, COMPILE), "the stale legacy file must be gone");
    let json = ran.lockfile_json.as_ref().expect("JSON");
    let removed = json_removed(json);
    assert_eq!(
        removal_of(&removed, "compileClasspath.lockfile"),
        "stale-dropped"
    );
    assert_eq!(
        removal_of(&removed, "runtimeClasspath.lockfile"),
        "migrated"
    );
}

#[test]
fn gradle_second_spawn_failure_restores_every_legacy_file_and_removes_the_created_locks() {
    let mut files = legacy_files();
    files.push((STALE, legacy(&["junit:junit:4.13.2"])));
    let body = gradle_body(
        &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"]),
        &write_to("buildscript-gradle.lockfile", &unified(&["empty="])),
        "echo junk > ROOT/gradle.lockfile\nexit 1",
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_legacy_untouched(&ran, &files);
}

#[test]
fn gradle_migration_spawn_failure_restores_the_legacy_layout() {
    let files = legacy_files();
    let body = "echo junk > ROOT/gradle.lockfile\nexit 1";

    let ran = run(&case(&files, body, "edit"));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_eq!(gradle_calls(&ran).len(), 1, "{:?}", ran.calls);
    assert_legacy_untouched(&ran, &files);
}

// --- refusals ---

#[test]
fn gradle_legacy_directory_beside_a_unified_lock_is_refused_naming_the_legacy_file() {
    let mut files = legacy_files();
    files.push(("gradle.lockfile", unified(&[GUAVA_OLD_BOTH])));

    let ran = run(&case(&files, "exit 0", "edit"));

    assert_refused_without_a_spawn(&ran, "LegacyLockLayout(BesideUnifiedLock)");
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["reason"], "legacy-lock-layout");
    assert!(
        json["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("compileClasspath.lockfile")),
        "{json}"
    );
}

#[test]
fn gradle_settings_lock_in_the_legacy_directory_is_refused_without_a_spawn() {
    let mut files = legacy_files();
    files.push((
        "gradle/dependency-locks/settings-classpath.lockfile",
        legacy(&["org.example:plugin:1.0"]),
    ));

    let ran = run(&case(&files, "exit 0", "edit"));

    assert_refused_without_a_spawn(&ran, "LegacyLockLayout(SettingsLock)");
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["reason"], "legacy-lock-layout");
    assert!(
        json["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("settings-classpath.lockfile")),
        "{json}"
    );
}

#[test]
fn gradle_empty_legacy_directory_beside_a_unified_lock_is_not_refused() {
    let old = unified(&[
        "com.google.guava:guava:32.1.2-jre=compileClasspath",
        "empty=",
    ]);
    let new = unified(&[
        "com.google.guava:guava:33.0.0-jre=compileClasspath",
        "empty=",
    ]);
    let files = vec![
        ("build.gradle", BUILD_GRADLE.to_owned()),
        ("gradle.lockfile", old),
        (
            "gradle/dependency-locks/README.txt",
            "not a lock\n".to_owned(),
        ),
    ];
    let body = write_to("gradle.lockfile", &new);

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let calls = gradle_calls(&ran);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with(SPAWN_TWO), "{}", calls[0]);
}

#[test]
fn legacy_layout_conflict_messages_are_actionable_and_never_mention_write_locks() {
    let beside =
        UnsupportedReason::LegacyLockLayout(LegacyLayoutConflict::BesideUnifiedLock).to_string();
    let settings =
        UnsupportedReason::LegacyLockLayout(LegacyLayoutConflict::SettingsLock).to_string();

    assert!(
        beside.contains("gradle.lockfile") && beside.contains("gradle/dependency-locks"),
        "{beside}"
    );
    assert!(settings.contains("settings"), "{settings}");
    for text in [&beside, &settings] {
        assert!(!text.contains("--write-locks"), "{text}");
    }
    assert_ne!(beside, settings);
}

fn subproject_case<'a>(files: &'a [(&'a str, String)], body: &'a str) -> Case<'a> {
    Case {
        manifest: "app/build.gradle",
        ..case(files, body, "edit")
    }
}

#[test]
fn gradle_legacy_layout_of_a_subproject_migrates_through_its_project_task() {
    let files = vec![
        ("settings.gradle", "include 'app'\n".to_owned()),
        ("app/build.gradle", BUILD_GRADLE.to_owned()),
        (
            "app/gradle/dependency-locks/compileClasspath.lockfile",
            legacy(&[GUAVA_OLD]),
        ),
        (
            "app/gradle/dependency-locks/runtimeClasspath.lockfile",
            legacy(&[GUAVA_OLD]),
        ),
    ];
    let migrated = write_to(
        "app/gradle.lockfile",
        &unified(&[GUAVA_OLD_BOTH, "empty=kapt"]),
    );
    let finished = write_to(
        "app/gradle.lockfile",
        &unified(&[GUAVA_NEW_BOTH, "empty=kapt"]),
    );
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{migrated}\n;;\n*)\n{finished}\n;;\nesac\n"
    );

    let ran = run(&subproject_case(&files, &body));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let calls = gradle_calls(&ran);
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with(&format!(
            "gradle --no-daemon --console=plain :app:dependencies --update-locks {MIGRATION_MARKER}|"
        )),
        "{}",
        calls[0]
    );
    assert!(!exists(
        &ran,
        "app/gradle/dependency-locks/runtimeClasspath.lockfile"
    ));
}

#[test]
fn gradle_buildscript_lock_beside_a_legacy_layout_is_refused_without_a_spawn() {
    let mut files = legacy_files();
    files.push(("buildscript-gradle.lockfile", unified(&["empty="])));

    let ran = run(&case(&files, "exit 0", "edit"));

    assert_refused_without_a_spawn(&ran, "LegacyLockLayout(BesideUnifiedLock)");
}

#[test]
fn gradle_symlinked_legacy_lock_file_is_refused_without_a_spawn() {
    let files = legacy_files();
    let project = harness::prepare(&case(&files, "exit 0", "edit"));
    let link = project
        .root
        .join("gradle/dependency-locks/extraClasspath.lockfile");
    std::os::unix::fs::symlink(project.root.join(COMPILE), link).expect("symlink");

    let output = project
        .child(&case(&files, "exit 0", "edit"))
        .output()
        .expect("child");

    let outcome = harness::outcome_of(&String::from_utf8_lossy(&output.stdout));
    assert!(outcome.contains("LockfileSymlink"), "{outcome}");
    assert!(project.calls().is_empty(), "{:?}", project.calls());
}

#[test]
fn gradle_legacy_layout_in_buildsrc_is_refused_without_a_spawn() {
    let mut files = legacy_files();
    files.push((
        "buildSrc/gradle/dependency-locks/compileClasspath.lockfile",
        legacy(&[GUAVA_OLD]),
    ));

    let ran = run(&case(&files, "exit 0", "edit"));

    assert_refused_without_a_spawn(&ran, "LockfileOwnershipMismatch");
}

#[test]
fn gradle_migration_reports_the_unified_lock_and_relative_paths_in_json() {
    let files = legacy_files();
    let ran = run(&case(&files, &happy_body(), "edit"));

    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["path"], "gradle.lockfile", "{json}");
    let created = json_paths(json, "created");
    let removed: Vec<String> = json_removed(json)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    assert!(
        created.contains(&"gradle.lockfile".to_owned()),
        "{created:?}"
    );
    assert!(removed.contains(&RUNTIME.to_owned()), "{removed:?}");
    for path in created.iter().chain(&removed) {
        assert!(!path.starts_with('/'), "absolute path in the JSON: {path}");
    }
}

#[test]
fn gradle_buildscript_legacy_file_located_first_still_reports_the_project_lock() {
    let mut files = legacy_files();
    files.push((BUILDSCRIPT_LEGACY, legacy(&[])));
    let extra = write_to(
        "buildscript-gradle.lockfile",
        &unified(&["empty=classpath"]),
    );
    let body = gradle_body(
        &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"]),
        &extra,
        &write_to(
            "gradle.lockfile",
            &unified(&[GUAVA_NEW_BOTH, "empty=annotationProcessor"]),
        ),
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["path"], "gradle.lockfile", "{json}");
}

#[test]
fn gradle_conflict_in_a_subproject_names_that_projects_legacy_file() {
    let files = vec![
        ("settings.gradle", "include 'lib'\n".to_owned()),
        ("lib/build.gradle", BUILD_GRADLE.to_owned()),
        ("lib/gradle.lockfile", unified(&[GUAVA_OLD_BOTH])),
        (
            "lib/gradle/dependency-locks/compileClasspath.lockfile",
            legacy(&[GUAVA_OLD]),
        ),
        ("gradle/dependency-locks/aaa.lockfile", legacy(&[GUAVA_OLD])),
    ];

    let ran = run(&Case {
        manifest: "lib/build.gradle",
        ..case(&files, "exit 0", "edit")
    });

    assert_refused_without_a_spawn(&ran, "LegacyLockLayout(BesideUnifiedLock)");
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert!(
        json["path"].as_str().is_some_and(
            |path| path.ends_with("lib/gradle/dependency-locks/compileClasspath.lockfile")
        ),
        "{json}"
    );
}

#[test]
fn gradle_created_lock_left_as_a_symlink_is_not_followed_and_is_rolled_back() {
    let files = legacy_files();
    let finished = "rm -f ROOT/gradle.lockfile\necho x > ROOT/target.txt\nln -s ROOT/target.txt ROOT/gradle.lockfile";
    let body = gradle_body(
        &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"]),
        "",
        finished,
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(
        ran.outcome.contains("LockfileUnreadable"),
        "{}",
        ran.outcome
    );
    for (path, text) in files
        .iter()
        .filter(|(path, _)| path.starts_with(LEGACY_DIR))
    {
        assert_eq!(ran.read(path), text.as_bytes(), "{path}");
    }
    assert!(
        std::fs::symlink_metadata(ran.root.join("gradle.lockfile")).is_err(),
        "the symlinked created lock must be removed"
    );
}

fn edited_build_gradle() -> String {
    BUILD_GRADLE.replace("32.1.2-jre", "33.0.0-jre")
}

#[test]
fn gradle_edit_pin_with_a_legacy_layout_migrates_with_the_neutral_declaration_then_applies_the_edit()
 {
    let files = legacy_files();
    let neutral_check = "grep -q 'guava:32.1.2-jre' ROOT/build.gradle || exit 9";
    let edited_check = "grep -q 'guava:33.0.0-jre' ROOT/build.gradle || exit 10\n";
    let body = gradle_body(
        &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"]),
        neutral_check,
        &format!(
            "{edited_check}{}",
            write_to(
                "gradle.lockfile",
                &unified(&[GUAVA_NEW_BOTH, "empty=annotationProcessor"])
            )
        ),
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(gradle_calls(&ran).len(), 2, "{:?}", ran.calls);
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
    assert!(
        String::from_utf8(ran.read("gradle.lockfile"))
            .expect("utf-8")
            .contains(GUAVA_NEW_BOTH)
    );
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert!(json.get("migration").is_some(), "{json}");
    assert!(!ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
}

#[test]
fn gradle_edit_pin_locked_at_several_legacy_versions_is_refused_without_a_spawn() {
    let files = vec![
        ("build.gradle", BUILD_GRADLE.to_owned()),
        (COMPILE, legacy(&[GUAVA_OLD])),
        (RUNTIME, legacy(&["com.google.guava:guava:31.0-jre"])),
    ];

    let ran = run(&case(&files, "exit 0", "edit"));

    assert!(
        ran.outcome
            .contains("LegacyLockLayout(EditedPinLockedAtSeveralVersions)"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["reason"], "legacy-lock-layout");
    assert!(
        json["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("build.gradle")),
        "{json}"
    );
    assert_legacy_untouched(&ran, &files);
}

#[test]
fn gradle_edit_pin_with_two_declarations_is_refused_without_a_spawn() {
    let two_declarations = BUILD_GRADLE.replace(
        "}\n",
        "    testImplementation 'com.google.guava:guava:32.1.2-jre'\n}\n",
    );
    let files = vec![
        ("build.gradle", two_declarations),
        (COMPILE, legacy(&[GUAVA_OLD])),
        (RUNTIME, legacy(&[GUAVA_OLD])),
    ];

    let ran = run(&case(&files, "exit 0", "edit"));

    assert!(
        ran.outcome
            .contains("LegacyLockLayout(EditedPinWithoutSingleDeclaration)"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
    assert_legacy_untouched(&ran, &files);
}

#[test]
fn gradle_edited_pin_conflict_messages_advise_a_working_path_and_never_mention_write_locks() {
    for conflict in [
        LegacyLayoutConflict::EditedPinLockedAtSeveralVersions,
        LegacyLayoutConflict::EditedPinWithoutSingleDeclaration,
    ] {
        let text = UnsupportedReason::LegacyLockLayout(conflict).to_string();

        assert!(text.contains(":dependencies --update-locks"), "{text}");
        assert!(!text.contains("--write-locks"), "{text}");
        assert!(!text.contains("rerun without"), "{text}");
    }
}

#[test]
fn gradle_edit_pin_absent_from_the_legacy_state_keeps_its_edited_declaration() {
    let files = vec![
        ("build.gradle", BUILD_GRADLE.to_owned()),
        (COMPILE, legacy(&["org.other:lib:1.0"])),
        (RUNTIME, legacy(&["org.other:lib:1.0"])),
    ];
    let edited_check = "grep -q 'guava:33.0.0-jre' ROOT/build.gradle || exit 9";
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{edited_check}\n{}\n;;\n*)\n{}\n;;\nesac\n",
        write_to(
            "gradle.lockfile",
            &unified(&["org.other:lib:1.0=compileClasspath,runtimeClasspath"])
        ),
        write_to(
            "gradle.lockfile",
            &unified(&[
                "com.google.guava:guava:33.0.0-jre=compileClasspath",
                "org.other:lib:1.0=compileClasspath,runtimeClasspath"
            ])
        )
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
}

/// impl-critic R4: a unified manifest project beside a legacy sibling that never locks the pin.
#[test]
fn gradle_unified_manifest_project_with_a_legacy_sibling_regenerates_for_an_edit_pin() {
    let lib_old = "commons-io:commons-io:2.11.0";
    let files = vec![
        ("settings.gradle", "include 'lib'\n".to_owned()),
        ("build.gradle", BUILD_GRADLE.to_owned()),
        (
            "gradle.lockfile",
            unified(&["com.google.guava:guava:32.1.2-jre=compileClasspath"]),
        ),
        ("lib/build.gradle", "plugins { id 'java' }\n".to_owned()),
        (
            "lib/gradle/dependency-locks/compileClasspath.lockfile",
            legacy(&[lib_old]),
        ),
    ];
    let edited_check = "grep -q 'guava:33.0.0-jre' ROOT/build.gradle || exit 9";
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{edited_check}\n{}\n;;\n*)\n{}\n;;\nesac\n",
        write_to(
            "lib/gradle.lockfile",
            &unified(&["commons-io:commons-io:2.11.0=compileClasspath"])
        ),
        write_to(
            "gradle.lockfile",
            &unified(&["com.google.guava:guava:33.0.0-jre=compileClasspath"])
        )
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(gradle_calls(&ran).len(), 2, "{:?}", ran.calls);
    assert!(!exists(
        &ran,
        "lib/gradle/dependency-locks/compileClasspath.lockfile"
    ));
    assert!(exists(&ran, "lib/gradle.lockfile"));
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
    let json = ran.lockfile_json.as_ref().expect("JSON");
    assert_eq!(json["path"], "gradle.lockfile", "{json}");
}

#[test]
fn gradle_other_version_in_another_project_or_scope_does_not_refuse_the_edit_pin() {
    let mut files = legacy_files();
    files.push((
        "lib/gradle/dependency-locks/compileClasspath.lockfile",
        legacy(&["com.google.guava:guava:31.0-jre"]),
    ));
    files.push((
        BUILDSCRIPT_LEGACY,
        legacy(&["com.google.guava:guava:30.0-jre"]),
    ));
    files.push(("settings.gradle", "include 'lib'\n".to_owned()));
    files.push(("lib/build.gradle", "plugins { id 'java' }\n".to_owned()));
    let neutral_check = "grep -q 'guava:32.1.2-jre' ROOT/build.gradle || exit 9";
    let migration_writes = format!(
        "{}\n{}\n{}",
        write_to(
            "gradle.lockfile",
            &unified(&[GUAVA_OLD_BOTH, "empty=annotationProcessor"])
        ),
        write_to(
            "lib/gradle.lockfile",
            &unified(&["com.google.guava:guava:31.0-jre=compileClasspath"])
        ),
        write_to(
            "buildscript-gradle.lockfile",
            &unified(&["com.google.guava:guava:30.0-jre=classpath"])
        )
    );
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{neutral_check}\n{migration_writes}\n;;\n*)\n{}\n;;\nesac\n",
        write_to(
            "gradle.lockfile",
            &unified(&[GUAVA_NEW_BOTH, "empty=annotationProcessor"])
        )
    );

    let ran = run(&case(&files, &body, "edit"));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
}

#[test]
fn gradle_migration_spawn_failure_with_an_edit_pin_keeps_the_edit_and_restores_the_locks() {
    let files = legacy_files();
    let body = "echo junk > ROOT/gradle.lockfile\nexit 1";

    let ran = run(&case(&files, body, "edit"));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_eq!(gradle_calls(&ran).len(), 1, "{:?}", ran.calls);
    assert_eq!(ran.read("build.gradle"), edited_build_gradle().into_bytes());
    assert_legacy_untouched(&ran, &files);
}
