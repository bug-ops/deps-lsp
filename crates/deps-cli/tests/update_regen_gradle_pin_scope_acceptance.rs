//! #2130 / #2133 acceptance: a unified-layout `--update-locks` run may move only the pinned
//! coordinates (a configuration missing from the lock is resolved fresh by Gradle and must not
//! drag unrelated modules to their newest version), while a pin may land on a newer version than
//! its target when the declaration is dynamic. Fake `gradle` scripts run through a re-executed
//! test binary (see `common/regen_harness.rs`).

#![cfg(all(unix, feature = "gradle"))]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const HEADER: &str = "# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\n# This file is expected to be part of source control.\n";
const LANG3_BUMP: &str =
    "org.apache.commons:commons-lang3|org.apache.commons:commons-lang3|3.17.0|3.18.0|3.17.0|3.18.0";
const DYNAMIC_BUMP: &str =
    "org.apache.commons:commons-lang3|org.apache.commons:commons-lang3|3.+|3.18.0|3.17.0|3.18.0";

fn lock(lines: &[&str]) -> String {
    let lines: String = lines.iter().flat_map(|line| [*line, "\n"]).collect();
    format!("{HEADER}{lines}")
}

fn build_gradle(version: &str) -> String {
    format!(
        "plugins {{ id 'java' }}\ndependencies {{\n    implementation 'org.apache.commons:commons-lang3:{version}'\n    runtimeOnly 'commons-io:commons-io:2.11.0'\n}}\n"
    )
}

fn write_lock(text: &str) -> String {
    format!("cat > ROOT/gradle.lockfile <<'EOF'\n{text}EOF\n")
}

fn case<'a>(
    files: &'a [(&'a str, String)],
    body: &'a str,
    mode: &'a str,
    bumps: &'a str,
) -> Case<'a> {
    Case {
        ecosystem: "gradle",
        manifest: "build.gradle",
        files: files
            .iter()
            .map(|(path, text)| (*path, text.as_bytes().to_vec()))
            .collect(),
        tools: vec![("gradle", body)],
        mode,
        bumps,
        cooldown_fallback: false,
        unlistened: false,
    }
}

fn initial_lock() -> String {
    lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.17.0=compileClasspath",
        "empty=annotationProcessor",
    ])
}

fn assert_lock_unchanged(ran: &Ran, original: &str) {
    assert_eq!(ran.read("gradle.lockfile"), original.as_bytes());
}

#[test]
fn gradle_unified_run_that_moves_a_module_of_a_configuration_missing_from_the_lock_is_refused() {
    let original = initial_lock();
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", original.clone()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "commons-io:commons-io:2.22.0=runtimeClasspath,testRuntimeClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath,runtimeClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(
        ran.outcome.contains("LockStateDrift") && ran.outcome.contains("Gained"),
        "{}",
        ran.outcome
    );
    assert_lock_unchanged(&ran, &original);
}

#[test]
fn gradle_unified_run_that_moves_only_the_pinned_module_everywhere_is_accepted() {
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", initial_lock()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath,runtimeClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn gradle_unified_run_that_changes_an_unrelated_module_of_a_known_configuration_is_refused() {
    let original = initial_lock();
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", original.clone()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.22.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
    assert_lock_unchanged(&ran, &original);
}

#[test]
fn gradle_security_pin_of_a_dynamic_declaration_accepts_a_newer_locked_version() {
    let files = vec![
        ("build.gradle", build_gradle("3.+")),
        ("gradle.lockfile", initial_lock()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.22.0=compileClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "lockonly", DYNAMIC_BUMP));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(ran.outcome.contains("Newer"), "{}", ran.outcome);
}

#[test]
fn gradle_pin_locked_below_its_target_is_still_a_version_mismatch() {
    let original = initial_lock();
    let files = vec![
        ("build.gradle", build_gradle("3.+")),
        ("gradle.lockfile", original.clone()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.17.1=compileClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "lockonly", DYNAMIC_BUMP));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
    assert_lock_unchanged(&ran, &original);
}

fn newer_lang3_lock() -> String {
    write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.22.0=compileClasspath",
        "empty=annotationProcessor",
    ]))
}

#[test]
fn gradle_edited_pin_locked_above_its_target_is_still_a_version_mismatch() {
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", initial_lock()),
    ];

    let ran = run(&case(&files, &newer_lang3_lock(), "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
}

#[test]
fn gradle_cooldown_fallback_pin_is_refused_before_any_newer_version_can_count() {
    let files = vec![
        ("build.gradle", build_gradle("3.+")),
        ("gradle.lockfile", initial_lock()),
    ];
    let body = newer_lang3_lock();
    let mut scenario = case(&files, &body, "lockonly", DYNAMIC_BUMP);
    scenario.cooldown_fallback = true;

    let ran = run(&scenario);

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
}

#[test]
fn gradle_pin_locked_at_an_unorderable_version_fails_closed() {
    let files = vec![
        ("build.gradle", build_gradle("3.+")),
        ("gradle.lockfile", initial_lock()),
    ];
    let body = write_lock(&lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.22.0-rc1=compileClasspath",
        "empty=annotationProcessor",
    ]));

    let ran = run(&case(&files, &body, "lockonly", DYNAMIC_BUMP));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
}

const MIGRATION_MARKER: &str = "invalid.deps-cli:lock-layout-migration";

#[test]
fn gradle_migrating_run_that_moves_a_non_pin_coordinate_is_refused() {
    let legacy = lock(&[
        "commons-io:commons-io:2.11.0",
        "org.apache.commons:commons-lang3:3.17.0",
    ]);
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle/dependency-locks/compileClasspath.lockfile", legacy),
    ];
    let migrated = lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.17.0=compileClasspath",
    ]);
    let moved = lock(&[
        "commons-io:commons-io:2.22.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
    ]);
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{}\n;;\n*)\n{}\n;;\nesac\n",
        write_lock(&migrated),
        write_lock(&moved)
    );

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
    assert!(!ran.root.join("gradle.lockfile").exists());
}

#[test]
fn gradle_spawn_that_creates_a_sibling_lock_with_a_non_pin_module_is_refused_and_removed() {
    let original = initial_lock();
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", original.clone()),
    ];
    let body = format!(
        "{}cat > ROOT/buildscript-gradle.lockfile <<'EOF'\n{}EOF\n",
        write_lock(&lock(&[
            "commons-io:commons-io:2.11.0=compileClasspath",
            "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
            "empty=annotationProcessor",
        ])),
        lock(&["org.other:tool:9.9.9=classpath"]),
    );

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
    assert_lock_unchanged(&ran, &original);
    assert!(!ran.root.join("buildscript-gradle.lockfile").exists());
}

#[test]
fn gradle_spawn_that_creates_a_pin_only_sibling_lock_reports_it_as_created() {
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        ("gradle.lockfile", initial_lock()),
    ];
    let body = format!(
        "{}cat > ROOT/buildscript-gradle.lockfile <<'EOF'\n{}EOF\n",
        write_lock(&lock(&[
            "commons-io:commons-io:2.11.0=compileClasspath",
            "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
            "empty=annotationProcessor",
        ])),
        lock(&["org.apache.commons:commons-lang3:3.18.0=classpath"]),
    );

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(
        ran.outcome.contains("Created(") && ran.outcome.contains("buildscript-gradle.lockfile"),
        "{}",
        ran.outcome
    );
}

#[test]
fn gradle_migrating_run_that_creates_a_sibling_lock_in_a_unified_project_is_refused_and_removed() {
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        (
            "gradle/dependency-locks/compileClasspath.lockfile",
            lock(&[
                "commons-io:commons-io:2.11.0",
                "org.apache.commons:commons-lang3:3.17.0",
            ]),
        ),
        ("lib/build.gradle", "plugins { id 'java' }\n".to_owned()),
        (
            "lib/gradle.lockfile",
            lock(&["commons-io:commons-io:2.11.0=compileClasspath"]),
        ),
    ];
    let migrated = lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.17.0=compileClasspath",
    ]);
    let finished = lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
    ]);
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{}\n;;\n*)\n{}cat > ROOT/lib/buildscript-gradle.lockfile <<'EOF'\n{}EOF\n\n;;\nesac\n",
        write_lock(&migrated),
        write_lock(&finished),
        lock(&["org.other:tool:9.9.9=classpath"]),
    );

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
    assert!(!ran.root.join("lib/buildscript-gradle.lockfile").exists());
    assert!(!ran.root.join("gradle.lockfile").exists());
}

#[test]
fn gradle_migration_spawn_that_creates_a_sibling_lock_in_a_unified_project_is_refused_and_removed()
{
    let files = vec![
        ("build.gradle", build_gradle("3.17.0")),
        (
            "gradle/dependency-locks/compileClasspath.lockfile",
            lock(&[
                "commons-io:commons-io:2.11.0",
                "org.apache.commons:commons-lang3:3.17.0",
            ]),
        ),
        ("lib/build.gradle", "plugins { id 'java' }\n".to_owned()),
        (
            "lib/gradle.lockfile",
            lock(&["commons-io:commons-io:2.11.0=compileClasspath"]),
        ),
    ];
    let migrated = lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.17.0=compileClasspath",
    ]);
    let finished = lock(&[
        "commons-io:commons-io:2.11.0=compileClasspath",
        "org.apache.commons:commons-lang3:3.18.0=compileClasspath",
    ]);
    let body = format!(
        "case \"$*\" in\n*{MIGRATION_MARKER}*)\n{}cat > ROOT/lib/buildscript-gradle.lockfile <<'EOF'\n{}EOF\n\n;;\n*)\n{}\n;;\nesac\n",
        write_lock(&migrated),
        lock(&["org.other:tool:9.9.9=classpath"]),
        write_lock(&finished),
    );

    let ran = run(&case(&files, &body, "edit", LANG3_BUMP));

    assert!(ran.outcome.contains("LockStateDrift"), "{}", ran.outcome);
    assert!(!ran.root.join("lib/buildscript-gradle.lockfile").exists());
}
