//! #2084 / #2085 / #2086 acceptance: NuGet, Gradle and SwiftPM lock-file regeneration driven
//! through fake tools in a re-executed test binary (see `common/regen_harness.rs`).
//!
//! Fake tools record `tool argv|cwd|env`; argv is matched through the `starts_with("<tool>
//! <argv>|")` form so a trailing difference fails. Not covered here (needs the real tools, left
//! to the Docker verification): real flag acceptance by `dotnet` and `gradle`.

#![cfg(all(unix, feature = "nuget", feature = "gradle", feature = "swift"))]
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

fn cwd_of(call: &str) -> &str {
    call.split('|').nth(1).expect("cwd field")
}

fn regenerated(ran: &Ran) -> bool {
    ran.outcome.starts_with("Regenerated")
}

// --- NuGet ---

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n  </ItemGroup>\n</Project>\n";

fn nuget_lock(version: &str) -> String {
    format!(
        "{{\n  \"version\": 1,\n  \"dependencies\": {{\n    \"net8.0\": {{\n      \"Newtonsoft.Json\": {{\n        \"type\": \"Direct\",\n        \"requested\": \"[{version}, )\",\n        \"resolved\": \"{version}\",\n        \"contentHash\": \"abc\"\n      }}\n    }}\n  }}\n}}\n"
    )
}

const NEWTONSOFT_EDIT: &str = "Newtonsoft.Json|Newtonsoft.Json|13.0.1|13.0.3|13.0.1|13.0.3";

fn dotnet_writing_lock(path: &str) -> String {
    format!("cat > ROOT/{path} <<'EOF'\n{}EOF\n", nuget_lock("13.0.3"))
}

#[test]
fn nuget_manifest_edit_restores_the_project_with_the_lock_file_and_verifies() {
    let old = nuget_lock("13.0.1");
    let body = dotnet_writing_lock("packages.lock.json");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ), ("packages.lock.json", &old)],
        vec![("dotnet", &body)],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    let restores = calls_starting(
        &ran,
        "dotnet restore App.csproj --use-lock-file --no-dependencies --disable-build-servers|",
    );
    assert_eq!(restores.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(restores[0]), ran.root.display().to_string());
    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn nuget_other_floating_requirement_is_refused_without_a_spawn() {
    for sibling in [
        "<PackageReference Include=\"Serilog\" Version=\"2.*\" />",
        "<PackageReference Include=\"Serilog\" Version=\"[2.0,3.0)\" />",
    ] {
        let csproj = CSPROJ.replace("  </ItemGroup>", &format!("    {sibling}\n  </ItemGroup>"));
        let old = nuget_lock("13.0.1");
        let ran = run(&case(
            "nuget",
            "App.csproj",
            vec![("App.csproj", &csproj), ("packages.lock.json", &old)],
            vec![("dotnet", "exit 0")],
            "edit",
            NEWTONSOFT_EDIT,
        ));

        assert!(
            ran.outcome.contains("OtherFloatingRequirements"),
            "{sibling}: {}",
            ran.outcome
        );
        assert!(ran.calls.is_empty(), "{sibling}: {:?}", ran.calls);
    }
}

#[test]
fn nuget_exact_sibling_requirements_still_regenerate() {
    let csproj = CSPROJ.replace(
        "  </ItemGroup>",
        "    <PackageReference Include=\"Serilog\" Version=\"2.10.0\" />\n    <PackageReference Include=\"Other\" Version=\"[1.0.0]\" />\n  </ItemGroup>",
    );
    let old = nuget_lock("13.0.1");
    let body = dotnet_writing_lock("packages.lock.json");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", &csproj), ("packages.lock.json", &old)],
        vec![("dotnet", &body)],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn nuget_never_passes_force_evaluate() {
    let old = nuget_lock("13.0.1");
    let body = dotnet_writing_lock("packages.lock.json");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ), ("packages.lock.json", &old)],
        vec![("dotnet", &body)],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(
        ran.calls
            .iter()
            .all(|call| !call.contains("--force-evaluate")),
        "{:?}",
        ran.calls
    );
}

#[test]
fn nuget_per_project_lock_file_is_the_one_regenerated() {
    let old = nuget_lock("13.0.1");
    let body = dotnet_writing_lock("packages.App.lock.json");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ), ("packages.App.lock.json", &old)],
        vec![("dotnet", &body)],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(regenerated(&ran), "{}", ran.outcome);
    assert_eq!(
        ran.read("packages.App.lock.json"),
        nuget_lock("13.0.3").into_bytes()
    );
}

#[test]
fn nuget_lock_only_pins_are_refused_without_a_spawn() {
    let old = nuget_lock("13.0.1");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ), ("packages.lock.json", &old)],
        vec![("dotnet", "exit 0")],
        "lockonly",
        "Newtonsoft.Json|Newtonsoft.Json|13.0.1|13.0.1|13.0.1|13.0.3",
    ));

    assert!(
        ran.outcome
            .contains("LockfileOnlyUpdateUnsupported(Dotnet)"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn nuget_central_package_versions_are_refused_without_a_spawn() {
    let props = "<Project>\n  <ItemGroup>\n    <PackageVersion Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n  </ItemGroup>\n</Project>\n";
    let old = nuget_lock("13.0.1");
    let ran = run(&case(
        "nuget",
        "Directory.Packages.props",
        vec![
            ("Directory.Packages.props", props),
            ("packages.lock.json", &old),
        ],
        vec![("dotnet", "exit 0")],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(
        ran.outcome.contains("CentralPackageVersions"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn nuget_packages_config_has_nothing_to_regenerate() {
    let config = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<packages>\n  <package id=\"Newtonsoft.Json\" version=\"13.0.1\" targetFramework=\"net48\" />\n</packages>\n";
    let ran = run(&case(
        "nuget",
        "packages.config",
        vec![("packages.config", config)],
        vec![("dotnet", "exit 0")],
        "edit",
        "Newtonsoft.Json|Newtonsoft.Json|13.0.1|13.0.3|13.0.1|13.0.3",
    ));

    assert!(ran.outcome.contains("NotApplicable"), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn nuget_without_a_lock_file_has_nothing_to_regenerate() {
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ)],
        vec![("dotnet", "exit 0")],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(ran.outcome.contains("NoLockfilePresent"), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn nuget_failed_restore_puts_the_lock_file_back() {
    let old = nuget_lock("13.0.1");
    let ran = run(&case(
        "nuget",
        "App.csproj",
        vec![("App.csproj", CSPROJ), ("packages.lock.json", &old)],
        vec![("dotnet", "echo garbage > ROOT/packages.lock.json\nexit 1")],
        "edit",
        NEWTONSOFT_EDIT,
    ));

    assert!(ran.outcome.starts_with("Failed"), "{}", ran.outcome);
    assert_eq!(ran.read("packages.lock.json"), old.into_bytes());
}

// --- Gradle ---

const BUILD_GRADLE: &str = "plugins { id 'java' }\ndependencies {\n    implementation 'com.google.guava:guava:32.1.2-jre'\n}\n";
const GUAVA_EDIT: &str =
    "com.google.guava:guava|com.google.guava:guava|32.1.2-jre|33.0.0-jre|32.1.2-jre|33.0.0-jre";

fn gradle_lock(version: &str) -> String {
    format!("# lock\ncom.google.guava:guava:{version}=compileClasspath,runtimeClasspath\nempty=\n")
}

fn gradle_writing(paths: &[&str]) -> String {
    let lock = gradle_lock("33.0.0-jre");
    let mut script = String::new();
    for path in paths {
        script.push_str(&format!("cat > ROOT/{path} <<'EOF'\n{lock}EOF\n"));
    }
    script
}

#[test]
fn gradle_manifest_edit_updates_locks_at_the_build_root() {
    let old = gradle_lock("32.1.2-jre");
    let body = gradle_writing(&["gradle.lockfile"]);
    let ran = run(&case(
        "gradle",
        "build.gradle",
        vec![("build.gradle", BUILD_GRADLE), ("gradle.lockfile", &old)],
        vec![("gradle", &body)],
        "edit",
        GUAVA_EDIT,
    ));

    let updates = calls_starting(
        &ran,
        "gradle --no-daemon --console=plain :dependencies --update-locks com.google.guava:guava|",
    );
    assert_eq!(updates.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(updates[0]), ran.root.display().to_string());
    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn gradle_subproject_runs_at_the_settings_root_and_reports_every_lock_as_a_companion() {
    let old = gradle_lock("32.1.2-jre");
    let body = gradle_writing(&["app/gradle.lockfile", "gradle.lockfile"]);
    let ran = run(&case(
        "gradle",
        "app/build.gradle",
        vec![
            ("settings.gradle", "include 'app'\n"),
            ("app/build.gradle", BUILD_GRADLE),
            ("app/gradle.lockfile", &old),
            ("gradle.lockfile", &old),
        ],
        vec![("gradle", &body)],
        "edit",
        GUAVA_EDIT,
    ));

    let updates = calls_starting(
        &ran,
        "gradle --no-daemon --console=plain :app:dependencies :dependencies --update-locks com.google.guava:guava|",
    );
    assert_eq!(updates.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(updates[0]), ran.root.display().to_string());
    assert!(regenerated(&ran), "{}", ran.outcome);
    assert!(
        ran.outcome.contains("File(") && ran.outcome.contains("/project/gradle.lockfile"),
        "the root lock must be a companion: {}",
        ran.outcome
    );
}

#[test]
fn gradle_lock_holding_a_newer_version_than_the_target_is_a_mismatch_and_restored() {
    let old = gradle_lock("32.1.2-jre");
    let body = format!(
        "cat > ROOT/gradle.lockfile <<'EOF'\n{}EOF\n",
        gradle_lock("33.1.0-jre")
    );
    let ran = run(&case(
        "gradle",
        "build.gradle",
        vec![("build.gradle", BUILD_GRADLE), ("gradle.lockfile", &old)],
        vec![("gradle", &body)],
        "edit",
        GUAVA_EDIT,
    ));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
    assert_eq!(ran.read("gradle.lockfile"), old.into_bytes());
}

#[test]
fn gradle_lock_in_buildsrc_or_an_included_build_is_refused_without_a_spawn() {
    let old = gradle_lock("32.1.2-jre");
    for nested in ["buildSrc/gradle.lockfile", "included/gradle.lockfile"] {
        let ran = run(&case(
            "gradle",
            "build.gradle",
            vec![
                ("settings.gradle", "includeBuild 'included'\n"),
                ("included/settings.gradle", "rootProject.name = 'i'\n"),
                ("build.gradle", BUILD_GRADLE),
                ("gradle.lockfile", &old),
                (nested, &old),
            ],
            vec![("gradle", "exit 0")],
            "edit",
            GUAVA_EDIT,
        ));

        assert!(
            ran.outcome.contains("LockfileOwnershipMismatch"),
            "{nested}: {}",
            ran.outcome
        );
        assert!(ran.calls.is_empty(), "{nested}: {:?}", ran.calls);
    }
}

#[test]
fn gradle_settings_file_above_the_repository_is_refused_without_a_spawn() {
    let old = gradle_lock("32.1.2-jre");
    let mut outer = case(
        "gradle",
        "build.gradle",
        vec![
            ("../settings.gradle", "include 'project'\n"),
            ("build.gradle", BUILD_GRADLE),
            ("gradle.lockfile", &old),
        ],
        vec![("gradle", "exit 0")],
        "edit",
        GUAVA_EDIT,
    );
    outer.unlistened = true;

    let ran = run(&outer);

    assert!(
        ran.outcome.contains("LockfileOutsideRepository"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn gradle_settings_file_inside_the_repository_still_runs_under_open_pr() {
    let old = gradle_lock("32.1.2-jre");
    let body = gradle_writing(&["gradle.lockfile"]);
    let mut inner = case(
        "gradle",
        "build.gradle",
        vec![
            ("settings.gradle", "rootProject.name = 'x'\n"),
            ("build.gradle", BUILD_GRADLE),
            ("gradle.lockfile", &old),
        ],
        vec![("gradle", &body)],
        "edit",
        GUAVA_EDIT,
    );
    inner.unlistened = true;

    let ran = run(&inner);

    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn gradle_failure_restores_every_lock_of_the_set() {
    let old = gradle_lock("32.1.2-jre");
    let body =
        "echo garbage > ROOT/gradle.lockfile\necho garbage > ROOT/app/gradle.lockfile\nexit 1";
    let ran = run(&case(
        "gradle",
        "app/build.gradle",
        vec![
            ("settings.gradle", "include 'app'\n"),
            ("app/build.gradle", BUILD_GRADLE),
            ("app/gradle.lockfile", &old),
            ("gradle.lockfile", &old),
        ],
        vec![("gradle", body)],
        "edit",
        GUAVA_EDIT,
    ));

    assert!(ran.outcome.starts_with("Failed"), "{}", ran.outcome);
    assert_eq!(ran.read("gradle.lockfile"), old.clone().into_bytes());
    assert_eq!(ran.read("app/gradle.lockfile"), old.into_bytes());
}

#[test]
fn gradle_lock_only_pin_uses_the_same_update_locks_form() {
    let old = gradle_lock("32.1.2-jre");
    let body = gradle_writing(&["gradle.lockfile"]);
    let ran = run(&case(
        "gradle",
        "build.gradle",
        vec![("build.gradle", BUILD_GRADLE), ("gradle.lockfile", &old)],
        vec![("gradle", &body)],
        "lockonly",
        "com.google.guava:guava|com.google.guava:guava|32.1.2-jre|32.1.2-jre|32.1.2-jre|33.0.0-jre",
    ));

    assert_eq!(
        calls_starting(
            &ran,
            "gradle --no-daemon --console=plain :dependencies --update-locks com.google.guava:guava|"
        )
        .len(),
        1,
        "{:?}",
        ran.calls
    );
}

#[test]
fn gradle_legacy_lock_layout_is_refused_without_a_spawn() {
    let old = gradle_lock("32.1.2-jre");
    let ran = run(&case(
        "gradle",
        "build.gradle",
        vec![
            ("build.gradle", BUILD_GRADLE),
            ("gradle.lockfile", &old),
            ("gradle/dependency-locks/compileClasspath.lockfile", &old),
        ],
        vec![("gradle", "exit 0")],
        "edit",
        GUAVA_EDIT,
    ));

    assert!(ran.outcome.contains("LegacyLockLayout"), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn gradle_cooldown_fallback_target_is_refused_without_a_spawn() {
    let old = gradle_lock("32.1.2-jre");
    let mut case = case(
        "gradle",
        "build.gradle",
        vec![("build.gradle", BUILD_GRADLE), ("gradle.lockfile", &old)],
        vec![("gradle", "exit 0")],
        "edit",
        GUAVA_EDIT,
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
fn gradle_symlinked_lock_file_in_the_set_is_refused_without_a_spawn() {
    let old = gradle_lock("32.1.2-jre");
    let ran_case = case(
        "gradle",
        "build.gradle",
        vec![
            ("build.gradle", BUILD_GRADLE),
            ("gradle.lockfile", &old),
            ("real.txt", &old),
        ],
        vec![("gradle", "exit 0")],
        "edit",
        GUAVA_EDIT,
    );
    let project = harness::prepare(&ran_case);
    std::fs::create_dir_all(project.root.join("sub")).expect("dir");
    std::os::unix::fs::symlink(
        project.root.join("real.txt"),
        project.root.join("sub/gradle.lockfile"),
    )
    .expect("symlink");
    let output = project.child(&ran_case).output().expect("child");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        harness::outcome_of(&stdout).contains("LockfileSymlink"),
        "{stdout}"
    );
    assert!(project.calls().is_empty(), "{:?}", project.calls());
}

#[test]
fn gradle_without_a_lock_file_has_nothing_to_regenerate() {
    let ran = run(&case(
        "gradle",
        "build.gradle",
        vec![("build.gradle", BUILD_GRADLE)],
        vec![("gradle", "exit 0")],
        "edit",
        GUAVA_EDIT,
    ));

    assert!(ran.outcome.contains("NoLockfilePresent"), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- Swift ---

const PACKAGE_SWIFT: &str = "// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(\n    name: \"app\",\n    dependencies: [\n        .package(url: \"https://github.com/apple/swift-log.git\", from: \"1.5.0\"),\n    ],\n    targets: [.executableTarget(name: \"app\")]\n)\n";

fn package_resolved(version: &str) -> String {
    format!(
        "{{\n  \"pins\" : [\n    {{\n      \"identity\" : \"swift-log\",\n      \"kind\" : \"remoteSourceControl\",\n      \"location\" : \"https://github.com/apple/swift-log.git\",\n      \"state\" : {{\n        \"revision\" : \"abc\",\n        \"version\" : \"{version}\"\n      }}\n    }}\n  ],\n  \"version\" : 2\n}}\n"
    )
}

fn swift_writing() -> String {
    format!(
        "cat > ROOT/Package.resolved <<'EOF'\n{}EOF\n",
        package_resolved("1.6.0")
    )
}

const SWIFT_LOG_EDIT: &str = "apple/swift-log|swift-log.git|1.5.0|1.6.0|1.5.0|1.6.0";
const SWIFT_LOG_LOCK_ONLY: &str = "apple/swift-log|swift-log.git|1.5.0|1.5.0|1.5.0|1.6.0";

#[test]
fn swift_manifest_edit_runs_package_resolve_in_the_manifest_dir() {
    let old = package_resolved("1.5.0");
    let body = swift_writing();
    let ran = run(&case(
        "swift",
        "Package.swift",
        vec![("Package.swift", PACKAGE_SWIFT), ("Package.resolved", &old)],
        vec![("swift", &body)],
        "edit",
        SWIFT_LOG_EDIT,
    ));

    let resolves = calls_starting(&ran, "swift package resolve|");
    assert_eq!(resolves.len(), 1, "{:?}", ran.calls);
    assert_eq!(cwd_of(resolves[0]), ran.root.display().to_string());
    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn swift_lock_only_pin_runs_package_update_with_the_identity() {
    let old = package_resolved("1.5.0");
    let body = swift_writing();
    let ran = run(&case(
        "swift",
        "Package.swift",
        vec![("Package.swift", PACKAGE_SWIFT), ("Package.resolved", &old)],
        vec![("swift", &body)],
        "lockonly",
        SWIFT_LOG_LOCK_ONLY,
    ));

    assert_eq!(
        calls_starting(&ran, "swift package update swift-log|").len(),
        1,
        "{:?}",
        ran.calls
    );
    assert!(
        calls_starting(&ran, "swift package resolve|").is_empty(),
        "{:?}",
        ran.calls
    );
    assert!(regenerated(&ran), "{}", ran.outcome);
}

#[test]
fn swift_cooldown_fallback_target_is_refused_without_a_spawn() {
    let old = package_resolved("1.5.0");
    let mut case = case(
        "swift",
        "Package.swift",
        vec![("Package.swift", PACKAGE_SWIFT), ("Package.resolved", &old)],
        vec![("swift", "exit 0")],
        "edit",
        SWIFT_LOG_EDIT,
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
fn swift_lock_in_an_ancestor_directory_is_a_workspace_member_refusal() {
    let old = package_resolved("1.5.0");
    let ran = run(&case(
        "swift",
        "sub/Package.swift",
        vec![
            ("sub/Package.swift", PACKAGE_SWIFT),
            ("Package.resolved", &old),
        ],
        vec![("swift", "exit 0")],
        "edit",
        SWIFT_LOG_EDIT,
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

#[test]
fn swift_failed_resolve_puts_the_lock_file_back() {
    let old = package_resolved("1.5.0");
    let ran = run(&case(
        "swift",
        "Package.swift",
        vec![("Package.swift", PACKAGE_SWIFT), ("Package.resolved", &old)],
        vec![("swift", "echo garbage > ROOT/Package.resolved\nexit 1")],
        "edit",
        SWIFT_LOG_EDIT,
    ));

    assert!(ran.outcome.starts_with("Failed"), "{}", ran.outcome);
    assert_eq!(ran.read("Package.resolved"), old.into_bytes());
}
