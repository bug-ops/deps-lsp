//! #2113 acceptance: NuGet lock-file-only pins regenerate through an exact pin written to the
//! manifest, a `--force` restore, the declared requirement restored in the lock file, and a
//! `--locked-mode --force` settle restore; the float guard reads the original lock file as well
//! as the manifest.
//!
//! Written tests-first against the final plan (`Relax::RestoreRequested`, `RestoreMode`,
//! `RegenerationError::LockfilePinNotKept`, `RekeyRefusal::OriginalRequestMissing`). Fake `dotnet`
//! shell scripts run through a re-executed test binary (see `common/regen_harness.rs`); the fakes
//! check the manifest bytes they are called with, so an exact pin that is not written (or not
//! written back) fails the run. Real `dotnet` behaviour is covered by the live-tester contract.

#![cfg(all(unix, feature = "nuget"))]
#[path = "common/regen_harness.rs"]
mod harness;

use deps_cli::update::{CurrentVersion, Outcome, PlannedUpdateItem};
use deps_core::{ConcreteVersion, EcosystemId};
use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const RESOLVE_ARGV: &str = "dotnet restore App.csproj --use-lock-file --no-dependencies --disable-build-servers --force -p:RestoreLockedMode=false|";
const LOCKED_ARGV: &str = "dotnet restore App.csproj --use-lock-file --no-dependencies --disable-build-servers --force --locked-mode|";
const SERILOG_LOCK_ONLY: &str = "Serilog|Serilog|2.10.0|2.10.0|2.10.0|2.12.0";

fn csproj(version: &str) -> String {
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Serilog\" Version=\"{version}\" />\n  </ItemGroup>\n</Project>\n"
    )
}

fn direct(name: &str, requested: &str, resolved: &str) -> String {
    format!(
        "      \"{name}\": {{\n        \"type\": \"Direct\",\n        \"requested\": \"{requested}\",\n        \"resolved\": \"{resolved}\",\n        \"contentHash\": \"abc\"\n      }}"
    )
}

fn central(name: &str, requested: &str, resolved: &str) -> String {
    direct(name, requested, resolved).replace("\"Direct\"", "\"CentralTransitive\"")
}

fn project_entry(name: &str, dependency: &str, range: &str) -> String {
    format!(
        "      \"{name}\": {{\n        \"type\": \"Project\",\n        \"dependencies\": {{\n          \"{dependency}\": \"{range}\"\n        }}\n      }}"
    )
}

fn lock_in(frameworks: &[(&str, &[String])]) -> String {
    let sections: Vec<String> = frameworks
        .iter()
        .map(|(tfm, entries)| format!("    \"{tfm}\": {{\n{}\n    }}", entries.join(",\n")))
        .collect();
    format!(
        "{{\n  \"version\": 1,\n  \"dependencies\": {{\n{}\n  }}\n}}\n",
        sections.join(",\n")
    )
}

fn lock(entries: &[String]) -> String {
    lock_in(&[("net8.0", entries)])
}

const FLOATING_REQUESTED: &str = "[2.*, )";
const PINNED_REQUESTED: &str = "[2.12.0, 2.12.0]";

fn floating_old_lock() -> String {
    lock(&[direct("Serilog", FLOATING_REQUESTED, "2.10.0")])
}

fn floating_pinned_lock() -> String {
    lock(&[direct("Serilog", PINNED_REQUESTED, "2.12.0")])
}

fn write_lock(text: &str) -> String {
    format!("cat > ROOT/packages.lock.json <<'EOF'\n{text}EOF\n")
}

/// Resolve restore (no `--locked-mode`) requires the exact pin in the manifest and writes
/// `resolved_lock`; the locked-mode settle requires the declared requirement back and runs `settle`.
fn floating_body(resolved_lock: &str, settle: &str) -> String {
    format!(
        "case \"$*\" in\n*--locked-mode*)\ngrep -q 'Version=\"2\\.\\*\"' ROOT/App.csproj || exit 8\n{settle}\n;;\n*)\ngrep -q 'Version=\"\\[2\\.12\\.0\\]\"' ROOT/App.csproj || exit 7\n{}\n;;\nesac\n",
        write_lock(resolved_lock)
    )
}

fn case<'a>(manifest: &'a str, lock: &'a str, body: &'a str, fallback: bool) -> Case<'a> {
    Case {
        ecosystem: "nuget",
        manifest: "App.csproj",
        files: vec![
            ("App.csproj", manifest.as_bytes().to_vec()),
            ("packages.lock.json", lock.as_bytes().to_vec()),
        ],
        tools: vec![("dotnet", body)],
        mode: "lockonly",
        bumps: SERILOG_LOCK_ONLY,
        cooldown_fallback: fallback,
        unlistened: false,
    }
}

fn restores(ran: &Ran) -> Vec<&String> {
    ran.calls_of("dotnet")
        .into_iter()
        .filter(|call| call.starts_with("dotnet restore "))
        .collect()
}

fn regenerated(ran: &Ran) -> bool {
    ran.outcome.starts_with("Regenerated")
}

fn assert_refused_without_a_spawn(ran: &Ran, needle: &str) {
    assert!(ran.outcome.contains(needle), "{}", ran.outcome);
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

// --- regeneration of floating lock-only pins ---

#[test]
fn nuget_floating_lock_only_pin_runs_resolve_then_locked_and_keeps_the_declared_requirement() {
    let manifest = csproj("2.*");
    let old = floating_old_lock();
    let body = floating_body(&floating_pinned_lock(), "exit 0");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(regenerated(&ran), "{}", ran.outcome);
    let calls = restores(&ran);
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(calls[0].starts_with(RESOLVE_ARGV), "{}", calls[0]);
    assert!(calls[1].starts_with(LOCKED_ARGV), "{}", calls[1]);
    assert!(
        ran.calls
            .iter()
            .all(|call| !call.contains("--force-evaluate")),
        "{:?}",
        ran.calls
    );
    assert_eq!(ran.read("App.csproj"), manifest.into_bytes());
    assert_eq!(
        ran.read("packages.lock.json"),
        floating_pinned_lock()
            .replace(PINNED_REQUESTED, FLOATING_REQUESTED)
            .into_bytes()
    );
}

#[test]
fn nuget_cooldown_fallback_floating_lock_only_pin_regenerates() {
    let manifest = csproj("2.*");
    let old = floating_old_lock();
    let body = floating_body(&floating_pinned_lock(), "exit 0");

    let ran = run(&case(&manifest, &old, &body, true));

    assert!(regenerated(&ran), "{}", ran.outcome);
    assert!(
        !ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert_eq!(restores(&ran).len(), 2, "{:?}", ran.calls);
    assert_eq!(ran.read("App.csproj"), manifest.into_bytes());
}

#[test]
fn nuget_fixed_lock_only_pin_runs_one_resolve_restore() {
    let manifest = csproj("2.12.0");
    let old = lock(&[direct("Serilog", "[2.10.0, )", "2.10.0")]);
    let new = lock(&[direct("Serilog", "[2.12.0, )", "2.12.0")]);
    let body = write_lock(&new);

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(regenerated(&ran), "{}", ran.outcome);
    let calls = restores(&ran);
    assert_eq!(calls.len(), 1, "{:?}", ran.calls);
    assert!(calls[0].starts_with(RESOLVE_ARGV), "{}", calls[0]);
    assert_eq!(ran.read("packages.lock.json"), new.into_bytes());
}

#[test]
fn nuget_cooldown_fallback_fixed_lock_only_pin_is_refused_without_a_spawn() {
    let manifest = csproj("2.12.0");
    let old = lock(&[direct("Serilog", "[2.10.0, )", "2.10.0")]);

    let ran = run(&case(&manifest, &old, "exit 0", true));

    assert_refused_without_a_spawn(&ran, "CooldownFallbackTarget");
}

// --- float guard over the original lock file ---

#[test]
fn nuget_direct_float_in_the_lock_but_not_the_manifest_is_refused_without_a_spawn() {
    let manifest = csproj("2.*");
    let old = lock(&[
        direct("Serilog", FLOATING_REQUESTED, "2.10.0"),
        direct("Other.Package", "[1.*, )", "1.4.0"),
    ]);

    let ran = run(&case(&manifest, &old, "exit 0", false));

    assert_refused_without_a_spawn(&ran, "OtherFloatingRequirements");
}

#[test]
fn nuget_central_transitive_float_in_the_lock_is_refused_without_a_spawn() {
    let manifest = csproj("2.*");
    let old = lock(&[
        direct("Serilog", FLOATING_REQUESTED, "2.10.0"),
        central("Transitive.Pin", "[1.0.0, 2.0.0)", "1.2.0"),
    ]);

    let ran = run(&case(&manifest, &old, "exit 0", false));

    assert_refused_without_a_spawn(&ran, "OtherFloatingRequirements");
}

#[test]
fn nuget_project_reference_dependency_range_with_an_upper_bound_is_refused_without_a_spawn() {
    let manifest = csproj("2.*");
    let old = lock(&[
        direct("Serilog", FLOATING_REQUESTED, "2.10.0"),
        project_entry("Lib", "Other.Package", "[1.0.0, 2.0.0)"),
    ]);

    let ran = run(&case(&manifest, &old, "exit 0", false));

    assert_refused_without_a_spawn(&ran, "OtherFloatingRequirements");
}

#[test]
fn nuget_float_in_a_second_framework_section_is_refused_without_a_spawn() {
    let manifest = csproj("2.*");
    let net8 = [direct("Serilog", FLOATING_REQUESTED, "2.10.0")];
    let net6 = [
        direct("Serilog", FLOATING_REQUESTED, "2.10.0"),
        direct("Other.Package", "[1.*, )", "1.4.0"),
    ];
    let old = lock_in(&[("net6.0", &net6), ("net8.0", &net8)]);

    let ran = run(&case(&manifest, &old, "exit 0", false));

    assert_refused_without_a_spawn(&ran, "OtherFloatingRequirements");
}

#[test]
fn nuget_exact_bracket_pair_requirement_in_the_lock_does_not_count_as_floating() {
    let manifest = csproj("2.*");
    let old = lock(&[
        direct("Serilog", FLOATING_REQUESTED, "2.10.0"),
        direct("Other.Package", "[1.4.0, 1.4.0]", "1.4.0"),
    ]);
    let pinned = lock(&[
        direct("Serilog", PINNED_REQUESTED, "2.12.0"),
        direct("Other.Package", "[1.4.0, 1.4.0]", "1.4.0"),
    ]);
    let body = floating_body(&pinned, "exit 0");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(regenerated(&ran), "{}", ran.outcome);
    assert_eq!(restores(&ran).len(), 2, "{:?}", ran.calls);
}

#[test]
fn nuget_unparsable_lock_is_unrecognized_before_any_spawn() {
    let manifest = csproj("2.*");

    let ran = run(&case(&manifest, "this is not json", "exit 0", false));

    assert_refused_without_a_spawn(&ran, "UnrecognizedLockfile");
}

// --- failure handling and refusal variants ---

#[test]
fn nuget_locked_mode_settle_failure_restores_the_manifest_and_the_lock() {
    let manifest = csproj("2.*");
    let old = floating_old_lock();
    let body = floating_body(&floating_pinned_lock(), "exit 1");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(
        ran.outcome.starts_with("Failed(ToolFailed"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("App.csproj"), manifest.into_bytes());
    assert_eq!(ran.read("packages.lock.json"), old.into_bytes());
}

#[test]
fn nuget_lock_without_the_pinned_version_is_pin_not_kept_and_restored() {
    let manifest = csproj("2.*");
    let old = floating_old_lock();
    let drifted = lock(&[direct("Serilog", PINNED_REQUESTED, "2.11.0")]);
    let body = floating_body(&drifted, "exit 0");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(
        ran.outcome.contains("LockfilePinNotKept") && ran.outcome.contains("PinnedEntryMissing"),
        "{}",
        ran.outcome
    );
    let json = ran.lockfile_json.as_ref().expect("child printed the JSON");
    assert_eq!(json["kind"], "lockfile-pin-not-kept");
    assert_eq!(ran.read("App.csproj"), manifest.into_bytes());
    assert_eq!(ran.read("packages.lock.json"), old.into_bytes());
}

#[test]
fn nuget_framework_section_absent_from_the_original_lock_is_original_request_missing() {
    let manifest = csproj("2.*");
    let old = floating_old_lock();
    let entries = [direct("Serilog", PINNED_REQUESTED, "2.12.0")];
    let widened = lock_in(&[("net6.0", &entries), ("net8.0", &entries)]);
    let body = floating_body(&widened, "exit 0");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(
        ran.outcome.contains("LockfilePinNotKept")
            && ran.outcome.contains("OriginalRequestMissing"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("App.csproj"), manifest.into_bytes());
    assert_eq!(ran.read("packages.lock.json"), old.into_bytes());
}

// --- reason text ---

#[test]
fn nuget_requires_lockfile_update_reason_names_nuget_as_a_tool_that_can_move_the_lock() {
    let item = PlannedUpdateItem::new(
        "Serilog".to_owned(),
        CurrentVersion::Resolved(ConcreteVersion::from("2.10.0")),
        Outcome::RequiresLockfileUpdate {
            target: ConcreteVersion::from("2.12.0"),
            ecosystem: EcosystemId::NuGet,
        },
        vec![],
        false,
        None,
        None,
    );

    let reason = item.reason();

    assert!(
        reason.ends_with("--lockfile regenerate for NuGet)"),
        "{reason}"
    );
}

#[test]
fn nuget_floating_pin_is_rekeyed_in_every_framework_section_with_a_case_insensitive_id() {
    let manifest = csproj("2.*");
    let sections = |requested: &str, resolved: &str| {
        let entries = [direct("serilog", requested, resolved)];
        lock_in(&[("net6.0", &entries), ("net8.0", &entries)])
    };
    let old = sections(FLOATING_REQUESTED, "2.10.0");
    let pinned = sections(PINNED_REQUESTED, "2.12.0");
    let body = floating_body(&pinned, "exit 0");

    let ran = run(&case(&manifest, &old, &body, false));

    assert!(regenerated(&ran), "{}", ran.outcome);
    assert_eq!(
        ran.read("packages.lock.json"),
        sections(FLOATING_REQUESTED, "2.12.0").into_bytes()
    );
}
