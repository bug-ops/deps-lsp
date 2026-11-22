//! #2100 (partial: plan split) acceptance: a NuGet plan that mixes manifest-edit pins and
//! lock-file-only pins regenerates for the edit pins instead of being refused as a whole. The
//! lock-only pins stay untouched (`requires-lockfile-update`), and a lock-only pin with a floating
//! requirement still refuses the whole run (plan rev 2, Track C, M6). A plan of lock-only pins
//! alone stays refused (covered by `update_lockers_nge_acceptance.rs`).
//!
//! The shared harness runs one mode per case, so this file carries its own child entry point:
//! each `REGEN_BUMPS` line is `name|anchor|from|to|current|target|edit` or `...|lock`. The fake
//! `dotnet` records its calls (see `common/regen_harness.rs`).

#![cfg(all(unix, feature = "nuget"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use std::path::PathBuf;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    mixed_child_main().await;
}

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n    <PackageReference Include=\"Serilog\" Version=\"2.10.0\" />\n  </ItemGroup>\n</Project>\n";

fn lock(newtonsoft: &str, serilog: &str) -> String {
    let entry = |name: &str, version: &str| {
        format!(
            "      \"{name}\": {{\n        \"type\": \"Direct\",\n        \"requested\": \"[{version}, )\",\n        \"resolved\": \"{version}\",\n        \"contentHash\": \"abc\"\n      }}"
        )
    };
    format!(
        "{{\n  \"version\": 1,\n  \"dependencies\": {{\n    \"net8.0\": {{\n{},\n{}\n    }}\n  }}\n}}\n",
        entry("Newtonsoft.Json", newtonsoft),
        entry("Serilog", serilog)
    )
}

const NEWTONSOFT_EDIT: &str = "Newtonsoft.Json|Newtonsoft.Json|13.0.1|13.0.3|13.0.1|13.0.3|edit";
const SERILOG_LOCK_ONLY: &str = "Serilog|Serilog|2.10.0|2.10.0|2.10.0|2.12.0|lock";

fn mixed_case<'a>(csproj: &'a str, old_lock: &'a str, body: &'a str, bumps: &'a str) -> Case<'a> {
    Case {
        ecosystem: "nuget",
        manifest: "App.csproj",
        files: vec![
            ("App.csproj", csproj.as_bytes().to_vec()),
            ("packages.lock.json", old_lock.as_bytes().to_vec()),
        ],
        tools: vec![("dotnet", body)],
        mode: "mixed",
        bumps,
        cooldown_fallback: false,
        unlistened: false,
    }
}

const PINS_LINE: &str = "reported pins: ";

/// The packages of the regenerated lock file's pin reports, as the child listed them.
fn reported_pins(outcome: &str) -> Vec<&str> {
    outcome
        .lines()
        .find_map(|line| line.strip_prefix(PINS_LINE))
        .map(|names| names.split(',').filter(|name| !name.is_empty()).collect())
        .expect("the child lists the reported pins")
}

fn restore_calls(ran: &Ran) -> Vec<&String> {
    ran.calls_of("dotnet")
        .into_iter()
        .filter(|call| call.starts_with("dotnet restore "))
        .collect()
}

#[test]
fn nuget_mixed_plan_regenerates_for_the_edit_pins_and_leaves_the_lock_only_pin_untouched() {
    let old = lock("13.0.1", "2.10.0");
    let body = format!(
        "cat > ROOT/packages.lock.json <<'EOF'\n{}EOF\n",
        lock("13.0.3", "2.10.0")
    );
    let bumps = format!("{NEWTONSOFT_EDIT}\n{SERILOG_LOCK_ONLY}");

    let ran = run(&mixed_case(CSPROJ, &old, &body, &bumps));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(
        !ran.outcome.contains("LockfileOnlyUpdateUnsupported"),
        "{}",
        ran.outcome
    );
    assert_eq!(restore_calls(&ran).len(), 1, "{:?}", ran.calls);
    assert!(
        ran.calls
            .iter()
            .all(|call| !call.contains("--force-evaluate")),
        "{:?}",
        ran.calls
    );
    assert!(ran.outcome.contains("Newtonsoft.Json"), "{}", ran.outcome);
    assert_eq!(
        reported_pins(&ran.outcome),
        ["Newtonsoft.Json"],
        "the lock-only pin is not reported as applied: {}",
        ran.outcome
    );
    let final_lock = String::from_utf8(ran.read("packages.lock.json")).expect("utf-8");
    assert!(
        final_lock.contains("\"resolved\": \"13.0.3\""),
        "{final_lock}"
    );
}

#[test]
fn nuget_mixed_plan_with_a_floating_lock_only_pin_regenerates() {
    let csproj = CSPROJ.replace("Version=\"2.10.0\"", "Version=\"2.*\"");
    let old = lock("13.0.1", "2.10.0").replace("[2.10.0, )", "[2.*, )");
    let resolved = lock("13.0.3", "2.12.0").replace("[2.12.0, )", "[2.12.0, 2.12.0]");
    let body = format!(
        "case \"$*\" in\n*--locked-mode*)\ngrep -q 'Version=\"2\\.\\*\"' ROOT/App.csproj || exit 8\n;;\n*)\ngrep -q 'Version=\"\\[2\\.12\\.0\\]\"' ROOT/App.csproj || exit 7\ncat > ROOT/packages.lock.json <<'EOF'\n{resolved}EOF\n;;\nesac\n"
    );
    let bumps = format!("{NEWTONSOFT_EDIT}\n{SERILOG_LOCK_ONLY}");

    let ran = run(&mixed_case(&csproj, &old, &body, &bumps));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    let calls = restore_calls(&ran);
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(!calls[0].contains("--locked-mode"), "{}", calls[0]);
    assert!(calls[1].contains("--locked-mode"), "{}", calls[1]);
    assert_eq!(
        reported_pins(&ran.outcome),
        ["Newtonsoft.Json", "Serilog"],
        "{}",
        ran.outcome
    );
    assert_eq!(
        String::from_utf8(ran.read("App.csproj")).expect("utf-8"),
        csproj.replace("13.0.1", "13.0.3"),
        "only the planned edit remains in the manifest"
    );
    let final_lock = String::from_utf8(ran.read("packages.lock.json")).expect("utf-8");
    assert_eq!(final_lock, resolved.replace("[2.12.0, 2.12.0]", "[2.*, )"));
}

async fn mixed_child_main() {
    use std::str::FromStr;
    use std::sync::Arc;

    use deps_cli::format::DryRun;
    use deps_cli::update::regen::{
        LockfileMode, ManifestTarget, RegenerationGate, regenerate_lockfile,
    };
    use deps_cli::update::{CurrentVersion, Outcome, PlannedUpdateItem, UpdatePlan, apply_plan};
    use deps_core::edit::ManifestEdit;
    use deps_core::net_policy::{MapEnv, RegistryEnvironment};
    use deps_core::policy_config::PolicyConfig;
    use deps_core::position::{Position, Range};
    use deps_core::{ConcreteVersion, EcosystemId, EcosystemRegistry, HttpCache, NetworkMode};
    use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

    let root = PathBuf::from(harness::env("REGEN_DIR"));
    let manifest = root.join(harness::env("REGEN_MANIFEST"));
    let id = EcosystemId::from_str(&harness::env("REGEN_ECO")).expect("ecosystem id");
    let content = std::fs::read_to_string(&manifest).expect("manifest");

    let items = harness::env("REGEN_BUMPS")
        .lines()
        .map(|line| {
            let mut fields = line.split('|');
            let mut next = || fields.next().expect("bump field");
            let (name, anchor, from, to, current, target, kind) =
                (next(), next(), next(), next(), next(), next(), next());
            let outcome = if kind == "lock" {
                Outcome::RequiresLockfileUpdate {
                    target: ConcreteVersion::from(target),
                    ecosystem: id,
                }
            } else {
                let (line_no, text) = content
                    .lines()
                    .enumerate()
                    .find(|(_, text)| text.contains(anchor))
                    .expect("anchor line");
                let anchor_at = text.find(anchor).expect("anchor");
                let start = text
                    .match_indices(from)
                    .map(|(index, _)| index)
                    .find(|index| *index >= anchor_at)
                    .expect("from text");
                let line_no = u32::try_from(line_no).expect("line");
                let start = u32::try_from(start).expect("col");
                let end = start + u32::try_from(from.len()).expect("len");
                Outcome::Applied {
                    edit: ManifestEdit {
                        range: Range::new(
                            Position::new(line_no, start),
                            Position::new(line_no, end),
                        ),
                        new_text: to.to_owned(),
                    },
                    target: ConcreteVersion::from(target),
                }
            };
            PlannedUpdateItem::new(
                name.to_owned(),
                CurrentVersion::Resolved(ConcreteVersion::from(current)),
                outcome,
                vec![],
                false,
                None,
                None,
            )
        })
        .collect();
    let plan = UpdatePlan { items };
    apply_plan(&plan, &manifest, &content, DryRun::No).expect("apply the plan");

    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, cache, &runtime);
    let ecosystem = registry.get(id).expect("ecosystem registered");
    let uri = url::Url::from_file_path(&manifest).expect("uri");
    let display = PathBuf::from(harness::env("REGEN_MANIFEST"));
    let original_text = std::fs::read_to_string(&manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display,
        uri: &uri,
        original: deps_cli::update::regen::OriginalManifest::new(&original_text),
    };
    let gate = RegenerationGate::new(LockfileMode::Regenerate, DryRun::No, NetworkMode::Online);
    let run = regenerate_lockfile(plan, &target, gate).await;
    use deps_cli::update::regen::LockfileOutcome;
    let reported = match &run.lockfile {
        LockfileOutcome::Regenerated { pins, .. } => pins
            .iter()
            .map(|pin| pin.package.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(","),
        LockfileOutcome::Skipped(_)
        | LockfileOutcome::NotApplicable(_)
        | LockfileOutcome::Unsupported { .. }
        | LockfileOutcome::Failed(_) => String::new(),
    };
    println!(
        "{}{:?}\n{PINS_LINE}{reported}{}",
        harness::OUTCOME_OPEN,
        run.lockfile,
        harness::OUTCOME_CLOSE
    );
}
