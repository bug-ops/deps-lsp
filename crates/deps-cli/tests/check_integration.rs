//! Integration tests for the `check` pipeline: `walk` → `report::check_manifest` →
//! `format`/`exit`, run against real fixture manifests and real ecosystem registrations
//! (via `deps_engine::setup::register_ecosystems`) — never a fake `Ecosystem`, since none of
//! the ecosystem crates expose a public way to inject a mock registry from outside their own
//! crate (their `with_base_for_test`-style constructors are `#[cfg(test)] pub(crate)`).
//!
//! Every scenario here runs `--offline` (FR-013): [`deps_core::HttpCache::set_offline`]
//! intercepts before any real HTTP call reaches the network, so these tests are fast and
//! deterministic without needing a mock registry server. This also doubles as the SC-004
//! network-isolation test — see `test_offline_run_completes_without_network_access`, and its
//! doc comment for exactly what is (and is not) proved without a request-counting test
//! double (spec 062 review S6).
//!
//! // TODO(critic): FR-005 automated parity test vs deps-lsp handlers::diagnostics (T025)
//!
//! A live cross-tool parity check against `deps-lsp`'s own diagnostics path (FR-005/SC-001)
//! is deferred to manual verification (`.claude/rules/continuous-improvement.md`) and a
//! follow-up automated test that drives a real `deps-lsp` `ServerState` — see this PR's
//! handoff notes for why: `deps-lsp`'s `generate_diagnostics_internal` is `pub(crate)` and
//! `handle_diagnostics` needs a live `tower_lsp_server::Client`, both nontrivial to construct
//! from an external crate's test suite. **Structural non-drift is not, in fact, guaranteed
//! "today" without qualification** (correction, spec 062 review C2): both adapters call the
//! same `deps_engine::classify::*` functions and the identical `Ecosystem::generate_diagnostics`,
//! but C2 proved the *inputs* fed into that shared call can still diverge per adapter (this
//! crate was dropping `fetch_result.licenses` entirely before that fix landed) — sharing the
//! classification function does not, by itself, prove every adapter assembles its inputs
//! identically. The live parity test above is what would actually close that gap; until it
//! exists, non-drift rests on manual review of each `VersionData` assembly site matching.

// `allow-expect-in-tests` only recognizes `#[test]` bodies, not the plain helper functions
// (`offline_context`/`run_pipeline`) every test here calls.
#![allow(clippy::expect_used)]

use deps_cli::exit::{EXIT_CLEAN, exit_code};
use deps_cli::report::{CheckContext, CheckReport, FailOnPolicy, check_manifest};
use deps_cli::{format, walk};
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use std::sync::Arc;
use std::time::Duration;

/// Builds a real, fully-registered [`EcosystemRegistry`] plus an offline [`CheckContext`] —
/// the same construction `main.rs` performs, minus config-file loading.
fn offline_context() -> (EcosystemRegistry, CheckContext) {
    let policy = PolicyConfig::default();
    let runtime = EcosystemRuntime::from_policy(&policy);
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    cache.set_offline(true);
    assert!(
        cache.is_offline(),
        "test setup bug: HttpCache must actually be offline before this helper is trusted"
    );
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);

    let mut policy = policy;
    policy.network.offline = true;

    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy,
    };
    (registry, ctx)
}

/// Runs the full `walk` → `check_manifest` pipeline against `dir` and returns the assembled
/// report plus whether any manifest's registry fetch was reported unreachable.
async fn run_pipeline(dir: &std::path::Path) -> (CheckReport, bool) {
    let (registry, ctx) = offline_context();
    let outcome = walk::walk(&[dir.to_path_buf()], &registry, false);
    assert!(!outcome.truncated);

    let mut findings = Vec::new();
    let mut had_execution_error = false;
    for manifest in outcome.manifests {
        let content = deps_core::fs_probe::read_to_string_capped(&manifest.path, 10_000_000)
            .expect("read fixture manifest")
            .expect("fixture manifest under size cap");
        let result = check_manifest(
            &manifest.ecosystem,
            &manifest.path,
            &manifest.display_path,
            &content,
            &ctx,
        )
        .await
        .expect("check_manifest must not fail for a well-formed fixture");
        had_execution_error |= result.registry_unreachable;
        findings.extend(result.findings);
    }
    (CheckReport { findings }, had_execution_error)
}

/// SC-004's network-isolation guarantee, composed from two facts rather than one black-box
/// timing heuristic (spec 062 review S6):
///
/// 1. `offline_context`'s own assertion proves *this crate's* wiring actually calls
///    `HttpCache::set_offline(true)` — the exact class of bug this PR's own history hit once
///    (the original implementation gated only the OSV scan and forgot the registry fetch
///    path entirely).
/// 2. `HttpCache::ensure_online` — the shared gate every one of `deps-core`'s 4 send sites
///    checks before opening a socket — is deps-core's own, separately audited invariant (spec
///    062 security review F1's audit verified this empirically with a canary token), not
///    something this crate's test suite re-proves from scratch.
///
/// Together these give a real, non-heuristic proof, but neither one is a request counter: no
/// `Registry` implementation is injectable from outside its own ecosystem crate (see this
/// file's module doc), so there is no way to assert "zero calls reached a `Registry` method"
/// from here — only "zero calls reached the network", which is the property SC-004 actually
/// cares about. The bounded timeout below is a belt-and-suspenders regression signal on top of
/// those two proofs, not the proof itself: a real (accidental) network attempt against an
/// unreachable/slow host would hang well past it.
#[tokio::test]
async fn test_offline_run_completes_without_network_access() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let (report, _had_error) =
        tokio::time::timeout(Duration::from_secs(10), run_pipeline(dir.path()))
            .await
            .expect("offline run must not block on network I/O");

    // `serde` has no lock-file-resolved version and offline mode never fetches, so it
    // surfaces as an unresolved-lookup finding rather than a crash or a silently empty report.
    assert!(
        !report.findings.is_empty(),
        "offline mode must still report on what it can determine"
    );
}

#[tokio::test]
async fn test_empty_directory_produces_no_findings_and_clean_exit() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let (report, had_error) = run_pipeline(dir.path()).await;
    assert!(report.findings.is_empty());
    assert!(!had_error);
    assert_eq!(
        exit_code(&report, &FailOnPolicy::default_categories(), had_error),
        EXIT_CLEAN
    );
}

#[tokio::test]
async fn test_multi_ecosystem_fixture_tree_discovers_both_manifests() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write cargo manifest");
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"fixture","dependencies":{"left-pad":"1.0.0"}}"#,
    )
    .expect("write npm manifest");

    let (report, _had_error) = run_pipeline(dir.path()).await;
    let ecosystems: std::collections::HashSet<_> =
        report.findings.iter().map(|f| f.ecosystem).collect();
    assert!(ecosystems.contains(&deps_core::EcosystemId::Cargo));
    assert!(ecosystems.contains(&deps_core::EcosystemId::Npm));
}

#[tokio::test]
async fn test_table_and_json_formatters_render_the_same_pipeline_output() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let (report, _had_error) = run_pipeline(dir.path()).await;

    let table = format::table::render(&report);
    assert!(table.contains("Cargo.toml"));

    let json = format::json::render(&report).expect("json render must succeed");
    let document: format::json::ReportDocument =
        serde_json::from_str(&json).expect("json must round-trip");
    assert_eq!(document.schema_version, format::json::SCHEMA_VERSION);
    assert_eq!(document.findings.len(), report.findings.len());
}

#[tokio::test]
async fn test_sarif_formatter_renders_the_same_pipeline_output() {
    // Directory name needs percent-encoding (`#` reads as a URI fragment separator, space is
    // invalid in a bare URI-reference) — the repro this test guards against (spec 062 review S2/B3).
    let dir = tempfile::tempdir().expect("create temp dir");
    let manifest_dir = dir.path().join("weird dir#name");
    std::fs::create_dir(&manifest_dir).expect("create nested fixture dir");
    std::fs::write(
        manifest_dir.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let (report, _had_error) = run_pipeline(dir.path()).await;
    assert!(
        !report.findings.is_empty(),
        "serde 1.0 must produce at least one finding"
    );

    let sarif = format::sarif::to_sarif(&report);
    let results = sarif.runs[0]
        .results
        .as_ref()
        .expect("results must be present");
    assert_eq!(results.len(), report.findings.len());

    for result in results {
        let uri = result
            .locations
            .as_ref()
            .expect("locations must be present")[0]
            .physical_location
            .as_ref()
            .expect("physicalLocation must be present")
            .artifact_location
            .as_ref()
            .expect("artifactLocation must be present")
            .uri
            .as_ref()
            .expect("uri must be present");
        assert!(
            !uri.contains('#'),
            "a literal '#' in {uri:?} would be read as a URI fragment separator"
        );
        assert!(
            !uri.contains(' '),
            "a literal space in {uri:?} is not a valid URI-reference"
        );
        assert!(
            !uri.contains('\\'),
            "{uri:?} must use '/' separators, not the platform's own (possibly '\\\\') display form"
        );
        assert!(
            !std::path::Path::new(uri).is_absolute(),
            "{uri:?} must stay relative to the walked root, matching table/json's own display_path"
        );
    }

    let json = format::sarif::render(&report).expect("sarif render must succeed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("sarif must round-trip");
    assert_eq!(parsed["version"], "2.1.0");
}

#[tokio::test]
async fn test_walk_paths_default_to_current_directory_semantics_via_single_file() {
    // Exercises the "explicit manifest path, not a directory" branch of `walk::walk` end to
    // end (FR-002's routing applies identically either way).
    let dir = tempfile::tempdir().expect("create temp dir");
    let manifest = dir.path().join("Cargo.toml");
    std::fs::write(&manifest, "[package]\nname = \"fixture\"\n").expect("write fixture manifest");

    let (registry, ctx) = offline_context();
    let outcome = walk::walk(std::slice::from_ref(&manifest), &registry, false);
    assert_eq!(outcome.manifests.len(), 1);

    let content = deps_core::fs_probe::read_to_string_capped(&manifest, 10_000_000)
        .expect("read manifest")
        .expect("under size cap");
    let result = check_manifest(
        &outcome.manifests[0].ecosystem,
        &manifest,
        &manifest,
        &content,
        &ctx,
    )
    .await
    .expect("check_manifest must succeed");
    // `Cargo.toml` with no `[dependencies]` produces no findings at all.
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn test_sarif_formatter_relativizes_an_absolute_single_file_path() {
    // An explicit file path routes through `walk::walk`'s `root.is_file()` branch, which passes
    // the absolute path through as `display_path` unchanged (spec 062 review R1: `manifest_uri`
    // must not leak it into `artifactLocation.uri` as-is).
    let dir = tempfile::tempdir().expect("create temp dir");
    let manifest = dir.path().join("Cargo.toml");
    assert!(
        manifest.is_absolute(),
        "test setup bug: fixture path must be absolute"
    );
    std::fs::write(
        &manifest,
        "[package]\nname = \"fixture\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let (registry, ctx) = offline_context();
    let outcome = walk::walk(std::slice::from_ref(&manifest), &registry, false);
    assert_eq!(outcome.manifests.len(), 1);
    assert!(
        outcome.manifests[0].display_path.is_absolute(),
        "test setup bug: this must exercise the absolute-display_path branch"
    );

    let content = deps_core::fs_probe::read_to_string_capped(&manifest, 10_000_000)
        .expect("read manifest")
        .expect("under size cap");
    let result = check_manifest(
        &outcome.manifests[0].ecosystem,
        &manifest,
        &manifest,
        &content,
        &ctx,
    )
    .await
    .expect("check_manifest must succeed");
    assert!(
        !result.findings.is_empty(),
        "serde 1.0 must produce at least one finding"
    );

    let report = CheckReport {
        findings: result.findings,
    };
    let sarif = format::sarif::to_sarif(&report);
    let results = sarif.runs[0]
        .results
        .as_ref()
        .expect("results must be present");
    for result in results {
        let uri = result
            .locations
            .as_ref()
            .expect("locations must be present")[0]
            .physical_location
            .as_ref()
            .expect("physicalLocation must be present")
            .artifact_location
            .as_ref()
            .expect("artifactLocation must be present")
            .uri
            .as_ref()
            .expect("uri must be present");
        assert!(
            !std::path::Path::new(uri).is_absolute(),
            "{uri:?} must not stay absolute — it leaks local machine path structure into a \
             document meant to be uploaded to GitHub code scanning"
        );
    }
}

/// Reviewer follow-up #5: exercises the *real* wiring in `main.rs` (warnings →
/// `had_execution_error` → `exit_code`) via the actual built binary, not `run_pipeline`'s
/// simplified reimplementation above — `run_pipeline` hardcodes `walk::walk(..., false)` and
/// never touches `main.rs::run_check`'s own warning/exit-code logic, so a regression there
/// could pass every other test in this file while silently reopening a fail-open gap.
#[test]
fn test_respect_gitignore_flag_reaches_the_real_exit_code_wiring() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::create_dir(dir.path().join(".git")).expect("create .git marker");
    std::fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("write fixture manifest");

    let exe = env!("CARGO_BIN_EXE_deps-cli");
    let output = std::process::Command::new(exe)
        .args(["check", "--offline", "--respect-gitignore"])
        .arg(dir.path())
        .output()
        .expect("run the real deps-cli binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a manifest excluded by --respect-gitignore must exit 2 (execution error), not 0 — \
         stderr: {stderr}"
    );
    assert!(
        stderr.contains("excluded from the scan"),
        "must warn about the excluded manifest, stderr: {stderr}"
    );
}

/// Companion to the above: the same fixture under the default (`respect_gitignore: false`)
/// mode must find the manifest and exit clean through the real binary too.
#[test]
fn test_default_mode_ignores_gitignore_through_the_real_binary_and_exits_clean() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::create_dir(dir.path().join(".git")).expect("create .git marker");
    std::fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("write fixture manifest");

    let exe = env!("CARGO_BIN_EXE_deps-cli");
    let output = std::process::Command::new(exe)
        .args(["check", "--offline"])
        .arg(dir.path())
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
