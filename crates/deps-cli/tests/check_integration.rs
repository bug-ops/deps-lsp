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
use deps_core::policy_config::{LicensePolicyConfig, PolicyConfig};
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
    let outcome = walk::walk(
        &[dir.to_path_buf()],
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
    assert!(!outcome.truncated);

    let mut findings = Vec::new();
    let mut had_execution_error = false;
    for manifest in outcome.manifests {
        let content = deps_core::fs_probe::read_to_string_capped(&manifest.path, 10_000_000)
            .expect("read fixture manifest")
            .expect("fixture manifest under size cap");
        // Review finding M2: mirrors main.rs's fix — `uri_path` (not `path`) drives lockfile
        // lookup, so this harness exercises the same correct wiring `check` itself uses.
        let result = check_manifest(
            &manifest.ecosystem,
            &manifest.uri_path,
            &manifest.display_path,
            &content,
            &ctx,
        )
        .await
        .expect("check_manifest must not fail for a well-formed fixture");
        had_execution_error |= result.registry_unreachable || result.license_fetch_incomplete;
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
    let outcome = walk::walk(
        std::slice::from_ref(&manifest),
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
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
    let outcome = walk::walk(
        std::slice::from_ref(&manifest),
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
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

/// Issue #1124's own repro, exercised through the real binary (mirroring reviewer follow-up
/// #5's rationale above for `--respect-gitignore`): a manifest replaced by a broken symlink
/// must not be silently dropped from the scan, and the warning must distinguish this case
/// (possible tampering) from an ordinary excluded manifest.
#[cfg(unix)]
#[test]
fn test_broken_symlink_manifest_reaches_the_real_exit_code_wiring() {
    let dir = tempfile::tempdir().expect("create temp dir");
    // M1 (critic follow-up): a second *recognized* manifest, so `manifests.is_empty()` isn't
    // an independent, overlapping reason for a non-zero exit — the broken symlink must be the
    // only thing driving `had_execution_error` here. `--fail-on vulnerable` matches the
    // issue's own literal repro command.
    std::fs::write(
        dir.path().join("package.json"),
        "{\"name\": \"fixture\", \"version\": \"0.1.0\"}\n",
    )
    .expect("write a second, recognized manifest");
    std::os::unix::fs::symlink(
        dir.path().join("does-not-exist.toml"),
        dir.path().join("Cargo.toml"),
    )
    .expect("create broken symlink replacing Cargo.toml");

    let exe = env!("CARGO_BIN_EXE_deps-cli");
    let output = std::process::Command::new(exe)
        .args(["check", "--offline", "--fail-on", "vulnerable"])
        .arg(dir.path())
        .output()
        .expect("run the real deps-cli binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a manifest replaced by a broken symlink must exit 2 (execution error), not 0, even \
         though a second manifest was found and scanned cleanly — stderr: {stderr}"
    );
    assert!(
        stderr.contains("could not be resolved"),
        "must warn with the broken-symlink-specific message, not the generic excluded-manifest \
         one, stderr: {stderr}"
    );
    assert!(
        !stderr.contains("no manifests were discovered"),
        "the second manifest must have been found — this exit code must come from the broken \
         symlink alone, stderr: {stderr}"
    );
}

/// Companion to the above: the same fixture under `--follow-symlinks` must still report the
/// broken symlink (resolving it is impossible by definition), not treat the flag as silencing
/// the warning.
#[cfg(unix)]
#[test]
fn test_broken_symlink_manifest_still_reported_under_follow_symlinks() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::os::unix::fs::symlink(
        dir.path().join("does-not-exist.toml"),
        dir.path().join("Cargo.toml"),
    )
    .expect("create broken symlink replacing Cargo.toml");

    let exe = env!("CARGO_BIN_EXE_deps-cli");
    let output = std::process::Command::new(exe)
        .args(["check", "--offline", "--follow-symlinks"])
        .arg(dir.path())
        .output()
        .expect("run the real deps-cli binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--follow-symlinks must not turn a broken symlink into a clean exit — stderr: {stderr}"
    );
    assert!(stderr.contains("could not be resolved"), "stderr: {stderr}");
}

/// Review finding M2: a manifest symlinked from directory A (which has its own `Cargo.lock`)
/// to a target manifest in directory B (which has none) must find A's lockfile during
/// `check_manifest`'s lockfile/in-use-version discovery, not B's absence of one — matching
/// US-002's own shared-manifest-symlinked-into-multiple-package-directories scenario, where
/// each symlinked location has its own adjacent lockfile.
///
/// Exercises the exact mechanism `check_manifest` -> `load_resolved_versions` relies on
/// (`Ecosystem::lockfile_provider().locate_lockfile`) directly against the URIs
/// [`DiscoveredManifest::uri_path`]/[`DiscoveredManifest::path`] actually produce, rather than
/// observing an indirect effect through findings (which would need a populated/mocked registry
/// to show a version difference).
#[cfg(unix)]
#[tokio::test]
async fn test_follow_symlinks_lockfile_lookup_uses_symlinks_directory_not_targets() {
    // A and B are both subdirectories of one walked root — the symlink's target must stay
    // inside the walked root (FR-004) for `--follow-symlinks` to resolve and route it at all;
    // A/B being two independent, unrelated temp directories would make the target a root
    // escape instead, an unrelated scenario this test isn't exercising.
    let root = tempfile::tempdir().expect("create walked root");
    let dir_a = root.path().join("a");
    let dir_b = root.path().join("b");
    std::fs::create_dir(&dir_a).expect("mkdir a");
    std::fs::create_dir(&dir_b).expect("mkdir b");

    std::fs::write(
        dir_b.join("manifest-data"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nonce_cell = \"1\"\n",
    )
    .expect("write target manifest in B");
    std::fs::write(
        dir_a.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"once_cell\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .expect("write A's Cargo.lock");
    std::os::unix::fs::symlink(dir_b.join("manifest-data"), dir_a.join("Cargo.toml"))
        .expect("symlink A/Cargo.toml -> B/Cargo.toml");

    let (registry, ctx) = offline_context();
    let outcome = walk::walk(
        &[root.path().to_path_buf()],
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Follow,
    );
    assert_eq!(
        outcome.manifests.len(),
        1,
        "ignored_manifests: {:?}, walk_errors: {:?}",
        outcome.ignored_manifests,
        outcome.walk_errors
    );
    let manifest = &outcome.manifests[0];

    // Sanity check on the fields M2's fix relies on: `path` (content read, canonicalized by
    // the C1/S3 containment check) resolves to B's real file; `uri_path` (lockfile lookup)
    // stays A's encountered symlink path, not canonicalized — matching `route_path`'s
    // semantics (see `route_file`'s doc).
    assert_eq!(
        manifest.path.canonicalize().expect("canonicalize path"),
        dir_b
            .join("manifest-data")
            .canonicalize()
            .expect("canonicalize B/Cargo.toml")
    );
    assert_eq!(manifest.uri_path, dir_a.join("Cargo.toml"));

    let lockfile_provider = manifest
        .ecosystem
        .lockfile_provider()
        .expect("cargo ecosystem must have a lock file provider");

    let uri_path_uri = url::Url::from_file_path(&manifest.uri_path).expect("uri_path to file uri");
    let path_uri = url::Url::from_file_path(&manifest.path).expect("path to file uri");

    assert_eq!(
        lockfile_provider.locate_lockfile(&uri_path_uri),
        Some(dir_a.join("Cargo.lock")),
        "lockfile lookup driven by uri_path must find A's Cargo.lock"
    );
    assert_eq!(
        lockfile_provider.locate_lockfile(&path_uri),
        None,
        "lockfile lookup driven by the resolved target path (B) must find nothing — B has no \
         Cargo.lock; if this were Some, check_manifest would silently anchor lockfile lookup \
         at the wrong directory"
    );

    // End-to-end: exercise the exact call `main.rs` makes (`manifest.uri_path`, per M2's fix)
    // and confirm A's lockfile actually gets parsed into the cache — the load-bearing
    // assertion that would catch a regression reverting `main.rs`'s argument choice, not just
    // the underlying `locate_lockfile` mechanism checked above.
    let content = std::fs::read_to_string(&manifest.path).expect("read manifest content");
    check_manifest(
        &manifest.ecosystem,
        &manifest.uri_path,
        &manifest.display_path,
        &content,
        &ctx,
    )
    .await
    .expect("check_manifest must succeed with the correct (uri_path) wiring");
    assert_eq!(
        ctx.lockfile_cache.len(),
        1,
        "check_manifest called with uri_path must have found and cached A's Cargo.lock"
    );

    // Simulates the M2 bug (passing the resolved target path instead of uri_path) against a
    // fresh cache — must find and cache nothing, since B has no Cargo.lock.
    let buggy_ctx = CheckContext {
        cache: Arc::clone(&ctx.cache),
        osv: Arc::clone(&ctx.osv),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy: ctx.policy.clone(),
    };
    check_manifest(
        &manifest.ecosystem,
        &manifest.path,
        &manifest.display_path,
        &content,
        &buggy_ctx,
    )
    .await
    .expect("check_manifest must still succeed (absence of a lock file is not an error)");
    assert_eq!(
        buggy_ctx.lockfile_cache.len(),
        0,
        "check_manifest called with the resolved target path (the bug M2 fixes) must find no \
         lockfile at all, proving the two wirings genuinely diverge"
    );
}

/// Builds a real, fully-registered [`EcosystemRegistry`] plus a *non*-offline
/// [`CheckContext`] under `license_policy` — mirrors [`offline_context`] but leaves
/// `HttpCache` free to make real requests, for the tier-3 license-prefetch parity tests
/// below (issue #1133).
fn live_context(license_policy: LicensePolicyConfig) -> (EcosystemRegistry, CheckContext) {
    let policy = PolicyConfig {
        license_policy,
        ..PolicyConfig::default()
    };
    let runtime = EcosystemRuntime::from_policy(&policy);
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);

    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy,
    };
    (registry, ctx)
}

/// Issue #1133 parity: `deps-cli check` must reach the same license-policy verdict as
/// `deps-lsp` for the four tier-3 ecosystems (Dart, Swift, Gradle, Deno), whose license
/// needs a dedicated [`deps_core::Ecosystem::fetch_license`] call beyond the registry's
/// hot-path version-list response. Before this fix, `deps-cli` silently never called it
/// (spec 062 deviation #2), so a `license_policy` never fired for these ecosystems — a
/// dependency with a real, denied license would pass `check` cleanly instead of failing it.
///
/// Each test below fetches the same dependency/version `deps-lsp`'s own
/// `document::osv_scan::tests::license_prefetch_tests` live tests use (see
/// `crates/deps-lsp/src/document/osv_scan.rs`), so a regression that breaks tier-3 wiring in
/// one adapter but not the other would produce a mismatch across the two test suites even
/// though `tower_lsp_server`'s `Client` requirement keeps them from sharing one test
/// function (see this file's module doc). The manifest requirement syntax differs from
/// `deps-lsp`'s fixture where needed (an exact/bare pin instead of a caret range) — unlike
/// `deps-lsp`'s test, which injects `resolved_versions` directly into `DocumentState`,
/// `check_manifest`'s public API has no equivalent shortcut and only ever sees a real lock
/// file (absent here) or the manifest's own already-concrete requirement.
///
/// `allow: ["0BSD"]` is deliberately a real SPDX id that none of these four fixture
/// dependencies actually carry: an *unknown* license (tier-3 prefetch silently failing,
/// e.g. from a network error) never violates a policy ([`deps_core::licenses::evaluate`]'s
/// `evaluate_unknown_license_never_violates` contract) — so this can only produce a
/// `Category::License` finding when a real, non-"0BSD" license genuinely reached the
/// policy engine, which is exactly the property this test protects.
mod tier3_license_prefetch_parity {
    use super::*;
    use deps_cli::report::Category;

    #[cfg(feature = "dart")]
    #[tokio::test]
    #[ignore = "hits the real pub.dev API"]
    async fn test_live_dart_tier3_license_feeds_check_license_policy() {
        let (registry, ctx) =
            live_context(LicensePolicyConfig::new().with_allow(vec!["0BSD".to_string()]));
        let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
        let manifest_path = url.to_file_path().expect("file-scheme uri");
        let ecosystem = registry.for_uri(&url).expect("Dart ecosystem not found");
        // A bare exact pin (no `^`), not `deps-lsp`'s live test's `^1.0.0` — Dart is
        // `BareRequirementPolicy::Concrete`, so this resolves without needing a lock file.
        let content = "dependencies:\n  http: 1.2.0\n";

        let result = check_manifest(&ecosystem, &manifest_path, &manifest_path, content, &ctx)
            .await
            .expect("check_manifest must not fail for a well-formed fixture");

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == Category::License
                    && f.dependency_name.as_deref() == Some("http")),
            "expected a license-policy finding for 'http', got: {:?}",
            result.findings
        );
    }

    #[cfg(feature = "swift")]
    #[tokio::test]
    #[ignore = "hits the real GitHub API"]
    async fn test_live_swift_tier3_license_feeds_check_license_policy() {
        let (registry, ctx) =
            live_context(LicensePolicyConfig::new().with_allow(vec!["0BSD".to_string()]));
        let url = deps_core::test_util::test_uri("/test/Package.swift");
        let manifest_path = url.to_file_path().expect("file-scheme uri");
        let ecosystem = registry.for_uri(&url).expect("Swift ecosystem not found");
        // `.exact(...)` (parsed to an explicit `=`-pinned requirement), not `deps-lsp`'s
        // live test's `.upToNextMajor(from:)` range — resolves without needing a lock file.
        let content =
            r#".package(url: "https://github.com/apple/swift-nio.git", .exact("2.65.0"))"#;

        let result = check_manifest(&ecosystem, &manifest_path, &manifest_path, content, &ctx)
            .await
            .expect("check_manifest must not fail for a well-formed fixture");

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == Category::License
                    && f.dependency_name.as_deref() == Some("apple/swift-nio")),
            "expected a license-policy finding for 'apple/swift-nio', got: {:?}",
            result.findings
        );
    }

    #[cfg(feature = "gradle")]
    #[tokio::test]
    #[ignore = "hits the real Maven Central API"]
    async fn test_live_gradle_tier3_license_feeds_check_license_policy() {
        // Held per `deps_core::fs_probe::snapshot_guard`'s doc: gradle's `parse_manifest`
        // transitively touches fs_probe, and other tests in this binary do too.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let (registry, ctx) =
            live_context(LicensePolicyConfig::new().with_allow(vec!["0BSD".to_string()]));
        let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
        let manifest_path = url.to_file_path().expect("file-scheme uri");
        let ecosystem = registry.for_uri(&url).expect("Gradle ecosystem not found");
        let content =
            "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n}\n";

        let result = check_manifest(&ecosystem, &manifest_path, &manifest_path, content, &ctx)
            .await
            .expect("check_manifest must not fail for a well-formed fixture");

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == Category::License
                    && f.dependency_name.as_deref() == Some("com.squareup.okhttp3:okhttp")),
            "expected a license-policy finding for 'com.squareup.okhttp3:okhttp', got: {:?}",
            result.findings
        );
    }

    #[cfg(feature = "deno")]
    #[tokio::test]
    #[ignore = "hits the real JSR API"]
    async fn test_live_deno_tier3_license_feeds_check_license_policy() {
        let (registry, ctx) =
            live_context(LicensePolicyConfig::new().with_allow(vec!["0BSD".to_string()]));
        let url = deps_core::test_util::test_uri("/test/deno.json");
        let manifest_path = url.to_file_path().expect("file-scheme uri");
        let ecosystem = registry.for_uri(&url).expect("Deno ecosystem not found");
        // A bare *full* version (no `^`/`~` range operator), not `deps-lsp`'s live test's
        // `^1.0` — Deno is `BareRequirementPolicy::ConcreteIfFullVersion` (#667), so this
        // resolves to an in-use version straight from the manifest requirement, with no
        // lock file needed (unlike `deps-lsp`'s test, which injects `resolved_versions`
        // directly into `DocumentState`, a shortcut `check_manifest`'s public API has no
        // equivalent for).
        let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@1.0.24"}}"#;

        let result = check_manifest(&ecosystem, &manifest_path, &manifest_path, content, &ctx)
            .await
            .expect("check_manifest must not fail for a well-formed fixture");

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == Category::License
                    && f.dependency_name.as_deref() == Some("jsr:@std/fs")),
            "expected a license-policy finding for 'jsr:@std/fs', got: {:?}",
            result.findings
        );
    }
}

/// Issue #1133 critic S2: a CI-executable (never `#[ignore]`) regression guard that
/// `check_manifest` actually reaches `prefetch_tier3_licenses` — every test in
/// `tier3_license_prefetch_parity` above is `#[ignore]`d (live network), so deleting the
/// `licenses.extend`/`tokio::join!` wiring in `report.rs` would leave
/// `cargo nextest run --workspace --all-features` green. This module closes that gap with a
/// fully network-free `Ecosystem` test double
/// ([`deps_engine::test_util::TestTier3Ecosystem`]) instead: no `#[ignore]`, no real
/// registry, runs on every `cargo nextest run` invocation.
mod tier3_wiring_regression {
    use super::*;
    use deps_cli::report::Category;
    use deps_core::Ecosystem;
    use deps_core::policy_config::DiagnosticsConfig;
    use deps_engine::test_util::TestTier3Ecosystem;

    /// A minimal, non-offline [`CheckContext`] under `policy` — unlike [`live_context`], the
    /// `Ecosystem` this is paired with never touches the network regardless of the
    /// `offline` flag, so this stays deterministic and fast without needing one.
    fn wiring_test_context(policy: PolicyConfig) -> CheckContext {
        let cache = Arc::new(HttpCache::new());
        CheckContext {
            cache: Arc::clone(&cache),
            osv: Arc::new(OsvClient::new(cache)),
            lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
            policy,
        }
    }

    #[tokio::test]
    async fn check_manifest_reaches_tier3_prefetch_wiring_without_network() {
        // OSV disabled so `ctx.osv.scan(..)` (a real network client) is never invoked —
        // this test's only network-shaped call is `TestTier3Ecosystem::fetch_license`,
        // which never touches a socket.
        let policy = PolicyConfig {
            diagnostics: DiagnosticsConfig::new().with_vulnerabilities_enabled(false),
            license_policy: LicensePolicyConfig::new().with_allow(vec!["0BSD".to_string()]),
            ..PolicyConfig::default()
        };
        let ctx = wiring_test_context(policy);

        let ecosystem: Arc<dyn Ecosystem> =
            Arc::new(TestTier3Ecosystem::returning(vec!["MIT".to_string()]));
        let url = deps_core::test_util::test_uri("/test/manifest.toml");
        let manifest_path = url.to_file_path().expect("file-scheme uri");

        let result = check_manifest(&ecosystem, &manifest_path, &manifest_path, "unused", &ctx)
            .await
            .expect("check_manifest must not fail for this fixture");

        assert!(
            result
                .findings
                .iter()
                .any(|f| f.category == Category::License
                    && f.dependency_name.as_deref() == Some("dep-0")),
            "check_manifest did not reach the tier-3 license prefetch wiring: {:?}",
            result.findings
        );
    }

    /// The M1 gate's other half: with no `license_policy` configured, `check_manifest` must
    /// never call `Ecosystem::fetch_license` at all — a [`TestTier3Ecosystem::pending`]
    /// would hang this test forever if the gate didn't short-circuit before it.
    #[tokio::test]
    async fn check_manifest_skips_tier3_prefetch_when_license_policy_is_empty() {
        let policy = PolicyConfig {
            diagnostics: DiagnosticsConfig::new().with_vulnerabilities_enabled(false),
            ..PolicyConfig::default()
        };
        assert!(
            policy.license_policy.to_policy().is_empty(),
            "test setup bug: this policy must have no license_policy configured"
        );
        let ctx = wiring_test_context(policy);

        let ecosystem: Arc<dyn Ecosystem> = Arc::new(TestTier3Ecosystem::pending());
        let url = deps_core::test_util::test_uri("/test/manifest.toml");
        let manifest_path = url.to_file_path().expect("file-scheme uri");

        tokio::time::timeout(
            Duration::from_secs(5),
            check_manifest(&ecosystem, &manifest_path, &manifest_path, "unused", &ctx),
        )
        .await
        .expect("must not hang: an empty license_policy must skip the tier-3 fetch entirely")
        .expect("check_manifest must not fail for this fixture");
    }
}
