//! Acceptance tests for #1964 / spec 101: operator advisory exemptions through `deps-cli check`.
//!
//! The in-process half drives the real `check_manifest` pipeline against a `mockito` OSV server;
//! the binary half pins the `--advisory-exemptions` flag and the rule that exemptions never come
//! from `deps.toml` or from auto-discovery.
//!
//! Assumption (plan, Breaking list): `CheckContext` gains a public field
//! `advisory_exemptions: Arc<OperatorExemptions>`.

#![cfg(feature = "cargo")]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::path::Path;
use std::sync::Arc;

use deps_cli::exit::{EXIT_CLEAN, EXIT_POLICY_VIOLATION, ExecutionOutcome, exit_code};
use deps_cli::report::{
    Category, CheckContext, CheckFinding, CheckReport, FailOnPolicy, OsvCoverage, check_manifest,
};
use deps_cli::walk;
use deps_core::diagnostic::DiagnosticKind;
use deps_core::lsp_helpers::exemption::{ExemptionFile, OperatorExemptions};
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

const ID_A: &str = "GHSA-aaaa-aaaa-aaaa";
const ID_B: &str = "GHSA-bbbb-bbbb-bbbb";
const ID_MAL: &str = "MAL-2024-0001";
const ID_ALIASED_MAL: &str = "GHSA-cccc-cccc-cccc";

fn entry(id: &str, extra: &str) -> String {
    format!("[[advisory]]\nid = \"{id}\"\nreason = \"accepted for this release\"\n{extra}\n")
}

fn record(id: &str, severity: Option<&str>, aliases: &[&str]) -> String {
    let severity = severity.map_or(String::new(), |s| {
        format!(r#","database_specific":{{"severity":"{s}"}}"#)
    });
    let aliases = aliases
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"id":"{id}","modified":"2023-01-01T00:00:00Z","summary":"s","aliases":[{aliases}]{severity},
        "affected":[{{"package":{{"name":"serde","ecosystem":"crates.io"}},
        "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"1.0.200"}}]}}]}}]}}"#
    )
}

struct Outcome {
    report: CheckReport,
    coverage: OsvCoverage,
    policy: PolicyConfig,
}

impl Outcome {
    fn advisories(&self) -> Vec<&str> {
        self.report
            .findings
            .iter()
            .filter_map(|f| match &f.kind {
                DiagnosticKind::Advisory(id) => Some(id.as_str()),
                _ => None,
            })
            .collect()
    }

    fn exempted_notes(&self) -> Vec<&CheckFinding> {
        self.report
            .findings
            .iter()
            .filter(|f| matches!(f.kind, DiagnosticKind::AdvisoryExempted))
            .collect()
    }

    fn exit(&self, categories: Vec<Category>) -> i32 {
        exit_code(
            &self.report,
            &FailOnPolicy::new(categories),
            &self.coverage,
            self.policy.osv_checks(),
            ExecutionOutcome::Clean,
        )
    }
}

fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    let z = i64::try_from(secs / 86_400).expect("fits") + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Scans a `serde = "=1.0.100"` fixture against a mock OSV that reports `records` and applies
/// `exemptions_toml` (an operator file body) when given.
async fn scan(records: &[(&str, Option<&str>, &[&str])], exemptions_toml: Option<&str>) -> Outcome {
    let mut osv = mockito::Server::new_async().await;
    let vulns = records
        .iter()
        .map(|(id, _, _)| format!(r#"{{"id":"{id}","modified":"2023-01-01T00:00:00Z"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let _batch = osv
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(format!(r#"{{"results":[{{"vulns":[{vulns}]}}]}}"#))
        .expect_at_least(1)
        .create_async()
        .await;
    #[allow(
        clippy::collection_is_never_read,
        reason = "mocks must outlive the scan"
    )]
    let mut _records = Vec::new();
    for (id, severity, aliases) in records {
        _records.push(
            osv.mock("GET", format!("/v1/vulns/{id}").as_str())
                .with_status(200)
                .with_body(record(id, *severity, aliases))
                .expect_at_least(0)
                .create_async()
                .await,
        );
    }

    let dir = tempfile::tempdir().expect("project dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"=1.0.100\"\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(
        dir.path().join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .expect("write Cargo.lock");

    let exemptions = match exemptions_toml {
        None => OperatorExemptions::none(),
        Some(body) => {
            let operator_dir = tempfile::tempdir().expect("operator dir outside the scanned tree");
            let file = operator_dir.path().join("advisory-exemptions.toml");
            std::fs::write(&file, body).expect("write exemptions");
            OperatorExemptions::load(&ExemptionFile::for_test(file))
                .expect("valid exemption file")
                .expect("file exists")
        }
    };

    let policy = PolicyConfig::default();
    let runtime =
        EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&MapEnv::new()));
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy: policy.clone(),
        advisory_exemptions: Arc::new(exemptions),
    };

    let outcome = walk::walk(
        &[dir.path().to_path_buf()],
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
    let mut report = CheckReport::default();
    let mut coverage = OsvCoverage::default();
    for manifest in outcome.manifests() {
        let content = std::fs::read_to_string(&manifest.path).expect("read manifest");
        let result = check_manifest(
            &manifest.ecosystem,
            &manifest.uri_path,
            &manifest.display_path,
            &content,
            &ctx,
        )
        .await
        .expect("check_manifest");
        coverage.add(&result.osv_coverage);
        report.findings.extend(result.findings);
    }
    Outcome {
        report,
        coverage,
        policy,
    }
}

const TWO: [(&str, Option<&str>, &[&str]); 2] =
    [(ID_A, Some("HIGH"), &[]), (ID_B, Some("LOW"), &[])];

#[tokio::test]
async fn check_without_exemptions_reports_every_advisory() {
    let run = scan(&TWO, None).await;

    let mut ids = run.advisories();
    ids.sort_unstable();
    assert_eq!(ids, [ID_A, ID_B]);
    assert!(run.exempted_notes().is_empty());
}

#[tokio::test]
async fn check_exempted_advisory_is_hidden_and_counted_once() {
    let run = scan(&TWO, Some(&entry(ID_A, ""))).await;

    assert_eq!(run.advisories(), [ID_B]);
    let notes = run.exempted_notes();
    assert_eq!(notes.len(), 1, "one note per dependency");
    assert!(notes[0].message.contains(ID_A), "{}", notes[0].message);
    assert!(
        notes[0]
            .message
            .contains("1 advisory exempted by operator config"),
        "{}",
        notes[0].message
    );
    assert_eq!(notes[0].category(), Category::Other);
    assert_eq!(format!("{:?}", notes[0].severity), "Information");
}

#[tokio::test]
async fn check_exempting_every_advisory_lists_sorted_ids_and_clears_the_vulnerable_gate() {
    let toml = format!("{}{}", entry(ID_B, ""), entry(ID_A, ""));
    let run = scan(&TWO, Some(&toml)).await;

    assert!(run.advisories().is_empty());
    let notes = run.exempted_notes();
    assert_eq!(notes.len(), 1);
    let message = &notes[0].message;
    assert!(
        message.contains("2 advisories exempted by operator config"),
        "{message}"
    );
    assert!(
        message.find(ID_A).expect("A listed") < message.find(ID_B).expect("B listed"),
        "ids are sorted: {message}"
    );
    assert_eq!(run.exit(vec![Category::Vulnerable]), EXIT_CLEAN);
}

/// M4: the visible exemption notice is `Category::Other`, so `--fail-on other` fails on it.
#[tokio::test]
async fn check_exemption_notice_is_failed_on_by_the_other_category() {
    let run = scan(&TWO, Some(&entry(ID_A, ""))).await;

    assert_eq!(run.exit(vec![Category::Other]), EXIT_POLICY_VIOLATION);
}

#[tokio::test]
async fn check_exemption_matches_an_alias_of_the_advisory() {
    let records: [(&str, Option<&str>, &[&str]); 1] = [(ID_A, Some("HIGH"), &["CVE-2099-0001"])];
    let run = scan(&records, Some(&entry("CVE-2099-0001", ""))).await;

    assert!(run.advisories().is_empty());
    assert_eq!(run.exempted_notes().len(), 1);
}

#[tokio::test]
async fn check_expired_exemption_is_inert() {
    let run = scan(&TWO, Some(&entry(ID_A, "expires = \"2000-01-01\""))).await;

    let mut ids = run.advisories();
    ids.sort_unstable();
    assert_eq!(ids, [ID_A, ID_B]);
    assert!(run.exempted_notes().is_empty());
}

#[tokio::test]
async fn check_future_dated_exemption_is_honored() {
    let run = scan(&TWO, Some(&entry(ID_A, "expires = \"2099-12-31\""))).await;

    assert_eq!(run.advisories(), [ID_B]);
    assert_eq!(run.exempted_notes().len(), 1);
}

/// Expiry is inclusive: an entry that expires today still applies today.
#[tokio::test]
async fn check_exemption_expiring_today_is_still_honored() {
    let extra = format!("expires = \"{}\"", today_utc());
    let run = scan(&TWO, Some(&entry(ID_A, &extra))).await;

    assert_eq!(run.advisories(), [ID_B]);
}

#[tokio::test]
async fn check_unrelated_exemption_changes_nothing() {
    let run = scan(&TWO, Some(&entry("GHSA-zzzz-zzzz-zzzz", ""))).await;

    assert_eq!(run.advisories().len(), 2);
    assert!(run.exempted_notes().is_empty());
}

#[tokio::test]
async fn check_malicious_advisory_is_never_exempted() {
    let records: [(&str, Option<&str>, &[&str]); 2] =
        [(ID_MAL, None, &[]), (ID_A, Some("HIGH"), &[])];
    let toml = format!("{}{}", entry(ID_MAL, ""), entry(ID_A, ""));
    let run = scan(&records, Some(&toml)).await;

    assert_eq!(run.advisories(), [ID_MAL]);
    let notes = run.exempted_notes();
    assert_eq!(notes.len(), 1);
    assert!(!notes[0].message.contains(ID_MAL), "{}", notes[0].message);
}

/// A non-`MAL-` primary id that aliases a `MAL-` record is still malware.
#[tokio::test]
async fn check_advisory_aliasing_a_malicious_record_is_never_exempted() {
    let records: [(&str, Option<&str>, &[&str]); 1] = [(ID_ALIASED_MAL, None, &["MAL-2024-0002"])];
    let run = scan(&records, Some(&entry(ID_ALIASED_MAL, ""))).await;

    assert_eq!(run.advisories(), [ID_ALIASED_MAL]);
    assert!(run.exempted_notes().is_empty());
}

// ---- binary: flag and trust boundary ---------------------------------------------------------

/// A scanned tree with one manifest and no dependencies: `check` exits 2 on an empty tree, and
/// this needs no network.
fn manifest_tree() -> tempfile::TempDir {
    let tree = tempfile::tempdir().expect("tree");
    std::fs::write(
        tree.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");
    tree
}

fn run_binary(args: &[&str], dir: &Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .arg("check")
        .args(args)
        .arg(dir)
        .output()
        .expect("run the real deps-cli binary")
}

fn code(output: &std::process::Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn cli_help_documents_the_advisory_exemptions_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["check", "--help"])
        .output()
        .expect("run help");
    assert!(String::from_utf8_lossy(&output.stdout).contains("--advisory-exemptions"));
}

#[test]
fn cli_valid_exemption_file_on_an_empty_tree_exits_clean() {
    let tree = manifest_tree();
    let ops = tempfile::tempdir().expect("operator dir");
    let file = ops.path().join("ex.toml");
    std::fs::write(&file, entry(ID_A, "expires = \"2099-01-01\"")).expect("write");

    let output = run_binary(
        &["--advisory-exemptions", file.to_str().expect("utf8")],
        tree.path(),
    );

    assert_eq!(
        code(&output),
        Some(EXIT_CLEAN),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_missing_exemption_file_is_a_config_error() {
    let tree = manifest_tree();
    let missing = tree.path().join("nope.toml");

    let output = run_binary(
        &["--advisory-exemptions", missing.to_str().expect("utf8")],
        tree.path(),
    );

    assert_eq!(code(&output), Some(deps_cli::exit::EXIT_EXECUTION_ERROR));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("nope.toml"),
        "the error must name the file, not be a usage error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_malformed_exemption_file_is_a_config_error_without_echoing_its_content() {
    let tree = manifest_tree();
    let ops = tempfile::tempdir().expect("operator dir");
    let file = ops.path().join("ex.toml");
    std::fs::write(&file, "[[advisory]]\nid = \"TOPSECRETVALUE\nreason =").expect("write");

    let output = run_binary(
        &["--advisory-exemptions", file.to_str().expect("utf8")],
        tree.path(),
    );

    assert_eq!(code(&output), Some(deps_cli::exit::EXIT_EXECUTION_ERROR));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ex.toml"),
        "the error must name the file: {stderr}"
    );
    assert!(!stderr.contains("TOPSECRETVALUE"), "{stderr}");
}

#[test]
fn cli_invalid_entry_in_exemption_file_is_a_config_error() {
    let tree = manifest_tree();
    let ops = tempfile::tempdir().expect("operator dir");
    let file = ops.path().join("ex.toml");
    std::fs::write(&file, "[[advisory]]\nid = \"GHSA-aaaa-aaaa-aaaa\"\n").expect("write");

    let output = run_binary(
        &["--advisory-exemptions", file.to_str().expect("utf8")],
        tree.path(),
    );

    assert_eq!(code(&output), Some(deps_cli::exit::EXIT_EXECUTION_ERROR));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ex.toml"));
}

/// The CLI never discovers an exemption file by itself, not even a conventional name in the tree.
#[test]
fn cli_does_not_auto_discover_an_exemption_file_in_the_tree() {
    let tree = manifest_tree();
    std::fs::write(
        tree.path().join("advisory-exemptions.toml"),
        "not even toml [[[",
    )
    .expect("write");
    let nested = tree.path().join("deps-lsp");
    std::fs::create_dir(&nested).expect("mkdir");
    std::fs::write(nested.join("advisory-exemptions.toml"), "not even toml [[[").expect("write");

    let output = run_binary(&[], tree.path());

    assert_eq!(
        code(&output),
        Some(EXIT_CLEAN),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
