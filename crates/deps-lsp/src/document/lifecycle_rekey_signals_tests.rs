//! End-to-end check that every per-package signal channel follows the normalized key when a
//! manifest declares one package under two spellings (`Django` / `django`, #1873).
//!
//! `normalized_rekey_tests` in `lifecycle.rs` seeds only cached/resolved/vulnerabilities/outcomes;
//! this seeds licenses, typosquats, GOSSIP findings, `latest_status` and `candidate_status` too,
//! so a prune or survivor path that forgets one of them fails here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use deps_core::PackageVersions;
use deps_core::osv::{CandidateStatuses, ScanOutcome, UpgradeStatus};
use deps_core::test_util::{stub_gossip_findings, vuln_key};
use deps_core::{ConcreteVersion, EcosystemId, GossipFindings, TyposquatSignal};

fn manifest(deps: &[(&str, &str)]) -> String {
    let mut out = String::from("[tool.poetry.dependencies]\n");
    for (name, req) in deps {
        out.push_str(&format!("\"{name}\" = \"{req}\"\n"));
    }
    out
}

fn django() -> NormalizedName {
    NormalizedName::for_test("django")
}

/// A genuine signal value, resolved through a mocked deps.dev: `TyposquatSignal` has no public
/// constructor, so its key is re-assigned to `django` by the caller.
async fn real_typosquat_signal() -> TyposquatSignal {
    let mut server = mockito::Server::new_async().await;
    fn mock(server: &mut mockito::ServerGuard, path: &str, body: &str) -> mockito::Mock {
        server
            .mock("GET", path)
            .with_status(200)
            .with_body(body)
            .create()
    }
    let _mocks = [
        mock(
            &mut server,
            "/v3alpha/systems/pypi/packages/djang0:similarlyNamedPackages",
            r#"{"packageKey": {"name": "djang0"}, "packages": [{"packageKey": {"name": "django"}}]}"#,
        ),
        mock(
            &mut server,
            "/v3alpha/systems/pypi/packages/djang0",
            r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#,
        ),
        mock(
            &mut server,
            "/v3alpha/systems/pypi/packages/djang0/versions/1.0.0:dependents",
            r#"{"dependentCount": 3}"#,
        ),
        mock(
            &mut server,
            "/v3alpha/systems/pypi/packages/django",
            r#"{"versions": [{"versionKey": {"version": "5.0"}, "isDefault": true}]}"#,
        ),
        mock(
            &mut server,
            "/v3alpha/systems/pypi/packages/django/versions/5.0:dependents",
            r#"{"dependentCount": 900}"#,
        ),
    ];
    let client = Arc::new(deps_core::DepsDevClient::for_test(
        Arc::new(deps_core::HttpCache::new()),
        server.url(),
    ));
    let state = ServerState::new();
    let url = deps_core::test_util::test_uri("/test/pyproject.toml");
    let ecosystem = state.ecosystem_registry.for_uri(&url).expect("pypi");
    let parse = ecosystem
        .parse_manifest(&manifest(&[("djang0", "==1.0.0")]), &url)
        .await
        .unwrap();
    let outcome = deps_core::lsp_helpers::fetch_typosquat_signals(
        deps_core::EcosystemId::Pypi,
        parse.as_ref(),
        ecosystem.formatter(),
        deps_core::NetworkMode::Online,
        Some(&client),
    )
    .await;
    outcome
        .signals
        .into_values()
        .next()
        .expect("the mocked pre-fetch resolves a signal")
}

fn gossip() -> GossipFindings {
    stub_gossip_findings("5.0", None)
}

/// Opens `content` and seeds every per-package signal channel for `django`.
async fn open_fully_seeded(content: &str) -> (Arc<ServerState>, Uri, Arc<dyn Ecosystem>) {
    let state = Arc::new(ServerState::new());
    let url = deps_core::test_util::test_uri("/test/pyproject.toml");
    let uri = crate::lsp_types_interop::to_lsp_uri(&url);
    let ecosystem = state.ecosystem_registry.for_uri(&url).expect("pypi");
    let parse = ecosystem.parse_manifest(content, &url).await.unwrap();
    let mut doc =
        DocumentState::new_from_parse_result(EcosystemId::Pypi, content.to_string(), parse);
    doc.update_cached_versions(HashMap::from([(
        django(),
        PackageVersions::latest_only("5.0"),
    )]));
    let signals = &mut doc.signals;
    signals
        .resolved_versions
        .insert(django(), ConcreteVersion::new("4.1"));
    signals
        .licenses
        .insert(django(), vec!["BSD-3-Clause".to_string()]);
    signals
        .typosquats
        .insert(django(), real_typosquat_signal().await);
    signals.gossip_findings.insert(django(), gossip());
    for key in ["django", "django\u{0}v:4.0"] {
        signals
            .vulnerabilities
            .insert(vuln_key(key), ScanOutcome::Clean);
        signals
            .latest_status
            .insert(vuln_key(key), UpgradeStatus::NotChecked);
        signals
            .candidate_status
            .insert(vuln_key(key), CandidateStatuses::PerVersion(HashMap::new()));
    }
    state.update_document(uri.clone(), doc);
    (state, uri, ecosystem)
}

async fn edit(
    state: &ServerState,
    uri: &Uri,
    ecosystem: &Arc<dyn Ecosystem>,
    content: &str,
) -> DependencyDiff {
    let (parse, diff, _) = parse_and_diff_manifest(uri, content, state, ecosystem).await;
    assert!(commit_parsed_document(
        uri,
        ecosystem.as_ref(),
        content.to_string(),
        parse,
        None,
        state,
        CommitOptions {
            diff: &diff,
            guard: CommitGuard::Unconditional,
        },
    ));
    diff
}

fn assert_every_channel_holds_django(state: &ServerState, uri: &Uri) {
    let signals = &state.get_document(uri).unwrap().signals;
    assert!(signals.cached_versions.contains_key(&django()));
    assert!(signals.resolved_versions.contains_key(&django()));
    assert!(signals.licenses.contains_key(&django()));
    assert!(signals.typosquats.contains_key(&django()));
    assert!(signals.gossip_findings.contains_key(&django()));
    assert!(signals.vulnerabilities.contains_key(&vuln_key("django")));
    assert!(signals.latest_status.contains_key(&vuln_key("django")));
    assert!(signals.candidate_status.contains_key(&vuln_key("django")));
}

#[tokio::test]
async fn deleting_one_spelling_keeps_every_channel_of_the_survivor() {
    let (state, uri, ecosystem) =
        open_fully_seeded(&manifest(&[("Django", "==4.0"), ("django", "==4.1")])).await;

    let diff = edit(&state, &uri, &ecosystem, &manifest(&[("django", "==4.1")])).await;

    assert!(diff.removed.is_empty(), "the package is still declared");
    assert_every_channel_holds_django(&state, &uri);
}

#[tokio::test]
async fn renaming_the_spelling_keeps_every_channel() {
    let (state, uri, ecosystem) = open_fully_seeded(&manifest(&[("Django", "==4.1")])).await;

    let diff = edit(&state, &uri, &ecosystem, &manifest(&[("django", "==4.1")])).await;

    assert!(diff.removed.is_empty() && diff.version_changed.is_empty());
    assert_every_channel_holds_django(&state, &uri);
}

#[tokio::test]
async fn removing_every_spelling_empties_every_channel() {
    let (state, uri, ecosystem) =
        open_fully_seeded(&manifest(&[("Django", "==4.0"), ("django", "==4.1")])).await;

    let diff = edit(&state, &uri, &ecosystem, &manifest(&[])).await;

    assert_eq!(diff.removed.as_slice(), [django()]);
    let signals = &state.get_document(&uri).unwrap().signals;
    assert!(signals.cached_versions.is_empty());
    assert!(signals.resolved_versions.is_empty());
    assert!(signals.licenses.is_empty());
    assert!(signals.typosquats.is_empty());
    assert!(signals.gossip_findings.is_empty());
    assert!(signals.vulnerabilities.is_empty());
    assert!(signals.latest_status.is_empty());
    assert!(signals.candidate_status.is_empty());
}
