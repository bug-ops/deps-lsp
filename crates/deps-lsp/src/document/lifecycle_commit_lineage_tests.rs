//! #2183/#2184: what a commit derives from the entry it replaces, and what it carries over.
//!
//! The seam is the split between parsing (`parse_manifest_for_change`) and committing
//! (`commit_parsed_document`): a test commits something else in between, which is what a
//! faster concurrent change does.

use super::*;

async fn open(state: &ServerState, path: &str, content: &str) -> (Uri, Arc<dyn Ecosystem>) {
    let url = deps_core::test_util::test_uri(path);
    let uri = crate::lsp_types_interop::to_lsp_uri(&url);
    let ecosystem = state.ecosystem_registry.for_uri(&url).expect("ecosystem");
    let parsed = Arc::clone(&ecosystem)
        .parse_manifest(content, &url)
        .await
        .expect("parse");
    state.update_document(
        uri.clone(),
        DocumentState::new_from_parse_result(ecosystem.ecosystem_id(), content.to_owned(), parsed),
    );
    (uri, ecosystem)
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn commit_diffs_against_the_entry_it_replaces_not_the_one_seen_at_parse_time() {
    let state = ServerState::new();
    let (uri, ecosystem) = open(
        &state,
        "/test/Cargo.toml",
        "[dependencies]\nserde = \"1\"\n",
    )
    .await;
    let content = "[dependencies]\nserde = \"1\"\nanyhow = \"1\"\n";
    let (parsed, _) = parse_manifest_for_change(&uri, content, &state, &ecosystem).await;
    // A concurrent change lands between that parse and its commit.
    parse_and_commit(
        &state,
        &uri,
        &ecosystem,
        "[dependencies]\nserde = \"1\"\nanyhow = \"1\"\ntokio = \"1\"\n",
    )
    .await;

    let report = commit_parsed_document(
        &uri,
        ecosystem.as_ref(),
        content.to_owned(),
        parsed,
        None,
        &state,
        CommitOptions {
            guard: CommitGuard::IfTracked,
            position: CommitPosition::Advance,
        },
    )
    .expect("tracked");

    assert!(report.diff.added.is_empty(), "{:?}", report.diff.added);
    assert_eq!(
        report.diff.removed.as_slice(),
        [deps_core::NormalizedName::for_test("tokio")]
    );
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn every_commit_advances_the_stamp_within_one_open() {
    let state = ServerState::new();
    let content = "[dependencies]\nserde = \"1\"\n";
    let (uri, ecosystem) = open(&state, "/test/Cargo.toml", content).await;
    let before = state.get_document(&uri).unwrap().commit_stamp();

    parse_and_commit(&state, &uri, &ecosystem, content).await;
    let after = state.get_document(&uri).unwrap().commit_stamp();

    assert_eq!(before.epoch, after.epoch);
    assert_ne!(before.seq, after.seq);
}

#[cfg(feature = "dart")]
#[tokio::test]
async fn license_obligation_survives_a_later_commit_and_settles_on_a_finished_round() {
    let state = Arc::new(ServerState::new());
    state.set_license_policy(deps_core::LicensePolicy::new(
        vec!["MIT".to_owned()],
        vec![],
    ));
    let empty = "name: x\ndependencies:\n";
    let (uri, ecosystem) = open(&state, "/test/pubspec.yaml", empty).await;
    let obligation = |state: &ServerState| state.get_document(&uri).unwrap().license_refresh();
    assert_eq!(obligation(&state), LicenseRefresh::Settled);

    let with_dep = "name: x\ndependencies:\n  http: ^1.0.0\n";
    parse_and_commit(&state, &uri, &ecosystem, with_dep).await;
    assert_eq!(obligation(&state), LicenseRefresh::Pending);

    // A newer edit that adds nothing keeps the obligation: its task still owes the fetch.
    parse_and_commit(&state, &uri, &ecosystem, &format!("{with_dep}# note\n")).await;
    assert_eq!(obligation(&state), LicenseRefresh::Pending);

    // A round with nothing to fetch settles it.
    parse_and_commit(&state, &uri, &ecosystem, empty).await;
    run_license_prefetch(
        uri.clone(),
        Arc::clone(&state),
        ecosystem,
        deps_core::policy_config::FetchTimeout::constant::<5>(),
    )
    .await;
    assert_eq!(obligation(&state), LicenseRefresh::Settled);
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn an_ecosystem_without_a_dedicated_license_fetch_never_owes_one() {
    let state = ServerState::new();
    state.set_license_policy(deps_core::LicensePolicy::new(
        vec!["MIT".to_owned()],
        vec![],
    ));
    let (uri, ecosystem) = open(&state, "/test/Cargo.toml", "[dependencies]\n").await;

    parse_and_commit(&state, &uri, &ecosystem, "[dependencies]\nserde = \"1\"\n").await;

    assert_eq!(
        state.get_document(&uri).unwrap().license_refresh(),
        LicenseRefresh::Settled
    );
}

/// A full refetch another commit requested between this commit's parse and its write is served
/// by this commit: it is read under the same entry the commit writes through.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn commit_reports_a_refetch_requested_after_its_parse() {
    let state = ServerState::new();
    let content = "[dependencies]\nserde = \"1\"\n";
    let (uri, ecosystem) = open(&state, "/test/Cargo.toml", content).await;
    let (parsed, _) = parse_manifest_for_change(&uri, content, &state, &ecosystem).await;
    let requested = state.escalate_refetch(&uri);

    let report = commit_parsed_document(
        &uri,
        ecosystem.as_ref(),
        content.to_owned(),
        parsed,
        None,
        &state,
        CommitOptions {
            guard: CommitGuard::IfTracked,
            position: CommitPosition::Advance,
        },
    )
    .expect("tracked");

    assert_eq!(report.escalation, Some(requested));
}
