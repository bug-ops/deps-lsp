//! Acceptance tests for #1719 / spec 103 at the `TagIndex` / candidate level: a tag pin and a
//! candidate tag scan every release tag on their commit, across majors, exactly like a SHA pin.
//!
//! Assumption (plan N3): the floating-pin "scan targets" built from the commit's full
//! releases are observable through `ResolvedPin::siblings()`.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use deps_core::lsp_helpers::{
    CandidateTagSource, CommitSha, PinResolution, ResolvedPin, SiblingScope, TagIndex,
    TaggedVersions,
};
use deps_core::osv::SiblingCoverage;
use deps_core::pagination::ListCoverage;
use deps_core::{ConcreteVersion, EcosystemId};

fn sha() -> CommitSha {
    CommitSha::parse(&"a".repeat(40)).expect("40 hex")
}

fn index(tags: &[&str]) -> TagIndex {
    let sha = sha();
    TagIndex::from_tags(tags.iter().map(|t| (*t, &sha)))
}

fn sibling_names(pin: &ResolvedPin) -> Vec<&str> {
    pin.siblings().iter().map(ConcreteVersion::as_str).collect()
}

fn resolved(resolution: PinResolution) -> (ResolvedPin, ListCoverage) {
    match resolution {
        PinResolution::Resolved {
            pin,
            sibling_coverage,
        } => (pin, sibling_coverage),
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[test]
fn resolved_exact_tag_carries_cross_major_siblings() {
    let idx = index(&["v4.8.0", "v4.9.0", "v5.0.0"]);

    let pin = idx.resolved_exact_tag("v4.8.0").expect("indexed");

    assert_eq!(pin.version().as_str(), "v4.8.0");
    assert_eq!(sibling_names(&pin), ["v4.9.0", "v5.0.0"]);
}

#[test]
fn resolved_exact_tag_keeps_written_tag_as_primary_when_newer_major_exists() {
    let idx = index(&["v4.8.0", "v4.9.0", "v5.0.0"]);

    let pin = idx.resolved_exact_tag("v4.9.0").expect("indexed");

    assert_eq!(pin.version().as_str(), "v4.9.0");
    assert_eq!(sibling_names(&pin), ["v4.8.0", "v5.0.0"]);
}

#[test]
fn exact_tag_resolution_matches_sha_pin_siblings() {
    let sha = sha();
    let idx = index(&["v4.8.0", "v5.0.0"]);

    let (pin, coverage) = resolved(idx.exact_tag_resolution("v4.8.0"));
    let sha_pin = idx.resolved_pin(&sha).expect("sha pin resolves");

    assert_eq!(coverage, ListCoverage::Complete);
    assert_eq!(sibling_names(&pin), ["v5.0.0"]);
    assert_eq!(
        sibling_names(&pin),
        sibling_names(&sha_pin),
        "tag pin and SHA pin see the same release names"
    );
}

#[test]
fn resolved_release_same_major_scope_still_excludes_other_majors() {
    let idx = index(&["v4.8.0", "v4.9.0", "v5.0.0"]);

    let pin = idx
        .resolved_release("v4.8.0", SiblingScope::SameMajor)
        .expect("indexed");

    assert_eq!(sibling_names(&pin), ["v4.9.0"]);
}

/// F1 precondition: a partial floating tag with no full release of its own stays the primary
/// (#1684: the primary is never an unrelated release) and gains the commit's full releases as
/// scan targets.
#[test]
fn floating_tag_resolution_partial_primary_gets_cross_major_full_releases() {
    let idx = index(&["v4", "v5.0.0"]);

    let (pin, coverage) = resolved(idx.floating_tag_resolution("v4"));

    assert_eq!(pin.version().as_str(), "v4");
    assert!(
        sibling_names(&pin).contains(&"v5.0.0"),
        "{:?}",
        sibling_names(&pin)
    );
    assert_eq!(coverage, ListCoverage::Complete);
}

#[test]
fn floating_tag_resolution_never_adopts_unrelated_release_as_primary() {
    for other in ["v5.0.0", "v99.0.0"] {
        let idx = index(&["v4", other]);

        let (pin, _) = resolved(idx.floating_tag_resolution("v4"));

        assert_eq!(pin.version().as_str(), "v4", "{other}");
    }
}

#[test]
fn floating_tag_resolution_full_release_primary_gets_whole_commit_siblings() {
    let idx = index(&["v4", "v4.2.2", "v5.0.0"]);

    let (pin, _) = resolved(idx.floating_tag_resolution("v4"));

    assert_eq!(pin.version().as_str(), "v4.2.2");
    assert!(
        sibling_names(&pin).contains(&"v5.0.0"),
        "{:?}",
        sibling_names(&pin)
    );
}

/// F4: the written tag alone on its commit has nothing to scan.
#[test]
fn floating_tag_resolution_lone_partial_tag_has_no_siblings() {
    let idx = index(&["v4"]);

    let (pin, _) = resolved(idx.floating_tag_resolution("v4"));

    assert_eq!(pin.version().as_str(), "v4");
    assert!(pin.siblings().is_empty());
}

/// F3: the truncated list is reported through the coverage, so the scan fails closed.
#[test]
fn floating_tag_resolution_truncated_index_reports_truncated_coverage() {
    let idx = index(&["v4", "v5.0.0"]).with_coverage(ListCoverage::Truncated);

    let (_, coverage) = resolved(idx.floating_tag_resolution("v4"));

    assert_eq!(coverage, ListCoverage::Truncated);
}

/// U1: a candidate tag on the same commit as a newer major is checked against that major.
#[test]
fn candidate_siblings_tag_pin_include_cross_major_tags() {
    let idx = Arc::new(index(&["v4.8.0", "v4.9.0", "v5.0.0"]));
    let source = CandidateTagSource::tag_pin(idx);

    let siblings = source
        .siblings_of(&ConcreteVersion::new("v4.9.0"), EcosystemId::GithubActions)
        .expect("candidate indexed");

    let names: Vec<&str> = siblings
        .siblings()
        .iter()
        .map(ConcreteVersion::as_str)
        .collect();
    assert!(names.contains(&"v5.0.0"), "{names:?}");
    assert!(names.contains(&"v4.8.0"), "{names:?}");
}

/// Plan: after #1719 the two constructors are equal in behaviour.
#[test]
fn candidate_tag_source_tag_pin_and_commit_pin_agree() {
    let idx = Arc::new(index(&["v4.8.0", "v4.9.0", "v5.0.0"]));
    let candidate = ConcreteVersion::new("v4.9.0");

    let tag = CandidateTagSource::tag_pin(Arc::clone(&idx))
        .siblings_of(&candidate, EcosystemId::GithubActions)
        .expect("tag pin");
    let commit = CandidateTagSource::commit_pin(idx)
        .siblings_of(&candidate, EcosystemId::GithubActions)
        .expect("commit pin");

    assert_eq!(tag, commit);
}

/// U3: a truncated list still fails closed.
#[test]
fn candidate_siblings_truncated_index_reports_truncated_coverage() {
    let idx = Arc::new(index(&["v4.9.0", "v5.0.0"]).with_coverage(ListCoverage::Truncated));
    let source = CandidateTagSource::tag_pin(idx);

    let siblings = source
        .siblings_of(&ConcreteVersion::new("v4.9.0"), EcosystemId::GithubActions)
        .expect("candidate indexed");

    assert_eq!(siblings.sibling_coverage(), SiblingCoverage::Truncated);
}

/// U2: a candidate with no other release tag on its commit has no siblings.
#[test]
fn candidate_siblings_lone_candidate_has_none() {
    let idx = Arc::new(index(&["v4.9.0"]));
    let source = CandidateTagSource::tag_pin(idx);

    let siblings = source
        .siblings_of(&ConcreteVersion::new("v4.9.0"), EcosystemId::GithubActions)
        .expect("candidate indexed");

    assert!(siblings.siblings().is_empty());
}
