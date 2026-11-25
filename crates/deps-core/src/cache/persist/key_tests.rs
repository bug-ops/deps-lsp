//! Acceptance tests for spec 051 T001 (`persist::key`): the persist eligibility rule.

use super::key::{PageNumber, PageRole, PersistKey, PersistableHost};
use crate::cache::CacheTier;
use crate::cache::CredentialPartition;
use crate::cache::auth::KeyAuth;
use crate::net_policy::WorkspaceRegistryAccess;
use proptest::prelude::*;

const ACCEPT: &str = "application/json";

fn baseline_anon(url: &str, role: Option<PageRole>) -> Option<PersistKey> {
    PersistKey::new(url, CacheTier::Baseline, KeyAuth::ANONYMOUS, ACCEPT, role)
}

fn page(n: u32) -> PageNumber {
    PageNumber::new(n).expect("non-zero page number")
}

fn url_of(key: &PersistKey) -> &str {
    key.url()
}

#[test]
fn persistable_host_from_host_refuses_unlisted_hosts() {
    for host in [
        "github.example.com",
        "evil.example",
        "API.GITHUB.COM.evil.example",
        "api.github.com.",
        "www.npmjs.com",
        "search.maven.org",
        "api.osv.dev",
        "api.deps.dev",
        "",
    ] {
        assert!(PersistableHost::from_host(host).is_none(), "{host:?}");
    }
}

#[test]
fn persist_key_new_accepts_listed_urls() {
    let listing = Some(PageRole::ListingPage);
    let standalone = Some(PageRole::Standalone);
    let accepted: [(&str, Option<PageRole>); 10] = [
        (
            "https://api.github.com/repos/o/r/tags?per_page=100&page=1",
            listing,
        ),
        ("https://api.github.com/repos/o/r/tags?page=2", listing),
        (
            "https://api.github.com/repos/o/r/compare/v1...v2",
            standalone,
        ),
        (
            "https://api.github.com/repos/o/r/compare/v1...v2?page=1",
            standalone,
        ),
        (
            "https://api.github.com/repos/o/r/releases?per_page=30&page=3",
            listing,
        ),
        (
            "https://gitlab.com/api/v4/projects/1/repository/tags?order_by=updated&sort=desc",
            None,
        ),
        (
            "https://gitlab.com/api/v4/projects/1/repository/tags?order_by=updated&sort=desc&page=2",
            listing,
        ),
        ("https://index.crates.io/se/rd/serde", None),
        ("https://registry.npmjs.org/left-pad", None),
        ("https://pypi.org/pypi/requests/json", None),
    ];
    for (url, role) in accepted {
        let key = baseline_anon(url, role).unwrap_or_else(|| panic!("{url} must be persistable"));
        assert_eq!(url_of(&key), url);
    }
}

#[test]
fn persist_key_new_refuses_body_dependent_post_hosts() {
    for url in [
        "https://api.osv.dev/v1/query",
        "https://api.osv.dev/v1/querybatch",
        "https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx",
        "https://api.deps.dev/v3alpha/findingsbatch",
    ] {
        assert!(baseline_anon(url, None).is_none(), "{url} must be refused");
    }
}

#[test]
fn persist_key_new_refuses_ineligible_urls() {
    let listing = Some(PageRole::ListingPage);
    let refused = [
        "https://api.github.com/repos/o/r/tags?access_token=abc",
        "https://gitlab.com/api/v4/projects/1/repository/tags?private_token=abc",
        "https://api.github.com/repos/o/r/tags?unknown=1",
        "https://api.github.com/repos/o/r/tags?per_page=1&per_page=2",
        "https://api.github.com/repos/o/r/tags?page=1&page=2",
        "https://api.github.com/repos/o/r/tags?per_page=123456789012345678901234567890123",
        "https://api.github.com/repos/o/r/tags?per_page=a%20b",
        "https://api.github.com/repos/o/r/tags?per_page=",
        "https://user:pass@api.github.com/repos/o/r/tags",
        "https://user@api.github.com/repos/o/r/tags",
        "https://api.github.com/repos/o/r/tags#frag",
        "https://140.82.112.5/repos/o/r/tags",
        "https://[2606:50c0:8000::1]/repos/o/r/tags",
        "https://github.corp.example/api/v3/repos/o/r/tags",
        "http://api.github.com/repos/o/r/tags",
        "https://api.github.com:8443/repos/o/r/tags",
        "not a url",
        "",
    ];
    for url in refused {
        assert!(
            baseline_anon(url, listing).is_none(),
            "{url:?} must be refused"
        );
    }
}

#[test]
fn persist_key_new_accepts_explicit_default_port() {
    assert!(baseline_anon("https://api.github.com:443/repos/o/r/tags", None).is_some());
}

#[test]
fn persist_key_new_refuses_value_boundaries() {
    let ok = format!("https://api.github.com/x?per_page={}", "1".repeat(32));
    let long = format!("https://api.github.com/x?per_page={}", "1".repeat(33));
    assert!(baseline_anon(&ok, None).is_some());
    assert!(baseline_anon(&long, None).is_none());
}

#[test]
fn persist_key_new_refuses_non_baseline_tiers_and_credentialed_auth() {
    let url = "https://api.github.com/repos/o/r/tags";
    let tiers = [
        CacheTier::Pinned { digest: 1 },
        CacheTier::WorkspaceDeclared(WorkspaceRegistryAccess::PublicOnly),
    ];
    for tier in tiers {
        assert!(PersistKey::new(url, tier, KeyAuth::ANONYMOUS, ACCEPT, None).is_none());
    }
    let partition = CredentialPartition::new(7);
    for auth in [
        KeyAuth::Credential(partition),
        KeyAuth::Anonymous(Some(partition)),
    ] {
        assert!(PersistKey::new(url, CacheTier::Baseline, auth, ACCEPT, None).is_none());
    }
}

#[test]
fn persist_key_new_page_without_declared_role_is_none() {
    let url = "https://api.github.com/repos/o/r/tags?page=2";
    assert!(baseline_anon(url, None).is_none());
    assert!(baseline_anon(url, Some(PageRole::ListingPage)).is_some());
    assert!(baseline_anon(url, Some(PageRole::Standalone)).is_some());
}

#[test]
fn persist_key_new_declared_role_without_page_is_accepted() {
    let url = "https://api.github.com/repos/o/r/compare/a...b";
    assert!(baseline_anon(url, Some(PageRole::Standalone)).is_some());
}

#[test]
fn persist_key_new_refuses_a_page_with_leading_zeros() {
    let listing = Some(PageRole::ListingPage);
    for url in [
        "https://api.github.com/x?page=02",
        "https://api.github.com/x?page=007",
    ] {
        assert!(baseline_anon(url, listing).is_none(), "{url}");
    }
}

#[test]
fn persist_key_new_refuses_non_numeric_page() {
    let listing = Some(PageRole::ListingPage);
    for url in [
        "https://api.github.com/x?page=0",
        "https://api.github.com/x?page=abc",
        "https://api.github.com/x?page=-1",
        "https://api.github.com/x?page=",
    ] {
        assert!(baseline_anon(url, listing).is_none(), "{url}");
    }
}

#[test]
fn sibling_page_replaces_only_the_page_value_keeping_order() {
    let key = baseline_anon(
        "https://api.github.com/repos/o/r/tags?per_page=100&page=3&sort=desc",
        Some(PageRole::ListingPage),
    )
    .expect("eligible");
    let sibling = key.sibling_page(page(1)).expect("has page key");
    assert_eq!(
        url_of(&sibling),
        "https://api.github.com/repos/o/r/tags?per_page=100&page=1&sort=desc"
    );
    assert_eq!(
        url_of(&key),
        "https://api.github.com/repos/o/r/tags?per_page=100&page=3&sort=desc"
    );
}

#[test]
fn sibling_page_without_page_key_is_none_above_one() {
    let key = baseline_anon(
        "https://api.github.com/repos/o/r/tags?per_page=100",
        Some(PageRole::ListingPage),
    )
    .expect("eligible");
    assert!(key.sibling_page(page(2)).is_none());
    assert!(key.sibling_page(page(u32::MAX)).is_none());
}

#[test]
fn sibling_page_without_page_key_yields_same_url_for_page_one() {
    let url = "https://api.github.com/repos/o/r/tags?per_page=100";
    let key = baseline_anon(url, Some(PageRole::ListingPage)).expect("eligible");
    let sibling = key
        .sibling_page(page(1))
        .expect("page 1 is the implicit page");
    assert_eq!(url_of(&sibling), url);
}

#[test]
fn page_number_new_refuses_zero() {
    assert!(PageNumber::new(0).is_none());
    assert!(PageNumber::new(1).is_some());
}

proptest! {
    #[test]
    fn persist_key_new_never_panics_on_arbitrary_strings(
        url in "\\PC*",
        role in prop_oneof![
            Just(None),
            Just(Some(PageRole::ListingPage)),
            Just(Some(PageRole::Standalone)),
        ],
    ) {
        let _ = baseline_anon(&url, role);
    }

    #[test]
    fn persist_key_new_never_panics_on_url_shaped_input(
        host in prop_oneof![Just("api.github.com".to_owned()), "[a-z0-9.:@\\[\\]-]{0,20}"],
        path in "[ -~]{0,30}",
        query in "[ -~]{0,40}",
        fragment in "[ -~]{0,10}",
    ) {
        let url = format!("https://{host}/{path}?{query}#{fragment}");
        if let Some(key) = baseline_anon(&url, Some(PageRole::ListingPage)) {
            let _ = key.sibling_page(page(2));
        }
    }
}
