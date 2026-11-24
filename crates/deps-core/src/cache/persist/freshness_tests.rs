//! Acceptance tests for spec 051 T002 (`persist::freshness`): age classification.
//!
//! Window and cap are restated as literals so the tests also pin the constants.

use super::freshness::{DiskFreshness, Restored, ValidatedAt, classify, classify_restored};
use super::key::{PageRole, PersistKey};
use crate::cache::CacheTier;
use crate::cache::auth::KeyAuth;
use proptest::prelude::*;
use std::time::{Duration, SystemTime};

const WINDOW: Duration = Duration::from_mins(10);
const WINDOW_LESS_1S: Duration = Duration::from_secs(599);
const MAX_AGE: Duration = Duration::from_hours(168);
const MAX_AGE_LESS_1S: Duration = Duration::from_secs(168 * 3600 - 1);
const SECOND: Duration = Duration::from_secs(1);
const TAGS: &str = "https://api.github.com/repos/o/r/tags";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_hours(500_000)
}

fn aged(age: Duration) -> ValidatedAt {
    ValidatedAt::new(now() - age)
}

fn ahead(skew: Duration) -> ValidatedAt {
    ValidatedAt::new(now() + skew)
}

fn restored(url: &str, role: Option<PageRole>, validated_at: ValidatedAt) -> Restored {
    let key = PersistKey::new(
        url,
        CacheTier::Baseline,
        KeyAuth::ANONYMOUS,
        "application/json",
        role,
    )
    .expect("eligible key");
    Restored::new(key, validated_at)
}

fn listing(page: u32, validated_at: ValidatedAt) -> Restored {
    let url = format!("{TAGS}?page={page}");
    restored(&url, Some(PageRole::ListingPage), validated_at)
}

#[test]
fn classify_boundaries() {
    let cases = [
        ("age 0", aged(Duration::ZERO), DiskFreshness::Fresh),
        (
            "window minus 1s",
            aged(WINDOW_LESS_1S),
            DiskFreshness::Fresh,
        ),
        ("exactly window", aged(WINDOW), DiskFreshness::Revalidate),
        (
            "max age minus 1s",
            aged(MAX_AGE_LESS_1S),
            DiskFreshness::Revalidate,
        ),
        ("exactly max age", aged(MAX_AGE), DiskFreshness::Expired),
        (
            "far beyond max age",
            aged(MAX_AGE * 100),
            DiskFreshness::Expired,
        ),
        ("mtime now+1s", ahead(SECOND), DiskFreshness::Revalidate),
        (
            "mtime now+60s",
            ahead(Duration::from_secs(60)),
            DiskFreshness::Revalidate,
        ),
        (
            "mtime now+61s",
            ahead(Duration::from_secs(61)),
            DiskFreshness::FromFuture,
        ),
        (
            "mtime far future",
            ahead(MAX_AGE * 100),
            DiskFreshness::FromFuture,
        ),
    ];
    for (label, validated_at, expected) in cases {
        assert_eq!(classify(validated_at, now()), expected, "{label}");
    }
}

#[test]
fn classify_backward_clock_jump_never_fresh_for_old_entry() {
    let validated_at = aged(WINDOW + SECOND);
    for jump_back in [
        Duration::from_secs(1),
        Duration::from_secs(3600),
        MAX_AGE,
        MAX_AGE * 10,
    ] {
        assert_ne!(
            classify(validated_at, now() - jump_back),
            DiskFreshness::Fresh,
            "clock moved back by {jump_back:?}"
        );
    }
}

#[test]
fn classify_backward_clock_jump_beyond_skew_is_from_future() {
    let validated_at = aged(WINDOW);
    assert_eq!(
        classify(validated_at, now() - WINDOW - Duration::from_secs(61)),
        DiskFreshness::FromFuture
    );
}

proptest! {
    #[test]
    fn classify_matches_age_rule_for_any_age(age_secs in 0u64..(30 * 24 * 3600)) {
        let age = Duration::from_secs(age_secs);
        let expected = if age < WINDOW {
            DiskFreshness::Fresh
        } else if age < MAX_AGE {
            DiskFreshness::Revalidate
        } else {
            DiskFreshness::Expired
        };
        prop_assert_eq!(classify(aged(age), now()), expected);
    }

    #[test]
    fn classify_future_mtime_never_fresh(skew_secs in 1u64..(10 * 24 * 3600)) {
        let skew = Duration::from_secs(skew_secs);
        let expected = if skew <= Duration::from_secs(60) {
            DiskFreshness::Revalidate
        } else {
            DiskFreshness::FromFuture
        };
        prop_assert_eq!(classify(ahead(skew), now()), expected);
    }
}

#[test]
fn classify_restored_page_above_one_without_anchor_never_fresh() {
    let entry = listing(2, aged(Duration::ZERO));
    let result = classify_restored(&entry, None, now());
    assert_eq!(result, DiskFreshness::Revalidate);
}

#[test]
fn classify_restored_page_above_one_with_fresh_anchor_and_not_older_is_fresh() {
    let anchor = listing(1, aged(Duration::from_secs(120)));
    let same_stamp = listing(2, aged(Duration::from_secs(120)));
    let newer = listing(3, aged(Duration::from_secs(60)));
    assert_eq!(
        classify_restored(&same_stamp, Some(&anchor), now()),
        DiskFreshness::Fresh
    );
    assert_eq!(
        classify_restored(&newer, Some(&anchor), now()),
        DiskFreshness::Fresh
    );
}

#[test]
fn classify_restored_page_older_than_anchor_never_fresh() {
    let anchor = listing(1, aged(Duration::from_secs(60)));
    let older = listing(2, aged(Duration::from_secs(61)));
    assert_eq!(
        classify_restored(&older, Some(&anchor), now()),
        DiskFreshness::Revalidate
    );
}

#[test]
fn classify_restored_page_above_one_with_stale_anchor_never_fresh() {
    let anchor = listing(1, aged(WINDOW));
    let entry = listing(2, aged(Duration::ZERO));
    assert_eq!(
        classify_restored(&entry, Some(&anchor), now()),
        DiskFreshness::Revalidate
    );
}

#[test]
fn classify_restored_listing_page_keeps_worse_own_verdicts() {
    let anchor = listing(1, aged(Duration::ZERO));
    let expired = listing(2, aged(MAX_AGE));
    let from_future = listing(2, ahead(Duration::from_secs(61)));
    assert_eq!(
        classify_restored(&expired, Some(&anchor), now()),
        DiskFreshness::Expired
    );
    assert_eq!(
        classify_restored(&from_future, None, now()),
        DiskFreshness::FromFuture
    );
}

#[test]
fn classify_restored_page_one_uses_classify_only() {
    let fresh = listing(1, aged(WINDOW_LESS_1S));
    let stale = listing(1, aged(WINDOW));
    assert_eq!(classify_restored(&fresh, None, now()), DiskFreshness::Fresh);
    assert_eq!(
        classify_restored(&stale, None, now()),
        DiskFreshness::Revalidate
    );
}

#[test]
fn classify_restored_standalone_ignores_anchor() {
    let url = format!("{TAGS}?per_page=1&page=2");
    let fresh = restored(&url, Some(PageRole::Standalone), aged(Duration::ZERO));
    let stale_anchor = listing(1, aged(WINDOW));
    assert_eq!(classify_restored(&fresh, None, now()), DiskFreshness::Fresh);
    assert_eq!(
        classify_restored(&fresh, Some(&stale_anchor), now()),
        DiskFreshness::Fresh
    );
    let old = restored(&url, Some(PageRole::Standalone), aged(WINDOW));
    assert_eq!(
        classify_restored(&old, None, now()),
        DiskFreshness::Revalidate
    );
}

#[test]
fn classify_restored_without_page_key_uses_classify_only() {
    let fresh = restored(TAGS, None, aged(Duration::ZERO));
    let expired = restored(TAGS, None, aged(MAX_AGE));
    assert_eq!(classify_restored(&fresh, None, now()), DiskFreshness::Fresh);
    assert_eq!(
        classify_restored(&expired, None, now()),
        DiskFreshness::Expired
    );
}

#[test]
fn classify_restored_backward_clock_jump_never_fresh_for_old_page() {
    let anchor = listing(1, aged(WINDOW + SECOND));
    let entry = listing(2, aged(WINDOW + SECOND));
    let jumped = now() - Duration::from_secs(3600);
    assert_ne!(
        classify_restored(&entry, Some(&anchor), jumped),
        DiskFreshness::Fresh
    );
}
