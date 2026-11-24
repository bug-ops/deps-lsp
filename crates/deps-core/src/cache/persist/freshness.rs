//! Age classification of entries restored from disk (spec 051).
//!
//! Pure and total: every verdict is derived from a file's last-validation
//! time and an explicit `now`, so the rules are testable without a clock.
//! The window and the age cap are private and not configurable.

use super::key::{PageNumber, PageRole, PersistKey};
use std::time::{Duration, SystemTime};

/// Age below which a restored entry is served without any request.
const RESTORED_FRESHNESS_WINDOW: Duration = Duration::from_mins(10);

/// Age at which a persisted entry is no longer usable at all.
const MAX_PERSISTED_AGE: Duration = Duration::from_hours(168);

/// Largest tolerated gap between a file time and a `now` that is behind it.
const FUTURE_SKEW_TOLERANCE: Duration = Duration::from_mins(1);

/// The instant an entry was last validated against the registry.
///
/// Taken from the modification time of the entry file, so a restamp after a
/// `304` extends freshness without rewriting the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ValidatedAt(SystemTime);

impl ValidatedAt {
    /// Wraps a validation instant.
    #[must_use]
    pub(super) const fn new(at: SystemTime) -> Self {
        Self(at)
    }
}

/// How a persisted entry may be used at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiskFreshness {
    /// Serve without a request.
    Fresh,
    /// Usable, but validate first when online; serve as-is when offline.
    Revalidate,
    /// Older than the age cap; discard.
    Expired,
    /// Stamped further ahead of `now` than clock skew explains; discard.
    FromFuture,
}

/// Classifies one entry by age alone.
///
/// `Fresh` needs `0 <= age < 10 min`. An age of at least 7 days is `Expired`.
/// A stamp up to 60 s ahead of `now` is clock skew and yields `Revalidate`,
/// never `Fresh`; anything further ahead is `FromFuture`. A backward clock
/// jump therefore cannot make an old entry `Fresh`.
///
/// # Examples
///
/// ```ignore
/// let now = SystemTime::now();
/// assert_eq!(classify(ValidatedAt::new(now), now), DiskFreshness::Fresh);
/// ```
#[must_use]
pub(super) fn classify(validated_at: ValidatedAt, now: SystemTime) -> DiskFreshness {
    match now.duration_since(validated_at.0) {
        Ok(age) if age < RESTORED_FRESHNESS_WINDOW => DiskFreshness::Fresh,
        Ok(age) if age < MAX_PERSISTED_AGE => DiskFreshness::Revalidate,
        Ok(_) => DiskFreshness::Expired,
        Err(ahead) if ahead.duration() <= FUTURE_SKEW_TOLERANCE => DiskFreshness::Revalidate,
        Err(_) => DiskFreshness::FromFuture,
    }
}

/// An entry decoded from disk: its key and last-validation instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Restored {
    key: PersistKey,
    validated_at: ValidatedAt,
}

impl Restored {
    /// Pairs a decoded key with its validation instant.
    #[must_use]
    pub(super) const fn new(key: PersistKey, validated_at: ValidatedAt) -> Self {
        Self { key, validated_at }
    }
}

/// Classifies a restored entry, anchoring listing pages to page 1.
///
/// A `ListingPage` above page 1 may be `Fresh` only when page 1 is present,
/// itself `Fresh`, and not newer than this entry; otherwise the pages could
/// come from different snapshots of the listing, so it is capped at
/// `Revalidate`. `Standalone` entries, page 1 and keys without `page` use
/// [`classify`] alone. `Expired` and `FromFuture` verdicts are kept.
///
/// # Examples
///
/// ```ignore
/// // Page 2 with no page-1 anchor is never served without validation.
/// assert_eq!(classify_restored(&page2, None, now), DiskFreshness::Revalidate);
/// ```
#[must_use]
pub(super) fn classify_restored(
    entry: &Restored,
    page1: Option<&Restored>,
    now: SystemTime,
) -> DiskFreshness {
    let own = classify(entry.validated_at, now);
    if own != DiskFreshness::Fresh || !is_listing_page_above_one(&entry.key) {
        return own;
    }
    let anchored = page1.is_some_and(|anchor| {
        classify(anchor.validated_at, now) == DiskFreshness::Fresh
            && entry.validated_at.0 >= anchor.validated_at.0
    });
    if anchored {
        DiskFreshness::Fresh
    } else {
        DiskFreshness::Revalidate
    }
}

fn is_listing_page_above_one(key: &PersistKey) -> bool {
    key.page_role() == Some(PageRole::ListingPage)
        && key
            .page()
            .is_some_and(|page| Some(page) != PageNumber::new(1))
}
