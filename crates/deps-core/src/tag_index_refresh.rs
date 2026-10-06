//! Shared tag-index store-and-notify path for ecosystems backed by a git tags datasource.
//!
//! [`TagIndexRefreshSender`] owns the broadcast channel behind
//! [`Ecosystem::tag_index_refreshes`](crate::Ecosystem::tag_index_refreshes) and the rule for
//! when a refetched [`TagIndex`] counts as a refresh, so GitHub Actions and GitLab CI cannot
//! diverge on it.

use std::hash::Hash;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::broadcast;

use crate::lsp_helpers::TagIndex;
use crate::{PackageName, TagIndexRefreshes};

/// Capacity of the refresh channel; a receiver that falls further behind gets
/// `RecvError::Lagged` and must treat every package as refreshed.
const CHANNEL_CAPACITY: usize = 256;

/// A tag-index map key that names the package it indexes, so the package announced for a
/// refresh can never differ from the entry that was replaced.
pub trait TagIndexKey: Eq + Hash + Clone {
    /// The package this key indexes.
    fn package(&self) -> &PackageName;
}

impl TagIndexKey for PackageName {
    fn package(&self) -> &PackageName {
        self
    }
}

/// A key qualified by something else (GitLab's endpoint kind) and the package.
impl<Q: Eq + Hash + Clone> TagIndexKey for (Q, PackageName) {
    fn package(&self) -> &PackageName {
        &self.1
    }
}

/// Stores a fetched [`TagIndex`] and announces the package whose index first appeared or
/// observably changed.
///
/// Clones share one channel.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use dashmap::DashMap;
/// use deps_core::lsp_helpers::{CommitSha, TagIndex};
/// use deps_core::{PackageName, TagIndexRefreshSender};
///
/// let sender = TagIndexRefreshSender::new();
/// let mut refreshes = sender.subscribe();
/// let map: DashMap<PackageName, Arc<TagIndex>> = DashMap::new();
/// let name = PackageName::new("owner/repo");
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = || TagIndex::from_tags([("v1", &sha)]);
///
/// sender.replace(&map, name.clone(), index(), 8);
/// assert_eq!(refreshes.try_recv().unwrap(), name);
/// sender.replace(&map, name.clone(), index(), 8);
/// assert!(refreshes.try_recv().is_err());
/// ```
#[derive(Debug, Clone)]
pub struct TagIndexRefreshSender {
    tx: broadcast::Sender<PackageName>,
}

impl Default for TagIndexRefreshSender {
    fn default() -> Self {
        Self::new()
    }
}

impl TagIndexRefreshSender {
    /// Creates a sender with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(CHANNEL_CAPACITY).0,
        }
    }

    /// Returns an independent receiver that observes only refreshes sent after this call.
    #[must_use]
    pub fn subscribe(&self) -> TagIndexRefreshes {
        self.tx.subscribe()
    }

    /// Inserts `index` under `key` (evicting an arbitrary entry first when `map` holds
    /// `capacity` entries and `key` is new) and sends the key's package when the index is the
    /// first for `key` or [`TagIndex::observably_differs`] from the previous one.
    ///
    /// The event is sent after the insert, so a receiver reading `map` on receipt sees the
    /// new index.
    pub fn replace<K>(
        &self,
        map: &DashMap<K, Arc<TagIndex>>,
        key: K,
        index: TagIndex,
        capacity: usize,
    ) where
        K: TagIndexKey,
    {
        if !map.contains_key(&key) {
            crate::cache_policy::evict_arbitrary_if_full(map, capacity);
        }
        let name = key.package().clone();
        let index = Arc::new(index);
        let previous = map.insert(key, Arc::clone(&index));
        let changed = previous.is_none_or(|previous| previous.observably_differs(&index));
        if changed && self.tx.send(name).is_err() {
            tracing::trace!("tag index refreshed with no subscriber");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::CanonicalRepoName;
    use crate::lsp_helpers::CommitSha;
    use crate::pagination::ListCoverage;

    const CAPACITY: usize = 4;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    struct Fixture {
        sender: TagIndexRefreshSender,
        rx: TagIndexRefreshes,
        map: DashMap<PackageName, Arc<TagIndex>>,
        name: PackageName,
    }

    impl Fixture {
        fn new() -> Self {
            let sender = TagIndexRefreshSender::new();
            let rx = sender.subscribe();
            Self {
                sender,
                rx,
                map: DashMap::new(),
                name: PackageName::new("o/r"),
            }
        }

        fn replace(&self, index: TagIndex) {
            self.sender
                .replace(&self.map, self.name.clone(), index, CAPACITY);
        }
    }

    #[test]
    fn first_populate_sends() {
        let mut f = Fixture::new();
        f.replace(TagIndex::from_tags([("v1", &sha('a'))]));
        assert_eq!(f.rx.try_recv().unwrap(), f.name);
    }

    #[test]
    fn identical_refetch_is_silent() {
        let mut f = Fixture::new();
        let a = sha('a');
        f.replace(TagIndex::from_tags([("v1", &a)]));
        f.replace(TagIndex::from_tags([("v1", &a)]));
        f.rx.try_recv().unwrap();
        assert!(f.rx.try_recv().is_err());
    }

    /// A receiver reading the map on receipt sees the new index, not the replaced one.
    #[test]
    fn event_is_sent_after_the_index_is_inserted() {
        let mut f = Fixture::new();
        f.replace(TagIndex::from_tags([("v1", &sha('a'))]));
        f.rx.try_recv().unwrap();
        f.replace(TagIndex::from_tags([("v1", &sha('b'))]));

        let refreshed = f.rx.try_recv().unwrap();
        let current = f
            .map
            .get(&refreshed)
            .map(|entry| Arc::clone(&entry))
            .unwrap();
        assert_eq!(current.tag_to_sha.get("v1"), Some(&sha('b')));
    }

    #[test]
    fn mapping_change_sends() {
        let mut f = Fixture::new();
        f.replace(TagIndex::from_tags([("v1", &sha('a'))]));
        f.rx.try_recv().unwrap();
        f.replace(TagIndex::from_tags([("v1", &sha('b'))]));
        assert_eq!(f.rx.try_recv().unwrap(), f.name);
    }

    #[test]
    fn coverage_change_sends() {
        let mut f = Fixture::new();
        let a = sha('a');
        f.replace(TagIndex::from_tags([("v1", &a)]));
        f.rx.try_recv().unwrap();
        f.replace(TagIndex::from_tags([("v1", &a)]).with_coverage(ListCoverage::Truncated));
        assert_eq!(f.rx.try_recv().unwrap(), f.name);
    }

    #[test]
    fn canonical_name_change_sends() {
        let mut f = Fixture::new();
        let a = sha('a');
        f.replace(TagIndex::from_tags([("v1", &a)]));
        f.rx.try_recv().unwrap();
        let canonical = CanonicalRepoName::from_commit_url(&format!(
            "https://api.github.com/repos/O/R/commits/{}",
            a.as_str()
        ));
        assert!(canonical.is_some());
        f.replace(TagIndex::from_tags([("v1", &a)]).with_canonical_repo_name(canonical));
        assert_eq!(f.rx.try_recv().unwrap(), f.name);
    }

    #[test]
    fn full_map_evicts_before_insert() {
        let f = Fixture::new();
        for i in 0..3 {
            let n = PackageName::new(format!("o/r{i}"));
            f.sender.replace(&f.map, n, TagIndex::default(), 2);
        }
        assert_eq!(f.map.len(), 2);
    }
}
