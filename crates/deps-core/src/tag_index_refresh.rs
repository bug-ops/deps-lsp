//! Typed refresh broadcasts of ecosystems backed by a shared git tags datasource.
//!
//! [`RefreshSender`] owns the broadcast channel behind
//! [`Ecosystem::refresh_events`](crate::Ecosystem::refresh_events) and the rule for when a
//! refetched [`TagIndex`] counts as a refresh, so GitHub Actions and GitLab CI cannot diverge
//! on it. The same channel carries the follow-up events of background probes
//! ([`RefreshEvent::ProbeEvidence`]) and of identity changes that require re-parsing
//! ([`RefreshEvent::ReparseOpenDocuments`]).

use std::hash::Hash;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::broadcast;

use crate::NormalizedName;
use crate::lsp_helpers::TagIndex;

/// Capacity of the refresh channel; a receiver that falls further behind gets
/// `RecvError::Lagged` and must treat every repository as refreshed.
const CHANNEL_CAPACITY: usize = 256;

/// Something an ecosystem announces to every open document it may concern.
///
/// Exhaustive so a listener decides what each event means for it. The repository payloads are
/// normalized names, the same key the ecosystem's stores use.
///
/// # Examples
///
/// ```
/// use deps_core::RefreshEvent;
///
/// let event = RefreshEvent::ReparseOpenDocuments { generation: 3 };
/// assert_eq!(event, RefreshEvent::ReparseOpenDocuments { generation: 3 });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshEvent {
    /// The tag index of this repository first appeared or observably changed. A listener
    /// re-runs probes for documents referencing it, rescans vulnerabilities and republishes.
    TagIndex(NormalizedName),
    /// A background probe stored new evidence about this repository. A listener only
    /// republishes diagnostics: it must not re-run probes or re-evaluate vulnerabilities, or
    /// the probe's own event would trigger it again.
    ProbeEvidence(NormalizedName),
    /// The identity decisions the ecosystem's parser consults changed (a new `generation`), so
    /// its open documents must be re-parsed, at most once per content version and generation.
    ReparseOpenDocuments {
        /// The monotonically increasing generation of the changed decisions.
        generation: u64,
    },
}

/// Receiver of an ecosystem's [`RefreshEvent`]s, see
/// [`Ecosystem::refresh_events`](crate::Ecosystem::refresh_events).
pub type RefreshEvents = broadcast::Receiver<RefreshEvent>;

/// Stores a fetched [`TagIndex`] and announces refreshes of an ecosystem.
///
/// Clones share one channel.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use dashmap::DashMap;
/// use deps_core::lsp_helpers::{CommitSha, NormalizeName, PackageNaming, TagIndex};
/// use deps_core::{PackageName, RefreshEvent, RefreshSender};
///
/// struct Lowercase;
/// impl PackageNaming for Lowercase {
///     fn normalized_spelling(&self, name: &PackageName) -> String { name.as_str().to_lowercase() }
/// }
///
/// let sender = RefreshSender::new();
/// let mut events = sender.subscribe();
/// let map: DashMap<PackageName, Arc<TagIndex>> = DashMap::new();
/// let name = PackageName::new("Owner/Repo");
/// let repository = Lowercase.normalize_package_name(&name);
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = || TagIndex::from_tags([("v1", &sha)]);
///
/// sender.replace(&map, name.clone(), &repository, index(), 8);
/// assert_eq!(events.try_recv().unwrap(), RefreshEvent::TagIndex(repository.clone()));
/// sender.replace(&map, name, &repository, index(), 8);
/// assert!(events.try_recv().is_err());
/// ```
#[derive(Debug, Clone)]
pub struct RefreshSender {
    tx: broadcast::Sender<RefreshEvent>,
}

impl Default for RefreshSender {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshSender {
    /// Creates a sender with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(CHANNEL_CAPACITY).0,
        }
    }

    /// Returns an independent receiver that observes only events sent after this call.
    #[must_use]
    pub fn subscribe(&self) -> RefreshEvents {
        self.tx.subscribe()
    }

    /// Inserts `index` under `key` (evicting an arbitrary entry first when `map` holds
    /// `capacity` entries and `key` is new) and sends [`RefreshEvent::TagIndex`] for
    /// `repository` when the index is the first for `key` or [`TagIndex::observably_differs`]
    /// from the previous one.
    ///
    /// `repository` is the normalized spelling of the package `key` indexes, supplied by the
    /// caller because only the ecosystem's formatter can derive it. The event is sent after the
    /// insert, so a receiver reading `map` on receipt sees the new index.
    pub fn replace<K>(
        &self,
        map: &DashMap<K, Arc<TagIndex>>,
        key: K,
        repository: &NormalizedName,
        index: TagIndex,
        capacity: usize,
    ) where
        K: Eq + Hash + Clone,
    {
        if !map.contains_key(&key) {
            crate::cache_policy::evict_arbitrary_if_full(map, capacity);
        }
        let index = Arc::new(index);
        let previous = map.insert(key, Arc::clone(&index));
        let changed = previous.is_none_or(|previous| previous.observably_differs(&index));
        if changed {
            self.send(RefreshEvent::TagIndex(repository.clone()));
        }
    }

    /// Announces that a probe stored new evidence about `repository`.
    pub fn send_probe_evidence(&self, repository: NormalizedName) {
        self.send(RefreshEvent::ProbeEvidence(repository));
    }

    /// Announces that the ecosystem's open documents must be re-parsed for `generation`.
    pub fn send_reparse_open_documents(&self, generation: u64) {
        self.send(RefreshEvent::ReparseOpenDocuments { generation });
    }

    fn send(&self, event: RefreshEvent) {
        if self.tx.send(event).is_err() {
            tracing::trace!("refresh event with no subscriber");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PackageName;
    use crate::github::CanonicalRepoName;
    use crate::lsp_helpers::CommitSha;
    use crate::pagination::ListCoverage;

    const CAPACITY: usize = 4;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    struct Fixture {
        sender: RefreshSender,
        rx: RefreshEvents,
        map: DashMap<PackageName, Arc<TagIndex>>,
        name: PackageName,
        repository: NormalizedName,
    }

    impl Fixture {
        fn new() -> Self {
            let sender = RefreshSender::new();
            let rx = sender.subscribe();
            Self {
                sender,
                rx,
                map: DashMap::new(),
                name: PackageName::new("o/r"),
                repository: NormalizedName::for_test("o/r"),
            }
        }

        fn replace(&self, index: TagIndex) {
            self.sender.replace(
                &self.map,
                self.name.clone(),
                &self.repository,
                index,
                CAPACITY,
            );
        }

        fn tag_index_event(&self) -> RefreshEvent {
            RefreshEvent::TagIndex(self.repository.clone())
        }
    }

    #[test]
    fn first_populate_sends() {
        let mut f = Fixture::new();
        f.replace(TagIndex::from_tags([("v1", &sha('a'))]));
        assert_eq!(f.rx.try_recv().unwrap(), f.tag_index_event());
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

        assert_eq!(f.rx.try_recv().unwrap(), f.tag_index_event());
        let current = f.map.get(&f.name).map(|entry| Arc::clone(&entry)).unwrap();
        assert_eq!(current.sha_for_tag("v1"), Some(&sha('b')));
    }

    #[test]
    fn mapping_change_sends() {
        let mut f = Fixture::new();
        f.replace(TagIndex::from_tags([("v1", &sha('a'))]));
        f.rx.try_recv().unwrap();
        f.replace(TagIndex::from_tags([("v1", &sha('b'))]));
        assert_eq!(f.rx.try_recv().unwrap(), f.tag_index_event());
    }

    #[test]
    fn coverage_change_sends() {
        let mut f = Fixture::new();
        let a = sha('a');
        f.replace(TagIndex::from_tags([("v1", &a)]));
        f.rx.try_recv().unwrap();
        f.replace(TagIndex::from_tags([("v1", &a)]).with_coverage(ListCoverage::Truncated));
        assert_eq!(f.rx.try_recv().unwrap(), f.tag_index_event());
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
        assert_eq!(f.rx.try_recv().unwrap(), f.tag_index_event());
    }

    #[test]
    fn full_map_evicts_before_insert() {
        let f = Fixture::new();
        for i in 0..3 {
            let n = PackageName::new(format!("o/r{i}"));
            let repository = NormalizedName::for_test(format!("o/r{i}"));
            f.sender
                .replace(&f.map, n, &repository, TagIndex::default(), 2);
        }
        assert_eq!(f.map.len(), 2);
    }

    #[test]
    fn probe_evidence_and_reparse_events_are_distinct_from_tag_index() {
        let mut f = Fixture::new();
        f.sender.send_probe_evidence(f.repository.clone());
        f.sender.send_reparse_open_documents(7);
        assert_eq!(
            f.rx.try_recv().unwrap(),
            RefreshEvent::ProbeEvidence(f.repository.clone())
        );
        assert_eq!(
            f.rx.try_recv().unwrap(),
            RefreshEvent::ReparseOpenDocuments { generation: 7 }
        );
        assert!(f.rx.try_recv().is_err());
    }
}
