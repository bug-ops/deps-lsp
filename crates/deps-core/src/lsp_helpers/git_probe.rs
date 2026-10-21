//! Background git-ref probes: the typed ref a request URL may be built from, the evidence
//! probes gather, and the bounded stores diagnostics read it from.
//!
//! Diagnostics generation stays synchronous and network-free. A probe runs in a spawned task
//! (see [`Ecosystem::background_probes`](crate::Ecosystem::background_probes)), stores only
//! authoritative answers here, and reports whether anything changed through a [`ProbeReport`].
//! Specs 086 (branch evidence) and 087 (commit lineage and default-branch membership) share
//! this infrastructure; an inconclusive answer (rate limit, 5xx, timeout, overflow) is never
//! stored, so the pin it concerns stays silent.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::{CommitSha, RequirementStatus, is_dot_segment, is_tag_shaped};
use crate::NormalizedName;
use crate::cache::BodyLimit;

/// Entries each evidence store keeps before evicting the least recently used one.
pub const EVIDENCE_STORE_CAPACITY: usize = 4096;

/// Longest ref, in bytes, [`ProbeRef::parse`] accepts.
const MAX_PROBE_REF_BYTES: usize = 255;

/// A tag-shaped ref text proven safe to place in the path of a token-bearing request.
///
/// The only constructor is [`Self::parse`], so no probe URL can be built from manifest text
/// that was not checked. It accepts a ref that [`is_tag_shaped`] and consists only of
/// `[A-Za-z0-9._+-]`, at most 255 bytes, with no leading `.` or `-`, no trailing `.` or
/// `.lock`, and no `..`. That rejects `/`, `?`, `#`, `%`, `@{`, whitespace and control
/// characters, every one of which could retarget the request. [`Self::as_path_segment`]
/// additionally percent-encodes the ref, regardless.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::ProbeRef;
///
/// let git_ref = ProbeRef::parse("v40").unwrap();
/// assert_eq!(git_ref.as_str(), "v40");
/// assert_eq!(ProbeRef::parse("v1+build").unwrap().as_path_segment().to_string(), "v1%2Bbuild");
/// assert!(ProbeRef::parse("1/../../../../user").is_none());
/// assert!(ProbeRef::parse("1?x#y").is_none());
/// assert!(ProbeRef::parse("main").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeRef(String);

impl ProbeRef {
    /// The checked ref for `written`, or `None` when probing it could build an unsafe request.
    #[must_use]
    pub fn parse(written: &str) -> Option<Self> {
        let plain_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-');
        let accepted = is_tag_shaped(written)
            && written.len() <= MAX_PROBE_REF_BYTES
            && written.chars().all(plain_char)
            && !written.starts_with(['.', '-'])
            && !written.ends_with('.')
            && !written.ends_with(".lock")
            && !written.contains("..")
            && !is_dot_segment(written);
        accepted.then(|| Self(written.to_string()))
    }

    /// The ref text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The ref percent-encoded for use as one URL path segment.
    #[must_use]
    pub fn as_path_segment(&self) -> PercentEncoded<'_> {
        PercentEncoded(urlencoding::encode(&self.0))
    }
}

/// A string percent-encoded for a URL path segment, rendered through [`fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercentEncoded<'a>(Cow<'a, str>);

impl fmt::Display for PercentEncoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the forge answered about a branch named like a partial tag ref.
///
/// Only authoritative answers exist: `200` is [`Self::Exists`], `404` against a repository whose
/// tag list was readable is [`Self::Absent`]. Everything else is inconclusive and not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchEvidence {
    /// A branch with that name exists, so the ref may be a documented moving-branch pin.
    Exists,
    /// No branch has that name.
    Absent,
}

/// Whether a probe pass changed what an ecosystem would show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbeEffect {
    /// Nothing observable changed.
    #[default]
    Unchanged,
    /// New evidence landed; diagnostics, hover and code actions must be regenerated.
    Republish,
    /// A probe changed how the manifest must be parsed; the document must be re-parsed.
    Reparse,
}

impl ProbeEffect {
    /// The stronger of two effects: [`Self::Reparse`] over [`Self::Republish`] over
    /// [`Self::Unchanged`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::ProbeEffect::{Republish, Reparse, Unchanged};
    ///
    /// assert_eq!(Unchanged.max(Republish), Republish);
    /// assert_eq!(Reparse.max(Republish), Reparse);
    /// ```
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        match (self, other) {
            (Self::Reparse, _) | (_, Self::Reparse) => Self::Reparse,
            (Self::Republish, _) | (_, Self::Republish) => Self::Republish,
            (Self::Unchanged, Self::Unchanged) => Self::Unchanged,
        }
    }
}

/// When, relative to the registry fetch of a document, a probe runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePhase {
    /// Before the fetch, for probes that decide what the fetch asks for (Swift's SCM-to-registry
    /// identity lookups).
    PreFetch,
    /// After the fetch, for probes that need the fetched tag index (GitHub Actions, GitLab CI).
    PostFetch,
}

/// The outcome of one [`Ecosystem::background_probes`](crate::Ecosystem::background_probes)
/// pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeReport {
    /// What changed.
    pub effect: ProbeEffect,
    /// Requests actually sent.
    pub issued: usize,
    /// Probes skipped because the rate budget denied a permit.
    pub skipped_over_budget: usize,
    /// Probes that ended without an authoritative answer.
    pub inconclusive: usize,
    /// Registry identity lookups (Swift's SCM-to-registry swap) that ended without an answer.
    ///
    /// Counted apart from [`Self::inconclusive`]: the CLI reports them in their own note and
    /// they say nothing about the rate budget of ref probes, so [`Self::unanswered`] excludes
    /// them.
    pub incomplete_identity_lookups: usize,
}

impl ProbeReport {
    /// The report of two passes taken together: the stronger effect and the summed counts.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{ProbeEffect, ProbeReport};
    ///
    /// let a = ProbeReport { effect: ProbeEffect::Republish, issued: 2, ..ProbeReport::default() };
    /// let b = ProbeReport { inconclusive: 1, ..ProbeReport::default() };
    /// let merged = a.merge(b);
    /// assert_eq!(merged.effect, ProbeEffect::Republish);
    /// assert_eq!((merged.issued, merged.inconclusive), (2, 1));
    /// let lookups = ProbeReport { incomplete_identity_lookups: 2, ..ProbeReport::default() };
    /// assert_eq!(merged.merge(lookups).incomplete_identity_lookups, 2);
    /// assert_eq!(lookups.unanswered(), 0);
    /// ```
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self {
            effect: self.effect.max(other.effect),
            issued: self.issued + other.issued,
            skipped_over_budget: self.skipped_over_budget + other.skipped_over_budget,
            inconclusive: self.inconclusive + other.inconclusive,
            incomplete_identity_lookups: self.incomplete_identity_lookups
                + other.incomplete_identity_lookups,
        }
    }

    /// Probes that produced no answer, which the CLI mentions in one stderr note.
    #[must_use]
    pub const fn unanswered(&self) -> usize {
        self.skipped_over_budget + self.inconclusive
    }
}

/// A bounded map that evicts its least recently used entry and marks entries stale after a TTL.
///
/// Stale-while-revalidate: [`Self::get`] keeps serving the last authoritative answer after its
/// TTL, because dropping it would flip a proven pin back to "outdated" (and let update-all
/// downgrade it) merely because the document sat idle. [`Self::get_fresh`] is what a prober
/// asks, so a stale entry is re-probed; a probe without an authoritative answer never replaces
/// it.
///
/// The store behind [`BranchEvidenceStore`] and [`CommitEvidenceStore`]. Reads and writes take
/// one short lock and never block on I/O.
#[derive(Debug)]
pub struct EvidenceStore<K, V> {
    capacity: usize,
    ttl: Option<Duration>,
    inner: Mutex<StoreInner<K, V>>,
}

#[derive(Debug, Clone, Copy)]
enum Freshness {
    Any,
    Fresh,
}

#[derive(Debug)]
struct StoreInner<K, V> {
    entries: HashMap<K, Slot<V>>,
    tick: u64,
}

#[derive(Debug)]
struct Slot<V> {
    value: V,
    stored: Instant,
    used: u64,
}

impl<K: Eq + Hash + Clone, V: Clone> EvidenceStore<K, V> {
    /// A store of at most `capacity` entries whose entries expire after `ttl` when given.
    #[must_use]
    pub fn new(capacity: usize, ttl: Option<Duration>) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            inner: Mutex::new(StoreInner {
                entries: HashMap::new(),
                tick: 0,
            }),
        }
    }

    /// The stored value for `key`, refreshing its recency, whether or not its TTL has passed.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<V> {
        self.read_at(key, Instant::now(), Freshness::Any)
    }

    /// The stored value for `key` only while its TTL has not passed: `None` for an absent or
    /// stale entry, which is what tells a prober to ask again.
    #[must_use]
    pub fn get_fresh(&self, key: &K) -> Option<V> {
        self.read_at(key, Instant::now(), Freshness::Fresh)
    }

    fn read_at(&self, key: &K, now: Instant, freshness: Freshness) -> Option<V> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.tick += 1;
        let tick = inner.tick;
        let slot = inner.entries.get_mut(key)?;
        let stale = self
            .ttl
            .is_some_and(|ttl| now.saturating_duration_since(slot.stored) >= ttl);
        match freshness {
            Freshness::Fresh if stale => None,
            Freshness::Fresh | Freshness::Any => {
                slot.used = tick;
                Some(slot.value.clone())
            }
        }
    }

    /// Stores `value` under `key`, evicting the least recently used entry when full, and makes
    /// it fresh. Returns whether the stored value differs from what was there (a new key or a
    /// changed value): re-confirming a stale answer is no change.
    pub fn insert(&self, key: K, value: V) -> bool
    where
        V: PartialEq,
    {
        self.insert_at(key, value, Instant::now())
    }

    fn insert_at(&self, key: K, value: V, now: Instant) -> bool
    where
        V: PartialEq,
    {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.tick += 1;
        let tick = inner.tick;
        let changed = inner
            .entries
            .get(&key)
            .is_none_or(|previous| previous.value != value);
        if !inner.entries.contains_key(&key) && inner.entries.len() >= self.capacity {
            let oldest = inner
                .entries
                .iter()
                .min_by_key(|(_, slot)| slot.used)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                inner.entries.remove(&oldest);
            }
        }
        inner.entries.insert(
            key,
            Slot {
                value,
                stored: now,
                used: tick,
            },
        );
        changed
    }

    /// Number of stored entries, expired ones included until read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    /// Whether no entry is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BranchKey {
    repository: NormalizedName,
    git_ref: ProbeRef,
}

/// Branch evidence per (normalized repository, ref), stale after the TTL.
///
/// Keyed by [`NormalizedName`] so `Actions/Checkout` and `actions/checkout` probe once. A
/// branch can be created or deleted, so entries expire instead of being memoized forever.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use deps_core::lsp_helpers::{BranchEvidence, BranchEvidenceStore, NormalizeName, PackageNaming, ProbeRef};
/// use deps_core::PackageName;
///
/// struct Lowercase;
/// impl PackageNaming for Lowercase {
///     fn normalized_spelling(&self, name: &PackageName) -> String { name.as_str().to_lowercase() }
/// }
///
/// let store = BranchEvidenceStore::new(Duration::from_secs(3600));
/// let repo = Lowercase.normalize_package_name(&PackageName::new("Actions/Checkout"));
/// let git_ref = ProbeRef::parse("v40").unwrap();
/// assert!(store.get(&repo, &git_ref).is_none());
/// assert!(store.record(repo.clone(), git_ref.clone(), BranchEvidence::Absent));
/// assert_eq!(store.get(&repo, &git_ref), Some(BranchEvidence::Absent));
/// assert!(!store.record(repo, git_ref, BranchEvidence::Absent));
/// ```
#[derive(Debug)]
pub struct BranchEvidenceStore(EvidenceStore<BranchKey, BranchEvidence>);

impl BranchEvidenceStore {
    /// An empty store whose entries expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self(EvidenceStore::new(EVIDENCE_STORE_CAPACITY, Some(ttl)))
    }

    /// The last authoritative evidence for `git_ref` in `repository`, stale or not.
    #[must_use]
    pub fn get(&self, repository: &NormalizedName, git_ref: &ProbeRef) -> Option<BranchEvidence> {
        self.0.get(&Self::key(repository, git_ref))
    }

    /// The evidence for `git_ref` in `repository` while its TTL has not passed; `None` asks a
    /// prober to refresh it.
    #[must_use]
    pub fn get_fresh(
        &self,
        repository: &NormalizedName,
        git_ref: &ProbeRef,
    ) -> Option<BranchEvidence> {
        self.0.get_fresh(&Self::key(repository, git_ref))
    }

    fn key(repository: &NormalizedName, git_ref: &ProbeRef) -> BranchKey {
        BranchKey {
            repository: repository.clone(),
            git_ref: git_ref.clone(),
        }
    }

    /// Records an authoritative answer; returns whether it changed what was known (the cue to
    /// report [`ProbeEffect::Republish`]).
    pub fn record(
        &self,
        repository: NormalizedName,
        git_ref: ProbeRef,
        evidence: BranchEvidence,
    ) -> bool {
        self.0.insert(
            BranchKey {
                repository,
                git_ref,
            },
            evidence,
        )
    }
}

/// Whether a commit pin descends from the latest release commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitLineage {
    /// The forge reports the pin ahead of the latest release; `ahead_by` is unknown on GitLab.
    AheadOfLatest {
        /// Commits the pin is ahead of the release, when the forge reports it.
        ahead_by: Option<u32>,
    },
    /// The pin is not ahead of the latest release (behind, diverged or identical).
    NotAhead,
}

/// Whether a commit pin is reachable from the repository's default branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultBranchMembership {
    /// The pin lies on the default branch's history, so it belongs to the project.
    Reachable,
    /// Reachability was not proven (ahead of HEAD, diverged, or anything else).
    NotProven,
}

/// Largest compare response a lineage or membership probe accepts.
///
/// With `per_page=1&page=2` a compare answer is about 13 KiB (`files` is empty); anything bigger
/// is not the endpoint's summary and is inconclusive.
pub const COMPARE_BODY_LIMIT: BodyLimit = BodyLimit::new(256 * 1024);

/// The `status` of a GitHub compare response, parsed to a closed set.
///
/// A status text outside it is not a variant: [`CompareSummary::parse`] returns `None`, so an
/// unknown status is inconclusive instead of being guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareStatus {
    /// The head is ahead of the base.
    Ahead,
    /// The head is behind the base.
    Behind,
    /// Base and head each have commits the other lacks.
    Diverged,
    /// Base and head are the same commit.
    Identical,
}

/// The two fields of a compare response a probe reads.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommitLineage, CompareStatus, CompareSummary};
///
/// let body = br#"{"status":"ahead","ahead_by":3,"behind_by":0,"files":[]}"#;
/// let summary = CompareSummary::parse(body).unwrap();
/// assert_eq!(summary.status, CompareStatus::Ahead);
/// assert_eq!(CommitLineage::from_compare(summary), CommitLineage::AheadOfLatest { ahead_by: Some(3) });
/// assert!(CompareSummary::parse(br#"{"status":"sideways"}"#).is_none());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareSummary {
    /// How the head relates to the base.
    pub status: CompareStatus,
    /// Commits the head is ahead of the base.
    pub ahead_by: u32,
}

impl CompareSummary {
    /// Reads `body`, or `None` when it is not JSON with a known `status`.
    #[must_use]
    pub fn parse(body: &[u8]) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct Wire<'a> {
            status: &'a str,
            #[serde(default)]
            ahead_by: u32,
        }
        let wire: Wire<'_> = serde_json::from_slice(body).ok()?;
        let status = match wire.status {
            "ahead" => CompareStatus::Ahead,
            "behind" => CompareStatus::Behind,
            "diverged" => CompareStatus::Diverged,
            "identical" => CompareStatus::Identical,
            _ => return None,
        };
        Some(Self {
            status,
            ahead_by: wire.ahead_by,
        })
    }
}

impl CommitLineage {
    /// The lineage of a pin from `compare/{latest_release}...{pin}`: only `ahead` is ahead.
    #[must_use]
    pub const fn from_compare(summary: CompareSummary) -> Self {
        match summary.status {
            CompareStatus::Ahead => Self::AheadOfLatest {
                ahead_by: Some(summary.ahead_by),
            },
            CompareStatus::Behind | CompareStatus::Diverged | CompareStatus::Identical => {
                Self::NotAhead
            }
        }
    }

    /// The lineage of `pin` from GitLab's `merge_base(latest, pin)`: ahead when the merge base
    /// is the release commit and the pin is a different commit. GitLab reports no count.
    #[must_use]
    pub fn from_merge_base(merge_base: &CommitSha, latest: &CommitSha, pin: &CommitSha) -> Self {
        if merge_base == latest && pin != latest {
            Self::AheadOfLatest { ahead_by: None }
        } else {
            Self::NotAhead
        }
    }
}

impl DefaultBranchMembership {
    /// Membership of a pin from `compare/HEAD...{pin}`: the pin is on the default branch when
    /// it is behind or identical to HEAD. Ahead and diverged commits are not proven.
    #[must_use]
    pub const fn from_compare(summary: CompareSummary) -> Self {
        match summary.status {
            CompareStatus::Behind | CompareStatus::Identical => Self::Reachable,
            CompareStatus::Ahead | CompareStatus::Diverged => Self::NotProven,
        }
    }

    /// Membership of `pin` from GitLab's `merge_base(HEAD, pin)`: reachable when the merge base
    /// is the pin itself.
    #[must_use]
    pub fn from_merge_base(merge_base: &CommitSha, pin: &CommitSha) -> Self {
        if merge_base == pin {
            Self::Reachable
        } else {
            Self::NotProven
        }
    }
}

/// The two proofs that a commit pin newer than the latest release is not a downgrade target.
///
/// Lineage alone is not enough: a fork-network commit compares as ahead of a release commit.
/// Reachability from the default branch is what shows the commit belongs to the project, so
/// both are required.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommitEvidence, CommitLineage, DefaultBranchMembership};
///
/// let proven = CommitEvidence {
///     lineage: Some(CommitLineage::AheadOfLatest { ahead_by: Some(3) }),
///     membership: Some(DefaultBranchMembership::Reachable),
/// };
/// assert_eq!(proven.proven_ahead("v4.2.2").unwrap().ahead_by, Some(3));
///
/// let imposter = CommitEvidence { membership: Some(DefaultBranchMembership::NotProven), ..proven };
/// assert!(imposter.proven_ahead("v4.2.2").is_none());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitEvidence {
    /// Lineage against the latest release commit, if probed.
    pub lineage: Option<CommitLineage>,
    /// Reachability from the default branch, if probed.
    pub membership: Option<DefaultBranchMembership>,
}

impl CommitEvidence {
    /// The proof that the pin is ahead of release `latest_tag` and on the default branch, or
    /// `None` unless both [`CommitLineage::AheadOfLatest`] and
    /// [`DefaultBranchMembership::Reachable`] hold.
    #[must_use]
    pub fn proven_ahead(&self, latest_tag: &str) -> Option<AheadProof> {
        match (self.lineage?, self.membership?) {
            (CommitLineage::AheadOfLatest { ahead_by }, DefaultBranchMembership::Reachable) => {
                Some(AheadProof {
                    ahead_by,
                    latest_tag: latest_tag.to_string(),
                })
            }
            (CommitLineage::AheadOfLatest { .. }, DefaultBranchMembership::NotProven)
            | (
                CommitLineage::NotAhead,
                DefaultBranchMembership::Reachable | DefaultBranchMembership::NotProven,
            ) => None,
        }
    }
}

/// A pin proven newer than the latest release and part of the default branch.
///
/// It feeds the status override, the update-all exclusion (update-all only rewrites an
/// `Outdated` pin) and the hover line, see [`HoverProvenance::CommitAheadOfLatestRelease`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AheadProof {
    /// Commits the pin is ahead of the release, when the forge reports it.
    pub ahead_by: Option<u32>,
    /// The latest release tag the pin is ahead of.
    pub latest_tag: String,
}

impl AheadProof {
    /// `status` with a pin the proof covers lifted from `Outdated` to `UpToDate`; any other
    /// status is left alone.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{AheadProof, RequirementStatus};
    ///
    /// let proof = AheadProof { ahead_by: None, latest_tag: "v4.2.2".into() };
    /// assert_eq!(proof.override_status(RequirementStatus::Outdated), RequirementStatus::UpToDate);
    /// assert_eq!(proof.override_status(RequirementStatus::Unresolved), RequirementStatus::Unresolved);
    /// ```
    #[must_use]
    pub const fn override_status(&self, status: RequirementStatus) -> RequirementStatus {
        match status {
            RequirementStatus::Outdated => RequirementStatus::UpToDate,
            RequirementStatus::UpToDate | RequirementStatus::Unresolved => status,
        }
    }

    /// The hover note for this proof.
    #[must_use]
    pub fn hover_provenance(&self) -> HoverProvenance {
        HoverProvenance::CommitAheadOfLatestRelease {
            ahead_by: self.ahead_by,
            latest_tag: self.latest_tag.clone(),
        }
    }
}

/// An extra, provenance-explaining line of a dependency's hover.
///
/// Returned by
/// [`PackageRendering::hover_provenance`](super::PackageRendering::hover_provenance). The
/// variants are exhaustive and carry typed fields, which the hover renderer sanitizes; an
/// ecosystem never supplies markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoverProvenance {
    /// A SHA pin proven newer than the latest release (spec 087).
    CommitAheadOfLatestRelease {
        /// Commits ahead of the release, when known.
        ahead_by: Option<u32>,
        /// The latest release tag.
        latest_tag: String,
    },
    /// A source-control dependency served by a registry identity (spec 088).
    ResolvedViaRegistryIdentity {
        /// The registry identity the dependency was swapped to.
        identity: crate::PackageName,
        /// The source-control URL as written, credential-redacted.
        scm: crate::redact::RedactedUrl,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LineageKey {
    repository: NormalizedName,
    latest: CommitSha,
    pin: CommitSha,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MembershipKey {
    repository: NormalizedName,
    pin: CommitSha,
}

/// Commit lineage and default-branch membership per repository.
///
/// Lineage is keyed by both fixed SHAs and has no expiry: a new latest release changes the key,
/// so the proof is re-evaluated against it. Membership moves with the default branch's HEAD, so
/// it goes stale after the TTL and is re-proven then, but the last answer keeps being served
/// until a probe replaces it.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use deps_core::lsp_helpers::{CommitEvidenceStore, CommitLineage, CommitSha, NormalizeName, PackageNaming};
/// use deps_core::PackageName;
///
/// struct Lowercase;
/// impl PackageNaming for Lowercase {
///     fn normalized_spelling(&self, name: &PackageName) -> String { name.as_str().to_lowercase() }
/// }
///
/// let store = CommitEvidenceStore::new(Duration::from_secs(3600));
/// let repo = Lowercase.normalize_package_name(&PackageName::new("o/r"));
/// let release = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let pin = CommitSha::parse(&"b".repeat(40)).unwrap();
/// store.record_lineage(repo.clone(), release.clone(), pin.clone(), CommitLineage::NotAhead);
/// assert_eq!(store.evidence(&repo, &release, &pin).lineage, Some(CommitLineage::NotAhead));
/// let newer = CommitSha::parse(&"c".repeat(40)).unwrap();
/// assert_eq!(store.evidence(&repo, &newer, &pin).lineage, None);
/// ```
#[derive(Debug)]
pub struct CommitEvidenceStore {
    lineage: EvidenceStore<LineageKey, CommitLineage>,
    membership: EvidenceStore<MembershipKey, DefaultBranchMembership>,
}

impl CommitEvidenceStore {
    /// An empty store whose membership entries expire after `membership_ttl`.
    #[must_use]
    pub fn new(membership_ttl: Duration) -> Self {
        Self {
            lineage: EvidenceStore::new(EVIDENCE_STORE_CAPACITY, None),
            membership: EvidenceStore::new(EVIDENCE_STORE_CAPACITY, Some(membership_ttl)),
        }
    }

    /// Everything stored about `pin` against the release commit `latest` in `repository`.
    #[must_use]
    pub fn evidence(
        &self,
        repository: &NormalizedName,
        latest: &CommitSha,
        pin: &CommitSha,
    ) -> CommitEvidence {
        CommitEvidence {
            lineage: self.lineage(repository, latest, pin),
            membership: self.membership(repository, pin),
        }
    }

    /// The stored lineage of `pin` against `latest`.
    #[must_use]
    pub fn lineage(
        &self,
        repository: &NormalizedName,
        latest: &CommitSha,
        pin: &CommitSha,
    ) -> Option<CommitLineage> {
        self.lineage.get(&LineageKey {
            repository: repository.clone(),
            latest: latest.clone(),
            pin: pin.clone(),
        })
    }

    /// The last authoritative membership of `pin`, stale or not.
    #[must_use]
    pub fn membership(
        &self,
        repository: &NormalizedName,
        pin: &CommitSha,
    ) -> Option<DefaultBranchMembership> {
        self.membership.get(&MembershipKey {
            repository: repository.clone(),
            pin: pin.clone(),
        })
    }

    /// The membership of `pin` while its TTL has not passed; `None` asks a prober to refresh
    /// it (HEAD moves, so membership is re-proven, but never dropped meanwhile).
    #[must_use]
    pub fn membership_fresh(
        &self,
        repository: &NormalizedName,
        pin: &CommitSha,
    ) -> Option<DefaultBranchMembership> {
        self.membership.get_fresh(&MembershipKey {
            repository: repository.clone(),
            pin: pin.clone(),
        })
    }

    /// Records an authoritative lineage; returns whether it changed what was known.
    pub fn record_lineage(
        &self,
        repository: NormalizedName,
        latest: CommitSha,
        pin: CommitSha,
        lineage: CommitLineage,
    ) -> bool {
        self.lineage.insert(
            LineageKey {
                repository,
                latest,
                pin,
            },
            lineage,
        )
    }

    /// Records an authoritative membership; returns whether it changed what was known.
    pub fn record_membership(
        &self,
        repository: NormalizedName,
        pin: CommitSha,
        membership: DefaultBranchMembership,
    ) -> bool {
        self.membership
            .insert(MembershipKey { repository, pin }, membership)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_ref_accepts_plain_tag_shapes() {
        for ok in [
            "v40",
            "v1",
            "5.x",
            "v3-node20",
            "1.2.3-rc.1",
            "v1+build",
            "4",
        ] {
            assert_eq!(ProbeRef::parse(ok).unwrap().as_str(), ok, "{ok}");
        }
    }

    #[test]
    fn probe_ref_rejects_traversal_and_url_metacharacters() {
        for bad in [
            "1/../../../../user",
            "1?x#y",
            "1#y",
            "a%2Fb",
            "1%2e%2e",
            "v1/x",
            "v1..2",
            "v1@{u}",
            "v1 2",
            "v1\n",
            "v1\u{7f}",
            "v1\\x",
            "v1.",
            "v1.lock",
            "-1",
            ".1",
            "..",
            ".",
            "",
            "main",
            "v",
            "ｖ1",
        ] {
            assert!(ProbeRef::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn probe_ref_length_boundary_is_255_bytes() {
        let at_limit = format!("v{}", "1".repeat(254));
        assert_eq!(at_limit.len(), 255);
        assert!(ProbeRef::parse(&at_limit).is_some());
        assert!(ProbeRef::parse(&format!("{at_limit}1")).is_none());
    }

    #[test]
    fn probe_ref_path_segment_is_percent_encoded() {
        let git_ref = ProbeRef::parse("1.0+x").unwrap();
        assert_eq!(git_ref.as_path_segment().to_string(), "1.0%2Bx");
    }

    #[test]
    fn probe_effect_max_is_symmetric_and_ordered() {
        use ProbeEffect::{Reparse, Republish, Unchanged};
        for (a, b, want) in [
            (Unchanged, Unchanged, Unchanged),
            (Unchanged, Republish, Republish),
            (Republish, Reparse, Reparse),
            (Reparse, Unchanged, Reparse),
        ] {
            assert_eq!(a.max(b), want);
            assert_eq!(b.max(a), want);
        }
    }

    #[test]
    fn probe_report_unanswered_counts_budget_and_inconclusive() {
        let report = ProbeReport {
            skipped_over_budget: 2,
            inconclusive: 3,
            issued: 9,
            ..ProbeReport::default()
        };
        assert_eq!(report.unanswered(), 5);
    }

    fn store(capacity: usize, ttl: Option<Duration>) -> EvidenceStore<u32, u32> {
        EvidenceStore::new(capacity, ttl)
    }

    #[test]
    fn store_evicts_least_recently_used_at_capacity() {
        let s = store(2, None);
        s.insert(1, 10);
        s.insert(2, 20);
        assert_eq!(s.get(&1), Some(10));
        s.insert(3, 30);
        assert_eq!(s.get(&2), None);
        assert_eq!(s.get(&1), Some(10));
        assert_eq!(s.get(&3), Some(30));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn store_overwriting_a_key_at_capacity_evicts_nothing() {
        let s = store(2, None);
        s.insert(1, 10);
        s.insert(2, 20);
        assert!(s.insert(1, 11));
        assert!(!s.insert(1, 11));
        assert_eq!(s.get(&2), Some(20));
    }

    #[test]
    fn store_serves_stale_entries_but_does_not_report_them_fresh() {
        let s = store(4, Some(Duration::from_secs(60)));
        let start = Instant::now();
        s.insert_at(1, 10, start);
        let at = |secs| start + Duration::from_secs(secs);
        assert_eq!(s.read_at(&1, at(59), Freshness::Fresh), Some(10));
        assert_eq!(s.read_at(&1, at(60), Freshness::Fresh), None);
        assert_eq!(
            s.read_at(&1, at(60), Freshness::Any),
            Some(10),
            "stale-while-revalidate"
        );
        assert_eq!(s.len(), 1, "expiry removes nothing");
    }

    #[test]
    fn reconfirming_a_stale_answer_refreshes_it_without_reporting_a_change() {
        let s = store(4, Some(Duration::from_secs(60)));
        let start = Instant::now();
        s.insert_at(1, 10, start);
        assert!(!s.insert_at(1, 10, start + Duration::from_secs(61)));
        assert_eq!(
            s.read_at(&1, start + Duration::from_secs(62), Freshness::Fresh),
            Some(10)
        );
        assert!(
            s.insert_at(1, 11, start + Duration::from_secs(63)),
            "a changed answer is a change"
        );
    }

    #[test]
    fn store_without_ttl_never_expires() {
        let s = store(4, None);
        let start = Instant::now();
        s.insert_at(1, 10, start);
        assert_eq!(
            s.read_at(&1, start + Duration::from_hours(24 * 365), Freshness::Fresh),
            Some(10)
        );
    }

    #[test]
    fn store_is_bounded_by_the_requested_capacity() {
        let s = store(8, None);
        for i in 0..100 {
            s.insert(i, i);
        }
        assert_eq!(s.len(), 8);
    }

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    const AHEAD: CommitLineage = CommitLineage::AheadOfLatest { ahead_by: Some(2) };

    #[test]
    fn proven_ahead_truth_table() {
        use CommitLineage::NotAhead;
        use DefaultBranchMembership::{NotProven, Reachable};
        let proof = |lineage, membership| {
            CommitEvidence {
                lineage,
                membership,
            }
            .proven_ahead("v1")
            .is_some()
        };
        assert!(proof(Some(AHEAD), Some(Reachable)));
        assert!(!proof(Some(AHEAD), Some(NotProven)));
        assert!(!proof(Some(AHEAD), None));
        assert!(!proof(Some(NotAhead), Some(Reachable)));
        assert!(!proof(Some(NotAhead), Some(NotProven)));
        assert!(!proof(None, Some(Reachable)));
        assert!(!proof(None, None));
    }

    #[test]
    fn ahead_proof_only_lifts_an_outdated_status() {
        let proof = AheadProof {
            ahead_by: Some(1),
            latest_tag: "v1".into(),
        };
        assert_eq!(
            proof.override_status(RequirementStatus::Outdated),
            RequirementStatus::UpToDate
        );
        assert_eq!(
            proof.override_status(RequirementStatus::UpToDate),
            RequirementStatus::UpToDate
        );
        assert_eq!(
            proof.override_status(RequirementStatus::Unresolved),
            RequirementStatus::Unresolved
        );
    }

    fn repo(name: &str) -> NormalizedName {
        NormalizedName::for_test(name)
    }

    #[test]
    fn lineage_key_changes_with_the_latest_release_commit() {
        let s = CommitEvidenceStore::new(Duration::from_secs(60));
        s.record_lineage(repo("o/r"), sha('a'), sha('e'), AHEAD);
        assert_eq!(s.lineage(&repo("o/r"), &sha('a'), &sha('e')), Some(AHEAD));
        assert_eq!(s.lineage(&repo("o/r"), &sha('b'), &sha('e')), None);
    }

    #[test]
    fn lineage_has_no_ttl_but_membership_goes_stale_and_is_still_served() {
        let s = CommitEvidenceStore::new(Duration::from_secs(60));
        let start = Instant::now();
        let later = start + Duration::from_secs(61);
        let lineage_key = LineageKey {
            repository: repo("o/r"),
            latest: sha('a'),
            pin: sha('e'),
        };
        s.lineage.insert_at(lineage_key.clone(), AHEAD, start);
        assert_eq!(
            s.lineage.read_at(&lineage_key, later, Freshness::Fresh),
            Some(AHEAD)
        );
        let membership_key = MembershipKey {
            repository: repo("o/r"),
            pin: sha('e'),
        };
        s.membership.insert_at(
            membership_key.clone(),
            DefaultBranchMembership::Reachable,
            start,
        );
        assert_eq!(
            s.membership
                .read_at(&membership_key, later, Freshness::Fresh),
            None
        );
        assert_eq!(
            s.membership.read_at(&membership_key, later, Freshness::Any),
            Some(DefaultBranchMembership::Reachable),
            "the stale answer is still served"
        );
    }

    #[test]
    fn evidence_stores_share_one_entry_for_one_normalized_repository() {
        let s = BranchEvidenceStore::new(Duration::from_secs(60));
        let git_ref = ProbeRef::parse("v40").unwrap();
        assert!(s.record(repo("o/r"), git_ref.clone(), BranchEvidence::Absent));
        assert_eq!(s.get(&repo("o/r"), &git_ref), Some(BranchEvidence::Absent));
        assert_eq!(s.get(&repo("o/other"), &git_ref), None);
    }
}
