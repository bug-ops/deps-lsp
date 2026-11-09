//! One background probe pass over the git refs and commit pins of a document, shared by every
//! git-tags ecosystem (GitHub Actions, GitLab CI).
//!
//! An ecosystem decides *what* is worth asking through [`ProbeStores::question_for`] and *how* to
//! ask its forge (a [`ProbeBackend`], answering through [`branch_answer`] and
//! [`parsed_answer`]); this module owns the rest: store hits draw no permit, permits come from
//! one [`ProbeAllowance`] in priority order (lineage, then membership, then branch), requests run
//! at most [`PROBE_CONCURRENCY`] at a time, only authoritative answers are stored, and every
//! repository whose evidence changed is announced once.

use std::collections::HashSet;
use std::time::Duration;

use dashmap::{DashMap, DashSet};
use futures::StreamExt;
use futures::stream;

use super::{
    AheadProof, BranchEvidence, BranchEvidenceStore, CommitEvidenceStore, CommitLineage, CommitSha,
    DefaultBranchMembership, GitPinView, LowercaseNaming, NormalizeName, PinResolution,
    ProbeEffect, ProbeRef, ProbeReport, TagIndex, TagName, UnpublishedRef,
};
use crate::ecosystem::BoxFuture;
use crate::pagination::ListCoverage;
use crate::rate_limit::ProbeAllowance;
use crate::single_flight::InFlightGuard;
use crate::tag_index_refresh::RefreshSender;
use crate::{DepsError, NormalizedName, PackageName};

/// Requests of one pass in flight at once.
pub const PROBE_CONCURRENCY: usize = 4;

/// How long branch evidence and default-branch membership stay valid.
///
/// ASSUMPTION: the tag index itself has no TTL (it is revalidated on every fetch), so one hour
/// stands in for "the tag-index TTL" of specs 086/087.
pub const EVIDENCE_TTL: Duration = Duration::from_hours(1);

/// Latest-release records kept per ecosystem.
const MAX_LATEST_RELEASES: usize = 256;

/// The newest stable release of a repository, as the last tags fetch saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRelease {
    /// The tag name as published.
    pub tag: TagName,
    /// The commit the tag points at.
    pub commit: CommitSha,
}

/// A published tag of a git forge, as far as [`ProbeStores::record_latest_from`] needs to read
/// it.
pub trait GitTagVersion {
    /// The tag name as published.
    fn tag(&self) -> &str;

    /// Whether the tag is a prerelease, which never counts as the latest release.
    fn is_prerelease(&self) -> bool;

    /// The commit the tag points at, when the forge reported it.
    fn commit(&self) -> Option<&CommitSha>;
}

/// The evidence an ecosystem's probes gather, shared by its registry (which fills it), its
/// formatter (which reads it synchronously) and its probe pass.
///
/// # Examples
///
/// ```
/// use deps_core::NormalizedName;
/// use deps_core::lsp_helpers::ProbeStores;
///
/// let stores = ProbeStores::default();
/// assert!(stores.latest(&NormalizedName::for_test("o/r")).is_none());
/// ```
#[derive(Debug)]
pub struct ProbeStores {
    /// Branch evidence per (repository, ref).
    pub branches: BranchEvidenceStore,
    /// Commit lineage and default-branch membership per repository.
    pub commits: CommitEvidenceStore,
    latest: DashMap<NormalizedName, LatestRelease>,
    in_flight: DashSet<ProbeKey>,
}

/// One question a pass asks, as the single-flight set knows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProbeKey {
    Lineage(NormalizedName, CommitSha, CommitSha),
    Membership(NormalizedName, CommitSha),
    Branch(NormalizedName, ProbeRef),
}

/// Proof that this pass is the only one asking its question right now; released on drop.
type Claim<'a> = InFlightGuard<'a, ProbeKey, DashSet<ProbeKey>>;

impl Default for ProbeStores {
    fn default() -> Self {
        Self::new(EVIDENCE_TTL)
    }
}

impl ProbeStores {
    /// Empty stores whose branch and membership entries expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            branches: BranchEvidenceStore::new(ttl),
            commits: CommitEvidenceStore::new(ttl),
            latest: DashMap::new(),
            in_flight: DashSet::new(),
        }
    }

    /// Claims `key` for the calling pass, or `None` when another pass (of any document) is
    /// already asking the same question: one request and one permit per question, whatever
    /// the number of open documents that reference it.
    fn claim(&self, key: ProbeKey) -> Option<Claim<'_>> {
        self.in_flight
            .insert(key.clone())
            .then(|| InFlightGuard::new(&self.in_flight, key))
    }

    /// Records the newest stable release of `repository`.
    pub fn record_latest(&self, repository: NormalizedName, latest: LatestRelease) {
        if !self.latest.contains_key(&repository) {
            crate::cache_policy::evict_arbitrary_if_full(&self.latest, MAX_LATEST_RELEASES);
        }
        self.latest.insert(repository, latest);
    }

    /// Records the newest stable release among `newest_first`, keyed by `package` normalized
    /// the way every other key of these stores is.
    ///
    /// Records nothing when every tag is a prerelease, or when the newest stable one carries
    /// no commit: an older release must not stand in for it.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::lsp_helpers::{
    ///     CommitSha, GitTagVersion, LowercaseNaming, NormalizeName, ProbeStores,
    /// };
    ///
    /// struct Tag {
    ///     name: &'static str,
    ///     prerelease: bool,
    ///     sha: CommitSha,
    /// }
    ///
    /// impl GitTagVersion for Tag {
    ///     fn tag(&self) -> &str {
    ///         self.name
    ///     }
    ///     fn is_prerelease(&self) -> bool {
    ///         self.prerelease
    ///     }
    ///     fn commit(&self) -> Option<&CommitSha> {
    ///         Some(&self.sha)
    ///     }
    /// }
    ///
    /// let sha = |c: char| CommitSha::parse(&c.to_string().repeat(40)).unwrap();
    /// let tags = [
    ///     Tag { name: "v5.0.0-rc1", prerelease: true, sha: sha('b') },
    ///     Tag { name: "v4.2.2", prerelease: false, sha: sha('a') },
    /// ];
    /// let stores = ProbeStores::default();
    /// let package = PackageName::new("Actions/Checkout");
    /// stores.record_latest_from(&package, &tags);
    ///
    /// let repository = LowercaseNaming.normalize_package_name(&package);
    /// let latest = stores.latest(&repository).unwrap();
    /// assert_eq!(latest.tag.as_str(), "v4.2.2");
    /// assert_eq!(latest.commit, sha('a'));
    /// ```
    pub fn record_latest_from<V: GitTagVersion>(&self, package: &PackageName, newest_first: &[V]) {
        let Some(latest) = newest_first.iter().find(|tag| !tag.is_prerelease()) else {
            return;
        };
        let Some(commit) = latest.commit() else {
            return;
        };
        self.record_latest(
            LowercaseNaming.normalize_package_name(package),
            LatestRelease {
                tag: TagName::from_published(latest.tag().to_string()),
                commit: commit.clone(),
            },
        );
    }

    /// The newest stable release of `repository` the last fetch saw.
    #[must_use]
    pub fn latest(&self, repository: &NormalizedName) -> Option<LatestRelease> {
        self.latest.get(repository).map(|entry| entry.clone())
    }

    /// The question a pin of `package` asks the forge, given the complete tag `index` of its
    /// repository; `None` when the pin asks nothing.
    ///
    /// A partial tag ref that a complete index does not list may be a branch, so it asks for the
    /// branch; a commentless SHA pin that no tag names asks to be proven ahead of the latest
    /// release, which needs a recorded latest release. Anything the shared safety checks refuse
    /// ([`ProbeRef::parse`]) asks nothing. The repository key is normalized here, so every key
    /// of these stores shares one naming.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    /// use deps_core::lsp_helpers::{CommitSha, GitPinView, ProbeQuestion, ProbeStores, TagIndex};
    ///
    /// let stores = ProbeStores::default();
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v4.3.1", &sha)]);
    /// let package = PackageName::new("actions/checkout");
    ///
    /// let partial = stores.question_for(&package, &index, GitPinView::Tag { written: "v40" });
    /// # use std::assert_matches;
    /// assert_matches!(partial, Some(ProbeQuestion::Branch(_)));
    ///
    /// let published = stores.question_for(&package, &index, GitPinView::Tag { written: "v4.3.1" });
    /// assert!(published.is_none());
    /// assert!(stores.question_for(&package, &index, GitPinView::Other).is_none());
    /// ```
    #[must_use]
    pub fn question_for(
        &self,
        package: &PackageName,
        index: &TagIndex,
        pin: GitPinView<'_>,
    ) -> Option<ProbeQuestion> {
        let repository = LowercaseNaming.normalize_package_name(package);
        match pin {
            GitPinView::Tag { written } => {
                if index.unpublished_tag_ref(written) != Some(UnpublishedRef::Partial) {
                    return None;
                }
                Some(ProbeQuestion::Branch(BranchProbe {
                    repository,
                    package: package.clone(),
                    git_ref: ProbeRef::parse(written)?,
                }))
            }
            GitPinView::Sha { sha, comment: None } => {
                if index.pin_resolution(sha, None) != PinResolution::Untagged {
                    return None;
                }
                let latest = self.latest(&repository)?;
                Some(ProbeQuestion::Commit(CommitProbe {
                    repository,
                    package: package.clone(),
                    latest: latest.commit,
                    pin: sha.clone(),
                }))
            }
            GitPinView::Sha {
                comment: Some(_), ..
            }
            | GitPinView::Other => None,
        }
    }

    /// [`Self::proof`] for a pin `index` can speak for: only a commit no tag names can be ahead
    /// of the latest release, and only a complete tag list proves that no tag names it.
    #[must_use]
    pub fn proof_for_untagged(
        &self,
        repository: &NormalizedName,
        index: &TagIndex,
        pin: &CommitSha,
    ) -> Option<AheadProof> {
        if index.coverage() != ListCoverage::Complete || index.tag_for_sha(pin).is_some() {
            return None;
        }
        self.proof(repository, pin)
    }

    /// The proof that `pin` is ahead of the latest release of `repository` and on its default
    /// branch, when both probes have stored it.
    #[must_use]
    pub fn proof(&self, repository: &NormalizedName, pin: &CommitSha) -> Option<AheadProof> {
        let latest = self.latest(repository)?;
        self.commits
            .evidence(repository, &latest.commit, pin)
            .proven_ahead(&latest.tag)
    }
}

/// A commit pin worth proving ahead of the latest release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitProbe {
    /// The normalized repository, the evidence key.
    pub repository: NormalizedName,
    /// The repository as the forge is asked about it.
    pub package: PackageName,
    /// The commit of the latest release.
    pub latest: CommitSha,
    /// The pinned commit.
    pub pin: CommitSha,
}

/// A partial tag ref worth asking the forge about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchProbe {
    /// The normalized repository, the evidence key.
    pub repository: NormalizedName,
    /// The repository as the forge is asked about it.
    pub package: PackageName,
    /// The ref, already checked for a safe request URL.
    pub git_ref: ProbeRef,
}

/// One question a pin asks its forge, as decided by [`ProbeStores::question_for`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeQuestion {
    /// Whether a partial tag ref is a branch.
    Branch(BranchProbe),
    /// Whether a commit pin is ahead of the latest release.
    Commit(CommitProbe),
}

/// Everything one document asks the forge, built by its ecosystem.
#[derive(Debug, Default)]
pub struct ProbePlan {
    /// Commit pins to prove.
    pub commits: Vec<CommitProbe>,
    /// Partial refs to ask about.
    pub branches: Vec<BranchProbe>,
}

impl ProbePlan {
    /// Whether nothing is to be asked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.branches.is_empty()
    }

    /// Adds `question` to the plan.
    pub fn push(&mut self, question: ProbeQuestion) {
        match question {
            ProbeQuestion::Branch(probe) => self.branches.push(probe),
            ProbeQuestion::Commit(probe) => self.commits.push(probe),
        }
    }
}

/// The answer to one probe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAnswer<T> {
    /// The forge answered authoritatively.
    Answer(T),
    /// Rate limit, server error, timeout, overflow, empty repository or any other response that
    /// proves nothing: nothing is stored.
    Inconclusive,
}

/// Which request an answer belongs to, for the log line behind an inconclusive one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// The branch-exists request.
    Branch,
    /// The ahead-of-latest-release request.
    Lineage,
    /// The reachable-from-default-branch request.
    Membership,
}

impl ProbeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Branch => "branch",
            Self::Lineage => "lineage",
            Self::Membership => "membership",
        }
    }
}

/// The answer to a branch request: a success means the branch exists, `404` is the only
/// authoritative negative, and every other failure is inconclusive and logged.
///
/// # Examples
///
/// ```
/// use deps_core::DepsError;
/// use deps_core::lsp_helpers::{BranchEvidence, ProbeAnswer, branch_answer};
///
/// assert_eq!(
///     branch_answer(Ok(())),
///     ProbeAnswer::Answer(BranchEvidence::Exists)
/// );
/// let missing = DepsError::HttpStatus { url: "https://forge.example/b".into(), status: 404 };
/// assert_eq!(
///     branch_answer::<()>(Err(missing)),
///     ProbeAnswer::Answer(BranchEvidence::Absent)
/// );
/// let down = DepsError::HttpStatus { url: "https://forge.example/b".into(), status: 503 };
/// assert_eq!(branch_answer::<()>(Err(down)), ProbeAnswer::Inconclusive);
/// ```
#[must_use]
pub fn branch_answer<T>(result: Result<T, DepsError>) -> ProbeAnswer<BranchEvidence> {
    match result {
        Ok(_) => ProbeAnswer::Answer(BranchEvidence::Exists),
        Err(DepsError::HttpStatus { status: 404, .. }) => {
            ProbeAnswer::Answer(BranchEvidence::Absent)
        }
        Err(error) => inconclusive(ProbeKind::Branch, &error),
    }
}

/// The answer to a lineage or membership request: `parse` reads the response body, and a
/// failed request or an unreadable body is inconclusive and logged.
///
/// # Examples
///
/// ```
/// use deps_core::DepsError;
/// use deps_core::lsp_helpers::{ProbeAnswer, ProbeKind, parsed_answer};
///
/// let read = |body: &str| body.parse::<u32>().ok();
/// assert_eq!(
///     parsed_answer(ProbeKind::Lineage, Ok("3"), read),
///     ProbeAnswer::Answer(3)
/// );
/// assert_eq!(
///     parsed_answer(ProbeKind::Lineage, Ok("<html>"), read),
///     ProbeAnswer::Inconclusive
/// );
/// let down = DepsError::HttpStatus { url: "https://forge.example/c".into(), status: 503 };
/// assert_eq!(
///     parsed_answer(ProbeKind::Membership, Err(down), read),
///     ProbeAnswer::Inconclusive
/// );
/// ```
#[must_use]
pub fn parsed_answer<B, E>(
    kind: ProbeKind,
    result: Result<B, DepsError>,
    parse: impl FnOnce(B) -> Option<E>,
) -> ProbeAnswer<E> {
    match result {
        Ok(body) => parse(body).map_or_else(
            || {
                tracing::debug!(
                    probe = kind.as_str(),
                    "probe response unreadable, inconclusive"
                );
                ProbeAnswer::Inconclusive
            },
            ProbeAnswer::Answer,
        ),
        Err(error) => inconclusive(kind, &error),
    }
}

fn inconclusive<T>(kind: ProbeKind, error: &DepsError) -> ProbeAnswer<T> {
    tracing::debug!(%error, probe = kind.as_str(), "probe inconclusive");
    ProbeAnswer::Inconclusive
}

/// How an ecosystem asks its forge. Every method issues exactly one request.
pub trait ProbeBackend: Send + Sync {
    /// Whether `package` has a branch named `git_ref`.
    fn branch<'a>(
        &'a self,
        package: &'a PackageName,
        git_ref: &'a ProbeRef,
    ) -> BoxFuture<'a, ProbeAnswer<BranchEvidence>>;

    /// Whether `pin` is ahead of the release commit `latest`.
    fn lineage<'a>(
        &'a self,
        package: &'a PackageName,
        latest: &'a CommitSha,
        pin: &'a CommitSha,
    ) -> BoxFuture<'a, ProbeAnswer<CommitLineage>>;

    /// Whether `pin` is reachable from the default branch.
    fn membership<'a>(
        &'a self,
        package: &'a PackageName,
        pin: &'a CommitSha,
    ) -> BoxFuture<'a, ProbeAnswer<DefaultBranchMembership>>;
}

/// What a pass found, beyond the [`ProbeReport`].
#[derive(Debug, Default)]
pub struct ProbeOutcome {
    /// The report counts and effect.
    pub report: ProbeReport,
    /// Repositories whose stored evidence changed, each once.
    pub changed: Vec<NormalizedName>,
}

/// Awaits `requests` with at most [`PROBE_CONCURRENCY`] in flight, in completion order.
async fn run_bounded<F: Future>(requests: Vec<F>) -> Vec<F::Output> {
    stream::iter(requests)
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await
}

/// What distinguishes one phase of a pass from the others; [`run_phase`] owns the rest.
trait ProbePhaseKind {
    type Probe: Sync;
    type Answer: Send;

    fn key(probe: &Self::Probe) -> ProbeKey;

    fn repository(probe: &Self::Probe) -> &NormalizedName;

    /// Whether the phase asks about `probe` at all.
    fn eligible(stores: &ProbeStores, probe: &Self::Probe) -> bool;

    /// Whether the store already holds a fresh answer to `probe`.
    fn settled(stores: &ProbeStores, probe: &Self::Probe) -> bool;

    fn ask<'a>(
        backend: &'a dyn ProbeBackend,
        probe: &'a Self::Probe,
    ) -> BoxFuture<'a, ProbeAnswer<Self::Answer>>;

    /// Stores `answer`, and whether the stored evidence changed.
    fn record(stores: &ProbeStores, probe: &Self::Probe, answer: Self::Answer) -> bool;
}

struct LineagePhase;
struct MembershipPhase;
struct BranchPhase;

impl ProbePhaseKind for LineagePhase {
    type Probe = CommitProbe;
    type Answer = CommitLineage;

    fn repository(probe: &CommitProbe) -> &NormalizedName {
        &probe.repository
    }

    fn key(probe: &CommitProbe) -> ProbeKey {
        ProbeKey::Lineage(
            probe.repository.clone(),
            probe.latest.clone(),
            probe.pin.clone(),
        )
    }

    fn eligible(_: &ProbeStores, probe: &CommitProbe) -> bool {
        probe.latest != probe.pin
    }

    fn settled(stores: &ProbeStores, probe: &CommitProbe) -> bool {
        stores
            .commits
            .lineage(&probe.repository, &probe.latest, &probe.pin)
            .is_some()
    }

    fn ask<'a>(
        backend: &'a dyn ProbeBackend,
        probe: &'a CommitProbe,
    ) -> BoxFuture<'a, ProbeAnswer<CommitLineage>> {
        backend.lineage(&probe.package, &probe.latest, &probe.pin)
    }

    fn record(stores: &ProbeStores, probe: &CommitProbe, answer: CommitLineage) -> bool {
        stores.commits.record_lineage(
            probe.repository.clone(),
            probe.latest.clone(),
            probe.pin.clone(),
            answer,
        )
    }
}

impl ProbePhaseKind for MembershipPhase {
    type Probe = CommitProbe;
    type Answer = DefaultBranchMembership;

    fn repository(probe: &CommitProbe) -> &NormalizedName {
        &probe.repository
    }

    fn key(probe: &CommitProbe) -> ProbeKey {
        ProbeKey::Membership(probe.repository.clone(), probe.pin.clone())
    }

    fn eligible(stores: &ProbeStores, probe: &CommitProbe) -> bool {
        matches!(
            stores
                .commits
                .lineage(&probe.repository, &probe.latest, &probe.pin),
            Some(CommitLineage::AheadOfLatest { .. })
        )
    }

    fn settled(stores: &ProbeStores, probe: &CommitProbe) -> bool {
        stores
            .commits
            .membership_fresh(&probe.repository, &probe.pin)
            .is_some()
    }

    fn ask<'a>(
        backend: &'a dyn ProbeBackend,
        probe: &'a CommitProbe,
    ) -> BoxFuture<'a, ProbeAnswer<DefaultBranchMembership>> {
        backend.membership(&probe.package, &probe.pin)
    }

    fn record(stores: &ProbeStores, probe: &CommitProbe, answer: DefaultBranchMembership) -> bool {
        stores
            .commits
            .record_membership(probe.repository.clone(), probe.pin.clone(), answer)
    }
}

impl ProbePhaseKind for BranchPhase {
    type Probe = BranchProbe;
    type Answer = BranchEvidence;

    fn repository(probe: &BranchProbe) -> &NormalizedName {
        &probe.repository
    }

    fn key(probe: &BranchProbe) -> ProbeKey {
        ProbeKey::Branch(probe.repository.clone(), probe.git_ref.clone())
    }

    fn eligible(_: &ProbeStores, _: &BranchProbe) -> bool {
        true
    }

    fn settled(stores: &ProbeStores, probe: &BranchProbe) -> bool {
        stores
            .branches
            .get_fresh(&probe.repository, &probe.git_ref)
            .is_some()
    }

    fn ask<'a>(
        backend: &'a dyn ProbeBackend,
        probe: &'a BranchProbe,
    ) -> BoxFuture<'a, ProbeAnswer<BranchEvidence>> {
        backend.branch(&probe.package, &probe.git_ref)
    }

    fn record(stores: &ProbeStores, probe: &BranchProbe, answer: BranchEvidence) -> bool {
        stores
            .branches
            .record(probe.repository.clone(), probe.git_ref.clone(), answer)
    }
}

// A named generic function, not a closure: a closure returning an `async` block over a `&dyn`
// backend defeats the higher-ranked lifetime inference once the pass is boxed into a `Send`
// future.
async fn ask_one<'a, K: ProbePhaseKind>(
    backend: &'a dyn ProbeBackend,
    probe: &'a K::Probe,
) -> (&'a K::Probe, ProbeAnswer<K::Answer>) {
    (probe, K::ask(backend, probe).await)
}

/// One phase: the questions of `probes` that are eligible, not yet answered and not being asked
/// by another pass, each paid for with a permit, then asked and stored.
async fn run_phase<K: ProbePhaseKind>(
    probes: &[K::Probe],
    backend: &dyn ProbeBackend,
    allowance: &ProbeAllowance,
    stores: &ProbeStores,
    outcome: &mut ProbeOutcome,
) {
    let mut seen = HashSet::new();
    let mut claims = Vec::new();
    let mut requests = Vec::new();
    for probe in probes {
        if !K::eligible(stores, probe) || K::settled(stores, probe) {
            continue;
        }
        let key = K::key(probe);
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some(claim) = stores.claim(key) else {
            continue;
        };
        if K::settled(stores, probe) {
            continue;
        }
        if allowance.try_acquire().is_none() {
            outcome.report.skipped_over_budget += 1;
            continue;
        }
        claims.push(claim);
        requests.push(ask_one::<K>(backend, probe));
    }
    for (probe, answer) in run_bounded(requests).await {
        outcome.report.issued += 1;
        match answer {
            ProbeAnswer::Answer(answer) => {
                if K::record(stores, probe, answer) {
                    outcome.changed.push(K::repository(probe).clone());
                }
            }
            ProbeAnswer::Inconclusive => outcome.report.inconclusive += 1,
        }
    }
    drop(claims);
}

/// Runs `plan` against `backend`, drawing permits from `allowance`, storing authoritative
/// answers in `stores` and announcing every repository whose evidence changed once on
/// `announce`.
///
/// Order within the pass: lineage probes first, then membership probes for the pins found ahead,
/// then branch probes, so scarce permits go to the most valuable proof. A fresh store hit is
/// free, and so is a question another pass (of any document) is already asking: it is claimed
/// in `stores` before a permit is drawn, so N documents referencing one repository spend one
/// permit and send one request. A stale hit is asked again, and a request without an
/// authoritative answer (`inconclusive`) leaves the stale answer in place. A denied permit
/// counts as `skipped_over_budget`.
pub async fn run_probe_pass(
    plan: &ProbePlan,
    backend: &dyn ProbeBackend,
    allowance: &ProbeAllowance,
    stores: &ProbeStores,
    announce: &RefreshSender,
) -> ProbeOutcome {
    let mut outcome = ProbeOutcome::default();
    run_phase::<LineagePhase>(&plan.commits, backend, allowance, stores, &mut outcome).await;
    run_phase::<MembershipPhase>(&plan.commits, backend, allowance, stores, &mut outcome).await;
    run_phase::<BranchPhase>(&plan.branches, backend, allowance, stores, &mut outcome).await;

    let mut announced = HashSet::new();
    outcome
        .changed
        .retain(|repository| announced.insert(repository.clone()));
    for repository in &outcome.changed {
        announce.send_probe_evidence(repository.clone());
    }
    if !outcome.changed.is_empty() {
        outcome.report.effect = ProbeEffect::Republish;
    }
    tracing::debug!(
        issued = outcome.report.issued,
        skipped_over_budget = outcome.report.skipped_over_budget,
        inconclusive = outcome.report.inconclusive,
        "background probe pass finished"
    );
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::{
        DEFAULT_COOLDOWN_SECS, ProbeCredential, QuotaHeaders, QuotaMeter, RateLimitGate,
    };
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<&'static str>>,
        branch: Option<BranchEvidence>,
        lineage: Option<CommitLineage>,
        membership: Option<DefaultBranchMembership>,
    }

    impl Fake {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn answer<T: Copy>(value: Option<T>) -> ProbeAnswer<T> {
        value.map_or(ProbeAnswer::Inconclusive, ProbeAnswer::Answer)
    }

    impl ProbeBackend for Fake {
        fn branch<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a ProbeRef,
        ) -> BoxFuture<'a, ProbeAnswer<BranchEvidence>> {
            self.calls.lock().unwrap().push("branch");
            Box::pin(std::future::ready(answer(self.branch)))
        }

        fn lineage<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a CommitSha,
            _: &'a CommitSha,
        ) -> BoxFuture<'a, ProbeAnswer<CommitLineage>> {
            self.calls.lock().unwrap().push("lineage");
            Box::pin(std::future::ready(answer(self.lineage)))
        }

        fn membership<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a CommitSha,
        ) -> BoxFuture<'a, ProbeAnswer<DefaultBranchMembership>> {
            self.calls.lock().unwrap().push("membership");
            Box::pin(std::future::ready(answer(self.membership)))
        }
    }

    fn allowance(credential: ProbeCredential) -> ProbeAllowance {
        ProbeAllowance::new(
            credential,
            Arc::new(QuotaMeter::new(QuotaHeaders::GitHub)),
            Arc::new(RateLimitGate::new(DEFAULT_COOLDOWN_SECS)),
        )
    }

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn repo() -> NormalizedName {
        NormalizedName::for_test("o/r")
    }

    fn commit_probe(pin: char) -> CommitProbe {
        CommitProbe {
            repository: repo(),
            package: PackageName::new("o/r"),
            latest: sha('a'),
            pin: sha(pin),
        }
    }

    fn branch_probe(git_ref: &str) -> BranchProbe {
        BranchProbe {
            repository: repo(),
            package: PackageName::new("o/r"),
            git_ref: ProbeRef::parse(git_ref).unwrap(),
        }
    }

    const AHEAD: CommitLineage = CommitLineage::AheadOfLatest { ahead_by: Some(1) };

    #[tokio::test]
    async fn lineage_then_membership_then_branch_and_proof_is_stored() {
        let fake = Fake {
            branch: Some(BranchEvidence::Absent),
            lineage: Some(AHEAD),
            membership: Some(DefaultBranchMembership::Reachable),
            ..Fake::default()
        };
        let stores = ProbeStores::default();
        stores.record_latest(
            repo(),
            LatestRelease {
                tag: "v1.0.0".into(),
                commit: sha('a'),
            },
        );
        let plan = ProbePlan {
            commits: vec![commit_probe('b')],
            branches: vec![branch_probe("v40")],
        };
        let outcome = run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Token),
            &stores,
            &RefreshSender::new(),
        )
        .await;

        assert_eq!(fake.calls(), ["lineage", "membership", "branch"]);
        assert_eq!(outcome.report.issued, 3);
        assert_eq!(outcome.report.effect, ProbeEffect::Republish);
        assert_eq!(
            stores.proof(&repo(), &sha('b')).unwrap().latest_tag(),
            &TagName::from("v1.0.0")
        );
        assert_eq!(
            stores
                .branches
                .get(&repo(), &ProbeRef::parse("v40").unwrap()),
            Some(BranchEvidence::Absent)
        );
    }

    #[tokio::test]
    async fn not_ahead_pin_costs_one_request_and_no_membership() {
        let fake = Fake {
            lineage: Some(CommitLineage::NotAhead),
            ..Fake::default()
        };
        let stores = ProbeStores::default();
        let plan = ProbePlan {
            commits: vec![commit_probe('b')],
            branches: vec![],
        };
        run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Token),
            &stores,
            &RefreshSender::new(),
        )
        .await;
        assert_eq!(fake.calls(), ["lineage"]);
    }

    #[tokio::test]
    async fn store_hits_draw_no_permit_and_no_request() {
        let fake = Fake {
            branch: Some(BranchEvidence::Exists),
            ..Fake::default()
        };
        let stores = ProbeStores::default();
        let plan = ProbePlan {
            commits: vec![],
            branches: vec![branch_probe("v1")],
        };
        let allowance = allowance(ProbeCredential::Anonymous);
        run_probe_pass(&plan, &fake, &allowance, &stores, &RefreshSender::new()).await;
        let second = run_probe_pass(&plan, &fake, &allowance, &stores, &RefreshSender::new()).await;
        assert_eq!(fake.calls(), ["branch"]);
        assert_eq!(second.report, ProbeReport::default());
    }

    #[tokio::test]
    async fn anonymous_budget_caps_requests_and_counts_the_rest() {
        let fake = Fake {
            branch: Some(BranchEvidence::Absent),
            ..Fake::default()
        };
        let stores = ProbeStores::default();
        let plan = ProbePlan {
            commits: vec![],
            branches: (1..=9).map(|n| branch_probe(&format!("v{n}"))).collect(),
        };
        let outcome = run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Anonymous),
            &stores,
            &RefreshSender::new(),
        )
        .await;
        assert_eq!(outcome.report.issued, 4);
        assert_eq!(outcome.report.skipped_over_budget, 5);
    }

    #[tokio::test]
    async fn inconclusive_answers_store_nothing_and_are_counted() {
        let fake = Fake::default();
        let stores = ProbeStores::default();
        let plan = ProbePlan {
            commits: vec![commit_probe('b')],
            branches: vec![branch_probe("v40")],
        };
        let outcome = run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Token),
            &stores,
            &RefreshSender::new(),
        )
        .await;
        assert_eq!(outcome.report.inconclusive, 2);
        assert_eq!(outcome.report.effect, ProbeEffect::Unchanged);
        assert!(
            stores
                .branches
                .get(&repo(), &ProbeRef::parse("v40").unwrap())
                .is_none()
        );
    }

    #[tokio::test]
    async fn duplicates_are_asked_once() {
        let fake = Fake {
            branch: Some(BranchEvidence::Absent),
            ..Fake::default()
        };
        let stores = ProbeStores::default();
        let plan = ProbePlan {
            commits: vec![],
            branches: vec![branch_probe("v40"), branch_probe("v40")],
        };
        run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Token),
            &stores,
            &RefreshSender::new(),
        )
        .await;
        assert_eq!(fake.calls(), ["branch"]);
    }

    /// A stale answer is re-asked, served meanwhile, and not replaced by an inconclusive probe.
    #[tokio::test]
    async fn stale_membership_is_reprobed_and_survives_an_inconclusive_answer() {
        let stores = ProbeStores::new(Duration::ZERO);
        stores
            .commits
            .record_lineage(repo(), sha('a'), sha('b'), AHEAD);
        stores
            .commits
            .record_membership(repo(), sha('b'), DefaultBranchMembership::Reachable);
        stores.record_latest(
            repo(),
            LatestRelease {
                tag: "v1.0.0".into(),
                commit: sha('a'),
            },
        );
        let plan = ProbePlan {
            commits: vec![commit_probe('b')],
            branches: vec![],
        };
        let fake = Fake::default();

        let outcome = run_probe_pass(
            &plan,
            &fake,
            &allowance(ProbeCredential::Token),
            &stores,
            &RefreshSender::new(),
        )
        .await;

        assert_eq!(
            fake.calls(),
            ["membership"],
            "a stale answer is asked again"
        );
        assert_eq!(outcome.report.inconclusive, 1);
        assert!(
            stores.proof(&repo(), &sha('b')).is_some(),
            "the proof is still served"
        );
    }

    /// A backend that yields once before answering, so two passes overlap.
    struct Slow {
        calls: Mutex<usize>,
    }

    impl ProbeBackend for Slow {
        fn branch<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a ProbeRef,
        ) -> BoxFuture<'a, ProbeAnswer<BranchEvidence>> {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async {
                tokio::task::yield_now().await;
                ProbeAnswer::Answer(BranchEvidence::Absent)
            })
        }

        fn lineage<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a CommitSha,
            _: &'a CommitSha,
        ) -> BoxFuture<'a, ProbeAnswer<CommitLineage>> {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async {
                tokio::task::yield_now().await;
                ProbeAnswer::Answer(AHEAD)
            })
        }

        fn membership<'a>(
            &'a self,
            _: &'a PackageName,
            _: &'a CommitSha,
        ) -> BoxFuture<'a, ProbeAnswer<DefaultBranchMembership>> {
            Box::pin(async { ProbeAnswer::Inconclusive })
        }
    }

    /// FR-028/029: N documents referencing one question spend one permit and one request.
    #[tokio::test]
    async fn overlapping_passes_for_one_question_spend_one_permit() {
        let stores = ProbeStores::default();
        let allowance = allowance(ProbeCredential::Anonymous);
        let backend = Slow {
            calls: Mutex::new(0),
        };
        let branches = ProbePlan {
            commits: vec![],
            branches: vec![branch_probe("v40")],
        };
        let commits = ProbePlan {
            commits: vec![commit_probe('b')],
            branches: vec![],
        };

        let announce = RefreshSender::new();
        let (a, b, c, d) = tokio::join!(
            run_probe_pass(&branches, &backend, &allowance, &stores, &announce),
            run_probe_pass(&branches, &backend, &allowance, &stores, &announce),
            run_probe_pass(&commits, &backend, &allowance, &stores, &announce),
            run_probe_pass(&commits, &backend, &allowance, &stores, &announce),
        );

        assert_eq!(
            *backend.calls.lock().unwrap(),
            2,
            "one branch, one lineage request"
        );
        assert_eq!(a.report.issued + b.report.issued, 1);
        assert_eq!(
            c.report.issued + d.report.issued,
            2,
            "one lineage, one membership"
        );
        let granted = (0..10)
            .filter(|_| allowance.try_acquire().is_some())
            .count();
        assert_eq!(granted, 1, "four tokens minus the three spent");
    }

    #[tokio::test]
    async fn a_claim_dropped_by_panic_or_cancellation_releases_its_key() {
        let stores = ProbeStores::new(Duration::ZERO);
        let key = || ProbeKey::Branch(repo(), ProbeRef::parse("v40").unwrap());

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _claim = stores.claim(key()).unwrap();
            panic!("probe pass panicked while holding its claim");
        }));
        assert!(panicked.is_err());
        assert!(
            stores.claim(key()).is_some(),
            "unwinding released the claim"
        );

        let stores = Arc::new(stores);
        let (claimed_tx, claimed_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn({
            let stores = Arc::clone(&stores);
            async move {
                let _claim = stores.claim(key());
                claimed_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        });
        claimed_rx.await.unwrap();
        assert!(stores.claim(key()).is_none(), "the holder owns the key");
        holder.abort();
        assert!(holder.await.unwrap_err().is_cancelled());
        assert!(
            stores.claim(key()).is_some(),
            "cancellation released the claim"
        );
    }

    #[tokio::test]
    async fn a_released_claim_lets_the_next_pass_ask_again() {
        let stores = ProbeStores::new(Duration::ZERO);
        let key = || ProbeKey::Branch(repo(), ProbeRef::parse("v40").unwrap());
        let first = stores.claim(key());
        assert!(first.is_some());
        assert!(stores.claim(key()).is_none());
        drop(first);
        assert!(stores.claim(key()).is_some());
    }

    #[tokio::test]
    async fn a_tripped_gate_denies_every_probe() {
        let fake = Fake::default();
        let stores = ProbeStores::default();
        let gate = Arc::new(RateLimitGate::new(DEFAULT_COOLDOWN_SECS));
        gate.trip();
        let allowance = ProbeAllowance::new(
            ProbeCredential::Token,
            Arc::new(QuotaMeter::new(QuotaHeaders::GitHub)),
            gate,
        );
        let plan = ProbePlan {
            commits: vec![],
            branches: vec![branch_probe("v40")],
        };
        let outcome =
            run_probe_pass(&plan, &fake, &allowance, &stores, &RefreshSender::new()).await;
        assert!(fake.calls().is_empty());
        assert_eq!(outcome.report.skipped_over_budget, 1);
    }
}
