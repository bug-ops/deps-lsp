//! One background probe pass over the git refs and commit pins of a document, shared by every
//! git-tags ecosystem (GitHub Actions, GitLab CI).
//!
//! An ecosystem decides *what* is worth asking (its [`ProbePlan`]) and *how* to ask its forge
//! (a [`ProbeBackend`]); this module owns the rest: store hits draw no permit, permits come from
//! one [`ProbeAllowance`] in priority order (lineage, then membership, then branch), requests run
//! at most [`PROBE_CONCURRENCY`] at a time, and only authoritative answers are stored.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use dashmap::DashMap;
use futures::StreamExt;
use futures::stream;

use super::{
    AheadProof, BranchEvidence, BranchEvidenceStore, CommitEvidenceStore, CommitLineage, CommitSha,
    DefaultBranchMembership, ProbeEffect, ProbeRef, ProbeReport, TagIndex,
};
use crate::ecosystem::BoxFuture;
use crate::pagination::ListCoverage;
use crate::rate_limit::ProbeAllowance;
use crate::{NormalizedName, PackageName};

/// Requests of one pass in flight at once.
pub const PROBE_CONCURRENCY: usize = 4;

/// How long branch evidence and default-branch membership stay valid.
///
/// ASSUMPTION: the tag index itself has no TTL (it is revalidated on every fetch), so one hour
/// stands in for "the tag-index TTL" of specs 086/087.
pub const EVIDENCE_TTL: Duration = Duration::from_secs(3600);

/// Latest-release records kept per ecosystem.
const MAX_LATEST_RELEASES: usize = 256;

/// The newest stable release of a repository, as the last tags fetch saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRelease {
    /// The tag name as published.
    pub tag: String,
    /// The commit the tag points at.
    pub commit: CommitSha,
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
    in_flight: Mutex<HashSet<ProbeKey>>,
}

/// One question a pass asks, as the single-flight map knows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProbeKey {
    Lineage(NormalizedName, CommitSha, CommitSha),
    Membership(NormalizedName, CommitSha),
    Branch(NormalizedName, ProbeRef),
}

/// Proof that this pass is the only one asking its question right now; released on drop.
#[derive(Debug)]
struct InFlight<'a> {
    stores: &'a ProbeStores,
    key: ProbeKey,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.stores
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

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
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    /// Claims `key` for the calling pass, or `None` when another pass (of any document) is
    /// already asking the same question: one request and one permit per question, whatever
    /// the number of open documents that reference it.
    fn claim(&self, key: ProbeKey) -> Option<InFlight<'_>> {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.clone())
            .then(|| InFlight { stores: self, key })
    }

    /// Records the newest stable release of `repository`.
    pub fn record_latest(&self, repository: NormalizedName, latest: LatestRelease) {
        if !self.latest.contains_key(&repository) {
            crate::cache_policy::evict_arbitrary_if_full(&self.latest, MAX_LATEST_RELEASES);
        }
        self.latest.insert(repository, latest);
    }

    /// The newest stable release of `repository` the last fetch saw.
    #[must_use]
    pub fn latest(&self, repository: &NormalizedName) -> Option<LatestRelease> {
        self.latest.get(repository).map(|entry| entry.clone())
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
    /// Repositories whose stored evidence changed.
    pub changed: Vec<NormalizedName>,
}

/// Awaits `requests` with at most [`PROBE_CONCURRENCY`] in flight, in completion order.
async fn run_bounded<F: Future>(requests: Vec<F>) -> Vec<F::Output> {
    stream::iter(requests)
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await
}

// Named functions, not closures: a closure returning an `async` block over a `&dyn` backend
// defeats the higher-ranked lifetime inference once the pass is boxed into a `Send` future.
async fn ask_lineage<'a>(
    backend: &'a dyn ProbeBackend,
    probe: &'a CommitProbe,
) -> (&'a CommitProbe, ProbeAnswer<CommitLineage>) {
    let answer = backend
        .lineage(&probe.package, &probe.latest, &probe.pin)
        .await;
    (probe, answer)
}

async fn ask_membership<'a>(
    backend: &'a dyn ProbeBackend,
    probe: &'a CommitProbe,
) -> (&'a CommitProbe, ProbeAnswer<DefaultBranchMembership>) {
    let answer = backend.membership(&probe.package, &probe.pin).await;
    (probe, answer)
}

async fn ask_branch<'a>(
    backend: &'a dyn ProbeBackend,
    probe: &'a BranchProbe,
) -> (&'a BranchProbe, ProbeAnswer<BranchEvidence>) {
    let answer = backend.branch(&probe.package, &probe.git_ref).await;
    (probe, answer)
}

/// Runs `plan` against `backend`, drawing permits from `allowance` and storing authoritative
/// answers in `stores`.
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
) -> ProbeOutcome {
    let mut outcome = ProbeOutcome::default();

    let mut seen = HashSet::new();
    let mut lineage_work = Vec::new();
    let mut claims = Vec::new();
    for probe in &plan.commits {
        let known = || {
            stores
                .commits
                .lineage(&probe.repository, &probe.latest, &probe.pin)
                .is_some()
        };
        let key = (&probe.repository, &probe.latest, &probe.pin);
        if !seen.insert(key) || probe.latest == probe.pin || known() {
            continue;
        }
        let Some(claim) = stores.claim(ProbeKey::Lineage(
            probe.repository.clone(),
            probe.latest.clone(),
            probe.pin.clone(),
        )) else {
            continue;
        };
        if known() {
            continue;
        }
        if allowance.try_acquire().is_none() {
            outcome.report.skipped_over_budget += 1;
            continue;
        }
        claims.push(claim);
        lineage_work.push(probe);
    }
    let mut requests = Vec::new();
    for probe in lineage_work {
        requests.push(ask_lineage(backend, probe));
    }
    let answers = run_bounded(requests).await;
    for (probe, answer) in answers {
        outcome.report.issued += 1;
        match answer {
            ProbeAnswer::Answer(lineage) => {
                if stores.commits.record_lineage(
                    probe.repository.clone(),
                    probe.latest.clone(),
                    probe.pin.clone(),
                    lineage,
                ) {
                    outcome.changed.push(probe.repository.clone());
                }
            }
            ProbeAnswer::Inconclusive => outcome.report.inconclusive += 1,
        }
    }

    drop(claims);
    let mut seen = HashSet::new();
    let mut membership_work = Vec::new();
    let mut claims = Vec::new();
    for probe in &plan.commits {
        let ahead = matches!(
            stores
                .commits
                .lineage(&probe.repository, &probe.latest, &probe.pin),
            Some(CommitLineage::AheadOfLatest { .. })
        );
        let fresh = || {
            stores
                .commits
                .membership_fresh(&probe.repository, &probe.pin)
                .is_some()
        };
        if !ahead || !seen.insert((&probe.repository, &probe.pin)) || fresh() {
            continue;
        }
        let Some(claim) = stores.claim(ProbeKey::Membership(
            probe.repository.clone(),
            probe.pin.clone(),
        )) else {
            continue;
        };
        if fresh() {
            continue;
        }
        if allowance.try_acquire().is_none() {
            outcome.report.skipped_over_budget += 1;
            continue;
        }
        claims.push(claim);
        membership_work.push(probe);
    }
    let mut requests = Vec::new();
    for probe in membership_work {
        requests.push(ask_membership(backend, probe));
    }
    let answers = run_bounded(requests).await;
    for (probe, answer) in answers {
        outcome.report.issued += 1;
        match answer {
            ProbeAnswer::Answer(membership) => {
                if stores.commits.record_membership(
                    probe.repository.clone(),
                    probe.pin.clone(),
                    membership,
                ) {
                    outcome.changed.push(probe.repository.clone());
                }
            }
            ProbeAnswer::Inconclusive => outcome.report.inconclusive += 1,
        }
    }

    drop(claims);
    let mut seen = HashSet::new();
    let mut branch_work = Vec::new();
    let mut claims = Vec::new();
    for probe in &plan.branches {
        let fresh = || {
            stores
                .branches
                .get_fresh(&probe.repository, &probe.git_ref)
                .is_some()
        };
        if !seen.insert((&probe.repository, &probe.git_ref)) || fresh() {
            continue;
        }
        let Some(claim) = stores.claim(ProbeKey::Branch(
            probe.repository.clone(),
            probe.git_ref.clone(),
        )) else {
            continue;
        };
        if fresh() {
            continue;
        }
        if allowance.try_acquire().is_none() {
            outcome.report.skipped_over_budget += 1;
            continue;
        }
        claims.push(claim);
        branch_work.push(probe);
    }
    let mut requests = Vec::new();
    for probe in branch_work {
        requests.push(ask_branch(backend, probe));
    }
    let answers = run_bounded(requests).await;
    for (probe, answer) in answers {
        outcome.report.issued += 1;
        match answer {
            ProbeAnswer::Answer(evidence) => {
                if stores
                    .branches
                    .record(probe.repository.clone(), probe.git_ref.clone(), evidence)
                {
                    outcome.changed.push(probe.repository.clone());
                }
            }
            ProbeAnswer::Inconclusive => outcome.report.inconclusive += 1,
        }
    }

    drop(claims);
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
        let outcome =
            run_probe_pass(&plan, &fake, &allowance(ProbeCredential::Token), &stores).await;

        assert_eq!(fake.calls(), ["lineage", "membership", "branch"]);
        assert_eq!(outcome.report.issued, 3);
        assert_eq!(outcome.report.effect, ProbeEffect::Republish);
        assert_eq!(
            stores.proof(&repo(), &sha('b')).unwrap().latest_tag,
            "v1.0.0"
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
        run_probe_pass(&plan, &fake, &allowance(ProbeCredential::Token), &stores).await;
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
        run_probe_pass(&plan, &fake, &allowance, &stores).await;
        let second = run_probe_pass(&plan, &fake, &allowance, &stores).await;
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
        let outcome =
            run_probe_pass(&plan, &fake, &allowance(ProbeCredential::Token), &stores).await;
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
        run_probe_pass(&plan, &fake, &allowance(ProbeCredential::Token), &stores).await;
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

        let outcome =
            run_probe_pass(&plan, &fake, &allowance(ProbeCredential::Token), &stores).await;

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

        let (a, b, c, d) = tokio::join!(
            run_probe_pass(&branches, &backend, &allowance, &stores),
            run_probe_pass(&branches, &backend, &allowance, &stores),
            run_probe_pass(&commits, &backend, &allowance, &stores),
            run_probe_pass(&commits, &backend, &allowance, &stores),
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
        let outcome = run_probe_pass(&plan, &fake, &allowance, &stores).await;
        assert!(fake.calls().is_empty());
        assert_eq!(outcome.report.skipped_over_budget, 1);
    }
}
