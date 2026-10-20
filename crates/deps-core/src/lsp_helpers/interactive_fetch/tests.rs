use std::assert_matches;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use super::attempt::{AttemptEnd, AttemptEvidence, evidence};
use super::breaker::{
    Admission, BREAKER_CAP, BREAKER_OPEN_DURATION, BreakerAdmission, EndpointBreaker,
    EndpointHealth, PROBE_LEASE, ProbeId, Verdict, verdict,
};
use super::key::{
    BreakerEvidence, EndpointKey, LookupKind, ManifestFingerprint, SourceFingerprint,
};
use super::memo::{Decision, FastFail, INTERACTIVE_FAILURE_TTL, INTERACTIVE_MEMO_CAP};
use super::*;
use crate::endpoint_contact::{Contact, RequestNote, ResponseSeen, note_request};
use crate::lsp_helpers::DependencyOutcomes;
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;
use crate::test_util::{MockRegistry, MockVersion};
use crate::{ConcreteVersion, EcosystemId, ErrorOrigin, FetchFailure};
use crate::{EgressTier, RegistryEndpoint};

#[derive(Clone, Copy)]
enum Fetch {
    Succeed,
    Fail,
    /// Fails with an error that says nothing about the endpoint (a local policy block).
    FailLocal,
    /// A local failure that surfaces only after 6 s, such as a DNS preflight timeout.
    FailLocalSlow,
    Stall,
}

struct Failure(ErrorOrigin);

impl InteractiveFetchError for Failure {
    fn log_cause(&self) -> (Option<u16>, &'static str) {
        (None, "test")
    }

    fn origin(&self) -> ErrorOrigin {
        self.0
    }
}

struct Fixture {
    ecosystem: EcosystemId,
    gate: InteractiveFetchGate,
    cached: HashMap<PackageName, crate::PackageVersions>,
    resolved: HashMap<PackageName, ConcreteVersion>,
    calls: AtomicUsize,
    kind: std::sync::Mutex<AuxiliaryLookup>,
    manifest: url::Url,
    registry: MockRegistry,
}

fn manifest(path: &str) -> url::Url {
    url::Url::parse(&format!("file://{path}")).unwrap()
}

impl Fixture {
    fn new() -> Self {
        Self {
            ecosystem: EcosystemId::Cargo,
            gate: InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap()),
            cached: HashMap::new(),
            resolved: HashMap::new(),
            calls: AtomicUsize::new(0),
            kind: std::sync::Mutex::new(AuxiliaryLookup::PinResolution),
            manifest: manifest("/project/Cargo.toml"),
            registry: MockRegistry::new(),
        }
    }

    fn with_endpoint(mut self, endpoint: RegistryEndpoint) -> Self {
        self.registry = MockRegistry::new().with_endpoint(endpoint);
        self
    }

    fn with_ecosystem(mut self, ecosystem: EcosystemId) -> Self {
        self.ecosystem = ecosystem;
        self
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    async fn run_full(
        &self,
        manifest: &url::Url,
        name: &str,
        source: &DependencySource,
        outcomes: &DependencyOutcomes,
        network: NetworkMode,
        fetch: Fetch,
    ) -> InteractiveFetch<u8> {
        self.run_via(
            &self.registry,
            manifest,
            name,
            source,
            outcomes,
            network,
            fetch,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a test fixture's full request shape"
    )]
    async fn run_via(
        &self,
        registry: &MockRegistry,
        manifest: &url::Url,
        name: &str,
        source: &DependencySource,
        outcomes: &DependencyOutcomes,
        network: NetworkMode,
        fetch: Fetch,
    ) -> InteractiveFetch<u8> {
        let package = PackageName::new(name);
        let versions = VersionData::new(&self.cached, &self.resolved)
            .with_ecosystem(self.ecosystem)
            .with_network(network)
            .with_outcomes(outcomes)
            .with_interactive_fetch_gate(&self.gate);
        let request = InteractiveFetchRequest::new(
            versions,
            manifest,
            &package,
            name,
            source,
            FetchContext::Hover,
        );
        let kind = *self.kind.lock().unwrap();
        await_interactive_fetch(
            registry,
            async {
                self.calls.fetch_add(1, Ordering::SeqCst);
                match fetch {
                    Fetch::Succeed => {
                        note_request().answered();
                        Ok(1)
                    }
                    Fetch::Fail => {
                        note_request().answered();
                        Err(Failure(ErrorOrigin::Endpoint))
                    }
                    Fetch::FailLocal => Err(Failure(ErrorOrigin::Unattributed)),
                    Fetch::FailLocalSlow => {
                        let _note = note_request();
                        tokio::time::sleep(Duration::from_secs(6)).await;
                        Err(Failure(ErrorOrigin::Unattributed))
                    }
                    Fetch::Stall => {
                        let _note = note_request();
                        tokio::time::sleep(REGISTRY_FETCH_BUDGET + Duration::from_secs(5)).await;
                        Ok(1)
                    }
                }
            },
            request,
            kind,
        )
        .await
    }

    async fn run(
        &self,
        name: &str,
        outcomes: &DependencyOutcomes,
        fetch: Fetch,
    ) -> InteractiveFetch<u8> {
        self.run_full(
            &self.manifest,
            name,
            &DependencySource::Registry,
            outcomes,
            NetworkMode::Online,
            fetch,
        )
        .await
    }
}

fn failing(name: &str, failure: FetchFailure) -> DependencyOutcomes {
    DependencyOutcomes::new().with_fetch_failure(name, failure)
}

fn assert_degraded<T>(result: &InteractiveFetch<T>, expected: NoLiveList) {
    let actual = match result {
        InteractiveFetch::Degraded(kind) => Some(*kind),
        InteractiveFetch::Live(_) => None,
    };
    assert_eq!(actual, Some(expected));
}

#[tokio::test(start_paused = true)]
async fn seeded_transient_failure_skips_the_live_call() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);

    let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn seeded_actionable_failure_skips_the_live_call() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Actionable("rate limited".into()));

    let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn not_attempted_is_not_a_known_failure() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::NotAttempted);

    let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn seeded_record_is_ignored_once_outcomes_clear() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);
    fixture.run("serde", &outcomes, Fetch::Succeed).await;
    assert_eq!(fixture.gate.len(), 1);

    let result = fixture
        .run("serde", &DependencyOutcomes::new(), Fetch::Succeed)
        .await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn live_success_keeps_stale_background_outcomes_from_reseeding() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);
    fixture.run("serde", &outcomes, Fetch::Succeed).await;
    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
    let recovered = fixture.run("serde", &outcomes, Fetch::Succeed).await;
    assert_matches!(recovered, InteractiveFetch::Live(1));

    let next = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_matches!(next, InteractiveFetch::Live(1));
    assert_eq!(
        fixture.calls(),
        2,
        "the first request only seeded; two live calls"
    );
}

#[tokio::test(start_paused = true)]
async fn live_success_without_a_background_failure_leaves_the_memo_empty() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    fixture.run("serde", &none, Fetch::Fail).await;
    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;

    let result = fixture.run("serde", &none, Fetch::Succeed).await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert!(fixture.gate.is_empty());
}

#[tokio::test(start_paused = true)]
async fn seeding_is_discarded_when_the_gate_was_invalidated_after_the_read() {
    let fixture = Fixture::new();
    let package = PackageName::new("serde");
    let source = DependencySource::Registry;
    let outcomes = failing("serde", FetchFailure::Transient);
    let request = InteractiveFetchRequest::new(
        VersionData::new(&fixture.cached, &fixture.resolved)
            .with_ecosystem(EcosystemId::Cargo)
            .with_outcomes(&outcomes)
            .with_interactive_fetch_gate(&fixture.gate),
        &fixture.manifest,
        &package,
        "serde",
        &source,
        FetchContext::Hover,
    );
    let (gate, lookup) = request
        .gated(&fixture.registry, LookupKind::VersionList)
        .unwrap();
    let generation = gate.generation();
    gate.invalidate_all();

    let decision = gate.decide(&lookup, true, generation, now());

    assert_matches!(
        decision,
        Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
    );
    assert!(
        gate.is_empty(),
        "a seed read before the invalidation must not survive"
    );
}

#[tokio::test(start_paused = true)]
async fn elapse_is_memoized_so_the_next_request_makes_no_call() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();

    let first = fixture.run("serde", &none, Fetch::Stall).await;
    let second = fixture.run("serde", &none, Fetch::Stall).await;

    assert_degraded(&first, NoLiveList::Unverified);
    assert_degraded(&second, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn memo_expires_after_the_ttl() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    fixture.run("serde", &none, Fetch::Stall).await;

    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
    let result = fixture.run("serde", &none, Fetch::Succeed).await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn stale_seeded_record_gets_one_live_retry() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);
    fixture.run("serde", &outcomes, Fetch::Succeed).await;

    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
    let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn memoized_error_is_replayed_as_unverified() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();

    let first = fixture.run("serde", &none, Fetch::Fail).await;
    let second = fixture.run("serde", &none, Fetch::Succeed).await;

    assert_degraded(&first, NoLiveList::Failed);
    assert_degraded(&second, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn stale_seeded_record_stays_unverified_when_the_failure_persists() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);
    fixture.run("serde", &outcomes, Fetch::Fail).await;

    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
    let retry = fixture.run("serde", &outcomes, Fetch::Fail).await;

    assert_degraded(&retry, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn same_name_in_two_manifests_does_not_share_a_record() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    let other = manifest("/other-project/Cargo.toml");
    fixture.run("serde", &none, Fetch::Fail).await;

    let result = fixture
        .run_full(
            &other,
            "serde",
            &DependencySource::Registry,
            &none,
            NetworkMode::Online,
            Fetch::Succeed,
        )
        .await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 2);
    assert_eq!(
        fixture.gate.len(),
        1,
        "only the first manifest's failure is recorded"
    );
}

#[tokio::test(start_paused = true)]
async fn same_name_from_two_sources_is_tracked_independently() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    let alternate = DependencySource::AlternateRegistry {
        index: "https://203.0.113.7/".into(),
        mirrors_crates_io: false,
    };
    fixture
        .run_full(
            &fixture.manifest,
            "serde",
            &alternate,
            &none,
            NetworkMode::Online,
            Fetch::Stall,
        )
        .await;

    let default_source = fixture.run("serde", &none, Fetch::Succeed).await;

    assert_matches!(default_source, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn saturated_gate_degrades_immediately_without_a_memo_write() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();

    let (_, _, _, fourth) = tokio::join!(
        fixture.run("a", &none, Fetch::Stall),
        fixture.run("b", &none, Fetch::Stall),
        fixture.run("c", &none, Fetch::Stall),
        async {
            let result = fixture.run("d", &none, Fetch::Succeed).await;
            assert_eq!(fixture.gate.len(), 0, "saturation must not be memoized");
            result
        },
    );

    assert_degraded(&fourth, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 3);
    assert_eq!(fixture.gate.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn invalidation_during_an_await_discards_its_record() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();

    let (stalled, ()) = tokio::join!(fixture.run("serde", &none, Fetch::Stall), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        fixture.gate.invalidate_all();
    });

    assert_degraded(&stalled, NoLiveList::Unverified);
    assert!(fixture.gate.is_empty());
    let retry = fixture.run("serde", &none, Fetch::Succeed).await;
    assert_matches!(retry, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn offline_mode_ignores_the_gate() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);

    let result = fixture
        .run_full(
            &fixture.manifest,
            "serde",
            &DependencySource::Registry,
            &outcomes,
            NetworkMode::Offline,
            Fetch::Succeed,
        )
        .await;

    assert_matches!(result, InteractiveFetch::Live(1));
    assert!(fixture.gate.is_empty());
}

#[tokio::test(start_paused = true)]
async fn request_without_a_gate_is_the_plain_bounded_await() {
    let cached = HashMap::new();
    let resolved = HashMap::new();
    let package = PackageName::new("serde");
    let source = DependencySource::Registry;
    let outcomes = failing("serde", FetchFailure::Transient);
    let document = manifest("/project/Cargo.toml");
    let request = InteractiveFetchRequest::new(
        VersionData::new(&cached, &resolved)
            .with_ecosystem(EcosystemId::Cargo)
            .with_outcomes(&outcomes),
        &document,
        &package,
        "serde",
        &source,
        FetchContext::CodeAction,
    );

    let result = await_interactive_fetch(
        &MockRegistry::new(),
        async { Ok::<_, ()>(1_u8) },
        request,
        AuxiliaryLookup::PinResolution,
    )
    .await;

    assert_matches!(result, InteractiveFetch::Live(1));
}

#[tokio::test(start_paused = true)]
async fn memo_stays_within_the_cap_and_sweeps_expired_entries() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    for index in 0..INTERACTIVE_MEMO_CAP {
        fixture
            .run(&format!("pkg{index}"), &none, Fetch::Fail)
            .await;
    }
    assert_eq!(fixture.gate.len(), INTERACTIVE_MEMO_CAP);

    fixture.run("overflow-1", &none, Fetch::Fail).await;
    assert_eq!(fixture.gate.len(), INTERACTIVE_MEMO_CAP);

    tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
    fixture.run("overflow-2", &none, Fetch::Fail).await;
    assert_eq!(fixture.gate.len(), 1);
}

#[derive(Clone, Copy)]
enum Versions {
    /// A response arrives after the delay and the list is served.
    Succeed(Duration),
    /// An error response (an HTTP status) arrives after the delay.
    Fail(Duration),
    /// The transport fails after the delay with no response, such as a connect timeout.
    Transport(Duration),
    /// Served after the delay without any request: a memo, a fresh cache entry, or a wait on
    /// another task's lock.
    Untouched(Duration),
    /// Waits on another task for the delay, then sends a request of its own that never answers.
    WaitThenStall(Duration),
    /// A chain whose first hop answers in 1 s and whose second hop never does.
    AnswerThenStall,
    /// Pages that each answer in 3 s, for far longer than the budget.
    Paging,
}

impl Versions {
    const STALL: Self = Self::Succeed(Duration::from_secs(60));
}

fn list() -> SharedVersions {
    SharedVersions::from(vec![Box::new(MockVersion::new("1.0.0")) as Box<dyn Version>])
}

const fn secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

impl Fixture {
    async fn versions(
        &self,
        name: &str,
        freshness: FreshnessSettings,
        behavior: Versions,
    ) -> InteractiveFetch<SharedVersions> {
        self.versions_in(FetchContext::Hover, name, freshness, behavior)
            .await
    }

    async fn versions_in(
        &self,
        context: FetchContext,
        name: &str,
        freshness: FreshnessSettings,
        behavior: Versions,
    ) -> InteractiveFetch<SharedVersions> {
        let package = PackageName::new(name);
        let source = DependencySource::Registry;
        let outcomes = DependencyOutcomes::new();
        let request = InteractiveFetchRequest::new(
            VersionData::new(&self.cached, &self.resolved)
                .with_ecosystem(self.ecosystem)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&self.gate),
            &self.manifest,
            &package,
            name,
            &source,
            context,
        );
        let (gate, lookup) = request
            .gated(&self.registry, LookupKind::VersionList)
            .unwrap();
        let fetch = async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut note = (!matches!(
                behavior,
                Versions::Untouched(_) | Versions::WaitThenStall(_)
            ))
            .then(note_request);
            match behavior {
                Versions::Untouched(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(list())
                }
                Versions::WaitThenStall(delay) => {
                    tokio::time::sleep(delay).await;
                    let _own = note_request();
                    tokio::time::sleep(secs(60)).await;
                    Ok(list())
                }
                Versions::AnswerThenStall => {
                    tokio::time::sleep(secs(1)).await;
                    answered(note.take());
                    let _next = note_request();
                    tokio::time::sleep(secs(60)).await;
                    Ok(list())
                }
                Versions::Paging => {
                    for _ in 0..20 {
                        tokio::time::sleep(secs(3)).await;
                        answered(note.take());
                        note = Some(note_request());
                    }
                    Ok(list())
                }
                Versions::Succeed(delay) => {
                    tokio::time::sleep(delay).await;
                    answered(note.take());
                    Ok(list())
                }
                Versions::Fail(delay) => {
                    tokio::time::sleep(delay).await;
                    answered(note.take());
                    Err(())
                }
                Versions::Transport(delay) => {
                    tokio::time::sleep(delay).await;
                    Err(())
                }
            }
        };
        flight::await_shared(gate, lookup, fetch, &request, ListShape::of(freshness)).await
    }

    async fn enriched(&self, name: &str, behavior: Versions) -> InteractiveFetch<SharedVersions> {
        self.versions(name, FreshnessSettings::default(), behavior)
            .await
    }

    async fn bare(&self, name: &str, behavior: Versions) -> InteractiveFetch<SharedVersions> {
        self.versions(name, FreshnessSettings::Disabled, behavior)
            .await
    }
}

fn live_list(result: InteractiveFetch<SharedVersions>) -> SharedVersions {
    result.into_live().expect("a live list")
}

#[tokio::test(start_paused = true)]
async fn concurrent_requests_for_one_package_share_one_fetch() {
    let fixture = Fixture::new();
    let succeed = Versions::Succeed(secs(2));

    let (a, b, c) = tokio::join!(
        fixture.enriched("serde", succeed),
        fixture.enriched("serde", succeed),
        fixture.enriched("serde", succeed),
    );

    let (a, b, c) = (live_list(a), live_list(b), live_list(c));
    assert_eq!(fixture.calls(), 1);
    assert!(Arc::ptr_eq(&a, &b) && Arc::ptr_eq(&a, &c));
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn bare_request_follows_an_enriched_flight() {
    let fixture = Fixture::new();

    let (enriched, bare) = tokio::join!(
        fixture.enriched("serde", Versions::Succeed(secs(2))),
        fixture.bare("serde", Versions::Succeed(secs(2))),
    );

    assert!(Arc::ptr_eq(&live_list(enriched), &live_list(bare)));
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn enriched_request_does_not_follow_a_bare_flight() {
    let fixture = Fixture::new();

    let (bare, enriched) = tokio::join!(
        fixture.bare("serde", Versions::Succeed(secs(2))),
        fixture.enriched("serde", Versions::Succeed(secs(2))),
    );

    assert!(!Arc::ptr_eq(&live_list(bare), &live_list(enriched)));
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn leader_error_reaches_followers_as_unverified_without_a_second_fetch() {
    let fixture = Fixture::new();

    let (leader, follower) = tokio::join!(
        fixture.enriched("serde", Versions::Fail(secs(1))),
        fixture.enriched("serde", Versions::Succeed(secs(1))),
    );

    assert_degraded(&leader, NoLiveList::Failed);
    assert_degraded(&follower, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.gate.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn leader_elapse_is_the_shared_answer() {
    let fixture = Fixture::new();

    let (leader, follower) = tokio::join!(
        fixture.enriched("serde", Versions::STALL),
        fixture.enriched("serde", Versions::STALL),
    );

    assert_degraded(&leader, NoLiveList::Unverified);
    assert_degraded(&follower, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.gate.len(), 1);
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

async fn cancel_leader_then_follow(
    fixture: &Fixture,
    cancel_after: Duration,
    follower: Versions,
) -> InteractiveFetch<SharedVersions> {
    let cancelled_leader = async {
        let outcome =
            tokio::time::timeout(cancel_after, fixture.enriched("serde", Versions::STALL)).await;
        assert!(outcome.is_err(), "the leader must still be waiting");
    };
    let ((), result) = tokio::join!(cancelled_leader, fixture.enriched("serde", follower));
    result
}

#[tokio::test(start_paused = true)]
async fn cancelled_leader_hands_the_flight_to_a_follower() {
    let fixture = Fixture::new();

    let result = cancel_leader_then_follow(&fixture, secs(1), Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(result).len(), 1);
    assert_eq!(
        fixture.calls(),
        2,
        "the leader polled once, the promoted follower once"
    );
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn follower_promoted_with_most_of_the_budget_memoizes_its_elapse() {
    let fixture = Fixture::new();

    let result = cancel_leader_then_follow(&fixture, secs(2), Versions::STALL).await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert_eq!(fixture.gate.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn follower_promoted_late_leaves_the_memo_alone() {
    let fixture = Fixture::new();

    let result = cancel_leader_then_follow(&fixture, secs(6), Versions::STALL).await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert!(
        fixture.gate.is_empty(),
        "an elapse with under half the budget proves nothing about the registry"
    );
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn follower_promoted_late_still_records_a_success() {
    let fixture = Fixture::new();

    let result = cancel_leader_then_follow(&fixture, secs(6), Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(result).len(), 1);
    assert!(fixture.gate.is_empty());
}

#[tokio::test(start_paused = true)]
async fn followers_hold_permits_so_a_fourth_waiter_degrades() {
    let fixture = Fixture::new();
    let succeed = Versions::Succeed(secs(2));

    let (_, _, _, other) = tokio::join!(
        fixture.enriched("serde", succeed),
        fixture.enriched("serde", succeed),
        fixture.enriched("serde", succeed),
        async {
            let result = fixture.enriched("other", succeed).await;
            assert_eq!(fixture.gate.len(), 0, "saturation must not be memoized");
            result
        },
    );

    assert_degraded(&other, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn requests_after_an_invalidation_never_join_an_earlier_flight() {
    let fixture = Fixture::new();

    let (before, after, ()) = tokio::join!(
        fixture.enriched("serde", Versions::Succeed(secs(5))),
        async {
            tokio::time::sleep(secs(2)).await;
            fixture.enriched("serde", Versions::Succeed(secs(1))).await
        },
        async {
            tokio::time::sleep(secs(1)).await;
            fixture.gate.invalidate_all();
        },
    );

    assert!(!Arc::ptr_eq(&live_list(before), &live_list(after)));
    assert_eq!(fixture.calls(), 2);
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn memoized_failure_skips_the_flight_entirely() {
    let fixture = Fixture::new();
    fixture
        .enriched("serde", Versions::Fail(Duration::ZERO))
        .await;

    let result = fixture.enriched("serde", Versions::Succeed(secs(1))).await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn public_entry_point_shares_the_registry_list() {
    let fixture = Fixture::new();
    let registry = MockRegistry::new().with_versions(vec![MockVersion::new("2.0.0")]);
    let package = PackageName::new("serde");
    let source = DependencySource::Registry;
    let outcomes = DependencyOutcomes::new();
    let request = InteractiveFetchRequest::new(
        VersionData::new(&fixture.cached, &fixture.resolved)
            .with_ecosystem(EcosystemId::Cargo)
            .with_outcomes(&outcomes)
            .with_interactive_fetch_gate(&fixture.gate),
        &fixture.manifest,
        &package,
        "serde",
        &source,
        FetchContext::CodeAction,
    );

    let result = await_interactive_versions(&registry, request, FreshnessSettings::Disabled).await;

    let live = live_list(result);
    assert_eq!(live[0].version_string().as_str(), "2.0.0");
}

impl Fixture {
    fn endpoint(&self) -> EndpointKey {
        scoped_endpoint(&self.manifest)
    }

    fn health(&self) -> Option<EndpointHealth> {
        self.gate.breaker.health(&self.endpoint())
    }

    async fn code_action(
        &self,
        name: &str,
        behavior: Versions,
    ) -> InteractiveFetch<SharedVersions> {
        self.versions_in(
            FetchContext::CodeAction,
            name,
            FreshnessSettings::Disabled,
            behavior,
        )
        .await
    }

    /// Hovers on `name`, dropping the await after `after` the way a cancelled request does.
    async fn cancelled_hover(&self, name: &str, after: Duration) {
        let outcome = tokio::time::timeout(after, self.enriched(name, Versions::STALL)).await;
        assert!(outcome.is_err(), "the hover must still be waiting");
    }

    /// Two distinct packages that stall to the end of the budget: opens the breaker.
    async fn open_the_breaker(&self) {
        self.enriched("slow-a", Versions::STALL).await;
        self.enriched("slow-b", Versions::STALL).await;
        assert_matches!(self.health(), Some(EndpointHealth::Open { .. }));
    }
}

fn scoped_endpoint(manifest: &url::Url) -> EndpointKey {
    EndpointKey::Scoped {
        ecosystem: EcosystemId::Cargo,
        manifest: ManifestFingerprint::of(manifest),
        source: SourceFingerprint::of(&DependencySource::Registry),
    }
}

fn answered(note: Option<RequestNote>) {
    if let Some(note) = note {
        note.answered();
    }
}

fn is_open(health: Option<EndpointHealth>) -> bool {
    matches!(health, Some(EndpointHealth::Open { .. }))
}

const ANSWERED: Contact = Contact {
    response: ResponseSeen::Yes,
    stall: Duration::ZERO,
};

const fn stalled_for(stall: Duration) -> Contact {
    Contact {
        response: ResponseSeen::No,
        stall,
    }
}

const fn answered_then_stalled_for(stall: Duration) -> Contact {
    Contact {
        response: ResponseSeen::Yes,
        stall,
    }
}

#[test]
fn evidence_follows_the_unified_table() {
    let budget = secs(10);
    let just_under = |limit: Duration| limit.saturating_sub(Duration::from_millis(1));
    let untouched = Contact::UNTOUCHED;
    let cases = [
        // A response within the budget vouches for the endpoint; nothing else does.
        (
            AttemptEnd::Live,
            ANSWERED,
            just_under(secs(9)),
            AttemptEvidence::Answered,
        ),
        (
            AttemptEnd::Live,
            untouched,
            just_under(secs(9)),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Live,
            ANSWERED,
            secs(9),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Live,
            ANSWERED,
            secs(10),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Endpoint),
            ANSWERED,
            just_under(secs(9)),
            AttemptEvidence::Answered,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Endpoint),
            untouched,
            just_under(secs(9)),
            AttemptEvidence::Inconclusive,
        ),
        // A request outstanding for half the budget accuses it, however the attempt ends.
        (
            AttemptEnd::Err(ErrorOrigin::Endpoint),
            stalled_for(secs(9)),
            secs(9),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Endpoint),
            stalled_for(Duration::from_millis(9500)),
            Duration::from_millis(9500),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Endpoint),
            ANSWERED,
            secs(9),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Unattributed),
            stalled_for(just_under(secs(5))),
            just_under(secs(5)),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Unattributed),
            stalled_for(secs(5)),
            secs(5),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Unattributed),
            stalled_for(secs(9)),
            secs(9),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Err(ErrorOrigin::Unattributed),
            untouched,
            secs(9),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Elapsed,
            stalled_for(secs(10)),
            secs(10),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Elapsed,
            stalled_for(secs(5)),
            secs(5),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Elapsed,
            stalled_for(just_under(secs(5))),
            just_under(secs(5)),
            AttemptEvidence::Inconclusive,
        ),
        // Waiting on another task's lock sends no request of its own.
        (
            AttemptEnd::Elapsed,
            untouched,
            secs(10),
            AttemptEvidence::Inconclusive,
        ),
        // Pagination keeps receiving responses, so no request has been outstanding long.
        (
            AttemptEnd::Elapsed,
            ANSWERED,
            secs(10),
            AttemptEvidence::Inconclusive,
        ),
        // A request that only started late, after a lock wait or a long response, is too young.
        (
            AttemptEnd::Elapsed,
            answered_then_stalled_for(secs(2)),
            secs(10),
            AttemptEvidence::Inconclusive,
        ),
        // A chain whose first hop answered fast and whose second hop hangs.
        (
            AttemptEnd::Elapsed,
            answered_then_stalled_for(secs(5)),
            secs(10),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Cancelled,
            stalled_for(secs(5)),
            secs(5),
            AttemptEvidence::Slow,
        ),
        (
            AttemptEnd::Cancelled,
            stalled_for(just_under(secs(5))),
            just_under(secs(5)),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Cancelled,
            untouched,
            Duration::ZERO,
            AttemptEvidence::Inconclusive,
        ),
    ];
    for (end, contact, waited, expected) in cases {
        assert_eq!(
            evidence(end, contact, waited, budget),
            expected,
            "{end:?} {contact:?} after {waited:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_single_slow_package_does_not_open_the_breaker() {
    let fixture = Fixture::new();

    fixture.enriched("slow-a", Versions::STALL).await;
    let next = fixture.enriched("other", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn two_distinct_slow_packages_open_the_breaker_and_the_next_hover_makes_no_call() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;

    let refused = fixture.enriched("third", Versions::Succeed(secs(1))).await;

    assert_degraded(&refused, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
    assert_eq!(fixture.gate.len(), 2, "a refusal is not memoized");
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_generic_path_is_refused_by_the_same_breaker() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    fixture.run("slow-a", &none, Fetch::Stall).await;
    fixture.run("slow-b", &none, Fetch::Stall).await;

    let refused = fixture.run("third", &none, Fetch::Succeed).await;

    assert_degraded(&refused, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_answer_within_the_ttl_keeps_slow_packages_from_opening_the_breaker() {
    let fixture = Fixture::new();

    fixture.enriched("fast", Versions::Succeed(secs(6))).await;
    fixture.enriched("slow-a", Versions::STALL).await;
    fixture.enriched("slow-b", Versions::STALL).await;
    let next = fixture.enriched("next", Versions::Succeed(secs(1))).await;

    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            last_answered: Some(_),
            suspect: None
        })
    );
    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_live_list_near_the_budget_is_not_an_answer() {
    let fixture = Fixture::new();

    fixture
        .enriched(
            "stale-served",
            Versions::Succeed(Duration::from_millis(9500)),
        )
        .await;
    assert_eq!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            last_answered: None,
            suspect: None
        })
    );
    fixture.enriched("slow-a", Versions::STALL).await;
    fixture.enriched("slow-b", Versions::STALL).await;

    assert!(is_open(fixture.health()));
}

#[tokio::test(start_paused = true)]
async fn a_fast_error_answers_for_the_endpoint_and_a_late_one_is_slow() {
    let fixture = Fixture::new();

    fixture.enriched("fast", Versions::Fail(secs(3))).await;
    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            last_answered: Some(_),
            suspect: None
        })
    );

    let late = Fixture::new();
    late.enriched("late", Versions::Transport(Duration::from_millis(9500)))
        .await;
    assert_matches!(
        late.health(),
        Some(EndpointHealth::Closed {
            last_answered: None,
            suspect: Some(_)
        })
    );
}

#[tokio::test(start_paused = true)]
async fn two_hovers_cancelled_after_half_the_budget_open_the_breaker() {
    let fixture = Fixture::new();

    fixture.cancelled_hover("cancelled-a", secs(6)).await;
    fixture.cancelled_hover("cancelled-b", secs(6)).await;
    let refused = fixture.enriched("third", Versions::Succeed(secs(1))).await;

    assert!(is_open(fixture.health()));
    assert_degraded(&refused, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
    assert!(fixture.gate.is_empty(), "a cancel never writes the memo");
}

#[tokio::test(start_paused = true)]
async fn hovers_cancelled_early_are_no_evidence() {
    let fixture = Fixture::new();

    fixture.cancelled_hover("cancelled-a", secs(2)).await;
    fixture.cancelled_hover("cancelled-b", secs(2)).await;
    let next = fixture.enriched("third", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 3);
    assert!(fixture.gate.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_code_action_is_never_refused_and_its_answer_closes_the_breaker() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;

    let action = fixture.code_action("fix", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(action).len(), 1);
    assert_eq!(fixture.calls(), 3);
    assert_matches!(fixture.health(), Some(EndpointHealth::Closed { .. }));
    let hover = fixture.enriched("after", Versions::Succeed(secs(1))).await;
    assert_eq!(live_list(hover).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_code_action_that_stalls_still_counts_as_slow_evidence() {
    let fixture = Fixture::new();

    fixture.code_action("action-a", Versions::STALL).await;
    fixture.enriched("slow-b", Versions::STALL).await;

    assert!(is_open(fixture.health()));
}

#[tokio::test(start_paused = true)]
async fn the_probe_that_gets_a_list_closes_the_breaker_and_others_wait() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;
    tokio::time::advance(BREAKER_OPEN_DURATION).await;

    let (probe, concurrent) = tokio::join!(
        fixture.enriched("probe", Versions::Succeed(secs(6))),
        async {
            tokio::time::sleep(secs(1)).await;
            fixture
                .enriched("concurrent", Versions::Succeed(secs(1)))
                .await
        },
    );

    assert_eq!(live_list(probe).len(), 1);
    assert_degraded(&concurrent, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 3);
    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            last_answered: Some(_),
            ..
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_probe_reopens_the_breaker() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;
    tokio::time::advance(BREAKER_OPEN_DURATION).await;

    let probe = fixture.enriched("probe", Versions::STALL).await;
    let refused = fixture.enriched("after", Versions::Succeed(secs(1))).await;

    assert_degraded(&probe, NoLiveList::Unverified);
    assert_degraded(&refused, NoLiveList::Unverified);
    assert!(is_open(fixture.health()));
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_chain_whose_second_hop_hangs_after_a_fast_first_hop_opens_the_breaker() {
    let fixture = Fixture::new();

    fixture.enriched("chain-a", Versions::AnswerThenStall).await;
    fixture.enriched("chain-b", Versions::AnswerThenStall).await;

    assert!(is_open(fixture.health()));
}

#[tokio::test(start_paused = true)]
async fn a_paginating_fetch_that_keeps_receiving_responses_never_opens_the_breaker() {
    let fixture = Fixture::new();

    fixture.enriched("paged-a", Versions::Paging).await;
    fixture.enriched("paged-b", Versions::Paging).await;

    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed { suspect: None, .. })
    );
}

#[tokio::test(start_paused = true)]
async fn lookups_that_only_wait_on_a_lock_never_open_the_breaker() {
    let fixture = Fixture::new();

    fixture
        .enriched("waiter-a", Versions::Untouched(secs(60)))
        .await;
    fixture
        .enriched("waiter-b", Versions::Untouched(secs(60)))
        .await;

    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed { suspect: None, .. })
    );
}

#[tokio::test(start_paused = true)]
async fn a_probe_served_without_a_request_does_not_close_the_breaker_but_a_network_probe_does() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;
    tokio::time::advance(BREAKER_OPEN_DURATION).await;

    let memo_probe = fixture.enriched("memo", Versions::Untouched(secs(1))).await;
    assert_eq!(live_list(memo_probe).len(), 1);
    assert!(is_open(fixture.health()), "no response, no vouching");

    let network_probe = fixture.enriched("net", Versions::Succeed(secs(1))).await;
    assert_eq!(live_list(network_probe).len(), 1);
    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            last_answered: Some(_),
            ..
        })
    );
}

#[tokio::test(start_paused = true)]
async fn an_aborted_probe_lets_the_next_request_probe_again() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;
    tokio::time::advance(BREAKER_OPEN_DURATION).await;

    fixture.cancelled_hover("probe", secs(2)).await;
    let next = fixture.enriched("next", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 4);
    assert_matches!(fixture.health(), Some(EndpointHealth::Closed { .. }));
}

#[tokio::test(start_paused = true)]
async fn hovers_for_one_package_on_an_open_breaker_are_all_refused() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;

    let (first, second) = tokio::join!(
        fixture.enriched("third", Versions::Succeed(secs(1))),
        fixture.enriched("third", Versions::Succeed(secs(1))),
    );

    assert_degraded(&first, NoLiveList::Unverified);
    assert_degraded(&second, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn invalidation_resets_the_breaker() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;

    fixture.gate.invalidate_all();
    let next = fixture.enriched("third", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_cancel_that_outlives_an_invalidation_leaves_no_evidence() {
    let fixture = Fixture::new();

    let ((), ()) = tokio::join!(fixture.cancelled_hover("serde", secs(6)), async {
        tokio::time::sleep(secs(1)).await;
        fixture.gate.invalidate_all();
    });

    assert_eq!(fixture.gate.breaker.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_promoted_follower_with_most_of_the_budget_reports_its_elapse() {
    let fixture = Fixture::new();

    cancel_leader_then_follow(&fixture, secs(1), Versions::STALL).await;

    assert_matches!(
        fixture.health(),
        Some(EndpointHealth::Closed {
            suspect: Some(_),
            ..
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_promoted_follower_with_little_budget_left_reports_nothing() {
    let fixture = Fixture::new();
    let start = now();

    cancel_leader_then_follow(&fixture, secs(6), Versions::STALL).await;

    let Some(EndpointHealth::Closed {
        suspect: Some(suspect),
        ..
    }) = fixture.health()
    else {
        panic!("the cancelled leader left a suspect");
    };
    assert_eq!(
        suspect.at,
        start + secs(6),
        "the follower's truncated elapse at 10 s must not refresh the suspect"
    );
}

#[test]
fn a_stale_probe_settling_inconclusive_leaves_a_closed_breaker_closed() {
    let breaker = EndpointBreaker::default();
    let endpoint = Fixture::new().endpoint();
    let (a, b) = (PackageName::new("a"), PackageName::new("b"));
    let start = now();
    breaker.report(&endpoint, &a, AttemptEvidence::Slow, None, start);
    breaker.report(&endpoint, &b, AttemptEvidence::Slow, None, start);
    let reopened = start + BREAKER_OPEN_DURATION;
    let Admission::Probe(probe) = breaker.admit(
        &endpoint,
        BreakerAdmission::Enforce,
        BreakerEvidence::Counts,
        reopened,
    ) else {
        panic!("an expired open breaker hands out the probe");
    };
    breaker.report(&endpoint, &a, AttemptEvidence::Answered, None, reopened);
    let closed = breaker.health(&endpoint);

    breaker.report(
        &endpoint,
        &b,
        AttemptEvidence::Inconclusive,
        Some(probe),
        reopened,
    );
    breaker.report(&endpoint, &b, AttemptEvidence::Slow, Some(probe), reopened);

    assert_eq!(breaker.health(&endpoint), closed);
    assert_matches!(closed, Some(EndpointHealth::Closed { .. }));
}

#[test]
fn the_same_package_twice_is_not_corroboration() {
    let breaker = EndpointBreaker::default();
    let endpoint = Fixture::new().endpoint();
    let package = PackageName::new("a");
    let start = now();

    breaker.report(&endpoint, &package, AttemptEvidence::Slow, None, start);
    breaker.report(
        &endpoint,
        &package,
        AttemptEvidence::Slow,
        None,
        start + secs(1),
    );

    assert_matches!(
        breaker.health(&endpoint),
        Some(EndpointHealth::Closed {
            suspect: Some(_),
            ..
        })
    );
}

#[test]
fn a_stale_suspect_is_not_corroboration() {
    let breaker = EndpointBreaker::default();
    let endpoint = Fixture::new().endpoint();
    let start = now();

    breaker.report(
        &endpoint,
        &PackageName::new("a"),
        AttemptEvidence::Slow,
        None,
        start,
    );
    breaker.report(
        &endpoint,
        &PackageName::new("b"),
        AttemptEvidence::Slow,
        None,
        start + BREAKER_OPEN_DURATION,
    );

    assert_matches!(
        breaker.health(&endpoint),
        Some(EndpointHealth::Closed { .. })
    );
}

#[test]
fn the_breaker_stays_within_its_cap() {
    let breaker = EndpointBreaker::default();
    let package = PackageName::new("a");
    let start = now();
    for index in 0..BREAKER_CAP + 50 {
        let endpoint = breaker_endpoint(index);
        let at = start + Duration::from_millis(index as u64);
        breaker.report(&endpoint, &package, AttemptEvidence::Answered, None, at);
    }

    assert!(breaker.len() <= BREAKER_CAP);
    assert!(
        breaker.len() > BREAKER_CAP / 2,
        "eviction is a bounded batch"
    );
}

impl Fixture {
    async fn lookup(
        &self,
        kind: AuxiliaryLookup,
        name: &str,
        fetch: Fetch,
    ) -> InteractiveFetch<u8> {
        *self.kind.lock().unwrap() = kind;
        self.run(name, &DependencyOutcomes::new(), fetch).await
    }
}

#[tokio::test(start_paused = true)]
async fn an_auxiliary_lookup_gets_half_the_version_list_budget() {
    let fixture = Fixture::new();
    let started = tokio::time::Instant::now();

    let result = fixture
        .lookup(AuxiliaryLookup::Decoration, "serde", Fetch::Stall)
        .await;

    assert_degraded(&result, NoLiveList::Unverified);
    assert_eq!(started.elapsed(), secs(5));
}

#[tokio::test(start_paused = true)]
async fn a_second_request_on_a_timed_out_lookup_returns_at_once_without_a_call() {
    for kind in [AuxiliaryLookup::Decoration, AuxiliaryLookup::PinResolution] {
        let fixture = Fixture::new();
        fixture.lookup(kind, "serde", Fetch::Stall).await;
        let waiting = tokio::time::Instant::now();

        let second = fixture.lookup(kind, "serde", Fetch::Succeed).await;

        assert_degraded(&second, NoLiveList::Unverified);
        assert_eq!(waiting.elapsed(), Duration::ZERO, "{kind:?}");
        assert_eq!(fixture.calls(), 1, "{kind:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_second_request_on_a_failed_lookup_returns_at_once_without_a_call() {
    let fixture = Fixture::new();
    let first = fixture
        .lookup(AuxiliaryLookup::PinResolution, "comp", Fetch::Fail)
        .await;

    let second = fixture
        .lookup(AuxiliaryLookup::PinResolution, "comp", Fetch::Succeed)
        .await;

    assert_degraded(&first, NoLiveList::Failed);
    assert_degraded(&second, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn each_lookup_kind_keeps_its_own_failure_record() {
    let fixture = Fixture::new();
    fixture
        .lookup(AuxiliaryLookup::Decoration, "serde", Fetch::Stall)
        .await;

    let pin = fixture
        .lookup(AuxiliaryLookup::PinResolution, "serde", Fetch::Succeed)
        .await;
    let list = fixture.enriched("serde", Versions::Succeed(secs(1))).await;

    assert_matches!(pin, InteractiveFetch::Live(1));
    assert_eq!(live_list(list).len(), 1);
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn auxiliary_lookups_hold_dispatch_permits_like_version_lists() {
    let fixture = Fixture::new();

    let (_, _, _, version_list) = tokio::join!(
        fixture.lookup(AuxiliaryLookup::Decoration, "a", Fetch::Stall),
        fixture.lookup(AuxiliaryLookup::Decoration, "b", Fetch::Stall),
        fixture.lookup(AuxiliaryLookup::Decoration, "c", Fetch::Stall),
        fixture.enriched("d", Versions::Succeed(secs(1))),
    );

    assert_degraded(&version_list, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn slow_decorations_leave_no_breaker_evidence() {
    let fixture = Fixture::new();

    fixture
        .lookup(AuxiliaryLookup::Decoration, "a", Fetch::Stall)
        .await;
    fixture
        .lookup(AuxiliaryLookup::Decoration, "b", Fetch::Stall)
        .await;
    assert_eq!(fixture.health(), None, "a decoration leaves no evidence");
    let next = fixture.enriched("next", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(next).len(), 1);
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_refused_decoration_cannot_close_the_breaker() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;

    let answered = fixture
        .lookup(AuxiliaryLookup::Decoration, "fast", Fetch::Succeed)
        .await;

    assert_degraded(&answered, NoLiveList::Unverified);
    assert!(is_open(fixture.health()));
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_decoration_cannot_take_the_half_open_probe() {
    let fixture = Fixture::new();
    fixture.open_the_breaker().await;
    tokio::time::advance(BREAKER_OPEN_DURATION).await;

    let decoration = fixture
        .lookup(AuxiliaryLookup::Decoration, "deco", Fetch::Succeed)
        .await;
    assert_degraded(&decoration, NoLiveList::Unverified);
    assert!(is_open(fixture.health()));

    let list = fixture.enriched("probe", Versions::Succeed(secs(1))).await;
    assert_eq!(live_list(list).len(), 1);
    assert_matches!(fixture.health(), Some(EndpointHealth::Closed { .. }));
}

#[tokio::test(start_paused = true)]
async fn slow_pin_resolutions_open_the_breaker_for_version_lists() {
    let fixture = Fixture::new();

    fixture
        .lookup(AuxiliaryLookup::PinResolution, "a", Fetch::Stall)
        .await;
    fixture
        .lookup(AuxiliaryLookup::PinResolution, "b", Fetch::Stall)
        .await;
    let refused = fixture.enriched("c", Versions::Succeed(secs(1))).await;

    assert!(is_open(fixture.health()));
    assert_degraded(&refused, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_truncated_leaders_failure_is_not_adopted_by_a_request_that_joined_it() {
    let fixture = Fixture::new();

    let ((), promoted, joiner) = tokio::join!(
        fixture.cancelled_hover("serde", secs(6)),
        fixture.enriched("serde", Versions::STALL),
        async {
            tokio::time::sleep(secs(7)).await;
            fixture.enriched("serde", Versions::Succeed(secs(1))).await
        },
    );

    assert_degraded(&promoted, NoLiveList::Unverified);
    assert_eq!(
        live_list(joiner).len(),
        1,
        "the joiner follows the truncated leader, then takes over and answers itself"
    );
    assert_eq!(fixture.calls(), 3);
    assert_eq!(fixture.gate.in_flight_len(), 0);
}

fn breaker_endpoint(index: usize) -> EndpointKey {
    scoped_endpoint(&manifest(&format!("/project-{index}/Cargo.toml")))
}

fn open_endpoint(breaker: &EndpointBreaker, endpoint: &EndpointKey, at: std::time::Instant) {
    for package in ["a", "b"] {
        breaker.report(
            endpoint,
            &PackageName::new(package),
            AttemptEvidence::Slow,
            None,
            at,
        );
    }
    assert_matches!(breaker.health(endpoint), Some(EndpointHealth::Open { .. }));
}

#[test]
fn a_full_breaker_evicts_a_closed_endpoint_before_an_open_one() {
    let breaker = EndpointBreaker::default();
    let start = now();
    let closed = breaker_endpoint(0);
    breaker.report(
        &closed,
        &PackageName::new("a"),
        AttemptEvidence::Answered,
        None,
        start,
    );
    for index in 1..BREAKER_CAP {
        open_endpoint(
            &breaker,
            &breaker_endpoint(index),
            start + Duration::from_millis(index as u64),
        );
    }
    assert_eq!(breaker.len(), BREAKER_CAP);

    let newcomer = breaker_endpoint(BREAKER_CAP);
    breaker.report(
        &newcomer,
        &PackageName::new("a"),
        AttemptEvidence::Answered,
        None,
        start + secs(1),
    );

    assert_eq!(breaker.len(), BREAKER_CAP);
    assert_eq!(
        breaker.health(&closed),
        None,
        "the closed endpoint made room"
    );
    assert!(breaker.health(&newcomer).is_some());
    for index in 1..BREAKER_CAP {
        assert_matches!(
            breaker.health(&breaker_endpoint(index)),
            Some(EndpointHealth::Open { .. }),
            "open endpoint {index} must survive"
        );
    }
}

#[test]
fn a_breaker_full_of_open_endpoints_does_not_track_a_newcomer() {
    let breaker = EndpointBreaker::default();
    let start = now();
    for index in 0..BREAKER_CAP {
        open_endpoint(&breaker, &breaker_endpoint(index), start);
    }

    let newcomer = breaker_endpoint(BREAKER_CAP);
    breaker.report(
        &newcomer,
        &PackageName::new("a"),
        AttemptEvidence::Answered,
        None,
        start + secs(1),
    );

    assert_eq!(breaker.len(), BREAKER_CAP);
    assert_eq!(breaker.health(&newcomer), None);
}

#[test]
fn an_expired_open_endpoint_is_evicted_to_make_room() {
    let breaker = EndpointBreaker::default();
    let start = now();
    for index in 0..BREAKER_CAP {
        open_endpoint(&breaker, &breaker_endpoint(index), start);
    }

    let newcomer = breaker_endpoint(BREAKER_CAP);
    breaker.report(
        &newcomer,
        &PackageName::new("a"),
        AttemptEvidence::Answered,
        None,
        start + BREAKER_OPEN_DURATION,
    );

    assert_eq!(breaker.len(), 1);
    assert!(breaker.health(&newcomer).is_some());
}

fn url(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

fn endpoint_at(text: &str, egress: EgressTier) -> RegistryEndpoint {
    RegistryEndpoint::base(&url(text), egress)
}

fn registry_at(text: &str, egress: EgressTier) -> MockRegistry {
    MockRegistry::new().with_endpoint(endpoint_at(text, egress))
}

fn route_of(
    fixture: &Fixture,
    registry: &MockRegistry,
    ecosystem: EcosystemId,
    name: &str,
) -> EndpointKey {
    let package = PackageName::new(name);
    let source = DependencySource::Registry;
    let outcomes = DependencyOutcomes::new();
    let request = InteractiveFetchRequest::new(
        VersionData::new(&fixture.cached, &fixture.resolved)
            .with_ecosystem(ecosystem)
            .with_outcomes(&outcomes)
            .with_interactive_fetch_gate(&fixture.gate),
        &fixture.manifest,
        &package,
        name,
        &source,
        FetchContext::Hover,
    );
    let (_, lookup) = request
        .gated(registry, LookupKind::VersionList)
        .expect("a gated request");
    lookup.route.endpoint()
}

#[test]
fn routes_split_by_endpoint_egress_and_ecosystem_but_not_by_manifest() {
    let fixture = Fixture::new();
    let local = registry_at("https://art.corp/npm/local/", EgressTier::Baseline);
    let remote = registry_at("https://art.corp/npm/remote/", EgressTier::Baseline);
    let guarded = registry_at("https://art.corp/npm/local/", EgressTier::Guarded);
    let cargo = EcosystemId::Cargo;
    let reference = route_of(&fixture, &local, cargo, "pkg");

    assert_eq!(reference, route_of(&fixture, &local, cargo, "other-pkg"));
    assert_ne!(reference, route_of(&fixture, &remote, cargo, "pkg"));
    assert_ne!(reference, route_of(&fixture, &guarded, cargo, "pkg"));
    assert_ne!(
        reference,
        route_of(&fixture, &local, EcosystemId::Npm, "pkg")
    );
    let elsewhere = Fixture {
        manifest: manifest("/elsewhere/Cargo.toml"),
        ..Fixture::new()
    };
    assert_eq!(reference, route_of(&elsewhere, &local, cargo, "pkg"));
}

#[tokio::test(start_paused = true)]
async fn a_resolved_endpoint_shares_breaker_and_memo_across_manifests() {
    let fixture =
        Fixture::new().with_endpoint(endpoint_at("https://art.corp/npm/", EgressTier::Baseline));
    let (none, source) = (DependencyOutcomes::new(), DependencySource::Registry);
    let online = NetworkMode::Online;
    for (name, path) in [("slow-a", "/one/p.json"), ("slow-b", "/two/p.json")] {
        fixture
            .run_full(&manifest(path), name, &source, &none, online, Fetch::Stall)
            .await;
    }

    let refused = fixture
        .run_full(
            &manifest("/three/p.json"),
            "third",
            &source,
            &none,
            online,
            Fetch::Succeed,
        )
        .await;
    let memoized = fixture
        .run_full(
            &manifest("/four/p.json"),
            "slow-a",
            &source,
            &none,
            online,
            Fetch::Succeed,
        )
        .await;

    assert_degraded(&refused, NoLiveList::Unverified);
    assert_degraded(&memoized, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_unresolved_endpoint_keeps_the_breaker_per_manifest() {
    let fixture = Fixture::new();
    let (none, source) = (DependencyOutcomes::new(), DependencySource::Registry);
    let online = NetworkMode::Online;
    for (name, path) in [("slow-a", "/one/p.json"), ("slow-b", "/two/p.json")] {
        fixture
            .run_full(&manifest(path), name, &source, &none, online, Fetch::Stall)
            .await;
    }

    let live = fixture
        .run_full(
            &manifest("/one/p.json"),
            "third",
            &source,
            &none,
            online,
            Fetch::Succeed,
        )
        .await;

    assert_matches!(live, InteractiveFetch::Live(1));
    assert_eq!(fixture.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn two_endpoints_of_one_manifest_have_independent_breakers() {
    let fixture = Fixture::new();
    let (none, source) = (DependencyOutcomes::new(), DependencySource::Registry);
    let online = NetworkMode::Online;
    let dead = registry_at("https://dead.example/", EgressTier::Baseline);
    let live = registry_at("https://live.example/", EgressTier::Baseline);
    let at = &fixture.manifest;
    for name in ["slow-a", "slow-b"] {
        fixture
            .run_via(&dead, at, name, &source, &none, online, Fetch::Stall)
            .await;
    }

    let healthy = fixture
        .run_via(&live, at, "other", &source, &none, online, Fetch::Succeed)
        .await;
    let refused = fixture
        .run_via(&dead, at, "third", &source, &none, online, Fetch::Succeed)
        .await;

    assert_matches!(healthy, InteractiveFetch::Live(1));
    assert_degraded(&refused, NoLiveList::Unverified);
}

#[tokio::test(start_paused = true)]
async fn a_pin_resolution_honors_a_stalled_version_list_without_polling() {
    let fixture = Fixture::new();
    let started = tokio::time::Instant::now();
    fixture.enriched("comp", Versions::STALL).await;

    let pin = fixture
        .lookup(AuxiliaryLookup::PinResolution, "comp", Fetch::Succeed)
        .await;

    assert_degraded(&pin, NoLiveList::Unverified);
    assert_eq!(started.elapsed(), secs(10), "the pin fetch costs nothing");
    assert_eq!(fixture.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_pin_resolution_does_not_degrade_the_version_list() {
    let fixture = Fixture::new();
    fixture
        .lookup(AuxiliaryLookup::PinResolution, "comp", Fetch::Stall)
        .await;

    let list = fixture.enriched("comp", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(list).len(), 1);
    assert_eq!(fixture.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_latest_fallback_ignores_the_background_failure_but_keeps_its_own_record() {
    let fixture = Fixture::new();
    let outcomes = failing("serde", FetchFailure::Transient);
    *fixture.kind.lock().unwrap() = AuxiliaryLookup::LatestFallback;

    let polled = fixture.run("serde", &outcomes, Fetch::Stall).await;
    let replay = fixture.run("serde", &outcomes, Fetch::Succeed).await;

    assert_degraded(&polled, NoLiveList::Unverified);
    assert_degraded(&replay, NoLiveList::Unverified);
    assert_eq!(
        fixture.calls(),
        1,
        "the seed was ignored; the memo replayed"
    );
    assert_eq!(fixture.gate.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_latest_fallback_does_not_degrade_the_version_list() {
    let fixture = Fixture::new();
    fixture
        .lookup(AuxiliaryLookup::LatestFallback, "serde", Fetch::Stall)
        .await;

    let list = fixture.enriched("serde", Versions::Succeed(secs(1))).await;

    assert_eq!(live_list(list).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_latest_fallback_counts_for_the_endpoint_breaker() {
    let fixture = Fixture::new();

    fixture
        .lookup(AuxiliaryLookup::LatestFallback, "a", Fetch::Stall)
        .await;
    fixture
        .lookup(AuxiliaryLookup::LatestFallback, "b", Fetch::Stall)
        .await;

    assert!(is_open(fixture.health()));
}

#[tokio::test(start_paused = true)]
async fn a_local_failure_is_no_evidence_but_an_endpoint_failure_answers() {
    let none = DependencyOutcomes::new();
    let local = Fixture::new();
    local.run("slow-a", &none, Fetch::Stall).await;
    local.run("blocked", &none, Fetch::FailLocal).await;
    local.run("slow-b", &none, Fetch::Stall).await;
    assert!(
        is_open(local.health()),
        "a local failure vouches for nothing"
    );

    let remote = Fixture::new();
    remote.run("slow-a", &none, Fetch::Stall).await;
    remote.run("refused", &none, Fetch::Fail).await;
    remote.run("slow-b", &none, Fetch::Stall).await;
    assert_matches!(remote.health(), Some(EndpointHealth::Closed { .. }));
}

#[test]
fn lookup_kinds_follow_the_policy_table() {
    use super::key::{BackgroundSeed, MAX_LOOKUP_BUDGET};
    let pin = LookupKind::Auxiliary(AuxiliaryLookup::PinResolution);
    let decoration = LookupKind::Auxiliary(AuxiliaryLookup::Decoration);
    let fallback = LookupKind::Auxiliary(AuxiliaryLookup::LatestFallback);
    let (counts, ignored) = (BreakerEvidence::Counts, BreakerEvidence::Ignored);
    let (applies, not_applied) = (BackgroundSeed::Applies, BackgroundSeed::Ignored);
    let honors_list = Some(LookupKind::VersionList);
    let cases = [
        (LookupKind::VersionList, secs(10), counts, applies, None),
        (pin, secs(5), counts, applies, honors_list),
        (decoration, secs(5), ignored, applies, None),
        (fallback, secs(5), counts, not_applied, None),
    ];
    for (kind, budget, evidence, seed, honors) in cases {
        assert_eq!(kind.budget(), budget, "{kind:?}");
        assert_eq!(kind.breaker_evidence(), evidence, "{kind:?}");
        assert_eq!(kind.background_seed(), seed, "{kind:?}");
        assert_eq!(kind.memo_policy().honors, honors, "{kind:?}");
        assert!(kind.budget() <= MAX_LOOKUP_BUDGET, "{kind:?}");
    }
}

/// Opens `endpoint` at `start` and takes its probe once the open period ran out.
fn expired_probe(
    breaker: &EndpointBreaker,
    endpoint: &EndpointKey,
    start: std::time::Instant,
) -> (ProbeId, std::time::Instant) {
    open_endpoint(breaker, endpoint, start);
    let reopened = start + BREAKER_OPEN_DURATION;
    let Admission::Probe(probe) = breaker.admit(
        endpoint,
        BreakerAdmission::Enforce,
        BreakerEvidence::Counts,
        reopened,
    ) else {
        panic!("an expired open breaker hands out the probe");
    };
    (probe, reopened)
}

fn report_for(
    breaker: &EndpointBreaker,
    endpoint: &EndpointKey,
    evidence: AttemptEvidence,
    probe: Option<ProbeId>,
    at: std::time::Instant,
) {
    breaker.report(endpoint, &PackageName::new("a"), evidence, probe, at);
}

#[test]
fn verdict_follows_the_health_table() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let (_, reopened) = expired_probe(&breaker, &endpoint, start);
    let half_open = breaker.health(&endpoint).unwrap();
    let open = EndpointHealth::Open {
        until: start + BREAKER_OPEN_DURATION,
    };
    let closed = EndpointHealth::Closed {
        last_answered: None,
        suspect: None,
    };
    let lease_end = reopened + PROBE_LEASE;
    let (counts, ignored) = (BreakerEvidence::Counts, BreakerEvidence::Ignored);
    let before_expiry = start + BREAKER_OPEN_DURATION.saturating_sub(secs(1));

    assert_eq!(verdict(None, counts, start), Verdict::Proceed);
    assert_eq!(verdict(Some(&closed), counts, start), Verdict::Proceed);
    assert_eq!(verdict(Some(&open), counts, before_expiry), Verdict::Refuse);
    assert_eq!(verdict(Some(&open), counts, reopened), Verdict::TakeProbe);
    assert_eq!(verdict(Some(&open), ignored, reopened), Verdict::Refuse);
    let within_lease = reopened + PROBE_LEASE.saturating_sub(secs(1));
    assert_eq!(
        verdict(Some(&half_open), counts, within_lease),
        Verdict::Refuse
    );
    assert_eq!(
        verdict(Some(&half_open), counts, lease_end),
        Verdict::TakeProbe
    );
    assert_eq!(
        verdict(Some(&half_open), ignored, lease_end),
        Verdict::Refuse,
        "an expired lease must not hand a probe to a lookup that cannot settle it"
    );
}

#[test]
fn the_write_pass_re_decides_on_the_current_entry() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let counts = BreakerEvidence::Counts;
    assert_eq!(
        breaker.take_probe(&endpoint, counts, start),
        Admission::Proceed,
        "vacant"
    );

    report_for(&breaker, &endpoint, AttemptEvidence::Answered, None, start);
    assert_eq!(
        breaker.take_probe(&endpoint, counts, start),
        Admission::Proceed,
        "turned closed"
    );

    let other = breaker_endpoint(1);
    let (_, reopened) = expired_probe(&breaker, &other, start);
    assert_eq!(
        breaker.take_probe(&other, counts, reopened),
        Admission::Refused,
        "fresh half-open"
    );
}

#[test]
fn a_probe_that_ends_inconclusive_leaves_the_next_request_to_probe() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let (probe, reopened) = expired_probe(&breaker, &endpoint, start);

    let inconclusive = AttemptEvidence::Inconclusive;
    report_for(&breaker, &endpoint, inconclusive, Some(probe), reopened);

    assert_eq!(
        breaker.health(&endpoint),
        Some(EndpointHealth::Open { until: reopened })
    );
    assert_matches!(
        breaker.admit(
            &endpoint,
            BreakerAdmission::Enforce,
            BreakerEvidence::Counts,
            reopened
        ),
        Admission::Probe(_)
    );
}

#[test]
fn a_lost_probe_expires_and_a_stale_probe_can_only_close() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let (stale, reopened) = expired_probe(&breaker, &endpoint, start);
    let later = reopened + PROBE_LEASE;
    let Admission::Probe(fresh) = breaker.admit(
        &endpoint,
        BreakerAdmission::Enforce,
        BreakerEvidence::Counts,
        later,
    ) else {
        panic!("a lost probe is reissued once its lease ends");
    };
    assert_ne!(stale, fresh);
    let held = breaker.health(&endpoint);

    report_for(
        &breaker,
        &endpoint,
        AttemptEvidence::Slow,
        Some(stale),
        later,
    );
    let inconclusive = AttemptEvidence::Inconclusive;
    report_for(&breaker, &endpoint, inconclusive, Some(stale), later);
    assert_eq!(
        breaker.health(&endpoint),
        held,
        "a stale probe cannot reopen"
    );

    let answered = AttemptEvidence::Answered;
    report_for(&breaker, &endpoint, answered, Some(stale), later);
    assert_matches!(
        breaker.health(&endpoint),
        Some(EndpointHealth::Closed { .. })
    );
}

/// S1: the read pass of `report` sees `Closed{suspect: a}` and a corroborating slow `b` would
/// open the breaker; a concurrent live answer lands before the write pass. The write pass must
/// fold `b` into the answered state, not write the `Open` the stale read implied.
#[test]
fn a_report_applies_to_the_current_health_not_to_an_earlier_read() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let (a, b, c) = (
        PackageName::new("a"),
        PackageName::new("b"),
        PackageName::new("c"),
    );
    breaker.report(&endpoint, &a, AttemptEvidence::Slow, None, start);

    breaker.report_between(
        &endpoint,
        &b,
        AttemptEvidence::Slow,
        None,
        start + secs(2),
        || {
            breaker.report(
                &endpoint,
                &c,
                AttemptEvidence::Answered,
                None,
                start + secs(1),
            );
        },
    );

    assert_matches!(
        breaker.health(&endpoint),
        Some(EndpointHealth::Closed {
            last_answered: Some(_),
            suspect: None
        })
    );
}

#[test]
fn answers_inside_the_refresh_window_do_not_rewrite_the_entry() {
    let (breaker, endpoint, start) = (EndpointBreaker::default(), breaker_endpoint(0), now());
    let answered_at = || match breaker.health(&endpoint) {
        Some(EndpointHealth::Closed { last_answered, .. }) => last_answered,
        other => panic!("expected a closed endpoint, got {other:?}"),
    };
    let answered = AttemptEvidence::Answered;
    report_for(&breaker, &endpoint, answered, None, start);

    report_for(&breaker, &endpoint, answered, None, start + secs(1));
    assert_eq!(answered_at(), Some(start));
    let inconclusive = AttemptEvidence::Inconclusive;
    report_for(&breaker, &endpoint, inconclusive, None, start + secs(2));
    assert_eq!(answered_at(), Some(start));
    report_for(&breaker, &endpoint, answered, None, start + secs(6));
    assert_eq!(answered_at(), Some(start + secs(6)));
}

#[test]
fn a_full_breaker_makes_room_with_a_bounded_batch_of_closed_endpoints() {
    let breaker = EndpointBreaker::default();
    let start = now();
    let answered = AttemptEvidence::Answered;
    for index in 0..BREAKER_CAP {
        report_for(&breaker, &breaker_endpoint(index), answered, None, start);
    }
    assert_eq!(breaker.len(), BREAKER_CAP);

    let newcomer = breaker_endpoint(BREAKER_CAP);
    report_for(&breaker, &newcomer, answered, None, start + secs(1));

    assert_eq!(breaker.len(), BREAKER_CAP - BREAKER_CAP / 10 + 1);
    assert!(breaker.health(&newcomer).is_some());
}

#[tokio::test(start_paused = true)]
async fn the_memo_evicts_exactly_one_oldest_record_per_insert_at_the_cap() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();
    for index in 0..INTERACTIVE_MEMO_CAP {
        fixture
            .run(&format!("pkg{index}"), &none, Fetch::Fail)
            .await;
        tokio::time::advance(Duration::from_millis(1)).await;
    }

    fixture.run("overflow", &none, Fetch::Fail).await;

    assert_eq!(fixture.gate.len(), INTERACTIVE_MEMO_CAP);
    let calls = fixture.calls();
    let oldest = fixture.run("pkg0", &none, Fetch::Succeed).await;
    let next_oldest = fixture.run("pkg1", &none, Fetch::Succeed).await;
    assert_matches!(oldest, InteractiveFetch::Live(1));
    assert_degraded(&next_oldest, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), calls + 1);
}

#[tokio::test(start_paused = true)]
async fn slow_local_failures_of_distinct_packages_open_the_breaker() {
    let fixture = Fixture::new();
    let none = DependencyOutcomes::new();

    fixture.run("dns-a", &none, Fetch::FailLocalSlow).await;
    fixture.run("dns-b", &none, Fetch::FailLocalSlow).await;

    assert!(is_open(fixture.health()));
}

#[tokio::test(start_paused = true)]
async fn a_seed_from_one_manifest_survives_another_manifests_clean_request() {
    let fixture =
        Fixture::new().with_endpoint(endpoint_at("https://art.corp/npm/", EgressTier::Baseline));
    let source = DependencySource::Registry;
    let online = NetworkMode::Online;
    let (first, second) = (manifest("/one/p.json"), manifest("/two/p.json"));
    let failing = failing("serde", FetchFailure::Transient);
    let clean = DependencyOutcomes::new();
    let fetch = Fetch::Succeed;

    let seeded = fixture
        .run_full(&first, "serde", &source, &failing, online, fetch)
        .await;
    let other = fixture
        .run_full(&second, "serde", &source, &clean, online, fetch)
        .await;
    let again = fixture
        .run_full(&first, "serde", &source, &failing, online, fetch)
        .await;

    assert_degraded(&seeded, NoLiveList::Unverified);
    assert_matches!(other, InteractiveFetch::Live(1));
    assert_degraded(&again, NoLiveList::Unverified);
    assert_eq!(fixture.calls(), 1, "only the clean manifest fetched");
    assert_eq!(
        fixture.gate.len(),
        1,
        "the seed was neither removed nor rewritten"
    );
}

#[tokio::test(start_paused = true)]
async fn a_latest_fallback_is_not_starved_by_a_saturated_gate() {
    let fixture = Fixture::new();

    let (_, _, _, fallback) = tokio::join!(
        fixture.lookup(AuxiliaryLookup::Decoration, "a", Fetch::Stall),
        fixture.lookup(AuxiliaryLookup::Decoration, "b", Fetch::Stall),
        fixture.lookup(AuxiliaryLookup::Decoration, "c", Fetch::Stall),
        fixture.lookup(AuxiliaryLookup::LatestFallback, "d", Fetch::Succeed),
    );

    assert_matches!(fallback, InteractiveFetch::Live(1));
}

mod coalesced;
