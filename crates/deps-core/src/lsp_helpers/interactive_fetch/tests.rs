use std::assert_matches;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use super::memo::{Decision, FastFail, INTERACTIVE_FAILURE_TTL, INTERACTIVE_MEMO_CAP};
use super::*;
use crate::lsp_helpers::DependencyOutcomes;
use crate::test_util::{MockRegistry, MockVersion};
use crate::{ConcreteVersion, EcosystemId, FetchFailure};

#[derive(Clone, Copy)]
enum Fetch {
    Succeed,
    Fail,
    Stall,
}

struct Fixture {
    gate: InteractiveFetchGate,
    cached: HashMap<PackageName, crate::PackageVersions>,
    resolved: HashMap<PackageName, ConcreteVersion>,
    calls: AtomicUsize,
    manifest: url::Url,
}

fn manifest(path: &str) -> url::Url {
    url::Url::parse(&format!("file://{path}")).unwrap()
}

impl Fixture {
    fn new() -> Self {
        Self {
            gate: InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap()),
            cached: HashMap::new(),
            resolved: HashMap::new(),
            calls: AtomicUsize::new(0),
            manifest: manifest("/project/Cargo.toml"),
        }
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
        let package = PackageName::new(name);
        let versions = VersionData::new(&self.cached, &self.resolved)
            .with_ecosystem(EcosystemId::Cargo)
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
        await_interactive_fetch(
            async {
                self.calls.fetch_add(1, Ordering::SeqCst);
                match fetch {
                    Fetch::Succeed => Ok(1),
                    Fetch::Fail => Err(()),
                    Fetch::Stall => {
                        tokio::time::sleep(REGISTRY_FETCH_BUDGET + Duration::from_secs(5)).await;
                        Ok(1)
                    }
                }
            },
            request,
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
    assert!(
        matches!(result, InteractiveFetch::Degraded(kind) if *kind == expected),
        "expected Degraded({expected:?})"
    );
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
    let (gate, key) = request.gated().unwrap();
    let generation = gate.generation();
    gate.invalidate_all();

    let decision = gate.decide(&key, true, generation, now());

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

    let result = await_interactive_fetch(async { Ok::<_, ()>(1_u8) }, request).await;

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
    Succeed(Duration),
    Fail(Duration),
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
        let package = PackageName::new(name);
        let source = DependencySource::Registry;
        let outcomes = DependencyOutcomes::new();
        let request = InteractiveFetchRequest::new(
            VersionData::new(&self.cached, &self.resolved)
                .with_ecosystem(EcosystemId::Cargo)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&self.gate),
            &self.manifest,
            &package,
            name,
            &source,
            FetchContext::Hover,
        );
        let (gate, key) = request.gated().unwrap();
        let fetch = async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match behavior {
                Versions::Succeed(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(list())
                }
                Versions::Fail(delay) => {
                    tokio::time::sleep(delay).await;
                    Err(())
                }
            }
        };
        flight::await_shared(gate, key, fetch, &request, ListShape::of(freshness)).await
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
