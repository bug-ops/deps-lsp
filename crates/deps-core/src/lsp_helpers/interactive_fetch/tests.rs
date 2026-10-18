use std::assert_matches;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use super::attempt::{AttemptEnd, AttemptEvidence, evidence};
use super::breaker::{
    Admission, BREAKER_CAP, BREAKER_OPEN_DURATION, BreakerAdmission, EndpointBreaker,
    EndpointHealth,
};
use super::key::{
    BreakerEvidence, EndpointKey, LookupKind, ManifestFingerprint, SourceFingerprint,
};
use super::memo::{Decision, FastFail, INTERACTIVE_FAILURE_TTL, INTERACTIVE_MEMO_CAP};
use super::*;
use crate::lsp_helpers::DependencyOutcomes;
use crate::lsp_helpers::REGISTRY_FETCH_BUDGET;
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
    kind: std::sync::Mutex<AuxiliaryLookup>,
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
            kind: std::sync::Mutex::new(AuxiliaryLookup::PinResolution),
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
        let kind = *self.kind.lock().unwrap();
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
    let (gate, key) = request.gated(LookupKind::VersionList).unwrap();
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

    let result = await_interactive_fetch(
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
                .with_ecosystem(EcosystemId::Cargo)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&self.gate),
            &self.manifest,
            &package,
            name,
            &source,
            context,
        );
        let (gate, key) = request.gated(LookupKind::VersionList).unwrap();
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

impl Fixture {
    fn endpoint(&self) -> EndpointKey {
        EndpointKey {
            ecosystem: EcosystemId::Cargo,
            manifest: ManifestFingerprint::of(&self.manifest),
            source: SourceFingerprint::of(&DependencySource::Registry),
        }
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

fn is_open(health: Option<EndpointHealth>) -> bool {
    matches!(health, Some(EndpointHealth::Open { .. }))
}

#[test]
fn evidence_follows_the_unified_table() {
    let budget = secs(10);
    let just_under = |limit: Duration| limit.saturating_sub(Duration::from_millis(1));
    let cases = [
        (
            AttemptEnd::Live,
            just_under(secs(9)),
            AttemptEvidence::Answered,
        ),
        (AttemptEnd::Live, secs(9), AttemptEvidence::Inconclusive),
        (AttemptEnd::Live, secs(10), AttemptEvidence::Inconclusive),
        (
            AttemptEnd::Err,
            just_under(secs(9)),
            AttemptEvidence::Answered,
        ),
        (AttemptEnd::Err, secs(9), AttemptEvidence::Slow),
        (AttemptEnd::Elapsed, secs(10), AttemptEvidence::Slow),
        (AttemptEnd::Elapsed, secs(5), AttemptEvidence::Slow),
        (
            AttemptEnd::Elapsed,
            just_under(secs(5)),
            AttemptEvidence::Inconclusive,
        ),
        (AttemptEnd::Cancelled, secs(5), AttemptEvidence::Slow),
        (
            AttemptEnd::Cancelled,
            just_under(secs(5)),
            AttemptEvidence::Inconclusive,
        ),
        (
            AttemptEnd::Cancelled,
            Duration::ZERO,
            AttemptEvidence::Inconclusive,
        ),
    ];
    for (end, waited, expected) in cases {
        assert_eq!(
            evidence(end, waited, budget),
            expected,
            "{end:?} after {waited:?}"
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
    late.enriched("late", Versions::Fail(Duration::from_millis(9500)))
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
        let manifest = manifest(&format!("/project-{index}/Cargo.toml"));
        let endpoint = EndpointKey {
            ecosystem: EcosystemId::Cargo,
            manifest: ManifestFingerprint::of(&manifest),
            source: SourceFingerprint::of(&DependencySource::Registry),
        };
        let at = start + Duration::from_millis(index as u64);
        breaker.report(&endpoint, &package, AttemptEvidence::Answered, None, at);
    }

    assert_eq!(breaker.len(), BREAKER_CAP);
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
