//! Breaker evidence for attempts that wait on a request another task put on the wire.

use super::*;
use crate::endpoint_contact::AttemptContact;
use crate::observe_endpoint;

const fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// A task of the background fetch that holds one request on `endpoint` for `hold`.
async fn holds_request(ecosystem: EcosystemId, endpoint: RegistryEndpoint, hold: Duration) {
    observe_endpoint(ecosystem, endpoint, async move {
        let _note = note_request();
        tokio::time::sleep(hold).await;
    })
    .await;
}

/// A task that holds the shared lock or cell for `hold` with no request on the wire.
async fn holds_idle(ecosystem: EcosystemId, endpoint: RegistryEndpoint, hold: Duration) {
    observe_endpoint(ecosystem, endpoint, tokio::time::sleep(hold)).await;
}

/// `count` pages that each answer after a second.
async fn pages(ecosystem: EcosystemId, endpoint: RegistryEndpoint, count: u32) {
    observe_endpoint(ecosystem, endpoint, async move {
        for _ in 0..count {
            let note = note_request();
            tokio::time::sleep(secs(1)).await;
            note.answered();
        }
    })
    .await;
}

fn endpoint_of(host: &str) -> RegistryEndpoint {
    endpoint_at(
        &format!("https://{host}.coalesce.example/"),
        EgressTier::Baseline,
    )
}

impl Fixture {
    fn resolved_health(&self) -> Option<EndpointHealth> {
        let route = route_of(self, &self.registry, self.ecosystem, "probe");
        self.gate.breaker.health(&route)
    }

    async fn cancelled_with(&self, name: &str, after: Duration, behavior: Versions) {
        let outcome = tokio::time::timeout(after, self.enriched(name, behavior)).await;
        assert!(outcome.is_err(), "the hover must still be waiting");
    }

    /// Hovers `a` and `b` from 0.5 s to 6.0 s, then hovers `c` at 6.1 s.
    async fn two_cancelled_then_a_third(
        &self,
        behavior: Versions,
    ) -> InteractiveFetch<SharedVersions> {
        tokio::time::sleep(ms(500)).await;
        tokio::join!(
            self.cancelled_with("a", ms(5500), behavior),
            self.cancelled_with("b", ms(5500), behavior),
        );
        tokio::time::sleep(ms(100)).await;
        self.enriched("c", Versions::Untouched(secs(1))).await
    }

    async fn two_cancelled_after(&self, after: Duration, behavior: Versions) {
        tokio::join!(
            self.cancelled_with("a", after, behavior),
            self.cancelled_with("b", after, behavior),
        );
    }
}

/// Which shared wait an ecosystem's interactive attempt may sit in.
enum SharedWait {
    None,
    ServiceIndexCell,
    PerRepositoryLock,
}

/// Exhaustive on purpose: a new ecosystem must decide here whether it coalesces.
const fn shared_wait(ecosystem: EcosystemId) -> SharedWait {
    match ecosystem {
        EcosystemId::Cargo
        | EcosystemId::Npm
        | EcosystemId::Pypi
        | EcosystemId::Go
        | EcosystemId::Bundler
        | EcosystemId::Dart
        | EcosystemId::Maven
        | EcosystemId::Composer
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::Deno
        | EcosystemId::GitlabCi => SharedWait::None,
        EcosystemId::NuGet => SharedWait::ServiceIndexCell,
        EcosystemId::GithubActions => SharedWait::PerRepositoryLock,
    }
}

#[tokio::test(start_paused = true)]
async fn every_ecosystem_opens_the_breaker_for_own_requests_and_for_waiters() {
    for &ecosystem in EcosystemId::ALL {
        let label = match shared_wait(ecosystem) {
            SharedWait::None => "no shared wait",
            SharedWait::ServiceIndexCell => "service index cell",
            SharedWait::PerRepositoryLock => "per-repository lock",
        };

        let own = Fixture::new()
            .with_ecosystem(ecosystem)
            .with_endpoint(endpoint_of(&format!("own-{}", ecosystem.id())));
        let refused = own.two_cancelled_then_a_third(Versions::STALL).await;
        assert_degraded(&refused, NoLiveList::Unverified);
        assert_eq!(own.calls(), 2, "{ecosystem} own request ({label})");

        let endpoint = endpoint_of(&format!("wait-{}", ecosystem.id()));
        let waiter = Fixture::new()
            .with_ecosystem(ecosystem)
            .with_endpoint(endpoint);
        let refused = tokio::select! {
            () = holds_request(ecosystem, endpoint, secs(300)) => unreachable!(),
            refused = waiter.two_cancelled_then_a_third(Versions::Untouched(secs(60))) => refused,
        };
        assert_degraded(&refused, NoLiveList::Unverified);
        assert_eq!(waiter.calls(), 2, "{ecosystem} waiter ({label})");
        assert!(is_open(waiter.resolved_health()), "{ecosystem} ({label})");
    }
}

#[tokio::test(start_paused = true)]
async fn a_takeover_after_the_holder_is_dropped_still_reads_as_slow() {
    let endpoint = endpoint_of("takeover");
    let fixture = Fixture::new().with_endpoint(endpoint);

    tokio::join!(
        holds_request(EcosystemId::Cargo, endpoint, secs(5)),
        fixture.two_cancelled_then_a_third(Versions::WaitThenStall(ms(4500))),
    );

    assert!(is_open(fixture.resolved_health()));
}

#[tokio::test(start_paused = true)]
async fn a_waiter_joining_a_request_outstanding_for_59_seconds_is_not_slow() {
    let endpoint = endpoint_of("late-join");
    let fixture = Fixture::new().with_endpoint(endpoint);
    let late = async {
        tokio::time::sleep(secs(59)).await;
        fixture
            .two_cancelled_after(ms(100), Versions::Untouched(secs(60)))
            .await;
    };

    tokio::select! {
        () = holds_request(EcosystemId::Cargo, endpoint, secs(300)) => unreachable!(),
        () = late => {}
    }

    assert!(!is_open(fixture.resolved_health()));
}

#[tokio::test(start_paused = true)]
async fn waiting_on_a_paging_holder_never_opens_the_breaker() {
    let endpoint = endpoint_of("paging");
    let fixture = Fixture::new().with_endpoint(endpoint);

    tokio::select! {
        () = pages(EcosystemId::Cargo, endpoint, 20) => unreachable!(),
        () = fixture.two_cancelled_after(secs(9), Versions::Untouched(secs(60))) => {}
    }

    assert!(!is_open(fixture.resolved_health()));
}

#[tokio::test(start_paused = true)]
async fn waiting_on_a_holder_with_no_request_is_inconclusive() {
    let endpoint = endpoint_of("idle-holder");
    let fixture = Fixture::new().with_endpoint(endpoint);

    tokio::select! {
        () = holds_idle(EcosystemId::Cargo, endpoint, secs(300)) => unreachable!(),
        () = fixture.two_cancelled_after(secs(8), Versions::Untouched(secs(60))) => {}
    }

    assert!(!is_open(fixture.resolved_health()));
}

#[tokio::test(start_paused = true)]
async fn a_fast_coalesced_answer_is_not_slow() {
    let endpoint = endpoint_of("fast-coalesced");
    let fixture = Fixture::new().with_endpoint(endpoint);

    let (served, ()) = tokio::join!(
        fixture.enriched("a", Versions::Untouched(ms(200))),
        holds_request(EcosystemId::Cargo, endpoint, ms(200)),
    );

    assert_eq!(live_list(served).len(), 1);
    assert!(!is_open(fixture.resolved_health()));
}

#[tokio::test(start_paused = true)]
async fn a_decoration_writes_no_shared_state() {
    let endpoint = endpoint_of("decoration");
    let RegistryEndpoint::Resolved(fingerprint) = endpoint else {
        panic!("the test endpoint must resolve");
    };
    let fixture = Fixture::new().with_endpoint(endpoint);
    let watcher = AttemptContact::on_endpoint(EcosystemId::Cargo, fingerprint);

    let decoration = fixture
        .lookup(AuxiliaryLookup::Decoration, "a", Fetch::Stall)
        .await;

    assert_degraded(&decoration, NoLiveList::Unverified);
    assert_eq!(
        watcher.observe(tokio::time::Instant::now()).0,
        Contact::UNTOUCHED
    );
}

#[tokio::test(start_paused = true)]
async fn a_probe_coalesced_onto_a_stalled_request_rearms_the_breaker() {
    let endpoint = endpoint_of("probe-rearm");
    let fixture = Fixture::new().with_endpoint(endpoint);
    let scenario = async {
        let refused = fixture
            .two_cancelled_then_a_third(Versions::Untouched(secs(60)))
            .await;
        assert_degraded(&refused, NoLiveList::Unverified);

        tokio::time::sleep(BREAKER_OPEN_DURATION).await;
        fixture
            .cancelled_with("probe", ms(5500), Versions::Untouched(secs(60)))
            .await;

        let polled_before = fixture.calls();
        let after = tokio::time::timeout(
            ms(100),
            fixture.enriched("after", Versions::Untouched(secs(60))),
        )
        .await
        .expect("the re-armed breaker refuses without polling");
        assert_degraded(&after, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), polled_before);
    };

    tokio::join!(
        holds_request(EcosystemId::Cargo, endpoint, secs(300)),
        scenario
    );
}
