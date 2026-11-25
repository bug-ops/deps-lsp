//! #2161: `for_uri` stays pure and static; `for_uri_blocking` adds the content-aware
//! `claims_unrouted_manifest` fallback, only for local absolute `file:` URIs that static routing
//! did not match, trying claimants in ascending `EcosystemId` order.
//!
//! Declared from `ecosystem_registry.rs` as a child module.

use super::*;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ClaimingEcosystem {
    ecosystem: EcosystemId,
    filenames: &'static [&'static str],
    claims: bool,
    calls: Arc<AtomicUsize>,
}

impl ClaimingEcosystem {
    fn new(
        ecosystem: EcosystemId,
        filenames: &'static [&'static str],
        claims: bool,
    ) -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fake = Arc::new(Self {
            ecosystem,
            filenames,
            claims,
            calls: Arc::clone(&calls),
        });
        (fake, calls)
    }
}

impl crate::ecosystem::private::Sealed for ClaimingEcosystem {}

impl crate::ecosystem::EcosystemBase for ClaimingEcosystem {
    fn ecosystem_id(&self) -> EcosystemId {
        self.ecosystem
    }

    fn display_name(&self) -> &'static str {
        self.ecosystem.id()
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        self.filenames
    }

    fn claims_unrouted_manifest(&self, _path: &Path) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.claims
    }

    fn registry(&self) -> Arc<dyn crate::Registry> {
        unimplemented!()
    }

    fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
        unimplemented!()
    }
}

crate::impl_stub_typed_ecosystem!(ClaimingEcosystem);

fn unrouted_uri() -> url::Url {
    crate::test_util::test_uri("/project/unrouted.bin")
}

#[test]
fn for_uri_never_calls_the_claim() {
    let registry = EcosystemRegistry::new();
    let (fake, calls) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], true);
    registry.register(fake);

    assert!(registry.for_uri(&unrouted_uri()).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn for_uri_blocking_routes_an_unrouted_file_uri_to_a_claimant() {
    let registry = EcosystemRegistry::new();
    let (fake, calls) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], true);
    registry.register(fake);

    let routed = registry.for_uri_blocking(&unrouted_uri()).unwrap();

    assert_eq!(routed.ecosystem_id(), EcosystemId::Cargo);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn for_uri_blocking_returns_none_when_no_ecosystem_claims() {
    let registry = EcosystemRegistry::new();
    let (fake, calls) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], false);
    registry.register(fake);

    assert!(registry.for_uri_blocking(&unrouted_uri()).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn for_uri_blocking_does_not_call_a_claim_for_a_static_hit() {
    let registry = EcosystemRegistry::new();
    let (static_fake, static_calls) =
        ClaimingEcosystem::new(EcosystemId::Go, &["pinned.manifest"], true);
    let (claimant, claimant_calls) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], true);
    registry.register(static_fake);
    registry.register(claimant);
    let uri = crate::test_util::test_uri("/project/pinned.manifest");

    let routed = registry.for_uri_blocking(&uri).unwrap();

    assert_eq!(routed.ecosystem_id(), EcosystemId::Go);
    assert_eq!(static_calls.load(Ordering::SeqCst), 0);
    assert_eq!(claimant_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn for_uri_blocking_does_not_call_a_claim_for_a_non_file_uri() {
    let registry = EcosystemRegistry::new();
    let (fake, calls) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], true);
    registry.register(fake);
    let uri = url::Url::parse("https://example.com/unrouted.bin").unwrap();

    assert!(registry.for_uri_blocking(&uri).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn for_uri_blocking_prefers_the_lowest_ecosystem_id_among_claimants() {
    let registry = EcosystemRegistry::new();
    let (npm, _) = ClaimingEcosystem::new(EcosystemId::Npm, &[], true);
    let (cargo, _) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], true);
    registry.register(npm);
    registry.register(cargo);

    let routed = registry.for_uri_blocking(&unrouted_uri()).unwrap();

    assert_eq!(routed.ecosystem_id(), EcosystemId::Cargo);
}

#[test]
fn for_uri_blocking_skips_a_non_claiming_lower_id() {
    let registry = EcosystemRegistry::new();
    let (cargo, _) = ClaimingEcosystem::new(EcosystemId::Cargo, &[], false);
    let (npm, _) = ClaimingEcosystem::new(EcosystemId::Npm, &[], true);
    registry.register(cargo);
    registry.register(npm);

    let routed = registry.for_uri_blocking(&unrouted_uri()).unwrap();

    assert_eq!(routed.ecosystem_id(), EcosystemId::Npm);
}
