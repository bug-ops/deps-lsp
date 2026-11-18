//! #2101 acceptance: a bounded NuGet range is not "already resolving" to a fix target above its
//! inclusive lower bound, because NuGet restore picks the lowest applicable version.
//!
//! The planner half (`Some(true)` from the matcher at the `NoOpRewrite` arm becomes
//! `Unfixable(UnsupportedRequirementShape)`) is asserted by the developer's updated in-module
//! `FloorLikeFormatter` test in `deps-cli`, which has no public planner seam without OSV.
#![allow(clippy::expect_used)]

use deps_core::lsp_helpers::RequirementGate;
use deps_core::{ConcreteVersion, VersionReq};
use deps_nuget::NuGetFormatter;

fn resolves(requirement: &str, target: &str) -> bool {
    NuGetFormatter.requirement_already_resolves_to(
        &VersionReq::new(requirement),
        &ConcreteVersion::new(target),
    )
}

#[test]
fn requirement_already_resolves_to_bounded_range_above_the_lower_bound_is_false() {
    for requirement in [
        "[1.0.0,2.0.0)",
        "[1.0,2.0)",
        "[1.0.0,2.0.0]",
        "(1.0.0,2.0.0)",
    ] {
        assert!(
            !resolves(requirement, "1.0.2"),
            "{requirement} restores its lower bound, not 1.0.2"
        );
    }
}

#[test]
fn requirement_already_resolves_to_bounded_range_whose_inclusive_lower_bound_is_the_target() {
    // Guard (holds before the change too): the lowest admissible member is the target.
    assert!(resolves("[1.0.2,2.0.0)", "1.0.2"));
    assert!(resolves("[1.0,2.0)", "1.0.0"), "1.0 normalizes to 1.0.0");
}

#[test]
fn requirement_already_resolves_to_exclusive_lower_bound_is_never_the_target() {
    assert!(!resolves("(1.0.0,2.0.0)", "1.0.0"));
}

#[test]
fn requirement_already_resolves_to_exact_pin_only_for_the_pinned_version() {
    assert!(resolves("[1.0.2]", "1.0.2"));
    assert!(!resolves("[1.0.2]", "1.0.3"));
}

#[test]
fn requirement_already_resolves_to_floating_pattern_keeps_the_matcher_answer() {
    // Guard: a floating pattern genuinely follows forward.
    assert!(resolves("1.0.*", "1.0.2"));
    assert!(!resolves("1.0.*", "1.1.0"));
}
