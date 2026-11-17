//! `trybuild` compile-fail harness for `ProbeDependency::route_probes` (#2023).
//!
//! The method has no default: an implementor that omits it must fail to compile, so a future
//! ecosystem cannot slip past the #1999 non-public-route oracle by silently inheriting an empty
//! route list. Same slow-cold-cache and stable/beta `.stderr` drift caveats as
//! `redacting_debug_compile_fail.rs`; regenerate with `TRYBUILD=overwrite`.

#[test]
#[ignore = "slow on cold cache: trybuild rebuilds deps-core's dependency graph in an isolated \
            sandbox (target/tests/trybuild/); run explicitly in CI like \
            redacting_debug_compile_fail"]
fn probe_dependency_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/probe_dependency_compile_fail/fixtures/*.rs");
}
