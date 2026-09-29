//! Fuzzes every ecosystem's [`deps_core::lsp_helpers::RequirementGate::compile_requirement`]/
//! [`deps_core::lsp_helpers::RequirementMatcher::matches`]/
//! [`deps_core::lsp_helpers::RequirementMatcher::explicitly_excludes`]/
//! [`deps_core::lsp_helpers::RequirementResolution::version_satisfies_requirement`]/
//! [`deps_core::lsp_helpers::RequirementGate::is_requirement_up_to_date`]/
//! [`deps_core::lsp_helpers::RequirementGate::requirement_already_resolves_to`] from
//! arbitrary `(version, requirement)` string pairs (#1627).
//!
//! Property under test: no call panics for any input, capped or not. For a requirement within
//! [`deps_core::lsp_helpers::MAX_REQUIREMENT_LEN`] — the only shape reachable on any
//! production call path, since every one of them now gates on
//! [`deps_core::lsp_helpers::requirement_is_oversized`] before reaching a matcher — no single
//! call exceeds [`MAX_CALL_DURATION`] either, the CWE-407 property this issue is about (e.g.
//! many short clauses that still stall a matcher despite being within the cap). An oversized
//! requirement is still fuzzed for panics (uncapped calls can and do legitimately take
//! longer), just not held to the timing bound, since no production caller ever hands a matcher
//! one.

#![no_main]

#[path = "../shared/panic_guard.rs"]
mod panic_guard;

use deps_core::lsp_helpers::{RequirementGate, requirement_is_oversized};
use deps_core::{ConcreteVersion, Ecosystem, EcosystemId, VersionReq};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

/// Generous bound for a single matcher call against a requirement within
/// [`MAX_REQUIREMENT_LEN`] — real ecosystem calls complete in low single-digit milliseconds
/// even at that length; this only needs to sit well below the fuzzer's own per-run timeout to
/// fail loudly instead of just hanging.
const MAX_CALL_DURATION: Duration = Duration::from_millis(500);

/// One instance per ecosystem, sharing a single [`deps_core::HttpCache`] — none of it is ever
/// exercised here, since every fuzzed method is a pure function of its string arguments. Built
/// from an exhaustive match over [`EcosystemId::ALL`] (not a hand-written list — #758 removed
/// that exact drift-prone pattern elsewhere), so a future 15th ecosystem fails this crate's
/// build instead of silently missing fuzz coverage.
static ECOSYSTEMS: LazyLock<Vec<Arc<dyn Ecosystem>>> = LazyLock::new(|| {
    let cache = Arc::new(deps_core::HttpCache::new());
    EcosystemId::ALL
        .iter()
        .map(|id| -> Arc<dyn Ecosystem> {
            match id {
                EcosystemId::Cargo => Arc::new(deps_cargo::CargoEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Npm => Arc::new(deps_npm::NpmEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Pypi => Arc::new(deps_pypi::PypiEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Go => Arc::new(deps_go::GoEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Bundler => {
                    Arc::new(deps_bundler::BundlerEcosystem::new(Arc::clone(&cache)))
                }
                EcosystemId::Dart => Arc::new(deps_dart::DartEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Maven => Arc::new(deps_maven::MavenEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Gradle => {
                    Arc::new(deps_gradle::GradleEcosystem::new(Arc::clone(&cache)))
                }
                EcosystemId::Swift => Arc::new(deps_swift::SwiftEcosystem::new(Arc::clone(&cache))),
                EcosystemId::Composer => {
                    Arc::new(deps_composer::ComposerEcosystem::new(Arc::clone(&cache)))
                }
                EcosystemId::NuGet => Arc::new(deps_nuget::NuGetEcosystem::new(Arc::clone(&cache))),
                EcosystemId::GithubActions => Arc::new(
                    deps_github_actions::GithubActionsEcosystem::new(Arc::clone(&cache)),
                ),
                EcosystemId::GitlabCi => {
                    Arc::new(deps_gitlab_ci::GitlabCiEcosystem::new(Arc::clone(&cache)))
                }
                EcosystemId::Deno => Arc::new(deps_deno::DenoEcosystem::new(Arc::clone(&cache))),
            }
        })
        .collect()
});

/// Runs `f`, panicking (failing the fuzz run) if `bound_duration` and it takes longer than
/// [`MAX_CALL_DURATION`] — the CWE-407 property this target exists to catch. `f` always runs
/// regardless of `bound_duration`, so an uncapped call is still fuzzed for panics, just not
/// held to the timing bound (see this module's doc).
fn timed<T>(label: &str, bound_duration: bool, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    assert!(
        !bound_duration || elapsed < MAX_CALL_DURATION,
        "{label} took {elapsed:?}, exceeding {MAX_CALL_DURATION:?} for a requirement within \
         MAX_REQUIREMENT_LEN"
    );
    result
}

fuzz_target!(|data: &[u8]| {
    // First byte splits the rest of `data` between the version and requirement strings; both
    // must be valid, non-empty UTF-8 — every ecosystem already short-circuits on an empty
    // requirement, so that shape adds no coverage here.
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let split = (split as usize).min(rest.len());
    let (version_bytes, requirement_bytes) = rest.split_at(split);
    let Ok(version_str) = std::str::from_utf8(version_bytes) else {
        return;
    };
    let Ok(requirement_str) = std::str::from_utf8(requirement_bytes) else {
        return;
    };
    if version_str.is_empty() || requirement_str.is_empty() {
        return;
    }

    let version = ConcreteVersion::new(version_str);
    let requirement = VersionReq::new(requirement_str);
    let bound_duration = !requirement_is_oversized(&requirement);

    panic_guard::run_aborting_on_escape(|| {
        for ecosystem in ECOSYSTEMS.iter() {
            let formatter = ecosystem.formatter();
            if let Some(matcher) = timed("compile_requirement", bound_duration, || {
                formatter.compile_requirement(&requirement)
            }) {
                let _ = timed("matches", bound_duration, || matcher.matches(&version));
                let _ = timed("explicitly_excludes", bound_duration, || {
                    matcher.explicitly_excludes(&version)
                });
            }
            let _ = timed("version_satisfies_requirement", bound_duration, || {
                formatter.version_satisfies_requirement(&version, &requirement)
            });
            let _ = timed("is_requirement_up_to_date", bound_duration, || {
                formatter.is_requirement_up_to_date(&requirement, &version)
            });
            let _ = timed("requirement_already_resolves_to", bound_duration, || {
                formatter.requirement_already_resolves_to(&requirement, &version)
            });
        }
    });
});
