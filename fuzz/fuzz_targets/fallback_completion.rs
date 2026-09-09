//! Fuzzes [`deps_core::Ecosystem::fallback_completion_prefix`] and
//! [`deps_core::Ecosystem::fallback_completion_is_bare`] — the raw-text scanners
//! (`deps_core::fallback_completion`) driving the parse-failure completion path directly
//! over untrusted, still-being-typed editor document content (#740).
//!
//! Property under test: neither method ever panics for any `(content, line, character)`
//! input, for any of the 14 ecosystems, valid manifest syntax or not. All 14 are
//! constructed and called every run so a future override is picked up automatically, even
//! though only 10 currently override `fallback_completion_prefix` (Bundler/Gradle/Swift/
//! GitLab CI fall through to the trait's `None` default) and only npm/Maven/Composer have
//! a non-constant `fallback_completion_is_bare` (NuGet's override is a fixed `true`/`false`
//! constant) — the no-op calls for the rest are harmless and kept for future-proofing.

#![no_main]

use deps_core::Ecosystem;
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock};
use tower_lsp_server::ls_types::Position;

/// One instance per ecosystem, sharing a single [`deps_core::HttpCache`] — none of it is
/// ever exercised here, since both fuzzed methods operate on raw text only, never on the
/// registry or a parsed manifest.
static ECOSYSTEMS: LazyLock<Vec<Arc<dyn Ecosystem>>> = LazyLock::new(|| {
    let cache = Arc::new(deps_core::HttpCache::new());
    vec![
        Arc::new(deps_cargo::CargoEcosystem::new(Arc::clone(&cache))) as Arc<dyn Ecosystem>,
        Arc::new(deps_npm::NpmEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_pypi::PypiEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_go::GoEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_bundler::BundlerEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_dart::DartEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_maven::MavenEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_gradle::GradleEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_swift::SwiftEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_composer::ComposerEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_nuget::NuGetEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_github_actions::GithubActionsEcosystem::new(
            Arc::clone(&cache),
        )),
        Arc::new(deps_gitlab_ci::GitlabCiEcosystem::new(Arc::clone(&cache))),
        Arc::new(deps_deno::DenoEcosystem::new(Arc::clone(&cache))),
    ]
});

fuzz_target!(|data: &[u8]| {
    // First 8 bytes drive `Position` (line, character as little-endian `u32`s); the rest
    // is the document content. Shorter inputs are simply not interesting.
    if data.len() < 8 {
        return;
    }
    let (position_bytes, content_bytes) = data.split_at(8);
    let Ok(content) = std::str::from_utf8(content_bytes) else {
        return;
    };
    let line = u32::from_le_bytes(position_bytes[0..4].try_into().expect("4 bytes"));
    let character = u32::from_le_bytes(position_bytes[4..8].try_into().expect("4 bytes"));
    let position = Position::new(line, character);

    for ecosystem in ECOSYSTEMS.iter() {
        let _ = ecosystem.fallback_completion_prefix(content, position);
        let _ = ecosystem.fallback_completion_is_bare(content, position);
    }
});
