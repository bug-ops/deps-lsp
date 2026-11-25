// This crate delegates version lookups to `deps-maven`'s `MavenCentralRegistry`, whose
// `Registry::get_latest_matching` boxed-future coercion is close enough to rustc's default
// recursion limit that the fuzz CI job's `-D warnings` nightly build has turned a
// previously-silent trait-solver retry into a hard `recursion_depth_exceeding_limit` error in
// several other ecosystem crates (rust-lang/rust#159228; same class of fix as deps-cargo
// #745, deps-nuget #696, deps-swift #673, deps-composer). Pre-emptive, matching convention.
#![recursion_limit = "256"]

//! Gradle build system support for deps-lsp.
//!
//! Provides parsing and version resolution for Gradle manifest formats:
//! - `gradle/*.versions.toml` (Version Catalog, `libs.versions.toml` and custom-named ones)
//! - `build.gradle.kts` (Kotlin DSL)
//! - `build.gradle` (Groovy DSL)
//!
//! Registry integration reuses `deps_maven::MavenCentralRegistry`.

pub mod ecosystem;
pub mod formatter;
mod license;
pub mod lockfile;
pub mod parser;
pub mod range;
mod settings_catalogs;
pub mod types;
pub mod version;

/// Basename glob for the static routing of Gradle version catalogs (`libs.versions.toml`,
/// `plugins.versions.toml`, ...). Catalogs that `settings.gradle(.kts)` declares under another
/// name are routed through `claims_unrouted_manifest` instead; classification of a routed
/// file uses [`is_catalog_file_name`].
pub(crate) const CATALOG_PATTERN: &str = "*.versions.toml";

/// Whether a basename that is routed to Gradle is a version catalog: any `.toml` (ASCII
/// case-insensitive), because Gradle imports only TOML catalogs and routing is the gate.
pub(crate) fn is_catalog_file_name(name: &str) -> bool {
    deps_core::gradle_layout::is_version_catalog_file(std::path::Path::new(name))
}

pub use ecosystem::GradleEcosystem;
pub use formatter::GradleFormatter;
pub use lockfile::GradleLockParser;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_gradle_lock;
// `license` itself stays unconditionally private (impl-critic M1): only this one
// fuzz-only wrapper is re-exported, and only under the non-default `fuzzing` feature
// (issue #691, see this crate's Cargo.toml) — `fuzz/`'s `registry_xml_parser` target
// reaches it as `deps_gradle::fuzz_parse_pom_licenses`; the crate's default public API is
// unaffected.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use license::fuzz_parse_pom_licenses;
pub use parser::{GradleParseResult, parse_gradle};
pub use types::{GradleDependency, GradleVersion};

/// Display name for the registry backing Gradle dependency resolution.
///
/// Gradle resolves through `deps_maven::MavenCentralRegistry`, so this
/// reuses Maven's registry display name rather than introducing a
/// separate, potentially divergent one.
pub use deps_maven::registry::REGISTRY;
