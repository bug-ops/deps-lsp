// This crate defines the `Registry`/`Ecosystem` boxed-future trait signatures (and the
// `impl_dependency!`/`impl_version!` macros generating their `Send`-bound futures) that every
// ecosystem crate's `get_latest_matching`-style implementation coerces into; rustc's default
// recursion limit has proven occasionally insufficient to prove that bound for several such
// implementations, downgrading a previously-silent trait-solver retry into
// `recursion_depth_exceeding_limit`, which the fuzz CI job's `-D warnings` nightly build turns
// into a hard error (rust-lang/rust#159228). Same class of fix as deps-cargo (#745),
// deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

//! Core abstractions for deps-lsp.
//!
//! This crate provides the foundational traits and utilities used across
//! all ecosystem-specific implementations (Cargo, npm, PyPI, etc.).
//!
//! # Architecture
//!
//! deps-core defines:
//! - **Traits**: `Registry`, `Version`, `Metadata`, `Ecosystem`, `ParseResult`
//! - **HTTP Cache**: Shared caching layer with ETag/Last-Modified validation
//! - **Error Types**: Unified error handling across all ecosystems
//!
//! # API stability (issue #769)
//!
//! Most public structs and enums here are `#[non_exhaustive]` so a new field or variant
//! never breaks a downstream ecosystem crate's exhaustive match or struct literal; a type
//! with no `pub` fields is deliberately left exhaustive instead, since `#[non_exhaustive]`
//! would be a semantic no-op for it — an external crate can't literal-construct or
//! destructure it either way.

// #673: re-enable the three cast-safety pedantic lints the workspace allows by default
// (`Cargo.toml`'s `[workspace.lints.clippy]`), specifically for this crate — deps-core
// computes LSP offset/length/position math from parsed, attacker-influenceable input,
// where a silent truncation/sign-loss/precision-loss cast is exactly the class of bug
// this issue is about. Sites confirmed safe are individually `#[allow]`ed with a
// one-line justification, not blanket-allowed.
#![warn(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
/// HTTP response cache with `ETag`/`Last-Modified` conditional-request validation.
pub mod cache;
pub mod completion;
/// Shared `#[macro_export]`ed conformance-test scaffolding (#758).
///
/// Ecosystem crates invoke these macros instead of hand-copying the same test family. Gated
/// identically to [`test_util`].
#[cfg(any(test, feature = "test-util"))]
pub mod conformance;
/// Per-document ceiling on tracked dependencies, enforced by
/// [`ecosystem::parse_manifest_blocking`] for all 14 ecosystems (#796).
pub mod dependency_cap;
pub mod deps_dev;
/// The [`ecosystem::Ecosystem`] trait: the sealed extension point every package
/// ecosystem crate implements to plug into the LSP server.
pub mod ecosystem;
/// Routes a manifest path to its owning [`ecosystem::Ecosystem`] implementation.
pub mod ecosystem_registry;
/// Unified error types (`DepsError`, `FetchFailure`) shared across ecosystems.
pub mod error;
pub mod fallback_completion;
pub mod freshness;
pub mod fs_probe;
pub mod github;
pub mod json_ast;
pub mod json_helpers;
pub mod licenses;
pub mod lockfile;
pub mod lsp_helpers;
pub mod macros;
pub mod mtime_cache;
pub mod net_policy;
pub mod osv;
pub mod package;
pub mod pagination;
/// Shared manifest-parsing helpers: bounded JSON/TOML/YAML nesting checks and
/// depth-limited parsing used by every ecosystem's manifest parser.
pub mod parser;
/// The [`registry::Registry`] trait: version lookup and search that every
/// ecosystem's registry client implements.
pub mod registry;
pub mod secret;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod version_matcher;
pub mod xml_bounds;

// Re-export commonly used types
pub use cache::{BodyLimit, CachedResponse, HttpCache};
pub use dependency_cap::{DependencyBudget, MAX_DEPENDENCIES_PER_DOCUMENT};
pub use deps_dev::{DepsDevClient, ProvenanceStatus, ScorecardSummary, SupplyChainTrustSignal};
pub use ecosystem::{
    Dependency, Ecosystem, EcosystemConfig, EcosystemId, LicenseSource, ParseResult,
    parse_manifest_blocking,
};
pub use ecosystem_registry::EcosystemRegistry;
pub use error::{DepsError, FetchFailure, Result};
pub use freshness::{
    DEFAULT_COOLDOWN_SECS, FreshnessSettings, PublishTime, format_relative_age, is_within_cooldown,
};
pub use json_ast::{JsonAst, JsonSection, find_last_prop};
pub use json_helpers::string_valued_entries;
pub use licenses::{
    LicensePolicy, LicenseViolation, MAX_POM_LICENSE_NAME_RAW_CHARS, ViolationReason,
    evaluate as evaluate_license_policy, resolve_license_entries,
};
pub use lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource, read_and_parse_lockfile,
    read_lockfile_content,
};
pub use lsp_helpers::{
    DependencyOutcome, DependencyOutcomes, DiagnosticMessages, DiagnosticPolicy,
    DiagnosticSeverities, EcosystemFormatter, HOVER_RECENT_VERSIONS,
    LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE, LineOffsetTable, OsvNaming, PackageNaming,
    PackageRendering, PackageVersions, RequirementMatcher, RequirementResolution,
    RequirementStatus, SourcePolicy, UNSATISFIABLE_DIAGNOSTIC_CODE, VersionData,
    collect_update_all_edits, generate_code_actions as lsp_generate_code_actions,
    generate_code_lenses as lsp_generate_code_lenses, generate_hover as lsp_generate_hover,
    generate_inlay_hints as lsp_generate_inlay_hints, is_dot_segment,
    is_safe_maven_coordinate_segment, is_safe_package_name, is_safe_registry_url,
    is_safe_version_string, is_same_major_minor, maven_coordinate_path, position_in_range,
    requirement_is_unsatisfiable, warn_rejected_value,
};
pub use mtime_cache::{DEFAULT_MAX_CACHED_FILES, MAX_CACHED_FILE_BYTES, MtimeFileCache};
pub use package::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};
pub use parser::{
    DependencySource, LoadingState, MAX_JSON_NESTING_DEPTH, MAX_TOML_NESTING_DEPTH,
    MAX_YAML_EXPANDED_BYTES, MAX_YAML_NESTING_DEPTH, check_json_nesting_depth,
    check_toml_nesting_depth, check_yaml_expansion, check_yaml_nesting_depth,
    json_depth_error_message, parse_json_checked, yaml_scalar_string,
};
pub use registry::{
    Deprecation, Metadata, Registry, RemovalStatus, Version, find_latest_stable,
    has_default_prerelease_marker, hash_routing_key, is_existence_wildcard,
    is_existence_wildcard_str, select_latest_for_existence,
};
pub use version_matcher::{
    Pep440Matcher, SemverMatcher, VersionRequirementMatcher, extract_pypi_min_version,
    normalize_and_parse_version, normalize_operator_spacing,
};
