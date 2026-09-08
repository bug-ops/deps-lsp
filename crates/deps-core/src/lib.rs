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
// #673 S5: restriction lints, scoped to this crate only via a source attribute (which
// overrides the crate's `[lints] workspace = true` Cargo.toml table regardless of that
// table's level) rather than a duplicated `[lints.clippy]` table in Cargo.toml — avoids
// ~90 lines of drift-prone duplication of the workspace allow-list. Deliberately never
// added to `[workspace.lints.clippy]` itself (the three lints must stay opt-in per crate,
// not workspace-wide — see PR discussion). Sites confirmed safe are individually
// `#[allow]`ed with a one-line justification, not blanket-allowed.
#![warn(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

pub mod cache;
pub mod completion;
pub mod deps_dev;
pub mod ecosystem;
pub mod ecosystem_registry;
pub mod error;
pub mod freshness;
pub mod fs_probe;
pub mod github;
pub mod json_ast;
pub mod json_helpers;
pub mod lockfile;
pub mod lsp_helpers;
pub mod macros;
pub mod mtime_cache;
pub mod net_policy;
pub mod osv;
pub mod package;
pub mod pagination;
pub mod parser;
pub mod registry;
pub mod secret;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod version_matcher;

// Re-export commonly used types
pub use cache::{BodyLimit, CachedResponse, HttpCache};
pub use deps_dev::{DepsDevClient, ProvenanceStatus, ScorecardSummary, SupplyChainTrustSignal};
pub use ecosystem::{Dependency, Ecosystem, EcosystemConfig, EcosystemId, ParseResult};
pub use ecosystem_registry::EcosystemRegistry;
pub use error::{DepsError, FetchFailure, Result};
pub use freshness::{
    DEFAULT_COOLDOWN_SECS, FreshnessSettings, PublishTime, format_relative_age, is_within_cooldown,
};
pub use json_ast::{JsonAst, JsonSection, find_last_prop};
pub use json_helpers::string_valued_entries;
pub use lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource, read_lockfile_content,
};
pub use lsp_helpers::{
    DependencyOutcome, DependencyOutcomes, DiagnosticMessages, DiagnosticPolicy,
    DiagnosticSeverities, EcosystemFormatter, HOVER_RECENT_VERSIONS, LineOffsetTable, OsvNaming,
    PackageNaming, PackageRendering, PackageVersions, RequirementMatcher, RequirementResolution,
    RequirementStatus, SourcePolicy, UNSATISFIABLE_DIAGNOSTIC_CODE, VersionData,
    collect_update_all_edits, generate_code_actions as lsp_generate_code_actions,
    generate_code_lenses as lsp_generate_code_lenses, generate_hover as lsp_generate_hover,
    generate_inlay_hints as lsp_generate_inlay_hints, is_dot_segment,
    is_safe_maven_coordinate_segment, is_safe_package_name, is_safe_registry_url,
    is_safe_version_string, is_same_major_minor, position_in_range, requirement_is_unsatisfiable,
    warn_rejected_value,
};
pub use mtime_cache::{DEFAULT_MAX_CACHED_FILES, MAX_CACHED_FILE_BYTES, MtimeFileCache};
pub use package::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};
pub use parser::{
    DependencySource, LoadingState, MAX_JSON_NESTING_DEPTH, MAX_TOML_NESTING_DEPTH,
    MAX_YAML_EXPANDED_BYTES, MAX_YAML_NESTING_DEPTH, check_json_nesting_depth,
    check_toml_nesting_depth, check_yaml_expansion, check_yaml_nesting_depth,
    json_depth_error_message, parse_json_checked,
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
