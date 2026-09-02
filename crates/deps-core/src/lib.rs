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

pub mod cache;
pub mod completion;
pub mod ecosystem;
pub mod ecosystem_registry;
pub mod error;
pub mod freshness;
pub mod github;
pub mod lockfile;
pub mod lsp_helpers;
pub mod macros;
pub mod net_policy;
pub mod osv;
pub mod package;
pub mod parser;
pub mod registry;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod version_matcher;

// Re-export commonly used types
pub use cache::{BodyLimit, CachedResponse, HttpCache};
pub use ecosystem::{Dependency, Ecosystem, EcosystemConfig, EcosystemId, ParseResult};
pub use ecosystem_registry::EcosystemRegistry;
pub use error::{DepsError, Result};
pub use freshness::{
    DEFAULT_COOLDOWN_SECS, FreshnessSettings, PublishTime, format_relative_age, is_within_cooldown,
};
pub use lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource, read_lockfile_content,
};
pub use lsp_helpers::{
    DiagnosticSeverities, EcosystemFormatter, HOVER_RECENT_VERSIONS, LineOffsetTable,
    PackageVersions, RequirementMatcher, RequirementStatus, UNSATISFIABLE_DIAGNOSTIC_CODE,
    VersionData, collect_update_all_edits, generate_code_actions as lsp_generate_code_actions,
    generate_code_lenses as lsp_generate_code_lenses, generate_hover as lsp_generate_hover,
    generate_inlay_hints as lsp_generate_inlay_hints, is_dot_segment,
    is_safe_maven_coordinate_segment, is_safe_package_name, is_safe_registry_url,
    is_safe_version_string, is_same_major_minor, position_in_range, requirement_is_unsatisfiable,
    warn_rejected_value,
};
pub use package::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};
pub use parser::{
    DependencySource, LoadingState, MAX_JSON_NESTING_DEPTH, MAX_TOML_NESTING_DEPTH,
    MAX_YAML_EXPANDED_BYTES, MAX_YAML_NESTING_DEPTH, check_json_nesting_depth,
    check_toml_nesting_depth, check_yaml_expansion, check_yaml_nesting_depth, parse_json_checked,
};
pub use registry::{
    Deprecation, Metadata, Registry, RemovalStatus, Version, find_latest_stable,
    has_default_prerelease_marker, is_existence_wildcard, is_existence_wildcard_str,
    select_latest_for_existence,
};
pub use version_matcher::{
    Pep440Matcher, SemverMatcher, VersionRequirementMatcher, extract_pypi_min_version,
    normalize_and_parse_version, normalize_operator_spacing,
};
