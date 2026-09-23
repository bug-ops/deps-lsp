// rustc's default recursion limit can't always prove the `Send` bound on the boxed futures
// `impl_dependency!`/`impl_version!` generate, turning a silent trait-solver retry into a hard
// error under `-D warnings` (rust-lang/rust#159228). Same fix as deps-cargo #745, deps-nuget
// #696, deps-swift #673.
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
//! never breaks a downstream ecosystem crate's exhaustive match or struct literal. This is a
//! per-kind decision, not one policy for both: on a **struct** with no `pub` fields,
//! `#[non_exhaustive]` is a semantic no-op (an external crate can't literal-construct or
//! destructure it either way), so such structs are deliberately left exhaustive instead. On
//! an **enum**, `#[non_exhaustive]` always forces a downstream `match` to carry a wildcard
//! arm, regardless of any variant's field visibility — each enum opts in when that forced
//! wildcard is wanted and stays exhaustive when a future variant should instead be a
//! compile error downstream; see the individual enum's own doc comment for which applies.
//!
//! A few pre-1.0 dependency types remain visible in public signatures as a deliberate
//! semver commitment rather than an oversight:
//! - [`error::SanitizedRegistryError`] implements `From<reqwest::Error>` — a `reqwest`
//!   major bump that reshapes `Error` is a breaking change for this crate too.
//! - [`parser::yaml_scalar_string`] takes `&yaml_rust2::Yaml`; `yaml_rust2` is re-exported
//!   from the crate root so callers can name the type without their own direct dependency,
//!   and a `yaml-rust2` major bump is likewise a breaking change here.
//! - `deps-gitlab-ci`'s `gitlab_version_req` (`crates/deps-gitlab-ci/src/component.rs`)
//!   returns `semver::VersionReq` directly — low risk since `semver` is unusually stable
//!   pre-1.0, but the same commitment applies.
//! - [`cache_policy`] takes/returns `&dashmap::DashMap<K, V>` in its public functions; this
//!   is not new coupling — [`registry::register_capped_with_occupied`] already exposes
//!   `&DashMap` publicly without a `pub use dashmap` — so a `dashmap` major bump is already
//!   a breaking change here regardless of this module's visibility.
//!
//! ## LSP type stability (issue #832, narrowed by #1071 and #1083)
//!
//! `tower-lsp-server` is pinned pre-1.0, so a `tower-lsp-server` minor bump (e.g. 0.23 →
//! 0.24) is not an implementation detail this crate can absorb silently — it forces a
//! breaking release of `deps-core`: a minor version bump while `deps-core` itself remains
//! pre-1.0, a major version bump once `deps-core` reaches 1.0. This section describes which
//! parts of the public API still carry that coupling.
//!
//! As of issue #1071, a dependency's own *domain* data never carried it in the first place:
//! [`ecosystem::Dependency`]'s range accessors return [`position::Range`], and
//! [`ecosystem::ParseResult::uri`] / [`ecosystem::Ecosystem::parse_manifest`] use `url::Url`
//! — neither names a `tower-lsp-server` type.
//!
//! As of issue #1083, the remaining *response*-shaped surface — `generate_hover`,
//! `generate_diagnostics` (retyped to the protocol-agnostic [`diagnostic::Diagnostic`], not
//! merely gated), `generate_code_actions`, `generate_code_lenses`, `generate_inlay_hints`,
//! `generate_document_links`, `generate_completions`/`complete_version`/
//! `complete_package_name`/`complete_feature`, and the [`completion`] module itself — is
//! gated behind the `lsp-responses` Cargo feature, along with the `tower-lsp-server`
//! dependency it requires. The feature is **not** part of this crate's `default` set:
//! Cargo does not allow a `workspace = true` dependency edge to turn off a feature that a
//! crate defaults on, so making it default here would make it inescapable for `deps-engine`
//! (see `deps-engine/Cargo.toml`'s own `lsp-responses` feature doc) — every consumer that
//! wants it, including each of the 14 `deps-<ecosystem>` crates via their own
//! identically-named feature, must request `deps-core/lsp-responses` explicitly (`deps-lsp`
//! does, directly and via `deps-engine`; `deps-cli` never does). Under `--no-default-features`
//! (or with `lsp-responses` otherwise off), `deps-core` links no `tower-lsp-server` code at
//! all, [`tower_lsp_server`] is not re-exported, and an ecosystem crate's `Ecosystem` impl
//! simply doesn't declare the gated trait methods (the trait itself omits them when the
//! feature is off, so there is nothing to implement) — this is FR-001/SC-001's mechanism for
//! keeping `deps-cli`'s dependency tree free of `tower-lsp-server` entirely (verified by
//! `cargo tree -p deps-cli -e features,no-dev` in CI).
//!
//! Downstream consumers implementing [`ecosystem::Ecosystem`] with `lsp-responses` enabled
//! should depend on the exact matching `tower-lsp-server` version through the
//! [`tower_lsp_server`] re-export rather than adding their own separate direct dependency,
//! which could otherwise drift out of sync with the version `deps-core` was built against.
//! `deps-core`'s own `lsp_helpers` converts a [`position::Position`]/[`position::Range`] into
//! its `ls_types` equivalent internally via their `From` impls wherever one must be embedded
//! in a gated response.
//!
//! Whether the *rest* of `deps-core`'s public API should stop naming third-party dependency
//! types generally (`reqwest::Error`, `yaml_rust2::Yaml`, ...) is issue #851's broader, still-
//! open question — out of scope for #1071/#1083.

// #673: re-enables the cast-safety pedantic lints the workspace allows by default, since this
// crate computes LSP offset/position math from attacker-influenceable input. Confirmed-safe
// sites get an individual `#[allow]` with justification, not a blanket allow.
#![warn(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

// #1238: lets `redact_debug::RedactingDebug`'s generated code say `deps_core::redact_debug::…`
// unconditionally, whether the derive is used by an external consumer or by a type defined
// inside this crate itself (e.g. a future `lsp_helpers::git_ref::ResolvedShaPin` migration) —
// a crate has no external name for itself without this alias.
extern crate self as deps_core;

/// HTTP response cache with `ETag`/`Last-Modified` conditional-request validation.
pub mod cache;
/// Bounded-`DashMap` capacity policies shared by [`cache`], [`github`], [`deps_dev`], and
/// [`osv`].
///
/// `pub`, so ecosystem crates (`deps-gitlab-ci`, `deps-github-actions`, `deps-npm`) reach it
/// directly too.
pub mod cache_policy;
#[cfg(feature = "lsp-responses")]
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
/// Protocol-agnostic [`diagnostic::Diagnostic`]/[`diagnostic::Severity`] types (issue #1083).
///
/// The domain-level replacement for `tower_lsp_server::ls_types::{Diagnostic,
/// DiagnosticSeverity, DiagnosticRelatedInformation, CodeDescription}` returned by
/// [`lsp_helpers::generate_diagnostics_from_cache`] and
/// [`ecosystem::Ecosystem::generate_diagnostics`].
pub mod diagnostic;
/// The [`ecosystem::Ecosystem`] trait: the sealed extension point every package
/// ecosystem crate implements to plug into the LSP server.
pub mod ecosystem;
/// Routes a manifest path to its owning [`ecosystem::Ecosystem`] implementation.
pub mod ecosystem_registry;
pub mod edit;
/// Unified error types (`DepsError`, `FetchFailure`) shared across ecosystems.
pub mod error;
pub mod fallback_completion;
pub mod freshness;
pub mod fs_probe;
pub mod github;
/// Protocol-agnostic [`hover::Hover`] type (issue #1277).
///
/// The domain-level replacement for `tower_lsp_server::ls_types::Hover` returned by
/// [`lsp_helpers::generate_hover`] and [`ecosystem::Ecosystem::generate_hover`]. Gated
/// behind the `lsp-responses` feature, unlike [`diagnostic`] — see this module's own doc
/// for why.
#[cfg(feature = "lsp-responses")]
#[cfg_attr(docsrs, doc(cfg(feature = "lsp-responses")))]
pub mod hover;
/// Shared bracket-interval version-range grammar (`[1.0,2.0)`-shaped), used by
/// `deps-maven`, `deps-gradle`, and `deps-nuget` (#821).
pub mod interval;
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
/// The policy-relevant subset of `deps-lsp`'s configuration.
///
/// Diagnostics severities, cache, freshness, supply-chain, registries, network, license
/// policy — shared with `deps-cli` so both compose the same type instead of each parsing its
/// own copy.
pub mod policy_config;
/// Protocol-agnostic [`position::Position`]/[`position::Range`] types (issue #1071).
///
/// The domain-level replacement for `tower_lsp_server::ls_types::{Position, Range}` in
/// [`ecosystem::Dependency`]'s range accessors.
pub mod position;
/// Shared escape-aware string-literal and comment scanning.
///
/// [`quote_scan::read_string_literal`], [`quote_scan::strip_line_comment`],
/// [`quote_scan::blank_comments`], [`quote_scan::is_code_byte`],
/// [`quote_scan::last_string_literal`], and [`quote_scan::find_closing_quote_before_comment`],
/// parameterized over [`quote_scan::ScanSyntax`] — used by `deps-bundler`, `deps-swift`,
/// `deps-pypi`, and `deps-gradle` instead of each hand-rolling its own scanner (#1022,
/// #1174).
pub mod quote_scan;
/// Local, process-lifetime rate-limit short-circuiting.
///
/// [`rate_limit::RateLimitGate`] is shared by `deps-github-actions` and `deps-gitlab-ci`.
pub mod rate_limit;
/// Redaction: URL/declaration-key/parse-error text and in-memory secret values (issue #1247).
///
/// Extracted from [`net_policy`], which kept the old paths as re-exports.
pub mod redact;
/// Compile-time-enforced `Debug` redaction: the [`redact_debug::RedactingDebug`] derive
/// (issue #1238).
pub mod redact_debug;
/// The [`registry::Registry`] trait: version lookup and search that every
/// ecosystem's registry client implements.
pub mod registry;
/// Re-export of [`redact::secret`] at its pre-#1247 path.
pub use redact::secret;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod version_matcher;
pub mod xml_bounds;
pub mod yaml_anchor;
pub mod yaml_walk;

/// Re-export of the LSP protocol types that appear in this crate's public trait
/// signatures. `deps-core`'s version tracks `tower-lsp-server`'s: a
/// `tower-lsp-server` bump is a breaking change here, by construction. See the
/// "LSP type stability" section of this module's docs for detail.
///
/// Only present when the `lsp-responses` feature is enabled — see that feature's own
/// doc comment in `Cargo.toml` for what it gates and why.
#[cfg(feature = "lsp-responses")]
pub use tower_lsp_server;

pub use cache::{BodyLimit, CachedResponse, HttpCache};
pub use dependency_cap::{DependencyBudget, MAX_DEPENDENCIES_PER_DOCUMENT};
pub use deps_dev::{DepsDevClient, ProvenanceStatus, ScorecardSummary, SupplyChainTrustSignal};
pub use ecosystem::{
    BlockedRegistryOccurrence, BlockedSourceClass, Dependency, Ecosystem, EcosystemConfig,
    EcosystemId, LicenseSource, ParseResult, parse_manifest_blocking,
};
pub use ecosystem_registry::EcosystemRegistry;
pub use edit::{
    EditSpan, ManifestEdit, PlannedUpdate, UnplannableReason, UpdateCandidate, UpdateKind,
    apply_edits, classify_update, collect_update_candidates, collect_update_edits,
    dedup_overlapping_edits, fix_target_is_verified, plan_vulnerability_fix,
};
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
    RequirementStatus, SourcePolicy, UNSATISFIABLE_DIAGNOSTIC_CODE, VersionData, is_dot_segment,
    is_safe_feature_name, is_safe_maven_coordinate_segment, is_safe_package_name,
    is_safe_registry_url, is_safe_version_string, is_same_major_minor, maven_coordinate_path,
    position_in_range, requirement_is_unsatisfiable, warn_rejected_value,
};
/// LSP-response-shaped re-exports, present only when the `lsp-responses` feature is enabled.
#[cfg(feature = "lsp-responses")]
pub use lsp_helpers::{
    collect_update_all_edits, generate_code_actions as lsp_generate_code_actions,
    generate_code_lenses as lsp_generate_code_lenses, generate_hover as lsp_generate_hover,
    generate_inlay_hints as lsp_generate_inlay_hints, single_file_edit, to_ls_uri,
};
pub use mtime_cache::{DEFAULT_MAX_CACHED_FILES, MAX_CACHED_FILE_BYTES, MtimeFileCache};
pub use package::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};
pub use parser::{
    DependencySource, LoadingState, MAX_JSON_NESTING_DEPTH, MAX_TOML_NESTING_DEPTH,
    MAX_YAML_EXPANDED_BYTES, MAX_YAML_NESTING_DEPTH, check_json_nesting_depth,
    check_toml_nesting_depth, check_yaml_bounds, check_yaml_expansion, check_yaml_nesting_depth,
    json_depth_error_message, parse_json_checked, yaml_scalar_string,
};
pub use position::{Position, Range};
pub use registry::{
    Deprecation, Metadata, Registry, RemovalStatus, Version, classify_default_registry_url,
    existence_wildcard_req, find_latest_stable, has_default_prerelease_marker, hash_routing_key,
    is_existence_wildcard, is_existence_wildcard_str, not_found_or, select_latest_for_existence,
};
pub use version_matcher::{
    Pep440Matcher, SemverMatcher, VersionRequirementMatcher, extract_pypi_min_version,
    normalize_and_parse_version, normalize_operator_spacing,
};

/// Re-exported so a caller of [`yaml_scalar_string`] can name `yaml_rust2::Yaml` without
/// depending on `yaml-rust2` directly — see the "API stability" section above for the
/// semver implication of this pre-1.0 dependency coupling.
pub use yaml_rust2;

/// Re-exported so a caller of [`error::SanitizedRegistryError`]'s `From<reqwest::Error>`
/// impl can name `reqwest::Error` without depending on `reqwest` directly — see the "API
/// stability" section above for the semver implication of this pre-1.0 dependency coupling.
pub use reqwest;
