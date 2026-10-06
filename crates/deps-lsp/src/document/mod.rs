//! Document management module.
//!
//! This module provides infrastructure for managing LSP documents:
//! - `state`: Document and server state management
//! - `lifecycle`: Document open/change event handling and stage sequencing
//! - `fetch`: Registry fetch fan-out and dependency-source routing
//! - `osv_scan`: OSV vulnerability scan orchestration
//! - `typosquat`: Typosquat pre-fetch orchestration and its declared-name staleness gate
//! - `diff`: Dependency diffing and cache reconciliation
//! - `resolved`: Lock-file and in-use dependency version resolution
//! - `loader`: Disk-based document loading for cold start support

mod diff;
mod fetch;
mod gossip_prefetch;
pub(crate) mod keychain_refresh;
mod lifecycle;
pub(crate) mod listener_lifecycle;
mod loader;
mod osv_scan;
mod prefetch_support;
mod typosquat;
// Every snapshot test inside is gated on one of these ecosystem features; with none
// enabled, the module's shared fixtures/helpers would otherwise be dead code.
#[cfg(all(
    test,
    any(
        feature = "cargo",
        feature = "npm",
        feature = "pypi",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "gradle",
        feature = "swift",
        feature = "composer",
        feature = "nuget",
        feature = "deno"
    )
))]
mod osv_snapshot_tests;
pub(crate) mod reparse;
mod resolved;
mod state;
pub(crate) mod tag_refresh;

pub(crate) use diff::reload_resolved_versions;
pub(crate) use lifecycle::{
    ChangeTaskTriggerGates, ResolvedVersionMove, change_task_triggers,
    republish_diagnostics_for_open_documents, trigger_gossip_prefetch_for_open_documents,
    trigger_osv_rescan_for_open_documents, trigger_typosquat_prefetch_for_open_documents,
};
pub use lifecycle::{ensure_document_loaded, handle_document_change, handle_document_open};
pub use loader::load_document_from_disk;
pub(crate) use osv_scan::{rescan_after_resolved_version_change, run_license_prefetch};
pub(crate) use resolved::RefetchPolicy;
pub(crate) use state::{
    CLIENT_REFRESH_TIMEOUT, PrefetchVisibility, RefreshKind, refresh_with_timeout, spawn_supervised,
};
pub use state::{ColdStartLimiter, DocumentState, LoadingState, PackageSignals, ServerState};
