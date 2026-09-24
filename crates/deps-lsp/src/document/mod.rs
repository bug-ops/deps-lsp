//! Document management module.
//!
//! This module provides infrastructure for managing LSP documents:
//! - `state`: Document and server state management
//! - `lifecycle`: Document open/change event handling and stage sequencing
//! - `fetch`: Registry fetch fan-out and dependency-source routing
//! - `osv_scan`: OSV vulnerability scan orchestration
//! - `diff`: Dependency diffing and cache reconciliation
//! - `resolved`: Lock-file and in-use dependency version resolution
//! - `loader`: Disk-based document loading for cold start support

mod diff;
mod fetch;
mod lifecycle;
mod loader;
mod osv_scan;
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

pub(crate) use diff::reload_resolved_versions;
pub use lifecycle::{ensure_document_loaded, handle_document_change, handle_document_open};
pub use loader::load_document_from_disk;
pub(crate) use osv_scan::rescan_after_resolved_version_change;
pub(crate) use resolved::RefetchPolicy;
pub(crate) use state::CLIENT_REFRESH_TIMEOUT;
pub use state::{ColdStartLimiter, DocumentState, LoadingState, ServerState};
