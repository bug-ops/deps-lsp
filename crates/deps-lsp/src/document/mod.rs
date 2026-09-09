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
#[cfg(test)]
mod osv_snapshot_tests;
pub(crate) mod reparse;
mod resolved;
mod state;

// Re-export all public items from submodules
pub use lifecycle::{ensure_document_loaded, handle_document_change, handle_document_open};
pub use loader::load_document_from_disk;
pub(crate) use resolved::{RefetchPolicy, split_resolved_packages};
pub(crate) use state::CLIENT_REFRESH_TIMEOUT;
pub use state::{ColdStartLimiter, DocumentState, LoadingState, ServerState};
