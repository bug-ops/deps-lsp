//! Document management module.
//!
//! This module provides infrastructure for managing LSP documents:
//! - `state`: Document and server state management
//! - `lifecycle`: Document open/change event handling
//! - `loader`: Disk-based document loading for cold start support

mod lifecycle;
mod loader;
#[cfg(test)]
mod osv_snapshot_tests;
pub(crate) mod reparse;
mod state;

// Re-export all public items from submodules
pub(crate) use lifecycle::RefetchPolicy;
pub use lifecycle::{ensure_document_loaded, handle_document_change, handle_document_open};
pub use loader::load_document_from_disk;
pub(crate) use state::CLIENT_REFRESH_TIMEOUT;
pub use state::{ColdStartLimiter, DocumentState, LoadingState, ServerState};
