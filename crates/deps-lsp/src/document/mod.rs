//! Document management module.
//!
//! This module provides infrastructure for managing LSP documents:
//! - [`state`]: Document and server state management
//! - [`lifecycle`]: Document open/change event handling
//! - [`loader`]: Disk-based document loading for cold start support

mod lifecycle;
mod loader;
mod state;

// Re-export all public items from submodules
pub use lifecycle::{ensure_document_loaded, handle_document_change, handle_document_open};
pub use loader::load_document_from_disk;
pub use state::{DocumentState, Ecosystem, ServerState, UnifiedDependency, UnifiedVersion};
