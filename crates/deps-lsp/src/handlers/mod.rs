//! LSP protocol handlers.
//!
//! This module contains all Language Server Protocol request handlers for
//! deps-lsp. Each handler is responsible for a specific LSP feature:
//!
//! - [`completion`]: Package name and version completions
//! - [`hover`]: Hover documentation with crate metadata
//! - [`inlay_hints`]: Inline version annotations
//! - [`diagnostics`]: Outdated/yanked version warnings
//! - [`code_actions`]: Quick fixes (e.g., "Update to latest version")
//!
//! # Handler Architecture
//!
//! All handlers follow the same pattern:
//! 1. Extract document state from `ServerState`
//! 2. Compute response from parsed dependencies and cached versions
//! 3. Return LSP-compliant response types
//! 4. Gracefully degrade on errors (never panic)
//!
//! Handlers are pure functions that don't perform I/O directly. Network
//! requests are handled by background tasks spawned on document open/change.
//!
//! # Examples
//!
//! ```no_run
//! // Handler functions are called by tower-lsp backend
//! // They receive ServerState via Arc and LSP request parameters
//! use deps_lsp::document::ServerState;
//! use std::sync::Arc;
//!
//! let state = Arc::new(ServerState::new());
//! // Handlers use state.get_document() to access parsed dependencies
//! ```

pub mod cargo_handler_impl;
pub mod code_actions;
pub mod completion;
pub mod diagnostics;
pub mod hover;
pub mod inlay_hints;
pub mod npm_handler_impl;
pub mod pypi_handler_impl;

pub use cargo_handler_impl::CargoHandlerImpl;
pub use npm_handler_impl::NpmHandlerImpl;
pub use pypi_handler_impl::PyPiHandlerImpl;
