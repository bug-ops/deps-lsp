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
//! Handlers delegate to ecosystem-specific implementations via the
//! `Ecosystem` trait. Each ecosystem (Cargo, npm, PyPI) provides its own
//! implementation of LSP features.
//!
//! The general flow is:
//! 1. Extract document state and ecosystem from `ServerState`
//! 2. Delegate to `ecosystem.generate_*()` methods
//! 3. Return LSP-compliant response types
//! 4. Gracefully degrade on errors (never panic)
//!
//! # Examples
//!
//! ```no_run
//! use deps_lsp::document::ServerState;
//! use std::sync::Arc;
//!
//! let state = Arc::new(ServerState::new());
//! // Handlers use state.get_document() and ecosystem_registry
//! ```

pub mod code_actions;
pub mod completion;
pub mod diagnostics;
pub mod hover;
pub mod inlay_hints;
