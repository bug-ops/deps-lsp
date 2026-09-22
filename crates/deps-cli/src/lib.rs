#![recursion_limit = "256"]

//! Library surface for `deps-cli`'s `check` subcommand.
//!
//! Split out from `main.rs` so integration tests can drive the walk/classify/report
//! pipeline directly, without spawning a subprocess. Every version verdict is produced by
//! calling into [`deps_engine::classify`] and [`deps_core::Ecosystem::generate_diagnostics`]
//! — the identical path `deps-lsp` uses — so this crate never reimplements outdated/yanked/
//! vulnerable/unsatisfiable/deprecated classification itself (spec 062 FR-005).

pub mod cli;
pub mod config;
pub mod exit;
pub mod format;
pub mod report;
mod sanitize;
pub mod walk;
