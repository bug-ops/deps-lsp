#![recursion_limit = "256"]

//! Library surface for `deps-cli`'s `check` subcommand.
//!
//! Split out from `main.rs` so integration tests can drive the walk/classify/report
//! pipeline directly, without spawning a subprocess. Every version verdict is produced by
//! calling into [`deps_engine::classify`] and [`deps_core::Ecosystem::generate_diagnostics`]
//! — the identical path `deps-lsp` uses — so this crate never reimplements outdated/yanked/
//! vulnerable/unsatisfiable/deprecated classification itself (spec 062 FR-005).

pub mod analyze;
pub mod cli;
pub mod config;
pub mod exit;
pub mod format;
pub mod report;
mod sanitize;
pub mod update;
pub mod walk;

/// Manifest file size cap, shared by `check`'s and `update`'s manifest reads and `update`'s
/// TOCTOU re-read (FR-019).
///
/// Mirrors `deps-lsp`'s `document::loader::MAX_FILE_SIZE`
/// (`fs_probe::read_to_string_capped`'s own TOCTOU-safe cap, not reachable from this crate).
pub const MAX_MANIFEST_FILE_SIZE: u64 = 10_000_000;
