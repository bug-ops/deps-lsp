// Boxed futures across ecosystem crates can exceed rustc's default trait-solver recursion
// limit when proving `Send`, failing the fuzz CI job's `-D warnings` (rust-lang/rust#159228);
// same class of fix as deps-cargo #745, deps-nuget #696, deps-swift #673, deps-composer.
#![recursion_limit = "256"]

//! The `deps-lsp` binary crate.
//!
//! Wires a running `tower-lsp-server` [`LanguageServer`](tower_lsp_server::LanguageServer)
//! implementation on top of the [`deps_engine`] composition root.
//!
//! [`deps_engine::setup::register_ecosystems`] (re-exported here at the crate root — see
//! below) registers every feature-enabled ecosystem crate against an [`EcosystemRegistry`],
//! threading live-updatable settings ([`deps_engine::setup::EcosystemRuntime`]) into the ones
//! that need them; this composition is shared with every other driving adapter (`deps-cli`,
//! future `deps-mcp`) rather than reimplemented here, since a Cargo cycle prevents it from
//! living in `deps-core` itself (issue #1058). [`server::Backend`] is the `LanguageServer`
//! implementation itself; `document` holds the per-document state machine driving
//! hover/completion/diagnostics.

/// Live configuration parsing and the config schema (`deny_unknown_fields`).
pub mod config;
pub mod document;
pub mod file_watcher;
pub mod handlers;
/// Domain-type ⇄ LSP-protocol-type conversions.
///
/// `url::Url`/`deps_core::position::{Position, Range}` ⇄ `tower_lsp_server::ls_types`
/// conversions — the sole adapter boundary between deps-core's domain types and the LSP
/// protocol (issue #1071).
pub mod lsp_types_interop;
pub mod progress;
/// The `tower-lsp-server` [`LanguageServer`](tower_lsp_server::LanguageServer) implementation.
pub mod server;

#[cfg(test)]
mod test_utils;

pub use deps_core::parser::DependencySource;
pub use deps_core::{DepsError, EcosystemRegistry, HttpCache, Result};
pub use server::Backend;

// Composition root moved to deps-engine (#1058) so deps-cli/deps-mcp share one wiring;
// re-exported here unchanged for API compatibility (see tests/public_api_paths.rs).
//
// Glob, not an explicit list: deps_engine::setup's pub surface is entirely feature-gated,
// so an explicit list would have to duplicate that cfg gating. Trade-off (architecture-decision.md
// §7.3): any future pub item there silently becomes part of this crate's public API too.
pub use deps_engine::setup::*;
