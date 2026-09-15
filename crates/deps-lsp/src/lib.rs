// `document/fetch.rs` and the test-only mock `Registry` implementations in `test_utils.rs`/
// `handlers/completion.rs` box futures for every ecosystem's `get_latest_matching`-style call;
// rustc's default recursion limit has proven occasionally insufficient to prove the resulting
// `Send` bound for several ecosystem crates' own implementations, downgrading a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz
// CI job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same
// class of fix as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

//! The `deps-lsp` binary crate: wires a running `tower-lsp-server`
//! [`LanguageServer`](tower_lsp_server::LanguageServer) implementation on top of the
//! [`deps_engine`] composition root.
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
pub mod progress;
/// The `tower-lsp-server` [`LanguageServer`](tower_lsp_server::LanguageServer) implementation.
pub mod server;

#[cfg(test)]
mod test_utils;

pub use deps_core::parser::DependencySource;
pub use deps_core::{DepsError, EcosystemRegistry, HttpCache, Result};
pub use server::Backend;

// The composition root — `EcosystemRuntime`/`register_ecosystems` and every ecosystem's
// concrete types — now lives in `deps-engine` (issue #1058), so `deps-cli`/`deps-mcp` share
// the exact same wiring instead of each re-registering ecosystems independently. Re-exported
// here, unchanged in path, so this remains non-breaking for anything depending on
// `deps_lsp::EcosystemRuntime`/`deps_lsp::register_ecosystems`/the ecosystem type re-exports
// (see `crates/deps-lsp/tests/public_api_paths.rs`).
//
// Deliberately a glob, not the explicit list `tasks.md`'s T004 originally specified:
// `deps_engine::setup`'s own `pub` surface is entirely feature-gated per-ecosystem, so an
// explicit list here would have to duplicate that same `#[cfg(feature = ...)]` gating a
// second time to stay in sync, or list types unconditionally and let deps-engine's own cfg
// silently drop the unavailable ones (harder to audit than the glob). The trade-off, accepted
// here: any future `pub` item added to `deps_engine::setup` becomes `deps_lsp` public API
// automatically, and would silently shadow on a name collision — see architecture-decision.md
// §7.3's public-dependency-coupling cost, which this is one instance of.
pub use deps_engine::setup::*;
