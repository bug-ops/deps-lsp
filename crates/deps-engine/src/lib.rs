// `setup::register_ecosystems` constructs every feature-enabled ecosystem's registry client
// and formatter behind a boxed `Ecosystem` trait object; proving the resulting `Send` bound
// across 14 crates' own `get_latest_matching`-style implementations has, in the crate this
// module was moved from, occasionally exceeded rustc's default recursion limit, downgrading a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit` under `-D
// warnings` (rust-lang/rust#159228). Same class of fix as deps-cargo (#745), deps-nuget
// (#696), deps-swift (#673), deps-composer, and deps-lsp (issue #1058, this module's origin).
#![recursion_limit = "256"]

//! The workspace's composition root.
//!
//! Wires every feature-enabled `deps-<ecosystem>` crate's [`deps_core::ecosystem::Ecosystem`]
//! implementation into a [`deps_core::EcosystemRegistry`].
//!
//! This crate exists only because Cargo forbids a cycle: `deps-core` cannot depend on any
//! `deps-<ecosystem>` crate, since all 14 already depend on `deps-core`. Every driving adapter
//! (`deps-lsp`, and future `deps-cli`/`deps-mcp`) depends on `deps-engine` instead of
//! reimplementing ecosystem registration itself — see `specs/062-cli-check-mode/
//! architecture-decision.md` for the full design rationale (issue #1058).
//!
//! Three modules:
//!
//! - [`setup`] — the composition root itself: `EcosystemRuntime`, `register_ecosystems`, and
//!   the ~110 concrete ecosystem types re-exported for convenience, moved verbatim from
//!   `deps-lsp/src/lib.rs`.
//! - [`classify`] — the pure dependency-classification layer (in-use-version/lockfile
//!   resolution, OSV scan-target and fix-target-verification decisions, registry fetch
//!   fan-out, and outcome-merging helpers), moved from `deps-lsp`'s `document/` module
//!   (issue #1059) so a future `deps-cli` reaches identical verdicts without reimplementing
//!   any of it.
//! - [`progress`] — a driving-adapter-agnostic progress-reporting port fetch tasks report
//!   through, also moved from `deps-lsp` as part of #1059.

pub mod classify;
pub mod progress;
pub mod setup;
