//! Verdict classification: deciding what a dependency's status is.
//!
//! Every function here answers "what is true about this dependency" — outdated, yanked,
//! vulnerable, unsatisfiable, deprecated, fetch-failed — from data already in hand. None of it
//! knows when to ask a registry, how to report progress, or what to do if its input changes
//! mid-flight: those are orchestration concerns each driving adapter (`deps-lsp`, `deps-cli`,
//! ...) owns for itself. See `specs/062-cli-check-mode/architecture-decision.md` §3.2 for the
//! full split rationale (issue #1059).

pub mod diff;
pub mod fetch;
pub mod license;
pub mod osv;
pub mod resolved;
