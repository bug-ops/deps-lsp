// `DenoRegistry`'s `Registry::get_latest_matching` boxed-future coercion dispatches through
// `JsrRegistry` and the `deps-npm` client's own async chains; rustc's default recursion limit
// is occasionally insufficient to prove the resulting `Send` bound and downgrades a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz
// CI job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same
// class of fix as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

//! Deno/JSR ecosystem support for deps-lsp.
//!
//! Parses `deno.json`/`deno.jsonc` manifests and routes each `imports` entry to the
//! right registry: `jsr:` specifiers to a JSR registry client (this crate), `npm:`
//! specifiers to the existing `deps-npm` client — through a single dispatching
//! `deps_core::Registry` facade, [`DenoRegistry`]. See [`crate::registry`]'s module docs
//! for the full architecture.

pub mod ecosystem;
pub mod formatter;
pub mod parser;
pub mod registry;
pub mod specifier;
pub mod types;

pub use ecosystem::DenoEcosystem;
pub use formatter::DenoFormatter;
pub use parser::{DenoParseResult, parse_deno_json};
pub use registry::{DenoRegistry, JsrRegistry};
pub use types::{DenoDependency, DenoDependencySection, DenoMetadata, JsrPackage, JsrVersion};
