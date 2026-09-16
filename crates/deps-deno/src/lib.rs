// Boxed-future `Send`-bound proof dispatching through `JsrRegistry` and `deps-npm`'s async
// chains occasionally exceeds rustc's default recursion limit, turning a silent trait-solver
// retry into a hard `-D warnings` error on the fuzz CI job (rust-lang/rust#159228). Same fix
// as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
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
