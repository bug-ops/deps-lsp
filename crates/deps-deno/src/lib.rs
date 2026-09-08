//! Deno/JSR ecosystem support for deps-lsp.
//!
//! Parses `deno.json`/`deno.jsonc` manifests and routes each `imports` entry to the
//! right registry: `jsr:` specifiers to a JSR registry client (this crate), `npm:`
//! specifiers to the existing `deps-npm` client — through a single dispatching
//! `deps_core::Registry` facade, [`DenoRegistry`]. See [`crate::registry`]'s module docs
//! for the full architecture.

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
#![warn(clippy::string_slice)]

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
