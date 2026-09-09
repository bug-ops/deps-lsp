//! Deno/JSR ecosystem support for deps-lsp.
//!
//! Parses `deno.json`/`deno.jsonc` manifests and routes each `imports` entry to the
//! right registry: `jsr:` specifiers to a JSR registry client (this crate), `npm:`
//! specifiers to the existing `deps-npm` client — through a single dispatching
//! `deps_core::Registry` facade, [`DenoRegistry`]. See [`crate::registry`]'s module docs
//! for the full architecture.

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
// #683: the three remaining #673 restriction lints, scoped to this crate only via a source
// attribute (which overrides this crate's `[lints] workspace = true` Cargo.toml table
// regardless of that table's level) rather than a duplicated `[lints.clippy]` table — avoids
// ~90 lines of drift-prone duplication of the workspace allow-list. Deliberately never added
// to `[workspace.lints.clippy]` itself (must stay opt-in per crate, not workspace-wide).
// Sites confirmed safe are individually `#[allow]`ed with a one-line justification.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]

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
