//! Go module ecosystem support for deps-lsp.
//!
//! This crate provides parsing, registry access, and LSP features for Go modules (go.mod files).
//!
//! # Features
//!
//! - Parse go.mod files with accurate position tracking
//! - Fetch version data from proxy.golang.org
//! - Generate LSP features (inlay hints, hover, completions)
//! - Support for go.mod directives: require, replace, exclude
//!
//! # Example
//!
//! ```no_run
//! use deps_go::parse_go_mod;
//! use tower_lsp_server::ls_types::Uri;
//!
//! let content = r#"
//! module example.com/myapp
//!
//! go 1.21
//!
//! require github.com/gin-gonic/gin v1.9.1
//! "#;
//!
//! let uri = Uri::from_file_path("/test/go.mod").unwrap();
//! let result = parse_go_mod(content, &uri).unwrap();
//! assert_eq!(result.dependencies.len(), 1);
//! ```

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

pub mod config;
pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use config::{GoEnvConfig, GoParseContext};
pub use ecosystem::GoEcosystem;
pub use formatter::GoFormatter;
pub use lockfile::{GoSumParser, parse_go_sum};
pub use parser::{GoParseResult, parse_go_mod, parse_go_mod_with_context};
pub use registry::{GoRegistry, package_url};
pub use types::{GoDependency, GoDirective, GoMetadata, GoVersion};
pub use version::{
    base_version_from_pseudo, compare_versions, escape_module_path, escape_version,
    is_pseudo_version,
};
