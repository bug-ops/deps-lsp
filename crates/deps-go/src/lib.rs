// Boxed-future `Send`-bound proof for `get_latest_matching_from`'s async chain occasionally
// exceeds rustc's default recursion limit, turning a silent trait-solver retry into a hard
// `-D warnings` error on the fuzz CI job (rust-lang/rust#159228). Same fix as deps-cargo
// (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

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
//! use url::Url;
//!
//! let content = r#"
//! module example.com/myapp
//!
//! go 1.21
//!
//! require github.com/gin-gonic/gin v1.9.1
//! "#;
//!
//! let uri = Url::from_file_path("/test/go.mod").unwrap();
//! let result = parse_go_mod(content, &uri).unwrap();
//! assert_eq!(result.dependencies.len(), 1);
//! ```

pub mod config;
pub mod ecosystem;
/// Version formatting and comparison for Go modules (semver, pseudo-versions, `+incompatible`).
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

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
