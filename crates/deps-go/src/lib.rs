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

pub mod error;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use error::{GoError, Result};
pub use parser::{GoParseResult, parse_go_mod};
pub use registry::{GoRegistry, package_url};
pub use types::{GoDependency, GoDirective, GoMetadata, GoVersion};
pub use version::{
    base_version_from_pseudo, compare_versions, escape_module_path, is_pseudo_version,
};
