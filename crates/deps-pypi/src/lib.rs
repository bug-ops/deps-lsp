//! PyPI/Python support for deps-lsp.
//!
//! This crate provides parsing, validation, and registry client functionality
//! for Python dependency management in `pyproject.toml` files (PEP 621 and
//! Poetry formats) and in `requirements.txt`/`constraints.txt` files (pip's
//! requirements file format).
//!
//! # Features
//!
//! - **PEP 621 Support**: Parse `[project.dependencies]` and `[project.optional-dependencies]`
//! - **Poetry Support**: Parse `[tool.poetry.dependencies]` and `[tool.poetry.group.*.dependencies]`
//! - **requirements.txt / constraints.txt Support**: Parse pip's line-oriented requirements
//!   file format, including comments, continuations, per-requirement options, and includes
//! - **PEP 508 Parsing**: Handle complex dependency specifications with extras and markers
//! - **PEP 440 Versions**: Validate and compare Python version specifiers
//! - **PEP 503 Name Normalization**: One canonical normalizer ([`name::normalize`]) shared by
//!   registry lookups, the formatter, and lock file parsing
//! - **PyPI API Client**: Fetch package metadata from PyPI JSON API with HTTP caching
//!
//! # Architecture
//!
//! deps-pypi follows the same architecture as deps-cargo and deps-npm:
//! - **Types**: `PypiDependency`, `PypiVersion`, `PypiPackage` with LSP range tracking
//! - **Parser**: Parse both PEP 621 and Poetry formats using `toml-span`
//! - **Registry**: PyPI JSON API client with HTTP caching
//! - **Error Handling**: Typed errors with `thiserror`
//!
//! # Examples
//!
//! ## Parsing pyproject.toml
//!
//! ```no_run
//! use deps_pypi::PypiParser;
//! use tower_lsp_server::ls_types::Uri;
//!
//! let content = r#"
//! [project]
//! dependencies = [
//!     "requests>=2.28.0,<3.0",
//!     "flask[async]>=3.0",
//! ]
//! "#;
//!
//! let parser = PypiParser::new();
//! let uri = Uri::from_file_path("/project/pyproject.toml").unwrap();
//! let result = parser.parse_content(content, &uri).unwrap();
//!
//! assert_eq!(result.dependencies.len(), 2);
//! assert_eq!(result.dependencies[0].name, "requests");
//! assert_eq!(result.dependencies[1].extras, vec!["async"]);
//! ```
//!
//! ## Fetching versions from PyPI
//!
//! ```no_run
//! use deps_pypi::PypiRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! # #[tokio::main]
//! # async fn main() {
//! let cache = Arc::new(HttpCache::new());
//! let registry = PypiRegistry::new(cache);
//!
//! let versions = registry.get_versions("requests").await.unwrap();
//! assert!(!versions.is_empty());
//!
//! let latest = registry
//!     .get_latest_matching("requests", ">=2.28.0,<3.0")
//!     .await
//!     .unwrap();
//! assert!(latest.is_some());
//! # }
//! ```
//!
//! ## Supported Formats
//!
//! ### PEP 621 (Standard)
//!
//! ```toml
//! [project]
//! dependencies = [
//!     "requests>=2.28.0,<3.0",
//!     "flask[async]>=3.0",
//!     "numpy>=1.24; python_version>='3.9'",
//! ]
//!
//! [project.optional-dependencies]
//! dev = ["pytest>=7.0", "mypy>=1.0"]
//! ```
//!
//! ### Poetry
//!
//! ```toml
//! [tool.poetry.dependencies]
//! python = "^3.9"
//! requests = "^2.28.0"
//! flask = {version = "^3.0", extras = ["async"]}
//!
//! [tool.poetry.group.dev.dependencies]
//! pytest = "^7.0"
//! mypy = "^1.0"
//! ```

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod name;
pub mod parser;
pub mod registry;
mod search;
pub mod types;

// Re-export commonly used types
pub use ecosystem::PypiEcosystem;
pub use error::{PypiError, Result};
pub use formatter::PypiFormatter;
pub use lockfile::PypiLockParser;
pub use parser::PypiParser;
pub use registry::PypiRegistry;
pub use types::{
    PypiDependency, PypiDependencySection, PypiDependencySource, PypiPackage, PypiVersion,
};
