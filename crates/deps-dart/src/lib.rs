//! pubspec.yaml parsing and pub.dev integration.
//!
//! This crate provides Dart/Pub ecosystem support for the deps-lsp server,
//! including pubspec.yaml parsing, dependency extraction, and pub.dev
//! registry integration.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

pub use ecosystem::DartEcosystem;
pub use error::{DartError, Result};
pub use formatter::DartFormatter;
pub use lockfile::PubspecLockParser;
pub use parser::{DartParseResult, parse_pubspec_yaml};
pub use registry::{PubDevRegistry, package_url};
pub use types::{DartDependency, DartVersion, DependencySection, DependencySource, PackageInfo};
