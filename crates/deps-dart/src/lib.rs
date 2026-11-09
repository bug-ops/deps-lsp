// `PubDevRegistry`'s `Registry::get_latest_matching` boxed-future coercion nests through its
// own `async fn` call chain; rustc's default recursion limit is occasionally insufficient to
// prove the resulting `Send` bound and downgrades a previously-silent trait-solver retry into
// `recursion_depth_exceeding_limit`, which the fuzz CI job's `-D warnings` nightly build turns
// into a hard error (rust-lang/rust#159228). Same class of fix as deps-cargo (#745),
// deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

//! pubspec.yaml parsing and pub.dev integration.
//!
//! This crate provides Dart/Pub ecosystem support for the deps-lsp server,
//! including pubspec.yaml parsing, dependency extraction, and pub.dev
//! registry integration.

pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

pub use ecosystem::DartEcosystem;
pub use formatter::DartFormatter;
pub use lockfile::PubspecLockParser;
pub use parser::{DartParseResult, parse_pubspec_yaml};
pub use registry::{PubDevRegistry, package_url};
pub use types::{DartDependency, DartVersion, DependencySection, DependencySource, PackageInfo};
