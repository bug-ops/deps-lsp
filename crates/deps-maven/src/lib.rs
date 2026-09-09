// `MavenCentralRegistry`'s `Registry::get_latest_matching` boxed-future coercion nests
// through `get_latest_matching_typed`'s own `async fn` call chain; rustc's default recursion
// limit is occasionally insufficient to prove the resulting `Send` bound and downgrades a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz
// CI job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same
// class of fix as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
// deps-gradle delegates version lookups to this registry and shares the same exposure.
#![recursion_limit = "256"]

//! pom.xml parsing and Maven Central integration.
//!
//! This crate provides Maven/JVM ecosystem support for the deps-lsp server,
//! including pom.xml parsing, dependency extraction, and Maven Central
//! registry integration.

pub mod ecosystem;
pub mod formatter;
pub mod interval;
pub mod parser;
pub mod range;
pub mod registry;
pub mod types;
pub mod version;

pub use ecosystem::MavenEcosystem;
pub use formatter::MavenFormatter;
pub use parser::{MavenParseResult, parse_pom_xml};
pub use registry::{MavenCentralRegistry, package_url};
pub use types::{ArtifactInfo, MavenDependency, MavenScope, MavenVersion};
