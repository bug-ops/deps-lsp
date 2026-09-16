// Boxed-future `Send`-bound proof for `get_latest_matching`'s async chain occasionally
// exceeds rustc's default recursion limit, turning a silent trait-solver retry into a hard
// `-D warnings` error on the fuzz CI job (rust-lang/rust#159228). Same fix as deps-cargo
// (#745), deps-nuget (#696), deps-swift (#673), deps-composer. deps-gradle shares this
// exposure via delegation.
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
