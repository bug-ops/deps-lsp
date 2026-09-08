//! pom.xml parsing and Maven Central integration.
//!
//! This crate provides Maven/JVM ecosystem support for the deps-lsp server,
//! including pom.xml parsing, dependency extraction, and Maven Central
//! registry integration.

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
#![warn(clippy::string_slice)]

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
