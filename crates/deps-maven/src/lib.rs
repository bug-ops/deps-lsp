//! pom.xml parsing and Maven Central integration.
//!
//! This crate provides Maven/JVM ecosystem support for the deps-lsp server,
//! including pom.xml parsing, dependency extraction, and Maven Central
//! registry integration.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

pub use ecosystem::MavenEcosystem;
pub use error::{MavenError, Result};
pub use formatter::MavenFormatter;
pub use parser::{MavenParseResult, parse_pom_xml};
pub use registry::{MavenCentralRegistry, package_url};
pub use types::{ArtifactInfo, MavenDependency, MavenScope, MavenVersion};
