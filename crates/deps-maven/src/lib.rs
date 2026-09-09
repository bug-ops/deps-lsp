//! pom.xml parsing and Maven Central integration.
//!
//! This crate provides Maven/JVM ecosystem support for the deps-lsp server,
//! including pom.xml parsing, dependency extraction, and Maven Central
//! registry integration.

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
