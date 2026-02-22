//! Gradle build system support for deps-lsp.
//!
//! Provides parsing and version resolution for Gradle manifest formats:
//! - `gradle/libs.versions.toml` (Version Catalog)
//! - `build.gradle.kts` (Kotlin DSL)
//! - `build.gradle` (Groovy DSL)
//!
//! Registry integration reuses `deps_maven::MavenCentralRegistry`.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod parser;
pub mod types;

pub use ecosystem::GradleEcosystem;
pub use error::{GradleError, Result};
pub use formatter::GradleFormatter;
pub use parser::{GradleParseResult, parse_gradle};
pub use types::{GradleDependency, GradleVersion};
