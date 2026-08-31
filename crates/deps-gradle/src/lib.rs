//! Gradle build system support for deps-lsp.
//!
//! Provides parsing and version resolution for Gradle manifest formats:
//! - `gradle/libs.versions.toml` (Version Catalog)
//! - `build.gradle.kts` (Kotlin DSL)
//! - `build.gradle` (Groovy DSL)
//!
//! Registry integration reuses `deps_maven::MavenCentralRegistry`.

pub mod ecosystem;
pub mod formatter;
pub mod parser;
pub mod range;
pub mod types;

pub use ecosystem::GradleEcosystem;
pub use formatter::GradleFormatter;
pub use parser::{GradleParseResult, parse_gradle};
pub use types::{GradleDependency, GradleVersion};

/// Display name for the registry backing Gradle dependency resolution.
///
/// Gradle resolves through `deps_maven::MavenCentralRegistry`, so this
/// reuses Maven's registry display name rather than introducing a
/// separate, potentially divergent one.
pub use deps_maven::registry::REGISTRY;
