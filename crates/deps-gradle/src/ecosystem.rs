//! Gradle ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
    position_in_range,
};
use deps_maven::MavenCentralRegistry;

use crate::formatter::GradleFormatter;

pub struct GradleEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: GradleFormatter,
}

impl GradleEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(cache)),
            formatter: GradleFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(self.registry.as_ref(), prefix, 20)
            .await
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
        )
        .await
    }

    /// Detects completion context for Gradle files at the given position.
    ///
    /// Returns ("version" | "package" | "", current_value).
    fn detect_completion_context<'a>(
        content: &'a str,
        position: Position,
        uri: &Uri,
    ) -> (&'static str, &'a str) {
        let path = uri.path().to_string();
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;
        let col_idx = position.character as usize;

        if line_idx >= lines.len() {
            return ("", "");
        }

        let line = lines[line_idx];
        let before_cursor = &line[..col_idx.min(line.len())];

        if path.ends_with("libs.versions.toml") {
            detect_catalog_context(before_cursor, line)
        } else if path.ends_with(".gradle.kts") || path.ends_with(".gradle") {
            detect_dsl_context(before_cursor, line)
        } else {
            ("", "")
        }
    }
}

/// Detects completion context in version catalog files.
fn detect_catalog_context<'a>(before_cursor: &str, line: &'a str) -> (&'static str, &'a str) {
    // version = "..." or version.ref = "..."
    if let Some(eq_pos) = before_cursor.rfind("version")
        && let after = &before_cursor[eq_pos..]
        && after.contains('=')
        && let Some(quote_start) = after.rfind('"')
    {
        let value_start = eq_pos + quote_start + 1;
        if value_start <= line.len() {
            let quote_end = line[value_start..]
                .find('"')
                .map_or(line.len(), |i| value_start + i);
            return ("version", &line[value_start..quote_end]);
        }
    }

    // module = "..."
    if let Some(eq_pos) = before_cursor.rfind("module")
        && let after = &before_cursor[eq_pos..]
        && after.contains('=')
        && let Some(quote_start) = after.rfind('"')
    {
        let value_start = eq_pos + quote_start + 1;
        if value_start <= line.len() {
            let quote_end = line[value_start..]
                .find('"')
                .map_or(line.len(), |i| value_start + i);
            return ("package", &line[value_start..quote_end]);
        }
    }

    ("", "")
}

/// Detects completion context in Kotlin/Groovy DSL files.
fn detect_dsl_context<'a>(before_cursor: &str, line: &'a str) -> (&'static str, &'a str) {
    let in_string = before_cursor
        .chars()
        .filter(|&c| c == '"' || c == '\'')
        .count()
        % 2
        == 1;
    if !in_string {
        return ("", "");
    }

    let colon_count = before_cursor.chars().filter(|&c| c == ':').count();
    let quote_char = if before_cursor.contains('"') {
        '"'
    } else {
        '\''
    };

    let Some(open_pos) = before_cursor.rfind(quote_char) else {
        return ("", "");
    };

    match colon_count {
        0 | 1 => {
            let close = line[open_pos + 1..]
                .find(['"', '\''])
                .map_or(line.len(), |i| open_pos + 1 + i);
            ("package", &line[open_pos + 1..close])
        }
        _ => {
            let version_start = before_cursor
                .char_indices()
                .filter(|(_, c)| *c == ':')
                .nth(1)
                .map(|(i, _)| i + 1)
                .unwrap_or(before_cursor.len());
            let close = line[version_start..]
                .find(['"', '\''])
                .map_or(line.len(), |i| version_start + i);
            ("version", &line[version_start..close])
        }
    }
}

impl Ecosystem for GradleEcosystem {
    fn id(&self) -> &'static str {
        "gradle"
    }

    fn display_name(&self) -> &'static str {
        "Gradle (JVM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &[
            "libs.versions.toml",
            "build.gradle.kts",
            "build.gradle",
            "settings.gradle.kts",
            "settings.gradle",
        ]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result =
                crate::parser::parse_gradle(content, uri).map_err(deps_core::DepsError::from)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move {
            let uri = parse_result.uri();
            let (ctx_type, value) = Self::detect_completion_context(content, position, uri);

            match ctx_type {
                "version" => {
                    let dep = parse_result.dependencies().into_iter().find(|d| {
                        d.version_range()
                            .is_some_and(|r| position_in_range(position, r))
                            || d.name_range().start.line == position.line
                    });
                    if let Some(dep) = dep {
                        self.complete_versions(dep.name(), value).await
                    } else {
                        vec![]
                    }
                }
                "package" => self.complete_package_names(value).await,
                _ => vec![],
            }
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> Arc<deps_core::HttpCache> {
        Arc::new(deps_core::HttpCache::new())
    }

    #[test]
    fn test_ecosystem_id() {
        let eco = GradleEcosystem::new(make_cache());
        assert_eq!(eco.id(), "gradle");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let eco = GradleEcosystem::new(make_cache());
        assert_eq!(eco.display_name(), "Gradle (JVM)");
    }

    #[test]
    fn test_manifest_filenames() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.manifest_filenames().contains(&"libs.versions.toml"));
        assert!(eco.manifest_filenames().contains(&"build.gradle.kts"));
        assert!(eco.manifest_filenames().contains(&"build.gradle"));
        assert!(eco.manifest_filenames().contains(&"settings.gradle.kts"));
        assert!(eco.manifest_filenames().contains(&"settings.gradle"));
    }

    #[test]
    fn test_lockfile_filenames_empty() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.lockfile_filenames().is_empty());
    }

    #[test]
    fn test_lockfile_provider_none() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.lockfile_provider().is_none());
    }

    #[test]
    fn test_as_any() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.as_any().is::<GradleEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_short_prefix() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(eco.complete_package_names("a").await.is_empty());
        assert!(eco.complete_package_names("").await.is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_kts() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"junit:junit:4.13.2\")\n}\n";
        let uri = Uri::from_file_path("/project/build.gradle.kts").unwrap();
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_groovy() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n";
        let uri = Uri::from_file_path("/project/build.gradle").unwrap();
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }
}
