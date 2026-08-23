//! Code lens handler: "Update N outdated dependencies".
//!
//! Mirrors `handlers::code_actions`' delegation pattern, but produces a single
//! document-scoped lens (or none) bound to [`COMMAND_ID`] rather than a per-position
//! action. The command handler that applies the edit lives in `server::execute_command`,
//! not here — it needs the raw `Vec<TextEdit>`, not the wrapped `CodeLens`.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{CodeLens, CodeLensParams};

/// The `workspace/executeCommand` id bound to the lens produced here.
pub const COMMAND_ID: &str = "deps-lsp.updateAllOutdated";

/// Handles `textDocument/codeLens` requests using trait-based delegation.
///
/// Returns zero or one lens for the document. Zero when: the code lens feature is
/// disabled (`enabled` is `false`); the document cannot be loaded; it has no parse
/// result; it is not [ready for a batch
/// update](crate::document::DocumentState::is_ready_for_batch_update) (version data is
/// still loading, or the document has no known LSP version — the same two conditions
/// `execute_update_all_outdated` requires, so the lens never renders a click target the
/// command would then refuse); or every dependency is up to date / not safely editable
/// (see `deps_core::lsp_helpers::collect_update_all_edits`).
pub async fn handle_code_lens(
    state: Arc<ServerState>,
    params: CodeLensParams,
    enabled: bool,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Vec<CodeLens> {
    if !enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, config).await {
        tracing::warn!("Could not load document for code lens: {:?}", uri);
        return vec![];
    }

    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id()) {
        Some(e) => e,
        None => return vec![],
    };

    // Refuse the same conditions `execute_update_all_outdated` requires before acting,
    // so the lens never renders a click target the command would then refuse: version
    // data isn't `Loading` (avoids counting against an empty cache, also mirrors
    // `diagnostics::generate_diagnostics_internal`), and the document has a known LSP
    // version (`None` means it was loaded from disk after a missed `didOpen` — see
    // `DocumentState::is_ready_for_batch_update`).
    if !doc.is_ready_for_batch_update() {
        return vec![];
    }

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    ecosystem
        .generate_code_lenses(
            parse_result,
            &doc.content,
            VersionData::new(&doc.cached_versions, &doc.resolved_versions),
            uri,
            COMMAND_ID,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;
    use tower_lsp_server::ls_types::TextDocumentIdentifier;

    fn params(uri: tower_lsp_server::ls_types::Uri) -> CodeLensParams {
        CodeLensParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_handle_code_lens_disabled_returns_empty() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let (client, config) = create_test_client_and_config();

        let result = handle_code_lens(state, params(uri), false, client, config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_code_lens_missing_document_returns_empty() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/unknown.txt");
        let (client, config) = create_test_client_and_config();

        let result = handle_code_lens(state, params(uri), true, client, config).await;
        assert!(result.is_empty());
    }

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        async fn seed(
            state: &Arc<ServerState>,
            uri: &tower_lsp_server::ls_types::Uri,
            content: &str,
            cached: std::collections::HashMap<String, String>,
        ) {
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem
                .parse_manifest(content, uri)
                .await
                .expect("failed to parse manifest");
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.to_string(),
                parse_result,
            );
            doc_state.update_cached_versions(cached);
            doc_state.set_loaded();
            doc_state.set_version(Some(1));
            state.update_document(uri.clone(), doc_state);
        }

        #[tokio::test]
        async fn test_handle_code_lens_no_parse_result_returns_empty() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let (client, config) = create_test_client_and_config();
            let result = handle_code_lens(state, params(uri), true, client, config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_code_lens_loading_returns_empty() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0.0\"\n";
            let mut cached = std::collections::HashMap::new();
            cached.insert("serde".to_string(), "1.2.0".to_string());
            seed(&state, &uri, content, cached).await;
            state.documents.get_mut(&uri).unwrap().set_loading();

            let (client, config) = create_test_client_and_config();
            let result = handle_code_lens(state, params(uri), true, client, config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_code_lens_no_version_returns_empty() {
            // Regression guard (S1): a document with `version: None` (populated from
            // disk after a missed didOpen) must not render a lens that
            // `execute_update_all_outdated` would then always refuse on click.
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0.0\"\n";
            let mut cached = std::collections::HashMap::new();
            cached.insert("serde".to_string(), "1.2.0".to_string());
            seed(&state, &uri, content, cached).await;
            state.documents.get_mut(&uri).unwrap().set_version(None);

            let (client, config) = create_test_client_and_config();
            let result = handle_code_lens(state, params(uri), true, client, config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_code_lens_up_to_date_fixture_returns_no_lens() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0.0\"\n";
            let mut cached = std::collections::HashMap::new();
            cached.insert("serde".to_string(), "1.0.0".to_string());
            seed(&state, &uri, content, cached).await;

            let (client, config) = create_test_client_and_config();
            let result = handle_code_lens(state, params(uri), true, client, config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_code_lens_outdated_fixture_returns_one_lens() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0.0\"\n";
            let mut cached = std::collections::HashMap::new();
            cached.insert("serde".to_string(), "1.2.0".to_string());
            seed(&state, &uri, content, cached).await;

            let (client, config) = create_test_client_and_config();
            let result = handle_code_lens(state, params(uri.clone()), true, client, config).await;

            assert_eq!(result.len(), 1);
            let command = result[0].command.as_ref().expect("lens has a command");
            assert_eq!(command.title, "Update 1 outdated dependency");
            assert_eq!(command.command, COMMAND_ID);
            let args = command
                .arguments
                .as_ref()
                .expect("command has arguments")
                .first()
                .expect("command has one argument");
            assert_eq!(args["uri"], uri.as_str());
        }
    }

    /// Cross-ecosystem consistency matrix for `collect_update_all_edits` (required by
    /// `.claude/rules/continuous-improvement.md`'s cross-ecosystem rule and §6 of the
    /// design plan). Exercises the real per-ecosystem parser/formatter, including the
    /// fragile ecosystems the §4.4 literal-span guard must skip: every "passes" fixture
    /// asserts the *resulting document text is a valid, re-parseable declaration* (not
    /// merely "an edit exists"); every "skipped" fixture asserts no edit is produced at
    /// all, proving the guard — not the absence of a fixture — is what stops it.
    mod cross_ecosystem_tests {
        use super::*;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::TextEdit;

        /// Applies a single `TextEdit` to `content`, using the exact inverse of the
        /// `Position`-to-byte-offset conversion `collect_update_all_edits` used to build
        /// the edit's range in the first place.
        fn apply_single_edit(content: &str, edit: &TextEdit) -> String {
            let table = deps_core::LineOffsetTable::new(content);
            let start = table.position_to_byte_offset(content, edit.range.start);
            let end = table.position_to_byte_offset(content, edit.range.end);
            format!("{}{}{}", &content[..start], edit.new_text, &content[end..])
        }

        /// Asserts the ecosystem produces exactly one edit for `content`, and that
        /// applying it yields text which both contains `expected_fragment` and still
        /// parses successfully under the same ecosystem parser.
        async fn assert_single_edit_produces_valid_declaration(
            ecosystem: &dyn deps_core::Ecosystem,
            uri: &tower_lsp_server::ls_types::Uri,
            content: &str,
            cached: HashMap<String, String>,
            expected_fragment: &str,
        ) {
            let parse_result = ecosystem
                .parse_manifest(content, uri)
                .await
                .expect("fixture must parse");
            let resolved = HashMap::new();
            let edits = deps_core::collect_update_all_edits(
                parse_result.as_ref(),
                content,
                deps_core::VersionData::new(&cached, &resolved),
                ecosystem.formatter(),
            );
            assert_eq!(edits.len(), 1, "expected exactly one edit for this fixture");

            let new_content = apply_single_edit(content, &edits[0]);
            assert!(
                new_content.contains(expected_fragment),
                "resulting text should contain {expected_fragment:?}, got: {new_content}"
            );
            ecosystem
                .parse_manifest(&new_content, uri)
                .await
                .unwrap_or_else(|e| panic!("resulting text failed to re-parse: {e}"));
        }

        /// Asserts the ecosystem produces no edit at all — the literal-span guard case.
        async fn assert_guard_skips(
            ecosystem: &dyn deps_core::Ecosystem,
            uri: &tower_lsp_server::ls_types::Uri,
            content: &str,
            cached: HashMap<String, String>,
        ) {
            let parse_result = ecosystem
                .parse_manifest(content, uri)
                .await
                .expect("fixture must parse");
            let resolved = HashMap::new();
            let edits = deps_core::collect_update_all_edits(
                parse_result.as_ref(),
                content,
                deps_core::VersionData::new(&cached, &resolved),
                ecosystem.formatter(),
            );
            assert!(
                edits.is_empty(),
                "expected the literal-span guard to skip this dependency"
            );
        }

        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn test_cargo_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0.0\"\n";
            let mut cached = HashMap::new();
            cached.insert("serde".to_string(), "1.2.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "serde = \"1.2.0\"",
            )
            .await;
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let content = r#"{"dependencies": {"express": "^4.0.0"}}"#;
            let mut cached = HashMap::new();
            cached.insert("express".to_string(), "5.0.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "\"express\": \"5.0.0\"",
            )
            .await;
        }

        #[cfg(feature = "pypi")]
        #[tokio::test]
        async fn test_pypi_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("pypi").unwrap();
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            // An exact pin, not a lower bound: "==2.0.0" does not accept "2.5.0", unlike
            // ">=2.0.0" (which the "already accepts latest" rule would correctly skip).
            let content = "[project]\ndependencies = [\"requests==2.0.0\"]\n";
            let mut cached = HashMap::new();
            cached.insert("requests".to_string(), "2.5.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "requests>=2.5.0,<3",
            )
            .await;
        }

        #[cfg(feature = "go")]
        #[tokio::test]
        async fn test_go_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("go").unwrap();
            let uri = deps_core::test_util::test_uri("/test/go.mod");
            let content =
                "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n";
            let mut cached = HashMap::new();
            cached.insert(
                "github.com/gin-gonic/gin".to_string(),
                "v1.10.0".to_string(),
            );

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "require github.com/gin-gonic/gin v1.10.0",
            )
            .await;
        }

        #[cfg(feature = "dart")]
        #[tokio::test]
        async fn test_dart_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("dart").unwrap();
            let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
            // A major-version bump: "^1.0.0" does not accept "2.0.0".
            let content = "dependencies:\n  http: ^1.0.0\n";
            let mut cached = HashMap::new();
            cached.insert("http".to_string(), "2.0.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "http: ^2.0.0",
            )
            .await;
        }

        #[cfg(feature = "nuget")]
        #[tokio::test]
        async fn test_nuget_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("nuget").unwrap();
            let uri = deps_core::test_util::test_uri("/test/project.csproj");
            let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>"#;
            let mut cached = HashMap::new();
            cached.insert("Newtonsoft.Json".to_string(), "13.0.3".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                r#"Version="13.0.3""#,
            )
            .await;
        }

        #[cfg(feature = "composer")]
        #[tokio::test]
        async fn test_composer_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("composer").unwrap();
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let content = "{\n  \"require\": {\n    \"symfony/console\": \"^6.0\"\n  }\n}";
            let mut cached = HashMap::new();
            cached.insert("symfony/console".to_string(), "7.0.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "\"symfony/console\": \"7.0.0\"",
            )
            .await;
        }

        #[cfg(feature = "bundler")]
        #[tokio::test]
        async fn test_bundler_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("bundler").unwrap();
            let uri = deps_core::test_util::test_uri("/test/Gemfile");
            let content = "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'";
            let mut cached = HashMap::new();
            cached.insert("rails".to_string(), "8.0.0".to_string());

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "gem 'rails', '8.0.0'",
            )
            .await;
        }

        #[cfg(feature = "maven")]
        #[tokio::test]
        async fn test_maven_literal_version_is_edited() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("maven").unwrap();
            let uri = deps_core::test_util::test_uri("/test/pom.xml");
            let content = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
";
            let mut cached = HashMap::new();
            cached.insert(
                "org.apache.commons:commons-lang3".to_string(),
                "3.14.0".to_string(),
            );

            assert_single_edit_produces_valid_declaration(
                ecosystem.as_ref(),
                &uri,
                content,
                cached,
                "<version>3.14.0</version>",
            )
            .await;
        }

        #[cfg(feature = "maven")]
        #[tokio::test]
        async fn test_maven_property_version_is_skipped() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("maven").unwrap();
            let uri = deps_core::test_util::test_uri("/test/pom.xml");
            let content = r"<project>
  <properties>
    <slf4j.version>2.0.16</slf4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>
";
            let mut cached = HashMap::new();
            cached.insert("org.slf4j:slf4j-api".to_string(), "2.1.0".to_string());

            assert_guard_skips(ecosystem.as_ref(), &uri, content, cached).await;
        }

        #[cfg(feature = "gradle")]
        #[tokio::test]
        async fn test_gradle_dsl_variable_is_skipped() {
            // Gradle resolves `$var`/`${var}` references only from a real
            // `gradle.properties` file next to the build script, so this fixture is
            // written to a temp directory (mirrors `document::lifecycle`'s own
            // disk-based cold-start tests).
            let temp_dir = tempfile::TempDir::new().unwrap();
            let build_gradle_path = temp_dir.path().join("build.gradle");
            let content = "dependencies {\n    implementation \"org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion\"\n}\n";
            std::fs::write(&build_gradle_path, content).unwrap();
            std::fs::write(
                temp_dir.path().join("gradle.properties"),
                "kotlinVersion=2.1.10\n",
            )
            .unwrap();

            let uri = tower_lsp_server::ls_types::Uri::from_file_path(&build_gradle_path).unwrap();
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("gradle").unwrap();

            let mut cached = HashMap::new();
            cached.insert(
                "org.jetbrains.kotlin:kotlin-stdlib".to_string(),
                "2.2.0".to_string(),
            );

            assert_guard_skips(ecosystem.as_ref(), &uri, content, cached).await;
        }

        #[cfg(feature = "gradle")]
        #[tokio::test]
        async fn test_gradle_version_catalog_alias_is_skipped() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("gradle").unwrap();
            let uri = deps_core::test_util::test_uri("/test/gradle/libs.versions.toml");
            let content = "[versions]\nspring = \"3.2.0\"\n\n[libraries]\nspring-boot = { module = \"org.springframework.boot:spring-boot-starter\", version.ref = \"spring\" }\n";
            let mut cached = HashMap::new();
            cached.insert(
                "org.springframework.boot:spring-boot-starter".to_string(),
                "3.3.0".to_string(),
            );

            assert_guard_skips(ecosystem.as_ref(), &uri, content, cached).await;
        }

        #[cfg(feature = "swift")]
        #[tokio::test]
        async fn test_swift_from_form_is_skipped() {
            let state = ServerState::new();
            let ecosystem = state.ecosystem_registry.get("swift").unwrap();
            let uri = deps_core::test_util::test_uri("/test/Package.swift");
            let content = r#"
let package = Package(
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
    ]
)
"#;
            let mut cached = HashMap::new();
            cached.insert("apple/swift-nio".to_string(), "3.0.0".to_string());

            assert_guard_skips(ecosystem.as_ref(), &uri, content, cached).await;
        }
    }
}
