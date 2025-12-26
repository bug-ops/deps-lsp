//! Core completion infrastructure for deps-lsp.
//!
//! This module provides generic completion functionality that works across
//! all package ecosystems (Cargo, npm, PyPI, etc.). It handles:
//!
//! - Context detection - determining what type of completion is appropriate
//! - Prefix extraction - getting the text typed so far
//! - CompletionItem builders - creating LSP completion responses
//!
//! # Architecture
//!
//! The completion system uses trait objects (`dyn Dependency`, `dyn ParseResult`,
//! `dyn Version`, `dyn Metadata`) to work generically across ecosystems.
//!
//! # Examples
//!
//! ```no_run
//! use deps_core::completion::{detect_completion_context, CompletionContext};
//! use tower_lsp_server::ls_types::Position;
//!
//! // In your ecosystem's generate_completions implementation:
//! async fn generate_completions(
//!     parse_result: &dyn deps_core::ParseResult,
//!     position: Position,
//!     content: &str,
//! ) -> Vec<tower_lsp_server::ls_types::CompletionItem> {
//!     let context = detect_completion_context(parse_result, position, content);
//!
//!     match context {
//!         CompletionContext::PackageName { prefix } => {
//!             // Search registry and build completions
//!             vec![]
//!         }
//!         CompletionContext::Version { package_name, prefix } => {
//!             // Fetch versions and build completions
//!             vec![]
//!         }
//!         _ => vec![],
//!     }
//! }
//! ```

use crate::{Metadata, ParseResult, Version};
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionItemTag, CompletionTextEdit, Documentation,
    MarkupContent, MarkupKind, Position, Range, TextEdit,
};

/// Context for completion request based on cursor position.
///
/// This enum represents what type of completion is appropriate at the
/// current cursor location within a manifest file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionContext {
    /// Cursor is within or after a package name.
    ///
    /// Example: `serd|` or `tokio|` where | represents cursor position.
    PackageName {
        /// Partial package name typed so far (may be empty).
        prefix: String,
    },

    /// Cursor is within a version string.
    ///
    /// Example: `"1.0|"` or `"^2.|"` where | represents cursor position.
    Version {
        /// Package name this version belongs to.
        package_name: String,
        /// Partial version typed so far (may include operators like ^, ~).
        prefix: String,
    },

    /// Cursor is within a feature array.
    ///
    /// Example: `features = ["deri|"]` where | represents cursor position.
    Feature {
        /// Package name whose features are being completed.
        package_name: String,
        /// Partial feature name typed so far (may be empty).
        prefix: String,
    },

    /// Cursor is not in a valid completion position.
    None,
}

/// Detects the completion context based on cursor position.
///
/// This function analyzes the cursor position relative to parsed dependencies
/// to determine what type of completion should be offered.
///
/// # Arguments
///
/// * `parse_result` - Parsed manifest with dependency information
/// * `position` - Cursor position in the document (LSP Position, 0-based line, 0-based character)
/// * `content` - Full document content for prefix extraction
///
/// # Returns
///
/// A `CompletionContext` indicating what type of completion is appropriate,
/// or `CompletionContext::None` if the cursor is not in a valid position.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::detect_completion_context;
/// use tower_lsp_server::ls_types::Position;
///
/// # async fn example(parse_result: &dyn deps_core::ParseResult, content: &str) {
/// // Cursor at position after "ser" in "serde"
/// let position = Position { line: 5, character: 3 };
/// let context = detect_completion_context(parse_result, position, content);
/// # }
/// ```
pub fn detect_completion_context(
    parse_result: &dyn ParseResult,
    position: Position,
    content: &str,
) -> CompletionContext {
    let dependencies = parse_result.dependencies();

    for dep in dependencies {
        // Check if position is within the dependency name range
        let name_range = dep.name_range();
        if position_in_range(position, name_range) {
            let prefix = extract_prefix(content, position, name_range);
            return CompletionContext::PackageName { prefix };
        }

        // Check if position is within the version range
        if let Some(version_range) = dep.version_range()
            && position_in_range(position, version_range)
        {
            let prefix = extract_prefix(content, position, version_range);
            return CompletionContext::Version {
                package_name: dep.name().to_string(),
                prefix,
            };
        }

        // TODO: Feature detection - ecosystem-specific, requires more context
    }

    CompletionContext::None
}

/// Checks if a position is within or at the end of a range.
///
/// LSP ranges are inclusive of start, exclusive of end.
/// We also consider the position to be "in range" if it's immediately
/// after the range end (for completion after typing).
const fn position_in_range(position: Position, range: Range) -> bool {
    // Before range start
    if position.line < range.start.line {
        return false;
    }

    if position.line == range.start.line && position.character < range.start.character {
        return false;
    }

    // After range end (allow one position past for completion)
    if position.line > range.end.line {
        return false;
    }

    if position.line == range.end.line && position.character > range.end.character + 1 {
        return false;
    }

    true
}

/// Converts UTF-16 offset to byte offset in a string.
///
/// LSP uses UTF-16 code units for character positions (for compatibility with
/// JavaScript and other languages). This function converts from UTF-16 offset
/// to byte offset for Rust string indexing.
///
/// # Arguments
///
/// * `s` - The string to index into
/// * `utf16_offset` - UTF-16 code unit offset (from LSP Position.character)
///
/// # Returns
///
/// Byte offset if valid, `None` if the UTF-16 offset is out of bounds.
///
/// # Examples
///
/// ```
/// # use deps_core::completion::utf16_to_byte_offset;
/// // ASCII: UTF-16 offset equals byte offset
/// assert_eq!(utf16_to_byte_offset("hello", 2), Some(2));
///
/// // Unicode: "日本語" - each char is 3 bytes but 1 UTF-16 code unit
/// assert_eq!(utf16_to_byte_offset("日本語", 0), Some(0));
/// assert_eq!(utf16_to_byte_offset("日本語", 1), Some(3));
/// assert_eq!(utf16_to_byte_offset("日本語", 2), Some(6));
///
/// // Emoji: "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
/// assert_eq!(utf16_to_byte_offset("😀test", 2), Some(4));
/// ```
pub fn utf16_to_byte_offset(s: &str, utf16_offset: u32) -> Option<usize> {
    let mut utf16_count = 0u32;
    for (byte_idx, ch) in s.char_indices() {
        if utf16_count >= utf16_offset {
            return Some(byte_idx);
        }
        utf16_count += ch.len_utf16() as u32;
    }
    if utf16_count == utf16_offset {
        return Some(s.len());
    }
    None
}

/// Extracts the prefix text from content at a position within a range.
///
/// This function finds the text from the start of the range up to the
/// cursor position, excluding any quote characters.
///
/// # Arguments
///
/// * `content` - Full document content
/// * `position` - Cursor position (LSP Position, 0-based line, UTF-16 character offset)
/// * `range` - Range containing the token (name, version, etc.)
///
/// # Returns
///
/// The prefix string typed so far, with quotes and extra whitespace removed.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::extract_prefix;
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let content = r#"serde = "1.0""#;
/// let position = Position { line: 0, character: 11 }; // After "1."
/// let range = Range {
///     start: Position { line: 0, character: 9 },
///     end: Position { line: 0, character: 13 },
/// };
///
/// let prefix = extract_prefix(content, position, range);
/// assert_eq!(prefix, "1.");
/// ```
pub fn extract_prefix(content: &str, position: Position, range: Range) -> String {
    // Get the line at the position - use nth() instead of collecting all lines
    let line = match content.lines().nth(position.line as usize) {
        Some(l) => l,
        None => return String::new(),
    };

    // Convert UTF-16 positions to byte offsets
    let start_byte = if position.line == range.start.line {
        match utf16_to_byte_offset(line, range.start.character) {
            Some(offset) => offset,
            None => return String::new(),
        }
    } else {
        0
    };

    let cursor_byte = match utf16_to_byte_offset(line, position.character) {
        Some(offset) => offset,
        None => return String::new(),
    };

    // Safety: ensure byte offsets are within bounds
    if start_byte > line.len() || cursor_byte > line.len() || start_byte > cursor_byte {
        return String::new();
    }

    // Extract substring
    let prefix = &line[start_byte..cursor_byte];

    // Remove quotes and trim whitespace
    prefix
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

/// Builds a completion item for a package name.
///
/// Creates a properly formatted LSP CompletionItem with documentation,
/// version information, and links to repository/docs.
///
/// # Arguments
///
/// * `metadata` - Package metadata from registry search
/// * `insert_range` - LSP range where the completion should be inserted
///
/// # Returns
///
/// A complete `CompletionItem` ready to send to the LSP client.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::build_package_completion;
/// use tower_lsp_server::ls_types::Range;
///
/// # async fn example(metadata: &dyn deps_core::Metadata) {
/// let range = Range::default(); // Use actual range from context
/// let item = build_package_completion(metadata, range);
/// assert_eq!(item.label, metadata.name());
/// # }
/// ```
pub fn build_package_completion(metadata: &dyn Metadata, insert_range: Range) -> CompletionItem {
    let name = metadata.name();
    let latest = metadata.latest_version();

    // Build markdown documentation
    let mut doc_parts = vec![format!("**{}** v{}", name, latest)];

    if let Some(desc) = metadata.description() {
        doc_parts.push(String::new()); // Empty line
        let truncated = if desc.len() > 200 {
            let mut end = 200;
            while end > 0 && !desc.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &desc[..end])
        } else {
            desc.to_string()
        };
        doc_parts.push(truncated);
    }

    // Add links section if we have any links
    let mut links = Vec::new();
    if let Some(repo) = metadata.repository() {
        links.push(format!("[Repository]({})", repo));
    }
    if let Some(docs) = metadata.documentation() {
        links.push(format!("[Documentation]({})", docs));
    }

    if !links.is_empty() {
        doc_parts.push(String::new()); // Empty line
        doc_parts.push(links.join(" | "));
    }

    CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::MODULE),
        detail: Some(format!("v{}", latest)),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::Markdown,
            value: doc_parts.join("\n"),
        })),
        insert_text: Some(name.to_string()),
        text_edit: Some(CompletionTextEdit::Edit(TextEdit {
            range: insert_range,
            new_text: name.to_string(),
        })),
        sort_text: Some(name.to_string()),
        filter_text: Some(name.to_string()),
        ..Default::default()
    }
}

/// Builds a completion item for a version string.
///
/// Creates a properly formatted LSP CompletionItem with version metadata
/// including yanked status, pre-release indicators, and appropriate sorting.
///
/// # Arguments
///
/// * `version` - Version information from registry
/// * `package_name` - Name of the package this version belongs to
/// * `insert_range` - LSP range where the completion should be inserted
///
/// # Returns
///
/// A complete `CompletionItem` with proper sorting and deprecation tags.
///
/// # Sorting
///
/// Versions are sorted in this priority order:
/// 1. Stable versions (not yanked, not pre-release) - newest first
/// 2. Pre-release versions - newest first
/// 3. Yanked versions - newest first
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::build_version_completion;
/// use tower_lsp_server::ls_types::Range;
///
/// # async fn example(version: &dyn deps_core::Version) {
/// let range = Range::default();
/// let item = build_version_completion(version, "serde", range);
/// assert_eq!(item.label, version.version_string());
/// # }
/// ```
pub fn build_version_completion(
    version: &dyn Version,
    package_name: &str,
    insert_range: Range,
) -> CompletionItem {
    let version_str = version.version_string();

    // Build detail text with status indicators
    let mut detail_parts = vec![format!("v{}", version_str)];

    if version.is_yanked() {
        detail_parts.push("(yanked)".to_string());
    }

    if version.is_prerelease() {
        detail_parts.push("(pre-release)".to_string());
    }

    let detail = detail_parts.join(" ");

    // Tags for deprecated/yanked versions
    let tags = if version.is_yanked() {
        Some(vec![CompletionItemTag::DEPRECATED])
    } else {
        None
    };

    // Sort key: stable first, then pre-release, then yanked
    // Within each group, sort by version (descending)
    let sort_prefix = if version.is_yanked() {
        "3_"
    } else if version.is_prerelease() {
        "2_"
    } else {
        "1_"
    };

    let sort_text = format!("{}{}", sort_prefix, version_str);

    CompletionItem {
        label: version_str.to_string(),
        kind: Some(CompletionItemKind::VALUE),
        detail: Some(detail),
        documentation: Some(Documentation::String(format!(
            "Version {} of {}",
            version_str, package_name
        ))),
        insert_text: Some(version_str.to_string()),
        text_edit: Some(CompletionTextEdit::Edit(TextEdit {
            range: insert_range,
            new_text: version_str.to_string(),
        })),
        sort_text: Some(sort_text),
        deprecated: Some(version.is_yanked()),
        tags,
        ..Default::default()
    }
}

/// Builds a completion item for a feature flag.
///
/// Creates a properly formatted LSP CompletionItem for feature flag names.
/// Only applicable to ecosystems that support features (e.g., Cargo).
///
/// # Arguments
///
/// * `feature_name` - Name of the feature flag
/// * `package_name` - Name of the package this feature belongs to
/// * `insert_range` - LSP range where the completion should be inserted
///
/// # Returns
///
/// A complete `CompletionItem` for the feature flag.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::build_feature_completion;
/// use tower_lsp_server::ls_types::Range;
///
/// let range = Range::default();
/// let item = build_feature_completion("derive", "serde", range);
/// assert_eq!(item.label, "derive");
/// ```
pub fn build_feature_completion(
    feature_name: &str,
    package_name: &str,
    insert_range: Range,
) -> CompletionItem {
    CompletionItem {
        label: feature_name.to_string(),
        kind: Some(CompletionItemKind::PROPERTY),
        detail: Some(format!("Feature of {}", package_name)),
        documentation: None,
        insert_text: Some(feature_name.to_string()),
        text_edit: Some(CompletionTextEdit::Edit(TextEdit {
            range: insert_range,
            new_text: feature_name.to_string(),
        })),
        sort_text: Some(feature_name.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    // Mock implementations for testing

    struct MockDependency {
        name: String,
        name_range: Range,
        version_range: Option<Range>,
    }

    impl crate::ecosystem::Dependency for MockDependency {
        fn name(&self) -> &str {
            &self.name
        }

        fn name_range(&self) -> Range {
            self.name_range
        }

        fn version_requirement(&self) -> Option<&str> {
            Some("1.0")
        }

        fn version_range(&self) -> Option<Range> {
            self.version_range
        }

        fn source(&self) -> crate::parser::DependencySource {
            crate::parser::DependencySource::Registry
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockParseResult {
        dependencies: Vec<MockDependency>,
    }

    impl ParseResult for MockParseResult {
        fn dependencies(&self) -> Vec<&dyn crate::ecosystem::Dependency> {
            self.dependencies
                .iter()
                .map(|d| d as &dyn crate::ecosystem::Dependency)
                .collect()
        }

        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }

        fn uri(&self) -> &tower_lsp_server::ls_types::Uri {
            // Create a dummy URL for testing
            static URL_STR: &str = "file:///test/Cargo.toml";
            static URL: once_cell::sync::Lazy<tower_lsp_server::ls_types::Uri> =
                once_cell::sync::Lazy::new(|| URL_STR.parse().unwrap());
            &URL
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockVersion {
        version: String,
        yanked: bool,
        prerelease: bool,
    }

    impl crate::registry::Version for MockVersion {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn is_prerelease(&self) -> bool {
            self.prerelease
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockMetadata {
        name: String,
        description: Option<String>,
        repository: Option<String>,
        documentation: Option<String>,
        latest_version: String,
    }

    impl crate::registry::Metadata for MockMetadata {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> Option<&str> {
            self.description.as_deref()
        }

        fn repository(&self) -> Option<&str> {
            self.repository.as_deref()
        }

        fn documentation(&self) -> Option<&str> {
            self.documentation.as_deref()
        }

        fn latest_version(&self) -> &str {
            &self.latest_version
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // Context detection tests

    #[test]
    fn test_detect_package_name_context_at_start() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".to_string(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 5,
                    },
                },
                version_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 0,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix } => {
                assert_eq!(prefix, "");
            }
            _ => panic!("Expected PackageName context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_package_name_context_partial() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".to_string(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 5,
                    },
                },
                version_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 3,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix } => {
                assert_eq!(prefix, "ser");
            }
            _ => panic!("Expected PackageName context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_version_context() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".to_string(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 5,
                    },
                },
                version_range: Some(Range {
                    start: Position {
                        line: 0,
                        character: 9,
                    },
                    end: Position {
                        line: 0,
                        character: 14,
                    },
                }),
            }],
        };

        let content = r#"serde = "1.0.1""#;
        let position = Position {
            line: 0,
            character: 11,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::Version {
                package_name,
                prefix,
            } => {
                assert_eq!(package_name, "serde");
                assert_eq!(prefix, "1.");
            }
            _ => panic!("Expected Version context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_no_context_before_dependencies() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".to_string(),
                name_range: Range {
                    start: Position {
                        line: 5,
                        character: 0,
                    },
                    end: Position {
                        line: 5,
                        character: 5,
                    },
                },
                version_range: None,
            }],
        };

        let content = "[dependencies]\nserde";
        let position = Position {
            line: 0,
            character: 10,
        };

        let context = detect_completion_context(&parse_result, position, content);

        assert_eq!(context, CompletionContext::None);
    }

    #[test]
    fn test_detect_no_context_invalid_position() {
        let parse_result = MockParseResult {
            dependencies: vec![],
        };

        let content = "";
        let position = Position {
            line: 100,
            character: 100,
        };

        let context = detect_completion_context(&parse_result, position, content);

        assert_eq!(context, CompletionContext::None);
    }

    // Prefix extraction tests

    #[test]
    fn test_extract_prefix_at_start() {
        let content = "serde";
        let position = Position {
            line: 0,
            character: 0,
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 5,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_extract_prefix_partial() {
        let content = "serde";
        let position = Position {
            line: 0,
            character: 3,
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 5,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "ser");
    }

    #[test]
    fn test_extract_prefix_with_quotes() {
        let content = r#"serde = "1.0""#;
        let position = Position {
            line: 0,
            character: 11,
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 9,
            },
            end: Position {
                line: 0,
                character: 13,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "1.");
    }

    #[test]
    fn test_extract_prefix_empty() {
        let content = r#"serde = """#;
        let position = Position {
            line: 0,
            character: 9,
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 9,
            },
            end: Position {
                line: 0,
                character: 11,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_extract_prefix_version_with_operator() {
        let content = r#"serde = "^1.0""#;
        let position = Position {
            line: 0,
            character: 12,
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 9,
            },
            end: Position {
                line: 0,
                character: 14,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "^1.");
    }

    // CompletionItem builder tests

    #[test]
    fn test_build_package_completion_full() {
        let metadata = MockMetadata {
            name: "serde".to_string(),
            description: Some("Serialization framework".to_string()),
            repository: Some("https://github.com/serde-rs/serde".to_string()),
            documentation: Some("https://docs.rs/serde".to_string()),
            latest_version: "1.0.214".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range);

        assert_eq!(item.label, "serde");
        assert_eq!(item.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(item.detail, Some("v1.0.214".to_string()));
        assert!(matches!(
            item.documentation,
            Some(Documentation::MarkupContent(_))
        ));

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.contains("**serde** v1.0.214"));
            assert!(content.value.contains("Serialization framework"));
            assert!(content.value.contains("Repository"));
            assert!(content.value.contains("Documentation"));
        }
    }

    #[test]
    fn test_build_package_completion_minimal() {
        let metadata = MockMetadata {
            name: "test-pkg".to_string(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: "0.1.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range);

        assert_eq!(item.label, "test-pkg");
        assert_eq!(item.detail, Some("v0.1.0".to_string()));

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.contains("**test-pkg** v0.1.0"));
            assert!(!content.value.contains("Repository"));
        }
    }

    #[test]
    fn test_build_version_completion_stable() {
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let range = Range::default();
        let item = build_version_completion(&version, "serde", range);

        assert_eq!(item.label, "1.0.0");
        assert_eq!(item.kind, Some(CompletionItemKind::VALUE));
        assert_eq!(item.detail, Some("v1.0.0".to_string()));
        assert_eq!(item.deprecated, Some(false));
        assert!(item.tags.is_none());
        assert!(item.sort_text.as_ref().unwrap().starts_with("1_"));
    }

    #[test]
    fn test_build_version_completion_yanked() {
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: true,
            prerelease: false,
        };

        let range = Range::default();
        let item = build_version_completion(&version, "serde", range);

        assert_eq!(item.detail, Some("v1.0.0 (yanked)".to_string()));
        assert_eq!(item.deprecated, Some(true));
        assert_eq!(item.tags, Some(vec![CompletionItemTag::DEPRECATED]));
        assert!(item.sort_text.as_ref().unwrap().starts_with("3_"));
    }

    #[test]
    fn test_build_version_completion_prerelease() {
        let version = MockVersion {
            version: "2.0.0-alpha.1".to_string(),
            yanked: false,
            prerelease: true,
        };

        let range = Range::default();
        let item = build_version_completion(&version, "tokio", range);

        assert_eq!(
            item.detail,
            Some("v2.0.0-alpha.1 (pre-release)".to_string())
        );
        assert_eq!(item.deprecated, Some(false));
        assert!(item.tags.is_none());
        assert!(item.sort_text.as_ref().unwrap().starts_with("2_"));
    }

    #[test]
    fn test_build_version_completion_sort_order() {
        let stable = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };
        let prerelease = MockVersion {
            version: "2.0.0-beta".to_string(),
            yanked: false,
            prerelease: true,
        };
        let yanked = MockVersion {
            version: "0.9.0".to_string(),
            yanked: true,
            prerelease: false,
        };

        let range = Range::default();
        let stable_item = build_version_completion(&stable, "test", range);
        let prerelease_item = build_version_completion(&prerelease, "test", range);
        let yanked_item = build_version_completion(&yanked, "test", range);

        // Stable should sort first (1_)
        assert!(stable_item.sort_text.as_ref().unwrap().starts_with("1_"));
        // Pre-release should sort second (2_)
        assert!(
            prerelease_item
                .sort_text
                .as_ref()
                .unwrap()
                .starts_with("2_")
        );
        // Yanked should sort last (3_)
        assert!(yanked_item.sort_text.as_ref().unwrap().starts_with("3_"));
    }

    #[test]
    fn test_build_feature_completion() {
        let range = Range::default();
        let item = build_feature_completion("derive", "serde", range);

        assert_eq!(item.label, "derive");
        assert_eq!(item.kind, Some(CompletionItemKind::PROPERTY));
        assert_eq!(item.detail, Some("Feature of serde".to_string()));
        assert!(item.documentation.is_none());
        assert_eq!(item.sort_text, Some("derive".to_string()));
    }

    #[test]
    fn test_position_in_range_within() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let position = Position {
            line: 0,
            character: 7,
        };

        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_start() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let position = Position {
            line: 0,
            character: 5,
        };

        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_end() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let position = Position {
            line: 0,
            character: 10,
        };

        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_one_past_end() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        // Allow one character past end for completion
        let position = Position {
            line: 0,
            character: 11,
        };

        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_before() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let position = Position {
            line: 0,
            character: 4,
        };

        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_after() {
        let range = Range {
            start: Position {
                line: 0,
                character: 5,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let position = Position {
            line: 0,
            character: 12,
        };

        assert!(!position_in_range(position, range));
    }

    // UTF-16 to byte offset conversion tests

    #[test]
    fn test_utf16_to_byte_offset_ascii() {
        let s = "hello";
        assert_eq!(utf16_to_byte_offset(s, 0), Some(0));
        assert_eq!(utf16_to_byte_offset(s, 2), Some(2));
        assert_eq!(utf16_to_byte_offset(s, 5), Some(5));
    }

    #[test]
    fn test_utf16_to_byte_offset_multibyte() {
        // "日本語" - each character is 3 bytes, 1 UTF-16 code unit
        let s = "日本語";
        assert_eq!(utf16_to_byte_offset(s, 0), Some(0));
        assert_eq!(utf16_to_byte_offset(s, 1), Some(3));
        assert_eq!(utf16_to_byte_offset(s, 2), Some(6));
        assert_eq!(utf16_to_byte_offset(s, 3), Some(9));
    }

    #[test]
    fn test_utf16_to_byte_offset_emoji() {
        // "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
        let s = "😀test";
        assert_eq!(utf16_to_byte_offset(s, 0), Some(0));
        assert_eq!(utf16_to_byte_offset(s, 2), Some(4)); // After emoji
        assert_eq!(utf16_to_byte_offset(s, 3), Some(5)); // After 't'
    }

    #[test]
    fn test_utf16_to_byte_offset_mixed() {
        // Mix of ASCII, multi-byte, and emoji
        let s = "hello 世界 😀!";
        assert_eq!(utf16_to_byte_offset(s, 0), Some(0)); // 'h'
        assert_eq!(utf16_to_byte_offset(s, 6), Some(6)); // '世'
        assert_eq!(utf16_to_byte_offset(s, 7), Some(9)); // '界'
        assert_eq!(utf16_to_byte_offset(s, 9), Some(13)); // '😀' (2 UTF-16 units)
        assert_eq!(utf16_to_byte_offset(s, 11), Some(17)); // '!'
    }

    #[test]
    fn test_utf16_to_byte_offset_out_of_bounds() {
        let s = "hello";
        assert_eq!(utf16_to_byte_offset(s, 100), None);
    }

    #[test]
    fn test_utf16_to_byte_offset_empty() {
        let s = "";
        assert_eq!(utf16_to_byte_offset(s, 0), Some(0));
        assert_eq!(utf16_to_byte_offset(s, 1), None);
    }

    // Unicode truncation tests

    #[test]
    fn test_build_package_completion_long_description_ascii() {
        let long_desc = "a".repeat(250);
        let metadata = MockMetadata {
            name: "test-pkg".to_string(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range);

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            // Should be truncated to 200 chars + "..."
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            assert!(lines[2].len() <= 203); // 200 + "..."
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_long_description_unicode() {
        // Create description with Unicode chars at the boundary
        // Each '日' is 3 bytes, so 67 chars = 201 bytes
        let mut long_desc = String::new();
        for _ in 0..67 {
            long_desc.push('日');
        }

        let metadata = MockMetadata {
            name: "test-pkg".to_string(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range);

        // Should not panic on truncation
        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            // Truncation should happen at a char boundary
            assert!(lines[2].is_char_boundary(lines[2].len()));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_long_description_emoji() {
        // Emoji "😀" is 4 bytes each
        // 51 emoji = 204 bytes
        let long_desc = "😀".repeat(51);

        let metadata = MockMetadata {
            name: "test-pkg".to_string(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range);

        // Should not panic on truncation
        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            // Truncation should happen at a char boundary
            assert!(lines[2].is_char_boundary(lines[2].len()));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_extract_prefix_unicode_package_name() {
        // Package name with Unicode characters
        let content = "日本語-crate = \"1.0\"";
        let position = Position {
            line: 0,
            character: 3, // UTF-16 offset after "日本語"
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "日本語");
    }

    #[test]
    fn test_extract_prefix_emoji_in_content() {
        // Content with emoji (rare but should handle gracefully)
        let content = "emoji-😀-crate = \"1.0\"";
        let position = Position {
            line: 0,
            character: 8, // UTF-16 offset after "emoji-😀"
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 14,
            },
        };

        let prefix = extract_prefix(content, position, range);
        assert_eq!(prefix, "emoji-😀");
    }
}
