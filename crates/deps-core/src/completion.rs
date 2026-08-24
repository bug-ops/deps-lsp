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
//!         CompletionContext::PackageName { prefix, range } => {
//!             // Search registry and build completions, replacing `range`
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

use crate::lsp_helpers::{escape_markdown, is_safe_version_string, warn_rejected_value};
use crate::{
    FreshnessSettings, Metadata, PackageName, ParseResult, PublishTime, Version,
    format_relative_age,
};
use std::time::Duration;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, CompletionTextEdit,
    Documentation, MarkupContent, MarkupKind, Position, Range, TextEdit,
};

/// Wall-clock budget `deps-lsp`'s completion handler gives an ecosystem's
/// `generate_completions` before treating it as a timeout.
///
/// Past this, the handler skips the fallback search rather than treating a
/// fast-but-empty result as "genuinely no results"
/// (`crates/deps-lsp/src/handlers/completion.rs`).
///
/// A registry-backed completion path that retries internally on failure (e.g.
/// `deps-maven`'s `search_typed`, #274) must size its own total retry budget to
/// exceed this constant: finishing sooner with an empty/error result is
/// indistinguishable, at the call site, from a query that legitimately has no
/// matches, and triggers a wasted (and, for a struggling registry, likely to also
/// fail) fallback search rather than the handler's existing skip-on-timeout path.
pub const COMPLETION_SEARCH_TIMEOUT: Duration = Duration::from_secs(2);

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
        /// Range of the full package-name token, to be replaced by the completion's
        /// `textEdit` (not just the already-typed prefix up to the cursor).
        range: Range,
    },

    /// Cursor is within a version string.
    ///
    /// Example: `"1.0|"` or `"^2.|"` where | represents cursor position.
    Version {
        /// Package name this version belongs to.
        package_name: PackageName,
        /// Partial version typed so far (may include operators like ^, ~).
        prefix: String,
    },

    /// Cursor is within a feature array.
    ///
    /// Example: `features = ["deri|"]` where | represents cursor position.
    Feature {
        /// Package name whose features are being completed.
        package_name: PackageName,
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
        // `position_in_range` tolerates a request position one column past
        // `name_range.end` (a convenience for firing completion right after the
        // last typed character), but the manifest text immediately following the
        // name is often structurally significant (a closing quote, the space
        // before `=`, ...). Widening the returned range to reach that far would
        // consume it once the client applies the edit. So this branch requires
        // *strict* containment (`position.character <= name_range.end.character`
        // on the end line) rather than reusing that tolerance — the boundary
        // case (cursor exactly at `name_range.end`) is already covered without
        // it, and a position one further past falls through to the checks below
        // instead of matching here.
        if position_in_range(position, name_range)
            && (name_range.end.line != position.line
                || position.character <= name_range.end.character)
        {
            let prefix = extract_prefix(content, position, name_range);
            return CompletionContext::PackageName {
                prefix,
                range: name_range,
            };
        }

        // Check if position is within the version range
        if let Some(version_range) = dep.version_range()
            && position_in_range(position, version_range)
        {
            let prefix = extract_prefix(content, position, version_range);
            return CompletionContext::Version {
                package_name: dep.name().clone(),
                prefix,
            };
        }

        // Check if position is within the features array range
        if let Some(features_range) = dep.features_range()
            && position_in_range(position, features_range)
        {
            let prefix = extract_feature_prefix(content, position);
            return CompletionContext::Feature {
                package_name: dep.name().clone(),
                prefix,
            };
        }
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

/// Converts a byte offset within `s` to a UTF-16 code unit offset (LSP `Position.character`).
///
/// `byte_offset` must fall on a UTF-8 char boundary of `s` (e.g. one produced by
/// `str::find`/`rfind`/slicing, never an arbitrary user-controlled value).
///
/// # Panics
///
/// Panics if `byte_offset` is out of bounds or does not fall on a UTF-8 char boundary of `s`.
///
/// # Examples
///
/// ```
/// # use deps_core::completion::byte_to_utf16_offset;
/// // ASCII: byte offset equals UTF-16 offset
/// assert_eq!(byte_to_utf16_offset("hello", 2), 2);
///
/// // Unicode: "日本語" - each char is 3 bytes but 1 UTF-16 code unit
/// assert_eq!(byte_to_utf16_offset("日本語", 0), 0);
/// assert_eq!(byte_to_utf16_offset("日本語", 3), 1);
/// assert_eq!(byte_to_utf16_offset("日本語", 6), 2);
///
/// // Emoji: "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
/// assert_eq!(byte_to_utf16_offset("😀test", 4), 2);
/// ```
pub fn byte_to_utf16_offset(s: &str, byte_offset: usize) -> u32 {
    s[..byte_offset].encode_utf16().count() as u32
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

/// Extracts the partial feature name typed at the cursor position.
///
/// Scans backwards from the cursor on the current line to find the start of
/// the feature string being typed. Handles both inline and multi-line arrays.
///
/// Returns an empty string when the cursor is not inside a quoted string
/// (e.g. right after `[` or between `, ` and the next `"`).
///
/// # Examples
///
/// ```no_run
/// # use deps_core::completion::extract_feature_prefix;
/// # use tower_lsp_server::ls_types::Position;
/// // Cursor inside: features = ["derive", "std", "ser|"]
/// let content = r#"serde = { version = "1", features = ["derive", "std", "ser"] }"#;
/// // cursor_char = index after "ser" inside the last quoted element
/// let ser_start = content.find(r#""ser""#).unwrap() + 1; // skip opening quote
/// let pos = Position { line: 0, character: (ser_start + "ser".len()) as u32 };
/// let prefix = extract_feature_prefix(content, pos);
/// assert_eq!(prefix, "ser");
/// ```
pub fn extract_feature_prefix(content: &str, position: Position) -> String {
    let line = match content.lines().nth(position.line as usize) {
        Some(l) => l,
        None => return String::new(),
    };

    let cursor_byte = match utf16_to_byte_offset(line, position.character) {
        Some(offset) => offset.min(line.len()),
        None => return String::new(),
    };

    let before_cursor = &line[..cursor_byte];

    // Use the text after the last '[' on this line as the relevant segment
    // (handles inline arrays; for multi-line arrays there is no '[' and we
    // use the whole line up to the cursor).
    let segment_start = before_cursor.rfind('[').map_or(0, |i| i + 1);
    let segment = &before_cursor[segment_start..];

    // Count '"' characters to determine whether the cursor is inside a string.
    // An odd count means the cursor is inside an open string literal.
    let quote_count = segment.chars().filter(|&c| c == '"').count();
    if quote_count % 2 == 0 {
        return String::new();
    }

    // Find the last opening quote and return the text after it.
    match segment.rfind('"') {
        Some(pos) => segment[pos + 1..].to_string(),
        None => String::new(),
    }
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
/// `Some(CompletionItem)` ready to send to the LSP client, or `None` when
/// `metadata.name()` fails [`crate::is_safe_package_name`] — a malicious/compromised
/// registry search result must not reach the manifest as an unsanitized `label`,
/// `insert_text`, `text_edit`, `sort_text`, or `filter_text`, so the item is dropped
/// rather than built with unsafe text.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::build_package_completion;
/// use tower_lsp_server::ls_types::Range;
///
/// # async fn example(metadata: &dyn deps_core::Metadata) {
/// let range = Range::default(); // Use actual range from context
/// let item = build_package_completion(metadata, range).unwrap();
/// assert_eq!(item.label, metadata.name().as_str());
/// # }
/// ```
pub fn build_package_completion(
    metadata: &dyn Metadata,
    insert_range: Range,
) -> Option<CompletionItem> {
    let name = metadata.name();
    if !crate::is_safe_package_name(name.as_str()) {
        warn_rejected_value(
            "is_safe_package_name",
            "primary completion path package name",
            name.as_str(),
        );
        return None;
    }
    let latest = metadata.latest_version();

    // Build markdown documentation
    let header = if latest.is_empty() {
        format!("**{}**", escape_markdown(name.as_str()))
    } else {
        format!(
            "**{}** v{}",
            escape_markdown(name.as_str()),
            escape_markdown(latest)
        )
    };
    let mut doc_parts = vec![header];

    if let Some(desc) = metadata.description() {
        doc_parts.push(String::new()); // Empty line
        // Truncate the raw description first, then escape — escaping first could
        // cut a `\`-escape sequence in half at the byte boundary.
        let truncated = if desc.len() > 200 {
            let end = desc.floor_char_boundary(200);
            format!("{}...", escape_markdown(&desc[..end]))
        } else {
            escape_markdown(desc)
        };
        doc_parts.push(truncated);
    }

    // Add links section if we have any links
    let mut links = Vec::new();
    if let Some(repo) = metadata.repository() {
        links.push(format!("[Repository]({})", escape_markdown(repo)));
    }
    if let Some(docs) = metadata.documentation() {
        links.push(format!("[Documentation]({})", escape_markdown(docs)));
    }

    if !links.is_empty() {
        doc_parts.push(String::new()); // Empty line
        doc_parts.push(links.join(" | "));
    }

    Some(CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::MODULE),
        detail: if latest.is_empty() {
            None
        } else {
            Some(format!("v{}", latest))
        },
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
    })
}

/// Builds a completion item for a version string.
///
/// Creates a properly formatted LSP CompletionItem with version metadata
/// in a simplified format matching Code Actions (Cmd+.) style.
///
/// # Arguments
///
/// * `display_item` - Version display metadata with label, description, and flags
/// * `insert_range` - Optional LSP range where the completion should replace text.
///   If `None`, the completion will insert at cursor position without replacing.
/// * `now` - Current instant, injected explicitly rather than read internally, so every
///   item in the same completion response has its age computed against one consistent
///   instant instead of drifting mid-request.
///
/// # Returns
///
/// A complete `CompletionItem` with simple index-based sorting and preselect.
///
/// # Format
///
/// - Label: `"version"` or `"version (latest)"` for the latest version
/// - Detail: `"Update package_name to version"`
/// - Label details: a greyed-out relative age (e.g. `"2 hours ago"`) when
///   `display_item.published_at` is known and `freshness_enabled` is `true`; omitted
///   entirely otherwise
/// - Preselect: `true` for latest version, `false` otherwise
/// - Sort: Index-based (00000, 00001, etc.)
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::{build_version_completion, VersionDisplayItem};
/// use deps_core::PackageName;
/// use tower_lsp_server::ls_types::Range;
///
/// # async fn example(version: &dyn deps_core::Version) {
/// let now = deps_core::PublishTime::now();
///
/// // Without range - insert at cursor
/// let display_item = VersionDisplayItem::new(version, &PackageName::new("serde"), 0, true);
/// let item = build_version_completion(&display_item, None, now, true);
/// assert_eq!(item.label, display_item.label);
///
/// // With range - replace existing text
/// let range = Range::default();
/// let item = build_version_completion(&display_item, Some(range), now, true);
/// # }
/// ```
pub fn build_version_completion(
    display_item: &VersionDisplayItem,
    insert_range: Option<Range>,
    now: PublishTime,
    freshness_enabled: bool,
) -> CompletionItem {
    // Simple index-based sorting (00000, 00001, etc.)
    let sort_text = format!("{:05}", display_item.index);

    // Greyed-out label suffix; unlike `label`, it never participates in filter matching,
    // so adding it cannot change which items match a typed prefix (FR-006).
    let label_details = freshness_enabled
        .then_some(display_item.published_at)
        .flatten()
        .map(|published_at| CompletionItemLabelDetails {
            detail: Some(format!(
                "  {}",
                format_relative_age(published_at.age_secs_from(now))
            )),
            description: None,
        });

    CompletionItem {
        label: display_item.label.clone(),
        kind: Some(CompletionItemKind::VALUE),
        detail: Some(display_item.description.clone()),
        documentation: None,
        insert_text: Some(display_item.version.clone()),
        text_edit: insert_range.map(|range| {
            CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: display_item.version.clone(),
            })
        }),
        sort_text: Some(sort_text),
        preselect: Some(display_item.is_latest),
        label_details,
        ..Default::default()
    }
}

/// Display metadata for a single version in LSP responses.
///
/// Captures common formatting logic shared between completion items and code actions.
#[derive(Debug, Clone)]
pub struct VersionDisplayItem {
    /// Raw version string (e.g., "1.0.0")
    pub version: String,
    /// Display label with "(latest)" suffix for first item
    pub label: String,
    /// Action description (e.g., "Update serde to 1.0.0")
    pub description: String,
    /// Zero-based index for sorting
    pub index: usize,
    /// True if this is the latest non-yanked version
    pub is_latest: bool,
    /// When this version was published, if the registry exposes it.
    ///
    /// `None` for ecosystems without publish metadata (see
    /// [`Version::published_at`]) — callers must degrade gracefully rather than
    /// rendering a placeholder age.
    pub published_at: Option<PublishTime>,
}

impl VersionDisplayItem {
    /// Creates a display item from version metadata.
    pub fn new(
        version: &dyn Version,
        package_name: &PackageName,
        index: usize,
        is_latest: bool,
    ) -> Self {
        let version_str = version.version_string();
        let label = if is_latest {
            format!("{} (latest)", version_str)
        } else {
            version_str.to_string()
        };
        let description = format!("Update {} to {}", package_name, version_str);

        Self {
            version: version_str.to_string(),
            label,
            description,
            index,
            is_latest,
            published_at: version.published_at(),
        }
    }
}

/// Filters and formats versions for LSP display.
///
/// Returns up to 5 non-yanked versions with display metadata. An
/// advisory-deprecated version (e.g. an abandoned Composer package, a
/// deprecated npm package) is not excluded here — only a hard yank is
/// (#347): excluding advisory-only flags would leave a deprecated-but-
/// installable package with zero version completions.
pub fn prepare_version_display_items<V: AsRef<dyn Version>>(
    versions: &[V],
    package_name: &PackageName,
) -> Vec<VersionDisplayItem> {
    versions
        .iter()
        .map(|v| v.as_ref())
        .filter(|v| !v.removal_status().blocks_resolution())
        .take(MAX_COMPLETION_VERSIONS)
        .enumerate()
        .map(|(index, version)| VersionDisplayItem::new(version, package_name, index, index == 0))
        .collect()
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
/// * `insert_range` - LSP range where the completion should be inserted, or `None` to omit
///   `textEdit` and let the client insert at cursor position via `insertText`
///
/// # Returns
///
/// A complete `CompletionItem` for the feature flag.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::build_feature_completion;
///
/// let item = build_feature_completion("derive", &deps_core::PackageName::new("serde"), None);
/// assert_eq!(item.label, "derive");
/// ```
pub fn build_feature_completion(
    feature_name: &str,
    package_name: &PackageName,
    insert_range: Option<Range>,
) -> CompletionItem {
    CompletionItem {
        label: feature_name.to_string(),
        kind: Some(CompletionItemKind::PROPERTY),
        detail: Some(format!("Feature of {}", package_name)),
        documentation: None,
        insert_text: Some(feature_name.to_string()),
        text_edit: insert_range.map(|range| {
            CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: feature_name.to_string(),
            })
        }),
        sort_text: Some(feature_name.to_string()),
        ..Default::default()
    }
}

/// Maximum number of version completions to show (matches Code Actions limit).
const MAX_COMPLETION_VERSIONS: usize = 5;

/// Checks whether `prefix` has an acceptable length (2 to 200 characters, inclusive) for
/// triggering a package-name completion search.
///
/// Length is measured in Unicode scalar values (`chars().count()`), not bytes, so a
/// multi-byte prefix (e.g. CJK) is bounded by how many characters the user typed rather
/// than how many bytes those characters happen to occupy.
///
/// # Examples
///
/// ```
/// # use deps_core::completion::is_valid_completion_prefix_len;
/// assert!(!is_valid_completion_prefix_len("a")); // 1 char, too short
/// assert!(is_valid_completion_prefix_len("ab")); // 2 chars, accepted
///
/// // "日" is 1 char / 3 bytes: rejected despite being >= 2 bytes.
/// assert!(!is_valid_completion_prefix_len("日"));
/// // "日本" is 2 chars / 6 bytes: accepted.
/// assert!(is_valid_completion_prefix_len("日本"));
/// ```
#[must_use]
pub fn is_valid_completion_prefix_len(prefix: &str) -> bool {
    (2..=200).contains(&prefix.chars().count())
}

/// Generic package name completion using any `Registry` implementation.
///
/// Searches the registry for packages matching `prefix` and returns up to `limit`
/// completion items, each with its `textEdit` set to replace `insert_range`. Returns
/// empty vec if `prefix` is shorter than 2 characters or longer than 200 characters.
/// A result whose name fails [`build_package_completion`]'s [`crate::is_safe_package_name`]
/// gate is silently dropped rather than surfaced as an error, matching the fallback-search
/// completion builder's convention (`create_package_completion_item` in `deps-lsp`).
pub async fn complete_package_names_generic(
    registry: &dyn crate::Registry,
    prefix: &str,
    limit: usize,
    insert_range: Range,
) -> Vec<CompletionItem> {
    if !is_valid_completion_prefix_len(prefix) {
        return vec![];
    }

    let results = match registry.search(prefix, limit).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Registry search failed for '{}': {}", prefix, e);
            return vec![];
        }
    };

    results
        .into_iter()
        .filter_map(|metadata| build_package_completion(metadata.as_ref(), insert_range))
        .collect()
}

/// Generic version completion logic used by all ecosystems.
///
/// Filters versions by prefix (stripping ecosystem-specific operators),
/// hides yanked/deprecated versions, returns up to 5 completion items.
///
/// # Arguments
///
/// * `registry` - Package registry to fetch versions from
/// * `package_name` - Name of the package
/// * `prefix` - Partial version string typed by user (may include operators)
/// * `operator_chars` - Ecosystem-specific version operators to strip (e.g., `&['^', '~']`)
///
/// # Returns
///
/// Up to 5 completion items for non-yanked versions, filtered by prefix.
/// If no versions match the prefix, returns up to 5 non-yanked versions.
/// The first item (latest version) is marked with "(latest)" suffix and preselected.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::complete_versions_generic;
/// use deps_core::PackageName;
///
/// # async fn example(registry: &dyn deps_core::Registry) {
/// let freshness = deps_core::FreshnessSettings::default();
///
/// // Cargo: strip ^, ~, =, <, > operators
/// let items = complete_versions_generic(
///     registry,
///     &PackageName::new("serde"),
///     "^1.0",
///     &['^', '~', '=', '<', '>'],
///     freshness,
/// ).await;
///
/// // Go: no operators to strip
/// let items = complete_versions_generic(
///     registry,
///     &PackageName::new("github.com/gin-gonic/gin"),
///     "v1.9",
///     &[],
///     freshness,
/// ).await;
/// # }
/// ```
pub async fn complete_versions_generic(
    registry: &dyn crate::Registry,
    package_name: &PackageName,
    prefix: &str,
    operator_chars: &[char],
    freshness: FreshnessSettings,
) -> Vec<CompletionItem> {
    let versions = match registry.get_versions_with(package_name, freshness).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to fetch versions for '{}': {}", package_name, e);
            return vec![];
        }
    };

    let clean_prefix = prefix.trim_start_matches(operator_chars).trim();

    // Filter versions by prefix first
    let filtered_versions: Vec<_> = versions
        .iter()
        .filter(|v| v.version_string().starts_with(clean_prefix))
        .collect();

    // Use filtered or all versions, prepare_version_display_items will handle yanked filtering
    let display_items = if filtered_versions.is_empty() {
        prepare_version_display_items(&versions, package_name)
    } else {
        prepare_version_display_items(&filtered_versions, package_name)
    };

    // Don't provide text_edit range - let LSP client insert at cursor position
    let now = PublishTime::now();
    display_items
        .iter()
        // A registry-reported version is exactly as untrusted as the one fed into
        // `format_version_replacing`/`format_version_for_text_edit` (see
        // `is_safe_version_string`'s doc comment) — a completion item's
        // `insert_text`/`text_edit` is a manifest-write sink too, and fires on
        // ordinary typing rather than a quickfix click.
        .filter(|item| {
            let safe = is_safe_version_string(&item.version);
            if !safe {
                warn_rejected_value(
                    "is_safe_version_string",
                    "version completion item",
                    &item.version,
                );
            }
            safe
        })
        .map(|item| build_version_completion(item, None, now, freshness.enabled))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    fn pkg(s: &str) -> PackageName {
        PackageName::new(s)
    }

    // Mock implementations for testing

    struct MockDependency {
        name: crate::PackageName,
        name_range: Range,
        version_range: Option<Range>,
        features_range: Option<Range>,
    }

    impl crate::ecosystem::Dependency for MockDependency {
        fn name(&self) -> &crate::PackageName {
            &self.name
        }

        fn name_range(&self) -> Range {
            self.name_range
        }

        fn version_requirement(&self) -> Option<&crate::VersionReq> {
            static VERSION_REQ: std::sync::LazyLock<crate::VersionReq> =
                std::sync::LazyLock::new(|| crate::VersionReq::new("1.0"));
            Some(&VERSION_REQ)
        }

        fn version_range(&self) -> Option<Range> {
            self.version_range
        }

        fn features_range(&self) -> Option<Range> {
            self.features_range
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
            static URL: std::sync::LazyLock<tower_lsp_server::ls_types::Uri> =
                std::sync::LazyLock::new(|| "file:///test/Cargo.toml".parse().unwrap());
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

        fn removal_status(&self) -> crate::RemovalStatus {
            crate::RemovalStatus::from_yanked(self.yanked)
        }

        fn is_prerelease(&self) -> bool {
            self.prerelease
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A [`MockVersion`] variant that reports a `published_at`, used only by the
    /// freshness-specific tests below — kept separate so the many pre-existing
    /// `MockVersion` literals do not need a new field added to every call site.
    struct MockVersionWithAge {
        version: String,
        published_at: Option<PublishTime>,
    }

    impl crate::registry::Version for MockVersionWithAge {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn published_at(&self) -> Option<PublishTime> {
            self.published_at
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Clone)]
    struct MockMetadata {
        name: crate::PackageName,
        description: Option<String>,
        repository: Option<String>,
        documentation: Option<String>,
        latest_version: String,
    }

    impl crate::registry::Metadata for MockMetadata {
        fn name(&self) -> &crate::PackageName {
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

    struct MockRegistry {
        versions: Vec<MockVersion>,
    }

    impl crate::Registry for MockRegistry {
        fn get_versions<'a>(
            &'a self,
            _package_name: &'a crate::PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            let versions: Vec<Box<dyn crate::Version>> = self
                .versions
                .iter()
                .map(|v| {
                    Box::new(MockVersion {
                        version: v.version.clone(),
                        yanked: v.yanked,
                        prerelease: v.prerelease,
                    }) as Box<dyn crate::Version>
                })
                .collect();
            Box::pin(async move { Ok(versions) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a crate::PackageName,
            _req: &'a crate::VersionReq,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(None) })
        }

        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Registry stub whose `search` returns preconfigured metadata, used to verify
    /// [`complete_package_names_generic`] threads its `insert_range` into every
    /// returned item's `text_edit` instead of defaulting to a placeholder range.
    struct MockSearchRegistry {
        results: Vec<MockMetadata>,
    }

    impl crate::Registry for MockSearchRegistry {
        fn get_versions<'a>(
            &'a self,
            _package_name: &'a crate::PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a crate::PackageName,
            _req: &'a crate::VersionReq,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Option<Box<dyn crate::Version>>>>
        {
            Box::pin(async move { Ok(None) })
        }

        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
        {
            let results: Vec<Box<dyn crate::Metadata>> = self
                .results
                .iter()
                .cloned()
                .map(|m| Box::new(m) as Box<dyn crate::Metadata>)
                .collect();
            Box::pin(async move { Ok(results) })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_uses_insert_range() {
        let registry = MockSearchRegistry {
            results: vec![MockMetadata {
                name: pkg("serde"),
                description: None,
                repository: None,
                documentation: None,
                latest_version: "1.0.0".to_string(),
            }],
        };

        let insert_range = Range {
            start: Position {
                line: 3,
                character: 4,
            },
            end: Position {
                line: 3,
                character: 7,
            },
        };

        let items = complete_package_names_generic(&registry, "ser", 5, insert_range).await;

        assert_eq!(items.len(), 1);
        assert_ne!(insert_range, Range::default());
        match &items[0].text_edit {
            Some(CompletionTextEdit::Edit(edit)) => {
                assert_eq!(edit.range, insert_range);
                assert_eq!(edit.new_text, "serde");
            }
            other => panic!("Expected a textEdit::Edit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_short_prefix_empty() {
        let registry = MockSearchRegistry {
            results: vec![MockMetadata {
                name: pkg("serde"),
                description: None,
                repository: None,
                documentation: None,
                latest_version: "1.0.0".to_string(),
            }],
        };

        let items = complete_package_names_generic(&registry, "s", 5, Range::default()).await;
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_drops_unsafe_names() {
        // A registry search can return a mix of safe and malicious/compromised
        // results (e.g. a Gradle Groovy breakout name); only the safe ones should
        // survive into the returned completion list.
        let registry = MockSearchRegistry {
            results: vec![
                MockMetadata {
                    name: pkg("serde"),
                    description: None,
                    repository: None,
                    documentation: None,
                    latest_version: "1.0.0".to_string(),
                },
                MockMetadata {
                    name: pkg("guava'); System.exit(1); //"),
                    description: None,
                    repository: None,
                    documentation: None,
                    latest_version: "1.0.0".to_string(),
                },
            ],
        };

        let items = complete_package_names_generic(&registry, "gua", 5, Range::default()).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "serde");
    }

    #[test]
    fn test_is_valid_completion_prefix_len_ascii_short_rejected() {
        assert!(!is_valid_completion_prefix_len("a"));
    }

    #[test]
    fn test_is_valid_completion_prefix_len_one_char_cjk_rejected() {
        // "日" is 1 char but 3 bytes — a byte-length guard would wrongly accept it.
        assert!(!is_valid_completion_prefix_len("日"));
    }

    #[test]
    fn test_is_valid_completion_prefix_len_two_char_cjk_accepted() {
        // "日本" is 2 chars but 6 bytes — must be accepted under char-count semantics.
        assert!(is_valid_completion_prefix_len("日本"));
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_one_char_cjk_prefix_empty() {
        // "日" is 1 char but 3 bytes — a byte-length guard would wrongly accept it.
        let registry = MockSearchRegistry {
            results: vec![MockMetadata {
                name: pkg("serde"),
                description: None,
                repository: None,
                documentation: None,
                latest_version: "1.0.0".to_string(),
            }],
        };

        let items = complete_package_names_generic(&registry, "日", 5, Range::default()).await;
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_two_char_cjk_prefix_accepted() {
        // "日本" is 2 chars / 6 bytes — must pass the guard and reach the registry search.
        let registry = MockSearchRegistry {
            results: vec![MockMetadata {
                name: pkg("serde"),
                description: None,
                repository: None,
                documentation: None,
                latest_version: "1.0.0".to_string(),
            }],
        };

        let items = complete_package_names_generic(&registry, "日本", 5, Range::default()).await;
        assert_eq!(items.len(), 1);
    }

    // Context detection tests

    #[test]
    fn test_detect_package_name_context_at_start() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".into(),
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
                features_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 0,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "");
                assert_eq!(
                    range,
                    Range {
                        start: Position {
                            line: 0,
                            character: 0
                        },
                        end: Position {
                            line: 0,
                            character: 5
                        },
                    }
                );
            }
            _ => panic!("Expected PackageName context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_package_name_context_partial() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".into(),
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
                features_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 3,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "ser");
                assert_eq!(
                    range,
                    Range {
                        start: Position {
                            line: 0,
                            character: 0
                        },
                        end: Position {
                            line: 0,
                            character: 5
                        },
                    }
                );
            }
            _ => panic!("Expected PackageName context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_package_name_context_one_past_end_does_not_widen_range() {
        // `position_in_range` tolerates a request one column past `name_range.end`,
        // but the text right after a name is often structurally significant (a
        // closing quote, the space before `=`, ...) — widening the range to reach
        // a position past the name would consume that character once a client
        // applies the edit, corrupting the manifest. So a one-past-end position
        // must NOT produce a PackageName context (there is nothing else on this
        // line for it to match either, so it falls through to `None`).
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".into(),
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
                features_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 6,
        };

        let context = detect_completion_context(&parse_result, position, content);

        assert_eq!(context, CompletionContext::None);
    }

    #[test]
    fn test_detect_package_name_context_exactly_at_end_matches_unwidened_range() {
        // The cursor sitting exactly at `name_range.end` (right after the last
        // typed character, no tolerance needed) must still fire PackageName with
        // the name's own unwidened range.
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".into(),
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
                features_range: None,
            }],
        };

        let content = "serde";
        let position = Position {
            line: 0,
            character: 5,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "serde");
                assert_eq!(
                    range,
                    Range {
                        start: Position {
                            line: 0,
                            character: 0
                        },
                        end: Position {
                            line: 0,
                            character: 5
                        },
                    }
                );
            }
            _ => panic!("Expected PackageName context, got {:?}", context),
        }
    }

    #[test]
    fn test_detect_package_name_context_fires_for_ecosystem_supplied_partial_name() {
        // #310 (deps-deno): a scheme-prefixed but structurally incomplete specifier value
        // ("jsr:", "jsr:@", "jsr:@std", "jsr:@std/") has no complete name to parse, yet
        // completion must still fire while the user is mid-keystroke. This is deliberately
        // NOT solved by adding jsr:/npm:-specific logic here — `detect_completion_context`
        // stays ecosystem-agnostic. Instead, `deps-deno`'s parser (mirroring `deps-npm`,
        // which always builds a `Dependency` from a `dependencies` object key regardless of
        // scope completeness) supplies a `Dependency` whose `name`/`name_range` cover the
        // partial text directly; the existing range-containment check below requires no
        // change to handle it. This test documents and locks in that consistency.
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "jsr:@std/".into(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 9,
                    },
                },
                version_range: None,
                features_range: None,
            }],
        };

        let content = "jsr:@std/";
        let position = Position {
            line: 0,
            character: 9,
        };

        let context = detect_completion_context(&parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "jsr:@std/");
                assert_eq!(range, parse_result.dependencies[0].name_range);
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_version_context() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "serde".into(),
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
                features_range: None,
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
                name: "serde".into(),
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
                features_range: None,
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
            name: "serde".to_string().into(),
            description: Some("Serialization framework".to_string()),
            repository: Some("https://github.com/serde-rs/serde".to_string()),
            documentation: Some("https://docs.rs/serde".to_string()),
            latest_version: "1.0.214".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        assert_eq!(item.label, "serde");
        assert_eq!(item.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(item.detail, Some("v1.0.214".to_string()));
        assert!(matches!(
            item.documentation,
            Some(Documentation::MarkupContent(_))
        ));

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.contains("**serde** v1\\.0\\.214"));
            assert!(content.value.contains("Serialization framework"));
            assert!(content.value.contains("Repository"));
            assert!(content.value.contains("Documentation"));
        }
    }

    #[test]
    fn test_build_package_completion_minimal() {
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: "0.1.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        assert_eq!(item.label, "test-pkg");
        assert_eq!(item.detail, Some("v0.1.0".to_string()));

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.contains("**test\\-pkg** v0\\.1\\.0"));
            assert!(!content.value.contains("Repository"));
        }
    }

    #[test]
    fn test_build_package_completion_empty_latest_version() {
        let metadata = MockMetadata {
            name: "swift-nio".to_string().into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: String::new(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        assert_eq!(item.detail, None);

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.contains("**swift\\-nio**"));
            assert!(!content.value.trim_end().ends_with('v'));
        }
    }

    #[test]
    fn test_build_package_completion_escapes_description_markdown() {
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some("Fast *bold* _italic_ [link](evil) `code`".to_string()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(!content.value.contains("*bold*"));
            assert!(!content.value.contains("_italic_"));
            assert!(!content.value.contains("[link](evil)"));
            assert!(content.value.contains(r"\*bold\*"));
            assert!(content.value.contains(r"\[link\]\(evil\)"));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_escapes_repository_link_breakout() {
        // A malicious repository URL that attempts to close the `[Repository](...)`
        // link early and splice in a new, attacker-controlled markdown link.
        let malicious_repo = "https://legit.example)[Click here](https://evil.example";
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: None,
            repository: Some(malicious_repo.to_string()),
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(!content.value.contains(")[Click here]("));
            assert!(content.value.contains(r"\)\[Click here\]\("));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_escapes_documentation_link_breakout() {
        let malicious_docs = "https://legit.example)[Click here](https://evil.example";
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: None,
            repository: None,
            documentation: Some(malicious_docs.to_string()),
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(!content.value.contains(")[Click here]("));
            assert!(content.value.contains(r"\)\[Click here\]\("));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_truncate_then_escape_no_dangling_backslash() {
        // A special character sitting right at the 200-char truncation boundary:
        // truncating BEFORE escaping (correct order) keeps the escape sequence
        // whole; escaping before truncating would risk cutting between the
        // backslash and the character it escapes, leaving a dangling `\`.
        let mut desc = "a".repeat(199);
        desc.push('*');
        desc.push_str(&"b".repeat(50));

        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some(desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            let desc_line = lines[2];
            assert!(desc_line.ends_with(r"\*..."), "got: {desc_line}");
            assert!(
                !desc_line.ends_with(r"\..."),
                "dangling backslash: {desc_line}"
            );
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_escapes_malicious_version_link_breakout() {
        // A crafted latest-version string attempting to close the leading bold span
        // and splice in a live, attacker-controlled markdown link — same injection
        // class as description/repository/documentation. `latest_version` isn't
        // gated by `is_safe_package_name` (that only guards `name`), so it must
        // still be escaped in the rendered documentation.
        let malicious_latest = "1.0.0)[click](https://evil.example";
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: malicious_latest.to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(!content.value.contains(")[click]("));
            assert!(
                content
                    .value
                    .contains(r"1\.0\.0\)\[click\]\(https\:\/\/evil\.example")
            );
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_rejects_unsafe_name() {
        // A crafted package name attempting to close the leading bold span and
        // splice in a live, attacker-controlled markdown link — reachable simply
        // by typing a package-name prefix (no malicious manifest required). Such
        // a name fails `is_safe_package_name` (structural characters like `[`,
        // `]`, `(`, `)`, `*`, and space are not in its allowlist), so the whole
        // completion item must be dropped rather than built with unsafe text.
        let malicious_name = "a** [Official Download](https://evil.example) **b";
        let metadata = MockMetadata {
            name: malicious_name.to_string().into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        assert!(build_package_completion(&metadata, range).is_none());
    }

    #[test]
    fn test_build_package_completion_benign_repository_url_round_trips() {
        // Backslash-escaping ASCII punctuation is visually inert on render (CommonMark
        // strips the backslash for the literal character), so a normal URL must still
        // render as the same, unmangled link once those escapes are stripped.
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: None,
            repository: Some("https://github.com/owner/repo".to_string()),
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let unescaped: String = content.value.chars().filter(|&c| c != '\\').collect();
            assert!(unescaped.contains("[Repository](https://github.com/owner/repo)"));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_escapes_html_in_description() {
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some("<img src=x onerror=alert(1)>".to_string()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(!content.value.contains("<img src=x onerror=alert(1)>"));
            assert!(
                content
                    .value
                    .contains(r"\<img src\=x onerror\=alert\(1\)\>")
            );
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_empty_description() {
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some(String::new()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            assert!(content.value.starts_with(r"**test\-pkg** v1\.0\.0"));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_truncate_snaps_multibyte_boundary() {
        // A 3-byte character straddling the 200-byte truncation boundary: truncation
        // must snap back to a valid char boundary rather than panicking mid-codepoint,
        // proving `floor_char_boundary` is exercised as a genuine non-identity op
        // (unlike an all-ASCII description, where every byte offset is already a
        // char boundary).
        let mut desc = "a".repeat(199);
        desc.push('日'); // 3 bytes, occupies byte offsets 199..202 — straddles byte 200
        desc.push('*');
        desc.push_str(&"b".repeat(50));

        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some(desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            let desc_line = lines[2];
            assert!(!desc_line.contains('日'));
            assert!(desc_line.ends_with("..."));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_version_completion_stable() {
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let now = PublishTime::now();
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, false);
        let item = build_version_completion(&display_item, None, now, true);

        assert_eq!(item.label, "1.0.0");
        assert_eq!(item.kind, Some(CompletionItemKind::VALUE));
        assert_eq!(item.detail, Some("Update serde to 1.0.0".to_string()));
        assert_eq!(item.documentation, None);
        assert_eq!(item.preselect, Some(false));
        assert_eq!(item.sort_text, Some("00000".to_string()));
        assert_eq!(item.text_edit, None); // No text_edit when range is None
    }

    #[test]
    fn test_build_version_completion_latest() {
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let now = PublishTime::now();
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);
        let item = build_version_completion(&display_item, None, now, true);

        assert_eq!(item.label, "1.0.0 (latest)");
        assert_eq!(item.kind, Some(CompletionItemKind::VALUE));
        assert_eq!(item.detail, Some("Update serde to 1.0.0".to_string()));
        assert_eq!(item.documentation, None);
        assert_eq!(item.preselect, Some(true));
        assert_eq!(item.sort_text, Some("00000".to_string()));
        assert_eq!(item.text_edit, None); // No text_edit when range is None
    }

    #[test]
    fn test_build_version_completion_not_latest() {
        let version = MockVersion {
            version: "0.9.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let now = PublishTime::now();
        let display_item = VersionDisplayItem::new(&version, &pkg("tokio"), 1, false);
        let item = build_version_completion(&display_item, None, now, true);

        assert_eq!(item.label, "0.9.0");
        assert_eq!(item.detail, Some("Update tokio to 0.9.0".to_string()));
        assert_eq!(item.documentation, None);
        assert_eq!(item.preselect, Some(false));
        assert_eq!(item.sort_text, Some("00001".to_string()));
        assert_eq!(item.text_edit, None); // No text_edit when range is None
    }

    #[test]
    fn test_build_version_completion_sort_order() {
        let v1 = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };
        let v2 = MockVersion {
            version: "0.9.0".to_string(),
            yanked: false,
            prerelease: false,
        };
        let v3 = MockVersion {
            version: "0.8.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let display_item1 = VersionDisplayItem::new(&v1, &pkg("test"), 0, true);
        let display_item2 = VersionDisplayItem::new(&v2, &pkg("test"), 1, false);
        let display_item3 = VersionDisplayItem::new(&v3, &pkg("test"), 2, false);
        let now = PublishTime::now();
        let item1 = build_version_completion(&display_item1, None, now, true);
        let item2 = build_version_completion(&display_item2, None, now, true);
        let item3 = build_version_completion(&display_item3, None, now, true);

        // Simple index-based sorting
        assert_eq!(item1.sort_text.as_ref().unwrap(), "00000");
        assert_eq!(item2.sort_text.as_ref().unwrap(), "00001");
        assert_eq!(item3.sort_text.as_ref().unwrap(), "00002");

        // First item should be preselected
        assert_eq!(item1.preselect, Some(true));
        assert_eq!(item2.preselect, Some(false));
        assert_eq!(item3.preselect, Some(false));
    }

    #[test]
    fn test_version_completion_semantic_ordering() {
        let versions = [
            MockVersion {
                version: "0.14.0".to_string(),
                yanked: false,
                prerelease: false,
            },
            MockVersion {
                version: "0.8.0".to_string(),
                yanked: false,
                prerelease: false,
            },
            MockVersion {
                version: "0.2.0".to_string(),
                yanked: false,
                prerelease: false,
            },
        ];

        let now = PublishTime::now();
        let items: Vec<_> = versions
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                let display_item = VersionDisplayItem::new(v, &pkg("test"), idx, idx == 0);
                build_version_completion(&display_item, None, now, true)
            })
            .collect();

        assert_eq!(items[0].sort_text.as_ref().unwrap(), "00000");
        assert_eq!(items[1].sort_text.as_ref().unwrap(), "00001");
        assert_eq!(items[2].sort_text.as_ref().unwrap(), "00002");

        let mut sorted_items = items;
        sorted_items.sort_by(|a, b| {
            a.sort_text
                .as_ref()
                .unwrap()
                .cmp(b.sort_text.as_ref().unwrap())
        });

        assert_eq!(sorted_items[0].label, "0.14.0 (latest)");
        assert_eq!(sorted_items[1].label, "0.8.0");
        assert_eq!(sorted_items[2].label, "0.2.0");
    }

    #[test]
    fn test_version_completion_index_ordering() {
        let versions = ["1.20.0", "1.9.0", "1.2.0", "0.99.0", "0.50.0"];

        let now = PublishTime::now();
        let items: Vec<_> = versions
            .iter()
            .enumerate()
            .map(|(idx, ver)| {
                let v = MockVersion {
                    version: ver.to_string(),
                    yanked: false,
                    prerelease: false,
                };
                let display_item = VersionDisplayItem::new(&v, &pkg("test"), idx, idx == 0);
                build_version_completion(&display_item, None, now, true)
            })
            .collect();

        assert_eq!(items[0].sort_text.as_ref().unwrap(), "00000");
        assert_eq!(items[1].sort_text.as_ref().unwrap(), "00001");
        assert_eq!(items[2].sort_text.as_ref().unwrap(), "00002");
        assert_eq!(items[3].sort_text.as_ref().unwrap(), "00003");
        assert_eq!(items[4].sort_text.as_ref().unwrap(), "00004");

        let mut sorted_items = items;
        sorted_items.sort_by(|a, b| {
            a.sort_text
                .as_ref()
                .unwrap()
                .cmp(b.sort_text.as_ref().unwrap())
        });

        assert_eq!(sorted_items[0].label, "1.20.0 (latest)");
        assert_eq!(sorted_items[1].label, "1.9.0");
        assert_eq!(sorted_items[2].label, "1.2.0");
        assert_eq!(sorted_items[3].label, "0.99.0");
        assert_eq!(sorted_items[4].label, "0.50.0");
    }

    #[test]
    fn test_version_display_item_latest() {
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        assert_eq!(item.version, "1.0.0");
        assert_eq!(item.label, "1.0.0 (latest)");
        assert_eq!(item.description, "Update serde to 1.0.0");
        assert_eq!(item.index, 0);
        assert!(item.is_latest);
    }

    #[test]
    fn test_version_display_item_not_latest() {
        let version = MockVersion {
            version: "0.9.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let item = VersionDisplayItem::new(&version, &pkg("tokio"), 1, false);

        assert_eq!(item.version, "0.9.0");
        assert_eq!(item.label, "0.9.0");
        assert_eq!(item.description, "Update tokio to 0.9.0");
        assert_eq!(item.index, 1);
        assert!(!item.is_latest);
    }

    #[test]
    fn test_prepare_version_display_items_filters_yanked() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".to_string(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".to_string(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.8.0".to_string(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"));

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].version, "1.0.0");
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert!(items[0].is_latest);
        assert_eq!(items[1].version, "0.8.0");
        assert_eq!(items[1].label, "0.8.0");
        assert!(!items[1].is_latest);
    }

    #[test]
    fn test_prepare_version_display_items_limits_to_5() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = (0..10)
            .map(|i| {
                std::sync::Arc::new(MockVersion {
                    version: format!("1.0.{}", i),
                    yanked: false,
                    prerelease: false,
                }) as std::sync::Arc<dyn crate::Version>
            })
            .collect();

        let items = prepare_version_display_items(&versions, &pkg("test"));

        assert_eq!(items.len(), 5);
        assert_eq!(items[0].version, "1.0.0");
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[4].version, "1.0.4");
        assert_eq!(items[4].label, "1.0.4");
    }

    #[test]
    fn test_prepare_version_display_items_empty() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![];

        let items = prepare_version_display_items(&versions, &pkg("test"));

        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_prepare_version_display_items_all_yanked() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".to_string(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".to_string(),
                yanked: true,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"));

        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_build_feature_completion() {
        let item = build_feature_completion("derive", &pkg("serde"), None);

        assert_eq!(item.label, "derive");
        assert_eq!(item.kind, Some(CompletionItemKind::PROPERTY));
        assert_eq!(item.detail, Some("Feature of serde".to_string()));
        assert!(item.documentation.is_none());
        assert!(item.text_edit.is_none());
        assert_eq!(item.sort_text, Some("derive".to_string()));
    }

    #[test]
    fn test_build_feature_completion_with_range() {
        let range = Range::default();
        let item = build_feature_completion("derive", &pkg("serde"), Some(range));

        assert_eq!(item.label, "derive");
        assert!(item.text_edit.is_some());
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

    // Byte to UTF-16 offset conversion tests

    #[test]
    fn test_byte_to_utf16_offset_ascii() {
        let s = "hello";
        assert_eq!(byte_to_utf16_offset(s, 0), 0);
        assert_eq!(byte_to_utf16_offset(s, 2), 2);
        assert_eq!(byte_to_utf16_offset(s, 5), 5);
    }

    #[test]
    fn test_byte_to_utf16_offset_multibyte() {
        // "日本語" - each character is 3 bytes, 1 UTF-16 code unit
        let s = "日本語";
        assert_eq!(byte_to_utf16_offset(s, 0), 0);
        assert_eq!(byte_to_utf16_offset(s, 3), 1);
        assert_eq!(byte_to_utf16_offset(s, 6), 2);
        assert_eq!(byte_to_utf16_offset(s, 9), 3);
    }

    #[test]
    fn test_byte_to_utf16_offset_emoji() {
        // "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
        let s = "😀test";
        assert_eq!(byte_to_utf16_offset(s, 0), 0);
        assert_eq!(byte_to_utf16_offset(s, 4), 2); // After emoji
        assert_eq!(byte_to_utf16_offset(s, 5), 3); // After 't'
    }

    #[test]
    fn test_byte_to_utf16_offset_mixed() {
        // Mix of ASCII, multi-byte, and emoji
        let s = "hello 世界 😀!";
        assert_eq!(byte_to_utf16_offset(s, 0), 0); // 'h'
        assert_eq!(byte_to_utf16_offset(s, 6), 6); // '世'
        assert_eq!(byte_to_utf16_offset(s, 9), 7); // '界'
        assert_eq!(byte_to_utf16_offset(s, 13), 9); // '😀' (2 UTF-16 units)
        assert_eq!(byte_to_utf16_offset(s, 17), 11); // '!'
    }

    #[test]
    fn test_byte_to_utf16_offset_empty() {
        let s = "";
        assert_eq!(byte_to_utf16_offset(s, 0), 0);
    }

    // Unicode truncation tests

    #[test]
    fn test_build_package_completion_long_description_ascii() {
        let long_desc = "a".repeat(250);
        let metadata = MockMetadata {
            name: "test-pkg".to_string().into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

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
            name: "test-pkg".to_string().into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

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
            name: "test-pkg".to_string().into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".to_string(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

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

    // Generic version completion tests

    #[tokio::test]
    async fn test_complete_versions_generic_operator_stripping() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.1.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        // Test with Cargo-style operators (^, ~, =, <, >)
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "^1.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        // Should return versions starting with "1.0" (after stripping ^)
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.0.1");

        // Test with tilde operator
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "~1.1",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "1.1.0 (latest)");

        // Test with equals operator
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "=2.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "2.0.0 (latest)");

        // Test with no operator (should work the same)
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "1.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.0.1");
    }

    #[tokio::test]
    async fn test_complete_versions_generic_fallback_when_no_prefix_match() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.1.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.1.0".to_string(),
                    yanked: true, // Yanked version
                    prerelease: false,
                },
            ],
        };

        // Test with prefix that doesn't match any version
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "3.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        // Should fallback to showing all non-yanked versions
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.1.0");
        assert_eq!(items[2].label, "2.0.0");

        // Yanked version should not be included in fallback
        assert!(!items.iter().any(|item| item.label == "2.1.0"));

        // Test with empty prefix (should show all non-yanked)
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.1.0");
        assert_eq!(items[2].label, "2.0.0");
    }

    #[tokio::test]
    async fn test_complete_versions_generic_filters_yanked_in_prefix_match() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1".to_string(),
                    yanked: true, // Yanked version
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.2".to_string(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        // Test that yanked versions are filtered out even when prefix matches
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "1.0",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        // Should only include non-yanked versions
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.0.2");

        // Yanked version 1.0.1 should not be included
        assert!(!items.iter().any(|item| item.label == "1.0.1"));
    }

    #[tokio::test]
    async fn test_complete_versions_generic_filters_unsafe_version_string() {
        // Regression (critic S3): `build_version_completion` writes `insert_text`/
        // `text_edit.new_text` straight from a registry-reported version, the same
        // untrusted data source as the REFACTOR code-action loop. An unsafe
        // registry version must never surface as a completion item, while an
        // ordinary safe version alongside it must still be offered.
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1\", \"evil\": \"true".to_string(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "1.0",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert!(
            !items.iter().any(|item| item.label.contains("evil")),
            "an unsafe version string must never be offered as a completion item: {items:?}"
        );
        assert!(
            items.iter().any(|item| item.label.starts_with("1.0.0")),
            "a safe version must still be offered: {items:?}"
        );
    }

    #[tokio::test]
    async fn test_complete_versions_generic_limit_5() {
        // Create more than 5 versions
        let versions: Vec<_> = (0..10)
            .map(|i| MockVersion {
                version: format!("1.0.{}", i),
                yanked: false,
                prerelease: false,
            })
            .collect();

        let registry = MockRegistry { versions };

        // Test that we only return 5 items
        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "1.0",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 5);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[4].label, "1.0.4");
    }

    #[tokio::test]
    async fn test_complete_versions_generic_go_no_operators() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "v1.9.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "v1.9.1".to_string(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "v1.10.0".to_string(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        // Go has no operators, so empty array
        let items = complete_versions_generic(
            &registry,
            &pkg("github.com/gin-gonic/gin"),
            "v1.9",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "v1.9.0 (latest)");
        assert_eq!(items[1].label, "v1.9.1");
    }

    // --- Feature completion detection tests ---

    fn make_dep_with_features_range(
        name: &str,
        name_range: Range,
        features_range: Range,
    ) -> MockDependency {
        MockDependency {
            name: name.into(),
            name_range,
            version_range: None,
            features_range: Some(features_range),
        }
    }

    #[test]
    fn test_detect_feature_context_inline() {
        // serde = { version = "1", features = ["derive", "std"] }
        // col:                                 36              52
        let features_range = Range {
            start: Position {
                line: 0,
                character: 36,
            },
            end: Position {
                line: 0,
                character: 52,
            },
        };
        let dep = make_dep_with_features_range(
            "serde",
            Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
            features_range,
        );
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let content = r#"serde = { version = "1", features = ["derive", "std"] }"#;

        // Content: ...["derive",...  => '"' is at char 37, 'd'=38, 'e'=39, 'r'=40
        // Cursor after 'r' (insertion point) = character 41
        let position = Position {
            line: 0,
            character: 41,
        };
        let context = detect_completion_context(&parse_result, position, content);
        assert!(
            matches!(context, CompletionContext::Feature { ref package_name, ref prefix }
                if package_name == "serde" && prefix == "der"),
            "Expected Feature context with prefix 'der', got {context:?}"
        );
    }

    #[test]
    fn test_detect_feature_context_empty_prefix() {
        // Cursor right after opening quote: features = ["|"]
        let features_range = Range {
            start: Position {
                line: 0,
                character: 11,
            },
            end: Position {
                line: 0,
                character: 15,
            },
        };
        let dep = make_dep_with_features_range(
            "tokio",
            Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
            features_range,
        );
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let content = r#"features = [""]"#;
        // Cursor between the two quotes: position character 13
        let position = Position {
            line: 0,
            character: 13,
        };
        let context = detect_completion_context(&parse_result, position, content);
        assert!(
            matches!(context, CompletionContext::Feature { ref package_name, ref prefix }
                if package_name == "tokio" && prefix.is_empty()),
            "Expected Feature context with empty prefix, got {context:?}"
        );
    }

    #[test]
    fn test_detect_feature_context_second_item() {
        // features = ["full", "rt-|"]
        let features_range = Range {
            start: Position {
                line: 0,
                character: 11,
            },
            end: Position {
                line: 0,
                character: 28,
            },
        };
        let dep = make_dep_with_features_range(
            "tokio",
            Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
            features_range,
        );
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let content = r#"features = ["full", "rt-"]"#;
        // Cursor after "rt-": character 24
        let position = Position {
            line: 0,
            character: 24,
        };
        let context = detect_completion_context(&parse_result, position, content);
        assert!(
            matches!(context, CompletionContext::Feature { ref package_name, ref prefix }
                if package_name == "tokio" && prefix == "rt-"),
            "Expected Feature context with prefix 'rt-', got {context:?}"
        );
    }

    #[test]
    fn test_detect_no_feature_context_outside_range() {
        let features_range = Range {
            start: Position {
                line: 2,
                character: 11,
            },
            end: Position {
                line: 2,
                character: 20,
            },
        };
        let dep = make_dep_with_features_range(
            "serde",
            Range {
                start: Position {
                    line: 2,
                    character: 0,
                },
                end: Position {
                    line: 2,
                    character: 5,
                },
            },
            features_range,
        );
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Cursor is on line 0, not line 2 where features are
        let content = "[package]\nname = \"test\"\nfeatures = [\"full\"]";
        let position = Position {
            line: 0,
            character: 5,
        };
        let context = detect_completion_context(&parse_result, position, content);
        assert_eq!(context, CompletionContext::None);
    }

    #[test]
    fn test_extract_feature_prefix_basic() {
        let content = r#"serde = { features = ["derive"] }"#;
        // '"' is at char 22, 'd'=23, 'e'=24, 'r'=25, 'i'=26
        // Cursor after 'i' (insertion point) = character 27
        let position = Position {
            line: 0,
            character: 27,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "deri");
    }

    #[test]
    fn test_extract_feature_prefix_empty() {
        let content = r#"features = [""]"#;
        // Cursor between opening and closing quote at character 13
        let position = Position {
            line: 0,
            character: 13,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_extract_feature_prefix_multiline() {
        let content = "features = [\n    \"rt-multi-thread\",\n    \"mac\"\n]";
        // Line 2: `    "mac"` — '"' at char 4, 'm'=5, 'a'=6, 'c'=7
        // Cursor after 'c' (insertion point) = character 8
        let position = Position {
            line: 2,
            character: 8,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "mac");
    }

    #[test]
    fn test_extract_feature_prefix_no_quote() {
        let content = "features = [\n    \n]";
        // Cursor on blank line inside array
        let position = Position {
            line: 1,
            character: 4,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_extract_feature_prefix_between_items_no_quote() {
        // Cursor between a comma and the next opening quote: ["full", |]
        // After "full" the quote count is 2 (even) → not inside a string → empty prefix
        let content = r#"features = ["full", ]"#;
        // Cursor after ", " at character 19 (before `]`)
        let position = Position {
            line: 0,
            character: 19,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "");
    }

    #[test]
    fn test_extract_feature_prefix_cursor_after_opening_bracket() {
        // Cursor right after `[`, before any quote: features = [|]
        let content = "features = []";
        let position = Position {
            line: 0,
            character: 12,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, "");
    }

    // --- Release-freshness signal (issue #145): VersionDisplayItem.published_at,
    // build_version_completion's label_details ---

    #[test]
    fn test_version_display_item_captures_published_at() {
        let version = MockVersionWithAge {
            version: "1.0.0".to_string(),
            published_at: Some(PublishTime::from_unix_secs(1_000)),
        };

        let item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        assert_eq!(item.published_at, Some(PublishTime::from_unix_secs(1_000)));
    }

    #[test]
    fn test_version_display_item_published_at_none_when_unavailable() {
        // Plain `MockVersion` doesn't override `published_at`, so it falls back to
        // the `Version` trait's default `None` — the ecosystems-without-metadata case.
        let version = MockVersion {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
        };

        let item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        assert_eq!(item.published_at, None);
    }

    #[test]
    fn test_build_version_completion_label_details_present_when_published_at_known() {
        let now = PublishTime::from_unix_secs(10_000);
        let published_two_hours_ago = PublishTime::from_unix_secs(10_000 - 2 * 3600);
        let version = MockVersionWithAge {
            version: "1.2.3".to_string(),
            published_at: Some(published_two_hours_ago),
        };
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        let item = build_version_completion(&display_item, None, now, true);

        let details = item
            .label_details
            .expect("label_details must be set when published_at is known");
        assert_eq!(details.detail, Some("  2 hours ago".to_string()));
        assert_eq!(details.description, None);
    }

    #[test]
    fn test_build_version_completion_label_details_absent_when_freshness_disabled() {
        // `freshness.enabled: false` must suppress label_details even when
        // published_at is known — the escape hatch must be all-or-nothing.
        let now = PublishTime::from_unix_secs(10_000);
        let published_two_hours_ago = PublishTime::from_unix_secs(10_000 - 2 * 3600);
        let version = MockVersionWithAge {
            version: "1.2.3".to_string(),
            published_at: Some(published_two_hours_ago),
        };
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        let item = build_version_completion(&display_item, None, now, false);

        assert!(item.label_details.is_none());
    }

    #[test]
    fn test_build_version_completion_label_details_absent_when_published_at_unknown() {
        let version = MockVersion {
            version: "1.2.3".to_string(),
            yanked: false,
            prerelease: false,
        };
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        let item = build_version_completion(&display_item, None, PublishTime::now(), true);

        assert!(item.label_details.is_none());
    }

    /// FR-006 regression guard: when freshness data is absent (the pre-feature and
    /// 5-deferred-ecosystem case), `label`, `sort_text`, `preselect`, and the item
    /// count/order out of `prepare_version_display_items` must stay byte-identical to
    /// what this suite asserted before `published_at`/`label_details` existed.
    #[test]
    fn test_build_version_completion_byte_identical_output_without_freshness_data() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".to_string(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".to_string(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.8.0".to_string(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let display_items = prepare_version_display_items(&versions, &pkg("test"));
        assert_eq!(display_items.len(), 2, "yanked filtering must be unchanged");

        let now = PublishTime::now();
        let items: Vec<_> = display_items
            .iter()
            .map(|item| build_version_completion(item, None, now, true))
            .collect();

        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[0].sort_text, Some("00000".to_string()));
        assert_eq!(items[0].preselect, Some(true));
        assert_eq!(items[0].label_details, None);

        assert_eq!(items[1].label, "0.8.0");
        assert_eq!(items[1].sort_text, Some("00001".to_string()));
        assert_eq!(items[1].preselect, Some(false));
        assert_eq!(items[1].label_details, None);
    }
}
