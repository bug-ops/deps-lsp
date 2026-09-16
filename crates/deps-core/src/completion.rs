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
//! `dyn Version`, `dyn Metadata`) to work generically across ecosystems. See
//! [`crate::Ecosystem::generate_completions`]'s trait doc for the canonical example of how
//! an ecosystem plugs into this module's [`CompletionRequest`]/[`CompletionContext`]
//! machinery via [`crate::Ecosystem::complete_package_name`],
//! [`crate::Ecosystem::complete_version`], [`crate::Ecosystem::complete_feature`].

use crate::lsp_helpers::{escape_markdown, is_safe_version_string, warn_rejected_value};
use crate::{
    ConcreteVersion, FreshnessSettings, Metadata, PackageName, ParseResult, PublishTime, Version,
    format_relative_age,
};
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, CompletionTextEdit,
    Documentation, MarkupContent, MarkupKind, Position, Range, TextEdit,
};

/// Re-exported from [`crate::lsp_helpers::COMPLETION_SEARCH_TIMEOUT`] — moved there (issue
/// #1083) since a registry-backed completion path's own retry-budget constant (e.g.
/// `deps-maven`'s `RECENT_FAILURE_TTL`) needs it independent of the `lsp-responses` feature
/// this module is gated behind.
pub use crate::lsp_helpers::COMPLETION_SEARCH_TIMEOUT;

/// Result of [`Ecosystem::generate_completions`](crate::Ecosystem::generate_completions).
///
/// Carries the completion items produced for this specific call, plus whether they are
/// a possibly-truncated view of a larger candidate set that the LSP client should
/// re-query for as the user keeps typing.
///
/// Supersedes the ecosystem-wide `Ecosystem::completions_are_incomplete()` flag (#419):
/// `is_incomplete` is computed per call from the actual completion context and result
/// set, so only the specific context that is genuinely truncated (e.g. PyPI's unranked,
/// index-backed package-name search) is flagged — a version completion, a comment
/// position, or any other exhaustive context in the same manifest correctly reports
/// `is_incomplete: false` instead of inheriting the worst case across the whole
/// ecosystem (#427).
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Completions {
    /// The completion items for this call.
    pub items: Vec<CompletionItem>,
    /// Whether `items` is a possibly-truncated view of a larger candidate set.
    pub is_incomplete: bool,
}

impl Completions {
    /// Constructs a `Completions` from its items, with [`Self::is_incomplete`] left `false` —
    /// chain [`Self::with_incomplete`] to mark it truncated.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::completion::Completions;
    ///
    /// let completions = Completions::new(vec![]).with_incomplete(true);
    /// assert!(completions.is_incomplete);
    /// ```
    #[must_use]
    pub fn new(items: Vec<CompletionItem>) -> Self {
        Self {
            items,
            is_incomplete: false,
        }
    }

    /// Overrides [`Self::is_incomplete`]. See [`Self::new`].
    #[must_use]
    pub const fn with_incomplete(mut self, is_incomplete: bool) -> Self {
        self.is_incomplete = is_incomplete;
        self
    }
}

impl From<Vec<CompletionItem>> for Completions {
    /// Wraps an always-exhaustive result set, i.e. `is_incomplete: false`.
    fn from(items: Vec<CompletionItem>) -> Self {
        Self::new(items)
    }
}

/// Bundles the request-scoped inputs [`crate::Ecosystem`]'s completion hooks need.
///
/// Covers `complete_package_name`/`complete_version`/`complete_feature`, so a future input
/// costs one field here instead of a signature break across every ecosystem crate — mirrors
/// [`crate::lsp_helpers::VersionData`]'s identical rationale for the hover/diagnostics
/// family.
///
/// `#[non_exhaustive]`: a struct literal only works inside this crate — construct via
/// [`Self::new`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct CompletionRequest<'a> {
    /// The manifest's parsed dependencies — used by a hook that re-derives its own
    /// dependency lookup instead of trusting the context's bare `package_name`/`prefix`
    /// (e.g. cursor-position-based version resolution, issue #593).
    pub parse_result: &'a dyn ParseResult,
    /// Cursor position the completion request fired at.
    pub position: Position,
    /// Freshness display settings, threaded through to
    /// [`complete_versions_generic`] and friends.
    pub freshness: FreshnessSettings,
}

impl<'a> CompletionRequest<'a> {
    /// Constructs a `CompletionRequest` from its fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every ecosystem crate goes through this constructor instead.
    #[must_use]
    pub const fn new(
        parse_result: &'a dyn ParseResult,
        position: Position,
        freshness: FreshnessSettings,
    ) -> Self {
        Self {
            parse_result,
            position,
            freshness,
        }
    }
}

/// Context for completion request based on cursor position.
///
/// This enum represents what type of completion is appropriate at the
/// current cursor location within a manifest file.
///
/// `#[non_exhaustive]`: still blocks out-of-crate construction and forces a wildcard on the
/// one remaining downstream match (`deps-deno`'s test, a binding catch-all rather than a
/// contentful arm). The exhaustive dispatch match itself lives in
/// [`crate::Ecosystem::generate_completions`]'s default implementation, inside this crate —
/// so `#[non_exhaustive]` does not apply there, and adding a variant is a compile error in
/// that one place instead of a silent no-op downstream (issue #793). An ecosystem that
/// overrides `generate_completions` wholesale (`deps-maven`, `deps-gradle`) opts out of that
/// guarantee and takes the obligation on itself.
#[non_exhaustive]
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
        // #905 S1: a synthetic name_range is not a real position — accepting a completion here
        // would insert text at a bogus range, so skip the dependency entirely.
        if dep.name_range_is_synthetic() {
            continue;
        }

        let name_range: Range = dep.name_range().into();
        // Unlike `position_in_range`'s one-past-end tolerance, this needs *strict* containment:
        // the text right after a name is often structurally significant (closing quote, space
        // before `=`), and widening the range to reach it would consume that char on edit.
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

        if let Some(version_range) = dep.version_range().map(Into::into)
            && position_in_range(position, version_range)
        {
            // #919: `version_range` can span a non-literal token (Maven `${property}`, Gradle
            // `$var`, a YAML alias) — accepting a completion there would splice version text
            // into that reference instead of a literal, so withhold the `Version` context.
            if crate::lsp_helpers::dependency_version_range_is_literal(
                dep,
                content,
                version_range.into(),
            ) {
                let prefix = extract_prefix(content, position, version_range);
                return CompletionContext::Version {
                    package_name: dep.name().clone(),
                    prefix,
                };
            }
        }

        if let Some(features_range) = dep.features_range().map(Into::into)
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
    if position.line < range.start.line {
        return false;
    }

    if position.line == range.start.line && position.character < range.start.character {
        return false;
    }

    if position.line > range.end.line {
        return false;
    }

    if position.line == range.end.line && position.character > range.end.character + 1 {
        return false;
    }

    true
}

/// Converts a byte offset within `s` to a UTF-16 code unit offset (LSP `Position.character`).
///
/// Re-exported from [`crate::lsp_helpers::byte_to_utf16_offset`] — see
/// [`utf16_to_byte_offset`]'s doc for why.
pub use crate::lsp_helpers::byte_to_utf16_offset;
/// Converts UTF-16 offset to byte offset in a string.
///
/// Re-exported from [`crate::lsp_helpers::utf16_to_byte_offset`] — moved there (issue #1083)
/// since `deps-core`'s own [`crate::lsp_helpers::LineOffsetTable`] needs it independent of the
/// `lsp-responses` feature this module is gated behind.
pub use crate::lsp_helpers::utf16_to_byte_offset;

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
#[expect(
    clippy::string_slice,
    reason = "start_byte/cursor_byte come from utf16_to_byte_offset (char_indices-based) and \
              are bounds/ordering-checked above, so both are verified char boundaries"
)]
pub fn extract_prefix(content: &str, position: Position, range: Range) -> String {
    let line = match content.lines().nth(position.line as usize) {
        Some(l) => l,
        None => return String::new(),
    };

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

    if start_byte > line.len() || cursor_byte > line.len() || start_byte > cursor_byte {
        return String::new();
    }

    let prefix = &line[start_byte..cursor_byte];

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
/// (e.g. right after `[` or between `, ` and the next `"`), using
/// [`crate::fallback_completion::open_quoted_tail`]'s escape-aware quote-parity check
/// (#733) rather than a naive `"` count, which would miscount an escaped `\"`.
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
#[expect(
    clippy::string_slice,
    reason = "cursor_byte comes from utf16_to_byte_offset (char_indices-based) and is clamped \
              to line.len(); segment_start is an ASCII-char ([) index"
)]
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

    // Text after the last '[' (inline arrays); multi-line arrays have none, so use the whole line.
    let segment_start = before_cursor.rfind('[').map_or(0, |i| i + 1);
    let segment = &before_cursor[segment_start..];

    // Escape-aware quote-parity check (#733): a naive `filter(|&c| c == '"').count()`
    // miscounts a `\"` escape inside a feature name, desyncing the open/closed check
    // from the string's real state.
    crate::fallback_completion::open_quoted_tail(segment)
        .unwrap_or_default()
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
#[expect(
    clippy::string_slice,
    reason = "end is floor_char_boundary-clamped just below before slicing desc"
)]
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
    let latest = metadata.latest_version().as_str();

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
        doc_parts.push(String::new());
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

    let mut links = Vec::new();
    if let Some(repo) = metadata.repository() {
        links.push(format!("[Repository]({})", escape_markdown(repo)));
    }
    if let Some(docs) = metadata.documentation() {
        links.push(format!("[Documentation]({})", escape_markdown(docs)));
    }

    if !links.is_empty() {
        doc_parts.push(String::new());
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
        insert_text: Some(display_item.version.to_string()),
        text_edit: insert_range.map(|range| {
            CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: display_item.version.to_string(),
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct VersionDisplayItem {
    /// Raw version string (e.g., "1.0.0")
    pub version: ConcreteVersion,
    /// Display label with "(latest)" suffix for the registry-selected latest version —
    /// not necessarily the first display item (#956).
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
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead. Already
    /// covers every field, so no `with_*` setters are needed on top of it.
    #[must_use]
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
            version: version_str.clone(),
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
///
/// `latest_idx` is the index, within `versions` (before this function's own
/// yanked-filter/cap), that the caller's [`crate::Registry::select_latest_matching`] picked —
/// the exact same call hover's `live_latest_idx` delegates to (#313, `lsp_helpers/hover.rs`).
/// It is threaded in rather than re-derived here with a generic [`Version::is_stable`] scan:
/// an ecosystem whose `select_latest_matching` applies a ranking preference beyond plain
/// resolvability (e.g. npm's #338 NFR-002 preferring a non-deprecated version over a newer
/// deprecated one, or a fallback pick for an all-prerelease list) must get that identical
/// preference reflected here too, rather than completion/code-actions independently picking a
/// different "latest" than hover and disagreeing about what a click actually writes (#952).
/// Matched by the pre-filter index (not a version string) so two entries sharing a version
/// string can never both — or wrongly — receive the marker (mirrors `hover.rs`'s own
/// index-based match for the same reason).
///
/// If `latest_idx` survives the yanked filter but falls outside the raw-order
/// `MAX_COMPLETION_VERSIONS`-entry display cap (e.g. 6+ consecutive pre-release/flagged
/// versions ahead of the first stable release), it is not silently dropped from the returned
/// list: the first `MAX_COMPLETION_VERSIONS - 1` surviving entries are kept in raw order and
/// the picked entry is appended as the final one, still tagged/preselected (#956) — matching
/// hover's own *uncapped* `**Latest**:` header, which always resolves to this same pick
/// regardless of any display-window size. Hover's own *capped* "Recent versions" list
/// (`HOVER_RECENT_VERSIONS`, `lsp_helpers/hover.rs`'s `push_recent_versions_hover_section`)
/// carries the identical bump-in fix (#961) — a pre-existing instance of this same defect
/// class in a different surface, resolved as a follow-up to this function's own fix rather
/// than left standing. Finding the picked entry only scans as far past the cap as it sits,
/// rather than materializing every surviving version up front — this stays `O(cap)` in the
/// common case (no pick, or a pick already within the cap), which matters for a registry
/// with thousands of versions (e.g. an npm packument) queried on every completion keystroke.
///
/// # Examples
///
/// ```
/// use deps_core::completion::prepare_version_display_items;
/// use deps_core::{PackageName, Version};
/// use std::any::Any;
/// use std::sync::Arc;
///
/// struct SimpleVersion(deps_core::ConcreteVersion);
///
/// impl Version for SimpleVersion {
///     fn version_string(&self) -> &deps_core::ConcreteVersion {
///         &self.0
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// // 5 pre-releases sort ahead of the picked stable version in raw fetch order, pushing it
/// // to post-filter index 5 — one past the `MAX_COMPLETION_VERSIONS` (5) display cap.
/// let versions: Vec<Arc<dyn Version>> = vec![
///     Arc::new(SimpleVersion("2.0.0-rc5".into())),
///     Arc::new(SimpleVersion("2.0.0-rc4".into())),
///     Arc::new(SimpleVersion("2.0.0-rc3".into())),
///     Arc::new(SimpleVersion("2.0.0-rc2".into())),
///     Arc::new(SimpleVersion("2.0.0-rc1".into())),
///     Arc::new(SimpleVersion("1.0.0".into())),
/// ];
///
/// // The registry resolved index 5 ("1.0.0") as latest.
/// let items = prepare_version_display_items(&versions, &PackageName::new("demo"), Some(5));
///
/// assert_eq!(items.len(), 5, "still capped at MAX_COMPLETION_VERSIONS");
/// assert_eq!(items[4].version, "1.0.0");
/// assert!(items[4].is_latest, "the pick is bumped in rather than dropped");
/// ```
pub fn prepare_version_display_items<V: AsRef<dyn Version>>(
    versions: &[V],
    package_name: &PackageName,
    latest_idx: Option<usize>,
) -> Vec<VersionDisplayItem> {
    let mut survivors = versions
        .iter()
        .map(AsRef::as_ref)
        .enumerate()
        .filter(|(_, v)| !v.removal_status().blocks_resolution());

    let mut head: Vec<(usize, &dyn Version)> =
        survivors.by_ref().take(MAX_COMPLETION_VERSIONS).collect();

    // The pick fell outside the raw-order display cap: bump it in as the window's final
    // entry instead of silently dropping it, if it survived the yanked filter (#956).
    if let Some(idx) = latest_idx
        && !head.iter().any(|(i, _)| *i == idx)
        && let Some(pick) = survivors.find(|(i, _)| *i == idx)
    {
        head.truncate(MAX_COMPLETION_VERSIONS - 1);
        head.push(pick);
    }

    head.into_iter()
        .enumerate()
        .map(|(display_index, (orig_index, version))| {
            VersionDisplayItem::new(
                version,
                package_name,
                display_index,
                Some(orig_index) == latest_idx,
            )
        })
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
/// Whichever item the registry resolves as latest, via
/// [`Registry::select_latest_matching`](crate::Registry::select_latest_matching) — not
/// necessarily the first — is marked with "(latest)" suffix and preselected; a pre-release or
/// deprecated release sorting above it in fetch order is offered unlabeled instead (#952).
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
    complete_versions_generic_from(
        registry,
        package_name,
        &crate::parser::DependencySource::Registry,
        prefix,
        operator_chars,
        freshness,
    )
    .await
}

/// Like [`complete_versions_generic`], but resolves through [`crate::Registry::get_versions_from`].
///
/// Routes on `source`, so a registry that routes a dependency's fetch across more than one
/// underlying index (e.g. a per-instance-host `AlternateRegistry`, GitLab CI's
/// `deps-gitlab-ci`) completes against the correct index instead of falling back to a
/// source-unaware default.
///
/// [`complete_versions_generic`] delegates to this with
/// [`crate::parser::DependencySource::Registry`] — behavior-preserving for every one of its
/// 18 existing call sites, all of which pass a plain registry-resolved dependency: this is
/// exactly the source [`crate::Registry::get_versions_from`]'s default implementation
/// forwards to [`crate::Registry::get_versions_with`] for, so nothing observable changes for
/// them.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::complete_versions_generic_from;
/// use deps_core::parser::DependencySource;
/// use deps_core::PackageName;
///
/// # async fn example(registry: &dyn deps_core::Registry) {
/// let freshness = deps_core::FreshnessSettings::default();
/// let items = complete_versions_generic_from(
///     registry,
///     &PackageName::new("gitlab.com/org/proj"),
///     &DependencySource::Registry,
///     "1.",
///     &[],
///     freshness,
/// ).await;
/// # }
/// ```
pub async fn complete_versions_generic_from(
    registry: &dyn crate::Registry,
    package_name: &PackageName,
    source: &crate::parser::DependencySource,
    prefix: &str,
    operator_chars: &[char],
    freshness: FreshnessSettings,
) -> Vec<CompletionItem> {
    let versions = match registry
        .get_versions_from(package_name, source, freshness)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to fetch versions for '{}': {}", package_name, e);
            return vec![];
        }
    };

    let clean_prefix = prefix.trim_start_matches(operator_chars).trim();
    let has_prefix_match = versions
        .iter()
        .any(|v| v.version_string().as_str().starts_with(clean_prefix));

    // The same registry-delegated pick `prepare_version_display_items` needs (see its doc
    // comment) — computed over whichever slice is actually about to be displayed (the
    // prefix-narrowed subset, when non-empty, same as the fallback-to-all-versions case
    // right below), so a prefix match still gets the correct stable/non-deprecated entry
    // tagged within itself rather than unconditionally the first one shown.
    let wildcard_req = crate::existence_wildcard_req();
    let display_items = if has_prefix_match {
        let filtered_versions: Vec<Box<dyn Version>> = versions
            .into_iter()
            .filter(|v| v.version_string().as_str().starts_with(clean_prefix))
            .collect();
        let latest_idx = registry.select_latest_matching(&filtered_versions, &wildcard_req);
        prepare_version_display_items(&filtered_versions, package_name, latest_idx)
    } else {
        let latest_idx = registry.select_latest_matching(&versions, &wildcard_req);
        prepare_version_display_items(&versions, package_name, latest_idx)
    };

    // Don't provide text_edit range - let LSP client insert at cursor position
    let now = PublishTime::now();
    display_items
        .iter()
        // A registry-reported version is untrusted the same way `format_version_for_text_edit`'s
        // input is (see `is_safe_version_string`'s doc comment) — this sink fires on ordinary
        // typing rather than a quickfix click.
        .filter(|item| {
            let safe = is_safe_version_string(item.version.as_str());
            if !safe {
                warn_rejected_value(
                    "is_safe_version_string",
                    "version completion item",
                    item.version.as_str(),
                );
            }
            safe
        })
        .map(|item| build_version_completion(item, None, now, freshness.enabled))
        .collect()
}

/// Version completion resolved by **cursor position**, not by package name (issue #593).
///
/// Finds the dependency in `parse_result` whose `version_range` contains `position` — the
/// same containment check [`detect_completion_context`] used to decide this is a `Version`
/// context in the first place — then completes through [`complete_versions_generic_from`]
/// against that dependency's own [`crate::Dependency::source`]. Unlike a name join (the old
/// per-ecosystem `resolve_completion_source` pattern this replaces), two dependencies sharing
/// one [`PackageName`] but resolving to different sources never collide: the cursor position
/// unambiguously identifies which occurrence the user is editing, so each completes against
/// its own source independently instead of both offering nothing.
///
/// Deliberately reuses this module's own (lenient) `position_in_range` rather than
/// [`crate::lsp_helpers::position_in_range`] (the two differ at the one-past-`range.end`
/// boundary) — using a different predicate here than the one [`detect_completion_context`]
/// used to decide `position` is even inside a `Version` context would let this lookup silently
/// disagree with its own caller and return empty at a boundary the caller already committed to.
///
/// # Source-resolvability gate
///
/// [`crate::Registry::get_versions_from`]'s default/documented contract does not itself fail
/// closed for a source an ecosystem's registry does not specifically route (see that method's
/// docs) — several concrete `Registry` implementations forward an unrecognized source (e.g.
/// `Git`, `Path`, an unresolved `CustomRegistry`) to their default public-registry client
/// rather than erroring. Gating on `formatter`'s
/// [`SourcePolicy::can_resolve_source`](crate::lsp_helpers::SourcePolicy::can_resolve_source)
/// first — the same check [`crate::lsp_helpers::generate_hover`] and diagnostics/code-actions
/// already use — is what keeps that permissive default from leaking a private/non-registry
/// dependency's name to a public registry on every keystroke.
///
/// # Examples
///
/// ```no_run
/// use deps_core::completion::complete_versions_at_position;
/// use deps_core::lsp_helpers::SourcePolicy;
/// use tower_lsp_server::ls_types::Position;
///
/// struct DefaultFormatter;
/// impl SourcePolicy for DefaultFormatter {}
///
/// # async fn example(registry: &dyn deps_core::Registry, parse_result: &dyn deps_core::ParseResult) {
/// let freshness = deps_core::FreshnessSettings::default();
/// let position = Position { line: 3, character: 12 };
/// let items = complete_versions_at_position(
///     registry,
///     &DefaultFormatter,
///     parse_result,
///     position,
///     "1.",
///     &['^', '~'],
///     freshness,
/// ).await;
/// # }
/// ```
pub async fn complete_versions_at_position(
    registry: &dyn crate::Registry,
    formatter: &dyn crate::lsp_helpers::SourcePolicy,
    parse_result: &dyn ParseResult,
    position: Position,
    prefix: &str,
    operator_chars: &[char],
    freshness: FreshnessSettings,
) -> Vec<CompletionItem> {
    let Some(dep) = parse_result.dependencies().into_iter().find(|d| {
        d.version_range()
            .is_some_and(|r| position_in_range(position, r.into()))
    }) else {
        return vec![];
    };

    let source = dep.source();
    if !formatter.can_resolve_source(&source) {
        return vec![];
    }

    complete_versions_generic_from(
        registry,
        dep.name(),
        &source,
        prefix,
        operator_chars,
        freshness,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::assert_matches;

    fn pkg(s: &str) -> PackageName {
        PackageName::new(s)
    }

    // Mock implementations for testing

    struct MockDependency {
        name: crate::PackageName,
        name_range: crate::position::Range,
        version_range: Option<crate::position::Range>,
        features_range: Option<crate::position::Range>,
    }

    impl crate::ecosystem::Dependency for MockDependency {
        fn name(&self) -> &crate::PackageName {
            &self.name
        }

        fn name_range(&self) -> crate::position::Range {
            self.name_range
        }

        fn version_requirement(&self) -> Option<&crate::VersionReq> {
            static VERSION_REQ: std::sync::LazyLock<crate::VersionReq> =
                std::sync::LazyLock::new(|| crate::VersionReq::new("1.0"));
            Some(&VERSION_REQ)
        }

        fn version_range(&self) -> Option<crate::position::Range> {
            self.version_range
        }

        fn features_range(&self) -> Option<crate::position::Range> {
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

        fn uri(&self) -> &url::Url {
            static URL: std::sync::LazyLock<url::Url> =
                std::sync::LazyLock::new(|| "file:///test/Cargo.toml".parse().unwrap());
            &URL
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockVersion {
        version: ConcreteVersion,
        yanked: bool,
        prerelease: bool,
    }

    impl crate::registry::Version for MockVersion {
        fn version_string(&self) -> &ConcreteVersion {
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
        version: ConcreteVersion,
        published_at: Option<PublishTime>,
    }

    impl crate::registry::Version for MockVersionWithAge {
        fn version_string(&self) -> &ConcreteVersion {
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
        latest_version: ConcreteVersion,
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

        fn latest_version(&self) -> &ConcreteVersion {
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

        // Mirrors the real 3-rung existence ladder every ecosystem's own `select_latest_matching`
        // delegates to (`crate::select_latest_for_existence`), rather than the trait default
        // (always `None`) — needed so this mock exercises the same registry-delegated `(latest)`
        // pick `prepare_version_display_items` now requires (#952), not an unconditionally
        // absent one that would leave every version untagged regardless of pre-release status.
        fn select_latest_matching(
            &self,
            versions: &[Box<dyn crate::Version>],
            _req: &crate::VersionReq,
        ) -> Option<usize> {
            crate::select_latest_for_existence(versions, |v| v.as_ref())
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
                latest_version: "1.0.0".into(),
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
                latest_version: "1.0.0".into(),
            }],
        };

        let items = complete_package_names_generic(&registry, "s", 5, Range::default()).await;
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_generic_drops_unsafe_names() {
        // A malicious/compromised result (e.g. a Gradle Groovy breakout name) must not
        // survive into the returned completion list.
        let registry = MockSearchRegistry {
            results: vec![
                MockMetadata {
                    name: pkg("serde"),
                    description: None,
                    repository: None,
                    documentation: None,
                    latest_version: "1.0.0".into(),
                },
                MockMetadata {
                    name: pkg("guava'); System.exit(1); //"),
                    description: None,
                    repository: None,
                    documentation: None,
                    latest_version: "1.0.0".into(),
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

    /// M2 (critic, #739 follow-up): pins the upper-bound boundary from both sides, so a
    /// regression from the inclusive `(2..=200)` to an exclusive `(2..200)` range would be
    /// caught here (the 200-char case would start failing).
    #[test]
    fn test_is_valid_completion_prefix_len_200_chars_accepted() {
        assert!(is_valid_completion_prefix_len(&"a".repeat(200)));
    }

    #[test]
    fn test_is_valid_completion_prefix_len_201_chars_rejected() {
        assert!(!is_valid_completion_prefix_len(&"a".repeat(201)));
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
                latest_version: "1.0.0".into(),
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
                latest_version: "1.0.0".into(),
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
                }
                .into(),
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

    /// #905 S1: a dependency with a synthetic `name_range()` (e.g. `deps-dart`'s
    /// container-anchor alias resolution) resolves to `Range::default()` — position (0,0)
    /// here — which must never yield a `PackageName` completion context. Accepting such a
    /// completion would insert text at that bogus range, worse than the read-only hover case
    /// this same guard already protects.
    #[test]
    fn test_detect_completion_context_skips_synthetic_range_dependency() {
        struct SyntheticDep {
            name: crate::PackageName,
        }

        impl crate::ecosystem::Dependency for SyntheticDep {
            fn name(&self) -> &crate::PackageName {
                &self.name
            }
            fn name_range(&self) -> crate::position::Range {
                crate::position::Range::default()
            }
            fn version_requirement(&self) -> Option<&crate::VersionReq> {
                None
            }
            fn version_range(&self) -> Option<crate::position::Range> {
                None
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn name_range_is_synthetic(&self) -> bool {
                true
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct SyntheticParseResult {
            dep: SyntheticDep,
        }

        impl ParseResult for SyntheticParseResult {
            fn dependencies(&self) -> Vec<&dyn crate::ecosystem::Dependency> {
                vec![&self.dep as &dyn crate::ecosystem::Dependency]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                static URI: std::sync::LazyLock<url::Url> =
                    std::sync::LazyLock::new(|| crate::test_util::test_uri("/test/pubspec.yaml"));
                &URI
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let parse_result = SyntheticParseResult {
            dep: SyntheticDep {
                name: "synthetic-pkg".into(),
            },
        };

        let context = detect_completion_context(
            &parse_result,
            Position {
                line: 0,
                character: 0,
            },
            "",
        );

        assert_matches!(context, CompletionContext::None);
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
                }
                .into(),
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
        // Widening to a one-past-end position would consume structurally significant text
        // (closing quote, space before `=`) on edit, so it must fall through to `None` instead.
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
                }
                .into(),
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
                }
                .into(),
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
        // #310 (deps-deno): a structurally incomplete specifier ("jsr:@std/") has no complete
        // name to parse, yet completion must still fire mid-keystroke. Not solved with
        // jsr:/npm:-specific logic here — `deps-deno`'s parser instead supplies a `Dependency`
        // whose `name_range` covers the partial text directly, needing no change here.
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
                }
                .into(),
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
                assert_eq!(range, parse_result.dependencies[0].name_range.into());
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
                }
                .into(),
                // `MockDependency::version_requirement()` always reports "1.0" (see its
                // impl below) — `version_range` must slice to exactly that literal text
                // for the #919 literal-span guard in `detect_completion_context` to admit
                // a `Version` context at all.
                version_range: Some(
                    Range {
                        start: Position {
                            line: 0,
                            character: 9,
                        },
                        end: Position {
                            line: 0,
                            character: 12,
                        },
                    }
                    .into(),
                ),
                features_range: None,
            }],
        };

        let content = r#"serde = "1.0""#;
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

    /// #919: `version_range` slicing to a Maven-style `${property}` interpolation — text
    /// that differs from the dependency's own declared `version_requirement` ("1.0", per
    /// `MockDependency`) — must withhold the `Version` completion context entirely, rather
    /// than let a completion splice version text into the middle of the interpolation.
    #[test]
    fn test_detect_version_context_withheld_for_property_interpolation() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "slf4j-api".into(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 9,
                    },
                }
                .into(),
                version_range: Some(
                    Range {
                        start: Position {
                            line: 0,
                            character: 13,
                        },
                        end: Position {
                            line: 0,
                            character: 29,
                        },
                    }
                    .into(),
                ),
                features_range: None,
            }],
        };

        let content = r#"slf4j-api = "${slf4j.version}""#;
        let position = Position {
            line: 0,
            character: 20,
        };

        let context = detect_completion_context(&parse_result, position, content);

        assert_eq!(context, CompletionContext::None);
    }

    /// #919: `version_range` slicing to a YAML alias-shaped value (`*anchor`, GitLab CI /
    /// GitHub Actions `ref: *pin` reuse) must likewise withhold the `Version` context — the
    /// slice text ("*pin") never matches the declared literal ("1.0"), so the guard rejects
    /// it exactly like the property-interpolation case above.
    #[test]
    fn test_detect_version_context_withheld_for_yaml_alias() {
        let parse_result = MockParseResult {
            dependencies: vec![MockDependency {
                name: "my-job".into(),
                name_range: Range {
                    start: Position {
                        line: 0,
                        character: 0,
                    },
                    end: Position {
                        line: 0,
                        character: 6,
                    },
                }
                .into(),
                version_range: Some(
                    Range {
                        start: Position {
                            line: 0,
                            character: 7,
                        },
                        end: Position {
                            line: 0,
                            character: 11,
                        },
                    }
                    .into(),
                ),
                features_range: None,
            }],
        };

        let content = "my-job *pin";
        let position = Position {
            line: 0,
            character: 9,
        };

        let context = detect_completion_context(&parse_result, position, content);

        assert_eq!(context, CompletionContext::None);
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
                }
                .into(),
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
            name: "serde".into(),
            description: Some("Serialization framework".to_string()),
            repository: Some("https://github.com/serde-rs/serde".to_string()),
            documentation: Some("https://docs.rs/serde".to_string()),
            latest_version: "1.0.214".into(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        assert_eq!(item.label, "serde");
        assert_eq!(item.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(item.detail, Some("v1.0.214".to_string()));
        assert_matches!(item.documentation, Some(Documentation::MarkupContent(_)));

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
            name: "test-pkg".into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: "0.1.0".into(),
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
            name: "swift-nio".into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: String::new().into(),
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
            name: "test-pkg".into(),
            description: Some("Fast *bold* _italic_ [link](evil) `code`".to_string()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
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
        // Attempts to close `[Repository](...)` early and splice in an attacker-controlled link.
        let malicious_repo = "https://legit.example)[Click here](https://evil.example";
        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: None,
            repository: Some(malicious_repo.to_string()),
            documentation: None,
            latest_version: "1.0.0".into(),
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
            name: "test-pkg".into(),
            description: None,
            repository: None,
            documentation: Some(malicious_docs.to_string()),
            latest_version: "1.0.0".into(),
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
        // Truncating BEFORE escaping keeps an escape sequence at the boundary whole;
        // escaping first would risk cutting between the backslash and its character.
        let mut desc = "a".repeat(199);
        desc.push('*');
        desc.push_str(&"b".repeat(50));

        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: Some(desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
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
        // `latest_version` isn't gated by `is_safe_package_name` (that only guards `name`),
        // so it must still be escaped to prevent the same link-breakout injection.
        let malicious_latest = "1.0.0)[click](https://evil.example";
        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: malicious_latest.into(),
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
        // Reachable simply by typing a prefix (no malicious manifest required); such a name
        // fails `is_safe_package_name`'s allowlist, so the whole item must be dropped.
        let malicious_name = "a** [Official Download](https://evil.example) **b";
        let metadata = MockMetadata {
            name: malicious_name.into(),
            description: None,
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
        };

        let range = Range::default();
        assert!(build_package_completion(&metadata, range).is_none());
    }

    #[test]
    fn test_build_package_completion_benign_repository_url_round_trips() {
        // Backslash-escaping is visually inert on render (CommonMark strips it), so a normal
        // URL must still render unmangled once those escapes are stripped.
        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: None,
            repository: Some("https://github.com/owner/repo".to_string()),
            documentation: None,
            latest_version: "1.0.0".into(),
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
            name: "test-pkg".into(),
            description: Some("<img src=x onerror=alert(1)>".to_string()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
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
            name: "test-pkg".into(),
            description: Some(String::new()),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
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
        // A 3-byte character straddling byte 200: truncation must snap back to a valid char
        // boundary rather than panicking mid-codepoint.
        let mut desc = "a".repeat(199);
        desc.push('日'); // 3 bytes, occupies byte offsets 199..202 — straddles byte 200
        desc.push('*');
        desc.push_str(&"b".repeat(50));

        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: Some(desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
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
            version: "1.0.0".into(),
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
            version: "1.0.0".into(),
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
            version: "0.9.0".into(),
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
            version: "1.0.0".into(),
            yanked: false,
            prerelease: false,
        };
        let v2 = MockVersion {
            version: "0.9.0".into(),
            yanked: false,
            prerelease: false,
        };
        let v3 = MockVersion {
            version: "0.8.0".into(),
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

        assert_eq!(item1.sort_text.as_ref().unwrap(), "00000");
        assert_eq!(item2.sort_text.as_ref().unwrap(), "00001");
        assert_eq!(item3.sort_text.as_ref().unwrap(), "00002");

        assert_eq!(item1.preselect, Some(true));
        assert_eq!(item2.preselect, Some(false));
        assert_eq!(item3.preselect, Some(false));
    }

    #[test]
    fn test_version_completion_semantic_ordering() {
        let versions = [
            MockVersion {
                version: "0.14.0".into(),
                yanked: false,
                prerelease: false,
            },
            MockVersion {
                version: "0.8.0".into(),
                yanked: false,
                prerelease: false,
            },
            MockVersion {
                version: "0.2.0".into(),
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
                    version: (*ver).into(),
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
            version: "1.0.0".into(),
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
            version: "0.9.0".into(),
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
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".into(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.8.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(0));

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
                    version: format!("1.0.{}", i).into(),
                    yanked: false,
                    prerelease: false,
                }) as std::sync::Arc<dyn crate::Version>
            })
            .collect();

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(0));

        assert_eq!(items.len(), 5);
        assert_eq!(items[0].version, "1.0.0");
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[4].version, "1.0.4");
        assert_eq!(items[4].label, "1.0.4");
    }

    #[test]
    fn test_prepare_version_display_items_empty() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![];

        let items = prepare_version_display_items(&versions, &pkg("test"), None);

        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_prepare_version_display_items_all_yanked() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".into(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".into(),
                yanked: true,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(0));

        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_prepare_version_display_items_tags_caller_supplied_index_not_raw_zero() {
        // `is_latest` follows the caller-supplied `latest_idx` — the registry-delegated pick
        // (#952) — even when that index isn't 0, e.g. because the registry ranked a
        // pre-release below a stable release in its own `select_latest_matching`.
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "13.0.5-beta1".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "13.0.4".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "13.0.3".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(1));

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].version, "13.0.5-beta1");
        assert!(!items[0].is_latest, "index 0 was not the supplied pick");
        assert_eq!(items[1].version, "13.0.4");
        assert_eq!(items[1].label, "13.0.4 (latest)");
        assert!(items[1].is_latest);
        assert_eq!(items[2].version, "13.0.3");
        assert!(!items[2].is_latest);
    }

    #[test]
    fn test_prepare_version_display_items_none_latest_idx_tags_nothing() {
        // A registry-delegated pick of `None` (e.g. every candidate filtered/exhausted)
        // must not fall back to tagging raw index 0.
        let versions: Vec<std::sync::Arc<dyn crate::Version>> =
            vec![std::sync::Arc::new(MockVersion {
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            })];

        let items = prepare_version_display_items(&versions, &pkg("test"), None);

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "1.0.0");
        assert!(!items[0].is_latest);
    }

    #[test]
    fn test_prepare_version_display_items_latest_idx_maps_through_internal_yanked_filter() {
        // `latest_idx` refers to a position in the *pre-filter* `versions` slice; this
        // function's own internal yanked filter must not shift which entry it points to.
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "2.0.0".into(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.9.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.8.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        // Caller picked pre-filter index 2 ("1.8.0") as latest.
        let items = prepare_version_display_items(&versions, &pkg("test"), Some(2));

        assert_eq!(items.len(), 2, "the yanked entry is still filtered out");
        assert_eq!(items[0].version, "1.9.0");
        assert!(!items[0].is_latest);
        assert_eq!(items[1].version, "1.8.0");
        assert_eq!(items[1].label, "1.8.0 (latest)");
        assert!(items[1].is_latest);
    }

    /// Regression for #956: the registry-selected pick (`latest_idx`) survives the yanked
    /// filter but lands at post-filter position 5 — one past the raw-order display cap
    /// (`MAX_COMPLETION_VERSIONS` = 5) — because 6 pre-release entries sort ahead of it. It
    /// must still be included and tagged, not silently dropped from the returned window.
    #[test]
    fn test_prepare_version_display_items_bumps_pick_outside_raw_order_window() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc5".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc4".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc3".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc2".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc1".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(5));

        assert_eq!(items.len(), 5, "still capped at MAX_COMPLETION_VERSIONS");
        assert_eq!(
            items[3].version, "2.0.0-rc2",
            "raw-order window kept otherwise"
        );
        assert_eq!(
            items[4].version, "1.0.0",
            "the pick is appended rather than dropped"
        );
        assert_eq!(items[4].label, "1.0.0 (latest)");
        assert!(items[4].is_latest);
        assert!(
            items.iter().take(4).all(|item| !item.is_latest),
            "no pre-release entry is mislabeled as latest"
        );
    }

    /// Boundary check for #956: `pick_pos == MAX_COMPLETION_VERSIONS - 1` (4) is the last
    /// slot already inside the raw-order display cap, so no bump/append happens — unlike
    /// `pos == 5` in the test above.
    #[test]
    fn test_prepare_version_display_items_pick_at_last_window_slot_not_bumped() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc4".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc3".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc2".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "2.0.0-rc1".into(),
                yanked: false,
                prerelease: true,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let items = prepare_version_display_items(&versions, &pkg("test"), Some(4));

        assert_eq!(
            items.len(),
            5,
            "all 5 raw-order entries returned, nothing bumped"
        );
        assert_eq!(items[4].version, "1.0.0");
        assert_eq!(items[4].label, "1.0.0 (latest)");
        assert!(items[4].is_latest);
        assert!(items.iter().take(4).all(|item| !item.is_latest));
    }

    /// `latest_idx` points at a *yanked* entry while 6 other non-yanked survivors remain —
    /// unlike `test_prepare_version_display_items_all_yanked`, where survivors end up empty
    /// and the `None` fallthrough is trivially unobservable. Plain `.take(5)` windowing must
    /// apply, with nothing appended and no entry incorrectly tagged `is_latest`.
    #[test]
    fn test_prepare_version_display_items_pick_filtered_out_with_many_survivors() {
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = vec![
            std::sync::Arc::new(MockVersion {
                version: "9.9.9".into(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.6.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.5.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.4.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.3.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.2.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "1.1.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        // The registry picked the yanked raw-index-0 entry as "latest" — an edge case
        // `select_latest_matching` shouldn't produce in practice, but the function must
        // degrade gracefully rather than panic or misbehave if it does.
        let items = prepare_version_display_items(&versions, &pkg("test"), Some(0));

        assert_eq!(
            items.len(),
            5,
            "capped at MAX_COMPLETION_VERSIONS, no bump since the pick never survives"
        );
        assert_eq!(items[0].version, "1.6.0");
        assert_eq!(items[4].version, "1.2.0");
        assert!(
            items.iter().all(|item| !item.is_latest),
            "the yanked pick is never tagged"
        );
    }

    /// Large-scale mapping check: yanked entries interleaved before and after non-yanked
    /// ones (12 raw entries, alternating), with the picked stable version near the end.
    /// Confirms `orig_index` bookkeeping survives significant reindexing by the yanked
    /// filter, both for the "already in head" check and the bounded remainder lookup.
    #[test]
    fn test_prepare_version_display_items_bump_survives_interleaved_yanked_at_scale() {
        let specs: [(&str, bool, bool); 12] = [
            ("3.0.0-rc1", false, true),
            ("2.9.0", true, false),
            ("2.8.0-rc1", false, true),
            ("2.7.0", true, false),
            ("2.6.0-rc1", false, true),
            ("2.5.0", true, false),
            ("2.4.0-rc1", false, true),
            ("2.3.0", true, false),
            ("2.2.0-rc1", false, true),
            ("2.1.0", true, false),
            ("2.0.0-rc1", false, true),
            ("1.0.0", false, false),
        ];
        let versions: Vec<std::sync::Arc<dyn crate::Version>> = specs
            .into_iter()
            .map(|(version, yanked, prerelease)| {
                std::sync::Arc::new(MockVersion {
                    version: version.into(),
                    yanked,
                    prerelease,
                }) as std::sync::Arc<dyn crate::Version>
            })
            .collect();

        // Registry picked raw index 11 ("1.0.0") as latest.
        let items = prepare_version_display_items(&versions, &pkg("test"), Some(11));

        assert_eq!(
            items.len(),
            5,
            "capped at MAX_COMPLETION_VERSIONS despite 7 survivors"
        );
        assert_eq!(items[0].version, "3.0.0-rc1");
        assert_eq!(
            items[3].version, "2.4.0-rc1",
            "4th surviving entry in raw order, yanked ones skipped"
        );
        assert_eq!(
            items[4].version, "1.0.0",
            "the pick is bumped in from post-filter position 6"
        );
        assert_eq!(items[4].label, "1.0.0 (latest)");
        assert!(items[4].is_latest);
        assert!(items.iter().take(4).all(|item| !item.is_latest));
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

    #[test]
    fn test_byte_to_utf16_offset_never_panics_on_bad_offsets() {
        // #680: `byte_offset` is not guaranteed to be a valid char boundary or even in
        // bounds — `floor_char_boundary` must clamp both cases rather than let the
        // internal slice panic.
        let s = "日本語";

        // Offset 1 lands inside the first 3-byte character ('日'); floors down to 0.
        assert_eq!(byte_to_utf16_offset(s, 1), 0);
        // Offset 2 also lands inside '日'; still floors down to 0.
        assert_eq!(byte_to_utf16_offset(s, 2), 0);
        // Exactly at `s.len()` (9 bytes): the whole string.
        assert_eq!(byte_to_utf16_offset(s, 9), 3);
        // Past the end: saturates to `s.len()` rather than panicking.
        assert_eq!(byte_to_utf16_offset(s, 999), 3);
    }

    // Unicode truncation tests

    #[test]
    fn test_build_package_completion_long_description_ascii() {
        let long_desc = "a".repeat(250);
        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            assert!(lines[2].len() <= 203); // 200 + "..."
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_long_description_unicode() {
        // Each '日' is 3 bytes, so 67 chars = 201 bytes, straddling the 200-byte boundary.
        let mut long_desc = String::new();
        for _ in 0..67 {
            long_desc.push('日');
        }

        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            assert!(lines[2].is_char_boundary(lines[2].len()));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_build_package_completion_long_description_emoji() {
        // "😀" is 4 bytes each; 51 emoji = 204 bytes, straddling the 200-byte boundary.
        let long_desc = "😀".repeat(51);

        let metadata = MockMetadata {
            name: "test-pkg".into(),
            description: Some(long_desc),
            repository: None,
            documentation: None,
            latest_version: "1.0.0".into(),
        };

        let range = Range::default();
        let item = build_package_completion(&metadata, range).unwrap();

        if let Some(Documentation::MarkupContent(content)) = item.documentation {
            let lines: Vec<_> = content.value.lines().collect();
            assert!(lines[2].ends_with("..."));
            assert!(lines[2].is_char_boundary(lines[2].len()));
        } else {
            panic!("Expected MarkupContent documentation");
        }
    }

    #[test]
    fn test_extract_prefix_unicode_package_name() {
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
                    version: "1.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.1.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "^1.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.0.1");

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

    /// GitLab CI ecosystem plan §7a.1: `complete_versions_generic` must produce
    /// byte-identical items before and after becoming a thin delegation to
    /// [`complete_versions_generic_from`] with a plain [`crate::parser::DependencySource::Registry`].
    #[tokio::test]
    async fn test_complete_versions_generic_delegates_to_from_byte_identical() {
        let registry = MockRegistry {
            versions: vec![MockVersion {
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            }],
        };

        let via_generic = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "1.0",
            &[],
            FreshnessSettings::default(),
        )
        .await;
        let via_from = complete_versions_generic_from(
            &registry,
            &pkg("test-pkg"),
            &crate::parser::DependencySource::Registry,
            "1.0",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(via_generic.len(), via_from.len());
        assert_eq!(via_generic[0].label, via_from[0].label);
    }

    /// A registry stub whose `get_versions_from` override returns a distinct version list
    /// per [`crate::parser::DependencySource`] — proves
    /// [`complete_versions_generic_from`] genuinely threads `source` through to
    /// `Registry::get_versions_from` rather than silently dropping it to the
    /// source-unaware `get_versions_with` default (the class of bug M10 flagged: a stub
    /// that ignores `source`, like [`MockRegistry`] above, would never catch this).
    struct RoutingMockRegistry;

    impl crate::Registry for RoutingMockRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a crate::PackageName,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            Box::pin(async move {
                Ok(vec![Box::new(MockVersion {
                    version: "9.9.9".into(),
                    yanked: false,
                    prerelease: false,
                }) as Box<dyn crate::Version>])
            })
        }

        fn get_versions_from<'a>(
            &'a self,
            _name: &'a crate::PackageName,
            source: &'a crate::parser::DependencySource,
            _freshness: FreshnessSettings,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
        {
            let version = if matches!(
                source,
                crate::parser::DependencySource::AlternateRegistry { .. }
            ) {
                "2.0.0"
            } else {
                "1.0.0"
            };
            Box::pin(async move {
                Ok(vec![Box::new(MockVersion {
                    version: version.into(),
                    yanked: false,
                    prerelease: false,
                }) as Box<dyn crate::Version>])
            })
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

        // See `MockRegistry`'s identical override above: without this, `select_latest_matching`
        // defaults to `None` and no item in this test would ever carry the `(latest)` label.
        fn select_latest_matching(
            &self,
            versions: &[Box<dyn crate::Version>],
            _req: &crate::VersionReq,
        ) -> Option<usize> {
            crate::select_latest_for_existence(versions, |v| v.as_ref())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[tokio::test]
    async fn test_complete_versions_generic_from_routes_source_to_get_versions_from() {
        let registry = RoutingMockRegistry;
        let alternate = crate::parser::DependencySource::AlternateRegistry {
            index: "gitlab-ci:deadbeef".into(),
            mirrors_crates_io: false,
        };

        let items = complete_versions_generic_from(
            &registry,
            &pkg("test-pkg"),
            &alternate,
            "",
            &[],
            FreshnessSettings::default(),
        )
        .await;
        assert_eq!(items[0].label, "2.0.0 (latest)");

        // The source-unaware `get_versions` override (returning "9.9.9") must never be
        // reached by the source-aware helper.
        assert_ne!(items[0].label, "9.9.9 (latest)");
    }

    #[tokio::test]
    async fn test_complete_versions_generic_fallback_when_no_prefix_match() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.1.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "2.1.0".into(),
                    yanked: true, // Yanked version
                    prerelease: false,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "3.0",
            &['^', '~', '=', '<', '>'],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.1.0");
        assert_eq!(items[2].label, "2.0.0");
        assert!(!items.iter().any(|item| item.label == "2.1.0"));

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
                    version: "1.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1".into(),
                    yanked: true, // Yanked version
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.2".into(),
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

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "1.0.0 (latest)");
        assert_eq!(items[1].label, "1.0.2");
        assert!(!items.iter().any(|item| item.label == "1.0.1"));
    }

    #[tokio::test]
    async fn test_complete_versions_generic_filters_unsafe_version_string() {
        // Critic S3: `build_version_completion` writes insert_text/text_edit straight from a
        // registry-reported version, the same untrusted source as the REFACTOR code-action loop.
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "1.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "1.0.1\", \"evil\": \"true".into(),
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
        let versions: Vec<_> = (0..10)
            .map(|i| MockVersion {
                version: format!("1.0.{}", i).into(),
                yanked: false,
                prerelease: false,
            })
            .collect();

        let registry = MockRegistry { versions };

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
                    version: "v1.9.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "v1.9.1".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "v1.10.0".into(),
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

    #[tokio::test]
    async fn test_complete_versions_generic_from_skips_prerelease_at_raw_top() {
        // #952 (sibling of #313, previously hover-only): when raw fetch-order top is a
        // pre-release, `(latest)`/`preselect` must land on the first stable entry via
        // `Registry::select_latest_matching`, not raw index 0.
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "13.0.5-beta1".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "13.0.4".into(),
                    yanked: false,
                    prerelease: false,
                },
                MockVersion {
                    version: "13.0.3".into(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("Newtonsoft.Json"),
            "",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "13.0.5-beta1");
        assert_eq!(
            items[0].preselect,
            Some(false),
            "the pre-release must not be preselected"
        );
        assert_eq!(items[1].label, "13.0.4 (latest)");
        assert_eq!(
            items[1].preselect,
            Some(true),
            "the first stable entry must be preselected instead"
        );
        assert_eq!(items[2].label, "13.0.3");
        assert_eq!(items[2].preselect, Some(false));
    }

    #[tokio::test]
    async fn test_complete_versions_generic_from_all_prerelease_still_marks_a_latest() {
        // Critic C1: when every version is a pre-release, completion must still agree with
        // hover's fallback (ranking the newest overall) rather than tagging nothing.
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "2.0.0-beta2".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0-beta1".into(),
                    yanked: false,
                    prerelease: true,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "2.0.0-beta2 (latest)");
        assert_eq!(items[0].preselect, Some(true));
        assert_eq!(items[1].label, "2.0.0-beta1");
        assert_eq!(items[1].preselect, Some(false));
    }

    #[tokio::test]
    async fn test_complete_versions_generic_from_prefers_non_deprecated_over_newer_deprecated() {
        // Critic S1: same #952 defect class with "deprecated" substituted for "pre-release"
        // (npm's #338 NFR-002 shape) — must prefer the older, non-flagged release.
        use crate::lsp_helpers::test_support::{
            MockRegistryPreferringUnflagged, MockVersionWithStatus,
        };

        let registry = MockRegistryPreferringUnflagged {
            versions: vec![
                MockVersionWithStatus {
                    version: "2.0.0".into(),
                    status: crate::RemovalStatus::AdvisoryDeprecated,
                },
                MockVersionWithStatus {
                    version: "1.9.0".into(),
                    status: crate::RemovalStatus::Available,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].label, "2.0.0",
            "the deprecated entry is still offered"
        );
        assert_eq!(
            items[0].preselect,
            Some(false),
            "but must not be labeled/preselected as latest"
        );
        assert_eq!(items[1].label, "1.9.0 (latest)");
        assert_eq!(items[1].preselect, Some(true));
    }

    /// Regression for #956 through the prefix-filtering branch of
    /// `complete_versions_generic_from`: `latest_idx` is computed over the already
    /// prefix-narrowed slice (`completion.rs`'s `has_prefix_match` branch), so the bump must
    /// still apply when *that* slice's own registry pick falls outside its own display cap —
    /// not just when it happens over the full unfiltered version list.
    #[tokio::test]
    async fn test_complete_versions_generic_from_bump_survives_prefix_filtering() {
        let registry = MockRegistry {
            versions: vec![
                MockVersion {
                    version: "2.0.0-rc5".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0-rc4".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0-rc3".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0-rc2".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0-rc1".into(),
                    yanked: false,
                    prerelease: true,
                },
                MockVersion {
                    version: "2.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
                // Does not match the "2." prefix below, so it must not affect the
                // prefix-narrowed slice's own bump computation.
                MockVersion {
                    version: "1.0.0".into(),
                    yanked: false,
                    prerelease: false,
                },
            ],
        };

        let items = complete_versions_generic(
            &registry,
            &pkg("test-pkg"),
            "2.",
            &[],
            FreshnessSettings::default(),
        )
        .await;

        // Prefix "2." narrows to 6 entries (5 pre-releases + stable "2.0.0"); the stable
        // pick lands at post-filter index 5 within that narrowed slice — one past the
        // MAX_COMPLETION_VERSIONS(5) cap — so it is bumped in as the final display item.
        assert_eq!(
            items.len(),
            5,
            "capped, bumped via the prefix-filtered slice"
        );
        assert_eq!(items[3].label, "2.0.0-rc2");
        assert_eq!(items[4].label, "2.0.0 (latest)");
        assert_eq!(items[4].preselect, Some(true));
        assert!(
            items
                .iter()
                .take(4)
                .all(|item| item.preselect != Some(true))
        );
        assert!(
            !items.iter().any(|item| item.label == "2.0.0-rc1"),
            "the 5th raw-order pre-release is displaced by the bumped pick"
        );
    }

    // --- Feature completion detection tests ---

    fn make_dep_with_features_range(
        name: &str,
        name_range: Range,
        features_range: Range,
    ) -> MockDependency {
        MockDependency {
            name: name.into(),
            name_range: name_range.into(),
            version_range: None,
            features_range: Some(features_range.into()),
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

    /// #733: a naive `"` count miscounts an escaped `\"` inside a feature name,
    /// desyncing the open/closed check from the segment's real quote state. Here the
    /// segment up to the cursor (`"a\"b`) has one real quote (the opening quote; the
    /// escaped one doesn't count) — an odd count, correctly "open" with tail `a\"b`.
    /// A naive count sees two `"` characters (even, wrongly "closed") and would
    /// collapse the prefix to empty; the escape-aware check must still find the
    /// string open with the correct tail.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a short ASCII test line can never overflow u32"
    )]
    #[test]
    fn test_extract_feature_prefix_skips_escaped_quote() {
        let content = r#"features = ["a\"b"#;
        let position = Position {
            line: 0,
            character: content.chars().count() as u32,
        };
        let prefix = extract_feature_prefix(content, position);
        assert_eq!(prefix, r#"a\"b"#);
    }

    // --- Release-freshness signal (issue #145): VersionDisplayItem.published_at,
    // build_version_completion's label_details ---

    #[test]
    fn test_version_display_item_captures_published_at() {
        let version = MockVersionWithAge {
            version: "1.0.0".into(),
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
            version: "1.0.0".into(),
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
            version: "1.2.3".into(),
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
            version: "1.2.3".into(),
            published_at: Some(published_two_hours_ago),
        };
        let display_item = VersionDisplayItem::new(&version, &pkg("serde"), 0, true);

        let item = build_version_completion(&display_item, None, now, false);

        assert!(item.label_details.is_none());
    }

    #[test]
    fn test_build_version_completion_label_details_absent_when_published_at_unknown() {
        let version = MockVersion {
            version: "1.2.3".into(),
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
                version: "1.0.0".into(),
                yanked: false,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.9.0".into(),
                yanked: true,
                prerelease: false,
            }),
            std::sync::Arc::new(MockVersion {
                version: "0.8.0".into(),
                yanked: false,
                prerelease: false,
            }),
        ];

        let display_items = prepare_version_display_items(&versions, &pkg("test"), Some(0));
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
