//! LSP-only completion support for Swift Package Manager (issue #1282).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use tower_lsp_server::ls_types::{CompletionItem, CompletionTextEdit, Range as LspRange, TextEdit};

use deps_core::{is_safe_registry_url, lsp_helpers::warn_rejected_value};

use crate::types::SwiftPackage;

/// Builds a completion item that inserts the full GitHub URL for `.package(url: "...")`.
///
/// The completion fires with the cursor inside the `url:` string literal (see
/// `SwiftEcosystem::generate_completions`), so the insertable text must always be a
/// full URL — never the bare `owner/repo` identity — regardless of how much of the
/// scheme the user has typed so far. `replace_range` should be the dependency's
/// `name_range()` (the byte span of the whole URL literal) whenever the caller can resolve
/// it — [`deps_core::completion::build_package_completion_fields`] supplies no
/// `insert_text`/`text_edit` at all, so this function always builds them itself. When
/// `None` (the dependency containing the cursor could not be found), falls back to
/// `insert_text`-only — the same safe pattern used by `create_package_completion_item` in
/// `deps-lsp` — rather than guessing a range.
///
/// Returns `None` when `url` doesn't pass [`is_safe_registry_url`], or when the base
/// builder itself rejects `package.name` — a malicious/compromised search result must
/// not reach the manifest as an unsanitized `TextEdit`, so the item is dropped rather
/// than built with unsafe text.
pub(super) fn build_url_completion(
    package: &SwiftPackage,
    replace_range: Option<LspRange>,
    index: usize,
    prefix: &str,
) -> Option<CompletionItem> {
    let url = package
        .repository
        .clone()
        .unwrap_or_else(|| format!("https://github.com/{}", package.name.as_str()));

    if !is_safe_registry_url(&url) {
        warn_rejected_value("is_safe_registry_url", "swift url completion", &url);
        return None;
    }

    let mut item = deps_core::completion::build_package_completion_fields(package, index, prefix)?;

    item.insert_text = Some(url.clone());
    item.filter_text = Some(url.clone());
    // `sort_text` is left as `build_package_completion_fields` computed it: `prefix` here is
    // already the GitHub-scheme-stripped query (see `strip_github_prefix`), which is the
    // same shape as `package.name()`, so the shared tiering is correct as-is (#1282 S1).
    item.text_edit = replace_range.map(|range| {
        CompletionTextEdit::Edit(TextEdit {
            range,
            new_text: url,
        })
    });

    Some(item)
}

/// Strips a leading `https://github.com/` (or `https://github.com`) scheme from a
/// completion prefix, leaving the search query GitHub's repository search expects.
pub(super) fn strip_github_prefix(prefix: &str) -> &str {
    prefix
        .strip_prefix("https://github.com/")
        .or_else(|| prefix.strip_prefix("https://github.com"))
        .unwrap_or(prefix)
}
