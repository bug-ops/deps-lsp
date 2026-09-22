//! Protocol-agnostic hover type (issue #1277).
//!
//! [`Hover`](crate::hover::Hover) is the domain-level replacement for
//! `tower_lsp_server::ls_types::Hover` in [`crate::lsp_helpers::generate_hover`]'s and
//! [`crate::ecosystem::Ecosystem::generate_hover`]'s return value: `deps-lsp` only ever
//! produces `HoverContents::Markup(MarkupKind::Markdown)`, so this type collapses that
//! 3-variant enum to a single markdown string and lets [`MarkupKind::Markdown`] become an
//! implementation detail of the `deps-lsp`-side conversion
//! (`crates/deps-lsp/src/lsp_types_interop.rs`) instead of part of every ecosystem's
//! response-building code.
//!
//! Unlike [`crate::diagnostic`], this module is gated behind the `lsp-responses` feature
//! (not unconditionally public): `deps-cli` never renders a hover card, so there is no
//! consumer for this type outside the `lsp-responses`-gated response-building surface —
//! see `lib.rs`'s "LSP type stability" doc section for the feature's full rationale.
//!
//! [`MarkupKind::Markdown`]: tower_lsp_server::ls_types::MarkupKind::Markdown

use crate::position::Range;

/// A hover response's content and span.
///
/// Field-for-field equivalent to the single shape `tower_lsp_server::ls_types::Hover` is
/// ever constructed with in this codebase
/// (`HoverContents::Markup(MarkupContent { kind: MarkupKind::Markdown, .. })`), but carrying
/// no dependency on `tower-lsp-server`.
///
/// `deps-lsp` converts this into `tower_lsp_server::ls_types::Hover` at its own boundary
/// (`crates/deps-lsp/src/lsp_types_interop.rs::to_lsp_hover`).
///
/// # Examples
///
/// ```
/// use deps_core::hover::Hover;
/// use deps_core::position::{Position, Range};
///
/// let hover = Hover::new(
///     "# serde\n\n**Latest**: `1.0.0`",
///     Some(Range::new(Position::new(0, 0), Position::new(0, 5))),
/// );
/// assert!(hover.markdown().starts_with("# serde"));
/// ```
///
/// # The sanitization backstop this design relies on (issue #1276/#1280's pattern, extended to hover)
///
/// `markdown` is private and [`Self`] does not implement `Default` — the only ways to set it
/// from outside this crate are [`Self::new`], [`Self::push_markdown`], and
/// [`Self::rewrite_markdown`], every one of which routes the value it sets through
/// `crate::lsp_helpers::replace_markdown_unsafe_chars_keep_newlines`. There is deliberately
/// no bare `set_markdown` that would let a caller bypass the filter. Setting `markdown`
/// directly fails to compile (the field does not exist from outside this crate):
///
/// ```compile_fail
/// use deps_core::hover::Hover;
///
/// let mut hover = Hover::new("safe", None);
/// hover.markdown = "raw".to_string();
/// ```
///
/// ## What this guarantee covers, and what it does not
///
/// This closes the **bidi-override/invisible/control-character class** (the #1271 class,
/// `crate::lsp_helpers::is_markdown_unsafe`) at every hover construction and mutation site
/// at once. It does **not** close markdown-injection (unescaped `[`, `]`, backticks reaching
/// the rendered card as structural Markdown) and does **not** length-cap any field — the
/// #1272 class. Per-site `escape_markdown`/`markdown_code_span`/`truncate_for_diagnostic`
/// remain mandatory for producer code, exactly as [`crate::diagnostic::Diagnostic::new`]'s own
/// doc states for length-capping: this type is a defense-in-depth backstop on top of
/// producer-side sanitization, not a replacement for it. Do not treat "constructed through
/// `Hover`" as "safe to interpolate unescaped input into".
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hover {
    markdown: String,
    /// Span the hover applies to, when the response is anchored to a specific location in
    /// the document (e.g. the dependency name range).
    pub range: Option<Range>,
}

impl Hover {
    /// Builds a [`Hover`] from its `markdown`/`range` fields.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must call this constructor instead.
    ///
    /// `markdown` is sanitized through
    /// `crate::lsp_helpers::replace_markdown_unsafe_chars_keep_newlines` on this
    /// constructor path, on top of (not instead of) producer-side sanitization — see this
    /// type's doc for exactly which class of issue this closes and which it does not.
    /// Unlike [`crate::diagnostic::Diagnostic::new`]'s filter, this preserves `\n`: hover
    /// content is a multi-section Markdown document, not a single-line label, so collapsing
    /// its structural newlines would be a regression, not a sanitization.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::hover::Hover;
    ///
    /// let hover = Hover::new("# serde\n\n**Current**: `1.0.0`", None);
    /// assert_eq!(hover.markdown(), "# serde\n\n**Current**: `1.0.0`");
    /// assert_eq!(hover.range, None);
    /// ```
    #[must_use]
    pub fn new(markdown: impl Into<String>, range: Option<Range>) -> Self {
        Self {
            markdown: crate::lsp_helpers::replace_markdown_unsafe_chars_keep_newlines(
                &markdown.into(),
            ),
            range,
        }
    }

    /// Returns the hover Markdown, sanitized only for the bidi-override/invisible/control-
    /// character class — see [`Self`]'s "What this guarantee covers, and what it does not"
    /// section; this is not a guarantee against markdown-injection or unbounded length.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::hover::Hover;
    ///
    /// let hover = Hover::new("**Latest**: `1.0.0`", None);
    /// assert_eq!(hover.markdown(), "**Latest**: `1.0.0`");
    /// ```
    #[must_use]
    pub fn markdown(&self) -> &str {
        &self.markdown
    }

    /// Appends `extra` to [`Self::markdown`], sanitizing it the same way [`Self::new`]
    /// sanitizes its initial value.
    ///
    /// For an ecosystem's `generate_hover` override that adds a trailing section (e.g. a
    /// catalog-source note or an update-footer) after the shared base hover was already
    /// built.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::hover::Hover;
    ///
    /// let mut hover = Hover::new("# express", None);
    /// hover.push_markdown("\n\n**Catalog**: `default`");
    /// assert!(hover.markdown().ends_with("**Catalog**: `default`"));
    /// ```
    pub fn push_markdown(&mut self, extra: &str) {
        self.markdown
            .push_str(&crate::lsp_helpers::replace_markdown_unsafe_chars_keep_newlines(extra));
    }

    /// Replaces [`Self::markdown`] with the result of `f`, applied to the current value —
    /// sanitizing the result the same way [`Self::new`] sanitizes its initial value.
    ///
    /// For an ecosystem's `generate_hover` override that needs to splice or annotate a line
    /// somewhere inside the already-built base hover (not just append at the end, which
    /// [`Self::push_markdown`] covers) — e.g. inserting a resolved-tag note after the
    /// `**Current**` line. Deliberately the only read-modify-write path: there is no bare
    /// `set_markdown` that would let `f`'s result skip the filter.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::hover::Hover;
    ///
    /// let mut hover = Hover::new("**Current**: `main`", None);
    /// hover.rewrite_markdown(|md| md.replace("`main`", "`main` (resolved: `a1b2c3d`)"));
    /// assert!(hover.markdown().contains("resolved: `a1b2c3d`"));
    /// ```
    pub fn rewrite_markdown(&mut self, f: impl FnOnce(&str) -> String) {
        let rewritten = f(&self.markdown);
        self.markdown = crate::lsp_helpers::replace_markdown_unsafe_chars_keep_newlines(&rewritten);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::Position;

    #[test]
    fn test_hover_new_sets_markdown_and_range() {
        let range = Range::new(Position::new(0, 0), Position::new(0, 4));
        let hover = Hover::new("# serde", Some(range));
        assert_eq!(hover.markdown(), "# serde");
        assert_eq!(hover.range, Some(range));
    }

    #[test]
    fn test_hover_new_leaves_range_unset_when_none() {
        let hover = Hover::new("# serde", None);
        assert_eq!(hover.range, None);
    }

    /// #1276-class backstop, extended to hover (#1277): a bidi-override character in
    /// `markdown` must not survive construction through `new`.
    #[test]
    fn test_hover_new_sanitizes_bidi_override_in_markdown() {
        let hover = Hover::new("# serde\u{202E}gnp.sj", None);
        assert_eq!(hover.markdown(), "# serde gnp.sj");
    }

    /// The finding that shapes this whole module (architect handoff): hover markdown is a
    /// multi-section document with structural newlines, unlike a single-line diagnostic
    /// message — `Hover::new`'s filter must not collapse them.
    #[test]
    fn test_hover_new_preserves_structural_newlines() {
        let hover = Hover::new("# serde\n\n**Current**: `1.0.0`", None);
        assert_eq!(hover.markdown(), "# serde\n\n**Current**: `1.0.0`");
    }

    #[test]
    fn test_hover_push_markdown_appends_sanitized_content() {
        let mut hover = Hover::new("# express", None);
        hover.push_markdown("\n\n**Catalog**: `default`\u{202E}gnp.sj");
        assert_eq!(
            hover.markdown(),
            "# express\n\n**Catalog**: `default` gnp.sj"
        );
    }

    #[test]
    fn test_hover_rewrite_markdown_replaces_sanitized_content() {
        let mut hover = Hover::new("**Current**: `main`", None);
        hover.rewrite_markdown(|md| format!("{md}\u{202E}gnp.sj"));
        assert_eq!(hover.markdown(), "**Current**: `main` gnp.sj");
    }

    #[test]
    fn test_hover_rewrite_markdown_can_splice_mid_string() {
        let mut hover = Hover::new("**Current**: `main`", None);
        hover.rewrite_markdown(|md| md.replace("`main`", "`main` (resolved: `a1b2c3d`)"));
        assert_eq!(
            hover.markdown(),
            "**Current**: `main` (resolved: `a1b2c3d`)"
        );
    }

    /// #1277 review M5 / tester coverage gap: mirrors
    /// `test_replace_markdown_unsafe_chars_is_idempotent` (`lsp_helpers/mod.rs`) for the
    /// keep-newlines variant — pins the *full* `is_markdown_unsafe` character class through
    /// `Hover::new` in one place (prior coverage only pinned U+202E), and confirms
    /// idempotency, the same guarantee the sibling filter carries.
    #[test]
    fn test_hover_new_sanitizes_full_unsafe_char_class_and_is_idempotent() {
        for c in [
            '\u{202E}',  // RLO
            '\u{2066}',  // LRI
            '\u{200B}',  // ZWSP
            '\u{2060}',  // WORD JOINER
            '\u{2028}',  // LS
            '\u{2029}',  // PS
            '\u{FEFF}',  // ZWNBSP / BOM
            '\u{FFFA}',  // interlinear annotation anchor
            '\u{E0041}', // Unicode tag character ("A")
            '\t',
        ] {
            let once = Hover::new(format!("a{c}b"), None);
            assert_eq!(
                once.markdown(),
                "a b",
                "{c:?} must be replaced with a space"
            );
            let twice = Hover::new(once.markdown(), None);
            assert_eq!(
                twice.markdown(),
                once.markdown(),
                "{c:?} must not change on re-application"
            );
        }
    }

    /// #1277 review M5: `\n` is the one character `Hover`'s filter treats differently from
    /// its `Diagnostic`-oriented sibling — pin that this holds through every sanitizing entry
    /// point (`new`, `push_markdown`, `rewrite_markdown`), not just `new` (already covered by
    /// `test_hover_new_preserves_structural_newlines`).
    #[test]
    fn test_hover_preserves_newlines_through_every_sanitizing_entry_point() {
        let mut hover = Hover::new("# serde", None);
        hover.push_markdown("\n\n**Current**: `1.0.0`");
        assert_eq!(hover.markdown(), "# serde\n\n**Current**: `1.0.0`");

        hover.rewrite_markdown(|md| format!("{md}\n\n**Latest**: `1.0.1`"));
        assert_eq!(
            hover.markdown(),
            "# serde\n\n**Current**: `1.0.0`\n\n**Latest**: `1.0.1`"
        );
    }
}
