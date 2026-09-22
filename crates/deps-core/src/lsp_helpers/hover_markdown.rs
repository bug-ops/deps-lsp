//! Typed markdown-fragment builder for hover cards (issue #1310).
//!
//! [`generate_hover`](super::generate_hover) accumulates one hover card's Markdown by
//! calling into ~12 `push_*_hover_section` helpers, each of which used to take a bare
//! `&mut String` — meaning nothing stopped a future call site from interpolating an
//! attacker-controlled value straight into the accumulator with no length cap or
//! escaping (the exact gap #1311 closed, one call site at a time). [`HoverMarkdown`]
//! replaces that `&mut String` parameter. Every method that can carry untrusted,
//! registry-/manifest-controlled text — [`HoverMarkdown::push_text`],
//! [`HoverMarkdown::push_code`], [`HoverMarkdown::push_label`], [`HoverMarkdown::push_link`] —
//! applies a length cap and/or escapes the value it is given, so a call site can no
//! longer *forget* to do so. [`HoverMarkdown::push_static`] only accepts `&'static
//! str` — a `format!`-produced `String` cannot be passed to it — which is what makes
//! raw, unescaped interpolation of a runtime value fail to compile rather than merely
//! being a reviewable convention. The remaining methods —
//! [`HoverMarkdown::push_number`] and [`HoverMarkdown::push_relative_age`] — accept a
//! runtime value with no cap or escaping too, but each is narrowed by its own type
//! (a sealed [`SafeNumber`], or a raw `u64` duration) to content that can structurally
//! never carry attacker-controlled text; `push_trusted` is the one remaining unchecked
//! escape hatch, and is deliberately `pub(crate)` (not exported outside `deps-core`)
//! rather than public for exactly that reason.
//!
//! This is a second, independent layer on top of [`crate::hover::Hover::new`]'s own
//! whole-document bidi/invisible-character sweep (#1277/#1309): that sweep runs once,
//! at the very end, and only ever strips the narrower `is_markdown_unsafe` set.
//! [`HoverMarkdown`] runs per-field, while the document is still being built, and closes
//! length-cap and markdown-escaping gaps — neither backstop is a substitute for the
//! other. Per-field it goes further still for name/version-shaped fields: `push_text`/
//! `push_code`/`push_label`/`push_link` additionally run
//! [`crate::net_policy::sanitize_invisible`]'s full bidi-override/invisible-character
//! sweep first when `kind`'s [`FieldKind`] says the field's shape makes that safe
//! (#1311/#1313: a name/version/identifier has no legitimate use for any `Cf`/`Zl`/`Zp`
//! character, but free-form prose can, so [`FieldKind::Prose`] opts out — see its own
//! doc).

use std::borrow::Cow;

use crate::hover::Hover;
use crate::net_policy::sanitize_invisible;
use crate::position::Range;

use super::diagnostics::{
    MAX_DIAGNOSTIC_NAME_CHARS, MAX_DIAGNOSTIC_PROSE_CHARS, MAX_VERSION_DIAGNOSTIC_CHARS,
};
use super::{escape_markdown, markdown_code_span, strip_markdown_unsafe_chars};

/// Selects the length cap a value is truncated to before rendering, and whether it is
/// swept for the full bidi-override/invisible-character class before that.
///
/// Passed to [`HoverMarkdown::push_text`], [`HoverMarkdown::push_code`],
/// [`HoverMarkdown::push_label`], and [`HoverMarkdown::push_link`].
///
/// **Length cap**: reuses the exact bounds `deps-core`'s diagnostics sinks apply to the
/// same field shapes, so a hover card and a diagnostic for the same dependency never
/// disagree on how much of an overlong value they show (#1310, following #1311's
/// per-site caps).
///
/// **Sanitization strength**: [`Self::Name`]/[`Self::Version`] additionally run the
/// value through [`sanitize_invisible`] before escaping (#1313's `sanitize_then`
/// pattern, folded into the builder). [`Self::Prose`] does not — see its own doc for
/// why. A call site declares what *kind* of field it is rendering instead of picking a
/// magic number or independently deciding whether to sanitize, either of which can
/// silently drift from the shared rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A dependency/package name, version-constraint expression, or another short
    /// identifier of the same shape (e.g. a suggested-replacement package name, a PEP
    /// 508 marker expression). Swept for invisible/bidi characters before escaping —
    /// safe because no legitimate name/identifier/expression needs one (#1313).
    Name,
    /// A version-shaped string: a manifest requirement, a resolved/latest/candidate
    /// version, or a git tag. Swept for invisible/bidi characters before escaping, for
    /// the same reason as [`Self::Name`].
    Version,
    /// Free-form prose: a deprecation reason, an OSV advisory summary or id. **Not**
    /// swept for invisible/bidi characters — only the narrower `is_markdown_unsafe` set
    /// [`Hover::new`]'s whole-document sweep already covers applies. Real prose can
    /// legitimately carry right-to-left marks (Arabic/Hebrew) or emoji ZWJ sequences
    /// that [`sanitize_invisible`]'s full `Cf`/`Zl`/`Zp` sweep would mangle (measured:
    /// it splits a ZWJ-joined emoji family into separate glyphs and breaks Persian
    /// ZWNJ word-joining) — this is the weaker of the two sanitization tiers,
    /// deliberately. An OSV advisory `id` lands here too even though it's
    /// identifier-shaped: it is out of #1311/#1313's reclassification scope (unlike
    /// `marker_expr`/`deprecation.replacement`), left as a candidate for a future pass.
    Prose,
}

impl FieldKind {
    /// The character cap this kind bounds a value to before it is rendered.
    const fn max_chars(self) -> usize {
        match self {
            Self::Name => MAX_DIAGNOSTIC_NAME_CHARS,
            Self::Version => MAX_VERSION_DIAGNOSTIC_CHARS,
            Self::Prose => MAX_DIAGNOSTIC_PROSE_CHARS,
        }
    }

    /// Whether this kind is swept with [`sanitize_invisible`] before escaping/capping —
    /// see this type's own doc for the name/version-vs-prose rationale.
    const fn sweeps_invisible(self) -> bool {
        match self {
            Self::Name | Self::Version => true,
            Self::Prose => false,
        }
    }
}

/// Accumulates one hover card's Markdown, one typed fragment at a time.
///
/// Every mutating method other than [`Self::push_static`] applies the length cap
/// and/or escaping its own doc describes — see this module's doc for why that
/// distinction is the point of this type. [`Self::finish`] hands the accumulated
/// string to [`Hover::new`], which applies its own whole-document bidi/invisible-
/// character sweep on top.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{FieldKind, HoverMarkdown};
///
/// let mut markdown = HoverMarkdown::new();
/// markdown.push_static("**Current**: ");
/// markdown.push_code("1.0.0", FieldKind::Version);
/// markdown.push_static("\n\n");
///
/// let hover = markdown.finish(None);
/// assert_eq!(hover.markdown(), "**Current**: `1.0.0`\n\n");
/// ```
#[derive(Debug, Default)]
pub struct HoverMarkdown(String);

impl HoverMarkdown {
    /// Creates an empty builder with a capacity matching a typical hover card's size.
    #[must_use]
    pub fn new() -> Self {
        Self(String::with_capacity(512))
    }

    /// Appends a compile-time string literal (or another value of type `&'static
    /// str`, e.g. [`crate::lsp_helpers::DiagnosticMessages::yanked_label`]'s return
    /// value) verbatim — structural Markdown (headers, labels, separators) rather than
    /// interpolated data, so no cap or escaping applies.
    ///
    /// The `&'static str` bound is the compile-time gate this type exists for: a
    /// `format!`-produced `String` does not have `'static` lifetime in general, so it
    /// cannot be passed here — every interpolation of a runtime value is forced
    /// through one of the typed methods below instead.
    pub fn push_static(&mut self, literal: &'static str) -> &mut Self {
        self.0.push_str(literal);
        self
    }

    /// Appends `untrusted` as escaped Markdown prose, truncated to `kind`'s cap.
    ///
    /// When `kind.sweeps_invisible()` (see [`FieldKind`]'s doc), `untrusted` is first
    /// run through [`sanitize_invisible`] — a 1:1 character mapping, so it cannot shift
    /// a truncation boundary, hence sweep-then-truncate-then-escape is order-safe.
    /// Truncates the (possibly swept) *raw* value first, then escapes the result —
    /// bounding the same raw-character count `deps-core`'s diagnostics sinks bound for
    /// the same field shape, matching
    /// [`crate::lsp_helpers::sanitize_and_truncate_for_diagnostic`]'s order. Use
    /// [`Self::push_label`] instead when the value is short, rendered, user-visible
    /// text (a name) where the *rendered* length must stay bounded.
    pub fn push_text(&mut self, untrusted: &str, kind: FieldKind) -> &mut Self {
        let swept = sweep_if(untrusted, kind);
        let truncated = super::diagnostics::truncate_for_diagnostic(&swept, kind.max_chars());
        self.0.push_str(&escape_markdown(&truncated));
        self
    }

    /// Appends `untrusted` as a Markdown code span (`` `like this` ``), truncated to
    /// `kind`'s cap.
    ///
    /// Sweeps first (when `kind.sweeps_invisible()`), then truncates, then wraps — same
    /// order and rationale as [`Self::push_text`]. The intended method for version/tag-
    /// shaped values, which this crate always renders as code spans.
    pub fn push_code(&mut self, untrusted: &str, kind: FieldKind) -> &mut Self {
        let swept = sweep_if(untrusted, kind);
        let truncated = super::diagnostics::truncate_for_diagnostic(&swept, kind.max_chars());
        self.0.push_str(&markdown_code_span(&truncated));
        self
    }

    /// Appends `untrusted` as escaped, plain (non-code-span) rendered text, capping the
    /// *escaped* result to `kind`'s length.
    ///
    /// Sweeps first (when `kind.sweeps_invisible()`), then escapes, then truncates —
    /// the opposite escape/truncate order from [`Self::push_text`], deliberately:
    /// `escape_markdown` backslash-escapes every ASCII punctuation character (common in
    /// names: `-`, `_`, `.`, `@`), which can more than double a short raw value's
    /// length. Capping the raw length first would leave the *rendered* text unbounded;
    /// this method bounds what is actually shown instead, at the cost of a possible
    /// trailing lone backslash on the rare cut landing between an escape's backslash
    /// and its punctuation character (cosmetic only, since this is plain text, not a
    /// link destination — see [`Self::push_link`]). The sweep always runs first
    /// regardless: it is a 1:1 character mapping, so its position relative to the
    /// escape/truncate order doesn't change the final bound, but it must still run
    /// *before* `escape_markdown` (escaping doesn't neutralize an invisible character).
    pub fn push_label(&mut self, untrusted: &str, kind: FieldKind) -> &mut Self {
        self.0.push_str(&capped_escaped_label(untrusted, kind));
        self
    }

    /// Appends a Markdown link, `[label](url)`.
    ///
    /// `label` is swept (when `kind.sweeps_invisible()`), capped, and escaped exactly
    /// like [`Self::push_label`] (rendered-length bound). `url` is passed through
    /// [`crate::lsp_helpers::strip_markdown_unsafe_chars`] only — **never** length-capped:
    /// an earlier version of the hover header's link truncated the destination at a
    /// fixed raw-character boundary, which broke legitimate long, non-malicious links
    /// (a Go module path or an npm scoped package routinely exceeds 128 chars) and, not
    /// being percent-encoding-aware, could cut inside a `%XX` escape and leave a
    /// structurally malformed dangling `%X`. Preserve this asymmetry in any new call
    /// site: capping `url` here would reintroduce that regression.
    ///
    /// # `url` is not fully sanitized here — caller obligation
    ///
    /// `strip_markdown_unsafe_chars` covers **only** the narrow bidi-override/invisible
    /// character subset `is_markdown_unsafe` names — it is consumer-side defense-in-depth,
    /// not the primary gate. It does **not** guard the
    /// *structural* Markdown breakout set (`(`, `)`, `[`, `]`, `` ` ``, `<`, `>`): a `url`
    /// containing an unescaped `)` breaks out of the link destination early. Every
    /// existing caller passes a `url` that already went through a producer-side gate
    /// before reaching this method — an `EcosystemFormatter::package_url` implementation
    /// (required to pass `crate::conformance::assert_package_url_hostile_input_safe`) or
    /// an equivalent allowlist/percent-encoding gate (e.g. `is_safe_registry_url`, the
    /// gate `completion::build_package_completion` applies to a registry-supplied
    /// `repository`/`documentation` URL, #1285). **A new call site must gate `url`
    /// through one of these *before* calling `push_link`** — this method does not, and
    /// cannot without reintroducing the length-cap regression above, do it for you.
    /// `strip_markdown_unsafe_chars`, not [`escape_markdown`]: full Markdown escaping
    /// backslash-escapes every ASCII punctuation character, mangling an ordinary,
    /// non-malicious URL's `/`/`:`/`.`; and space-substitution (correct for label/code-span
    /// *text*) is wrong for a link *destination*, where CommonMark forbids an unescaped
    /// literal space outright, so a fired substitution would turn the link into broken
    /// non-link text instead of sanitizing it in place — stripping keeps the surrounding
    /// URL syntactically valid instead.
    pub fn push_link(&mut self, label: &str, kind: FieldKind, url: &str) -> &mut Self {
        use std::fmt::Write as _;

        let capped_label = capped_escaped_label(label, kind);
        let _ = write!(
            self.0,
            "[{capped_label}]({})",
            strip_markdown_unsafe_chars(url)
        );
        self
    }

    /// Appends `value` verbatim, with no cap or escaping.
    ///
    /// `pub(crate)`, **not** `pub` (#1310 critic S1): a generic "trust me" sink taking
    /// any `impl AsRef<str>` would be strictly more permissive than [`Self::push_static`]
    /// and reachable from every ecosystem crate through [`HoverMarkdown`]'s otherwise-public
    /// API, reopening the exact raw-interpolation gap this type exists to close. Kept
    /// internal to `deps-core` for the one legitimate remaining shape: the *already*
    /// capped-and-escaped output of a helper that sanitizes its own inputs before
    /// returning — e.g. `lsp_helpers::hover::format_license_list`/`format_advisory_aliases`,
    /// whose every element already went through [`super::diagnostics::truncate_for_diagnostic`]
    /// and [`escape_markdown`]/[`markdown_code_span`] before being joined. Even at this
    /// narrower visibility, only call it with such a helper's return value — never with a
    /// raw `format!` of untrusted data; use [`Self::push_text`]/[`Self::push_code`] for
    /// that, or [`Self::push_number`]/[`Self::push_relative_age`] for structurally-safe
    /// numeric/duration content.
    pub(crate) fn push_trusted(&mut self, value: impl AsRef<str>) -> &mut Self {
        self.0.push_str(value.as_ref());
        self
    }

    /// Appends a primitive numeric value's `Display` output verbatim: no cap or escaping
    /// applies, but none is needed since [`SafeNumber`] is implemented only for types
    /// whose rendered form can never contain a Markdown-special character (unlike
    /// `push_trusted`, a `String` cannot be passed here).
    pub fn push_number(&mut self, value: impl SafeNumber) -> &mut Self {
        use std::fmt::Write as _;
        let _ = write!(self.0, "{value}");
        self
    }

    /// Appends a relative-age phrase (e.g. `"3 days ago"`), formatted from `age_secs` via
    /// [`crate::format_relative_age`].
    ///
    /// Structurally safe with no cap/escaping needed: `age_secs` is always a duration this
    /// crate computed itself (a registry-reported publish timestamp subtracted from "now"),
    /// and `format_relative_age`'s own implementation is the sole source of the phrase's
    /// fixed vocabulary — unlike [`Self::push_text`]/[`Self::push_code`], no untrusted text
    /// ever passes through the call site.
    pub fn push_relative_age(&mut self, age_secs: u64) -> &mut Self {
        self.0.push_str(&crate::format_relative_age(age_secs));
        self
    }

    /// Returns the Markdown accumulated so far.
    ///
    /// For tests and for a caller that needs to inspect the in-progress document (e.g.
    /// checking whether a footer was already appended) before continuing to build it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the builder, handing its accumulated Markdown to [`Hover::new`].
    ///
    /// [`Hover::new`] applies its own whole-document bidi/invisible-character sweep on
    /// top of every per-field cap/escape this type already applied — see this module's
    /// doc for why both layers are needed.
    #[must_use]
    pub fn finish(self, range: Option<Range>) -> Hover {
        Hover::new(self.0, range)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Marker for a primitive numeric type safe to render via [`HoverMarkdown::push_number`]
/// with no cap or escaping.
///
/// Sealed (implemented only inside this crate, for `usize`/`u64`/`i64`/`f64`) so a type
/// whose `Display` output *could* carry Markdown-special characters — most importantly
/// `String` itself — cannot be passed to `push_number`, closing the loophole a bare
/// `impl Display` bound would leave open (#1310 critic S1).
pub trait SafeNumber: sealed::Sealed + std::fmt::Display {}

macro_rules! impl_safe_number {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl SafeNumber for $ty {}
        )+
    };
}

impl_safe_number!(usize, u64, i64, f64);

impl std::fmt::Display for HoverMarkdown {
    /// Writes the Markdown accumulated so far — the same value [`HoverMarkdown::as_str`]
    /// returns.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shared sweep-then-escape-then-truncate logic for [`HoverMarkdown::push_label`] and
/// [`HoverMarkdown::push_link`]'s label half — see [`HoverMarkdown::push_label`]'s doc
/// for why the escape/truncate order is the opposite of [`HoverMarkdown::push_text`]'s.
fn capped_escaped_label(untrusted: &str, kind: FieldKind) -> Cow<'static, str> {
    let escaped = escape_markdown(&sweep_if(untrusted, kind));
    match super::diagnostics::truncate_for_diagnostic(&escaped, kind.max_chars()) {
        Cow::Borrowed(_) => Cow::Owned(escaped),
        Cow::Owned(truncated) => Cow::Owned(truncated),
    }
}

/// Applies [`sanitize_invisible`] to `untrusted` when `kind.sweeps_invisible()`, else
/// returns it unchanged — the one place [`FieldKind`]'s sanitization-strength axis is
/// read, shared by [`HoverMarkdown::push_text`]/[`HoverMarkdown::push_code`]/
/// [`capped_escaped_label`].
fn sweep_if(untrusted: &str, kind: FieldKind) -> Cow<'_, str> {
    if kind.sweeps_invisible() {
        sanitize_invisible(untrusted)
    } else {
        Cow::Borrowed(untrusted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_static_appends_verbatim() {
        let mut markdown = HoverMarkdown::new();
        markdown.push_static("# hello");
        assert_eq!(markdown.as_str(), "# hello");
    }

    #[test]
    fn push_text_truncates_raw_value_then_escapes() {
        let long = "a-b.".repeat(200);
        let mut markdown = HoverMarkdown::new();
        markdown.push_text(&long, FieldKind::Prose);
        let rendered = markdown.as_str();
        assert!(rendered.contains('…'));
        // Escaping happens after truncation, so every escaped `-`/`.` is still present
        // right up to the truncation point.
        assert!(rendered.starts_with("a\\-b\\."));
    }

    #[test]
    fn push_code_wraps_in_a_code_span_and_truncates() {
        let long = "9".repeat(5000);
        let mut markdown = HoverMarkdown::new();
        markdown.push_code(&long, FieldKind::Version);
        let rendered = markdown.as_str();
        assert!(rendered.starts_with('`'));
        assert!(rendered.contains('…'));
        assert!(rendered.len() < long.len());
    }

    #[test]
    fn push_label_bounds_the_rendered_escaped_length() {
        // Every character escapes to two, so the raw length is far short of the cap
        // but the escaped/rendered length would exceed it without label's order.
        let long = "-".repeat(200);
        let mut markdown = HoverMarkdown::new();
        markdown.push_label(&long, FieldKind::Name);
        let rendered = markdown.as_str();
        assert!(
            rendered.chars().count() <= FieldKind::Name.max_chars() + 1,
            "rendered label must be bounded by the cap (plus the ellipsis marker); got {} chars",
            rendered.chars().count()
        );
    }

    /// #1310 critic M2: a boundary test per [`FieldKind`], not just the 5000-char
    /// extreme, so an off-by-one in [`FieldKind::max_chars`]'s truncation or a swapped
    /// kind would actually be caught (all three kinds happen to resolve to the same
    /// literal cap today, so an extreme-only test can't distinguish them).
    #[test]
    fn push_code_boundary_at_and_over_cap_for_every_field_kind() {
        for kind in [FieldKind::Name, FieldKind::Version, FieldKind::Prose] {
            let cap = kind.max_chars();

            let at_cap = "9".repeat(cap);
            let mut markdown = HoverMarkdown::new();
            markdown.push_code(&at_cap, kind);
            assert_eq!(
                markdown.as_str(),
                format!("`{at_cap}`"),
                "kind={kind:?}: a value exactly at the cap must render whole"
            );

            let under_cap = "9".repeat(cap - 1);
            let mut markdown = HoverMarkdown::new();
            markdown.push_code(&under_cap, kind);
            assert_eq!(markdown.as_str(), format!("`{under_cap}`"), "kind={kind:?}");

            let over_cap = "9".repeat(cap + 1);
            let mut markdown = HoverMarkdown::new();
            markdown.push_code(&over_cap, kind);
            assert_eq!(
                markdown.as_str(),
                format!("`{}…`", "9".repeat(cap)),
                "kind={kind:?}: a value one over the cap must truncate to exactly `cap` \
                 chars plus the ellipsis marker"
            );
        }
    }

    /// See [`push_code_boundary_at_and_over_cap_for_every_field_kind`] — same rationale,
    /// for [`HoverMarkdown::push_text`]'s truncate-then-escape order.
    #[test]
    fn push_text_boundary_at_and_over_cap_for_every_field_kind() {
        for kind in [FieldKind::Name, FieldKind::Version, FieldKind::Prose] {
            let cap = kind.max_chars();

            let at_cap = "9".repeat(cap);
            let mut markdown = HoverMarkdown::new();
            markdown.push_text(&at_cap, kind);
            assert_eq!(markdown.as_str(), at_cap, "kind={kind:?}");

            let over_cap = "9".repeat(cap + 1);
            let mut markdown = HoverMarkdown::new();
            markdown.push_text(&over_cap, kind);
            assert_eq!(
                markdown.as_str(),
                format!("{}…", "9".repeat(cap)),
                "kind={kind:?}"
            );
        }
    }

    /// Complements [`push_label_bounds_the_rendered_escaped_length`] with the other
    /// boundary side: a value whose *escaped* length lands exactly at the cap must
    /// render whole, not truncated.
    #[test]
    fn push_label_stays_whole_when_escaped_length_is_exactly_at_the_cap() {
        // Every `-` escapes to `\-` (2 chars), so `cap / 2` dashes escape to exactly `cap`.
        let half = FieldKind::Name.max_chars() / 2;
        let at_cap = "-".repeat(half);
        let mut markdown = HoverMarkdown::new();
        markdown.push_label(&at_cap, FieldKind::Name);
        let rendered = markdown.as_str();
        assert_eq!(rendered.chars().count(), FieldKind::Name.max_chars());
        assert!(!rendered.contains('…'));
    }

    #[test]
    fn push_link_caps_label_but_not_url() {
        let long_url = format!("https://example.com/{}", "a".repeat(5000));
        let mut markdown = HoverMarkdown::new();
        markdown.push_link("serde", FieldKind::Name, &long_url);
        let rendered = markdown.as_str();
        assert!(rendered.starts_with("[serde]("));
        assert!(
            rendered.contains(&long_url),
            "url must not be truncated; got: {rendered}"
        );
    }

    /// #1311/#1313: a `sanitize_invisible`-only codepoint — one `is_markdown_unsafe`
    /// (`Hover::new`'s whole-document sweep) does **not** name, so it survives that
    /// sweep untouched — must still be stripped from `Name`/`Version`-kind fields via
    /// the sweep `push_code`/`push_text`/`push_label` now apply. U+0600 (ARABIC NUMBER
    /// SIGN) is one such codepoint — #1323 widened `is_markdown_unsafe` to close
    /// several other such gaps, but U+0600 remains deliberately exempt from it (a
    /// genuine Arabic prefixed-format sign, #1248), so it still pins this property.
    #[test]
    fn push_code_strips_sanitize_invisible_only_codepoints_for_name_and_version_kinds() {
        for kind in [FieldKind::Name, FieldKind::Version] {
            let mut markdown = HoverMarkdown::new();
            markdown.push_code(&format!("1.0{}0", '\u{0600}'), kind);
            assert!(
                !markdown.as_str().contains('\u{0600}'),
                "kind={kind:?}: U+0600 must be stripped; got: {markdown}"
            );
        }
    }

    /// `FieldKind::Prose` must **not** be swept: real prose can legitimately carry
    /// emoji ZWJ sequences and RTL marks that `sanitize_invisible`'s full
    /// `Cf`/`Zl`/`Zp` sweep would mangle (security's empirical finding — a ZWJ-joined
    /// emoji family splits into separate glyphs, an RTL mark is stripped outright).
    /// Also pins that U+0600 (ARABIC NUMBER SIGN, a `sanitize_invisible`-stripped
    /// codepoint `is_markdown_unsafe` deliberately still exempts, #1248/#1323) survives
    /// in `Prose` — a deliberate trade-off, not a regression, since `Prose` only ever
    /// gets the narrower whole-document sweep.
    #[test]
    fn push_text_does_not_sweep_prose_preserving_zwj_and_rtl_marks_and_u0600() {
        let zwj_emoji = "👨\u{200d}👩\u{200d}👧"; // family emoji, ZWJ-joined
        let mut markdown = HoverMarkdown::new();
        markdown.push_text(zwj_emoji, FieldKind::Prose);
        assert_eq!(
            markdown.as_str(),
            zwj_emoji,
            "a ZWJ-joined emoji sequence must survive Prose unchanged"
        );

        let rtl_mark = format!("note{}: right-to-left", '\u{200f}');
        let mut markdown = HoverMarkdown::new();
        markdown.push_text(&rtl_mark, FieldKind::Prose);
        assert!(
            markdown.as_str().contains('\u{200f}'),
            "an RTL mark must survive Prose unchanged; got: {markdown}"
        );

        let mut markdown = HoverMarkdown::new();
        markdown.push_text(&format!("note{}", '\u{0600}'), FieldKind::Prose);
        assert!(
            markdown.as_str().contains('\u{0600}'),
            "U+0600 survives in Prose by design (weaker sanitization tier); got: {markdown}"
        );
    }

    #[test]
    fn push_trusted_appends_verbatim_with_no_cap() {
        let long = "9".repeat(5000);
        let mut markdown = HoverMarkdown::new();
        markdown.push_trusted(&long);
        assert_eq!(markdown.as_str(), long);
    }

    #[test]
    fn push_number_appends_display_output_verbatim() {
        let mut markdown = HoverMarkdown::new();
        markdown.push_number(42_usize);
        assert_eq!(markdown.as_str(), "42");

        let mut markdown = HoverMarkdown::new();
        markdown.push_number(8.5_f64);
        assert_eq!(markdown.as_str(), "8.5");
    }

    #[test]
    fn push_relative_age_matches_format_relative_age() {
        let mut markdown = HoverMarkdown::new();
        markdown.push_relative_age(3600);
        assert_eq!(markdown.as_str(), crate::format_relative_age(3600));
    }

    #[test]
    fn finish_hands_off_to_hover_and_still_sanitizes_bidi_overrides() {
        let mut markdown = HoverMarkdown::new();
        markdown.push_static("safe");
        markdown.push_trusted(format!("{}text", '\u{202e}'));
        let hover = markdown.finish(None);
        assert!(!hover.markdown().contains('\u{202e}'));
    }
}
