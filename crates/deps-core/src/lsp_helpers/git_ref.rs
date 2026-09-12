//! Shared git-tags-datasource parser scaffolding, extracted from
//! `deps-github-actions`'s originally crate-private `parser.rs`/`formatter.rs` helpers so a
//! second git-tags-shaped ecosystem (GitLab CI) can reuse the same hardened span/text
//! plumbing instead of forking it. `deps-github-actions` now imports these instead of
//! defining them locally.

use super::LineOffsetTable;

/// Length of a full, lowercase-or-not hex commit SHA (git's SHA-1 object id).
const SHA_LEN: usize = 40;

/// Whether `s` is a 40-character hex string — a git commit SHA shape, shared by every
/// ecosystem resolving refs against a git-tags-datasource API (GitHub, GitLab).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_full_sha;
///
/// assert!(is_full_sha(&"a".repeat(40)));
/// assert!(!is_full_sha(&"a".repeat(39)));
/// assert!(!is_full_sha("not-a-sha"));
/// ```
#[must_use]
pub fn is_full_sha(s: &str) -> bool {
    s.len() == SHA_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `s` has the shape of a tag ref: an optional leading `v`/`V` followed by a digit.
///
/// Anything else (that isn't an [`is_full_sha`] SHA) is treated as a branch name — the
/// "honest unknown" side, since a branch cannot be resolved to a concrete version without
/// registry access.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_tag_shaped;
///
/// assert!(is_tag_shaped("v4"));
/// assert!(is_tag_shaped("4.2.0"));
/// assert!(!is_tag_shaped("main"));
/// assert!(!is_tag_shaped(&"a".repeat(40)));
/// ```
#[must_use]
pub fn is_tag_shaped(s: &str) -> bool {
    if is_full_sha(s) {
        return false;
    }
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    stripped.starts_with(|c: char| c.is_ascii_digit())
}

/// Rewrites `tag` to match `current`'s leading `v`/`V` prefix style (or lack of one).
///
/// A repository/project can change its tagging convention over time (`4.0.0` -> `v5.0.0`);
/// a formatted replacement should still read naturally against the user's existing pin
/// style rather than silently flipping it.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::match_v_prefix_style;
///
/// assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
/// assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
/// ```
// `tag[1..]` only runs when `tag_has_v` (an ASCII 'v'/'V' prefix check), so index 1 is
// always a char boundary.
#[allow(clippy::string_slice)]
#[must_use]
pub fn match_v_prefix_style(current: &str, tag: &str) -> String {
    let current_has_v = current.starts_with(['v', 'V']);
    let tag_has_v = tag.starts_with(['v', 'V']);
    match (current_has_v, tag_has_v) {
        (true, false) => format!("v{tag}"),
        (false, true) => tag[1..].to_string(),
        _ => tag.to_string(),
    }
}

/// Resolves a `yaml-rust2` scanner marker's `(line, col)` position into a byte offset in
/// `content`, via a shared, once-per-document [`LineOffsetTable`].
///
/// Deliberately does **not** use `yaml_rust2::scanner::Marker::index()` — despite its own
/// doc comment claiming a byte count, `Scanner::scan_block_scalar_content_line`
/// (`yaml-rust2` 0.12.0's `scanner.rs:1778-1779`) advances `mark.index` by the **byte**
/// length of each block-scalar (`|`/`>`) content line, not its char count, once the
/// scanner's internal 16-char lookahead buffer empties mid-line — which happens on
/// essentially every real content line. Every multi-byte UTF-8 character consumed this way
/// desyncs `index` permanently for the rest of the document (#879). `Marker::line()`/
/// `Marker::col()` are unaffected: `col` resets to `0` on every line break
/// (`Scanner::skip_nl`), so the corruption from one block-scalar content line never carries
/// into a later scalar's own `col` — safe for every value this crate resolves spans for
/// (`uses:`, `ref:`, `project:`, `include:`), none of which are themselves inside a block
/// scalar's own content.
///
/// This `line`/`col`-based resolver is a workaround for an upstream `yaml-rust2` 0.12.0 bug
/// (tracked in #880, not yet reported upstream). Do not simplify this back to
/// `Marker::index()`-based resolution without first checking whether the upstream bug has
/// been fixed.
///
/// `line` is 1-indexed and `col` a 0-indexed **char** count within that line, matching
/// `yaml-rust2`'s own `Marker::line()`/`Marker::col()` *behavior* — note that
/// `yaml_rust2::scanner::Marker::col()`'s own doc comment claims 1-indexed while its `Display`
/// impl prints `col + 1`, i.e. the doc is wrong the same way `index()`'s was; do not "fix" the
/// `col.min(...)`/`.nth(col)` arithmetic below to match that prose. Returns `content.len()` if
/// `line` is past the end of `content`. `line` must be `>= 1` (see `debug_assert!` below) —
/// every marker `yaml-rust2` actually emits satisfies this.
///
/// # Line-ending assumption
///
/// Like every other [`LineOffsetTable`] lookup, this counts only `\n` as a line break. A
/// document using bare `\r` (no `\n`) line endings is out of scope: `yaml-rust2` still
/// advances `mark.line` across such a break (`Scanner::skip_nl`), but `LineOffsetTable::new`
/// never splits on a lone `\r`, so `line` can run past the table's line count for any content
/// after the first line — this function then falls back to `content.len()`, and the caller's
/// [`locate_value_span`] fails to find the value, dropping the candidate (logged at `debug`
/// — see its own doc comment) the same way as any other fallback-scan miss.
/// Bare-`\r` YAML is not a realistic manifest shape; LF and CRLF, which `yaml-rust2` and this
/// crate both handle throughout, are unaffected.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, marker_byte_offset};
///
/// let content = "a: b\nc: \u{2014}d\n";
/// let table = LineOffsetTable::new(content);
/// // Line 2 ("c: \u{2014}d"), char column 4 -> the 'd' right after the multi-byte em dash.
/// assert_eq!(marker_byte_offset(content, &table, 2, 4), content.find('d').unwrap());
/// ```
#[must_use]
pub fn marker_byte_offset(
    content: &str,
    table: &LineOffsetTable,
    line: usize,
    col: usize,
) -> usize {
    debug_assert!(line >= 1, "yaml-rust2 marker line is 1-indexed, got 0");
    let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
        return content.len();
    };
    let line_end = table.line_start(line).unwrap_or(content.len());
    let line_text = content.get(line_start..line_end).unwrap_or_default();
    // #742-style fast path: an ASCII line has 1 byte per char, so `col` (a char count) is
    // already a byte offset — skip the `char_indices()` walk entirely. Without this,
    // `marker_byte_offset` was O(line length) per call, turning a wide single-line manifest
    // (the exact shape `MAX_FALLBACK_SCAN_BYTES` was bounded against) back into an O(n^2)
    // parse.
    let byte_in_line = if table
        .line_is_ascii
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or(false)
    {
        col.min(line_text.len())
    } else {
        // #882: a non-ASCII line falls back to a char-boundary walk, but a naive
        // `char_indices().nth(col)` per call is O(line length), turning N lookups on the
        // same wide non-ASCII line into O(N x line length). `LineOffsetTable`'s cached
        // per-line index makes every lookup after the first on a given line O(1).
        table.non_ascii_char_byte_offset(line.saturating_sub(1), line_text, col)
    };
    line_start + byte_in_line
}

/// Upper bound, in bytes past `search_from`, on how far [`locate_value_span`]'s fallback
/// scan will search.
///
/// The fallback exists only to correct for `yaml-rust2`'s marker-vs-value quoting offset —
/// a handful of bytes at most for any real manifest value. Leaving the scan unbounded made
/// it an `O(line_length x value_length)` scan over the *rest of the line* regardless of how
/// far away the real match could possibly be: a several-megabyte single-line manifest
/// (comfortably under the crate's YAML expansion-size gate) could cost whole minutes of
/// single-core CPU per `didOpen`/`didChange` (security S-2). Capping the window bounds the
/// fallback's cost independent of line length; a value that genuinely cannot be located
/// within this window is treated the same as any other unlocatable value — the candidate is
/// silently skipped, not an error.
pub const MAX_FALLBACK_SCAN_BYTES: usize = 1024;

/// Finds the byte offset in `content` (searching only within the line starting at
/// `search_from`) where the literal bytes of `value` occur.
///
/// The scanner-reported marker usually points exactly at the value's start for a plain
/// scalar, but may point at the opening quote for a quoted one — rather than
/// reverse-engineering `yaml-rust2`'s exact escaping/quoting byte accounting, this verifies
/// the direct-offset guess first and falls back to a bounded same-line search (see
/// [`MAX_FALLBACK_SCAN_BYTES`]), which is exact for the unescaped ASCII text most manifest
/// values are.
///
/// Returns `None` if `search_from` is past the end of `content` (checked first, before the
/// `value.is_empty()` short-circuit below — #673 M2) or `value` cannot be located within
/// the bounded fallback scan — logged at `debug` (value length only, never the value text
/// itself, matching the `warn_rejected_value` convention) so a future resolver miss (e.g.
/// #879's class of bug, or [`marker_byte_offset`]'s documented bare-`\r` gap) is diagnosable
/// instead of vanishing the candidate with zero trace.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::locate_value_span;
///
/// let content = "prefix xxxxx actions/checkout@v4 suffix";
/// let (start, end) = locate_value_span(content, 0, "actions/checkout@v4").unwrap();
/// assert_eq!(&content[start..end], "actions/checkout@v4");
/// ```
#[must_use]
pub fn locate_value_span(content: &str, search_from: usize, value: &str) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    // `search_from` is a caller-supplied byte offset (`#673`: this is a `pub fn`, so its
    // bound is not otherwise mechanically guaranteed) — reject it upfront, before the
    // `value.is_empty()` case below, rather than letting either slice further down panic on
    // an out-of-range start index (#673 M2: this must run first, or an empty `value` would
    // return `Some((search_from, search_from))` unchecked for an out-of-range `search_from`).
    if search_from > bytes.len() {
        tracing::debug!(
            search_from,
            content_len = bytes.len(),
            "locate_value_span: search_from past end of content"
        );
        return None;
    }
    if value.is_empty() {
        return Some((search_from, search_from));
    }
    // Every slice/index from here on is bounds-checked by the `search_from <= bytes.len()`
    // guard above combined with each expression's own `<=`/`.min(...)` clamp.
    #[allow(clippy::indexing_slicing)]
    {
        if search_from + value.len() <= bytes.len()
            && &bytes[search_from..search_from + value.len()] == value.as_bytes()
        {
            return Some((search_from, search_from + value.len()));
        }
    }
    // Bound the window *before* searching for '\n', not after (issue #885 rework):
    // searching the whole remainder of `content` for the next real newline before
    // clamping to `MAX_FALLBACK_SCAN_BYTES` made that clamp limit only `scan_end`'s
    // *value*, not the cost of computing it — the `position()` scan itself still ran
    // the full remaining-line length. On a single huge physical line (#885's own
    // shape), this reintroduced the same O(remaining-document-length)-per-call cost
    // the cap exists to prevent. Bounding first makes `position()` itself
    // O(`MAX_FALLBACK_SCAN_BYTES`); the resulting `scan_end` is identical either way
    // (`min` is order-independent), so this is a pure performance fix, no behavior
    // change. Guarded by the `search_from <= bytes.len()` check above.
    #[allow(clippy::indexing_slicing)]
    let window_end = bytes
        .len()
        .min(search_from.saturating_add(MAX_FALLBACK_SCAN_BYTES));
    #[allow(clippy::indexing_slicing)]
    let scan_end = bytes[search_from..window_end]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(window_end, |p| search_from + p);
    #[allow(clippy::indexing_slicing)]
    let haystack = &bytes[search_from..scan_end];
    let needle = value.as_bytes();
    let found = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| (search_from + rel, search_from + rel + needle.len()));
    if found.is_none() {
        tracing::debug!(
            search_from,
            value_len = needle.len(),
            scan_bytes = scan_end - search_from,
            "locate_value_span: value not found within bounded fallback scan"
        );
    }
    found
}

#[cfg(test)]
// Fixtures are single-line ASCII literals with hand-computed byte offsets.
#[allow(clippy::string_slice)]
mod tests {
    use super::*;

    #[test]
    fn test_is_full_sha_accepts_and_rejects() {
        assert!(is_full_sha(&"a".repeat(40)));
        assert!(!is_full_sha(&"a".repeat(39)));
        assert!(!is_full_sha(&"g".repeat(40)));
    }

    #[test]
    fn test_is_tag_shaped() {
        assert!(is_tag_shaped("v4"));
        assert!(is_tag_shaped("4.2.0"));
        assert!(!is_tag_shaped("main"));
        assert!(!is_tag_shaped(&"a".repeat(40)));
    }

    #[test]
    fn test_match_v_prefix_style() {
        assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
        assert_eq!(match_v_prefix_style("v4", "v5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "5.0.0"), "5.0.0");
    }

    #[test]
    fn test_locate_value_span_finds_value_within_fallback_bound() {
        let content = "prefix xxxxx actions/checkout@v4 suffix";
        let value = "actions/checkout@v4";
        let (start, end) = locate_value_span(content, 0, value).unwrap();
        assert_eq!(&content[start..end], value);
    }

    #[test]
    fn test_locate_value_span_out_of_bounds_search_from_rejected_even_with_empty_value() {
        // #673 M2: the `search_from > bytes.len()` guard must run before the
        // `value.is_empty()` early return, or this returned `Some((usize::MAX, usize::MAX))`.
        let content = "short";
        assert_eq!(locate_value_span(content, usize::MAX, ""), None);
        assert_eq!(locate_value_span(content, content.len() + 1, ""), None);
    }

    #[test]
    fn test_locate_value_span_gives_up_beyond_fallback_bound_instead_of_hanging() {
        let filler = "x".repeat(MAX_FALLBACK_SCAN_BYTES + 100);
        let value = "actions/checkout@v4";
        let content = format!("{filler}{value}");
        assert_eq!(locate_value_span(&content, 0, value), None);
    }

    #[test]
    fn test_locate_value_span_bounded_scan_stays_fast_on_a_huge_line() {
        // Regression guard for the quadratic blowup itself (security S-2): a
        // several-megabyte single-line haystack (well under the crate's YAML
        // expansion-size gate) must resolve in milliseconds, not minutes, once the scan
        // is bounded.
        let filler = "y".repeat(6 * 1024 * 1024);
        let value = "not-present-in-filler@v4";
        let content = format!("{filler}\n");
        let start = std::time::Instant::now();
        let result = locate_value_span(&content, 0, value);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "locate_value_span took {:?}, expected a bounded scan to finish in well under 1s",
            start.elapsed()
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_locate_value_span_many_fallback_scans_on_one_huge_line_stay_bounded() {
        // Regression for #885's rework (S2 finding): the pre-fix code searched the
        // whole remainder of `content` for the next real newline *before* clamping
        // to `MAX_FALLBACK_SCAN_BYTES`, so on a single huge physical line with no
        // real newline nearby, each fallback-triggering call (the quoted-scalar
        // case, where the direct-offset check misses and this scan runs) still cost
        // O(remaining-document-length) despite the cap. Simulates many quoted
        // `uses:`-shaped dependencies spread across one multi-megabyte single-line
        // manifest, each forcing the fallback path since `value` never matches at
        // its own `search_from`.
        let filler_segment = "z".repeat(64);
        let mut content = String::new();
        let mut offsets = Vec::new();
        for _ in 0..2000 {
            offsets.push(content.len());
            content.push_str(&filler_segment);
        }
        content.push_str(&"w".repeat(8 * 1024 * 1024));
        let value = "actions/checkout@v4";

        let start = std::time::Instant::now();
        for &offset in &offsets {
            let _ = locate_value_span(&content, offset, value);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "{} locate_value_span fallback calls against an 8MB-tail single line took \
             {elapsed:?}; expected the pre-bound window to make each call's cost \
             independent of the trailing content size",
            offsets.len()
        );
    }

    #[test]
    fn test_marker_byte_offset_ascii() {
        let content = "hello\nworld";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 1, 0), 0);
        assert_eq!(marker_byte_offset(content, &table, 2, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_multibyte() {
        let content = "\u{3000}a\nb";
        let table = LineOffsetTable::new(content);
        // U+3000 is 3 bytes; the second char ('a') on line 1 starts at byte 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 1), 3);
        // Line 2 ('b') starts right after the '\n'.
        assert_eq!(marker_byte_offset(content, &table, 2, 0), 5);
    }

    #[test]
    fn test_marker_byte_offset_block_scalar_drift_regression() {
        // #879: a non-ASCII char inside a `|` block scalar content line must not desync the
        // byte offset resolved for a later scalar on the same document — this reproduces the
        // upstream yaml-rust2 Marker::index() drift scenario using line/col directly, which
        // must stay immune to it.
        let content = "run: |\n  echo \u{2014} hi\nuses: actions/checkout@v4\n";
        let table = LineOffsetTable::new(content);
        // Line 3, col 6 is where "actions/checkout@v4" starts (after "uses: ").
        let expected = content.find("actions/checkout@v4").unwrap();
        assert_eq!(marker_byte_offset(content, &table, 3, 6), expected);
    }

    #[test]
    fn test_marker_byte_offset_line_past_end_returns_content_len() {
        let content = "hello";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 5, 0), content.len());
    }

    #[test]
    fn test_marker_byte_offset_multiple_multibyte_chars_before_target_col() {
        // Several multi-byte chars precede the target column within the same line — each
        // must be counted as one *char*, not its own UTF-8 byte length, when walking to
        // `col` (#879's exact failure mode, direct on the resolver rather than through a
        // full yaml-rust2 parse).
        let content = "\u{2014}\u{2014}\u{3000}target";
        let table = LineOffsetTable::new(content);
        // 3 leading multi-byte chars (3 + 3 + 3 = 9 bytes), then "target" starts at char
        // column 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_col_past_end_of_line_clamps_to_line_end() {
        let content = "ab\ncd";
        let table = LineOffsetTable::new(content);
        // Line 1 ("ab") has only 2 chars; a col past that clamps to the line span's byte
        // end (`table.line_start(1)`, i.e. right after the '\n', where the next line
        // starts), rather than panicking or reading past that into line 2's content.
        assert_eq!(marker_byte_offset(content, &table, 1, 100), 3);
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_matches_char_indices_result() {
        // Differential test: the `line_is_ascii` fast path (`col.min(line_text.len())`) must
        // agree with the pre-S1 general `char_indices().nth(col)` walk (reimplemented here,
        // verbatim, independent of `marker_byte_offset`'s own fast-path branch) for every
        // column on an ASCII line, including an overshoot past the line's end — the exact
        // class of desync S1's fix could silently introduce if the two arms ever diverged.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "uses: actions/checkout@v4\nref: v1.0.0\n";
        let table = LineOffsetTable::new(content);
        for col in 0..=35 {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "ascii fast path desynced from the general char_indices() walk at col {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_stays_linear_on_a_huge_single_line() {
        // Regression guard for S1 (impl-critic, #879 follow-up): without the `line_is_ascii`
        // fast path, `marker_byte_offset` was O(line length) per call via
        // `char_indices().nth(col)`, reintroducing the same O(n^2) shape
        // `MAX_FALLBACK_SCAN_BYTES` was bounded against for a wide single-line manifest
        // (`MAX_FALLBACK_SCAN_BYTES`'s own doc names this exact threat model). 5000 lookups
        // at increasing columns on a several-megabyte ASCII line must stay well under a
        // second, not tens of seconds.
        let filler = "x".repeat(6 * 1024 * 1024);
        let table = LineOffsetTable::new(&filler);
        let start = std::time::Instant::now();
        for col in (0..filler.len()).step_by(filler.len() / 5000) {
            assert_eq!(marker_byte_offset(&filler, &table, 1, col), col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge ASCII line, expected well \
             under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_cache_stays_fast_on_a_huge_single_line() {
        // Regression guard for #882: without the per-line char-boundary cache, a non-ASCII
        // line's `char_indices().nth(col)` walk was O(line length) *per call*, so N lookups
        // on the same wide non-ASCII line cost O(N x line length) — a several-hundred-KB
        // line with 5000 lookups took ~500ms in a release build. 5000 lookups here (a
        // smaller line than the perf agent's throwaway release-build bench, sized to stay
        // fast in a debug test build too) must complete well under a second.
        let filler = "x".repeat(200 * 1024);
        let content = format!("{filler}\u{2014}{filler}");
        let table = LineOffsetTable::new(&content);
        let char_count = content.chars().count();
        let start = std::time::Instant::now();
        for col in (0..char_count).step_by((char_count / 5000).max(1)) {
            let _ = marker_byte_offset(&content, &table, 1, col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge non-ASCII line, expected \
             well under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_cache_matches_char_indices_result() {
        // Differential test: the cached char-boundary path must agree with a plain
        // reimplemented `char_indices().nth(col)` walk for every column on a non-ASCII line —
        // the exact class of desync a caching bug could silently introduce.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "\u{1f680}rocket \u{2014} emoji then em dash \u{3000} and more";
        let table = LineOffsetTable::new(content);
        for col in 0..=(content.chars().count() + 5) {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "cached non-ASCII path desynced from the general char_indices() walk at col \
                 {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_multiple_non_ascii_lines_cache_isolation() {
        // Coverage gap flagged by the #882 review: the cache is keyed by 0-indexed line
        // number in a `HashMap`, so two or more distinct non-ASCII lines in the same document
        // must resolve independently regardless of query order — querying line 2, then line
        // 3, then re-querying line 2 must not leak or desync line 2's cached boundaries.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "ascii only\n\u{2014}em dash line\n\u{1f680}rocket \u{3000}ideographic line\nascii again";
        let table = LineOffsetTable::new(content);

        // Query line 3 first, then line 2, then re-query line 3 and line 2 — deliberately out
        // of line order and with a repeat, to catch any cross-line contamination.
        let cases: &[(usize, usize)] = &[(3, 5), (2, 2), (3, 0), (2, 5), (3, 8), (2, 0)];
        for &(line, col) in cases {
            assert_eq!(
                marker_byte_offset(content, &table, line, col),
                slow_path(content, &table, line, col),
                "line {line} col {col} desynced after interleaved multi-line lookups"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_still_correct_without_fast_path() {
        // The fast path must only trigger for a genuinely ASCII line; a non-ASCII line still
        // takes the O(line) `char_indices()` walk, unchanged from before S1.
        let content = "\u{1f680}rocket \u{2014} emoji then em dash";
        let table = LineOffsetTable::new(content);
        let expected = content.char_indices().nth(3).unwrap().0;
        assert_eq!(marker_byte_offset(content, &table, 1, 3), expected);
    }

    #[test]
    fn test_marker_byte_offset_lone_cr_document_documented_limitation() {
        // S2 (impl-critic, #879 follow-up): a bare-`\r` (no `\n`) document is out of scope
        // for `LineOffsetTable`/`marker_byte_offset`, per the function's own "Line-ending
        // assumption" doc section — `line` runs past the table's single line-start entry, so
        // this falls back to `content.len()` rather than the true offset. Locking in the
        // documented (not silently reverted) behavior, not asserting it is desirable.
        let content = "on: push\rjobs:\r  build:\r    steps:\r      - uses: actions/checkout@v4\r";
        let table = LineOffsetTable::new(content);
        // yaml-rust2 would report line 5 for the `uses:` value here; only line 1 exists in
        // the table since it never splits on a lone `\r`.
        assert_eq!(marker_byte_offset(content, &table, 5, 14), content.len());
    }
}
