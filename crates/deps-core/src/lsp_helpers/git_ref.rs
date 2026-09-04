//! Shared git-tags-datasource parser scaffolding, extracted from
//! `deps-github-actions`'s originally crate-private `parser.rs`/`formatter.rs` helpers so a
//! second git-tags-shaped ecosystem (GitLab CI) can reuse the same hardened span/text
//! plumbing instead of forking it. `deps-github-actions` now imports these instead of
//! defining them locally.

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

/// Maps a `yaml-rust2` char index to a byte offset in `content`, and a byte offset to the
/// end of its containing line.
///
/// `yaml_rust2::scanner::Marker::index()` increments once per `char` consumed by the
/// scanner (it is built over `Parser::new_from_str`'s `str::chars()` iterator) — despite
/// its own doc comment claiming "in bytes", it is a **character** index, verified against
/// `yaml-rust2` 0.12's `Scanner::skip_non_blank`/`skip_blank` (`self.mark.index += 1` per
/// char, not per byte). For ASCII-only content the two coincide, but non-ASCII text
/// upstream of a value would silently desync every downstream byte-offset computation
/// without this table.
pub struct CharOffsets {
    byte_of_char: Vec<usize>,
}

impl CharOffsets {
    /// Builds the table for `content`.
    #[must_use]
    pub fn new(content: &str) -> Self {
        let mut byte_of_char: Vec<usize> = content.char_indices().map(|(b, _)| b).collect();
        byte_of_char.push(content.len());
        Self { byte_of_char }
    }

    /// Converts a `yaml-rust2` marker char index into a byte offset in the content this
    /// table was built from.
    #[must_use]
    pub fn byte_offset(&self, char_index: usize) -> usize {
        self.byte_of_char
            .get(char_index)
            .copied()
            .unwrap_or(*self.byte_of_char.last().unwrap_or(&0))
    }
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
    if value.is_empty() {
        return Some((search_from, search_from));
    }
    let bytes = content.as_bytes();
    if search_from + value.len() <= bytes.len()
        && &bytes[search_from..search_from + value.len()] == value.as_bytes()
    {
        return Some((search_from, search_from + value.len()));
    }
    let line_end = bytes[search_from..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| search_from + p);
    let scan_end = line_end.min(search_from.saturating_add(MAX_FALLBACK_SCAN_BYTES));
    let haystack = &bytes[search_from..scan_end];
    let needle = value.as_bytes();
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| (search_from + rel, search_from + rel + needle.len()))
}

#[cfg(test)]
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
    fn test_char_offsets_byte_offset_ascii() {
        let offsets = CharOffsets::new("hello");
        assert_eq!(offsets.byte_offset(0), 0);
        assert_eq!(offsets.byte_offset(5), 5);
    }

    #[test]
    fn test_char_offsets_byte_offset_multibyte() {
        let content = "\u{3000}a";
        let offsets = CharOffsets::new(content);
        // U+3000 is 3 bytes; the second char ('a') starts at byte 3.
        assert_eq!(offsets.byte_offset(1), 3);
    }
}
