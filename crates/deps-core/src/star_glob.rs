//! Shared `*`-only glob matching.

/// Returns whether `text` matches `pattern`, where `*` matches any run of characters
/// (including `/`) and everything else is literal.
///
/// Linear time: the text between stars is located left to right with one substring search
/// each, so there is no backtracking and no nested scan.
///
/// # Examples
///
/// ```
/// use deps_core::star_glob::matches;
///
/// assert!(matches("serde*", "serde_json"));
/// assert!(matches("@types/*", "@types/node"));
/// assert!(!matches("*-core", "deps-core-x"));
/// ```
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    let Some((first, after_first)) = pattern.split_once('*') else {
        return pattern == text;
    };
    let Some(rest) = text.strip_prefix(first) else {
        return false;
    };
    let (middle, last) = after_first.rsplit_once('*').unwrap_or(("", after_first));
    let Some(mut rest) = rest.strip_suffix(last) else {
        return false;
    };
    for piece in middle.split('*').filter(|piece| !piece.is_empty()) {
        let Some((_, after)) = rest.split_once(piece) else {
            return false;
        };
        rest = after;
    }
    true
}
