//! Line-oriented parsing for `requirements.txt` / `constraints.txt` — pip's
//! requirements file format.
//!
//! Every requirement line is routed through the shared
//! [`PypiParser::parse_pep508_requirement`](super::PypiParser) — the same
//! function the `pyproject.toml` paths use — so hover, diagnostics, markers
//! and extras render identically to a PEP 621 dependency string. This
//! module's job is purely to turn free-form line-oriented text into
//! `(requirement text, absolute byte span)` pairs, plus a content gate that
//! keeps prose files that happen to match the routing pattern (e.g.
//! `product-requirements.txt`) from producing spurious network requests and
//! diagnostics.

use super::{ParseResult, PypiParser};
use crate::error::Result;
use crate::types::{PypiDependencySection, PypiDependencySource};
use deps_core::lsp_helpers::LineOffsetTable;
use tower_lsp_server::ls_types::Uri;

// TODO(critic): surface -r/-c targets as documentLinks

/// Pip option tokens recognized on an option line (a line whose first
/// whitespace-delimited token starts with `-`). Matched by exact equality
/// against the token's name — the part before an `=` for the long `--opt=value`
/// spelling — see [`parse_requirements`] — so an unrecognized `-`-leading line
/// (e.g. a markdown bullet `- item`) is not silently treated as an option.
const KNOWN_OPTIONS: &[&str] = &[
    "-r",
    "-c",
    "-e",
    "-i",
    "-f",
    "--requirement",
    "--constraint",
    "--editable",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--trusted-host",
    "--pre",
    "--no-binary",
    "--only-binary",
    "--no-index",
    "--prefer-binary",
    "--require-hashes",
    "--use-feature",
    "--global-option",
    "--config-settings",
    "--hash",
];

/// URL/scheme prefixes of a nameless requirement (§3.6): a bare direct
/// reference with no package name, which must never reach the PEP 508
/// parser but also must not count as a parse failure.
const NAMELESS_URL_PREFIXES: &[&str] = &["http://", "https://", "git+", "file:"];

/// Archive file suffixes of a nameless requirement (a bare wheel/sdist path).
const NAMELESS_ARCHIVE_SUFFIXES: &[&str] = &[".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip"];

impl PypiParser {
    /// Parses a `requirements.txt`/`constraints.txt` file (pip's
    /// requirements file format) and extracts all dependencies.
    ///
    /// Reuses the shared PEP 508 machinery
    /// (`PypiParser::parse_pep508_requirement`) for every requirement line,
    /// so hover, diagnostics, markers and extras render identically to
    /// `pyproject.toml`. A line that fails to parse is logged and skipped
    /// rather than failing the whole file — a requirements file is
    /// free-form text under active editing, and a half-typed line must not
    /// blank out hover for every other dependency.
    ///
    /// Applies a content gate before returning: since `.txt` is routed here
    /// by filename pattern rather than a fixed name, a prose file that
    /// happens to match (`product-requirements.txt`) would otherwise send a
    /// PyPI request and emit an "Unknown package" warning for every
    /// single-word line. The gate keeps the parsed dependencies only if the
    /// file shows a strong pip signal — a recognized option, or a
    /// successfully parsed line whose dependency carries a version
    /// requirement or a Git/URL source — or more lines parsed than failed —
    /// real prose fails every line, but a hand-written unpinned
    /// `requests\nflask\nnumpy` (or that file mid-edit, with one partially
    /// typed line) survives. The signal is read off the *parsed* dependency
    /// rather than scanned from raw text, so an operator- or `@`-looking
    /// substring inside a prose sentence (an email address, a comparison)
    /// cannot short-circuit the gate.
    ///
    /// # Errors
    ///
    /// Never actually errs — the `Result` return type exists for symmetry
    /// with [`PypiParser::parse_content`](super::PypiParser::parse_content).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_pypi::parser::PypiParser;
    /// use tower_lsp_server::ls_types::Uri;
    ///
    /// let parser = PypiParser::new();
    /// let uri = Uri::from_file_path("/project/requirements.txt").unwrap();
    /// let result = parser
    ///     .parse_requirements("requests==2.31.0\nflask>=3.0\n", &uri)
    ///     .unwrap();
    /// assert_eq!(result.dependencies.len(), 2);
    /// ```
    pub fn parse_requirements(&self, content: &str, uri: &Uri) -> Result<ParseResult> {
        let line_table = LineOffsetTable::new(content);
        let mut dependencies = Vec::new();
        let mut strong_signal = false;
        let mut failed_lines: usize = 0;

        let mut lines = content.lines().enumerate().peekable();
        while let Some((line_idx, raw_line)) = lines.next() {
            let Some(mut line_start) = line_table.line_start(line_idx) else {
                continue;
            };

            // A leading BOM is skipped like whitespace rather than stripped
            // from `content` — stripping would desync every later offset by
            // 3 bytes from the document the editor holds.
            let line = if line_idx == 0 {
                match raw_line.strip_prefix('\u{feff}') {
                    Some(stripped) => {
                        line_start += raw_line.len() - stripped.len();
                        stripped
                    }
                    None => raw_line,
                }
            } else {
                raw_line
            };

            // Cut at the first `#` at index 0 or preceded by ASCII
            // whitespace (pip's own `COMMENT_RE`), which protects URL
            // fragments (`#egg=name`) that are never whitespace-preceded.
            // Deliberately quote-unaware, matching pip's identical behavior:
            // `pkg==1.0; extra == "a #b"` mis-cuts inside the quoted marker,
            // same as it would in pip itself.
            let without_comment = strip_comment(line);
            let trimmed = without_comment.trim();
            if trimmed.is_empty() {
                continue;
            }

            let leading_ws = without_comment.len() - without_comment.trim_start().len();
            let abs_start = line_start + leading_ws;

            // A line ending in `\` (after comment-stripping) is a
            // continuation: parse the requirement from this first physical
            // line alone, and consume the following continuation lines
            // without parsing them. `version_range` is nulled below whenever
            // a continuation was present — continuations in practice exist
            // to carry `--hash`/per-requirement options, so suppressing the
            // "update version" edit is correct in every realistic case.
            let (text, had_continuation) = match trimmed.strip_suffix('\\') {
                Some(stripped) => {
                    while let Some((_, next_raw)) = lines.peek() {
                        let continues = strip_comment(next_raw).trim().ends_with('\\');
                        lines.next();
                        if !continues {
                            break;
                        }
                    }
                    (stripped.trim_end(), true)
                }
                None => (trimmed, false),
            };

            // Option lines: recognized by an exact match on the token's name
            // (accepting both `--opt value` and `--opt=value` spellings) so
            // an unrecognized `-`-leading line (a markdown bullet `- item`)
            // counts as a parse failure instead of being silently skipped.
            if let Some(first_token) = text.split_whitespace().next()
                && first_token.starts_with('-')
            {
                let option_name = first_token.split('=').next().unwrap_or(first_token);
                if KNOWN_OPTIONS.contains(&option_name) {
                    strong_signal = true;
                } else {
                    failed_lines += 1;
                }
                continue;
            }

            // Per-requirement options (`--hash=...`, `--global-option=...`):
            // cut at the first whitespace-delimited `--` token.
            let (req_text, had_hash_option) = split_requirement_options(text);
            let req_text = req_text.trim_end();
            if req_text.is_empty() {
                continue;
            }

            // A bare URL, filesystem path, or archive file has no package
            // name and must never reach the PEP 508 parser, but is not a
            // parse failure either — `name @ https://...` (which does have
            // a name) is unaffected and falls through to the parser below.
            if is_nameless_requirement(req_text) {
                continue;
            }

            let abs_end = abs_start + req_text.len();
            match self.parse_pep508_requirement(
                req_text,
                Some(abs_start..abs_end),
                content,
                &line_table,
            ) {
                Ok(mut dep) => {
                    dep.section = PypiDependencySection::Requirements;
                    if had_continuation || had_hash_option {
                        dep.version_range = None;
                    }
                    // A strong signal is derived from the *parsed* dependency,
                    // not a raw-text scan of the line: scanning for tokens like
                    // `@` or `>=` over free-form text is fooled by an email
                    // address or a comparison-looking sentence fragment
                    // ("Author: jane@example.com"), which would otherwise
                    // short-circuit the gate this heuristic exists to enforce.
                    if !strong_signal
                        && (dep.version_req.is_some()
                            || matches!(
                                dep.source,
                                PypiDependencySource::Git { .. } | PypiDependencySource::Url { .. }
                            ))
                    {
                        strong_signal = true;
                    }
                    dependencies.push(dep);
                }
                Err(e) => {
                    tracing::debug!("Failed to parse requirements line '{req_text}': {e}");
                    failed_lines += 1;
                }
            }
        }

        let keep = strong_signal || (!dependencies.is_empty() && failed_lines < dependencies.len());

        Ok(ParseResult {
            dependencies: if keep { dependencies } else { Vec::new() },
            workspace_root: None,
            uri: uri.clone(),
        })
    }
}

/// Cuts `line` at the first `#` that is at index 0 or preceded by ASCII
/// whitespace, matching pip's `COMMENT_RE = r'(^|\s+)#.*$'`.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Splits `text` at the first whitespace-delimited token starting with
/// `--` (a per-requirement option like `--hash=sha256:...`), returning the
/// requirement text before it and whether a `--hash`/`--hash=...` token was
/// present anywhere on the line.
fn split_requirement_options(text: &str) -> (&str, bool) {
    let had_hash = text
        .split_whitespace()
        .any(|tok| tok == "--hash" || tok.starts_with("--hash="));

    for token in text.split_whitespace() {
        if token.starts_with("--") {
            // SAFETY-free pointer arithmetic: `token` is a genuine subslice of
            // `text` produced by `split_whitespace`, so this offset is valid.
            let offset = token.as_ptr() as usize - text.as_ptr() as usize;
            return (text[..offset].trim_end(), had_hash);
        }
    }

    (text, had_hash)
}

/// True for a bare URL, filesystem path, or archive file — a line with no
/// package name that must not reach `parse_pep508_requirement`. A `name @
/// https://…/x.tar.gz` direct reference has a name before the `@` and is
/// deliberately NOT nameless, even though it ends in an archive suffix.
fn is_nameless_requirement(text: &str) -> bool {
    if NAMELESS_URL_PREFIXES.iter().any(|p| text.starts_with(p)) {
        return true;
    }
    if text == "." || text.starts_with("./") || text.starts_with("../") || text.starts_with('/') {
        return true;
    }
    !text.contains('@') && NAMELESS_ARCHIVE_SUFFIXES.iter().any(|s| text.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/requirements.txt")
    }

    fn parse(content: &str) -> ParseResult {
        PypiParser::new()
            .parse_requirements(content, &test_uri())
            .unwrap()
    }

    // --- Basics ---

    #[test]
    fn test_basic_pinned() {
        let result = parse("requests==2.31.0\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("==2.31.0")
        );
    }

    #[test]
    fn test_basic_range() {
        let result = parse("flask>=3.0,<4\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "flask");
    }

    #[test]
    fn test_bare_name_no_specifier() {
        let result = parse("requests==1.0.0\nflask\n");
        let flask = result
            .dependencies
            .iter()
            .find(|d| d.name == "flask")
            .unwrap();
        assert_eq!(flask.version_req, None);
    }

    #[test]
    fn test_extras() {
        let result = parse("requests==1.0.0\nflask[async,dotenv]>=3.0\n");
        let flask = result
            .dependencies
            .iter()
            .find(|d| d.name == "flask")
            .unwrap();
        assert_eq!(flask.extras, vec!["async", "dotenv"]);
    }

    #[test]
    fn test_tilde_equal() {
        let result = parse("numpy ~= 1.24\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "numpy");
    }

    #[test]
    fn test_spaces_around_operator() {
        let result = parse("requests == 2.31.0\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    // --- Spaced extras (S3): version_range must slice to exactly the source text ---

    fn slice(content: &str, range: tower_lsp_server::ls_types::Range) -> String {
        let table = LineOffsetTable::new(content);
        let start = table.position_to_byte_offset(content, range.start);
        let end = table.position_to_byte_offset(content, range.end);
        content[start..end].to_string()
    }

    #[test]
    fn test_spaced_extras_version_range() {
        let content = "flask[async, dotenv]>=3.0\n";
        let result = parse(content);
        let dep = &result.dependencies[0];
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice(content, version_range), ">=3.0");
    }

    #[test]
    fn test_spaced_extras_and_spaced_operator_version_range() {
        let content = "flask [async] >= 3.0\n";
        let result = parse(content);
        let dep = &result.dependencies[0];
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice(content, version_range), ">= 3.0");
    }

    #[test]
    fn test_dotted_source_name_version_range() {
        let content = "my__pkg==1.0\n";
        let result = parse(content);
        let dep = &result.dependencies[0];
        let version_range = dep.version_range.expect("version_range should be set");
        assert_eq!(slice(content, version_range), "==1.0");
    }

    // --- Positions ---

    #[test]
    fn test_indented_line_position() {
        let content = "  requests==2.0\n";
        let result = parse(content);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name_range.start.character, 2);
    }

    #[test]
    fn test_position_after_non_ascii_comment() {
        let content = "# héllo wörld\nrequests==2.0\n";
        let result = parse(content);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name_range.start.line, 1);
        assert_eq!(dep.name_range.start.character, 0);
    }

    #[test]
    fn test_last_line_no_trailing_newline() {
        let content = "requests==2.0\nflask==1.0";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 2);
        let flask = result
            .dependencies
            .iter()
            .find(|d| d.name == "flask")
            .unwrap();
        assert_eq!(flask.name_range.start.line, 1);
    }

    // --- CRLF (M2) ---

    #[test]
    fn test_crlf_line_endings_positions_correct() {
        let content = "requests==1.0\r\nflask==2.0\r\nnumpy==3.0\r\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 3);
        let numpy = result
            .dependencies
            .iter()
            .find(|d| d.name == "numpy")
            .unwrap();
        assert_eq!(numpy.name_range.start.line, 2);
        assert_eq!(numpy.name_range.start.character, 0);
    }

    // --- BOM (M3) ---

    #[test]
    fn test_bom_on_first_line() {
        let content = "\u{feff}requests==2.0\nflask==1.0\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 2);
        let requests = result
            .dependencies
            .iter()
            .find(|d| d.name == "requests")
            .unwrap();
        assert_eq!(requests.name_range.start.line, 0);
        // The BOM counts as one UTF-16 code unit, same as the editor's own
        // column count for that position — see module docs on BOM handling.
        assert_eq!(requests.name_range.start.character, 1);
        let flask = result
            .dependencies
            .iter()
            .find(|d| d.name == "flask")
            .unwrap();
        assert_eq!(flask.name_range.start.line, 1);
        assert_eq!(flask.name_range.start.character, 0);
    }

    // --- UTF-8 boundary (M1) — exercised at the deps-core level; see
    // `deps_core::lsp_helpers` tests for `byte_offset_to_position`.

    // --- Comments ---

    #[test]
    fn test_full_line_comment() {
        let result = parse("# just a comment\nrequests==1.0\n");
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_trailing_comment() {
        let result = parse("requests==1.0  # pinned for compat\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    #[test]
    fn test_hash_in_url_fragment_not_cut() {
        // `#egg=` immediately follows a non-whitespace character, so it is
        // not treated as a comment start.
        let content = "mylib @ https://example.com/mylib.tar.gz#egg=mylib\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "mylib");
    }

    #[test]
    fn test_hash_with_no_preceding_whitespace_not_cut() {
        let content = "requests==1.0#nospace\n";
        // The whole line (no valid PEP 508 text after the mis-included `#nospace`)
        // fails to parse as a well-formed requirement; the point of this test is
        // only that `strip_comment` did NOT cut before the `#`.
        let without_comment = strip_comment(content.trim_end());
        assert_eq!(without_comment, "requests==1.0#nospace");
    }

    #[test]
    fn test_quoted_marker_hash_mis_cut_matches_pip() {
        // Accepted, pip-matching behavior (M6): the comment stripper is
        // quote-unaware, so a `#` inside a quoted marker value is still cut
        // if whitespace-preceded, exactly like pip's own `COMMENT_RE`.
        let content = "pkg==1.0; extra == \"a #b\"\n";
        let without_comment = strip_comment(content.trim_end());
        assert_eq!(without_comment, "pkg==1.0; extra == \"a ");
    }

    // --- Markers ---

    #[test]
    fn test_marker_on_line() {
        let result = parse("pkg==1.0; python_version < \"3.9\"\n");
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].markers.is_some());
    }

    #[test]
    fn test_compound_marker_on_line() {
        let content = "pkg==1.0; sys_platform == 'win32' and python_version >= '3.8'\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        let markers = result.dependencies[0].markers.as_ref().unwrap();
        assert!(markers.contains("sys_platform"));
    }

    #[test]
    fn test_oversized_marker_on_line_skips_normalization() {
        let long_marker: String = "os_name == 'a' or ".repeat(200) + "os_name == 'a'";
        assert!(long_marker.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg==1.0; {long_marker}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].markers, Some(long_marker));
    }

    #[test]
    fn test_deeply_nested_marker_on_line_skips_normalization() {
        let depth = 1000;
        let nested_marker = format!("{}os_name == 'a'{}", "(".repeat(depth), ")".repeat(depth));
        assert!(nested_marker.len() < super::super::MAX_MARKER_LEN);
        let content = format!("pkg==1.0; {nested_marker}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].markers, Some(nested_marker));
    }

    // --- Options (§3.4) ---

    #[test]
    fn test_option_lines_skipped_not_failures() {
        let content = "-r base.txt\n--requirement base.txt\n-c constraints.txt\n-e .\n-e git+https://example.com/pkg#egg=pkg\n--index-url https://example.com\n--extra-index-url https://example.com\n--find-links ./wheels\n--pre\nrequests==1.0\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    #[test]
    fn test_option_lines_equals_form_recognized() {
        // C1 regression: pip accepts both `--index-url URL` and
        // `--index-url=URL`; the `=` form is idiomatic in corporate/internal
        // requirements files and must not count as a parse failure.
        let content = "--index-url=https://internal.example/simple\nrequests\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    // --- pip-compile shape (S1) ---

    #[test]
    fn test_pip_compile_continuation_with_hashes() {
        let content =
            "pkg==1.0 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\nother==2.0\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 2);
        let pkg = result
            .dependencies
            .iter()
            .find(|d| d.name == "pkg")
            .unwrap();
        assert_eq!(pkg.version_range, None);
        let other = result
            .dependencies
            .iter()
            .find(|d| d.name == "other")
            .unwrap();
        assert!(other.version_range.is_some());
    }

    #[test]
    fn test_inline_hash_single_line_nulls_version_range() {
        let content = "pkg==1.0 --hash=sha256:aaaa\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_range, None);
    }

    #[test]
    fn test_non_hash_continuation_still_nulls_version_range() {
        let content = "pkg \\\n    ==1.0\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_range, None);
    }

    // --- Skipped shapes (§3.6) ---

    #[test]
    fn test_skipped_bare_url() {
        let result = parse("https://example.com/pkg.whl\nrequests==1.0\n");
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    #[test]
    fn test_skipped_local_paths() {
        let content = "./local/pkg\n/abs/path\n../rel\n.\nrequests==1.0\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "requests");
    }

    #[test]
    fn test_named_direct_reference_kept() {
        let content = "mylib @ https://example.com/mylib.tar.gz\n";
        let result = parse(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "mylib");
        assert!(matches!(
            result.dependencies[0].source,
            PypiDependencySource::Url { .. }
        ));
        assert_eq!(result.dependencies[0].version_req, None);
    }

    // --- Robustness ---

    #[test]
    fn test_garbage_line_skipped_surrounding_lines_parse() {
        let content = "requests==1.0\n>>>> merge conflict\nflask==2.0\n!!!\n[\nnumpy==3.0\n";
        let result = parse(content);
        let names: Vec<&str> = result
            .dependencies
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"numpy"));
    }

    #[test]
    fn test_empty_file() {
        let result = parse("");
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_file_of_only_comments() {
        let result = parse("# one\n# two\n");
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_constraints_txt_parses_identically() {
        let uri = deps_core::test_util::test_uri("/test/constraints.txt");
        let result = PypiParser::new()
            .parse_requirements("requests==1.0\nflask==2.0\n", &uri)
            .unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert!(
            result
                .dependencies
                .iter()
                .all(|d| matches!(d.section, PypiDependencySection::Requirements))
        );
    }

    // --- Content gate (§2.3, S2, N2, N3) ---

    #[test]
    fn test_gate_drops_prose_file() {
        let content = "Product requirements\n\nThe API must be fast.\n- a bullet\n";
        let result = parse(content);
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_gate_keeps_unpinned_hand_written_file() {
        // The `failed_lines < dependencies.len()` relaxation exists for this:
        // no strong signal anywhere, yet all 3 lines parse successfully.
        let result = parse("requests\nflask\nnumpy\n");
        assert_eq!(result.dependencies.len(), 3);
    }

    #[test]
    fn test_gate_survives_mid_typing_edit() {
        // N2: a partially typed 4th line must not wipe the 3 already-valid
        // dependencies. `django >` has a bare `>` NOT followed by a digit,
        // so it is not a strong signal, and fails to parse as PEP 508.
        let result = parse("requests\nflask\nnumpy\ndjango >\n");
        assert_eq!(result.dependencies.len(), 3);
    }

    #[test]
    fn test_gate_bare_less_than_digit_is_strong_signal() {
        let result = parse("flask<4\n");
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_gate_email_in_prose_does_not_defeat_gate() {
        // C2 regression: an `@` in an email address and no PEP 440 operator
        // anywhere must not set `strong_signal` via a raw-text scan — the
        // signal is derived from the parsed dependency, not the source text.
        // "Overview" alone parses as a bare (unpinned) dependency, so without
        // the fix this file would ship 1 spurious dependency with a network
        // request and an "Unknown package" warning.
        let content = "Requirements Document\n\nAuthor: jane@example.com\nOverview\n";
        let result = parse(content);
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_gate_markdown_bullets_are_failures_not_prose_survivors() {
        // N3: an unrecognized `-`-leading line counts as a failure, so this
        // realistic prose shape (1 dep "Requirements", 2 bullet failures) is
        // dropped rather than producing a spurious "Unknown package" warning.
        let content = "Requirements\n\n- Fast response\n- Scalable\n";
        let result = parse(content);
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_gate_option_only_file_no_panic() {
        let result = parse("-r base.txt\n");
        assert!(result.dependencies.is_empty());
    }
}
