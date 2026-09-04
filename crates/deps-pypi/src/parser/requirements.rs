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

use super::{ParseResult, PypiParser, RequirementRef};
use crate::config::PypiIndexConfig;
use crate::error::Result;
use crate::types::{PypiDependencySection, PypiDependencySource};
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::net_policy::RegistryAccessPolicy;
use tower_lsp_server::ls_types::{Range, Uri};

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
    /// requirement or a Git/URL source — or, when `require_strong_signal` is
    /// `false`, more lines parsed than failed — real prose fails every line,
    /// but a hand-written unpinned `requests\nflask\nnumpy` (or that file
    /// mid-edit, with one partially typed line) survives. The signal is read
    /// off the *parsed* dependency rather than scanned from raw text, so an
    /// operator- or `@`-looking substring inside a prose sentence (an email
    /// address, a comparison) cannot short-circuit the gate.
    ///
    /// `require_strong_signal` drops that ratio-based arm entirely, requiring
    /// the strong-signal check alone. Set this when the caller routed to this
    /// parser via a weaker signal than a basename match — PyPI's
    /// `requirements/*.txt` [`Ecosystem::manifest_directory_patterns`](deps_core::Ecosystem::manifest_directory_patterns)
    /// fallback matches *every* `.txt` file under a directory literally named
    /// `requirements/`, including requirements-engineering docs folders with
    /// no relation to Python; without this, prose lines that happen to parse
    /// as bare PEP 508 names (`"Introduction"`, `"Scope"`) can still clear the
    /// ratio arm and trigger live PyPI lookups on what is not a manifest at
    /// all (#452 S6).
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
    ///     .parse_requirements("requests==2.31.0\nflask>=3.0\n", &uri, false)
    ///     .unwrap();
    /// assert_eq!(result.dependencies.len(), 2);
    /// ```
    pub fn parse_requirements(
        &self,
        content: &str,
        uri: &Uri,
        require_strong_signal: bool,
    ) -> Result<ParseResult> {
        self.parse_requirements_with_policy(
            content,
            uri,
            require_strong_signal,
            &RegistryAccessPolicy::default(),
        )
    }

    /// Like [`Self::parse_requirements`], but resolves `--index-url`/`--extra-index-url`
    /// declarations (spec FR-001–FR-006) against `policy` rather than the default
    /// (`public_only`) — the production entry point `PypiEcosystem` calls, threading through
    /// its own live `RegistryAccessPolicy` handle.
    ///
    /// # Errors
    ///
    /// Same as [`Self::parse_requirements`] — never actually errs.
    pub fn parse_requirements_with_policy(
        &self,
        content: &str,
        uri: &Uri,
        require_strong_signal: bool,
        policy: &RegistryAccessPolicy,
    ) -> Result<ParseResult> {
        // Two-pass parse (fixes S2): pip applies `--index-url`/`--extra-index-url`
        // file-wide, not from-this-line-down, so every declaration must be collected before
        // any dependency's source is resolved — a dependency declared *before* a late
        // `--index-url` line must still route through it.
        let config = collect_index_config(content, policy);

        let line_table = LineOffsetTable::new(content);
        let mut dependencies = Vec::new();
        let mut document_links = Vec::new();
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
                    if matches!(option_name, "-r" | "-c" | "--requirement" | "--constraint")
                        && let Some((target, target_offset)) =
                            extract_option_target(first_token, text)
                    {
                        let target_abs_start = abs_start + target_offset;
                        let target_abs_end = target_abs_start + target.len();
                        document_links.push(RequirementRef {
                            range: Range::new(
                                line_table.byte_offset_to_position(content, target_abs_start),
                                line_table.byte_offset_to_position(content, target_abs_end),
                            ),
                            target: target.to_string(),
                        });
                    }
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
                    // FR-002/003/005/006: a plain registry-sourced dependency routes through
                    // this file's collected `--index-url`/`--extra-index-url` config; a
                    // Git/Path/Url-sourced one is untouched — those have no PyPI index
                    // routing concept.
                    if dep.source == PypiDependencySource::Registry {
                        dep.source = config.resolve_source_for(None);
                    }
                    dependencies.push(dep);
                }
                // A length-cap rejection is "we refused to parse this",
                // not evidence the file isn't a requirements file — unlike
                // a genuine syntax error, it must not count toward
                // `failed_lines`, or a handful of oversized lines could
                // starve the keep heuristic below and blank hover/diagnostics
                // for every legitimate dependency in the file.
                Err(crate::error::PypiError::RequirementTooLong { len, max }) => {
                    tracing::warn!(
                        "Requirements line too long ({len} bytes, max {max}), skipping: {}",
                        super::truncate_for_log(req_text)
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to parse requirements line '{}': {e}",
                        super::truncate_for_log(req_text)
                    );
                    failed_lines += 1;
                }
            }
        }

        let keep = strong_signal
            || (!require_strong_signal
                && !dependencies.is_empty()
                && failed_lines < dependencies.len());

        Ok(ParseResult {
            dependencies: if keep { dependencies } else { Vec::new() },
            workspace_root: None,
            uri: uri.clone(),
            document_links: if keep { document_links } else { Vec::new() },
            // Any `--index-url`/`--extra-index-url` occurrence sets `strong_signal` (it's a
            // `KNOWN_OPTIONS` entry), so `keep` is always true whenever `config` has anything
            // to register — gating on `keep` here only ever discards chains for a prose file
            // that was never going to register any, never a real one.
            resolved_chains: if keep {
                config.resolved_chains()
            } else {
                Vec::new()
            },
        })
    }
}

/// Pass 1 of the two-pass parse (fixes S2): scans every physical line of `content` and
/// collects every `--index-url <url>`/`--index-url=<url>`/`-i <url>`/`--extra-index-url
/// <url>`/`--extra-index-url=<url>` occurrence into a [`PypiIndexConfig`], regardless of its
/// position relative to any dependency line. Mirrors [`PypiParser::parse_requirements_with_policy`]'s
/// main loop's comment-stripping/trimming, but does not need continuation-joining: an
/// option's target is read from its own physical line only, matching pip's own line-oriented
/// option grammar (a continued `--index-url` value is not a realistic real-world shape).
fn collect_index_config(content: &str, policy: &RegistryAccessPolicy) -> PypiIndexConfig {
    let mut config = PypiIndexConfig::new();

    for (line_idx, raw_line) in content.lines().enumerate() {
        // A leading BOM on the first physical line is not ASCII/Unicode whitespace, so
        // `str::trim()` alone never removes it — without stripping it here the same way the
        // main parsing loop below does, a file starting with a BOM immediately followed by
        // `--index-url`/`--extra-index-url` would have that line's leading token read as
        // `"\u{feff}--index-url"` (fails the `starts_with('-')` check) and silently skip the
        // whole declaration, leaving every dependency in the file resolving against
        // `pypi.org` instead (validator finding S1).
        let line = if line_idx == 0 {
            raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line)
        } else {
            raw_line
        };
        let without_comment = strip_comment(line);
        let trimmed = without_comment.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some(first_token) = trimmed.split_whitespace().next() else {
            continue;
        };
        if !first_token.starts_with('-') {
            continue;
        }

        let option_name = first_token.split('=').next().unwrap_or(first_token);
        if !matches!(option_name, "--index-url" | "-i" | "--extra-index-url") {
            continue;
        }

        let Some((target, _offset)) = extract_option_target(first_token, trimmed) else {
            continue;
        };

        match option_name {
            "--index-url" | "-i" => config.set_primary(target, policy),
            "--extra-index-url" => config.add_extra(target, policy),
            _ => unreachable!("matched above"),
        }
    }

    config
}

/// Extracts the target path/URL text and its byte offset within `text` for a
/// `-r`/`-c`/`--requirement`/`--constraint` option line — either the
/// `--long=value` spelling (target sliced out of `text` right after the
/// matched `=`) or the space-separated spelling (target is whatever follows
/// `first_token`, whitespace-trimmed). Returns `None` when the option carries
/// no target text at all (a bare `-r` with nothing after it).
fn extract_option_target<'a>(first_token: &str, text: &'a str) -> Option<(&'a str, usize)> {
    if let Some(eq_idx) = first_token.find('=') {
        let after_eq = &text[eq_idx + 1..];
        // Bounded to just this token's own value (validator finding S2) — a later option on
        // the same line (e.g. `--index-url=https://x --trusted-host x`) must not be swallowed
        // into the value, which could otherwise silently produce a mangled-but-technically-
        // parseable URL once whitespace gets percent-encoded rather than a clean parse
        // failure.
        let value_end = after_eq.find(char::is_whitespace).unwrap_or(after_eq.len());
        let target = &after_eq[..value_end];
        return (!target.is_empty()).then_some((target, eq_idx + 1));
    }

    let rest = &text[first_token.len()..];
    let leading_ws = rest.len() - rest.trim_start().len();
    let after_ws = &rest[leading_ws..];
    // Same bound as the `=`-spelling branch above — stop at the next whitespace run rather
    // than capturing the rest of the line, which would otherwise include any further option
    // present on the same line.
    let value_end = after_ws.find(char::is_whitespace).unwrap_or(after_ws.len());
    let target = &after_ws[..value_end];
    (!target.is_empty()).then_some((target, first_token.len() + leading_ws))
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

    use std::assert_matches;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/requirements.txt")
    }

    fn parse(content: &str) -> ParseResult {
        PypiParser::new()
            .parse_requirements(content, &test_uri(), false)
            .unwrap()
    }

    /// Like [`parse`], but with `require_strong_signal: true` — the gate a
    /// directory-pattern-only match (`requirements/base.txt`) gets (#452 S6).
    fn parse_strict(content: &str) -> ParseResult {
        PypiParser::new()
            .parse_requirements(content, &test_uri(), true)
            .unwrap()
    }

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::All)
    }

    /// Like [`parse`], but threading an explicit policy through
    /// [`PypiParser::parse_requirements_with_policy`] — the entry point T003's own tests use.
    fn parse_with_policy(content: &str, policy: &RegistryAccessPolicy) -> ParseResult {
        PypiParser::new()
            .parse_requirements_with_policy(content, &test_uri(), false, policy)
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

    // --- Requirement length cap (issue #229) ---

    #[test]
    fn test_oversized_extras_list_rejected_fast() {
        // Regression test for #229: `pep508_rs` 0.9.2 parses an extras list
        // in O(n²). Before the length cap, a single line this size would
        // take on the order of seconds to parse (extrapolating the measured
        // quadratic growth); with the cap it is rejected in O(1) and the
        // rest of the file still parses normally.
        let huge_extras = "a,".repeat(500_000); // ~1 MiB extras list
        let oversized_requirement = format!("pkg[{huge_extras}]==1.0");
        assert!(oversized_requirement.len() > super::super::MAX_REQUIREMENT_LEN);
        let content = format!("{oversized_requirement}\ngood-pkg==2.0\n");

        let start = std::time::Instant::now();
        let result = parse(&content);
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "oversized extras line took too long to reject: {elapsed:?}"
        );
        // The oversized line is skipped entirely (never handed to
        // `pep508_rs`), but the rest of the file is unaffected.
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "good-pkg");
    }

    #[test]
    fn test_oversized_line_rejection_does_not_count_as_failed_line() {
        // Regression test for critic finding S2: a length-cap rejection must
        // not count toward `failed_lines`, which feeds the "is this really a
        // requirements file" keep heuristic. Bare package names (no version
        // specifier, no strong signal) alone are kept only while
        // `failed_lines < dependencies.len()`; before the fix, 3 oversized
        // lines pushed `failed_lines` past that threshold and blanked the
        // whole file, including the two legitimate bare-name dependencies.
        let huge_extras = "a,".repeat(500_000);
        let oversized = format!("pkg[{huge_extras}]==1.0");
        assert!(oversized.len() > super::super::MAX_REQUIREMENT_LEN);
        let content = format!("{oversized}\n{oversized}\n{oversized}\nrequests\nflask\n");

        let result = parse(&content);

        let mut names: Vec<&str> = result
            .dependencies
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["flask", "requests"]);
    }

    #[test]
    fn test_requirement_length_boundary() {
        // Regression test for critic finding M1: pins the 4096/4097 boundary
        // against the requirement string's own length, not incidental file
        // length. A single extra name made entirely of 'a' gives exact,
        // syntactically-valid control over the total byte length.
        let build = |total_len: usize| {
            let fixed = "pkg[]==1.0".len();
            format!("pkg[{}]==1.0", "a".repeat(total_len - fixed))
        };
        let max = super::super::MAX_REQUIREMENT_LEN;

        let at_cap = build(max);
        assert_eq!(at_cap.len(), max);
        let result = parse(&format!("{at_cap}\n"));
        assert_eq!(
            result.dependencies.len(),
            1,
            "a requirement exactly at the cap must be accepted"
        );

        let over_cap = build(max + 1);
        assert_eq!(over_cap.len(), max + 1);
        let result = parse(&format!("{over_cap}\n"));
        assert_eq!(
            result.dependencies.len(),
            0,
            "a requirement one byte over the cap must be rejected"
        );
    }

    #[test]
    fn test_marker_extras_bracket_injection_rejected() {
        // Regression test for #261: a `;` landing before an oversized
        // extras/version tail (rather than before an actual marker) must not
        // have that tail stored verbatim on `markers`.
        let huge_extras = "a".repeat(60_000);
        let content = format!("pkg;[{huge_extras}]==1.0\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_keyword_repeated_without_separators_rejected() {
        // Regression test for the substring-only `looks_like_marker` bypass:
        // a marker variable name repeated with no separators contains
        // "extra" as a substring but tokenizes as one giant unrecognized
        // identifier, not a real reference to the `extra` marker variable.
        let garbage = "extra".repeat(1600);
        assert!(garbage.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg; {garbage}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_keyword_padded_with_unquoted_garbage_rejected() {
        // Regression test for the substring-only `looks_like_marker` bypass:
        // a real marker variable followed by an unquoted run of filler bytes
        // used to pass (keyword present as a substring, all bytes in the
        // allowed character set); the filler is not a quoted string literal,
        // a known identifier, or an operator, so it must now be rejected.
        let filler = "A".repeat(5000);
        let raw_marker = format!("python_version <{filler}>");
        assert!(raw_marker.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg; {raw_marker}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_repeated_token_no_operator_rejected() {
        // Regression test for the reviewer's residual #261 bypass: bare
        // whitespace-separated repetition of a recognized marker variable,
        // with no comparison operator anywhere, used to still tokenize as
        // "marker-shaped" (at least one recognized token present) and be
        // retained verbatim.
        let garbage = "python_version ".repeat(500);
        let content = format!("pkg; {garbage}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_and_joined_repeated_token_no_operator_rejected() {
        // Same bypass shape, joined by `and` instead of bare whitespace —
        // still no comparison operator anywhere in the text.
        let garbage = "python_version and ".repeat(400) + "python_version";
        let content = format!("pkg; {garbage}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_chained_comparison_rejected() {
        // Regression test for the reviewer's round-3 #261 bypass: chained
        // comparisons share one operand across more than one clause
        // (`a == b == c == ...`), which PEP 508's grammar has no production
        // for — `pep508_rs` itself rejects a short version of this shape
        // outright.
        let chain = "python_version==".repeat(500) + "python_version";
        assert!(chain.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg; {chain}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_marker_chained_in_rejected() {
        // Same bypass shape using `in` instead of `==`.
        let chain = "python_version in ".repeat(500) + "python_version";
        assert!(chain.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg; {chain}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, None);
    }

    #[test]
    fn test_oversized_in_operator_marker_still_normalizes() {
        // Legitimate use of the `in` operator must still be preserved
        // through the raw fallback once it's oversized enough to bypass
        // `pep508_rs`'s parser.
        let marker =
            "python_version in '3.8'".to_string() + &" or python_version in '3.8'".repeat(200);
        assert!(marker.len() > super::super::MAX_MARKER_LEN);
        let content = format!("pkg; {marker}\n");
        let result = parse(&content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "pkg");
        assert_eq!(result.dependencies[0].markers, Some(marker));
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

    // --- documentLink targets (#452) ---

    #[test]
    fn test_document_links_short_form() {
        let content = "-r other-requirements.txt\n-c constraints.txt\nrequests==1.0\n";
        let result = parse(content);
        assert_eq!(result.document_links.len(), 2);
        assert_eq!(result.document_links[0].target, "other-requirements.txt");
        assert_eq!(result.document_links[1].target, "constraints.txt");
    }

    #[test]
    fn test_document_links_long_form_space_separated() {
        let content = "--requirement base.txt\n--constraint constraints.txt\n";
        let result = parse(content);
        assert_eq!(result.document_links.len(), 2);
        assert_eq!(result.document_links[0].target, "base.txt");
        assert_eq!(result.document_links[1].target, "constraints.txt");
    }

    #[test]
    fn test_document_links_long_form_equals_separated() {
        let content = "--requirement=base.txt\n--constraint=constraints.txt\n";
        let result = parse(content);
        assert_eq!(result.document_links.len(), 2);
        assert_eq!(result.document_links[0].target, "base.txt");
        assert_eq!(result.document_links[1].target, "constraints.txt");
    }

    #[test]
    fn test_document_links_range_slices_to_target_text_only() {
        let content = "-r other-requirements.txt\n";
        let result = parse(content);
        let link = &result.document_links[0];
        assert_eq!(slice(content, link.range), "other-requirements.txt");
    }

    #[test]
    fn test_document_links_ignores_unrelated_options() {
        // Options other than -r/-c/--requirement/--constraint (even other
        // known ones) must never produce a document link.
        let content = "-e .\n--index-url https://example.com\n--pre\nrequests==1.0\n";
        let result = parse(content);
        assert!(result.document_links.is_empty());
    }

    #[test]
    fn test_document_links_bare_option_with_no_target_is_skipped() {
        let content = "-r\nrequests==1.0\n";
        let result = parse(content);
        assert!(result.document_links.is_empty());
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
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::Url { .. }
        );
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
            .parse_requirements("requests==1.0\nflask==2.0\n", &uri, false)
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

    // --- require_strong_signal: directory-pattern-only gate (#452 S6) ---

    #[test]
    fn test_strict_gate_drops_prose_that_would_survive_ratio_gate() {
        // A requirements-engineering docs file living under a directory literally
        // named `requirements/` is routed to PyPI purely by directory-name
        // convention (`Ecosystem::manifest_directory_patterns`) — far weaker
        // evidence than a basename match. Bare-word lines like "Introduction"/
        // "Scope" parse as valid (unpinned) PEP 508 names, so the ratio-based
        // arm alone keeps this file; `require_strong_signal: true` must still
        // drop it.
        let content = "Introduction\n\nScope\n\nThis document defines the requirements.\n";

        let lenient = parse(content);
        assert!(
            !lenient.dependencies.is_empty(),
            "sanity check: the ratio gate alone would keep this file"
        );

        let strict = parse_strict(content);
        assert!(strict.dependencies.is_empty());
    }

    #[test]
    fn test_strict_gate_still_keeps_file_with_real_pip_option() {
        // A genuine pip option line is a strong signal regardless of the gate
        // mode — `require_strong_signal` only removes the *ratio* arm.
        let content = "-r base.txt\nrequests==1.0\n";
        let result = parse_strict(content);
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.document_links.len(), 1);
    }

    #[test]
    fn test_strict_gate_still_keeps_file_with_version_specifier() {
        let content = "requests==2.31.0\n";
        let result = parse_strict(content);
        assert_eq!(result.dependencies.len(), 1);
    }

    // --- T003: --index-url / --extra-index-url / -i capture (FR-001, US-001, US-002) ---

    #[test]
    fn test_index_url_routes_every_dependency() {
        let content = "--index-url https://pypi.mycorp.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }

    /// `--index-url=<url>` (equals spelling) is captured identically to the space-separated
    /// form.
    #[test]
    fn test_index_url_equals_spelling() {
        let content = "--index-url=https://pypi.mycorp.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }

    /// `-i` is pip's short alias for `--index-url`.
    #[test]
    fn test_short_dash_i_alias() {
        let content = "-i https://pypi.mycorp.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }

    /// S2 regression: a dependency declared *before* a late `--index-url` line still routes
    /// through it — the two-pass parse's whole reason for existing.
    #[test]
    fn test_index_url_after_dependency_line_still_routes_it() {
        let content = "requests==2.31.0\n--index-url https://pypi.mycorp.example/simple\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert!(
            matches!(
                result.dependencies[0].source,
                PypiDependencySource::AlternateRegistry { .. }
            ),
            "dependency declared before a late --index-url must still resolve through it, \
             got {:?}",
            result.dependencies[0].source
        );
    }

    /// FR-005(b): `--extra-index-url` alone, no explicit primary — routes through the
    /// extras+implicit-public chain, not plain `Registry`.
    #[test]
    fn test_extra_index_url_alone_routes_through_chain() {
        let content = "--extra-index-url https://extra.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }

    /// FR-006: an explicit `--index-url` that fails validation fails closed
    /// (`CustomRegistry`), not a silent `pypi.org` fallback — the #248-class regression.
    #[test]
    fn test_invalid_index_url_fails_closed() {
        let content = "--index-url not-a-valid-url\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(
            result.dependencies[0].source,
            PypiDependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
    }

    /// US-004: no `--index-url`/`--extra-index-url` anywhere -> every dependency stays plain
    /// `Registry`, byte-identical to pre-feature behavior.
    #[test]
    fn test_no_index_declaration_is_plain_registry() {
        let result = parse("requests==2.31.0\nflask>=3.0\n");
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            assert_eq!(dep.source, PypiDependencySource::Registry);
        }
    }

    /// Existing `KNOWN_OPTIONS` classification (e.g. `--pre`, `--no-index`) is unaffected by
    /// the new capture logic — an unrelated recognized option still contributes no index
    /// routing.
    #[test]
    fn test_unrelated_known_option_does_not_affect_routing() {
        let content = "--pre\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].source,
            PypiDependencySource::Registry
        );
    }

    /// A direct URL/Git-sourced dependency is untouched by index routing — those have no
    /// PyPI index concept.
    #[test]
    fn test_git_sourced_dependency_untouched_by_index_config() {
        let content = "--index-url https://pypi.mycorp.example/simple\nname @ https://example.com/name.tar.gz\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::Url { .. }
        );
    }

    /// Validator finding S1: a UTF-8 BOM on the first physical line must not defeat
    /// `--index-url` capture — without stripping it in pass 1, `"\u{feff}--index-url"` fails
    /// the `starts_with('-')` check and the whole declaration is silently skipped.
    #[test]
    fn test_index_url_after_bom_on_first_line_still_captured() {
        let content = "\u{feff}--index-url https://pypi.mycorp.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert!(
            matches!(
                result.dependencies[0].source,
                PypiDependencySource::AlternateRegistry { .. }
            ),
            "BOM must not defeat --index-url capture, got {:?}",
            result.dependencies[0].source
        );
    }

    /// Validator finding S2: a multi-option line must not let a later option's token(s) leak
    /// into the earlier option's captured value — `extract_option_target` must bound the
    /// value to the current token only, not the rest of the line. Tested directly against
    /// `extract_option_target`, since the parsed-config-level chain key is an opaque hash
    /// that can't itself distinguish a clean value from a mangled one.
    #[test]
    fn test_extract_option_target_space_separated_stops_at_next_option() {
        let text =
            "--index-url https://pypi.mycorp.example/simple --trusted-host pypi.mycorp.example";
        let (target, _offset) = extract_option_target("--index-url", text).unwrap();
        assert_eq!(target, "https://pypi.mycorp.example/simple");
    }

    /// Same bug (S2), `--opt=value` equals-spelling with a trailing option on the same line.
    #[test]
    fn test_extract_option_target_equals_separated_stops_at_next_option() {
        let text =
            "--index-url=https://pypi.mycorp.example/simple --trusted-host pypi.mycorp.example";
        let first_token = text.split_whitespace().next().unwrap();
        let (target, _offset) = extract_option_target(first_token, text).unwrap();
        assert_eq!(target, "https://pypi.mycorp.example/simple");
    }

    /// End-to-end confirmation that the fix actually reaches `PypiIndexConfig`: a chain built
    /// from a multi-option line resolves via a clean single-hop URL, not a policy-rejected
    /// mangled one (the mangled form, once percent-encoded, is a different — and differently
    /// classified — URL, so this would fail closed to `CustomRegistry` if the bug regressed).
    #[test]
    fn test_index_url_multi_option_line_does_not_swallow_trailing_options() {
        let content = "--index-url https://pypi.mycorp.example/simple --trusted-host pypi.mycorp.example\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert!(
            matches!(
                result.dependencies[0].source,
                PypiDependencySource::AlternateRegistry { .. }
            ),
            "a mangled URL would still validate as *some* URL but registers a different \
             chain than the clean one — got {:?}",
            result.dependencies[0].source
        );
    }

    /// Same bug (S2), `--extra-index-url=<url>` equals-spelling with a trailing option on the
    /// same line.
    #[test]
    fn test_extra_index_url_equals_multi_option_line_does_not_swallow_trailing_options() {
        let content = "--extra-index-url=https://extra.example/simple --trusted-host extra.example\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }

    /// T012 test gap #12: `--extra-index-url=<url>` equals-spelling is captured identically
    /// to the space-separated form (only `--index-url=` was previously covered).
    #[test]
    fn test_extra_index_url_equals_spelling() {
        let content = "--extra-index-url=https://extra.example/simple\nrequests==2.31.0\n";
        let result = parse_with_policy(content, &all_policy());
        assert_matches!(
            result.dependencies[0].source,
            PypiDependencySource::AlternateRegistry { .. }
        );
    }
}
