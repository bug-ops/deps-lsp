//! Python dependency manifest parsing.
//!
//! Two manifest shapes share the [`PypiParser`] type and its `parse_result`
//! representation:
//! - `pyproject.rs`: TOML-based manifests (PEP 621, PEP 735, Poetry, PEP
//!   517/518 build-system requires).
//! - `requirements.rs`: line-oriented `requirements.txt`/`constraints.txt`
//!   files (pip's requirements file format).
//!
//! Both paths funnel every PEP 508 requirement string through the shared
//! `PypiParser::parse_pep508_requirement` below (private — an implementation
//! detail, not part of the public API), so hover, diagnostics, markers and
//! extras render identically regardless of which manifest shape produced the
//! dependency.

use crate::error::{PypiError, Result};
use crate::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
use deps_core::lsp_helpers::LineOffsetTable;
use pep508_rs::{MarkerTree, Requirement, VersionOrUrl};
use std::any::Any;
use std::str::FromStr;
use tower_lsp_server::ls_types::{Position, Range, Uri};

pub mod pyproject;
pub mod requirements;

/// Marker expressions longer than this are not handed to `pep508_rs`'s
/// recursive-descent parser, which has no depth limit and can overflow the
/// stack on deeply nested expressions (verified: ~5000 nested parens, ~10 KiB,
/// aborts the process; ~4000 survives). Text over the cap falls back to its
/// raw, unnormalized form (see [`bounded_marker_fallback`]) rather than
/// being parsed.
const MAX_MARKER_LEN: usize = 2048;

/// Requirement strings (name + extras + version specifier, excluding the
/// marker section) longer than this are rejected outright rather than handed
/// to `pep508_rs`'s extras-list parser, which runs in O(n²) on the extras
/// list (verified: `pkg[a,a,a,...]` with ~256 KiB of repeated single-char
/// extras takes ~400ms to parse; the cost grows quadratically with input
/// length). Real-world requirement lines are well under 200 bytes, so this
/// cap leaves ample headroom while bounding worst-case parse time for a
/// single requirement to well under a millisecond.
const MAX_REQUIREMENT_LEN: usize = 4096;

/// Generous bound on PEP 508 marker parenthesis nesting depth.
///
/// `pep508_rs`'s recursive-descent marker parser recurses once per nesting
/// level with no depth limit, so a marker can overflow the stack from
/// nesting alone while staying well under [`MAX_MARKER_LEN`] — a marker can
/// pack roughly one `(`/`)` pair per 2 bytes (verified: 1016 levels in 2047
/// bytes aborts the process on a 256 KiB stack). Real-world markers rarely
/// nest more than 2-3 levels, so this cap leaves ample headroom.
const MAX_MARKER_DEPTH: u32 = 32;

/// PEP 508 marker environment variable names (`marker.rs`'s `env_var`
/// production), plus `extra`. A genuine marker expression is built around
/// one of these; text that lacks all of them is not a marker at all — e.g.
/// leftover extras/version syntax that ended up past a `;` by accident.
const MARKER_VARIABLE_NAMES: &[&str] = &[
    "python_version",
    "python_full_version",
    "os_name",
    "sys_platform",
    "platform_release",
    "platform_system",
    "platform_version",
    "platform_machine",
    "platform_python_implementation",
    "implementation_name",
    "implementation_version",
    "extra",
];

/// Independent, generous ceiling on marker text retained by the raw-marker
/// fallback below (triggered when text is too long or too deeply nested for
/// `pep508_rs`'s parser). Kept well above [`MAX_MARKER_LEN`] so
/// legitimate-if-verbose marker chains that only barely miss the parser's
/// cap are still retained, while still bounding what a crafted
/// marker-shaped payload can push into a dependency's `markers` field and,
/// from there, hover.
const MAX_FALLBACK_MARKER_LEN: usize = MAX_MARKER_LEN * 4;

/// One lexical unit of a candidate marker expression, as classified by
/// [`tokenize_marker`] and consumed by [`validate_marker_grammar`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkerToken {
    /// `(`, opening a grouped sub-expression.
    LParen,
    /// `)`, closing a grouped sub-expression.
    RParen,
    /// The `and` boolean connective.
    And,
    /// The `or` boolean connective.
    Or,
    /// A comparison operator: `==`, `!=`, `<=`, `>=`, `~=`, `<`, `>`.
    CmpOp,
    /// The `in` keyword (also the second half of a `not in` operator).
    In,
    /// The `not` keyword, valid only as the first half of `not in`.
    Not,
    /// A recognized marker variable name (an operand).
    Var,
    /// A quoted string literal (an operand).
    Str,
}

/// Tokenizes `text` for [`looks_like_marker`], or returns `None` if any byte
/// or word doesn't fit one of PEP 508's marker-expression lexical classes.
///
/// Quote-matching mirrors `pep508_rs`'s tokenizer: a quote opens on an
/// unquoted `'`/`"` and closes on the next occurrence of that same byte, with
/// no escape handling — so quoted content, including non-ASCII bytes, is
/// opaque to this scanner.
fn tokenize_marker(text: &str) -> Option<Vec<MarkerToken>> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut tokens: Vec<MarkerToken> = Vec::new();

    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'(' => {
                tokens.push(MarkerToken::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(MarkerToken::RParen);
                i += 1;
            }
            quote @ (b'\'' | b'"') => {
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                if i >= bytes.len() {
                    return None; // unterminated string literal
                }
                i += 1; // consume closing quote
                tokens.push(MarkerToken::Str);
            }
            b'=' | b'!' | b'<' | b'>' | b'~' => {
                let start = i;
                while i < bytes.len() && matches!(bytes[i], b'=' | b'!' | b'<' | b'>' | b'~') {
                    i += 1;
                }
                if !matches!(
                    &text[start..i],
                    "==" | "!=" | "<=" | ">=" | "~=" | "<" | ">"
                ) {
                    return None;
                }
                tokens.push(MarkerToken::CmpOp);
            }
            b if b.is_ascii_alphanumeric() || b == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &text[start..i];
                tokens.push(if MARKER_VARIABLE_NAMES.contains(&word) {
                    MarkerToken::Var
                } else {
                    match word {
                        "and" => MarkerToken::And,
                        "or" => MarkerToken::Or,
                        "not" => MarkerToken::Not,
                        "in" => MarkerToken::In,
                        _ => return None,
                    }
                });
            }
            _ => return None,
        }
    }

    Some(tokens)
}

/// One step in the bounded grammar walk performed by [`validate_marker_grammar`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClauseState {
    /// Expecting the start of a new atom: `(` or an operand.
    ExpectAtom,
    /// Consumed a clause's first operand; expecting its comparison operator.
    ExpectOperator,
    /// Consumed `not`; the only valid continuation is `in`.
    ExpectIn,
    /// Consumed a clause's operator; expecting its second operand.
    ExpectSecondOperand,
    /// Just completed a full atom (clause or parenthesized group); expecting
    /// `and`, `or`, `)`, or end of input.
    AfterAtom,
}

/// Validates that `tokens` decomposes as a PEP 508 `marker_expr`:
///
/// ```text
/// marker_expr    := marker_and ('or' marker_and)*
/// marker_and     := marker_atom ('and' marker_atom)*
/// marker_atom    := '(' marker_expr ')' | marker_clause
/// marker_clause  := operand comparison_op operand
/// operand        := marker_variable | quoted_string
/// comparison_op  := '==' | '!=' | '<=' | '>=' | '<' | '>' | '~=' | 'in' | 'not' 'in'
/// ```
///
/// Each `marker_clause` consumes exactly one `operand op operand` triple, so
/// an operand can never be shared between two clauses — this is what rejects
/// chained comparisons like `a == b == c` or `a in b in c`, which PEP 508's
/// grammar has no production for (`pep508_rs` itself rejects them).
///
/// This walks the token stream once, left to right, tracking only the
/// current [`ClauseState`] and a paren-nesting counter — no recursion and no
/// per-level state stack, so nesting depth is unbounded (needed: a genuine
/// marker can nest hundreds of levels within [`MAX_FALLBACK_MARKER_LEN`] and
/// must still validate, since parenthesis-nesting depth is already handled
/// separately by routing such text away from `pep508_rs`'s own unbounded
/// recursive-descent parser — see [`MAX_MARKER_DEPTH`], [`marker_too_deep`]).
/// A closing `)` always returns the *enclosing* level to `AfterAtom`
/// regardless of depth, since a parenthesized group is itself a complete atom
/// to whatever follows it — no per-level bookkeeping beyond the depth count
/// is needed to know that.
fn validate_marker_grammar(tokens: &[MarkerToken]) -> bool {
    let mut state = ClauseState::ExpectAtom;
    let mut depth: usize = 0;

    for &tok in tokens {
        state = match (state, tok) {
            (ClauseState::ExpectAtom, MarkerToken::LParen) => {
                depth += 1;
                ClauseState::ExpectAtom
            }
            (ClauseState::ExpectAtom, MarkerToken::Var | MarkerToken::Str) => {
                ClauseState::ExpectOperator
            }
            (ClauseState::ExpectOperator, MarkerToken::CmpOp | MarkerToken::In) => {
                ClauseState::ExpectSecondOperand
            }
            (ClauseState::ExpectOperator, MarkerToken::Not) => ClauseState::ExpectIn,
            (ClauseState::ExpectIn, MarkerToken::In) => ClauseState::ExpectSecondOperand,
            (ClauseState::ExpectSecondOperand, MarkerToken::Var | MarkerToken::Str) => {
                ClauseState::AfterAtom
            }
            (ClauseState::AfterAtom, MarkerToken::And | MarkerToken::Or) => ClauseState::ExpectAtom,
            (ClauseState::AfterAtom, MarkerToken::RParen) if depth > 0 => {
                depth -= 1;
                ClauseState::AfterAtom
            }
            _ => return false,
        };
    }

    state == ClauseState::AfterAtom && depth == 0
}

/// Returns `true` if `text` tokenizes and parses cleanly as a PEP 508
/// `marker_expr` (see [`validate_marker_grammar`] for the grammar).
///
/// This is enough to reject the length/depth-bypass fallback's actual threat
/// model: arbitrary attacker-controlled bytes with no marker structure at
/// all — e.g. PEP 508 extras/version syntax that ends up past a `;` by
/// accident (#261), a marker keyword padded with unrelated filler, bare
/// repetition of recognized marker-variable tokens with no operator between
/// them, or operand-sharing chained comparisons (`a == b == c`, `a in b in
/// c`) that a per-operand adjacency check cannot distinguish from a real
/// clause. Genuine, if oversized or deeply-nested, marker expressions still
/// tokenize and parse cleanly and are preserved verbatim.
fn looks_like_marker(text: &str) -> bool {
    tokenize_marker(text).is_some_and(|tokens| validate_marker_grammar(&tokens))
}

/// Bounds raw marker text before it is stored verbatim on a dependency's
/// `markers` field (and, from there, rendered into hover), for text that
/// bypassed `pep508_rs`'s parser entirely because it was too long or too
/// deeply nested (see [`marker_too_deep`], [`MAX_MARKER_LEN`]).
///
/// Text that isn't plausibly a marker expression ([`looks_like_marker`]) or
/// that exceeds [`MAX_FALLBACK_MARKER_LEN`] is dropped rather than
/// retained.
fn bounded_marker_fallback(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_FALLBACK_MARKER_LEN || !looks_like_marker(raw) {
        return None;
    }
    Some(raw.to_string())
}

/// Returns `true` if `marker` nests parentheses deeper than [`MAX_MARKER_DEPTH`].
///
/// Tracks quoted-string state the same way `pep508_rs`'s tokenizer does
/// (`marker/parse.rs`: a quote opens on an unquoted `'`/`"` and closes on the
/// next occurrence of that same character, with no escape handling) so that
/// `(`/`)` bytes inside a quoted marker value — e.g. `extra == ')'` — are not
/// mistaken for real nesting. A scanner that counted paren bytes unconditionally
/// could be tricked into undercounting depth by parentheses hidden in quoted
/// values while the real recursive-descent parser, which treats quoted content
/// as opaque, keeps recursing.
fn marker_too_deep(marker: &str) -> bool {
    let mut depth: u32 = 0;
    let mut quote: Option<u8> = None;
    for b in marker.bytes() {
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' => {
                depth += 1;
                if depth > MAX_MARKER_DEPTH {
                    return true;
                }
            }
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Longest prefix of an attacker-controlled requirement/dependency string
/// logged verbatim by [`truncate_for_log`].
const MAX_LOGGED_LEN: usize = 200;

/// Truncates `s` to a safe-to-log prefix, so a warn!/debug! call site can
/// never turn into a multi-megabyte synchronous write to the (by default,
/// unbuffered, stderr-backed) log sink — exactly the size range
/// [`MAX_REQUIREMENT_LEN`] exists to reject, up to the ~10 MB overall file
/// cap. Falls back to `s` unchanged when it's already short enough.
fn truncate_for_log(s: &str) -> std::borrow::Cow<'_, str> {
    if s.len() <= MAX_LOGGED_LEN {
        return std::borrow::Cow::Borrowed(s);
    }
    let boundary = s.floor_char_boundary(MAX_LOGGED_LEN);
    std::borrow::Cow::Owned(format!("{}... ({} bytes total)", &s[..boundary], s.len()))
}

/// A `-r`/`-c` reference to another requirements/constraints file.
///
/// Surfaced as a `textDocument/documentLink` so it can be ctrl/cmd-clicked
/// open. Only produced by [`PypiParser::parse_requirements`] —
/// `pyproject.toml` has no equivalent file-to-file reference.
#[derive(Debug, Clone)]
pub struct RequirementRef {
    /// Source range of the referenced path text on the option line.
    pub range: tower_lsp_server::ls_types::Range,
    /// The target as written in the file (e.g. `"constraints.txt"`), not yet
    /// resolved to an absolute URI — resolution happens against the
    /// containing document's URI in `PypiEcosystem`'s
    /// [`Ecosystem::generate_document_links`](deps_core::Ecosystem::generate_document_links) override.
    pub target: String,
}

/// Parse result containing all dependencies from a Python dependency manifest.
///
/// Stores dependencies and optional workspace information for LSP operations.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// All dependencies found in the manifest
    pub dependencies: Vec<PypiDependency>,
    /// Workspace root path (None for Python - no workspace concept like Cargo)
    pub workspace_root: Option<std::path::PathBuf>,
    /// URI of the parsed file
    pub uri: Uri,
    /// `-r`/`-c` file references found in a requirements file (always empty
    /// for `pyproject.toml`).
    pub document_links: Vec<RequirementRef>,
}

impl deps_core::ParseResult for ParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.workspace_root.as_deref()
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parser for Python dependency manifests.
///
/// Supports `pyproject.toml` (PEP 621, PEP 735, Poetry, PEP 517/518) via
/// [`PypiParser::parse_content`] and `requirements.txt`/`constraints.txt`
/// (pip's requirements file format) via
/// [`PypiParser::parse_requirements`].
///
/// # Examples
///
/// ```no_run
/// use deps_pypi::parser::PypiParser;
/// use tower_lsp_server::ls_types::Uri;
///
/// let content = r#"
/// [project]
/// dependencies = ["requests>=2.28.0", "flask[async]>=3.0"]
/// "#;
///
/// let parser = PypiParser::new();
/// let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();
/// let result = parser.parse_content(content, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
/// ```
pub struct PypiParser;

impl PypiParser {
    /// Create a new PyPI parser.
    pub const fn new() -> Self {
        Self
    }

    /// Parse a PEP 508 requirement string, shared by every manifest shape.
    ///
    /// Example: `requests[security,socks]>=2.28.0,<3.0; python_version>='3.8'`
    ///
    /// `span` is the requirement string's source byte range (used for both
    /// `Position` tracking and, via [`span_to_range`], UTF-16-correct
    /// `markers_range` computation). TOML callers pass `value.span.start..value.span.end`;
    /// the requirements.txt line parser passes the requirement text's absolute
    /// byte offsets directly, with no TOML dependency.
    fn parse_pep508_requirement(
        &self,
        requirement_str: &str,
        span: Option<std::ops::Range<usize>>,
        content: &str,
        line_table: &LineOffsetTable,
    ) -> Result<PypiDependency> {
        let base_position = span
            .clone()
            .map(|r| span_start(content, line_table, toml_span::Span::new(r.start, r.end)));

        // `;` never appears inside a version/extras clause, so the first
        // occurrence unambiguously anchors the marker section (direct-reference
        // URLs containing `;` are a known, documented edge case - see #<follow-up>).
        let semicolon_idx = requirement_str.find(';');

        // The name/extras/version portion — excluding the marker section —
        // over the cap is rejected outright rather than handed to
        // `pep508_rs`, whose extras-list parser runs in O(n²) on the extras
        // list — an attacker-controlled `pkg[a,a,a,...]` list can otherwise
        // block a tokio worker for minutes. Measured against this portion
        // only (not the whole `requirement_str`) so an oversized *marker*
        // still takes the `MAX_MARKER_LEN` graceful-degradation path below
        // instead of being rejected here too. Unlike that marker guard,
        // there's no cheap subset to fall back to for extras: the quadratic
        // cost lives in the name/extras/version portion itself, so the whole
        // dependency is skipped instead.
        let pre_marker_len = semicolon_idx.unwrap_or(requirement_str.len());
        if pre_marker_len > MAX_REQUIREMENT_LEN {
            tracing::warn!(
                "Requirement string exceeds the {MAX_REQUIREMENT_LEN}-byte length cap ({} bytes), skipping: {}",
                pre_marker_len,
                truncate_for_log(requirement_str)
            );
            return Err(PypiError::RequirementTooLong {
                len: pre_marker_len,
                max: MAX_REQUIREMENT_LEN,
            });
        }

        // Pathologically long or deeply nested marker expressions can overflow
        // the stack in `pep508_rs`'s unbounded recursive-descent parser. Parse
        // only the name/version/extras portion and skip marker normalization
        // instead of handing the oversized/deeply-nested marker text to the
        // parser.
        let marker_too_complex = semicolon_idx.is_some_and(|idx| {
            let marker_text = &requirement_str[idx..];
            marker_text.len() > MAX_MARKER_LEN || marker_too_deep(marker_text)
        });
        let parse_str = if marker_too_complex {
            &requirement_str[..semicolon_idx.unwrap()]
        } else {
            requirement_str
        };

        let requirement = Requirement::from_str(parse_str)
            .map_err(|e| PypiError::InvalidDependencySpec { source: e })?;

        let name = requirement.name.to_string();
        let name_range = base_position
            .map(|pos| {
                Range::new(
                    pos,
                    Position::new(pos.line, pos.character + name.len() as u32),
                )
            })
            .unwrap_or_default();

        // Version/extras text never extends past the marker section.
        let version_end = semicolon_idx.unwrap_or(requirement_str.len());

        let (version_req, version_range, source) = match requirement.version_or_url {
            Some(VersionOrUrl::VersionSpecifier(specs)) => {
                let version_str = specs.to_string();
                // Derive `start_offset` by scanning the *raw* requirement text
                // for the first specifier character at bracket-depth 0, rather
                // than computing it from the pep508-normalized name and
                // rejoined extras — those diverge from source spacing/casing
                // (spaced extras `flask [async] >= 3.0`, a normalized name
                // like `my-pkg` for source `my__pkg`), which would otherwise
                // point `version_range` at the wrong bytes.
                let mut depth = 0usize;
                let derived = requirement_str[..version_end]
                    .char_indices()
                    .find_map(|(i, c)| match c {
                        '[' => {
                            depth += 1;
                            None
                        }
                        ']' => {
                            depth = depth.saturating_sub(1);
                            None
                        }
                        '=' | '<' | '>' | '!' | '~' if depth == 0 => Some(i),
                        _ => None,
                    });
                let start_offset = derived.unwrap_or_else(|| {
                    let extras_str_len = if requirement.extras.is_empty() {
                        0
                    } else {
                        let extras_joined = requirement
                            .extras
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        extras_joined.len() + 2 // +2 for [ and ]
                    };
                    name.len() + extras_str_len
                });

                // Calculate original version length from requirement_str, bounded
                // at the marker section so the range never overlaps markers_range
                // (it is the sole TextEdit target for the "update version" code
                // action, so overlap would delete the marker on accept).
                // pep508 normalizes version specifiers (e.g., ">=1.7,<2.0" -> ">=1.7, <2.0")
                // We need the original length for correct position tracking
                let original_version_len = version_end.saturating_sub(start_offset);

                // `start_offset` is a byte index added directly to `pos.character`,
                // an LSP UTF-16 code-unit count. Safe only because every character
                // that can precede a PEP 508 specifier (name, `[`, extras, `]`,
                // whitespace) is guaranteed ASCII by the PEP 508 grammar — do not
                // generalize this arithmetic to a context where that isn't true.
                let version_range = base_position.map(|pos| {
                    Range::new(
                        Position::new(pos.line, pos.character + start_offset as u32),
                        Position::new(
                            pos.line,
                            pos.character + start_offset as u32 + original_version_len as u32,
                        ),
                    )
                });
                (
                    Some(version_str),
                    version_range,
                    PypiDependencySource::Registry,
                )
            }
            Some(VersionOrUrl::Url(url)) => {
                let url_str = url.to_string();
                if url_str.starts_with("git+") {
                    (
                        None,
                        None,
                        PypiDependencySource::Git {
                            url: url_str,
                            rev: None,
                        },
                    )
                } else if url_str.ends_with(".whl") || url_str.ends_with(".tar.gz") {
                    (None, None, PypiDependencySource::Url { url: url_str })
                } else {
                    (None, None, PypiDependencySource::Registry)
                }
            }
            None => (None, None, PypiDependencySource::Registry),
        };

        let extras: Vec<String> = requirement
            .extras
            .into_iter()
            .map(|e| e.to_string())
            .collect();

        let markers = if marker_too_complex {
            let raw_marker = requirement_str[semicolon_idx.unwrap() + 1..].trim();
            if raw_marker.is_empty() {
                None
            } else {
                tracing::warn!(
                    "Marker expression for '{}' is too complex ({} bytes, over the {}-byte length cap or {}-level nesting cap), skipping normalization",
                    name,
                    raw_marker.len(),
                    MAX_MARKER_LEN,
                    MAX_MARKER_DEPTH
                );
                bounded_marker_fallback(raw_marker)
            }
        } else {
            requirement.marker.try_to_string()
        };

        // The marker text starts right after the first `;` in the original
        // requirement string; `pep508_rs` doesn't expose a source span for it.
        let markers_range = markers.as_ref().and_then(|_| {
            let idx = semicolon_idx?;
            span.map(|r| {
                span_to_range(
                    content,
                    line_table,
                    toml_span::Span::new(r.start + idx + 1, r.end),
                )
            })
        });

        Ok(PypiDependency {
            name: name.into(),
            name_range,
            version_req: version_req.map(Into::into),
            version_range,
            extras,
            extras_range: None,
            markers,
            markers_range,
            section: PypiDependencySection::Dependencies,
            source,
        })
    }
}

impl Default for PypiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert the start of a byte span to an LSP Position.
///
/// toml-span string spans exclude surrounding quotes, so the span start
/// points directly to the first character of the string content.
fn span_start(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Position {
    line_table.byte_offset_to_position(content, span.start)
}

/// Converts a byte span to an LSP `Range` using the pre-computed line table.
fn span_to_range(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Range {
    let start = line_table.byte_offset_to_position(content, span.start);
    let end = line_table.byte_offset_to_position(content, span.end);
    Range::new(start, end)
}

/// Parses a raw PEP 508 marker expression and serializes it back through
/// `MarkerTree` for consistency with the PEP 621 requirement-string path,
/// which canonicalizes markers on serialization (e.g. `python_version`
/// comparisons become `python_full_version`).
///
/// Returns `None` for an empty/whitespace-only expression, or one that
/// normalizes to the trivially-true marker (which has no string form, e.g.
/// `os_name == 'a' or os_name != 'a'`) — matching the PEP 621 path, which
/// likewise yields `None` for an absent or always-true marker. If the
/// expression fails to parse, or exceeds [`MAX_MARKER_LEN`] or
/// [`MAX_MARKER_DEPTH`] and bypasses the parser entirely, it falls back to
/// [`bounded_marker_fallback`], which drops text that isn't plausibly a
/// marker expression or that exceeds [`MAX_FALLBACK_MARKER_LEN`].
fn normalize_marker_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > MAX_MARKER_LEN || marker_too_deep(trimmed) {
        tracing::warn!(
            "Marker expression is too complex ({} bytes, over the {}-byte length cap or {}-level nesting cap), skipping normalization: '{}'",
            trimmed.len(),
            MAX_MARKER_LEN,
            MAX_MARKER_DEPTH,
            truncate_for_log(trimmed)
        );
        return bounded_marker_fallback(trimmed);
    }
    match MarkerTree::from_str(trimmed) {
        Ok(tree) => tree.try_to_string(),
        Err(e) => {
            tracing::warn!("Failed to parse marker expression '{}': {}", trimmed, e);
            bounded_marker_fallback(trimmed)
        }
    }
}
