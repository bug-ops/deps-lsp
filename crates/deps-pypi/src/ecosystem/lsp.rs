//! LSP-only completion/document-link support for PyPI (issue #1137, #937 document-link
//! hardening).
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: PEP 508's `==`, `!=`, `<=`, `>=`, `<`, `>`, `~=` plus
/// Poetry's caret (`^2.28`, `[tool.poetry.dependencies]`) — `^` was missing here despite
/// `parser::pyproject::parse_poetry_dependencies` accepting caret constraints, so a Poetry
/// manifest's completion silently fell back to an unfiltered list (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['>', '<', '=', '~', '!', '^'];

/// Whether `target` is safe to resolve into a clickable `DocumentLink`.
///
/// Rejects every ASCII control character (`char::is_control()`, the same gate
/// [`deps_core::lsp_helpers::escape_markdown`] uses) plus the Unicode
/// bidi/format characters that gate alone misses — RLO/LRO-family overrides
/// (U+202A-U+202E, U+2066-U+2069), explicit directional marks (U+200E/U+200F),
/// zero-width joiners/spaces (U+200B-U+200D, U+2060, U+FEFF), and the
/// JS/JSON5 line terminators U+2028/U+2029. Without this, a target like
/// `"safe.txt\u{202E}txt.evil"` renders right-to-left in the editor (reading
/// as an innocuous `.txt` file) while the link actually opens `.evil` —
/// link-target spoofing, not merely a cosmetic issue, since the resolved URI
/// is exactly what the user's click opens.
pub(super) fn is_safe_document_link_target(target: &str) -> bool {
    !target.is_empty()
        && target.chars().all(|c| {
            !c.is_control()
                && !matches!(c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{FEFF}'
                )
        })
}

/// Whether `target` is written as an absolute filesystem path — a POSIX-style
/// `/...`/`\...` root, or a Windows drive prefix (`C:\...`, `C:/...`, or the
/// drive-*relative* `C:evil.txt`/bare `C:` forms).
///
/// Checked on the raw string rather than `std::path::Path::is_absolute()`: that method's
/// notion of "absolute" is platform-dependent (a Windows drive prefix is not absolute per
/// `Path` on a POSIX host), but `link.target` is manifest text that could name either
/// path style regardless of which OS `deps-lsp` itself runs on. The drive-letter check
/// deliberately has no separator requirement after the colon: per `std::path`'s own docs,
/// `Path::join`ing a "prefix but no root" path (Windows' term for exactly this
/// `C:evil.txt`/`C:` shape) onto any base discards the base entirely, same as a fully
/// separator-rooted `C:\...` — requiring a separator here would let that variant silently
/// bypass the whole guard on Windows (#937 finding C1). That base-discard is
/// Windows-specific — on POSIX, `Path::join` treats `C:evil.txt` as an ordinary relative
/// segment (`Path::new("/project").join("C:x") == "/project/C:x"`) — but this function has
/// no way to know which platform authored the requirements file, so it rejects the shape
/// uniformly rather than trusting the host OS's own `Path::join` semantics.
pub(super) fn is_absolute_document_link_target(target: &str) -> bool {
    target.starts_with('/')
        || target.starts_with('\\')
        || matches!(target.as_bytes(), [drive, b':', ..] if drive.is_ascii_alphabetic())
}

/// Lexically resolves `.`/`..` components in `path` without touching the filesystem — no
/// `canonicalize`, no symlink resolution, since `generate_document_links` never opens the
/// target, only publishes it as a clickable `DocumentLink`.
///
/// Assumes `path` is rooted: a `..` with nothing left to pop is simply dropped rather
/// than kept as a literal component — the same clamp-at-root behavior a real filesystem
/// gives `/..`. Keeping it (a prior version of this function did) produces a non-canonical
/// path like `/../etc/shadow`: still rejected by the workspace-root containment check
/// today, but a misleading tooltip if that check is ever skipped (#937 finding C2). Every
/// call site upholds the assumption: the join-target call always sees `base_dir.join(...)`
/// (rooted, since `base_dir` comes from the manifest's own file URI), and the
/// workspace-root call site filters through [`is_absolute_document_link_target`] first
/// (#937 finding R2) rather than `Path::is_absolute()` — the latter is platform-dependent
/// (a POSIX-style root like `/project` is not "absolute" per `Path` on Windows, only
/// "has_root"), which would silently skip containment for exactly that shape on Windows. A
/// relative `path` isn't rejected here either way, it just won't clamp to a meaningful
/// root.
pub(super) fn lexically_normalize(path: &std::path::Path) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}
