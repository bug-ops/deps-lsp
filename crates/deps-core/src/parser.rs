use crate::error::Result;
use tower_lsp_server::ls_types::{Range, Uri};

/// Maximum allowed nesting depth for TOML table/array recursion before
/// [`check_toml_nesting_depth`] rejects the input.
///
/// Counts both `[`/`{` bracket depth and dotted-key/table-header segment
/// count (e.g. `a.b.c` or `[a.b.c]`), since both drive `toml-span`'s
/// recursive descent.
///
/// `toml-span` 0.7.1's recursive-descent parser has no recursion limit, so
/// either a deeply nested `[[[...]]]` array/`{{{...}}}` inline-table
/// literal, or a dotted key/header with many `.`-separated segments, can
/// overflow the native thread stack and abort the whole process (SIGABRT)
/// before `toml_span::parse` ever returns an error. As a library, `deps-core`
/// cannot rely on its consumers raising their stack size, so this constant
/// deliberately assumes the smallest stack any caller is likely to run on: a
/// `tokio` worker thread's 2 MiB default (relevant since lock file parsing
/// runs inside `tokio::spawn`), not the platform's larger 8 MiB main-thread
/// default. `deps-lsp`, the one consumer in this workspace, additionally
/// raises its `tokio` worker stacks to 8 MiB as defense-in-depth on top of
/// this guard (see `WORKER_THREAD_STACK_SIZE` in `deps-lsp`'s `main.rs`), but
/// the constant itself stays sized for the 2 MiB floor. Stack cost per level
/// is also shape-dependent: nested inline tables (`{a={a=...}}`) cost
/// noticeably more per level than nested arrays in a debug build.
///
/// Bisected against the real `toml_span` 0.7.1 recursion on a 2 MiB stack:
/// a debug build survives depth 220 for inline tables / 305 for arrays; a
/// release build survives roughly 2485 / 1805. 64 leaves a >3x margin under
/// the tightest of these (debug inline tables, 220) while still being far
/// deeper than any real manifest needs — across a corpus of thousands of
/// real-world `.toml` files, the deepest observed bracket nesting was 5 and
/// the deepest dotted-key path was 6 segments.
pub const MAX_TOML_NESTING_DEPTH: usize = 64;

/// Scans raw TOML text for table/array recursion deeper than `max_depth`.
///
/// `toml-span::parse` has no public option to cap recursion, so callers must
/// reject pathological input before handing it to the parser. This performs a
/// single-pass structural scan — no actual parsing, so it cannot itself
/// recurse or overflow — that bounds the two independent ways TOML content
/// drives `toml-span`'s table/array recursion:
///
/// - **Bracket nesting**: `[`/`{` and `]`/`}` pairs, as in `[[[1]]]` or
///   `{a={a=1}}`.
/// - **Dotted-key/header segments**: each `.` in a dotted key (`a.b.c = 1`)
///   or dotted table header (`[a.b.c]`) creates one level of table nesting
///   with zero bracket characters, so bracket-only counting alone is not
///   sufficient. Dots are only counted in *key* position (start of a
///   top-level statement, inside a `[...]`/`[[...]]` header, or right after
///   `{`/`,` while the innermost open bracket is `{`) — never in *value*
///   position, so `a = 3.14` and multi-segment version/date values are not
///   miscounted.
///
/// Both counts accumulate into one shared depth budget bounded by
/// `max_depth`, since both are ways `toml-span` recurses. Bracket characters
/// and dots inside string literals or line comments are skipped, so this
/// does not misfire on values like `"flask[async]>=3.0"` or `# example:
/// [1, 2]`. Both single-line (`"..."`, `'...'`, honoring `\"` escapes) and
/// multi-line (`"""..."""`, `'''...'''`, including a body that legally ends
/// with 1-2 extra literal quote characters before the closing delimiter, per
/// the TOML spec) string forms are recognized, so brackets and dots inside a
/// multi-line string body are never miscounted.
///
/// # Errors
///
/// Returns `Err(depth)` with the depth reached the instant nesting exceeds
/// `max_depth`.
///
/// # Examples
///
/// ```
/// use deps_core::parser::check_toml_nesting_depth;
///
/// assert!(check_toml_nesting_depth(r#"a = [1, 2, [3, 4]]"#, 4).is_ok());
/// assert!(check_toml_nesting_depth("a = '''don't'''\nb = [1]", 4).is_ok());
/// assert!(check_toml_nesting_depth("a = 3.14\nb.c = 1", 4).is_ok());
///
/// let deeply_nested = format!("a = {}1{}", "[".repeat(10), "]".repeat(10));
/// assert_eq!(check_toml_nesting_depth(&deeply_nested, 4), Err(5));
///
/// let deep_dotted_key = format!("a{} = 1", ".a".repeat(10));
/// assert_eq!(check_toml_nesting_depth(&deep_dotted_key, 4), Err(5));
/// ```
pub fn check_toml_nesting_depth(content: &str, max_depth: usize) -> std::result::Result<(), usize> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut depth: usize = 0;
    let mut i = 0;

    // Bracket kinds currently open, used only to tell whether a `,` is
    // inside an inline table (`{`, next token is a key) or an array (`[`,
    // next token is a value).
    let mut bracket_stack: Vec<u8> = Vec::new();
    // Dot-segment counts not yet released, one frame per currently-open key
    // context: index 0 is the persistent top-level-statement frame (reset at
    // each top-level newline); further frames are pushed per open `{`.
    let mut dot_frames: Vec<usize> = vec![0];
    let mut in_key = true;

    while i < len {
        match bytes[i] {
            b'#' => {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            quote @ (b'"' | b'\'') => {
                let is_multiline =
                    bytes.get(i + 1) == Some(&quote) && bytes.get(i + 2) == Some(&quote);
                i = if is_multiline {
                    skip_multiline_string(bytes, i + 3, quote)
                } else {
                    skip_single_line_string(bytes, i + 1, quote)
                };
            }
            b'{' => {
                depth += 1;
                if depth > max_depth {
                    return Err(depth);
                }
                bracket_stack.push(b'{');
                dot_frames.push(0);
                in_key = true;
                i += 1;
            }
            b'[' => {
                depth += 1;
                if depth > max_depth {
                    return Err(depth);
                }
                bracket_stack.push(b'[');
                i += 1;
            }
            b'}' => {
                if dot_frames.len() > 1 {
                    depth = depth.saturating_sub(dot_frames.pop().unwrap_or(0));
                }
                depth = depth.saturating_sub(1);
                bracket_stack.pop();
                in_key = false;
                i += 1;
            }
            b']' => {
                depth = depth.saturating_sub(1);
                bracket_stack.pop();
                i += 1;
            }
            b'.' if in_key => {
                depth += 1;
                if let Some(top) = dot_frames.last_mut() {
                    *top += 1;
                }
                if depth > max_depth {
                    return Err(depth);
                }
                i += 1;
            }
            b'=' if in_key => {
                in_key = false;
                i += 1;
            }
            b',' => {
                match bracket_stack.last() {
                    Some(b'{') => {
                        if dot_frames.len() > 1 {
                            depth = depth.saturating_sub(dot_frames.pop().unwrap_or(0));
                        }
                        dot_frames.push(0);
                        in_key = true;
                    }
                    Some(b'[') => in_key = false,
                    _ => {}
                }
                i += 1;
            }
            b'\n' => {
                if bracket_stack.is_empty() {
                    depth = depth.saturating_sub(dot_frames[0]);
                    dot_frames[0] = 0;
                    in_key = true;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }

    Ok(())
}

/// Advances past a single-line TOML string (`"..."` or `'...'`), returning
/// the index just past its closing quote (or `bytes.len()` if unterminated —
/// `toml_span` reports the real syntax error in that case, so it is safe for
/// the rest of the file to be treated as string content here).
fn skip_single_line_string(bytes: &[u8], mut i: usize, quote: u8) -> usize {
    let len = bytes.len();
    while i < len {
        if bytes[i] == b'\\' && quote == b'"' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    i
}

/// Advances past a multi-line TOML string body (after its opening `"""`/`'''`),
/// returning the index just past the closing delimiter.
///
/// Per the TOML spec, a multi-line basic string body may end with 1-2 literal
/// quote characters immediately before the closing triple quote (e.g.
/// `"""ends with "".""""` — content `ends with ""."`, then the closer). Any
/// run of 3+ consecutive unescaped quote characters is therefore treated as
/// the closing delimiter, regardless of how many of those quotes are "extra"
/// literal content versus the delimiter itself — the distinction does not
/// matter here since the whole run is consumed either way.
fn skip_multiline_string(bytes: &[u8], mut i: usize, quote: u8) -> usize {
    let len = bytes.len();
    while i < len {
        if bytes[i] == b'\\' && quote == b'"' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            let run_start = i;
            while i < len && bytes[i] == quote {
                i += 1;
            }
            if i - run_start >= 3 {
                return i;
            }
            continue;
        }
        i += 1;
    }
    i
}

/// Generic manifest parser interface.
///
/// Implementors parse ecosystem-specific manifest files (Cargo.toml, package.json, etc.)
/// and extract dependency information with precise LSP positions.
///
/// # Note
///
/// This trait is being phased out in favor of the `Ecosystem` trait.
/// New implementations should use `Ecosystem::parse_manifest()` instead.
pub trait ManifestParser: Send + Sync {
    /// Parsed dependency type for this ecosystem.
    type Dependency: DependencyInfo + Clone + Send + Sync;

    /// Parse result containing dependencies and optional workspace information.
    type ParseResult: ParseResultInfo<Dependency = Self::Dependency> + Send;

    /// Parses a manifest file and extracts all dependencies with positions.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Manifest syntax is invalid
    /// - File path cannot be determined from URL
    fn parse(&self, content: &str, doc_uri: &Uri) -> Result<Self::ParseResult>;
}

/// Dependency information trait.
///
/// All parsed dependencies must implement this for generic handler access.
///
/// # Note
///
/// The new `Ecosystem` trait uses `crate::ecosystem::Dependency` instead.
/// This trait is kept for backward compatibility during migration.
pub trait DependencyInfo {
    /// Dependency name (package/crate name).
    fn name(&self) -> &str;

    /// LSP range of the dependency name in the source file.
    fn name_range(&self) -> Range;

    /// Version requirement string (e.g., "^1.0", "~2.3.4").
    fn version_requirement(&self) -> Option<&str>;

    /// LSP range of the version string (for inlay hints positioning).
    fn version_range(&self) -> Option<Range>;

    /// Dependency source (registry, git, path).
    fn source(&self) -> DependencySource;

    /// Feature flags requested (Cargo-specific, empty for npm).
    fn features(&self) -> &[String] {
        &[]
    }
}

/// Parse result information trait.
///
/// # Note
///
/// The new `Ecosystem` trait uses `crate::ecosystem::ParseResult` instead.
/// This trait is kept for backward compatibility during migration.
pub trait ParseResultInfo {
    type Dependency: DependencyInfo;

    /// All dependencies found in the manifest.
    fn dependencies(&self) -> &[Self::Dependency];

    /// Workspace root path (for monorepo support).
    fn workspace_root(&self) -> Option<&std::path::Path>;
}

/// Dependency source location (shared across all ecosystems).
///
/// Covers the union of all source types across Cargo, npm, PyPI, Go,
/// Dart, Bundler, Maven, and Gradle ecosystems.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependencySource {
    /// Default package registry (crates.io, npm, PyPI, pub.dev, rubygems.org, Maven Central).
    Registry,

    /// Git repository dependency.
    Git {
        url: String,
        /// Git ref: commit SHA, tag, or branch name (ecosystem-specific semantics).
        rev: Option<String>,
    },

    /// Local filesystem path dependency.
    Path { path: String },

    /// Direct URL to artifact (PyPI wheels, npm tarballs).
    Url { url: String },

    /// SDK-provided dependency (Dart: `sdk: flutter`).
    Sdk { sdk: String },

    /// Workspace-inherited dependency (Cargo: `workspace = true`).
    Workspace,

    /// Custom/alternative registry (Bundler custom sources, private registries).
    CustomRegistry { url: String },
}

impl DependencySource {
    /// Returns true if this dependency comes from any registry (default or custom).
    ///
    /// Registry dependencies support version fetching and update checks.
    /// Git, Path, Url, Sdk, and Workspace dependencies do not.
    pub fn is_registry(&self) -> bool {
        matches!(self, Self::Registry | Self::CustomRegistry { .. })
    }

    /// Returns true if version resolution is possible for this source.
    ///
    /// Currently equivalent to `is_registry()`, but semantically distinct
    /// for future extensibility (e.g., Git tags could support version listing).
    pub fn is_version_resolvable(&self) -> bool {
        self.is_registry()
    }
}

/// Loading state for registry data fetching.
///
/// Tracks the current state of background registry operations to provide
/// user feedback about data availability.
///
/// # State Transitions
///
/// Complete state machine diagram showing all valid transitions:
///
/// ```text
///        ┌─────┐
///        │Idle │ (Initial state: no data loaded, not loading)
///        └──┬──┘
///           │
///           │ didOpen/didChange
///           │ (start fetching)
///           ▼
///      ┌────────┐
///      │Loading │ (Fetching registry data)
///      └───┬────┘
///          │
///          ├─────── Success ──────┐
///          │                       ▼
///          │                  ┌────────┐
///          │                  │Loaded  │ (Data cached and ready)
///          │                  └───┬────┘
///          │                      │
///          │                      │ didChange/refresh
///          │                      │ (re-fetch)
///          │                      │
///          │                      ▼
///          │                  ┌────────┐
///          │                  │Loading │
///          │                  └────────┘
///          │
///          └─────── Error ─────────┐
///                                   ▼
///                              ┌────────┐
///                              │Failed  │ (Fetch failed, old cache may exist)
///                              └───┬────┘
///                                  │
///                                  │ didChange/retry
///                                  │ (try again)
///                                  │
///                                  ▼
///                              ┌────────┐
///                              │Loading │
///                              └────────┘
/// ```
///
/// # Key Behaviors
///
/// - **Idle**: Initial state when no data has been fetched yet
/// - **Loading**: Actively fetching from registry (may show loading indicator)
/// - **Loaded**: Successfully fetched and cached data
/// - **Failed**: Network/registry error occurred (falls back to old cache if available)
///
/// # Thread Safety
///
/// This enum is `Copy` for efficient passing across thread boundaries in async contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadingState {
    /// No data loaded, not currently loading
    #[default]
    Idle,
    /// Currently fetching registry data
    Loading,
    /// Data fetched and cached
    Loaded,
    /// Fetch failed (old cached data may still be available)
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_toml_nesting_depth_empty_content() {
        assert_eq!(check_toml_nesting_depth("", 4), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_no_brackets() {
        assert_eq!(check_toml_nesting_depth("a = 1\nb = \"text\"\n", 4), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_exactly_at_max() {
        let content = format!("a = {}1{}", "[".repeat(4), "]".repeat(4));
        assert_eq!(check_toml_nesting_depth(&content, 4), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_one_over_max() {
        let content = format!("a = {}1{}", "[".repeat(5), "]".repeat(5));
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_toml_nesting_depth_double_quoted_string_ignored() {
        let content = r#"a = "[[[[[unbalanced brackets]]]]]""#;
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_single_quoted_string_ignored() {
        let content = "a = '[[[[[unbalanced brackets]]]]]'";
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_escaped_quote_in_string() {
        // The escaped quote must not terminate the string early, so the
        // brackets that follow stay inside the string and are ignored.
        let content = r#"a = "embedded \" quote [[[[[""#;
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_comment_ignored() {
        let content = "# [[[[[unbalanced comment brackets]]]]]\na = 1\n";
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_mixed_array_and_table_nesting() {
        // [ { [ { -> depth 4 at the innermost brace.
        let content = "a = [{ b = [{ c = 1 }] }]";
        assert_eq!(check_toml_nesting_depth(content, 4), Ok(()));
        assert_eq!(check_toml_nesting_depth(content, 3), Err(4));
    }

    #[test]
    fn test_check_toml_nesting_depth_inline_table_at_production_boundary() {
        // Nested inline tables (`{a={a=...}}`) are the shape that actually
        // exhausts a 2 MiB tokio worker stack before nested arrays do
        // (impl-critic C3) — exercise it against the real, shipped
        // `MAX_TOML_NESTING_DEPTH`, not just an arbitrary small max_depth.
        let depth = MAX_TOML_NESTING_DEPTH;
        let at_max = format!("a = {}1{}", "{a=".repeat(depth), "}".repeat(depth));
        assert_eq!(check_toml_nesting_depth(&at_max, depth), Ok(()));

        let over_max = format!("a = {}1{}", "{a=".repeat(depth + 1), "}".repeat(depth + 1));
        assert_eq!(check_toml_nesting_depth(&over_max, depth), Err(depth + 1));
    }

    #[test]
    fn test_check_toml_nesting_depth_dotted_header_at_production_boundary() {
        // Regression test for impl-critic C4: `[a.a.a...]` nests one table
        // level per `.` segment with zero bracket characters, so a
        // bracket-only scanner scores this depth 0 and lets it straight
        // through to `toml_span::parse`, which still stack-overflows.
        let depth = MAX_TOML_NESTING_DEPTH;
        let at_max = format!("[{}a]\ny = 1\n", "a.".repeat(depth - 1));
        assert_eq!(check_toml_nesting_depth(&at_max, depth), Ok(()));

        let over_max = format!("[{}a]\ny = 1\n", "a.".repeat(depth));
        assert_eq!(check_toml_nesting_depth(&over_max, depth), Err(depth + 1));
    }

    #[test]
    fn test_check_toml_nesting_depth_dotted_key_at_production_boundary() {
        // Same C4 bypass, via a dotted key (`a.a.a...= 1`) instead of a
        // dotted table header.
        let depth = MAX_TOML_NESTING_DEPTH;
        let at_max = format!("a{} = 1\n", ".a".repeat(depth));
        assert_eq!(check_toml_nesting_depth(&at_max, depth), Ok(()));

        let over_max = format!("a{} = 1\n", ".a".repeat(depth + 1));
        assert_eq!(check_toml_nesting_depth(&over_max, depth), Err(depth + 1));
    }

    #[test]
    fn test_check_toml_nesting_depth_legitimate_dotted_keys_accepted() {
        // Positive test: common, shallow legitimate dotted-key patterns must
        // never be rejected, and a float/version-like dot in value position
        // must never be miscounted as a key segment.
        let content = r#"
[tool.poetry.dependencies]
requests = { version = "^2.28", extras = ["socks"] }

[libraries]
spring-boot = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring" }

[metrics]
cpu_load = 3.14
"#;
        assert_eq!(
            check_toml_nesting_depth(content, MAX_TOML_NESTING_DEPTH),
            Ok(())
        );
    }

    #[test]
    fn test_check_toml_nesting_depth_dotted_array_of_tables_header_at_boundary() {
        // `[[a.a...]]` double-bracket header: 2 bracket levels + N dot
        // segments must compose into one shared budget, not be tracked
        // independently (which would let brackets and dots each stay under
        // the cap while their sum exceeds it).
        let depth = MAX_TOML_NESTING_DEPTH;
        let at_max = format!("[[{}a]]\ny = 1\n", "a.".repeat(depth - 2));
        assert_eq!(check_toml_nesting_depth(&at_max, depth), Ok(()));

        let over_max = format!("[[{}a]]\ny = 1\n", "a.".repeat(depth - 1));
        assert_eq!(check_toml_nesting_depth(&over_max, depth), Err(depth + 1));
    }

    #[test]
    fn test_check_toml_nesting_depth_dotted_key_inside_bracket_header_composes() {
        // A `[a.b]` header (dots released at bracket depth 0 on the header's
        // own newline) followed by a dotted key whose value is an inline
        // table with its own dotted key (`c.d.e = {f.g = 1}`) exercises
        // bracket-depth and dot-segment accounting interleaving on adjacent
        // statements — the header's dots must not leak into the next
        // statement's budget, and the inline table's dots must still stack
        // on top of its own bracket depth correctly.
        let content = "[a.b]\nc.d.e = {f.g = 1}\n";
        // Real accounting: header contributes max transient depth 2 (1
        // bracket + 1 dot), fully released at its newline; the second line
        // peaks at depth 4 (2 dots for c.d.e's key, +1 for the `{`, +1 for
        // f.g's dot) — never higher, and never carrying over the header's
        // released dots.
        assert_eq!(check_toml_nesting_depth(content, 4), Ok(()));
        assert_eq!(check_toml_nesting_depth(content, 3), Err(4));
    }

    #[test]
    fn test_check_toml_nesting_depth_many_dotted_key_statements_do_not_accumulate() {
        // Hundreds of top-level dotted-key statements, each individually
        // well under the cap, must never accumulate across statements — a
        // per-key release that fired late (or not at all) would eventually
        // push a long file over the cap even though no single statement
        // does.
        let mut content = String::new();
        for i in 0..500 {
            content.push_str(&format!("k{i}.a.b.c = {i}\n"));
        }
        assert_eq!(check_toml_nesting_depth(&content, 4), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_sibling_inline_tables_in_array_do_not_accumulate() {
        // Many sibling `{ ... }` entries in one array, each with a short
        // dotted key, must not falsely accumulate depth across entries —
        // only one entry's dots are ever held at a time, matching how
        // `toml_span`'s recursion actually unwinds between array elements.
        let mut content = String::from("deps = [\n");
        for i in 0..200 {
            content.push_str(&format!(
                "  {{ name = \"pkg{i}\", version.ref = \"v\" }},\n"
            ));
        }
        content.push_str("]\n");
        assert_eq!(
            check_toml_nesting_depth(&content, MAX_TOML_NESTING_DEPTH),
            Ok(())
        );
    }

    #[test]
    fn test_check_toml_nesting_depth_multiline_literal_odd_quote_count() {
        // A multi-line literal string containing an apostrophe (odd count of
        // its own quote char) must not desync the scanner into thinking the
        // string never closes.
        let content = format!("a = '''don't'''\nb = {}1{}", "[".repeat(5), "]".repeat(5));
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_toml_nesting_depth_rejects_original_sigabrt_payloads() {
        // The exact payload shapes that reproduced the #150 SIGABRT even
        // after the first version of this guard shipped (impl-critic C1):
        // a multi-line string with an odd count of its own quote char,
        // followed by 20000-deep nesting.
        let n = 20_000;
        let payload1 = format!("a = '''don't'''\nb = {}1{}", "[".repeat(n), "]".repeat(n));
        let payload2 = format!(
            "a = \"\"\"x\"y\"\"\"\nb = {}1{}",
            "[".repeat(n),
            "]".repeat(n)
        );

        assert!(check_toml_nesting_depth(&payload1, MAX_TOML_NESTING_DEPTH).is_err());
        assert!(check_toml_nesting_depth(&payload2, MAX_TOML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_toml_nesting_depth_multiline_basic_odd_quote_count() {
        let content = format!(
            "a = \"\"\"x\"y\"\"\"\nb = {}1{}",
            "[".repeat(5),
            "]".repeat(5)
        );
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_toml_nesting_depth_multiline_basic_trailing_extra_quotes() {
        // TOML allows 1-2 literal quotes right before the closing triple
        // (here: 2 extra content quotes then the 3-quote closer, 5 in a
        // row). The scanner must still be back in normal mode right after,
        // so the nested array on the next line is counted correctly.
        let content = format!(
            "a = \"\"\"ends with two quotes: \"\"\"\"\"\nb = {}1{}",
            "[".repeat(5),
            "]".repeat(5)
        );
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_toml_nesting_depth_brackets_inside_multiline_string_ignored() {
        let content = "d = \"\"\"\nsize is 5\" wide [[[unbalanced]]]\n\"\"\"\ne = 1\n";
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_multiline_literal_brackets_ignored() {
        let content = "d = '''\n[[[unbalanced brackets]]]\n'''\ne = 1\n";
        assert_eq!(check_toml_nesting_depth(content, 0), Ok(()));
    }

    #[test]
    fn test_check_toml_nesting_depth_multiline_basic_one_extra_trailing_quote() {
        // Exactly 1 extra content quote before the closing triple (4-quote
        // run total), between the 0-extra and 2-extra cases already covered.
        let content = format!(
            "a = \"\"\"ends with one quote: \"\"\"\"\nb = {}1{}",
            "[".repeat(5),
            "]".repeat(5)
        );
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_toml_nesting_depth_adjacent_multiline_strings_then_nesting() {
        // Two separate multi-line strings (one basic, one literal) back to
        // back, each closing normally, must not leave the scanner desynced
        // for the real nesting that follows.
        let content = format!(
            "a = \"\"\"first\"\"\"\nb = '''second'''\nc = {}1{}",
            "[".repeat(5),
            "]".repeat(5)
        );
        assert_eq!(check_toml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_dependency_source_registry() {
        let source = DependencySource::Registry;
        assert_eq!(source, DependencySource::Registry);
        assert!(source.is_registry());
        assert!(source.is_version_resolvable());
    }

    #[test]
    fn test_dependency_source_git() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            rev: Some("main".into()),
        };

        assert!(!source.is_registry());
        assert!(!source.is_version_resolvable());

        match source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(rev, Some("main".into()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_source_git_no_rev() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            rev: None,
        };

        match source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert!(rev.is_none());
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_source_path() {
        let source = DependencySource::Path {
            path: "../local-crate".into(),
        };

        assert!(!source.is_registry());

        match source {
            DependencySource::Path { path } => {
                assert_eq!(path, "../local-crate");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_dependency_source_url() {
        let source = DependencySource::Url {
            url: "https://example.com/package.whl".into(),
        };
        assert!(!source.is_registry());
        assert!(!source.is_version_resolvable());
    }

    #[test]
    fn test_dependency_source_sdk() {
        let source = DependencySource::Sdk {
            sdk: "flutter".into(),
        };
        assert!(!source.is_registry());
    }

    #[test]
    fn test_dependency_source_workspace() {
        let source = DependencySource::Workspace;
        assert!(!source.is_registry());
        assert!(!source.is_version_resolvable());
    }

    #[test]
    fn test_dependency_source_custom_registry() {
        let source = DependencySource::CustomRegistry {
            url: "https://gems.example.com".into(),
        };
        assert!(source.is_registry());
        assert!(source.is_version_resolvable());
    }

    #[test]
    fn test_dependency_source_clone() {
        let source1 = DependencySource::Git {
            url: "https://example.com/repo".into(),
            rev: Some("v1.0".into()),
        };
        let source2 = source1.clone();

        assert_eq!(source1, source2);
    }

    #[test]
    fn test_dependency_source_equality() {
        let reg1 = DependencySource::Registry;
        let reg2 = DependencySource::Registry;
        assert_eq!(reg1, reg2);

        let git1 = DependencySource::Git {
            url: "https://example.com".into(),
            rev: None,
        };
        let git2 = DependencySource::Git {
            url: "https://example.com".into(),
            rev: None,
        };
        assert_eq!(git1, git2);

        let git3 = DependencySource::Git {
            url: "https://different.com".into(),
            rev: None,
        };
        assert_ne!(git1, git3);
    }

    #[test]
    fn test_dependency_source_debug() {
        let source = DependencySource::Registry;
        let debug = format!("{:?}", source);
        assert_eq!(debug, "Registry");

        let git = DependencySource::Git {
            url: "https://example.com".into(),
            rev: Some("main".into()),
        };
        let git_debug = format!("{:?}", git);
        assert!(git_debug.contains("https://example.com"));
        assert!(git_debug.contains("main"));
    }

    #[test]
    fn test_loading_state_default() {
        assert_eq!(LoadingState::default(), LoadingState::Idle);
    }

    #[test]
    fn test_loading_state_copy() {
        let state = LoadingState::Loading;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_loading_state_debug() {
        let debug_str = format!("{:?}", LoadingState::Loading);
        assert_eq!(debug_str, "Loading");
    }

    #[test]
    fn test_loading_state_all_variants() {
        let variants = [
            LoadingState::Idle,
            LoadingState::Loading,
            LoadingState::Loaded,
            LoadingState::Failed,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2);
                } else {
                    assert_ne!(v1, v2);
                }
            }
        }
    }
}
