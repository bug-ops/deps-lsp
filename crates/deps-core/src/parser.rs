use std::collections::BTreeMap;
use yaml_rust2::Event;
use yaml_rust2::parser::{MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

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

/// Maximum allowed nesting depth for YAML block/flow recursion before
/// [`check_yaml_nesting_depth`] rejects the input.
///
/// `yaml-rust2` 0.12's block-style (indentation-driven) sequence/mapping
/// parser recurses once per nesting level with no depth limit (its flow-style
/// `[[[...]]]` array parser already caps recursion, but block style and flow
/// objects do not). A deeply nested `pubspec.yaml`/`pubspec.lock` can overflow
/// the native thread stack and abort the whole process (SIGABRT) before
/// `YamlLoader::load_from_str` ever returns an error. As with
/// [`MAX_TOML_NESTING_DEPTH`], this constant assumes the smallest stack any
/// caller is likely to run on: a `tokio` worker thread's 2 MiB default, not
/// `deps-lsp`'s own 8 MiB `WORKER_THREAD_STACK_SIZE` (defense-in-depth on top
/// of this guard).
///
/// Bisected against the real `yaml-rust2` 0.12 recursion on a 2 MiB debug
/// stack: the cheapest attack — compact block-sequence chaining
/// (`- - - - 1`, 2 bytes per level) — survives depth 4535 and aborts at 4536;
/// growing-indent block mappings (`k:\n k:\n  k:\n...`), the tightest case,
/// survive depth 1993 and abort at 1994. 64 leaves a >30x margin under the
/// tightest of these while still being far deeper than any real manifest
/// needs — `pubspec.yaml`/`pubspec.lock` structures bottom out around 4-5
/// levels (e.g. `packages.<name>.description.<field>`).
pub const MAX_YAML_NESTING_DEPTH: usize = 64;

/// Scans raw YAML text for block/flow recursion deeper than `max_depth`.
///
/// `YamlLoader::load_from_str` has no public option to cap recursion, so
/// callers must reject pathological input before handing it to the parser.
/// This performs a single-pass structural scan — no actual parsing, so it
/// cannot itself recurse or overflow — that bounds the two independent ways
/// YAML content drives `yaml-rust2`'s recursion:
///
/// - **Flow-style bracket nesting**: `[`/`{` and `]`/`}` pairs, as in
///   `[[[1]]]` or `{a: {a: 1}}`.
/// - **Block-style indentation**: each line whose leading indentation is
///   deeper than the enclosing block context opens one nesting level (e.g. a
///   mapping key or sequence item indented under its parent); each `-` in a
///   compact chained sequence item (`- - - 1`) opens one level per dash,
///   since it is equivalent to one nested single-item sequence per level.
///
/// Both counts accumulate into one shared depth budget bounded by
/// `max_depth`. Line-start block indentation is scanned unconditionally on
/// every line, even one that looks like a continuation of a still-open flow
/// bracket from a previous line — an unclosed `[`/`{` must never be able to
/// suppress scanning for the rest of the file (impl-critic C2), so this
/// guard accepts occasionally over-counting a multi-line flow collection's
/// continuation lines as extra block levels in exchange for never being able
/// to go blind. A quote character is only treated as opening a quoted
/// scalar when it sits at a token-start position (line start, or right
/// after `: `, `- `, `[`, `{`, `,`) — never mid-token — so an apostrophe
/// inside a plain scalar like `doesn't` is left alone rather than
/// mistaken for the start of a string (impl-critic C1). Once a quoted
/// scalar is opened, it is only ever trusted to close on the *same* line:
/// hitting an unescaped `\n` before the matching quote resynchronizes the
/// scanner at that newline unconditionally (including across a `\` right
/// before it, which cannot extend the string past the line), rather than
/// scanning forward indefinitely looking for a close — so neither a stray
/// unquoted apostrophe nor a genuinely unterminated quoted scalar can ever
/// blind the scanner to more than the remainder of one line. `#` outside a
/// quoted scalar always starts a comment to end of line. Content indented
/// under a literal/folded block scalar (`|`/`>`) is not specially exempted
/// and is scanned like any other indentation, which can only make this
/// guard *more* conservative, never less. Only ASCII space counts as
/// indentation — a tab-indented line reads as indent 0, an assumption that
/// currently holds only because `yaml-rust2` itself rejects tabs used for
/// block indentation before recursing deep enough to matter.
///
/// # Errors
///
/// Returns `Err(depth)` with the depth reached the instant nesting exceeds
/// `max_depth`.
///
/// # Examples
///
/// ```
/// use deps_core::parser::check_yaml_nesting_depth;
///
/// assert!(check_yaml_nesting_depth("a:\n  b:\n    c: 1\n", 4).is_ok());
///
/// let deeply_nested = format!("{}1", "- ".repeat(10));
/// assert!(check_yaml_nesting_depth(&deeply_nested, 4).is_err());
///
/// // An apostrophe mid-scalar must not blind the scanner to nesting later
/// // in the file (impl-critic C1).
/// let content = format!("a: it doesn't panic\n{}1", "- ".repeat(10));
/// assert!(check_yaml_nesting_depth(&content, 4).is_err());
/// ```
pub fn check_yaml_nesting_depth(content: &str, max_depth: usize) -> std::result::Result<(), usize> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut depth: usize = 0;
    let mut indent_stack: Vec<usize> = Vec::new();
    let mut bracket_stack: Vec<u8> = Vec::new();

    let mut i = 0;
    while i < len {
        let mut indent = 0;
        while i < len && bytes[i] == b' ' {
            indent += 1;
            i += 1;
        }
        if i >= len || bytes[i] == b'\n' || bytes[i] == b'#' {
            i = skip_to_eol(bytes, i);
            if i < len && bytes[i] == b'\n' {
                i += 1;
            }
            continue;
        }

        while indent_stack.last().is_some_and(|&top| top > indent) {
            indent_stack.pop();
            depth = depth.saturating_sub(1);
        }

        let mut col = indent;
        while i < len && bytes[i] == b'-' && (i + 1 == len || matches!(bytes[i + 1], b' ' | b'\n'))
        {
            if indent_stack.last() != Some(&col) {
                depth += 1;
                if depth > max_depth {
                    return Err(depth);
                }
                indent_stack.push(col);
            }
            i += 1;
            col += 1;
            while i < len && bytes[i] == b' ' {
                i += 1;
                col += 1;
            }
        }

        if i < len && !matches!(bytes[i], b'\n' | b'#') && indent_stack.last() != Some(&col) {
            depth += 1;
            if depth > max_depth {
                return Err(depth);
            }
            indent_stack.push(col);
        }

        // `prev` tracks whether the byte at `i` sits at a token-start
        // position; starts `b' '` since we just consumed leading
        // whitespace/dash-chain separators above.
        let mut prev: u8 = b' ';
        while i < len && bytes[i] != b'\n' {
            match bytes[i] {
                b'#' => {
                    i = skip_to_eol(bytes, i);
                    break;
                }
                quote @ (b'"' | b'\'')
                    if matches!(prev, b' ' | b'\t' | b':' | b',' | b'[' | b'{' | b'-') =>
                {
                    i = skip_yaml_string(bytes, i + 1, quote);
                    prev = quote;
                }
                b'[' | b'{' => {
                    depth += 1;
                    if depth > max_depth {
                        return Err(depth);
                    }
                    bracket_stack.push(bytes[i]);
                    prev = bytes[i];
                    i += 1;
                }
                b']' | b'}' => {
                    if bracket_stack.pop().is_some() {
                        depth = depth.saturating_sub(1);
                    }
                    prev = bytes[i];
                    i += 1;
                }
                b => {
                    prev = b;
                    i += 1;
                }
            }
        }
        if i < len && bytes[i] == b'\n' {
            i += 1;
        }
    }

    Ok(())
}

/// Advances past the rest of the current line (used for blank and comment
/// lines), returning the index of the `\n` or `bytes.len()`.
fn skip_to_eol(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

/// Advances past a YAML quoted scalar opened at a token-start position
/// (`"..."` or `'...'`), returning the index just past its closing quote.
///
/// Only ever trusts a close on the *same* line: hits an unescaped `\n`
/// before finding the matching quote, this returns the index of that
/// newline unconsumed rather than continuing to search — so neither a
/// genuinely unterminated quoted scalar nor a `\` placed right before the
/// newline (which would otherwise "escape" it and extend the scan) can
/// blind the caller's line-oriented scan to more than the current line
/// (impl-critic C1). `yaml-rust2` reports the real syntax error for content
/// this treats as unterminated. Handles double-quote backslash escapes and
/// single-quote `''` escapes.
fn skip_yaml_string(bytes: &[u8], mut i: usize, quote: u8) -> usize {
    let len = bytes.len();
    while i < len && bytes[i] != b'\n' {
        if bytes[i] == b'\\' && quote == b'"' {
            if bytes.get(i + 1) == Some(&b'\n') {
                break;
            }
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            if quote == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    i
}

/// Fixed per-node byte floor [`check_yaml_expansion`] charges for every
/// `Yaml` node, on top of any heap content (e.g. a scalar's string bytes) it
/// owns.
///
/// Derived from `size_of::<yaml_rust2::Yaml>()` itself (64 bytes on a 64-bit
/// target as of `yaml-rust2` 0.12, dominated by the `String`/`Array`/`Hash`
/// variants' inline pointer+len+cap fields plus the enum discriminant)
/// rather than hardcoded, so a `yaml-rust2` layout change or a non-64-bit
/// target cannot silently drift this out of sync with reality — the size of
/// the value every `Yaml` node occupies wherever it is stored (a
/// `Vec<Yaml>` element, a `Hash` entry, or a clone inside `anchor_map`),
/// independent of its variant. This floor does *not* separately model every
/// real cost `YamlLoader` incurs beyond it: `Hash`'s `LinkedHashMap`
/// prev/next link pointers and hash-table slots, and `Vec`'s
/// capacity-doubling slack, both add further real allocation on top of what
/// this constant (and thus [`MAX_YAML_EXPANDED_BYTES`]) charges for — see
/// that constant's doc for the measured size of that gap.
const YAML_NODE_OVERHEAD_BYTES: u64 = size_of::<yaml_rust2::Yaml>() as u64;

/// Maximum total byte weight [`check_yaml_expansion`] allows a document to
/// expand to (counting anchor/alias-driven duplication) before rejecting it.
///
/// `yaml-rust2` 0.12's `YamlLoader::on_event_impl` deep-clones the whole
/// anchored subtree once per `Event::Alias` reference (`anchor_map.get(&id)
/// => v.clone()`), and again into `anchor_map` itself for every anchored
/// node. Nesting depth (bounded by [`MAX_YAML_NESTING_DEPTH`]) is irrelevant
/// to this: a shallow document with a handful of anchors, each aliased a
/// handful of times, expands exponentially in the memory actually
/// allocated. Critically, this must be a **byte** budget, not a node-count
/// budget: a single large scalar anchor (e.g. a 1 MB string) aliased many
/// times allocates megabytes per alias while costing only one node each, so
/// a node-count budget lets it through cheaply — a document under 3 MB can
/// exhaust hundreds of gigabytes this way. `YamlLoader` exposes no
/// budget/config hook, so callers must reject pathological input before
/// handing it to the loader.
///
/// `32 MiB` (`32 * 1024 * 1024` = 33,554,432) is the *charged* byte budget —
/// not an exact bound on `YamlLoader`'s real peak allocation. Charged bytes
/// track `YAML_NODE_OVERHEAD_BYTES`'s per-node floor plus scalar content,
/// which undercounts two real costs that floor doesn't model: `Hash`'s
/// `LinkedHashMap` prev/next link pointers and hash-table slots (hash-heavy
/// documents, e.g. a `pubspec.lock`), and `String`/`Vec` capacity-doubling
/// slack — the scanner builds every scalar via `String::new()` + repeated
/// `push`, so a single large scalar whose length lands just past a
/// power-of-two capacity boundary (e.g. 1,048,577 bytes) wastes nearly its
/// own length again in unused capacity, and the same growth pattern applies
/// to a `Vec` backing a long sequence. Measured with a counting allocator:
/// real peak allocation runs about 1.16x-1.74x the charged total depending
/// on document shape (steadier ~1.56x for hash-heavy lockfiles, up to ~2x
/// for a large scalar or long sequence whose length lands right past a
/// capacity-doubling boundary), so an accepted document charged right at
/// this limit really allocates roughly 50-65 MB, not 32 MB. Bytes
/// charged do not compound with nesting, so ~2x is the ceiling on that
/// ratio, not a growing multiplier — the budget stays a bounded, linear
/// function of input size either way, which is what actually matters for
/// this guard (an *unbounded* multiplier, as with the pre-fix node-count
/// budget's `O(2^depth)` blowup, is the failure mode this guards against).
///
/// Measured against real payloads (exact charged totals, reproducible
/// against the shape scaled up from
/// `test_check_yaml_expansion_few_hundred_package_lockfile_accepted`): a
/// 1.9 MB / 12,500-package synthetic `pubspec.lock` charges 12,416,870 bytes
/// (2.70x headroom); a 757 KB / 5,000-package one charges 4,961,870 bytes
/// (6.76x headroom); the doubling-chain attack payload (see
/// [`check_yaml_expansion`]'s doctest) charges 16,907,046 bytes at N=14
/// (accepted) and 33,815,273 at N=15 (rejected, in well under a
/// millisecond); and a single 1 MB anchor aliased 31 times (33,002,370
/// bytes charged, ~1 MB source) is accepted while 32 times (34,002,434
/// bytes) is rejected rather than allocating unboundedly.
pub const MAX_YAML_EXPANDED_BYTES: usize = 32 * 1024 * 1024;

/// Streams `content` through `yaml-rust2`'s own parser event stream and
/// tallies the total bytes the `Yaml` nodes `YamlLoader::load_from_str`
/// would allocate, rejecting once the tally exceeds `max_bytes`.
///
/// This is a pre-pass driven by the same `Parser`/event stream
/// `YamlLoader::load_from_str` itself uses (`Parser::new(content.chars())`,
/// `multi = true`), so anchor ids and event order are identical to the real
/// load — unlike a raw-text `&anchor`/`*alias` scan, which was tried and
/// rejected: ordinary prose such as `description: A widget *multiplier*
/// helper` sits at exactly the position a text scanner treats as a token
/// boundary, so it false-positives as an alias reference.
///
/// The accounting model mirrors `YamlLoader::on_event_impl` exactly, in
/// bytes rather than node count: a `Scalar` charges
/// `YAML_NODE_OVERHEAD_BYTES` plus its own string content length; a closed
/// `Sequence`/`Mapping` charges `YAML_NODE_OVERHEAD_BYTES` for itself,
/// plus the byte weight of its already-charged descendants. An anchored
/// node (`SequenceStart`/`MappingStart`/`Scalar` anchor id `> 0`) charges
/// its own subtree's byte weight a second time, mirroring
/// `insert_new_node`'s `anchor_map.insert` clone; an `Alias` charges the
/// referenced anchor's recorded byte weight (or
/// `YAML_NODE_OVERHEAD_BYTES` for an unknown anchor id, matching the
/// loader's own `Yaml::BadValue` fallback, which owns no heap content),
/// mirroring the `v.clone()` in the `Event::Alias` arm. All counting uses
/// `u64` with `saturating_add`, since the counter itself — not just the
/// input — is the attack surface.
///
/// This pre-pass is not itself free relative to `max_bytes`: its own
/// `anchors: BTreeMap<usize, u64>` grows by one entry per distinct anchor
/// id seen, so a document built almost entirely of many tiny anchors (e.g.
/// ~262,000 one-byte-scalar anchors, ~3.6 MB source) can transiently grow
/// this map to roughly the same order of magnitude as `max_bytes` itself
/// before the tally crosses it and rejection kicks in. This is bounded and
/// transient, not unbounded like the vulnerability this guard closes, but
/// callers should not assume the pre-pass's own peak memory is negligible
/// next to the budget it enforces.
///
/// Any `ScanError` from this pre-pass is ignored: the real
/// `YamlLoader::load_from_str` call that follows reports the authoritative
/// syntax error. If the budget was already exceeded before the scan error,
/// this still returns `Err`.
///
/// This pre-pass is, like the real load, driven by `Parser::load`'s mutually
/// recursive `load_node`/`load_mapping`/`load_sequence` — callers must run
/// [`check_yaml_nesting_depth`] first so this never recurses on input deep
/// enough to overflow the stack itself.
///
/// # Errors
///
/// Returns `Err(bytes)` with the byte tally reached the instant it exceeds
/// `max_bytes`.
///
/// # Examples
///
/// ```
/// use deps_core::parser::check_yaml_expansion;
///
/// assert!(check_yaml_expansion("a: 1\nb: [2, 3]\n", 1000).is_ok());
///
/// // A widget *multiplier* helper is a plain scalar, not an alias.
/// assert!(check_yaml_expansion("description: A widget *multiplier* helper", 1000).is_ok());
///
/// // Each anchor doubles the next one's alias count, so N levels expand to
/// // roughly 2^N nodes from a source only ~2N bytes long.
/// let mut doubling_chain = String::from("a0: &a0 [x, x]\n");
/// for i in 1..20 {
///     doubling_chain.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}]\n", prev = i - 1));
/// }
/// assert!(check_yaml_expansion(&doubling_chain, 1000).is_err());
/// ```
pub fn check_yaml_expansion(content: &str, max_bytes: usize) -> std::result::Result<(), usize> {
    struct Receiver {
        max: u64,
        consumed: u64,
        exceeded: bool,
        stack: Vec<(usize, u64)>,
        anchors: BTreeMap<usize, u64>,
    }

    impl Receiver {
        fn charge(&mut self, n: u64) {
            if self.exceeded {
                return;
            }
            self.consumed = self.consumed.saturating_add(n);
            if self.consumed > self.max {
                self.exceeded = true;
            }
        }

        /// Records a just-finished node's total subtree byte weight (`size`,
        /// including itself): charges the anchor-clone cost and remembers
        /// it for future aliases when `aid > 0`, then adds it to the
        /// enclosing container's running subtree weight, if any.
        fn finish(&mut self, size: u64, aid: usize) {
            if self.exceeded {
                return;
            }
            if aid > 0 {
                self.charge(size);
                self.anchors.insert(aid, size);
            }
            if let Some((_, parent_size)) = self.stack.last_mut() {
                *parent_size = parent_size.saturating_add(size);
            }
        }
    }

    impl MarkedEventReceiver for Receiver {
        fn on_event(&mut self, ev: Event, _mark: Marker) {
            if self.exceeded {
                return;
            }
            match ev {
                Event::SequenceStart(aid, _) | Event::MappingStart(aid, _) => {
                    self.stack.push((aid, 0));
                }
                Event::SequenceEnd | Event::MappingEnd => {
                    if let Some((aid, children_size)) = self.stack.pop() {
                        self.charge(YAML_NODE_OVERHEAD_BYTES);
                        self.finish(children_size.saturating_add(YAML_NODE_OVERHEAD_BYTES), aid);
                    }
                }
                Event::Scalar(ref v, _, aid, _) => {
                    let size = YAML_NODE_OVERHEAD_BYTES.saturating_add(v.len() as u64);
                    self.charge(size);
                    self.finish(size, aid);
                }
                Event::Alias(id) => {
                    let size = self
                        .anchors
                        .get(&id)
                        .copied()
                        .unwrap_or(YAML_NODE_OVERHEAD_BYTES);
                    self.charge(size);
                    self.finish(size, 0);
                }
                _ => {}
            }
        }
    }

    let mut recv = Receiver {
        max: max_bytes as u64,
        consumed: 0,
        exceeded: false,
        stack: Vec::new(),
        anchors: BTreeMap::new(),
    };

    let _ = Parser::new(content.chars()).load(&mut recv, true);

    if recv.exceeded {
        Err(usize::try_from(recv.consumed).unwrap_or(usize::MAX))
    } else {
        Ok(())
    }
}

/// Maximum allowed nesting depth for JSON array/object recursion before
/// [`check_json_nesting_depth`] rejects the input.
///
/// `serde_json` itself already caps recursion at a default depth of 128 for
/// every container it enters — `deserialize_any`/`Value`, but equally
/// `deserialize_seq`/`deserialize_map` (`check_recursion!` in its `de.rs`,
/// guarding all three), so ordinary typed struct/`Vec` deserialization is
/// covered exactly the same as parsing into a bare `Value`. This workspace
/// never enables the `unbounded_depth` feature or calls
/// `disable_recursion_limit`, so pathologically nested JSON cannot crash
/// this workspace via stack overflow regardless of which of these paths a
/// given call site uses. This guard is defense-in-depth, not a
/// vulnerability fix: an early, cheap, byte-level rejection that fails
/// faster and with a repo-specific error type than waiting for
/// `serde_json`'s own limit, and keeps every untrusted-JSON parse site
/// consistent with the [`MAX_TOML_NESTING_DEPTH`]/[`MAX_YAML_NESTING_DEPTH`]
/// guards already applied to manifests of those formats. The depth is
/// intentionally set narrower than `serde_json`'s built-in 128 — real
/// payloads (OSV `database_specific`/`ecosystem_specific`, npm's `time` map,
/// Packagist's `abandoned` field, ordinary `package.json`/`composer.json`
/// manifests and lockfiles) never approach double digits of nesting, so 64
/// is an arbitrary but generous ceiling chosen to match the existing
/// TOML/YAML constants' value, not a stack-size bisection.
pub const MAX_JSON_NESTING_DEPTH: usize = 64;

/// Scans raw JSON bytes for `[`/`{` nesting deeper than `max_depth`, before
/// handing the bytes to `serde_json::from_slice`/`from_str`.
///
/// A single-pass structural scan — no actual parsing, so it cannot itself
/// recurse or overflow. String contents (JSON's only escaping construct) are
/// tracked so bracket characters inside string literals are never
/// miscounted as structural nesting. Multi-byte UTF-8 sequences are safe to
/// scan byte-by-byte here: none of their continuation bytes collide with the
/// ASCII structural characters this function looks for.
///
/// An unterminated (or truncated) string literal makes the scanner treat the
/// rest of the buffer as string content and return `Ok`, undercounting any
/// nesting that follows. This is safe: `serde_json` tokenizes the same bytes
/// and will independently reject the identical malformed/truncated string
/// (an EOF-while-parsing-string or similar syntax error) before its own
/// recursive descent could ever reach nesting beyond what this scanner
/// already counted up to the unterminated quote.
///
/// # Errors
///
/// Returns `Err(depth)` with the depth reached the instant nesting exceeds
/// `max_depth`.
///
/// # Examples
///
/// ```
/// use deps_core::parser::check_json_nesting_depth;
///
/// assert!(check_json_nesting_depth(br#"{"a":[1,2,{"b":3}]}"#, 4).is_ok());
///
/// let deeply_nested = format!("{}1{}", "[".repeat(10), "]".repeat(10));
/// assert_eq!(check_json_nesting_depth(deeply_nested.as_bytes(), 4), Err(5));
/// ```
pub fn check_json_nesting_depth(
    content: &[u8],
    max_depth: usize,
) -> std::result::Result<(), usize> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in content {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max_depth {
                    return Err(depth);
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    Ok(())
}

/// Builds the `serde_json::Error` reporting a too-deep payload.
///
/// Shared internally by [`parse_json_checked`]'s two failure paths (too-deep vs. genuinely
/// malformed) so both produce the exact same error type. Synthesized via
/// `serde::de::Error::custom` so it is indistinguishable, to a caller's existing
/// malformed-JSON handling, from an error `serde_json` itself would have produced.
#[must_use]
fn json_depth_error(depth: usize) -> serde_json::Error {
    serde::de::Error::custom(format!(
        "JSON nesting depth {depth} exceeds maximum of {MAX_JSON_NESTING_DEPTH}"
    ))
}

/// Deserializes `bytes` into `T`, first rejecting payloads whose JSON nesting exceeds
/// [`MAX_JSON_NESTING_DEPTH`] (see that constant's doc for why).
///
/// The single shared entry point for every untrusted-JSON parse site in this workspace —
/// collapses what would otherwise be a per-crate copy of [`check_json_nesting_depth`] +
/// [`serde_json::from_slice`] into one call, and returns a `serde_json::Error` so a
/// too-deep payload converts into a caller's `DepsError` exactly like any other
/// malformed-JSON failure (via `?`, `.map_err(..)`, or `.ok()`).
///
/// # Errors
///
/// Returns an error if `bytes` nests deeper than [`MAX_JSON_NESTING_DEPTH`], or
/// `serde_json`'s own error if `bytes` is not valid JSON matching `T`.
///
/// # Examples
///
/// ```
/// use deps_core::parser::parse_json_checked;
///
/// let value: serde_json::Value = parse_json_checked(br#"{"a":1}"#).unwrap();
/// assert_eq!(value["a"], 1);
///
/// let deeply_nested = format!("{}1{}", "[".repeat(100), "]".repeat(100));
/// assert!(parse_json_checked::<serde_json::Value>(deeply_nested.as_bytes()).is_err());
/// ```
pub fn parse_json_checked<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> std::result::Result<T, serde_json::Error> {
    if let Err(depth) = check_json_nesting_depth(bytes, MAX_JSON_NESTING_DEPTH) {
        return Err(json_depth_error(depth));
    }
    serde_json::from_slice(bytes)
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

    /// Custom/alternative registry, named by an unresolved alias or raw index URL
    /// (Bundler custom sources, an unresolved Cargo `registry = "my-corp"`).
    ///
    /// This variant's meaning is unchanged by [`AlternateRegistry`](Self::AlternateRegistry)'s
    /// addition: it always means "not yet resolved to a concrete index this LSP can query" —
    /// `url` may hold a bare alias (`"my-corp"`) or a URL string, but never a value this LSP
    /// has validated and can fetch against. See [`AlternateRegistry`](Self::AlternateRegistry)
    /// for the resolved counterpart.
    CustomRegistry { url: String },

    /// A custom/alternative registry resolved to a concrete, fetchable index URL.
    ///
    /// Distinct from [`CustomRegistry`](Self::CustomRegistry) so "resolved" is a type-level
    /// state instead of string-sniffing an unresolved alias vs. a URL. Produced only by a
    /// parser that validated `index` against its own registry-configuration source (e.g.
    /// `deps-cargo`'s `.cargo/config.toml` resolution) — `deps-core` itself never constructs
    /// this variant. `index` is the `sparse+` prefix-stripped, https-only index URL; it
    /// carries no credential and is not itself an authorization decision — see the
    /// originating crate's config-resolution module for how (and whether) a request against
    /// it is authenticated.
    AlternateRegistry {
        /// The resolved index URL, validated and normalized by the originating parser.
        index: String,
        /// `true` exactly when this source was reached via a `[source.crates-io]
        /// replace-with` chain (Cargo `[source]` mirroring, spec
        /// `.local/specs/023-cargo-custom-registries/plan-1b.md` §1.3) — as opposed to an
        /// explicit `registry`/`registry-index` naming a genuinely different, private
        /// registry.
        ///
        /// Affects **presentation and advisory gating only, never routing**: Cargo verifies
        /// per-version checksum equality against crates.io for a mirror, so its content is
        /// exactly as trustworthy as crates.io's own for vulnerability-scanning and hover-link
        /// purposes, even though the fetch itself still goes to `index`, not to crates.io.
        /// See [`crate::lsp_helpers::EcosystemFormatter::source_is_public_registry_content`].
        mirrors_crates_io: bool,
    },
}

impl DependencySource {
    /// Returns true if this dependency comes from any registry (default or custom).
    ///
    /// Registry dependencies support version fetching and update checks.
    /// Git, Path, Url, Sdk, and Workspace dependencies do not.
    pub fn is_registry(&self) -> bool {
        matches!(
            self,
            Self::Registry | Self::CustomRegistry { .. } | Self::AlternateRegistry { .. }
        )
    }

    /// Returns true if this LSP can resolve version data for this source
    /// against the registry client it actually queries.
    ///
    /// `Registry` resolves to the ecosystem's default public registry
    /// (crates.io, npm, PyPI, ...), which every `deps-*` crate implements a
    /// client for. `CustomRegistry` names a private/alternative registry
    /// (e.g. Bundler `source "https://gems.mycorp.com"`, Cargo
    /// `registry = "my-corp"`) that this LSP has no client for — known
    /// limitation, tracked until private-registry client support exists.
    /// Diagnostics and hover must not silently fall back to checking a
    /// `CustomRegistry` dependency's name against the *public* registry, so
    /// this deliberately diverges from `is_registry()` and returns `false`
    /// for it, alongside Git/Path/Url/Sdk/Workspace sources.
    ///
    /// Also `false` for `AlternateRegistry`, even though it is resolved: this method answers
    /// "does the generic `Registry` trait (crates.io-shaped, one client per ecosystem)
    /// resolve this", not "is version data reachable at all". An ecosystem whose registry
    /// implements per-source routing (`deps-cargo`'s `CargoRegistry`) must use
    /// [`crate::lsp_helpers::EcosystemFormatter::can_resolve_source`] instead, which defaults
    /// to this method and is the only override point — see that method's docs.
    pub fn is_version_resolvable(&self) -> bool {
        matches!(self, Self::Registry)
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

    /// Builds `n` lines of block mapping, each one column deeper than the
    /// last (`k:\n k:\n  k:\n...`) — the tightest real `yaml-rust2` crash
    /// shape (impl-critic/tester finding), and exactly `n` scanner pushes.
    fn nested_mapping(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&" ".repeat(i));
            s.push_str("k:\n");
        }
        s
    }

    #[test]
    fn test_check_yaml_nesting_depth_empty_content() {
        assert_eq!(check_yaml_nesting_depth("", 4), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_no_nesting() {
        assert_eq!(
            check_yaml_nesting_depth("name: foo\nversion: 1.0.0\n", 1),
            Ok(())
        );
    }

    #[test]
    fn test_check_yaml_nesting_depth_dash_chain_exactly_at_max() {
        // N dashes push N levels, plus one more for the trailing scalar's
        // own column (deeper than the last dash), so N=3 peaks at depth 4.
        let content = format!("{}1", "- ".repeat(3));
        assert_eq!(check_yaml_nesting_depth(&content, 4), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_dash_chain_one_over_max() {
        let content = format!("{}1", "- ".repeat(4));
        assert_eq!(check_yaml_nesting_depth(&content, 4), Err(5));
    }

    #[test]
    fn test_check_yaml_nesting_depth_block_mapping_exactly_at_max() {
        assert_eq!(check_yaml_nesting_depth(&nested_mapping(4), 4), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_block_mapping_one_over_max() {
        assert_eq!(check_yaml_nesting_depth(&nested_mapping(5), 4), Err(5));
    }

    #[test]
    fn test_check_yaml_nesting_depth_double_quoted_string_ignored() {
        let content = r#"a: "[[[[[unbalanced brackets]]]]]""#;
        assert_eq!(check_yaml_nesting_depth(content, 1), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_single_quoted_string_ignored() {
        let content = "a: '[[[[[unbalanced brackets]]]]]'";
        assert_eq!(check_yaml_nesting_depth(content, 1), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_escaped_quote_in_string() {
        // The escaped quote must not terminate the string early, so the
        // brackets that follow stay inside the string and are ignored.
        let content = r#"a: "embedded \" quote [[[[[""#;
        assert_eq!(check_yaml_nesting_depth(content, 1), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_comment_ignored() {
        let content = "# [[[[[unbalanced comment brackets]]]]]\na: 1\n";
        assert_eq!(check_yaml_nesting_depth(content, 1), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_mixed_flow_and_block_nesting() {
        // a: -> depth 1, "  b:" -> depth 2, then [ [ [ inside the value ->
        // peaks at depth 5 — flow and block share one budget.
        let content = "a:\n  b: [c, [d, [e]]]\n";
        assert_eq!(check_yaml_nesting_depth(content, 5), Ok(()));
        assert_eq!(check_yaml_nesting_depth(content, 4), Err(5));
    }

    #[test]
    fn test_check_yaml_nesting_depth_dash_chain_at_production_boundary() {
        // N dashes plus the trailing scalar's own column peak at depth
        // N + 1, so N = depth - 1 is the boundary.
        let depth = MAX_YAML_NESTING_DEPTH;
        let at_max = format!("{}1", "- ".repeat(depth - 1));
        assert_eq!(check_yaml_nesting_depth(&at_max, depth), Ok(()));

        let over_max = format!("{}1", "- ".repeat(depth));
        assert_eq!(check_yaml_nesting_depth(&over_max, depth), Err(depth + 1));
    }

    #[test]
    fn test_check_yaml_nesting_depth_block_mapping_at_production_boundary() {
        let depth = MAX_YAML_NESTING_DEPTH;
        assert_eq!(
            check_yaml_nesting_depth(&nested_mapping(depth), depth),
            Ok(())
        );
        assert_eq!(
            check_yaml_nesting_depth(&nested_mapping(depth + 1), depth),
            Err(depth + 1)
        );
    }

    #[test]
    fn test_check_yaml_nesting_depth_rejects_original_sigabrt_payloads() {
        // Depths comfortably past the empirically bisected real `yaml-rust2`
        // 0.12 crash thresholds on a 2 MiB debug stack (compact dash chain
        // aborts at 4536, growing-indent block mapping aborts at 1994) —
        // stays a real regression test even if `MAX_YAML_NESTING_DEPTH`
        // changes later, mirroring the TOML sibling test's margin.
        let dash_chain = format!("{}1", "- ".repeat(6000));
        assert!(check_yaml_nesting_depth(&dash_chain, MAX_YAML_NESTING_DEPTH).is_err());

        let block_mapping = nested_mapping(2500);
        assert!(check_yaml_nesting_depth(&block_mapping, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_apostrophe_does_not_blind_scanner() {
        // impl-critic C1: an apostrophe mid-plain-scalar (e.g. `doesn't`)
        // must not be mistaken for opening a quoted scalar and swallow the
        // rest of the file, hiding the real nesting that follows.
        let payload = format!(
            "name: my_app\ndescription: A package that doesn't panic\n{}1",
            "- ".repeat(MAX_YAML_NESTING_DEPTH + 1)
        );
        assert!(check_yaml_nesting_depth(&payload, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_stray_double_quote_does_not_blind_scanner() {
        // Same root cause as above, with a stray `"` (e.g. a dimension
        // string like `6" long`) instead of an apostrophe.
        let payload = format!(
            "size: 6\" long\n{}1",
            "- ".repeat(MAX_YAML_NESTING_DEPTH + 1)
        );
        assert!(check_yaml_nesting_depth(&payload, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_unterminated_quote_only_blinds_one_line() {
        // A quote that genuinely never closes must resynchronize at the
        // next newline rather than scanning to EOF looking for a match.
        let payload = format!(
            "a: \"unterminated\n{}1",
            "- ".repeat(MAX_YAML_NESTING_DEPTH + 1)
        );
        assert!(check_yaml_nesting_depth(&payload, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_backslash_before_newline_does_not_extend_string() {
        // A `\` placed right before the line break must not "escape" the
        // newline and let an opened double-quoted scalar swallow further
        // lines (impl-critic C1 follow-up).
        let payload = format!(
            "a: \"unterminated\\\n{}1",
            "- ".repeat(MAX_YAML_NESTING_DEPTH + 1)
        );
        assert!(check_yaml_nesting_depth(&payload, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_unclosed_bracket_does_not_blind_scanner() {
        // impl-critic C2: an unclosed `[`/`{` must not permanently suppress
        // block-indentation scanning for the remainder of the file.
        let payload = format!("a: [\n{}1", "- ".repeat(MAX_YAML_NESTING_DEPTH + 1));
        assert!(check_yaml_nesting_depth(&payload, MAX_YAML_NESTING_DEPTH).is_err());
    }

    #[test]
    fn test_check_yaml_nesting_depth_many_sibling_keys_do_not_accumulate() {
        let mut content = String::from("dependencies:\n");
        for i in 0..2000 {
            content.push_str(&format!("  pkg{i}: ^1.0.0\n"));
        }
        assert_eq!(check_yaml_nesting_depth(&content, 2), Ok(()));
    }

    #[test]
    fn test_check_yaml_nesting_depth_multiline_flow_list_siblings_do_not_accumulate() {
        let mut content = String::from("dependencies: [\n");
        for _ in 0..2000 {
            content.push_str("  a,\n");
        }
        content.push_str("]\n");
        assert_eq!(check_yaml_nesting_depth(&content, 3), Ok(()));
    }

    /// Billion-laughs-style doubling chain: depth stays 2, but expanded
    /// `Yaml` node count is roughly `2^n` from a source only ~20 bytes/level
    /// long — the exact attack shape from issue #175.
    fn doubling_chain(n: usize) -> String {
        let mut s = String::from("name: app\na0: &a0 [x, x]\n");
        for i in 1..=n {
            s.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}]\n", prev = i - 1));
        }
        s
    }

    #[test]
    fn test_check_yaml_expansion_empty_content() {
        assert_eq!(check_yaml_expansion("", MAX_YAML_EXPANDED_BYTES), Ok(()));
    }

    #[test]
    fn test_check_yaml_expansion_rejects_n30_doubling_chain_attack() {
        // The exact #175 payload shape: N=30 expands to over 2^30 nodes,
        // far past MAX_YAML_EXPANDED_BYTES, and must be rejected instead of
        // handed to `YamlLoader::load_from_str` (which OOMs/SIGKILLs).
        assert!(check_yaml_expansion(&doubling_chain(30), MAX_YAML_EXPANDED_BYTES).is_err());
    }

    #[test]
    fn test_check_yaml_expansion_realistic_pubspec_yaml_accepted() {
        let yaml = r"
name: my_app
description: A sample app
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0.0
  provider: ^6.0.0
  my_pkg:
    git:
      url: https://github.com/user/repo.git
      ref: main
      path: packages/my_pkg
dev_dependencies:
  build_runner: ^2.4.0
";
        assert_eq!(check_yaml_expansion(yaml, MAX_YAML_EXPANDED_BYTES), Ok(()));
    }

    #[test]
    fn test_check_yaml_expansion_few_hundred_package_lockfile_accepted() {
        let mut lock = String::from("packages:\n");
        for i in 0..300 {
            lock.push_str(&format!(
                "  pkg_{i}:\n    dependency: \"direct main\"\n    description:\n      name: pkg_{i}\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.{i}.0\"\n"
            ));
        }
        assert_eq!(check_yaml_expansion(&lock, MAX_YAML_EXPANDED_BYTES), Ok(()));
    }

    #[test]
    fn test_check_yaml_expansion_asterisk_in_plain_scalar_not_misread_as_alias() {
        // The raw-text pre-scan approach this algorithm replaced
        // false-positived on ordinary prose like this — a real `Event::Alias`
        // is never produced for a `*`/`&` inside a plain scalar value.
        let cases = [
            "description: A widget *multiplier* helper\n",
            "description: see *.dart files\n",
            "e: text &y more\n",
        ];
        for content in cases {
            assert_eq!(
                check_yaml_expansion(content, MAX_YAML_EXPANDED_BYTES),
                Ok(()),
                "false positive on: {content:?}"
            );
        }
    }

    #[test]
    fn test_check_yaml_expansion_alias_to_undefined_anchor_accepted() {
        // `YamlLoader` itself falls back to `Yaml::BadValue` for an alias id
        // it has no anchor recorded for; this guard mirrors that fallback
        // (`unwrap_or(YAML_NODE_OVERHEAD_BYTES)`) rather than treating it as
        // unbounded.
        assert_eq!(
            check_yaml_expansion("a: *undefined\n", MAX_YAML_EXPANDED_BYTES),
            Ok(())
        );
    }

    #[test]
    fn test_check_yaml_expansion_self_referential_alias_accepted() {
        // A sequence aliasing its own not-yet-closed anchor: the anchor
        // isn't registered yet when the alias event fires, so this hits the
        // same `unwrap_or(YAML_NODE_OVERHEAD_BYTES)` fallback as an
        // undefined anchor (verified against real `yaml-rust2` 0.12
        // behavior, not assumed) rather than recursing.
        assert_eq!(
            check_yaml_expansion("a: &x [1, *x]\n", MAX_YAML_EXPANDED_BYTES),
            Ok(())
        );
    }

    #[test]
    fn test_check_yaml_expansion_at_production_boundary() {
        // N=14 (16,907,046 bytes charged) stays under the byte budget,
        // N=15 (33,815,273 bytes) crosses it — empirically verified against
        // the real `MAX_YAML_EXPANDED_BYTES`, not assumed.
        assert_eq!(
            check_yaml_expansion(&doubling_chain(14), MAX_YAML_EXPANDED_BYTES),
            Ok(())
        );
        assert!(check_yaml_expansion(&doubling_chain(15), MAX_YAML_EXPANDED_BYTES).is_err());
    }

    #[test]
    fn test_check_yaml_expansion_large_scalar_anchor_aliased_many_times_rejected() {
        // Regression test for the critic's CRITICAL 1 finding: a node-count
        // budget accepted a large-scalar anchor aliased many times (linear
        // node growth, but memory grows with anchor size x alias count).
        // A 1 MB anchor aliased 32 times is ~33 MB of real `YamlLoader`
        // allocation from a ~1 MB source — must be rejected under the byte
        // budget even though it would cost only 34 nodes under a node
        // budget.
        let anchor_value = "A".repeat(1_000_000);
        let mut content = format!("s: &s \"{anchor_value}\"\nl:\n");
        for _ in 0..32 {
            content.push_str("  - *s\n");
        }
        assert!(check_yaml_expansion(&content, MAX_YAML_EXPANDED_BYTES).is_err());
    }

    #[test]
    fn test_check_yaml_expansion_exact_max_boundary() {
        // `charge` compares with `>`, so a document whose total charge is
        // exactly `max_bytes` must be accepted, and one byte more must be
        // rejected — pins that this is intentional (an accidental `>=`
        // would reject the exact-max case and go uncaught otherwise).
        let scalar_len = 1000usize;
        let max_bytes = YAML_NODE_OVERHEAD_BYTES as usize + scalar_len;
        let content = "a".repeat(scalar_len);

        assert_eq!(check_yaml_expansion(&content, max_bytes), Ok(()));
        assert!(check_yaml_expansion(&content, max_bytes - 1).is_err());
    }

    #[test]
    fn test_check_yaml_expansion_matches_recursive_byte_weight_oracle() {
        // Pins the invariant the whole design rests on: `check_yaml_expansion`'s
        // streaming tally equals an independent, recursive byte-weight
        // computation over the real parsed `Yaml` tree, for anchor-free
        // docs. Catches an accidental algorithm regression, or a
        // `yaml-rust2` upgrade that changes what gets allocated, that unit
        // tests on fixed payloads alone would not.
        fn recursive_weight(y: &yaml_rust2::Yaml) -> u64 {
            match y {
                yaml_rust2::Yaml::String(s) => YAML_NODE_OVERHEAD_BYTES + s.len() as u64,
                yaml_rust2::Yaml::Array(arr) => {
                    YAML_NODE_OVERHEAD_BYTES + arr.iter().map(recursive_weight).sum::<u64>()
                }
                yaml_rust2::Yaml::Hash(h) => {
                    YAML_NODE_OVERHEAD_BYTES
                        + h.iter()
                            .map(|(k, v)| recursive_weight(k) + recursive_weight(v))
                            .sum::<u64>()
                }
                _ => YAML_NODE_OVERHEAD_BYTES,
            }
        }

        // Binary search for the smallest `max_bytes` that `check_yaml_expansion`
        // still accepts — since `charge` uses `>`, this is exactly the real
        // total charged.
        fn smallest_accepted(content: &str) -> u64 {
            let (mut lo, mut hi) = (0u64, 1_000_000u64);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if check_yaml_expansion(content, usize::try_from(mid).unwrap_or(usize::MAX)).is_ok()
                {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            lo
        }

        // All scalars quoted, so every leaf is `Yaml::String` and its
        // parsed length matches its source text exactly (an unquoted
        // integer/bool/null scalar's `Yaml` variant does not retain its
        // source text, which would make the oracle inexact).
        let docs = [
            r#"a: "hello""#,
            r#"a: ["x", "yy", "zzz"]"#,
            "a:\n  b: \"value\"\n  c:\n    - \"one\"\n    - \"two\"\n",
        ];

        for content in docs {
            let parsed = yaml_rust2::YamlLoader::load_from_str(content).unwrap();
            let expected = recursive_weight(&parsed[0]);
            assert_eq!(
                smallest_accepted(content),
                expected,
                "oracle mismatch for {content:?}"
            );
        }
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
        // `is_registry()` stays true (it does name a registry), but this LSP
        // has no client for a private/custom registry, so it must not be
        // treated as version-resolvable against the public registry (#248).
        assert!(source.is_registry());
        assert!(!source.is_version_resolvable());
    }

    #[test]
    fn test_dependency_source_alternate_registry() {
        let source = DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev".into(),
            mirrors_crates_io: false,
        };
        // `is_registry()` is true (it is a registry, just not the default one), but
        // the generic `Registry` trait still can't resolve it — only an ecosystem
        // whose `EcosystemFormatter::can_resolve_source` override understands this
        // variant (e.g. `deps-cargo`'s `CargoFormatter`) can.
        assert!(source.is_registry());
        assert!(!source.is_version_resolvable());
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
    fn test_check_json_nesting_depth_shallow_accepted() {
        let content = br#"{"a":[1,2,{"b":3}],"c":"[not{real}nesting]"}"#;
        assert_eq!(check_json_nesting_depth(content, 4), Ok(()));
    }

    #[test]
    fn test_check_json_nesting_depth_string_brackets_ignored() {
        // Brackets inside a string literal (including an escaped quote) must
        // never be counted as structural nesting.
        let content = br#"{"a":"[[[[[\"]]]]]"}"#;
        assert_eq!(check_json_nesting_depth(content, 1), Ok(()));
    }

    #[test]
    fn test_check_json_nesting_depth_mixed_array_and_object_nesting() {
        let content = br#"[{"a":[{"b":1}]}]"#;
        assert_eq!(check_json_nesting_depth(content, 4), Ok(()));
        assert_eq!(check_json_nesting_depth(content, 3), Err(4));
    }

    #[test]
    fn test_check_json_nesting_depth_deeply_nested_array_rejected() {
        // The #430 attack shape: without this guard, `serde_json::from_slice`
        // would still not crash — it independently halts at its own default
        // recursion limit (128) with a clean `Err`. This guard rejects the
        // same shape earlier, at a stricter depth (64), with a repo-specific
        // `check_json_nesting_depth` error rather than a `serde_json::Error`.
        let deeply_nested = format!("{}1{}", "[".repeat(10), "]".repeat(10));
        assert_eq!(
            check_json_nesting_depth(deeply_nested.as_bytes(), 4),
            Err(5)
        );
    }

    #[test]
    fn test_check_json_nesting_depth_unterminated_string_blinds_scanner_but_serde_json_still_rejects()
     {
        // An unterminated `"` makes the scanner treat everything after it as
        // string content, so it returns `Ok` even with deep nesting past the
        // quote. This is safe only because `serde_json` independently halts
        // on the same malformed input via its own tokenizer.
        let payload = format!("\"unterminated{}1", "[".repeat(MAX_JSON_NESTING_DEPTH + 1));
        assert_eq!(
            check_json_nesting_depth(payload.as_bytes(), MAX_JSON_NESTING_DEPTH),
            Ok(())
        );
        assert!(serde_json::from_str::<serde_json::Value>(&payload).is_err());
    }

    #[test]
    fn test_check_json_nesting_depth_at_production_boundary() {
        let depth = MAX_JSON_NESTING_DEPTH;
        let at_max = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(check_json_nesting_depth(at_max.as_bytes(), depth), Ok(()));

        let over_max = format!("{}1{}", "[".repeat(depth + 1), "]".repeat(depth + 1));
        assert_eq!(
            check_json_nesting_depth(over_max.as_bytes(), depth),
            Err(depth + 1)
        );
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
