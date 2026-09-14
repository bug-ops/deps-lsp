//! Gemfile DSL parser with position tracking.
//!
//! Parses Gemfile files using regex-based line parsing to extract dependencies
//! with precise LSP positions.

use crate::types::{BundlerDependency, DependencyGroup, DependencySource};
use deps_core::Result;
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use regex::Regex;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::{Range, Uri};

/// Result of parsing a Gemfile.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct BundlerParseResult {
    /// Dependencies found in the `Gemfile`.
    pub dependencies: Vec<BundlerDependency>,
    /// The `ruby` directive's version constraint, if declared.
    pub ruby_version: Option<String>,
    /// The top-level `source` URL, if declared.
    pub source_url: Option<String>,
    /// URI of the manifest this result was parsed from.
    pub uri: Uri,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

// Regex patterns for Gemfile parsing
// Compile-time-constant patterns; a malformed literal is a build-visible programmer error,
// not attacker-influenceable input.
#[allow(clippy::expect_used)]
static GEM_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*gem\s+['"]([^'"]+)['"]"#).expect("Invalid regex"));

/// Matches a gem's version-constraint string, e.g. `gem "rails", "~> 7.0"`. Tolerant of a
/// trailing comment after the closing quote (`"~> 7.0" # pinned for Rails 7 compat`, #988) —
/// mirroring the comment-tolerance already added to the block-tracking regexes in #986.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static VERSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([~>=<!\d][^'"]*)['"]\s*(?:,|(?:#.*)?$)"#).expect("Invalid regex")
});

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*source\s+['"]([^'"]+)['"]\s*$"#).expect("Invalid regex"));

/// Matches a `source "..." do` block opener, e.g. `source "https://gems.corp" do`. Tolerates
/// a trailing comment (`... do # internal mirror`) — critic finding S2: without this, the
/// block never opens and every gem inside it silently resolves against the file-level source.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_BLOCK_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*source\s+['"]([^'"]+)['"]\s+do\s*(#.*)?$"#).expect("Invalid regex")
});

/// Builds the key-delimiter portion shared by every Bundler per-gem inline option, matching
/// either the modern `key:` syntax or Ruby's legacy hash-rocket `:key =>` syntax. Independent
/// of value shape, so it composes with any value pattern (`option_value_pattern` below for
/// quoted-string values, or a bespoke value pattern for array/boolean/symbol values like
/// [`GROUP_OPTION`], [`REQUIRE_OPTION`], and [`PLATFORMS_OPTION`]) — the single place the
/// hash-rocket gap (#987, #990) is fixed for all seven `*_OPTION` regexes.
fn option_key_pattern(key: &str) -> String {
    format!(r"(?:\b{key}:|:{key}\s*=>)")
}

/// Joins an option's key pattern with its value pattern (`key_pattern\s*value_pattern`) — the
/// single place every `*_OPTION` regex composes its key and value halves, so a future grammar
/// tweak (e.g. loosening `\s*` to `\s+`) is a one-line change instead of one edit per option.
fn option_pattern(key: &str, value_pattern: &str) -> String {
    format!(r"{}\s*{value_pattern}", option_key_pattern(key))
}

/// Builds a regex pattern matching a Bundler per-gem inline option with a quoted-string value,
/// in either the modern `key: value` syntax or Ruby's legacy hash-rocket `:key => value` syntax
/// (e.g. `source: "..."` or `:source => "..."`). Shared by [`SOURCE_OPTION`], [`GIT_OPTION`],
/// [`PATH_OPTION`], and [`GITHUB_OPTION`].
fn option_value_pattern(key: &str) -> String {
    option_pattern(key, r#"['"]([^'"]+)['"]"#)
}

/// Matches the per-gem inline `source:` option, e.g. `gem "x", source: "https://gems.corp"`
/// or the hash-rocket form `gem "x", :source => "https://gems.corp"`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_value_pattern("source")).expect("Invalid regex"));

/// Matches any recognized per-gem inline option's *key* alone (`source:`/`:source =>`,
/// `group:`/`:group =>`, `git:`/`:git =>`, `path:`/`:path =>`, `github:`/`:github =>`,
/// `require:`/`:require =>`, `platforms:`/`:platforms =>`) — used by `extract_version` to find
/// where a `gem` call's keyword-argument territory begins, so a quoted option value (e.g.
/// `require: "5.x_bridge"`) is never mistaken for a positional version constraint (code-review
/// finding).
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static ANY_OPTION_KEY: LazyLock<Regex> = LazyLock::new(|| {
    let alternation = [
        "source",
        "group",
        "git",
        "path",
        "github",
        "require",
        "platforms",
    ]
    .iter()
    .map(|key| option_key_pattern(key))
    .collect::<Vec<_>>()
    .join("|");
    Regex::new(&alternation).expect("Invalid regex")
});

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static RUBY_VERSION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*ruby\s+['"]([^'"]+)['"]\s*$"#).expect("Invalid regex"));

// Same guarantee as GEM_PATTERN above. Comment-tolerant for the same reason as
// SOURCE_BLOCK_START.
#[allow(clippy::expect_used)]
static GROUP_BLOCK_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*group\s+(.+?)\s+do\s*(#.*)?$").expect("Invalid regex"));

/// Matches any other `... do` block opener Bundler's DSL supports besides `group`/`source`
/// (`platforms ... do`, `install_if ... do`, `git "..." do`, `path "..." do`, `env ... do`,
/// etc.) — pushed onto [`OpenBlock::Other`] purely to keep [`BLOCK_END`] pops balanced
/// against pushes. Critic finding S1: without this, one of these openers nested inside a
/// `source ... do` block pops the *source* block early and every gem declared after it
/// silently resolves against the file-level source instead.
///
/// Anchored so `do` must appear before any `#` — critic finding N1: an unanchored pattern
/// also matches a `do` occurring only inside a trailing comment (`gem "rails" # lots to do`),
/// which would silently drop the whole line as a false block opener instead of parsing it.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GENERIC_BLOCK_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^#]*\bdo\s*(\|[^|]*\|)?\s*(#.*)?$").expect("Invalid regex"));

/// Matches Ruby's `end`-terminated block keywords that do **not** take a `do` (`if`,
/// `unless`, `case`, `begin`, `def`, `class`, `module`, `while`, `until`, `for`) — anchored at
/// the line start, with an optional leading `identifier = ` assignment prefix (`flag = if
/// COND ... end`, an expression-valued `if`), so the common single-line statement-modifier
/// form (`gem "x" if RUBY_VERSION > "2.0"`, which starts with `gem`, not the keyword or an
/// assignment to it) is correctly left unmatched, since that form has no matching `end` to
/// balance. Pushed onto [`OpenBlock::Other`] for the same reason as [`GENERIC_BLOCK_START`] —
/// code-review finding #1 (post-N1): without this, one of these constructs (most commonly `if
/// RUBY_PLATFORM =~ ... / end`) nested inside a `source ... do` block still pops the *source*
/// block early via its own bare `end`, reopening the same #980 leak class through a different
/// Ruby construct. The assignment-prefix extension closes the residual `flag = if ... end`
/// case impl-critic flagged after the initial fix (validated fix, same leak direction).
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static BARE_BLOCK_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:\S+\s*=\s*)?(if|unless|case|begin|def|class|module|while|until|for)\b")
        .expect("Invalid regex")
});

/// Matches the closing `end` of a `group`/`source`/other `... do` block. Comment-tolerant
/// (critic finding S2): without this, `end # close` never closes a `source` block and the
/// rest of the file is mis-classified as `CustomRegistry` (safe direction, but a functional
/// regression for every later gem's hover/diagnostics).
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static BLOCK_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*end\s*(#.*)?$").expect("Invalid regex"));

/// Matches the per-gem inline `group:` option, e.g. `gem "x", group: [:test]` or the
/// hash-rocket form `gem "x", :group => [:test]`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GROUP_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&option_pattern("group", r"(\[.+?\]|:\w+)")).expect("Invalid regex")
});

/// Matches the per-gem inline `git:` option, e.g. `gem "x", git: "https://..."` or the
/// hash-rocket form `gem "x", :git => "https://..."`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GIT_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_value_pattern("git")).expect("Invalid regex"));

/// Matches the per-gem inline `path:` option, e.g. `gem "x", path: "../local"` or the
/// hash-rocket form `gem "x", :path => "../local"`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static PATH_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_value_pattern("path")).expect("Invalid regex"));

/// Matches the per-gem inline `github:` option, e.g. `gem "x", github: "org/repo"` or the
/// hash-rocket form `gem "x", :github => "org/repo"`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GITHUB_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_value_pattern("github")).expect("Invalid regex"));

/// Matches the per-gem inline `require:` option, e.g. `gem "x", require: false` or the
/// hash-rocket form `gem "x", :require => false`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static REQUIRE_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&option_pattern("require", r#"(false|['"][^'"]*['"]\s*)"#)).expect("Invalid regex")
});

/// Matches the per-gem inline `platforms:` option, e.g. `gem "x", platforms: :ruby` or the
/// hash-rocket form `gem "x", :platforms => :ruby`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static PLATFORMS_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&option_pattern("platforms", r"(\[.+?\]|:\w+)")).expect("Invalid regex")
});

/// Which kind of `group ... do`, `source ... do`, or other Bundler DSL `... do ... end` block
/// is currently open while scanning the file — tracks only the *kind*, not the block's value.
///
/// Every kind shares one `end`-terminated syntax and can nest inside any other in any order,
/// so they are all tracked on a single stack rather than as independent `Option`s (or just the
/// two kinds this parser cares about) — anything less than tracking every opener leaves
/// [`BLOCK_END`]'s pops unbalanced against pushes, popping the wrong (e.g. an enclosing
/// `source`) block early (critic finding S1).
///
/// A `Group`/`Source` block's classification value lives on the parallel `group_stack`/
/// `source_stack` in [`parse_gemfile`] instead of inside this enum (#1009): popping this stack
/// tells which side-stack, if any, to also pop, so [`current_group`]/[`current_source_block`]
/// become O(1) `.last()` reads instead of an O(depth) reverse scan of a value-carrying stack on
/// every `gem` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenBlockKind {
    /// An open `group :name do ... end` block; its value is on `group_stack`'s top.
    Group,
    /// An open `source "url" do ... end` block; its value is on `source_stack`'s top.
    Source,
    /// Any other open `... do ... end` block this parser does not otherwise interpret
    /// (`platforms ... do`, `install_if ... do`, `git "..." do`, `path "..." do`, `env ...
    /// do`, etc.) — tracked purely to keep the stack balanced.
    Other,
}

/// Returns the innermost open `group` block's classification, if any — O(1), the top of
/// `group_stack`.
fn current_group(group_stack: &[DependencyGroup]) -> Option<DependencyGroup> {
    group_stack.last().cloned()
}

/// Returns the innermost open `source` block's URL, if any — O(1), the top of `source_stack`.
fn current_source_block(source_stack: &[String]) -> Option<&str> {
    source_stack.last().map(String::as_str)
}

/// A `gem` declaration whose argument list is still open across multiple physical lines —
/// Ruby's implicit line continuation on a trailing comma (no backslash needed), e.g. an inline
/// `:source => ...` option split onto its own line. Accumulated until a line closes the call,
/// then resolved exactly like a single-line `gem` call, but scanning every accumulated line for
/// each option instead of just one (#991: previously such a continuation line matched none of
/// this parser's line-level patterns and was silently dropped, leaving its `gem` misclassified
/// as `DependencySource::Registry`).
struct PendingGem<'a> {
    /// The gem name, captured from the line that opened the call.
    name: String,
    /// Document range of the gem name.
    name_range: Range,
    /// Each physical line belonging to this call (the first line's post-name remainder, then
    /// each continuation line in full) together with its absolute byte offset in the source, so
    /// an option value on any line still gets a correct LSP range.
    segments: Vec<(&'a str, usize)>,
}

/// Hard cap on how many physical lines a single [`PendingGem`] may accumulate before being
/// force-closed. `budget.allow()` counts resolved dependencies, not raw continuation lines, and
/// the continuation branch runs ahead of it every iteration — without a cap, a single
/// `gem "x",` followed by an unbounded run of blank/comment-only continuation lines would grow
/// `segments` without limit before the budget ever gets a chance to matter (impl-critic M1).
/// Generous enough for any real Gemfile's multi-line `gem` call (which rarely exceeds a
/// handful of option lines).
const MAX_PENDING_GEM_SEGMENTS: usize = 256;

/// Strips a Gemfile line's trailing `# comment`, skipping any `#` that appears inside a
/// single- or double-quoted string — in particular Ruby string interpolation like `#{...}`
/// inside a double-quoted option value. A naive (non-quote-aware) strip truncated a
/// continuation line right at `#{`, dropping its trailing comma and closing a pending
/// multi-line `gem` call one line early, re-leaking its `source:`/`git:`/`path:` option to the
/// public registry — the same #991 leak class, just triggered by string interpolation instead
/// of a bare continuation (impl-critic S2). Feeds only [`ends_with_trailing_comma`] and
/// [`continues_gem_declaration`]; unrelated to the simpler (non-quote-aware) comment tolerance
/// the block-tracking regexes elsewhere in this module use, since those match whole
/// single-line constructs where a `#` inside a quoted URL is not a realistic concern.
// `idx` comes from `char_indices()`, always a char boundary.
#[allow(clippy::string_slice)]
fn strip_trailing_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            // A backslash only escapes the next character inside a quoted string — outside
            // one, Ruby gives it no such meaning, so it must not swallow a real comment's `#`
            // (code-review finding: `require: foo \# real comment` failed to detect the
            // comment because the bare backslash was unconditionally treated as an escape).
            '\\' if in_single || in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..idx],
            _ => {}
        }
    }
    line
}

/// True when a comment-stripped, trimmed line ends with one of Ruby's two implicit
/// line-continuation signals: a trailing comma (an open argument list, no backslash needed) or
/// a trailing backslash (explicit continuation, valid on any statement — impl-critic S3; e.g.
/// `gem "x", \` continued on the next line).
fn signals_line_continuation(stripped: &str) -> bool {
    stripped.ends_with(',') || stripped.ends_with('\\')
}

/// True when `line`, once its trailing comment is stripped, ends with a continuation signal
/// (see [`signals_line_continuation`]). Used only for the line that *opens* a `gem` call: an
/// empty/non-continuing remainder there (a bare `gem "x"` with no arguments) correctly means
/// the call is already closed, unlike on a continuation line (see [`continues_gem_declaration`]).
fn ends_with_trailing_comma(line: &str) -> bool {
    signals_line_continuation(strip_trailing_comment(line).trim_end())
}

/// True when `line` keeps an already-open `gem` call's argument list going onto the next line.
/// A blank or comment-only continuation line carries no continuation signal either way, so it
/// preserves the call's already-open state, rather than prematurely closing it in front of a
/// commented-out continuation (e.g. a comment line between `gem "x",` and its `:source => ...`
/// option). Only valid to call on a line known to follow an already-open call — see
/// [`ends_with_trailing_comma`] for the line that opens one.
fn continues_gem_declaration(line: &str) -> bool {
    let stripped = strip_trailing_comment(line).trim();
    stripped.is_empty() || signals_line_continuation(stripped)
}

/// True when `line` independently matches one of `parse_gemfile`'s other top-level line
/// patterns (a new `gem`, a block opener/closer, `source`, or `ruby` declaration) — checked
/// only while a [`PendingGem`] is open, to detect that its argument list implicitly ended one
/// line early instead of swallowing this line as one of its segments. Tester-found bugs:
/// swallowing a `BLOCK_END` line here skipped its `group_stack`/`source_stack` pop, leaking
/// stale group/source state into every later gem in the file; swallowing a new `gem` line here
/// silently dropped that gem's declaration entirely (the same "gem disappears" leak class
/// #991 itself fixes, just with a different trigger).
fn starts_new_top_level_construct(line: &str) -> bool {
    SOURCE_BLOCK_START.is_match(line)
        || SOURCE_PATTERN.is_match(line)
        || RUBY_VERSION_PATTERN.is_match(line)
        || GROUP_BLOCK_START.is_match(line)
        || BLOCK_END.is_match(line)
        || GENERIC_BLOCK_START.is_match(line)
        || BARE_BLOCK_START.is_match(line)
        || GEM_PATTERN.is_match(line)
}

/// Resolves a [`PendingGem`] once its multi-line argument list has closed, applying the same
/// option-precedence rules as the single-line path (see `extract_source`'s doc) but scanning
/// every accumulated physical line for each option instead of just one.
///
/// Each segment is comment-stripped (via the same quote/interpolation-aware
/// [`strip_trailing_comment`] used for the continuation heuristic) before option extraction —
/// impl-critic S5: without this, a commented-out option on a continuation line (e.g. `#
/// source: "..."`) still matched `extract_source`'s regexes against the raw text and was
/// treated as an active option.
fn finalize_pending_gem(
    pending: PendingGem<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    gemfile_source_url: Option<&str>,
    block_source_url: Option<&str>,
    block_group: Option<DependencyGroup>,
) -> BundlerDependency {
    let stripped_segments: Vec<(&str, usize)> = pending
        .segments
        .iter()
        .map(|(text, offset)| (strip_trailing_comment(text), *offset))
        .collect();
    let (version_req, version_range) = extract_version(&stripped_segments, content, line_table);
    let lines: Vec<&str> = stripped_segments.iter().map(|(text, _)| *text).collect();
    let group =
        extract_group(&lines).unwrap_or_else(|| block_group.unwrap_or(DependencyGroup::Default));
    let source = extract_source(&lines, gemfile_source_url, block_source_url);
    let platforms = extract_platforms(&lines);
    let require = extract_require(&lines);

    BundlerDependency {
        name: pending.name.into(),
        name_range: pending.name_range,
        version_req: version_req.map(Into::into),
        version_range,
        group,
        source,
        platforms,
        require,
    }
}

/// Parses a Gemfile and extracts all dependencies with positions.
///
/// # Errors
///
/// Currently infallible: malformed or unrecognized lines are skipped rather than
/// erroring. Returns `Result` for interface consistency with other ecosystem parsers.
// The `caps.get(0).unwrap().end()` offset is a regex match end, always a char boundary.
// Group 1 is mandatory in `GEM_PATTERN` and group 0 always exists on a successful match.
#[allow(clippy::string_slice, clippy::unwrap_used)]
pub fn parse_gemfile(content: &str, doc_uri: &Uri) -> Result<BundlerParseResult> {
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut ruby_version = None;
    let mut source_url = None;
    let mut open_blocks: Vec<OpenBlockKind> = Vec::new();
    let mut group_stack: Vec<DependencyGroup> = Vec::new();
    let mut source_stack: Vec<String> = Vec::new();
    let mut pending_gem: Option<PendingGem<'_>> = None;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    for (line_idx, line) in content.lines().enumerate() {
        let Some(line_start) = line_table.line_start(line_idx) else {
            continue;
        };

        // A continuation line of a still-open multi-line `gem` call (#991) — must be checked
        // before every other line-level pattern below, since its content usually belongs to
        // the `gem` call's argument list, not to a new top-level construct.
        if let Some(pending) = pending_gem.take() {
            if starts_new_top_level_construct(line) {
                // This line is not actually part of the pending call's argument list — it
                // independently opens/closes/declares something else (a new `gem`, a block
                // opener/closer, `source`, `ruby`, ...). Finalize the pending gem from what
                // was already accumulated, without consuming this line, and let it fall
                // through to the normal dispatch chain below. Swallowing it unconditionally
                // previously either lost a `BLOCK_END` pop (desyncing `group_stack`/
                // `source_stack` for the rest of the file) or silently dropped the next `gem`
                // declaration entirely.
                dependencies.push(finalize_pending_gem(
                    pending,
                    content,
                    &line_table,
                    source_url.as_deref(),
                    current_source_block(&source_stack),
                    current_group(&group_stack),
                ));
                // Falls through — `line` is reprocessed by the checks below.
            } else {
                let mut pending = pending;
                pending.segments.push((line, line_start));
                let still_open = continues_gem_declaration(line)
                    && pending.segments.len() < MAX_PENDING_GEM_SEGMENTS;
                if still_open {
                    pending_gem = Some(pending);
                } else {
                    dependencies.push(finalize_pending_gem(
                        pending,
                        content,
                        &line_table,
                        source_url.as_deref(),
                        current_source_block(&source_stack),
                        current_group(&group_stack),
                    ));
                }
                continue;
            }
        }

        // Check for source block start (must precede the single-line SOURCE_PATTERN check:
        // SOURCE_PATTERN is `$`-anchored and never matches a `... do` opener, but checking
        // this first keeps the precedence explicit).
        if let Some(caps) = SOURCE_BLOCK_START.captures(line) {
            source_stack.push(caps[1].to_string());
            open_blocks.push(OpenBlockKind::Source);
            continue;
        }

        // Check for source declaration
        if let Some(caps) = SOURCE_PATTERN.captures(line) {
            if source_url.is_none() {
                source_url = Some(caps[1].to_string());
            }
            continue;
        }

        // Check for ruby version
        if let Some(caps) = RUBY_VERSION_PATTERN.captures(line) {
            ruby_version = Some(caps[1].to_string());
            continue;
        }

        // Check for group block start
        if let Some(caps) = GROUP_BLOCK_START.captures(line) {
            group_stack.push(parse_group_symbols(&caps[1]));
            open_blocks.push(OpenBlockKind::Group);
            continue;
        }

        // Check for a block end (closes whichever block is innermost) — must precede the
        // generic opener check below: critic finding N1, `end # nothing left to do` would
        // otherwise match GENERIC_BLOCK_START's `do` first and be mistaken for an opener
        // instead of the closer it actually is.
        if BLOCK_END.is_match(line) {
            match open_blocks.pop() {
                Some(OpenBlockKind::Group) => {
                    group_stack.pop();
                }
                Some(OpenBlockKind::Source) => {
                    source_stack.pop();
                }
                Some(OpenBlockKind::Other) | None => {}
            }
            continue;
        }

        // Check for any other `... do` block opener (platforms, install_if, git, path, env,
        // etc.) — pushed only to keep BLOCK_END's pops balanced (critic finding S1).
        if GENERIC_BLOCK_START.is_match(line) {
            open_blocks.push(OpenBlockKind::Other);
            continue;
        }

        // Check for a bare (no `do`) `end`-terminated block keyword (if/unless/case/begin/
        // def/class/module/while/until/for) — pushed for the same balancing reason as
        // GENERIC_BLOCK_START above (code-review finding #1).
        if BARE_BLOCK_START.is_match(line) {
            open_blocks.push(OpenBlockKind::Other);
            continue;
        }

        // Check for gem declaration
        if let Some(caps) = GEM_PATTERN.captures(line) {
            if !budget.allow() {
                continue;
            }

            let name = caps[1].to_string();

            // Find name position in line
            let name_match = caps.get(1).unwrap();
            let name_start = line_start + name_match.start();
            let name_end = line_start + name_match.end();

            let name_range = byte_span_to_range(content, &line_table, name_start, name_end);

            let rest_offset = line_start + caps.get(0).unwrap().end();
            let rest_of_line = &line[caps.get(0).unwrap().end()..];

            // A `gem` call whose argument list is still open (e.g. a trailing comma before an
            // option on its own line, #991) — accumulate rather than resolve now.
            if ends_with_trailing_comma(rest_of_line) {
                pending_gem = Some(PendingGem {
                    name,
                    name_range,
                    segments: vec![(rest_of_line, rest_offset)],
                });
                continue;
            }

            // Comment-stripped (impl-critic S5) before option extraction, so a trailing
            // comment mentioning an option-like string is never mistaken for an active one.
            let stripped_rest = strip_trailing_comment(rest_of_line);

            // Extract version if present
            let (version_req, version_range) =
                extract_version(&[(stripped_rest, rest_offset)], content, &line_table);

            // Extract group from inline option or current block
            let group = extract_group(std::slice::from_ref(&stripped_rest))
                .unwrap_or_else(|| current_group(&group_stack).unwrap_or(DependencyGroup::Default));

            // Extract source
            let source = extract_source(
                std::slice::from_ref(&stripped_rest),
                source_url.as_deref(),
                current_source_block(&source_stack),
            );

            // Extract platforms
            let platforms = extract_platforms(std::slice::from_ref(&stripped_rest));

            // Extract require option
            let require = extract_require(std::slice::from_ref(&stripped_rest));

            dependencies.push(BundlerDependency {
                name: name.into(),
                name_range,
                version_req: version_req.map(Into::into),
                version_range,
                group,
                source,
                platforms,
                require,
            });
        }
    }

    // The file ended while a `gem` call was still open (e.g. a trailing comma with no further
    // lines) — resolve it with whatever was accumulated instead of silently dropping it.
    if let Some(pending) = pending_gem.take() {
        dependencies.push(finalize_pending_gem(
            pending,
            content,
            &line_table,
            source_url.as_deref(),
            current_source_block(&source_stack),
            current_group(&group_stack),
        ));
    }

    Ok(BundlerParseResult {
        dependencies,
        ruby_version,
        source_url,
        uri: doc_uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

/// Scans each `(line, base_offset)` segment in order and returns the version constraint from
/// the first eligible one, with a range computed against that specific line's offset — so a
/// version on a continuation line of a multi-line `gem` call (#991) still gets a correct LSP
/// range instead of one derived from the wrong physical line.
///
/// A version constraint can only be a *positional* argument, and Ruby requires positional
/// arguments before keyword arguments in a method call — so each segment is searched only up
/// to the start of its first recognized option key ([`ANY_OPTION_KEY`]), if any, and once a
/// segment contains one, scanning stops there entirely (every later segment is necessarily
/// inside keyword-argument territory too). Without this, `VERSION_PATTERN` — which matches any
/// quoted string starting with a version-ish character — could match an unrelated option's
/// value on a later line (e.g. `require: "5.x_bridge"`) and misreport it as the version
/// constraint, while the real one further down was never reached (code-review finding).
// Group 1 is mandatory in `VERSION_PATTERN`; `key_match.start()` is a regex match-start offset,
// always a char boundary.
#[allow(clippy::unwrap_used, clippy::string_slice)]
fn extract_version(
    lines: &[(&str, usize)],
    content: &str,
    line_table: &LineOffsetTable,
) -> (Option<String>, Option<Range>) {
    for (line, base_offset) in lines {
        let line: &str = line;
        let key_match = ANY_OPTION_KEY.find(line);
        let search_area = key_match.map_or(line, |m| &line[..m.start()]);

        if let Some(caps) = VERSION_PATTERN.captures(search_area) {
            let version = caps[1].to_string();
            let version_match = caps.get(1).unwrap();
            let version_start = base_offset + version_match.start();
            let version_end = base_offset + version_match.end();

            let version_range = byte_span_to_range(content, line_table, version_start, version_end);

            return (Some(version), Some(version_range));
        }

        if key_match.is_some() {
            // This segment already entered keyword-argument territory — no positional version
            // can appear on this or any later segment.
            break;
        }
    }
    (None, None)
}

/// Scans each accumulated line for the inline `group:` option, returning the first match.
fn extract_group(lines: &[&str]) -> Option<DependencyGroup> {
    lines
        .iter()
        .find_map(|line| GROUP_OPTION.captures(line))
        .map(|caps| parse_group_symbols(&caps[1]))
}

fn parse_group_symbols(text: &str) -> DependencyGroup {
    let text = text.trim();

    if text.contains(":development") {
        DependencyGroup::Development
    } else if text.contains(":test") {
        DependencyGroup::Test
    } else if text.contains(":production") {
        DependencyGroup::Production
    } else if text.starts_with(':') {
        DependencyGroup::Custom(text.trim_start_matches(':').to_string())
    } else {
        DependencyGroup::Default
    }
}

/// Bundler's implicit default gem source when a Gemfile declares no `source` line.
const DEFAULT_RUBYGEMS_SOURCE: &str = "https://rubygems.org";

/// Classifies a plain registry URL: the implicit default (rubygems.org) resolves as
/// `Registry`; anything else has no client this LSP can query, so it becomes
/// `CustomRegistry` — mirroring Cargo's `registry = "..."` handling (#248). Thin wrapper
/// around the shared `deps_core::classify_default_registry_url` (code-review finding #2: this
/// was byte-identical logic duplicated with `deps-dart`'s `classify_hosted_url`).
fn classify_registry_url(url: &str) -> DependencySource {
    deps_core::classify_default_registry_url(url.to_string(), &[DEFAULT_RUBYGEMS_SOURCE])
}

/// Classifies a gem's dependency source.
///
/// `lines` is every physical line belonging to this `gem` call (just the one line for a
/// single-line declaration; the post-name remainder plus every continuation line for a
/// multi-line one, #991) — each option pattern is checked against every line in order, so an
/// option on any continuation line is still found regardless of which line the eventual match
/// comes from.
///
/// `gemfile_source_url` is the Gemfile-level, single-line `source "..."` declaration (if
/// any); `block_source_url` is the innermost enclosing `source "..." do ... end` block's URL
/// (if any) — both captured once per file in [`parse_gemfile`] and threaded through here so a
/// gem with no per-line `git:`/`github:`/`path:`/`source:` option is classified against the
/// source that actually resolves it, rather than defaulting to the public registry.
///
/// Precedence: `git:`/`github:`/`path:` (explicit non-registry source) → inline `source:`
/// option → enclosing `source ... do` block → file-level `source` → `Registry`.
fn extract_source(
    lines: &[&str],
    gemfile_source_url: Option<&str>,
    block_source_url: Option<&str>,
) -> DependencySource {
    if let Some(caps) = lines.iter().find_map(|line| GIT_OPTION.captures(line)) {
        return DependencySource::Git {
            url: caps[1].to_string(),
            rev: None,
        };
    }

    if let Some(caps) = lines.iter().find_map(|line| GITHUB_OPTION.captures(line)) {
        return DependencySource::Git {
            url: format!("https://github.com/{}", &caps[1]),
            rev: None,
        };
    }

    if let Some(caps) = lines.iter().find_map(|line| PATH_OPTION.captures(line)) {
        return DependencySource::Path {
            path: caps[1].to_string(),
        };
    }

    if let Some(caps) = lines.iter().find_map(|line| SOURCE_OPTION.captures(line)) {
        return classify_registry_url(&caps[1]);
    }

    if let Some(url) = block_source_url {
        return classify_registry_url(url);
    }

    gemfile_source_url.map_or(DependencySource::Registry, classify_registry_url)
}

/// Scans each accumulated line for the inline `platforms:` option, returning the first match.
fn extract_platforms(lines: &[&str]) -> Vec<String> {
    let Some(caps) = lines
        .iter()
        .find_map(|line| PLATFORMS_OPTION.captures(line))
    else {
        return vec![];
    };
    let platforms_str = &caps[1];
    if platforms_str.starts_with('[') {
        // Parse array: [:mingw, :mswin]
        platforms_str
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .map(|s| s.trim().trim_start_matches(':').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        // Single symbol: :ruby
        vec![platforms_str.trim_start_matches(':').to_string()]
    }
}

/// Scans each accumulated line for the inline `require:` option, returning the first match.
fn extract_require(lines: &[&str]) -> Option<String> {
    let caps = lines
        .iter()
        .find_map(|line| REQUIRE_OPTION.captures(line))?;
    let value = &caps[1];
    if value == "false" {
        Some("false".to_string())
    } else {
        Some(value.trim_matches(|c| c == '\'' || c == '"').to_string())
    }
}

/// Parser for Gemfile manifests.
pub struct BundlerParser;

deps_core::impl_parse_result!(
    BundlerParseResult,
    BundlerDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Uri {
        #[cfg(windows)]
        let path = "C:/test/Gemfile";
        #[cfg(not(windows))]
        let path = "/test/Gemfile";
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_simple_gem() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, None);
    }

    #[test]
    fn test_parse_gem_with_version() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    #[test]
    fn test_parse_gem_with_group() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rspec', group: :test";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
    }

    #[test]
    fn test_parse_group_block() {
        let gemfile = r"source 'https://rubygems.org'

group :development, :test do
  gem 'rspec'
  gem 'pry'
end

gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        // rspec and pry should be in development group (development is checked first)
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
        assert_matches!(result.dependencies[1].group, DependencyGroup::Development);

        // rails should be default group
        assert_matches!(result.dependencies[2].group, DependencyGroup::Default);
    }

    #[test]
    fn test_parse_git_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', git: 'https://github.com/rails/rails.git'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    #[test]
    fn test_parse_github_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', github: 'rails/rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Git { url, .. } => {
                assert!(url.contains("github.com/rails/rails"));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_parse_path_source() {
        let gemfile = r"source 'https://rubygems.org'
gem 'local_gem', path: '../local_gem'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Path { .. });
    }

    #[test]
    fn test_parse_ruby_version() {
        let gemfile = r"source 'https://rubygems.org'
ruby '3.2.2'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.ruby_version, Some("3.2.2".into()));
    }

    #[test]
    fn test_parse_source_url() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.source_url, Some("https://rubygems.org".into()));
    }

    #[test]
    fn test_default_rubygems_source_classified_as_registry() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert!(result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_custom_gemfile_source_classified_as_custom_registry() {
        let gemfile = r"source 'https://gems.mycorp.com'
gem 'internal-gem'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(!result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_custom_gemfile_source_does_not_override_explicit_git_source() {
        let gemfile = r"source 'https://gems.mycorp.com'
gem 'rails', git: 'https://github.com/rails/rails.git'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    /// Security regression: the block form `source "..." do ... end` was previously invisible
    /// to `SOURCE_PATTERN` (`$`-anchored), so a gem declared inside it silently fell through
    /// to `Registry` and leaked its name to rubygems.org.
    #[test]
    fn test_source_block_form_classified_as_custom_registry() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.mycorp.com" do
  gem "internal-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// A gem outside a `source ... do` block still resolves against the file-level source.
    #[test]
    fn test_source_block_does_not_leak_into_surrounding_gems() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.mycorp.com" do
  gem "internal-gem"
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// Security regression: the per-gem inline `source:` option was previously not consulted
    /// by `extract_source` at all, so a gem using it silently fell through to `Registry` and
    /// leaked its name to rubygems.org.
    #[test]
    fn test_inline_source_option_classified_as_custom_registry() {
        let gemfile = r#"source "https://rubygems.org"
gem "internal-gem", source: "https://gems.mycorp.com""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// The inline `source:` option must still lose to an explicit `git:`/`path:` option, per
    /// `extract_source`'s documented precedence.
    #[test]
    fn test_inline_source_option_does_not_override_explicit_git_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", git: "https://github.com/rails/rails.git", source: "https://gems.mycorp.com""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    /// Trap regression: a `group` block nested inside a `source ... do` block (or vice versa)
    /// must not mis-pair its `end` against the wrong opener — both the group classification
    /// and the source classification must still resolve correctly for a gem declared inside
    /// both.
    #[test]
    fn test_nested_group_inside_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.mycorp.com" do
  group :test do
    gem "internal-test-gem"
  end
  gem "internal-gem"
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }

        assert_matches!(result.dependencies[1].group, DependencyGroup::Default);
        match &result.dependencies[1].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }

        assert_matches!(result.dependencies[2].group, DependencyGroup::Default);
        assert_eq!(result.dependencies[2].source, DependencySource::Registry);
    }

    /// Trap regression: a `source ... do` block nested inside a `group` block must also
    /// unwind correctly — the reverse nesting order from the test above.
    #[test]
    fn test_nested_source_block_inside_group() {
        let gemfile = r#"source "https://rubygems.org"
group :test do
  source "https://gems.mycorp.com" do
    gem "internal-test-gem"
  end
  gem "rspec"
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }

        assert_matches!(result.dependencies[1].group, DependencyGroup::Test);
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);

        assert_matches!(result.dependencies[2].group, DependencyGroup::Default);
        assert_eq!(result.dependencies[2].source, DependencySource::Registry);
    }

    /// Security regression (impl-critic S1): an unrecognized `... do` opener (`platforms ...
    /// do` here — Bundler also has `install_if`, `git "..." do`, `path "..." do`, `env ...
    /// do`) nested inside a `source ... do` block must not pop the *source* block early. Before
    /// the `OpenBlock::Other` fix, `platforms :ruby do ... end`'s own `end` popped the
    /// enclosing `source` block, so `after-inner-gem` (declared after it but still textually
    /// inside the `source` block) silently resolved against rubygems.org instead.
    #[test]
    fn test_unrecognized_do_block_does_not_unbalance_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  platforms :ruby do
    gem "inner-gem"
  end
  gem "after-inner-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            match &dep.source {
                DependencySource::CustomRegistry { url } => {
                    assert_eq!(url, "https://gems.corp");
                }
                other => panic!("expected CustomRegistry for {}, got {other:?}", dep.name),
            }
        }
    }

    /// Security regression (impl-critic S1): same trap, but the unbalancing opener
    /// (`install_if ... do`) sits *after* the gem it must not affect, closing on `install_if`'s
    /// own `end` while the `source` block is still open around it.
    #[test]
    fn test_unrecognized_do_block_after_gem_does_not_unbalance_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "before-inner-gem"
  install_if -> { true } do
    gem "conditional-gem"
  end
  gem "after-inner-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        for dep in &result.dependencies {
            match &dep.source {
                DependencySource::CustomRegistry { url } => {
                    assert_eq!(url, "https://gems.corp");
                }
                other => panic!("expected CustomRegistry for {}, got {other:?}", dep.name),
            }
        }
    }

    /// Security regression (impl-critic S2): a trailing comment on the `source ... do` opener
    /// must not prevent the block from opening — before the fix, `SOURCE_BLOCK_START`'s `$`
    /// anchor never matched the comment-bearing line, so the gem inside silently resolved
    /// against the file-level rubygems.org source instead.
    #[test]
    fn test_source_block_start_tolerates_trailing_comment() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do # internal mirror
  gem "internal-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security/functional regression (impl-critic S2): a trailing comment on `end` must
    /// still close the block — before the fix, `BLOCK_END`'s `$` anchor never matched, so the
    /// `source` block stayed open for the rest of the file and every later gem was
    /// mis-classified as `CustomRegistry` instead of `Registry`.
    #[test]
    fn test_block_end_tolerates_trailing_comment() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "internal-gem"
end # close

gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// impl-critic M1: a trailing slash on the default rubygems.org source must not cause a
    /// misclassification as `CustomRegistry`.
    #[test]
    fn test_classify_registry_url_ignores_trailing_slash() {
        assert_eq!(
            classify_registry_url("https://rubygems.org/"),
            DependencySource::Registry
        );
        assert_eq!(
            classify_registry_url("https://rubygems.org"),
            DependencySource::Registry
        );
    }

    /// Regression (impl-critic N1, case 1): a gem line whose trailing comment happens to end
    /// in the word "do" must still parse as a normal gem declaration — before the fix,
    /// `GENERIC_BLOCK_START` was unanchored and matched the `do` inside the comment, silently
    /// dropping the dependency and unbalancing the block stack for the rest of the file.
    #[test]
    fn test_gem_line_with_trailing_do_comment_still_parses() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", "~> 7.0" # lots of things to do
gem "rspec""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert_eq!(result.dependencies[1].name, "rspec");
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// Regression (impl-critic N1, case 2): `end # nothing left to do` must still close the
    /// enclosing block — before the fix (and the `BLOCK_END`-before-`GENERIC_BLOCK_START`
    /// reorder), the `do` inside the comment made `GENERIC_BLOCK_START` match first, so the
    /// `source` block never closed and every later gem stayed mis-classified `CustomRegistry`.
    #[test]
    fn test_block_end_with_trailing_do_comment_still_closes_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "internal-gem"
end # nothing left to do

gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// Regression (impl-critic N1, case 3): a bare comment line ending in "do" must not push
    /// an unbalancing `Other` block.
    #[test]
    fn test_bare_comment_line_ending_in_do_does_not_push_block() {
        let gemfile = r#"source "https://rubygems.org"
# things left to do
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Sanity check (impl-critic N1): a normal Gemfile mixing a `ruby` directive, a `group
    /// ... do` block, and an unrelated `.each do |x|` iterator block must still parse exactly
    /// as before these fixes.
    #[test]
    fn test_normal_gemfile_with_each_block_unaffected() {
        let gemfile = r#"source "https://rubygems.org"
ruby "3.2.2"

%w[foo bar].each do |name|
  gem name
end

group :development, :test do
  gem "rspec"
end

gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.ruby_version, Some("3.2.2".into()));
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "rspec");
        // `parse_group_symbols` checks `:development` before `:test` (matching the existing
        // test_group_array_syntax precedent), so `group :development, :test do` resolves to
        // `Development`, not `Test`.
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
        assert_eq!(result.dependencies[1].name, "rails");
        assert_matches!(result.dependencies[1].group, DependencyGroup::Default);
    }

    /// Security regression (code-review finding #1, post-N1): a bare (no `do`) `if ... end`
    /// block nested inside a `source ... do` block must not pop the *source* block early via
    /// its own `end`. Exact repro from the reviewer: before the `BARE_BLOCK_START` fix,
    /// `after-if-gem` (declared after the `if` block but still textually inside the `source`
    /// block) silently resolved against rubygems.org instead of staying `CustomRegistry`.
    #[test]
    fn test_bare_if_block_does_not_unbalance_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  if RUBY_PLATFORM =~ /darwin/
    gem "mac-only-gem"
  end
  gem "after-if-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            match &dep.source {
                DependencySource::CustomRegistry { url } => {
                    assert_eq!(url, "https://gems.corp");
                }
                other => panic!("expected CustomRegistry for {}, got {other:?}", dep.name),
            }
        }
    }

    /// Same trap as above, covering `unless`, `case`, and `def` — the other bare
    /// `end`-terminated keywords `BARE_BLOCK_START` must recognize.
    #[test]
    fn test_other_bare_block_keywords_do_not_unbalance_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  unless ENV["CI"]
    gem "dev-only-gem"
  end
  case RUBY_PLATFORM
  when /darwin/
    gem "mac-gem"
  end
  def helper_method
    true
  end
  gem "after-all-blocks-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        for dep in &result.dependencies {
            match &dep.source {
                DependencySource::CustomRegistry { url } => {
                    assert_eq!(url, "https://gems.corp");
                }
                other => panic!("expected CustomRegistry for {}, got {other:?}", dep.name),
            }
        }
    }

    /// Sanity check: a single-line statement-modifier `if`/`unless` (`gem "x" if cond`) must
    /// NOT be treated as a block opener — the line starts with `gem`, not the keyword, so
    /// `BARE_BLOCK_START`'s line-start anchor correctly leaves it unmatched (this form has no
    /// matching `end` to balance).
    #[test]
    fn test_statement_modifier_if_is_not_treated_as_block_opener() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "mac-only-gem" if RUBY_PLATFORM =~ /darwin/
  gem "after-modifier-gem" unless ENV["CI"]
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_eq!(result.dependencies[0].name, "mac-only-gem");
        assert_eq!(result.dependencies[1].name, "after-modifier-gem");
        for dep in &result.dependencies[..2] {
            match &dep.source {
                DependencySource::CustomRegistry { url } => {
                    assert_eq!(url, "https://gems.corp");
                }
                other => panic!("expected CustomRegistry for {}, got {other:?}", dep.name),
            }
        }
        assert_eq!(result.dependencies[2].name, "rails");
        assert_eq!(result.dependencies[2].source, DependencySource::Registry);
    }

    /// Security regression (impl-critic, post-#1): the expression-valued (assignment) form
    /// `flag = if COND ... end` has its `if` preceded by `flag = `, so it does not start the
    /// line — before extending `BARE_BLOCK_START` with the optional assignment prefix, this
    /// bare `end` still popped the enclosing `source` block early, and `after-assignment-gem`
    /// (declared after it but still textually inside the block) silently fell back to
    /// `Registry` — the same leak direction the original #980 fix and finding #1 both close.
    #[test]
    fn test_assignment_form_if_block_does_not_unbalance_source_block() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  flag = if RUBY_VERSION > "3"
    true
  else
    false
  end
  gem "after-assignment-gem"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    #[test]
    fn test_position_tracking() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Name should be on line 1 (0-indexed)
        assert_eq!(dep.name_range.start.line, 1);
        // Version should also be on line 1
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 1);
    }

    #[test]
    fn test_parse_platforms() {
        let gemfile = r"source 'https://rubygems.org'
gem 'tzinfo-data', platforms: [:mingw, :mswin]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].platforms, vec!["mingw", "mswin"]);
    }

    #[test]
    fn test_parse_require_false() {
        let gemfile = r"source 'https://rubygems.org'
gem 'puma', require: false";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some("false".into()));
    }

    #[test]
    fn test_empty_gemfile() {
        let gemfile = "";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_gemfile_with_comments() {
        let gemfile = r"source 'https://rubygems.org'
# This is a comment
gem 'rails'
# gem 'disabled'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
    }

    #[test]
    fn test_parse_production_group() {
        let gemfile = r"source 'https://rubygems.org'
gem 'unicorn', group: :production";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Production);
    }

    #[test]
    fn test_parse_development_group() {
        let gemfile = r"source 'https://rubygems.org'
gem 'pry', group: :development";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
    }

    #[test]
    fn test_parse_custom_group() {
        let gemfile = r"source 'https://rubygems.org'
gem 'sidekiq', group: :staging";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        if let DependencyGroup::Custom(name) = &result.dependencies[0].group {
            assert_eq!(name, "staging");
        } else {
            panic!("Expected custom group");
        }
    }

    #[test]
    fn test_parse_group_block_test() {
        let gemfile = r"source 'https://rubygems.org'
group :test do
  gem 'minitest'
end";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
    }

    #[test]
    fn test_parse_group_block_production() {
        let gemfile = r"source 'https://rubygems.org'
group :production do
  gem 'newrelic_rpm'
end";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Production);
    }

    #[test]
    fn test_parse_single_platform() {
        let gemfile = r"source 'https://rubygems.org'
gem 'wdm', platforms: :mswin";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].platforms, vec!["mswin"]);
    }

    #[test]
    fn test_parse_require_custom_path() {
        let gemfile = r"source 'https://rubygems.org'
gem 'my_gem', require: 'custom/path'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some("custom/path".into()));
    }

    #[test]
    fn test_parse_multiple_sources() {
        let gemfile = r"source 'https://rubygems.org'
source 'https://gems.example.com'
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        // First source should be kept
        assert_eq!(result.source_url, Some("https://rubygems.org".into()));
    }

    #[test]
    fn test_parse_double_quoted_strings() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", "~> 7.0""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.source_url, Some("https://rubygems.org".into()));
    }

    #[test]
    fn test_parse_gem_with_multiple_options() {
        let gemfile = r"source 'https://rubygems.org'
gem 'sidekiq', '~> 7.0', require: false, group: :production";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].name, "sidekiq");
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
        assert_eq!(result.dependencies[0].require, Some("false".into()));
        assert_matches!(result.dependencies[0].group, DependencyGroup::Production);
    }

    #[test]
    fn test_parse_nested_group_blocks() {
        let gemfile = r"source 'https://rubygems.org'
group :development do
  gem 'pry'
end
group :test do
  gem 'rspec'
end
gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
        assert_matches!(result.dependencies[1].group, DependencyGroup::Test);
        assert_matches!(result.dependencies[2].group, DependencyGroup::Default);
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();

        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<BundlerParseResult>());
    }

    #[test]
    fn test_parse_version_operators() {
        let gemfile = r"source 'https://rubygems.org'
gem 'gem1', '>= 1.0'
gem 'gem2', '> 2.0'
gem 'gem3', '<= 3.0'
gem 'gem4', '< 4.0'
gem 'gem5', '!= 5.0'";

        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 5);
        assert_eq!(result.dependencies[0].version_req, Some(">= 1.0".into()));
        assert_eq!(result.dependencies[1].version_req, Some("> 2.0".into()));
        assert_eq!(result.dependencies[2].version_req, Some("<= 3.0".into()));
        assert_eq!(result.dependencies[3].version_req, Some("< 4.0".into()));
        assert_eq!(result.dependencies[4].version_req, Some("!= 5.0".into()));
    }

    #[test]
    fn test_parse_exact_version() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '7.0.8'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("7.0.8".into()));
    }

    #[test]
    fn test_parse_result_uri() {
        use deps_core::ParseResult;

        let uri = test_uri();
        let gemfile = r"source 'https://rubygems.org'";
        let result = parse_gemfile(gemfile, &uri).unwrap();

        assert_eq!(result.uri(), &uri);
    }

    #[test]
    fn test_group_array_syntax() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rspec', group: [:test, :development]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        // When array contains both :test and :development, development is checked first
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
    }

    #[test]
    fn test_whitespace_handling() {
        let gemfile = "source 'https://rubygems.org'\n  gem  'rails'  ";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
    }

    #[test]
    fn test_gem_without_source() {
        let gemfile = "gem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.source_url.is_none());
    }

    #[test]
    fn test_unicode_in_content() {
        let gemfile = "source 'https://rubygems.org'\n# UTF-8: \u{1F600}\ngem 'rails'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    /// Security regression (#987): the hash-rocket `:source => "..."` form was previously
    /// unmatched by `SOURCE_OPTION` (`key: value` only), so a gem using it silently fell
    /// through to `Registry` and leaked its name to rubygems.org.
    #[test]
    fn test_hash_rocket_source_option_classified_as_custom_registry() {
        let gemfile = r#"source "https://rubygems.org"
gem "internal-gem", :source => "https://gems.mycorp.com""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.mycorp.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (#987), same gap as above for the `git:` option.
    #[test]
    fn test_hash_rocket_git_option_classified_as_git_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", :git => "https://github.com/rails/rails.git""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Git { url, .. } => {
                assert_eq!(url, "https://github.com/rails/rails.git");
            }
            other => panic!("expected Git source, got {other:?}"),
        }
    }

    /// Security regression (#987), same gap as above for the `path:` option.
    #[test]
    fn test_hash_rocket_path_option_classified_as_path_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "local_gem", :path => "../local_gem""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Path { path } => {
                assert_eq!(path, "../local_gem");
            }
            other => panic!("expected Path source, got {other:?}"),
        }
    }

    /// Security regression (#987), same gap as above for the `github:` option.
    #[test]
    fn test_hash_rocket_github_option_classified_as_git_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", :github => "rails/rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Git { url, .. } => {
                assert!(url.contains("github.com/rails/rails"));
            }
            other => panic!("expected Git source, got {other:?}"),
        }
    }

    /// The hash-rocket `:git =>` option must still take precedence over `:source =>`, mirroring
    /// `test_inline_source_option_does_not_override_explicit_git_source` for the modern syntax.
    #[test]
    fn test_hash_rocket_git_option_takes_precedence_over_hash_rocket_source_option() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", :git => "https://github.com/rails/rails.git", :source => "https://gems.mycorp.com""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    /// Regression (#988): a trailing comment after a version constraint must not drop
    /// `version_req` entirely — before the fix, `VERSION_PATTERN` was anchored right after the
    /// closing quote and never matched a line like `gem "rails", "~> 7.0" # pinned`.
    #[test]
    fn test_version_with_trailing_comment_still_captured() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", "~> 7.0" # pinned for Rails 7 compat"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    /// Sanity check: a version constraint immediately followed by more inline options (no
    /// comment) must still parse exactly as before this fix.
    #[test]
    fn test_version_followed_by_options_without_comment_still_captured() {
        let gemfile = r"source 'https://rubygems.org'
gem 'sidekiq', '~> 7.0', require: false";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    /// Security regression (#990), same gap as #987 but for the `group:` option: the
    /// hash-rocket `:group => [...]` form was previously unmatched by `GROUP_OPTION`
    /// (`key:`-only), so the gem's group inline option was silently dropped.
    #[test]
    fn test_hash_rocket_group_option_array_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "rspec", :group => [:test]"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
    }

    /// Same gap as above for the `group:` option with a bare symbol value.
    #[test]
    fn test_hash_rocket_group_option_symbol_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "sidekiq", :group => :production"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Production);
    }

    /// Security regression (#990), same gap as #987 but for the `require:` option.
    #[test]
    fn test_hash_rocket_require_option_false_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "puma", :require => false"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some("false".into()));
    }

    /// Same gap as above for the `require:` option with a custom path value.
    #[test]
    fn test_hash_rocket_require_option_custom_path_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "my_gem", :require => "custom/path""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some("custom/path".into()));
    }

    /// Security regression (#990), same gap as #987 but for the `platforms:` option.
    #[test]
    fn test_hash_rocket_platforms_option_symbol_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "wdm", :platforms => :mswin"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].platforms, vec!["mswin"]);
    }

    /// Same gap as above for the `platforms:` option with an array value.
    #[test]
    fn test_hash_rocket_platforms_option_array_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "tzinfo-data", :platforms => [:mingw, :mswin]"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].platforms, vec!["mingw", "mswin"]);
    }

    /// A Gemfile mixing modern and hash-rocket syntax across different gems and options must
    /// resolve every option correctly regardless of which syntax each line uses.
    #[test]
    fn test_mixed_modern_and_hash_rocket_syntax_gemfile() {
        let gemfile = r#"source "https://rubygems.org"
gem "rspec", group: [:test], :require => false
gem "sidekiq", :group => :production, require: "sidekiq/testing"
gem "wdm", platforms: :mswin
gem "tzinfo-data", :platforms => [:mingw, :mswin]"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);

        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
        assert_eq!(result.dependencies[0].require, Some("false".into()));

        assert_matches!(result.dependencies[1].group, DependencyGroup::Production);
        assert_eq!(
            result.dependencies[1].require,
            Some("sidekiq/testing".into())
        );

        assert_eq!(result.dependencies[2].platforms, vec!["mswin"]);
        assert_eq!(result.dependencies[3].platforms, vec!["mingw", "mswin"]);
    }

    /// Regression (impl-critic M1): the modern `{key}:` branch must not match a key that is
    /// merely a suffix of a longer identifier — `subgroup:` must not be mistaken for `group:`.
    /// Without the `\b` left word boundary, `GROUP_OPTION` matched inside `subgroup:` and
    /// misclassified the gem's group.
    #[test]
    fn test_group_option_does_not_match_prefixed_key() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", subgroup: [:test]"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Default);
    }

    /// Same M1 regression for `REQUIRE_OPTION`: `autorequire:` must not be mistaken for
    /// `require:`.
    #[test]
    fn test_require_option_does_not_match_prefixed_key() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", autorequire: false"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, None);
    }

    /// Same M1 regression for `PLATFORMS_OPTION`: `force_ruby_platforms:` must not be mistaken
    /// for `platforms:`.
    #[test]
    fn test_platforms_option_does_not_match_prefixed_key() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails", force_ruby_platforms: :ruby"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert!(result.dependencies[0].platforms.is_empty());
    }

    /// Sanity check accompanying the M1 fix: the real `group:`/`require:`/`platforms:` keys
    /// (immediately preceded by a comma+space, a normal word boundary) must still match.
    #[test]
    fn test_real_keys_still_match_after_word_boundary_fix() {
        let gemfile = r#"source "https://rubygems.org"
gem "rspec", group: [:test], require: false, platforms: :ruby"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
        assert_eq!(result.dependencies[0].require, Some("false".into()));
        assert_eq!(result.dependencies[0].platforms, vec!["ruby"]);
    }

    /// Security regression (#991): a `gem` declaration split across lines, with the
    /// hash-rocket `:source =>` option on a continuation line rather than the `gem` line
    /// itself, was previously invisible to `SOURCE_OPTION` (matched against the same line as
    /// `GEM_PATTERN` only) — the continuation line matched none of this parser's line-level
    /// patterns and was silently dropped, so the gem fell through to `Registry` and leaked its
    /// name to rubygems.org.
    #[test]
    fn test_multiline_gem_hash_rocket_source_option_classified_as_custom_registry() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"internal-gem\",\n  :source => \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "internal-gem");
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Same #991 gap, modern `source:` syntax on the continuation line.
    #[test]
    fn test_multiline_gem_modern_source_option_classified_as_custom_registry() {
        let gemfile = r#"source "https://rubygems.org"
gem "internal-gem",
  source: "https://gems.corp""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Same #991 gap for `git:`, `path:`, and `github:` on a continuation line.
    #[test]
    fn test_multiline_gem_git_path_github_options_classified() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails",
  git: "https://github.com/rails/rails.git"
gem "local_gem",
  path: "../local_gem"
gem "sidekiq",
  github: "sidekiq/sidekiq""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        match &result.dependencies[0].source {
            DependencySource::Git { url, .. } => assert!(url.contains("rails/rails")),
            other => panic!("expected Git source, got {other:?}"),
        }
        match &result.dependencies[1].source {
            DependencySource::Path { path } => assert_eq!(path, "../local_gem"),
            other => panic!("expected Path source, got {other:?}"),
        }
        match &result.dependencies[2].source {
            DependencySource::Git { url, .. } => {
                assert!(url.contains("github.com/sidekiq/sidekiq"));
            }
            other => panic!("expected Git source, got {other:?}"),
        }
    }

    /// #991: a multi-line `gem` call must still resolve its version, group, platforms, and
    /// require options correctly when they are spread across several continuation lines, not
    /// just the source option.
    #[test]
    fn test_multiline_gem_all_options_spread_across_lines() {
        let gemfile = r#"source "https://rubygems.org"
gem "sidekiq",
  "~> 7.0",
  require: false,
  group: :production,
  platforms: [:ruby]"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "sidekiq");
        assert_eq!(dep.version_req, Some("~> 7.0".into()));
        assert_eq!(dep.require, Some("false".into()));
        assert_matches!(dep.group, DependencyGroup::Production);
        assert_eq!(dep.platforms, vec!["ruby"]);
    }

    /// #991: an explicit `git:`/`path:` option on a continuation line must still take
    /// precedence over an inline `source:` option elsewhere in the same multi-line call,
    /// mirroring `extract_source`'s documented precedence for the single-line case.
    #[test]
    fn test_multiline_gem_git_option_takes_precedence_over_source_option() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails",
  git: "https://github.com/rails/rails.git",
  source: "https://gems.corp""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    /// #991: a multi-line `gem` call declared inside a `source ... do` block must still be
    /// classified against the enclosing block's URL (not the file-level source) when it has no
    /// per-gem source option of its own.
    #[test]
    fn test_multiline_gem_inside_source_block_uses_block_source() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "internal-gem",
    require: false
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].require, Some("false".into()));
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// #991: a comment line interleaved inside a multi-line `gem` call must not prematurely
    /// close the call in front of the option it precedes.
    #[test]
    fn test_multiline_gem_with_interleaved_comment_still_associates_option() {
        let gemfile = r#"source "https://rubygems.org"
gem "internal-gem",
  # internal mirror, do not query rubygems.org
  source: "https://gems.corp""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// #991: a `gem` call with no trailing comma at all (the common case) must be completely
    /// unaffected by the multi-line tracking — sanity check against a false-positive
    /// continuation trigger.
    #[test]
    fn test_single_line_gem_without_trailing_comma_unaffected() {
        let gemfile = r"source 'https://rubygems.org'
gem 'rails'
gem 'rspec', group: :test";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert_matches!(result.dependencies[1].group, DependencyGroup::Test);
    }

    /// #991 edge case: the file ends while a `gem` call is still open (trailing comma, no
    /// further lines) — must resolve gracefully from whatever was accumulated rather than
    /// panicking or dropping the gem entirely.
    #[test]
    fn test_multiline_gem_unterminated_at_eof_still_resolves() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"internal-gem\",\n  :source => \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "internal-gem");
    }

    /// #1009: repeated open/close of `group`/`source` blocks — each pushed and popped many
    /// times in sequence (not nested) — must still classify every gem against the
    /// currently-open block, exercising the O(1) `group_stack`/`source_stack` push/pop path
    /// rather than a stale value surviving a pop.
    #[test]
    fn test_repeated_sequential_group_and_source_blocks_do_not_leak_state() {
        let gemfile = r#"source "https://rubygems.org"
group :development do
  gem "pry"
end
source "https://gems.corp" do
  gem "internal-gem"
end
group :test do
  gem "rspec"
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);

        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);

        assert_matches!(result.dependencies[1].group, DependencyGroup::Default);
        match &result.dependencies[1].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }

        assert_matches!(result.dependencies[2].group, DependencyGroup::Test);
        assert_eq!(result.dependencies[2].source, DependencySource::Registry);

        assert_matches!(result.dependencies[3].group, DependencyGroup::Default);
        assert_eq!(result.dependencies[3].source, DependencySource::Registry);
    }

    /// #1009: three levels of nested `source` blocks must each correctly reveal the
    /// next-innermost URL on pop — the `source_stack` must behave as a real stack, not just a
    /// single cached "current" value that would collapse this back to depth 1.
    #[test]
    fn test_triple_nested_source_blocks_unwind_correctly() {
        let gemfile = r#"source "https://rubygems.org"
source "https://outer.corp" do
  gem "outer-gem"
  source "https://middle.corp" do
    gem "middle-gem"
    source "https://inner.corp" do
      gem "inner-gem"
    end
    gem "middle-gem-2"
  end
  gem "outer-gem-2"
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 6);

        let expect_source = |dep: &BundlerDependency, expected: &str| match &dep.source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, expected),
            other => panic!("expected CustomRegistry({expected}), got {other:?}"),
        };

        expect_source(&result.dependencies[0], "https://outer.corp");
        expect_source(&result.dependencies[1], "https://middle.corp");
        expect_source(&result.dependencies[2], "https://inner.corp");
        expect_source(&result.dependencies[3], "https://middle.corp");
        expect_source(&result.dependencies[4], "https://outer.corp");
        assert_eq!(result.dependencies[5].source, DependencySource::Registry);
    }

    /// Regression (tester-found bug 1, post-#991/#1009 fix): a pending multi-line `gem` call
    /// closed by a `BLOCK_END` line must not swallow that `end` as one of its own segments —
    /// doing so skipped the `group_stack` pop, leaking the enclosing `group :test` into every
    /// later gem in the file instead of just the ones actually inside the block.
    #[test]
    fn test_pending_gem_closed_by_block_end_still_pops_group_stack() {
        let gemfile = r#"source "https://rubygems.org"
group :test do
  gem "rspec",
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
        assert_matches!(result.dependencies[1].group, DependencyGroup::Default);
    }

    /// Same bug 1 trap for `source ... do` blocks: swallowing the closing `end` into a pending
    /// gem's segments must not leak the block's source into gems declared after it.
    #[test]
    fn test_pending_gem_closed_by_block_end_still_pops_source_stack() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "internal-gem",
end
gem "rails""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// Regression (tester-found bug 2): a pending multi-line `gem` call closed by another real
    /// `gem` declaration (rather than an option line) must not swallow that next `gem` line —
    /// both gems must appear in the result.
    #[test]
    fn test_pending_gem_closed_by_next_gem_declaration_does_not_drop_it() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"leaky-gem\",\ngem \"other-gem\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "leaky-gem");
        assert_eq!(result.dependencies[1].name, "other-gem");
    }

    /// Same bug 2 trap, chained: a second multi-line `gem` call immediately follows the first
    /// (no blank line between), and the second one's own continuation option must still
    /// resolve correctly after the reprocessing fallthrough.
    #[test]
    fn test_chained_multiline_gem_declarations_both_resolve_correctly() {
        let gemfile = r#"source "https://rubygems.org"
gem "leaky-gem",
gem "other-gem",
  source: "https://gems.corp""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "leaky-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert_eq!(result.dependencies[1].name, "other-gem");
        match &result.dependencies[1].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Confirms `starts_new_top_level_construct` also covers impl-critic's independent S1
    /// repro: a pending gem closed by a `source ... do` block-opener line must not swallow
    /// that opener — the block must actually open, so gems declared inside it are classified
    /// against its URL rather than the public registry.
    #[test]
    fn test_pending_gem_closed_by_source_block_start_still_opens_block() {
        let gemfile = r#"gem "a",
source "https://gems.corp" do
  gem "private_one"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "a");
        assert_eq!(result.dependencies[1].name, "private_one");
        match &result.dependencies[1].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Confirms impl-critic's second independent S1 repro: a pending gem closed by `end`
    /// inside a `group` block must still pop `group_stack`, so multiple gems declared after
    /// the block (not just the very next one) all correctly fall back to the default group.
    #[test]
    fn test_pending_gem_closed_by_block_end_does_not_leak_group_to_multiple_following_gems() {
        let gemfile = r#"group :development do
  gem "pry",
end
gem "rails"
gem "puma""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_matches!(result.dependencies[0].group, DependencyGroup::Development);
        assert_matches!(result.dependencies[1].group, DependencyGroup::Default);
        assert_matches!(result.dependencies[2].group, DependencyGroup::Default);
    }

    /// Security regression (impl-critic S2): Ruby string interpolation (`#{...}`) inside a
    /// double-quoted option value on a continuation line must not be mistaken for a comment —
    /// the naive (non-quote-aware) comment strip truncated the line right at `#{`, dropping
    /// its trailing comma and closing the pending multi-line `gem` call one line early, so the
    /// `source:` option on the next line was never associated with it and the gem leaked to
    /// the public registry.
    #[test]
    fn test_multiline_gem_string_interpolation_not_mistaken_for_comment() {
        let gemfile = r#"source "https://rubygems.org"
gem "sidekiq-pro",
    require: "sidekiq/pro#{SUFFIX}",
    source: "https://gems.contribsys.com/""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].require,
            Some("sidekiq/pro#{SUFFIX}".into())
        );
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.contribsys.com/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (impl-critic M1): `PendingGem` accumulation must be bounded, so a `gem
    /// "x",` declaration followed by an unbounded run of blank continuation lines cannot grow
    /// the accumulator without limit. A real option placed well past the cap is treated as
    /// belonging to a different, already-closed call (silently unassociated, like any other
    /// unrecognized line) rather than the parser accumulating indefinitely — and parsing must
    /// still recover correctly for whatever follows.
    #[test]
    fn test_pending_gem_accumulation_is_bounded() {
        let mut gemfile = String::from("source \"https://rubygems.org\"\ngem \"x\",\n");
        for _ in 0..500 {
            gemfile.push('\n');
        }
        gemfile.push_str("  source: \"https://gems.corp\"\n");
        gemfile.push_str("gem \"rails\"");

        let result = parse_gemfile(&gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "x");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert_eq!(result.dependencies[1].name, "rails");
        assert_eq!(result.dependencies[1].source, DependencySource::Registry);
    }

    /// Security regression (impl-critic S3): a `gem` call continued via an explicit trailing
    /// backslash — valid Ruby line continuation, distinct from an open (comma-terminated)
    /// argument list — must still associate the option on the next line with the gem, not leak
    /// it to the public registry.
    #[test]
    fn test_backslash_continuation_still_associates_source_option() {
        let gemfile =
            "source \"https://rubygems.org\"\ngem \"foo\", \\\n    source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (impl-critic S5): a commented-out option on a continuation line
    /// (`# source: "..."`) must not be mistaken for an active one — `finalize_pending_gem`
    /// must comment-strip every segment before option extraction, so the gem still resolves
    /// against the enclosing `source ... do` block's URL rather than the commented-out value.
    #[test]
    fn test_commented_out_option_on_continuation_line_is_ignored() {
        let gemfile = r#"source "https://gems.corp" do
  gem "private",
      # source: "https://rubygems.org"
      require: false
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].require, Some("false".into()));
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "https://gems.corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Same S5 gap on the single-line fast path: a trailing comment mentioning an option-like
    /// string must not be mistaken for an active option on an ordinary (non-continuation)
    /// `gem` line either.
    #[test]
    fn test_commented_out_option_on_single_line_gem_is_ignored() {
        let gemfile = r#"source "https://rubygems.org"
gem "rails" # git: "https://example.com/evil.git""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (code-review finding, bug 1): a keyword option's quoted value on an earlier
    /// continuation line (e.g. `require: "5.x_bridge"`, which happens to start with a digit)
    /// must not be mistaken for the positional version constraint on a later line —
    /// `extract_version` must stop scanning once it enters keyword-argument territory rather
    /// than returning the first `VERSION_PATTERN` match found anywhere in the accumulated
    /// segments.
    #[test]
    fn test_keyword_option_value_not_mistaken_for_version() {
        let gemfile = r#"source "https://rubygems.org"
gem "foo",
  require: "5.x_bridge",
  "~> 1.0""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].require, Some("5.x_bridge".into()));
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Same bug 1 gap on the single-line fast path, which shares `extract_version` with the
    /// multi-line path.
    #[test]
    fn test_keyword_option_value_not_mistaken_for_version_single_line() {
        let gemfile = r#"source "https://rubygems.org"
gem "sidekiq", require: false, group: :production"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, None);
        assert_eq!(result.dependencies[0].require, Some("false".into()));
        assert_matches!(result.dependencies[0].group, DependencyGroup::Production);
    }

    /// A version constraint positioned before any keyword option, spread across its own
    /// continuation line, must still be found — sanity check that bug 1's fix (stop at the
    /// first keyword-bearing segment) does not also break the legitimate ordering.
    #[test]
    fn test_version_before_keyword_options_on_own_continuation_line_still_found() {
        let gemfile = r#"source "https://rubygems.org"
gem "sidekiq",
  "~> 7.0",
  require: "5.x_bridge""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
        assert_eq!(result.dependencies[0].require, Some("5.x_bridge".into()));
    }

    /// Regression (code-review finding, bug 2): a bare backslash outside any quoted string has
    /// no escaping meaning in Ruby, so it must not swallow the `#` that starts a real trailing
    /// comment — `strip_trailing_comment`'s escape tracking must only apply while inside a
    /// single- or double-quoted string.
    #[test]
    fn test_strip_trailing_comment_bare_backslash_does_not_escape_hash() {
        let line = "require: foo \\# real comment";
        assert_eq!(strip_trailing_comment(line), "require: foo \\");
    }

    /// Sanity check accompanying bug 2's fix: a backslash-escaped quote *inside* a quoted
    /// string must still be treated as an escape (not close the string early), so a `#` that
    /// follows immediately inside the still-open string is correctly not mistaken for a
    /// comment start.
    #[test]
    fn test_strip_trailing_comment_escaped_quote_inside_string_still_tracked() {
        let line = r#"source: "a\"b#c""#;
        assert_eq!(strip_trailing_comment(line), line);
    }
}
