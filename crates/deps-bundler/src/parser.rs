//! Gemfile DSL parser with position tracking.
//!
//! Parses Gemfile files using regex-based line parsing to extract dependencies
//! with precise LSP positions.

use crate::types::{BundlerDependency, DependencyGroup, DependencySource};
use deps_core::Result;
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use regex::Regex;
use std::collections::HashSet;
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
// Accepts either the bare `gem "name"` form or a parenthesized `gem("name")` / `gem ("name")`
// call (#1021) — before this fix, `\s+` between `gem` and the opening quote was mandatory, so a
// parenthesized call (top-level or nested inside any block) never matched at all and silently
// produced no dependency, no diagnostic, no hover, and no completion.
#[allow(clippy::expect_used)]
static GEM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*gem(?:\s+|\s*\(\s*)['"]([^'"]+)['"]"#).expect("Invalid regex")
});

/// Matches a gem's version-constraint string, e.g. `gem "rails", "~> 7.0"`. Tolerant of a
/// trailing comment after the closing quote (`"~> 7.0" # pinned for Rails 7 compat`, #988) —
/// mirroring the comment-tolerance already added to the block-tracking regexes in #986.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static VERSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([~>=<!\d][^'"]*)['"]\s*(?:,|(?:#.*)?$)"#).expect("Invalid regex")
});

/// Same as [`VERSION_PATTERN`] but also accepts a closing `)` as a terminator, for a
/// parenthesized `gem("rails", "~> 7.0")` call (#1021). Deliberately a *separate* pattern rather
/// than folding `)` into `VERSION_PATTERN` itself (critic finding S3): a bare, non-parenthesized
/// `gem "x" if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.1")` line also ends in a
/// `)` — from the `if`-modifier's condition, not the gem call — so accepting `)` unconditionally
/// let an unrelated quoted string inside that condition be misread as the gem's version. Callers
/// use this pattern only once they know the call itself opened with `(` (see `is_paren_call` in
/// [`parse_gemfile`]/[`PendingGem`]).
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static VERSION_PATTERN_PAREN_TERMINATED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([~>=<!\d][^'"]*)['"]\s*(?:,|\)|(?:#.*)?$)"#).expect("Invalid regex")
});

/// Matches a statement-modifier `if`/`unless` keyword (`gem "x" if COND`, `gem "x" unless
/// COND`). [`extract_version`] stops its positional-version search before this keyword, so a
/// quoted string inside the modifier's condition (e.g. `Gem::Version.new("3.1")`) is never
/// mistaken for the gem's own version constraint (critic finding S3 for #1021) — otherwise a
/// version-shaped literal in the condition either gets reported as a phantom version constraint
/// on a gem that declares none, or shadows a real version constraint earlier in the same call.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static STATEMENT_MODIFIER_KEYWORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:if|unless)\b").expect("Invalid regex"));

/// Matches the opening of a nested method call, e.g. `legacy_check(` — an identifier immediately
/// followed by (optional whitespace then) `(`. [`extract_version`] stops its positional-version
/// search before such a call the same way it stops before [`ANY_OPTION_KEY`]/
/// [`STATEMENT_MODIFIER_KEYWORD`] (correctness-gate finding F5): without this, a version-shaped
/// quoted string that is actually an *argument to a nested call*, not the gem's own version, gets
/// misread as the gem's version constraint whenever [`VERSION_PATTERN_PAREN_TERMINATED`]'s `)`
/// terminator happens to line up with the nested call's own closing paren — e.g.
/// `gem("rails", legacy_check("~> 1.0"), platforms: [:mri])`, where truncating only at
/// `platforms:` leaves `legacy_check("~> 1.0")` in the search area and `"~> 1.0"` followed by
/// `legacy_check`'s own `)` satisfies the pattern. Checked via [`first_code_match`] like the
/// other two boundary keywords, so a call-shaped substring *inside* an already-quoted value
/// (part of the real version string's own content) is never mistaken for one.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static NESTED_CALL_OPEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[[:alpha:]_][[:alnum:]_]*[!?]?\s*\(").expect("Invalid regex"));

/// Matches a colon directly followed (only whitespace between) by a closing `]`/`}`/`)` — a
/// dangling, empty value position such as `a: ]` or `a: }`. Used by [`bracket_depths`] (critic
/// finding, 8th vector round 2) to force-poison a closer even when it type-matches the innermost
/// open bracket: a well-formed Gemfile never has a hash/array value that's simply empty like
/// this, so it's treated as broken/mid-edit content, same as a genuinely mismatched closer.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static DANGLING_VALUE_BEFORE_CLOSER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r":\s*([\]}\)])").expect("Invalid regex"));

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*source\s+['"]([^'"]+)['"]\s*$"#).expect("Invalid regex"));

/// Matches the `source\s+` keyword prefix of a `source "..." do` block opener — the fixed part
/// [`parse_source_block_start`] anchors on before hand-scanning the URL literal itself.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_BLOCK_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*source\s+").expect("Invalid regex"));

/// Matches what must follow a `source "..." do` block opener's URL literal: whitespace, `do`,
/// and an optional trailing comment. Tolerates the comment (`... do # internal mirror`) — critic
/// finding S2: without this, the block never opens and every gem inside it silently resolves
/// against the file-level source.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_BLOCK_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+do\s*(#.*)?$").expect("Invalid regex"));

/// Matches a `source "..." do` block opener, e.g. `source "https://gems.corp" do`, returning the
/// URL literal's content.
///
/// Quote-aware (#1019): the `regex` crate has no backreferences, so a single regex capture group
/// like `['"]([^'"]+)['"]` stops at the *first* quote character it meets — which fails on a URL
/// literal containing Ruby string interpolation with a different quote type nested inside, e.g.
/// `source "https://#{ENV['CREDS']}@gems.contribsys.com/" do`. Reads the literal via the shared,
/// interpolation-aware [`deps_core::quote_scan::read_string_literal`] (#1041: this used to be a
/// hand-rolled scanner local to this function, duplicating the same interpolation-depth and
/// nested-quote tracking [`option_string_value`] independently needed for inline option values —
/// now a single implementation in `deps-core` backs both call sites).
// `prefix_end` is a regex match end, always a char boundary; `literal.content`/`literal.end`
// come from `read_string_literal`, likewise always char-boundary bounds.
#[allow(clippy::string_slice)]
fn parse_source_block_start(line: &str) -> Option<&str> {
    let prefix_end = SOURCE_BLOCK_PREFIX.find(line)?.end();
    let rest = &line[prefix_end..];
    let first = rest.chars().next()?;
    if first != '\'' && first != '"' {
        return None;
    }
    let literal = deps_core::quote_scan::read_string_literal(
        rest,
        0,
        deps_core::quote_scan::ScanSyntax::Ruby,
    )?;
    // Reject an empty URL (`source "" do`) — correctness-gate finding F6: `read_string_literal`
    // itself accepts a zero-length literal (`""`/`''`), but the regex this hand-scan replaced
    // (`['"]([^'"]+)['"]`, one-or-more) never did, so an empty source URL used to fall through
    // this check entirely and stay untracked. Matching that pre-existing behavior here keeps a
    // classification regression out of scope: a `CustomRegistry("")` block is not a plausible
    // real Gemfile shape this fix should newly start accepting.
    if literal.content.is_empty() {
        return None;
    }
    if SOURCE_BLOCK_SUFFIX.is_match(&rest[literal.end..]) {
        Some(&rest[literal.content])
    } else {
        None
    }
}

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

/// Matches the per-gem inline `source:` option's *key* alone, e.g. `source:` or
/// `:source =>` — its string value is read separately by [`option_string_value`], which
/// scans past the key for a string literal rather than a fixed-width value regex (#1020:
/// a value regex built on `['"][^'"]+['"]` truncates at the first embedded quote of the
/// *other* kind, e.g. an unescaped `'` inside a `"`-delimited value).
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_key_pattern("source")).expect("Invalid regex"));

/// Matches any recognized per-gem inline option's *key* alone (`source:`/`:source =>`,
/// `group:`/`:group =>`, `git:`/`:git =>`, `path:`/`:path =>`, `github:`/`:github =>`,
/// `require:`/`:require =>`, `platforms:`/`:platforms =>`, `install_if:`/`:install_if =>`) —
/// used by `extract_version` to find where a `gem` call's keyword-argument territory begins, so
/// a quoted option value (e.g. `require: "5.x_bridge"`) is never mistaken for a positional
/// version constraint (code-review finding). `install_if` was added per critic finding S3
/// (#1021): its value is commonly a lambda (`install_if: -> { ... }`) that can itself contain a
/// version-shaped quoted string, which must not be scanned as this gem's version either.
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
        "install_if",
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
// SOURCE_BLOCK_SUFFIX (`parse_source_block_start`).
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

/// Matches the per-gem inline `git:` option's *key* alone. See [`SOURCE_OPTION`] for why
/// the value is not part of this pattern.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GIT_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_key_pattern("git")).expect("Invalid regex"));

/// Matches the per-gem inline `path:` option's *key* alone. See [`SOURCE_OPTION`] for why
/// the value is not part of this pattern.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static PATH_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_key_pattern("path")).expect("Invalid regex"));

/// Matches the per-gem inline `github:` option's *key* alone. See [`SOURCE_OPTION`] for
/// why the value is not part of this pattern.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GITHUB_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_key_pattern("github")).expect("Invalid regex"));

/// Matches the per-gem inline `require:` option's *key* alone, e.g. `require:` or
/// `:require =>`. Unlike [`SOURCE_OPTION`]/[`GIT_OPTION`]/[`PATH_OPTION`]/[`GITHUB_OPTION`],
/// `require`'s value is not always a string (`require: false` is valid), so
/// [`extract_require`] parses its value directly rather than through
/// [`option_string_value`].
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static REQUIRE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_key_pattern("require")).expect("Invalid regex"));

/// Matches the per-gem inline `platforms:` option, e.g. `gem "x", platforms: :ruby` or the
/// hash-rocket form `gem "x", :platforms => :ruby`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static PLATFORMS_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&option_pattern("platforms", r"(\[.+?\]|:\w+)")).expect("Invalid regex")
});

/// Returns the first match of `re` on `line` that sits in code — outside every string
/// literal and comment (per [`deps_core::quote_scan::CodeSpans`]) — rather than simply the
/// first match `re` finds.
///
/// A decoy match (an option-key-shaped substring sitting inside an already-open quoted
/// value, e.g. `git:` inside `path: 'vendor/git: "cache"'`) is skipped in favor of the
/// next candidate instead of rejecting the line outright — S1: the old idiom
/// (`re.captures(line)`, taking whichever match `regex` finds first, decoy or not) could
/// match the decoy and never see the real option further down the same line.
///
/// Builds one [`deps_core::quote_scan::CodeSpans`] for `line` and checks every `find_iter`
/// candidate against it, rather than reclassifying all of `line` per candidate — #1022
/// impl-critic C1: the latter made a single lookup O(candidates × line length), quadratic
/// once the `*_OPTION` regexes went key-only (a decoy key can now match anywhere on the
/// line, not just right before a quote) against an adversarial line packed with decoys.
///
/// Used by [`extract_version`] to locate `ANY_OPTION_KEY`/`STATEMENT_MODIFIER_KEYWORD` on a
/// single, not-yet-joined physical line (each with its own LSP-range-bearing offset, #991) —
/// the per-`gem`-call option lookups instead go through [`OptionScan`], which additionally
/// gates on bracket depth 0 over the whole joined call text (#1039).
fn first_code_match<'a>(line: &'a str, re: &Regex) -> Option<regex::Match<'a>> {
    let code = deps_core::quote_scan::CodeSpans::new(line, deps_core::quote_scan::ScanSyntax::Ruby);
    re.find_iter(line).find(|m| code.is_code_byte(m.start()))
}

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
    /// Stack of currently-unclosed `[`/`{`/`(` characters across every accumulated segment, each
    /// popped by a later `]`/`}` (see [`apply_bracket_delta`]) — a non-empty stack means an
    /// array/hash literal (e.g. `platforms: [`) opened on an earlier line is still unclosed,
    /// which keeps the call open even without a trailing comma or backslash (#1017). A stack
    /// (rather than a signed depth counter) structurally rules out the negative-depth bug a
    /// counter had (critic finding M1: an unmatched closing bracket earlier in the call could
    /// drive a counter negative and then mask a later, legitimate literal opening) — popping an
    /// empty stack is simply a no-op — and lets [`bracket_only_should_stop`] tell an array (`[`)
    /// context apart from a hash (`{`) context via the top element (critic finding, correctness
    /// gate re-check: an anchored option-key-shaped line like `source: "..."` is plausible hash
    /// content but not array element content, so whether to trust it depends on bracket *kind*,
    /// not just depth).
    bracket_stack: Vec<char>,
    /// Whether the call opened with `gem(...)` rather than the bare `gem ...` form — threaded
    /// through to [`extract_version`] so its `)`-as-terminator tolerance (#1021) only applies
    /// when there's an actual enclosing `gem(...)` paren to terminate against, not any unrelated
    /// trailing `)` on the line (critic finding S3).
    is_paren_call: bool,
}

/// Hard cap on how many physical lines a single [`PendingGem`] may accumulate before being
/// force-closed. `budget.allow()` counts resolved dependencies, not raw continuation lines, and
/// the continuation branch runs ahead of it every iteration — without a cap, a single
/// `gem "x",` followed by an unbounded run of blank/comment-only continuation lines would grow
/// `segments` without limit before the budget ever gets a chance to matter (impl-critic M1).
/// Generous enough for any real Gemfile's multi-line `gem` call (which rarely exceeds a
/// handful of option lines).
const MAX_PENDING_GEM_SEGMENTS: usize = 256;

/// Hard cap on segments while a [`PendingGem`]'s bracket depth is positive — deliberately far
/// below [`MAX_PENDING_GEM_SEGMENTS`] (critic finding S2 for #1017): an unclosed `[`/`{` is a
/// routine transient state while editing (the LSP's normal operating condition, not a corner
/// case), so a call relying solely on bracket depth to stay open — no trailing comma or
/// backslash signal — must not be allowed to run nearly as long as one with an explicit
/// continuation signal, or it silently absorbs later, unrelated statements. Generous enough for
/// any real multi-line array/hash literal (which rarely exceeds a handful of elements).
const MAX_BRACKET_ONLY_CONTINUATION_SEGMENTS: usize = 20;

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
///
/// Thin wrapper over the shared [`deps_core::quote_scan::strip_line_comment`] (#1022) — kept
/// as its own named function so this doc comment, which explains why *this call site* needs
/// quote-aware stripping, stays attached to it.
fn strip_trailing_comment(line: &str) -> &str {
    deps_core::quote_scan::strip_line_comment(line, deps_core::quote_scan::ScanSyntax::Ruby)
}

/// Applies the `[`/`{`/`(`/`]`/`}`/`)` characters `line` contributes to `stack`, quote-aware
/// (ignoring bracket characters inside a string literal or comment) via the shared
/// [`deps_core::quote_scan::CodeSpans`] (#1022/#1036: the hand-rolled quote/escape state
/// machine this used before duplicated the same rules `strip_trailing_comment` now delegates to
/// `deps_core::quote_scan` for) — pushing each opener, popping on each closer (a closer on an
/// empty stack is a no-op) — so a `platforms: [` (or any other array/hash/paren-call) opened on
/// one line keeps a [`PendingGem`] open across every line until the literal actually closes, even
/// when a line doesn't end in a trailing comma or backslash (#1017). Tracking `(`/`)` (correctness
/// gate finding F1) matters for the same reason: an option value that itself opens a method call
/// spanning lines, e.g. `install_if: SomeCheck(\n  ENV["X"]\n), source: "..."`, has no trailing
/// comma or backslash on its first line either — without paren-tracking the call closed one line
/// too early and the trailing `source:` on the third line was silently dropped, leaking to the
/// public registry (the same #1019 leak class). This must stay in sync with [`bracket_depths`],
/// the extraction sink, which already tracks `(`/`)` on the joined text — before this fix the two
/// disagreed on when a call was "still open". A stack instead of a signed counter means an
/// unmatched closer can never leave a negative balance (critic finding M1) and lets callers
/// recover the *kind* of the innermost still-open literal via `stack.last()`, not just whether one
/// is open (needed by [`bracket_only_should_stop`]). Callers pass an already comment-stripped line
/// (via [`strip_trailing_comment`]) so a bracket inside a trailing comment is never counted —
/// though `CodeSpans` would also exclude one on its own.
///
/// **Why relaxing the `(`-kind absorption guard is still safe against the S2 leak class**
/// (correctness-gate finding F1, verified by adversarial review): this function pops `stack` on
/// *any* closer, while [`bracket_depths`] pops its own depth counter only on a closer whose type
/// matches the innermost open bracket — a mismatched or excess closer instead poisons every later
/// position in [`bracket_depths`] to a sentinel that can never compare equal to 0 (see that
/// function's doc). Popping unconditionally can only make this stack's length shrink faster than,
/// never slower than, `bracket_depths`' own depth, so this stack's length is always ≤
/// `bracket_depths`' computed depth at every position in the joined text. Consequently, whenever
/// [`bracket_only_should_stop`] sees this stack non-empty (an open `(`, which it never content-gates
/// for that kind) and lets a line be absorbed, `bracket_depths` at that same position is guaranteed
/// to be either poisoned or strictly greater than 0 — so [`OptionScan`]'s depth-0 match gate still
/// rejects any `source:`/`git:`/`path:`/`group:` text absorbed while a `(` continuation is open,
/// regardless of the shape check `(`-kind continuations skip.
fn apply_bracket_delta(line: &str, stack: &mut Vec<char>) {
    let code = deps_core::quote_scan::CodeSpans::new(line, deps_core::quote_scan::ScanSyntax::Ruby);
    for (idx, ch) in line.char_indices() {
        if !code.is_code_byte(idx) {
            continue;
        }
        match ch {
            '[' | '{' | '(' => stack.push(ch),
            ']' | '}' | ')' => {
                stack.pop();
            }
            _ => {}
        }
    }
}

/// True when a comment-stripped, trimmed, non-empty line looks like array/hash literal element
/// content for the innermost currently-open bracket `current_kind` (`Some('[')`/`Some('{')`) — a
/// bare symbol (`:mri`), a quoted string, a closing `]`/`}`, or a leading `,` (all valid inside
/// either kind), or, *only* while `current_kind` is `Some('{')`, a recognized per-gem option key
/// anchored at the start of the line ([`ANY_OPTION_KEY`], e.g. `source: "..."` — plausible
/// content for a hash literal like `gem "x", { source: "..." }`, but never for an array element:
/// `[source: "..."]` isn't valid Ruby array content). Used only to decide whether such a line may
/// be absorbed into a still bracket-open [`PendingGem`] (see [`bracket_only_should_stop`]).
///
/// Not called at all when `current_kind` is `Some('(')` — see [`bracket_only_should_stop`], which
/// skips this content-shape check entirely for a paren-open continuation, since a method call's
/// argument list can contain arbitrary Ruby expressions with no fixed shape to allowlist.
///
/// Gating the option-key branch on bracket kind matters (correctness-gate re-check after critic
/// findings S2/S2b): an anchored option-key match alone is indistinguishable from a genuinely new
/// top-level declaration when the open bracket is `[` — `gem "x", platforms: [` followed by a
/// bare `source: "https://evil.example.com"` line must NOT adopt that `source:` merely because it
/// is anchored-option-key-shaped, since array element content can never look like that. Also
/// anchoring the check at position 0 (critic finding S2b): `ANY_OPTION_KEY` also matches `git:`
/// *inside* `Bundler.require(git: "...")` as a substring, so an unanchored check would still let
/// that unrelated statement through.
fn looks_like_option_or_array_content(stripped: &str, current_kind: Option<char>) -> bool {
    let array_element_shaped = stripped.starts_with(':')
        || stripped.starts_with('\'')
        || stripped.starts_with('"')
        || stripped.starts_with(']')
        || stripped.starts_with('}')
        || stripped.starts_with(',');
    array_element_shaped
        || (current_kind == Some('{')
            && ANY_OPTION_KEY
                .find(stripped)
                .is_some_and(|m| m.start() == 0))
}

/// True when `line` must not be absorbed into a [`PendingGem`] that is currently open *only*
/// because of an unclosed bracket/brace literal (no trailing comma or backslash signal) —
/// because it doesn't look like array/hash literal element content for `current_kind`, the
/// innermost currently-open bracket (critic findings S2/S2b/correctness-gate re-check for
/// #1017). Allowlisting the shapes Ruby's array/hash grammar actually produces for the bracket
/// kind actually open, rather than blocklisting unrelated-statement shapes or allowlisting by
/// shape alone, is the conservative direction: a blocklist is open-ended and was still
/// bypassable (e.g. `x = { source: "..." }` isn't `identifier(`-shaped but still leaks a fake
/// `source:`), and a kind-blind allowlist let an anchored `source:`/`git:`-shaped line through
/// even while the open bracket was an array (`[`), where such a line can never be legitimate
/// content.
///
/// A blank/comment-only line is deliberately *not* a boundary on its own (critic finding S2a):
/// it carries no statement content, so it can't be the unrelated line this guard exists to
/// catch, and [`MAX_BRACKET_ONLY_CONTINUATION_SEGMENTS`] already bounds a run of them — this
/// also keeps parity with the comma-continued path, which already tolerates blank lines between
/// continuation options.
///
/// When `current_kind` is `Some('(')` this always returns `false` — never a boundary
/// (correctness-gate finding F1): the array/hash allowlist in
/// [`looks_like_option_or_array_content`] doesn't apply to a method call's argument list, which
/// can contain arbitrary Ruby expressions (`install_if: SomeCheck(\n  ENV["X"]\n), source:
/// "..."` — `ENV["X"]` is legitimate paren-call content but isn't array/hash-element-shaped).
/// Trusting the depth signal alone here matches the comma-continuation path, which never
/// validates content shape either; [`MAX_BRACKET_ONLY_CONTINUATION_SEGMENTS`] still bounds how
/// long an unclosed `(` can keep absorbing lines.
fn bracket_only_should_stop(line: &str, current_kind: Option<char>) -> bool {
    if current_kind == Some('(') {
        return false;
    }
    let stripped = strip_trailing_comment(line).trim();
    !stripped.is_empty() && !looks_like_option_or_array_content(stripped, current_kind)
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
    parse_source_block_start(line).is_some()
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
    let (version_req, version_range) = extract_version(
        &stripped_segments,
        content,
        line_table,
        pending.is_paren_call,
    );
    let lines: Vec<&str> = stripped_segments.iter().map(|(text, _)| *text).collect();
    let joined = joined_lines(&lines);
    let scan = OptionScan::new(&joined);
    let group =
        extract_group(&scan).unwrap_or_else(|| block_group.unwrap_or(DependencyGroup::Default));
    let source = extract_source(&scan, gemfile_source_url, block_source_url);
    let platforms = extract_platforms(&scan);
    let require = extract_require(&scan);

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
            // #1017 follow-up (critic findings S2/S2b): while an array/hash literal opened by
            // this call is still unclosed, a line that doesn't look like content for the
            // innermost open bracket's *kind* must not be silently absorbed either — an unclosed
            // bracket is a routine transient mid-edit state, not license to swallow everything up
            // to the next recognized top-level construct or the segment cap.
            let bracket_only_boundary = !pending.bracket_stack.is_empty()
                && bracket_only_should_stop(line, pending.bracket_stack.last().copied());
            if starts_new_top_level_construct(line) || bracket_only_boundary {
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
                apply_bracket_delta(strip_trailing_comment(line), &mut pending.bracket_stack);
                pending.segments.push((line, line_start));
                // A call relying solely on bracket depth to stay open (no trailing comma or
                // backslash signal) is capped far below the general limit (critic finding S2).
                let segment_cap = if pending.bracket_stack.is_empty() {
                    MAX_PENDING_GEM_SEGMENTS
                } else {
                    MAX_BRACKET_ONLY_CONTINUATION_SEGMENTS
                };
                let still_open = (continues_gem_declaration(line)
                    || !pending.bracket_stack.is_empty())
                    && pending.segments.len() < segment_cap;
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
        if let Some(url) = parse_source_block_start(line) {
            source_stack.push(url.to_string());
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

            // Whether the call opened with `gem(...)` rather than bare `gem ...` — checked only
            // against the *prefix* before the captured name (between the match start and
            // `name_match.start()`), not the whole match (correctness-gate re-check, finding #2):
            // using the whole match wrongly flipped this to `true` whenever the gem name itself
            // contained a literal `(`, e.g. `gem "weird(name)"`. Gates `extract_version`'s
            // `)`-as-terminator tolerance (critic finding S3 for #1021).
            let match_start = caps.get(0).unwrap().start();
            let is_paren_call = line[match_start..name_match.start()].contains('(');

            // Comment-stripped (impl-critic S5) before option extraction, so a trailing
            // comment mentioning an option-like string is never mistaken for an active one.
            let stripped_rest = strip_trailing_comment(rest_of_line);

            // A `gem` call whose argument list is still open — either a trailing comma before an
            // option on its own line (#991), or an array/hash literal opened but not yet closed
            // on this line, e.g. `gem "x", platforms: [` (#1017) — accumulate rather than
            // resolve now.
            let mut opening_bracket_stack: Vec<char> = Vec::new();
            apply_bracket_delta(stripped_rest, &mut opening_bracket_stack);
            if ends_with_trailing_comma(rest_of_line) || !opening_bracket_stack.is_empty() {
                pending_gem = Some(PendingGem {
                    name,
                    name_range,
                    segments: vec![(rest_of_line, rest_offset)],
                    bracket_stack: opening_bracket_stack,
                    is_paren_call,
                });
                continue;
            }

            // Extract version if present
            let (version_req, version_range) = extract_version(
                &[(stripped_rest, rest_offset)],
                content,
                &line_table,
                is_paren_call,
            );

            // Extract group from inline option or current block
            let scan = OptionScan::new(stripped_rest);
            let group = extract_group(&scan)
                .unwrap_or_else(|| current_group(&group_stack).unwrap_or(DependencyGroup::Default));

            // Extract source
            let source = extract_source(
                &scan,
                source_url.as_deref(),
                current_source_block(&source_stack),
            );

            // Extract platforms
            let platforms = extract_platforms(&scan);

            // Extract require option
            let require = extract_require(&scan);

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
/// to the start of its first recognized, code-positioned option key ([`ANY_OPTION_KEY`] via
/// [`first_code_match`] — M4: a decoy key sitting inside an earlier quoted positional value
/// must not truncate the search area before the real option territory begins), if any, and
/// once a segment contains one, scanning stops there entirely (every later segment is
/// necessarily inside keyword-argument territory too). Without this, `VERSION_PATTERN` — which
/// matches any quoted string starting with a version-ish character — could match an unrelated
/// option's value on a later line (e.g. `require: "5.x_bridge"`) and misreport it as the
/// version constraint, while the real one further down was never reached (code-review finding).
///
/// Each segment's search area is also truncated at a trailing `if`/`unless` statement-modifier
/// keyword ([`STATEMENT_MODIFIER_KEYWORD`], critic finding S3 for #1021): a quoted,
/// version-shaped string in the modifier's condition (e.g. `Gem::Version.new("3.1")`) must never
/// be mistaken for the gem's own version constraint.
///
/// `allow_paren_terminator` selects [`VERSION_PATTERN_PAREN_TERMINATED`] over the base
/// [`VERSION_PATTERN`] — pass `true` only when the `gem` call itself opened with `(` (see
/// `is_paren_call`), since a `)` terminator is otherwise ambiguous with an unrelated nested call
/// later on the same line (critic finding S3).
///
/// Each segment's search area is additionally truncated at the first [`NESTED_CALL_OPEN`] match
/// (correctness-gate finding F5): `VERSION_PATTERN_PAREN_TERMINATED`'s `)` terminator is
/// otherwise ambiguous not just with the gem call's own closing paren (critic finding S3, handled
/// above) but with *any* nested call's closing paren too — e.g. `gem("rails",
/// legacy_check("~> 1.0"), platforms: [:mri])`, where `"~> 1.0"` followed by `legacy_check`'s own
/// `)` would otherwise satisfy the pattern despite belonging to that unrelated nested call, not
/// to the gem itself.
///
/// **Known limitation (correctness-gate M2, documented rather than fixed — low severity, only
/// reachable during a transient mid-edit state):** unlike `extract_group`/`extract_source`/
/// `extract_platforms`/`extract_require`, this function has no [`bracket_depths`] gating, since it
/// runs per raw physical segment rather than over `finalize_pending_gem`'s joined text. A line
/// absorbed into a still-open [`PendingGem`] purely because of an unclosed `(` (see
/// [`bracket_only_should_stop`]'s F1 relaxation) can therefore still supply a phantom version —
/// e.g. `gem "sidekiq-pro", tags: Check(` followed by `RAILS = "7.0.4"` yields
/// `version_req: Some("7.0.4")`. The blast radius is a wrong outdated/unsatisfiable diagnostic
/// while the file sits in that transient unclosed-paren state, not a source misclassification (the
/// leak class this module exists to close): `extract_source` and friends stay correctly gated via
/// `OptionScan`'s depth-0 check regardless. A `{`-kind absorption doesn't share this exposure,
/// since [`bracket_only_should_stop`] still content-gates it.
///
/// **Known limitation (correctness-gate M3, documented rather than fixed — safe direction, false
/// negative not false positive, and rare):** [`NESTED_CALL_OPEN`] truncates before *every* nested
/// call, not only ones that could supply a false `)` terminator, so a real version constraint that
/// happens to follow an already-closed nested call is missed — e.g. `gem("rails",
/// legacy_check(:x), "~> 7.0")` yields `version_req: None` where `~> 7.0` is a genuine,
/// syntactically-valid positional requirement. Distinguishing "nested call already closed before
/// this version" from "version is itself inside/after the nested call that F5 must truncate
/// before" needs real paren-depth tracking over the segment, not just the first-match boundary
/// this function already computes for [`ANY_OPTION_KEY`]/[`STATEMENT_MODIFIER_KEYWORD`] — not
/// attempted here to avoid over-engineering a rare, safe-direction gap.
// Group 1 is mandatory in both version patterns; `key_match.start()`/`modifier_match.start()`/
// `nested_call_match.start()` are regex match-start offsets, always char boundaries.
#[allow(clippy::unwrap_used, clippy::string_slice)]
fn extract_version(
    lines: &[(&str, usize)],
    content: &str,
    line_table: &LineOffsetTable,
    allow_paren_terminator: bool,
) -> (Option<String>, Option<Range>) {
    let version_pattern: &Regex = if allow_paren_terminator {
        &VERSION_PATTERN_PAREN_TERMINATED
    } else {
        &VERSION_PATTERN
    };

    for (line, base_offset) in lines {
        let line: &str = line;
        let key_match = first_code_match(line, &ANY_OPTION_KEY);
        let modifier_match = first_code_match(line, &STATEMENT_MODIFIER_KEYWORD);
        let nested_call_match = first_code_match(line, &NESTED_CALL_OPEN);
        let boundary = key_match
            .map(|m| m.start())
            .into_iter()
            .chain(modifier_match.map(|m| m.start()))
            .chain(nested_call_match.map(|m| m.start()))
            .min()
            .unwrap_or(line.len());
        let search_area = &line[..boundary];

        if let Some(caps) = version_pattern.captures(search_area) {
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

/// Joins every accumulated physical line of a (possibly multi-line) `gem` call into one search
/// string, so a bracket/comma-held value that itself spans multiple lines — e.g. a `platforms:
/// [` array literal not closed until a later line (#1017) — can still be matched by a single,
/// line-oriented `Regex` instead of requiring the whole value to sit on one physical line. This
/// only reunites lines the parser already accumulated into one [`PendingGem`]; a bare `key:` on
/// one line whose value sits on the next with no bracket/comma linking them is not itself
/// treated as a continuation (see `ends_with_trailing_comma`/`apply_bracket_delta`) and so never
/// reaches here.
///
/// Callers join once and build one [`OptionScan`] from the result, shared by
/// `extract_group`/`extract_source`/`extract_platforms`/`extract_require` (correctness-gate
/// re-check, finding #4: those four previously each joined/rescanned the same text
/// independently — up to 4x redundant allocation per multi-line `gem` call). For a single-line
/// call, the caller passes that line directly instead of joining a one-element slice.
///
/// Deliberately always inserts a space, even at a backslash-continued line boundary
/// (correctness-gate finding F7, investigated and rejected): live-verified against Ruby 4.0.6
/// (PRISM parser, `ruby -c`) that backslash-newline continuation does **not** splice adjacent
/// text at the character level the way this finding assumed — `fo\` / `o` does not lex as the
/// identifier `foo` (confirmed: raises `NameError: undefined local variable 'o'`, i.e. two
/// separate tokens), and the finding's own repro (`req\` / `uire: "bar"`) is itself a Ruby syntax
/// error (`ruby -c`: "unexpected label"), not valid-but-unusual Ruby. A mid-token backslash split
/// can't occur in valid Ruby, so there is no real input this would misparse either way; joining
/// with a space (or without one) is equally inert for the token-boundary continuations that *are*
/// valid Ruby (e.g. `gem "x", \` / `source: "y"`), since both sides already sit at a token
/// boundary where whitespace is optional.
fn joined_lines(lines: &[&str]) -> String {
    lines.join(" ")
}

/// Computes, for every byte offset in `text`, the unmatched `[`/`{`/`(` nesting depth strictly
/// before that offset — quote-aware (ignoring bracket characters inside a string literal or
/// comment) via `code`, the shared [`deps_core::quote_scan::CodeSpans`] classification built
/// once by [`OptionScan::new`] — scanned in one continuous pass over the *whole* joined text.
///
/// This is the structural fix for the #1017 leak class surviving repeated absorption-guard
/// tweaks (S2/S2b, correctness-gate finding #1): `extract_source`/`group`/`platforms`/`require`
/// previously matched an option-key pattern *anywhere* in the joined text with no notion of
/// nesting at all, so any `source:`/`git:`-shaped text became the gem's source regardless of
/// where it actually sat — e.g. `install_if: { source: "evil" }` leaks on a *single* line, no
/// continuation or absorption involved. The absorption guard only filters what text gets
/// *joined*; the sink accepting anything nested is the actual defect. [`OptionScan`]'s helpers
/// use this table so only a match whose key starts at depth 0 — a *direct* keyword argument of
/// the `gem` call, not nested inside another option's value — is trusted. This defends against a
/// distinct vector from `code`, which instead catches a decoy match inside an already-open
/// quoted *value* on the same line (e.g. `path: 'vendor/git: "cache"'`, #1022) — no bracket is
/// involved there at all, so bracket depth alone would not exclude it; both checks are required
/// together (see [`first_code_match_at_depth_zero`]).
///
/// **Scope of the guarantee**: this is sound for *well-formed* Ruby — a `source:` (or other
/// option key) genuinely at depth 0 in syntactically valid text is correctly a direct keyword
/// argument of the `gem` call, and one genuinely nested is correctly rejected. It is best-effort
/// and fail-closed, not exhaustive, against text containing *invalid* Ruby: depth is a proxy for
/// real structure, which is undefined once the text isn't structurally valid to begin with. An
/// odd quote run can still hide a bracket from `code`, a balanced inner pair (`({})`) can still
/// restore an empty stack ahead of a later excess closer, and the comma-continuation path (kept
/// open by a trailing comma alone, no bracket involved) is untouched by any of this. Closing
/// those requires a real bracket/string-aware scanner, tracked as its own follow-up
/// (bug-ops/deps-lsp#1039, sibling scope to #1022) rather than further pattern-matching here —
/// every such vector requires the Gemfile to already contain invalid Ruby, so it grants no
/// capability beyond what a valid `source: "evil"` already would.
///
/// A closer that doesn't match the innermost currently-open bracket — either the *type* is
/// wrong (e.g. a stray `]` while only a `{` is open) or there's nothing open at all — makes the
/// text structurally broken from that point on: **fail-closed poisoning** (critic finding, 8th
/// vector / correctness-gate re-check round 5) marks every later position untrusted (a sentinel
/// depth that can never compare equal to 0) rather than the earlier `.max(0)` clamp, which let
/// such a stray closer silently reset nesting to 0 and made everything after it read as a direct
/// depth-0 keyword argument again — the same malformed/mid-edit class (a file mid-edit is an
/// LSP's normal operating condition, not a rare adversarial-only shape) the team already ruled
/// unacceptable for the original S2.
///
/// A *matched* closer (type and nesting both correct) behaves normally — pops the stack, depth
/// decreases — so a real `platforms: [ :mri ], source: "..."` still resolves `source:` at depth
/// 0 after the array legitimately closes; only a genuinely mismatched or excess closer poisons.
///
/// The gem call's own trailing `)` surviving into the joined text for a parenthesized call is
/// itself such an unmatched closer (its opening `(` sits before the captured name and is
/// excluded from `text`), but it always comes *after* all the options, so poisoning starting
/// there has no effect on anything already matched — verified for both single- and multi-line
/// paren calls.
///
/// Scanning the *joined* text in one continuous pass — rather than per original physical line —
/// also closes the #1017/#3 per-line reset gap for this specific sink: a string literal that
/// spans a line boundary and is later closed still tracks correctly here, because there are no
/// independent per-line resets once the lines are joined into one string.
///
/// A closer that *does* type-match the innermost open bracket is additionally forced to poison
/// anyway when it directly follows a bare `key:` with nothing but whitespace in between — e.g.
/// `install_if: { a: } , source: "evil" }` (critic finding, 8th vector round 2). Here the first
/// `}` properly closes the `{` by pure type-matched counting, so `source:` — found *before* the
/// text's later, genuinely-unmatched second `}` — would otherwise still read as a legitimate
/// depth-0 match despite the text being just as structurally broken. A hash/array value is never
/// genuinely empty like this in a well-formed Gemfile, so [`DANGLING_VALUE_BEFORE_CLOSER`] flags
/// it as broken/mid-edit content too, the same conservative direction as every other stray-closer
/// shape.
// `idx` comes from `char_indices()` over `text`, always < `text.len()` and thus a valid index
// into `depths` (sized `text.len() + 1`).
#[allow(clippy::indexing_slicing)]
fn bracket_depths(text: &str, code: &deps_core::quote_scan::CodeSpans<'_>) -> Vec<i32> {
    let mut depths = vec![0i32; text.len() + 1];
    let mut stack: Vec<char> = Vec::new();
    let mut poisoned = false;
    let dangling_closers: HashSet<usize> = DANGLING_VALUE_BEFORE_CLOSER
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|m| m.start()))
        .collect();
    for (idx, ch) in text.char_indices() {
        if poisoned {
            depths[idx] = i32::MAX;
            continue;
        }
        // Written before `ch` is processed below, so a closer that poisons *this* position
        // still leaves it (and everything before it) trusted — only later positions are
        // affected.
        depths[idx] = i32::try_from(stack.len()).unwrap_or(i32::MAX);
        if code.is_code_byte(idx) {
            let dangling = dangling_closers.contains(&idx);
            match ch {
                '[' | '{' | '(' => stack.push(ch),
                ']' if !dangling && stack.last() == Some(&'[') => {
                    stack.pop();
                }
                '}' if !dangling && stack.last() == Some(&'{') => {
                    stack.pop();
                }
                ')' if !dangling && stack.last() == Some(&'(') => {
                    stack.pop();
                }
                ']' | '}' | ')' => poisoned = true,
                _ => {}
            }
        }
    }
    if let Some(last) = depths.last_mut() {
        *last = if poisoned {
            i32::MAX
        } else {
            i32::try_from(stack.len()).unwrap_or(i32::MAX)
        };
    }
    depths
}

/// Precomputed, shared classification of a (possibly multi-line, already [`joined_lines`])
/// `gem` call's option text — built once and reused by `extract_group`/`extract_source`/
/// `extract_platforms`/`extract_require`, each of which needs *both* independent defenses on
/// every candidate match: `code` (is this position outside every string literal and comment —
/// #1022's defense against a decoy match inside an already-open quoted value) and `depths` (is
/// this position at bracket depth 0 — #1039's defense against an option key nested inside
/// another option's value, see [`bracket_depths`]). Neither alone is sufficient — a decoy key
/// inside an already-open quoted value (`path: 'vendor/git: "cache"'`) sits at depth 0 (no
/// bracket involved) but is not code; an option key genuinely nested inside another option's
/// hash value (`install_if: { source: "evil" }`) is code (not inside any string) but sits at
/// depth > 0.
struct OptionScan<'a> {
    text: &'a str,
    code: deps_core::quote_scan::CodeSpans<'a>,
    depths: Vec<i32>,
}

impl<'a> OptionScan<'a> {
    fn new(text: &'a str) -> Self {
        let code =
            deps_core::quote_scan::CodeSpans::new(text, deps_core::quote_scan::ScanSyntax::Ruby);
        let depths = bracket_depths(text, &code);
        Self { text, code, depths }
    }
}

/// Returns the first match of `re` in `scan`'s text that is both code-positioned and at bracket
/// depth 0 (see [`OptionScan`]) — a direct keyword argument of the `gem` call, not a decoy match
/// inside an already-open quoted value and not nested inside another option's value.
// A match's start is always a valid `scan.text` offset (at most `scan.text.len()`), and
// `scan.depths` is sized `scan.text.len() + 1` (see `bracket_depths`), so indexing it at a
// match start never panics.
#[allow(clippy::indexing_slicing)]
fn first_code_match_at_depth_zero<'a>(
    scan: &OptionScan<'a>,
    re: &Regex,
) -> Option<regex::Match<'a>> {
    re.find_iter(scan.text)
        .find(|m| scan.code.is_code_byte(m.start()) && scan.depths[m.start()] == 0)
}

/// Same as [`first_code_match_at_depth_zero`], but for a regex with capture groups the caller
/// needs: returns the first eligible match's full [`regex::Captures`] directly (via
/// `captures_iter`, one regex pass), instead of the caller having to re-run `captures` on the
/// matched substring to recover groups after the fact.
// Same guarantee as `first_code_match_at_depth_zero` above.
#[allow(clippy::indexing_slicing)]
fn first_code_captures_at_depth_zero<'a>(
    scan: &OptionScan<'a>,
    re: &Regex,
) -> Option<regex::Captures<'a>> {
    re.captures_iter(scan.text).find(|caps| {
        let start = caps.get(0).map_or(0, |m| m.start());
        scan.code.is_code_byte(start) && scan.depths[start] == 0
    })
}

/// Reads a Bundler inline option's string value: finds `key_re`'s first eligible match
/// ([`first_code_match_at_depth_zero`]), skips whitespace, and reads the string literal that
/// follows via [`deps_core::quote_scan::read_string_literal`] — escape-aware, so an embedded
/// escaped quote of the *other* kind (e.g. `\'` inside a `"`-delimited value) no longer
/// truncates the value early (#1020).
///
/// Returns `None` for a missing key, a value that is not a string literal at all, an
/// unterminated one, or an **empty** one — S2: mirrors the `+` (one-or-more) that the value
/// regex this replaces used, so `source: ""` / `github: ""` / `git: ""` / `path: ""` keep
/// falling through to the next-lower-precedence source instead of resolving to e.g.
/// `CustomRegistry("")`. [`extract_require`] does not use this helper precisely because
/// `require: ""` must keep parsing (its value regex used `*`, not `+`).
///
/// Only ever tries the *first* eligible key: on an (invalid, duplicated-key) line like `git:
/// SOME_CONST, git: "..."`, this returns `None` rather than backtracking to the second `git:`
/// the way the old single key+value regex would have via its own internal backtracking
/// (impl-critic m2). Not reachable from valid Ruby (a duplicate keyword argument is itself a
/// syntax error), and the fallthrough direction is the same safe one as every other `None` case
/// above.
// `key_match.end()` is a regex match-end offset, always a char boundary; `rest.trim_start()`
// only trims whitespace, itself always single-byte ASCII, so `at` stays a char boundary;
// `literal.content` comes from `read_string_literal`, likewise always char-boundary bounds.
#[allow(clippy::string_slice)]
fn option_string_value<'a>(scan: &OptionScan<'a>, key_re: &Regex) -> Option<&'a str> {
    let key_match = first_code_match_at_depth_zero(scan, key_re)?;
    let rest = &scan.text[key_match.end()..];
    let at = key_match.end() + (rest.len() - rest.trim_start().len());
    let quote = scan.text[at..].chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let literal = deps_core::quote_scan::read_string_literal(
        scan.text,
        at,
        deps_core::quote_scan::ScanSyntax::Ruby,
    )?;
    if literal.content.is_empty() {
        return None;
    }
    Some(&scan.text[literal.content])
}

/// Scans `scan`'s text for the inline `group:` option at bracket depth 0 and outside every
/// string literal/comment (see [`OptionScan`]), returning the first match.
fn extract_group(scan: &OptionScan<'_>) -> Option<DependencyGroup> {
    let caps = first_code_captures_at_depth_zero(scan, &GROUP_OPTION)?;
    Some(parse_group_symbols(&caps[1]))
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
/// `scan` wraps every physical line belonging to this `gem` call, already joined by
/// [`joined_lines`] (just that one line for a single-line declaration; the post-name remainder
/// plus every continuation line for a multi-line one, #991) — each option pattern is checked
/// against it in order at bracket depth 0 and outside every string/comment (see [`OptionScan`]),
/// so an option on any continuation line is still found regardless of which line the eventual
/// match comes from, while a decoy match inside an already-open quoted value or an
/// option-key-shaped match nested inside another option's value (e.g. `install_if: { source:
/// "..." }`) are both correctly ignored.
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
    scan: &OptionScan<'_>,
    gemfile_source_url: Option<&str>,
    block_source_url: Option<&str>,
) -> DependencySource {
    if let Some(value) = option_string_value(scan, &GIT_OPTION) {
        return DependencySource::Git {
            url: value.to_string(),
            rev: None,
        };
    }

    if let Some(value) = option_string_value(scan, &GITHUB_OPTION) {
        return DependencySource::Git {
            url: format!("https://github.com/{value}"),
            rev: None,
        };
    }

    if let Some(value) = option_string_value(scan, &PATH_OPTION) {
        return DependencySource::Path {
            path: value.to_string(),
        };
    }

    if let Some(value) = option_string_value(scan, &SOURCE_OPTION) {
        return classify_registry_url(value);
    }

    if let Some(url) = block_source_url {
        return classify_registry_url(url);
    }

    gemfile_source_url.map_or(DependencySource::Registry, classify_registry_url)
}

/// Scans `scan`'s text — every accumulated line already joined by [`joined_lines`] (so a value
/// may itself span lines, #1017) — for the inline `platforms:` option at bracket depth 0 and
/// outside every string literal/comment (see [`OptionScan`]), returning the first match.
fn extract_platforms(scan: &OptionScan<'_>) -> Vec<String> {
    let Some(caps) = first_code_captures_at_depth_zero(scan, &PLATFORMS_OPTION) else {
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

/// Scans `scan`'s text — every accumulated line already joined by [`joined_lines`] (so a value
/// may itself span lines, #1017) — for the inline `require:` option at bracket depth 0 and
/// outside every string literal/comment (see [`OptionScan`]), returning the first match.
///
/// Unlike [`extract_source`]'s options, `require`'s value is not always a string
/// (`require: false`), so it is parsed directly here rather than through
/// [`option_string_value`] — and, unlike that helper, an **empty** string value
/// (`require: ""`) is accepted, not rejected (S2): `REQUIRE_OPTION`'s old value pattern used
/// `*` (zero-or-more), not `+`, so `require: ""` has always meant "explicitly disable the
/// default require", distinct from no `require:` option at all.
///
/// The `false` branch requires a word boundary right after it (N4: `require: falsey` and
/// `require: false_thing` are option-value-shaped text that happens to start with `false`,
/// not the boolean literal — a bug in the regex this replaces, `(false|...)`, which matched
/// on the `false` prefix alone; fixed here since this line is being rewritten anyway).
// `key_match.end()` and `rest.trim_start()`'s skip are always char boundaries — see
// `option_string_value`'s identical justification.
#[allow(clippy::string_slice)]
fn extract_require(scan: &OptionScan<'_>) -> Option<String> {
    let key_match = first_code_match_at_depth_zero(scan, &REQUIRE_OPTION)?;
    let rest = &scan.text[key_match.end()..];
    let trimmed = rest.trim_start();
    if let Some(after_false) = trimmed.strip_prefix("false") {
        let is_word_boundary = after_false
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if is_word_boundary {
            return Some("false".to_string());
        }
    }
    let at = key_match.end() + (rest.len() - trimmed.len());
    let quote = scan.text[at..].chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let literal = deps_core::quote_scan::read_string_literal(
        scan.text,
        at,
        deps_core::quote_scan::ScanSyntax::Ruby,
    )?;
    Some(scan.text[literal.content].to_string())
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

    // --- #1022/#1020/#1023 regression tests ---

    /// S1 repro (architect/critic handoff, #1022): `path:`'s single-quoted value contains a
    /// `"`-delimited substring that looks like another option (`git: "cache"`). The old value
    /// regex `['"]([^'"]+)['"]` closed on the first embedded quote of *either* kind, so
    /// `path:`'s "value" ended at `vendor/git: `, leaving `"cache"', git: ` unconsumed and
    /// the real `git:` option undetected. `option_string_value`/`read_string_literal` only
    /// close a `'`-delimited literal on another `'`, so `path:`'s value is genuinely
    /// `vendor/git: "cache"` and the real, later `git:` option is found.
    #[test]
    fn test_path_option_decoy_does_not_swallow_real_git_option() {
        let gemfile = r#"source "https://rubygems.org"
gem "x", path: 'vendor/git: "cache"', git: "https://real.example/r""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::Git { ref url, .. } if url == "https://real.example/r"
        );
    }

    /// S2: an inline `source:` option with an **empty** string value must fall through to
    /// the enclosing `source ... do` block's URL, not resolve to `CustomRegistry("")` —
    /// `option_string_value` rejects an empty span, mirroring the `+` (one-or-more) the old
    /// value regex used.
    #[test]
    fn test_empty_source_option_falls_through_to_block_source() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "x", source: ""
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://gems.corp"
        );
    }

    /// S2, `github:` variant of the same empty-value fallthrough.
    #[test]
    fn test_empty_github_option_falls_through_to_block_source() {
        let gemfile = r#"source "https://rubygems.org"
source "https://gems.corp" do
  gem "x", github: ""
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://gems.corp"
        );
    }

    /// S2 carve-out: unlike `source:`/`git:`/`path:`/`github:`, `require: ""` must still
    /// parse to an empty string rather than being rejected — `REQUIRE_OPTION`'s old value
    /// pattern always allowed zero-or-more characters (`*`), not one-or-more, and
    /// `extract_require` preserves that by not routing through `option_string_value`.
    #[test]
    fn test_empty_require_option_still_parses() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"x\", require: \"\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].require, Some(String::new()));
    }

    /// #1020 repro (backslash form): a backslash-escaped apostrophe inside a `"`-delimited
    /// `source:` value must not be mistaken for the string's close.
    #[test]
    fn test_1020_source_option_backslash_escaped_apostrophe_not_truncated() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"x\", source: \"https://o\\'brien.example/gems\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://o\\'brien.example/gems"
        );
    }

    /// #1020 repro (no-backslash form, critic-found): an *unescaped* apostrophe inside a
    /// `"`-delimited value is not a delimiter at all under Ruby syntax (`"` and `'` each only
    /// close their own kind), so it must not truncate the value either.
    #[test]
    fn test_1020_source_option_unescaped_apostrophe_not_truncated() {
        let gemfile =
            "source \"https://rubygems.org\"\ngem \"x\", source: \"https://o'brien.example/gems\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://o'brien.example/gems"
        );
    }

    /// N1 (critic second-pass finding): `GROUP_OPTION` must also route through
    /// `first_code_match`, not just the other six `*_OPTION` lookups — otherwise a
    /// `group:`-shaped decoy inside an already-open quoted value (here, `source:`'s) is
    /// mistaken for a real `group:` option.
    #[test]
    fn test_group_option_decoy_inside_source_value_is_ignored() {
        let gemfile = r#"source "https://rubygems.org"
gem "x", source: "https://h/group: [:test]""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].group, DependencyGroup::Default);
    }

    /// #1023.2 regression: `extract_group`/`extract_source`/`extract_platforms`/
    /// `extract_require` switching from `&[&str]` to `&[(&str, usize)]` (dropping
    /// `finalize_pending_gem`'s second, offset-stripped `Vec` allocation) must not disturb
    /// the budget/truncation interaction with a still-pending multi-line `gem` call at the
    /// budget boundary — the file-end `PendingGem` flush must still respect
    /// `MAX_DEPENDENCIES_PER_DOCUMENT` rather than smuggling one more dependency past it.
    #[test]
    fn test_budget_boundary_with_trailing_multiline_gem() {
        let mut gemfile = String::from("source \"https://rubygems.org\"\n");
        for i in 0..deps_core::MAX_DEPENDENCIES_PER_DOCUMENT {
            gemfile.push_str(&format!("gem \"g{i}\"\n"));
        }
        gemfile.push_str("gem \"over\",\n  source: \"https://internal.example\"");

        let result = parse_gemfile(&gemfile, &test_uri()).unwrap();

        assert_eq!(
            result.dependencies.len(),
            deps_core::MAX_DEPENDENCIES_PER_DOCUMENT
        );
        assert!(!result.dependencies.iter().any(|d| d.name == "over"));
        assert_eq!(
            result.dependency_truncation,
            Some((
                deps_core::MAX_DEPENDENCIES_PER_DOCUMENT,
                deps_core::MAX_DEPENDENCIES_PER_DOCUMENT + 1
            ))
        );
    }

    /// Security regression (#1019): a `source ... do` block URL containing Ruby string
    /// interpolation with a single-quoted literal nested inside (`ENV['CREDS']`) must still
    /// open the block — before the fix, `SOURCE_BLOCK_START`'s single regex capture group
    /// stopped at the first quote it met (the nested `'` before `CREDS`), so the block never
    /// opened and `sidekiq-pro` silently fell through to the public rubygems.org registry.
    #[test]
    fn test_source_block_url_with_nested_interpolated_quote_still_opens() {
        let gemfile = r#"source "https://#{ENV['CREDS']}@gems.contribsys.com/" do
  gem "sidekiq-pro"
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{ENV['CREDS']}@gems.contribsys.com/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (#1017): a multi-line `gem` call whose continuation opens an
    /// array literal (`platforms: [`) rather than ending in a trailing comma must still be
    /// tracked as open across every line until the literal closes — before the bracket-depth
    /// fix, `source:` on the fourth line was dropped entirely (never associated with `foo`)
    /// and `platforms` stayed empty, since `[`-signaled continuation matched none of this
    /// parser's line-level patterns.
    #[test]
    fn test_multiline_gem_continuation_via_open_bracket() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"foo\", platforms: [\n  :mri\n],\n   source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].platforms, vec!["mri"]);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (#1021): a parenthesized `gem(...)` call at the top level must be recognized
    /// as a dependency — before the fix, `GEM_PATTERN` required whitespace (never a `(`)
    /// between `gem` and the opening quote, so this line matched nothing at all: no
    /// diagnostic, no hover, no completion.
    #[test]
    fn test_parenthesized_gem_call_top_level() {
        let gemfile = r#"source "https://rubygems.org"
gem("rails")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
    }

    /// Regression (#1021): a parenthesized `gem(...)` call nested inside a block (`group`
    /// here) must also be recognized — the same gap applied regardless of nesting, since
    /// `GEM_PATTERN` is checked identically at every nesting depth.
    #[test]
    fn test_parenthesized_gem_call_inside_block() {
        let gemfile = r#"source "https://rubygems.org"
group :test do
  gem("rspec")
end"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rspec");
        assert_matches!(result.dependencies[0].group, DependencyGroup::Test);
    }

    /// A parenthesized `gem(...)` call with a version constraint must still resolve it — the
    /// closing `)` right after the version's quote is a valid terminator, not just a comma or
    /// end-of-line/comment.
    #[test]
    fn test_parenthesized_gem_call_with_version() {
        let gemfile = r#"source "https://rubygems.org"
gem("rails", "~> 7.0")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    /// Interaction check across #1019/#1017/#1021: a `source ... do` block whose URL has a
    /// nested interpolated quote, opened with a parenthesized `gem(...)` call whose bracketed
    /// `platforms:` array spans multiple lines and closes on the same line as the call's own
    /// closing `)`. All three fixes must compose correctly — the block must still open, the
    /// call must still be recognized, the array must resolve fully, and the bracket-depth
    /// tracking must not consume the gem call's closing `)` as part of the array.
    #[test]
    fn test_source_block_paren_gem_and_bracket_continuation_compose() {
        let gemfile = "source \"https://#{ENV['CREDS']}@gems.contribsys.com/\" do\n  gem(\"sidekiq-pro\", platforms: [\n    :mri\n  ])\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "sidekiq-pro");
        assert_eq!(result.dependencies[0].platforms, vec!["mri"]);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{ENV['CREDS']}@gems.contribsys.com/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (critic finding S1, #1019 follow-up): the *mirror-image* nested-quote
    /// case — a `source ... do` URL interpolating a value with the *same* quote type as the
    /// outer literal (`"https://#{ENV["CREDS"]}@..."` vs. the cross-type `ENV['CREDS']` already
    /// covered) — must also still open the block instead of silently leaking to the public
    /// registry.
    #[test]
    fn test_source_block_url_with_same_type_nested_interpolated_quote_still_opens() {
        let gemfile = "source \"https://#{ENV[\"CREDS\"]}@gems.contribsys.com/\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{ENV[\"CREDS\"]}@gems.contribsys.com/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (#1036 follow-up, `scan_quoted_literal`'s escape-awareness): a `source ... do`
    /// block URL containing a backslash-escaped instance of its own outer quote, outside any
    /// interpolation, must not truncate early — mirrors
    /// `test_1020_source_option_backslash_escaped_apostrophe_not_truncated`'s inline-option
    /// coverage for the block form.
    #[test]
    fn test_source_block_url_with_escaped_quote_still_opens() {
        let gemfile = "source \"https://o\\\"brien.example/gems\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://o\\\"brien.example/gems");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (#1036 follow-up): an escaped quote *inside* an interpolation span must not
    /// confuse the outer escape-awareness — at interpolation depth > 0 the content is Ruby code,
    /// not string-literal content, so a nested `ENV["A\"B"]` neither closes the outer literal
    /// early nor desyncs the `{`/`}` depth tracking that ends the interpolation span.
    #[test]
    fn test_source_block_url_with_escaped_quote_inside_interpolation_still_opens() {
        let gemfile = "source \"https://#{ENV[\"A\\\"B\"]}@host/\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{ENV[\"A\\\"B\"]}@host/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (critic finding S2, #1017 follow-up): an unclosed `[` with no
    /// trailing comma — a routine transient state while editing — must not let the pending gem
    /// silently absorb a later, unrelated statement and adopt its `git:`-looking keyword
    /// argument. Exact repro from the reviewer.
    #[test]
    fn test_bracket_only_continuation_does_not_absorb_unrelated_statement() {
        let gemfile = r#"source "https://rubygems.org"
gem "public-gem", platforms: [:mri
Bundler.require(git: "https://github.com/attacker/repo")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "public-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (critic finding S2a, #1017 follow-up): a blank line *inside* a legitimate
    /// multi-line `platforms: [ … ]` array is valid Ruby and must not truncate the continuation
    /// — both the array's remaining elements and a `source:` option after the array closes must
    /// still be found. (An earlier version of the S2 fix wrongly treated any blank line as a
    /// boundary, dropping both.)
    #[test]
    fn test_bracket_only_continuation_tolerates_blank_line_inside_array() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"foo\", platforms: [\n  :mri,\n\n  :mswin\n],\n  source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].platforms, vec!["mri", "mswin"]);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (critic finding S2b, #1017 follow-up): a line that isn't shaped like
    /// array/hash literal content must still be rejected even when it doesn't match the
    /// `identifier(`-shaped blocklist the original S2 fix used — e.g. a hash-literal assignment
    /// whose braces don't open with `(`. The allowlist-based fix must reject this on its own
    /// terms (it doesn't start with `:`/a quote/`]`/`}`/`,`, and no option key is anchored at
    /// its start), not because it happens to also look like a method call.
    #[test]
    fn test_bracket_only_continuation_rejects_non_option_shaped_line() {
        let gemfile = r#"source "https://rubygems.org"
gem "public-gem", platforms: [:mri
x = { source: "https://sneaky.example" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "public-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// M1 (continuation tracking): an unmatched closing bracket earlier in the call
    /// (`require: ]],`) must not corrupt `PendingGem::bracket_stack`'s tracking of a later
    /// `platforms: [` array — a stray `]`/`}` pops an already-empty stack as a no-op rather than
    /// driving a counter negative, so `foo` is still recognized as one dependency spanning every
    /// line down to `source:` (not split or truncated early).
    ///
    /// Superseded for the *sink* by the 8th-vector fix (`bracket_depths`' fail-closed
    /// poisoning): `require: ]],`'s own stray `]` (nothing open yet to match it) is exactly the
    /// malformed/mid-edit shape that now poisons the sink's trust in the rest of the text, so
    /// `platforms`/`source` are conservatively *not* extracted here — this is intentional
    /// (matches every other stray-closer test in this module), not a regression of M1's own
    /// continuation-tracking guarantee, which this test still exercises via `dependencies.len()`.
    #[test]
    fn test_bracket_depth_clamped_at_zero_does_not_mask_later_array() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"foo\", require: ]],\n  platforms: [\n    :mri\n  ],\n  source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].platforms, Vec::<String>::new());
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// M1 sibling (correctness-gate re-check, critic's own follow-up): the test above no longer
    /// discriminates `PendingGem::bracket_stack`'s actual fix, since its malformed fixture is now
    /// *also* caught by the 8th-vector sink poisoning — `platforms == []` and `source ==
    /// Registry` are exactly the poisoned-sink symptoms, so that assertion would still pass even
    /// if the stack fix itself were reverted back to a signed, clampable counter.
    ///
    /// This variant puts the same-looking `]]` text *inside a quoted string*
    /// (`require: "]]",`) instead of as bare syntax — quote-aware, it never reaches either
    /// bracket tracker as real brackets, so nothing is malformed here at all: the array and
    /// `source:` that follow are genuinely well-formed Ruby and must resolve normally. This
    /// specifically exercises the stack's ability to keep tracking correctly through a call that
    /// merely *looks* similar to the M1 fixture, rather than through actually-malformed input.
    #[test]
    fn test_bracket_like_text_inside_string_does_not_trigger_poisoning() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"foo\", require: \"]]\",\n  platforms: [\n    :mri\n  ],\n  source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].platforms, vec!["mri"]);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (critic finding S3, #1021 follow-up): a bare (non-parenthesized) `gem` call
    /// with a trailing `if` statement-modifier whose condition contains a version-shaped quoted
    /// string must not report that string as the gem's version constraint — this gem declares
    /// none.
    #[test]
    fn test_statement_modifier_condition_not_mistaken_for_version() {
        let gemfile = r#"source "https://rubygems.org"
gem "nokogiri" if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.1")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Regression (critic finding S3, #1021 follow-up): the real version constraint before an
    /// `if` statement-modifier must still be found, not shadowed by a version-shaped quoted
    /// string inside the modifier's condition.
    #[test]
    fn test_real_version_before_statement_modifier_not_shadowed() {
        let gemfile = r#"source "https://rubygems.org"
gem "nokogiri", "~> 1.16" if Gem::Version.new(RUBY_VERSION) >= Gem::Version.new("3.1")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("~> 1.16".into()));
    }

    /// Regression (critic finding S3, #1021 follow-up): an `install_if:` lambda containing a
    /// version-shaped quoted string must not be mistaken for the gem's version constraint.
    #[test]
    fn test_install_if_lambda_condition_not_mistaken_for_version() {
        let gemfile = r#"source "https://rubygems.org"
gem "pg", install_if: -> { ENV.fetch("DB", "1") == "1" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Security regression (correctness-gate re-check, finding #1 — S2's leak class reintroduced
    /// via a new vector): an anchored `source:`-shaped line must NOT be absorbed while the
    /// innermost open bracket is an array (`[`) — such a line can never be legitimate array
    /// element content, so it's indistinguishable from a genuinely new, unrelated top-level
    /// declaration. Exact repro from the reviewer: `innocent-gem`'s `platforms: [` is left open
    /// (never closed), and the very next line looks like an anchored `source:` option — it must
    /// not be adopted.
    #[test]
    fn test_bracket_only_continuation_rejects_option_key_line_inside_array_bracket() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\nsource: \"https://evil.example.com\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Trade-off accompanying the depth-zero sink fix (correctness-gate structural fix,
    /// root-cause round): a `gem` call whose entire option list is wrapped in an explicit hash
    /// literal (`gem "foo", { source: "..." }` — valid but unusual Ruby, since bare keyword args
    /// without the braces are equivalent and far more common) is no longer treated as a source
    /// override, even though the `{` immediately follows the gem name with no intervening option
    /// key. The absorption guard still lets this line join the pending call's text (it's
    /// plausible hash content), but the sink now requires an option key to sit at true bracket
    /// depth 0, and this `source:` sits at depth 1 (nested inside the `{`) either way.
    /// Distinguishing "this brace is the whole options hash" from "this brace is another
    /// option's nested value" (e.g. `install_if: { source: ... }`, the actual attack shape)
    /// reliably would need real Ruby parsing; the security-conservative choice applies the same
    /// rule to both.
    #[test]
    fn test_hash_wrapped_options_no_longer_treated_as_direct_kwargs() {
        let gemfile =
            "source \"https://rubygems.org\"\ngem \"foo\", {\n  source: \"https://gems.corp\"\n}";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "foo");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (correctness-gate re-check, finding #2): `is_paren_call` must be computed only
    /// from the prefix before the captured gem name, not the whole `GEM_PATTERN` match — a gem
    /// name that itself contains a literal `(` (highly unusual, but not invalid Ruby syntax for
    /// a string) must not flip a bare, non-parenthesized call into "paren call" and pick up an
    /// unrelated later call's closing `)` as a version terminator.
    #[test]
    fn test_gem_name_containing_paren_does_not_enable_paren_version_terminator() {
        let gemfile = r#"source "https://rubygems.org"
gem "weird(name)", check(RUBY_VERSION, "~> 1.0")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].name, "weird(name)");
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Control case for the test above: a normal parenthesized call still resolves its version
    /// correctly — confirms the fix didn't disable `is_paren_call` altogether.
    #[test]
    fn test_normal_gem_name_with_paren_call_still_resolves_version() {
        let gemfile = r#"source "https://rubygems.org"
gem("rails", "~> 7.0")"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    /// Security regression — root-cause round (correctness-gate re-check): decisive proof the
    /// leak class lives in the *sink* (`extract_source` et al.), not the absorption guard. This
    /// leaks on a SINGLE line with no continuation or absorption involved at all — `source:`
    /// nested inside `install_if:`'s hash-literal value must not be treated as the gem's own
    /// source. Exact repro from the reviewer.
    #[test]
    fn test_source_key_nested_in_install_if_hash_value_not_treated_as_gem_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "innocent-gem", install_if: { source: "https://evil.example.com" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round: a leading-comma-shaped line absorbed into an
    /// unclosed array must still be rejected by the sink's depth-zero gate, regardless of the
    /// absorption guard's `array_element_shaped` allowance for a leading `,`.
    #[test]
    fn test_leading_comma_source_nested_in_array_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\n, source: \"https://evil.example.com\"\n]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round: the hash-rocket option spelling (`:source =>`)
    /// nested inside an unclosed array must also be rejected by the depth-zero gate — the sink
    /// fix isn't specific to the modern `key:` syntax.
    #[test]
    fn test_hash_rocket_source_nested_in_array_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\n:source => \"https://evil.example.com\"\n]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round: a leading-quote-shaped line (a plausible array
    /// string element) that also happens to contain `source:` further along must still be
    /// rejected by the depth-zero gate while nested inside an unclosed array.
    #[test]
    fn test_leading_quote_source_nested_in_array_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\n\"x\", source: \"https://evil.example.com\"\n]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round: `platforms: [{ ... }]` — a hash nested two levels
    /// deep (array containing a hash) — must not let a `source:` key inside it leak through,
    /// even though the absorption guard's hash-kind allowance lets the line join (current open
    /// bracket is `{`, the innermost one). Depth 0 means direct keyword argument of `gem`, not
    /// "nested inside anything that happens to look like a hash".
    #[test]
    fn test_source_nested_two_levels_deep_in_array_of_hashes_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [{\nsource: \"https://evil.example.com\"\n}]";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round: `platforms: { ... }` (a bare hash, not an array)
    /// as the option's value must also keep a nested `source:` from leaking.
    #[test]
    fn test_source_nested_in_platforms_hash_value_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: {\nsource: \"https://evil.example.com\"\n}";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — root-cause round, #3 interaction: a string literal that spans a
    /// physical line boundary and is later closed must not desync the sink's bracket-depth
    /// tracking into treating a genuinely-nested `source:` as depth 0. Unlike the per-physical-
    /// line `apply_bracket_delta` used for the absorption guard's continuation decisions (which
    /// still has the per-line `CodeSpans`-reset gap, #3, deferred alongside #1022), the sink's
    /// [`bracket_depths`] rescans the fully-joined text in one continuous pass, so the `]`
    /// embedded in the still-open string is correctly recognized as string content, not a real
    /// closer — the array never actually closes, so the trailing `source:` stays nested.
    #[test]
    fn test_multiline_string_spanning_line_boundary_does_not_desync_sink_depth_tracking() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\"a string that never closes\n], source: \"https://evil.example.com\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — 8th-vector round (critic re-check 5): a bracket-*typed* stray
    /// closer (`]`) inside `install_if:`'s hash value, mismatched against the open `{`, must
    /// poison the sink's trust in everything after it — rejecting the later `source:` instead of
    /// letting the old `.max(0)` clamp silently reset nesting back to 0.
    #[test]
    fn test_mismatched_bracket_type_poisons_later_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "innocent-gem", install_if: { a: ] , source: "https://evil.example.com" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — 8th-vector round: same as above with a mismatched `)` instead of
    /// `]` — parens must poison on mismatch too, not just brackets/braces.
    #[test]
    fn test_mismatched_paren_poisons_later_source() {
        let gemfile = r#"source "https://rubygems.org"
gem "innocent-gem", install_if: { a: ) , source: "https://evil.example.com" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — 8th-vector round: a closer that *does* type-match the open bracket
    /// (`}` properly closing `{`) still must not re-trust the text after it, because it directly
    /// follows a dangling `a:` value with nothing between the colon and the closer —
    /// [`DANGLING_VALUE_BEFORE_CLOSER`]'s force-poison, since pure type-matching alone can't
    /// catch this (the later, genuinely-unmatched second `}` comes *after* `source:`, too late
    /// for forward-only poisoning to help on its own).
    #[test]
    fn test_dangling_value_before_matched_closer_still_poisons() {
        let gemfile = r#"source "https://rubygems.org"
gem "innocent-gem", install_if: { a: } , source: "https://evil.example.com" }"#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — 8th-vector round: multi-line form of the mismatched-bracket-type
    /// case — a `]` on its own continuation line, mismatched against `install_if:`'s open `{`.
    #[test]
    fn test_mismatched_bracket_type_poisons_across_multiple_lines() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", install_if: {\n],\nsource: \"https://evil.example.com\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression — 8th-vector round: multi-line form with a doubled closer (`]]`) —
    /// the second `]` has nothing left to match once the first legitimately closes `platforms:
    /// [`, so it poisons the trailing `source:`.
    #[test]
    fn test_doubled_closer_poisons_across_multiple_lines() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", platforms: [\n]],\nsource: \"https://evil.example.com\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Performance regression (critic finding S1): `bracket_depths` collected
    /// [`DANGLING_VALUE_BEFORE_CLOSER`] candidate offsets into a `Vec<usize>` and checked
    /// membership with `Vec::contains`, an O(n) scan repeated for every code byte — quadratic
    /// overall. Each decoy here (`x: )` inside an already-quoted option value) matches the
    /// dangling-closer regex without ever poisoning (it's not a code byte), so this file builds
    /// a large `dangling_closers` set purely to stress the lookup, not the poisoning logic
    /// itself. `parse_gemfile` runs on every document change, so this must stay fast at a size
    /// representative of a large real-world `Gemfile`; the assertion is on correctness (the
    /// real trailing `source:` still resolves) rather than wall-clock time, since a timing
    /// assertion would be flaky across CI hardware — a reintroduced `Vec::contains` scan would
    /// still pass this test, just far slower, which is caught by [`bracket_depths`]'s own
    /// `HashSet` choice rather than by this test's assertions.
    #[test]
    fn test_many_dangling_closer_decoys_still_resolve_trailing_source() {
        // A single physical line, not a multi-line continuation — `MAX_PENDING_GEM_SEGMENTS`
        // caps continuation at 256 lines, far too few to build a joined option text anywhere
        // near the size that exposed the quadratic `Vec::contains` scan.
        let mut gemfile = String::from("source \"https://rubygems.org\"\ngem \"real-gem\", ");
        for i in 0..4000 {
            gemfile.push_str(&format!("opt{i}: \"x: ) ' x\", "));
        }
        gemfile.push_str("source: \"https://gems.corp\"\n");
        let result = parse_gemfile(&gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "real-gem");
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://gems.corp"
        );
    }

    /// Regression (correctness-gate finding F1): an option value that opens a method call
    /// spanning multiple lines, with no trailing comma or backslash on its first line, must keep
    /// the `gem` call open until the call's own `)` closes — otherwise the call finalizes one
    /// line early and the real trailing `source:` on the third line is silently dropped, leaking
    /// this gem to the public registry. Exact repro from the reviewer.
    #[test]
    fn test_paren_only_continuation_keeps_call_open_across_lines() {
        let gemfile = "gem \"sidekiq-pro\", install_if: SomeCheck(\n  ENV[\"X\"]\n), source: \"https://gems.corp\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "sidekiq-pro");
        assert_matches!(
            result.dependencies[0].source,
            DependencySource::CustomRegistry { ref url } if url == "https://gems.corp"
        );
    }

    /// Regression (correctness-gate finding F1): the paren-only continuation guard must not
    /// require array/hash-shaped content on continuation lines — a nested call's arguments have
    /// no fixed shape (`ENV["X"]` here isn't array/hash-element-shaped, e.g. doesn't start with
    /// `:`/quote/`,`/`]`/`}`) and must still be absorbed rather than treated as an unrelated
    /// top-level statement.
    #[test]
    fn test_paren_only_continuation_tolerates_non_array_shaped_content() {
        let gemfile = "gem \"x\", install_if: Check(\n  some_arbitrary_expression + 1\n)";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "x");
    }

    /// Security regression (correctness-gate finding F1, adversarial-review vector): skipping the
    /// array/hash content-shape gate for a `(`-only continuation (see
    /// [`test_paren_only_continuation_tolerates_non_array_shaped_content`] above) must not reopen
    /// the #1017/S2 leak class — a decoy `source:`-shaped line absorbed while an `install_if:`
    /// call's argument list is still open must still be rejected by [`bracket_depths`]'s depth-zero
    /// gate, exactly like the `[`/`{` decoy vectors above, because [`apply_bracket_delta`]'s stack
    /// never outlives `bracket_depths`' own nesting depth (see that function's doc).
    #[test]
    fn test_source_nested_in_open_paren_continuation_not_treated_as_gem_source() {
        let gemfile = "source \"https://rubygems.org\"\ngem \"innocent-gem\", install_if: Check(\nsource: \"https://evil.example.com\"\n)";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "innocent-gem");
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (correctness-gate finding F2): a `{`/`}` inside a quoted literal nested inside
    /// a `source ... do` block's URL interpolation must not be mistaken for an interpolation-depth
    /// marker — the `}` inside the nested `"A}B"` string must not prematurely close the
    /// interpolation span, which would let the nested string's own closing quote be misread as
    /// the outer literal's terminator and truncate the scan before ` do` is ever seen. Exact
    /// repro from the reviewer.
    #[test]
    fn test_source_block_url_interpolation_with_brace_inside_nested_string_still_opens() {
        let gemfile = "source \"https://#{ENV[\"A}B\"]}@x.com/\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{ENV[\"A}B\"]}@x.com/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (correctness-gate M1, critic finding): a `'` inside `#{...}` that is part of a
    /// regex literal, not a nested string, must not stick F2's nested-quote latch open — that
    /// swallows the real `}` terminator and the block never opens. Exact repro from the critic
    /// (`ruby -c` confirmed valid).
    #[test]
    fn test_source_block_url_interpolation_with_regex_literal_apostrophe_still_opens() {
        let gemfile =
            "source \"https://#{t.sub(/'/, \"\")}@gems.corp/\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{t.sub(/'/, \"\")}@gems.corp/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (correctness-gate M1, critic finding): a `'` inside `#{...}` that is part of a
    /// Ruby character literal (`?'`), not a nested string, must likewise not stick the
    /// nested-quote latch open. Exact repro from the critic (`ruby -c` confirmed valid).
    #[test]
    fn test_source_block_url_interpolation_with_character_literal_apostrophe_still_opens() {
        let gemfile =
            "source \"https://#{a == ?' ? b : c}@gems.corp/\" do\n  gem \"sidekiq-pro\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://#{a == ?' ? b : c}@gems.corp/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Regression (correctness-gate finding F5): a version-shaped quoted string that is actually
    /// an argument to an unrelated nested call must not be misread as the gem's own version —
    /// `legacy_check("~> 1.0")`'s own closing paren must not satisfy
    /// `VERSION_PATTERN_PAREN_TERMINATED`'s `)` terminator in place of the gem call's. Exact
    /// repro from the reviewer.
    #[test]
    fn test_nested_call_argument_not_mistaken_for_gem_version() {
        let gemfile = "gem(\"rails\", legacy_check(\"~> 1.0\"), platforms: [:mri])";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "rails");
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Regression (correctness-gate finding F5): a version constraint that legitimately precedes
    /// a nested call argument must still be found — the nested-call boundary must not truncate
    /// the search area before a real, earlier version constraint.
    #[test]
    fn test_version_before_nested_call_argument_still_found() {
        let gemfile = "gem(\"rails\", \"~> 7.0\", legacy_check(\"whatever\"))";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("~> 7.0".into()));
    }

    /// Known limitation, pinned (correctness-gate M3): a real version constraint that follows an
    /// already-*closed* nested call is dropped — [`NESTED_CALL_OPEN`] truncates before every
    /// nested call, not only ones whose own `)` could be mistaken for the gem's terminator (F5's
    /// actual problem). Safe direction (missing data, not misattributed data) and rare, so
    /// documented as a known gap in `extract_version`'s doc rather than fixed; this test pins the
    /// current (imperfect) behavior so a future change to this area doesn't silently flip it.
    #[test]
    fn test_known_limitation_version_after_closed_nested_call_is_dropped() {
        let gemfile = "gem(\"rails\", legacy_check(:x), \"~> 7.0\")";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, None);
    }

    /// Known limitation, pinned (correctness-gate M2): a phantom version can be read from a line
    /// absorbed into a [`PendingGem`] purely because of a still-unclosed `(` (F1's shape-gate
    /// relaxation) — `extract_version` has no [`bracket_depths`] gating, unlike
    /// `extract_source`/`extract_group`/`extract_platforms`/`extract_require`. Blast radius is a
    /// wrong outdated/unsatisfiable diagnostic during a transient mid-edit state, not a source
    /// misclassification (the leak class this module exists to close) — `source` stays correctly
    /// `Registry` here even though `version_req` is wrong. Documented rather than fixed; this test
    /// pins the current (imperfect) behavior.
    #[test]
    fn test_known_limitation_phantom_version_from_unclosed_paren_continuation() {
        let gemfile = "gem \"sidekiq-pro\", tags: Check(\nRAILS = \"7.0.4\"";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("7.0.4".into()));
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (correctness-gate finding F6): an empty `source "" do` URL must not open a
    /// `CustomRegistry("")` block — matches the pre-hand-scan regex's `+` (one-or-more) rejection
    /// of an empty literal.
    #[test]
    fn test_source_block_start_rejects_empty_url() {
        let gemfile = "source \"\" do\n  gem \"foo\"\nend";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Security regression (#1041 repro 1): an inline `source:` option value with Ruby
    /// interpolation nesting the outer literal's own quote type must resolve to the full,
    /// untruncated URL — mirroring the block-form coverage already in place
    /// (`test_source_block_url_with_same_type_nested_interpolated_quote_still_opens`) for the
    /// inline-option path (`option_string_value` -> `deps_core::quote_scan::read_string_literal`),
    /// which had no interpolation awareness before this fix.
    #[test]
    fn test_1041_inline_source_option_with_same_type_nested_interpolated_quote_not_truncated() {
        let gemfile =
            r#"gem "sidekiq-pro", source: "https://#{ENV["TOKEN"]}@gems.contribsys.com/""#;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, r#"https://#{ENV["TOKEN"]}@gems.contribsys.com/"#);
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (#1041 repro 2, the #991 leak class): nested same-type interpolation
    /// in an *unrelated* option's value (`require:`) must not desync the quote/comment scanner
    /// and swallow a later `source:` option on the same line — before this fix, the inner `#` of
    /// the nested `#{c}` interpolation was misread as starting a line comment, discarding the
    /// rest of the line (including `source:`) and silently falling through to the public
    /// registry.
    #[test]
    fn test_1041_nested_interpolation_in_unrelated_option_does_not_leak_source() {
        let gemfile = r##"gem "p", require: "#{a["b#{c}"]}", source: "https://gems.corp/""##;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].require,
            Some(r#"#{a["b#{c}"]}"#.to_string())
        );
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (impl-critic finding S1 on the #1041 fix): a single-quoted Ruby
    /// literal never interpolates, so an unbalanced `#{` inside one (`require: '#{'`) must not
    /// be treated as opening an interpolation span — doing so misreads the literal's own very
    /// next `'` as still inside an unclosed interpolation, making the whole `require` value
    /// look unterminated, absorbing the rest of the line (the real `source:` option included)
    /// into it, and silently falling through to the public registry. Exact repro from the
    /// critic (`ruby -c` confirmed valid).
    #[test]
    fn test_1041_critic_s1_single_quoted_unbalanced_interpolation_does_not_leak_source() {
        let gemfile = r"gem 'p', require: '#{', source: 'https://gems.corp/'";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].require, Some("#{".to_string()));
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp/");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (impl-critic finding S1 on the #1041 fix): the same single-quoted,
    /// no-interpolation rule applies when the unbalanced `#{` sits in the `source:` value
    /// itself — the literal `#{` is just two ordinary characters of the URL, not the start of
    /// an interpolation span, and the source must still resolve (to that literal value) rather
    /// than looking unterminated.
    #[test]
    fn test_1041_critic_s1_single_quoted_source_with_hash_brace_content() {
        let gemfile = r"gem 'p', source: 'https://gems.corp/#{', platforms: :ruby";
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gems.corp/#{");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// Security regression (impl-critic finding S2 on the #1041 fix): a regex-literal apostrophe
    /// inside an *unrelated* option's interpolated value (`require:`) must not latch onto a
    /// *later, unrelated* apostrophe elsewhere on the line (here, inside the `source:` URL
    /// itself) and swallow everything in between — including the real `source:` option — as
    /// misidentified "nested string content". Exact repro from the critic.
    #[test]
    fn test_1041_critic_s2_regex_apostrophe_does_not_swallow_later_source_option() {
        let gemfile = r##"gem "p", require: "#{x =~ /'/}", source: "https://a'b}c", extra: "d""##;
        let result = parse_gemfile(gemfile, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].require,
            Some(r"#{x =~ /'/}".to_string())
        );
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://a'b}c");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }
}
