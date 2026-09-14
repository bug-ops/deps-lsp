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

/// Builds a regex pattern matching a Bundler per-gem inline option in either the modern
/// `key: value` syntax or Ruby's legacy hash-rocket `:key => value` syntax (e.g. `source:
/// "..."` or `:source => "..."`). Shared by [`SOURCE_OPTION`], [`GIT_OPTION`],
/// [`PATH_OPTION`], and [`GITHUB_OPTION`] so the hash-rocket gap (#987) is fixed once for all
/// four options instead of patched separately per option.
fn option_value_pattern(key: &str) -> String {
    format!(r#"(?:{key}:|:{key}\s*=>)\s*['"]([^'"]+)['"]"#)
}

/// Matches the per-gem inline `source:` option, e.g. `gem "x", source: "https://gems.corp"`
/// or the hash-rocket form `gem "x", :source => "https://gems.corp"`.
// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static SOURCE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&option_value_pattern("source")).expect("Invalid regex"));

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

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static GROUP_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"group:\s*(\[.+?\]|:\w+)").expect("Invalid regex"));

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

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static REQUIRE_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"require:\s*(false|['"][^'"]*['"]\s*)"#).expect("Invalid regex"));

// Same guarantee as GEM_PATTERN above.
#[allow(clippy::expect_used)]
static PLATFORMS_OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"platforms:\s*(\[.+?\]|:\w+)").expect("Invalid regex"));

/// A `group ... do`, `source ... do`, or any other Bundler DSL `... do ... end` block
/// currently open while scanning the file.
///
/// Every kind shares one `end`-terminated syntax and can nest inside any other in any order,
/// so they are all tracked on a single stack rather than as independent `Option`s (or just the
/// two kinds this parser cares about) — anything less than tracking every opener leaves
/// [`BLOCK_END`]'s pops unbalanced against pushes, popping the wrong (e.g. an enclosing
/// `source`) block early (critic finding S1).
#[derive(Debug, Clone)]
enum OpenBlock {
    /// An open `group :name do ... end` block.
    Group(DependencyGroup),
    /// An open `source "url" do ... end` block.
    Source(String),
    /// Any other open `... do ... end` block this parser does not otherwise interpret
    /// (`platforms ... do`, `install_if ... do`, `git "..." do`, `path "..." do`, `env ...
    /// do`, etc.) — tracked purely to keep the stack balanced.
    Other,
}

/// Returns the innermost open `group` block's classification, if any.
fn current_group(open_blocks: &[OpenBlock]) -> Option<DependencyGroup> {
    open_blocks.iter().rev().find_map(|block| match block {
        OpenBlock::Group(group) => Some(group.clone()),
        OpenBlock::Source(_) | OpenBlock::Other => None,
    })
}

/// Returns the innermost open `source` block's URL, if any.
fn current_source_block(open_blocks: &[OpenBlock]) -> Option<&str> {
    open_blocks.iter().rev().find_map(|block| match block {
        OpenBlock::Source(url) => Some(url.as_str()),
        OpenBlock::Group(_) | OpenBlock::Other => None,
    })
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
    let mut open_blocks: Vec<OpenBlock> = Vec::new();
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    for (line_idx, line) in content.lines().enumerate() {
        let Some(line_start) = line_table.line_start(line_idx) else {
            continue;
        };

        // Check for source block start (must precede the single-line SOURCE_PATTERN check:
        // SOURCE_PATTERN is `$`-anchored and never matches a `... do` opener, but checking
        // this first keeps the precedence explicit).
        if let Some(caps) = SOURCE_BLOCK_START.captures(line) {
            open_blocks.push(OpenBlock::Source(caps[1].to_string()));
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
            open_blocks.push(OpenBlock::Group(parse_group_symbols(&caps[1])));
            continue;
        }

        // Check for a block end (closes whichever block is innermost) — must precede the
        // generic opener check below: critic finding N1, `end # nothing left to do` would
        // otherwise match GENERIC_BLOCK_START's `do` first and be mistaken for an opener
        // instead of the closer it actually is.
        if BLOCK_END.is_match(line) {
            open_blocks.pop();
            continue;
        }

        // Check for any other `... do` block opener (platforms, install_if, git, path, env,
        // etc.) — pushed only to keep BLOCK_END's pops balanced (critic finding S1).
        if GENERIC_BLOCK_START.is_match(line) {
            open_blocks.push(OpenBlock::Other);
            continue;
        }

        // Check for a bare (no `do`) `end`-terminated block keyword (if/unless/case/begin/
        // def/class/module/while/until/for) — pushed for the same balancing reason as
        // GENERIC_BLOCK_START above (code-review finding #1).
        if BARE_BLOCK_START.is_match(line) {
            open_blocks.push(OpenBlock::Other);
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

            // Extract version if present
            let rest_of_line = &line[caps.get(0).unwrap().end()..];
            let (version_req, version_range) = extract_version(
                rest_of_line,
                content,
                &line_table,
                line_start + caps.get(0).unwrap().end(),
            );

            // Extract group from inline option or current block
            let group = extract_group(rest_of_line)
                .unwrap_or_else(|| current_group(&open_blocks).unwrap_or(DependencyGroup::Default));

            // Extract source
            let source = extract_source(
                rest_of_line,
                source_url.as_deref(),
                current_source_block(&open_blocks),
            );

            // Extract platforms
            let platforms = extract_platforms(rest_of_line);

            // Extract require option
            let require = extract_require(rest_of_line);

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

    Ok(BundlerParseResult {
        dependencies,
        ruby_version,
        source_url,
        uri: doc_uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

// Group 1 is mandatory in `VERSION_PATTERN`.
#[allow(clippy::unwrap_used)]
fn extract_version(
    line: &str,
    content: &str,
    line_table: &LineOffsetTable,
    base_offset: usize,
) -> (Option<String>, Option<Range>) {
    if let Some(caps) = VERSION_PATTERN.captures(line) {
        let version = caps[1].to_string();
        let version_match = caps.get(1).unwrap();
        let version_start = base_offset + version_match.start();
        let version_end = base_offset + version_match.end();

        let version_range = byte_span_to_range(content, line_table, version_start, version_end);

        (Some(version), Some(version_range))
    } else {
        (None, None)
    }
}

fn extract_group(line: &str) -> Option<DependencyGroup> {
    GROUP_OPTION
        .captures(line)
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
/// `gemfile_source_url` is the Gemfile-level, single-line `source "..."` declaration (if
/// any); `block_source_url` is the innermost enclosing `source "..." do ... end` block's URL
/// (if any) — both captured once per file in [`parse_gemfile`] and threaded through here so a
/// gem with no per-line `git:`/`github:`/`path:`/`source:` option is classified against the
/// source that actually resolves it, rather than defaulting to the public registry.
///
/// Precedence: `git:`/`github:`/`path:` (explicit non-registry source) → inline `source:`
/// option → enclosing `source ... do` block → file-level `source` → `Registry`.
fn extract_source(
    line: &str,
    gemfile_source_url: Option<&str>,
    block_source_url: Option<&str>,
) -> DependencySource {
    if let Some(caps) = GIT_OPTION.captures(line) {
        return DependencySource::Git {
            url: caps[1].to_string(),
            rev: None,
        };
    }

    if let Some(caps) = GITHUB_OPTION.captures(line) {
        return DependencySource::Git {
            url: format!("https://github.com/{}", &caps[1]),
            rev: None,
        };
    }

    if let Some(caps) = PATH_OPTION.captures(line) {
        return DependencySource::Path {
            path: caps[1].to_string(),
        };
    }

    if let Some(caps) = SOURCE_OPTION.captures(line) {
        return classify_registry_url(&caps[1]);
    }

    if let Some(url) = block_source_url {
        return classify_registry_url(url);
    }

    gemfile_source_url.map_or(DependencySource::Registry, classify_registry_url)
}

fn extract_platforms(line: &str) -> Vec<String> {
    if let Some(caps) = PLATFORMS_OPTION.captures(line) {
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
    } else {
        vec![]
    }
}

fn extract_require(line: &str) -> Option<String> {
    if let Some(caps) = REQUIRE_OPTION.captures(line) {
        let value = &caps[1];
        if value == "false" {
            Some("false".to_string())
        } else {
            Some(value.trim_matches(|c| c == '\'' || c == '"').to_string())
        }
    } else {
        None
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
}
